package com.vault.ui.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.net.Uri
import android.util.Base64
import android.util.LruCache
import android.widget.Toast
import com.vault.R
import com.vault.storage.MediaCrypto
import com.vault.storage.PmvMediaRef
import com.vault.storage.readAtMost
import com.vault.ui.uiText
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.foundation.Image
import androidx.compose.ui.Alignment
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.DigestInputStream
import java.security.DigestOutputStream

const val IMAGE_FILE_PREFIX = "img:"

private fun cacheKey(b64: String, px: Int): String {
    val suffix = b64.takeLast(48)
    return "$suffix|$px"
}

object BitmapCache {
    private const val MAX_BYTES = 16 * 1024 * 1024
    private val cache = object : LruCache<String, Bitmap>(MAX_BYTES) {
        override fun sizeOf(key: String, value: Bitmap) = value.allocationByteCount
    }
    fun get(key: String) = cache.get(key)
    fun put(key: String, bmp: Bitmap) { cache.put(key, bmp) }
    fun clear() { cache.evictAll() }
}

fun parseImageList(field: JsonElement?): List<String> {
    if (field == null) return emptyList()
    return runCatching {
        when (field) {
            is JsonArray -> field.jsonArray.map(::mediaValueString).filter(String::isNotBlank)
            is JsonPrimitive -> field.contentOrNull?.let { listOf(it) } ?: emptyList()
            is kotlinx.serialization.json.JsonObject ->
                mediaValueString(field).takeIf(String::isNotBlank)?.let(::listOf) ?: emptyList()
            else -> emptyList()
        }
    }.getOrDefault(emptyList())
}

fun List<String>.toJsonField(): JsonElement = buildJsonArray { forEach { add(it) } }

fun imageFileFromRef(context: Context, ref: String): File? {
    if (!ref.startsWith(IMAGE_FILE_PREFIX)) return null
    val name = ref.removePrefix(IMAGE_FILE_PREFIX)
    if (name.isBlank() || '/' in name || '\\' in name || ".." in name) return null
    return sequenceOf(
        File(context.filesDir, "images/$name"),
        File(context.cacheDir, "vault_media/images/$name"),
        File(context.cacheDir, "pmve_media_staging/images/$name"),
    ).firstOrNull(File::isFile)
}

private fun decodeFromFile(path: String, maxDecodePx: Int): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeFile(path, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    val longest = maxOf(bounds.outWidth, bounds.outHeight)
    while (longest / sample > maxDecodePx) sample *= 2
    val cfg = if (maxDecodePx <= 512) Bitmap.Config.RGB_565 else Bitmap.Config.ARGB_8888
    val opts = BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = cfg }
    return BitmapFactory.decodeFile(path, opts)?.oriented(runCatching { java.io.FileInputStream(path).use(::readImageOrientation) }.getOrDefault(1))
}

private fun decodeFromPmvE(context: Context, value: String, maxDecodePx: Int): Bitmap? {
    val orientation = runCatching {
        val uri = PmvMediaUiSession.issue(value, mimeType = "image/*")
        try { context.contentResolver.openInputStream(uri)?.use(::readImageOrientation) ?: 1 }
        finally { com.vault.storage.PmvMediaContentRegistry.revoke(uri) }
    }.getOrDefault(1)
    fun decode(options: BitmapFactory.Options): Bitmap? {
        val uri = PmvMediaUiSession.issue(value, mimeType = "image/*")
        return try {
            context.contentResolver.openInputStream(uri)?.buffered()?.use { input ->
                BitmapFactory.decodeStream(input, null, options)
            }
        } finally {
            com.vault.storage.PmvMediaContentRegistry.revoke(uri)
        }
    }
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    decode(bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    val longest = maxOf(bounds.outWidth, bounds.outHeight)
    while (longest / sample > maxDecodePx) sample *= 2
    val config = if (maxDecodePx <= 512) Bitmap.Config.RGB_565 else Bitmap.Config.ARGB_8888
    return decode(BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = config })?.oriented(orientation)
}

/** 读取媒体文件并解密（旧明文原样返回）。 */
private fun readMediaBytes(context: Context, file: File): ByteArray? =
    MediaCrypto.decrypt(file.readBytes())

private fun decodeBytesImpl(bytes: ByteArray, maxDecodePx: Int): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    val longest = maxOf(bounds.outWidth, bounds.outHeight)
    while (longest / sample > maxDecodePx) sample *= 2
    val cfg = if (maxDecodePx <= 512) Bitmap.Config.RGB_565 else Bitmap.Config.ARGB_8888
    val opts = BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = cfg }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)?.oriented(bytes.inputStream().use(::readImageOrientation))
}

private fun decodeBase64Impl(b64: String, maxDecodePx: Int): Bitmap? {
    val clean = if (b64.contains(",")) b64.substringAfter(",") else b64
    val bytes = Base64.decode(clean, Base64.DEFAULT)
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    val longest = maxOf(bounds.outWidth, bounds.outHeight)
    while (longest / sample > maxDecodePx) sample *= 2
    val cfg = if (maxDecodePx <= 512) Bitmap.Config.RGB_565 else Bitmap.Config.ARGB_8888
    val opts = BitmapFactory.Options().apply { inSampleSize = sample; inPreferredConfig = cfg }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)?.oriented(bytes.inputStream().use(::readImageOrientation))
}

@Composable
fun Base64Image(
    b64: String,
    modifier: Modifier = Modifier,
    contentScale: ContentScale = ContentScale.Crop,
    maxDecodePx: Int = 1024,
) {
    if (b64.isBlank()) return
    val ctx = LocalContext.current
    val isFileRef = b64.startsWith(IMAGE_FILE_PREFIX)
    val isObjectRef = isPmvEMediaRef(b64)
    val key = remember(b64, maxDecodePx) {
        val suffix = if (isFileRef) b64.substringAfter(IMAGE_FILE_PREFIX) else b64.takeLast(96)
        "$suffix|$maxDecodePx"
    }
    val cached = remember(key) { BitmapCache.get(key)?.asImageBitmap() }
    var failed by remember(key) { mutableStateOf(false) }
    var longLoading by remember(key) { mutableStateOf(false) }
    val bmp by produceState<ImageBitmap?>(cached, b64, maxDecodePx) {
        if (cached != null) return@produceState
        // 导入期间 IO/内存压力大，首次解码可能失败；自动重试数次，
        // 期间保持“图像加载中”占位，导入完成后能自动显示正常图片。
        var decoded: ImageBitmap? = null
        repeat(3) { attempt ->
            if (decoded != null) return@repeat
            decoded = withContext(Dispatchers.Default) {
                runCatching {
                    val bm = when {
                        isObjectRef -> decodeFromPmvE(ctx, b64, maxDecodePx)
                        isFileRef -> {
                            val file = imageFileFromRef(ctx, b64) ?: return@withContext null
                            decodeBytesImpl(readMediaBytes(ctx, file) ?: return@withContext null, maxDecodePx)
                        }
                        else -> decodeBase64Impl(b64, maxDecodePx)
                    }
                    bm?.let { BitmapCache.put(key, it); it.asImageBitmap() }
                }.getOrNull()
            }
            if (decoded == null && attempt < 2) {
                delay(500L * (attempt + 1))
            }
        }
        value = decoded
        if (decoded == null) failed = true
    }
    val loading = bmp == null && !failed
    LaunchedEffect(key, loading) {
        longLoading = false
        if (!loading) return@LaunchedEffect
        delay(10_000)
        if (loading) longLoading = true
    }
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        val bitmap = bmp
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = contentScale,
            )
        } else {
            // 加载占位：解码未完成时明确提示“图像加载中”，失败时提示失败，避免黑屏无反馈。
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                if (failed) {
                    Text(
                        uiText("图片尚未导入完成，请稍后查看"),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                } else {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        strokeWidth = 2.dp,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        uiText("图像加载中"),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                    if (longLoading) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            uiText("如果长期未加载完成，请退出后重新查看"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }
        }
    }
}

fun expandImageBase64(
    context: Context,
    b64: String,
    marginRatio: Float = 0.06f,
    quality: Int = 85,
    deleteSourceOnSuccess: Boolean = false,
): String {
    return runCatching {
        val src = when {
            isPmvEMediaRef(b64) -> decodeFromPmvE(context, b64, 2048) ?: return@runCatching b64
            b64.startsWith(IMAGE_FILE_PREFIX) -> {
                val file = imageFileFromRef(context, b64)
                    ?: error(context.getString(R.string.system_media_image_file_missing))
                decodeBytesImpl(readMediaBytes(context, file) ?: return@runCatching b64, 2048)
                    ?: return@runCatching b64
            }
            else -> decodeBase64Impl(b64, 2048) ?: return@runCatching b64
        }
        val shortSide = minOf(src.width, src.height)
        val pad = (shortSide * marginRatio).toInt().coerceAtLeast(8)
        val out = Bitmap.createBitmap(src.width + pad * 2, src.height + pad * 2, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(out)
        canvas.drawColor(Color.WHITE)
        canvas.drawBitmap(src, pad.toFloat(), pad.toFloat(), null)
        src.recycle()
        val baos = ByteArrayOutputStream()
        out.compress(Bitmap.CompressFormat.JPEG, quality, baos)
        out.recycle()
        if (b64.startsWith(IMAGE_FILE_PREFIX) || isPmvEMediaRef(b64)) {
            val pmve = PmvMediaUiSession.isBound()
            val dir = if (pmve) PmvMediaUiSession.stagingDirectory(context, "images")
            else File(context.filesDir, "images").also { it.mkdirs() }
            val encoded = baos.toByteArray()
            val name = "${sha256Hex(encoded)}.jpg"
            val target = File(dir, name)
            if (!target.exists()) {
                if (!pmve) requireMediaCapacity(context, encoded.size.toLong())
                if (pmve) target.writeBytes(encoded) else target.writeBytes(MediaCrypto.encrypt(encoded))
            }
            if (deleteSourceOnSuccess && b64.startsWith(IMAGE_FILE_PREFIX)) {
                imageFileFromRef(context, b64)?.takeIf { it != target }?.delete()
            }
            "$IMAGE_FILE_PREFIX$name"
        } else {
            Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP)
        }
    }.getOrDefault(b64)
}

fun isGifBytes(bytes: ByteArray): Boolean =
    bytes.size >= 6 && bytes[0] == 0x47.toByte() && bytes[1] == 0x49.toByte() &&
        bytes[2] == 0x46.toByte() && bytes[3] == 0x38.toByte() &&
        (bytes[4] == 0x37.toByte() || bytes[4] == 0x39.toByte()) && bytes[5] == 0x61.toByte()

fun isMotionPhotoByHeader(bytes: ByteArray): Boolean {
    if (bytes.size < 4 || bytes[0] != 0xFF.toByte() || bytes[1] != 0xD8.toByte()) return false
    val header = String(bytes, 0, bytes.size, Charsets.ISO_8859_1)
    return "MotionPhoto" in header || "Container:Directory" in header
}

data class ImageExportInfo(val mime: String, val extension: String)

fun imageExportInfo(context: Context, value: String): ImageExportInfo {
    val header = when {
        isPmvEMediaRef(value) -> runCatching {
            val ref = PmvMediaRef.fromExternalString(value)
            val output = ByteArrayOutputStream(minOf(16L, ref.size).toInt())
            PmvMediaUiSession.copyRangeTo(value, 0, minOf(16L, ref.size), output)
            output.toByteArray()
        }.getOrNull()
        value.startsWith(IMAGE_FILE_PREFIX) -> imageFileFromRef(context, value)?.let { file ->
            file.inputStream().buffered().use { raw ->
                MediaCrypto.decryptStream(raw).use { plain -> plain.readAtMost(16) }
            }
        }
        else -> null
    }
    return detectImageExportInfo(header ?: ByteArray(0))
}

private fun detectImageExportInfo(header: ByteArray): ImageExportInfo = when {
    header.size >= 6 && isGifBytes(header) -> ImageExportInfo("image/gif", "gif")
    header.size >= 8 && header.copyOfRange(0, 8).contentEquals(byteArrayOf(
        0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
    )) -> ImageExportInfo("image/png", "png")
    header.size >= 12 && String(header, 0, 4, Charsets.US_ASCII) == "RIFF" &&
        String(header, 8, 4, Charsets.US_ASCII) == "WEBP" -> ImageExportInfo("image/webp", "webp")
    header.size >= 12 && String(header, 4, 8, Charsets.US_ASCII).startsWith("ftyphei") ->
        ImageExportInfo("image/heic", "heic")
    else -> ImageExportInfo("image/jpeg", "jpg")
}

fun encodeImageFromUri(
    context: Context,
    uri: Uri,
    maxInputBytes: Long = if (PmvMediaUiSession.isBound()) MAX_PMVE_IMAGE_BYTES else MAX_IMAGE_BYTES,
): String {
    val tempFile = File(context.cacheDir, "img_${Thread.currentThread().id}_${System.nanoTime()}")
    try {
        val digest = MessageDigest.getInstance("SHA-256")
        context.contentResolver.openInputStream(uri)?.use { input ->
            tempFile.outputStream().use { output ->
                var total = 0L
                val buf = ByteArray(32 * 1024)
                while (true) {
                    val count = input.read(buf)
                    if (count < 0) break
                    total += count
                    require(total <= maxInputBytes) { context.getString(R.string.system_media_image_too_large) }
                    digest.update(buf, 0, count)
                    output.write(buf, 0, count)
                }
            }
        } ?: error(context.getString(R.string.system_media_image_read_failed))

        val ext = tempFile.inputStream().use { input ->
            val header = ByteArray(16)
            input.read(header)
            ".${detectImageExportInfo(header).extension}"
        }
        val name = digest.digest().joinToString("") { "%02x".format(it) } + ext
        val pmve = PmvMediaUiSession.isBound()
        val dir = if (pmve) PmvMediaUiSession.stagingDirectory(context, "images")
        else File(context.filesDir, "images").also { it.mkdirs() }
        val target = File(dir, name)
        if (!target.exists()) {
            if (!pmve) requireMediaCapacity(context, tempFile.length())
            if (pmve) {
                // 边复制边算目标哈希并与源摘要比对：不一致仅提示，不中断导入
                tempFile.inputStream().buffered().use { input ->
                    val copyDigest = MessageDigest.getInstance("SHA-256")
                    target.outputStream().buffered().use { output ->
                        DigestOutputStream(output, copyDigest).use { verified -> input.copyTo(verified) }
                    }
                    if (!MessageDigest.isEqual(copyDigest.digest(), name.substringBeforeLast('.').hexBytes())) {
                        Toast.makeText(context, context.getString(R.string.system_media_image_import_corrupt), Toast.LENGTH_SHORT).show()
                    }
                }
            } else {
                val copyDigest = MessageDigest.getInstance("SHA-256")
                tempFile.inputStream().buffered().use { input ->
                    DigestInputStream(input, copyDigest).use { plain ->
                        target.outputStream().buffered().use { output -> MediaCrypto.encryptStream(plain, output) }
                    }
                }
                if (!MessageDigest.isEqual(copyDigest.digest(), name.substringBeforeLast('.').hexBytes())) {
                    Toast.makeText(context, context.getString(R.string.system_media_image_import_corrupt), Toast.LENGTH_SHORT).show()
                }
            }
        }
        return "$IMAGE_FILE_PREFIX$name"
    } finally {
        tempFile.delete()
    }
}

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

private fun String.hexBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun deleteImageFiles(context: Context, refs: Iterable<String>) {
    refs.forEach { ref ->
        imageFileFromRef(context, ref)?.delete()
    }
}
