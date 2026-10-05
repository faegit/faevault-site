package com.vault.ui.media

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.util.Base64
import android.widget.Toast
import androidx.core.content.FileProvider
import com.vault.R
import com.vault.storage.MediaCrypto
import java.io.File
import java.io.FileNotFoundException
import java.security.MessageDigest
import java.security.DigestOutputStream

private fun decodeImageBytes(b64: String): ByteArray {
    val clean = if (b64.contains(",")) b64.substringAfter(",") else b64
    return Base64.decode(clean, Base64.DEFAULT)
}

fun copyImageToClipboard(context: Context, b64: String) {
    runCatching {
        if (isPmvEMediaRef(b64)) {
            val info = imageExportInfo(context, b64)
            val uri = PmvMediaUiSession.issue(
                b64,
                displayName = "vault-image.${info.extension}",
                mimeType = info.mime,
            )
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            com.vault.ui.writeSensitiveClip(context, ClipData.newUri(context.contentResolver, "image", uri))
            Toast.makeText(context, context.getString(R.string.media_image_copied), Toast.LENGTH_SHORT).show()
            return
        }
        val dir = File(context.cacheDir, "img_share").apply { mkdirs() }
        dir.listFiles()?.filter { it.isFile && System.currentTimeMillis() - it.lastModified() > 10 * 60 * 1000L }
            ?.forEach(File::delete)
        val file: File
        if (b64.startsWith(IMAGE_FILE_PREFIX)) {
            val src = imageFileFromRef(context, b64) ?: error(context.getString(R.string.media_image_file_missing))
            val ext = src.extension.ifEmpty { "jpg" }
            file = File(dir, "img_${System.currentTimeMillis()}.$ext")
            val expected = b64.removePrefix(IMAGE_FILE_PREFIX).substringBeforeLast('.').takeIf { it.matches(HEX64) }
            var digest: MessageDigest? = null
            val targetOut = if (expected != null) {
                digest = MessageDigest.getInstance("SHA-256")
                DigestOutputStream(file.outputStream().buffered(), digest)
            } else {
                file.outputStream().buffered()
            }
            src.inputStream().buffered().use { raw ->
                MediaCrypto.decryptStream(raw).use { plain ->
                    targetOut.use { output -> plain.copyTo(output) }
                }
            }
            if (expected != null && digest != null && !MessageDigest.isEqual(digest.digest(), expected.hexBytes())) {
                Toast.makeText(context, context.getString(R.string.media_image_verify_failed), Toast.LENGTH_SHORT).show()
            }
        } else {
            val bytes = decodeImageBytes(b64)
            val ext = if (isGifBytes(bytes)) "gif" else "jpg"
            file = File(dir, "img_${System.currentTimeMillis()}.$ext")
            file.writeBytes(bytes)
        }
        val authority = "${context.packageName}.fileprovider"
        val uri: Uri = FileProvider.getUriForFile(context, authority, file)
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        com.vault.ui.writeSensitiveClip(context, ClipData.newUri(context.contentResolver, "image", uri))
        Toast.makeText(context, context.getString(R.string.media_image_copied), Toast.LENGTH_SHORT).show()
    }.onFailure { error ->
        val detail = if (error is PmvMediaSessionLockedException) {
            context.getString(R.string.system_media_session_locked)
        } else {
            error.message
        }
        Toast.makeText(context, context.getString(R.string.media_copy_image_failed, detail), Toast.LENGTH_SHORT).show()
    }
}

fun saveImageToUri(context: Context, b64: String, uri: Uri) {
    runCatching {
        if (isPmvEMediaRef(b64)) {
            context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                PmvMediaUiSession.copyTo(b64, output)
            } ?: throw FileNotFoundException(context.getString(R.string.media_cannot_write_location))
        } else if (b64.startsWith(IMAGE_FILE_PREFIX)) {
            val file = imageFileFromRef(context, b64) ?: error(context.getString(R.string.media_image_file_missing))
            context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
                val expected = b64.removePrefix(IMAGE_FILE_PREFIX).substringBeforeLast('.').takeIf { it.matches(HEX64) }
                var digest: MessageDigest? = null
                val targetOut = if (expected != null) {
                    digest = MessageDigest.getInstance("SHA-256")
                    DigestOutputStream(out, digest)
                } else {
                    out
                }
                file.inputStream().buffered().use { raw ->
                    MediaCrypto.decryptStream(raw).use { plain -> plain.copyTo(targetOut) }
                }
                if (expected != null && digest != null && !MessageDigest.isEqual(digest.digest(), expected.hexBytes())) {
                    Toast.makeText(context, context.getString(R.string.media_image_verify_failed), Toast.LENGTH_SHORT).show()
                }
            } ?: throw FileNotFoundException(context.getString(R.string.media_cannot_write_location))
        } else {
            val bytes = decodeImageBytes(b64)
            context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
                ?: throw FileNotFoundException(context.getString(R.string.media_cannot_write_location))
        }
        Toast.makeText(context, context.getString(R.string.media_image_saved), Toast.LENGTH_SHORT).show()
    }.onFailure { error ->
        val detail = if (error is PmvMediaSessionLockedException) {
            context.getString(R.string.system_media_session_locked)
        } else {
            error.message
        }
        Toast.makeText(context, context.getString(R.string.media_save_failed, detail), Toast.LENGTH_SHORT).show()
    }
}

private val HEX64 = Regex("[0-9a-f]{64}")

private fun String.hexBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
