package com.vault.ui.media

import android.content.Context
import android.net.Uri
import android.widget.Toast
import com.vault.R
import com.vault.storage.MediaCrypto
import com.vault.storage.PmvMediaRef
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.DigestOutputStream
import java.util.UUID

const val ATTACHMENT_FILE_PREFIX = "att:"

data class StoredAttachment(
    val ref: String,
    val size: Long,
    val sha256: String,
)

fun attachmentFileFromRef(context: Context, ref: String): File? {
    if (!ref.startsWith(ATTACHMENT_FILE_PREFIX)) return null
    val name = ref.removePrefix(ATTACHMENT_FILE_PREFIX)
    if (name.isBlank() || '/' in name || '\\' in name || ".." in name) return null
    return sequenceOf(
        File(context.filesDir, "attachments/$name"),
        File(context.cacheDir, "vault_media/attachments/$name"),
        File(context.cacheDir, "pmve_media_staging/attachments/$name"),
    ).firstOrNull(File::isFile)
}

fun storeAttachmentFromUri(
    context: Context,
    uri: Uri,
    maxBytes: Long,
): StoredAttachment {
    val pmve = PmvMediaUiSession.isBound()
    val directory = if (pmve) PmvMediaUiSession.stagingDirectory(context, "attachments")
    else File(context.filesDir, "attachments").also { it.mkdirs() }
    val file = File(directory, ".${UUID.randomUUID()}.tmp")
    val digest = MessageDigest.getInstance("SHA-256")
    var total = 0L
    try {
        context.contentResolver.openInputStream(uri)?.use { input ->
            file.outputStream().buffered().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= maxBytes) { context.getString(R.string.system_media_attachment_too_large) }
                    digest.update(buffer, 0, count)
                    output.write(buffer, 0, count)
                }
            }
        } ?: error(context.getString(R.string.system_media_attachment_read_failed))
        require(total > 0) { context.getString(R.string.system_media_attachment_empty) }
        val hash = digest.digest().joinToString("") { "%02x".format(it) }
        val target = File(directory, hash)
        if (target.exists()) {
            file.delete()
        } else {
            if (!pmve) requireMediaCapacity(context, total)
            if (pmve) {
                check(file.renameTo(target)) { context.getString(R.string.system_media_publish_staging_failed) }
            } else {
                file.inputStream().buffered().use { input ->
                    target.outputStream().buffered().use { output -> MediaCrypto.encryptStream(input, output) }
                }
                file.delete()
            }
        }
        return StoredAttachment(
            ref = "$ATTACHMENT_FILE_PREFIX${target.name}",
            size = total,
            sha256 = hash,
        )
    } catch (error: Throwable) {
        file.delete()
        throw error
    }
}

fun exportAttachmentToUri(
    context: Context,
    dataRefOrBase64: String,
    target: Uri,
) {
    val expected = expectedSha256(dataRefOrBase64)
    context.contentResolver.openOutputStream(target, "wt")?.use { output ->
        var digest: MessageDigest? = null
        val digestOutput = if (expected != null) {
            digest = MessageDigest.getInstance("SHA-256")
            DigestOutputStream(output, digest)
        } else {
            output
        }
        try {
            when {
                isPmvEMediaRef(dataRefOrBase64) -> PmvMediaUiSession.copyTo(dataRefOrBase64, digestOutput)
                dataRefOrBase64.startsWith(ATTACHMENT_FILE_PREFIX) -> {
                    val source = attachmentFileFromRef(context, dataRefOrBase64)
                        ?: error(context.getString(R.string.system_media_attachment_file_missing))
                    source.inputStream().buffered().use { raw ->
                        MediaCrypto.decryptStream(raw).use { plain -> plain.copyTo(digestOutput) }
                    }
                }
                else -> {
                    val start = dataRefOrBase64.indexOf(',').let { if (it >= 0) it + 1 else 0 }
                    java.util.Base64.getMimeDecoder().wrap(StringAsciiInputStream(dataRefOrBase64, start)).use { input ->
                        input.copyTo(digestOutput)
                    }
                }
            }
            if (expected != null && digest != null && !MessageDigest.isEqual(digest.digest(), expected.hexBytes())) {
                Toast.makeText(context, context.getString(R.string.system_media_attachment_export_corrupt), Toast.LENGTH_SHORT).show()
            }
        } catch (error: Throwable) {
            // PMVE 对象读取阶段已做摘要校验，失败即数据损坏：只提示，不中断导出流程
            if (error is PmvMediaSessionLockedException) {
                throw error
            } else if (expected != null) {
                Toast.makeText(context, context.getString(R.string.system_media_attachment_export_corrupt), Toast.LENGTH_SHORT).show()
            } else {
                throw error
            }
        }
    } ?: error(context.getString(R.string.system_media_attachment_create_failed))
}

/** 从引用中推导应校验的 SHA-256：att 文件名即哈希，PMVE 对象引用内嵌哈希；base64 无参考值。 */
private fun expectedSha256(dataRefOrBase64: String): String? = when {
    isPmvEMediaRef(dataRefOrBase64) -> runCatching {
        PmvMediaRef.fromExternalString(dataRefOrBase64).sha256
            .joinToString("") { "%02x".format(it) }
    }.getOrNull()
    dataRefOrBase64.startsWith(ATTACHMENT_FILE_PREFIX) ->
        dataRefOrBase64.removePrefix(ATTACHMENT_FILE_PREFIX).takeIf { it.matches(HEX64) }
    else -> null
}

private val HEX64 = Regex("[0-9a-f]{64}")

private fun String.hexBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private class StringAsciiInputStream(
    private val value: String,
    private var index: Int,
) : InputStream() {
    override fun read(): Int = if (index >= value.length) -1 else value[index++].code and 0xff

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (index >= value.length) return -1
        val count = minOf(length, value.length - index)
        for (position in 0 until count) buffer[offset + position] = value[index++].code.toByte()
        return count
    }
}
