package com.vault.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.SequenceInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** 读取至多 [maxBytes] 字节（到达流尾即返回不足部分），等价 Java 11 的 InputStream.readNBytes。 */
internal fun InputStream.readAtMost(maxBytes: Int): ByteArray {
    if (maxBytes <= 0) return ByteArray(0)
    val buffer = ByteArray(maxBytes)
    var total = 0
    while (total < maxBytes) {
        val read = read(buffer, total, maxBytes - total)
        if (read < 0) break
        total += read
    }
    return if (total == maxBytes) buffer else buffer.copyOf(total)
}

/**
 * 媒体静态加密上下文：密钥从库 DEK 经 HKDF-SHA256 派生（与 PC 端 core/media_files.py 一致），
 * 仅解锁会话内激活。媒体文件落盘为 AES-256-GCM 密文，文件格式：
 * `VMED + version(1) + nonce(12) + ciphertext+tag`。
 */
object MediaCrypto {

    private const val MAGIC = "VMED"
    private const val VERSION = 0x01
    private const val INFO = "vault-media-v1"
    private const val NONCE_LEN = 12
    private const val TAG_BITS = 128
    private const val HEADER_LEN = 4 + 1 + NONCE_LEN

    private var activeDek: ByteArray? = null

    fun setContext(vaultId: String, dek: ByteArray) {
        require(vaultId.isNotBlank() && dek.isNotEmpty()) { "媒体上下文需要 vaultId 与 DEK" }
        activeDek = dek.copyOf()
    }

    fun clear() {
        activeDek?.fill(0)
        activeDek = null
    }

    fun isActive(): Boolean = activeDek != null

    private fun requireKey(): ByteArray = activeDek ?: error("媒体未解锁，无法访问媒体文件")

    /** 与 PC 端一致的派生：HKDF-SHA256(DEK, salt=zeros, info="vault-media-v1", 32B)。 */
    fun mediaKey(): ByteArray = hkdf(requireKey(), INFO.encodeToByteArray(), 32)

    private fun hkdf(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(ByteArray(32), ikm)
        val out = ByteArrayOutputStream()
        var block = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            block = hmac(prk, block + info + byteArrayOf(counter.toByte()))
            out.write(block)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun hmac(key: ByteArray, value: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(value)
    }

    private fun cipher(mode: Int, nonce: ByteArray, key: ByteArray, aad: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            updateAAD(aad)
            this
        }

    fun isEncrypted(raw: ByteArray): Boolean =
        raw.size >= 4 && raw.copyOfRange(0, 4).toString(Charsets.US_ASCII) == MAGIC

    fun encrypt(plain: ByteArray): ByteArray {
        val key = mediaKey()
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val ct = cipher(Cipher.ENCRYPT_MODE, nonce, key, INFO.encodeToByteArray()).doFinal(plain)
        val out = ByteArray(HEADER_LEN + ct.size)
        MAGIC.toByteArray().copyInto(out, 0)
        out[4] = VERSION.toByte()
        nonce.copyInto(out, 5)
        ct.copyInto(out, HEADER_LEN)
        return out
    }

    /**
     * 流式加密到 VMED 格式。调用方保有输入/输出流的生命周期；内存占用固定为复制缓冲区和
     * 单次 GCM update 的输出，不随媒体文件总大小增长。
     */
    fun encryptStream(plain: InputStream, encrypted: OutputStream) {
        val key = mediaKey()
        val nonce = ByteArray(NONCE_LEN).also { SecureRandom().nextBytes(it) }
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        try {
            encrypted.write(MAGIC.toByteArray(Charsets.US_ASCII))
            encrypted.write(VERSION)
            encrypted.write(nonce)
            val cipher = cipher(Cipher.ENCRYPT_MODE, nonce, key, INFO.encodeToByteArray())
            while (true) {
                val count = plain.read(buffer)
                if (count < 0) break
                cipher.update(buffer, 0, count)?.let(encrypted::write)
            }
            encrypted.write(cipher.doFinal())
        } finally {
            buffer.fill(0)
            nonce.fill(0)
            key.fill(0)
        }
    }

    /** 解密；非加密格式（旧明文）原样返回。 */
    fun decrypt(raw: ByteArray): ByteArray {
        if (!isEncrypted(raw)) return raw
        val key = mediaKey()
        val nonce = raw.copyOfRange(5, HEADER_LEN)
        val body = raw.copyOfRange(HEADER_LEN, raw.size)
        return cipher(Cipher.DECRYPT_MODE, nonce, key, INFO.encodeToByteArray()).doFinal(body)
    }

    /**
     * 流式解密（导出用）：读取 VMED 头后返回 CipherInputStream；明文文件原样透传。
     * 调用方必须读到底，GCM tag 校验在读到流尾时生效（密文被篡改会抛 AEADBadTagException）。
     */
    fun decryptStream(raw: InputStream): InputStream {
        val magic = raw.readAtMost(MAGIC.length)
        if (magic.size < MAGIC.length || magic.toString(Charsets.US_ASCII) != MAGIC) {
            // 旧明文格式：把已读出的前缀并回原流
            return SequenceInputStream(ByteArrayInputStream(magic), raw)
        }
        val version = raw.read()
        if (version != VERSION) throw IllegalArgumentException("媒体加密格式版本无效")
        val nonce = raw.readAtMost(NONCE_LEN)
        if (nonce.size != NONCE_LEN) throw IllegalArgumentException("媒体加密文件头被截断")
        val key = mediaKey()
        val cipher = cipher(Cipher.DECRYPT_MODE, nonce, key, INFO.encodeToByteArray())
        key.fill(0)
        nonce.fill(0)
        return CipherInputStream(raw, cipher)
    }

    /** 仅校验文件是否可被当前密钥解密（用于内容寻址去重冲突判断）。 */
    fun decryptable(raw: ByteArray): Boolean {
        if (!isEncrypted(raw)) return false
        return try {
            decrypt(raw)
            true
        } catch (_: Throwable) {
            false
        }
    }

    /** 文件版认证检查：流式读到 GCM tag，避免为去重校验加载完整媒体密文。 */
    fun decryptable(file: java.io.File): Boolean {
        if (!file.isFile) return false
        val encrypted = file.inputStream().use { input ->
            val prefix = input.readAtMost(MAGIC.length)
            prefix.size == MAGIC.length && prefix.toString(Charsets.US_ASCII) == MAGIC
        }
        if (!encrypted) return false
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        return try {
            file.inputStream().buffered().use { input ->
                decryptStream(input).use { plain ->
                    while (plain.read(buffer) >= 0) Unit
                }
            }
            true
        } catch (_: Throwable) {
            false
        } finally {
            buffer.fill(0)
        }
    }

    /** 明文大小（加密文件扣除头与 tag 开销）；旧明文返回原大小。 */
    fun plaintextSize(raw: ByteArray): Int = if (isEncrypted(raw)) raw.size - HEADER_LEN - TAG_BITS / 8 else raw.size

    /** 磁盘媒体文件的明文字节数（加密文件扣除头与 tag 开销）。 */
    fun filePlaintextSize(file: java.io.File): Long {
        val size = file.length()
        if (size >= HEADER_LEN + TAG_BITS / 8) {
            file.inputStream().use { input ->
                val header = input.readAtMost(4)
                if (header.size == 4 && header.toString(Charsets.US_ASCII) == MAGIC) {
                    return size - HEADER_LEN - TAG_BITS / 8
                }
            }
        }
        return size
    }

    fun sha256OfPlaintext(raw: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(raw)
}
