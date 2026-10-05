package com.vault.crypto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * 恢复密钥的编码/生成/校验原语（PMVE 也在使用的实时功能，与旧格式容器无关）。
 */
object RecoveryKeyCodec {
    const val KEY_SIZE = 32
    const val RECOVERY_PREFIX = "PMRK1"
    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    private val rng = SecureRandom()

    class RecoveryKeyException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

    fun generateRecoveryKey(): Pair<ByteArray, String> {
        val secret = ByteArray(KEY_SIZE).also(rng::nextBytes)
        return secret to encodeRecoveryKey(secret)
    }

    fun encodeRecoveryKey(secret: ByteArray): String {
        if (secret.size != KEY_SIZE) throw RecoveryKeyException("恢复密钥必须是 256 位")
        val body = encodeCrockford(secret, 52) + recoveryChecksum(secret)
        return "$RECOVERY_PREFIX-${body.chunked(4).joinToString("-")}"
    }

    fun decodeRecoveryKey(text: String): ByteArray {
        val compact = text.filterNot { it == '-' || it.isWhitespace() }.uppercase()
        if (!compact.startsWith(RECOVERY_PREFIX)) throw RecoveryKeyException("恢复密钥版本无效")
        val encoded = compact.removePrefix(RECOVERY_PREFIX)
        if (encoded.length != 56) throw RecoveryKeyException("恢复密钥长度无效")
        val secret = decodeCrockford(encoded.take(52), KEY_SIZE)
        if (encoded.takeLast(4) != recoveryChecksum(secret)) throw RecoveryKeyException("恢复密钥校验码不正确")
        return secret
    }

    fun recoveryKeyFingerprint(secret: ByteArray): String {
        if (secret.size != KEY_SIZE) throw RecoveryKeyException("恢复密钥必须是 256 位")
        return encodeCrockford(sha256("PMRK1 fingerprint\u0000".encodeToByteArray() + secret), 52).take(6)
    }

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun recoveryChecksum(secret: ByteArray): String {
        val digest = sha256("PMRK1\u0000".encodeToByteArray() + secret)
        val twentyBits = ((digest[0].toInt() and 0xff) shl 12) or
            ((digest[1].toInt() and 0xff) shl 4) or ((digest[2].toInt() and 0xff) ushr 4)
        return encodeCrockford(BigInteger.valueOf(twentyBits.toLong()), 4)
    }

    private fun encodeCrockford(bytes: ByteArray, width: Int): String =
        encodeCrockford(BigInteger(1, bytes), width)

    private fun encodeCrockford(input: BigInteger, width: Int): String {
        var value = input
        val chars = CharArray(width) { '0' }
        val mask = BigInteger.valueOf(31)
        for (index in width - 1 downTo 0) {
            chars[index] = CROCKFORD[value.and(mask).toInt()]
            value = value.shiftRight(5)
        }
        require(value.signum() == 0) { "value does not fit Crockford width" }
        return chars.concatToString()
    }

    private fun decodeCrockford(text: String, byteLength: Int): ByteArray {
        var value = BigInteger.ZERO
        text.forEach { char ->
            val digit = CROCKFORD.indexOf(char)
            if (digit < 0) throw RecoveryKeyException("恢复密钥包含无效字符")
            value = value.shiftLeft(5).or(BigInteger.valueOf(digit.toLong()))
        }
        if (value.bitLength() > byteLength * 8) throw RecoveryKeyException("恢复密钥长度或前导位无效")
        val raw = value.toByteArray().let { if (it.size > byteLength) it.copyOfRange(it.size - byteLength, it.size) else it }
        return ByteArray(byteLength - raw.size) + raw
    }
}
