package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.VaultCrypto
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * .pmbak 备份加密（V2 布局），与桌面端 core/pmv_backup.py 逐字节对齐。
 *
 * 布局:
 * ```
 * PMXB(4) | VERSION(1)=2 | KDF_ID(1)=1 | MEMORY_KIB(4 BE) | ITERATIONS(4 BE) | PARALLELISM(4 BE)
 * | SALT(16) | NONCE(12) | CIPHERTEXT + GCM TAG(16)
 * ```
 *
 * - KDF: Argon2id v1.3（复用 [PmvKeySchedule.derivePasswordKek] 参数：m=64MiB, t=3, p=1, salt=16B）
 * - AEAD: AES-256-GCM，AAD 绑定 MAGIC/版本/KDF 参数/salt（域前缀 `PMV backup v2\0`）
 * - 导出口令以 UTF-8 编码输入，密钥使用后立即填零
 */
object PmvBackupCrypto {
    const val MAGIC_BACKUP = "PMXB"
    const val VERSION_V2 = 2
    const val KDF_ID_ARGON2ID = 1

    private val MAGIC_BACKUP_BYTES = MAGIC_BACKUP.encodeToByteArray()
    private const val NONCE_SIZE = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_SIZE = 4 + 1 + 1 + 4 + 4 + 4 + 16 + 12
    private const val MIN_ENCRYPTED = HEADER_SIZE + GCM_TAG_BITS / 8

    private const val AAD_DOMAIN = "PMV backup v2\u0000"

    private val rng = SecureRandom()

    /** 新格式加密打包。返回完整 PMXB v2 文件字节。 */
    fun encrypt(plaintext: ByteArray, passwordUtf8: ByteArray): ByteArray {
        val salt = ByteArray(PmvKeySchedule.KDF_SALT_SIZE).also(rng::nextBytes)
        val nonce = ByteArray(NONCE_SIZE).also(rng::nextBytes)
        val key = PmvKeySchedule.derivePasswordKek(passwordUtf8, salt)
        val ciphertext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aad(salt))
            cipher.doFinal(plaintext)
        } finally {
            key.fill(0)
        }
        return MAGIC_BACKUP.encodeToByteArray() +
            byteArrayOf(VERSION_V2.toByte(), KDF_ID_ARGON2ID.toByte()) +
            uint32be(PmvKeySchedule.ARGON2_MEMORY_KIB) +
            uint32be(PmvKeySchedule.ARGON2_ITERATIONS) +
            uint32be(PmvKeySchedule.ARGON2_PARALLELISM) +
            salt + nonce + ciphertext
    }

    /** 新格式解密。头部不符/版本不支持 → [VaultCrypto.CorruptFileError]；tag 校验失败 → [VaultCrypto.DecryptError]。 */
    fun decrypt(raw: ByteArray, passwordUtf8: ByteArray): ByteArray {
        if (raw.size < MIN_ENCRYPTED) {
            throw VaultCrypto.CorruptFileError("文件头不匹配或数据过短")
        }
        if (raw.copyOfRange(0, 4).contentEquals(MAGIC_BACKUP_BYTES).not()) {
            throw VaultCrypto.CorruptFileError("不是有效的加密备份文件")
        }
        if ((raw[4].toInt() and 0xff) != VERSION_V2) {
            throw VaultCrypto.CorruptFileError("不支持的备份版本: ${raw[4].toInt() and 0xff}")
        }
        if ((raw[5].toInt() and 0xff) != KDF_ID_ARGON2ID) {
            throw VaultCrypto.CorruptFileError("不支持的备份 KDF: ${raw[5].toInt() and 0xff}")
        }
        var off = 6
        val memoryKib = readUint32be(raw, off); off += 4
        val iterations = readUint32be(raw, off); off += 4
        val parallelism = readUint32be(raw, off); off += 4
        if (memoryKib != PmvKeySchedule.ARGON2_MEMORY_KIB ||
            iterations != PmvKeySchedule.ARGON2_ITERATIONS ||
            parallelism != PmvKeySchedule.ARGON2_PARALLELISM
        ) {
            throw VaultCrypto.CorruptFileError("不支持的备份 KDF 参数")
        }
        val salt = raw.copyOfRange(off, off + PmvKeySchedule.KDF_SALT_SIZE); off += PmvKeySchedule.KDF_SALT_SIZE
        val nonce = raw.copyOfRange(off, off + NONCE_SIZE); off += NONCE_SIZE
        val ciphertext = raw.copyOfRange(off, raw.size)
        val key = PmvKeySchedule.derivePasswordKek(passwordUtf8, salt)
        return try {
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
                cipher.updateAAD(aad(salt))
                cipher.doFinal(ciphertext)
            } catch (e: AEADBadTagException) {
                throw VaultCrypto.DecryptError("备份口令错误或备份文件已损坏")
            }
        } finally {
            key.fill(0)
            salt.fill(0)
        }
    }

    /** 域分离 AAD：绑定 MAGIC、版本、KDF 枚举与参数、salt，防止参数/盐被替换。 */
    private fun aad(salt: ByteArray): ByteArray =
        AAD_DOMAIN.encodeToByteArray() +
            MAGIC_BACKUP.encodeToByteArray() +
            byteArrayOf(VERSION_V2.toByte(), KDF_ID_ARGON2ID.toByte()) +
            uint32be(PmvKeySchedule.ARGON2_MEMORY_KIB) +
            uint32be(PmvKeySchedule.ARGON2_ITERATIONS) +
            uint32be(PmvKeySchedule.ARGON2_PARALLELISM) +
            salt

    private fun uint32be(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun readUint32be(data: ByteArray, off: Int): Int =
        ((data[off].toInt() and 0xff) shl 24) or
            ((data[off + 1].toInt() and 0xff) shl 16) or
            ((data[off + 2].toInt() and 0xff) shl 8) or
            (data[off + 3].toInt() and 0xff)
}
