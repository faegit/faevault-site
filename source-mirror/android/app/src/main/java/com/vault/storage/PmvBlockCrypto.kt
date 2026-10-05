package com.vault.storage

import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** PMV Block 的 AES-256-GCM 原语。调用方负责提供已经按用途派生的 Key。 */
object PmvBlockCrypto {
    private const val GCM_TAG_BITS = PmvContainerFormat.GCM_TAG_SIZE * 8
    private val secureRandom = SecureRandom()

    fun seal(
        vaultId: UUID,
        key: ByteArray,
        blockType: PmvContainerFormat.BlockType,
        objectId: UUID,
        objectRevision: Long,
        plaintext: ByteArray,
        blockId: UUID = UUID.randomUUID(),
        chunkIndex: Int = -1,
        flags: Int = 0,
        codecId: Int = 0,
    ): PmvContainerFormat.EncodedBlock {
        requireKey(key)
        require(plaintext.size <= PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE - PmvContainerFormat.GCM_TAG_SIZE) {
            "Block 明文超过格式上限"
        }
        val encodedPlaintext = PmvCompression.encode(codecId, plaintext)
        require(encodedPlaintext.size <= PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE - PmvContainerFormat.GCM_TAG_SIZE) {
            if (encodedPlaintext !== plaintext) encodedPlaintext.fill(0)
            "编码后的 Block 明文超过格式上限"
        }
        val nonce = ByteArray(PmvContainerFormat.GCM_NONCE_SIZE).also(secureRandom::nextBytes)
        val header = PmvContainerFormat.BlockHeader(
            blockId = blockId,
            blockType = blockType,
            objectId = objectId,
            objectRevision = objectRevision,
            chunkIndex = chunkIndex,
            flags = flags,
            cryptoSuiteId = 1,
            codecId = codecId,
            plainSize = plaintext.size.toLong(),
            cipherSize = encodedPlaintext.size.toLong() + PmvContainerFormat.GCM_TAG_SIZE,
            nonce = nonce,
        )
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(PmvContainerFormat.blockAad(vaultId, header))
            val ciphertext = cipher.doFinal(encodedPlaintext)
            check(ciphertext.size.toLong() == header.cipherSize) { "AES-GCM 输出长度与 Header 不一致" }
            PmvContainerFormat.EncodedBlock(header, ciphertext)
        } finally {
            if (encodedPlaintext !== plaintext) encodedPlaintext.fill(0)
        }
    }

    fun open(
        vaultId: UUID,
        key: ByteArray,
        block: PmvContainerFormat.EncodedBlock,
    ): ByteArray {
        requireKey(key)
        require(block.header.cryptoSuiteId == 1) { "不支持的 PMV 密码学套件" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(GCM_TAG_BITS, block.header.nonce),
        )
        cipher.updateAAD(PmvContainerFormat.blockAad(vaultId, block.header))
        val encodedPlaintext = cipher.doFinal(block.ciphertext)
        return try {
            PmvCompression.decode(block.header.codecId, encodedPlaintext, block.header.plainSize)
        } catch (error: Throwable) {
            encodedPlaintext.fill(0)
            throw error
        }.also { plaintext ->
            if (plaintext !== encodedPlaintext) encodedPlaintext.fill(0)
        }
    }

    private fun requireKey(key: ByteArray) {
        require(key.size == 32) { "PMV Block Key 必须为 256 bit" }
    }
}
