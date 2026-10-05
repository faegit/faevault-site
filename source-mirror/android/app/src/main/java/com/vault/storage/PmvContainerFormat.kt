package com.vault.storage

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 最终 PMV 容器的基础二进制格式原语。
 *
 * PMVE 容器格式：超级块/提交/块编解码。所有多字节整数固定使用大端序，
 * Superblock 固定 4 KiB 并以 HMAC-SHA256 认证；Block Header 固定 128 B，其规范化编码可直接
 * 作为后续 AEAD AAD 的组成部分。
 */
object PmvContainerFormat {
    const val FORMAT_VERSION = 1
    const val SUPERBLOCK_SIZE = 4 * 1024
    const val VAULT_HEADER_SIZE = 4 * 1024
    const val VAULT_HEADER_PRIMARY_OFFSET = SUPERBLOCK_SIZE * 2L
    const val VAULT_HEADER_SECONDARY_OFFSET = VAULT_HEADER_PRIMARY_OFFSET + VAULT_HEADER_SIZE
    const val DATA_START = VAULT_HEADER_SECONDARY_OFFSET + VAULT_HEADER_SIZE
    const val BLOCK_HEADER_SIZE = 128
    const val GCM_NONCE_SIZE = 12
    const val GCM_TAG_SIZE = 16
    const val MAX_BLOCK_CIPHER_SIZE = 16 * 1024 * 1024 + GCM_TAG_SIZE

    private const val SUPERBLOCK_AUTH_SIZE = 32
    private val SUPERBLOCK_MAGIC = "PMVS".encodeToByteArray()
    private val BLOCK_MAGIC = "PMVB".encodeToByteArray()
    private val BLOCK_AAD_DOMAIN = "PMV Block AAD v1\u0000".encodeToByteArray()

    data class Superblock(
        val vaultId: UUID,
        val sequence: Long,
        val latestCommitOffset: Long,
        val latestIndexOffset: Long,
        val committedFileEnd: Long,
        val kdfParametersOffset: Long,
        val featureFlags: Long,
    ) {
        init {
            require(sequence >= 0) { "Superblock sequence 不能为负数" }
            require(committedFileEnd >= DATA_START) { "提交文件边界无效" }
            for ((label, offset) in listOf(
                "Commit" to latestCommitOffset,
                "Index" to latestIndexOffset,
                "KDF" to kdfParametersOffset,
            )) {
                require(offset == 0L || offset in DATA_START..committedFileEnd) {
                    "$label 偏移超出提交边界"
                }
            }
        }
    }

    enum class BlockType(val id: Int) {
        ENTRY(1),
        LOGIN_INDEX(2),
        OBJECT_METADATA(3),
        IMAGE_CHUNK(4),
        ATTACHMENT_CHUNK(5),
        INDEX_PAGE(6),
        COMMIT(7),
        TOMBSTONE(8),
        OTHER(255),
        ;

        companion object {
            fun fromId(id: Int): BlockType = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("未知 PMV Block 类型")
        }
    }

    data class BlockHeader(
        val blockId: UUID,
        val blockType: BlockType,
        val objectId: UUID,
        val objectRevision: Long,
        val chunkIndex: Int,
        val flags: Int,
        val cryptoSuiteId: Int,
        val codecId: Int,
        val plainSize: Long,
        val cipherSize: Long,
        val nonce: ByteArray,
    ) {
        init {
            require(objectRevision >= 0) { "对象修订号不能为负数" }
            require(chunkIndex >= -1) { "Chunk 序号无效" }
            require(cryptoSuiteId > 0) { "密码学套件无效" }
            require(codecId >= 0) { "压缩编码无效" }
            require(plainSize >= 0) { "明文长度无效" }
            require(cipherSize >= GCM_TAG_SIZE) { "密文长度小于认证标签" }
            require(cipherSize <= MAX_BLOCK_CIPHER_SIZE) { "单个 Block 密文超过格式上限" }
            require(nonce.size == GCM_NONCE_SIZE) { "GCM nonce 必须为 96 bit" }
        }

        override fun equals(other: Any?): Boolean = other is BlockHeader &&
            blockId == other.blockId && blockType == other.blockType && objectId == other.objectId &&
            objectRevision == other.objectRevision && chunkIndex == other.chunkIndex && flags == other.flags &&
            cryptoSuiteId == other.cryptoSuiteId && codecId == other.codecId && plainSize == other.plainSize &&
            cipherSize == other.cipherSize && nonce.contentEquals(other.nonce)

        override fun hashCode(): Int {
            var result = blockId.hashCode()
            result = 31 * result + blockType.hashCode()
            result = 31 * result + objectId.hashCode()
            result = 31 * result + objectRevision.hashCode()
            result = 31 * result + chunkIndex
            result = 31 * result + flags
            result = 31 * result + cryptoSuiteId
            result = 31 * result + codecId
            result = 31 * result + plainSize.hashCode()
            result = 31 * result + cipherSize.hashCode()
            return 31 * result + nonce.contentHashCode()
        }
    }

    /** 已完成加密、可直接追加到容器的数据块。 */
    data class EncodedBlock(
        val header: BlockHeader,
        val ciphertext: ByteArray,
    ) {
        init {
            require(header.cipherSize == ciphertext.size.toLong()) { "Block 密文长度与 Header 不一致" }
        }
    }

    fun encodeSuperblock(value: Superblock, authenticationKey: ByteArray): ByteArray {
        require(authenticationKey.size >= 32) { "Superblock 认证密钥至少为 256 bit" }
        val output = ByteBuffer.allocate(SUPERBLOCK_SIZE).order(ByteOrder.BIG_ENDIAN)
        output.put(SUPERBLOCK_MAGIC)
        output.putInt(FORMAT_VERSION)
        output.putUuid(value.vaultId)
        output.putLong(value.sequence)
        output.putLong(value.latestCommitOffset)
        output.putLong(value.latestIndexOffset)
        output.putLong(value.committedFileEnd)
        output.putLong(value.kdfParametersOffset)
        output.putLong(value.featureFlags)
        val raw = output.array()
        val tagOffset = SUPERBLOCK_SIZE - SUPERBLOCK_AUTH_SIZE
        val tag = hmacSha256(authenticationKey, raw.copyOfRange(0, tagOffset))
        tag.copyInto(raw, tagOffset)
        tag.fill(0)
        return raw
    }

    fun decodeSuperblock(raw: ByteArray, authenticationKey: ByteArray): Superblock {
        require(raw.size == SUPERBLOCK_SIZE) { "Superblock 大小无效" }
        require(authenticationKey.size >= 32) { "Superblock 认证密钥至少为 256 bit" }
        val tagOffset = SUPERBLOCK_SIZE - SUPERBLOCK_AUTH_SIZE
        val expected = hmacSha256(authenticationKey, raw.copyOfRange(0, tagOffset))
        val actual = raw.copyOfRange(tagOffset, raw.size)
        val authenticated = MessageDigest.isEqual(expected, actual)
        expected.fill(0)
        actual.fill(0)
        require(authenticated) { "Superblock 认证失败" }

        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(SUPERBLOCK_MAGIC.size).also(input::get)
        require(magic.contentEquals(SUPERBLOCK_MAGIC)) { "Superblock magic 无效" }
        require(input.int == FORMAT_VERSION) { "Superblock 版本无效" }
        return Superblock(
            vaultId = input.getUuid(),
            sequence = input.long,
            latestCommitOffset = input.long,
            latestIndexOffset = input.long,
            committedFileEnd = input.long,
            kdfParametersOffset = input.long,
            featureFlags = input.long,
        )
    }

    fun selectLatestSuperblock(
        slotA: ByteArray,
        slotB: ByteArray,
        authenticationKey: ByteArray,
    ): Superblock? = listOf(slotA, slotB)
        .mapNotNull { runCatching { decodeSuperblock(it, authenticationKey) }.getOrNull() }
        .maxByOrNull(Superblock::sequence)

    fun encodeBlockHeader(value: BlockHeader): ByteArray =
        ByteBuffer.allocate(BLOCK_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(BLOCK_MAGIC)
            putInt(FORMAT_VERSION)
            putInt(BLOCK_HEADER_SIZE)
            putUuid(value.blockId)
            putInt(value.blockType.id)
            putUuid(value.objectId)
            putLong(value.objectRevision)
            putInt(value.chunkIndex)
            putInt(value.flags)
            putInt(value.cryptoSuiteId)
            putInt(value.codecId)
            putLong(value.plainSize)
            putLong(value.cipherSize)
            put(value.nonce)
        }.array()

    fun decodeBlockHeader(raw: ByteArray): BlockHeader {
        require(raw.size == BLOCK_HEADER_SIZE) { "Block Header 大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(BLOCK_MAGIC.size).also(input::get)
        require(magic.contentEquals(BLOCK_MAGIC)) { "Block magic 无效" }
        require(input.int == FORMAT_VERSION) { "Block 版本无效" }
        require(input.int == BLOCK_HEADER_SIZE) { "Block Header 长度无效" }
        val result = BlockHeader(
            blockId = input.getUuid(),
            blockType = BlockType.fromId(input.int),
            objectId = input.getUuid(),
            objectRevision = input.long,
            chunkIndex = input.int,
            flags = input.int,
            cryptoSuiteId = input.int,
            codecId = input.int,
            plainSize = input.long,
            cipherSize = input.long,
            nonce = ByteArray(GCM_NONCE_SIZE).also(input::get),
        )
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "Block Header 保留字段非零" }
        return result
    }

    fun blockAad(vaultId: UUID, header: BlockHeader): ByteArray =
        ByteBuffer.allocate(BLOCK_AAD_DOMAIN.size + 16 + BLOCK_HEADER_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(BLOCK_AAD_DOMAIN)
            putUuid(vaultId)
            put(encodeBlockHeader(header))
        }.array()

    private fun hmacSha256(key: ByteArray, value: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(value)
        }

    private fun ByteBuffer.putUuid(value: UUID) {
        putLong(value.mostSignificantBits)
        putLong(value.leastSignificantBits)
    }

    private fun ByteBuffer.getUuid(): UUID = UUID(long, long)
}
