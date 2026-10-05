package com.vault.storage

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/** Canonical, bounded and streaming PMV attachment/image representation. */
object PmvAttachmentCodec {
    const val CHUNK_SIZE = 8 * 1024 * 1024
    private const val VERSION = 1
    private const val HEADER_SIZE = 96
    private const val RECORD_SIZE = 48
    const val MAX_CHUNKS =
        (PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE - PmvContainerFormat.GCM_TAG_SIZE - HEADER_SIZE) / RECORD_SIZE
    private val MAGIC = "PMOA".encodeToByteArray()

    enum class Kind(val id: Int, val blockType: PmvContainerFormat.BlockType) {
        IMAGE(1, PmvContainerFormat.BlockType.IMAGE_CHUNK),
        ATTACHMENT(2, PmvContainerFormat.BlockType.ATTACHMENT_CHUNK),
        ;

        companion object {
            fun fromId(id: Int): Kind = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("未知附件种类")
        }
    }

    data class Chunk(val index: Int, val plainSize: Int, val sha256: ByteArray) {
        init {
            require(index >= 0) { "Chunk 序号无效" }
            require(plainSize in 1..CHUNK_SIZE) { "Chunk 大小无效" }
            require(sha256.size == 32) { "Chunk 摘要必须为 SHA-256" }
        }
    }

    data class Manifest(
        val objectId: UUID,
        val generation: Long,
        val kind: Kind,
        val totalSize: Long,
        val sha256: ByteArray,
        val chunks: List<Chunk>,
    ) {
        init {
            require(generation >= 0) { "附件 generation 不能为负数" }
            require(totalSize >= 0) { "附件大小不能为负数" }
            require(sha256.size == 32) { "附件摘要必须为 SHA-256" }
            require(chunks.size <= MAX_CHUNKS) { "附件 Chunk 数量超过格式上限" }
            val expectedCount = if (totalSize == 0L) 0L else (totalSize - 1) / CHUNK_SIZE + 1
            require(expectedCount == chunks.size.toLong()) { "附件大小与 Chunk 数量不一致" }
            var sum = 0L
            chunks.forEachIndexed { index, chunk ->
                require(chunk.index == index) { "Chunk 必须连续且按序" }
                val expectedSize = if (index == chunks.lastIndex) {
                    (totalSize - index.toLong() * CHUNK_SIZE).toInt()
                } else CHUNK_SIZE
                require(chunk.plainSize == expectedSize) { "Chunk 大小与附件大小不一致" }
                sum += chunk.plainSize
            }
            require(sum == totalSize) { "Chunk 总大小与附件大小不一致" }
        }
    }

    class ChunkFailure(val chunkIndex: Int, cause: Throwable) :
        IllegalArgumentException("附件 Chunk $chunkIndex 验证失败", cause)

    fun encodeManifest(value: Manifest): ByteArray {
        val size = Math.addExact(HEADER_SIZE, Math.multiplyExact(value.chunks.size, RECORD_SIZE))
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(VERSION)
            putLong(value.objectId.mostSignificantBits)
            putLong(value.objectId.leastSignificantBits)
            putLong(value.generation)
            put(value.kind.id.toByte())
            repeat(7) { put(0) }
            putLong(value.totalSize)
            putInt(CHUNK_SIZE)
            putInt(value.chunks.size)
            put(value.sha256)
            repeat(8) { put(0) }
            value.chunks.forEach { chunk ->
                putInt(chunk.index)
                putInt(chunk.plainSize)
                put(chunk.sha256)
                repeat(8) { put(0) }
            }
        }.array()
    }

    fun decodeManifest(raw: ByteArray): Manifest {
        require(raw.size >= HEADER_SIZE && (raw.size - HEADER_SIZE) % RECORD_SIZE == 0) {
            "附件 Manifest 长度无效"
        }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals(MAGIC)) { "附件 Manifest magic 无效" }
        require(input.int == VERSION) { "附件 Manifest 版本无效" }
        val objectId = UUID(input.long, input.long)
        val generation = input.long
        val kind = Kind.fromId(input.get().toInt() and 0xff)
        repeat(7) { require(input.get() == 0.toByte()) { "附件 Manifest 保留字段非零" } }
        val totalSize = input.long
        require(input.int == CHUNK_SIZE) { "附件 Chunk 大小不受支持" }
        val count = input.int
        require(count in 0..MAX_CHUNKS) { "附件 Chunk 数量无效" }
        require(raw.size == HEADER_SIZE + count * RECORD_SIZE) { "附件 Manifest 记录数不匹配" }
        val wholeDigest = ByteArray(32).also(input::get)
        repeat(8) { require(input.get() == 0.toByte()) { "附件 Manifest 保留字段非零" } }
        val chunks = List(count) {
            val chunk = Chunk(input.int, input.int, ByteArray(32).also(input::get))
            repeat(8) { require(input.get() == 0.toByte()) { "附件 Chunk 保留字段非零" } }
            chunk
        }
        return Manifest(objectId, generation, kind, totalSize, wholeDigest, chunks)
    }

    fun sealManifest(vaultId: UUID, key: ByteArray, value: Manifest): PmvContainerFormat.EncodedBlock =
        PmvBlockCrypto.seal(
            vaultId, key, PmvContainerFormat.BlockType.OBJECT_METADATA, value.objectId,
            value.generation, encodeManifest(value), chunkIndex = -1,
        )

    fun openManifest(vaultId: UUID, key: ByteArray, block: PmvContainerFormat.EncodedBlock): Manifest {
        require(block.header.blockType == PmvContainerFormat.BlockType.OBJECT_METADATA) { "不是附件 Manifest Block" }
        require(block.header.chunkIndex == -1) { "附件 Manifest chunkIndex 无效" }
        return decodeManifest(PmvBlockCrypto.open(vaultId, key, block)).also {
            require(it.objectId == block.header.objectId && it.generation == block.header.objectRevision) {
                "附件 Manifest 与 Block Header 绑定不一致"
            }
        }
    }

    /** 每次最多保留一个 8 MiB 明文块；块经 [emit] 立即交给调用方。 */
    fun sealFrom(
        input: InputStream,
        expectedSize: Long,
        vaultId: UUID,
        objectId: UUID,
        generation: Long,
        kind: Kind,
        keyForChunk: (Int) -> ByteArray,
        emit: (PmvContainerFormat.EncodedBlock) -> Unit,
    ): Manifest {
        require(expectedSize >= 0) { "附件大小不能为负数" }
        val expectedChunks = if (expectedSize == 0L) 0L else (expectedSize - 1) / CHUNK_SIZE + 1
        require(expectedChunks <= MAX_CHUNKS) { "附件 Chunk 数量超过格式上限" }
        val whole = MessageDigest.getInstance("SHA-256")
        val records = ArrayList<Chunk>(expectedChunks.toInt())
        var remaining = expectedSize
        var index = 0
        while (remaining > 0) {
            val wanted = minOf(CHUNK_SIZE.toLong(), remaining).toInt()
            val plain = ByteArray(wanted)
            var offset = 0
            while (offset < wanted) {
                val read = input.read(plain, offset, wanted - offset)
                require(read >= 0) { "附件流提前结束" }
                if (read == 0) continue
                offset += read
            }
            whole.update(plain)
            val digest = MessageDigest.getInstance("SHA-256").digest(plain)
            val key = keyForChunk(index)
            try {
                emit(PmvBlockCrypto.seal(
                    vaultId, key, kind.blockType, objectId, generation, plain,
                    chunkIndex = index,
                    codecId = PmvCompression.chooseCodec(plain),
                ))
            } finally {
                plain.fill(0)
            }
            records += Chunk(index, wanted, digest)
            remaining -= wanted
            index++
        }
        require(input.read() == -1) { "附件流长于声明大小" }
        return Manifest(objectId, generation, kind, expectedSize, whole.digest(), records)
    }

    /** 按 Manifest 顺序逐块拉取、认证并写出；失败异常携带准确块号。 */
    fun openTo(
        manifest: Manifest,
        vaultId: UUID,
        keyForChunk: (Int) -> ByteArray,
        blockForChunk: (Int) -> PmvContainerFormat.EncodedBlock,
        output: OutputStream,
    ) {
        val whole = MessageDigest.getInstance("SHA-256")
        manifest.chunks.forEach { record ->
            try {
                val block = blockForChunk(record.index)
                require(block.header.blockType == manifest.kind.blockType &&
                    block.header.objectId == manifest.objectId &&
                    block.header.objectRevision == manifest.generation &&
                    block.header.chunkIndex == record.index &&
                    block.header.plainSize == record.plainSize.toLong()) { "Chunk Header 与 Manifest 不一致" }
                val plain = PmvBlockCrypto.open(vaultId, keyForChunk(record.index), block)
                try {
                    require(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(plain), record.sha256)) {
                        "Chunk 摘要不匹配"
                    }
                    whole.update(plain)
                    output.write(plain)
                } finally {
                    plain.fill(0)
                }
            } catch (failure: Exception) {
                if (failure is ChunkFailure) throw failure
                throw ChunkFailure(record.index, failure)
            }
        }
        require(MessageDigest.isEqual(whole.digest(), manifest.sha256)) { "附件整体摘要不匹配" }
    }
}
