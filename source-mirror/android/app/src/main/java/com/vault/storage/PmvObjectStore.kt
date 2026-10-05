package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID

/**
 * Callback-based PMV object access planner.
 *
 * This class deliberately does not publish indexes or commit a transaction. Chunks and the
 * manifest are appended first and the index records are returned only after every validation and
 * append succeeds. A caller can therefore make the object visible atomically in a later commit.
 */
object PmvObjectStore {
    data class StoredBlock(val offset: Long, val length: Long) {
        init {
            require(offset >= PmvContainerFormat.DATA_START.toLong()) { "Block offset 无效" }
            require(length >= (PmvContainerFormat.BLOCK_HEADER_SIZE + PmvContainerFormat.GCM_TAG_SIZE).toLong()) {
                "Block length 无效"
            }
        }
    }

    data class ImportResult(
        val manifest: PmvAttachmentCodec.Manifest,
        val objectRecord: PmvObjectIndexCodec.ObjectRecord,
        val chunkRecords: List<PmvObjectIndexCodec.ChunkRecord>,
    )

    /**
     * Seals and immediately appends each 8 MiB chunk, followed by its manifest.
     *
     * [append] must not make a block visible by itself. The returned records are the only values
     * that should be merged into ObjectIndex/ChunkIndex by the future transaction writer.
     */
    fun importFrom(
        input: InputStream,
        expectedSize: Long,
        vaultId: UUID,
        objectId: UUID,
        generation: Long,
        kind: PmvAttachmentCodec.Kind,
        attachmentRootKey: ByteArray,
        append: (PmvContainerFormat.EncodedBlock) -> StoredBlock,
    ): ImportResult {
        val objectKey = PmvKeySchedule.deriveAttachmentObjectKey(attachmentRootKey, objectId, generation)
        val storedChunks = ArrayList<Pair<StoredBlock, ByteArray>>()
        var pendingChunkKey: ByteArray? = null
        try {
            val manifest = PmvAttachmentCodec.sealFrom(
                input = input,
                expectedSize = expectedSize,
                vaultId = vaultId,
                objectId = objectId,
                generation = generation,
                kind = kind,
                keyForChunk = { index ->
                    check(pendingChunkKey == null) { "前一个 Chunk key 未清理" }
                    PmvKeySchedule.deriveChunkKey(objectKey, index.toLong()).also { pendingChunkKey = it }
                },
                emit = { block ->
                    try {
                        val location = append(block)
                        require(location.length == storedLength(block)) { "Chunk 持久化长度不匹配" }
                        storedChunks += location to PmvIntegrity.encryptedBlockDigest(block)
                    } finally {
                        pendingChunkKey?.fill(0)
                        pendingChunkKey = null
                    }
                },
            )
            check(storedChunks.size == manifest.chunks.size) { "Chunk 持久化记录数量不匹配" }

            val chunkRecords = manifest.chunks.mapIndexed { index, chunk ->
                val (location, cipherDigest) = storedChunks[index]
                PmvObjectIndexCodec.ChunkRecord(
                    key = PmvObjectIndexCodec.ChunkKey(objectId, generation, index),
                    blockOffset = location.offset,
                    blockLength = location.length,
                    plainDigest = chunk.sha256.copyOf(),
                    cipherDigest = cipherDigest,
                )
            }

            val manifestPlain = PmvAttachmentCodec.encodeManifest(manifest)
            val manifestBlock = PmvAttachmentCodec.sealManifest(vaultId, objectKey, manifest)
            val manifestLocation = append(manifestBlock)
            require(manifestLocation.length == storedLength(manifestBlock)) { "Manifest 持久化长度不匹配" }
            val objectRecord = try {
                PmvObjectIndexCodec.ObjectRecord(
                    key = PmvObjectIndexCodec.ObjectKey(objectId, generation),
                    manifestOffset = manifestLocation.offset,
                    manifestLength = manifestLocation.length,
                    plainDigest = sha256(manifestPlain),
                    cipherDigest = PmvIntegrity.encryptedBlockDigest(manifestBlock),
                )
            } finally {
                manifestPlain.fill(0)
            }
            return ImportResult(manifest, objectRecord, chunkRecords)
        } finally {
            pendingChunkKey?.fill(0)
            objectKey.fill(0)
        }
    }

    /** Authenticated descriptor, without decrypting media chunks. */
    internal fun readManifest(
        objectRecord: PmvObjectIndexCodec.ObjectRecord,
        vaultId: UUID,
        attachmentRootKey: ByteArray,
        readBlock: (Long, Long) -> PmvContainerFormat.EncodedBlock,
    ): PmvAttachmentCodec.Manifest {
        val opened = openManifest(objectRecord, vaultId, attachmentRootKey, readBlock)
        return try { opened.manifest } finally { opened.objectKey.fill(0) }
    }

    fun openTo(
        objectRecord: PmvObjectIndexCodec.ObjectRecord,
        vaultId: UUID,
        attachmentRootKey: ByteArray,
        readBlock: (offset: Long, length: Long) -> PmvContainerFormat.EncodedBlock,
        findChunk: (PmvObjectIndexCodec.ChunkKey) -> PmvObjectIndexCodec.ChunkRecord?,
        output: OutputStream,
    ) {
        val opened = openManifest(objectRecord, vaultId, attachmentRootKey, readBlock)
        try {
            val whole = MessageDigest.getInstance("SHA-256")
            opened.manifest.chunks.forEach { chunk ->
                val plain = openChunk(opened.manifest, chunk.index, vaultId, opened.objectKey, readBlock, findChunk)
                try {
                    whole.update(plain)
                    output.write(plain)
                } finally {
                    plain.fill(0)
                }
            }
            require(MessageDigest.isEqual(whole.digest(), opened.manifest.sha256)) { "附件整体摘要不匹配" }
        } finally {
            opened.objectKey.fill(0)
        }
    }

    /** Reads [length] bytes without touching chunks outside the requested range. */
    fun openRangeTo(
        objectRecord: PmvObjectIndexCodec.ObjectRecord,
        offset: Long,
        length: Long,
        vaultId: UUID,
        attachmentRootKey: ByteArray,
        readBlock: (offset: Long, length: Long) -> PmvContainerFormat.EncodedBlock,
        findChunk: (PmvObjectIndexCodec.ChunkKey) -> PmvObjectIndexCodec.ChunkRecord?,
        output: OutputStream,
    ) {
        require(offset >= 0 && length >= 0) { "读取范围不能为负数" }
        val opened = openManifest(objectRecord, vaultId, attachmentRootKey, readBlock)
        try {
            require(offset <= opened.manifest.totalSize && length <= opened.manifest.totalSize - offset) {
                "读取范围超出附件边界"
            }
            if (length == 0L) return
            val first = (offset / PmvAttachmentCodec.CHUNK_SIZE).toInt()
            val last = ((offset + length - 1) / PmvAttachmentCodec.CHUNK_SIZE).toInt()
            for (index in first..last) {
                val plain = openChunk(opened.manifest, index, vaultId, opened.objectKey, readBlock, findChunk)
                try {
                    val chunkStart = index.toLong() * PmvAttachmentCodec.CHUNK_SIZE
                    val from = maxOf(offset, chunkStart) - chunkStart
                    val until = minOf(offset + length, chunkStart + plain.size) - chunkStart
                    output.write(plain, from.toInt(), (until - from).toInt())
                } finally {
                    plain.fill(0)
                }
            }
        } finally {
            opened.objectKey.fill(0)
        }
    }

    private data class OpenedManifest(
        val manifest: PmvAttachmentCodec.Manifest,
        val objectKey: ByteArray,
    )

    private fun openManifest(
        record: PmvObjectIndexCodec.ObjectRecord,
        vaultId: UUID,
        attachmentRootKey: ByteArray,
        readBlock: (Long, Long) -> PmvContainerFormat.EncodedBlock,
    ): OpenedManifest {
        val block = readBlock(record.manifestOffset, record.manifestLength)
        require(storedLength(block) == record.manifestLength) { "Manifest Block 长度与 ObjectIndex 不匹配" }
        require(MessageDigest.isEqual(PmvIntegrity.encryptedBlockDigest(block), record.cipherDigest)) {
            "Manifest 密文摘要与 ObjectIndex 不匹配"
        }
        val key = PmvKeySchedule.deriveAttachmentObjectKey(
            attachmentRootKey, record.key.objectId, record.key.generation,
        )
        try {
            val manifest = PmvAttachmentCodec.openManifest(vaultId, key, block)
            require(manifest.objectId == record.key.objectId && manifest.generation == record.key.generation) {
                "Manifest 与 ObjectIndex key 不匹配"
            }
            val encoded = PmvAttachmentCodec.encodeManifest(manifest)
            try {
                require(MessageDigest.isEqual(sha256(encoded), record.plainDigest)) {
                    "Manifest 明文摘要与 ObjectIndex 不匹配"
                }
            } finally {
                encoded.fill(0)
            }
            return OpenedManifest(manifest, key)
        } catch (failure: Throwable) {
            key.fill(0)
            throw failure
        }
    }

    private fun openChunk(
        manifest: PmvAttachmentCodec.Manifest,
        index: Int,
        vaultId: UUID,
        objectKey: ByteArray,
        readBlock: (Long, Long) -> PmvContainerFormat.EncodedBlock,
        findChunk: (PmvObjectIndexCodec.ChunkKey) -> PmvObjectIndexCodec.ChunkRecord?,
    ): ByteArray {
        val manifestRecord = manifest.chunks[index]
        try {
            val key = PmvObjectIndexCodec.ChunkKey(manifest.objectId, manifest.generation, index)
            val indexRecord = requireNotNull(findChunk(key)) { "ChunkIndex 缺少分块 $index" }
            require(MessageDigest.isEqual(indexRecord.plainDigest, manifestRecord.sha256)) {
                "ChunkIndex 与 Manifest 摘要不匹配"
            }
            val block = readBlock(indexRecord.blockOffset, indexRecord.blockLength)
            require(storedLength(block) == indexRecord.blockLength) { "Chunk Block 长度与 ChunkIndex 不匹配" }
            require(MessageDigest.isEqual(PmvIntegrity.encryptedBlockDigest(block), indexRecord.cipherDigest)) {
                "Chunk 密文摘要与 ChunkIndex 不匹配"
            }
            require(
                block.header.blockType == manifest.kind.blockType &&
                    block.header.objectId == manifest.objectId &&
                    block.header.objectRevision == manifest.generation &&
                    block.header.chunkIndex == index &&
                    block.header.plainSize == manifestRecord.plainSize.toLong(),
            ) { "Chunk Header 与 Manifest 不一致" }
            val chunkKey = PmvKeySchedule.deriveChunkKey(objectKey, index.toLong())
            val plain = try {
                PmvBlockCrypto.open(vaultId, chunkKey, block)
            } finally {
                chunkKey.fill(0)
            }
            if (!MessageDigest.isEqual(sha256(plain), manifestRecord.sha256)) {
                plain.fill(0)
                throw IllegalArgumentException("Chunk 摘要不匹配")
            }
            return plain
        } catch (failure: Exception) {
            if (failure is PmvAttachmentCodec.ChunkFailure) throw failure
            throw PmvAttachmentCodec.ChunkFailure(index, failure)
        }
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + block.ciphertext.size

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
}
