package com.vault.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PmvObjectStoreTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val objectId = UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")
    private val rootKey = ByteArray(32) { it.toByte() }

    private class Storage {
        var next = PmvContainerFormat.DATA_START.toLong()
        val blocks = linkedMapOf<Long, PmvContainerFormat.EncodedBlock>()
        fun append(block: PmvContainerFormat.EncodedBlock): PmvObjectStore.StoredBlock {
            val offset = next
            val length = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + block.ciphertext.size
            blocks[offset] = block
            next += length
            return PmvObjectStore.StoredBlock(offset, length)
        }
        fun read(offset: Long, length: Long): PmvContainerFormat.EncodedBlock =
            requireNotNull(blocks[offset]).also {
                require(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + it.ciphertext.size == length)
            }
    }

    @Test fun multiChunkZeroAndBoundaryObjectsRoundTrip() {
        listOf(0, PmvAttachmentCodec.CHUNK_SIZE, PmvAttachmentCodec.CHUNK_SIZE + 19).forEach { size ->
            val plain = ByteArray(size) { (it * 31).toByte() }
            val storage = Storage()
            val result = PmvObjectStore.importFrom(ByteArrayInputStream(plain), size.toLong(), vaultId,
                objectId, size.toLong(), PmvAttachmentCodec.Kind.ATTACHMENT, rootKey, storage::append)
            val chunks = result.chunkRecords.associateBy { it.key }
            val output = ByteArrayOutputStream()
            PmvObjectStore.openTo(result.objectRecord, vaultId, rootKey, storage::read, chunks::get, output)
            assertArrayEquals(plain, output.toByteArray())
            assertEquals(if (size == 0) 0 else (size - 1) / PmvAttachmentCodec.CHUNK_SIZE + 1,
                result.chunkRecords.size)
        }
    }

    @Test fun rangeReadsOnlyNecessaryChunks() {
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE * 2 + 31) { it.toByte() }
        val storage = Storage()
        val result = PmvObjectStore.importFrom(ByteArrayInputStream(plain), plain.size.toLong(), vaultId,
            objectId, 4, PmvAttachmentCodec.Kind.IMAGE, rootKey, storage::append)
        val chunks = result.chunkRecords.associateBy { it.key }
        val requested = mutableListOf<PmvObjectIndexCodec.ChunkKey>()
        val output = ByteArrayOutputStream()
        val start = PmvAttachmentCodec.CHUNK_SIZE.toLong() - 3
        PmvObjectStore.openRangeTo(result.objectRecord, start, 9, vaultId, rootKey, storage::read,
            { key -> requested += key; chunks[key] }, output)
        assertArrayEquals(plain.copyOfRange(start.toInt(), start.toInt() + 9), output.toByteArray())
        assertEquals(listOf(0, 1), requested.map { it.chunkIndex })
    }

    @Test fun rejectsSwappedWrongLocationTagAndDigest() {
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 1)
        val storage = Storage()
        val result = PmvObjectStore.importFrom(ByteArrayInputStream(plain), plain.size.toLong(), vaultId,
            objectId, 8, PmvAttachmentCodec.Kind.ATTACHMENT, rootKey, storage::append)
        val chunks = result.chunkRecords.associateBy { it.key }

        assertThrows(PmvAttachmentCodec.ChunkFailure::class.java) {
            PmvObjectStore.openTo(result.objectRecord, vaultId, rootKey,
                { offset, length ->
                    if (offset == result.chunkRecords[0].blockOffset) storage.read(result.chunkRecords[1].blockOffset,
                        result.chunkRecords[1].blockLength) else storage.read(offset, length)
                }, chunks::get, ByteArrayOutputStream())
        }

        val badLocation = result.chunkRecords[0].copy(blockLength = result.chunkRecords[0].blockLength + 1)
        assertThrows(PmvAttachmentCodec.ChunkFailure::class.java) {
            PmvObjectStore.openTo(result.objectRecord, vaultId, rootKey, storage::read,
                { if (it == badLocation.key) badLocation else chunks[it] }, ByteArrayOutputStream())
        }

        val block = storage.blocks.getValue(result.chunkRecords[0].blockOffset)
        block.ciphertext[0] = (block.ciphertext[0].toInt() xor 1).toByte()
        assertThrows(PmvAttachmentCodec.ChunkFailure::class.java) {
            PmvObjectStore.openTo(result.objectRecord, vaultId, rootKey, storage::read, chunks::get,
                ByteArrayOutputStream())
        }

        val badTagRecord = result.chunkRecords[0].copy(cipherDigest = PmvIntegrity.encryptedBlockDigest(block))
        assertThrows(PmvAttachmentCodec.ChunkFailure::class.java) {
            PmvObjectStore.openTo(result.objectRecord, vaultId, rootKey, storage::read,
                { if (it == badTagRecord.key) badTagRecord else chunks[it] }, ByteArrayOutputStream())
        }

        val badManifest = result.objectRecord.copy(plainDigest = ByteArray(32) { 1 })
        assertThrows(IllegalArgumentException::class.java) {
            PmvObjectStore.openTo(badManifest, vaultId, rootKey, storage::read, chunks::get,
                ByteArrayOutputStream())
        }
    }

    @Test fun failedOrCancelledImportPublishesNoIndexRecordsAndBuffersAtMostOneChunk() {
        var maxRequest = 0
        val tenGiB = 10L * 1024 * 1024 * 1024
        val stream = object : InputStream() {
            override fun read(): Int = 0
            override fun read(target: ByteArray, offset: Int, length: Int): Int {
                maxRequest = maxOf(maxRequest, length)
                java.util.Arrays.fill(target, offset, offset + length, 0.toByte())
                return length
            }
        }
        val storage = Storage()
        var appendCount = 0
        var published: PmvObjectStore.ImportResult? = null
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            published = PmvObjectStore.importFrom(stream, tenGiB, vaultId, objectId, 9,
                PmvAttachmentCodec.Kind.ATTACHMENT, rootKey) { block ->
                storage.append(block).also {
                    appendCount++
                    if (appendCount == 2) throw java.util.concurrent.CancellationException()
                }
            }
        }
        assertEquals(null, published)
        assertTrue(storage.blocks.isNotEmpty())
        assertTrue(maxRequest <= PmvAttachmentCodec.CHUNK_SIZE)
    }
}
