package com.vault.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PmvAttachmentCodecTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val objectId = UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")
    private fun key(index: Int) = ByteArray(32) { (it + index).toByte() }

    @Test fun multiChunkRoundTripIsStreamingAndCanonical() {
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 17) { it.toByte() }
        val blocks = mutableListOf<PmvContainerFormat.EncodedBlock>()
        val manifest = PmvAttachmentCodec.sealFrom(
            ByteArrayInputStream(plain), plain.size.toLong(), vaultId, objectId, 7,
            PmvAttachmentCodec.Kind.ATTACHMENT, ::key, blocks::add,
        )
        assertEquals(2, blocks.size)
        assertArrayEquals(PmvAttachmentCodec.encodeManifest(manifest), PmvAttachmentCodec.encodeManifest(
            PmvAttachmentCodec.decodeManifest(PmvAttachmentCodec.encodeManifest(manifest))))
        val output = ByteArrayOutputStream()
        PmvAttachmentCodec.openTo(manifest, vaultId, ::key, blocks::get, output)
        assertArrayEquals(plain, output.toByteArray())
    }

    @Test fun tamperReportsExactChunkWithoutFetchingLaterChunk() {
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 2)
        val blocks = mutableListOf<PmvContainerFormat.EncodedBlock>()
        val manifest = PmvAttachmentCodec.sealFrom(ByteArrayInputStream(plain), plain.size.toLong(), vaultId,
            objectId, 1, PmvAttachmentCodec.Kind.IMAGE, ::key, blocks::add)
        blocks[1].ciphertext[0] = (blocks[1].ciphertext[0].toInt() xor 1).toByte()
        var highestRequested = -1
        val failure = assertThrows(PmvAttachmentCodec.ChunkFailure::class.java) {
            PmvAttachmentCodec.openTo(manifest, vaultId, ::key, { blocks[it].also { _ -> highestRequested = it } }, ByteArrayOutputStream())
        }
        assertEquals(1, failure.chunkIndex)
        assertEquals(1, highestRequested)
    }

    @Test fun rejectsOutOfOrderAndOversizedMetadata() {
        val digest = ByteArray(32)
        assertThrows(IllegalArgumentException::class.java) {
            PmvAttachmentCodec.Manifest(objectId, 0, PmvAttachmentCodec.Kind.IMAGE, 1, digest,
                listOf(PmvAttachmentCodec.Chunk(1, 1, digest)))
        }
        val valid = PmvAttachmentCodec.Manifest(objectId, 0, PmvAttachmentCodec.Kind.IMAGE, 1, digest,
            listOf(PmvAttachmentCodec.Chunk(0, 1, digest)))
        val encoded = PmvAttachmentCodec.encodeManifest(valid)
        encoded[88] = 1
        assertThrows(IllegalArgumentException::class.java) { PmvAttachmentCodec.decodeManifest(encoded) }
    }

    @Test fun tenGiBManifestDoesNotAllocateAttachmentContents() {
        val total = 10L * 1024 * 1024 * 1024
        val count = ((total - 1) / PmvAttachmentCodec.CHUNK_SIZE + 1).toInt()
        val chunks = List(count) { index ->
            val size = if (index == count - 1) (total - index.toLong() * PmvAttachmentCodec.CHUNK_SIZE).toInt()
            else PmvAttachmentCodec.CHUNK_SIZE
            PmvAttachmentCodec.Chunk(index, size, ByteArray(32))
        }
        val encoded = PmvAttachmentCodec.encodeManifest(
            PmvAttachmentCodec.Manifest(objectId, 2, PmvAttachmentCodec.Kind.ATTACHMENT, total, ByteArray(32), chunks),
        )
        assertEquals(96 + count * 48, encoded.size)
    }

    @Test fun canonicalBytesMatchDesktopFixture() {
        val manifest = PmvAttachmentCodec.Manifest(
            objectId, 7, PmvAttachmentCodec.Kind.ATTACHMENT, 1, ByteArray(32) { it.toByte() },
            listOf(PmvAttachmentCodec.Chunk(0, 1, ByteArray(32) { (31 - it).toByte() })),
        )
        val actual = PmvAttachmentCodec.encodeManifest(manifest).joinToString("") { "%02x".format(it) }
        assertEquals(
            "504d4f4100000001102132435465768798a9bacbdcedfe0f0000000000000007" +
                "020000000000000000000000000000010080000000000001" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "0000000000000000" +
                "00000000000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100" +
                "0000000000000000",
            actual,
        )
    }
}
