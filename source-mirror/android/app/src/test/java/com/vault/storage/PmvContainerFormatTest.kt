package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

class PmvContainerFormatTest {

    private val authKey = ByteArray(32) { (it * 7).toByte() }
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")

    @Test
    fun `authenticated superblock roundtrips in a fixed slot`() {
        assertEquals(8_192L, PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
        assertEquals(12_288L, PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET)
        assertEquals(16_384L, PmvContainerFormat.DATA_START)
        val original = PmvContainerFormat.Superblock(
            vaultId = vaultId,
            sequence = 42,
            latestCommitOffset = 16_384,
            latestIndexOffset = 18_432,
            committedFileEnd = 20_480,
            kdfParametersOffset = PmvContainerFormat.DATA_START,
            featureFlags = 5,
        )

        val encoded = PmvContainerFormat.encodeSuperblock(original, authKey)
        val decoded = PmvContainerFormat.decodeSuperblock(encoded, authKey)

        assertEquals(PmvContainerFormat.SUPERBLOCK_SIZE, encoded.size)
        assertEquals(original, decoded)
    }

    @Test
    fun `newest invalid superblock falls back to previous authenticated slot`() {
        val older = PmvContainerFormat.Superblock(vaultId, 7, 16_384, 16_384, 16_384, 16_384, 0)
        val newer = PmvContainerFormat.Superblock(vaultId, 8, 20_480, 16_384, 24_576, 16_384, 0)
        val olderBytes = PmvContainerFormat.encodeSuperblock(older, authKey)
        val tamperedNewer = PmvContainerFormat.encodeSuperblock(newer, authKey).also { it[80] = (it[80] + 1).toByte() }

        assertEquals(older, PmvContainerFormat.selectLatestSuperblock(olderBytes, tamperedNewer, authKey))
        assertNull(PmvContainerFormat.selectLatestSuperblock(tamperedNewer, tamperedNewer, authKey))
    }

    @Test
    fun `block header roundtrips and every security field changes AAD`() {
        val original = PmvContainerFormat.BlockHeader(
            blockId = UUID.fromString("11111111-2222-3333-4444-555555555555"),
            blockType = PmvContainerFormat.BlockType.ATTACHMENT_CHUNK,
            objectId = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            objectRevision = 9,
            chunkIndex = 3,
            flags = 2,
            cryptoSuiteId = 1,
            codecId = 0,
            plainSize = 8L * 1024 * 1024,
            cipherSize = 8L * 1024 * 1024 + 16,
            nonce = ByteArray(12) { it.toByte() },
        )

        val encoded = PmvContainerFormat.encodeBlockHeader(original)
        val decoded = PmvContainerFormat.decodeBlockHeader(encoded)
        val aad = PmvContainerFormat.blockAad(vaultId, original)

        assertEquals(original, decoded)
        assertArrayEquals(aad, PmvContainerFormat.blockAad(vaultId, decoded))
        assertNotEquals(aad.toList(), PmvContainerFormat.blockAad(vaultId, original.copy(chunkIndex = 4)).toList())
        assertNotEquals(aad.toList(), PmvContainerFormat.blockAad(vaultId, original.copy(objectRevision = 10)).toList())
        assertNotEquals(aad.toList(), PmvContainerFormat.blockAad(vaultId, original.copy(codecId = 1)).toList())
    }

    @Test
    fun `block header rejects invalid nonce and length relationships`() {
        assertThrows(IllegalArgumentException::class.java) {
            PmvContainerFormat.BlockHeader(
                blockId = UUID.randomUUID(),
                blockType = PmvContainerFormat.BlockType.ENTRY,
                objectId = UUID.randomUUID(),
                objectRevision = 1,
                chunkIndex = -1,
                flags = 0,
                cryptoSuiteId = 1,
                codecId = 0,
                plainSize = 10,
                cipherSize = 25,
                nonce = ByteArray(11),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvContainerFormat.BlockHeader(
                blockId = UUID.randomUUID(),
                blockType = PmvContainerFormat.BlockType.ENTRY,
                objectId = UUID.randomUUID(),
                objectRevision = 1,
                chunkIndex = -1,
                flags = 0,
                cryptoSuiteId = 1,
                codecId = 0,
                plainSize = 10,
                cipherSize = 15,
                nonce = ByteArray(12),
            )
        }
    }
}
