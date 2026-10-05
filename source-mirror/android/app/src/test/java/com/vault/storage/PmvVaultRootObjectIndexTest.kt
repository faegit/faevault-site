package com.vault.storage

import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class PmvVaultRootObjectIndexTest {
    private val id1 = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val id2 = UUID.fromString("10112233-4455-6677-8899-aabbccddeeff")
    private val d1 = ByteArray(32) { it.toByte() }
    private val d2 = ByteArray(32) { (255 - it).toByte() }

    @Test fun `cross-end fixed vault root fixture is canonical and offset independent`() {
        val a = root(PmvContainerFormat.DATA_START, 20_000)
        val b = root(80_000, 120_000)
        val encoded = PmvVaultRootCodec.encode(a)
        assertEquals(16 * 1024, encoded.size)
        assertArrayEquals("PMVR".encodeToByteArray(), encoded.copyOfRange(0, 4))
        assertEquals(1, encoded[32].toInt())
        assertEquals(1, encoded[33].toInt())
        assertEquals(0, encoded[96].toInt()) // optional login root: canonical absent
        assertEquals(a, PmvVaultRootCodec.decode(encoded))
        assertArrayEquals(PmvVaultRootCodec.logicalDigest(a), PmvVaultRootCodec.logicalDigest(b))
        assertEquals(PmvCommitCodec.ROOT_DIGEST_SIZE, PmvVaultRootCodec.logicalDigest(a).size)
    }

    @Test fun `vault root rejects reserved and noncanonical absent fields`() {
        val reserved = PmvVaultRootCodec.encode(root(PmvContainerFormat.DATA_START, 20_000)).also { it[it.lastIndex] = 1 }
        assertFails { PmvVaultRootCodec.decode(reserved) }
        val absentOffset = PmvVaultRootCodec.encode(root(PmvContainerFormat.DATA_START, 20_000)).also { it[111] = 1 }
        assertFails { PmvVaultRootCodec.decode(absentOffset) }
    }

    @Test fun `object and chunk fixed fixtures round trip and bind physical ciphertext`() {
        val objects = PmvObjectIndexCodec.ObjectPage(listOf(
            PmvObjectIndexCodec.ObjectRecord(PmvObjectIndexCodec.ObjectKey(id1, 7), PmvContainerFormat.DATA_START, 512, d1, d2),
            PmvObjectIndexCodec.ObjectRecord(PmvObjectIndexCodec.ObjectKey(id2, 8), 20_000, 640, d2, d1),
        ))
        val chunks = PmvObjectIndexCodec.ChunkPage(listOf(
            PmvObjectIndexCodec.ChunkRecord(PmvObjectIndexCodec.ChunkKey(id1, 7, 0), 24_576, 1_024, d1, d2),
            PmvObjectIndexCodec.ChunkRecord(PmvObjectIndexCodec.ChunkKey(id1, 7, 1), 25_600, 1_024, d2, d1),
        ))
        val objectRaw = PmvObjectIndexCodec.encodeObjectPage(objects)
        val chunkRaw = PmvObjectIndexCodec.encodeChunkPage(chunks)
        assertArrayEquals("PMOI".encodeToByteArray(), objectRaw.copyOfRange(0, 4))
        assertArrayEquals("PMCI".encodeToByteArray(), chunkRaw.copyOfRange(0, 4))
        assertEquals(objects, PmvObjectIndexCodec.decodeObjectPage(objectRaw))
        assertEquals(chunks, PmvObjectIndexCodec.decodeChunkPage(chunkRaw))
        assertEquals(objects.records[1], objects.find(PmvObjectIndexCodec.ObjectKey(id2, 8)))
        assertEquals(chunks.records[1], chunks.find(PmvObjectIndexCodec.ChunkKey(id1, 7, 1)))
        val physicallyMoved = PmvObjectIndexCodec.ObjectPage(listOf(
            objects.records[0].copy(manifestOffset = 30_000), objects.records[1].copy(manifestOffset = 31_000)))
        assertArrayEquals(PmvObjectIndexCodec.objectPageDigest(objects), PmvObjectIndexCodec.objectPageDigest(physicallyMoved))
        assertFalse(PmvObjectIndexCodec.objectPageDigest(objects).contentEquals(
            PmvObjectIndexCodec.objectPageDigest(PmvObjectIndexCodec.ObjectPage(listOf(
                objects.records[0].copy(cipherDigest = d1), objects.records[1])))))
        assertFails { PmvObjectIndexCodec.decodeObjectPage(objectRaw.copyOf().also { it[143] = 1 }) }
    }

    @Test fun `range roots binary locate reject overlap and ignore offsets in logical digest`() {
        val left = PmvObjectIndexCodec.RangeRecord(PmvObjectIndexCodec.ObjectKey(id1, 1), PmvObjectIndexCodec.ObjectKey(id1, 9), PmvContainerFormat.DATA_START, d1)
        val right = PmvObjectIndexCodec.RangeRecord(PmvObjectIndexCodec.ObjectKey(id2, 1), PmvObjectIndexCodec.ObjectKey(id2, 9), 20_000, d2)
        val root = PmvObjectIndexCodec.RangeRoot(listOf(left, right))
        assertEquals(right, root.findPage(PmvObjectIndexCodec.ObjectKey(id2, 4)))
        val moved = PmvObjectIndexCodec.RangeRoot(listOf(left.copy(pageOffset = 40_000), right.copy(pageOffset = 60_000)))
        assertArrayEquals(PmvObjectIndexCodec.objectRootDigest(root), PmvObjectIndexCodec.objectRootDigest(moved))
        assertEquals(root, PmvObjectIndexCodec.decodeObjectRoot(PmvObjectIndexCodec.encodeObjectRoot(root)))
        assertFails { PmvObjectIndexCodec.RangeRoot(listOf(left, left.copy(pageOffset = 30_000))) }

        val chunkLeft = PmvObjectIndexCodec.RangeRecord(PmvObjectIndexCodec.ChunkKey(id1, 3, 0), PmvObjectIndexCodec.ChunkKey(id1, 3, 9), PmvContainerFormat.DATA_START, d1)
        val chunkRight = PmvObjectIndexCodec.RangeRecord(PmvObjectIndexCodec.ChunkKey(id2, 4, 0), PmvObjectIndexCodec.ChunkKey(id2, 4, 9), 30_000, d2)
        val chunkRoot = PmvObjectIndexCodec.RangeRoot(listOf(chunkLeft, chunkRight))
        assertEquals(chunkRight, chunkRoot.findPage(PmvObjectIndexCodec.ChunkKey(id2, 4, 5)))
        assertEquals(chunkRoot, PmvObjectIndexCodec.decodeChunkRoot(PmvObjectIndexCodec.encodeChunkRoot(chunkRoot)))
    }

    @Test fun `sorted duplicate keys fail and unchanged COW page is reused`() {
        val record = PmvObjectIndexCodec.ObjectRecord(PmvObjectIndexCodec.ObjectKey(id1, 1), PmvContainerFormat.DATA_START, 200, d1, d2)
        assertFails { PmvObjectIndexCodec.ObjectPage(listOf(record, record)) }
        val page = PmvObjectIndexCodec.ObjectPage(listOf(record))
        val digest = PmvObjectIndexCodec.objectPageDigest(page)
        val plan = PmvObjectIndexCodec.planObjectPages(listOf(record), listOf(
            PmvObjectIndexCodec.ExistingPage(record.key, record.key, 44_000, digest)))
        assertEquals(44_000L, plan.single().reusedOffset)
    }

    private fun root(entryOffset: Long, objectOffset: Long) = PmvVaultRootCodec.Root(
        entry = PmvVaultRootCodec.Reference(PmvVaultRootCodec.RootType.ENTRY, entryOffset, 1_000, d1),
        objectIndex = PmvVaultRootCodec.Reference(PmvVaultRootCodec.RootType.OBJECT, objectOffset, 2_000, d2),
    )
    private fun assertFails(block: () -> Unit) { try { block(); fail("expected IllegalArgumentException") } catch (_: IllegalArgumentException) {} }
}
