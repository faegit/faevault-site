package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

class PmvEntryIndexRootCodecTest {
    private val id1 = UUID.fromString("00000000-0000-0000-0000-000000000001")
    private val id2 = UUID.fromString("00000000-0000-0000-0000-000000000002")
    private val id3 = UUID.fromString("00000000-0000-0000-0000-000000000003")
    private val id4 = UUID.fromString("00000000-0000-0000-0000-000000000004")

    @Test
    fun `root page roundtrips and locates a leaf by key range`() {
        val root = PmvEntryIndexRootCodec.Root(
            listOf(
                PmvEntryIndexRootCodec.Record(id1, id2, 16_384),
                PmvEntryIndexRootCodec.Record(id3, id4, 32_768),
            ),
        )

        val decoded = PmvEntryIndexRootCodec.decode(PmvEntryIndexRootCodec.encode(root))

        assertEquals(root, decoded)
        assertEquals(32_768L, decoded.findPage(id4)?.pageOffset)
        assertNull(decoded.findPage(UUID.fromString("00000000-0000-0000-0000-000000000005")))
    }

    @Test
    fun `root rejects overlapping reversed and duplicate page ranges`() {
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexRootCodec.Record(id2, id1, 16_384)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexRootCodec.Root(
                listOf(
                    PmvEntryIndexRootCodec.Record(id1, id3, 16_384),
                    PmvEntryIndexRootCodec.Record(id3, id4, 32_768),
                ),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexRootCodec.Root(
                listOf(
                    PmvEntryIndexRootCodec.Record(id1, id2, 16_384),
                    PmvEntryIndexRootCodec.Record(id3, id4, 16_384),
                ),
            )
        }
    }

    @Test
    fun `root rejects nonzero reserved bytes`() {
        val raw = PmvEntryIndexRootCodec.encode(
            PmvEntryIndexRootCodec.Root(
                listOf(PmvEntryIndexRootCodec.Record(id1, id2, 16_384)),
            ),
        )
        raw[raw.lastIndex] = 1

        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexRootCodec.decode(raw)
        }
    }
}
