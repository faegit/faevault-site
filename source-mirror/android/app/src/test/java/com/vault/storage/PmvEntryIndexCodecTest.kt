package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

class PmvEntryIndexCodecTest {

    @Test
    fun `fixed index page roundtrips and supports binary lookup`() {
        val firstId = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val secondId = UUID.fromString("00000000-0000-0000-0000-000000000002")
        val page = PmvEntryIndexCodec.Page(
            records = listOf(
                record(firstId, "login", 1, PmvContainerFormat.DATA_START).copy(
                    displayTitle = "账户",
                    favorite = true,
                    iconObjectId = UUID.fromString("10000000-0000-0000-0000-000000000001"),
                    modifiedAtEpochMillis = 1_700_000_000_000,
                ),
                record(secondId, "secure_note", 4, PmvContainerFormat.DATA_START + 8_192).copy(displayTitle = "私密笔记"),
            ),
            nextPageOffset = 65_536,
        )

        val encoded = PmvEntryIndexCodec.encode(page)
        val decoded = PmvEntryIndexCodec.decode(encoded)

        assertEquals(PmvEntryIndexCodec.PAGE_SIZE, encoded.size)
        assertEquals(page, decoded)
        assertEquals(secondId, decoded.find(secondId)?.entryId)
        assertNull(decoded.find(UUID.fromString("00000000-0000-0000-0000-000000000003")))
    }

    @Test
    fun `index page rejects unsorted duplicate and invalid record ranges`() {
        val firstId = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val secondId = UUID.fromString("00000000-0000-0000-0000-000000000002")

        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexCodec.Page(
                records = listOf(record(secondId, "login", 1, PmvContainerFormat.DATA_START), record(firstId, "login", 1, PmvContainerFormat.DATA_START + 8_192)),
                nextPageOffset = 0,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexCodec.Page(
                records = listOf(record(firstId, "login", 1, PmvContainerFormat.DATA_START), record(firstId, "login", 2, PmvContainerFormat.DATA_START + 8_192)),
                nextPageOffset = 0,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            record(firstId, "login", 1, 4_096)
        }
    }

    @Test
    fun `index page rejects overflow malformed links and nonzero reserved bytes`() {
        val records = (1..400).map { index ->
            record(UUID(0, index.toLong()), "type-${"x".repeat(48)}", 1, PmvContainerFormat.DATA_START + index * 256L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexCodec.encode(PmvEntryIndexCodec.Page(records, 0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexCodec.Page(emptyList(), 4_096)
        }

        val valid = PmvEntryIndexCodec.encode(
            PmvEntryIndexCodec.Page(
                listOf(record(UUID(0, 1), "login", 1, PmvContainerFormat.DATA_START)),
                0,
            ),
        )
        valid[valid.lastIndex] = 1
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryIndexCodec.decode(valid)
        }
    }

    private fun record(
        id: UUID,
        type: String,
        revision: Long,
        offset: Long,
    ) = PmvEntryIndexCodec.Record(
        entryId = id,
        entryType = type,
        revision = revision,
        offset = offset,
        length = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + 256,
        state = PmvEntryIndexCodec.State.ACTIVE,
    )
}
