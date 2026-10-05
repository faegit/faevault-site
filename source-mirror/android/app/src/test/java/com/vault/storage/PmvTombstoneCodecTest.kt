package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class PmvTombstoneCodecTest {
    @Test
    fun `fixed wire round trips and rejects noncanonical bytes`() {
        val value = PmvTombstoneCodec.Tombstone(
            UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f"),
            7,
            1234,
            ByteArray(32) { it.toByte() },
        )
        val raw = PmvTombstoneCodec.encode(value)
        assertEquals(PmvTombstoneCodec.SIZE, raw.size)
        assertTrue(raw.copyOfRange(0, 4).contentEquals("PMVT".encodeToByteArray()))
        assertEquals(value, PmvTombstoneCodec.decode(raw))
        raw[raw.lastIndex] = 1
        assertThrows(IllegalArgumentException::class.java) { PmvTombstoneCodec.decode(raw) }
    }
}
