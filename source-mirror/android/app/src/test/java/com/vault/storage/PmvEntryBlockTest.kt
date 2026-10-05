package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.GeneralSecurityException
import java.util.UUID

class PmvEntryBlockTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val entryId = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    private val entryKey = ByteArray(32) { (it * 19).toByte() }

    @Test
    fun `entry payload roundtrips without losing extensible fields`() {
        val entry = sampleEntry()

        val encoded = PmvEntryCodec.encode(entry)
        val decoded = PmvEntryCodec.decode(encoded, entryId)

        assertEquals(entry, decoded)
        assertEquals(
            JsonObject(mapOf("nested" to JsonPrimitive("preserved"))),
            decoded.fields["future_extension"],
        )
    }

    @Test
    fun `entry payload is canonical across map order and double formatting`() {
        val first = sampleEntry().copy(
            fields = linkedMapOf(
                "é" to JsonPrimitive(1.2300),
                "z" to JsonObject(linkedMapOf("β" to JsonPrimitive(-0.0), "a" to JsonPrimitive(true))),
            ),
        )
        val second = first.copy(
            fields = linkedMapOf(
                "z" to JsonObject(linkedMapOf("a" to JsonPrimitive(true), "β" to JsonPrimitive(0))),
                "é" to JsonPrimitive(1.23),
            ),
        )

        val encoded = PmvEntryCodec.encode(first)
        assertArrayEquals(encoded, PmvEntryCodec.encode(second))
        val text = encoded.decodeToString()
        assertEquals(false, text.contains("E"))
        assertEquals(false, text.contains("1700000000.0"))
        assertEquals(true, text.contains("\"z\":{\"a\":true,\"β\":0},\"é\":1.23"))
    }

    @Test
    fun `entry block authenticates payload and all bound metadata`() {
        val payload = PmvEntryCodec.encode(sampleEntry())
        val sealed = PmvBlockCrypto.seal(
            vaultId = vaultId,
            key = entryKey,
            blockType = PmvContainerFormat.BlockType.ENTRY,
            objectId = entryId,
            objectRevision = 7,
            plaintext = payload,
        )

        val opened = PmvBlockCrypto.open(vaultId, entryKey, sealed)
        assertEquals(sampleEntry(), PmvEntryCodec.decode(opened, entryId))

        val tamperedCiphertext = sealed.copy(ciphertext = sealed.ciphertext.copyOf().also { it[0] = (it[0] + 1).toByte() })
        assertThrows(GeneralSecurityException::class.java) {
            PmvBlockCrypto.open(vaultId, entryKey, tamperedCiphertext)
        }
        val tamperedRevision = sealed.copy(header = sealed.header.copy(objectRevision = 8))
        assertThrows(GeneralSecurityException::class.java) {
            PmvBlockCrypto.open(vaultId, entryKey, tamperedRevision)
        }
    }

    @Test
    fun `entry block rejects a different vault key and entry identity`() {
        val sealed = PmvBlockCrypto.seal(
            vaultId = vaultId,
            key = entryKey,
            blockType = PmvContainerFormat.BlockType.ENTRY,
            objectId = entryId,
            objectRevision = 7,
            plaintext = PmvEntryCodec.encode(sampleEntry()),
        )

        assertThrows(GeneralSecurityException::class.java) {
            PmvBlockCrypto.open(UUID.randomUUID(), entryKey, sealed)
        }
        assertThrows(GeneralSecurityException::class.java) {
            PmvBlockCrypto.open(vaultId, ByteArray(32) { 0x55 }, sealed)
        }
        val plaintext = PmvBlockCrypto.open(vaultId, entryKey, sealed)
        assertThrows(IllegalArgumentException::class.java) {
            PmvEntryCodec.decode(plaintext, UUID.randomUUID())
        }
    }

    private fun sampleEntry(): Entry = Entry(
        id = entryId.toString(),
        title = "示例账户",
        username = "alice@example.com",
        password = "correct horse battery staple",
        url = "https://example.com",
        secretType = "login",
        createdAt = 1_700_000_000.0,
        updatedAt = 1_700_000_100.0,
        fields = mapOf(
            "future_extension" to JsonObject(mapOf("nested" to JsonPrimitive("preserved"))),
        ),
    )
}
