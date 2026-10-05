package com.vault.storage

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class PmvVaultMetadataCodecTest {
    @Test
    fun canonicalRoundTripPreservesUnknownTopLevelFields() {
        val metadata = metadata()
        val encoded = PmvVaultMetadataCodec.encode(metadata)
        val decoded = PmvVaultMetadataCodec.decode(encoded, VAULT_ID)

        assertEquals(PmvContainerFormat.BlockType.OBJECT_METADATA, PmvVaultMetadataCodec.BLOCK_TYPE)
        assertArrayEquals(encoded, PmvVaultMetadataCodec.encode(decoded))
        assertEquals(metadata["future_extension"], decoded["future_extension"])
        assertTrue(encoded.decodeToString().contains("\"future_extension\""))
        assertTrue(encoded.decodeToString().contains("保险库"))
        assertArrayEquals(
            PmvVaultMetadataCodec.logicalDigest(metadata),
            PmvVaultMetadataCodec.logicalDigest(decoded),
        )
    }

    @Test
    fun rejectsNonCanonicalIdsOverlapInvalidUtf8AndSecretContent() {
        assertIllegalArgument {
            PmvVaultMetadataCodec.encode(metadata("\"vault_id\":\"00112233-4455-6677-8899-AABBCCDDEEFF\","))
        }
        assertIllegalArgument {
            PmvVaultMetadataCodec.encode(metadata("\"trash_order\":[\"10213243-5465-7687-98a9-bacbdcedfe0f\"],"))
        }
        assertIllegalArgument {
            PmvVaultMetadataCodec.encode(metadata("\"future_extension\":{\"password\":\"must-not-live-here\"},"))
        }
        assertIllegalArgument { PmvVaultMetadataCodec.decode(byteArrayOf(0xff.toByte())) }
        assertIllegalArgument {
            PmvVaultMetadataCodec.decode(PmvVaultMetadataCodec.encode(metadata()), UUID.randomUUID())
        }
    }

    private fun metadata(replacement: String? = null): JsonObject {
        val base = """{
            "schema":"pmv-vault-metadata",
            "version":1,
            "vault_id":"00112233-4455-6677-8899-aabbccddeeff",
            "entry_order":["10213243-5465-7687-98a9-bacbdcedfe0f"],
            "trash_order":["fedcba98-7654-4321-aaaa-bbbbbbbbbbbb"],
            "sync_meta":{"device_id":"11111111-2222-3333-4444-555555555555","future_counter":2},
            "key_revision":7,
            "export_epoch":1700000200.0,
            "purge_tombstones":{"fedcba98-7654-4321-aaaa-bbbbbbbbbbbb":1700000100.25},
            "future_extension":{"enabled":true,"label":"保险库"}
        }"""
        val transformed = when {
            replacement == null -> base
            replacement.startsWith("\"vault_id\"") -> base.replace(
                "\"vault_id\":\"00112233-4455-6677-8899-aabbccddeeff\",",
                replacement,
            )
            replacement.startsWith("\"trash_order\"") -> base.replace(
                "\"trash_order\":[\"fedcba98-7654-4321-aaaa-bbbbbbbbbbbb\"],",
                replacement,
            )
            else -> base.replace(
                "\"future_extension\":{\"enabled\":true,\"label\":\"保险库\"}",
                replacement.removeSuffix(","),
            )
        }
        return Json.parseToJsonElement(transformed).jsonObject
    }

    private fun assertIllegalArgument(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }

    private companion object {
        val VAULT_ID: UUID = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    }
}
