package com.vault

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PasskeyFixtureTest {
    private val root by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText()).jsonObject
    }

    @Test
    fun fixtureDeclaresVersionThreeAndPreservesLegacyMigrationCases() {
        assertEquals(3, root.getValue("schemaVersion").jsonPrimitive.content.toInt())
        assertTrue(root.getValue("records").jsonArray.isNotEmpty())
        assertTrue(root.getValue("invalid").jsonArray.size >= 2)

        val record = root.getValue("records").jsonArray.first().jsonObject.getValue("record").jsonObject
        val requiredFields = setOf(
            "schema_version", "rp_id", "rp_name", "user_id", "user_name", "user_display_name",
            "credential_id", "key_mode", "private_key", "public_key", "algorithm", "transports", "aaguid",
            "discoverable", "backup_eligible", "backup_state", "counter_mode", "sign_count",
            "created_at", "last_used_at", "future_record_field",
        )
        assertTrue(record.keys.containsAll(requiredFields))
        assertTrue(record.getValue("future_record_field").jsonObject.isNotEmpty())
        assertFalse("private_key_envelope" in record)
        assertFalse(record.getValue("public_key").jsonPrimitive.content.contains("="))

        val legacy = root.getValue("legacyV2").jsonObject
        assertEquals(2, legacy.getValue("schemaVersion").jsonPrimitive.content.toInt())
        assertTrue(legacy.getValue("valid").jsonArray.isNotEmpty())
        assertTrue(legacy.getValue("mergeCases").jsonArray.size >= 2)
        assertTrue(legacy.getValue("invalid").jsonArray.size >= 2)
    }
}
