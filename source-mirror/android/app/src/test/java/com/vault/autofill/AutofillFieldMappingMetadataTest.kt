package com.vault.autofill

import org.junit.Assert.*
import org.junit.Test

class AutofillFieldMappingMetadataTest {
    @Test fun mappingIsIsolatedToExactSourceAndReplacesRole() {
        val origin = TargetOrigin.Web("login.example.com")
        val fields = AutofillFieldMappingMetadata.add(emptyMap(), origin, "android|user", "username")
        assertEquals("username", AutofillFieldMappingMetadata.mappings(fields, origin)["android|user"])
        assertTrue(AutofillFieldMappingMetadata.mappings(fields, TargetOrigin.Web("example.com")).isEmpty())
        val replaced = AutofillFieldMappingMetadata.add(fields, origin, "android|user", "email")
        assertEquals(mapOf("android|user" to "email"), AutofillFieldMappingMetadata.mappings(replaced, origin))
    }
    @Test(expected = IllegalArgumentException::class) fun unknownRoleIsRejected() {
        AutofillFieldMappingMetadata.add(emptyMap(), TargetOrigin.Web("example.com"), "field", "unknown")
    }
    @Test fun removalLeavesSyncableTombstoneAndNoUsableMapping() {
        val origin = TargetOrigin.Web("example.com")
        val fields = AutofillFieldMappingMetadata.add(emptyMap(), origin, "field", "password")
        val removed = AutofillFieldMappingMetadata.remove(fields, origin)
        assertTrue(AutofillFieldMappingMetadata.mappings(removed, origin).isEmpty())
        assertTrue(removed[AutofillFieldMappingMetadata.FIELD_KEY].toString().contains("\"deleted\":true"))
    }
    @Test fun latestMappingWinsRegardlessOfArrayOrderAndDeletedWinsEqualTimestamp() {
        val origin = TargetOrigin.Web("example.com")
        fun row(role: String, timestamp: Long, deleted: Boolean = false) = kotlinx.serialization.json.buildJsonObject {
            put("origin", kotlinx.serialization.json.JsonPrimitive("https://example.com"))
            put("field_key", kotlinx.serialization.json.JsonPrimitive("field"))
            put("role", kotlinx.serialization.json.JsonPrimitive(role))
            put("updated_at", kotlinx.serialization.json.JsonPrimitive(timestamp))
            put("deleted", kotlinx.serialization.json.JsonPrimitive(deleted))
        }
        val old = row("username", 100)
        val newer = row("email", 200)
        fun fields(rows: List<kotlinx.serialization.json.JsonObject>) = mapOf(
            AutofillFieldMappingMetadata.FIELD_KEY to kotlinx.serialization.json.JsonArray(rows))
        assertEquals(mapOf("field" to "email"), AutofillFieldMappingMetadata.mappings(fields(listOf(newer, old)), origin))
        assertEquals(mapOf("field" to "email"), AutofillFieldMappingMetadata.mappings(fields(listOf(old, newer)), origin))
        val tombstone = row("email", 200, true)
        assertTrue(AutofillFieldMappingMetadata.mappings(fields(listOf(tombstone, newer, old)), origin).isEmpty())
        assertTrue(AutofillFieldMappingMetadata.mappings(fields(listOf(old, newer, tombstone)), origin).isEmpty())
        val restored = row("password", 300)
        assertEquals(mapOf("field" to "password"), AutofillFieldMappingMetadata.mappings(fields(listOf(restored, tombstone)), origin))
    }
}
