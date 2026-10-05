package com.vault.passkeys

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PasskeyBackupTransferTest {
    @Test
    fun `direct syncable passkey is detected and marked backed up without rewriting its key`() {
        val record = PasskeyRecord.parse(fixtureRecord(0))!!.copy(backupState = false)
        val entries = listOf(entryWith(record.toJson()))

        assertTrue(PasskeyBackupTransfer.containsSyncable(entries))
        val (updated, count) = PasskeyBackupTransfer.markBackedUp(entries)

        assertEquals(1, count)
        val updatedRecord = PasskeyRecord.parse(moduleValue(updated.single()))!!
        assertTrue(updatedRecord.backupState)
        assertEquals(record.privateKey, updatedRecord.privateKey)
        val (_, secondCount) = PasskeyBackupTransfer.markBackedUp(updated)
        assertEquals(0, secondCount)
    }

    @Test
    fun `device bound passkey is not considered syncable`() {
        assertFalse(PasskeyBackupTransfer.containsSyncable(listOf(entryWith(fixtureRecord(1)))))
    }

    private fun fixtureRecord(index: Int): JsonObject {
        val dir = System.getProperty("spec.dir") ?: "spec"
        return Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText())
            .jsonObject.getValue("records").jsonArray[index].jsonObject.getValue("record").jsonObject
    }

    private fun entryWith(record: JsonObject): Entry = Entry(
        id = "ca4a63f8-d46d-47db-a07c-aa32649539bb",
        title = "Example",
        updatedAt = 1.0,
        fields = mapOf(
            EntryModules.FIELD_KEY to JsonArray(listOf(JsonObject(mapOf(
                "id" to JsonPrimitive("2bd27c81511a4829a6f280ba6fb7bb74"),
                "type" to JsonPrimitive(ModuleType.PASSKEY),
                "title" to JsonPrimitive("Passkey"),
                "value" to record,
            )))),
        ),
    )

    private fun moduleValue(entry: Entry): JsonObject =
        (((entry.fields.getValue(EntryModules.FIELD_KEY) as JsonArray).single() as JsonObject)["value"] as JsonObject)
}
