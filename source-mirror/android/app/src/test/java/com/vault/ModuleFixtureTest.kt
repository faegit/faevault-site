package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.entryModules
import com.vault.model.matches
import com.vault.storage.VaultCodec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ModuleFixtureTest {
    private fun fixtureCases(): Map<String, JsonObject> {
        val root = File(System.getProperty("spec.dir") ?: "spec", "modules_v1_fixtures.json")
        return Json.parseToJsonElement(root.readText()).jsonObject["cases"]!!.jsonArray
            .associate { element -> element.jsonObject.let { EntryModules.primitive(it["name"]) to it } }
    }

    private fun roundTrip(case: JsonObject): Pair<Entry, List<JsonObject>> {
        val normalized = EntryModules.normalize(case["modules"])
        val entry = Entry(
            secretType = EntryModules.primitive(case["secret_type"]),
            fields = mapOf(EntryModules.FIELD_KEY to JsonArray(normalized)),
        )
        val encoded = VaultCodec.json.encodeToString(Entry.serializer(), entry)
        val restored = VaultCodec.json.decodeFromString(Entry.serializer(), encoded)
        return restored to restored.entryModules()
    }

    @Test
    fun sharedFixturesRoundTripAndProtectSensitiveValues() {
        val root = File(System.getProperty("spec.dir") ?: "spec", "modules_v1_fixtures.json")
        val cases = Json.parseToJsonElement(root.readText()).jsonObject["cases"]!!.jsonArray
        cases.forEach { element ->
            val case = element.jsonObject
            val normalized = EntryModules.normalize(case["modules"])
            val (entry, out) = roundTrip(case)
            assertEquals(normalized.map { EntryModules.primitive(it["type"]) }, out.map { EntryModules.primitive(it["type"]) })
            assertEquals(out.size, out.map { EntryModules.primitive(it["id"]) }.toSet().size)
            when (EntryModules.primitive(case["name"])) {
                "secure_note_sensitive" -> assertEquals("preserve", EntryModules.primitive(out[0]["future"]))
                "server_mixed" -> {
                    assertEquals("7", EntryModules.primitive((out[0]["config"] as JsonObject)["futureConfig"]))
                    assertFalse(entry.matches("secret"))
                }
                "mandatory_sensitive_false" -> {
                    assertTrue(EntryModules.primitive(out[0]["sensitive"]).toBoolean())
                    assertFalse(entry.matches("must-stay-hidden"))
                }
            }
        }
    }

    @Test
    fun sharedFixturesCoverAutofillAwareContactAndCustomModules() {
        val cases = fixtureCases()
        val contacts = EntryModules.normalize(cases.getValue("autofill_contact_text_variants")["modules"])
        assertEquals(listOf("text", "text", "text"), contacts.map { EntryModules.primitive(it["type"]) })
        assertEquals(
            listOf("email", "phone", "postal_code"),
            contacts.map { EntryModules.configuredAutofillRole(it)?.wire },
        )

        fun roundTripped(name: String) = roundTrip(cases.getValue(name)).second.single()
        assertEquals("email", EntryModules.primitive((roundTripped("custom_text_email_role")["config"] as JsonObject)["autofill_role"]))
        assertFalse("autofill_role" in (roundTripped("custom_text_exact_name")["config"] as JsonObject))
        assertEquals("custom_secret", EntryModules.primitive((roundTripped("custom_password_secret_role")["config"] as JsonObject)["autofill_role"]))
        val unknown = roundTripped("custom_text_unknown_role")["config"] as JsonObject
        assertEquals("future_role", EntryModules.primitive(unknown["autofill_role"]))
        assertEquals("keep", EntryModules.primitive(unknown["future_config"]))
    }
}
