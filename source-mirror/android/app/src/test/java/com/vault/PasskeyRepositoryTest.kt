package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import com.vault.model.VaultPayload
import com.vault.passkeys.PasskeyMutationResult
import com.vault.passkeys.PasskeyAvailability
import com.vault.passkeys.PasskeyRepository
import com.vault.passkeys.PasskeyRequests
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
import java.util.Base64

class PasskeyRepositoryTest {
    private val fixtureRecord: PasskeyRecord by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        val value = Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText())
            .jsonObject.getValue("legacyV2").jsonObject.getValue("valid").jsonArray.first().jsonObject.getValue("record").jsonObject
        PasskeyRecord.parse(value)!!
    }

    @Test
    fun findHonorsRpIdAllowListAndDeletedEntries() {
        val first = storedEntry("first", fixtureRecord)
        val secondRecord = fixtureRecord.copy(credentialId = b64(ByteArray(32) { 9 }))
        val second = storedEntry("second", secondRecord)
        val deleted = storedEntry("deleted", fixtureRecord).copy(deletedAt = 10.0)
        val payload = VaultPayload(entries = listOf(first, second, deleted))

        val discoverable = PasskeyRequests.parseGet(
            """{"challenge":"${b64("challenge".toByteArray())}","rpId":"example.com"}""",
        )
        val allowed = PasskeyRequests.parseGet(
            """{"challenge":"${b64("challenge".toByteArray())}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${secondRecord.credentialId}"}]}""",
        )

        assertEquals(setOf("first", "second"), PasskeyRepository.find(payload, discoverable).map { it.entry.id }.toSet())
        assertEquals(listOf("second"), PasskeyRepository.find(payload, allowed).map { it.entry.id })
    }

    @Test
    fun findExcludesUnresolvedKeyConflictsButDuplicateChecksStillSeeThem() {
        val conflicted = storedEntry("conflicted", fixtureRecord).let { entry ->
            val modules = (entry.fields.getValue(EntryModules.FIELD_KEY) as JsonArray).map { element ->
                val module = element.jsonObject
                JsonObject(module.toMutableMap().also {
                    it["config"] = JsonObject(
                        (module["config"] as JsonObject).toMutableMap().also { config ->
                            config["passkeyConflictStatus"] = JsonPrimitive("key_mismatch")
                        },
                    )
                })
            }
            entry.copy(fields = entry.fields + (EntryModules.FIELD_KEY to JsonArray(modules)))
        }
        val payload = VaultPayload(entries = listOf(conflicted))
        val request = PasskeyRequests.parseGet(
            """{"challenge":"${b64("challenge".toByteArray())}","rpId":"example.com"}""",
        )

        assertTrue(PasskeyRepository.find(payload, request).isEmpty())
        assertTrue(
            PasskeyRepository.add(payload, Entry(id = "new"), fixtureRecord) is
                PasskeyMutationResult.Duplicate,
        )
    }

    @Test
    fun unavailableCredentialsRemainManageableButAreNeverAdvertised() {
        val payload = VaultPayload(entries = listOf(storedEntry("first", fixtureRecord)))
        val request = PasskeyRequests.parseGet(
            """{"challenge":"${b64("challenge".toByteArray())}","rpId":"example.com"}""",
        )

        assertEquals(1, PasskeyRepository.all(payload).size)
        assertTrue(
            PasskeyRepository.find(payload, request) { PasskeyAvailability.OTHER_DEVICE }.isEmpty(),
        )
    }

    @Test
    fun exclusionAndDuplicateChecksApplyAcrossEntries() {
        val payload = VaultPayload(entries = listOf(storedEntry("first", fixtureRecord)))
        val request = PasskeyRequests.parseCreate(
            """
            {
              "challenge":"${b64("challenge".toByteArray())}",
              "rp":{"id":"example.com","name":"Example"},
              "user":{"id":"${b64("user".toByteArray())}","name":"alice","displayName":"Alice"},
              "pubKeyCredParams":[{"type":"public-key","alg":-7}],
              "excludeCredentials":[{"type":"public-key","id":"${fixtureRecord.credentialId}"}]
            }
            """.trimIndent(),
        )

        assertTrue(PasskeyRepository.hasExcludedCredential(payload, request))
        assertTrue(
            PasskeyRepository.add(payload, Entry(id = "new"), fixtureRecord) is
                PasskeyMutationResult.Duplicate,
        )
    }

    @Test
    fun addPreservesExistingEntryFieldsAndModules() {
        val ordinaryModule = EntryModules.create(ModuleType.TEXT)
        val entry = Entry(
            id = "new",
            fields = mapOf(
                "future_entry" to kotlinx.serialization.json.JsonPrimitive("keep"),
                EntryModules.FIELD_KEY to JsonArray(listOf(ordinaryModule)),
            ),
        )

        val result = PasskeyRepository.add(VaultPayload(), entry, fixtureRecord)
            as PasskeyMutationResult.Success

        assertEquals("keep", result.entry.fields["future_entry"]?.toString()?.trim('"'))
        assertEquals(2, (result.entry.fields[EntryModules.FIELD_KEY] as JsonArray).size)
    }

    @Test
    fun addUsesReservedModuleIdentityForEnvelopeContextBinding() {
        val result = PasskeyRepository.add(
            VaultPayload(),
            Entry(id = "reserved-entry"),
            fixtureRecord,
            moduleId = "reserved-module",
        ) as PasskeyMutationResult.Success

        val module = (result.entry.fields.getValue(EntryModules.FIELD_KEY) as JsonArray).single().jsonObject
        assertEquals("reserved-module", EntryModules.primitive(module["id"]))
    }

    @Test
    fun updatePreservesModuleAndEntryUnknownFieldsButCannotReplaceKeyMaterial() {
        val original = storedEntry("first", fixtureRecord)
        val payload = VaultPayload(entries = listOf(original))
        val module = (original.fields.getValue(EntryModules.FIELD_KEY) as JsonArray)
            .first().jsonObject
        val moduleId = EntryModules.primitive(module["id"])
        val updated = fixtureRecord.copy(lastUsedAt = "2026-07-16T01:00:00Z")

        val result = PasskeyRepository.update(
            payload,
            entryId = original.id,
            moduleId = moduleId,
            expectedCredentialId = fixtureRecord.credentialId,
            updatedRecord = updated,
            updatedAt = 20.0,
        ) as PasskeyMutationResult.Success

        val changed = result.entry
        val changedModule = (changed.fields.getValue(EntryModules.FIELD_KEY) as JsonArray)
            .first().jsonObject
        assertEquals("keep", changed.fields["future_entry"]?.toString()?.trim('"'))
        assertEquals("keep", changedModule["future_module"]?.toString()?.trim('"'))
        assertEquals(updated.toJson(), changedModule["value"])
        assertEquals(20.0, changed.updatedAt, 0.0)

        val wrongKey = updated.copy(privateKey = b64(ByteArray(96) { 7 }))
        assertTrue(
            PasskeyRepository.update(
                payload,
                original.id,
                moduleId,
                fixtureRecord.credentialId,
                wrongKey,
                30.0,
            ) is PasskeyMutationResult.Invalid,
        )
    }

    @Test
    fun representationsDoNotExposeCredentialMaterial() {
        val stored = PasskeyRepository.all(VaultPayload(entries = listOf(storedEntry("first", fixtureRecord)))).single()
        assertFalse(stored.toString().contains(fixtureRecord.credentialId))
        assertFalse(stored.toString().contains(fixtureRecord.privateKey))
    }

    private fun storedEntry(id: String, record: PasskeyRecord): Entry {
        val module = EntryModules.create(ModuleType.PASSKEY).let { raw ->
            JsonObject(
                raw.toMutableMap().also {
                    it["value"] = record.toJson()
                    it["future_module"] = kotlinx.serialization.json.JsonPrimitive("keep")
                },
            )
        }
        return Entry(
            id = id,
            title = id,
            updatedAt = 10.0,
            fields = mapOf(
                EntryModules.FIELD_KEY to JsonArray(listOf(module)),
                "future_entry" to kotlinx.serialization.json.JsonPrimitive("keep"),
            ),
        )
    }

    private fun b64(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}
