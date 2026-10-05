package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import com.vault.model.entryModules
import com.vault.passkeys.PasskeyAuthenticator
import com.vault.passkeys.PasskeyMerge
import com.vault.passkeys.PasskeyRequests
import com.vault.passkeys.SoftwarePasskeySigningKey
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

class PasskeyMergeTest {
    private val fixtureRecord: PasskeyRecord by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        val value = Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText())
            .jsonObject.getValue("legacyV2").jsonObject.getValue("valid").jsonArray.first().jsonObject.getValue("record").jsonObject
        PasskeyRecord.parse(value)!!
    }

    @Test
    fun sameKeyMergesMetadataAndAlwaysKeepsSyncedZero() {
        val local = module(
            fixtureRecord.copy(
                createdAt = "2026-07-15T00:00:00Z",
                lastUsedAt = "2026-07-15T12:00:00Z",
            ),
            "local",
        )
        val remote = module(
            fixtureRecord.copy(
                createdAt = "2026-07-14T00:00:00Z",
                lastUsedAt = "2026-07-16T00:00:00Z",
                unknownFields = JsonObject(
                    fixtureRecord.unknownFields + ("remote_future" to JsonPrimitive("keep")),
                ),
            ),
            "remote",
        )

        val result = PasskeyMerge.merge(listOf(local), listOf(remote))
        val record = PasskeyRecord.parse(result.modules.single()["value"]!!.jsonObject)!!

        assertEquals(0, record.signCount)
        assertEquals("2026-07-14T00:00:00Z", record.createdAt)
        assertEquals("2026-07-16T00:00:00Z", record.lastUsedAt)
        assertEquals(JsonPrimitive("keep"), record.unknownFields["remote_future"])
        assertFalse(result.hasKeyConflict)
    }

    @Test
    fun sameCredentialWithDifferentKeyPreservesBothAndMarksConflict() {
        val other = generatedRecord().copy(credentialId = fixtureRecord.credentialId)

        val result = PasskeyMerge.merge(
            listOf(module(fixtureRecord, "local")),
            listOf(module(other, "remote")),
        )

        assertTrue(result.hasKeyConflict)
        assertEquals(2, result.modules.size)
        val configs = result.modules.map { it["config"]!!.jsonObject }
        assertEquals(1, configs.map { it["passkeyConflictGroupId"] }.toSet().size)
        assertTrue(configs.all { it["passkeyConflictStatus"] == JsonPrimitive("key_mismatch") })
        assertNotEquals(
            result.modules[0]["value"]!!.jsonObject["public_key"],
            result.modules[1]["value"]!!.jsonObject["public_key"],
        )
    }

    @Test
    fun lwwCannotDropUniquePasskeyFromOlderEntryVersion() {
        val other = generatedRecord()
        val local = entry("same", 200.0, fixtureRecord)
        val remote = entry("same", 100.0, other)

        val (merged, stats) = VaultOps.mergeLww(
            local = VaultPayload(entries = listOf(local)),
            incoming = listOf(remote),
        )

        val passkeys = merged.entries.single().entryModules().filter {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        }
        assertEquals(2, passkeys.size)
        assertEquals(1, stats.takeLocal)
        assertEquals(0, stats.passkeyConflicts)
    }

    @Test
    fun lwwKeyMismatchKeepsBothAndReportsPasskeyConflict() {
        val conflicting = generatedRecord().copy(credentialId = fixtureRecord.credentialId)
        val local = entry("same", 200.0, fixtureRecord)
        val remote = entry("same", 100.0, conflicting)

        val (merged, stats) = VaultOps.mergeLww(
            local = VaultPayload(entries = listOf(local)),
            incoming = listOf(remote),
        )

        val passkeys = merged.entries.single().entryModules().filter {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        }
        assertEquals(2, passkeys.size)
        assertEquals(1, stats.passkeyConflicts)
    }

    private fun entry(id: String, updatedAt: Double, vararg records: PasskeyRecord): Entry =
        Entry(
            id = id,
            title = "Example",
            updatedAt = updatedAt,
            fields = mapOf(
                EntryModules.FIELD_KEY to JsonArray(
                    records.mapIndexed { index, record -> module(record, "module-$index") },
                ),
            ),
        )

    private fun module(record: PasskeyRecord, id: String): JsonObject =
        EntryModules.create(ModuleType.PASSKEY).let { raw ->
            JsonObject(
                raw.toMutableMap().also {
                    it["id"] = JsonPrimitive(id)
                    it["value"] = record.toJson()
                },
            )
        }

    private fun generatedRecord(): PasskeyRecord {
        val b64 = Base64.getUrlEncoder().withoutPadding()
        val request =
            """{"challenge":"${b64.encodeToString("challenge".toByteArray())}","rp":{"id":"example.com","name":"Example"},"user":{"id":"${b64.encodeToString("other-user".toByteArray())}","name":"bob","displayName":"Bob"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""
        SoftwarePasskeySigningKey.generate(PasskeyRequests.parseCreate(request).algorithm).use { key ->
            return PasskeyAuthenticator.create(
                request,
                "https://example.com",
                userVerified = true,
                signingKey = key,
                recordFactory = { seed ->
                    val privateBytes = key.exportPrivateKey()
                    try {
                        PasskeyRecord(
                        rpId = seed.rpId,
                        rpName = seed.rpName,
                        userId = seed.userId,
                        userName = seed.userName,
                        userDisplayName = seed.userDisplayName,
                        credentialId = seed.credentialId,
                        privateKey = b64.encodeToString(privateBytes),
                        publicKey = seed.publicKey,
                        signCount = 0,
                        createdAt = seed.createdAt,
                        lastUsedAt = "",
                        transports = "internal",
                        algorithm = seed.algorithm,
                        schemaVersion = PasskeyRecord.CURRENT_SCHEMA_VERSION,
                        aaguid = seed.aaguid,
                        discoverable = true,
                        backupEligible = true,
                        backupState = false,
                        )
                    } finally {
                        privateBytes.fill(0)
                    }
                },
            ).record
        }
    }
}
