package com.vault

import com.vault.model.PasskeyRecord
import com.vault.passkeys.PasskeyKeyMode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.UUID

class PasskeyRecordV3Test {
    private val fixtureRoot: JsonObject by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText()).jsonObject
    }

    private val fixtureV2: JsonObject get() = fixtureRoot.getValue("legacyV2").jsonObject
        .getValue("valid").jsonArray.first().jsonObject.getValue("record").jsonObject

    private val fixtureV3: JsonObject get() = fixtureRoot.getValue("records").jsonArray.first().jsonObject
        .getValue("record").jsonObject

    @Test
    fun `v3 syncable stores its private key directly inside the encrypted vault`() {
        val parsed = PasskeyRecord.parse(syncableV3())

        assertNotNull(parsed)
        assertEquals(3, parsed!!.schemaVersion)
        assertEquals(PasskeyKeyMode.SYNCABLE, parsed.keyMode)
        assertEquals(fixtureV2["private_key"]?.let { (it as JsonPrimitive).content }, parsed.privateKey)
        assertNull(parsed.deviceBinding)
        assertTrue("private_key" in parsed.toJson())
        assertFalse("private_key_envelope" in parsed.toJson())
    }

    @Test
    fun `v3 device bound requires binding and rejects every exported key carrier`() {
        val parsed = PasskeyRecord.parse(deviceBoundV3())

        assertNotNull(parsed)
        assertEquals(PasskeyKeyMode.DEVICE_BOUND, parsed!!.keyMode)
        assertNotNull(parsed.deviceBinding)
        assertFalse("private_key" in parsed.toJson())
        assertFalse("private_key_envelope" in parsed.toJson())

        assertNull(PasskeyRecord.parse(with(deviceBoundV3(), "private_key", JsonPrimitive("not-allowed"))))
        assertNull(PasskeyRecord.parse(with(deviceBoundV3(), "private_key_envelope", envelope())))
    }

    @Test
    fun `v3 rejects missing or mixed mode carriers`() {
        assertNull(PasskeyRecord.parse(with(syncableV3(), "private_key", JsonNull)))
        assertNull(PasskeyRecord.parse(with(syncableV3(), "private_key_envelope", envelope())))
        assertNull(PasskeyRecord.parse(with(syncableV3(), "device_binding", binding())))
        assertNull(PasskeyRecord.parse(with(deviceBoundV3(), "device_binding", JsonNull)))
        assertNull(PasskeyRecord.parse(with(deviceBoundV3(), "key_mode", JsonPrimitive("unknown"))))
    }

    @Test
    fun `v2 remains readable as legacy syncable and preserves unknown fields`() {
        val parsed = PasskeyRecord.parse(fixtureV2)

        assertNotNull(parsed)
        assertEquals(2, parsed!!.schemaVersion)
        assertEquals(PasskeyKeyMode.SYNCABLE, parsed.keyMode)
        assertTrue(parsed.privateKey.isNotEmpty())
        assertEquals(fixtureV2["future_field"], parsed.toJson()["future_field"])
    }

    @Test
    fun `shared v3 fixtures parse and retain future fields with direct syncable key material`() {
        val root = fixtureRoot
        assertTrue(root.getValue("testOnly").toString().toBoolean())
        val records = root.getValue("records").jsonArray.map { element ->
            element.jsonObject.getValue("record").jsonObject
        }
        assertEquals(2, records.size)
        records.forEach { record -> assertNotNull(PasskeyRecord.parse(record)) }
        val syncable = PasskeyRecord.parse(records.first())!!
        assertTrue("future_record_field" in syncable.toJson())
        assertTrue(syncable.privateKey.isNotEmpty())
    }

    private fun syncableV3(): JsonObject = v3().let { source ->
        JsonObject(source.toMutableMap().also {
            it["key_mode"] = JsonPrimitive("syncable")
            it["private_key"] = requireNotNull(fixtureV2["private_key"])
            it.remove("private_key_envelope")
            it.remove("device_binding")
        })
    }

    private fun deviceBoundV3(): JsonObject = v3().let { source ->
        JsonObject(source.toMutableMap().also {
            it["key_mode"] = JsonPrimitive("device_bound")
            it.remove("private_key")
            it.remove("private_key_envelope")
            it["device_binding"] = binding()
            it["backup_eligible"] = JsonPrimitive("false")
            it["backup_state"] = JsonPrimitive("false")
        })
    }

    private fun v3(): JsonObject = fixtureV3

    private fun envelope(): JsonObject = buildJsonObject {
        put("version", "1")
        put("keyset_id", UUID.fromString("2e6b26ca-9178-4c4d-a2d8-7b56f0415ba7").toString())
        put("nonce", "AAECAwQFBgcICQoL")
        put("ciphertext", "AAECAwQFBgcICQoLDA0ODw")
        put("aad_version", "1")
    }

    private fun binding(): JsonObject = buildJsonObject {
        put("provider", "android_keystore")
        put("device_id", UUID.fromString("e68e16cc-d6a0-4b20-bfb5-9c131f891b6d").toString())
        put("binding_id", "Kk3a5wP6xG9mR2uQv8sT0A")
        put("key_generation", "1")
    }

    private fun with(source: JsonObject, key: String, value: kotlinx.serialization.json.JsonElement): JsonObject =
        JsonObject(source.toMutableMap().also { it[key] = value })
}
