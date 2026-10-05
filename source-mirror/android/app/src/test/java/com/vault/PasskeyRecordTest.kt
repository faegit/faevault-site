package com.vault

import com.vault.model.PasskeyRecord
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class PasskeyRecordTest {
    private val fixtureRecord: JsonObject by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText())
            .jsonObject.getValue("legacyV2").jsonObject.getValue("valid").jsonArray.first().jsonObject.getValue("record").jsonObject
    }

    @Test
    fun parsesFullVersionTwoFixture() {
        val parsed = PasskeyRecord.parse(fixtureRecord)!!

        assertEquals(2, parsed.schemaVersion)
        assertEquals("example.com", parsed.rpId)
        assertEquals("9a2289d0-7b7b-4c5d-8d77-5f7a0643cc82", parsed.aaguid)
        assertTrue(parsed.discoverable)
        assertTrue(parsed.backupEligible)
        assertTrue(parsed.backupState)
        assertEquals(0, parsed.signCount)
    }

    @Test
    fun rejectsVersionTwoRecordsMissingAnyRequiredContractField() {
        requiredV2Fields.forEach { field ->
            val incomplete = JsonObject(fixtureRecord.toMutableMap().also { it.remove(field) })

            assertNull("$field must be present in schema v2", PasskeyRecord.parse(incomplete))
        }
    }

    @Test
    fun rejectsVersionTwoRecordsWithWrongTypeForAnyRequiredContractField() {
        requiredV2Fields.forEach { field ->
            val wrongType = JsonObject(fixtureRecord.toMutableMap().also {
                it[field] = JsonPrimitive(7)
            })

            assertNull("$field must be a JSON string in schema v2", PasskeyRecord.parse(wrongType))
        }
    }

    @Test
    fun acceptsPresentButEmptyVersionTwoLastUsedAt() {
        val parsed = PasskeyRecord.parse(v2("last_used_at" to JsonPrimitive("")))!!

        assertEquals("", parsed.lastUsedAt)
        assertEquals(JsonPrimitive(""), parsed.toJson()["last_used_at"])
    }

    @Test
    fun preservesUnknownFieldsAndOriginalBase64UrlStrings() {
        val privateKey = padded(fixtureRecord.getValue("private_key").toString().trim('"'))
        val publicKey = padded(fixtureRecord.getValue("public_key").toString().trim('"'))
        val source = JsonObject(fixtureRecord.toMutableMap().also {
            it["user_id"] = JsonPrimitive("dXNlcg==")
            it["credential_id"] = JsonPrimitive("MDEyMzQ1Njc4OWFiY2RlZg==")
            it["private_key"] = JsonPrimitive(privateKey)
            it["public_key"] = JsonPrimitive(publicKey)
            it["future_field"] = buildJsonObject {
                put("revision", 7)
                put("nested", buildJsonObject { put("enabled", true) })
            }
        })
        val before = JsonObject(source.toMap())

        val roundTrip = PasskeyRecord.parse(source)!!.toJson()

        assertEquals(source["user_id"], roundTrip["user_id"])
        assertEquals(source["credential_id"], roundTrip["credential_id"])
        assertEquals(source["private_key"], roundTrip["private_key"])
        assertEquals(source["public_key"], roundTrip["public_key"])
        assertEquals(source["future_field"], roundTrip["future_field"])
        assertEquals(before, source)
    }

    @Test
    fun rejectsSyncedZeroWithNonZeroCounterAndMismatchedPublicKey() {
        assertNull(PasskeyRecord.parse(v2("sign_count" to JsonPrimitive("1"))))
        assertNull(PasskeyRecord.parse(v2("public_key" to JsonPrimitive(otherP256CoseKey()))))
    }

    @Test
    fun validatesVersionTwoMetadataAndSafeBoundsStrictly() {
        assertNull(PasskeyRecord.parse(v2("schema_version" to JsonPrimitive("3"))))
        assertNull(PasskeyRecord.parse(v2("aaguid" to JsonPrimitive("not-a-uuid"))))
        assertNull(PasskeyRecord.parse(v2("discoverable" to JsonPrimitive(true))))
        assertNull(PasskeyRecord.parse(v2("backup_eligible" to JsonPrimitive("false"))))
        assertNull(PasskeyRecord.parse(v2("counter_mode" to JsonPrimitive("unknown"))))
        assertNull(PasskeyRecord.parse(v2("created_at" to JsonPrimitive("2026-02-30T00:00:00Z"))))
        assertNull(PasskeyRecord.parse(v2("last_used_at" to JsonPrimitive("yesterday"))))
        assertNull(PasskeyRecord.parse(v2("rp_name" to JsonPrimitive(7))))
        assertNull(PasskeyRecord.parse(v2("algorithm" to JsonPrimitive(-7))))
        assertNull(PasskeyRecord.parse(v2("algorithm" to JsonPrimitive("-256"))))
        assertNull(PasskeyRecord.parse(v2("algorithm" to JsonPrimitive("unsupported"))))
        assertNull(PasskeyRecord.parse(v2("transports" to JsonPrimitive("usb"))))
        assertNull(PasskeyRecord.parse(v2("credential_id" to JsonPrimitive(encode(ByteArray(1025))))))
    }

    @Test
    fun rejectsRpIdsThatTheDesktopCannotAccept() {
        listOf("1.2.3.4", "example.123", "exa_mple.com", "example.com/path").forEach { rpId ->
            assertNull(rpId, PasskeyRecord.parse(v2("rp_id" to JsonPrimitive(rpId))))
        }
        assertEquals("example.com", PasskeyRecord.parse(v2("rp_id" to JsonPrimitive("example.com")))?.rpId)
    }

    @Test
    fun validatesP256Pkcs8AndDeterministicCoseMaterial() {
        assertNull(PasskeyRecord.parse(v2("private_key" to JsonPrimitive(encode("not-pkcs8".toByteArray())))))
        assertNull(PasskeyRecord.parse(v2("public_key" to JsonPrimitive(encode(byteArrayOf(0xa1.toByte(), 0x01))))))

        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp384r1"))
        assertNull(PasskeyRecord.parse(v2("private_key" to JsonPrimitive(encode(generator.generateKeyPair().private.encoded)))))
    }

    @Test
    fun validatesRsaPkcs8AndCoseMaterial() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        val rsaPublic = pair.public as RSAPublicKey

        val modulus = rsaPublic.modulus.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        val exponent = rsaPublic.publicExponent.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()

        val coseKey = ByteArrayOutputStream().apply {
            write(0xa4)
            write(byteArrayOf(0x01, 0x03))
            write(byteArrayOf(0x03, 0x39, 0x01, 0x00))
            write(byteArrayOf(0x20))
            writeCborBytes(modulus)
            write(byteArrayOf(0x21))
            writeCborBytes(exponent)
        }.toByteArray()

        val parsed = PasskeyRecord.parse(v2(
            "algorithm" to JsonPrimitive("-257"),
            "private_key" to JsonPrimitive(encode(pair.private.encoded)),
            "public_key" to JsonPrimitive(encode(coseKey)),
        ))
        assertTrue(parsed != null)
        assertEquals(-257, parsed!!.algorithm)
    }

    @Test
    fun validatesEd25519Pkcs8AndCoseMaterial() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val generator = KeyPairGenerator.getInstance("Ed25519")
        val pair = generator.generateKeyPair()

        val pkcs8Der = pair.private.encoded
        val info = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(pkcs8Der)
        val seed = (info.parsePrivateKey() as org.bouncycastle.asn1.ASN1OctetString).octets
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes, got ${seed.size}" }
        val bcPrivate = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
        val bcPublic = bcPrivate.generatePublicKey()
        val rawPub = ByteArray(32)
        bcPublic.encode(rawPub, 0)
        val xBytes = rawPub

        val coseKey = ByteArrayOutputStream().apply {
            write(0xa4)
            write(byteArrayOf(0x01, 0x01))
            write(byteArrayOf(0x03, 0x27))
            write(byteArrayOf(0x20, 0x06))
            write(byteArrayOf(0x21, 0x58, 0x20))
            write(xBytes)
        }.toByteArray()

        val parsed = PasskeyRecord.parse(v2(
            "algorithm" to JsonPrimitive("-8"),
            "private_key" to JsonPrimitive(encode(pkcs8Der)),
            "public_key" to JsonPrimitive(encode(coseKey)),
        ))
        assertTrue(parsed != null)
        assertEquals(-8, parsed!!.algorithm)
    }

    @Test
    fun rejectsRecordsWithoutVersionTwoContractFields() {
        val incomplete = fixtureRecord.toMutableMap().also { values ->
            setOf(
                "schema_version", "aaguid", "discoverable", "backup_eligible",
                "backup_state", "counter_mode",
            ).forEach(values::remove)
            values["algorithm"] = JsonPrimitive("")
            values["transports"] = JsonPrimitive("")
            values["sign_count"] = JsonPrimitive(7)
        }

        assertNull(PasskeyRecord.parse(JsonObject(incomplete)))
    }

    @Test
    fun missingSchemaNeverReceivesDefaults() {
        val partial = fixtureRecord.toMutableMap().also {
            it.remove("schema_version")
            it["algorithm"] = JsonPrimitive("")
            it["transports"] = JsonPrimitive("")
        }

        assertNull(PasskeyRecord.parse(JsonObject(partial)))
    }

    @Test
    fun normalizesRpIdWithoutReencodingSecretBearingFields() {
        val parsed = PasskeyRecord.parse(v2("rp_id" to JsonPrimitive("EXAMPLE.COM.")))!!

        assertEquals("example.com", parsed.rpId)
        assertEquals(fixtureRecord["private_key"], parsed.toJson()["private_key"])
    }

    private fun v2(vararg overrides: Pair<String, JsonPrimitive>): JsonObject =
        JsonObject(fixtureRecord.toMutableMap().also { values ->
            overrides.forEach { (key, value) -> values[key] = value }
        })

    private val requiredV2Fields = listOf(
        "schema_version",
        "rp_id",
        "rp_name",
        "user_id",
        "user_name",
        "user_display_name",
        "credential_id",
        "private_key",
        "public_key",
        "algorithm",
        "transports",
        "aaguid",
        "discoverable",
        "backup_eligible",
        "backup_state",
        "counter_mode",
        "sign_count",
        "created_at",
        "last_used_at",
    )

    private fun padded(value: String): String = value.padEnd((value.length + 3) / 4 * 4, '=')
    private fun encode(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun ByteArrayOutputStream.writeCborBytes(data: ByteArray) {
        when {
            data.size < 24 -> write(0x40 or data.size)
            data.size <= 0xff -> { write(0x58); write(data.size) }
            data.size <= 0xffff -> { write(0x59); write(data.size ushr 8); write(data.size and 0xff) }
            else -> error("unsupported CBOR bytes length")
        }
        write(data)
    }

    private fun otherP256CoseKey(): String {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val public = generator.generateKeyPair().public as ECPublicKey
        val x = public.w.affineX.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        val y = public.w.affineY.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        val bytes = ByteArrayOutputStream().apply {
            write(0xa5)
            write(byteArrayOf(0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20))
            write(x)
            write(byteArrayOf(0x22, 0x58, 0x20))
            write(y)
        }.toByteArray()
        return encode(bytes)
    }
}
