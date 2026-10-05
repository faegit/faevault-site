package com.vault

import com.vault.model.PasskeyRecord
import com.vault.passkeys.PasskeyAuthenticator
import com.vault.passkeys.PasskeyDeviceBinding
import com.vault.passkeys.PasskeyKeyMode
import com.vault.passkeys.PasskeyLocalCounterStore
import com.vault.passkeys.PasskeyRequests
import com.vault.passkeys.SoftwarePasskeySigningKey
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Security
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

class PasskeyAuthenticatorTest {
    private fun b64(value: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())
    private val createJson = """{"challenge":"${b64("create")}","rp":{"id":"example.com","name":"Example"},"user":{"id":"${b64("user")}","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""

    /** Mirrors the production SYNCABLE record factory inside the encrypted vault entry. */
    private fun v3RecordFactory(key: SoftwarePasskeySigningKey): (PasskeyAuthenticator.CreationRecord) -> PasskeyRecord =
        { seed ->
            val privateBytes = key.exportPrivateKey()
            try {
                PasskeyRecord(
                rpId = seed.rpId,
                rpName = seed.rpName,
                userId = seed.userId,
                userName = seed.userName,
                userDisplayName = seed.userDisplayName,
                credentialId = seed.credentialId,
                privateKey = Base64.getUrlEncoder().withoutPadding().encodeToString(privateBytes),
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
                keyMode = PasskeyKeyMode.SYNCABLE,
                )
            } finally {
                privateBytes.fill(0)
            }
        }

    private fun createV3(
        requestJson: String,
        origin: String,
        userVerified: Boolean = true,
        clientDataHash: ByteArray? = null,
    ): Pair<SoftwarePasskeySigningKey, PasskeyAuthenticator.Created> {
        val algorithm = PasskeyRequests.parseCreate(requestJson).algorithm
        val key = SoftwarePasskeySigningKey.generate(algorithm)
        val created = PasskeyAuthenticator.create(
            requestJson,
            origin,
            userVerified,
            key,
            v3RecordFactory(key),
            clientDataHash,
        )
        return key to created
    }

    private fun <T> withCreated(
        requestJson: String,
        origin: String,
        userVerified: Boolean = true,
        clientDataHash: ByteArray? = null,
        block: (SoftwarePasskeySigningKey, PasskeyAuthenticator.Created) -> T,
    ): T {
        val (key, created) = createV3(requestJson, origin, userVerified, clientDataHash)
        return try {
            block(key, created)
        } finally {
            key.close()
        }
    }

    private fun verifyEcdsaRaw(publicKey: ECPublicKey, data: ByteArray, signature: ByteArray): Boolean {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        // WebAuthn ES256 签名为 ASN.1 DER，直接交给 JCA 验证
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(data)
        return verifier.verify(signature)
    }

    @Test fun createsAndSignsPasskey() {
        withCreated(createJson, "https://login.example.com") { key, created ->
            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
            val asserted = PasskeyAuthenticator.get(
                getJson,
                "https://login.example.com",
                created.record,
                userVerified = true,
                signingKey = key,
            )
            assertEquals(3, created.record.schemaVersion)
            assertTrue(created.record.discoverable)
            assertTrue(created.record.backupEligible)
            assertTrue(!created.record.backupState)
            assertEquals(0, asserted.record.signCount)
            val response = Json.parseToJsonElement(asserted.responseJson).jsonObject["response"]!!.jsonObject
            val authData = decode(response["authenticatorData"]!!.jsonPrimitive.content)
            assertEquals(0x0d, authData[32].toInt() and 0xff)
            assertEquals(
                0L,
                authData.copyOfRange(33, 37).fold(0L) { value, byte ->
                    (value shl 8) or (byte.toLong() and 0xff)
                },
            )
            val clientData = decode(response["clientDataJSON"]!!.jsonPrimitive.content)
            val signature = decode(response["signature"]!!.jsonPrimitive.content)
            val publicKey = publicFromPrivate(key.exportPrivateKey()) as ECPublicKey
            val signedData = authData + java.security.MessageDigest.getInstance("SHA-256").digest(clientData)
            assertTrue(verifyEcdsaRaw(publicKey, signedData, signature))
        }
    }

    @Test fun rejectsWrongOriginAndCredential() {
        assertThrows(IllegalArgumentException::class.java) {
            createV3(createJson, "http://example.com")
        }
        assertThrows(IllegalArgumentException::class.java) {
            createV3(createJson, "https://login.example.net")
        }
        withCreated(createJson, "https://example.com") { key, created ->
            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${b64("other credential id")}"}]}"""
            assertThrows(IllegalArgumentException::class.java) {
                PasskeyAuthenticator.get(
                    getJson,
                    "https://example.com",
                    created.record,
                    userVerified = true,
                    signingKey = key,
                )
            }
        }
    }

    @Test fun deviceBoundPasskeyUsesLocalMonotonicCounter() {
        val algorithm = PasskeyRequests.parseCreate(createJson).algorithm
        val key = SoftwarePasskeySigningKey.generate(algorithm)
        val binding = PasskeyDeviceBinding(
            provider = "android_keystore",
            deviceId = UUID.randomUUID(),
            bindingId = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also { SecureRandom().nextBytes(it) }),
            keyGeneration = 1,
        )
        val created = PasskeyAuthenticator.create(
            createJson,
            "https://example.com",
            true,
            key,
            recordFactory = { seed ->
                PasskeyRecord(
                    rpId = seed.rpId,
                    rpName = seed.rpName,
                    userId = seed.userId,
                    userName = seed.userName,
                    userDisplayName = seed.userDisplayName,
                    credentialId = seed.credentialId,
                    privateKey = Base64.getUrlEncoder().withoutPadding().encodeToString(key.exportPrivateKey().also { it.fill(0) }),
                    publicKey = seed.publicKey,
                    signCount = 0,
                    createdAt = seed.createdAt,
                    lastUsedAt = "",
                    transports = "internal",
                    algorithm = seed.algorithm,
                    schemaVersion = PasskeyRecord.CURRENT_SCHEMA_VERSION,
                    aaguid = seed.aaguid,
                    discoverable = true,
                    backupEligible = false,
                    backupState = false,
                    keyMode = PasskeyKeyMode.DEVICE_BOUND,
                    deviceBinding = binding,
                )
            },
        )
        val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
        val store = object : PasskeyLocalCounterStore {
            private var n = 100L
            override fun increment(identity: String) = ++n
            override fun peek(identity: String) = n
        }
        val asserted = PasskeyAuthenticator.get(
            getJson,
            "https://example.com",
            created.record,
            true,
            key,
            localCounterStore = store,
        )
        // 保险库内的 signCount 仍为 0（解析强制要求），真实计数只进入 authenticatorData
        assertEquals(0, asserted.record.signCount)
        val response = Json.parseToJsonElement(asserted.responseJson).jsonObject["response"]!!.jsonObject
        val authData = Base64.getUrlDecoder().decode(response["authenticatorData"]!!.jsonPrimitive.content)
        val counter = authData.copyOfRange(33, 37).fold(0L) { v, b -> (v shl 8) or (b.toLong() and 0xff) }
        assertEquals(101L, counter)
        key.close()
    }

    @Test fun allowsRelatedOriginRequests() {
        withCreated(createJson, "https://login.example.com") { key, created ->
            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
            val asserted = PasskeyAuthenticator.get(
                getJson,
                "https://login.example.com",
                created.record,
                userVerified = true,
                signingKey = key,
            )

            assertEquals(0, asserted.record.signCount)
        }
    }

    @Test fun signsPrivilegedBrowserHashAndReturnsCanonicalClientData() {
        withCreated(createJson, "https://login.example.com") { key, created ->
            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
            val origin = "https://login.example.com"
            // 任意浏览器哈希（Chrome 会随机插入 GREASE 成员，第三方无法复现其原文）
            val browserClientDataHash = MessageDigest.getInstance("SHA-256").digest("browser-client-data".toByteArray())
            val asserted = PasskeyAuthenticator.get(
                getJson,
                origin,
                created.record,
                userVerified = true,
                signingKey = key,
                clientDataHash = browserClientDataHash,
            )
            val response = Json.parseToJsonElement(asserted.responseJson).jsonObject["response"]!!.jsonObject
            val authData = decode(response["authenticatorData"]!!.jsonPrimitive.content)
            val clientData = decode(response["clientDataJSON"]!!.jsonPrimitive.content)
            val signature = decode(response["signature"]!!.jsonPrimitive.content)
            val publicKey = publicFromPrivate(key.exportPrivateKey()) as ECPublicKey
            val signedData = authData + browserClientDataHash

            // 返回结构完整的规范 clientDataJSON（不可是空占位符），但不要求与浏览器哈希一致；
            // 签名必须覆盖浏览器下发的哈希
            assertEquals(canonicalClientData("webauthn.get", b64("get"), origin), clientData.decodeToString())
            assertTrue(verifyEcdsaRaw(publicKey, signedData, signature))
        }
    }

    @Test fun rejectsOperationsWithoutUserVerificationOrWithInvalidBrowserHash() {
        assertThrows(IllegalArgumentException::class.java) {
            createV3(createJson, "https://example.com", userVerified = false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            createV3(
                createJson,
                "https://example.com",
                clientDataHash = ByteArray(31),
            )
        }
    }

    @Test fun returnsDiscoverableCredentialPropertiesWhenRequested() {
        val request = createJson.dropLast(1) + ""","extensions":{"credProps":true}}"""

        val created = createV3(request, "https://example.com").second
        val extensions = Json.parseToJsonElement(created.responseJson)
            .jsonObject["clientExtensionResults"]!!.jsonObject

        assertTrue(extensions["credProps"]!!.jsonObject["rk"]!!.jsonPrimitive.content.toBoolean())
    }

    @Test fun createsAndSignsRsaPasskey() {
        val rsaCreateJson = """{"challenge":"${b64("create")}","rp":{"id":"example.com","name":"Example"},"user":{"id":"${b64("user")}","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-257}]}"""
        withCreated(rsaCreateJson, "https://login.example.com") { key, created ->
            assertEquals(-257, created.record.algorithm)

            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
            val asserted = PasskeyAuthenticator.get(
                getJson,
                "https://login.example.com",
                created.record,
                userVerified = true,
                signingKey = key,
            )
            assertEquals(0, asserted.record.signCount)

            val response = Json.parseToJsonElement(asserted.responseJson).jsonObject["response"]!!.jsonObject
            val authData = decode(response["authenticatorData"]!!.jsonPrimitive.content)
            val signature = decode(response["signature"]!!.jsonPrimitive.content)
            val clientData = decode(response["clientDataJSON"]!!.jsonPrimitive.content)

            val rsaPrivate = KeyFactory.getInstance("RSA").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(key.exportPrivateKey())) as java.security.interfaces.RSAPrivateCrtKey
            val rsaPublic = java.security.KeyFactory.getInstance("RSA").generatePublic(java.security.spec.RSAPublicKeySpec(rsaPrivate.modulus, rsaPrivate.publicExponent))
            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(rsaPublic)
            verifier.update(authData + MessageDigest.getInstance("SHA-256").digest(clientData))
            assertTrue(verifier.verify(signature))
        }
    }

    @Test fun createsAndSignsEd25519Passkey() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val eddsaCreateJson = """{"challenge":"${b64("create")}","rp":{"id":"example.com","name":"Example"},"user":{"id":"${b64("user")}","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-8}]}"""
        withCreated(eddsaCreateJson, "https://login.example.com") { key, created ->
            assertEquals(-8, created.record.algorithm)

            val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
            val asserted = PasskeyAuthenticator.get(
                getJson,
                "https://login.example.com",
                created.record,
                userVerified = true,
                signingKey = key,
            )
            assertEquals(0, asserted.record.signCount)

            val response = Json.parseToJsonElement(asserted.responseJson).jsonObject["response"]!!.jsonObject
            val signature = decode(response["signature"]!!.jsonPrimitive.content)
            val authData = decode(response["authenticatorData"]!!.jsonPrimitive.content)
            val clientData = decode(response["clientDataJSON"]!!.jsonPrimitive.content)
            val signedHash = MessageDigest.getInstance("SHA-256").digest(clientData)

            val pkcs8Bytes = key.exportPrivateKey()
            val info = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(pkcs8Bytes)
            val seed = (info.parsePrivateKey() as org.bouncycastle.asn1.ASN1OctetString).octets
            val bcPrivate = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
            val bcPublic = bcPrivate.generatePublicKey()

            val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
            verifier.init(false, bcPublic)
            verifier.update(authData + signedHash, 0, authData.size + signedHash.size)
            assertTrue(verifier.verifySignature(signature))
        }
    }

    private fun decode(value: String) = Base64.getUrlDecoder().decode(value.padEnd((value.length + 3) / 4 * 4, '='))
    private fun publicFromPrivate(pkcs8: ByteArray): java.security.PublicKey {
        val privateKey = KeyFactory.getInstance("EC").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8)) as java.security.interfaces.ECPrivateKey
        val params = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1")
        val point = params.g.multiply(privateKey.s).normalize()
        java.security.Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        return KeyFactory.getInstance("EC", "BC").generatePublic(org.bouncycastle.jce.spec.ECPublicKeySpec(point, params))
    }

    /** Chrome 等特权浏览器对规范 clientDataJSON 的序列化方式：紧凑、固定字段顺序。 */
    private fun canonicalClientData(type: String, challenge: String, origin: String) =
        """{"type":"$type","challenge":"$challenge","origin":"$origin","crossOrigin":false}"""

    @Test fun createWithBrowserClientDataHashReturnsCanonicalJsonAndRecordsOnce() {
        val origin = "https://accounts.example.com"
        // 任意（与本地 JSON 必然不同的）浏览器哈希：创建必须照常成功
        val browserHash = MessageDigest.getInstance("SHA-256").digest("chrome-greased-client-data".toByteArray())
        var factoryCalls = 0
        val algorithm = PasskeyRequests.parseCreate(createJson).algorithm
        val key = SoftwarePasskeySigningKey.generate(algorithm)
        try {
            val created = PasskeyAuthenticator.create(
                createJson, origin, true, key,
                { seed -> factoryCalls++; v3RecordFactory(key)(seed) },
                browserHash,
            )
            assertEquals(1, factoryCalls)
            val clientData = decode(
                Json.parseToJsonElement(created.responseJson).jsonObject["response"]!!
                    .jsonObject["clientDataJSON"]!!.jsonPrimitive.content,
            )
            assertEquals(canonicalClientData("webauthn.create", b64("create"), origin), clientData.decodeToString())
        } finally {
            key.close()
        }
    }

    @Test fun createResponseIncludesChromeRequiredAttestationFields() {
        withCreated(createJson, "https://login.example.com") { key, created ->
            val response = Json.parseToJsonElement(created.responseJson)
                .jsonObject["response"]!!.jsonObject

            assertEquals(
                created.record.algorithm,
                response["publicKeyAlgorithm"]?.jsonPrimitive?.content?.toIntOrNull(),
            )
            val authenticatorData = decode(response["authenticatorData"]!!.jsonPrimitive.content)
            assertTrue(authenticatorData.size > 55)
            assertEquals(0x4d, authenticatorData[32].toInt() and 0xff)
            val publicKey = decode(response["publicKey"]!!.jsonPrimitive.content)
            assertArrayEquals(publicFromPrivate(key.exportPrivateKey()).encoded, publicKey)
        }
    }

    @Test fun defaultAttestationConveyanceIsNone() {
        withCreated(createJson, "https://login.example.com") { _, created ->
            val response = Json.parseToJsonElement(created.responseJson)
                .jsonObject["response"]!!.jsonObject
            val attestationObject = decode(response["attestationObject"]!!.jsonPrimitive.content)

            assertTrue(attestationObject.containsCborTextPair("fmt", "none"))
            assertTrue(attestationObject.containsCborEmptyMapValue("attStmt"))
        }
    }

    @Test fun directAttestationKeepsPackedSelfAttestationWithoutChangingClientDataShape() {
        val request = createJson.dropLast(1) + ",\"attestation\":\"direct\"}"
        withCreated(request, "https://login.example.com") { _, created ->
            val response = Json.parseToJsonElement(created.responseJson)
                .jsonObject["response"]!!.jsonObject
            val attestationObject = decode(response["attestationObject"]!!.jsonPrimitive.content)
            val clientData = decode(response["clientDataJSON"]!!.jsonPrimitive.content).decodeToString()

            assertTrue(attestationObject.containsCborTextPair("fmt", "packed"))
            assertTrue(!clientData.contains("\"attestation\""))
        }
    }

    private fun ByteArray.containsCborTextPair(key: String, value: String): Boolean =
        containsSubsequence(cborText(key) + cborText(value))

    private fun ByteArray.containsCborEmptyMapValue(key: String): Boolean =
        containsSubsequence(cborText(key) + byteArrayOf(0xa0.toByte()))

    private fun cborText(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size < 24)
        return byteArrayOf((0x60 or bytes.size).toByte()) + bytes
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean =
        indices.any { start ->
            start + needle.size <= size &&
                needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
}
