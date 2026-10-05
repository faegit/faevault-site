package com.vault.passkeys

import com.vault.model.PasskeyRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class PasskeySigningKeyTest {
    private fun b64(value: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())
    private val createJson = """{"challenge":"${b64("create")}","rp":{"id":"example.com","name":"Example"},"user":{"id":"${b64("user")}","name":"alice","displayName":"Alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""

    @Test
    fun `v3 syncable record opens directly after vault sync`() {
        val created = SoftwarePasskeySigningKey.generate(-7).use { key ->
            PasskeyAuthenticator.create(
                createJson,
                "https://login.example.com",
                true,
                key,
                recordFactory = { seed ->
                    val privateKey = key.exportPrivateKey()
                    try {
                        PasskeyRecord(
                            rpId = seed.rpId,
                            rpName = seed.rpName,
                            userId = seed.userId,
                            userName = seed.userName,
                            userDisplayName = seed.userDisplayName,
                            credentialId = seed.credentialId,
                            privateKey = Base64.getUrlEncoder().withoutPadding().encodeToString(privateKey),
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
                        privateKey.fill(0)
                    }
                },
            )
        }

        assertEquals(3, created.record.schemaVersion)
        assertTrue(created.record.privateKey.isNotEmpty())
        assertTrue("private_key" in created.record.toJson())
        assertFalse("private_key_envelope" in created.record.toJson())

        val opened = Base64.getUrlDecoder().decode(created.record.privateKey.padBase64())
        val publicCose = Base64.getUrlDecoder().decode(created.record.publicKey.padBase64())
        try {
            SoftwarePasskeySigningKey.open(created.record.algorithm, opened, publicCose).use { key ->
                val getJson = """{"challenge":"${b64("get")}","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"${created.record.credentialId}"}]}"""
                val asserted = PasskeyAuthenticator.get(getJson, "https://login.example.com", created.record, true, key)
                assertEquals(0, asserted.record.signCount)
            }
        } finally {
            opened.fill(0)
            publicCose.fill(0)
        }
    }
}
