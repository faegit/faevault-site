package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupCodecPasskeyTest {
    @Test
    fun `v3 payload encrypts direct syncable passkey content with a derived backup key`() {
        val privateKeyMarker = "syncable-private-key-marker-that-must-not-leak"
        val password = "Long-Passphrase-2026!"
        val payload = BackupCodec.BackupPayload(
            entries = listOf(Entry(id = "passkey-entry", title = "Example Passkey", fields = mapOf("private_key" to JsonPrimitive(privateKeyMarker)))),
        )

        val encoded = BackupCodec.encodeEncrypted(payload, password)
        try {
            assertFalse(encoded.containsSubsequence(privateKeyMarker.encodeToByteArray()))
            assertFalse(encoded.containsSubsequence(password.encodeToByteArray()))
            val decoded = BackupCodec.decodeEncrypted(encoded, password)
            assertEquals(JsonPrimitive(privateKeyMarker), decoded.entries.single().fields["private_key"])
        } finally {
            encoded.fill(0)
        }
    }

    @Test
    fun `encrypted backup export rejects weak password regardless of payload contents`() {
        assertThrows(IllegalArgumentException::class.java) {
            BackupCodec.encodeEncrypted(BackupCodec.BackupPayload(), "weak")
        }
    }

    @Test
    fun `v2 payload encrypted with a historical weak password remains import compatible`() {
        val payload = BackupCodec.BackupPayload(version = 2)
        val plaintext = Json {
            encodeDefaults = true
            explicitNulls = true
        }.encodeToString(BackupCodec.BackupPayload.serializer(), payload).encodeToByteArray()
        val weakPassword = "legacy".encodeToByteArray()
        val encoded = try {
            PmvBackupCrypto.encrypt(plaintext, weakPassword)
        } finally {
            plaintext.fill(0)
            weakPassword.fill(0)
        }
        val decoded = try { BackupCodec.decodeEncrypted(encoded, "legacy") } finally { encoded.fill(0) }
        assertEquals(2, decoded.version)
    }

    @Test
    fun `passkey export password policy rejects short weak secrets`() {
        assertTrue(BackupPasswordPolicy.isStrong("Long-Passphrase-2026!"))
        assertTrue(!BackupPasswordPolicy.isStrong("password"))
        assertTrue(!BackupPasswordPolicy.isStrong("alllowercasebutlong"))
    }

    @Test
    fun `encrypted backup retains platform rules and deletion tombstones`() {
        val exclusions = com.vault.model.AutofillExclusions(processes = listOf("EXAMPLE.EXE"), hosts = listOf("example.com"))
            .edit("hosts", "example.com", true, 20)
            .edit("packages", "com.example.app", false, 30)
        val payload = BackupCodec.BackupPayload(autofillExclusions = exclusions)
        val bytes = BackupCodec.encodeEncrypted(payload, "Long-Passphrase-2026!")
        try {
            assertEquals(exclusions, BackupCodec.decodeEncrypted(bytes, "Long-Passphrase-2026!").autofillExclusions)
        } finally { bytes.fill(0) }
        val legacy = VaultCodec.json.decodeFromString(BackupCodec.BackupPayload.serializer(), "{\"version\":2}")
        assertEquals(com.vault.model.AutofillExclusions(), legacy.autofillExclusions)
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        return indices.take(size - needle.size + 1).any { start ->
            needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
    }
}
