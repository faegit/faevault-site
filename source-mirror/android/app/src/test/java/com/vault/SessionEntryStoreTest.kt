package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.VaultPayload
import com.vault.model.displaySecret
import com.vault.model.expiryInfo
import com.vault.model.ExpiryStatus
import com.vault.model.otpDisplaySnapshot
import com.vault.security.SessionEntryStore
import com.vault.storage.VaultLogicalRevision
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionEntryStoreTest {
    @Test
    fun secretsAreRemovedFromPublishedPayloadAndRestoredOnDemand() {
        val original = Entry(
            id = "entry-1",
            title = "Example",
            username = "alice",
            password = "correct horse battery staple",
            notes = "private note",
            fields = mapOf("api_key" to JsonPrimitive("secret-token")),
        )
        SessionEntryStore().use { store ->
            val published = store.seal(VaultPayload(entries = listOf(original)))
            val redacted = published.entries.single()

            assertEquals("", redacted.password)
            assertEquals("", redacted.notes)
            assertTrue(redacted.fields.isEmpty())
            assertEquals(original, store.reveal(redacted))
            assertEquals(original, store.materialize(published).entries.single())
            assertTrue(
                VaultLogicalRevision.from(VaultPayload(entries = listOf(original))) !=
                    VaultLogicalRevision.from(published),
            )
            assertEquals(
                VaultLogicalRevision.from(VaultPayload(entries = listOf(original))),
                VaultLogicalRevision.from(store.materialize(published)),
            )
        }
    }

    @Test(expected = IllegalStateException::class)
    fun closedStoreCannotRevealSecrets() {
        val store = SessionEntryStore()
        val published = store.seal(VaultPayload(entries = listOf(Entry(id = "entry-1", password = "secret"))))
        store.close()
        store.reveal(published.entries.single())
    }

    @Test
    fun nonLoginListSummariesSurviveWhileDetailsStaySealed() {
        val originals = listOf(
            Entry(id = "card", secretType = SecretType.CARD_DOCUMENT, fields = mapOf("card_type" to JsonPrimitive("bank_card"), "card_number_last4" to JsonPrimitive("1234"))),
            Entry(id = "id", secretType = SecretType.CARD_DOCUMENT, fields = mapOf("card_type" to JsonPrimitive("id_card"), "full_name" to JsonPrimitive("Alice"), "id_number" to JsonPrimitive("1234567890"))),
            Entry(id = "wifi", secretType = SecretType.WIFI, fields = mapOf("ssid" to JsonPrimitive("Office WiFi"))),
            Entry(id = "api", secretType = SecretType.API_KEY, fields = mapOf("service" to JsonPrimitive("Cloud API"))),
            modularOtpEntry(),
            Entry(id = "server", secretType = SecretType.SERVER, fields = mapOf("server_host" to JsonPrimitive("server.example.com"))),
        )

        SessionEntryStore().use { store ->
            val published = store.seal(VaultPayload(entries = originals))

            assertEquals(
                listOf("**** 1234", "Alice", "Office WiFi", "Cloud API", "Work OTP", "server.example.com"),
                published.entries.map { it.displaySecret },
            )
            assertTrue(published.entries.all { it.fields.isEmpty() })
            assertEquals(originals, store.materialize(published).entries)
        }
    }

    @Test
    fun idSummaryDoesNotRetainTheFullDocumentNumber() {
        val original = Entry(
            id = "id",
            secretType = SecretType.CARD_DOCUMENT,
            fields = mapOf("card_type" to JsonPrimitive("id_card"), "id_number" to JsonPrimitive("1234567890")),
        )

        SessionEntryStore().use { store ->
            val published = store.seal(VaultPayload(entries = listOf(original))).entries.single()

            assertEquals("**** 7890", published.displaySecret)
            assertTrue("1234567890" !in published.displaySummary)
        }
    }

    @Test
    fun cardExpiryStatusSurvivesListRedaction() {
        val original = Entry(
            id = "expired-card",
            secretType = SecretType.CREDIT_CARD,
            fields = mapOf("expiry" to JsonPrimitive("01/20")),
        )

        SessionEntryStore().use { store ->
            val published = store.seal(VaultPayload(entries = listOf(original))).entries.single()
            assertTrue(published.fields.isEmpty())
            assertEquals(ExpiryStatus.EXPIRED, published.expiryInfo().status)
            assertEquals(original, store.reveal(published))
        }
    }

    @Test
    fun modularOtpCanRenderWithoutPublishingItsSecret() {
        val original = modularOtpEntry()

        SessionEntryStore().use { store ->
            val published = store.seal(VaultPayload(entries = listOf(original))).entries.single()

            assertEquals("Work OTP", published.displaySecret)
            assertTrue(published.fields.isEmpty())
            assertEquals(null, published.otpDisplaySnapshot(59))

            val snapshot = store.reveal(published).otpDisplaySnapshot(59)
            assertEquals("94287082", snapshot?.code)
            assertEquals("Example Inc", snapshot?.issuer)
            assertEquals("Work OTP", snapshot?.label)
        }
    }

    private fun modularOtpEntry(): Entry {
        val module = EntryModules.create(ModuleType.OTP).toMutableMap().apply {
            put("value", JsonObject(mapOf(
                "secret" to JsonPrimitive("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                "issuer" to JsonPrimitive("Example Inc"),
                "label" to JsonPrimitive("Work OTP"),
                "algorithm" to JsonPrimitive("SHA1"),
                "digits" to JsonPrimitive("8"),
                "period" to JsonPrimitive("30"),
                "type" to JsonPrimitive("totp"),
                "counter" to JsonPrimitive("0"),
            )))
        }
        return Entry(
            id = "otp",
            secretType = SecretType.OTP,
            fields = mapOf(EntryModules.FIELD_KEY to JsonArray(listOf(JsonObject(module)))),
        )
    }
}
