package com.vault.autofill

import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.autofill.AutofillRole
import com.vault.model.withAutofillLinks
import com.vault.model.withEntryModules
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillSourceResolverTest {
    @Test
    fun externalChoiceOverridesInternalAndSensitiveInternalStaysProtected() {
        val internalEmail = textVariant("internal", AutofillRole.EMAIL, "internal@example.com")
        val externalEmail = textVariant("external", AutofillRole.EMAIL, "external@example.com")
        val contact = Entry(id = "contact", title = "Contact").withEntryModules(listOf(externalEmail))
        val login = Entry(id = "login", title = "Login", username = "alice", password = "internal-secret")
            .withEntryModules(listOf(internalEmail))
            .withAutofillLinks(listOf(link(AutofillRole.EMAIL, contact.id, "external")))

        val snapshot = AutofillSourceResolver.resolve(login, listOf(login, contact), 1_700_000_000)

        assertEquals("external@example.com", snapshot.values.getValue(AutofillRole.EMAIL).value)
        assertEquals("internal-secret", snapshot.values.getValue(AutofillRole.PASSWORD).value)
        assertTrue(snapshot.values.getValue(AutofillRole.PASSWORD).requiresVerification)
    }

    @Test
    fun missingExternalChoiceFailsClosedWithoutInternalFallback() {
        val login = Entry(id = "login").withEntryModules(
            listOf(textVariant("internal", AutofillRole.EMAIL, "internal@example.com")),
        ).withAutofillLinks(listOf(link(AutofillRole.EMAIL, "missing", "gone")))

        val snapshot = AutofillSourceResolver.resolve(login, listOf(login), 1_700_000_000)

        assertNull(snapshot.values[AutofillRole.EMAIL])
        assertEquals(setOf(AutofillRole.EMAIL), snapshot.unavailableRoles)
    }

    @Test
    fun emailPhoneAndPostalCodeAreTextVariants() {
        val roles = listOf(AutofillRole.EMAIL, AutofillRole.PHONE, AutofillRole.POSTAL_CODE)
        val entry = Entry(id = "contact").withEntryModules(
            roles.mapIndexed { index, role -> textVariant("text-$index", role, "value-$index") },
        )
        val snapshot = AutofillSourceResolver.resolve(entry, listOf(entry), 1_700_000_000)
        roles.forEachIndexed { index, role -> assertEquals("value-$index", snapshot.values.getValue(role).value) }
    }

    @Test
    fun sensitiveValuesAreUnavailableUntilTheAuthenticatedFillGrantsVerification() {
        val entry = Entry(id = "login", password = "secret")
        val snapshot = AutofillSourceResolver.resolve(entry, listOf(entry), 1_700_000_000)

        assertNull(snapshot.valueFor(AutofillRole.PASSWORD, verificationGranted = false))
        assertEquals("secret", snapshot.valueFor(AutofillRole.PASSWORD, verificationGranted = true))
    }

    @Test
    fun linkedOtpModuleResolvesTheSelectedComputedField() {
        val otpModule = JsonObject(
            mapOf(
                "id" to JsonPrimitive("otp-module"),
                "type" to JsonPrimitive(ModuleType.OTP),
                "value" to JsonObject(
                    mapOf(
                        "secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                        "type" to JsonPrimitive("hotp"),
                        "counter" to JsonPrimitive("5"),
                    ),
                ),
            ),
        )
        val source = Entry(id = "otp-source").withEntryModules(listOf(otpModule))
        val login = Entry(id = "login").withAutofillLinks(
            listOf(
                AutofillLink(
                    "otp-link",
                    source.id,
                    listOf(AutofillFieldRef("otp-module", "@computed/one_time_code", AutofillRole.ONE_TIME_CODE, false)),
                ),
            ),
        )

        val snapshot = AutofillSourceResolver.resolve(login, listOf(login, source), 1_700_000_000)

        assertEquals(com.vault.model.OtpUtils.generateHOTP("JBSWY3DPEHPK3PXP", 5), snapshot.valueFor(AutofillRole.ONE_TIME_CODE, true))
    }

    @Test
    fun builtInEntryFieldsAreAvailableAsWholeEntryAutofillSources() {
        val card = Entry(
            id = "card",
            secretType = SecretType.CARD_DOCUMENT,
            fields = jsonFields(
                "cardholder" to "Alice",
                "card_number" to "4111111111111111",
                "expiry" to "12/30",
                "cvv" to "123",
            ),
        )
        val wifi = Entry(
            id = "wifi",
            secretType = SecretType.WIFI,
            fields = jsonFields("ssid" to "Home", "wifi_password" to "wifi-secret"),
        )
        val api = Entry(
            id = "api",
            secretType = SecretType.API_KEY,
            fields = jsonFields("api_key" to "key", "api_secret" to "secret"),
        )
        val server = Entry(
            id = "server",
            secretType = SecretType.SERVER,
            fields = jsonFields(
                "server_host" to "db.example.com",
                "server_port" to "5432",
                "server_user" to "db-user",
                "server_pass" to "db-password",
            ),
        )
        val otp = Entry(
            id = "otp",
            secretType = SecretType.OTP,
            fields = jsonFields(
                "secret" to "JBSWY3DPEHPK3PXP",
                "type" to "hotp",
                "counter" to "5",
            ),
        )

        assertValues(card, AutofillRole.CARDHOLDER to "Alice", AutofillRole.CARD_NUMBER to "4111111111111111", AutofillRole.CARD_EXPIRY to "12/30", AutofillRole.CARD_CVV to "123")
        assertValues(wifi, AutofillRole.SSID to "Home", AutofillRole.WIFI_PASSWORD to "wifi-secret")
        assertValues(api, AutofillRole.API_KEY to "key", AutofillRole.API_SECRET to "secret")
        assertValues(server, AutofillRole.HOST to "db.example.com", AutofillRole.PORT to "5432", AutofillRole.USERNAME to "db-user", AutofillRole.PASSWORD to "db-password")
        assertValues(otp, AutofillRole.ONE_TIME_CODE to com.vault.model.OtpUtils.generateHOTP("JBSWY3DPEHPK3PXP", 5))
    }

    private fun assertValues(entry: Entry, vararg expected: Pair<AutofillRole, String>) {
        val actual = AutofillSourceResolver.sourceValues(entry, 1_700_000_000).associate { it.role to it.value }
        expected.forEach { (role, value) -> assertEquals(value, actual[role]) }
    }

    private fun jsonFields(vararg fields: Pair<String, String>) =
        fields.associate { (key, value) -> key to JsonPrimitive(value) }

    private fun textVariant(id: String, role: AutofillRole, value: String): JsonObject =
        EntryModules.withAutofillRole(EntryModules.create(ModuleType.TEXT), role).let { module ->
            JsonObject(module.toMutableMap().also {
                it["id"] = JsonPrimitive(id)
                it["value"] = JsonPrimitive(value)
            })
        }

    private fun link(role: AutofillRole, sourceId: String, moduleId: String) = AutofillLink(
        id = "link-${role.wire}",
        sourceEntryId = sourceId,
        fields = listOf(AutofillFieldRef(moduleId, "value", role, false)),
    )
}
