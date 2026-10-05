package com.vault.autofill

import com.vault.model.ModuleType
import com.vault.model.autofill.AutofillFieldPolicy
import com.vault.model.autofill.AutofillPolicy
import com.vault.model.autofill.AutofillRole
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillFieldPolicyTest {
    @Test
    fun rolesUseStableStrictWireValues() {
        val expected = listOf(
            "username", "email", "password", "one_time_code", "full_name", "phone", "country",
            "region", "city", "street_address", "postal_code", "cardholder", "card_number",
            "card_expiry", "card_cvv", "id_number", "api_key", "api_secret", "host", "port",
            "database", "ssid", "wifi_password", "recovery_answer", "custom_text", "custom_secret", "none",
        )

        assertEquals(expected, AutofillRole.entries.map(AutofillRole::wire))
        expected.forEach { wire -> assertEquals(wire, AutofillRole.fromWire(wire)?.wire) }
        listOf("", " ", " EMAIL ", "Email", "unknown").forEach { assertNull(AutofillRole.fromWire(it)) }
    }

    @Test
    fun everySharedFixturePolicyCaseIsImplemented() {
        val root = Json.parseToJsonElement(
            File(
                System.getProperty("spec.dir") ?: "spec",
                "autofill_sources_v1_fixtures.json",
            ).readText(Charsets.UTF_8),
        ).jsonObject

        root.getValue("policy_cases").jsonArray.forEach { element ->
            val case = element.jsonObject
            val moduleType = case.getValue("module_type").jsonPrimitive.content
            val sourceKey = case.getValue("field").jsonPrimitive.content
            val expectedRole = case["role"]?.jsonPrimitive?.contentOrNull
            val actual = AutofillFieldPolicy.forField(moduleType, sourceKey)

            if (expectedRole == null) {
                assertNull(case.getValue("name").jsonPrimitive.content, actual)
            } else {
                requireNotNull(actual)
                assertEquals(AutofillRole.fromWire(expectedRole), actual.role)
                assertEquals(case.getValue("internal").jsonPrimitive.boolean, actual.internalDefault)
                assertEquals(case.getValue("external_default").jsonPrimitive.boolean, actual.externalDefault)
                assertEquals(case.getValue("verification").jsonPrimitive.boolean, actual.requiresVerification)
            }
        }
    }

    @Test
    fun topLevelLoginFieldsHaveExplicitPolicies() {
        assertEquals(
            AutofillPolicy(AutofillRole.USERNAME, true, true, false),
            AutofillFieldPolicy.forTopLevel("username"),
        )
        assertEquals(
            AutofillPolicy(AutofillRole.PASSWORD, true, false, true),
            AutofillFieldPolicy.forTopLevel("password"),
        )
        assertNull(AutofillFieldPolicy.forTopLevel("notes"))
        assertNull(AutofillFieldPolicy.forTopLevel("target_app"))
        assertNull(AutofillFieldPolicy.forTopLevel("unknown"))
    }

    @Test
    fun explicitModulePoliciesCoverSafeAndSensitiveSources() {
        assertPolicy("login_account", "username", AutofillRole.USERNAME, external = true, verification = false)
        assertPolicy("login_account", "password", AutofillRole.PASSWORD, external = false, verification = true)
        assertNull(AutofillFieldPolicy.forField("email", "value"))
        assertNull(AutofillFieldPolicy.forField("phone", "value"))
        assertNull(AutofillFieldPolicy.forField("postal_code", "value"))
        assertPolicy("address", "address", AutofillRole.STREET_ADDRESS, external = true, verification = false)
        assertPolicy("address", "postal_code", AutofillRole.POSTAL_CODE, external = true, verification = false)
        assertPolicy("card_document", "id_number", AutofillRole.ID_NUMBER, external = false, verification = true)
        assertPolicy("api_credential", "api_key", AutofillRole.API_KEY, external = false, verification = true)
        assertPolicy("wifi", "wifi_password", AutofillRole.WIFI_PASSWORD, external = false, verification = true)
        assertPolicy("server_connection", "password", AutofillRole.PASSWORD, external = false, verification = true)
        assertPolicy("database", "password", AutofillRole.PASSWORD, external = false, verification = true)
        assertPolicy("recovery", "answer", AutofillRole.RECOVERY_ANSWER, external = false, verification = true)
        assertPolicy("text", "value", AutofillRole.CUSTOM_TEXT, external = true, verification = false)
        assertPolicy("password", "value", AutofillRole.CUSTOM_SECRET, external = false, verification = true)
    }

    @Test
    fun everySensitiveRoleUsesItsVerificationFloorInPolicy() {
        val sensitivePolicies = listOf(
            requireNotNull(AutofillFieldPolicy.forTopLevel("password")),
            requireNotNull(AutofillFieldPolicy.forField("card_document", "cvv")),
            requireNotNull(AutofillFieldPolicy.forField("card_document", "id_number")),
            requireNotNull(AutofillFieldPolicy.forField("api_credential", "api_key")),
            requireNotNull(AutofillFieldPolicy.forField("api_credential", "api_secret")),
            requireNotNull(AutofillFieldPolicy.forField("wifi", "wifi_password")),
            requireNotNull(AutofillFieldPolicy.forField("recovery", "answer")),
            requireNotNull(AutofillFieldPolicy.forField("password", "value")),
        )
        val sensitiveRoles = AutofillRole.entries.filter(AutofillRole::minimumRequiresVerification)

        assertEquals(sensitiveRoles.toSet(), sensitivePolicies.map { it.role }.toSet())
        sensitivePolicies.forEach { policy ->
            assertTrue(policy.role.minimumRequiresVerification)
            assertTrue(policy.requiresVerification)
            assertFalse(policy.externalDefault)
        }
    }

    @Test
    fun unsupportedAndSecretBearingStorageFieldsArePermanentlyExcluded() {
        listOf(
            ModuleType.PASSKEY to "user_name",
            ModuleType.PASSKEY to "credential_id",
            ModuleType.OTP to "secret",
            ModuleType.OTP to "algorithm",
            ModuleType.OTP to "digits",
            ModuleType.OTP to "period",
            ModuleType.OTP to "counter",
            ModuleType.OTP to "otp_domains",
            ModuleType.SSH to "private_key",
            ModuleType.ATTACHMENTS to "value",
            ModuleType.IMAGES to "value",
            ModuleType.MULTILINE to "value",
            ModuleType.BOOLEAN to "value",
            ModuleType.TARGET_APP to "value",
            ModuleType.CARD_DOCUMENT to "withdrawal_password",
            "unknown_composite" to "value",
            ModuleType.LOGIN_ACCOUNT to "unknown",
        ).forEach { (moduleType, sourceKey) ->
            assertNull("$moduleType/$sourceKey", AutofillFieldPolicy.forField(moduleType, sourceKey))
        }
    }

    private fun assertPolicy(
        moduleType: String,
        sourceKey: String,
        role: AutofillRole,
        external: Boolean,
        verification: Boolean,
    ) {
        val policy = requireNotNull(AutofillFieldPolicy.forField(moduleType, sourceKey))
        assertEquals(role, policy.role)
        assertTrue(policy.internalDefault)
        assertEquals(external, policy.externalDefault)
        assertEquals(verification, policy.requiresVerification)
        if (verification) assertFalse(policy.externalDefault)
    }
}
