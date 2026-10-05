package com.vault.autofill

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillFixtureShapeTest {
    private val fixture = File(
        System.getProperty("spec.dir") ?: "spec",
        "autofill_sources_v1_fixtures.json",
    )

    private val expectedCaseNames = linkedMapOf(
        "policy_cases" to listOf(
            "safe_street_address",
            "safe_postal_code",
            "sensitive_card_cvv",
            "excluded_withdrawal_password",
            "excluded_passkey_private_key",
            "excluded_otp_secret",
            "computed_otp_code",
        ),
        "migration_cases" to listOf("legacy_bound_otp"),
        "normalization_cases" to listOf(
            "ascii_trim_and_hyphen",
            "unicode_whitespace",
            "ascii_case_and_underscore",
            "ascii_case_and_dot",
            "ascii_slash",
        ),
        "resolution_cases" to listOf(
            "priority_top_level_modules_external",
            "safe_external_value_selection",
            "duplicate_role_shadowing",
            "missing_source",
            "missing_module",
            "empty_field",
            "one_hop_only",
            "non_sensitive_custom_exact_name",
            "sensitive_custom_never_title_matched",
            "computed_otp_only",
            "malformed_sibling_link_isolation",
        ),
    )

    private val expectedIssueOrder = mapOf(
        "priority_top_level_modules_external" to listOf("ROLE_SHADOWED", "ROLE_SHADOWED", "ROLE_SHADOWED"),
        "safe_external_value_selection" to emptyList(),
        "duplicate_role_shadowing" to listOf("ROLE_SHADOWED"),
        "missing_source" to listOf("SOURCE_ENTRY_MISSING"),
        "missing_module" to listOf("SOURCE_MODULE_MISSING"),
        "empty_field" to listOf("SOURCE_FIELD_EMPTY"),
        "one_hop_only" to emptyList(),
        "non_sensitive_custom_exact_name" to emptyList(),
        "sensitive_custom_never_title_matched" to emptyList(),
        "computed_otp_only" to emptyList(),
        "malformed_sibling_link_isolation" to emptyList(),
    )

    private val knownIssueCodes = setOf(
        "SOURCE_ENTRY_MISSING",
        "SOURCE_MODULE_MISSING",
        "SOURCE_FIELD_EMPTY",
        "ROLE_SHADOWED",
    )

    private val forbiddenStoredKey = Regex(
        "(?i)(password|passwd|secret|seed|private[^a-z0-9]*key|credential[^a-z0-9]*id|aaguid|token|notes?)",
    )

    private fun document(): JsonObject {
        assertTrue("shared autofill fixture must exist: $fixture", fixture.isFile)
        return Json.parseToJsonElement(fixture.readText(Charsets.UTF_8)).jsonObject
    }

    @Test
    fun fixtureHasStableVersionSectionsAndUniqueCaseNames() {
        val root = document()
        assertEquals(1, root.getValue("version").jsonPrimitive.int)

        expectedCaseNames.forEach { (section, expectedNames) ->
            assertTrue("$section must be an array", root[section] is JsonArray)
            val names = root.getValue(section).jsonArray.mapIndexed { index, element ->
                val case = element as? JsonObject
                assertNotNull("$section[$index] must be an object", case)
                val name = case!!["name"] as? JsonPrimitive
                assertTrue("$section[$index].name must be a string", name?.isString == true)
                assertTrue("$section[$index].name must be nonblank", !name!!.content.isBlank())
                name.content
            }
            assertEquals("$section case names must be unique", names.size, names.toSet().size)
            assertEquals("$section case order is part of the contract", expectedNames, names)
        }
    }

    @Test
    fun policyMigrationAndNormalizationCasesLockRequiredBehavior() {
        val root = document()
        val policies = root.getValue("policy_cases").jsonArray.map { it.jsonObject }

        assertPolicy(policies, "address", "address", "street_address", true, true, false)
        assertPolicy(policies, "card_document", "cvv", "card_cvv", true, false, true)
        assertPolicy(policies, "card_document", "withdrawal_password", null, false, false, true)
        assertPolicy(policies, "passkey", "private_key", null, false, false, true)
        assertPolicy(policies, "otp", "secret", null, false, false, true)
        assertPolicy(policies, "otp", "@computed/one_time_code", "one_time_code", true, true, false)

        assertEquals(
            setOf("safe_internal_external", "sensitive_opt_in", "permanently_excluded", "computed_otp"),
            policies.map { it.getValue("policy_class").jsonPrimitive.content }.toSet(),
        )

        val migration = root.getValue("migration_cases").jsonArray
            .map { it.jsonObject }
            .single { it.getValue("fields").jsonObject["bound_otp_id"]?.jsonPrimitive?.content == "otp-entry" }
        assertEquals("otp-entry", migration.getValue("expected_source_entry_id").jsonPrimitive.content)
        assertEquals("@computed/one_time_code", migration.getValue("expected_source_key").jsonPrimitive.content)
        assertEquals("one_time_code", migration.getValue("expected_role").jsonPrimitive.content)

        val normalizations = root.getValue("normalization_cases").jsonArray
            .map { it.jsonObject }
            .associate { it.getValue("input").jsonPrimitive.content to it.getValue("expected").jsonPrimitive.content }
        assertEquals("billingemail", normalizations[" Billing-email "])
        assertEquals("账单邮箱", normalizations["账单 邮箱"])
        assertEquals("billingemail", normalizations["BILLING_EMAIL"])
        assertEquals("billingemail", normalizations["Billing.Email"])
        assertEquals("billingemail", normalizations["billing/email"])
    }

    @Test
    fun resolutionCasesHaveCompleteInputsAndOrderedExpectedValues() {
        val cases = document().getValue("resolution_cases").jsonArray.map { it.jsonObject }
        assertEquals(
            expectedCaseNames.getValue("resolution_cases"),
            cases.map { it.getValue("name").jsonPrimitive.content },
        )

        val expectedKeys = setOf(
            "role",
            "source_entry_id",
            "module_id",
            "source_key",
            "value",
            "requires_verification",
        )
        cases.forEach { case ->
            val caseName = case.getValue("name").jsonPrimitive.content
            val input = case.getValue("input").jsonObject
            val hostEntryId = requireNonblankString(input, "host_entry_id", "$caseName.input")
            val entries = input.getValue("entries").jsonArray.map { it.jsonObject }
            assertTrue("resolution input must include its host entry", entries.any {
                it.getValue("id").jsonPrimitive.content == hostEntryId
            })
            entries.forEach { assertCompleteEntry(caseName, it) }

            val expected = case.getValue("expected").jsonArray
            expected.forEach { item ->
                val value = item.jsonObject
                assertEquals("expected resolved object keys are the wire contract", expectedKeys, value.keys)
                requireNonblankString(value, "role", "$caseName.expected")
                requireNonblankString(value, "source_entry_id", "$caseName.expected")
                assertStringOrNull(value["module_id"], "$caseName.expected.module_id")
                requireNonblankString(value, "source_key", "$caseName.expected")
                requireNonblankString(value, "value", "$caseName.expected")
                requireBoolean(value, "requires_verification", "$caseName.expected")
            }

            val issueElement = case["expected_issues"]
            assertTrue("$caseName.expected_issues must be an array", issueElement is JsonArray)
            val issues = issueElement!!.jsonArray.mapIndexed { index, issue ->
                val primitive = issue as? JsonPrimitive
                assertTrue("$caseName.expected_issues[$index] must be a string", primitive?.isString == true)
                val code = primitive!!.content
                assertTrue("unknown issue code $code", code in knownIssueCodes)
                code
            }
            assertEquals("$caseName issue order is part of the contract", expectedIssueOrder.getValue(caseName), issues)
        }
    }

    @Test
    fun fixtureContainsNoSecretMaterialOrSecretBearingResolutionFields() {
        val root = document()
        root.getValue("resolution_cases").jsonArray.forEach { caseElement ->
            val case = caseElement.jsonObject
            val caseName = case.getValue("name").jsonPrimitive.content
            val violations = secretViolations(case.getValue("input"))
            assertTrue("$caseName contains secret material: $violations", violations.isEmpty())
        }

        val computedOtp = root.getValue("resolution_cases").jsonArray
            .map { it.jsonObject }
            .single { it.getValue("name").jsonPrimitive.content == "computed_otp_only" }
        val serializedInput = computedOtp.getValue("input").toString().lowercase()
        listOf("\"secret\"", "\"seed\"", "\"algorithm\"", "\"digits\"", "\"period\"", "\"counter\"")
            .forEach { forbidden -> assertFalse("computed OTP input must omit $forbidden", serializedInput.contains(forbidden)) }
        assertEquals(
            listOf("@computed/one_time_code"),
            computedOtp.getValue("expected").jsonArray.map { it.jsonObject.getValue("source_key").jsonPrimitive.content },
        )
    }

    @Test
    fun recursiveSecretScannerRejectsNestedKeysAndMaterial() {
        val nestedSecretKey = Json.parseToJsonElement(
            """{"modules":[{"config":{"SeCrEt":"SHOULD_BE_REJECTED"}}]}""",
        )
        val nestedSecretValue = Json.parseToJsonElement(
            """{"fields":{"profile":{"value":"password=SHOULD_BE_REJECTED"}}}""",
        )

        assertTrue(secretViolations(nestedSecretKey).isNotEmpty())
        assertTrue(secretViolations(nestedSecretValue).isNotEmpty())
    }

    private fun assertPolicy(
        policies: List<JsonObject>,
        moduleType: String,
        field: String,
        role: String?,
        internal: Boolean,
        externalDefault: Boolean,
        verification: Boolean,
    ) {
        val policy = policies.single {
            it.getValue("module_type").jsonPrimitive.content == moduleType &&
                it.getValue("field").jsonPrimitive.content == field
        }
        assertEquals(role, policy["role"]?.jsonPrimitive?.contentOrNull)
        assertEquals(internal, policy.getValue("internal").jsonPrimitive.boolean)
        assertEquals(externalDefault, policy.getValue("external_default").jsonPrimitive.boolean)
        assertEquals(verification, policy.getValue("verification").jsonPrimitive.boolean)
    }

    private fun assertCompleteEntry(caseName: String, entry: JsonObject) {
        listOf("id", "type", "title", "fields", "modules").forEach { key ->
            assertNotNull("entry must include $key", entry[key])
        }
        assertTrue(entry.getValue("fields") is JsonObject)
        assertTrue(entry.getValue("modules") is JsonArray)
        requireNonblankString(entry, "id", "$caseName.entry")
        requireNonblankString(entry, "type", "$caseName.entry")
        requireNonblankString(entry, "title", "$caseName.entry")

        entry.getValue("modules").jsonArray.forEach { moduleElement ->
            val module = moduleElement.jsonObject
            listOf("id", "type", "title", "fields", "config").forEach { key ->
                assertNotNull("module must include $key", module[key])
            }
            assertTrue(module.getValue("fields") is JsonObject)
            assertTrue(module.getValue("config") is JsonObject)
            requireNonblankString(module, "id", "$caseName.module")
            requireNonblankString(module, "type", "$caseName.module")
            requireNonblankString(module, "title", "$caseName.module")
        }

        val links = entry.getValue("fields").jsonObject["autofill_links"] ?: return
        assertTrue(links is JsonArray)
        links.jsonArray.forEachIndexed { linkIndex, linkElement ->
            val link = linkElement as? JsonObject
            assertNotNull("$caseName link[$linkIndex] must be an object", link)
            if (caseName == "malformed_sibling_link_isolation" && linkIndex == 0) {
                assertEquals(setOf("id", "source_entry_id", "fields"), link!!.keys)
                assertEquals("link-malformed", link.getValue("id").jsonPrimitive.content)
                assertEquals(7, link.getValue("source_entry_id").jsonPrimitive.int)
                assertEquals("invalid", link.getValue("fields").jsonPrimitive.content)
                return@forEachIndexed
            }

            requireNonblankString(link!!, "id", "$caseName.link[$linkIndex]")
            requireNonblankString(link, "source_entry_id", "$caseName.link[$linkIndex]")
            val fields = linkElement["fields"]
            assertTrue("$caseName.link[$linkIndex].fields must be an array", fields is JsonArray)
            fields!!.jsonArray.forEachIndexed { refIndex, refElement ->
                val ref = refElement as? JsonObject
                assertNotNull("$caseName.link[$linkIndex].fields[$refIndex] must be an object", ref)
                assertEquals(
                    setOf("module_id", "source_key", "role", "requires_verification"),
                    ref!!.keys,
                )
                assertStringOrNull(ref["module_id"], "$caseName.link[$linkIndex].fields[$refIndex].module_id")
                requireNonblankString(ref, "source_key", "$caseName.link[$linkIndex].fields[$refIndex]")
                requireNonblankString(ref, "role", "$caseName.link[$linkIndex].fields[$refIndex]")
                requireBoolean(ref, "requires_verification", "$caseName.link[$linkIndex].fields[$refIndex]")
            }
        }
    }

    private fun looksLikeSecret(value: String): Boolean {
        if (Regex("^\\d{6,8}$").matches(value)) return true
        if (Regex("(?i)(BEGIN [A-Z ]*PRIVATE KEY|otpauth://|(?:password|passwd|secret|seed|token)\\s*[:=])")
                .containsMatchIn(value)
        ) return true
        return false
    }

    private fun secretViolations(element: JsonElement): List<String> {
        val violations = mutableListOf<String>()

        fun walk(value: JsonElement, path: String) {
            when (value) {
                is JsonObject -> value.forEach { (key, child) ->
                    val childPath = "$path.$key"
                    if (forbiddenStoredKey.containsMatchIn(key)) violations += "forbidden key at $childPath"
                    walk(child, childPath)
                }
                is JsonArray -> value.forEachIndexed { index, child -> walk(child, "$path[$index]") }
                is JsonPrimitive -> if (value.isString) {
                    val content = value.content
                    if (content != "VALUE_REDACTED" && looksLikeSecret(content)) {
                        violations += "secret-like value at $path"
                    }
                }
            }
        }

        walk(element, "input")
        return violations
    }

    private fun requireNonblankString(objectValue: JsonObject, key: String, path: String): String {
        val primitive = objectValue[key] as? JsonPrimitive
        assertTrue("$path.$key must be a string", primitive?.isString == true)
        assertTrue("$path.$key must be nonblank", !primitive!!.content.isBlank())
        return primitive.content
    }

    private fun assertStringOrNull(value: JsonElement?, path: String) {
        assertTrue("$path must be a nonblank string or null", value === JsonNull ||
            value is JsonPrimitive && value.isString && value.content.isNotBlank())
    }

    private fun requireBoolean(objectValue: JsonObject, key: String, path: String): Boolean {
        val primitive = objectValue[key] as? JsonPrimitive
        assertTrue("$path.$key must be a boolean", primitive != null && !primitive.isString)
        return primitive!!.boolean
    }
}
