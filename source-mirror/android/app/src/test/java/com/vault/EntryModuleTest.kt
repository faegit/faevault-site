package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.normalized
import com.vault.model.entryModules
import com.vault.model.detailModules
import com.vault.model.matches
import com.vault.model.withEntryModules
import com.vault.model.associatedAppPackage
import com.vault.model.autofill.AutofillRole
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class EntryModuleTest {
    @Test
    fun booleanModuleUsesNativeJsonBooleanAndReadsLegacyStrings() {
        val created = EntryModules.create(ModuleType.BOOLEAN)
        assertFalse((created["value"] as JsonPrimitive).isString)
        assertFalse((created["value"] as JsonPrimitive).boolean)

        val legacy = JsonObject(created.toMutableMap().also { it["value"] = JsonPrimitive("true") })
        val normalized = EntryModules.normalize(JsonArray(listOf(legacy))).single()
        assertFalse((normalized["value"] as JsonPrimitive).isString)
        assertTrue((normalized["value"] as JsonPrimitive).boolean)
    }

    @Test
    fun datetimeModesHaveStableDefaultsAndLocalWallTimeValues() {
        val created = EntryModules.create(ModuleType.DATETIME)
        assertEquals("datetime", EntryModules.primitive((created["config"] as JsonObject)["mode"]))
        assertEquals("", EntryModules.primitive(created["value"]))

        assertTrue(EntryModules.isValidDateTimeValue("date", "2026-08-20"))
        assertTrue(EntryModules.isValidDateTimeValue("time", "23:59"))
        assertTrue(EntryModules.isValidDateTimeValue("datetime", "2026-08-20T23:59"))
        assertFalse(EntryModules.isValidDateTimeValue("datetime", "2026-08-20T23:59Z"))
    }

    @Test
    fun datetimeEditingPreservesTheOtherPartAcrossModes() {
        assertEquals(
            "2026-08-20T23:59",
            EntryModules.dateTimeValueForMode("2026-08-20T23:59", "datetime"),
        )
        assertEquals(
            "2026-08-20T23:59",
            EntryModules.withDateTimePart("2026-08-20T12:30", "datetime", hour = 23, minute = 59),
        )
        assertEquals(
            "23:59",
            EntryModules.withDateTimePart("12:30", "time", hour = 23, minute = 59),
        )
    }

    @Test
    fun cardTypeTemplatesKeepOnlyTheSelectedTemplateFields() {
        assertEquals(
            listOf(EntryModules.CARD_BANK, EntryModules.CARD_ID_CARD, EntryModules.CARD_CUSTOM),
            EntryModules.cardTypeLabels.keys.toList(),
        )
        assertEquals("其他卡证", EntryModules.cardTypeLabels.getValue(EntryModules.CARD_CUSTOM))

        val card = EntryModules.create(ModuleType.CARD_DOCUMENT)
        assertEquals("卡证", EntryModules.primitive(card["title"]))
        val bank = card["value"] as JsonObject
        assertEquals("bank_card", EntryModules.primitive(bank["card_type"]))
        assertTrue("bank_branch" in bank)

        val original = JsonObject(bank.toMutableMap().also {
            it["bank"] = JsonPrimitive("Example Bank")
            it["future_field"] = JsonPrimitive("keep")
        })
        val custom = EntryModules.cardValueForType(original, EntryModules.CARD_CUSTOM)
        assertEquals("custom", EntryModules.primitive(custom["card_type"]))
        assertFalse("bank" in custom)
        assertFalse("future_field" in custom)
        assertTrue("card_name" in custom)
        assertTrue("expiry" in custom)
        assertEquals(JsonArray(emptyList()), custom["images"])

        val identity = EntryModules.cardValueForType(custom, EntryModules.CARD_ID_CARD)
        assertEquals("id_card", EntryModules.primitive(identity["card_type"]))
        assertTrue("full_name" in identity)
        assertTrue("id_number" in identity)
        assertFalse("card_name" in identity)
    }

    @Test
    fun passkeyDefaultUsesTheFullVersionTwoContract() {
        val module = EntryModules.create(ModuleType.PASSKEY)
        val value = module["value"] as JsonObject

        assertEquals("2", EntryModules.primitive(value["schema_version"]))
        assertEquals("-7", EntryModules.primitive(value["algorithm"]))
        assertEquals("internal", EntryModules.primitive(value["transports"]))
        assertEquals("", EntryModules.primitive(value["aaguid"]))
        assertEquals("true", EntryModules.primitive(value["discoverable"]))
        assertEquals("true", EntryModules.primitive(value["backup_eligible"]))
        assertEquals("true", EntryModules.primitive(value["backup_state"]))
        assertEquals("synced_zero", EntryModules.primitive(value["counter_mode"]))
        assertEquals("0", EntryModules.primitive(value["sign_count"]))
        assertTrue((module["sensitive"] as JsonPrimitive).content.toBoolean())
    }

    @Test
    fun passkeyNormalizationNeverFillsOrRewritesAnExistingRecord() {
        val existingRecord = JsonObject(
            mapOf(
                "rp_id" to JsonPrimitive("legacy.example"),
                "private_key" to JsonPrimitive("exact-private-key-text"),
                "future_field" to JsonObject(mapOf("revision" to JsonPrimitive(7))),
            )
        )
        val rawModule = JsonObject(
            mapOf(
                "id" to JsonPrimitive("passkey-id"),
                "type" to JsonPrimitive(ModuleType.PASSKEY),
                "sensitive" to JsonPrimitive(false),
                "value" to existingRecord,
            )
        )
        val before = JsonObject(rawModule.toMap())

        val normalized = EntryModules.normalize(JsonArray(listOf(rawModule))).single()

        assertSame(existingRecord, normalized["value"])
        assertEquals(existingRecord, normalized["value"])
        assertFalse("schema_version" in (normalized["value"] as JsonObject))
        assertEquals(before, rawModule)
    }

    @Test
    fun normalizationPreservesUnknownAndRepairsDuplicateIds() {
        val raw = JsonArray(
            listOf(
                JsonObject(mapOf("id" to JsonPrimitive("same"), "type" to JsonPrimitive("future"), "future" to JsonPrimitive(1))),
                JsonObject(mapOf("id" to JsonPrimitive("same"), "type" to JsonPrimitive(ModuleType.TEXT))),
            )
        )
        val out = EntryModules.normalize(raw)
        assertEquals(JsonPrimitive(1), out[0]["future"])
        assertNotEquals(out[0]["id"], out[1]["id"])
    }

    @Test
    fun mandatorySensitivityAndSafeSearch() {
        val password = JsonObject(
            mapOf(
                "type" to JsonPrimitive(ModuleType.PASSWORD),
                "sensitive" to JsonPrimitive(false),
                "value" to JsonPrimitive("never-index"),
            )
        )
        val server = JsonObject(
            mapOf(
                "type" to JsonPrimitive(ModuleType.SERVER_CONNECTION),
                "value" to JsonObject(mapOf("host" to JsonPrimitive("example.internal"), "password" to JsonPrimitive("root-secret"))),
            )
        )
        val entry = Entry(title = "server", secretType = SecretType.SERVER).withEntryModules(listOf(password, server))
        assertTrue((entry.entryModules()[0]["sensitive"] as JsonPrimitive).content.toBoolean())
        assertTrue(entry.matches("example.internal"))
        assertFalse(entry.matches("never-index"))
        assertFalse(entry.matches("root-secret"))

        val passkey = EntryModules.normalize(JsonArray(listOf(JsonObject(mapOf(
            "type" to JsonPrimitive(ModuleType.PASSKEY),
            "sensitive" to JsonPrimitive(false),
        ))))).single()
        assertTrue((passkey["sensitive"] as JsonPrimitive).content.toBoolean())
        assertTrue("private_key" in EntryModules.catalog.getValue(ModuleType.PASSKEY).mandatorySensitiveFields)
    }

    @Test
    fun newCategoryPresets() {
        assertTrue(SecretType.SECURE_NOTE in SecretType.ALL)
        assertTrue(SecretType.PASSKEY in SecretType.ALL)
        assertFalse(SecretType.PASSKEY in SecretType.CREATABLE)
        assertEquals(ModuleType.MULTILINE, EntryModules.primitive(EntryModules.preset(SecretType.SECURE_NOTE)[0]["type"]))
        assertEquals(ModuleType.SERVER_CONNECTION, EntryModules.primitive(EntryModules.preset(SecretType.SERVER)[0]["type"]))
        assertTrue(EntryModules.preset(SecretType.CUSTOM).isEmpty())
    }

    @Test
    fun legacyLoginWithPasskeyModuleMigratesToIndependentType() {
        val legacy = Entry(secretType = SecretType.LOGIN)
            .withEntryModules(listOf(EntryModules.create(ModuleType.PASSKEY)))
        assertEquals(SecretType.PASSKEY, legacy.normalized(1.0).secretType)
    }

    @Test
    fun cardDocumentModuleIncludesCrossPlatformImageCollection() {
        val value = EntryModules.create(ModuleType.CARD_DOCUMENT)["value"] as JsonObject
        assertEquals(JsonArray(emptyList()), value["images"])
        val card = EntryModules.create(ModuleType.CARD_DOCUMENT).let { module ->
            val value = (module["value"] as JsonObject).toMutableMap().also {
                it["bank"] = JsonPrimitive("Example Bank")
                it["images"] = JsonArray(listOf(JsonPrimitive("base64-secret")))
            }
            JsonObject(module.toMutableMap().also { it["value"] = JsonObject(value) })
        }
        assertEquals(listOf("Example Bank"), EntryModules.searchableValues(card))
    }

    @Test
    fun searchableModuleTextHasBoundedTraversal() {
        var nested: kotlinx.serialization.json.JsonElement = JsonPrimitive("too deep")
        repeat(70) { nested = JsonArray(listOf(nested)) }
        val module = JsonObject(mapOf("type" to JsonPrimitive("text"), "value" to nested))
        assertTrue(EntryModules.searchableValues(module).isEmpty())

        val wide = JsonArray(List(1_001) { JsonPrimitive("hidden by size bound") })
        val wideModule = JsonObject(mapOf("type" to JsonPrimitive("text"), "value" to wide))
        assertTrue(EntryModules.searchableValues(wideModule).isEmpty())
        val normal = JsonArray(listOf(JsonPrimitive("visible"), JsonPrimitive(42)))
        val normalModule = JsonObject(mapOf("type" to JsonPrimitive("text"), "value" to normal))
        assertEquals(listOf("visible"), EntryModules.searchableValues(normalModule))
    }

    @Test
    fun removedBankAndIdentityModuleTypesAreNotMapped() {
        listOf("bank_card", "identity_document").forEach { removedType ->
            val raw = JsonObject(mapOf(
                "id" to JsonPrimitive("removed-$removedType"),
                "type" to JsonPrimitive(removedType),
                "sensitive" to JsonPrimitive(false),
                "value" to JsonObject(mapOf("full_name" to JsonPrimitive("测试")))
            ))
            val normalized = EntryModules.normalize(JsonArray(listOf(raw))).single()
            assertEquals(removedType, EntryModules.primitive(normalized["type"]))
        }
    }

    @Test
    fun selectionModulesPersistTheSameDefaultsShownByTheirDropdowns() {
        val wifi = EntryModules.create(ModuleType.WIFI)["value"] as JsonObject
        val database = EntryModules.create(ModuleType.DATABASE)["value"] as JsonObject
        val otp = EntryModules.create(ModuleType.OTP)["value"] as JsonObject

        assertEquals("无加密", EntryModules.primitive(wifi["security_type"]))
        assertEquals("MySQL", EntryModules.primitive(database["engine"]))
        assertEquals("totp", EntryModules.primitive(otp["type"]))
        assertEquals("SHA1", EntryModules.primitive(otp["algorithm"]))
        assertEquals("6", EntryModules.primitive(otp["digits"]))
        assertEquals("30", EntryModules.primitive(otp["period"]))
    }

    @Test
    fun contactValuesUseTextVariantsInsteadOfDedicatedModules() {
        listOf("email", "phone", "postal_code").forEach { removedType ->
            assertFalse(removedType in EntryModules.catalog)
            assertEquals(null, EntryModules.defaultAutofillRole(removedType))
        }
        listOf(AutofillRole.EMAIL, AutofillRole.PHONE, AutofillRole.POSTAL_CODE).forEach { role ->
            val text = EntryModules.withAutofillRole(EntryModules.create(ModuleType.TEXT), role)
            assertEquals(ModuleType.TEXT, EntryModules.primitive(text["type"]))
            assertEquals(role, EntryModules.configuredAutofillRole(text))
        }
    }

    @Test
    fun customAutofillRoleOptionsAreStableAndExcludedKindsHaveNone() {
        val nonSensitiveText = AutofillRole.entries.filterNot { it.minimumRequiresVerification }.map { it.wire }
        val password = listOf(
            "password", "card_cvv", "id_number", "api_key", "api_secret",
            "wifi_password", "recovery_answer", "custom_secret",
        )
        assertEquals(nonSensitiveText, EntryModules.autofillRoleOptions(ModuleType.TEXT).map { it.wire })
        assertEquals(AutofillRole.entries.map { it.wire }, EntryModules.autofillRoleOptions(ModuleType.TEXT, sensitive = true).map { it.wire })
        assertEquals(password, EntryModules.autofillRoleOptions(ModuleType.PASSWORD).map { it.wire })
        assertEquals(listOf("card_expiry", "custom_text"), EntryModules.autofillRoleOptions(ModuleType.DATETIME).map { it.wire })
        listOf(
            ModuleType.MULTILINE, ModuleType.BOOLEAN, ModuleType.IMAGES, ModuleType.ATTACHMENTS,
            ModuleType.PASSKEY, ModuleType.OTP, ModuleType.SSH,
            "email", "phone", "postal_code",
        ).forEach { assertTrue(EntryModules.autofillRoleOptions(it).isEmpty()) }
    }

    @Test
    fun removedContactModuleStaysOpaqueWhileAddressPostalCodeRemainsSupported() {
        val raw = JsonObject(mapOf(
            "id" to JsonPrimitive("postal001"),
            "type" to JsonPrimitive("postal_code"),
            "title" to JsonPrimitive("邮编"),
            "sensitive" to JsonPrimitive(false),
            "required" to JsonPrimitive(false),
            "config" to JsonObject(mapOf("future" to JsonPrimitive("keep"))),
            "value" to JsonPrimitive("100000"),
        ))

        val normalized = EntryModules.normalize(JsonArray(listOf(raw))).single()
        assertEquals("postal_code", EntryModules.primitive(normalized["type"]))
        assertEquals("邮编", EntryModules.primitive(normalized["title"]))
        assertEquals("100000", EntryModules.primitive(normalized["value"]))
        assertEquals("keep", EntryModules.primitive((normalized["config"] as JsonObject)["future"]))
        assertEquals(null, EntryModules.defaultAutofillRole("postal_code"))

        val address = EntryModules.create(ModuleType.ADDRESS)
        val value = address["value"] as JsonObject
        assertTrue("postal_code" in value)
    }

    @Test
    fun customAutofillRoleConfigRoundTripsAndUnknownValuesStayOpaque() {
        val raw = JsonObject(
            EntryModules.create(ModuleType.TEXT).toMutableMap().also {
                it["config"] = JsonObject(mapOf(
                    "autofill_role" to JsonPrimitive("future_role"),
                    "futureConfig" to JsonPrimitive(7),
                ))
            },
        )
        val normalized = EntryModules.normalize(JsonArray(listOf(raw))).single()
        val config = normalized["config"] as JsonObject
        assertEquals("future_role", EntryModules.primitive(config["autofill_role"]))
        assertEquals("7", EntryModules.primitive(config["futureConfig"]))
        assertEquals(null, EntryModules.configuredAutofillRole(normalized))

        val selected = EntryModules.withAutofillRole(normalized, AutofillRole.EMAIL)
        assertEquals(AutofillRole.EMAIL, EntryModules.configuredAutofillRole(selected))
        assertEquals("7", EntryModules.primitive((selected["config"] as JsonObject)["futureConfig"]))
        val cleared = EntryModules.withAutofillRole(selected, null)
        assertFalse("autofill_role" in (cleared["config"] as JsonObject))
    }

    @Test
    fun attachmentModuleIsSensitiveAndCrossPlatformSerializable() {
        val attachment = EntryModules.create(ModuleType.ATTACHMENTS)
        assertTrue((attachment["sensitive"] as JsonPrimitive).content.toBoolean())
        assertEquals(JsonArray(emptyList()), attachment["value"])
        assertTrue(EntryModules.searchableValues(attachment).isEmpty())
    }

    @Test
    fun targetAppFallsBackToReusableModule() {
        val module = EntryModules.create(ModuleType.TARGET_APP).let {
            JsonObject(it.toMutableMap().also { values -> values["value"] = JsonPrimitive("com.example.android") })
        }
        assertEquals("com.example.android", Entry().withEntryModules(listOf(module)).associatedAppPackage())
        assertEquals("com.top.level", Entry(targetApp = "com.top.level").withEntryModules(listOf(module)).associatedAppPackage())
    }

@Test
    fun detailModulesKeepAttachmentsAndOnlyConsumeThePrimarySpecializedModule() {
        mapOf(
            SecretType.OTP to ModuleType.OTP,
            SecretType.SECURE_NOTE to ModuleType.MULTILINE,
            SecretType.SERVER to ModuleType.SERVER_CONNECTION,
        ).forEach { (secretType, primaryType) ->
            val entry = Entry(secretType = secretType).withEntryModules(listOf(
                EntryModules.create(primaryType),
                EntryModules.create(ModuleType.ATTACHMENTS),
                EntryModules.create(primaryType),
            ))
            assertEquals(
                listOf(ModuleType.ATTACHMENTS, primaryType),
                entry.detailModules().map { EntryModules.primitive(it["type"]) },
            )
        }
    }

    @Test
    fun detailModulesForLoginSkipBothTargetAppAndOtp() {
        // LOGIN 的 OTP 模块由详情页专用区域渲染（不暴露密钥），因此与 TARGET_APP 一样被跳过。
        val entry = Entry(secretType = SecretType.LOGIN).withEntryModules(listOf(
            EntryModules.create(ModuleType.TARGET_APP),
            EntryModules.create(ModuleType.OTP),
            EntryModules.create(ModuleType.ATTACHMENTS),
            EntryModules.create(ModuleType.OTP),
        ))
        assertEquals(
            listOf(ModuleType.ATTACHMENTS, ModuleType.OTP),
            entry.detailModules().map { EntryModules.primitive(it["type"]) },
        )
    }
}
