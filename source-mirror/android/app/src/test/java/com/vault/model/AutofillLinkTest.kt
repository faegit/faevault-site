package com.vault.model

import com.vault.model.autofill.AutofillRole
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillLinkTest {
    @Test
    fun legacyOtpBindingMigratesWithoutImplicitRecursion() {
        val original = Entry(fields = mapOf(OTP_BINDING_KEY to JsonPrimitive("otp-entry")))

        assertEquals(emptyList<AutofillLink>(), original.autofillLinks())
        assertTrue(OTP_BINDING_KEY in original.fields)

        val migrated = original.migrateAutofillLinks()
        val field = migrated.autofillLinks().single().fields.single()
        assertEquals("otp-entry", migrated.autofillLinks().single().sourceEntryId)
        assertEquals(null, field.moduleId)
        assertEquals("@computed/one_time_code", field.sourceKey)
        assertEquals(AutofillRole.ONE_TIME_CODE, field.role)
        assertFalse(field.requiresVerification)
        assertFalse(OTP_BINDING_KEY in migrated.fields)
        assertEquals(migrated, migrated.migrateAutofillLinks())
    }

    @Test
    fun malformedLinkDoesNotDiscardValidSibling() {
        val valid = AutofillLink(
            id = "link-1",
            sourceEntryId = "contact-1",
            fields = listOf(AutofillFieldRef(null, "value", AutofillRole.EMAIL, false)),
        )
        val raw = JsonArray(
            listOf(
                JsonPrimitive("broken"),
                JsonObject(
                    mapOf(
                        "id" to JsonPrimitive("also-broken"),
                        "source_entry_id" to JsonPrimitive(7),
                        "fields" to JsonPrimitive("invalid"),
                    ),
                ),
                AutofillLinkCodec.encode(listOf(valid)).single(),
            ),
        )

        assertEquals(listOf(valid), AutofillLinkCodec.decode(raw))
    }

    @Test
    fun invalidLinksAndFieldReferencesAreDiscardedIndependently() {
        val raw = JsonArray(
            listOf(
                linkJson("", "source-blank-id", listOf(refJson(null, "value", "email", false))),
                linkJson("blank-source", " ", listOf(refJson(null, "value", "email", false))),
                linkJson(
                    "mixed-fields",
                    "source-1",
                    listOf(
                        JsonPrimitive("not-an-object"),
                        refJson(null, "", "email", false),
                        refJson(null, "value", "unknown", false),
                        refJson(JsonPrimitive(4), "value", "email", false),
                        refJson(null, "value", "email", JsonPrimitive("false")),
                        JsonObject(
                            mapOf(
                                "source_key" to JsonPrimitive("value"),
                                "role" to JsonPrimitive("email"),
                            ),
                        ),
                        JsonObject(
                            refJson(null, "value", "email", false) +
                                ("future" to JsonPrimitive("ignored")),
                        ),
                    ),
                ),
                linkJson("no-valid-fields", "source-2", listOf(refJson(null, "", "email", false))),
            ),
        )

        assertEquals(
            listOf(
                AutofillLink(
                    "mixed-fields",
                    "source-1",
                    listOf(AutofillFieldRef(null, "value", AutofillRole.EMAIL, false)),
                ),
            ),
            AutofillLinkCodec.decode(raw),
        )
    }

    @Test
    fun blankModuleIdDropsOnlyThatFieldReference() {
        val raw = JsonArray(
            listOf(
                linkJson(
                    "link",
                    "source",
                    listOf(
                        refJson(JsonPrimitive(" \t"), "value", "email", false),
                        refJson(null, "value", "phone", false),
                    ),
                ),
            ),
        )

        assertEquals(
            listOf(AutofillFieldRef(null, "value", AutofillRole.PHONE, false)),
            AutofillLinkCodec.decode(raw).single().fields,
        )
    }

    @Test
    fun missingRequiresVerificationDropsOnlyThatFieldReference() {
        val raw = JsonArray(
            listOf(
                linkJson(
                    "link",
                    "source",
                    listOf(
                        JsonObject(refJson(null, "value", "email", false) - "requires_verification"),
                        refJson(null, "value", "phone", false),
                    ),
                ),
            ),
        )

        assertEquals(
            listOf(AutofillFieldRef(null, "value", AutofillRole.PHONE, false)),
            AutofillLinkCodec.decode(raw).single().fields,
        )
    }

    @Test
    fun duplicateIdsAreRegeneratedWithoutChangingLinkOrderOrContents() {
        val raw = JsonArray(
            listOf(
                linkJson("duplicate", "source-1", listOf(refJson(null, "username", "username", false))),
                linkJson("other", "source-2", listOf(refJson(null, "value", "email", false))),
                linkJson("duplicate", "source-3", listOf(refJson(null, "value", "phone", false))),
                linkJson("duplicate", "source-4", listOf(refJson(null, "postal_code", "postal_code", false))),
            ),
        )

        val decoded = AutofillLinkCodec.decode(raw)
        assertEquals(listOf("source-1", "source-2", "source-3", "source-4"), decoded.map { it.sourceEntryId })
        assertEquals("duplicate", decoded.first().id)
        assertEquals(decoded.size, decoded.map { it.id }.toSet().size)
        assertNotEquals("duplicate", decoded[2].id)
        assertNotEquals("duplicate", decoded[3].id)
        assertEquals(listOf(AutofillRole.USERNAME, AutofillRole.EMAIL, AutofillRole.PHONE, AutofillRole.POSTAL_CODE), decoded.map { it.fields.single().role })
    }

    @Test
    fun duplicateIdRepairIsDeterministicAcrossIndependentDecodes() {
        val raw = JsonArray(
            listOf(
                linkJson("duplicate", "source-1", listOf(refJson(null, "value", "email", false))),
                linkJson("other", "source-2", listOf(refJson(null, "value", "phone", false))),
                linkJson("duplicate", "source-3", listOf(refJson(null, "postal_code", "postal_code", false))),
                linkJson("duplicate", "source-4", listOf(refJson(null, "username", "username", false))),
            ),
        )

        val first = AutofillLinkCodec.decode(raw)
        val second = AutofillLinkCodec.decode(raw)

        assertEquals(first, second)
        assertEquals(first.size, first.map { it.id }.toSet().size)
        assertEquals(listOf("source-1", "source-2", "source-3", "source-4"), first.map { it.sourceEntryId })
        assertEquals("duplicate", first.first().id)
    }

    @Test
    fun sensitiveRolesCannotDisableRuntimeVerification() {
        val sensitiveRoles = AutofillRole.entries.filter(AutofillRole::minimumRequiresVerification)
        val fields = sensitiveRoles.map { refJson(null, "source-${it.wire}", it.wire, false) } +
            refJson(null, "safe", AutofillRole.EMAIL.wire, false)

        val decoded = AutofillLinkCodec.decode(JsonArray(listOf(linkJson("link", "source", fields))))
            .single()
            .fields

        assertTrue(decoded.dropLast(1).all { it.requiresVerification })
        assertFalse(decoded.last().requiresVerification)
    }

    @Test
    fun encodeDecodeRoundTripWritesExplicitNullModuleId() {
        val links = listOf(
            AutofillLink(
                id = "link-1",
                sourceEntryId = "source-1",
                fields = listOf(
                    AutofillFieldRef(null, "value", AutofillRole.EMAIL, false),
                    AutofillFieldRef("phone-module", "value", AutofillRole.PHONE, false),
                ),
            ),
        )

        val encoded = AutofillLinkCodec.encode(links)
        val encodedFields = encoded.single().jsonObject.getValue("fields").jsonArray
        assertEquals(JsonNull, encodedFields.first().jsonObject["module_id"])
        assertEquals("phone-module", encodedFields.last().jsonObject.getValue("module_id").let { (it as JsonPrimitive).content })
        assertEquals(links, AutofillLinkCodec.decode(encoded))
    }

    @Test
    fun publicEncodeNormalizesMalformedInMemoryLinks() {
        val validEmail = AutofillFieldRef(null, "value", AutofillRole.EMAIL, false)
        val links = listOf(
            AutofillLink(" ", "source-blank-id", listOf(validEmail)),
            AutofillLink("blank-source", "\t", listOf(validEmail)),
            AutofillLink(
                "mixed",
                "source-mixed",
                listOf(
                    AutofillFieldRef(null, " ", AutofillRole.EMAIL, false),
                    validEmail,
                ),
            ),
            AutofillLink("empty", "source-empty", emptyList()),
            AutofillLink("duplicate", "source-first", listOf(validEmail)),
            AutofillLink(
                "duplicate",
                "source-second",
                listOf(AutofillFieldRef(null, "value", AutofillRole.PHONE, false)),
            ),
        )

        val encoded = AutofillLinkCodec.encode(links)
        val decoded = AutofillLinkCodec.decode(encoded)

        assertEquals(3, encoded.size)
        assertEquals(listOf("source-mixed", "source-first", "source-second"), decoded.map { it.sourceEntryId })
        assertEquals(listOf(validEmail), decoded.first().fields)
        assertEquals(decoded.size, decoded.map { it.id }.toSet().size)
        assertEquals(decoded, AutofillLinkCodec.decode(encoded))
    }

    @Test
    fun withAutofillLinksPreservesUnrelatedFieldsAndStoresNormalizedLinks() {
        val unrelated = JsonObject(mapOf("nested" to JsonPrimitive("keep")))
        val original = Entry(
            fields = mapOf(
                "unrelated" to unrelated,
                OTP_BINDING_KEY to JsonPrimitive("legacy"),
                AUTOFILL_LINKS_KEY to JsonPrimitive("malformed"),
            ),
        )
        val links = listOf(
            AutofillLink(
                "same-id",
                "source-1",
                listOf(AutofillFieldRef(null, "password", AutofillRole.PASSWORD, false)),
            ),
            AutofillLink(
                "same-id",
                "source-2",
                listOf(AutofillFieldRef(null, "value", AutofillRole.EMAIL, false)),
            ),
            AutofillLink("invalid", "source-3", emptyList()),
        )

        val updated = original.withAutofillLinks(links)
        assertEquals(unrelated, updated.fields["unrelated"])
        assertFalse(OTP_BINDING_KEY in updated.fields)
        assertEquals(2, updated.autofillLinks().size)
        assertEquals(2, updated.autofillLinks().map { it.id }.toSet().size)
        assertTrue(updated.autofillLinks().first().fields.single().requiresVerification)

        val cleared = updated.withAutofillLinks(emptyList())
        assertEquals(mapOf("unrelated" to unrelated), cleared.fields)
        assertFalse(AUTOFILL_LINKS_KEY in cleared.fields)
    }

    @Test
    fun migrationKeepsExistingLinksAndDoesNotDuplicateEquivalentOtpLink() {
        val emailLink = AutofillLink(
            "email-link",
            "contact-entry",
            listOf(AutofillFieldRef("email-module", "value", AutofillRole.EMAIL, false)),
        )
        val equivalent = AutofillLink(
            "otp-link",
            "otp-entry",
            listOf(AutofillFieldRef(null, "@computed/one_time_code", AutofillRole.ONE_TIME_CODE, false)),
        )
        val entry = Entry(
            fields = mapOf(
                "unrelated" to JsonPrimitive("keep"),
                OTP_BINDING_KEY to JsonPrimitive("otp-entry"),
                AUTOFILL_LINKS_KEY to AutofillLinkCodec.encode(listOf(emailLink, equivalent)),
            ),
        )

        val migrated = entry.migrateAutofillLinks()
        assertEquals(listOf(emailLink, equivalent), migrated.autofillLinks())
        assertEquals(JsonPrimitive("keep"), migrated.fields["unrelated"])
        assertFalse(OTP_BINDING_KEY in migrated.fields)
        assertEquals(migrated, migrated.migrateAutofillLinks())
    }

    @Test
    fun moduleScopedComputedOtpRefDoesNotBlockTopLevelLegacyMigration() {
        val moduleScoped = AutofillLink(
            "module-otp-link",
            "otp-entry",
            listOf(
                AutofillFieldRef(
                    "otp-module",
                    "@computed/one_time_code",
                    AutofillRole.ONE_TIME_CODE,
                    false,
                ),
            ),
        )
        val entry = Entry(
            fields = mapOf(
                OTP_BINDING_KEY to JsonPrimitive("otp-entry"),
                AUTOFILL_LINKS_KEY to AutofillLinkCodec.encode(listOf(moduleScoped)),
            ),
        )

        val migrated = entry.migrateAutofillLinks()

        assertEquals(2, migrated.autofillLinks().size)
        assertEquals(listOf("otp-module", null), migrated.autofillLinks().map { it.fields.single().moduleId })
        assertFalse(OTP_BINDING_KEY in migrated.fields)
        assertEquals(migrated, migrated.migrateAutofillLinks())
    }

    @Test
    fun malformedExistingLinksDoNotBlockLegacyMigration() {
        val existing = AutofillLink(
            "email-link",
            "contact-entry",
            listOf(AutofillFieldRef(null, "value", AutofillRole.EMAIL, false)),
        )
        val entry = Entry(
            fields = mapOf(
                OTP_BINDING_KEY to JsonPrimitive("otp-entry"),
                AUTOFILL_LINKS_KEY to JsonArray(
                    listOf(
                        JsonPrimitive("broken"),
                        AutofillLinkCodec.encode(listOf(existing)).single(),
                    ),
                ),
                "unrelated" to JsonPrimitive(42),
            ),
        )

        val migrated = entry.migrateAutofillLinks()
        assertEquals(listOf("contact-entry", "otp-entry"), migrated.autofillLinks().map { it.sourceEntryId })
        assertEquals(JsonPrimitive(42), migrated.fields["unrelated"])
        assertFalse(OTP_BINDING_KEY in migrated.fields)
    }

    private fun linkJson(id: String, sourceEntryId: String, fields: List<kotlinx.serialization.json.JsonElement>): JsonObject =
        JsonObject(
            mapOf(
                "id" to JsonPrimitive(id),
                "source_entry_id" to JsonPrimitive(sourceEntryId),
                "fields" to JsonArray(fields),
            ),
        )

    private fun refJson(
        moduleId: JsonPrimitive?,
        sourceKey: String,
        role: String,
        requiresVerification: Any,
    ): JsonObject = JsonObject(
        mapOf(
            "module_id" to (moduleId ?: JsonNull),
            "source_key" to JsonPrimitive(sourceKey),
            "role" to JsonPrimitive(role),
            "requires_verification" to when (requiresVerification) {
                is Boolean -> JsonPrimitive(requiresVerification)
                is JsonPrimitive -> requiresVerification
                else -> error("unsupported test value")
            },
        ),
    )
}
