package com.vault.ui

import com.vault.autofill.ResolvedAutofillValue
import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.Entry
import com.vault.model.autofill.AutofillRole
import com.vault.ui.screens.removeAutofillRole
import com.vault.ui.screens.replaceAutofillEntry
import com.vault.ui.screens.replaceAutofillRole
import com.vault.ui.screens.autofillLinkCategoryTypes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillLinkUiTest {
    @Test
    fun acceptingConflictReplacesOnlyTheSelectedRoleAndRemembersIt() {
        val existing = listOf(
            AutofillLink(
                "old",
                "old-source",
                listOf(
                    AutofillFieldRef("old-email", "value", AutofillRole.EMAIL, false),
                    AutofillFieldRef(null, "username", AutofillRole.USERNAME, false),
                ),
            ),
        )
        val source = Entry(id = "new-source", title = "Contact")
        val value = ResolvedAutofillValue(
            AutofillRole.EMAIL,
            "new@example.com",
            source.id,
            "new-email",
            "value",
            false,
        )

        val replaced = replaceAutofillRole(existing, source, value)

        assertEquals(1, replaced.flatMap(AutofillLink::fields).count { it.role == AutofillRole.EMAIL })
        assertEquals("new-source", replaced.single { it.fields.any { field -> field.role == AutofillRole.EMAIL } }.sourceEntryId)
        assertTrue(replaced.flatMap(AutofillLink::fields).any { it.role == AutofillRole.USERNAME })
    }

    @Test
    fun keepingCurrentLeavesLinksUnchangedAndRemovingRoleKeepsSiblings() {
        val links = listOf(
            AutofillLink(
                "same",
                "source",
                listOf(
                    AutofillFieldRef("email", "value", AutofillRole.EMAIL, false),
                    AutofillFieldRef("phone", "value", AutofillRole.PHONE, false),
                ),
            ),
        )

        assertEquals(links, links)
        val removed = removeAutofillRole(links, AutofillRole.EMAIL)
        assertEquals(listOf(AutofillRole.PHONE), removed.flatMap(AutofillLink::fields).map(AutofillFieldRef::role))
    }

    @Test
    fun selectingAnEntryLinksEveryUniqueFillableRoleAndPreservesUnrelatedRoles() {
        val existing = listOf(
            AutofillLink(
                "old",
                "old-source",
                listOf(
                    AutofillFieldRef(null, "username", AutofillRole.USERNAME, false),
                    AutofillFieldRef("phone", "value", AutofillRole.PHONE, false),
                ),
            ),
        )
        val source = Entry(id = "card", title = "Bank card")
        val values = listOf(
            ResolvedAutofillValue(AutofillRole.CARDHOLDER, "Alice", source.id, "card-module", "cardholder", false),
            ResolvedAutofillValue(AutofillRole.CARD_NUMBER, "4111", source.id, "card-module", "card_number", true),
            ResolvedAutofillValue(AutofillRole.CARD_NUMBER, "duplicate", source.id, "other", "card_number", true),
        )

        val replaced = replaceAutofillEntry(existing, source, values)

        val linkedCard = replaced.single { it.sourceEntryId == source.id }
        assertEquals(listOf(AutofillRole.CARDHOLDER, AutofillRole.CARD_NUMBER), linkedCard.fields.map(AutofillFieldRef::role))
        assertTrue(replaced.flatMap(AutofillLink::fields).any { it.role == AutofillRole.USERNAME })
        assertTrue(replaced.flatMap(AutofillLink::fields).any { it.role == AutofillRole.PHONE })
    }

    @Test
    fun categoryPickerUsesHomeOrderAndExcludesLoginAndPasskeys() {
        val order = listOf("otp", "passkey", "login", "card_document", "custom")

        assertEquals(listOf("otp", "card_document", "custom"), autofillLinkCategoryTypes(order))
    }
}
