package com.vault.ui

import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.autofill.AutofillRole
import com.vault.model.withAutofillLinks
import com.vault.ui.screens.linkedAutofillDetailGroups
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EntryDetailAutofillGroupsTest {
    @Test
    fun groupsAllLinkedRolesBySourceAndKeepsUnavailableSourcesVisible() {
        val card = Entry(id = "card", title = "工资卡", secretType = SecretType.CARD_DOCUMENT)
        val login = Entry(id = "login", secretType = SecretType.LOGIN).withAutofillLinks(
            listOf(
                AutofillLink(
                    id = "card-main",
                    sourceEntryId = card.id,
                    fields = listOf(
                        AutofillFieldRef(null, "card_number", AutofillRole.CARD_NUMBER, false),
                        AutofillFieldRef(null, "expiry", AutofillRole.CARD_EXPIRY, false),
                    ),
                ),
                AutofillLink(
                    id = "card-extra",
                    sourceEntryId = card.id,
                    fields = listOf(
                        AutofillFieldRef(null, "cvv", AutofillRole.CARD_CVV, true),
                        AutofillFieldRef(null, "expiry", AutofillRole.CARD_EXPIRY, false),
                    ),
                ),
                AutofillLink(
                    id = "missing",
                    sourceEntryId = "deleted-source",
                    fields = listOf(
                        AutofillFieldRef(null, "value", AutofillRole.CUSTOM_TEXT, false),
                    ),
                ),
            ),
        )

        val groups = linkedAutofillDetailGroups(login, listOf(card))

        assertEquals(2, groups.size)
        assertEquals(card, groups[0].source)
        assertEquals(
            listOf(AutofillRole.CARD_NUMBER, AutofillRole.CARD_EXPIRY, AutofillRole.CARD_CVV),
            groups[0].roles,
        )
        assertEquals("deleted-source", groups[1].sourceEntryId)
        assertNull(groups[1].source)
        assertEquals(listOf(AutofillRole.CUSTOM_TEXT), groups[1].roles)
    }
}
