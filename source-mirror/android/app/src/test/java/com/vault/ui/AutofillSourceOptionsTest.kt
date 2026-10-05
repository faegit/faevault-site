package com.vault.ui

import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class AutofillSourceOptionsTest {
    @Test
    fun editPickerReceivesRevealedLiveEntriesInsteadOfRedactedListMetadata() {
        val redactedCard = Entry(
            id = "card",
            title = "工资卡",
            secretType = SecretType.CARD_DOCUMENT,
            fields = emptyMap(),
        )
        val revealedCard = redactedCard.copy(
            fields = mapOf("card_number" to JsonPrimitive("4111111111111111")),
        )
        val currentLogin = Entry(id = "login", secretType = SecretType.LOGIN)
        val deleted = Entry(id = "deleted", secretType = SecretType.OTP, deletedAt = 1.0)

        val result = autofillSourceEntries(
            entries = listOf(redactedCard, currentLogin, deleted),
            currentEntryId = currentLogin.id,
            revealEntry = { id -> revealedCard.takeIf { id == revealedCard.id } },
        )

        assertEquals(listOf(revealedCard), result)
    }
}
