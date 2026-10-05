package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SavePolicyTest {
    private val origin = TargetOrigin.Web("example.com")

    @Test
    fun rejectsEmptyAndMismatchedPasswords() {
        assertTrue(SavePolicy.decide(SaveCandidate("u", ""), origin, emptyList(), null) is SaveDecision.Reject)
        assertTrue(
            SavePolicy.decide(
                SaveCandidate("u", password = null, newPassword = "one", confirmationPassword = "two"),
                origin,
                emptyList(),
                null,
            ) is SaveDecision.Reject,
        )
    }

    @Test
    fun acceptsMatchingNewPasswordAsCreate() {
        val result = SavePolicy.decide(
            SaveCandidate("u", password = null, newPassword = "new", confirmationPassword = "new"),
            origin,
            emptyList(),
            null,
        )

        assertEquals(SaveDecision.Create("u", "new"), result)
    }

    @Test
    fun marksUnchangedExistingCredentialForImmediateClose() {
        val result = SavePolicy.decide(
            SaveCandidate("u", "pw"),
            origin,
            listOf("entry"),
            ExistingCredential("u", "pw"),
        )

        assertEquals(SaveDecision.Unchanged, result)
    }

    @Test
    fun requiresUpdateChoiceForChangedExactMatch() {
        val result = SavePolicy.decide(
            SaveCandidate("u", "new"),
            origin,
            listOf("one", "two"),
            ExistingCredential("u", "old"),
        )

        assertEquals(SaveDecision.UpdateChoice("u", "new", listOf("one", "two")), result)
    }
}
