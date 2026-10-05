package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SaveCandidateExtractorTest {
    private val origin = TargetOrigin.Web("example.com")

    @Test
    fun combinesUsernameAndPasswordAcrossLoginSteps() {
        val usernameStep = form(
            ClassifiedField("username", FieldKind.USERNAME, 100, false, "alice@example.com"),
        )
        val passwordStep = form(
            ClassifiedField("password", FieldKind.PASSWORD, 100, true, "secret"),
        )

        val (_, candidate) = SaveCandidateExtractor.extract(listOf(usernameStep, passwordStep))!!

        assertEquals("alice@example.com", candidate.username)
        assertEquals("secret", candidate.password)
    }

    @Test
    fun usesLatestNonEmptyValuesAndKeepsPasswordConfirmation() {
        val old = form(
            ClassifiedField("username", FieldKind.USERNAME, 100, false, "old"),
        )
        val latest = form(
            ClassifiedField("username", FieldKind.USERNAME, 100, false, "new"),
            ClassifiedField("new", FieldKind.NEW_PASSWORD, 100, false, "secret"),
            ClassifiedField("confirm", FieldKind.NEW_PASSWORD, 100, false, "secret"),
        )

        val (_, candidate) = SaveCandidateExtractor.extract(listOf(old, latest))!!

        assertEquals("new", candidate.username)
        assertEquals("secret", candidate.newPassword)
        assertEquals("secret", candidate.confirmationPassword)
    }

    @Test
    fun keepsPasswordContextButDoesNotMixUsernameFromDifferentOrigin() {
        val first = form(ClassifiedField("u", FieldKind.USERNAME, 100, false, "alice"))
        val second = form(ClassifiedField("p", FieldKind.PASSWORD, 100, false, "secret")).copy(
            origin = TargetOrigin.Web("other.example"),
        )

        val (selected, candidate) = SaveCandidateExtractor.extract(listOf(first, second))!!

        assertEquals(TargetOrigin.Web("other.example"), selected.origin)
        assertNull(candidate.username)
        assertEquals("secret", candidate.password)
    }

    @Test
    fun ignoresPostLoginRedirectAfterLastPasswordContext() {
        val login = form(
            ClassifiedField("u", FieldKind.USERNAME, 100, false, "alice"),
            ClassifiedField("p", FieldKind.PASSWORD, 100, false, "secret"),
        )
        val redirected = form().copy(origin = TargetOrigin.Web("account.example.com"))

        val (selected, candidate) = SaveCandidateExtractor.extract(listOf(login, redirected))!!

        assertEquals(origin, selected.origin)
        assertEquals("alice", candidate.username)
        assertEquals("secret", candidate.password)
    }

    private fun form(vararg fields: ClassifiedField<String>) = ParsedForm(
        origin = origin,
        fields = fields.toList(),
        packageName = "com.android.chrome",
    )
}
