package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SaveRequestEnvelopeTest {
    @Test
    fun saveRequestSurvivesProcessLocalStoreLoss() {
        val request = PendingAutofillRequest.Save(
            form = ParsedForm(
                origin = TargetOrigin.AndroidPackage(
                    packageName = "com.example.app",
                    signingCertificateSha256 = setOf("bb", "aa"),
                ),
                fields = emptyList(),
                packageName = "com.example.app",
            ),
            candidate = SaveCandidate(
                username = "alice@example.com",
                password = "old-secret",
                newPassword = "new-secret",
                confirmationPassword = "new-secret",
            ),
        )

        val encoded = SaveRequestEnvelope.encode(request)

        AutofillRequestStore.clear() // Simulate Android killing and recreating the Vault process.

        val restored = requireNotNull(SaveRequestEnvelope.decode(encoded))

        assertEquals(request.form, restored.form)
        assertEquals(request.candidate, restored.candidate)
        assertTrue(AutofillRequestStore.peek("missing-after-process-death") == null)
    }

    @Test
    fun webOriginRoundTripsWithoutLosingBrowserIdentity() {
        val request = PendingAutofillRequest.Save(
            form = ParsedForm(
                origin = TargetOrigin.Web(
                    host = "login.example.com",
                    browserPackageName = "com.example.browser",
                    browserSigningCertificateSha256 = setOf("cc"),
                ),
                fields = emptyList(),
                packageName = "com.example.browser",
            ),
            candidate = SaveCandidate(username = null, password = "secret"),
        )

        assertEquals(request, SaveRequestEnvelope.from(request).toRequest())
    }

    @Test
    fun malformedSystemPayloadIsRejectedInsteadOfOpeningAnEmptySaveWindow() {
        assertNull(SaveRequestEnvelope.decode("{not-json"))
    }
}
