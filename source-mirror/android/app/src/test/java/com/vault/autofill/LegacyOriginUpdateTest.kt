package com.vault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LegacyOriginUpdateTest {
    @Test fun `automatic update only accepts exact authenticated origin`() {
        assertTrue(mayAutoApplySavedCredentialUpdate(OriginMatchLevel.EXACT))
        assertFalse(mayAutoApplySavedCredentialUpdate(OriginMatchLevel.LEGACY_PACKAGE))
        assertFalse(mayAutoApplySavedCredentialUpdate(OriginMatchLevel.PARENT_DOMAIN))
        assertFalse(mayAutoApplySavedCredentialUpdate(OriginMatchLevel.NONE))
    }
}
