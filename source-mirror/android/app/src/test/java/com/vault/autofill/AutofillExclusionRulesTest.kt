package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AutofillExclusionRulesTest {
    @Test fun fullUrlAndOriginMatchTheSameStoredHost() {
        assertEquals("login.example.com", normalizeExcludedHost(" https://LOGIN.Example.com:443/signin?q=1 "))
        assertEquals("login.example.com", normalizeExcludedHost("login.example.com."))
        assertEquals("login.example.com", normalizeExcludedHost("login.example.com/signin"))
    }
    @Test fun malformedInputsCannotCreateMisleadingExclusions() {
        assertNull(normalizeExcludedHost(""))
        assertNull(normalizeExcludedHost("not a host"))
        assertNull(normalizeExcludedHost("file:///etc/hosts"))
        assertNull(normalizeExcludedHost("https://example.com@attacker.com"))
    }
    @Test fun matchingDoesNotExpandToOtherSites() {
        assertEquals("sub.example.com", normalizeExcludedHost("sub.example.com"))
        assertEquals("example.com.attacker.com", normalizeExcludedHost("example.com.attacker.com"))
    }
}
