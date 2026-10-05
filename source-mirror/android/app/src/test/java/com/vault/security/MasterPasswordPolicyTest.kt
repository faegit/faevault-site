package com.vault.security

import com.vault.ui.InputFilters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MasterPasswordPolicyTest {
    private val commonPasswords = setOf("password", "summer", "123456")

    private fun assess(password: String) = MasterPasswordPolicy.assess(password) { candidate ->
        candidate in commonPasswords
    }

    @Test
    fun `six digit and short random passwords are blocked`() {
        assertEquals(MasterPasswordRisk.BLOCKED, assess("123456").risk)
        assertEquals(MasterPasswordRisk.BLOCKED, assess("aB3\$zQ").risk)
    }

    @Test
    fun `common password transformations are blocked without substring matching`() {
        assertEquals(MasterPasswordRisk.BLOCKED, assess("Password1!").risk)
        assertEquals(MasterPasswordRisk.BLOCKED, assess("Summer2026!").risk)
        assertEquals(MasterPasswordRisk.STRONG, assess("summer-orbit-cobalt-lantern-meadow").risk)
    }

    @Test
    fun `weak password needs an explicit standard-mode override`() {
        val result = assess("aB3\$zQ7!")

        assertEquals(MasterPasswordRisk.WEAK, result.risk)
        assertFalse(result.permits(highSecurityMode = true, weakPasswordConfirmed = true))
        assertFalse(result.permits(highSecurityMode = false, weakPasswordConfirmed = false))
        assertTrue(result.permits(highSecurityMode = false, weakPasswordConfirmed = true))
    }

    @Test
    fun `random passwords and long passphrases meet the recommendation`() {
        assertEquals(MasterPasswordRisk.STRONG, assess("V7!qL2#nP9@x").risk)
        assertEquals(
            MasterPasswordRisk.STRONG,
            assess("orbit cedar cobalt lantern meadow").risk,
        )
    }

    @Test
    fun `repeated words and repeated-character pseudo passphrases are blocked`() {
        assertEquals(MasterPasswordRisk.BLOCKED, assess("alpha alpha alpha alpha alpha").risk)
        assertEquals(MasterPasswordRisk.BLOCKED, assess("aaaa bbbb cccc dddd eeee").risk)
    }

    @Test
    fun `android input preserves passphrase spaces but removes unstable characters`() {
        assertEquals("orbit cedar", InputFilters.asciiPrintable("orbit cedar\n密"))
    }
}
