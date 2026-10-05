package com.vault.security

import org.junit.Assert.assertEquals
import org.junit.Test

class SecurePreferencesTest {
    @Test
    fun `fresh install accepts legacy plaintext exactly once`() {
        assertEquals(
            SecurePreferences.MigrationDecision.MIGRATE_PLAINTEXT,
            SecurePreferences.migrationDecision(false, mapOf("theme" to "dark")),
        )
    }

    @Test
    fun `plaintext cannot return after protected migration marker exists`() {
        assertEquals(
            SecurePreferences.MigrationDecision.REJECT,
            SecurePreferences.migrationDecision(true, mapOf("theme" to "dark")),
        )
    }

    @Test
    fun `deleting encrypted marker cannot reopen plaintext migration`() {
        assertEquals(
            SecurePreferences.MigrationDecision.REJECT,
            SecurePreferences.migrationDecision(true, emptyMap<String, Any>()),
        )
    }

    @Test
    fun `old fully encrypted store can receive protected marker`() {
        assertEquals(
            SecurePreferences.MigrationDecision.MARK_ENCRYPTED,
            SecurePreferences.migrationDecision(false, mapOf("theme" to "FAEP1:ciphertext")),
        )
    }
}
