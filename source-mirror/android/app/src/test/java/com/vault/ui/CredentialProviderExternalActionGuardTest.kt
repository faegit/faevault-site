package com.vault.ui

import com.vault.ui.screens.CredentialProviderExternalActionGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialProviderExternalActionGuardTest {
    @Test
    fun `activity result clears external action state`() {
        val states = mutableListOf<Boolean>()
        val guard = CredentialProviderExternalActionGuard(states::add)

        guard.start()
        assertTrue(guard.isInProgress)

        guard.finish()

        assertFalse(guard.isInProgress)
        assertEquals(listOf(true, false), states)
    }

    @Test
    fun `launch exception clears external action state`() {
        val states = mutableListOf<Boolean>()
        val guard = CredentialProviderExternalActionGuard(states::add)

        val launched = guard.launch { error("settings unavailable") }

        assertFalse(launched)
        assertFalse(guard.isInProgress)
        assertEquals(listOf(true, false), states)
    }

    @Test
    fun `activity result followed by resume only clears state once`() {
        val states = mutableListOf<Boolean>()
        val guard = CredentialProviderExternalActionGuard(states::add)

        guard.start()
        guard.finish()
        guard.finish()

        assertEquals(listOf(true, false), states)
    }
}
