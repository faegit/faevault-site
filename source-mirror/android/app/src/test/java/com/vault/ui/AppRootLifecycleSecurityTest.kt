package com.vault.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppRootLifecycleSecurityTest {
    @Test
    fun `backgrounding invalidates an unlock that is still running`() {
        assertTrue(shouldLockOnStop(UiState(phase = Phase.LOCKED, busy = true)))
        assertTrue(shouldLockOnStop(UiState(phase = Phase.LOCKED, unlockSuccess = true)))
    }

    @Test
    fun `backgrounding locks an unlocked vault but not an idle locked screen`() {
        assertTrue(shouldLockOnStop(UiState(phase = Phase.UNLOCKED)))
        assertFalse(shouldLockOnStop(UiState(phase = Phase.LOCKED)))
        assertFalse(shouldLockOnStop(UiState(phase = Phase.NO_VAULT, busy = true)))
    }

    @Test
    fun `an active external system flow keeps its lifecycle exemption`() {
        assertFalse(
            shouldLockOnStop(
                UiState(
                    phase = Phase.LOCKED,
                    busy = true,
                    isExternalActionInProgress = true,
                ),
            ),
        )
    }
}
