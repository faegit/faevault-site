package com.vault.security

import org.junit.Assert.assertEquals
import org.junit.Test

class LockoutCountdownTest {
    @Test fun keepsFinalPartialSecondBlocked() {
        assertEquals(30, LockoutPref.remainingSeconds(30_000))
        assertEquals(30, LockoutPref.remainingSeconds(29_999))
        assertEquals(2, LockoutPref.remainingSeconds(1_001))
        assertEquals(1, LockoutPref.remainingSeconds(1_000))
        assertEquals(1, LockoutPref.remainingSeconds(1))
        assertEquals(0, LockoutPref.remainingSeconds(0))
        assertEquals(0, LockoutPref.remainingSeconds(-1))
    }

    @Test fun handlesPersistedLargeDeadlineWithoutIntegerOverflow() {
        assertEquals(Int.MAX_VALUE, LockoutPref.remainingSeconds(Long.MAX_VALUE))
    }
}
