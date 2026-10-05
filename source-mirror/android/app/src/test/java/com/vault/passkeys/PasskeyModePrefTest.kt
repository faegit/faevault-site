package com.vault.passkeys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyModePrefTest {
    @Test fun `missing and invalid values default to asking on every creation`() {
        assertEquals(PasskeyCreationPreference.ASK_EVERY_TIME, PasskeyModePref.parseOrDefault(null))
        assertEquals(PasskeyCreationPreference.ASK_EVERY_TIME, PasskeyModePref.parseOrDefault("unknown"))
    }

    @Test fun `saved creation preferences preserve whether creation should ask`() {
        assertEquals(PasskeyCreationPreference.ASK_EVERY_TIME, PasskeyModePref.parseOrDefault("ask_every_time"))
        assertEquals(PasskeyCreationPreference.SYNCABLE, PasskeyModePref.parseOrDefault("syncable"))
        assertEquals(PasskeyCreationPreference.DEVICE_BOUND, PasskeyModePref.parseOrDefault("device_bound"))
        assertEquals(null, PasskeyCreationPreference.ASK_EVERY_TIME.fixedMode)
        assertEquals(PasskeyKeyMode.SYNCABLE, PasskeyCreationPreference.SYNCABLE.fixedMode)
        assertEquals(PasskeyKeyMode.DEVICE_BOUND, PasskeyCreationPreference.DEVICE_BOUND.fixedMode)
    }

    @Test fun `software syncable keys require activity user verification while device keys verify in keystore`() {
        assertTrue(PasskeyKeyMode.SYNCABLE.requiresActivityUserVerification())
        assertFalse(PasskeyKeyMode.DEVICE_BOUND.requiresActivityUserVerification())
    }
}
