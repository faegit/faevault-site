package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class RemoteUpdateNavigationTest {
    @Test fun notificationWaitsForUnlockAndNeverOpensAnotherVault() {
        val request = RemoteUpdateOpenRequest("first", "webdav", 1)
        assertEquals(RemoteUpdateNavigationDecision.WAIT_FOR_UNLOCK, remoteUpdateNavigationDecision(request, "first", false))
        assertEquals(RemoteUpdateNavigationDecision.OPEN, remoteUpdateNavigationDecision(request, "first", true))
        assertEquals(RemoteUpdateNavigationDecision.DROP, remoteUpdateNavigationDecision(request, "second", true))
        assertEquals(RemoteUpdateNavigationDecision.DROP, remoteUpdateNavigationDecision(request.copy(target = "unknown"), "first", true))
    }
}
