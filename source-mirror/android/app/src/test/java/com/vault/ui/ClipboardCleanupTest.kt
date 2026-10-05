package com.vault.ui

import org.junit.Assert.*
import org.junit.Test

class ClipboardCleanupTest {
    @Test fun deniedAccessKeepsCleanupPendingThenForegroundRetrySucceeds() {
        var readable = false
        var current: ClipboardOwner? = ClipboardOwner("ours")
        var clears = 0
        val read = { if (readable) current else null }
        val clear = { clears++; current = null }
        assertFalse(cleanOwnedClipboard("ours", read, clear))
        assertEquals(0, clears)
        readable = true
        assertTrue(cleanOwnedClipboard("ours", read, clear))
        assertEquals(1, clears)
    }

    @Test fun replacementContentIsNeverCleared() {
        assertTrue(cleanOwnedClipboard("old", { ClipboardOwner("new") }, { fail("Must preserve newer clipboard") }))
        assertTrue(cleanOwnedClipboard("old", { ClipboardOwner(null) }, { fail("Must preserve other apps clipboard") }))
    }

    @Test fun ignoredClearOrAccessExceptionKeepsCleanupPending() {
        assertFalse(cleanOwnedClipboard("ours", { ClipboardOwner("ours") }, {}))
        assertFalse(cleanOwnedClipboard("ours", { throw SecurityException() }, {}))
        assertFalse(cleanOwnedClipboard("ours", { ClipboardOwner("ours") }, { throw SecurityException() }))
    }
}
