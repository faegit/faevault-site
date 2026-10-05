package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EntryDetailScrollPositionTest {
    @Test
    fun preferenceKeyIsStableWithoutExposingEntryId() {
        val entryId = "private-entry-id"

        val first = detailScrollPreferenceKey(entryId)
        val second = detailScrollPreferenceKey(entryId)

        assertEquals(first, second)
        assertFalse(first.contains(entryId))
        assertTrue(first.startsWith("entry_"))
    }

    @Test
    fun persistedPositionRejectsInvalidValues() {
        assertEquals(0, sanitizeDetailScrollPosition(-1))
        assertEquals(1_234, sanitizeDetailScrollPosition(1_234))
        assertEquals(MAX_DETAIL_SCROLL_POSITION, sanitizeDetailScrollPosition(Int.MAX_VALUE))
    }
}
