package com.vault.storage

import org.junit.Assert.*
import org.junit.Test

class PendingPreferenceValuesTest {
    @Test
    fun `pending value is available immediately for same vault reinitialization`() {
        val values = PendingPreferenceValues()
        val token = values.stage("personal", "enabled", true)
        assertEquals(true, values.value("personal", "enabled"))
        assertNull(values.value("work", "enabled"))
        values.persisted(token)
        assertNull(values.value("personal", "enabled"))
    }

    @Test
    fun `older completion cannot discard a newer value even after ABA change`() {
        val values = PendingPreferenceValues()
        val first = values.stage("personal", "enabled", true)
        val second = values.stage("personal", "enabled", false)
        val newest = values.stage("personal", "enabled", true)
        values.persisted(first)
        values.persisted(second)
        assertEquals(true, values.value("personal", "enabled"))
        assertTrue(newest.generation > second.generation)
        values.persisted(newest)
        assertNull(values.value("personal", "enabled"))
    }

    @Test
    fun `failed write remains pending while independent settings finish`() {
        val values = PendingPreferenceValues()
        values.stage("personal", "seconds", 15)
        val layout = values.stage("personal", "mode", "two_columns")
        values.persisted(layout)
        assertEquals(15, values.value("personal", "seconds"))
        assertNull(values.value("personal", "mode"))
    }

    @Test
    fun `overlay rejects nonprimitive values`() {
        val values = PendingPreferenceValues()
        assertTrue(runCatching { values.stage("personal", "bad", ByteArray(32)) }.isFailure)
    }
}
