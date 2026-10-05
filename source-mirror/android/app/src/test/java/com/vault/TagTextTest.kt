package com.vault

import com.vault.ui.splitTagText
import org.junit.Assert.assertEquals
import org.junit.Test

class TagTextTest {
    @Test
    fun splitsOnAllSeparators() {
        assertEquals(listOf("a", "b"), splitTagText("a, b"))
        assertEquals(listOf("a", "b", "c"), splitTagText("a，b c"))
        assertEquals(listOf("a", "b"), splitTagText(" a \tb\nb "))
    }

    @Test
    fun dedupesPreservingOrder() {
        assertEquals(listOf("a", "b"), splitTagText("a, b, a"))
    }

    @Test
    fun dropsEmptyAndSeparatorOnly() {
        assertEquals(emptyList<String>(), splitTagText("  , ， \t\n"))
        assertEquals(listOf("x"), splitTagText("x,,,"))
    }

    @Test
    fun singleTagKept() {
        assertEquals(listOf("work"), splitTagText("work"))
    }
}