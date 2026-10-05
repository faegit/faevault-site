package com.vault

import com.vault.model.formatCardDate
import org.junit.Assert.assertEquals
import org.junit.Test

class CardDateFormatTest {
    @Test
    fun compactDateNormalizedToDashSeparated() {
        assertEquals("2023-01-01", formatCardDate("20230101"))
    }

    @Test
    fun isoDateSingleDigitMonthPadded() {
        assertEquals("2023-01-01", formatCardDate("2023-1-1"))
        assertEquals("2023-01-01", formatCardDate("2023/1/1"))
    }

    @Test
    fun yearMonthNormalized() {
        assertEquals("2024-02", formatCardDate("2024-2"))
        assertEquals("2024-02", formatCardDate("2024/02"))
        assertEquals("2024-02", formatCardDate("2024/2"))
    }

    @Test
    fun expiryMonthYearVariantsNormalized() {
        assertEquals("01/25", formatCardDate("0125"))
        assertEquals("01/25", formatCardDate("1/25"))
        assertEquals("01/25", formatCardDate("01/25"))
        assertEquals("2025-01", formatCardDate("1/2025"))
    }

    @Test
    fun longTermPreservedAsLongTerm() {
        assertEquals("长期", formatCardDate("长期"))
        assertEquals("长期", formatCardDate("长期有效"))
        assertEquals("长期", formatCardDate("永久"))
    }

    @Test
    fun unknownValuePassedThrough() {
        assertEquals("abc", formatCardDate("abc"))
        assertEquals("", formatCardDate(""))
    }

    @Test
    fun invalidMonthPassesThrough() {
        assertEquals("2025", formatCardDate("2025"))
        assertEquals("13/25", formatCardDate("13/25"))
    }
}