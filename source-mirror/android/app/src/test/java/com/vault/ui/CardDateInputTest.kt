package com.vault.ui

import org.junit.Assert.*
import org.junit.Test

class CardDateInputTest {
    @Test fun formatsEightDigitsAndFiltersPaste() {
        assertEquals("2025-09-06", InputFilters.formatDate("20250906"))
        assertEquals("2025-09-06", InputFilters.formatDate("2025/09/06"))
        assertEquals("2025-09-06", InputFilters.formatDate("2025年09月06日"))
        assertEquals("2025-09-06", InputFilters.formatDate("20250906123"))
        assertEquals("2025090", InputFilters.formatDate("2025-09-0"))
        assertEquals("", InputFilters.formatDate("invalid"))
    }
    @Test fun rejectsImpossibleAndIncompleteDatesWithoutCoercingThem() {
        assertTrue(InputFilters.isValidDate("2024-02-29"))
        assertFalse(InputFilters.isValidDate("2025-02-29"))
        assertFalse(InputFilters.isValidDate("2025-13-01"))
        assertFalse(InputFilters.isValidDate("2025-04-31"))
        assertFalse(InputFilters.isValidDate("2025090"))
        assertFalse(InputFilters.isValidDate("0000-01-01"))
        assertTrue(InputFilters.isValidDate(""))
        assertTrue(InputFilters.isValidDate("长期", true))
        assertFalse(InputFilters.isValidDate("长期"))
    }
    @Test fun bankExpiryKeepsMonthYearFormat() {
        assertEquals("09/25", InputFilters.formatExpiryMMYY("0925"))
    }
}
