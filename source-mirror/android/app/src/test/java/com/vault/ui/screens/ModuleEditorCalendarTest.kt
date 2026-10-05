package com.vault.ui.screens

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.DayOfWeek
import java.time.YearMonth
import java.util.Locale

class ModuleEditorCalendarTest {
    @Test fun enUsCalendarStartsSundayAndOffsetsFromSunday() {
        val layout = calendarWeekLayout(Locale.US, YearMonth.of(2026, 8))

        assertEquals(
            listOf(
                DayOfWeek.SUNDAY,
                DayOfWeek.MONDAY,
                DayOfWeek.TUESDAY,
                DayOfWeek.WEDNESDAY,
                DayOfWeek.THURSDAY,
                DayOfWeek.FRIDAY,
                DayOfWeek.SATURDAY,
            ),
            layout.weekdays,
        )
        assertEquals(6, layout.firstDayOffset)
    }

    @Test fun zhCnCalendarKeepsMondayFirstOrderAndOffset() {
        val layout = calendarWeekLayout(Locale.SIMPLIFIED_CHINESE, YearMonth.of(2026, 8))

        assertEquals(
            listOf(
                DayOfWeek.MONDAY,
                DayOfWeek.TUESDAY,
                DayOfWeek.WEDNESDAY,
                DayOfWeek.THURSDAY,
                DayOfWeek.FRIDAY,
                DayOfWeek.SATURDAY,
                DayOfWeek.SUNDAY,
            ),
            layout.weekdays,
        )
        assertEquals(5, layout.firstDayOffset)
    }
}
