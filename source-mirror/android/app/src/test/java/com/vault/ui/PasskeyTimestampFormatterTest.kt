package com.vault.ui

import com.vault.ui.screens.formatPasskeyTimestamp
import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.ZoneId

class PasskeyTimestampFormatterTest {
    @Test
    fun utcTimestampIsDisplayedInDeviceTimeZone() {
        assertEquals(
            "2026-08-26 22:14:55",
            formatPasskeyTimestamp(
                value = "2026-08-26T14:14:55.382Z",
                zoneId = ZoneId.of("Asia/Shanghai"),
            ),
        )
    }

    @Test
    fun explicitOffsetRepresentsTheSameLocalTime() {
        assertEquals(
            "2026-08-26 22:14:55",
            formatPasskeyTimestamp(
                value = "2026-08-26T22:14:55+08:00",
                zoneId = ZoneId.of("Asia/Shanghai"),
            ),
        )
    }

    @Test
    fun emptyAndInvalidValuesRemainUnchanged() {
        assertEquals("", formatPasskeyTimestamp("", ZoneId.of("Asia/Shanghai")))
        assertEquals("unknown", formatPasskeyTimestamp("unknown", ZoneId.of("Asia/Shanghai")))
    }
}
