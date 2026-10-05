package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoCloudSyncPrefsTest {
    @Test
    fun `daily and weekly schedules become due at their boundary`() {
        val started = 1_000L
        fun settings(minutes: Int) = AutoCloudSyncSettings(true, "drive", minutes, started, 0L, 0, "")

        val daily = settings(1_440)
        assertFalse(AutoCloudSyncPrefs.isDue(daily, started + 1_440L * 60_000L - 1L))
        assertTrue(AutoCloudSyncPrefs.isDue(daily, started + 1_440L * 60_000L))

        val weekly = settings(10_080)
        assertFalse(AutoCloudSyncPrefs.isDue(weekly, started + 10_080L * 60_000L - 1L))
        assertTrue(AutoCloudSyncPrefs.isDue(weekly, started + 10_080L * 60_000L))
    }

    @Test
    fun `间隔非法时回落到 60 分钟且不影响其他字段`() {
        val built = AutoCloudSyncPrefs.buildTargetSettings(
            target = "webdav",
            enabled = true,
            intervalMinutes = 7,
            enabledAt = 5_000L,
            lastSuccess = 9_000L,
            failures = 2,
            status = "上次失败",
        )

        assertEquals("webdav", built.target)
        assertEquals(60, built.intervalMinutes)
        assertTrue(built.enabled)
        assertEquals(5_000L, built.enabledAt)
        assertEquals(9_000L, built.lastSuccess)
        assertEquals(2, built.failures)
        assertEquals("上次失败", built.status)
    }

    @Test
    fun `合法间隔原样保留`() {
        listOf(15, 30, 60, 180, 360, 1_440, 10_080).forEach { minutes ->
            val built = AutoCloudSyncPrefs.buildTargetSettings(
                target = "drive",
                enabled = false,
                intervalMinutes = minutes,
                enabledAt = 0L,
                lastSuccess = 0L,
                failures = 0,
                status = "",
            )
            assertEquals(minutes, built.intervalMinutes)
        }
    }

    @Test
    fun `未启用时永不到期`() {
        val disabled = AutoCloudSyncSettings(false, "drive", 15, 0L, 0L, 0, "")
        assertFalse(AutoCloudSyncPrefs.isDue(disabled, Long.MAX_VALUE))
    }

    @Test
    fun `enabledAt 与 lastSuccess 取较晚者作为基准`() {
        val started = 1_000L
        val settings = AutoCloudSyncSettings(true, "drive", 60, started, started + 10L * 60_000L, 0, "")

        // 若错误地用 enabledAt 作基准，会在这里提前触发
        assertFalse(AutoCloudSyncPrefs.isDue(settings, started + 69L * 60_000L))
        assertTrue(AutoCloudSyncPrefs.isDue(settings, started + 70L * 60_000L))
    }
}
