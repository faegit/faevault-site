package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalBackupPolicyTest {

    @Test
    fun `device connection checks every configured interval for an external target`() {
        val external = "fs:ABCD-1234|doc:provider/ABCD-1234:backup"
        LocalBackupPolicy.INTERVALS.forEach { interval ->
            assertTrue(
                LocalBackupPolicy.shouldTriggerExternalConnectionCheck(
                    enabled = true,
                    intervalMillis = interval,
                    expectedVolumeIdentity = external,
                ),
            )
        }
        assertFalse(LocalBackupPolicy.shouldTriggerExternalConnectionCheck(false, LocalBackupPolicy.INTERVAL_REALTIME, external))
        assertFalse(LocalBackupPolicy.shouldTriggerExternalConnectionCheck(true, Long.MAX_VALUE, external))
        assertFalse(LocalBackupPolicy.shouldTriggerExternalConnectionCheck(true, LocalBackupPolicy.INTERVAL_REALTIME, null))
        assertFalse(
            LocalBackupPolicy.shouldTriggerExternalConnectionCheck(
                true,
                LocalBackupPolicy.INTERVAL_REALTIME,
                "internal|com.android.externalstorage.documents|primary:backup",
            ),
        )
    }

    @Test
    fun `device connection copies realtime or due scheduled backups only`() {
        val external = "fs:ABCD-1234|doc:provider/ABCD-1234:backup"
        val now = 10L * LocalBackupPolicy.INTERVAL_DAILY

        assertTrue(
            LocalBackupPolicy.shouldRunExternalConnectionBackup(
                enabled = true,
                nowMillis = now,
                lastBackupMillis = now,
                intervalMillis = LocalBackupPolicy.INTERVAL_REALTIME,
                expectedVolumeIdentity = external,
            ),
        )
        assertTrue(
            LocalBackupPolicy.shouldRunExternalConnectionBackup(
                enabled = true,
                nowMillis = now,
                lastBackupMillis = now - LocalBackupPolicy.INTERVAL_DAILY,
                intervalMillis = LocalBackupPolicy.INTERVAL_DAILY,
                expectedVolumeIdentity = external,
            ),
        )
        assertFalse(
            LocalBackupPolicy.shouldRunExternalConnectionBackup(
                enabled = true,
                nowMillis = now,
                lastBackupMillis = now - LocalBackupPolicy.INTERVAL_DAILY + 1L,
                intervalMillis = LocalBackupPolicy.INTERVAL_DAILY,
                expectedVolumeIdentity = external,
            ),
        )
        assertFalse(
            LocalBackupPolicy.shouldRunExternalConnectionBackup(
                enabled = true,
                nowMillis = now,
                lastBackupMillis = 0L,
                intervalMillis = LocalBackupPolicy.INTERVAL_DAILY,
                expectedVolumeIdentity = "internal|com.android.externalstorage.documents|primary:backup",
            ),
        )
    }
    @Test
    fun `realtime always runs and labels map to intervals`() {
        assertTrue(LocalBackupPolicy.shouldRun(1_000L, 900L, LocalBackupPolicy.INTERVAL_REALTIME))
        assertTrue(LocalBackupPolicy.shouldRun(1_000L, 1_000L, LocalBackupPolicy.INTERVAL_REALTIME))
        assertEquals("实时", LocalBackupPolicy.label(LocalBackupPolicy.INTERVAL_REALTIME))
        assertEquals("每小时", LocalBackupPolicy.label(LocalBackupPolicy.INTERVAL_HOURLY))
        assertEquals("每天", LocalBackupPolicy.label(LocalBackupPolicy.INTERVAL_DAILY))
        assertEquals("每周", LocalBackupPolicy.label(LocalBackupPolicy.INTERVAL_WEEKLY))
        assertEquals("每月", LocalBackupPolicy.label(LocalBackupPolicy.INTERVAL_MONTHLY))
    }

    @Test
    fun `interval gates by last backup time and force bypasses`() {
        val now = 100_000L
        val day = LocalBackupPolicy.INTERVAL_DAILY
        assertFalse(LocalBackupPolicy.shouldRun(now, now - day + 1, day))
        assertTrue(LocalBackupPolicy.shouldRun(now, now - day, day))
        assertTrue(LocalBackupPolicy.shouldRun(now, now - 1, day, force = true))
    }

    @Test
    fun `slider index mapping is clamped and round trips`() {
        assertEquals(0, LocalBackupPolicy.indexOf(LocalBackupPolicy.INTERVAL_REALTIME))
        assertEquals(4, LocalBackupPolicy.indexOf(LocalBackupPolicy.INTERVAL_MONTHLY))
        assertEquals(0, LocalBackupPolicy.indexOf(12_345L))
        assertEquals(LocalBackupPolicy.INTERVAL_DAILY, LocalBackupPolicy.intervalAt(2))
        assertEquals(LocalBackupPolicy.INTERVAL_MONTHLY, LocalBackupPolicy.intervalAt(99))
        assertEquals(LocalBackupPolicy.INTERVAL_REALTIME, LocalBackupPolicy.intervalAt(-1))
    }
}
