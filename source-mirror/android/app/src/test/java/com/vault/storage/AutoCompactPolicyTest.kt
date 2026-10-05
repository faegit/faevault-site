package com.vault.storage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoCompactPolicyTest {
    private val now = 1_800_000_000_000L

    @Test
    fun `compacts when commits and growth thresholds are met`() {
        assertTrue(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 500,
                lastCompactRevision = 100,
                fileSize = 8L * 1024 * 1024,
                lastCompactSize = 3L * 1024 * 1024,
                lastCompactAtMillis = now - 2L * 24 * 60 * 60 * 1000,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `does not compact when commits since last compact are too few`() {
        assertFalse(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 300,
                lastCompactRevision = 150,
                fileSize = 8L * 1024 * 1024,
                lastCompactSize = 3L * 1024 * 1024,
                lastCompactAtMillis = now - 2L * 24 * 60 * 60 * 1000,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `does not compact when file has not grown enough`() {
        assertFalse(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 500,
                lastCompactRevision = 100,
                fileSize = 3_200_000L,
                lastCompactSize = 3_000_000L,
                lastCompactAtMillis = now - 2L * 24 * 60 * 60 * 1000,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `does not compact tiny vaults`() {
        assertFalse(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 500,
                lastCompactRevision = 0,
                fileSize = 64L * 1024,
                lastCompactSize = 0L,
                lastCompactAtMillis = 0L,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `does not compact twice within the minimum interval`() {
        assertFalse(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 900,
                lastCompactRevision = 500,
                fileSize = 9L * 1024 * 1024,
                lastCompactSize = 3L * 1024 * 1024,
                lastCompactAtMillis = now - 60L * 60 * 1000,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `first run on a grown vault compacts once`() {
        assertTrue(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 300,
                lastCompactRevision = 0,
                fileSize = 2L * 1024 * 1024,
                lastCompactSize = 0L,
                lastCompactAtMillis = 0L,
                nowMillis = now,
            ),
        )
    }

    @Test
    fun `skips auto compact during the import cooldown window`() {
        assertFalse(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 300,
                lastCompactRevision = 0,
                fileSize = 2L * 1024 * 1024,
                lastCompactSize = 0L,
                lastCompactAtMillis = 0L,
                lastImportAtMillis = now - 60L * 60 * 1000,
                nowMillis = now,
            ),
        )
        // 冷却期过后可正常压缩
        assertTrue(
            AutoCompactPolicy.shouldCompact(
                currentRevision = 300,
                lastCompactRevision = 0,
                fileSize = 2L * 1024 * 1024,
                lastCompactSize = 0L,
                lastCompactAtMillis = 0L,
                lastImportAtMillis = now - 2L * 24 * 60 * 60 * 1000,
                nowMillis = now,
            ),
        )
    }
}
