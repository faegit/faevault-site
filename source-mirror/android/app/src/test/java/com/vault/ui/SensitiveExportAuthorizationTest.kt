package com.vault.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SensitiveExportAuthorizationTest {
    private val grant = SensitiveExportGrant("personal", 7, "archive", "content://provider/export/1", 30_000)

    @Test fun `authorization is one destination operation account and generation`() {
        assertTrue(grant.matches("personal", 7, "archive", "content://provider/export/1", 29_999))
        assertFalse(grant.matches("personal", 7, "archive", "content://provider/export/2", 29_999))
        assertFalse(grant.matches("personal", 7, "backup", "content://provider/export/1", 29_999))
        assertFalse(grant.matches("work", 7, "archive", "content://provider/export/1", 29_999))
        assertFalse(grant.matches("personal", 8, "archive", "content://provider/export/1", 29_999))
        assertFalse(grant.matches("personal", 7, "archive", "content://provider/export/1", 30_000))
    }
}
