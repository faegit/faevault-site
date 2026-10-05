package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

class CloudPreviewSessionCacheTest {
    @Test
    fun sameAssociationIsInspectedOnlyOnceUntilUserForcesRefresh() {
        val cache = CloudPreviewSessionCache<String>()

        assertTrue(cache.begin("drive", "vault-a|content://cloud/file"))
        assertFalse(cache.begin("drive", "vault-a|content://cloud/file"))

        cache.complete("drive", "vault-a|content://cloud/file", "同步完成后的预览")
        assertEquals("同步完成后的预览", cache.cached("drive", "vault-a|content://cloud/file"))
        assertFalse(cache.begin("drive", "vault-a|content://cloud/file"))
        assertTrue(cache.begin("drive", "vault-a|content://cloud/file", force = true))
    }

    @Test
    fun changedAssociationDoesNotReusePreviousPreview() {
        val cache = CloudPreviewSessionCache<String>()
        cache.begin("webdav", "vault-a|server-one")
        cache.complete("webdav", "vault-a|server-one", "旧服务器")

        assertNull(cache.cached("webdav", "vault-a|server-two"))
        assertTrue(cache.begin("webdav", "vault-a|server-two"))
    }

    @Test
    fun cancelledInspectionCanBeStartedAgain() {
        val cache = CloudPreviewSessionCache<String>()
        assertTrue(cache.begin("drive", "vault-a|uri"))

        cache.cancel("drive", "vault-a|uri")

        assertTrue(cache.begin("drive", "vault-a|uri"))
    }

    @Test
    fun reenteredScreenCanAwaitInspectionStartedByPreviousScreen() = runBlocking {
        val cache = CloudPreviewSessionCache<String>()
        assertTrue(cache.begin("drive", "vault-a|uri"))

        val secondScreen = async { cache.await("drive", "vault-a|uri") }
        cache.complete("drive", "vault-a|uri", "检测完成")

        assertEquals("检测完成", secondScreen.await())
    }
}
