package com.vault.ui

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultViewModelSessionSafetyTest {
    @Test
    fun invalidatedSessionCannotPublishAnOldTaskResult() {
        val fence = VaultSessionFence()
        val oldSession = fence.capture("personal")
        var visibleResult = "new-session"

        fence.invalidate()
        val published = fence.runIfCurrent(oldSession, "personal") {
            visibleResult = "old-session"
        }

        assertFalse(published)
        assertEquals("new-session", visibleResult)
    }

    @Test
    fun taskFromAnotherVaultCannotPublishEvenBeforeCancellationCompletes() {
        val fence = VaultSessionFence()
        val firstVaultSession = fence.capture("personal")
        var published = false

        val accepted = fence.runIfCurrent(firstVaultSession, "work") {
            published = true
        }

        assertFalse(accepted)
        assertFalse(published)
    }

    @Test
    fun invalidationWaitsForFencedCommitThenRejectsEveryLaterCommit() {
        val fence = VaultSessionFence()
        val token = fence.capture("personal")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val invalidated = CountDownLatch(1)
        val committed = mutableListOf<String>()
        val writer = Thread {
            fence.runIfCurrent(token, "personal") {
                entered.countDown()
                check(release.await(2, TimeUnit.SECONDS))
                committed += "write"
            }
        }
        writer.start()
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        val locker = Thread {
            fence.invalidate()
            invalidated.countDown()
        }
        locker.start()
        assertFalse(invalidated.await(50, TimeUnit.MILLISECONDS))
        release.countDown()
        assertTrue(invalidated.await(2, TimeUnit.SECONDS))
        writer.join(2_000)
        locker.join(2_000)
        assertEquals(listOf("write"), committed)
        assertFalse(fence.runIfCurrent(token, "personal") { committed += "stale-write" })
        assertEquals(listOf("write"), committed)
    }

    @Test
    fun externalActionFlagIsRestoredWhenOperationIsCancelled() = runBlocking {
        val transitions = mutableListOf<Boolean>()

        try {
            withExternalActionFlag({ transitions += it }) {
                throw CancellationException("locked")
            }
        } catch (_: CancellationException) {
            // Expected: cancellation must still release the lifecycle lock bypass.
        }

        assertEquals(listOf(true, false), transitions)
        assertFalse(transitions.last())
    }

    @Test
    fun externalActionFlagIsRestoredAfterSuccessfulOperation() = runBlocking {
        var active = false

        val result = withExternalActionFlag({ active = it }) {
            assertTrue(active)
            "done"
        }

        assertEquals("done", result)
        assertFalse(active)
    }
}
