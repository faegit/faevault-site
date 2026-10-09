package com.vault.storage

import com.vault.ui.VaultSessionFence
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class CloudSettingsWriteQueueTest {
    @Test
    fun `slow persistence leaves caller responsive and preserves write order`() = runBlocking {
        val queue = CloudSettingsWriteQueue()
        val caller = Thread.currentThread()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writes = mutableListOf<Int>()
        val first = async(start = CoroutineStart.UNDISPATCHED) {
            queue.write {
                assertNotSame(caller, Thread.currentThread())
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                writes.add(1)
            }
        }
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val second = async(start = CoroutineStart.UNDISPATCHED) { queue.write { writes.add(2) } }
            val third = async(start = CoroutineStart.UNDISPATCHED) { queue.write { writes.add(3) } }
            assertFalse(first.isCompleted)
            assertFalse(second.isCompleted)
            release.countDown()
            first.await(); second.await(); third.await()
            assertEquals(listOf(1, 2, 3), writes)
        } finally {
            release.countDown()
        }
    }

    @Test
    fun `failed write does not prevent a later setting from being saved`() = runBlocking {
        val queue = CloudSettingsWriteQueue()
        assertTrue(runCatching { queue.write { error("storage unavailable") } }.isFailure)
        assertEquals("saved", queue.write { "saved" })
    }

    @Test
    fun `queued credential mutation is rejected after switching vault sessions`() = runBlocking {
        val queue = CloudSettingsWriteQueue()
        val fence = VaultSessionFence()
        val token = fence.capture("personal")
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        var mutated = false
        val blocking = async(start = CoroutineStart.UNDISPATCHED) {
            queue.write {
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS))
            }
        }
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val saved = async(start = CoroutineStart.UNDISPATCHED) {
                queue.write { fence.runIfCurrent(token, "work") { mutated = true } }
            }
            fence.invalidate()
            release.countDown()
            blocking.await()
            assertFalse(saved.await())
            assertFalse(mutated)
        } finally {
            release.countDown()
        }
    }
}
