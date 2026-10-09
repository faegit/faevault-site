package com.vault.storage

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class PreferenceWriteQueueTest {
    @Test
    fun `writes stay off caller thread and retain captured vault and FIFO order`() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val caller = Thread.currentThread()
        val writes = mutableListOf<String>()
        val queue = PreferenceWriteQueue(owner) { throw AssertionError(it) }
        try {
            val first = queue.submit {
                assertNotSame(caller, Thread.currentThread())
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS))
                writes.add("first")
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            var currentVault = "personal"
            val capturedVault = currentVault
            val second = queue.submit { writes.add(capturedVault) }
            currentVault = "work"
            val third = queue.submit { writes.add("third") }
            assertEquals("work", currentVault)
            assertFalse(second.isCompleted)
            release.countDown()
            first.await()
            second.await()
            third.await()
            assertEquals(listOf("first", "personal", "third"), writes)
        } finally {
            release.countDown()
            owner.cancel()
        }
    }

    @Test
    fun `failed setting is reported and later setting still persists`() = runBlocking {
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val failures = mutableListOf<Throwable>()
        val queue = PreferenceWriteQueue(owner) { failures.add(it) }
        try {
            val failed = queue.submit { error("storage unavailable") }
            var saved = false
            val next = queue.submit { saved = true }
            assertTrue(runCatching { failed.await() }.isFailure)
            next.await()
            assertTrue(saved)
            assertEquals(1, failures.size)
            assertEquals("storage unavailable", failures.single().message)
        } finally {
            owner.cancel()
        }
    }
}
