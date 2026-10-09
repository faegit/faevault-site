package com.vault.ui

import com.vault.storage.RemoteUpdatePolicy
import com.vault.storage.RemoteUpdateState
import com.vault.storage.CloudSettingsWriteQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import org.junit.Assert.*
import org.junit.Test

class RemoteUpdateSettingsGateTest {
    @Test
    fun `reload spanning a completed toggle cannot publish old state`() {
        val gate = RemoteUpdateSettingsGate()
        var visible = true
        val loaded = CountDownLatch(1)
        val release = CountDownLatch(1)
        var accepted = true
        val reader = Thread {
            val revision = gate.revision
            val stored = true
            loaded.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            accepted = gate.publishIfCurrent(revision) { visible = stored }
        }
        reader.start()
        try {
            assertTrue(loaded.await(5, TimeUnit.SECONDS))
            gate.change { visible = false }
            // Completion must invalidate snapshots taken while the old value was still on disk.
            gate.change { }
            release.countDown()
            reader.join(5_000)
            assertFalse(reader.isAlive)
            assertFalse(accepted)
            assertFalse(visible)
        } finally {
            release.countDown()
            reader.join(5_000)
        }
    }

    @Test
    fun `read after a click but before its persistence also becomes stale`() {
        val gate = RemoteUpdateSettingsGate()
        gate.change { }
        val readRevision = gate.revision
        gate.change { }
        assertFalse(gate.publishIfCurrent(readRevision) { fail("Old settings published") })
    }

    @Test
    fun `acknowledgement and disable use the same serial transaction domain`() = runBlocking {
        val gate = RemoteUpdateSettingsGate()
        var disk = RemoteUpdateState(enabled = true, pending = "remote")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val acknowledgement = async(start = CoroutineStart.UNDISPATCHED) {
            gate.persistenceMutex.withLock {
                val snapshot = disk
                entered.complete(Unit)
                release.await()
                disk = RemoteUpdatePolicy.acknowledge(snapshot, "remote")
            }
        }
        entered.await()
        val disable = async(start = CoroutineStart.UNDISPATCHED) {
            gate.persistenceMutex.withLock { disk = disk.copy(enabled = false, pending = "") }
        }
        assertFalse(disable.isCompleted)
        release.complete(Unit)
        acknowledgement.await(); disable.await()
        assertFalse(disk.enabled)
        assertEquals("", disk.pending)
    }

    @Test
    fun `clear followed by reassociation stays ordered behind a running check`() = runBlocking {
        val gate = RemoteUpdateSettingsGate()
        val writes = CloudSettingsWriteQueue()
        val release = CompletableDeferred<Unit>()
        var stored = "old"
        val checking = async(start = CoroutineStart.UNDISPATCHED) {
            gate.persistenceMutex.withLock { release.await() }
        }
        val clear = async(start = CoroutineStart.UNDISPATCHED) {
            gate.persistenceMutex.withLock { writes.write { stored = "" } }
        }
        val reassociate = async(start = CoroutineStart.UNDISPATCHED) {
            gate.persistenceMutex.withLock { writes.write { stored = "new" } }
        }
        assertFalse(clear.isCompleted)
        assertFalse(reassociate.isCompleted)
        release.complete(Unit)
        checking.await(); clear.await(); reassociate.await()
        assertEquals("new", stored)
    }
}
