package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class VaultSyncSnapshotTest {
    @Test
    fun `sync snapshot waits for the current PMVE writer and copies one committed state`() {
        val source = File.createTempFile("pmve-live-", ".pmv")
        val target = File.createTempFile("pmve-snapshot-", ".pmv")
        val writerEntered = CountDownLatch(1)
        val releaseWriter = CountDownLatch(1)
        val expected = ByteArray(256 * 1024) { (it * 31).toByte() }
        val pool = Executors.newFixedThreadPool(2)
        try {
            source.writeBytes(byteArrayOf(1, 2, 3))
            val writer = pool.submit {
                PmvAppendOnlyFile.withExclusiveWriterLock(source) {
                    source.writeBytes(expected.copyOf(expected.size / 2))
                    writerEntered.countDown()
                    assertTrue(releaseWriter.await(5, TimeUnit.SECONDS))
                    source.writeBytes(expected)
                }
            }
            assertTrue(writerEntered.await(5, TimeUnit.SECONDS))

            val snapshot = pool.submit { copyPmvEFileSnapshot(source, target) }
            Thread.sleep(100)
            assertFalse("snapshot must not read a half-written PMVE file", snapshot.isDone)

            releaseWriter.countDown()
            writer.get(5, TimeUnit.SECONDS)
            snapshot.get(5, TimeUnit.SECONDS)
            assertArrayEquals(expected, target.readBytes())
        } finally {
            releaseWriter.countDown()
            pool.shutdownNow()
            source.delete()
            target.delete()
        }
    }
}
