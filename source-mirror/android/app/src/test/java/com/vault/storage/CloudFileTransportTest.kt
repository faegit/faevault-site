package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File

class CloudFileTransportTest {
    @Test fun `fake provider rejects upload after remote version changes`() {
        val provider = FakeProvider(byteArrayOf(1, 2, 3), CloudFileVersion(true, 3, 10, "v1"))
        val expected = provider.version()
        provider.replace(byteArrayOf(9), CloudFileVersion(true, 1, 11, "v2"))
        val source = tempFile(byteArrayOf(4, 5))

        assertThrows(CloudFileConflict::class.java) { provider.uploadIfUnchanged(source, expected) }
        assertArrayEquals(byteArrayOf(9), provider.bytes)
        source.delete()
    }

    @Test fun `fake provider streams file and advances version on matching CAS`() {
        val provider = FakeProvider(byteArrayOf(1), CloudFileVersion(true, 1, 10, "v1"))
        val source = tempFile(byteArrayOf(7, 8, 9))

        val uploaded = provider.uploadIfUnchanged(source, provider.version())

        assertArrayEquals(byteArrayOf(7, 8, 9), provider.bytes)
        assertEquals("v2", uploaded.etag)
        source.delete()
    }

    @Test fun `provider metadata without a stable version defers to authenticated content check`() {
        val expected = CloudFileVersion(exists = true, size = -1, lastModified = 0)

        assertEquals(false, CloudFileTransferGuard.requireUnchanged(expected, expected))
    }

    private class FakeProvider(
        initial: ByteArray,
        initialVersion: CloudFileVersion,
    ) : CloudFileTransport {
        var bytes = initial.copyOf()
            private set
        private var current = initialVersion

        override fun version(): CloudFileVersion = current

        override fun downloadTo(target: File): CloudFileVersion {
            target.outputStream().use { it.write(bytes) }
            return current
        }

        override fun uploadIfUnchanged(source: File, expected: CloudFileVersion): CloudFileVersion {
            CloudFileTransferGuard.requireUnchanged(expected, current)
            bytes = ByteArrayOutputStream().use { buffer ->
                source.inputStream().use { input -> input.copyTo(buffer) }
                buffer.toByteArray()
            }
            current = CloudFileVersion(true, bytes.size.toLong(), current.lastModified + 1, "v2")
            return current
        }

        fun replace(value: ByteArray, version: CloudFileVersion) {
            bytes = value.copyOf()
            current = version
        }
    }

    private fun tempFile(bytes: ByteArray): File =
        kotlin.io.path.createTempFile("cloud-provider", ".pmv").toFile().also { it.writeBytes(bytes) }
}
