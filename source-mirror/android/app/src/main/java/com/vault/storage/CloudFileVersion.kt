package com.vault.storage

/** Provider-neutral optimistic concurrency token for file-backed cloud synchronization. */
data class CloudFileVersion(
    val exists: Boolean,
    val size: Long,
    val lastModified: Long,
    val etag: String? = null,
) {
    fun matches(other: CloudFileVersion): Boolean {
        if (exists != other.exists) return false
        if (!exists) return true
        if (etag != null || other.etag != null) return etag != null && etag == other.etag
        return size == other.size && lastModified == other.lastModified
    }
}

class CloudFileConflict(message: String = "云端文件已被其他设备更新") : IllegalStateException(message)

/** Small file-only seam used by provider fakes; implementations own streaming and durability. */
interface CloudFileTransport {
    fun version(): CloudFileVersion
    fun downloadTo(target: java.io.File): CloudFileVersion
    fun uploadIfUnchanged(source: java.io.File, expected: CloudFileVersion): CloudFileVersion
}

object CloudFileTransferGuard {
    /**
     * Checks provider metadata when it is usable. A false result means the provider did not
     * expose a stable version token; callers must compare authenticated file content instead.
     */
    fun requireUnchanged(expected: CloudFileVersion, actual: CloudFileVersion): Boolean {
        if (expected.exists && expected.etag == null && (expected.size < 0L || expected.lastModified <= 0L)) {
            return false
        }
        if (!expected.matches(actual)) throw CloudFileConflict()
        return true
    }
}
