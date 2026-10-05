package com.vault.storage

import java.io.File

/** Copies a complete PMVE file while excluding every cooperating writer. */
internal fun copyPmvEFileSnapshot(source: File, target: File) {
    require(source.canonicalFile != target.canonicalFile) { "同步快照不得覆盖当前保险库" }
    PmvAppendOnlyFile.withExclusiveWriterLock(source) {
        source.inputStream().buffered().use { input ->
            target.outputStream().buffered().use { output -> input.copyTo(output) }
        }
    }
}
