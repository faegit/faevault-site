package com.vault.ui

import kotlinx.coroutines.sync.Mutex

/** Serializes disk transactions and rejects UI snapshots read before a newer click. */
internal class RemoteUpdateSettingsGate {
    val persistenceMutex = Mutex()
    private var version = 0L

    val revision: Long get() = synchronized(this) { version }

    fun <T> change(block: (Long) -> T): T = synchronized(this) {
        version += 1
        block(version)
    }

    fun publishIfCurrent(capturedRevision: Long, block: () -> Unit): Boolean = synchronized(this) {
        if (version != capturedRevision) false else {
            block()
            true
        }
    }
}
