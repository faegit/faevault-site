package com.vault.storage

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Keep keystore-backed writes off the caller thread while preserving click order. */
internal class CloudSettingsWriteQueue(private val dispatcher: CoroutineDispatcher = Dispatchers.IO) {
    private val mutex = Mutex()

    suspend fun <T> write(block: () -> T): T = mutex.withLock {
        withContext(dispatcher) { block() }
    }
}
