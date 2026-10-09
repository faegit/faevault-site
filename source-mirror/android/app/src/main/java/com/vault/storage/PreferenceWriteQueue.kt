package com.vault.storage

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/** One consumer preserves submission order independently of caller lifetime. */
internal class PreferenceWriteQueue(scope: CoroutineScope, private val onFailure: (Throwable) -> Unit) {
    private data class Write(val block: () -> Unit, val completion: CompletableDeferred<Unit>)
    private val pending = Channel<Write>(Channel.UNLIMITED)

    init {
        scope.launch {
            for (write in pending) {
                try {
                    write.block()
                    write.completion.complete(Unit)
                } catch (failure: Exception) {
                    onFailure(failure)
                    write.completion.completeExceptionally(failure)
                }
            }
        }
    }

    fun submit(block: () -> Unit): Deferred<Unit> {
        val completion = CompletableDeferred<Unit>()
        check(pending.trySend(Write(block, completion)).isSuccess)
        return completion
    }
}
