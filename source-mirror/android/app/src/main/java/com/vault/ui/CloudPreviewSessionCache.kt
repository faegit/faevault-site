package com.vault.ui

import kotlinx.coroutines.CompletableDeferred

/**
 * Keeps read-only cloud inspection state inside the ViewModel lifetime.
 * Re-entering the settings card must not start the same network inspection again.
 */
internal class CloudPreviewSessionCache<T> {
    private data class Slot<T>(
        val associationKey: String,
        val checking: Boolean,
        val value: T?,
        val completion: CompletableDeferred<T>,
    )

    private val slots = mutableMapOf<String, Slot<T>>()

    @Synchronized
    fun cached(provider: String, associationKey: String): T? =
        slots[provider]?.takeIf { it.associationKey == associationKey && !it.checking }?.value

    @Synchronized
    fun begin(provider: String, associationKey: String, force: Boolean = false): Boolean {
        val current = slots[provider]
        if (current?.associationKey == associationKey && current.checking) return false
        if (!force && current?.associationKey == associationKey && current.value != null) return false
        slots[provider] = Slot(
            associationKey,
            checking = true,
            value = null,
            completion = CompletableDeferred(),
        )
        return true
    }

    suspend fun await(provider: String, associationKey: String): T? {
        val slot = synchronized(this) {
            slots[provider]?.takeIf { it.associationKey == associationKey }
        } ?: return null
        return slot.value ?: slot.completion.await()
    }

    @Synchronized
    fun complete(provider: String, associationKey: String, value: T) {
        if (slots[provider]?.associationKey == associationKey) {
            val pending = requireNotNull(slots[provider])
            slots[provider] = Slot(
                associationKey,
                checking = false,
                value = value,
                completion = pending.completion,
            )
            pending.completion.complete(value)
        }
    }

    @Synchronized
    fun cancel(provider: String, associationKey: String) {
        if (slots[provider]?.associationKey == associationKey && slots[provider]?.checking == true) {
            slots.remove(provider)?.completion?.cancel()
        }
    }
}
