package com.vault.autofill

import android.view.autofill.AutofillId
import android.widget.inline.InlinePresentationSpec
import java.security.SecureRandom
import java.util.Base64
import java.util.LinkedHashMap

class ExpiringRequestStore<T>(
    private val ttlMs: Long,
    private val capacity: Int,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Item<T>(val value: T, val createdAt: Long)
    private val items = LinkedHashMap<String, Item<T>>()
    private val random = SecureRandom()

    @Synchronized
    fun put(value: T): String {
        purgeExpired()
        while (items.size >= capacity) items.remove(items.keys.first())
        val bytes = ByteArray(16).also(random::nextBytes)
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        items[token] = Item(value, clock())
        return token
    }

    @Synchronized
    fun take(token: String): T? {
        purgeExpired()
        return items.remove(token)?.value
    }

    @Synchronized
    fun peek(token: String): T? {
        purgeExpired()
        return items[token]?.value
    }

    @Synchronized
    fun remove(token: String): T? = items.remove(token)?.value

    @Synchronized
    fun clear() = items.clear()

    private fun purgeExpired() {
        val cutoff = clock() - ttlMs
        items.entries.removeAll { it.value.createdAt < cutoff }
    }
}

sealed interface PendingAutofillRequest {
    val form: ParsedForm<AutofillId>

    data class Fill(
        override val form: ParsedForm<AutofillId>,
        val inlineSpec: InlinePresentationSpec? = null,
    ) : PendingAutofillRequest
    data class Save(
        override val form: ParsedForm<AutofillId>,
        val candidate: SaveCandidate,
    ) : PendingAutofillRequest
}

object AutofillRequestStore {
    private val requests = ExpiringRequestStore<PendingAutofillRequest>(
        ttlMs = 2 * 60 * 1_000L,
        capacity = 32,
    )

    fun put(request: PendingAutofillRequest): String = requests.put(request)
    fun take(token: String): PendingAutofillRequest? = requests.take(token)
    fun peek(token: String): PendingAutofillRequest? = requests.peek(token)
    fun remove(token: String) = requests.remove(token)
    fun clear() = requests.clear()
}
