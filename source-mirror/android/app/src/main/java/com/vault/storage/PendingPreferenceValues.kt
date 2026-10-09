package com.vault.storage

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Only ordinary setting primitives are retained until their queued write succeeds. */
internal class PendingPreferenceValues {
    internal data class Token(val prefName: String, val key: String, val generation: Long)
    private data class Value(val generation: Long, val value: Any)
    private val generation = AtomicLong()
    private val pending = ConcurrentHashMap<Pair<String, String>, Value>()

    @Synchronized
    fun stage(prefName: String, key: String, value: Any): Token {
        require(value is Boolean || value is Int || value is String)
        val token = Token(prefName, key, generation.incrementAndGet())
        pending[prefName to key] = Value(token.generation, value)
        return token
    }

    fun value(prefName: String, key: String): Any? = pending[prefName to key]?.value

    fun persisted(token: Token) {
        pending.computeIfPresent(token.prefName to token.key) { _, current ->
            if (current.generation == token.generation) null else current
        }
    }
}
