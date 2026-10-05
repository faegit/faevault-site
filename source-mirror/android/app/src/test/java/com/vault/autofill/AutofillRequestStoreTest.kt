package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AutofillRequestStoreTest {
    @Test
    fun tokensAreSingleUseAndExpire() {
        var now = 100L
        val store = ExpiringRequestStore<String>(ttlMs = 20, capacity = 2, clock = { now })
        val token = store.put("secret-free request")

        assertEquals("secret-free request", store.take(token))
        assertNull(store.take(token))

        val expired = store.put("expired")
        now = 121L
        assertNull(store.take(expired))
    }

    @Test
    fun oldestRequestIsEvictedAtCapacity() {
        var now = 1L
        val store = ExpiringRequestStore<String>(ttlMs = 1_000, capacity = 2, clock = { now++ })
        val first = store.put("first")
        val second = store.put("second")
        val third = store.put("third")

        assertNull(store.take(first))
        assertEquals("second", store.take(second))
        assertEquals("third", store.take(third))
    }
}
