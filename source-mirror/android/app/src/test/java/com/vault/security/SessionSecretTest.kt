package com.vault.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SessionSecretTest {
    @Test
    fun `matches only the original mutable bytes`() {
        val input = "correct horse battery staple".encodeToByteArray()
        val secret = SessionSecret.fromUtf8(input)
        input.fill(0)

        assertTrue(secret.matches("correct horse battery staple".encodeToByteArray()))
        assertFalse(secret.matches("correct horse battery staplf".encodeToByteArray()))
        assertFalse(secret.matches("short".encodeToByteArray()))
    }

    @Test
    fun `scoped copy is cleared after normal and exceptional callbacks`() {
        val secret = SessionSecret.fromUtf8("master".encodeToByteArray())
        lateinit var normalCopy: ByteArray
        secret.useBytes { normalCopy = it }
        assertArrayEquals(ByteArray(normalCopy.size), normalCopy)

        lateinit var exceptionalCopy: ByteArray
        try {
            secret.useBytes {
                exceptionalCopy = it
                error("stop")
            }
            fail("callback exception must escape")
        } catch (_: IllegalStateException) {
            assertArrayEquals(ByteArray(exceptionalCopy.size), exceptionalCopy)
        }
    }

    @Test
    fun `closed secret cannot be used and exposes no zero argument reveal`() {
        val secret = SessionSecret.fromUtf8("master".encodeToByteArray())
        secret.close()
        try {
            secret.useBytes { }
            fail("closed secret must reject access")
        } catch (_: IllegalStateException) {
            // Expected.
        }
        assertFalse(SessionSecret::class.java.methods.any { it.name == "reveal" && it.parameterCount == 0 })
    }
}
