package com.vault.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultDeviceIdentityTest {
    @Test
    fun `generate encodes and decodes with stable public key`() {
        VaultDeviceIdentity.generate().use { identity ->
            val encoded = VaultDeviceIdentity.encode(identity)
            assertEquals(VaultDeviceIdentity.ENCODED_SIZE, encoded.size)
            VaultDeviceIdentity.decode(encoded).use { decoded ->
                assertEquals(identity.deviceId, decoded.deviceId)
                assertArrayEquals(identity.publicKey, decoded.publicKey)
                assertTrue(identity.withPrivateSeed { a -> decoded.withPrivateSeed { b -> a.contentEquals(b) } })
            }
        }
    }

    @Test
    fun `decode rejects tampered bytes and cleared identity rejects use`() {
        VaultDeviceIdentity.generate().use { identity ->
            val encoded = VaultDeviceIdentity.encode(identity)
            val tampered = encoded.copyOf().also { it[encoded.size - 2] = (it[encoded.size - 2].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) { VaultDeviceIdentity.decode(tampered) }

            val decoded = VaultDeviceIdentity.decode(encoded)
            decoded.close()
            assertTrue(decoded.isCleared)
            assertThrows(IllegalStateException::class.java) { decoded.withPrivateSeed { it } }
        }
    }

    @Test
    fun `fromSeed rejects wrong seed size and matches derived public key`() {
        assertThrows(IllegalArgumentException::class.java) {
            VaultDeviceIdentity.fromSeed(java.util.UUID.randomUUID(), ByteArray(16))
        }
        val seed = ByteArray(32) { (it + 1).toByte() }
        VaultDeviceIdentity.fromSeed(java.util.UUID.randomUUID(), seed).use { identity ->
            assertFalse(identity.publicKey.all { it == 0.toByte() })
        }
    }
}
