package com.vault.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class DeviceUnlockEnvelopeTest {
    private val identity = VaultKeyIdentity(
        vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
        keyRevision = 7,
        signingPublicKey = ByteArray(32) { (it + 1).toByte() },
    )

    @Test
    fun `PMVE RootKey round trip retains all binding fields`() {
        val rootKey = ByteArray(32) { (it * 3).toByte() }
        val encoded = DeviceUnlockEnvelopeCodec.encode(
            DeviceUnlockMaterial.pmveRootKey(rootKey, identity),
        )

        val decoded = DeviceUnlockEnvelopeCodec.decode(encoded)

        assertEquals(DeviceUnlockKeyKind.PMVE_ROOT_KEY, decoded.kind)
        assertEquals(identity, decoded.binding)
        decoded.withSecret(identity) { assertArrayEquals(rootKey, it) }
        decoded.close()
        encoded.fill(0)
        rootKey.fill(0)
    }

    @Test
    fun `RootKey refuses a different vault signing identity or key revision`() {
        val material = DeviceUnlockMaterial.pmveRootKey(ByteArray(32) { 9 }, identity)
        val wrong = VaultKeyIdentity(
            vaultId = identity.vaultId,
            keyRevision = identity.keyRevision + 1,
            signingPublicKey = identity.copySigningPublicKey(),
        )

        assertThrows(SecurityException::class.java) {
            material.withSecret(wrong) { error("must not expose RootKey") }
        }
        material.close()
    }

    @Test
    fun `temporary secret copy is cleared after use`() {
        val material = DeviceUnlockMaterial.pmveRootKey(ByteArray(32) { 4 }, identity)
        lateinit var exposed: ByteArray

        material.withSecret(identity) { exposed = it }

        assertTrue(exposed.all { it == 0.toByte() })
        material.close()
    }

    @Test
    fun `closing session credential clears it and prevents later reveal`() {
        val credential = VaultSessionCredential.RootKey(ByteArray(32) { 5 }, identity)

        credential.close()

        assertTrue(credential.isCleared)
        assertThrows(IllegalStateException::class.java) {
            credential.withRootKey(identity) { }
        }
    }
}
