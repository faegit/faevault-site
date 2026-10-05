package com.vault.storage

import com.vault.crypto.PmvKdfProfile
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class PmvVaultHeaderCodecTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val password = "pāss-原始".encodeToByteArray()
    private val recovery = ByteArray(32) { (0x20 + it).toByte() }
    private val root = ByteArray(32) { (0x40 + it).toByte() }
    private val seed = ByteArray(32) { (it + 1).toByte() }
    private val salt = ByteArray(16) { (0xa0 + it).toByte() }
    private val nonces = PmvVaultHeaderCodec.Nonces(
        ByteArray(12) { (0x10 + it).toByte() },
        ByteArray(12) { (0x30 + it).toByte() },
        ByteArray(12) { (0x50 + it).toByte() },
    )

    @Test
    fun deterministicHeaderUnlocksWithPasswordAndRecovery() {
        val raw = create()
        assertEquals(PmvVaultHeaderCodec.HEADER_SIZE, raw.size)
        PmvVaultHeaderCodec.unlockWithPassword(raw, password).use {
            assertEquals(vaultId, it.header.vaultId)
            assertEquals(7L, it.header.keyRevision)
            assertEquals(11L, it.header.headerRevision)
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(raw, recovery).use {
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
    }

    @Test
    fun wrongCredentialsTamperingUnknownSuiteAndParameterChangesFailClosed() {
        val raw = create()
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithPassword(raw, "wrong".encodeToByteArray())
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithRecovery(raw, ByteArray(32))
        }
        for (offset in listOf(120, 190, 250, 500, raw.lastIndex)) {
            val changed = raw.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) {
                PmvVaultHeaderCodec.unlockWithPassword(changed, password)
            }
        }
        val suite = raw.copyOf().also { it[15] = 2 }
        assertThrows(IllegalArgumentException::class.java) { PmvVaultHeaderCodec.decode(suite) }
        val memory = raw.copyOf().also { it[53] = 0 }
        assertThrows(IllegalArgumentException::class.java) { PmvVaultHeaderCodec.decode(memory) }
    }

    @Test
    fun passwordRewrapKeepsRecoverySlotAndDualSlotSelectionIsAuthenticated() {
        val old = create()
        val newPassword = "new-password".encodeToByteArray()
        val updated = PmvVaultHeaderCodec.rewrapPassword(
            old, password, newPassword, ByteArray(16) { (0xc0 + it).toByte() }, 12,
            ByteArray(12) { (0x70 + it).toByte() },
        )
        assertThrows(IllegalArgumentException::class.java) { PmvVaultHeaderCodec.unlockWithPassword(updated, password) }
        PmvVaultHeaderCodec.unlockWithPassword(updated, newPassword).use { assertArrayEquals(root, it.vaultRootKey) }
        PmvVaultHeaderCodec.unlockWithRecovery(updated, recovery).use { assertArrayEquals(root, it.vaultRootKey) }
        PmvVaultHeaderCodec.selectLatestWithRecovery(old, updated, recovery).use {
            assertNotNull(it)
            assertEquals(12L, it!!.header.headerRevision)
        }

        val forgedRevision = old.copyOf().also { it[47] = 99 }
        PmvVaultHeaderCodec.selectLatestWithRecovery(forgedRevision, updated, recovery).use {
            assertNotNull(it)
            assertEquals(12L, it!!.header.headerRevision)
        }
    }

    @Test
    fun hardenedParametersRoundTripAndPasswordRewrapPreservesNonPasswordSlots() {
        val hardened = PmvVaultHeaderCodec.create(
            vaultId = vaultId,
            keyRevision = 7,
            headerRevision = 11,
            passwordUtf8 = password,
            recoverySecret = recovery,
            vaultRootKey = root,
            signingPrivateSeed = seed,
            salt = salt,
            kdfParameters = PmvKdfProfile.HARDENED.parameters,
            nonces = nonces,
        )
        assertEquals(PmvKdfProfile.HARDENED.parameters, PmvVaultHeaderCodec.decode(hardened).kdfParameters)
        PmvVaultHeaderCodec.unlockWithPassword(hardened, password).use {
            assertArrayEquals(root, it.vaultRootKey)
        }

        val standard = create()
        val before = PmvVaultHeaderCodec.decode(standard)
        val updated = PmvVaultHeaderCodec.rewrapPassword(
            raw = standard,
            oldPasswordUtf8 = password,
            newPasswordUtf8 = password,
            newSalt = ByteArray(16) { (0xc0 + it).toByte() },
            newHeaderRevision = 12,
            targetParameters = PmvKdfProfile.HARDENED.parameters,
            newNonce = ByteArray(12) { (0x70 + it).toByte() },
        )
        val after = PmvVaultHeaderCodec.decode(updated)
        assertEquals(PmvKdfProfile.HARDENED.parameters, after.kdfParameters)
        assertEquals(before.keyRevision, after.keyRevision)
        assertEquals(12L, after.headerRevision)
        assertArrayEquals(before.recoveryEnvelope.nonce, after.recoveryEnvelope.nonce)
        assertArrayEquals(before.recoveryEnvelope.ciphertext, after.recoveryEnvelope.ciphertext)
        assertArrayEquals(before.signingSeedEnvelope.nonce, after.signingSeedEnvelope.nonce)
        assertArrayEquals(before.signingSeedEnvelope.ciphertext, after.signingSeedEnvelope.ciphertext)
        PmvVaultHeaderCodec.unlockWithPassword(updated, password).use {
            assertArrayEquals(root, it.vaultRootKey)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(updated, recovery).use {
            assertArrayEquals(root, it.vaultRootKey)
        }
    }

    @Test
    fun rootKeyUnlockAuthenticatesWholeHeaderAndSigningIdentity() {
        val raw = create()
        PmvVaultHeaderCodec.unlockWithRootKey(raw, root).use {
            assertEquals(11L, it.header.headerRevision)
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithRootKey(raw, ByteArray(32))
        }
        val tampered = raw.copyOf().also { it[500] = (it[500].toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithRootKey(tampered, root)
        }
    }

    @Test
    fun recoveryRotationPreservesRootSigningIdentityAndPasswordEnvelope() {
        val old = create()
        val oldHeader = PmvVaultHeaderCodec.decode(old)
        val newRecovery = ByteArray(32) { (0x60 + it).toByte() }
        val updated = PmvVaultHeaderCodec.rewrapRecovery(
            old,
            recovery,
            newRecovery,
            12,
            ByteArray(12) { (0x72 + it).toByte() },
        )
        val updatedHeader = PmvVaultHeaderCodec.decode(updated)

        assertEquals(12L, updatedHeader.headerRevision)
        assertArrayEquals(oldHeader.passwordEnvelope.nonce, updatedHeader.passwordEnvelope.nonce)
        assertArrayEquals(oldHeader.passwordEnvelope.ciphertext, updatedHeader.passwordEnvelope.ciphertext)
        assertArrayEquals(oldHeader.signingPublicKey, updatedHeader.signingPublicKey)
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithRecovery(updated, recovery)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(updated, newRecovery).use {
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
        PmvVaultHeaderCodec.unlockWithPassword(updated, password).use {
            assertArrayEquals(root, it.vaultRootKey)
        }
    }

    @Test
    fun passwordCanRegenerateRecoveryWithoutOldRecoverySecret() {
        val old = create()
        val oldHeader = PmvVaultHeaderCodec.decode(old)
        val newRecovery = ByteArray(32) { (0x80 + it).toByte() }
        val updated = PmvVaultHeaderCodec.rewrapRecoveryWithPassword(
            old,
            password,
            newRecovery,
            12,
            ByteArray(12) { (0x82 + it).toByte() },
        )
        val updatedHeader = PmvVaultHeaderCodec.decode(updated)

        assertEquals(12L, updatedHeader.headerRevision)
        assertArrayEquals(oldHeader.passwordEnvelope.nonce, updatedHeader.passwordEnvelope.nonce)
        assertArrayEquals(oldHeader.passwordEnvelope.ciphertext, updatedHeader.passwordEnvelope.ciphertext)
        assertArrayEquals(oldHeader.signingPublicKey, updatedHeader.signingPublicKey)
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithRecovery(updated, recovery)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(updated, newRecovery).use {
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
        PmvVaultHeaderCodec.unlockWithPassword(updated, password).use {
            assertArrayEquals(root, it.vaultRootKey)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.rewrapRecoveryWithPassword(old, "wrong".encodeToByteArray(), newRecovery, 12)
        }
    }

    @Test
    fun recoveryUnlockCanRewrapPasswordWithoutChangingRootOrRecovery() {
        val newPassword = "recovered-password".encodeToByteArray()
        val updated = PmvVaultHeaderCodec.rewrapPasswordWithRecovery(
            create(),
            recovery,
            newPassword,
            ByteArray(16) { (0xd0 + it).toByte() },
            12,
            ByteArray(12) { (0x7e + it).toByte() },
        )

        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultHeaderCodec.unlockWithPassword(updated, password)
        }
        PmvVaultHeaderCodec.unlockWithPassword(updated, newPassword).use {
            assertArrayEquals(root, it.vaultRootKey)
            assertArrayEquals(seed, it.signingPrivateSeed)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(updated, recovery).use {
            assertArrayEquals(root, it.vaultRootKey)
        }
    }

    @Test
    fun unlockCandidatesReturnsEveryAuthenticatedSlotNewestFirst() {
        val old = create()
        val newer = PmvVaultHeaderCodec.rewrapPassword(
            old,
            password,
            "new-password".encodeToByteArray(),
            ByteArray(16) { (0xc0 + it).toByte() },
            12,
            ByteArray(12) { (0x70 + it).toByte() },
        )
        val recoveryCandidates = PmvVaultHeaderCodec.unlockCandidatesWithRecovery(old, newer, recovery)
        try {
            assertEquals(listOf(12L, 11L), recoveryCandidates.map { it.header.headerRevision })
        } finally {
            recoveryCandidates.forEach(PmvVaultHeaderCodec.UnlockedHeader::close)
        }

        val forged = old.copyOf().also { it[47] = 99 }
        val rootCandidates = PmvVaultHeaderCodec.unlockCandidatesWithRootKey(forged, newer, root)
        try {
            assertEquals(1, rootCandidates.size)
            assertEquals(12L, rootCandidates.single().header.headerRevision)
            assertFalse(rootCandidates.single().vaultRootKey === root)
            assertTrue(root.contentEquals(rootCandidates.single().vaultRootKey))
        } finally {
            rootCandidates.forEach(PmvVaultHeaderCodec.UnlockedHeader::close)
        }
    }

    private fun create(): ByteArray = PmvVaultHeaderCodec.create(
        vaultId = vaultId,
        keyRevision = 7,
        headerRevision = 11,
        passwordUtf8 = password,
        recoverySecret = recovery,
        vaultRootKey = root,
        signingPrivateSeed = seed,
        salt = salt,
        nonces = nonces,
    )
}
