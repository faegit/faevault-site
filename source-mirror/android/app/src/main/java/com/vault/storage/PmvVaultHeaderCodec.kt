package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.PmvKdfParameters
import com.vault.crypto.PmvKdfPolicy
import com.vault.crypto.PmvKdfProfile
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Fixed 4 KiB PMV v1 bootstrap header and RootKey envelopes. */
object PmvVaultHeaderCodec {
    const val HEADER_SIZE = PmvContainerFormat.VAULT_HEADER_SIZE
    const val VERSION = 1
    const val SUITE_1 = 1
    const val PASSWORD_KDF_ARGON2ID = 1
    const val RECOVERY_KDF_HKDF_SHA256 = 2
    const val SIGNING_KDF_KEY_WRAP = 3
    const val PRIMARY_OFFSET = PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET
    const val SECONDARY_OFFSET = PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET

    private const val AUTH_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val ENVELOPE_CIPHER_SIZE = PmvKeySchedule.KEY_SIZE + PmvContainerFormat.GCM_TAG_SIZE
    private const val ENVELOPE_SIZE = NONCE_SIZE + ENVELOPE_CIPHER_SIZE
    private const val PASSWORD_ENVELOPE_OFFSET = 112
    private const val RECOVERY_ENVELOPE_OFFSET = PASSWORD_ENVELOPE_OFFSET + ENVELOPE_SIZE
    private const val SIGNING_ENVELOPE_OFFSET = RECOVERY_ENVELOPE_OFFSET + ENVELOPE_SIZE
    private const val RESERVED_OFFSET = SIGNING_ENVELOPE_OFFSET + ENVELOPE_SIZE
    private const val AUTH_OFFSET = HEADER_SIZE - AUTH_SIZE
    private val MAGIC = "PMVH".encodeToByteArray()
    private val AAD_DOMAIN = "pmv/v1/vault-header-envelope\u0000".encodeToByteArray()
    private val RECOVERY_INFO = "pmv/v1/recovery-kek".encodeToByteArray()

    enum class SlotType(val id: Int) { PASSWORD(1), RECOVERY(2), SIGNING_PRIVATE_SEED(3) }

    data class Envelope(val nonce: ByteArray, val ciphertext: ByteArray) {
        init {
            require(nonce.size == NONCE_SIZE) { "Envelope nonce must be 12 bytes" }
            require(ciphertext.size == ENVELOPE_CIPHER_SIZE) { "Envelope ciphertext must be 48 bytes" }
        }
    }

    data class Header(
        val vaultId: UUID,
        val keyRevision: Long,
        val headerRevision: Long,
        val kdfParameters: PmvKdfParameters,
        val salt: ByteArray,
        val signingPublicKey: ByteArray,
        val passwordEnvelope: Envelope,
        val recoveryEnvelope: Envelope,
        val signingSeedEnvelope: Envelope,
    ) {
        init {
            require(keyRevision >= 0) { "keyRevision must be non-negative" }
            require(headerRevision >= 0) { "headerRevision must be non-negative" }
            PmvKdfPolicy.validate(kdfParameters)
            require(salt.size == PmvKeySchedule.KDF_SALT_SIZE) { "Argon2id salt must be 16 bytes" }
            require(signingPublicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
        }
    }

    data class Nonces(
        val password: ByteArray,
        val recovery: ByteArray,
        val signingSeed: ByteArray,
    ) {
        init {
            require(password.size == NONCE_SIZE && recovery.size == NONCE_SIZE && signingSeed.size == NONCE_SIZE) {
                "All PMVH nonces must be 12 bytes"
            }
        }

        companion object {
            fun random(random: SecureRandom = SecureRandom()): Nonces = Nonces(
                ByteArray(NONCE_SIZE).also { random.nextBytes(it) },
                ByteArray(NONCE_SIZE).also { random.nextBytes(it) },
                ByteArray(NONCE_SIZE).also { random.nextBytes(it) },
            )
        }
    }

    class UnlockedHeader internal constructor(
        val header: Header,
        val vaultRootKey: ByteArray,
        val signingPrivateSeed: ByteArray,
        val superblockAuthenticationKey: ByteArray,
    ) : AutoCloseable {
        override fun close() {
            vaultRootKey.fill(0)
            signingPrivateSeed.fill(0)
            superblockAuthenticationKey.fill(0)
        }
    }

    fun create(
        vaultId: UUID,
        keyRevision: Long,
        headerRevision: Long,
        passwordUtf8: ByteArray,
        recoverySecret: ByteArray,
        vaultRootKey: ByteArray,
        signingPrivateSeed: ByteArray,
        salt: ByteArray,
        kdfParameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
        nonces: Nonces = Nonces.random(),
    ): ByteArray {
        require(recoverySecret.size == PmvKeySchedule.KEY_SIZE) { "Recovery secret must be 32 bytes" }
        require(vaultRootKey.size == PmvKeySchedule.KEY_SIZE) { "Vault RootKey must be 32 bytes" }
        require(signingPrivateSeed.size == 32) { "Ed25519 private seed must be 32 bytes" }
        val publicKey = Ed25519PrivateKeyParameters(signingPrivateSeed, 0).generatePublicKey().encoded
        PmvKdfPolicy.validate(kdfParameters)
        val passwordKek = PmvKeySchedule.derivePasswordKek(passwordUtf8, salt, kdfParameters)
        val recoveryKek = deriveRecoveryKek(recoverySecret, vaultId)
        val rootKeys = PmvKeySchedule.deriveRootKeys(vaultRootKey, vaultId)
        try {
            val header = Header(
                vaultId, keyRevision, headerRevision, kdfParameters, salt.copyOf(), publicKey,
                seal(passwordKek, nonces.password, vaultRootKey, envelopeAad(vaultId, keyRevision, publicKey, SlotType.PASSWORD, salt, kdfParameters)),
                seal(recoveryKek, nonces.recovery, vaultRootKey, envelopeAad(vaultId, keyRevision, publicKey, SlotType.RECOVERY, vaultId.toBytes())),
                seal(rootKeys.keyWrapKey, nonces.signingSeed, signingPrivateSeed, envelopeAad(vaultId, keyRevision, publicKey, SlotType.SIGNING_PRIVATE_SEED, vaultId.toBytes())),
            )
            return encodeAuthenticated(header, rootKeys.integrityKey)
        } finally {
            passwordKek.fill(0)
            recoveryKek.fill(0)
            rootKeys.close()
        }
    }

    fun decode(raw: ByteArray): Header {
        require(raw.size == HEADER_SIZE) { "PMVH header must be exactly 4096 bytes" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals(MAGIC)) { "Invalid PMVH magic" }
        require(input.int == VERSION) { "Unsupported PMVH version" }
        require(input.int == HEADER_SIZE) { "Invalid PMVH header size" }
        require(input.int == SUITE_1) { "Unsupported PMVH crypto suite" }
        val vaultId = UUID(input.long, input.long)
        val keyRevision = input.long.also { require(it >= 0) { "Invalid PMVH key revision" } }
        val headerRevision = input.long.also { require(it >= 0) { "Invalid PMVH header revision" } }
        require(input.int == PASSWORD_KDF_ARGON2ID) { "Unsupported PMVH password KDF" }
        val kdfParameters = PmvKdfParameters(input.int, input.int, input.int).also(PmvKdfPolicy::validate)
        val salt = ByteArray(16).also(input::get)
        val publicKey = ByteArray(32).also(input::get)
        require(publicKey.any { it != 0.toByte() }) { "Invalid Ed25519 public key" }
        val password = input.getEnvelope()
        val recovery = input.getEnvelope()
        val signing = input.getEnvelope()
        while (input.position() < AUTH_OFFSET) require(input.get() == 0.toByte()) { "PMVH reserved bytes must be zero" }
        return Header(vaultId, keyRevision, headerRevision, kdfParameters, salt, publicKey, password, recovery, signing)
    }

    fun unlockWithPassword(raw: ByteArray, passwordUtf8: ByteArray): UnlockedHeader {
        val header = decode(raw)
        val kek = PmvKeySchedule.derivePasswordKek(passwordUtf8, header.salt, header.kdfParameters)
        return try {
            unlock(raw, header, kek, SlotType.PASSWORD)
        } finally {
            kek.fill(0)
        }
    }

    fun unlockWithRecovery(raw: ByteArray, recoverySecret: ByteArray): UnlockedHeader {
        require(recoverySecret.size == PmvKeySchedule.KEY_SIZE) { "Recovery secret must be 32 bytes" }
        val header = decode(raw)
        val kek = deriveRecoveryKek(recoverySecret, header.vaultId)
        return try {
            unlock(raw, header, kek, SlotType.RECOVERY)
        } finally {
            kek.fill(0)
        }
    }

    /** Authenticates the complete header and unwraps its signing seed using an already-held RootKey. */
    fun unlockWithRootKey(raw: ByteArray, vaultRootKey: ByteArray): UnlockedHeader {
        require(vaultRootKey.size == PmvKeySchedule.KEY_SIZE) { "Vault RootKey must be 32 bytes" }
        val header = decode(raw)
        return unlockWithVerifiedRoot(raw, header, vaultRootKey.copyOf())
    }

    /** Rewraps only the password slot; recovery and signing envelopes remain valid. */
    fun rewrapPassword(
        raw: ByteArray,
        oldPasswordUtf8: ByteArray,
        newPasswordUtf8: ByteArray,
        newSalt: ByteArray,
        newHeaderRevision: Long,
        newNonce: ByteArray = Nonces.random().password,
        targetParameters: PmvKdfParameters? = null,
    ): ByteArray = unlockWithPassword(raw, oldPasswordUtf8).use { unlocked ->
        require(newHeaderRevision > unlocked.header.headerRevision) { "Header revision must increase" }
        val parameters = targetParameters ?: unlocked.header.kdfParameters
        PmvKdfPolicy.validate(parameters)
        val kek = PmvKeySchedule.derivePasswordKek(newPasswordUtf8, newSalt, parameters)
        try {
            val updated = unlocked.header.copy(
                headerRevision = newHeaderRevision,
                kdfParameters = parameters,
                salt = newSalt.copyOf(),
                passwordEnvelope = seal(
                    kek, newNonce, unlocked.vaultRootKey,
                    envelopeAad(unlocked.header.vaultId, unlocked.header.keyRevision, unlocked.header.signingPublicKey, SlotType.PASSWORD, newSalt, parameters),
                ),
            )
            encodeAuthenticated(updated, unlocked.superblockAuthenticationKey)
        } finally {
            kek.fill(0)
        }
    }

    /** Rewraps the recovery slot while preserving the RootKey, signing identity, and password slot. */
    fun rewrapRecovery(
        raw: ByteArray,
        oldRecoverySecret: ByteArray,
        newRecoverySecret: ByteArray,
        newHeaderRevision: Long,
        newNonce: ByteArray = Nonces.random().recovery,
    ): ByteArray = unlockWithRecovery(raw, oldRecoverySecret).use { unlocked ->
        require(newRecoverySecret.size == PmvKeySchedule.KEY_SIZE) { "Recovery secret must be 32 bytes" }
        require(newHeaderRevision > unlocked.header.headerRevision) { "Header revision must increase" }
        val kek = deriveRecoveryKek(newRecoverySecret, unlocked.header.vaultId)
        try {
            val updated = unlocked.header.copy(
                headerRevision = newHeaderRevision,
                recoveryEnvelope = seal(
                    kek, newNonce, unlocked.vaultRootKey,
                    envelopeAad(
                        unlocked.header.vaultId,
                        unlocked.header.keyRevision,
                        unlocked.header.signingPublicKey,
                        SlotType.RECOVERY,
                        unlocked.header.vaultId.toBytes(),
                    ),
                ),
            )
            encodeAuthenticated(updated, unlocked.superblockAuthenticationKey)
        } finally {
            kek.fill(0)
        }
    }

    /**
     * Rewraps the recovery slot using the password credential (no old recovery secret required).
     * Used by "重新生成恢复密钥" when the user is already unlocked with the master password.
     */
    fun rewrapRecoveryWithPassword(
        raw: ByteArray,
        passwordUtf8: ByteArray,
        newRecoverySecret: ByteArray,
        newHeaderRevision: Long,
        newNonce: ByteArray = Nonces.random().recovery,
    ): ByteArray = unlockWithPassword(raw, passwordUtf8).use { unlocked ->
        require(newRecoverySecret.size == PmvKeySchedule.KEY_SIZE) { "Recovery secret must be 32 bytes" }
        require(newHeaderRevision > unlocked.header.headerRevision) { "Header revision must increase" }
        val kek = deriveRecoveryKek(newRecoverySecret, unlocked.header.vaultId)
        try {
            val updated = unlocked.header.copy(
                headerRevision = newHeaderRevision,
                recoveryEnvelope = seal(
                    kek, newNonce, unlocked.vaultRootKey,
                    envelopeAad(
                        unlocked.header.vaultId,
                        unlocked.header.keyRevision,
                        unlocked.header.signingPublicKey,
                        SlotType.RECOVERY,
                        unlocked.header.vaultId.toBytes(),
                    ),
                ),
            )
            encodeAuthenticated(updated, unlocked.superblockAuthenticationKey)
        } finally {
            kek.fill(0)
        }
    }

    /** Uses the recovery credential to install a new password envelope over the same RootKey. */
    fun rewrapPasswordWithRecovery(
        raw: ByteArray,
        recoverySecret: ByteArray,
        newPasswordUtf8: ByteArray,
        newSalt: ByteArray,
        newHeaderRevision: Long,
        newNonce: ByteArray = Nonces.random().password,
        targetParameters: PmvKdfParameters? = null,
    ): ByteArray = unlockWithRecovery(raw, recoverySecret).use { unlocked ->
        require(newHeaderRevision > unlocked.header.headerRevision) { "Header revision must increase" }
        val parameters = targetParameters ?: unlocked.header.kdfParameters
        PmvKdfPolicy.validate(parameters)
        val kek = PmvKeySchedule.derivePasswordKek(newPasswordUtf8, newSalt, parameters)
        try {
            val updated = unlocked.header.copy(
                headerRevision = newHeaderRevision,
                kdfParameters = parameters,
                salt = newSalt.copyOf(),
                passwordEnvelope = seal(
                    kek, newNonce, unlocked.vaultRootKey,
                    envelopeAad(
                        unlocked.header.vaultId,
                        unlocked.header.keyRevision,
                        unlocked.header.signingPublicKey,
                        SlotType.PASSWORD,
                        newSalt,
                        parameters,
                    ),
                ),
            )
            encodeAuthenticated(updated, unlocked.superblockAuthenticationKey)
        } finally {
            kek.fill(0)
        }
    }

    fun unlockCandidatesWithPassword(
        slotA: ByteArray,
        slotB: ByteArray,
        passwordUtf8: ByteArray,
    ): List<UnlockedHeader> = unlockCandidates(slotA, slotB) { unlockWithPassword(it, passwordUtf8) }

    fun unlockCandidatesWithRecovery(
        slotA: ByteArray,
        slotB: ByteArray,
        recoverySecret: ByteArray,
    ): List<UnlockedHeader> = unlockCandidates(slotA, slotB) { unlockWithRecovery(it, recoverySecret) }

    fun unlockCandidatesWithRootKey(
        slotA: ByteArray,
        slotB: ByteArray,
        vaultRootKey: ByteArray,
    ): List<UnlockedHeader> = unlockCandidates(slotA, slotB) { unlockWithRootKey(it, vaultRootKey) }

    fun selectLatestWithPassword(slotA: ByteArray, slotB: ByteArray, passwordUtf8: ByteArray): UnlockedHeader? =
        selectLatest(unlockCandidatesWithPassword(slotA, slotB, passwordUtf8))

    fun selectLatestWithRecovery(slotA: ByteArray, slotB: ByteArray, recoverySecret: ByteArray): UnlockedHeader? =
        selectLatest(unlockCandidatesWithRecovery(slotA, slotB, recoverySecret))

    private fun selectLatest(candidates: List<UnlockedHeader>): UnlockedHeader? {
        candidates.drop(1).forEach(UnlockedHeader::close)
        return candidates.firstOrNull()
    }

    private fun unlockCandidates(
        slotA: ByteArray,
        slotB: ByteArray,
        unlocker: (ByteArray) -> UnlockedHeader,
    ): List<UnlockedHeader> = listOf(slotA, slotB)
        .mapNotNull { raw ->
            try {
                unlocker(raw)
            } catch (_: IllegalArgumentException) {
                null
            }
        }
        .sortedWith(compareByDescending<UnlockedHeader> { it.header.headerRevision }.thenByDescending { it.header.keyRevision })

    private fun unlock(raw: ByteArray, header: Header, kek: ByteArray, slot: SlotType): UnlockedHeader {
        val envelope = if (slot == SlotType.PASSWORD) header.passwordEnvelope else header.recoveryEnvelope
        val kdfSalt = if (slot == SlotType.PASSWORD) header.salt else header.vaultId.toBytes()
        val rootKey = open(
            kek,
            envelope,
            envelopeAad(
                header.vaultId,
                header.keyRevision,
                header.signingPublicKey,
                slot,
                kdfSalt,
                header.kdfParameters,
            ),
        )
        return unlockWithVerifiedRoot(raw, header, rootKey)
    }

    private fun unlockWithVerifiedRoot(raw: ByteArray, header: Header, rootKey: ByteArray): UnlockedHeader {
        val rootKeys = try {
            PmvKeySchedule.deriveRootKeys(rootKey, header.vaultId)
        } catch (error: Throwable) {
            rootKey.fill(0)
            throw error
        }
        var unwrappedSigningSeed: ByteArray? = null
        try {
            verifyHeaderAuthentication(raw, rootKeys.integrityKey)
            val signingSeed = open(
                rootKeys.keyWrapKey,
                header.signingSeedEnvelope,
                envelopeAad(header.vaultId, header.keyRevision, header.signingPublicKey, SlotType.SIGNING_PRIVATE_SEED, header.vaultId.toBytes()),
            )
            unwrappedSigningSeed = signingSeed
            val derivedPublic = Ed25519PrivateKeyParameters(signingSeed, 0).generatePublicKey().encoded
            if (!MessageDigest.isEqual(derivedPublic, header.signingPublicKey)) {
                throw IllegalArgumentException("PMVH signing seed does not match public key")
            }
            return UnlockedHeader(header, rootKey, signingSeed, rootKeys.integrityKey.copyOf())
        } catch (error: Throwable) {
            unwrappedSigningSeed?.fill(0)
            rootKey.fill(0)
            throw error
        } finally {
            rootKeys.close()
        }
    }

    private fun encodeAuthenticated(header: Header, integrityKey: ByteArray): ByteArray {
        require(integrityKey.size == 32) { "Integrity key must be 32 bytes" }
        val output = ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC); putInt(VERSION); putInt(HEADER_SIZE); putInt(SUITE_1)
            putLong(header.vaultId.mostSignificantBits); putLong(header.vaultId.leastSignificantBits)
            putLong(header.keyRevision); putLong(header.headerRevision)
            putInt(PASSWORD_KDF_ARGON2ID); putInt(header.kdfParameters.memoryKiB)
            putInt(header.kdfParameters.iterations); putInt(header.kdfParameters.parallelism)
            put(header.salt); put(header.signingPublicKey)
            putEnvelope(header.passwordEnvelope); putEnvelope(header.recoveryEnvelope); putEnvelope(header.signingSeedEnvelope)
            position(AUTH_OFFSET)
        }.array()
        hmac(integrityKey, output.copyOfRange(0, AUTH_OFFSET)).copyInto(output, AUTH_OFFSET)
        return output
    }

    private fun verifyHeaderAuthentication(raw: ByteArray, integrityKey: ByteArray) {
        val expected = hmac(integrityKey, raw.copyOfRange(0, AUTH_OFFSET))
        val actual = raw.copyOfRange(AUTH_OFFSET, HEADER_SIZE)
        require(MessageDigest.isEqual(expected, actual)) { "PMVH authentication failed" }
    }

    private fun envelopeAad(
        vaultId: UUID,
        keyRevision: Long,
        publicKey: ByteArray,
        slot: SlotType,
        salt: ByteArray,
        passwordKdfParameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
    ): ByteArray {
        val kdfId = when (slot) {
            SlotType.PASSWORD -> PASSWORD_KDF_ARGON2ID
            SlotType.RECOVERY -> RECOVERY_KDF_HKDF_SHA256
            SlotType.SIGNING_PRIVATE_SEED -> SIGNING_KDF_KEY_WRAP
        }
        val params = if (slot == SlotType.PASSWORD) intArrayOf(
            passwordKdfParameters.memoryKiB,
            passwordKdfParameters.iterations,
            passwordKdfParameters.parallelism,
        ) else intArrayOf(0, 0, 0)
        require(salt.size == 16) { "Envelope KDF salt must be 16 bytes" }
        return ByteBuffer.allocate(AAD_DOMAIN.size + 4 * 3 + 16 + 4 * 5 + 16 + 8 + 32).order(ByteOrder.BIG_ENDIAN).apply {
            put(AAD_DOMAIN); put(MAGIC); putInt(VERSION); putInt(SUITE_1)
            putLong(vaultId.mostSignificantBits); putLong(vaultId.leastSignificantBits)
            putInt(slot.id); putInt(kdfId); params.forEach { putInt(it) }; put(salt); putLong(keyRevision); put(publicKey)
        }.array()
    }

    private fun deriveRecoveryKek(secret: ByteArray, vaultId: UUID): ByteArray {
        require(secret.size == 32) { "Recovery secret must be 32 bytes" }
        return org.bouncycastle.crypto.generators.HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest()).run {
            init(org.bouncycastle.crypto.params.HKDFParameters(secret, vaultId.toBytes(), RECOVERY_INFO))
            ByteArray(32).also { generateBytes(it, 0, it.size) }
        }
    }

    private fun seal(key: ByteArray, nonce: ByteArray, plain: ByteArray, aad: ByteArray): Envelope {
        require(key.size == 32 && nonce.size == NONCE_SIZE && plain.size == 32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return Envelope(nonce.copyOf(), cipher.doFinal(plain))
    }

    private fun open(key: ByteArray, envelope: Envelope, aad: ByteArray): ByteArray = try {
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, envelope.nonce))
            updateAAD(aad)
            doFinal(envelope.ciphertext)
        }.also { require(it.size == 32) { "Invalid envelope plaintext" } }
    } catch (error: Exception) {
        throw IllegalArgumentException("PMVH credential or envelope authentication failed", error)
    }

    private fun hmac(key: ByteArray, value: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256")); doFinal(value)
    }

    private fun ByteBuffer.putEnvelope(value: Envelope) { put(value.nonce); put(value.ciphertext) }
    private fun ByteBuffer.getEnvelope(): Envelope = Envelope(ByteArray(NONCE_SIZE).also(::get), ByteArray(ENVELOPE_CIPHER_SIZE).also(::get))
    private fun UUID.toBytes(): ByteArray = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putLong(mostSignificantBits).putLong(leastSignificantBits).array()
}
