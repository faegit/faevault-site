package com.vault.storage

import com.vault.security.VaultDeviceIdentity
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.UUID

/** 同步设备授权握手：完整流程、重放、撤销、跨库/跨设备拒绝。 */
class DeviceAuthWireTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val vaultSeed = ByteArray(32) { (it * 3 + 1).toByte() }
    private val vaultPublicKey = Ed25519PrivateKeyParameters(vaultSeed, 0).generatePublicKey().encoded
    private val now = 1_000_000L

    private fun authorization(
        identity: VaultDeviceIdentity,
        epoch: Long,
        revokedAt: Long = 0L,
        permissions: Int = PmvSyncAuthorization.PERMISSION_READ or
            PmvSyncAuthorization.PERMISSION_WRITE or PmvSyncAuthorization.PERMISSION_AUTHORIZE,
    ) = PmvSyncAuthorization.signAuthorization(
        PmvSyncAuthorization.DeviceAuthorization(
            vaultId, identity.deviceId, identity.publicKey, permissions,
            issuedAtEpochMillis = 100L, expiresAtEpochMillis = 0L,
            revokedAtEpochMillis = revokedAt, epoch = epoch,
        ),
        vaultSeed,
    )

    private fun registry(vararg records: PmvSyncAuthorization.DeviceAuthorization) =
        PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublicKey).also { registry ->
            records.forEach(registry::install)
        }

    @Test
    fun `authorized device completes challenge and gains access`() {
        VaultDeviceIdentity.generate().use { device ->
            val gate = DeviceAuthWire.ServerGate(registry(authorization(device, 1)))
            val request = DeviceAuthWire.ChallengeRequest(
                clientNonce = ByteArray(32) { 1 },
                deviceId = device.deviceId,
                devicePublicKey = device.publicKey,
                vaultId = vaultId,
                operation = PmvSyncAuthorization.Operation.READ,
                requestedCommitId = null,
                requestDigest = ByteArray(32),
            )
            val encoded = gate.issue(request, now)
            assertEquals(PmvSyncAuthorization.CHALLENGE_SIZE, encoded.size)
            val signature = DeviceAuthWire.signChallenge(encoded, device)
            assertThrows(IllegalStateException::class.java) { gate.requireAuthorized() }
            gate.confirm(encoded, signature, now)
            assertEquals(device.deviceId, gate.requireAuthorized())
            // 单次使用：同一 challenge 重放必须失败
            assertThrows(IllegalArgumentException::class.java) {
                gate.confirm(encoded, signature, now + 1)
            }
        }
    }

    @Test
    fun `unregistered device and forged signature are rejected`() {
        VaultDeviceIdentity.generate().use { unregistered ->
            VaultDeviceIdentity.generate().use { registered ->
                val gate = DeviceAuthWire.ServerGate(registry(authorization(registered, 1)))
                val request = DeviceAuthWire.ChallengeRequest(
                    ByteArray(32) { 2 }, unregistered.deviceId, unregistered.publicKey, vaultId,
                    PmvSyncAuthorization.Operation.READ, null, ByteArray(32),
                )
                assertThrows(IllegalArgumentException::class.java) { gate.issue(request, now) }

                val own = DeviceAuthWire.ChallengeRequest(
                    ByteArray(32) { 3 }, registered.deviceId, registered.publicKey, vaultId,
                    PmvSyncAuthorization.Operation.READ, null, ByteArray(32),
                )
                val encoded = gate.issue(own, now)
                assertThrows(IllegalArgumentException::class.java) {
                    gate.confirm(encoded, ByteArray(64) { 7 }, now)
                }
            }
        }
    }

    @Test
    fun `revoked device and expired challenge fail closed`() {
        VaultDeviceIdentity.generate().use { revoked ->
            val gate = DeviceAuthWire.ServerGate(registry(authorization(revoked, 1, revokedAt = 500L)))
            val request = DeviceAuthWire.ChallengeRequest(
                ByteArray(32) { 4 }, revoked.deviceId, revoked.publicKey, vaultId,
                PmvSyncAuthorization.Operation.READ, null, ByteArray(32),
            )
            assertThrows(IllegalArgumentException::class.java) { gate.issue(request, now) }

            VaultDeviceIdentity.generate().use { valid ->
                val active = DeviceAuthWire.ServerGate(registry(authorization(valid, 1)))
                val encoded = active.issue(
                    DeviceAuthWire.ChallengeRequest(
                        ByteArray(32) { 5 }, valid.deviceId, valid.publicKey, vaultId,
                        PmvSyncAuthorization.Operation.READ, null, ByteArray(32),
                    ),
                    now,
                )
                val signature = DeviceAuthWire.signChallenge(encoded, valid)
                assertThrows(IllegalArgumentException::class.java) {
                    active.confirm(encoded, signature, now + 31_001)
                }
            }
        }
    }

    @Test
    fun `challenge is bound to vault device and operation`() {
        VaultDeviceIdentity.generate().use { device ->
            val otherVault = UUID.randomUUID()
            val gate = DeviceAuthWire.ServerGate(registry(authorization(device, 1)))
            assertThrows(IllegalArgumentException::class.java) {
                gate.issue(
                    DeviceAuthWire.ChallengeRequest(
                        ByteArray(32), device.deviceId, device.publicKey, otherVault,
                        PmvSyncAuthorization.Operation.READ, null, ByteArray(32),
                    ),
                    now,
                )
            }
            // READ 授权不能用于 WRITE
            val readOnly = PmvSyncAuthorization.signAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId, device.deviceId, device.publicKey, PmvSyncAuthorization.PERMISSION_READ,
                    100L, 0L, 0L, 1,
                ),
                vaultSeed,
            )
            val readGate = DeviceAuthWire.ServerGate(registry(readOnly))
            assertThrows(IllegalArgumentException::class.java) {
                readGate.issue(
                    DeviceAuthWire.ChallengeRequest(
                        ByteArray(32), device.deviceId, device.publicKey, vaultId,
                        PmvSyncAuthorization.Operation.WRITE, null, ByteArray(32),
                    ),
                    now,
                )
            }
        }
    }
}
