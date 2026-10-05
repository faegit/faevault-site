package com.vault.storage

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class PmvSyncAuthorizationTest {
    private val vaultSeed = ByteArray(32) { it.toByte() }
    private val deviceSeed = ByteArray(32) { (it + 32).toByte() }
    private val vaultPublic = Ed25519PrivateKeyParameters(vaultSeed, 0).generatePublicKey().encoded
    private val devicePublic = Ed25519PrivateKeyParameters(deviceSeed, 0).generatePublicKey().encoded

    @Test
    fun `authorization rejects permission sets that grant nothing defined`() {
        for (permissions in listOf(0, 8, 16, 0xFFFFFFF8.toInt())) {
            assertThrows(IllegalArgumentException::class.java) {
                PmvSyncAuthorization.DeviceAuthorization(
                    UUID.randomUUID(), UUID.randomUUID(), devicePublic,
                    permissions, 1_000, 0, 0, 1,
                )
            }
        }
    }

    @Test
    fun `transient grant does not consume the persistent epoch`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val now = 1_700_000_000_000L
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        val transient = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic, PmvSyncAuthorization.PERMISSION_READ,
                now, now + 300_000, 0, now,
            ), vaultSeed,
        )
        registry.install(transient, transient = true)
        assertTrue(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.READ, now))

        // 随后签发的持久授权（世代号=计数器）必须仍能装入。
        val persistent = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic,
                PmvSyncAuthorization.PERMISSION_READ or PmvSyncAuthorization.PERMISSION_WRITE,
                now, 0, 0, 1,
            ), vaultSeed,
        )
        registry.install(persistent)
        assertTrue(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.WRITE, now))
        val challenge = registry.issue(
            deviceId, PmvSyncAuthorization.Operation.WRITE, ByteArray(32), nowMillis = now,
        )
        registry.consume(
            challenge, PmvSyncAuthorization.signChallenge(challenge, deviceSeed), nowMillis = now + 1,
        )
        // 持久侧的单调性仍然生效。
        assertThrows(IllegalArgumentException::class.java) { registry.install(persistent) }
    }

    @Test
    fun `expired transient grant does not authorize`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val now = 1_700_000_000_000L
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(
            PmvSyncAuthorization.signAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId, deviceId, devicePublic, PmvSyncAuthorization.PERMISSION_READ,
                    now, now + 1_000, 0, now,
                ), vaultSeed,
            ), transient = true,
        )
        assertTrue(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.READ, now))
        assertFalse(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.READ, now + 2_000))
        assertThrows(IllegalArgumentException::class.java) {
            registry.issue(deviceId, PmvSyncAuthorization.Operation.READ, ByteArray(32), nowMillis = now + 2_000)
        }
    }

    @Test
    fun `transient grant cannot widen beyond its signature`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val now = 1_700_000_000_000L
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(
            PmvSyncAuthorization.signAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId, deviceId, devicePublic, PmvSyncAuthorization.PERMISSION_READ, now, 0, 0, now,
                ), vaultSeed,
            ), transient = true,
        )
        assertTrue(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.READ, now))
        assertFalse(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.WRITE, now))
        assertFalse(registry.isAuthorized(deviceId, PmvSyncAuthorization.Operation.AUTHORIZE, now))
    }

    @Test
    fun `undefined permission bits stay readable but never grant`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val legacy = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic, 15, 1_000, 10_000, 0, 1,
            ), vaultSeed,
        )
        val raw = PmvSyncAuthorization.encodeAuthorization(legacy)
        val decoded = PmvSyncAuthorization.decodeAuthorization(raw)
        // 重新编码必须逐字节复现，否则签名会失效。
        assertArrayEquals(raw, PmvSyncAuthorization.encodeAuthorization(decoded))
        assertTrue(PmvSyncAuthorization.verifyAuthorization(decoded, vaultPublic))
        assertEquals(15, decoded.permissions)
        assertEquals(PmvSyncAuthorization.DEFINED_PERMISSION_MASK, decoded.grantedPermissions)

        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(decoded)
        for (operation in PmvSyncAuthorization.Operation.entries) {
            assertTrue(registry.isAuthorized(deviceId, operation, nowMillis = 2_000))
        }
    }

    @Test
    fun `undefined permission bits cannot widen authority`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val readOnly = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic,
                PmvSyncAuthorization.PERMISSION_READ or 0b1111_1000, 1_000, 0, 0, 1,
            ), vaultSeed,
        )
        assertEquals(PmvSyncAuthorization.PERMISSION_READ, readOnly.grantedPermissions)
        assertTrue(readOnly.allows(PmvSyncAuthorization.Operation.READ))
        assertFalse(readOnly.allows(PmvSyncAuthorization.Operation.WRITE))
        assertFalse(readOnly.allows(PmvSyncAuthorization.Operation.AUTHORIZE))

        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(readOnly)
        assertThrows(IllegalArgumentException::class.java) {
            registry.issue(deviceId, PmvSyncAuthorization.Operation.WRITE, ByteArray(32), nowMillis = 2_000)
        }
    }


    @Test
    fun `registry enforces permission revocation monotonic epoch and replay`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val active = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic,
                PmvSyncAuthorization.PERMISSION_READ or PmvSyncAuthorization.PERMISSION_WRITE,
                1_000, 10_000, 0, 1,
            ), vaultSeed,
        )
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(active)
        val challenge = registry.issue(
            deviceId, PmvSyncAuthorization.Operation.WRITE, ByteArray(32), nowMillis = 2_000,
        )
        registry.consume(challenge, PmvSyncAuthorization.signChallenge(challenge, deviceSeed), 2_001)
        assertThrows(IllegalArgumentException::class.java) {
            registry.consume(challenge, PmvSyncAuthorization.signChallenge(challenge, deviceSeed), 2_002)
        }
        assertThrows(IllegalArgumentException::class.java) { registry.install(active) }

        registry.install(PmvSyncAuthorization.signAuthorization(
            active.copy(revokedAtEpochMillis = 3_000, epoch = 2, signature = ByteArray(64)), vaultSeed,
        ))
        assertThrows(IllegalArgumentException::class.java) {
            registry.issue(deviceId, PmvSyncAuthorization.Operation.READ, ByteArray(32), nowMillis = 4_000)
        }
    }

    @Test
    fun `signature binds vault operation and full challenge context`() {
        val challenge = PmvSyncAuthorization.Challenge(
            UUID.randomUUID(), UUID.randomUUID(), ByteArray(32) { it.toByte() },
            ByteArray(32) { (it + 32).toByte() }, PmvSyncAuthorization.Operation.READ,
            null, ByteArray(32), UUID.randomUUID(), 5_000,
        )
        val signature = PmvSyncAuthorization.signChallenge(challenge, deviceSeed)
        assertTrue(PmvSyncAuthorization.verifyChallenge(challenge, signature, devicePublic))
        assertFalse(PmvSyncAuthorization.verifyChallenge(
            challenge.copy(operation = PmvSyncAuthorization.Operation.WRITE), signature, devicePublic,
        ))
        assertFalse(PmvSyncAuthorization.verifyChallenge(
            challenge.copy(vaultId = UUID.randomUUID()), signature, devicePublic,
        ))
    }

    @Test
    fun `registry snapshots mutable key and challenge bytes`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val mutablePublic = devicePublic.copyOf()
        val authorization = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, mutablePublic, PmvSyncAuthorization.PERMISSION_READ,
                1_000, 10_000, 0, 1,
            ), vaultSeed,
        )
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(authorization)
        mutablePublic.fill(0)

        val challenge = registry.issue(
            deviceId, PmvSyncAuthorization.Operation.READ, ByteArray(32), nowMillis = 2_000,
        )
        val signedSnapshot = challenge.copy(
            serverNonce = challenge.serverNonce.copyOf(),
            clientNonce = challenge.clientNonce.copyOf(),
            requestDigest = challenge.requestDigest.copyOf(),
        )
        challenge.serverNonce.fill(0)
        registry.consume(
            signedSnapshot,
            PmvSyncAuthorization.signChallenge(signedSnapshot, deviceSeed),
            2_001,
        )
    }

    @Test
    fun `registry rejects malformed boundary inputs`() {
        val vaultId = UUID.randomUUID()
        val deviceId = UUID.randomUUID()
        val authorization = PmvSyncAuthorization.signAuthorization(
            PmvSyncAuthorization.DeviceAuthorization(
                vaultId, deviceId, devicePublic, PmvSyncAuthorization.PERMISSION_READ,
                1_000, 10_000, 0, 1,
            ), vaultSeed,
        )
        val registry = PmvSyncAuthorization.AuthorizationRegistry(vaultId, vaultPublic)
        registry.install(authorization)
        assertThrows(IllegalArgumentException::class.java) {
            registry.issue(deviceId, PmvSyncAuthorization.Operation.READ, ByteArray(31), nowMillis = 2_000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            registry.issue(
                deviceId, PmvSyncAuthorization.Operation.READ, ByteArray(32),
                requestDigest = ByteArray(31), nowMillis = 2_000,
            )
        }
    }

}
