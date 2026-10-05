package com.vault

import com.vault.model.SyncMeta
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 同库同步自动收敛：按“密钥更新时间”/版本号自动选择最新端，不再人工选择。 */
class KeyConvergenceTest {
    @Test
    fun newerTimeWinsRegardlessOfRevisionOrder() {
        // 远端时间更新 → 采用远端，即使远端版本号更低。
        assertTrue(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 5, localUpdatedAt = 100.0,
                remoteRevision = 3, remoteUpdatedAt = 200.0,
            ),
        )
        assertFalse(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 3, localUpdatedAt = 200.0,
                remoteRevision = 5, remoteUpdatedAt = 100.0,
            ),
        )
    }

    @Test
    fun missingTimeFallsBackToRevision() {
        assertTrue(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 1, localUpdatedAt = 0.0,
                remoteRevision = 2, remoteUpdatedAt = 0.0,
            ),
        )
        assertFalse(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 2, localUpdatedAt = 0.0,
                remoteRevision = 1, remoteUpdatedAt = 0.0,
            ),
        )
        // 一端缺少时间戳、另一端已盖章 → 有盖章的一端更新。
        assertTrue(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 1, localUpdatedAt = 0.0,
                remoteRevision = 1, remoteUpdatedAt = 200.0,
            ),
        )
        assertFalse(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 1, localUpdatedAt = 200.0,
                remoteRevision = 1, remoteUpdatedAt = 0.0,
            ),
        )
    }

    @Test
    fun equalVersionsKeepLocalDeterministically() {
        assertFalse(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 2, localUpdatedAt = 300.0,
                remoteRevision = 2, remoteUpdatedAt = 300.0,
            ),
        )
        assertFalse(
            VaultOps.remoteKeyVersionNewer(
                localRevision = 2, localUpdatedAt = 0.0,
                remoteRevision = 2, remoteUpdatedAt = 0.0,
            ),
        )
    }

    @Test
    fun mergeAdoptsNewerKeyMeta() {
        val local = payload(
            SyncMeta(deviceId = "11111111-1111-1111-1111-111111111111", keyRevision = 1, keyUpdatedAt = 100.0),
        )
        val remote = payload(
            SyncMeta(deviceId = "11111111-1111-1111-1111-111111111111", keyRevision = 2, keyUpdatedAt = 200.0),
        )
        assertEquals(remote.syncMeta, VaultOps.newerKeySyncMeta(local, remote))
        assertEquals(remote.syncMeta, VaultOps.newerKeySyncMeta(remote, local))
    }

    @Test
    fun syncMetaRoundTripsKeyUpdatedAt() {
        val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
            explicitNulls = true
        }
        val payload = payload(
            SyncMeta(deviceId = "11111111-1111-1111-1111-111111111111", keyRevision = 3, keyUpdatedAt = 987.5),
        )
        val encoded = json.encodeToString(VaultPayload.serializer(), payload)
        val obj = json.parseToJsonElement(encoded).jsonObject
        assertEquals(JsonPrimitive(987.5), obj.getValue("sync_meta").jsonObject["key_updated_at"])
        val decoded = json.decodeFromString(VaultPayload.serializer(), encoded)
        assertEquals(987.5, decoded.syncMeta.keyUpdatedAt, 0.0)
        assertEquals(3, decoded.syncMeta.keyRevision)
    }

    private fun payload(syncMeta: SyncMeta): VaultPayload =
        VaultPayload(entries = emptyList(), syncMeta = syncMeta)
}
