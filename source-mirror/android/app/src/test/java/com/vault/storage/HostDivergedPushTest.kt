package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import com.vault.ui.AuthenticatedPmvELineage
import com.vault.ui.PmvELineageClassifier
import com.vault.ui.PmvELineageRelation
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom
import java.util.UUID

class HostDivergedPushTest {
    private val password = "correct horse battery staple".encodeToByteArray()
    private val recoverySecret = ByteArray(32) { (it * 7 + 3).toByte() }
    private val vaultId = UUID.fromString("5ec0de00-0000-4000-8000-000000000001")
    private val hostDevice = UUID.fromString("d0000000-0000-4000-8000-0000000000a1")
    private val sharedDevice = UUID.fromString("d0000000-0000-4000-8000-0000000000b2")
    private val clientDevice = UUID.fromString("d0000000-0000-4000-8000-0000000000c3")

    @Test
    fun `主机与客户端从同一提交分叉应判定为 DIVERGED`() = withDivergence { divergence ->
        val relation = PmvELineageClassifier.classify(
            lineageOf(divergence.hostFile, divergence.rootKey, divergence),
            lineageOf(divergence.pushedFile, divergence.rootKey, divergence),
        )

        assertEquals(PmvELineageRelation.DIVERGED, relation)
    }

    @Test
    fun `mergeDiverged 保留两侧条目改动`() = withDivergence { divergence ->
        val (merged, _) = VaultOps.mergeDiverged(
            payloadOfFile(divergence.hostFile, divergence.rootKey),
            payloadOfFile(divergence.pushedFile, divergence.rootKey),
        )

        val titles = merged.entries.map { it.title }
        assertTrue(titles.contains("host-entry"))
        assertTrue(titles.contains("client-entry"))
    }

    @Test
    fun `mergeDiverged 收敛到两端较新的密钥版本`() = withDivergence { divergence ->
        val local = payloadOfFile(divergence.hostFile, divergence.rootKey)
        val remote = payloadOfFile(divergence.pushedFile, divergence.rootKey)
        assertEquals(1, local.syncMeta.keyRevision)
        assertEquals(2, remote.syncMeta.keyRevision)

        val (merged, _) = VaultOps.mergeDiverged(local, remote)

        assertEquals(2, merged.syncMeta.keyRevision)
        assertEquals(200.0, merged.syncMeta.keyUpdatedAt, 0.0)
    }

    @Test
    fun `mergeDiverged 在本端密钥更新时保留本端版本`() = withDivergence { divergence ->
        val local = payloadOfFile(divergence.hostFile, divergence.rootKey).copy(
            syncMeta = SyncMeta(hostDevice.toString(), 9, 900.0),
        )
        val remote = payloadOfFile(divergence.pushedFile, divergence.rootKey)

        val (merged, _) = VaultOps.mergeDiverged(local, remote)

        assertEquals(9, merged.syncMeta.keyRevision)
        assertEquals(900.0, merged.syncMeta.keyUpdatedAt, 0.0)
    }

    @Test
    fun `分叉合并落盘后设备注册表为两端并集且同设备取最大 epoch`() = withDivergence { divergence ->
        val hostPayload = payloadOfFile(divergence.hostFile, divergence.rootKey)
        val remotePayload = payloadOfFile(divergence.pushedFile, divergence.rootKey)
        val (merged, _) = VaultOps.mergeDiverged(hostPayload, remotePayload)
        val remoteRegistry = registryOf(divergence.pushedFile, divergence.rootKey)

        PmvVaultStore.openRootKey(divergence.hostFile, divergence.rootKey).use { session ->
            val localRegistry = PmvDeviceRegistry.decode(session.readMetadata())
            val identity = session.identity()
            val mergedMetadata = PmvDeviceRegistry.withRegistry(
                PmvEPayloadAdapter.toMetadata(
                    merged,
                    identity.vaultId,
                    previousMetadata = session.readMetadata(),
                ),
                unionDeviceRegistries(localRegistry, remoteRegistry),
            )
            session.saveFull(
                mergedMetadata,
                merged.entries + merged.trash,
                identity.sequence,
            )
        }

        val after = registryOf(divergence.hostFile, divergence.rootKey).associateBy { it.deviceId }
        assertEquals(3, after.size)
        assertEquals(2L, after.getValue(sharedDevice).epoch)
        assertEquals(5L, after.getValue(hostDevice).epoch)
        assertEquals(7L, after.getValue(clientDevice).epoch)
    }

    @Test
    fun `savePmvE 单独落盘不会并入远端设备`() = withDivergence { divergence ->
        val hostPayload = payloadOfFile(divergence.hostFile, divergence.rootKey)
        val remotePayload = payloadOfFile(divergence.pushedFile, divergence.rootKey)
        val (merged, _) = VaultOps.mergeDiverged(hostPayload, remotePayload)

        PmvVaultStore.openRootKey(divergence.hostFile, divergence.rootKey).use { session ->
            val normalized = PmvEPayloadAdapter.normalizePayload(merged)
            val metadata = PmvEPayloadAdapter.toMetadata(
                normalized,
                session.identity().vaultId,
                previousMetadata = session.readMetadata(),
            )
            session.saveFull(metadata, normalized.entries + normalized.trash, session.identity().sequence)
        }

        val after = registryOf(divergence.hostFile, divergence.rootKey).associateBy { it.deviceId }
        assertEquals(2, after.size)
        assertTrue(clientDevice !in after)
    }

    private fun withDivergence(block: (Divergence) -> Unit) {
        val directory = java.nio.file.Files.createTempDirectory("pmve-host-diverged-").toFile()
        try {
            val base = File(directory, "base.pmv")
            val host = File(directory, "host.pmv")
            val pushed = File(directory, "pushed.pmv")
            val random = RecordingRandom()
            val baseCommitId: UUID
            val rootKey: ByteArray
            val signingSeed: ByteArray
            PmvVaultStore.create(
                file = base,
                passwordUtf8 = password,
                recoverySecret = recoverySecret,
                initialMetadata = PmvEPayloadAdapter.toMetadata(payload(1, 100.0), vaultId),
                initialEntries = emptyList(),
                random = random,
                vaultId = vaultId,
            ).use { session ->
                baseCommitId = session.identity().latestCommitId
                rootKey = session.copyRootKeyForDeviceUnlock()
                signingSeed = random.seedFor(session.identity().signingPublicKey)
            }
            base.copyTo(host)
            base.copyTo(pushed)

            appendCommit(
                file = host,
                rootKey = rootKey,
                signingSeed = signingSeed,
                entry = entry("host-entry", 1.25),
                registry = listOf(authorization(sharedDevice, 1L), authorization(hostDevice, 5L)),
                keyRevision = 1,
                keyUpdatedAt = 100.0,
            )
            appendCommit(
                file = pushed,
                rootKey = rootKey,
                signingSeed = signingSeed,
                entry = entry("client-entry", 2.5),
                registry = listOf(authorization(sharedDevice, 2L), authorization(clientDevice, 7L)),
                keyRevision = 2,
                keyUpdatedAt = 200.0,
            )

            block(Divergence(host, pushed, rootKey, baseCommitId))
        } finally {
            directory.listFiles()?.forEach { it.delete() }
            directory.delete()
        }
    }

    private fun appendCommit(
        file: File,
        rootKey: ByteArray,
        signingSeed: ByteArray,
        entry: Entry,
        registry: List<PmvSyncAuthorization.DeviceAuthorization>,
        keyRevision: Int,
        keyUpdatedAt: Double,
    ) {
        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            val next = payload(keyRevision, keyUpdatedAt).copy(entries = listOf(entry))
            val metadata = PmvDeviceRegistry.withRegistry(
                PmvEPayloadAdapter.toMetadata(
                    next,
                    session.identity().vaultId,
                    previousMetadata = session.readMetadata(),
                ),
                registry.map { PmvSyncAuthorization.signAuthorization(it, signingSeed) },
            )
            session.saveFull(metadata, next.entries + next.trash, session.identity().sequence)
        }
    }

    private fun payload(keyRevision: Int, keyUpdatedAt: Double) = VaultPayload(
        entries = emptyList(),
        syncMeta = SyncMeta(hostDevice.toString(), keyRevision, keyUpdatedAt),
    )

    private fun authorization(deviceId: UUID, epoch: Long) = PmvSyncAuthorization.DeviceAuthorization(
        vaultId = vaultId,
        deviceId = deviceId,
        devicePublicKey = ByteArray(32) { (it * 11 + deviceId.hashCode()).toByte() },
        permissions = PmvSyncAuthorization.PERMISSION_READ or
            PmvSyncAuthorization.PERMISSION_WRITE or
            PmvSyncAuthorization.PERMISSION_AUTHORIZE,
        issuedAtEpochMillis = 1000L,
        expiresAtEpochMillis = 0L,
        revokedAtEpochMillis = 0L,
        epoch = epoch,
    )

    private fun entry(title: String, updatedAt: Double) = Entry(
        id = UUID.nameUUIDFromBytes(title.encodeToByteArray()).toString(),
        title = title,
        username = "user@$title.example",
        password = "secret-$title",
        url = "https://$title.example/login",
        secretType = "login",
        updatedAt = updatedAt,
    )

    private fun payloadOf(session: PmvVaultStore.Session): VaultPayload {
        val entries = session.listSummaries().map { summary ->
            requireNotNull(session.readEntry(summary.entryId))
        }
        return PmvEPayloadAdapter.fromMetadata(session.readMetadata(), entries)
    }

    private fun payloadOfFile(file: File, rootKey: ByteArray): VaultPayload =
        PmvVaultStore.openRootKey(file, rootKey).use(::payloadOf)

    private fun registryOf(
        file: File,
        rootKey: ByteArray,
    ): List<PmvSyncAuthorization.DeviceAuthorization> = PmvVaultStore.openRootKey(file, rootKey).use { session ->
        val publicKey = session.identity().signingPublicKey
        PmvDeviceRegistry.decode(session.readMetadata()).also {
            PmvDeviceRegistry.verifyAll(it, publicKey)
        }
    }

    private fun lineageOf(
        file: File,
        rootKey: ByteArray,
        divergence: Divergence,
    ): AuthenticatedPmvELineage {
        val identity = PmvVaultStore.openRootKey(file, rootKey).use { it.identity() }
        return AuthenticatedPmvELineage(
            vaultId = identity.vaultId,
            signingPublicKey = identity.signingPublicKey,
            keyRevision = identity.keyRevision,
            sequence = identity.sequence,
            commitId = identity.latestCommitId,
            parentCommitId = identity.parentCommitId,
            rootDigest = identity.rootDigest,
            authenticatedAncestorCommitIds = setOf(divergence.baseCommitId),
        )
    }

    private class RecordingRandom : SecureRandom() {
        private val chunks = mutableListOf<ByteArray>()
        private var produced = 0

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { bytes[it] = ((produced + it) % 251).toByte() }
            chunks += bytes.copyOf()
            produced += bytes.size
        }

        fun seedFor(vaultPublicKey: ByteArray): ByteArray = chunks.firstOrNull { candidate ->
            Ed25519PrivateKeyParameters(candidate, 0).generatePublicKey().encoded
                .contentEquals(vaultPublicKey)
        } ?: error("未能从确定性随机源定位 Vault 签名私钥")
    }

    private data class Divergence(
        val hostFile: File,
        val pushedFile: File,
        val rootKey: ByteArray,
        val baseCommitId: UUID,
    )
}
