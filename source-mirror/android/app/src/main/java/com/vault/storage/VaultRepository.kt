package com.vault.storage

import android.content.Context
import android.net.Uri
import com.vault.crypto.PmvKdfParameters
import com.vault.crypto.PmvKdfProfile
import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.VaultCrypto
import com.vault.model.Entry
import com.vault.model.VaultPayload
import com.vault.model.nowSeconds
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Collections
import java.util.UUID
import com.vault.ui.AuthenticatedPmvELineage
import com.vault.ui.PmvELineageClassifier
import com.vault.ui.PmvELineageRelation

data class VaultUnlockResult(
    val payload: VaultPayload,
    val dek: ByteArray? = null,
    /** PMVE device-unlock material（RootKey）。 */
    val rootKey: ByteArray? = null,
    /** Authenticated PMVE lineage used to bind device-unlock envelopes. */
    val identity: VaultIdentity? = null,
    val needsFastUnlockUpgrade: Boolean = false,
)

class VaultIdentity(
    val vaultId: UUID,
    val sequence: Long,
    val commitId: UUID,
    val parentCommitId: UUID?,
    val keyRevision: Long,
    val headerRevision: Long,
    signingPublicKey: ByteArray,
    rootDigest: ByteArray,
) {
    private val signingPublicKeyBytes: ByteArray = signingPublicKey.copyOf()
    private val rootDigestBytes: ByteArray = rootDigest.copyOf()
    val signingPublicKey: ByteArray get() = signingPublicKeyBytes.copyOf()
    val rootDigest: ByteArray get() = rootDigestBytes.copyOf()

    init {
        require(signingPublicKeyBytes.size == 32) { "PMVE Ed25519 公钥必须为 32 字节" }
        require(rootDigestBytes.size == 32) { "PMVE Commit Root Digest 必须为 32 字节" }
    }

    override fun equals(other: Any?): Boolean = other is VaultIdentity &&
        vaultId == other.vaultId && sequence == other.sequence && commitId == other.commitId &&
        parentCommitId == other.parentCommitId && keyRevision == other.keyRevision &&
        headerRevision == other.headerRevision &&
        signingPublicKeyBytes.contentEquals(other.signingPublicKeyBytes) &&
        rootDigestBytes.contentEquals(other.rootDigestBytes)

    override fun hashCode(): Int {
        var result = vaultId.hashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + commitId.hashCode()
        result = 31 * result + (parentCommitId?.hashCode() ?: 0)
        result = 31 * result + keyRevision.hashCode()
        result = 31 * result + headerRevision.hashCode()
        result = 31 * result + signingPublicKeyBytes.contentHashCode()
        return 31 * result + rootDigestBytes.contentHashCode()
    }
}

/** EntryIndex 明文摘要：不解密条目 payload 即可枚举类型与标题。 */
data class VaultEntrySummary(
    val entryId: String,
    val entryType: String,
    val displayTitle: String,
    val favorite: Boolean,
    val revision: Long,
)

interface VaultQuerySession : AutoCloseable {
    val format: VaultFileFormat
    val identity: VaultIdentity?
    fun queryDomain(domain: String): List<String>?
    fun queryPackage(packageName: String): List<String>?
    fun queryRpId(rpId: String): List<String>?
    fun readEntry(entryId: String): Entry?
    /** 枚举活跃条目的明文摘要（类型/标题），不解密条目 payload；不支持时返回 null。 */
    fun listSummaries(): List<VaultEntrySummary>?
    /** Authenticated rules are available without decrypting any Entry blocks. */
    fun autofillExclusions(): com.vault.model.AutofillExclusions? = null
}

class VaultStaleMutationException(message: String, cause: Throwable? = null) :
    IllegalStateException(message, cause)

class AuthenticatedVaultFile(
    file: File,
    val format: VaultFileFormat,
    val identity: VaultIdentity?,
    ancestorCommitIds: Set<UUID>,
    val payload: VaultPayload? = null,
) {
    val file: File = file.canonicalFile
    val ancestorCommitIds: Set<UUID> = Collections.unmodifiableSet(LinkedHashSet(ancestorCommitIds))
}

enum class VaultFileRelationship {
    SAME,
    REMOTE_DESCENDANT,
    LOCAL_DESCENDANT,
    DIVERGED,
    DIFFERENT_VAULT,
    INVALID,
}

/** 注册表 union：同一设备取 epoch 最大的记录（每条均已由 Vault 公钥验签）。 */
internal fun unionDeviceRegistries(
    first: List<PmvSyncAuthorization.DeviceAuthorization>,
    second: List<PmvSyncAuthorization.DeviceAuthorization>,
): List<PmvSyncAuthorization.DeviceAuthorization> {
    val byDevice = linkedMapOf<UUID, PmvSyncAuthorization.DeviceAuthorization>()
    (first + second).forEach { record ->
        val current = byDevice[record.deviceId]
        if (current == null || record.epoch > current.epoch) {
            byDevice[record.deviceId] = record
        }
    }
    return byDevice.values.sortedWith(
        compareBy({ it.deviceId.toString() }, { it.epoch }),
    )
}
/** 把认证结果转换为谱系判定输入。谱系只能来自已验签的 Commit 块，不能用 header 或 payload 字段代替。 */
internal fun AuthenticatedVaultFile.toPmvELineage(): AuthenticatedPmvELineage {
    val value = requireNotNull(identity) { "PMVE 认证结果缺少 identity" }
    val publicKey = value.signingPublicKey
    val rootDigest = value.rootDigest
    return try {
        AuthenticatedPmvELineage(
            vaultId = value.vaultId,
            signingPublicKey = publicKey,
            keyRevision = value.keyRevision,
            sequence = value.sequence,
            commitId = value.commitId,
            parentCommitId = value.parentCommitId,
            rootDigest = rootDigest,
            authenticatedAncestorCommitIds = ancestorCommitIds,
        )
    } finally {
        publicKey.fill(0)
        rootDigest.fill(0)
    }
}

internal fun classifyAuthenticatedVaultFiles(
    local: AuthenticatedVaultFile,
    remote: AuthenticatedVaultFile,
): VaultFileRelationship {
    if (local.identity == null || remote.identity == null) return VaultFileRelationship.INVALID
    return when (PmvELineageClassifier.classify(local.toPmvELineage(), remote.toPmvELineage())) {
        PmvELineageRelation.SAME -> VaultFileRelationship.SAME
        PmvELineageRelation.FAST_FORWARD -> VaultFileRelationship.REMOTE_DESCENDANT
        PmvELineageRelation.REMOTE_STALE -> VaultFileRelationship.LOCAL_DESCENDANT
        PmvELineageRelation.DIVERGED -> VaultFileRelationship.DIVERGED
        PmvELineageRelation.DIFFERENT -> VaultFileRelationship.DIFFERENT_VAULT
        PmvELineageRelation.INVALID -> VaultFileRelationship.INVALID
    }
}

internal fun requireInstallableVaultRelationship(relationship: VaultFileRelationship) {
    require(relationship == VaultFileRelationship.SAME ||
        relationship == VaultFileRelationship.REMOTE_DESCENDANT
    ) { "只允许安装相同或经认证的 PMVE 后代快照，实际关系为 $relationship" }
}

/** 局域网导入媒体提升结果；[created] 为 false 时表示复用了当前密钥可解密的既有内容。 */
data class ImportMediaPromotion(
    val ref: String,
    val created: Boolean,
)

data class PmvEMediaSaveResult(
    val identity: VaultIdentity,
    val entry: Entry,
    val entryRevision: Long,
    val refs: List<PmvMediaRef.Ref>,
)

/**
 * 单个账户的库读写。文件位置由 [VaultRegistry] 解析（filesDir/vaults/<name>.pmv）。
 *
 * 保存：写 *.tmp → 旧文件复制为 *.bak → 原子 rename 覆盖
 * 打开：主文件结构损坏（非密码错）时回退 *.bak
 */
class VaultRepository(
    private val context: Context,
    private val registry: VaultRegistry,
    private val vaultName: String,
) {

    private val vaultFile get() = registry.fileFor(vaultName)
    private val tmpFile get() = registry.tmpFor(vaultName)
    private val bakFile get() = registry.bakFor(vaultName)
    fun exists(): Boolean = vaultFile.exists()

    private fun localDeviceId(): String = com.vault.security.VaultDeviceIdentityStore(context, vaultName)
        .loadOrCreate().use { it.deviceId.toString() }

    private fun activityMetadata(session: PmvVaultStore.Session, metadata: JsonObject): JsonObject =
        DeviceActivity.touch(metadata, localDeviceId(), SystemDeviceName.read(context), parentCommitId = session.identity().latestCommitId.toString())

    fun deviceProfiles(rootKey: ByteArray): List<DeviceActivityProfile> = PmvVaultStore.openRootKey(vaultFile, rootKey).use {
        val id = localDeviceId()
        val currentVaultId = it.identity().vaultId
        val registry = PmvDeviceRegistry.decode(it.readMetadata()).also { records -> PmvDeviceRegistry.verifyAll(records, it.identity().signingPublicKey) }
        val profiles = DeviceActivity.profiles(it.readMetadata())
        val all = profiles + registry.filter { grant -> profiles.none { p -> p.deviceId == grant.deviceId.toString() } }
            .map { grant -> DeviceActivityProfile(grant.deviceId.toString(), "", "", 0, 0) }
        val withCurrent = if (all.none { profile -> profile.deviceId == id }) all + DeviceActivityProfile(id, "", "android", 0, 0) else all
        DeviceActivity.authorizedProfiles(withCurrent.map { profile ->
            val grant = PmvDeviceRegistry.latest(registry, UUID.fromString(profile.deviceId))
            profile.copy(name = if (profile.deviceId == id) SystemDeviceName.read(context) else profile.name,
                isCurrent = profile.deviceId == id, authorizationStatus = grant?.let { g ->
                if (g.vaultId != currentVaultId) "invalid" else if (g.revokedAtEpochMillis > 0) "revoked" else if (!g.activeAt(System.currentTimeMillis())) "expired" else "authorized"
            })
        })
    }

    fun authenticatedDeviceWriter(file: File, rootKey: ByteArray): DeviceActivityProfile? =
        PmvVaultStore.openRootKey(file, rootKey).use { DeviceActivity.writer(it.readMetadata(), it.identity().parentCommitId?.toString()) }

    /** 从 SAF Uri 复制库文件到当前账户位置；覆盖前调用方应确认。 */
    fun importFromUri(uri: Uri) {
        try {
            var total = 0L
            val maxBytes = 2L * 1024L * 1024L * 1024L
            context.contentResolver.openInputStream(uri)?.use { input ->
                tmpFile.outputStream().buffered().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= maxBytes) { "保险库导入文件超过安全大小限制" }
                        output.write(buffer, 0, count)
                    }
                }
            } ?: throw FileNotFoundException("无法打开所选文件")
            if (total < 5) throw VaultCrypto.CorruptFileError("所选文件不是有效的 .pmv 保险库文件")
            val magic = tmpFile.inputStream().use { input -> ByteArray(4).also(input::read) }
            if (VaultFileFormat.detect(magic) == VaultFileFormat.UNKNOWN) {
                throw VaultCrypto.CorruptFileError("所选文件不是有效的 .pmv 保险库文件")
            }
            if (vaultFile.exists()) vaultFile.copyTo(bakFile, overwrite = true)
            if (!tmpFile.renameTo(vaultFile)) {
                tmpFile.copyTo(vaultFile, overwrite = true)
            }
        } finally {
            if (tmpFile.exists()) tmpFile.delete()
        }
    }

    /** 从本地文件复制库文件到当前账户位置（局域网导出整库导入用）。 */
    fun importFromFile(source: java.io.File) {
        try {
            require(source.isFile) { "导入源文件不存在" }
            require(source.length() >= 5) { "保险库文件大小无效" }
            val magic = source.inputStream().use { input -> ByteArray(4).also(input::read) }
            if (VaultFileFormat.detect(magic) == VaultFileFormat.UNKNOWN) {
                throw VaultCrypto.CorruptFileError("所选文件不是有效的 .pmv 保险库文件")
            }
            if (vaultFile.exists()) vaultFile.copyTo(bakFile, overwrite = true)
            source.copyTo(vaultFile, overwrite = true)
        } finally {
            tmpFile.delete()
        }
    }

    fun open(passwordUtf8: ByteArray): VaultPayload {
        return openPmvE(passwordUtf8).also { it.rootKey?.fill(0) }.payload
    }

    fun openForUnlock(passwordUtf8: ByteArray): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return openPmvE(passwordUtf8)
    }

    /** PMVE 创建路径。 */
    fun createPmvE(
        passwordUtf8: ByteArray,
        recoverySecret: ByteArray,
        payload: VaultPayload,
    ): VaultUnlockResult {
        val normalized = PmvEPayloadAdapter.normalizePayload(payload)
        val vaultId = UUID.randomUUID()
        val metadata = PmvEPayloadAdapter.toMetadata(normalized, vaultId)
        return PmvVaultStore.create(
            file = vaultFile,
            passwordUtf8 = passwordUtf8,
            recoverySecret = recoverySecret,
            initialMetadata = metadata,
            initialEntries = normalized.entries + normalized.trash,
            vaultId = vaultId,
        ).use(::pmveUnlockResult)
    }

    fun openPmvE(passwordUtf8: ByteArray): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return try {
            PmvVaultStore.openPassword(vaultFile, passwordUtf8).use(::pmveUnlockResult)
        } catch (error: VaultCrypto.DecryptError) {
            throw error
        } catch (_: IllegalArgumentException) {
            // 密码错误时 PMVE 底层会抛「没有可由所给凭据认证的 PMV Header」等校验文案，
            // 统一转成主密码错误语义，避免把底层 Header 细节暴露给用户造成误解。
            throw VaultCrypto.DecryptError("主密码错误或 PMVE 库文件已损坏")
        }
    }

    fun openPmvEWithRecoveryKey(recoverySecret: ByteArray): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return try {
            PmvVaultStore.openRecovery(vaultFile, recoverySecret).use(::pmveUnlockResult)
        } catch (error: VaultCrypto.DecryptError) {
            throw error
        } catch (_: IllegalArgumentException) {
            // 恢复密钥错误时同样屏蔽底层 Header 文案，转为恢复密钥错误语义。
            throw VaultCrypto.DecryptError("恢复密钥错误或 PMVE 库文件已损坏")
        }
    }

    fun openPmvEWithRootKey(rootKey: ByteArray): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use(::pmveUnlockResult)
    }

    /** PMVE optimistic full save. Existing unknown metadata is merged back unchanged. */
    fun savePmvE(payload: VaultPayload, rootKey: ByteArray, expectedSequence: Long? = null): VaultPayload {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            savePmvE(session, payload, expectedSequence ?: session.identity().sequence)
        }
    }

    /** PMVE 压缩：回收历史 Block 垃圾空间，逻辑摘要与签名身份保持不变。 */
    fun compactPmvE(rootKey: ByteArray): VaultIdentity {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            session.compact().toVaultIdentity()
        }
    }

    /** 自动压缩决策所需的轻量统计：当前提交序号 + 库文件字节数。 */
    fun pmveMaintenanceStats(rootKey: ByteArray): Pair<Long, Long> {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        val sequence = PmvVaultStore.openRootKey(vaultFile, rootKey).use { it.identity().sequence }
        return sequence to vaultFile.length()
    }

    fun vaultFileSize(): Long = if (vaultFile.exists()) vaultFile.length() else 0L

    /** 若最新提交缺少登录快速索引则自动重建（自动填充精确查询依赖它）。 */
    fun ensurePmvELoginIndex(rootKey: ByteArray): Boolean {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            session.ensureLoginIndex()
        }
    }

    /** 读取并验证当前 PMVE 库的设备授权清单。 */
    fun loadDeviceRegistry(rootKey: ByteArray): List<PmvSyncAuthorization.DeviceAuthorization> {
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val records = PmvDeviceRegistry.decode(session.readMetadata())
            PmvDeviceRegistry.verifyAll(records, session.identity().signingPublicKey)
            records
        }
    }

    /** 签发并加入一台设备的授权（自授权或管理员添加），返回最新清单。 */
    fun authorizeDevice(
        rootKey: ByteArray,
        deviceId: UUID,
        devicePublicKey: ByteArray,
        permissions: Int,
        epoch: Long,
        issuedAtEpochMillis: Long = System.currentTimeMillis(),
    ): List<PmvSyncAuthorization.DeviceAuthorization> {
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            val current = PmvDeviceRegistry.decode(session.readMetadata()).also {
                PmvDeviceRegistry.verifyAll(it, identity.signingPublicKey)
            }
            val existing = PmvDeviceRegistry.latest(current, deviceId)
            require(existing == null || epoch > existing.epoch) { "设备授权 epoch 未递增" }
            val signed = session.signDeviceAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId = identity.vaultId,
                    deviceId = deviceId,
                    devicePublicKey = devicePublicKey,
                    permissions = permissions,
                    issuedAtEpochMillis = issuedAtEpochMillis,
                    expiresAtEpochMillis = 0L,
                    revokedAtEpochMillis = 0L,
                    epoch = epoch,
                ),
            )
            val updated = current.filter { it.deviceId != deviceId } + signed
            val metadata = PmvDeviceRegistry.withRegistry(session.readMetadata(), updated)
            val entries = session.listSummaries().map { summary ->
                requireNotNull(session.readEntry(summary.entryId)) { "PMVE EntryIndex 引用了不存在的 Entry" }
            }
            session.saveFull(activityMetadata(session, metadata), entries, identity.sequence)
            updated
        }
    }

    /** 撤销设备：签发更高 epoch 的 revoked 记录，返回最新清单。 */
    fun revokeDevice(
        rootKey: ByteArray,
        deviceId: UUID,
        revokedAtEpochMillis: Long = System.currentTimeMillis(),
    ): List<PmvSyncAuthorization.DeviceAuthorization> {
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            val current = PmvDeviceRegistry.decode(session.readMetadata()).also {
                PmvDeviceRegistry.verifyAll(it, identity.signingPublicKey)
            }
            val existing = PmvDeviceRegistry.latest(current, deviceId) ?: return@use current
            val signed = session.signDeviceAuthorization(
                existing.copy(
                    revokedAtEpochMillis = revokedAtEpochMillis,
                    epoch = existing.epoch + 1,
                ),
            )
            val updated = current.filter { it.deviceId != deviceId } + signed
            val metadata = PmvDeviceRegistry.withRegistry(session.readMetadata(), updated)
            val entries = session.listSummaries().map { summary ->
                requireNotNull(session.readEntry(summary.entryId)) { "PMVE EntryIndex 引用了不存在的 Entry" }
            }
            session.saveFull(activityMetadata(session, metadata), entries, identity.sequence)
            updated
        }
    }

    /** Atomically retain a signed revocation and remove the descriptive activity record. */
    fun removeDevice(rootKey: ByteArray, deviceId: UUID, expectedSequence: Long,
        now: Long = System.currentTimeMillis()): VaultUnlockResult {
        DeviceActivity.requireOtherDevice(deviceId.toString(), localDeviceId())
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            check(identity.sequence == expectedSequence) { "保险库已变化，请刷新后重试" }
            val current = PmvDeviceRegistry.decode(session.readMetadata()).also {
                PmvDeviceRegistry.verifyAll(it, identity.signingPublicKey)
            }
            val existing = requireNotNull(PmvDeviceRegistry.latest(current, deviceId)) { "设备授权记录不存在" }
            require(existing.vaultId == identity.vaultId && existing.activeAt(now)) { "设备授权已失效，请刷新" }
            val removed = DeviceActivity.remove(session.readMetadata(), deviceId.toString(), now)
            val signed = session.signDeviceAuthorization(existing.copy(
                revokedAtEpochMillis = maxOf(now, existing.issuedAtEpochMillis, 1L), epoch = Math.addExact(existing.epoch, 1L)))
            val metadata = PmvDeviceRegistry.withRegistry(removed, current.filter { it.deviceId != deviceId } + signed)
            val entries = session.listSummaries().map { requireNotNull(session.readEntry(it.entryId)) }
            session.saveFull(activityMetadata(session, metadata), entries, expectedSequence)
            pmveUnlockResult(session)
        }
    }

    fun openQueryWithPassword(passwordUtf8: ByteArray): VaultQuerySession {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return try {
            PmvEQuerySession(PmvVaultStore.openPassword(vaultFile, passwordUtf8))
        } catch (error: Exception) {
            throw VaultCrypto.DecryptError(error.message ?: "主密码错误或 PMVE 已损坏")
        }
    }

    /** 签发仅用于当前局域网导出会话的短期只读授权，不写入保险库设备清单。 */
    fun transientExportAuthorization(
        rootKey: ByteArray,
        deviceId: UUID,
        devicePublicKey: ByteArray,
        nowMillis: Long = System.currentTimeMillis(),
        lifetimeMillis: Long = 5L * 60L * 1000L,
    ): PmvSyncAuthorization.DeviceAuthorization {
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        require(lifetimeMillis in 1_000L..15L * 60L * 1000L) { "临时授权有效期无效" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            session.signDeviceAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId = identity.vaultId,
                    deviceId = deviceId,
                    devicePublicKey = devicePublicKey,
                    permissions = PmvSyncAuthorization.PERMISSION_READ,
                    issuedAtEpochMillis = nowMillis,
                    expiresAtEpochMillis = Math.addExact(nowMillis, lifetimeMillis),
                    revokedAtEpochMillis = 0L,
                    epoch = nowMillis,
                ),
            )
        }
    }

    /** 签发仅用于当前局域网同步会话的短期读写授权，不写入保险库设备清单。 */
    fun transientSyncAuthorization(
        rootKey: ByteArray,
        deviceId: UUID,
        devicePublicKey: ByteArray,
        nowMillis: Long = System.currentTimeMillis(),
        lifetimeMillis: Long = 5L * 60L * 1000L,
    ): PmvSyncAuthorization.DeviceAuthorization {
        require(isPmvE()) { "仅 PMVE 支持设备授权" }
        require(lifetimeMillis in 1_000L..15L * 60L * 1000L) { "临时授权有效期无效" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            session.signDeviceAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId = identity.vaultId,
                    deviceId = deviceId,
                    devicePublicKey = devicePublicKey,
                    permissions = PmvSyncAuthorization.PERMISSION_READ or
                        PmvSyncAuthorization.PERMISSION_WRITE,
                    issuedAtEpochMillis = nowMillis,
                    expiresAtEpochMillis = Math.addExact(nowMillis, lifetimeMillis),
                    revokedAtEpochMillis = 0L,
                    epoch = nowMillis,
                ),
            )
        }
    }

    /** PMVE RootKey 设备解锁查询路径。 */
    fun openQueryWithDeviceKey(deviceKey: ByteArray): VaultQuerySession {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return try {
            PmvEQuerySession(PmvVaultStore.openRootKey(vaultFile, deviceKey))
        } catch (error: Exception) {
            throw VaultCrypto.DecryptError(error.message ?: "RootKey 错误或 PMVE 已损坏")
        }
    }

    fun mutatePmvEWithPassword(
        passwordUtf8: ByteArray,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openPassword(vaultFile, passwordUtf8).use { session ->
            mutatePmvE(session, expectedSequence, transform)
        }
    }

    fun mutatePmvEWithRootKey(
        rootKey: ByteArray,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            mutatePmvE(session, expectedSequence, transform)
        }
    }

    fun fileFormat(): VaultFileFormat = VaultFileFormat.detect(vaultFile)

    fun isPmvE(): Boolean = fileFormat() == VaultFileFormat.PMVE

    fun authenticateExternalFile(file: File, passwordUtf8: ByteArray): AuthenticatedVaultFile {
        require(VaultFileFormat.detect(file) == VaultFileFormat.PMVE) { "不是有效的 PMVE 保险库文件" }
        return PmvVaultStore.openPassword(file, passwordUtf8).use { session ->
            authenticatedPmvEFile(file, session)
        }
    }

    /** PMVE RootKey external-file authentication。 */
    fun authenticateExternalFileWithDeviceKey(file: File, deviceKey: ByteArray): AuthenticatedVaultFile {
        require(VaultFileFormat.detect(file) == VaultFileFormat.PMVE) { "外部文件不是 PMVE" }
        return PmvVaultStore.openRootKey(file, deviceKey).use { session ->
            authenticatedPmvEFile(file, session)
        }
    }

    fun currentAuthenticatedFile(rootKey: ByteArray): AuthenticatedVaultFile =
        authenticateExternalFileWithDeviceKey(vaultFile, rootKey)

    fun currentIdentity(rootKey: ByteArray): VaultIdentity =
        requireNotNull(currentAuthenticatedFile(rootKey).identity) { "当前保险库不是 PMVE" }

    fun decodeExternalFileWithRootKey(file: File, rootKey: ByteArray): VaultPayload {
        require(VaultFileFormat.detect(file) == VaultFileFormat.PMVE) { "外部文件不是 PMVE" }
        return PmvVaultStore.openRootKey(file, rootKey).use(::pmvePayload)
    }

    fun classifyAuthenticatedFile(
        local: AuthenticatedVaultFile,
        remote: AuthenticatedVaultFile,
    ): VaultFileRelationship = classifyAuthenticatedVaultFiles(local, remote)

    fun replaceAuthenticatedFile(
        candidate: File,
        rootKey: ByteArray,
        expectedCurrent: VaultIdentity,
        expectedRemote: VaultIdentity,
    ): VaultUnlockResult {
        require(candidate.canonicalFile != vaultFile.canonicalFile) { "候选文件不得是当前保险库" }
        return PmvAppendOnlyFile.withExclusiveWriterLock(vaultFile) {
            val current = currentAuthenticatedFile(rootKey)
            require(current.identity == expectedCurrent) { "当前 PMVE 身份已变化" }
            val authenticatedCandidate = authenticateExternalFileWithDeviceKey(candidate, rootKey)
            require(authenticatedCandidate.identity == expectedRemote) { "候选 PMVE 身份与预期不一致" }
            requireInstallableVaultRelationship(classifyAuthenticatedFile(current, authenticatedCandidate))

            val install = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.install.tmp")
            val restore = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.restore.tmp")
            val backup = File(vaultFile.parentFile, "${vaultFile.name}.download.bak")
            try {
                copyFileDurably(candidate, install)
                copyFileDurably(vaultFile, restore)
                copyFileDurably(vaultFile, backup)
                syncParentDirectory(backup)
                atomicReplaceFile(install, vaultFile)
                try {
                    syncParentDirectory(vaultFile)
                    openPmvEWithRootKey(rootKey).also { installed ->
                        require(installed.identity == expectedRemote) { "安装后的 PMVE 身份不一致" }
                    }
                } catch (error: Throwable) {
                    try {
                        atomicReplaceFile(restore, vaultFile)
                        syncParentDirectory(vaultFile)
                    } catch (restoreError: Throwable) {
                        error.addSuppressed(restoreError)
                        throw IllegalStateException("远端 PMVE 安装失败，且本地文件恢复失败", error)
                    }
                    throw IllegalStateException("远端 PMVE 安装复验失败，已恢复本地文件", error)
                }
            } finally {
                install.delete()
                restore.delete()
            }
        }
    }

    /**
     * PMVE 分叉合并采纳：以 [candidate]（远端 Head）为基线，把本地与远端内容
     * （条目 LWW + 设备授权清单 union）提交到远端 Head 之上，并将该合并文件
     * 原子安装为本地库。用于 DIVERGED 关系的首次多设备同步收敛。
     */
    fun mergeAndAdoptAuthenticatedFile(
        candidate: File,
        rootKey: ByteArray,
        expectedRemote: VaultIdentity,
        mergeEntries: (VaultPayload, VaultPayload) -> VaultPayload,
    ): VaultUnlockResult {
        require(candidate.canonicalFile != vaultFile.canonicalFile) { "候选文件不得是当前保险库" }
        return PmvAppendOnlyFile.withExclusiveWriterLock(vaultFile) {
            val current = currentAuthenticatedFile(rootKey)
            val authenticatedCandidate = authenticateExternalFileWithDeviceKey(candidate, rootKey)
            require(authenticatedCandidate.identity == expectedRemote) { "候选 PMVE 身份与预期不一致" }
            require(classifyAuthenticatedFile(current, authenticatedCandidate) == VaultFileRelationship.DIVERGED) {
                "仅 DIVERGED 关系允许合并采纳"
            }

            val localHeaderRaw = PmvVaultStore.openRootKey(vaultFile, rootKey).use { it.copyHeaderRaw() }
            val localPayload: VaultPayload
            val localRegistry: List<PmvSyncAuthorization.DeviceAuthorization>
            val mergedIdentity: PmvVaultStore.Identity
            try {
                localPayload = PmvVaultStore.openRootKey(vaultFile, rootKey).use(::pmvePayload)
                localRegistry = PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
                    PmvDeviceRegistry.decode(session.readMetadata()).also {
                        PmvDeviceRegistry.verifyAll(it, session.identity().signingPublicKey)
                    }
                }
                mergedIdentity = PmvVaultStore.openRootKey(candidate, rootKey).use { session ->
                    val candidateIdentity = session.identity()
                    require(candidateIdentity.toVaultIdentity() == expectedRemote) { "候选 PMVE 身份与预期不一致" }
                    val remotePayload = pmvePayload(session)
                    val remoteRegistry = PmvDeviceRegistry.decode(session.readMetadata()).also {
                        PmvDeviceRegistry.verifyAll(it, candidateIdentity.signingPublicKey)
                    }
                    val mergedPayload = mergeEntries(localPayload, remotePayload)
                    // 若合并结果采用了“本端（更新）密钥版本”，合并文件的密码/恢复密钥槽
                    // 必须替换为本端头部，否则合并后本端新主密码会失效、退回旧密码。
                    val adoptLocalKey = mergedPayload.syncMeta == localPayload.syncMeta
                    val mergedRegistry = unionDeviceRegistries(localRegistry, remoteRegistry)
                    val mergedMetadata = PmvDeviceRegistry.withRegistry(
                        PmvEPayloadAdapter.toMetadata(mergedPayload, candidateIdentity.vaultId, session.readMetadata()),
                        mergedRegistry,
                    )
                    PmvVaultStore.openRootKey(vaultFile, rootKey).use { source ->
                        session.saveMerged(source, activityMetadata(session, DeviceActivity.merge(mergedMetadata, source.readMetadata())),
                            mergedPayload.entries + mergedPayload.trash, candidateIdentity.sequence)
                    }
                    if (adoptLocalKey) {
                        session.adoptHeader(localHeaderRaw)
                    }
                    session.identity()
                }
            } finally {
                localHeaderRaw.fill(0)
            }

            val install = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.merge.tmp")
            val restore = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.merge-restore.tmp")
            val backup = File(vaultFile.parentFile, "${vaultFile.name}.merge.bak")
            try {
                copyFileDurably(candidate, install)
                copyFileDurably(vaultFile, restore)
                copyFileDurably(vaultFile, backup)
                syncParentDirectory(backup)
                atomicReplaceFile(install, vaultFile)
                try {
                    syncParentDirectory(vaultFile)
                    openPmvEWithRootKey(rootKey).also { installed ->
                        require(installed.identity == mergedIdentity.toVaultIdentity()) { "安装后的合并 PMVE 身份不一致" }
                    }
                } catch (error: Throwable) {
                    try {
                        atomicReplaceFile(restore, vaultFile)
                        syncParentDirectory(vaultFile)
                    } catch (restoreError: Throwable) {
                        error.addSuppressed(restoreError)
                        throw IllegalStateException("PMVE 合并安装失败，且本地文件恢复失败", error)
                    }
                    throw IllegalStateException("PMVE 合并安装复验失败，已恢复本地文件", error)
                }
            } finally {
                install.delete()
                restore.delete()
            }
        }
    }

    /**
     * 分叉合并落盘：把 [remoteRegistry] 并入本地注册表后再保存。
     *
     * [savePmvE] 走 `previousMetadata` 继承本地注册表，直接用它保存合并结果会丢掉远端
     * 设备——那些设备下次连接即被判为未授权。[remoteRegistry] 必须是调用方从远端
     * metadata 取出并已用 Vault 签名公钥验签的记录。
     */
    fun savePmvEWithRegistry(
        payload: VaultPayload,
        rootKey: ByteArray,
        remoteRegistry: List<PmvSyncAuthorization.DeviceAuthorization>,
        expectedSequence: Long? = null,
    ): VaultPayload {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
            val identity = session.identity()
            val normalized = PmvEPayloadAdapter.normalizePayload(payload)
            val localRegistry = PmvDeviceRegistry.decode(session.readMetadata()).also {
                PmvDeviceRegistry.verifyAll(it, identity.signingPublicKey)
            }
            val mergedMetadata = PmvDeviceRegistry.withRegistry(
                PmvEPayloadAdapter.toMetadata(normalized, identity.vaultId, session.readMetadata()),
                unionDeviceRegistries(localRegistry, remoteRegistry),
            )
            session.saveFull(
                activityMetadata(session, mergedMetadata),
                normalized.entries + normalized.trash,
                expectedSequence ?: identity.sequence,
            )
            normalized
        }
    }

    /** 读取外部 PMVE 文件的设备注册表，并用该文件的 Vault 签名公钥逐条验签。 */
    fun authenticatedRegistryOf(file: File, rootKey: ByteArray): List<PmvSyncAuthorization.DeviceAuthorization> {
        require(VaultFileFormat.detect(file) == VaultFileFormat.PMVE) { "外部文件不是 PMVE" }
        return PmvVaultStore.openRootKey(file, rootKey).use { session ->
            val publicKey = session.identity().signingPublicKey
            PmvDeviceRegistry.decode(session.readMetadata()).also {
                PmvDeviceRegistry.verifyAll(it, publicKey)
            }
        }
    }

    fun save(payload: VaultPayload, passwordUtf8: ByteArray) {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvVaultStore.openPassword(vaultFile, passwordUtf8).use { session ->
            savePmvE(session, payload)
        }
    }

    /** Build a divergent merge on the external candidate without changing the current vault. */
    fun prepareMergedAuthenticatedFile(
        candidate: File,
        rootKey: ByteArray,
        expectedCurrent: VaultIdentity,
        expectedRemote: VaultIdentity,
        mergeEntries: (VaultPayload, VaultPayload) -> VaultPayload,
    ): VaultUnlockResult {
        require(candidate.canonicalFile != vaultFile.canonicalFile) { "候选文件不得是当前保险库" }
        val current = currentAuthenticatedFile(rootKey)
        require(current.identity == expectedCurrent) { "当前 PMVE 身份已变化" }
        val authenticatedCandidate = authenticateExternalFileWithDeviceKey(candidate, rootKey)
        require(authenticatedCandidate.identity == expectedRemote) { "候选 PMVE 身份与预期不一致" }
        require(classifyAuthenticatedFile(current, authenticatedCandidate) == VaultFileRelationship.DIVERGED) {
            "仅 DIVERGED 关系允许生成合并候选"
        }
        val localHeaderRaw = PmvVaultStore.openRootKey(vaultFile, rootKey).use { it.copyHeaderRaw() }
        try {
            val localPayload = PmvVaultStore.openRootKey(vaultFile, rootKey).use(::pmvePayload)
            val localRegistry = PmvVaultStore.openRootKey(vaultFile, rootKey).use { session ->
                PmvDeviceRegistry.decode(session.readMetadata()).also {
                    PmvDeviceRegistry.verifyAll(it, session.identity().signingPublicKey)
                }
            }
            PmvVaultStore.openRootKey(candidate, rootKey).use { session ->
                val remotePayload = pmvePayload(session)
                val remoteRegistry = PmvDeviceRegistry.decode(session.readMetadata()).also {
                    PmvDeviceRegistry.verifyAll(it, session.identity().signingPublicKey)
                }
                val mergedPayload = mergeEntries(localPayload, remotePayload)
                val mergedMetadata = PmvDeviceRegistry.withRegistry(
                    PmvEPayloadAdapter.toMetadata(mergedPayload, session.identity().vaultId, session.readMetadata()),
                    unionDeviceRegistries(localRegistry, remoteRegistry),
                )
                PmvVaultStore.openRootKey(vaultFile, rootKey).use { source ->
                    session.saveMerged(source, activityMetadata(session, DeviceActivity.merge(mergedMetadata, source.readMetadata())),
                        mergedPayload.entries + mergedPayload.trash, session.identity().sequence)
                }
                if (mergedPayload.syncMeta == localPayload.syncMeta) session.adoptHeader(localHeaderRaw)
            }
            return PmvVaultStore.openRootKey(candidate, rootKey).use(::pmveUnlockResult)
        } finally {
            localHeaderRaw.fill(0)
        }
    }

    /** Install a verified merge only if the local vault still has the identity used to prepare it. */
    fun installPreparedMergedFile(
        candidate: File,
        rootKey: ByteArray,
        expectedCurrent: VaultIdentity,
        expectedMerged: VaultIdentity,
    ): VaultUnlockResult {
        require(candidate.canonicalFile != vaultFile.canonicalFile) { "候选文件不得是当前保险库" }
        return PmvAppendOnlyFile.withExclusiveWriterLock(vaultFile) {
            val current = currentAuthenticatedFile(rootKey)
            require(current.identity == expectedCurrent) { "发布期间本地保险库已变化，未覆盖本地数据" }
            val prepared = authenticateExternalFileWithDeviceKey(candidate, rootKey)
            require(prepared.identity == expectedMerged) { "合并候选身份与已发布版本不一致" }
            require(classifyAuthenticatedFile(current, prepared) == VaultFileRelationship.DIVERGED) {
                "合并候选与当前保险库关系已变化，未覆盖本地数据"
            }
            val install = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.cloud-merge.tmp")
            val restore = File(vaultFile.parentFile, ".${vaultFile.name}.${UUID.randomUUID()}.cloud-restore.tmp")
            try {
                copyFileDurably(candidate, install)
                copyFileDurably(vaultFile, restore)
                atomicReplaceFile(install, vaultFile)
                try {
                    syncParentDirectory(vaultFile)
                    openPmvEWithRootKey(rootKey).also {
                        require(it.identity == expectedMerged) { "安装后的云端合并版本身份不一致" }
                    }
                } catch (error: Throwable) {
                    atomicReplaceFile(restore, vaultFile)
                    syncParentDirectory(vaultFile)
                    throw IllegalStateException("云端合并版本安装失败，已恢复本地文件", error)
                }
            } finally {
                install.delete()
                restore.delete()
            }
        }
    }

    fun createSyncSnapshot(): File {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        val directory = File(context.cacheDir, "sync_snapshots").also { it.mkdirs() }
        val target = File(directory, "${UUID.randomUUID()}.pmv")
        try {
            // PMVE 的权威内容就是本库文件（含媒体 Object 与提交谱系）；
            // 重建 payload 会产生悬空 ObjectRef，因此快照必须是库文件的字节副本。
            copyPmvEFileSnapshot(vaultFile, target)
            return target
        } catch (error: Throwable) {
            target.delete()
            throw error
        }
    }

    /** Rotate the entire encrypted vault, including the root and signing keys. */
    fun changePmvEPassword(oldPasswordUtf8: ByteArray, newPasswordUtf8: ByteArray, recoverySecret: ByteArray, beforeReplace: () -> Unit = {}): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvVaultStore.openPassword(vaultFile, oldPasswordUtf8).use {
            it.rotatePassword(newPasswordUtf8, recoverySecret, beforeReplace)
        }
        return PmvVaultStore.openPassword(vaultFile, newPasswordUtf8).use(::pmveUnlockResult)
    }

    /** PMVE 用恢复密钥重置主密码。 */
    fun resetPmvEPasswordWithRecovery(recoverySecret: ByteArray, newPasswordUtf8: ByteArray, beforeReplace: () -> Unit = {}): VaultUnlockResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvVaultStore.openRecovery(vaultFile, recoverySecret).use {
            it.rotatePassword(newPasswordUtf8, recoverySecret, beforeReplace)
        }
        return PmvVaultStore.openPassword(vaultFile, newPasswordUtf8).use(::pmveUnlockResult)
    }

    /** 读取当前 PMVH 的 KDF 参数（使用保险库根密钥，无需主密码）。 */
    fun currentKdfParameters(rootKey: ByteArray): PmvKdfParameters =
        PmvVaultStore.openRootKey(vaultFile, rootKey).use { it.kdfParameters() }

    /** 在保持主密码不变的前提下，用更高强度的 KDF 参数重新包装密码槽（审计发现 5）。 */
    fun upgradeKdfProfile(passwordUtf8: ByteArray, target: PmvKdfProfile) {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvVaultStore.openPassword(vaultFile, passwordUtf8).use {
            it.rewrapPasswordProfile(passwordUtf8, target)
        }
    }

    /** PMVE 用旧恢复密钥换发新恢复密钥（提交前旧密钥始终有效）。 */
    fun rotatePmvERecoveryKey(recoverySecret: ByteArray, newSecret: ByteArray): VaultIdentity {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvVaultStore.openRecovery(vaultFile, recoverySecret).use { session ->
            session.rotateRecovery(recoverySecret, newSecret)
            session.touchKeyRevision(nowSeconds()).toVaultIdentity()
        }
    }

    /** PMVE 用主密码重新生成恢复密钥（旧恢复密钥立即失效）。 */
    fun regeneratePmvERecoveryKey(passwordUtf8: ByteArray, newSecret: ByteArray) {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        require(newSecret.size == PmvKeySchedule.KEY_SIZE) { "恢复密钥必须为 32 字节" }
        PmvVaultStore.openPassword(vaultFile, passwordUtf8).use {
            it.regenerateRecoveryKey(passwordUtf8, newSecret)
            it.touchKeyRevision(nowSeconds())
        }
    }

    fun replaceFromRemote(
        raw: ByteArray,
        expectedDeviceId: String,
        rootKey: ByteArray,
    ): VaultPayload {
        val candidateFile = java.io.File(vaultFile.parentFile, "${vaultFile.name}.download-verify.tmp")
        try {
            candidateFile.outputStream().buffered().use { it.write(raw) }
            return replaceFromRemoteFile(candidateFile, expectedDeviceId, rootKey)
        } finally {
            candidateFile.delete()
        }
    }

    fun replaceFromRemoteFile(
        candidateFile: File,
        expectedDeviceId: String,
        rootKey: ByteArray,
    ): VaultPayload {
        require(VaultFileFormat.detect(candidateFile) == VaultFileFormat.PMVE) { "远端文件不是 PMVE 保险库" }
        val downloadBackup = java.io.File(vaultFile.parentFile, "${vaultFile.name}.download.bak")
        var replacementStarted = false
        try {
            val candidate = decodeExternalFileWithRootKey(candidateFile, rootKey)
            check(expectedDeviceId.isNotBlank() && candidate.syncMeta.deviceId == expectedDeviceId) {
                "远端文件不属于当前保险库"
            }
            vaultFile.copyTo(downloadBackup, overwrite = true)
            replacementStarted = true
            writeSafely { target ->
                candidateFile.inputStream().buffered().use { input ->
                    target.outputStream().buffered().use { output -> input.copyTo(output) }
                }
            }
            val verified = decodeExternalFileWithRootKey(vaultFile, rootKey)
            check(com.vault.storage.VaultLogicalRevision.from(verified) == com.vault.storage.VaultLogicalRevision.from(candidate)) {
                "下载覆盖后读回校验失败"
            }
            if (downloadBackup.length() > MAX_PERSISTENT_BACKUP_BYTES) downloadBackup.delete()
            return verified
        } catch (error: Throwable) {
            if (replacementStarted && downloadBackup.isFile) {
                runCatching {
                    writeSafely { target ->
                        downloadBackup.inputStream().buffered().use { input ->
                            target.outputStream().buffered().use(input::copyTo)
                        }
                    }
                }.exceptionOrNull()?.let(error::addSuppressed)
            }
            throw error
        }
    }

    private fun pmveUnlockResult(session: PmvVaultStore.Session): VaultUnlockResult {
        val storeIdentity = session.identity()
        return VaultUnlockResult(
            payload = pmvePayload(session),
            rootKey = session.copyRootKeyForDeviceUnlock(),
            identity = VaultIdentity(
                vaultId = storeIdentity.vaultId,
                sequence = storeIdentity.sequence,
                commitId = storeIdentity.latestCommitId,
                parentCommitId = storeIdentity.parentCommitId,
                keyRevision = storeIdentity.keyRevision,
                headerRevision = storeIdentity.headerRevision,
                signingPublicKey = storeIdentity.signingPublicKey,
                rootDigest = storeIdentity.rootDigest,
            ),
    )
}

    private fun pmvePayload(session: PmvVaultStore.Session): VaultPayload {
        val metadata = session.readMetadata()
        val entries = session.listSummaries().map { summary ->
            requireNotNull(session.readEntry(summary.entryId)) { "PMVE EntryIndex 引用了不存在的 Entry" }
        }
        return PmvEPayloadAdapter.fromMetadata(metadata, entries)
    }

    private fun savePmvE(
        session: PmvVaultStore.Session,
        payload: VaultPayload,
        expectedSequence: Long = session.identity().sequence,
    ): VaultPayload {
        val identity = session.identity()
        val normalized = PmvEPayloadAdapter.normalizePayload(payload)
        val metadata = PmvEPayloadAdapter.toMetadata(
            normalized,
            identity.vaultId,
            previousMetadata = session.readMetadata(),
        )
        session.saveFull(activityMetadata(session, metadata), normalized.entries + normalized.trash, expectedSequence)
        return normalized
    }

    private fun mutatePmvE(
        session: PmvVaultStore.Session,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity {
        val before = pmvePayload(session)
        val after = PmvEPayloadAdapter.normalizePayload(transform(before))
        val metadata = PmvEPayloadAdapter.toMetadata(
            after,
            session.identity().vaultId,
            previousMetadata = session.readMetadata(),
        )
        val result = try {
            session.applyMutation(expectedSequence) {
                PmvVaultStore.MutationContent(activityMetadata(session, metadata), after.entries + after.trash)
            }
        } catch (error: IllegalArgumentException) {
            if (error.message?.contains("基线已过期") == true) {
                throw VaultStaleMutationException("PMVE 提交基线已过期", error)
            }
            throw error
        }
        return result.identity.toVaultIdentity()
    }

    private fun PmvVaultStore.Identity.toVaultIdentity(): VaultIdentity = VaultIdentity(
        vaultId = vaultId,
        sequence = sequence,
        commitId = latestCommitId,
        parentCommitId = parentCommitId,
        keyRevision = keyRevision,
        headerRevision = headerRevision,
        signingPublicKey = signingPublicKey,
        rootDigest = rootDigest,
    )

    private fun authenticatedPmvEFile(
        file: File,
        session: PmvVaultStore.Session,
    ): AuthenticatedVaultFile {
        val storeIdentity = session.identity()
        val identity = storeIdentity.toVaultIdentity()
        val ancestors = session.withRootKeyForDeviceUnlock { rootKey ->
            readPmvEAncestorCommitIds(file, rootKey, identity)
        }
        return AuthenticatedVaultFile(file, VaultFileFormat.PMVE, identity, ancestors)
    }

    private fun readPmvEAncestorCommitIds(
        file: File,
        rootKey: ByteArray,
        latestIdentity: VaultIdentity,
    ): Set<UUID> {
        val rootKeys = PmvKeySchedule.deriveRootKeys(rootKey, latestIdentity.vaultId)
        return try {
            PmvAppendOnlyFile.open(file, rootKeys.integrityKey).use { container ->
                val state = container.state().superblock
                require(state.vaultId == latestIdentity.vaultId && state.sequence == latestIdentity.sequence) {
                    "PMVE Superblock 与认证身份不一致"
                }
                val commits = linkedMapOf<UUID, PmvCommitCodec.Commit>()
                var offset = PmvContainerFormat.DATA_START
                while (offset < state.committedFileEnd) {
                    val block = container.readBlock(offset)
                    if (block.header.blockType == PmvContainerFormat.BlockType.COMMIT) {
                        val key = PmvKeySchedule.deriveCommitBlockKey(
                            rootKeys.integrityKey,
                            block.header.objectId,
                            block.header.objectRevision,
                        )
                        val plaintext = try {
                            PmvBlockCrypto.open(latestIdentity.vaultId, key, block)
                        } finally {
                            key.fill(0)
                        }
                        val commit = try {
                            PmvCommitCodec.decode(plaintext)
                        } finally {
                            plaintext.fill(0)
                        }
                        require(commit.vaultId == latestIdentity.vaultId &&
                            commit.commitId == block.header.objectId &&
                            commit.revision == block.header.objectRevision &&
                            PmvCommitCodec.verifySignature(commit) &&
                            MessageDigest.isEqual(commit.signingPublicKey, latestIdentity.signingPublicKey)
                        ) { "PMVE 历史 Commit 无法认证" }
                        require(commits.put(commit.commitId, commit) == null) { "PMVE Commit ID 重复" }
                    }
                    offset = Math.addExact(
                        offset,
                        Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), block.header.cipherSize),
                    )
                }
                require(offset == state.committedFileEnd) { "PMVE Block 边界与 committed_file_end 不一致" }
                val latest = requireNotNull(commits[latestIdentity.commitId]) { "最新 Commit 不在认证日志中" }
                require(latest.revision == latestIdentity.sequence &&
                    MessageDigest.isEqual(latest.rootDigest, latestIdentity.rootDigest)
                ) { "最新 Commit 与认证身份不一致" }
                val ancestors = linkedSetOf<UUID>()
                var child = latest
                while (child.parentCommitId != null) {
                    val parentId = requireNotNull(child.parentCommitId)
                    require(ancestors.add(parentId)) { "PMVE Commit lineage 存在环" }
                    // 压缩后的库只保留最新提交（祖先提交块被回收）：父块缺失时停止
                    // 回溯，已认证的头部提交仍然可用；谱系分类退化为保守的 DIVERGED。
                    val parent = commits[parentId] ?: break
                    require(parent.revision < child.revision) { "PMVE Commit revision 未严格递增" }
                    child = parent
                }
                ancestors
            }
        } finally {
            rootKeys.close()
        }
    }

    private fun rejectExternalMediaDuringIdentityRead(kind: String, source: InputStream): String {
        source.close()
        throw IllegalStateException("$kind 媒体必须通过显式媒体迁移路径处理")
    }

    private fun copyFileDurably(source: File, target: File) {
        require(source.isFile) { "源文件不存在" }
        source.inputStream().buffered().use { input ->
            target.outputStream().buffered().use(input::copyTo)
        }
        FileOutputStream(target, true).use { it.fd.sync() }
    }

    private fun atomicReplaceFile(from: File, to: File) {
        try {
            java.nio.file.Files.move(
                from.toPath(),
                to.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (error: java.nio.file.AtomicMoveNotSupportedException) {
            throw IllegalStateException("文件系统不支持 PMVE 原子替换", error)
        }
    }

    private fun syncParentDirectory(file: File) {
        java.nio.channels.FileChannel.open(
            requireNotNull(file.canonicalFile.parentFile).toPath(),
            java.nio.file.StandardOpenOption.READ,
        ).use { it.force(true) }
    }

    private class PmvEQuerySession(
        private val session: PmvVaultStore.Session,
    ) : VaultQuerySession {
        override val format: VaultFileFormat = VaultFileFormat.PMVE
        override val identity: VaultIdentity get() = session.identity().let { value ->
            VaultIdentity(
                value.vaultId, value.sequence, value.latestCommitId, value.parentCommitId,
                value.keyRevision, value.headerRevision, value.signingPublicKey, value.rootDigest,
            )
        }
        override fun queryDomain(domain: String): List<String> = session.queryDomain(domain).map(UUID::toString)
        override fun queryPackage(packageName: String): List<String> = session.queryPackage(packageName).map(UUID::toString)
        override fun queryRpId(rpId: String): List<String> = session.queryRpId(rpId).map(UUID::toString)
        override fun autofillExclusions(): com.vault.model.AutofillExclusions =
            session.readMetadata()["autofill_exclusions"]?.let {
                VaultCodec.json.decodeFromJsonElement(com.vault.model.AutofillExclusions.serializer(), it).normalized()
            } ?: com.vault.model.AutofillExclusions()
        override fun readEntry(entryId: String): Entry? = runCatching { UUID.fromString(entryId) }.getOrNull()
            ?.let(session::readEntry)
        override fun listSummaries(): List<VaultEntrySummary> = session.listSummaries().map { summary ->
            VaultEntrySummary(
                entryId = summary.entryId.toString(),
                entryType = summary.entryType,
                displayTitle = summary.displayTitle,
                favorite = summary.favorite,
                revision = summary.revision,
            )
        }
        override fun close() = session.close()
    }

    /**
     * 局域网导入最终提交：把隔离区中的明文按内容寻址加密提升到媒体缓存。
     *
     * 同一明文若已有“当前库密钥可解密”的候选文件则安全复用；若基础 hash 文件属于
     * 其他账户密钥，不覆盖它，而是创建带随机后缀的新候选。返回值携带本事务是否创建
     * 文件，供调用方在后续库保存/receipt 失败时只回滚自己拥有的媒体。
     */
    fun promoteImportMedia(
        kind: String,
        source: InputStream,
        beforeCreate: (String) -> Unit = {},
    ): ImportMediaPromotion {
        check(!isPmvE()) { "PMVE 媒体必须通过 ObjectStore 原子事务保存" }
        val isImage = kind == "images"
        require(isImage || kind == "attachments") { "导入媒体类型无效" }
        val directory = File(context.cacheDir, "vault_media/$kind").also { it.mkdirs() }
        val plainTemp = File(directory, ".${UUID.randomUUID()}.import.tmp")
        val encryptedTemp = File(directory, ".${UUID.randomUUID()}.vmed.tmp")
        val digest = MessageDigest.getInstance("SHA-256")
        var createdTarget: File? = null
        var promotionComplete = false
        try {
            plainTemp.outputStream().buffered().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                try {
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                    }
                } finally {
                    buffer.fill(0)
                }
            }
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            val suffix = if (isImage) detectImageSuffix(plainTemp) else ""
            val prefix = if (isImage) "img:" else "att:"
            val candidates = directory.listFiles().orEmpty().filter { candidate ->
                candidate.isFile && !candidate.name.startsWith('.') &&
                    (candidate.name == "$hash$suffix" ||
                        candidate.name.startsWith("$hash-") && candidate.name.endsWith(suffix))
            }
            candidates.firstOrNull(MediaCrypto::decryptable)?.let { existing ->
                return ImportMediaPromotion(prefix + existing.name, created = false)
            }

            // 新文件始终使用不可预测的事务候选名，避免在“日志登记→目标创建”之间与
            // 另一个提升流程争用基础 hash 文件。已有相同内容仍由上面的 candidates 复用。
            val target = File(directory, "$hash-${UUID.randomUUID()}$suffix")
            val createdRef = prefix + target.name
            // 先把所有权写入崩溃恢复日志，再创建并写媒体内容；即使进程在加密/复制中退出，
            // 下次启动也能定位并删除本事务留下的空文件或半成品。
            beforeCreate(createdRef)
            check(target.createNewFile()) { "无法创建导入媒体文件" }
            createdTarget = target
            plainTemp.inputStream().buffered().use { plain ->
                encryptedTemp.outputStream().buffered().use { encrypted ->
                    MediaCrypto.encryptStream(plain, encrypted)
                }
            }
            encryptedTemp.copyTo(target, overwrite = true)
            FileOutputStream(target, true).use { output -> output.fd.sync() }
            runCatching {
                java.nio.channels.FileChannel.open(
                    directory.toPath(),
                    java.nio.file.StandardOpenOption.READ,
                ).use { it.force(true) }
            }
            promotionComplete = true
            return ImportMediaPromotion(createdRef, created = true)
        } finally {
            if (!promotionComplete) createdTarget?.delete()
            plainTemp.delete()
            encryptedTemp.delete()
        }
    }

    /** 仅回滚由本次提升新建的文件；复用的共享内容永不删除。 */
    fun rollbackImportMedia(promotion: ImportMediaPromotion) {
        if (!promotion.created) return
        val ref = promotion.ref
        val kind = when {
            ref.startsWith("img:") -> "images"
            ref.startsWith("att:") -> "attachments"
            else -> return
        }
        val name = ref.substringAfter(':')
        if (name.isBlank() || '/' in name || '\\' in name || name.startsWith('.') || ".." in name) return
        runCatching { File(context.cacheDir, "vault_media/$kind/$name").delete() }
    }

    /** 兼容旧调用点；新导入事务应使用 [promoteImportMedia] 获取回滚所有权。 */
    fun storeImportMedia(kind: String, source: InputStream): String = promoteImportMedia(kind, source).ref

    private fun detectImageSuffix(file: File): String = file.inputStream().use { input ->
        val header = ByteArray(16)
        val count = input.read(header)
        when {
            count >= 4 && header[0] == 'G'.code.toByte() && header[1] == 'I'.code.toByte() &&
                header[2] == 'F'.code.toByte() && header[3] == '8'.code.toByte() -> ".gif"
            count >= 4 && header[0] == 0x89.toByte() && header[1] == 'P'.code.toByte() &&
                header[2] == 'N'.code.toByte() && header[3] == 'G'.code.toByte() -> ".png"
            count >= 12 && String(header, 0, 4, Charsets.US_ASCII) == "RIFF" &&
                String(header, 8, 4, Charsets.US_ASCII) == "WEBP" -> ".webp"
            count >= 12 && String(header, 4, 8, Charsets.US_ASCII).startsWith("ftyphei") -> ".heic"
            else -> ".jpg"
        }
    }

    /** PMVE 权威 ObjectRef 全量流式读取；不会创建明文临时文件。 */
    fun openPmvEMedia(
        ref: PmvMediaRef.Ref,
        rootKey: ByteArray,
        output: java.io.OutputStream,
    ) {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvMediaObjectAdapter(vaultFile).open(ref, rootKey, output)
    }

    /** PMVE 权威 ObjectRef 范围读取，只解认证范围涉及的 Chunk。 */
    fun openPmvEMediaRange(
        ref: PmvMediaRef.Ref,
        rootKey: ByteArray,
        offset: Long,
        length: Long,
        output: java.io.OutputStream,
    ) {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        PmvMediaObjectAdapter(vaultFile).openRange(ref, rootKey, offset, length, output)
    }

    /** 创建进程内短时、一次性的流式预览/分享 URI。 */
    fun createPmvEMediaPreviewUri(
        ref: PmvMediaRef.Ref,
        rootKey: ByteArray,
        displayName: String,
        mimeType: String,
    ): Uri {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        return PmvMediaContentRegistry.issue(
            context,
            vaultName,
            rootKey,
            ref,
            displayName,
            mimeType,
        )
    }

    fun revokePmvEMediaPreviewUri(uri: Uri) = PmvMediaContentRegistry.revoke(uri)

    /**
     * 将 Entry 与其新媒体 Object 在同一 expected-sequence Commit 中发布。
     * Store 不关闭调用方拥有的输入流；失败或取消后重试必须重新打开输入流。
     */
    fun savePmvEEntryWithMedia(
        entry: Entry,
        expectedEntryRevision: Long?,
        streams: List<PmvMediaRef.LegacyStream>,
        rootKey: ByteArray,
        expectedSequence: Long,
    ): PmvEMediaSaveResult {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        val saved = PmvMediaObjectAdapter(vaultFile).saveEntryWithMedia(
            rootKey,
            expectedSequence,
            entry,
            expectedEntryRevision,
            streams,
            { session, metadata -> activityMetadata(session, metadata) },
        )
        return PmvEMediaSaveResult(
            saved.identity.toVaultIdentity(),
            saved.entry,
            saved.entryRevision,
            saved.refs.map(PmvMediaRef.Ref::copySha256),
        )
    }

    /** PMVE ObjectRef 流式读取门面。 */
    fun copyMediaPlainTo(
        value: JsonElement,
        deviceKey: ByteArray,
        output: java.io.OutputStream,
    ): Boolean {
        require(isPmvE()) { "保险库不是 PMVE 格式" }
        openPmvEMedia(parsePmvEMediaRef(value), deviceKey, output)
        return true
    }

    private fun parsePmvEMediaRef(value: JsonElement): PmvMediaRef.Ref = when (value) {
        is JsonObject -> PmvMediaRef.fromJson(value)
        is JsonPrimitive -> PmvMediaRef.fromExternalString(value.content)
        else -> throw IllegalArgumentException("PMVE media ref 必须为 canonical JSON 或字符串")
    }

    private fun writeSafely(data: ByteArray) {
        writeSafely { target -> target.outputStream().use { it.write(data) } }
    }

    private fun writeSafely(writeTemp: (File) -> Unit) {
        PmvAppendOnlyFile.withExclusiveWriterLock(vaultFile) {
            try {
                if (tmpFile.exists() && !tmpFile.delete()) error("无法清理旧的临时保险库文件")
                writeTemp(tmpFile)
                if (vaultFile.exists()) {
                    if (vaultFile.length() <= MAX_PERSISTENT_BACKUP_BYTES) {
                        try { vaultFile.copyTo(bakFile, overwrite = true) } catch (_: Throwable) {}
                    } else {
                        bakFile.delete()
                    }
                }
                if (!tmpFile.renameTo(vaultFile)) {
                    tmpFile.copyTo(vaultFile, overwrite = true)
                }
            } finally {
                if (tmpFile.exists()) tmpFile.delete()
            }
        }
    }

    fun readBytes(): ByteArray = vaultFile.readBytes()
    fun writeRaw(data: ByteArray) = writeSafely(data)
    fun syncFile(): java.io.File = vaultFile

    fun exportTo(uri: Uri) {
        context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
            vaultFile.inputStream().buffered().use { input -> input.copyTo(output) }
        } ?: throw FileNotFoundException("无法写入所选位置")
    }

    private fun VaultPayload.bumpKeyRevision(): VaultPayload = copy(
        syncMeta = syncMeta.copy(
            keyRevision = syncMeta.keyRevision + 1,
            keyUpdatedAt = nowSeconds(),
        ),
    )

    private companion object {
        const val MAX_PERSISTENT_BACKUP_BYTES = 16L * 1024L * 1024L
        const val MAX_INCREMENTAL_CHANGES = 32
    }
}
