package com.vault.ui

import android.app.Application
import android.content.Context
import android.content.ContentValues
import android.net.Uri
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import android.os.Environment
import android.provider.OpenableColumns
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.vault.crypto.KdfMigrationState
import com.vault.crypto.PmvKdfParameters
import com.vault.crypto.PmvKdfPolicy
import com.vault.crypto.PmvKdfProfile
import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.RecoveryKeyCodec
import com.vault.crypto.VaultCrypto
import com.vault.model.Entry
import com.vault.model.OtpDisplaySnapshot
import com.vault.model.SecretType
import com.vault.model.SyncMeta
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import com.vault.model.entrySecret
import com.vault.model.hasCurrentLeakCache
import com.vault.model.needsLeakCheck
import com.vault.model.nowSeconds
import com.vault.model.otpDisplaySnapshot
import com.vault.model.withLeakCheckResult
import com.vault.security.LeakCheckIntervalPref
import com.vault.security.LeakCheckEnabledPref
import com.vault.security.LeakOnlineCheckPref
import com.vault.security.LeakedPasswordCheck
import com.vault.security.PwnedPasswordsCheck
import com.vault.security.BiometricVault
import com.vault.security.DeviceUnlockKeyKind
import com.vault.security.DeviceUnlockMaterial
import com.vault.security.FailureSource
import com.vault.security.LockoutPref
import com.vault.security.CloudCredentialStore
import com.vault.security.VaultKeyIdentity
import com.vault.security.VaultDeviceIdentityStore
import com.vault.security.VaultSessionCredential
import com.vault.security.SessionEntryStore
import com.vault.security.PasswordHealth
import com.vault.security.PasswordHealthReport
import com.vault.security.VaultMaintenancePref
import com.vault.passkeys.PasskeyBackupTransfer
import com.vault.storage.AutoCompactPolicy
import com.vault.storage.CacheCleaner
import com.vault.storage.BackupCodec
import com.vault.storage.BackupPasswordPolicy
import com.vault.storage.MediaCrypto
import com.vault.storage.AutoCloudSyncPrefs
import com.vault.storage.AuthenticatedVaultFile
import com.vault.storage.CloudDirectoryInspection
import com.vault.storage.CloudDocumentMetadata
import com.vault.storage.CloudFileConflict
import com.vault.storage.CloudFileCheck
import com.vault.storage.CloudFileTransferGuard
import com.vault.storage.CloudFileVersion
import com.vault.storage.CloudTreeStorage
import com.vault.storage.VaultFileRelationship
import com.vault.storage.PmvVaultStore
import com.vault.storage.PmvVaultHeaderCodec
import com.vault.storage.SyncClient
import com.vault.storage.SyncForegroundService
import com.vault.storage.BackgroundTaskKind
import com.vault.storage.BackgroundTaskOutcome
import com.vault.storage.SyncServerHost
import com.vault.storage.LanImportConflictKind
import com.vault.storage.LanImportPolicy
import com.vault.storage.TrashRetentionPref
import com.vault.storage.VaultCodec
import com.vault.storage.VaultRegistry
import com.vault.storage.VaultRepository
import com.vault.storage.VaultUnlockResult
import com.vault.storage.VaultIdentity
import com.vault.storage.VaultFileFormat
import com.vault.storage.VaultLogicalRevision
import com.vault.storage.PmvMediaRef
import com.vault.storage.PmvDeviceRegistry
import com.vault.storage.PmvSyncAuthorization
import com.vault.storage.PmvAttachmentCodec
import com.vault.storage.WebDavCloud
import com.vault.storage.WebDavConfig
import com.vault.storage.WebDavMetadata
import com.vault.storage.toPmvELineage
import com.vault.ui.media.PmvMediaUiSession
import com.vault.ui.media.imageFileFromRef
import com.vault.ui.media.attachmentFileFromRef
import com.vault.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import org.json.JSONObject
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.resume
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

internal class VaultSessionFence {
    class Token internal constructor(val generation: Long, val vaultName: String?)

    private var generation = 0L

    @Synchronized
    fun capture(vaultName: String?): Token = Token(generation, vaultName)

    @Synchronized
    fun invalidate() {
        generation += 1
    }

    @Synchronized
    fun isCurrent(token: Token, vaultName: String?): Boolean =
        token.generation == generation && token.vaultName == vaultName

    @Synchronized
    fun runIfCurrent(token: Token, vaultName: String?, action: () -> Unit): Boolean {
        if (!isCurrent(token, vaultName)) return false
        action()
        return true
    }
}

internal suspend fun <T> withExternalActionFlag(
    setActive: (Boolean) -> Unit,
    action: suspend () -> T,
): T {
    setActive(true)
    return try {
        action()
    } finally {
        setActive(false)
    }
}

/**
 * 多账户状态机：
 *  - currentVault: 当前选中的账户名（null = 无任何账户）
 *  - phase: NO_VAULT / LOCKED / UNLOCKED 按当前账户判定
 *  - 切换账户会自动 lock 并切换到新账户的 LOCKED（或 NO_VAULT）
 */
class VaultViewModel(app: Application) : AndroidViewModel(app) {
    private var securitySessionUntilElapsed = 0L
    private var sensitiveExportGrant: SensitiveExportGrant? = null
    private var automaticLeakJob: Job? = null
    private var postUnlockJob: Job? = null
    private var autoCloudSyncJob: Job? = null
    private var remoteUpdateJob: Job? = null
    private var remoteUpdateOperationGeneration = 0L
    private var remoteUpdatePaused = false
    private val remoteUpdateMutex = kotlinx.coroutines.sync.Mutex()
    private data class RemoteUpdateProof(val session: VaultSessionFence.Token, val association: String, val version: String, val consumedVersion: String = "")
    private val remoteUpdateProofs = java.util.concurrent.ConcurrentHashMap<String, RemoteUpdateProof>()
    private val _remoteUpdateStates = MutableStateFlow<Map<String, com.vault.storage.RemoteUpdateState>>(emptyMap())
    val remoteUpdateStates: StateFlow<Map<String, com.vault.storage.RemoteUpdateState>> = _remoteUpdateStates.asStateFlow()
    private var cloudDiskOperationJob: Job? = null
    private var webDavOperationJob: Job? = null
    private val vaultSessionJobs = java.util.concurrent.ConcurrentHashMap.newKeySet<Job>()
    private var lanSyncKeepAliveJob: Job? = null
    private var lanTransferPollJob: Job? = null
    private val lanTransferDownloadSemaphore = java.util.concurrent.Semaphore(3)
    private val lanTransferJobs = java.util.Collections.synchronizedList(mutableListOf<Job>())
    /** 单条传输协程索引：key = 传输项 id（接收用 offer.id，发送用 pendingId），供单条取消。 */
    private val lanTransferJobsById = java.util.concurrent.ConcurrentHashMap<String, Job>()
    /** 用户主动取消的传输项（key = direction:id）：任务收尾不再覆盖其状态，也不计入失败/总进度。 */
    private val lanTransferCancelledKeys = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private var lanSyncSession: Pair<String, String>? = null
    private var lanTransferPinServer: String? = null
    private var lanTransferPinFailures = 0
    private val lanTransferTempFiles = java.util.Collections.synchronizedList(mutableListOf<File>())
    private val hostSendJobs = java.util.Collections.synchronizedList(mutableListOf<Job>())
    private var lanImportJob: Job? = null
    private var lanSyncJob: Job? = null
    private val _lanImportState = MutableStateFlow<LanImportState?>(null)
    val lanImportState: StateFlow<LanImportState?> = _lanImportState.asStateFlow()
    private val MAX_LAN_IMPORT_EXPORT_ATTEMPTS = 3
    private var lanImportExportAttempts = 0
    private var lanImportRetryContinuation: kotlin.coroutines.Continuation<Boolean>? = null
    private val _lanImportIntegrityRetry = MutableStateFlow<LanImportIntegrityRetry?>(null)
    val lanImportIntegrityRetry: StateFlow<LanImportIntegrityRetry?> = _lanImportIntegrityRetry.asStateFlow()
    private var lanImportConflictContinuation: kotlin.coroutines.Continuation<Boolean>? = null
    data class LanImportConflict(
        val sourceName: String,
        val existingName: String,
        val suggestedName: String,
        val sameVault: Boolean,
    )
    private val _lanImportConflict = MutableStateFlow<LanImportConflict?>(null)
    val lanImportConflict: StateFlow<LanImportConflict?> = _lanImportConflict.asStateFlow()
    /** 大文件（>10 GiB）放行提示：单次会话只提示一次，不限制传输。 */
    private var largeTransferWarned = false
    private var pendingLargeTransferUri: Uri? = null
    /** 剪贴板/IME 富内容已复制到私有缓存、等待大文件确认的待发送项。 */
    private var pendingCachedTransfer: PendingCachedTransfer? = null
    private val _pendingLargeTransfer = MutableStateFlow<Uri?>(null)
    val pendingLargeTransfer: StateFlow<Uri?> = _pendingLargeTransfer.asStateFlow()
    /** 活跃传输项的字节进度（key = direction:remoteId），用于汇总通知总进度。 */
    private val transferByteStates = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, Long>>()
    private var securityScanId: Long = 0L
    private var securityReportRevision: String? = null
    private var securityScanningRevision: String? = null
    private var pendingUnlock: PendingUnlock? = null
    private var unlockAttemptId: Long = 0L
    private var entryStore: SessionEntryStore? = null
    private val vaultOperationMutex = Mutex()
    private val vaultSessionFence = VaultSessionFence()
    private data class PendingUnlock(
        val payload: VaultPayload,
        val listIndex: VaultListIndex,
        val credential: VaultSessionCredential? = null,
        val repository: VaultRepository,
        val needsSave: Boolean,
        val purgedExpired: Boolean = false,
    ) {
        val password: VaultSessionCredential.Password? get() = credential.sessionPassword()
        val rootKey: VaultSessionCredential.RootKey? get() = credential.sessionRootKey()
    }

    private data class PreparedUnlock(
        val payload: VaultPayload,
        val listIndex: VaultListIndex,
        val needsSave: Boolean,
        val rootKey: ByteArray? = null,
        val identity: VaultIdentity? = null,
        val purgedExpired: Boolean = false,
    ) {
        fun clearKeys() {
            rootKey?.fill(0)
        }
    }

    /** beginUnlock IO 块产物：密封后的 payload、是否需要落盘、密钥与“是否清理了过期回收站”。 */
    private data class UnlockOpenResult(
        val sealed: VaultPayload,
        val needsSave: Boolean,
        val rootKey: ByteArray?,
        val identity: VaultIdentity?,
        val purgedExpired: Boolean,
    )

    private data class LanSyncResult(
        val payload: VaultPayload,
        val stats: VaultOps.LwwMergeStats,
        val uploaded: Boolean,
        val verified: Boolean,
        val remoteBytes: Long = 0L,
        val lineage: String = "",
        val replacementRootKey: ByteArray? = null,
        val replacementIdentity: VaultIdentity? = null,
        val keyConvergence: KeyConvergenceKind = KeyConvergenceKind.NONE,
    ) {
        fun clearReplacementKey() = replacementRootKey?.fill(0)
    }

    /** 局域网导入（整库导出）的进行中状态，驱动欢迎页/解锁页弹窗。 */
    sealed interface LanImportState {
        data object WaitingForExport : LanImportState
        data class Downloading(val transferred: Long, val total: Long) : LanImportState
        data object Checking : LanImportState
        data object Saving : LanImportState
    }

    /** 完整性校验失败后的重新申请下载状态。 */
    data class LanImportIntegrityRetry(val attempt: Int, val maxAttempts: Int)

    private val registry = VaultRegistry(app)
    private val registrySnapshot = registry.snapshot()

    private val _vaults = MutableStateFlow(registrySnapshot.vaults)
    val vaults: StateFlow<List<String>> = _vaults.asStateFlow()

    private val _trashedVaults = MutableStateFlow(registrySnapshot.trashedVaults)
    /** 回收站中的账户：name -> deletedAt(epoch ms)。 */
    val trashedVaults: StateFlow<Map<String, Long>> = _trashedVaults.asStateFlow()

    private val _currentVault = MutableStateFlow(registrySnapshot.currentVault)
    val currentVault: StateFlow<String?> = _currentVault.asStateFlow()

    private val _state = MutableStateFlow(initialState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    /** 当前局域网传输站（建立传输站）实例；null 表示未开启。 */
    private var lanHost: SyncServerHost? = null
    private val _lanHostState = MutableStateFlow(SyncServerHost.HostStatus())
    val lanHostState: StateFlow<SyncServerHost.HostStatus> = _lanHostState.asStateFlow()

    /** 当前连接为「导出」通道且尚未在传输页确认允许导出。 */
    private val _lanHostExportPending = MutableStateFlow(false)
    val lanHostExportPending: StateFlow<Boolean> = _lanHostExportPending.asStateFlow()
    private val _lanHostExportPendingDevice = MutableStateFlow("")
    val lanHostExportPendingDevice: StateFlow<String> = _lanHostExportPendingDevice.asStateFlow()
    private val _lanHostExportApprovalToken = MutableStateFlow("")
    val lanHostExportApprovalToken: StateFlow<String> = _lanHostExportApprovalToken.asStateFlow()
    private val _lanHostSyncPending = MutableStateFlow(false)
    val lanHostSyncPending: StateFlow<Boolean> = _lanHostSyncPending.asStateFlow()
    private val _lanHostSyncPendingDevice = MutableStateFlow("")
    val lanHostSyncPendingDevice: StateFlow<String> = _lanHostSyncPendingDevice.asStateFlow()
    private val _lanHostSyncApprovalToken = MutableStateFlow("")
    val lanHostSyncApprovalToken: StateFlow<String> = _lanHostSyncApprovalToken.asStateFlow()
    private val _lanHostTransferPending = MutableStateFlow(false)
    val lanHostTransferPending: StateFlow<Boolean> = _lanHostTransferPending.asStateFlow()
    private val _lanHostTransferPendingDevice = MutableStateFlow("")
    val lanHostTransferPendingDevice: StateFlow<String> = _lanHostTransferPendingDevice.asStateFlow()
    private val _lanHostTransferApprovalToken = MutableStateFlow("")
    val lanHostTransferApprovalToken: StateFlow<String> = _lanHostTransferApprovalToken.asStateFlow()

    /** 每次有设备配对成功后自增，供 UI 自动跳转到传输页。 */
    private val _lanHostConnectSignal = MutableStateFlow(0)
    val lanHostConnectSignal: StateFlow<Int> = _lanHostConnectSignal.asStateFlow()

    private val _recoveryFlow = MutableStateFlow(RecoveryFlowStep.NONE)
    val recoveryFlow: StateFlow<RecoveryFlowStep> = _recoveryFlow.asStateFlow()
    private var pendingRecoverySecret: ByteArray? = null
    private var pendingNewRecoverySecret: ByteArray? = null
    private val _localBackupStatus = MutableStateFlow(getApplication<Application>().getString(R.string.viewmodel_backup_disabled))
    val localBackupStatus: StateFlow<String> = _localBackupStatus.asStateFlow()
    @Volatile private var localBackupRunning = false
    private val _localBackupRunningFlow = MutableStateFlow(false)
    val localBackupRunningFlow: StateFlow<Boolean> = _localBackupRunningFlow.asStateFlow()

    private val _events = MutableStateFlow<UiEvent?>(null)
    val events: StateFlow<UiEvent?> = _events.asStateFlow()

    private val _syncResult = MutableStateFlow<SyncResultState?>(null)
    val syncResult: StateFlow<SyncResultState?> = _syncResult.asStateFlow()

    private val _cloudSyncState = MutableStateFlow(CloudSyncUiState())
    val cloudSyncState: StateFlow<CloudSyncUiState> = _cloudSyncState.asStateFlow()
    private val cloudPreviewCache = CloudPreviewSessionCache<CloudSyncPreview>()

    private val _securityReport = MutableStateFlow(PasswordHealthReport.EMPTY)
    val securityReport: StateFlow<PasswordHealthReport> = _securityReport.asStateFlow()

    private val _securityScanRunning = MutableStateFlow(false)
    val securityScanRunning: StateFlow<Boolean> = _securityScanRunning.asStateFlow()

    private val _securityScanProgress = MutableStateFlow(0f)
    val securityScanProgress: StateFlow<Float> = _securityScanProgress.asStateFlow()

    fun consumeEvent() { _events.value = null }

    init {
        // 文件扫描与过期账户清理不占用 UI 线程；完成后仅发布轻量列表快照。
        viewModelScope.launch {
            val snapshot = withContext(Dispatchers.IO) {
                registry.purgeExpired()
                registry.list() to registry.listTrashed()
            }
            _vaults.value = snapshot.first
            _trashedVaults.value = snapshot.second
        }
        // 本地定期备份检查：周期到达或设备恢复可用时自动备份。
        viewModelScope.launch {
            while (true) {
                delay(60_000L)
                performLocalBackup()
            }
        }
    }

    /** 内容变更后，用户从其他页面进入安全页时执行本地规则扫描；其余时间复用报告。 */
    fun scanPasswordHealth() {
        val published = _state.value.payload ?: run {
            clearSecurityReport()
            return
        }
        val revision = VaultLogicalRevision.from(published)
        if (revision == securityReportRevision || revision == securityScanningRevision) return
        val scanId = ++securityScanId
        securityScanningRevision = revision
        _securityScanRunning.value = true
        _securityScanProgress.value = 0f
        viewModelScope.launch {
            try {
                val report = withContext(Dispatchers.Default) {
                    val payload = materializePayload(published)
                    PasswordHealth.analyze(
                        context = getApplication(),
                        entries = payload.entries,
                        logicalRevision = revision,
                        force = true,
                    ) { checked, total ->
                        if (scanId == securityScanId) {
                            _securityScanProgress.value = if (total > 0) {
                                checked.toFloat() / total
                            } else {
                                1f
                            }
                        }
                    }
                }
                val currentRevision = _state.value.payload?.let(VaultLogicalRevision::from)
                if (scanId == securityScanId && currentRevision == revision) {
                    _securityReport.value = report
                    securityReportRevision = revision
                    _securityScanProgress.value = 1f
                }
            } finally {
                if (scanId == securityScanId) {
                    securityScanningRevision = null
                    _securityScanRunning.value = false
                }
            }
        }
    }

    private fun clearSecurityReport() {
        securityScanId += 1
        securityReportRevision = null
        securityScanningRevision = null
        _securityReport.value = PasswordHealthReport.EMPTY
        _securityScanRunning.value = false
        _securityScanProgress.value = 0f
    }


    /** 备份合并谱系不匹配确认：UI 观察该 StateFlow，非空时弹窗请用户决定。 */
    data class PendingCrossAccountImport(
        val incomingEntries: List<Entry>,
        val incomingDeviceId: String,
        val incomingExportEpoch: Double?,
        val incomingPurgeTombstones: Map<String, Double> = emptyMap(),
        val incomingDeletionBaseline: com.vault.model.DeletionBaseline = com.vault.model.DeletionBaseline(),
        val incomingExclusions: com.vault.model.AutofillExclusions = com.vault.model.AutofillExclusions(),
        val sourceLabel: String = "",
        /**
         * 创建这份待确认导入时所处的库。确认时必须复核：否则在 A 库创建、锁定后切到 B 库
         * 仍能点“仍然合并”，把 A 的明文条目并进 B（H-10）。
         */
        val targetVaultName: String? = null,
        val targetSessionGeneration: Long = -1L,
    )
    private val _pendingCrossAccountImport = MutableStateFlow<PendingCrossAccountImport?>(null)
    val pendingCrossAccountImport: StateFlow<PendingCrossAccountImport?> = _pendingCrossAccountImport.asStateFlow()
    fun cancelCrossAccountImport() {
        _pendingCrossAccountImport.value = null
    }

    private fun startLanSyncKeepAlive(
        serverUrl: String,
        pin: String,
        intervalMs: Long = 30_000L,
        transfer: Boolean = false,
    ) {
        lanSyncKeepAliveJob?.cancel()
        lanSyncSession = serverUrl to pin
        lanSyncKeepAliveJob = viewModelScope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (isActive) {
                delay(intervalMs)
                val ok = runCatching {
                    if (transfer) SyncClient.keepTransferAlive(serverUrl, pin)
                    else SyncClient.keepAlive(serverUrl, pin)
                }.isSuccess
                if (ok) {
                    consecutiveFailures = 0
                } else {
                    consecutiveFailures += 1
                    // 同步通道连续保活失败视为对方已断开：立即复位 UI，避免一直停留在“正在与对方同步”。
                    if (!transfer && consecutiveFailures >= 3) {
                        handleLanSyncDisconnected()
                        break
                    }
                }
            }
        }
    }

    /** 连接方检测到对方已断开：取消同步、清理状态与通知，并提示。 */
    private fun handleLanSyncDisconnected() {
        lanSyncJob?.cancel()
        lanSyncJob = null
        SyncForegroundService.interruptTask(getApplication(), LAN_SYNC_TASK_ID, localizeUiTextFor(getApplication(), "对方已断开连接"))
        _state.update { it.copy(syncRunning = false) }
        clearLanSyncProgress()
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_lan_peer_disconnected))
        // 最后清理会话与保活任务（会取消当前协程，放在最后执行）。
        cancelLanSyncSession()
    }

    /** 用户主动断开局域网同步：取消作业、清理状态与会话并提示。 */
    fun stopSync() {
        if (lanSyncJob == null && !_state.value.syncRunning) return
        lanSyncJob?.cancel()
        lanSyncJob = null
        SyncForegroundService.interruptTask(
            getApplication(),
            LAN_SYNC_TASK_ID,
            getApplication<Application>().getString(R.string.viewmodel_lan_sync_stopped),
        )
        _state.update { it.copy(syncRunning = false) }
        clearLanSyncProgress()
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_lan_sync_stopped))
        // 最后清理会话与保活任务（会取消当前协程，放在最后执行）。
        cancelLanSyncSession()
    }

    private fun stopLanSyncKeepAlive(clearSession: Boolean = true) {
        if (clearSession) lanSyncSession?.let { SyncClient.forgetSession(it.first, it.second) }
        lanSyncKeepAliveJob?.cancel()
        lanSyncKeepAliveJob = null
        lanSyncSession = null
    }

    private fun cancelLanSyncSession() {
        val session = lanSyncSession
        stopLanSyncKeepAlive(clearSession = false)
        if (session != null) viewModelScope.launch(Dispatchers.IO) {
            runCatching { SyncClient.cancelSession(session.first, session.second) }
            SyncClient.forgetSession(session.first, session.second)
        }
    }

    private fun repo(): VaultRepository? =
        _currentVault.value?.let { VaultRepository(getApplication(), registry, it) }

    private fun captureVaultSession(): VaultSessionFence.Token =
        vaultSessionFence.capture(_currentVault.value)

    private suspend fun <T> deviceOperation(block: (VaultRepository, ByteArray) -> T): T {
        val token = captureVaultSession()
        return vaultOperationMutex.withLock {
            requireVaultSessionCurrent(token)
            val repository = repo() ?: error(localizeUiTextFor(getApplication(), "请先解锁保险库"))
            val credential = _state.value.rootKey ?: error(localizeUiTextFor(getApplication(), "请先解锁保险库"))
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(token)
                credential.withRootKey(credential.identity) { key -> block(repository, key) }
            }.also { requireVaultSessionCurrent(token) }
        }
    }

    suspend fun deletionCleanupState(): com.vault.model.DeletionCleanupState =
        deviceOperation { repository, key -> repository.deletionCleanupState(key) }

    suspend fun startDeletionCleanupCheckpoint() = mutateDeletionCleanup(null)

    suspend fun executeDeletionCleanup(checkpointId: String) = mutateDeletionCleanup(checkpointId)

    private suspend fun mutateDeletionCleanup(checkpointId: String?) {
        val token = captureVaultSession()
        vaultOperationMutex.withLock {
            requireVaultSessionCurrent(token)
            val repository = repo() ?: error("保险库会话已失效")
            val root = _state.value.rootKey ?: error("保险库会话已失效")
            withContext(Dispatchers.IO) {
                var accepted = false
                vaultSessionFence.runIfCurrent(token, _currentVault.value) {
                    root.withRootKey(root.identity) { key ->
                        val before = repository.openPmvEWithRootKey(key)
                        val sequence = try { requireNotNull(before.identity).sequence }
                            finally { before.rootKey?.fill(0) }
                        val opened = if (checkpointId == null)
                            repository.startDeletionCleanupCheckpoint(key, sequence)
                        else repository.executeDeletionCleanup(key, sequence, checkpointId)
                        try {
                            val replacementRoot = VaultSessionCredential.RootKey(key, requireNotNull(opened.identity).deviceBinding())
                            val password = _state.value.credential.sessionPassword()
                            val replacement = if (password == null) replacementRoot
                                else VaultSessionCredential.Compound(password, replacementRoot)
                            val sealed = sealPayload(opened.payload)
                            _state.update { it.copy(payload = sealed, listIndex = VaultListIndex.from(sealed), credential = replacement) }
                            root.close()
                            accepted = true
                        } finally { opened.rootKey?.fill(0) }
                    }
                }
                if (!accepted) throw kotlinx.coroutines.CancellationException("Vault session changed")
            }
            requireVaultSessionCurrent(token)
            emitInfo(getApplication<Application>().getString(if (checkpointId == null)
                R.string.deletion_cleanup_started else R.string.deletion_cleanup_success))
        }
    }

    suspend fun deviceProfiles(): List<com.vault.storage.DeviceActivityProfile> = deviceOperation { r, key -> r.deviceProfiles(key) }
    private fun isVaultSessionCurrent(token: VaultSessionFence.Token): Boolean =
        vaultSessionFence.isCurrent(token, _currentVault.value)

    private fun requireVaultSessionCurrent(token: VaultSessionFence.Token) {
        if (!isVaultSessionCurrent(token)) {
            throw kotlinx.coroutines.CancellationException("Vault session changed")
        }
    }

    private fun sealPayloadForSession(token: VaultSessionFence.Token, payload: VaultPayload): VaultPayload {
        var sealed: VaultPayload? = null
        val accepted = vaultSessionFence.runIfCurrent(token, _currentVault.value) {
            sealed = sealPayload(payload)
        }
        if (!accepted) throw kotlinx.coroutines.CancellationException("Vault session changed")
        return requireNotNull(sealed)
    }

    private fun publishPayloadForSession(
        token: VaultSessionFence.Token,
        payload: VaultPayload,
    ): Boolean = vaultSessionFence.runIfCurrent(token, _currentVault.value) {
        val sealed = sealPayload(payload)
        val index = VaultListIndex.from(sealed)
        _state.update { it.copy(payload = sealed, listIndex = index) }
    }

    /** 仅停止依赖当前已解锁保险库的任务；用户显式开启的局域网内容传输继续运行。 */
    private fun invalidateVaultSession() {
        remoteUpdateProofs.clear()
        remoteUpdateJob?.cancel()
        remoteUpdateJob = null
        _remoteUpdateStates.value = emptyMap()
        vaultSessionFence.invalidate()

        // 待确认的跨账户导入持有 A 库的明文条目，锁定/切库/删除时立即销毁（H-10）：
        // lock()/switchTo()/deleteVault()/purgeVaultNow() 都走这里，一处即可覆盖。
        _pendingCrossAccountImport.value = null

        val hadLanSync = lanSyncJob != null
        vaultSessionJobs.toList().forEach { it.cancel() }
        vaultSessionJobs.clear()
        lanSyncJob = null
        if (hadLanSync) cancelLanSyncSession()

        cloudDiskOperationJob?.cancel()
        cloudDiskOperationJob = null
        webDavOperationJob?.cancel()
        webDavOperationJob = null
    }

    @Synchronized
    private fun sealPayload(payload: VaultPayload): VaultPayload {
        val replacement = SessionEntryStore()
        val exclusions = payload.autofillExclusions.merge(com.vault.autofill.AutofillExcludePref.snapshot(getApplication(), vaultName()))
        com.vault.autofill.AutofillExcludePref.replace(getApplication(), exclusions, vaultName())
        val redacted = replacement.seal(payload.copy(autofillExclusions = exclusions))
        entryStore?.close()
        entryStore = replacement
        // 条目密封区已重建，任何缓存的派生快照（见 otpDisplaySnapshot）随之失效。
        otpCache.clear()
        otpCacheStep.clear()
        return redacted
    }

    @Synchronized
    private fun materializePayload(payload: VaultPayload): VaultPayload =
        entryStore?.materialize(payload) ?: payload

    @Synchronized
    fun revealEntry(id: String): Entry? {
        val metadata = _state.value.payload?.entries?.firstOrNull { it.id == id } ?: return null
        return entryStore?.reveal(metadata) ?: metadata
    }

    fun loadEntry(id: String, onResult: (Entry?) -> Unit) = viewModelScope.launch {
        val metadata = _state.value.payload?.entries?.firstOrNull { it.id == id }
            ?: run { onResult(null); return@launch }
        val cached = entryStore?.reveal(metadata) ?: metadata
        onResult(cached)
    }

    fun startLanDataTransfer(
        serverUrl: String,
        pin: String,
        onResult: (LanTransferConnectResult) -> Unit = {},
    ) {
        if (_state.value.lanTransferActive || _state.value.lanTransferConnecting) return
        if (lanTransferPinServer != serverUrl) {
            lanTransferPinServer = serverUrl
            lanTransferPinFailures = 0
        }
        _state.update {
            it.copy(
                lanTransferActive = false,
                lanTransferConnecting = true,
                lanTransferDisconnected = false,
                lanTransferError = null,
                lanTransferItems = emptyList(),
            )
        }
        resetLargeTransferWarning()
        restoreCloudSyncState()
        viewModelScope.launch {
            runCatching {
                val transferRepo = repo() ?: error(getApplication<Application>().getString(R.string.viewmodel_current_vault_unavailable))
                check(transferRepo.isPmvE()) { getApplication<Application>().getString(R.string.viewmodel_transfer_device_auth_unsupported) }
                val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
                val transferDevice = VaultDeviceIdentityStore(getApplication(), _currentVault.value.orEmpty()).loadOrCreate()
                try {
                    withContext(Dispatchers.IO) {
                        SyncClient.authenticateDevice(
                            serverUrl,
                            pin,
                            rootSession.identity.vaultId,
                            transferDevice,
                            "read",
                            sessionOp = SyncServerHost.TRANSFER_OP,
                        )
                    }
                } finally {
                    transferDevice.close()
                }
                // 先完成同一 transfer 会话的设备证明和主机确认，再读取传输列表；
                // 不能在确认前用业务请求探测或读取对端数据。
                withContext(Dispatchers.IO) { SyncClient.listTransferOffers(serverUrl, pin) }
                // 保存 transfer 会话供发送/结束流程使用；并用同一通道令牌独立保活。
                // 文件选择器或后台切换会暂停轮询，不能依赖 1s 列表轮询维持连接。
                startLanSyncKeepAlive(serverUrl, pin, intervalMs = 10_000L, transfer = true)
                lanTransferPinFailures = 0
                _state.update { it.copy(lanTransferActive = true, lanTransferConnecting = false) }
                lanTransferCancelledKeys.clear()
                SyncForegroundService.beginTask(
                    getApplication(),
                    LAN_TRANSFER_TASK_ID,
                    BackgroundTaskKind.LAN_TRANSFER,
                    localizeUiTextFor(getApplication(), "文件传输"),
                    localizeUiTextFor(getApplication(), "正在连接对方设备…"),
                )
                startLanTransferPolling(serverUrl, pin)
                onResult(LanTransferConnectResult(connected = true))
            }.onFailure { error ->
                val pinRejected = error is SyncClient.PinValidationException
                if (pinRejected) lanTransferPinFailures += 1
                val remaining = (MAX_LAN_TRANSFER_PIN_ATTEMPTS - lanTransferPinFailures).coerceAtLeast(0)
                val message = when {
                    pinRejected && remaining > 0 -> getApplication<Application>().getString(R.string.viewmodel_lan_pin_attempts, remaining)
                    pinRejected -> getApplication<Application>().getString(R.string.viewmodel_lan_pin_exhausted)
                    else -> getApplication<Application>().getString(R.string.viewmodel_lan_connect_failed)
                }
                SyncClient.forgetSession(serverUrl, pin)
                _state.update {
                    it.copy(
                        lanTransferActive = false,
                        lanTransferConnecting = false,
                        lanTransferDisconnected = pinRejected && remaining == 0,
                        lanTransferError = message,
                    )
                }
                onResult(
                    LanTransferConnectResult(
                        connected = false,
                        pinRejected = pinRejected,
                        remainingPinAttempts = remaining,
                        message = message,
                    ),
                )
            }
        }
    }

    private fun startLanTransferPolling(serverUrl: String, pin: String) {
        lanTransferPollJob?.cancel()
        lanTransferPollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive && _state.value.lanTransferActive && !_state.value.lanTransferDisconnected) {
                runCatching {
                    val knownIds = _state.value.lanTransferItems
                        .filter { it.direction == LanTransferDirection.RECEIVED }
                        .mapTo(mutableSetOf()) { it.remoteId }
                    SyncClient.listTransferOffers(serverUrl, pin)
                        .filterNot { it.id in knownIds }
                        .forEach { offer ->
                            _state.update { state ->
                                val exists = state.lanTransferItems.any {
                                    it.remoteId == offer.id && it.direction == LanTransferDirection.RECEIVED
                                }
                                if (exists) state
                                else state.copy(lanTransferItems = state.lanTransferItems + LanTransferItem(
                                    remoteId = offer.id,
                                    name = offer.name,
                                    mime = offer.mime,
                                    kind = offer.kind,
                                    size = offer.size,
                                    direction = LanTransferDirection.RECEIVED,
                                    status = getApplication<Application>().getString(R.string.viewmodel_status_waiting_receive),
                                    statusCode = LanTransferStatusCode.WAITING_RECEIVE,
                                    path = transferPublicDisplayPath(offer.name),
                                ))
                            }
                            val job = if (offer.kind == "text") {
                                viewModelScope.launch(Dispatchers.IO) {
                                    receiveLanTransferOffer(serverUrl, pin, offer)
                                }
                            } else {
                                viewModelScope.launch(Dispatchers.IO) {
                                    lanTransferDownloadSemaphore.acquire()
                                    try {
                                        receiveLanTransferOffer(serverUrl, pin, offer)
                                    } finally {
                                        lanTransferDownloadSemaphore.release()
                                    }
                                }
                            }
                            lanTransferJobs += job
                            lanTransferJobsById[offer.id] = job
                            job.invokeOnCompletion {
                                lanTransferJobs.remove(job)
                                lanTransferJobsById.remove(offer.id)
                            }
                        }
                }.onFailure { error ->
                    stopLanSyncKeepAlive()
                    _state.update {
                        it.copy(
                            lanTransferActive = false,
                            lanTransferConnecting = false,
                            lanTransferDisconnected = true,
                            lanTransferError = getApplication<Application>().getString(R.string.viewmodel_peer_closed_transfer),
                        )
                    }
                    resetLargeTransferWarning()
                    synchronized(lanTransferJobs) {
                        lanTransferJobs.forEach { it.cancel() }
                        lanTransferJobs.clear()
                    }
                    lanTransferJobsById.values.forEach { it.cancel() }
                    lanTransferJobsById.clear()
                    lanTransferCancelledKeys.clear()
                    SyncClient.abortTransfers()
                    transferByteStates.clear()
                    clearLanTransferTempFiles()
                    SyncForegroundService.interruptTask(getApplication(), LAN_TRANSFER_TASK_ID, localizeUiTextFor(getApplication(), "连接已断开，传输中断"))
                }
                delay(1_000L)
            }
        }
    }

    private suspend fun receiveLanTransferOffer(serverUrl: String, pin: String, offer: SyncClient.TransferOffer) {
        val app = getApplication<Application>()
        val target = File.createTempFile("vault-transfer-receive-", ".part", app.cacheDir)
        _state.update { state ->
            val exists = state.lanTransferItems.any {
                it.remoteId == offer.id && it.direction == LanTransferDirection.RECEIVED
            }
            if (exists) {
                state.copy(lanTransferItems = state.lanTransferItems.map {
                    if (it.remoteId == offer.id && it.direction == LanTransferDirection.RECEIVED) {
                        it.copy(
                            status = getApplication<Application>().getString(R.string.viewmodel_status_receiving),
                            statusCode = LanTransferStatusCode.RECEIVING,
                        )
                    } else it
                })
            } else {
                state.copy(lanTransferItems = state.lanTransferItems + LanTransferItem(
                    remoteId = offer.id,
                    name = offer.name,
                    mime = offer.mime,
                    kind = offer.kind,
                    size = offer.size,
                    direction = LanTransferDirection.RECEIVED,
                    status = getApplication<Application>().getString(R.string.viewmodel_status_receiving),
                    statusCode = LanTransferStatusCode.RECEIVING,
                    path = transferPublicDisplayPath(offer.name),
                ))
            }
        }
        try {
            // runInterruptible 使断连时的协程取消能真正中断阻塞的 HTTP 读取
            runInterruptible {
                SyncClient.downloadTransferOffer(
                    serverUrl,
                    pin,
                    offer,
                    target,
                    onProgress = transferProgressUpdater(offer.id, LanTransferDirection.RECEIVED),
                    onIntegrityRetry = { attempt, maxAttempts ->
                        val canceled = lanTransferCancelledKeys.contains("RECEIVED:${offer.id}") ||
                            _state.value.lanTransferItems.any {
                                it.remoteId == offer.id &&
                                    it.direction == LanTransferDirection.RECEIVED &&
                                    it.statusCode == LanTransferStatusCode.CANCELLED
                            }
                        if (canceled) throw kotlinx.coroutines.CancellationException()
                        updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                            it.copy(status = getApplication<Application>().getString(R.string.viewmodel_transfer_retry, attempt, maxAttempts), statusCode = LanTransferStatusCode.RETRYING, progress = 0f)
                        }
                    },
                )
            }
            updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                it.copy(status = getApplication<Application>().getString(R.string.viewmodel_status_saving), statusCode = LanTransferStatusCode.SAVING, progress = 1f)
            }
            val receivedText = if (offer.kind == "text" && target.length() <= MAX_TRANSFER_CLIPBOARD_BYTES) {
                target.readText(Charsets.UTF_8)
            } else null
            val preview = receivedText?.take(4_096)
                ?: if (offer.kind == "text") readTransferTextPreview(target) else ""
            val published = publishReceivedTransfer(target, offer.name, offer.mime)
            if (lanTransferCancelledKeys.contains("RECEIVED:${offer.id}")) {
                // 下载完成瞬间被取消：保持“已取消”，不发布为已接收。
                updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                    it.copy(status = getApplication<Application>().getString(R.string.viewmodel_status_cancelled), statusCode = LanTransferStatusCode.CANCELLED)
                }
                finishTransferItem(offer.id, LanTransferDirection.RECEIVED)
                return
            }
            updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                it.copy(
                    status = getApplication<Application>().getString(R.string.viewmodel_status_received),
                    statusCode = LanTransferStatusCode.RECEIVED,
                    progress = 1f,
                    path = published.displayPath,
                    localPath = published.localPath,
                    openUri = published.uri.toString(),
                    textPreview = preview,
                )
            }
            finishTransferItem(offer.id, LanTransferDirection.RECEIVED)
            receivedText?.let { value ->
                viewModelScope.launch { copySensitive(app, "接收文本", value) }
            }
            runCatching { SyncClient.acknowledgeTransferOffer(serverUrl, pin, offer.id) }
                .onFailure { error ->
                        _state.update {
                            it.copy(
                                lanTransferError = getApplication<Application>().getString(
                                    R.string.viewmodel_transfer_saved_ack_failed,
                                    error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                                ),
                            )
                        }
                }
        } catch (error: Throwable) {
            if (error is kotlinx.coroutines.CancellationException || error is InterruptedException) {
                val canceled = lanTransferCancelledKeys.contains("RECEIVED:${offer.id}") ||
                    _state.value.lanTransferItems.any {
                        it.remoteId == offer.id &&
                            it.direction == LanTransferDirection.RECEIVED &&
                            it.statusCode == LanTransferStatusCode.CANCELLED
                    }
                updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                    it.copy(
                        status = if (canceled) getApplication<Application>().getString(R.string.viewmodel_status_cancelled)
                        else getApplication<Application>().getString(R.string.viewmodel_transfer_interrupted),
                        statusCode = if (canceled) LanTransferStatusCode.CANCELLED else LanTransferStatusCode.INTERRUPTED,
                    )
                }
                finishTransferItem(offer.id, LanTransferDirection.RECEIVED)
                throw error
            }
            val canceled = lanTransferCancelledKeys.contains("RECEIVED:${offer.id}") ||
                _state.value.lanTransferItems.any {
                    it.remoteId == offer.id &&
                        it.direction == LanTransferDirection.RECEIVED &&
                        it.statusCode == LanTransferStatusCode.CANCELLED
                }
            updateLanTransferItem(offer.id, LanTransferDirection.RECEIVED) {
                it.copy(
                    status = if (canceled) getApplication<Application>().getString(R.string.viewmodel_status_cancelled)
                    else transferUserMessage(error, sending = false),
                    statusCode = if (canceled) LanTransferStatusCode.CANCELLED else LanTransferStatusCode.FAILED,
                )
            }
            finishTransferItem(offer.id, LanTransferDirection.RECEIVED)
        } finally {
            target.delete()
        }
    }

    fun sendLanTransferText(text: String) {
        val value = text.trim()
        if (value.isEmpty()) return
        val session = lanSyncSession ?: return
        val pendingId = java.util.UUID.randomUUID().toString()
        val job = viewModelScope.launch(Dispatchers.IO) {
            val file = File.createTempFile("vault-transfer-text-", ".txt", getApplication<Application>().cacheDir)
            try {
                file.writeText(value, Charsets.UTF_8)
                lanTransferTempFiles += file
                sendLanTransferFileInternal(
                    session,
                    file.inputStream(),
                    file.length(),
                    "message_${java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.getDefault()).format(java.util.Date())}.txt",
                    "text/plain; charset=utf-8",
                    "text",
                    value.take(4_096),
                    localPath = file.absolutePath,
                    pendingId = pendingId,
                )
            } catch (error: Throwable) {
                file.delete()
                lanTransferTempFiles.remove(file)
                val canceled = _state.value.lanTransferItems.any {
                    it.remoteId == pendingId && it.direction == LanTransferDirection.SENT && it.statusCode == LanTransferStatusCode.CANCELLED
                }
                if (!canceled && error !is kotlinx.coroutines.CancellationException) {
                    _state.update {
                        it.copy(
                            lanTransferError = getApplication<Application>().getString(
                                R.string.viewmodel_send_text_failed,
                                error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                            ),
                        )
                    }
                }
            }
        }
        lanTransferJobs += job
        lanTransferJobsById[pendingId] = job
        job.invokeOnCompletion {
            lanTransferJobs.remove(job)
            lanTransferJobsById.remove(pendingId)
        }
    }

    fun sendLanTransferFile(uri: Uri) {
        val session = lanSyncSession ?: return
        if (pendingLargeTransferUri != null) return
        val pendingId = java.util.UUID.randomUUID().toString()
        val job = viewModelScope.launch(Dispatchers.IO) {
            val resolver = getApplication<Application>().contentResolver
            val knownSize = queryOpenableSize(resolver, uri)
            // 大文件单次会话只提示一次；确认后放行，不限制传输（仅保留 10 TiB 溢出护栏）。
            if (knownSize != null && knownSize > LAN_TRANSFER_WARN_BYTES && !largeTransferWarned) {
                pendingLargeTransferUri = uri
                _pendingLargeTransfer.value = uri
                return@launch
            }
            sendLanTransferFileCore(session, resolver, uri, knownSize, pendingId)
        }
        lanTransferJobs += job
        lanTransferJobsById[pendingId] = job
        job.invokeOnCompletion {
            lanTransferJobs.remove(job)
            lanTransferJobsById.remove(pendingId)
        }
    }

    /**
     * 剪贴板富内容发送（“发送图片/发送文件”菜单）。
     *
     * 按 Android 官方 Copy and paste 建议：剪贴板中的 content:// URI 属于临时授权，
     * 源应用关闭或授权撤销后可能失效，因此先在后台流式复制到本应用私有缓存，
     * 再与「发送文件」共用同一传输通道，避免读取失败被静默吞掉。
     */
    /**
     * 富内容统一发送入口（剪贴板/输入法粘贴等）。
     *
     * 剪贴板中的 content:// URI 属于临时授权，源应用关闭或授权撤销后可能失效，
     * 因此先流式复制到本应用私有缓存，再与「发送文件」共用同一传输核心；
     * 发送、取消、失败、连接中断后都会清理缓存文件。
     *
     * @param source 仅用于区分来源（paste / file-picker 等），当前只影响临时文件命名。
     */
    fun enqueueLanTransferContent(uri: Uri, host: Boolean, source: String = "paste") {
        val app = getApplication<Application>()
        val ready = if (host) {
            val h = lanHost
            h != null && h.status.value.op == SyncServerHost.TRANSFER_OP && h.status.value.paired
        } else {
            lanSyncSession != null
        }
        if (!ready) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_not_connected))
            return
        }
        if (pendingLargeTransferUri != null || pendingCachedTransfer != null) return
        val pendingId = java.util.UUID.randomUUID().toString()
        val job = viewModelScope.launch(Dispatchers.IO) {
            val resolver = app.contentResolver
            val tag = source.filter { it.isLetterOrDigit() }.take(12).ifBlank { "paste" }
            val file = File.createTempFile("vault-$tag-", ".part", app.cacheDir)
            try {
                val displayName = queryOpenableName(resolver, uri)
                val mime = runCatching { resolver.getType(uri) }.getOrNull() ?: "application/octet-stream"
                resolver.openInputStream(uri)?.use { input ->
                    file.outputStream().buffered().use { output ->
                        // 流式复制：4 MiB 缓冲，避免整文件读入内存（100 GB 级文件也只占少量内存）。
                        val buffer = ByteArray(4 * 1024 * 1024)
                        var total = 0L
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= MAX_LAN_TRANSFER_FILE_BYTES) {
                                getApplication<Application>().getString(R.string.viewmodel_transfer_size_limit)
                            }
                            output.write(buffer, 0, count)
                        }
                    }
                } ?: error(getApplication<Application>().getString(R.string.viewmodel_file_open_failed))
                // 大文件确认：与文件选择器同一规则，超过 10 GiB 且本会话未提示过时先确认。
                // 无法预先得知大小的 URI 在此已落入缓存，按实际大小判断。
                if (file.length() > LAN_TRANSFER_WARN_BYTES && !largeTransferWarned) {
                    pendingCachedTransfer = PendingCachedTransfer(file, displayName, mime, host, pendingId)
                    _pendingLargeTransfer.value = Uri.fromFile(file)
                    return@launch
                }
                dispatchCachedLanTransferFile(file, displayName, mime, host)
            } catch (error: Throwable) {
                file.delete()
                if (error is kotlinx.coroutines.CancellationException) throw error
                val message = error.message.orEmpty()
                emitError(if (message.contains("10 TiB")) message else getApplication<Application>().getString(R.string.viewmodel_clipboard_read_failed))
            }
        }
        lanTransferJobs += job
        lanTransferJobsById[pendingId] = job
        job.invokeOnCompletion {
            lanTransferJobs.remove(job)
            lanTransferJobsById.remove(pendingId)
        }
    }

    /** 已复制到私有缓存的富内容：按连接角色走现有发送核心（发送完成/失败后由发送侧删除缓存）。 */
    private fun dispatchCachedLanTransferFile(file: File, name: String, mime: String, host: Boolean) {
        if (host) {
            hostQueueTransferLocalFile(file, name, mime)
        } else {
            sendLanTransferLocalFile(file, name, mime)
        }
    }

    private fun queryOpenableName(resolver: android.content.ContentResolver, uri: Uri): String {
        var name = "file_${System.currentTimeMillis()}"
        runCatching {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    cursor.getString(0)?.take(255)?.let { name = it }
                }
            }
        }
        return name
    }

    /** 连接方：直接发送已复制到私有缓存的富内容（发送完成后删除缓存文件；历史记录不引用已删除的临时路径）。 */
    private fun sendLanTransferLocalFile(file: File, name: String, mime: String) {
        val session = lanSyncSession ?: run { file.delete(); return }
        val pendingId = java.util.UUID.randomUUID().toString()
        val job = viewModelScope.launch(Dispatchers.IO) {
            try {
                sendLanTransferFileInternal(
                    session,
                    file.inputStream(),
                    file.length(),
                    name,
                    mime,
                    "file",
                    "",
                    pendingId = pendingId,
                )
            } finally {
                file.delete()
            }
        }
        lanTransferJobs += job
        lanTransferJobsById[pendingId] = job
        job.invokeOnCompletion {
            lanTransferJobs.remove(job)
            lanTransferJobsById.remove(pendingId)
        }
    }

    /** 传输站：直接排队已复制到私有缓存的剪贴板内容（temporary 队列发送/取消后自动删除缓存文件）。 */
    private fun hostQueueTransferLocalFile(file: File, name: String, mime: String) {
        val host = lanHost ?: run { file.delete(); return }
        if (host.status.value.op != SyncServerHost.TRANSFER_OP || !host.status.value.paired) {
            file.delete()
            emitError(getApplication<Application>().getString(R.string.viewmodel_not_connected))
            return
        }
        val job = viewModelScope.launch(Dispatchers.IO) {
            try {
                host.queueTransferFile(file, name, mime, "file", temporary = true)
            } catch (error: Throwable) {
                file.delete()
                emitError(getApplication<Application>().getString(R.string.viewmodel_send_file_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            }
        }
        hostSendJobs += job
        job.invokeOnCompletion { hostSendJobs.remove(job) }
    }

    /** 大文件放行确认：继续则本会话不再提示；取消则丢弃本次选择。 */
    fun confirmLargeTransferSend(confirm: Boolean) {
        val uri = pendingLargeTransferUri
        val cached = pendingCachedTransfer
        if (uri == null && cached == null) return
        pendingLargeTransferUri = null
        pendingCachedTransfer = null
        _pendingLargeTransfer.value = null
        if (!confirm) {
            cached?.file?.delete()
            return
        }
        largeTransferWarned = true
        if (cached != null) {
            dispatchCachedLanTransferFile(cached.file, cached.name, cached.mime, cached.host)
        } else if (uri != null) {
            sendLanTransferFile(uri)
        }
    }

    private suspend fun sendLanTransferFileCore(
        session: Pair<String, String>,
        resolver: android.content.ContentResolver,
        uri: Uri,
        knownSize: Long?,
        pendingId: String,
    ) {
            var displayName = "file_${System.currentTimeMillis()}"
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) displayName = cursor.getString(0)?.take(255) ?: displayName
            }
            if (knownSize != null && knownSize >= 0) {
                try {
                    resolver.openInputStream(uri)?.let { input ->
                        sendLanTransferFileInternal(
                            session,
                            input,
                            knownSize,
                            displayName,
                            resolver.getType(uri) ?: "application/octet-stream",
                            "file",
                            "",
                            openUri = uri.toString(),
                            pendingId = pendingId,
                        )
                    } ?: error(getApplication<Application>().getString(R.string.viewmodel_file_open_failed))
                } catch (error: Throwable) {
                    val canceled = _state.value.lanTransferItems.any {
                        it.remoteId == pendingId && it.direction == LanTransferDirection.SENT && it.statusCode == LanTransferStatusCode.CANCELLED
                    }
                    if (!canceled && error !is kotlinx.coroutines.CancellationException) {
                        _state.update {
                            it.copy(
                                lanTransferError = getApplication<Application>().getString(
                                    R.string.viewmodel_send_file_failed,
                                    error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                                ),
                            )
                        }
                    }
                }
            } else {
                val temp = File.createTempFile("vault-transfer-file-", ".tmp", getApplication<Application>().cacheDir)
                try {
                    resolver.openInputStream(uri)?.use { input ->
                        temp.outputStream().buffered().use { output ->
                            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                            var total = 0L
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                total += count
                                require(total <= MAX_LAN_TRANSFER_FILE_BYTES) {
                                    getApplication<Application>().getString(R.string.viewmodel_transfer_size_limit)
                                }
                                output.write(buffer, 0, count)
                            }
                        }
                    } ?: error(getApplication<Application>().getString(R.string.viewmodel_file_open_failed))
                    sendLanTransferFileInternal(
                        session,
                        temp.inputStream(),
                        temp.length(),
                        displayName,
                        resolver.getType(uri) ?: "application/octet-stream",
                        "file",
                        "",
                        openUri = uri.toString(),
                        pendingId = pendingId,
                    )
                } catch (error: Throwable) {
                    _state.update {
                        it.copy(
                            lanTransferError = getApplication<Application>().getString(
                                R.string.viewmodel_send_file_failed,
                                error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                            ),
                        )
                    }
                } finally {
                    temp.delete()
                }
            }
    }

    private fun queryOpenableSize(resolver: android.content.ContentResolver, uri: Uri): Long? = try {
        resolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0) else -1L
        } ?: -1L
    } catch (_: Throwable) {
        -1L
    }.let { if (it < 0) null else it }

    private fun resetLargeTransferWarning() {
        largeTransferWarned = false
        pendingLargeTransferUri = null
        pendingCachedTransfer?.file?.delete()
        pendingCachedTransfer = null
        _pendingLargeTransfer.value = null
    }

    private suspend fun sendLanTransferFileInternal(
        session: Pair<String, String>,
        input: InputStream,
        size: Long,
        name: String,
        mime: String,
        kind: String,
        preview: String,
        localPath: String = "",
        openUri: String = "",
        pendingId: String,
    ) {
        val retrySource = File.createTempFile("vault-transfer-retry-", ".part", getApplication<Application>().cacheDir)
        _state.update {
            it.copy(lanTransferItems = it.lanTransferItems + LanTransferItem(
                remoteId = pendingId,
                name = name,
                mime = mime,
                kind = kind,
                size = size,
                direction = LanTransferDirection.SENT,
                status = getApplication<Application>().getString(R.string.viewmodel_status_sending),
                statusCode = LanTransferStatusCode.SENDING,
                localPath = localPath,
                openUri = openUri,
                textPreview = preview,
            ))
        }
        runCatching {
            input.use { source -> retrySource.outputStream().buffered().use(source::copyTo) }
            if (retrySource.length() != size) {
                throw SyncClient.IntegrityException(
                    getApplication<Application>().getString(R.string.viewmodel_transfer_size_mismatch),
                )
            }
            runInterruptible {
                SyncClient.uploadTransferFileWithRetry(
                    session.first,
                    session.second,
                    inputFactory = { retrySource.inputStream() },
                    size = size,
                    name = name,
                    mime = mime,
                    kind = kind,
                    onProgress = transferProgressUpdater(pendingId, LanTransferDirection.SENT),
                    onIntegrityRetry = { attempt, maxAttempts ->
                        val canceled = lanTransferCancelledKeys.contains("SENT:$pendingId") ||
                            _state.value.lanTransferItems.any {
                                it.remoteId == pendingId &&
                                    it.direction == LanTransferDirection.SENT &&
                    it.statusCode == LanTransferStatusCode.CANCELLED
                            }
                        if (canceled) throw kotlinx.coroutines.CancellationException()
                        updateLanTransferItem(pendingId, LanTransferDirection.SENT) {
                            it.copy(status = getApplication<Application>().getString(R.string.viewmodel_transfer_retry, attempt, maxAttempts), statusCode = LanTransferStatusCode.RETRYING, progress = 0f)
                        }
                    },
                    transferKey = pendingId,
                )
            }
        }
            .onSuccess { offer ->
                if (lanTransferCancelledKeys.contains("SENT:$pendingId")) {
                    // 发送完成瞬间被取消：保持“已取消”，不迁移进度、不发布为已发送。
                    updateLanTransferItem(pendingId, LanTransferDirection.SENT) {
                            it.copy(status = getApplication<Application>().getString(R.string.viewmodel_status_cancelled), statusCode = LanTransferStatusCode.CANCELLED)
                    }
                    finishTransferItem(pendingId, LanTransferDirection.SENT)
                    return@onSuccess
                }
                // 迁移累计 key：pendingId → offer.id，标记完成（贡献满进度）
                transferByteStates["SENT:$pendingId"]?.let { (_, total) ->
                    transferByteStates["SENT:${offer.id}"] = total to total
                }
                transferByteStates.remove("SENT:$pendingId")
                updateLanTransferItem(pendingId, LanTransferDirection.SENT) {
                    it.copy(remoteId = offer.id, status = getApplication<Application>().getString(R.string.viewmodel_status_sent), statusCode = LanTransferStatusCode.SENT, progress = 1f)
                }
                finishTransferItem(offer.id, LanTransferDirection.SENT)
            }
            .onFailure { error ->
                finishTransferItem(pendingId, LanTransferDirection.SENT)
                val interrupted = error is kotlinx.coroutines.CancellationException || error is InterruptedException
                val canceled = lanTransferCancelledKeys.contains("SENT:$pendingId") ||
                    _state.value.lanTransferItems.any {
                        it.remoteId == pendingId &&
                            it.direction == LanTransferDirection.SENT &&
                                it.statusCode == LanTransferStatusCode.CANCELLED
                    }
                updateLanTransferItem(pendingId, LanTransferDirection.SENT) {
                    it.copy(
                        status = when {
                            canceled -> getApplication<Application>().getString(R.string.viewmodel_status_cancelled)
                            interrupted -> getApplication<Application>().getString(R.string.viewmodel_transfer_interrupted)
                            else -> transferUserMessage(error, sending = true)
                        },
                        statusCode = when {
                            canceled -> LanTransferStatusCode.CANCELLED
                            interrupted -> LanTransferStatusCode.INTERRUPTED
                            else -> LanTransferStatusCode.FAILED
                        },
                    )
                }
            }
        retrySource.delete()
    }

    fun endLanDataTransfer() {
        if (!_state.value.lanTransferActive) return
        _state.update { it.copy(lanTransferActive = false) }
        resetLargeTransferWarning()
        val session = lanSyncSession
        lanTransferPollJob?.cancel()
        lanTransferPollJob = null
        synchronized(lanTransferJobs) {
            lanTransferJobs.forEach { it.cancel() }
            lanTransferJobs.clear()
        }
        lanTransferJobsById.values.forEach { it.cancel() }
        lanTransferJobsById.clear()
        lanTransferCancelledKeys.clear()
        SyncClient.abortTransfers()
        transferByteStates.clear()
        stopLanSyncKeepAlive(clearSession = false)
        SyncForegroundService.abandonTask(getApplication(), LAN_TRANSFER_TASK_ID)
        _state.update {
            it.copy(
                lanTransferConnecting = false,
                lanTransferDisconnected = false,
                lanTransferError = null,
            )
        }
        clearLanTransferTempFiles()
        if (session != null) viewModelScope.launch(Dispatchers.IO) {
            runCatching { SyncClient.endTransfer(session.first, session.second) }
            SyncClient.forgetSession(session.first, session.second)
        }
    }

    /** 单条传输取消（连接方）：立即终止正在接收/发送的指定条目，并保持“已取消”记录。 */
    fun cancelLanTransferItem(id: String, direction: LanTransferDirection) {
        if (_state.value.lanTransferItems.none {
                it.remoteId == id && it.direction == direction
            }
        ) return
        val key = "$direction:$id"
        lanTransferCancelledKeys += key
        // 先标记已取消，再中断连接：任务异常/收尾路径据此保留“已取消”，
        // 不会被误判为传输失败，也不会把已取消条目的进度补回总进度。
        updateLanTransferItem(id, direction) {
            it.copy(status = getApplication<Application>().getString(R.string.viewmodel_status_cancelled), statusCode = LanTransferStatusCode.CANCELLED, progress = 0f)
        }
        // 先关闭底层连接，再取消协程：阻塞读写在连接断开后立刻抛错退出。
        SyncClient.abortTransfer(id)
        lanTransferJobsById.remove(id)?.cancel()
        transferByteStates.remove(key)
        if (transferByteStates.isEmpty()) {
            SyncForegroundService.abandonTask(getApplication(), LAN_TRANSFER_TASK_ID)
        } else {
            pushTransferNotification()
        }
    }

    /** 单条传输取消（传输站主机）：终止等待接收/发送中/接收中的指定条目。 */
    fun cancelLanHostTransfer(id: String) {
        lanHost?.cancelTransferItem(id)
    }

    // ── 建立传输站（本机作为主机，供其他安卓/PC 连入） ──────────────────

    fun startLanHost() {
        val s = _state.value
        if (s.phase != Phase.UNLOCKED) return
        if (lanHost?.status?.value?.running == true) return
        if (s.syncRunning || s.lanTransferActive || s.lanTransferConnecting) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_transfer_busy))
            return
        }
        val sessionToken = captureVaultSession()
        val completed = java.util.concurrent.atomic.AtomicBoolean(false)
        val host = SyncServerHost(getApplication(), _currentVault.value.orEmpty()).apply {
            deviceAuthProvider = object : SyncServerHost.DeviceAuthProvider {
                private val registry by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
                    buildDeviceAuthRegistry()
                }

                override fun registry(): PmvSyncAuthorization.AuthorizationRegistry? = registry

                override fun enrollExportDevice(deviceId: UUID, devicePublicKey: ByteArray): Boolean {
                    val root = _state.value.credential.sessionRootKey() ?: return false
                    val r = repo() ?: return false
                    return runCatching {
                        val authorization = root.withRootKey(root.identity) { key ->
                            r.transientExportAuthorization(key, deviceId, devicePublicKey)
                        }
                        registry?.install(authorization, transient = true)
                        true
                    }.getOrDefault(false)
                }

                override fun enrollSyncDevice(deviceId: UUID, devicePublicKey: ByteArray): Boolean {
                    val root = _state.value.credential.sessionRootKey() ?: return false
                    val r = repo() ?: return false
                    return runCatching {
                        val authorization = root.withRootKey(root.identity) { key ->
                            r.transientSyncAuthorization(key, deviceId, devicePublicKey)
                        }
                        registry?.install(authorization, transient = true)
                        true
                    }.getOrDefault(false)
                }
            }
            vaultHandler = SyncServerHost.VaultHandler { file ->
                try {
                    updateLanSyncProgress(LAN_HOST_TASK_ID, localizeUiTextFor(getApplication(), "正在接收对方同步数据…"))
                    val before = _state.value.payload?.entries?.size ?: 0
                    val response = handleHostVaultPut(file)
                    val report = hostSyncResultFromResponse(
                        response, before, _state.value.payload?.entries?.size ?: before, file.length(),
                    )
                    vaultSessionFence.runIfCurrent(sessionToken, _currentVault.value) {
                        _syncResult.value = report
                        completed.set(true)
                        SyncForegroundService.succeedTask(getApplication(), LAN_HOST_TASK_ID,
                            getApplication<Application>().getString(R.string.viewmodel_lan_sync_completed))
                    }
                    response
                } catch (error: SyncServerHost.HostError) {
                    emitError(lanHostReceiveErrorMessage(error))
                    throw error
                }
            }
            onSyncStarted = {
                completed.set(false)
                _syncResult.value = null
                // 传输站侧同步实际开始：无论是否经过确认弹窗，都置位同步状态驱动页面展示。
                _state.update { it.copy(syncRunning = true) }
                updateLanSyncProgress(LAN_HOST_TASK_ID, localizeUiTextFor(getApplication(), "正在与对方同步…"))
            }
            onVaultSendProgress = { transferred, total ->
                updateLanSyncProgress(LAN_HOST_TASK_ID, localizeUiTextFor(getApplication(), "正在发送保险库数据…"), transferred, total)
            }
            onVaultReceiveProgress = { transferred, total ->
                updateLanSyncProgress(LAN_HOST_TASK_ID, localizeUiTextFor(getApplication(), "正在接收对方同步数据…"), transferred, total)
            }
            onSyncCompleted = {
                // 双向同步完成（传输站合并后断开连接）。
                viewModelScope.launch {
                    if (!isVaultSessionCurrent(sessionToken)) return@launch
                    stopLanHost()
                    emitInfo(getApplication<Application>().getString(R.string.viewmodel_lan_sync_completed))
                }
            }
            transferSink = SyncServerHost.TransferSink { file, name, mime, kind ->
                publishReceivedTransfer(file, name, mime).displayPath
            }
            onStopped = { reason ->
                _lanHostExportPending.value = false
                _lanHostExportPendingDevice.value = ""
                _lanHostExportApprovalToken.value = ""
                _lanHostSyncPending.value = false
                _lanHostSyncPendingDevice.value = ""
                _lanHostSyncApprovalToken.value = ""
                _lanHostTransferPending.value = false
                _lanHostTransferPendingDevice.value = ""
                _lanHostTransferApprovalToken.value = ""
                // 传输站停止（超时/对方断开/被取消等）后立即复位同步状态，
                // 避免 UI 一直停留在“正在与对方同步”。
                _state.update { it.copy(syncRunning = false) }
                clearLanSyncProgress()
                SyncForegroundService.abandonTask(getApplication(), LAN_HOST_TASK_ID)
                if (reason != null && !completed.get()) {
                    emitInfo(
                        if (reason == "等待连接超时") getApplication<Application>().getString(R.string.viewmodel_host_wait_timeout)
                        else getApplication<Application>().getString(R.string.viewmodel_host_stopped, reason),
                    )
                }
            }
            onSyncApprovalPending = { token, deviceId ->
                _lanHostSyncApprovalToken.value = token
                _lanHostSyncPendingDevice.value = deviceId.toString()
                _lanHostSyncPending.value = true
            }
            onExportApprovalPending = { token, deviceId ->
                _lanHostExportApprovalToken.value = token
                _lanHostExportPendingDevice.value = deviceId?.toString().orEmpty()
                _lanHostExportPending.value = true
            }
            onTransferApprovalPending = { token, deviceId ->
                _lanHostTransferApprovalToken.value = token
                _lanHostTransferPendingDevice.value = deviceId.toString()
                _lanHostTransferPending.value = true
            }
            onSyncRejected = { reason ->
                _lanHostSyncPending.value = false
                _lanHostSyncPendingDevice.value = ""
                emitError(
                    if (reason.contains("保险库 ID")) {
                        getApplication<Application>().getString(R.string.viewmodel_sync_rejected_same_vault, reason)
                    } else {
                        getApplication<Application>().getString(R.string.viewmodel_sync_rejected_generic, reason)
                    },
                )
            }
        }
        lanHost = host
        viewModelScope.launch {
            var lastPairSeq = 0
            host.status.collect { status ->
                _lanHostState.value = status
                if (status.pairSeq != lastPairSeq) {
                    lastPairSeq = status.pairSeq
                    // 新设备配对成功：通知 UI 自动进入传输页
                    _lanHostConnectSignal.value += 1
                }
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val (url, pin) = host.start()
                SyncForegroundService.beginTask(
                    getApplication(),
                    LAN_HOST_TASK_ID,
                    BackgroundTaskKind.LAN_TRANSFER,
                    localizeUiTextFor(getApplication(), "传输站"),
                    localizeUiTextFor(getApplication(), "传输站已开启，等待其他设备连接"),
                )
            } catch (error: Throwable) {
                lanHost = null
                val message = if (error is java.net.BindException) {
                    getApplication<Application>().getString(R.string.viewmodel_host_port_busy, SyncServerHost.PORT)
                } else {
                    getApplication<Application>().getString(
                        R.string.viewmodel_host_start_failed,
                        error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                    )
                }
                emitError(message)
            }
        }
    }

    /**
     * 主机侧「断开连接」：断开当前设备但传输站继续监听，可再接新设备。
     *
     * 与 stopLanHost 的区别是不拆传输站——用户只是要断开这一台，不是要关站。
     * 页面保留在传输视图，已完成的记录仍可查看。
     */
    fun disconnectLanHostPeer() {
        val host = lanHost ?: return
        host.disconnectPeer()
        _state.update { it.copy(syncRunning = false) }
        clearLanSyncProgress()
        synchronized(lanTransferJobs) {
            lanTransferJobs.forEach { it.cancel() }
            lanTransferJobs.clear()
        }
        lanTransferJobsById.values.forEach { it.cancel() }
        lanTransferJobsById.clear()
        lanTransferPollJob?.cancel()
        lanTransferPollJob = null
    }

    fun stopLanHost() {
        val host = lanHost ?: return
        lanHost = null
        host.stop()
        SyncForegroundService.abandonTask(getApplication(), LAN_HOST_TASK_ID)
        _lanHostState.value = SyncServerHost.HostStatus()
        _lanHostExportPending.value = false
        _lanHostExportPendingDevice.value = ""
        _lanHostExportApprovalToken.value = ""
        _lanHostSyncPending.value = false
        _lanHostSyncPendingDevice.value = ""
        _lanHostSyncApprovalToken.value = ""
        _lanHostTransferPending.value = false
        _lanHostTransferPendingDevice.value = ""
        _lanHostTransferApprovalToken.value = ""
        _state.update { it.copy(syncRunning = false) }
        clearLanSyncProgress()
    }

    /** 允许当前「导出」通道客户端拉取本机保险库。 */
    fun approveLanHostExport(sessionToken: String) {
        val host = lanHost ?: return
        if (!host.approveExport(sessionToken)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_transfer_device_auth_failed))
            return
        }
        _lanHostExportPending.value = false
        _lanHostExportPendingDevice.value = ""
        _lanHostExportApprovalToken.value = ""
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_send_allowed))
    }

    /** 拒绝当前「导出」请求并断开连接。 */
    fun rejectLanHostExport(sessionToken: String) {
        lanHost?.rejectExport(sessionToken)
        _lanHostExportPending.value = false
        _lanHostExportPendingDevice.value = ""
        _lanHostExportApprovalToken.value = ""
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_request_rejected))
    }

    /** 允许当前「同步」通道客户端读写本机保险库。 */
    fun approveLanHostSync(sessionToken: String) {
        val host = lanHost ?: return
        if (!host.approveSync(sessionToken)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_transfer_device_auth_failed))
            return
        }
        _lanHostSyncPending.value = false
        _lanHostSyncPendingDevice.value = ""
        _lanHostSyncApprovalToken.value = ""
        // 传输站侧同步开始：置位同步状态并驱动局域网同步页的状态/进度展示。
        _state.update { it.copy(syncRunning = true) }
        updateLanSyncProgress(LAN_HOST_TASK_ID, localizeUiTextFor(getApplication(), "正在与对方同步…"))
        emitInfo("已允许本次同步")
    }

    /** 拒绝当前「同步」请求并断开连接。 */
    fun rejectLanHostSync(sessionToken: String) {
        lanHost?.rejectSync(sessionToken)
        _lanHostSyncPending.value = false
        _lanHostSyncPendingDevice.value = ""
        _lanHostSyncApprovalToken.value = ""
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_sync_rejected))
    }

    fun approveLanHostTransfer(sessionToken: String) {
        val host = lanHost ?: return
        if (host.approveTransfer(sessionToken)) {
            _lanHostTransferPending.value = false
            _lanHostTransferPendingDevice.value = ""
            _lanHostTransferApprovalToken.value = ""
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_transfer_device_auth_approved))
        } else {
            emitError(getApplication<Application>().getString(R.string.viewmodel_transfer_device_auth_failed))
        }
    }

    fun rejectLanHostTransfer(sessionToken: String) {
        lanHost?.rejectTransfer(sessionToken)
        _lanHostTransferPending.value = false
        _lanHostTransferPendingDevice.value = ""
        _lanHostTransferApprovalToken.value = ""
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_request_rejected))
    }

    /** 主机（传输站）向已连接的「文件互传」客户端发送文本。 */
    fun hostQueueTransferText(text: String) {
        val host = lanHost ?: return
        if (host.status.value.op != SyncServerHost.TRANSFER_OP || !host.status.value.paired) return
        runCatching { host.queueTransferText(text) }
            .onFailure { emitError(getApplication<Application>().getString(R.string.viewmodel_send_text_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error))) }
    }

    /** 主机（传输站）向已连接的「文件互传」客户端发送文件（内容 URI → 临时文件 → 排队）。 */
    fun hostQueueTransferFile(uri: Uri) {
        val host = lanHost ?: return
        if (host.status.value.op != SyncServerHost.TRANSFER_OP || !host.status.value.paired) return
        val job = viewModelScope.launch(Dispatchers.IO) {
            val resolver = getApplication<Application>().contentResolver
            val temp = File.createTempFile("vault-host-send-", ".tmp", getApplication<Application>().cacheDir)
            try {
                var displayName = "file_${System.currentTimeMillis()}"
                resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) displayName = cursor.getString(0)?.take(255) ?: displayName
                }
                resolver.openInputStream(uri)?.use { input ->
                    temp.outputStream().buffered().use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        var total = 0L
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= SyncServerHost.MAX_TRANSFER_BYTES) {
                                getApplication<Application>().getString(R.string.viewmodel_transfer_size_limit)
                            }
                            output.write(buffer, 0, count)
                        }
                    }
                } ?: error(getApplication<Application>().getString(R.string.viewmodel_file_open_failed))
                host.queueTransferFile(
                    temp,
                    displayName,
                    resolver.getType(uri) ?: "application/octet-stream",
                    "file",
                    temporary = true,
                )
            } catch (error: Throwable) {
                temp.delete()
                emitError(getApplication<Application>().getString(R.string.viewmodel_send_file_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            }
        }
        hostSendJobs += job
        job.invokeOnCompletion { hostSendJobs.remove(job) }
    }

    // ── 局域网导入（接收端流程） ──────────────────────────

    /** 接收端：从传输站二维码启动局域网导入（只认当前传输站二维码）。 */
    fun lanImportFromQr(raw: String) {
        // 传输站二维码（https://…?ticket=…&pin=…）：走导出通道，
        // 等待主机批准后整库下载并注册为新账户。不再接受旧 vault-import:// 专用导入码。
        val station = com.vault.ui.scan.QrPayloadPolicy.parseSync(raw)
        if (station != null && station.pin != null) {
            lanImportFromStation(station.baseUrl, station.pin)
            return
        }
        emitError(getApplication<Application>().getString(R.string.viewmodel_qr_invalid))
    }

    /** 局域网导入（整库导出）：扫描传输站二维码后走导出通道，等待主机批准并整库下载，注册为新账户。 */
    fun lanImportFromStation(
        serverUrl: String,
        pin: String,
        onWaitingForExport: () -> Unit = {},
        onResult: (Boolean, String?) -> Unit = { _, _ -> },
    ) {
        if (pin.length != 6 || !pin.all(Char::isDigit)) {
            onResult(false, getApplication<Application>().getString(R.string.viewmodel_lan_import_pin_invalid))
            return
        }
        cancelLanImport()
        lanImportExportAttempts = 0
        _lanImportState.value = LanImportState.WaitingForExport
        lanImportJob = viewModelScope.launch {
            val cache = File(getApplication<Application>().cacheDir, "vault-export-${System.currentTimeMillis()}.pmv")
            try {
                var importedName: String? = null
                var sourceVaultName: String? = null
                withContext(Dispatchers.IO) {
                    // 下载 + 完整性校验：一次校验失败允许用户重新申请下载（最多 3 次）。
                    while (true) {
                        lanImportExportAttempts++
                        try {
                            SyncClient.downloadVaultExport(
                                serverUrl,
                                pin,
                                cache,
                                onWaitingForExport = {
                                    _lanImportState.value = LanImportState.WaitingForExport
                                    onWaitingForExport()
                                },
                                onProgress = { transferred, total ->
                                    _lanImportState.value = LanImportState.Downloading(transferred, total)
                                },
                                onVerifying = { _lanImportState.value = LanImportState.Checking },
                                onVaultName = { sourceVaultName = it },
                            )
                            break
                        } catch (error: SyncClient.ExportIntegrityException) {
                            cache.delete()
                            if (lanImportExportAttempts >= MAX_LAN_IMPORT_EXPORT_ATTEMPTS) throw error
                            val retry = suspendCancellableCoroutine<Boolean> { cont ->
                                lanImportRetryContinuation = cont
                                _lanImportIntegrityRetry.value = LanImportIntegrityRetry(
                                    lanImportExportAttempts,
                                    MAX_LAN_IMPORT_EXPORT_ATTEMPTS,
                                )
                            }
                            lanImportRetryContinuation = null
                            _lanImportIntegrityRetry.value = null
                            if (!retry) throw SyncClient.SyncException(
                                getApplication<Application>().getString(R.string.viewmodel_lan_import_cancelled),
                            )
                        }
                    }
                    val existing = registry.list()
                    val trashed = registry.listTrashed().keys
                    val incomingIdentity = LanImportPolicy.readPublicIdentity(cache)
                    val sameVaultExisting = incomingIdentity?.let { identity ->
                        (existing + trashed).firstOrNull { candidate ->
                            LanImportPolicy.readPublicIdentity(registry.fileFor(candidate))?.matches(identity) == true
                        }
                    }
                    val resolution = LanImportPolicy.resolveName(
                        sourceName = sourceVaultName,
                        existingNames = existing.toSet(),
                        trashedNames = trashed,
                        sameVaultExistingName = sameVaultExisting,
                    )
                    if (resolution.conflictKind != null) {
                        _lanImportState.value = null
                        val proceed = suspendCancellableCoroutine<Boolean> { continuation ->
                            lanImportConflictContinuation = continuation
                            _lanImportConflict.value = LanImportConflict(
                                sourceName = sourceVaultName?.trim().orEmpty().ifBlank { resolution.targetName },
                                existingName = requireNotNull(resolution.conflictingName),
                                suggestedName = resolution.targetName,
                                sameVault = resolution.conflictKind == LanImportConflictKind.SAME_VAULT,
                            )
                        }
                        lanImportConflictContinuation = null
                        _lanImportConflict.value = null
                        if (!proceed) throw kotlinx.coroutines.CancellationException(
                            getApplication<Application>().getString(R.string.viewmodel_lan_import_cancelled),
                        )
                    }
                    _lanImportState.value = LanImportState.Saving
                    val name = resolution.targetName
                    if (!registry.isValidName(name)) throw IllegalStateException(
                        getApplication<Application>().getString(R.string.viewmodel_lan_import_name_invalid),
                    )
                    val repo = VaultRepository(getApplication(), registry, name)
                    repo.importFromFile(cache)
                    registry.setCurrent(name)
                    _currentVault.value = name
                    refreshVaultList()
                    importedName = name
                }
                _lanImportState.value = null
                val name = requireNotNull(importedName)
                VaultMaintenancePref.recordImport(getApplication(), name)
                _state.value = UiState(phase = Phase.LOCKED)
                clearSecurityReport()
                // 成功导入后立即通知传输站关闭（同会话，不额外配对），并清理本地会话。
                runCatching { SyncClient.cancelExportSession(serverUrl, pin) }
                SyncClient.forgetSession(serverUrl, pin)
                emitInfo(getApplication<Application>().getString(R.string.viewmodel_account_received, name))
                onResult(true, name)
            } catch (error: kotlinx.coroutines.CancellationException) {
                lanImportRetryContinuation = null
                _lanImportIntegrityRetry.value = null
                lanImportConflictContinuation = null
                _lanImportConflict.value = null
                SyncClient.forgetSession(serverUrl, pin)
                _lanImportState.value = null
                onResult(false, getApplication<Application>().getString(R.string.viewmodel_lan_import_cancelled))
                throw error
            } catch (error: Throwable) {
                lanImportRetryContinuation = null
                _lanImportIntegrityRetry.value = null
                lanImportConflictContinuation = null
                _lanImportConflict.value = null
                SyncClient.forgetSession(serverUrl, pin)
                _lanImportState.value = null
                val message = lanImportUserMessage(error)
                emitError(message)
                onResult(false, message)
            } finally {
                cache.delete()
            }
        }
    }

    /** 取消进行中的局域网导入（欢迎页/解锁页弹窗的「取消」）。 */
    fun cancelLanImport() {
        lanImportJob?.cancel()
        lanImportJob = null
        _lanImportState.value = null
        lanImportRetryContinuation = null
        _lanImportIntegrityRetry.value = null
        lanImportConflictContinuation = null
        _lanImportConflict.value = null
    }

    /** 完整性校验失败后用户选择「重新申请下载」。 */
    fun confirmLanImportRetry() {
        lanImportRetryContinuation?.resume(true)
        lanImportRetryContinuation = null
        _lanImportIntegrityRetry.value = null
    }

    /** 完整性校验失败后用户选择「取消导入」。 */
    fun cancelLanImportRetry() {
        lanImportRetryContinuation?.resume(false)
        lanImportRetryContinuation = null
        _lanImportIntegrityRetry.value = null
    }

    /** 接收端：手动输入传输站完整地址启动局域网导入（地址统一包含 ticket 与 pin，不再单独输入 PIN）。 */
    fun lanImportManual(address: String) {
        val trimmed = address.trim().removeSuffix("/")
        if (!trimmed.startsWith("https://")) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_paste_address))
            return
        }
        val ticket = com.vault.storage.SyncClient.pairingTicket(trimmed)
        if (ticket.length < 12) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_address_incomplete))
            return
        }
        val pin = com.vault.storage.SyncClient.embeddedPin(trimmed).orEmpty()
        if (pin.length != 6 || !pin.all(Char::isDigit)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_address_expired))
            return
        }
        lanImportFromStation(trimmed, pin)
    }

    /** 主机收到客户端推送的 .pmv：校验身份/密钥/谱系 → 合并 → 保存，返回合并统计 JSON。 */
    private fun handleHostVaultPut(file: java.io.File): String {
        val r = repo() ?: throw SyncServerHost.HostError(500, "保险库会话已失效")
        val localPayload = _state.value.payload?.let(::materializePayload)
            ?: throw SyncServerHost.HostError(500, "保险库已锁定")
        return handlePmvEHostVaultPut(r, localPayload, file)
    }

    private fun handlePmvEHostVaultPut(
        repository: VaultRepository,
        localPayload: VaultPayload,
        candidateFile: File,
    ): String {
        val rootSession = _state.value.rootKey ?: throw SyncServerHost.HostError(423, "PMVE 会话已锁定")
        return rootSession.withRootKey(rootSession.identity) { rootKey ->
            if (VaultFileFormat.detect(candidateFile) != VaultFileFormat.PMVE) {
                throw SyncServerHost.HostError(409, "远端保险库格式与本地 PMVE 不一致")
            }
            val local = runCatching { repository.currentAuthenticatedFile(rootKey) }
                .getOrElse { throw SyncServerHost.HostError(409, "本地 PMVE 身份认证失败") }
            val remote = runCatching { repository.authenticateExternalFileWithDeviceKey(candidateFile, rootKey) }
                .getOrElse { throw SyncServerHost.HostError(409, "远端 PMVE 文件认证失败") }
            when (PmvELineageClassifier.classify(local.toPmvELineage(), remote.toPmvELineage())) {
                PmvELineageRelation.SAME -> {
                    val accepted = repository.acknowledgeDeletionCleanupCheckpoint(rootKey, requireNotNull(local.identity).sequence)
                    try {
                        replacePmvESessionRoot(requireNotNull(accepted.rootKey), requireNotNull(accepted.identity))
                    } finally { accepted.rootKey?.fill(0) }
                    _state.update { it.withPayload(sealPayload(accepted.payload)) }
                    emitInfo(getApplication<Application>().getString(R.string.viewmodel_sync_content_same))
                    JSONObject().put("identical", accepted.payload.entries.size).put("lineage", "same").toString()
                }
                PmvELineageRelation.FAST_FORWARD -> {
                    val keyConvergence = pmveKeyConvergenceKind(repository, rootKey, candidateFile)
                    val installed = repository.replaceAuthenticatedFile(
                        candidate = candidateFile,
                        rootKey = rootKey,
                        expectedCurrent = requireNotNull(local.identity),
                        expectedRemote = requireNotNull(remote.identity),
                    )
                    val installedRootKey = requireNotNull(installed.rootKey)
                    try {
                        replacePmvESessionRoot(installedRootKey, requireNotNull(installed.identity))
                    } finally {
                        installedRootKey.fill(0)
                    }
                    _state.update { it.withPayload(sealPayload(installed.payload)) }
                    if (keyConvergence != KeyConvergenceKind.NONE) {
                        _keyConvergedNotice.value = KeyConvergedNotice(
                            keyConvergence,
                            keyConvergedMessage(keyConvergence),
                        )
                    } else {
                        emitInfo(getApplication<Application>().getString(R.string.viewmodel_sync_remote_accepted, installed.payload.entries.size))
                    }
                    JSONObject()
                        .put("remote_wins", installed.payload.entries.size)
                        .put("lineage", "fast_forward")
                        .toString()
                }
                PmvELineageRelation.REMOTE_STALE -> {
                    // 简化后的双向流程：连接方固定回推，若其提交较旧说明本端数据已更新，
                    // 直接保留本端并视为同步成功，不再以 409 拒绝导致流程失败。
                    emitInfo(getApplication<Application>().getString(R.string.viewmodel_sync_local_kept))
                    JSONObject()
                        .put("local_wins", localPayload.entries.size)
                        .put("lineage", "remote_stale")
                        .toString()
                }
                PmvELineageRelation.DIVERGED -> {
                    val remotePayload = remote.payload
                        ?: repository.decodeExternalFileWithRootKey(candidateFile, rootKey)
                    val (merged, stats) = VaultOps.mergeDiverged(
                        localPayload,
                        remotePayload.copy(
                            entries = remotePayload.entries.filter { it.deletedAt == null } +
                                remotePayload.entries.filter { it.deletedAt != null },
                        ),
                    )
                    // 分叉收敛：与客户端 DIVERGED 走同一 mergeDiverged，并把远端设备注册表
                    // 并入本地。若直接用 savePmvE 落盘，previousMetadata 只会继承本地注册表，
                    // 远端设备下次连接即被判为未授权。
                    val remoteRegistry = repository.authenticatedRegistryOf(candidateFile, rootKey)
                    saveCurrent(repository, merged, registry = remoteRegistry)
                    _state.update { it.withPayload(sealPayload(merged)) }
                    emitInfo(getApplication<Application>().getString(R.string.viewmodel_sync_summary, stats.added, stats.takeRemote, stats.identical))
                    JSONObject()
                        .put("added", stats.added)
                        .put("remote_wins", stats.takeRemote)
                        .put("local_wins", stats.takeLocal)
                        .put("identical", stats.identical)
                        .put("kept_both", stats.keptBoth)
                        .put("conflicts", stats.conflicts)
                        .put("passkey_conflicts", stats.passkeyConflicts)
                        .put("purged", stats.purged)
                        .put("purge_skipped", stats.purgeSkipped)
                        .put("coalesced", stats.coalesced)
                        .put("lineage", "diverged")
                        .toString()
                }
                PmvELineageRelation.DIFFERENT ->
                    throw SyncServerHost.HostError(409, "不是同一份 PMVE 保险库")
                PmvELineageRelation.INVALID ->
                    throw SyncServerHost.HostError(409, "PMVE 身份或提交谱系无效")
            }
        }
    }

    private fun updateLanTransferItem(
        id: String,
        direction: LanTransferDirection,
        update: (LanTransferItem) -> LanTransferItem,
    ) {
        _state.update { state ->
            state.copy(lanTransferItems = state.lanTransferItems.map { item ->
                if (item.remoteId == id && item.direction == direction) update(item) else item
            })
        }
    }

    private fun transferProgressUpdater(
        id: String,
        direction: LanTransferDirection,
    ): (Long, Long) -> Unit {
        var lastPercent = -1
        return { transferred, total ->
            val percent = if (total <= 0L) 100 else ((transferred * 100L) / total).toInt().coerceIn(0, 100)
            transferByteStates["$direction:$id"] = transferred to total
            if (percent != lastPercent) {
                lastPercent = percent
                updateLanTransferItem(id, direction) { it.copy(progress = percent / 100f) }
                pushTransferNotification()
            }
        }
    }

    /** 汇总所有传输项（含已完成的）字节，推送单条总进度通知。进度单调递增不回退。 */
    private fun pushTransferNotification() {
        if (transferByteStates.isEmpty()) return
        val totalBytes = transferByteStates.values.sumOf { it.second.coerceAtLeast(0L) }
        val transferredBytes = transferByteStates.values.sumOf { it.first.coerceIn(0L, it.second.coerceAtLeast(0L)) }
        val count = transferByteStates.size
        SyncForegroundService.updateTask(
            getApplication(),
            LAN_TRANSFER_TASK_ID,
            if (count > 1) "正在传输 $count 项 · ${percentOf(transferredBytes, totalBytes)}%" else
                "正在传输 · ${percentOf(transferredBytes, totalBytes)}%",
            transferredBytes,
            totalBytes,
        )
    }

    private fun percentOf(transferred: Long, total: Long): Int =
        if (total <= 0L) 100 else ((transferred * 100L) / total).toInt().coerceIn(0, 100)

    /** 传输项完成/失败后：标记为完成态（贡献满进度），避免总进度回退；全部结束则切到完成/失败态。 */
    private fun finishTransferItem(id: String, direction: LanTransferDirection) {
        // 断连/结束后通知由调用方统一处理，避免取消中的任务把通知误改成“完成”
        if (_state.value.lanTransferDisconnected || !_state.value.lanTransferActive) return
        val key = "$direction:$id"
        // 用户主动取消的条目：不贡献进度、不参与成功/失败判定。
        if (lanTransferCancelledKeys.contains(key)) return
        transferByteStates[key]?.let { (_, total) ->
            transferByteStates[key] = total to total
        }
        if (transferByteStates.values.any { (transferred, total) -> total > 0L && transferred < total }) {
            pushTransferNotification()
        } else {
            val hasFailure = _state.value.lanTransferItems.any {
                val itemKey = "${it.direction}:${it.remoteId}"
                !lanTransferCancelledKeys.contains(itemKey) &&
                    it.statusCode != LanTransferStatusCode.CANCELLED &&
                    it.statusCode in setOf(LanTransferStatusCode.FAILED, LanTransferStatusCode.INTERRUPTED)
            }
            if (hasFailure) {
                SyncForegroundService.failTask(getApplication(), LAN_TRANSFER_TASK_ID, localizeUiTextFor(getApplication(), "存在传输失败的项目"))
            } else {
                val rejected = _state.value.lanTransferItems.any {
                    it.statusCode == LanTransferStatusCode.REJECTED
                }
                if (rejected) {
                    SyncForegroundService.interruptTask(getApplication(), LAN_TRANSFER_TASK_ID, localizeUiTextFor(getApplication(), "有内容被对方取消或拒绝，其余已完成"))
                } else {
                    SyncForegroundService.succeedTask(getApplication(), LAN_TRANSFER_TASK_ID, localizeUiTextFor(getApplication(), "传输已完成"))
                }
            }
        }
    }

    private fun clearLanTransferTempFiles() {
        synchronized(lanTransferTempFiles) {
            lanTransferTempFiles.forEach { it.delete() }
            lanTransferTempFiles.clear()
        }
    }

    private data class PublishedTransfer(
        val uri: Uri,
        val displayPath: String,
        val localPath: String = "",
    )

    /** 剪贴板/IME 富内容已复制到私有缓存、等待大文件确认的待发送项。 */
    private class PendingCachedTransfer(
        val file: File,
        val name: String,
        val mime: String,
        val host: Boolean,
        val pendingId: String,
    )

    private fun publishReceivedTransfer(source: File, requestedName: String, mime: String): PublishedTransfer {
        val app = getApplication<Application>()
        val cleanName = cleanTransferName(requestedName)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = app.contentResolver
            val relativePath = "${Environment.DIRECTORY_DOWNLOADS}/Vaultshare"
            // MediaStore 写入前自算唯一名：数字后缀插在扩展名之前、无括号（file_2.txt），
            // 避免系统在扩展名后追加 (1) 造成 file.txt (1) 这类命名。
            val uniqueName = uniqueMediaStoreName(resolver, relativePath, cleanName)
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, uniqueName)
                put(MediaStore.MediaColumns.MIME_TYPE, mime.ifBlank { "application/octet-stream" })
                put(MediaStore.MediaColumns.RELATIVE_PATH, relativePath)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: error("无法创建下载文件")
            try {
                resolver.openOutputStream(uri, "w")?.buffered()?.use { output ->
                    source.inputStream().buffered().use { input -> input.copyTo(output) }
                } ?: error("无法写入下载文件")
                resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }, null, null)
                // 系统可能把重名文件自动改成 “名称 (1).扩展名” 括号格式，
                // 检测后改回 “名称_序号.扩展名” 的规范格式再展示。
                val actualName = ensureMediaStoreNameFormat(resolver, uri, relativePath, uniqueName)
                return PublishedTransfer(uri, "内部存储/Download/Vaultshare/$actualName")
            } catch (error: Throwable) {
                resolver.delete(uri, null, null)
                throw error
            }
        }

        val publicDirectory = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            "Vaultshare",
        )
        val publicTarget = runCatching {
            check(publicDirectory.isDirectory || publicDirectory.mkdirs()) { "无法创建公共下载目录" }
            uniqueTransferFile(publicDirectory, cleanName).also { source.copyTo(it) }
        }.getOrNull()
        if (publicTarget != null) {
            return PublishedTransfer(
                Uri.fromFile(publicTarget),
                transferPublicDisplayPath(publicTarget.name),
                publicTarget.absolutePath,
            )
        }

        val fallbackDirectory = (app.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: File(app.filesDir, "received"))
            .resolve("Vaultshare")
            .also { it.mkdirs() }
        val fallback = uniqueTransferFile(fallbackDirectory, cleanName)
        source.copyTo(fallback)
        return PublishedTransfer(
            Uri.fromFile(fallback),
            "应用存储/Download/Vaultshare/${fallback.name}",
            fallback.absolutePath,
        )
    }

    private fun readTransferTextPreview(file: File): String =
        file.inputStream().bufferedReader(Charsets.UTF_8).use { reader ->
            val chars = CharArray(4_096)
            val count = reader.read(chars)
            if (count <= 0) "" else String(chars, 0, count)
        }

    private fun transferPublicDisplayPath(name: String): String =
        "内部存储/Download/Vaultshare/${cleanTransferName(name)}"

    private fun cleanTransferName(requestedName: String): String =
        requestedName.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[\\u0000-\\u001f<>:\"/\\\\|?*]"), "_")
            .trim().ifBlank { "received.bin" }.take(180)

    private fun uniqueTransferFile(directory: File, requestedName: String): File {
        val clean = cleanTransferName(requestedName)
        val base = clean.substringBeforeLast('.', clean)
        val extension = clean.substringAfterLast('.', "").let { if (it.isBlank()) "" else ".$it" }
        var candidate = File(directory, clean)
        var index = 2
        // 数字后缀插在扩展名之前、无括号：file_2.txt / app_2.apk
        while (candidate.exists()) candidate = File(directory, "${base}_$index$extension").also { index++ }
        return candidate
    }

    /** MediaStore 目标目录内查重并生成唯一名（数字后缀在扩展名之前）。仅 Q+ 的 MediaStore Downloads 路径使用。 */
    @RequiresApi(29)
    private fun uniqueMediaStoreName(
        resolver: android.content.ContentResolver,
        relativePath: String,
        requestedName: String,
    ): String {
        val base = requestedName.substringBeforeLast('.', requestedName)
        val extension = requestedName.substringAfterLast('.', "").let { if (it.isBlank()) "" else ".$it" }
        val existing = queryVaultshareNames(resolver, relativePath)
        if (requestedName !in existing) return requestedName
        var index = 2
        while ("${base}_$index$extension" in existing) index++
        return "${base}_$index$extension"
    }

    /** 查询 Vaultshare 目录内所有已存在的文件名（同时按相对路径与文件路径兜底匹配）。仅 Q+ 的 MediaStore Downloads 路径使用。 */
    @RequiresApi(29)
    private fun queryVaultshareNames(
        resolver: android.content.ContentResolver,
        relativePath: String,
    ): HashSet<String> {
        val existing = HashSet<String>()
        runCatching {
            resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.MediaColumns.DISPLAY_NAME),
                "${MediaStore.MediaColumns.RELATIVE_PATH}=? OR ${MediaStore.MediaColumns.DATA} LIKE ?",
                arrayOf(relativePath, "%/Vaultshare/%"),
                null,
            )?.use { cursor ->
                while (cursor.moveToNext()) {
                    cursor.getString(0)?.let(existing::add)
                }
            }
        }
        return existing
    }

    /** 写入后校验实际文件名：若系统改成了括号格式，则改回“名称_序号.扩展名”。仅 Q+ 的 MediaStore Downloads 路径使用。 */
    @RequiresApi(29)
    private fun ensureMediaStoreNameFormat(
        resolver: android.content.ContentResolver,
        uri: Uri,
        relativePath: String,
        requestedName: String,
    ): String {
        val actual = resolver.query(uri, arrayOf(MediaStore.MediaColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }.orEmpty().ifBlank { requestedName }
        if (actual == requestedName) return actual
        val existing = queryVaultshareNames(resolver, relativePath)
        existing += actual
        val base = requestedName.substringBeforeLast('.', requestedName)
        val extension = requestedName.substringAfterLast('.', "").let { if (it.isBlank() || it == requestedName) "" else ".$it" }
        var index = 2
        while ("${base}_$index$extension" in existing) index++
        val renamed = "${base}_$index$extension"
        runCatching {
            resolver.update(uri, ContentValues().apply { put(MediaStore.MediaColumns.DISPLAY_NAME, renamed) }, null, null)
        }
        return renamed
    }

    // 动态码派生快照缓存：key = entryId，value 仅保存展示用派生结果（码/计时/发行方），
    // 不含 OTP 密钥明文。条目内容变更时由 sealPayload() 清空。
    private val otpCache = LinkedHashMap<String, OtpDisplaySnapshot>()
    private val otpCacheStep = LinkedHashMap<String, Long>()

    /**
     * 列表仅取得已计算的动态码快照，不把 OTP 密钥放回 Compose 状态。
     * TOTP 码只在 period 边界变化，因此按 (id, timeStep) 做缓存：命中时只重算
     * remaining/progress（纯算术），避免每秒对每条可见 OTP 条目重复
     * AES-GCM 解密 + HMAC。对应 PC 端「OTP 时间窗缓存」（F3）。
     */
    @Synchronized
    fun otpDisplaySnapshot(id: String, epochSeconds: Long): OtpDisplaySnapshot? {
        if (_state.value.phase != Phase.UNLOCKED) return null
        // 先走缓存命中：命中时只做纯算术，避免每秒对每条可见 OTP 条目做全库线性扫描
        // （缓存由 sealPayload() 在条目变更时清空，命中即代表当前条目仍有效）
        val cached = otpCache[id]
        if (cached != null && otpStep(cached, epochSeconds) == otpCacheStep[id]) {
            if (cached.type == "hotp") return cached
            val remaining = cached.period - (epochSeconds % cached.period).toInt()
            return cached.copy(remaining = remaining, progress = remaining.toFloat() / cached.period)
        }
        val metadata = _state.value.payload?.entries?.firstOrNull { it.id == id } ?: return null
        val complete = entryStore?.reveal(metadata) ?: metadata
        val snap = complete.otpDisplaySnapshot(epochSeconds) ?: return null
        otpCache[id] = snap
        otpCacheStep[id] = otpStep(snap, epochSeconds)
        return snap
    }

    private fun otpStep(snap: OtpDisplaySnapshot, epochSeconds: Long): Long =
        if (snap.type == "hotp") snap.counter else epochSeconds / snap.period.toLong()

    fun scanDuplicateSummary(): VaultOps.DedupScan? =
        _state.value.payload?.let(::materializePayload)?.let(VaultOps::scanDuplicates)

    fun duplicateGroupsForMaintenance(): List<List<Entry>> =
        _state.value.payload?.let(::materializePayload)?.let(VaultOps::duplicateGroups).orEmpty()

    @Synchronized
    private fun clearEntryStore() {
        otpCache.clear()
        otpCacheStep.clear()
        entryStore?.close()
        entryStore = null
    }

    /** 当前账户的生物绑定（每个账户独立）。 */
    fun biometricFor(name: String) = BiometricVault(getApplication(), name)
    val biometric get() = _currentVault.value?.let { biometricFor(it) }

    fun hasRecoveryKey(name: String): Boolean =
        VaultRepository(getApplication(), registry, name).fileFormat() == VaultFileFormat.PMVE
    fun currentLogicalRevision(): String? = _state.value.payload?.let {
        VaultLogicalRevision.from(materializePayload(it))
    }
    fun currentDeviceUnlockMaterial(): DeviceUnlockMaterial? {
        _state.value.rootKey?.let { session ->
            val rootKey = session.copyRootKey(session.identity)
            return try { DeviceUnlockMaterial.pmveRootKey(rootKey, session.identity) } finally { rootKey.fill(0) }
        }
        return null
    }

    /** Compatibility name for the current Settings UI; the return type is no longer a raw DEK. */
    fun currentDekForBiometric(): DeviceUnlockMaterial? = currentDeviceUnlockMaterial()

    /** 恢复密钥解锁（不再同时重置密码）：验证并解锁，随后进入不可关闭的重发/重置流程。 */
    fun unlockViaRecoveryKey(keyText: String) = viewModelScope.launch {
        if (_state.value.busy || _state.value.unlockSuccess || pendingUnlock != null) return@launch
        val sessionToken = captureVaultSession()
        val attemptId = ++unlockAttemptId
        _state.update { it.copy(busy = true) }
        val r = repo()
        val secret = runCatching { com.vault.crypto.RecoveryKeyCodec.decodeRecoveryKey(keyText) }
            .getOrElse {
                if (attemptId == unlockAttemptId && isVaultSessionCurrent(sessionToken)) _state.update { it.copy(busy = false) }
                emitError(getApplication<Application>().getString(R.string.viewmodel_recovery_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_recovery_invalid)))
                return@launch
            }
        if (r == null) {
            secret.fill(0)
            if (attemptId == unlockAttemptId && isVaultSessionCurrent(sessionToken)) _state.update { it.copy(busy = false) }
            return@launch
        }
        runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(sessionToken)
                val opened = r.openPmvEWithRecoveryKey(secret)
                requireVaultSessionCurrent(sessionToken)
                val cleaned = VaultOps.purgeExpired(
                    opened.payload,
                    retentionDays = TrashRetentionPref.days.value,
                )
                if (cleaned !== opened.payload) {
                    opened.rootKey?.let { key -> runCatching { r.savePmvE(cleaned, key) } }
                }
                opened to cleaned
            }
        }.onSuccess { (opened, cleaned) ->
            if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) {
                opened.rootKey?.fill(0)
                secret.fill(0)
                return@onSuccess
            }
        val r = repo()
        if (r == null) {
            secret.fill(0)
            _state.update { it.copy(busy = false) }
            return@launch
        }
            pendingRecoverySecret?.fill(0)
            pendingRecoverySecret = secret.copyOf()
            val credential = sessionCredential(
                rootKey = opened.rootKey,
                identity = opened.identity,
            )
            opened.rootKey?.fill(0)
            _state.update {
                it.withPayload(sealPayload(cleaned)).copy(
                    phase = Phase.UNLOCKED,
                    credential = credential,
                    busy = false,
                    unlockSuccess = false,
                )
            }
            _recoveryFlow.value = RecoveryFlowStep.RESET_PASSWORD
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_recovery_verified))
        }.onFailure { error ->
            if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) return@onFailure
            emitError(getApplication<Application>().getString(R.string.viewmodel_recovery_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
        }.also {
            if (attemptId == unlockAttemptId && isVaultSessionCurrent(sessionToken) && _state.value.phase != Phase.UNLOCKED) _state.update { it.copy(busy = false) }
            secret.fill(0)
        }
    }

    /** 密码重置确认后：用旧恢复密钥设置新主密码；旧恢复密钥保留，供下一步轮换。 */
    fun resetPasswordAfterRecovery(
        newPassword: String,
        weakPasswordConfirmed: Boolean = false,
    ) = viewModelScope.launch {
        if (_state.value.busy) return@launch
        if (!acceptsNewMasterPassword(newPassword, weakPasswordConfirmed)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_password_min_length))
            return@launch
        }
        val r = repo() ?: return@launch
        val old = pendingRecoverySecret?.copyOf()
        if (old == null) return@launch
        val newPasswordUtf8 = newPassword.encodeToByteArray()
        val token = captureVaultSession()
        val cloudConfig = loadCloudConfig()
        var opened: com.vault.storage.VaultUnlockResult? = null
        _state.update { it.copy(busy = true) }
        try {
        runCatching {
            withContext(Dispatchers.IO) {
                r.resetPmvEPasswordWithRecovery(old, newPasswordUtf8) { requireVaultSessionCurrent(token) }.also { opened = it }
            }
        }.mapCatching { result ->
            requireVaultSessionCurrent(token)
            replacePmvESessionRoot(requireNotNull(result.rootKey), requireNotNull(result.identity))
            _state.update { it.withPayload(sealPayload(result.payload)) }
            val current = _state.value.credential
            if (current != null) {
                val retainedKey = current.sessionKey()
                current.sessionPassword()?.close()
                _state.update {
                    it.copy(
                        credential = retainedKey?.let { key ->
                            VaultSessionCredential.Compound(
                                VaultSessionCredential.Password(newPasswordUtf8),
                                key,
                            )
                        } ?: VaultSessionCredential.Password(newPasswordUtf8),
                    )
                }
            }
            _recoveryFlow.value = RecoveryFlowStep.REISSUE
            biometric?.clear()
            cloudConfig?.let { config -> runCatching { saveCloudConfig(config) }.onFailure {
                emitError(getApplication<Application>().getString(R.string.cloud_rotation_credentials_failed))
            } }
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_password_reset))
        }.onFailure { error ->
            emitError(getApplication<Application>().getString(R.string.viewmodel_password_reset_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
        }
        } finally {
            if (isVaultSessionCurrent(token)) _state.update { it.copy(busy = false) }
            opened?.rootKey?.fill(0)
            old.fill(0)
            newPasswordUtf8.fill(0)
        }
    }

    /** 恢复密钥重发确认后：用旧恢复密钥换发新密钥（提交前旧密钥始终有效）。 */
    fun confirmRecoveryReissue(newSecret: ByteArray) = viewModelScope.launch {
        val r = repo() ?: run { newSecret.fill(0); return@launch }
        val old = pendingRecoverySecret
        if (old == null) {
            newSecret.fill(0)
            return@launch
        }
        runCatching {
            withContext(Dispatchers.IO) {
                r.rotatePmvERecoveryKey(old, newSecret)
            }
        }.onSuccess {
            old.fill(0)
            pendingRecoverySecret = null
            pendingNewRecoverySecret?.fill(0)
            pendingNewRecoverySecret = null
            newSecret.fill(0)
            _recoveryFlow.value = RecoveryFlowStep.NONE
            _state.value.payload?.let(::materializePayload)?.let { current ->
                val bumped = current.copy(
                    syncMeta = current.syncMeta.copy(
                        keyRevision = current.syncMeta.keyRevision + 1,
                        keyUpdatedAt = nowSeconds(),
                    ),
                )
                _state.update { it.withPayload(sealPayload(bumped)) }
            }
                emitInfo(getApplication<Application>().getString(R.string.viewmodel_recovery_updated))
        }.onFailure { error ->
            emitError(getApplication<Application>().getString(R.string.viewmodel_recovery_update_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            newSecret.fill(0)
        }
    }

    private fun initialState(): UiState {
        return if (registrySnapshot.currentVault != null) {
            UiState(phase = Phase.LOCKED)
        } else {
            UiState(phase = Phase.NO_VAULT)
        }
    }

    fun confirmLanImportConflict() {
        lanImportConflictContinuation?.resume(true)
        lanImportConflictContinuation = null
        _lanImportConflict.value = null
    }

    fun cancelLanImportConflict() {
        lanImportConflictContinuation?.resume(false)
        lanImportConflictContinuation = null
        _lanImportConflict.value = null
    }

    private fun refreshVaultList() {
        _vaults.value = registry.list()
        _trashedVaults.value = registry.listTrashed()
    }

    // --- 账户管理 ---

    fun switchTo(name: String) {
        if (!registry.exists(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_account_missing)); return }
        invalidateVaultSession()
        MediaCrypto.clear()
        _state.value.credential?.close()
        clearEntryStore()
        clearUnlockPipeline()
        registry.setCurrent(name)
        _currentVault.value = name
        _state.value = UiState(phase = Phase.LOCKED)
        clearSecurityReport()
    }

    fun renameVault(old: String, new: String) {
        runCatching { registry.rename(old, new) }
            .onSuccess {
                refreshVaultList()
                if (_currentVault.value == old) {
                    _currentVault.value = new
                    com.vault.security.CurrentVaultKey.install(new)
                }
                emitInfo(getApplication<Application>().getString(R.string.viewmodel_renamed, new))
            }
            .onFailure {
                emitError(
                    getApplication<Application>().getString(
                        R.string.viewmodel_rename_failed,
                        it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                    ),
                )
            }
    }

    /**
     * 软删除：标记账户进入"回收站"，30 天后自动彻底清除；期间可调用 [restoreVault] 恢复。
     * 不立即清生物密钥/物理文件，以便恢复时无缝继续使用生物识别解锁。
     */
    fun deleteVault(name: String) {
        val wasCurrent = _currentVault.value == name
        registry.markForDeletion(name)
        refreshVaultList()
        if (wasCurrent) {
            invalidateVaultSession()
            MediaCrypto.clear()
            _state.value.credential?.close()
            clearEntryStore()
            clearUnlockPipeline()
            _currentVault.value = registry.current()
            _state.value = if (_currentVault.value == null) UiState(phase = Phase.NO_VAULT)
            else UiState(phase = Phase.LOCKED)
            clearSecurityReport()
        }
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_deleted, name))
    }

    /** 该账户名是否处于"已软删除"状态。用于新建账户时检测命名冲突 →引导用户恢复。 */
    fun isTrashed(name: String): Boolean = registry.listTrashed().containsKey(name)

    /** 从回收站恢复账户。恢复后正常进入登录列表，原生物识别绑定保持有效。 */
    fun restoreVault(name: String) {
        if (registry.restoreFromDeletion(name)) {
            refreshVaultList()
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_restored, name))
        }
    }

    /** 立即彻底删除账户（不再可恢复）。用于回收站里的"立即删除"按钮。 */
    fun purgeVaultNow(name: String) {
        val wasCurrent = _currentVault.value == name
        registry.purgeNow(name)
        refreshVaultList()
        if (wasCurrent) {
            invalidateVaultSession()
            MediaCrypto.clear()
            _state.value.credential?.close()
            clearEntryStore()
            clearUnlockPipeline()
            _currentVault.value = registry.current()
            _state.value = if (_currentVault.value == null) UiState(phase = Phase.NO_VAULT)
            else UiState(phase = Phase.LOCKED)
            clearSecurityReport()
        }
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_permanently_deleted, name))
    }

    /** 新建账户：会立刻成为当前账户并进入 Unlocked。 */
    fun createNewVault(
        name: String,
        password: String,
        recoverySecret: ByteArray,
        weakPasswordConfirmed: Boolean = false,
    ) = viewModelScope.launch {
        if (!acceptsNewMasterPassword(password, weakPasswordConfirmed)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_password_min_length))
            return@launch
        }
        if (!registry.isValidName(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_invalid_account_name)); return@launch }
        if (registry.fileFor(name).exists()) { emitError(getApplication<Application>().getString(R.string.viewmodel_account_exists)); return@launch }
        if (!com.vault.security.VaultNameScope.releaseName(getApplication(), name)) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_create_vault_failed,
                getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            return@launch
        }
        val tempRepo = VaultRepository(getApplication(), registry, name)
        val passwordUtf8 = password.encodeToByteArray()
        try {
        runCatching {
            withContext(Dispatchers.IO) {
                tempRepo.createPmvE(
                    passwordUtf8,
                    recoverySecret,
                    VaultPayload(syncMeta = SyncMeta(keyRevision = 1, keyCreatedAt = nowSeconds())),
                )
            }
        }.onSuccess { opened ->
                val credential = sessionCredential(
                    passwordUtf8 = passwordUtf8,
                    rootKey = opened.rootKey,
                    identity = opened.identity,
                )
                opened.rootKey?.fill(0)
                registry.setCurrent(name)
                _currentVault.value = name
                refreshVaultList()
                _state.update {
                    it.withPayload(sealPayload(opened.payload)).copy(
                        phase = Phase.UNLOCKED,
                        credential = credential,
                    )
                }
                viewModelScope.launch(Dispatchers.IO) {
                    runCatching { ensureDeviceAuthorization(tempRepo) }
                }
            }
            .onFailure { emitError(getApplication<Application>().getString(R.string.viewmodel_create_vault_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error))) }
        } finally {
            passwordUtf8.fill(0)
        }
    }

    /** 当前账户的文件格式（维护页据此显示 PMVE 升级入口）。 */
    fun currentVaultFormat(): VaultFileFormat = repo()?.fileFormat() ?: VaultFileFormat.UNKNOWN

    /** PMVE 设备自注册：只签发数据库读写与设备管理权限。 */
    private suspend fun ensureDeviceAuthorization(repository: VaultRepository) {
        if (!repository.isPmvE()) return
        val root = _state.value.credential.sessionRootKey() ?: return
        val name = _currentVault.value ?: return
        val identity = VaultDeviceIdentityStore(getApplication(), name).loadOrCreate()
        try {
            val now = System.currentTimeMillis()
            root.withRootKey(root.identity) { key ->
                val records = repository.loadDeviceRegistry(key)
                val existing = PmvDeviceRegistry.latest(records, identity.deviceId)
                val requiredPermissions = PmvSyncAuthorization.PERMISSION_READ or
                    PmvSyncAuthorization.PERMISSION_WRITE or
                    PmvSyncAuthorization.PERMISSION_AUTHORIZE
                if (existing?.activeAt(now) != true ||
                    existing.permissions and requiredPermissions != requiredPermissions ||
                    !existing.devicePublicKey.contentEquals(identity.publicKey)
                ) {
                    repository.authorizeDevice(
                        rootKey = key,
                        deviceId = identity.deviceId,
                        devicePublicKey = identity.publicKey,
                        permissions = requiredPermissions,
                        epoch = (existing?.epoch ?: 0L) + 1,
                        issuedAtEpochMillis = now,
                    )
                }
            }
        } finally {
            identity.close()
        }
    }

    /**
     * 自动填充依赖登录快速索引做精确查询；迁移/导入的库可能缺少该索引，
     * 解锁后在后台自动补齐（无索引时重建并提交，返回 true）。
     */
    private suspend fun ensureLoginIndexAfterUnlock(repository: VaultRepository) {
        if (!repository.isPmvE()) return
        val root = _state.value.credential.sessionRootKey() ?: return
        vaultOperationMutex.withLock {
            root.withRootKey(root.identity) { key -> repository.ensurePmvELoginIndex(key) }
        }
    }

    /**
     * PMVE 自动压缩：依据提交序号与文件增长判断是否回收历史 Block 垃圾空间，
     * 满足条件时在后台执行一次压缩并记录压缩进度。返回 true 表示本次执行了压缩。
     * 身份与内容摘要不变，失败不阻断解锁流程。
     */
    private suspend fun autoCompactIfNeeded(repository: VaultRepository): Boolean {
        if (!repository.isPmvE()) return false
        val root = _state.value.credential.sessionRootKey() ?: return false
        val name = _currentVault.value ?: return false
        val context = getApplication<Application>()
        var compacted = false
        vaultOperationMutex.withLock {
            root.withRootKey(root.identity) { key ->
                val (revision, size) = repository.pmveMaintenanceStats(key)
                val lastRevision = VaultMaintenancePref.lastCompactRevision(context, name)
                val lastSize = VaultMaintenancePref.lastCompactSize(context, name)
                val lastAt = VaultMaintenancePref.lastCompactAt(context, name)
                val lastImportAt = VaultMaintenancePref.lastImportAt(context, name)
                if (AutoCompactPolicy.shouldCompact(
                        revision, lastRevision, size, lastSize, lastAt, lastImportAt,
                    )
                ) {
                    repository.compactPmvE(key)
                    VaultMaintenancePref.recordCompact(context, name, revision, repository.vaultFileSize())
                    compacted = true
                }
            }
        }
        return compacted
    }

    /** 云端同步上传前压缩一次：存在实际历史垃圾时回收 Block 垃圾空间。
     *
     * 与自动压缩不同，不受 24 小时间隔与导入冷却限制——云同步上传本身是
     * 低频率操作，上传前压缩可减小云端体积，且压缩后签名身份与内容摘要
     * 保持不变。压缩失败不阻断同步流程。 */
    private fun compactBeforeCloudSync(repository: VaultRepository, rootKey: ByteArray) {
        if (!repository.isPmvE()) return
        val name = _currentVault.value ?: return
        val context = getApplication<Application>()
        val (revision, size) = repository.pmveMaintenanceStats(rootKey)
        val lastRevision = VaultMaintenancePref.lastCompactRevision(context, name)
        val lastSize = VaultMaintenancePref.lastCompactSize(context, name)
        if (AutoCompactPolicy.shouldCompact(
                revision, lastRevision, size, lastSize,
                lastCompactAtMillis = 0L,
                lastImportAtMillis = 0L,
            )
        ) {
            runCatching {
                repository.compactPmvE(rootKey)
                VaultMaintenancePref.recordCompact(context, name, revision, repository.vaultFileSize())
            }
        }
    }

    private fun lanImportUserMessage(error: Throwable): String {
        val detail = error.message.orEmpty()
        return when {
            detail.contains("等待主机确认") -> getApplication<Application>().getString(R.string.viewmodel_lan_import_wait_timeout)
            error is SyncClient.PinValidationException -> getApplication<Application>().getString(R.string.viewmodel_lan_import_pin_expired)
            error is SyncClient.ExportIntegrityException -> getApplication<Application>().getString(R.string.viewmodel_lan_import_integrity_failed)
            detail.contains("HTTP 403") -> getApplication<Application>().getString(R.string.viewmodel_lan_import_forbidden)
            detail.contains("HTTP 423") -> getApplication<Application>().getString(R.string.viewmodel_lan_import_locked)
            detail.contains("timed out", ignoreCase = true) || detail.contains("超时") ->
                getApplication<Application>().getString(R.string.viewmodel_lan_import_timeout)
            error is java.io.IOException || error.cause is java.io.IOException ->
                getApplication<Application>().getString(R.string.viewmodel_lan_import_disconnected)
            detail == "已取消导入" -> getApplication<Application>().getString(R.string.viewmodel_lan_import_cancelled_receive)
            else -> getApplication<Application>().getString(R.string.viewmodel_lan_import_failed)
        }
    }

    /** 从当前解锁会话构建设备授权注册表（供传输站认证握手使用；同一实例跨请求保持 pending challenge）。 */
    private fun buildDeviceAuthRegistry(): PmvSyncAuthorization.AuthorizationRegistry? {
        val s = _state.value
        val root = s.credential.sessionRootKey() ?: return null
        val r = repo() ?: return null
        return runCatching {
            root.withRootKey(root.identity) { key ->
                val records = r.loadDeviceRegistry(key)
                val registry = PmvSyncAuthorization.AuthorizationRegistry(
                    root.identity.vaultId,
                    root.identity.copySigningPublicKey(),
                )
                records.forEach(registry::install)
                registry
            }
        }.getOrNull()
    }

    /** 为导入账户命名提供同步校验，错误时保留命名窗口。 */
    fun importAccountNameError(name: String): String? = when {
        !registry.isValidName(name) -> getApplication<Application>().getString(R.string.viewmodel_invalid_account_name)
        registry.exists(name) -> getApplication<Application>().getString(R.string.viewmodel_account_exists)
        else -> null
    }

    /** 先读取并检查文件及冗余头结构，再进入命名；密码认证仍在解锁时完成。 */
fun validateImportFile(uri: Uri, onValid: () -> Unit) = viewModelScope.launch {
        val invalidFile = getApplication<Application>().getString(R.string.import_file_invalid)
        val result = runCatching {
            withContext(Dispatchers.IO) {
                val size = com.vault.storage.PmvVaultHeaderCodec.HEADER_SIZE
                val firstOffset = com.vault.storage.PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET.toInt()
                val secondOffset = com.vault.storage.PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET.toInt()
                getApplication<Application>().contentResolver.openInputStream(uri)?.use { raw ->
                    val input = java.io.DataInputStream(raw.buffered())
                    val prefix = ByteArray(secondOffset + size)
                    input.readFully(prefix)
                    require(com.vault.storage.VaultFileFormat.detect(prefix.copyOfRange(0, 4)) != com.vault.storage.VaultFileFormat.UNKNOWN) { invalidFile }
                    require(listOf(firstOffset, secondOffset).any { offset ->
                        runCatching { com.vault.storage.PmvVaultHeaderCodec.decode(prefix.copyOfRange(offset, offset + size)) }.isSuccess
                    }) { invalidFile }
                    var total = prefix.size.toLong()
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                    }
                    require(total > prefix.size) { invalidFile }
                } ?: error(invalidFile)
            }
        }
        result.onSuccess { onValid() }.onFailure { emitError(it.message ?: invalidFile) }
    }

    /** 从 SAF 导入 .pmv 为新账户。 */
    fun importVaultAs(name: String, uri: Uri) = viewModelScope.launch {
        if (!registry.isValidName(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_invalid_account_name)); return@launch }
        if (registry.exists(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_account_exists)); return@launch }
        val tempRepo = VaultRepository(getApplication(), registry, name)
        SyncForegroundService.beginTask(
            getApplication(),
            VAULT_ACCOUNT_IMPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "导入账户"),
            localizeUiTextFor(getApplication(), "正在导入保险库文件…"),
        )
        runCatching { withContext(Dispatchers.IO) { tempRepo.importFromUri(uri) } }
            .onSuccess {
                registry.setCurrent(name)
                _currentVault.value = name
                refreshVaultList()
                VaultMaintenancePref.recordImport(getApplication(), name)
                _state.value = UiState(phase = Phase.LOCKED)
                clearSecurityReport()
                SyncForegroundService.succeedTask(getApplication(), VAULT_ACCOUNT_IMPORT_TASK_ID, localizeUiTextFor(getApplication(), "已导入到账户「$name」"))
                emitInfo("已导入到账户「$name」")
            }
            .onFailure {
                SyncForegroundService.failTask(getApplication(), VAULT_ACCOUNT_IMPORT_TASK_ID, localizeUiTextFor(getApplication(), "导入失败：${it.message}"))
                emitError("导入失败：${it.message}")
            }
    }

    /**
     * 导入 .pmv 覆盖已删除的账户（回收站中）。
     * 先验证原主密码，再恢复账户、覆盖导入文件。
     */
    fun importVaultAsOverTrash(name: String, password: String, uri: Uri) = viewModelScope.launch {
        if (!registry.isValidName(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_invalid_account_name)); return@launch }
        if (!isTrashed(name)) { emitError(getApplication<Application>().getString(R.string.viewmodel_not_in_trash, name)); return@launch }
        val tempRepo = VaultRepository(getApplication(), registry, name)
        val passwordUtf8 = password.encodeToByteArray()
        val verified = try {
            runCatching { withContext(Dispatchers.IO) { tempRepo.open(passwordUtf8) } }
        } finally {
            passwordUtf8.fill(0)
        }
        verified
            .onFailure { emitError(getApplication<Application>().getString(R.string.viewmodel_wrong_password_ownership)); return@launch }
        registry.restoreFromDeletion(name)
        SyncForegroundService.beginTask(
            getApplication(),
            VAULT_ACCOUNT_IMPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "导入账户"),
            localizeUiTextFor(getApplication(), "正在导入保险库文件…"),
        )
        runCatching { withContext(Dispatchers.IO) { tempRepo.importFromUri(uri) } }
            .onSuccess {
                registry.setCurrent(name)
                _currentVault.value = name
                refreshVaultList()
                _state.value = UiState(phase = Phase.LOCKED)
                clearSecurityReport()
                SyncForegroundService.succeedTask(getApplication(), VAULT_ACCOUNT_IMPORT_TASK_ID, localizeUiTextFor(getApplication(), "已恢复并导入到账户「$name」"))
                emitInfo("已恢复并导入到账户「$name」")
            }
            .onFailure {
                SyncForegroundService.failTask(getApplication(), VAULT_ACCOUNT_IMPORT_TASK_ID, localizeUiTextFor(getApplication(), "导入失败：${it.message}"))
                emitError("导入失败：${it.message}")
            }
    }

    // --- 当前账户解锁/锁定 ---

    fun unlock(password: String): Job = beginUnlock(password.encodeToByteArray())

    private fun beginUnlock(passwordUtf8: ByteArray): Job {
        val sessionToken = captureVaultSession()
        return viewModelScope.launch {
            try {
            if (!isVaultSessionCurrent(sessionToken)) return@launch
            if (_state.value.busy || _state.value.unlockSuccess || pendingUnlock != null) return@launch
            val attemptId = ++unlockAttemptId
            val r = repo() ?: return@launch
            val ctx = getApplication<Application>()

        // 冷却期内拒绝解锁尝试
        if (LockoutPref.isCoolingDown(ctx)) {
            val secs = LockoutPref.remainingSeconds(LockoutPref.coolingRemainingMs(ctx))
            emitError(getApplication<Application>().getString(R.string.viewmodel_too_many_attempts, secs))
            return@launch
        }
        _state.update { it.copy(busy = true) }
        runCatching {
            val payloadResult = withContext(Dispatchers.IO) {
                val opened = r.openForUnlock(passwordUtf8)
                try {
                    val payload = opened.payload
                    val purged = VaultOps.purgeExpired(payload, retentionDays = TrashRetentionPref.days.value)
                    val cleaned = VaultOps.repairOtpBindings(purged)
                    UnlockOpenResult(
                        sealed = sealPayloadForSession(sessionToken, cleaned),
                        needsSave = cleaned !== payload || opened.needsFastUnlockUpgrade,
                        rootKey = opened.rootKey?.copyOf(),
                        identity = opened.identity,
                        purgedExpired = purged !== payload,
                    )
                } finally {
                    opened.rootKey?.fill(0)
                }
            }
            val listIndex = withContext(Dispatchers.Default) {
                VaultListIndex.from(payloadResult.sealed)
            }
            PreparedUnlock(
                payload = payloadResult.sealed,
                listIndex = listIndex,
                needsSave = payloadResult.needsSave,
                rootKey = payloadResult.rootKey,
                identity = payloadResult.identity,
                purgedExpired = payloadResult.purgedExpired,
            )
        }
            .onSuccess { prepared ->
                if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) {
                    prepared.clearKeys()
                    return@onSuccess
                }
                LockoutPref.clear(ctx)

                // 动画开始即发布已解锁状态并启动本地维护后台工作，与打勾动画并行执行；
                // 页面切换仍在动画回调里完成，云同步循环在进入主页后启动。
                val credential = sessionCredential(
                    passwordUtf8 = passwordUtf8,
                    rootKey = prepared.rootKey,
                    identity = prepared.identity,
                )
                val pending = PendingUnlock(
                    payload = prepared.payload,
                    listIndex = prepared.listIndex,
                    credential = credential,
                    repository = r,
                    needsSave = prepared.needsSave,
                    purgedExpired = prepared.purgedExpired,
                )
                prepared.clearKeys()
                pendingUnlock = pending
                _state.update {
                    it.withPayload(pending.payload).copy(
                        credential = pending.credential,
                        busy = false,
                        unlockSuccess = true,
                        autoLocked = false,
                    )
                }
                startUnlockBackgroundWork(pending)
                viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) { maybeAutoUpgradeKdf() }
            }
            .onFailure {
                if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) return@onFailure
                val isWrongPw = it is VaultCrypto.DecryptError
                if (isWrongPw) {
                    val res = LockoutPref.recordFailure(ctx, FailureSource.UNLOCK)
                    if (res.enteredCooldown) {
                        val secs = res.cooldownMs / 1000
                        _state.update { it.copy(busy = false) }
                        emitError(getApplication<Application>().getString(R.string.viewmodel_locked_seconds, secs), sticky = true)
                    } else {
                        val remaining = LockoutPref.MAX_ATTEMPTS - res.newFailCount
                        emitError(getApplication<Application>().getString(R.string.viewmodel_wrong_password_remaining, remaining))
                        // 退避由持久化的 next_attempt 截止时间拦截；校验已结束，停止等待动画。
                        _state.update { it.copy(busy = false) }
                    }
                } else {
                    _state.update { it.copy(busy = false) }
                    emitError(getApplication<Application>().getString(R.string.viewmodel_unlock_failed_detail, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unlock_failed)))
                }
            }
            } finally {
                passwordUtf8.fill(0)
            }
        }
    }

    fun unlockWithBiometric(material: DeviceUnlockMaterial): Job {
        val sessionToken = captureVaultSession()
        return viewModelScope.launch {
            if (!isVaultSessionCurrent(sessionToken)) {
                material.close()
                return@launch
            }
            if (_state.value.busy || _state.value.unlockSuccess || pendingUnlock != null) {
                material.close()
                return@launch
            }
            val attemptId = ++unlockAttemptId
            val r = repo() ?: run { material.close(); return@launch }
            _state.update { it.copy(busy = true) }
            runCatching {
            val opened = withContext(Dispatchers.IO) {
                require(material.kind == DeviceUnlockKeyKind.PMVE_ROOT_KEY) { "仅支持 PMVE 生物识别凭据" }
                val expected = requireNotNull(material.binding) { "PMVE 生物识别凭据缺少身份绑定" }
                val result = material.withSecret(expected) { r.openPmvEWithRootKey(it) }
                val actual = requireNotNull(result.identity) { "PMVE 解锁未返回保险库身份" }.deviceBinding()
                if (!expected.matches(actual)) {
                    result.rootKey?.fill(0)
                    biometric?.clear()
                    throw SecurityException("生物识别凭据与当前保险库身份不匹配，已清除")
                }
                result
            }
            try {
                val payload = opened.payload
                val purged = VaultOps.purgeExpired(payload, retentionDays = TrashRetentionPref.days.value)
                val cleaned = purged
                val sealedPayload = sealPayloadForSession(sessionToken, cleaned)
                PendingUnlock(
                    payload = sealedPayload,
                    listIndex = withContext(Dispatchers.Default) { VaultListIndex.from(sealedPayload) },
                    credential = sessionCredential(
                        rootKey = opened.rootKey,
                        identity = opened.identity,
                    ),
                    repository = r,
                    needsSave = cleaned !== payload || opened.needsFastUnlockUpgrade,
                    purgedExpired = cleaned !== payload,
                )
            } finally {
                opened.rootKey?.fill(0)
            }
        }.onSuccess { prepared ->
            if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) {
                prepared.credential?.close()
                return@onSuccess
            }
            // 指纹是活体硬件校验，不是在猜密码，所以成功后直接结束冷却：
            // 否则主人手滑输错密码后会被自己的指纹弹窗挡在模糊遮罩后面 30 秒。
            LockoutPref.clear(getApplication<Application>())
            pendingUnlock = prepared
            _state.update {
                it.withPayload(prepared.payload).copy(
                    credential = prepared.credential,
                    busy = false,
                    unlockSuccess = true,
                    autoLocked = false,
                )
            }
            startUnlockBackgroundWork(prepared)
        }.onFailure {
            if (attemptId != unlockAttemptId || !isVaultSessionCurrent(sessionToken)) return@onFailure
            _state.update { state -> state.copy(busy = false) }
            emitError(getApplication<Application>().getString(R.string.viewmodel_biometric_unlock_failed_detail, it.message ?: getApplication<Application>().getString(R.string.viewmodel_biometric_unlock_failed)))
        }
            material.close()
        }
    }

    fun completeUnlockAnimation() {
        if (!_state.value.unlockSuccess) return
        val unlocked = pendingUnlock ?: return
        pendingUnlock = null

        // payload/credential 已在动画开始时发布，这里只切换 phase 并结束动画。
        // 不重建 payload：动画期间本地维护任务可能已更新内存数据，覆盖会造成回退。
        _state.update {
            it.copy(
                phase = Phase.UNLOCKED,
                credential = unlocked.credential,
                busy = false,
                unlockSuccess = false,
                autoLocked = false,
            )
        }
        unlocked.rootKey?.let { session ->
            val name = _currentVault.value ?: error("当前保险库名称缺失")
            session.withRootKey(session.identity) { rootKey ->
                PmvMediaUiSession.bind(getApplication(), name, rootKey)
            }
        } ?: PmvMediaUiSession.clear()

        // 云同步循环在进入主页后启动；动画期间并行执行的是本地维护类任务。
        // 先按持久化状态整体复位 phase：上一个会话若在退后台/锁定时被取消，
        // phase 可能残留 RUNNING，不复位会让本次解锁后的自动同步被门禁永久挡死。
        restoreCloudSyncState()
        restartAutoCloudSync()
        // 动画期间并行启动的后台维护工作若被“退到后台”等暂停打断（任务被置空），
        // 在此兜底补启动；正常路径任务仍在运行，不会重复执行。
        startUnlockBackgroundWork(unlocked)
    }

    /**
     * 解锁动画期间即启动本地维护后台工作：设备身份校验、落盘保存、压缩、登录索引
     * 与泄露检测和打勾动画并行执行；自动云同步循环由进入主页后单独启动。
     * 幂等：仅在对应任务未启动（如动画期间被暂停）时才真正启动。
     */
    private fun startUnlockBackgroundWork(unlocked: PendingUnlock) {
        if (postUnlockJob == null) {
            val maintenanceToken = captureVaultSession()
            postUnlockJob = viewModelScope.launch {
                delay(POST_UNLOCK_SETTLE_MS)
                if (!unlockSessionActive()) return@launch
                withContext(Dispatchers.IO) {
                    runCatching { ensureDeviceAuthorization(unlocked.repository) }
                }
                if (!unlockSessionActive()) return@launch
                // 统一自动维护：临时文件清理与 PMVE 压缩都在后台执行，不再要求用户手动触发。
                withContext(Dispatchers.IO) {
                    runCatching { com.vault.storage.CacheCleaner.cleanForReport(getApplication()) }
                }
                // PMV 中的排除规则是跨设备迁移的权威来源，解锁后恢复到本地缓存。
                vaultOperationMutex.withLock {
                    val currentPayload = _state.value.payload?.let(::materializePayload) ?: return@withLock
                    withContext(Dispatchers.IO) {
                        runCatching {
                            vaultSessionFence.runIfCurrent(maintenanceToken, _currentVault.value) {
                                val root = _state.value.credential.sessionRootKey() ?: error("保险库会话已失效")
                                val opened = root.withRootKey(root.identity) { unlocked.repository.openPmvEWithRootKey(it) }
                                try {
                                    // Rebase maintenance onto the latest authenticated commit: another
                                    // process may have saved entries since unlock animation began.
                                    val base = if (unlocked.needsSave) VaultOps.repairOtpBindings(
                                        VaultOps.purgeExpired(opened.payload, retentionDays = TrashRetentionPref.days.value),
                                    ) else opened.payload
                                    val refreshed = base.copy(autofillExclusions = base.autofillExclusions.merge(currentPayload.autofillExclusions))
                                    if (unlocked.needsSave || refreshed.autofillExclusions != opened.payload.autofillExclusions) {
                                        check(saveAndPublishForSession(maintenanceToken, unlocked.repository,
                                            refreshed, requireNotNull(opened.identity).sequence)) { "保险库会话已失效" }
                                    } else if (VaultLogicalRevision.from(opened.payload) != VaultLogicalRevision.from(currentPayload)) {
                                        publishPayloadForSession(maintenanceToken, refreshed)
                                    }
                                } finally { opened.rootKey?.fill(0) }
                            }
                        }.onFailure { postError(localizeUiTextFor(getApplication(), "保险库维护保存失败：${it.message ?: "未知错误"}")) }
                    }
                }
                if (!unlockSessionActive()) return@launch
                // 过期回收站清理后立即压缩，回收追加写产生的死空间，
                // 不受自动压缩策略（提交数/间隔/冷却）门槛限制。
                if (unlocked.purgedExpired) {
                    val compacted = withContext(Dispatchers.IO) {
                        compactAfterExpiredPurge(unlocked.repository)
                    }
                    if (compacted) postInfo(getApplication<Application>().getString(R.string.viewmodel_auto_compacted))
                }
                var autoCompacted = false
                withContext(Dispatchers.IO) {
                    runCatching { ensureLoginIndexAfterUnlock(unlocked.repository) }
                    autoCompacted = runCatching { autoCompactIfNeeded(unlocked.repository) }.getOrDefault(false)
                }
                if (autoCompacted) {
                    postInfo(getApplication<Application>().getString(R.string.viewmodel_auto_compacted))
                }
                if (!unlockSessionActive()) return@launch
                automaticLeakJob?.cancel()
                automaticLeakJob = viewModelScope.launch {
                    // 全库解密是 CPU 重活，移到 IO 线程，避免解锁后主线程卡顿。
                    val leakPayload = withContext(Dispatchers.IO) { materializePayload(unlocked.payload) }
                    autoCheckLeaks(leakPayload, unlocked.repository, getApplication())
                }
            }
        }
    }

    /** 解锁动画期间（unlockSuccess）或已解锁（UNLOCKED）时，后台维护任务保持有效。 */
    private fun unlockSessionActive(): Boolean {
        val s = _state.value
        return s.phase == Phase.UNLOCKED || s.unlockSuccess
    }

    /**
     * 泄露检测：每个到检条目只走一次流水线。
     * 本地弱密码字典始终执行；联网开关开启时再查 Pwned Passwords。
     * 网络失败不覆盖旧缓存，联网关闭时把 pwnedCount 记为 0。
     */
    fun runManualLeakCheck() = viewModelScope.launch {
        if (!LeakCheckEnabledPref.enabled.value) {
            postInfo(getApplication<Application>().getString(R.string.viewmodel_leak_check_disabled))
            return@launch
        }
        if (_state.value.leakCheckRunning) return@launch
        val r = repo() ?: return@launch
        // 全库解密是 CPU 重活，移到 IO 线程，避免手动检测时主线程卡顿。
        val payload = withContext(Dispatchers.IO) { _state.value.payload?.let(::materializePayload) }
            ?: return@launch
        autoCheckLeaks(payload, r, getApplication(), force = true, reportProgress = true)
    }

    private suspend fun autoCheckLeaks(
        payload: VaultPayload,
        r: VaultRepository,
        ctx: android.content.Context,
        force: Boolean = false,
        reportProgress: Boolean = false,
        targetIds: Set<String>? = null,
    ) {
        if (!LeakCheckEnabledPref.enabled.value) return
        val recheckDays = LeakCheckIntervalPref.days.value
        val now = nowSeconds()
        val toCheck = payload.entries.filter { e ->
            e.deletedAt == null &&
                (targetIds == null || e.id in targetIds) &&
                e.needsLeakCheck(recheckDays = recheckDays, force = force, now = now)
        }
        if (reportProgress) {
            _state.update {
                it.copy(
                    leakCheckRunning = toCheck.isNotEmpty(),
                    leakCheckChecked = 0,
                    leakCheckTotal = toCheck.size,
                )
            }
        }
        if (toCheck.isEmpty()) {
            if (reportProgress) {
                SyncForegroundService.succeedTask(
                    getApplication(),
                    BREACH_CHECK_TASK_ID,
                    localizeUiTextFor(getApplication(), "没有需要检测的条目"),
                )
                postInfo("没有需要检测的条目")
            }
            return
        }
        if (reportProgress) {
            SyncForegroundService.beginTask(
                getApplication(),
                BREACH_CHECK_TASK_ID,
                BackgroundTaskKind.BREACH_CHECK,
                localizeUiTextFor(getApplication(), "密码泄露检测"),
                localizeUiTextFor(getApplication(), "正在检查密码泄露…"),
            )
        }

        var dirty = false
        val onlineEnabled = LeakOnlineCheckPref.enabled.value
        val pwnedCache = mutableMapOf<String, Int>()
        val pendingCheckedEntries = linkedMapOf<String, Entry>()
        fun publishProgress(checked: Int) {
            if (reportProgress) {
                _state.update { it.copy(leakCheckChecked = checked.coerceAtMost(toCheck.size)) }
                SyncForegroundService.updateTask(
                    getApplication(),
                    BREACH_CHECK_TASK_ID,
                    localizeUiTextFor(getApplication(), "正在检查密码泄露…"),
                    current = checked.toLong(),
                    total = toCheck.size.toLong(),
                )
            }
        }
        try {
        var checkedCount = 0
        for (snapshot in toCheck) {
            val current = payload.entries.firstOrNull { it.id == snapshot.id }
            if (current == null) {
                publishProgress(++checkedCount)
                continue
            }
            if (current.updatedAt != snapshot.updatedAt || current.deletedAt != null) {
                publishProgress(++checkedCount)
                continue
            }
            val e = current
            val secret = e.entrySecret()
            if (secret.isEmpty()) {
                publishProgress(++checkedCount)
                continue
            }

            val commonWeak = LeakedPasswordCheck.isLeaked(ctx, secret)
            val pwnedCount = if (onlineEnabled) {
                pwnedCache.getOrPut(secret) {
                    withContext(Dispatchers.IO) { PwnedPasswordsCheck.breachCount(secret) }
                }
            } else {
                0
            }
            if (pwnedCount < 0) {
                publishProgress(++checkedCount)
                continue
            }

            val checked = e.withLeakCheckResult(
                commonWeak = commonWeak,
                pwnedCount = pwnedCount,
                checkedAt = now,
            )
            dirty = true
            pendingCheckedEntries[checked.id] = checked
            publishProgress(++checkedCount)
        }

        if (dirty) {
            val currentPayload = _state.value.payload?.let(::materializePayload) ?: payload
            val newPayload = currentPayload.copy(entries = currentPayload.entries.map { current ->
                val checked = pendingCheckedEntries[current.id]
                if (checked != null && current.updatedAt == checked.updatedAt) checked else current
            })
            withContext(Dispatchers.IO) { runCatching { saveCurrent(r, newPayload) } }
            _state.update { it.withPayload(sealPayload(newPayload)) }
        }
        if (reportProgress) {
            _state.update { it.copy(leakCheckRunning = false, leakCheckChecked = toCheck.size) }
            val leaked = pendingCheckedEntries.values.count { (it.leakPwnedCount ?: 0) > 0 || it.leakCommonWeak }
            SyncForegroundService.succeedTask(
                getApplication(),
                BREACH_CHECK_TASK_ID,
                localizeUiTextFor(getApplication(), "已检查 ${toCheck.size} 个条目${if (leaked > 0) "，发现 $leaked 个存在泄露风险" else "，未发现泄露"}")
            )
        }
        } catch (t: Throwable) {
            if (reportProgress) {
                _state.update { it.copy(leakCheckRunning = false, leakCheckChecked = 0, leakCheckTotal = 0) }
                SyncForegroundService.failTask(
                    getApplication(),
                    BREACH_CHECK_TASK_ID,
                    localizeUiTextFor(getApplication(), "密码泄露检测失败：${t.message ?: "未知错误"}"),
                )
                postInfo(localizeUiTextFor(getApplication(), "密码泄露检测失败：${t.message ?: "未知错误"}"))
            }
        }
    }

    fun lock() {
        // 传输站需要已解锁的库才能合并客户端推送；锁库后立即停止主机会话。
        stopLanHost()
        invalidateVaultSession()
        pendingRecoverySecret?.fill(0)
        pendingNewRecoverySecret?.fill(0)
        pendingRecoverySecret = null
        pendingNewRecoverySecret = null
        _recoveryFlow.value = RecoveryFlowStep.NONE
        securitySessionUntilElapsed = 0L
        MediaCrypto.clear()
        _state.value.credential?.close()
        clearEntryStore()
        clearUnlockPipeline()
        pauseBackgroundWork()
        _state.update {
            UiState(
                phase = Phase.LOCKED,
                query = it.query,
                tagFilter = it.tagFilter,
                typeFilter = it.typeFilter,
                autoLocked = true,
                // 锁库只隐藏保险库内容，不结束用户显式开启的局域网内容传输。
                // 解锁后依靠这些状态重新显示传输页，连接仍只能由“结束传输”关闭。
                lanTransferActive = it.lanTransferActive,
                lanTransferConnecting = it.lanTransferConnecting,
                lanTransferDisconnected = it.lanTransferDisconnected,
                lanTransferItems = it.lanTransferItems,
                lanTransferError = it.lanTransferError,
            )
        }
        clearSecurityReport()
    }

    fun verifySessionPassword(candidate: String): Boolean {
        val ctx = getApplication<Application>()
        if (LockoutPref.isCoolingDown(ctx)) return false
        val candidateUtf8 = candidate.encodeToByteArray()
        return try {
            val current = _state.value
            if (current.phase != Phase.UNLOCKED || current.credential?.sessionKey() == null) return false
            val valid = runCatching { repo()?.open(candidateUtf8) != null }.getOrDefault(false)
            if (valid) {
                val key = requireNotNull(_state.value.credential?.sessionKey())
                _state.value.credential?.sessionPassword()?.close()
                _state.update {
                    it.copy(
                        credential = VaultSessionCredential.Compound(
                            VaultSessionCredential.Password(candidateUtf8),
                            key,
                        ),
                    )
                }
                LockoutPref.clear(ctx)
            } else {
                val res = LockoutPref.recordFailure(ctx, FailureSource.SENSITIVE_VERIFY)
                // 库已解锁却连续 5 次猜错主密码，持机者很可能不是用户：本次失败直接把会话
                // 降级为锁定，清掉已解密的内存态。只有本路径自己记满才锁，避免自动填充/通行密钥
                // 在系统弹窗里输错密码把用户正在用的主会话锁掉。
                if (res.enteredCooldown) {
                    lock()
                    emitError(
                        getApplication<Application>().getString(
                            R.string.viewmodel_locked_sensitive_verify,
                            res.cooldownMs / 1000,
                        ),
                        sticky = true,
                    )
                }
            }
            valid
        } finally {
            candidateUtf8.fill(0)
        }
    }

    fun hasSecuritySession(): Boolean =
        _state.value.phase == Phase.UNLOCKED && SystemClock.elapsedRealtime() < securitySessionUntilElapsed

    fun elevateSecuritySession() {
        securitySessionUntilElapsed = SystemClock.elapsedRealtime() + 5 * 60_000L
    }

    /** Commit exclusion edits immediately to the authenticated vault and publish exactly what was saved. */
    fun saveAutofillExclusions() {
        val token = captureVaultSession()
        val targetVault = token.vaultName ?: return
        viewModelScope.launch {
            runCatching {
                val snapshot = com.vault.autofill.AutofillExcludePref.snapshot(getApplication(), targetVault)
                vaultOperationMutex.withLock {
                    requireVaultSessionCurrent(token)
                    val repository = repo() ?: error("保险库会话已失效")
                    val payload = _state.value.payload?.let(::materializePayload) ?: error("保险库会话已失效")
                    val updated = payload.copy(autofillExclusions = payload.autofillExclusions.merge(snapshot))
                    withContext(Dispatchers.IO) {
                        val root = _state.value.credential.sessionRootKey() ?: error("保险库会话已失效")
                        val opened = root.withRootKey(root.identity) { repository.openPmvEWithRootKey(it) }
                        try {
                            check(VaultLogicalRevision.from(opened.payload.copy(autofillExclusions = payload.autofillExclusions)) ==
                                VaultLogicalRevision.from(payload)) { localizeUiTextFor(getApplication(), "保险库在编辑期间已变化，请重试") }
                            val merged = updated.copy(autofillExclusions = updated.autofillExclusions.merge(opened.payload.autofillExclusions))
                            check(saveAndPublishForSession(token, repository, merged, requireNotNull(opened.identity).sequence))
                        } finally {
                            opened.rootKey?.fill(0)
                        }
                        check(isVaultSessionCurrent(token)) { "保险库会话已失效" }
                    }
                }
            }.onFailure { postError(localizeUiTextFor(getApplication(), "自动填充排除项保存失败：${it.message ?: "未知错误"}")) }
        }
    }

    /** Serialize a vault mutation with session invalidation: lock/switch cannot return mid-commit. */
    private fun saveAndPublishForSession(
        token: VaultSessionFence.Token,
        repository: VaultRepository,
        payload: VaultPayload,
        expectedSequence: Long,
    ): Boolean {
        val accepted = vaultSessionFence.runIfCurrent(token, _currentVault.value) {
            val credential = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
            val value = payload.copy(
                autofillExclusions = payload.autofillExclusions.merge(com.vault.autofill.AutofillExcludePref.snapshot(getApplication(), vaultName())),
            )
            credential.withRootKey(credential.identity) { repository.savePmvE(value, it, expectedSequence) }
            val sealed = sealPayload(value)
            _state.update { it.copy(payload = sealed, listIndex = VaultListIndex.from(sealed)) }
        }
        if (accepted) runCatching { performLocalBackup() }
        return accepted
    }

    /** Bind a merge snapshot to the authenticated on-disk payload and its exact commit sequence. */
    private fun authenticatedPayloadSequence(
        repository: VaultRepository,
        rootSession: VaultSessionCredential.RootKey,
        expectedPayload: VaultPayload,
    ): Long {
        val opened = rootSession.withRootKey(rootSession.identity) { repository.openPmvEWithRootKey(it) }
        try {
            check(VaultLogicalRevision.from(materializePayload(opened.payload)) ==
                VaultLogicalRevision.from(materializePayload(expectedPayload))) {
                localizeUiTextFor(getApplication(), "保险库在导入期间已变化，请重新导入")
            }
            return requireNotNull(opened.identity).sequence
        } finally {
            opened.rootKey?.fill(0)
        }
    }

    fun authorizeSensitiveExport(operation: String, uri: Uri) {
        require(operation in setOf("raw", "backup", "archive"))
        val token = captureVaultSession()
        check(_state.value.phase == Phase.UNLOCKED && hasSecuritySession()) { localizeUiTextFor(getApplication(), "请先验证当前主密码") }
        sensitiveExportGrant = SensitiveExportGrant(token.vaultName, token.generation, operation,
            uri.toString(), SystemClock.elapsedRealtime() + 30_000L)
    }

    private fun consumeSensitiveExportAuthorization(operation: String, uri: Uri): VaultSessionFence.Token? {
        val grant = sensitiveExportGrant
        sensitiveExportGrant = null
        if (grant == null || !grant.matches(_currentVault.value, captureVaultSession().generation,
                operation, uri.toString(), SystemClock.elapsedRealtime()) ||
            _state.value.phase != Phase.UNLOCKED || !hasSecuritySession()) return null
        return captureVaultSession()
    }

    /** 回到主页时立即清除敏感内容二次保护会话，再次查看敏感内容需重新验证。 */
    fun clearSecuritySession() {
        securitySessionUntilElapsed = 0L
    }

    fun pauseBackgroundWork() {
        remoteUpdatePaused = true
        remoteUpdateOperationGeneration++
        remoteUpdateJob?.cancel()
        remoteUpdateJob = null
        autoCloudSyncJob?.cancel()
        autoCloudSyncJob = null
        postUnlockJob?.cancel()
        postUnlockJob = null
        automaticLeakJob?.cancel()
        automaticLeakJob = null
        _state.update { it.copy(leakCheckRunning = false, leakCheckChecked = 0, leakCheckTotal = 0) }
    }

    fun refreshAutoCloudSyncSchedule() {
        restartAutoCloudSync()
    }

    private fun restartAutoCloudSync() {
        restartRemoteUpdateDetection()
        autoCloudSyncJob?.cancel()
        autoCloudSyncJob = null
        if (_state.value.phase != Phase.UNLOCKED) return
        autoCloudSyncJob = viewModelScope.launch {
            while (_state.value.phase == Phase.UNLOCKED) {
                runAutoCloudSyncIfDue()
                delay(60_000L)
            }
        }
    }

    private fun restartRemoteUpdateDetection() {
        remoteUpdateJob?.cancel()
        if (_state.value.phase != Phase.UNLOCKED) return
        remoteUpdatePaused = false
        reloadRemoteUpdateStates()
        remoteUpdateJob = viewModelScope.launch {
            while (_state.value.phase == Phase.UNLOCKED) {
                checkRemoteUpdates().join()
                delay(60_000L)
            }
        }
    }

    private fun reloadRemoteUpdateStates() {
        _remoteUpdateStates.value = listOf("drive", "webdav").associateWith {
            com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vaultName(), it)
        }
    }

    fun setRemoteUpdateDetection(target: String, enabled: Boolean) {
        if (target !in listOf("drive", "webdav") || _state.value.phase != Phase.UNLOCKED) return
        val state = com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vaultName(), target)
        com.vault.storage.RemoteUpdatePrefs.save(getApplication(), vaultName(), target,
            state.copy(enabled = enabled, pending = if (enabled) state.pending else "", detectedAt = if (enabled) state.detectedAt else 0))
        reloadRemoteUpdateStates()
        if (!enabled) RemoteUpdateNotifications.cancel(getApplication(), vaultName(), target)
        else checkRemoteUpdates(target)
    }

    fun snoozeRemoteUpdate(target: String) {
        RemoteUpdateNotifications.cancel(getApplication(), vaultName(), target)
    }

    private data class RemoteAssociation(val identity: String, val uri: Uri? = null, val config: WebDavConfig? = null)
    private fun remoteAssociation(target: String): RemoteAssociation? {
        if (_state.value.phase != Phase.UNLOCKED) return null
        if (target == "drive") {
            val prefs = com.vault.security.SecurePreferences.get(getApplication(), "cloud_sync")
            val value = prefs.getString("uri_${AutoCloudSyncPrefs.suffix(cloudVaultKey())}", "").orEmpty()
            return value.takeIf { it.isNotBlank() }?.let { RemoteAssociation(it, Uri.parse(it)) }
        }
        val config = loadCloudConfig() ?: return null
        // Keep credential material out of persisted association keys.
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(config.toString().toByteArray()).joinToString("") { "%02x".format(it) }
        return RemoteAssociation(hash, config = config)
    }

    fun checkRemoteUpdates(target: String? = null, force: Boolean = false): Job = viewModelScope.launch {
        if (remoteUpdatePaused || !remoteUpdateMutex.tryLock()) return@launch
        try {
            val token = captureVaultSession()
            val vault = vaultName()
            val cloudPrefs = com.vault.security.SecurePreferences.get(getApplication(), "cloud_sync")
            if (!cloudPrefs.getBoolean("enabled_${AutoCloudSyncPrefs.suffix(cloudVaultKey())}", false)) {
                listOf("drive", "webdav").forEach { RemoteUpdateNotifications.cancel(getApplication(), vault, it) }
                return@launch
            }
            for (key in listOf("drive", "webdav").filter { target == null || it == target }) {
                if (_state.value.phase != Phase.UNLOCKED || !isVaultSessionCurrent(token) ||
                    _state.value.cloudSyncRunning || _cloudSyncState.value.phase == CloudSyncPhase.RUNNING ||
                    cloudDiskOperationJob?.isActive == true || webDavOperationJob?.isActive == true) return@launch
                val association = remoteAssociation(key)
                if (association == null) {
                    com.vault.storage.RemoteUpdatePrefs.associate(getApplication(), vault, key, "")
                    RemoteUpdateNotifications.cancel(getApplication(), vault, key)
                    continue
                }
                com.vault.storage.RemoteUpdatePrefs.associate(getApplication(), vault, key, association.identity)
                val state = com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vault, key)
                if (state.pending.isBlank()) RemoteUpdateNotifications.cancel(getApplication(), vault, key)
                val now = System.currentTimeMillis()
                if (!state.enabled || (!force && now - state.lastCheckedAt in 0 until 300_000L)) continue
                com.vault.storage.RemoteUpdatePrefs.save(getApplication(), vault, key, state.copy(lastCheckedAt = now))
                val operationGeneration = remoteUpdateOperationGeneration
                val version = runCatching { withContext(Dispatchers.IO) {
                    val metadata = if (key == "drive") CloudTreeStorage.metadata(getApplication(), association.uri!!).toCloudFileVersion()
                        else WebDavCloud.metadataOnly(association.config!!).toCloudFileVersion()
                    com.vault.storage.RemoteUpdatePolicy.version(metadata)
                } }.getOrNull()
                if (!isVaultSessionCurrent(token) || _state.value.phase != Phase.UNLOCKED ||
                    !cloudPrefs.getBoolean("enabled_${AutoCloudSyncPrefs.suffix(cloudVaultKey())}", false) ||
                    remoteAssociation(key)?.identity != association.identity || !com.vault.storage.RemoteUpdatePolicy.mayAcceptObservation(operationGeneration, remoteUpdateOperationGeneration, remoteUpdatePaused) || _state.value.cloudSyncRunning ||
                    _cloudSyncState.value.phase == CloudSyncPhase.RUNNING) continue
                val current = com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vault, key)
                if (!current.enabled || version == null) continue
                val observation = com.vault.storage.RemoteUpdatePolicy.observe(current, version, now)
                if (observation.state.pending.isNotBlank() && observation.state.pending != current.pending) cloudPreviewCache.invalidate(key)
                com.vault.storage.RemoteUpdatePrefs.save(getApplication(), vault, key, observation.state)
                if (observation.state.pending.isBlank()) RemoteUpdateNotifications.cancel(getApplication(), vault, key)
                if (observation.notify) RemoteUpdateNotifications.show(getApplication(), vault, key, now)
            }
            if (isVaultSessionCurrent(token) && _state.value.phase == Phase.UNLOCKED) reloadRemoteUpdateStates()
        } finally { remoteUpdateMutex.unlock() }
    }

    private fun rememberRemoteUpdateProof(target: String, association: String, metadata: CloudFileVersion, consumedMetadata: CloudFileVersion? = null, consumedVersion: String = "") {
        val version = com.vault.storage.RemoteUpdatePolicy.version(metadata) ?: return
        remoteUpdateProofs[target] = RemoteUpdateProof(captureVaultSession(), association, version,
            consumedVersion.ifBlank { consumedMetadata?.let(com.vault.storage.RemoteUpdatePolicy::version).orEmpty() })
    }

    private fun acknowledgeRemoteUpdate(target: String) {
        val proof = remoteUpdateProofs.remove(target) ?: return
        if (_state.value.phase != Phase.UNLOCKED || !isVaultSessionCurrent(proof.session) ||
            remoteAssociation(target)?.identity != proof.association) return
        val vault = vaultName()
        com.vault.storage.RemoteUpdatePrefs.associate(getApplication(), vault, target, proof.association)
        val state = com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vault, target)
        val acknowledged = com.vault.storage.RemoteUpdatePolicy.acknowledge(state, proof.version, proof.consumedVersion)
        com.vault.storage.RemoteUpdatePrefs.save(getApplication(), vault, target, acknowledged)
        reloadRemoteUpdateStates()
        if (acknowledged.pending.isBlank()) RemoteUpdateNotifications.cancel(getApplication(), vault, target)
    }

    private suspend fun runAutoCloudSyncIfDue() {
        val app = getApplication<Application>()
        val payload = _state.value.payload ?: return
        val vaultId = payload.syncMeta.deviceId.ifBlank { _currentVault.value.orEmpty() }

        val cloudPrefs = com.vault.security.SecurePreferences.get(app, "cloud_sync")

        val suffix = AutoCloudSyncPrefs.suffix(vaultId)
        val now = System.currentTimeMillis()

        for (target in listOf("drive", "webdav")) {
            if (_state.value.cloudSyncRunning || _cloudSyncState.value.phase == CloudSyncPhase.RUNNING) return
            // 读取与到期判定统一由 AutoCloudSyncPrefs 负责，避免此处再写一份周期逻辑。
            val settings = AutoCloudSyncPrefs.loadTarget(app, vaultId, target)
            if (!AutoCloudSyncPrefs.isDue(settings, now)) continue

            AutoCloudSyncPrefs.clearFailure(app, vaultId)

            val success = when (target) {
                "drive" -> {
                    val uri = cloudPrefs.getString("uri_$suffix", "").orEmpty()
                    if (uri.isBlank()) {
                        cloudPrefs.edit().putBoolean(AutoCloudSyncPrefs.key(vaultId, "drive_enabled"), false).apply()
                        AutoCloudSyncPrefs.skipped(app, vaultId, "云端硬盘未关联，自动同步已暂停")
                        continue
                    }
                    suspendCancellableCoroutine<Boolean> { continuation ->
                        syncCloudVault(Uri.parse(uri), notifyUser = false) {
                            if (continuation.isActive) continuation.resume(it)
                        }
                    }
                }
                "webdav" -> {
                    val connectivity = app.getSystemService(ConnectivityManager::class.java)
                    val network = connectivity?.activeNetwork
                    val capabilities = network?.let(connectivity::getNetworkCapabilities)
                    if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) != true) {
                        AutoCloudSyncPrefs.skipped(app, vaultId, "等待网络连接")
                        continue
                    }
                    if (loadCloudConfig() == null) {
                        cloudPrefs.edit().putBoolean(AutoCloudSyncPrefs.key(vaultId, "webdav_enabled"), false).apply()
                        AutoCloudSyncPrefs.skipped(app, vaultId, "WebDAV未关联，自动同步已暂停")
                        continue
                    }
                    suspendCancellableCoroutine<Boolean> { continuation ->
                        syncWebDav(notifyUser = false) { if (continuation.isActive) continuation.resume(it) }
                    }
                }
                else -> false
            }
            if (!success) {
                if (_state.value.cloudSyncRunning || _cloudSyncState.value.phase == CloudSyncPhase.RUNNING) {
                    AutoCloudSyncPrefs.skipped(app, vaultId, localizeUiTextFor(app, "同步正在进行，本次自动同步已跳过"), target)
                    continue
                }
                val reason = AutoCloudSyncPrefs.loadSyncStatus(app, vaultId).error
                    .ifBlank { localizeUiTextFor(app, "自动同步失败") }
                val severeMarkers = listOf(
                    localizeUiTextFor(app, "已删除"), localizeUiTextFor(app, "不属于当前保险库"),
                    localizeUiTextFor(app, "密码"), localizeUiTextFor(app, "损坏"),
                    localizeUiTextFor(app, "校验失败"), "deleted", "wrong vault", "password", "corrupt", "verification failed",
                )
                val normalizedReason = reason.lowercase(java.util.Locale.ROOT)
                val severe = severeMarkers.any { normalizedReason.contains(it.lowercase(java.util.Locale.ROOT)) }
                val failures = AutoCloudSyncPrefs.failure(app, vaultId,
                    "${localizeUiTextFor(app, "自动同步失败")}: $reason", target)
                if (severe || failures >= 3) {
                    AutoCloudSyncPrefs.save(app, vaultId, false, target, settings.intervalMinutes)
                    AutoCloudSyncPrefs.skipped(app, vaultId, "${localizeUiTextFor(app, "自动同步已暂停")}: $reason", target)
                    emitError(getApplication<Application>().getString(R.string.viewmodel_auto_sync_paused, target))
                }
            }
        }
    }

    fun autoLock() = lock()

    // --- 条目操作 ---

    fun addEntry(entry: Entry) = mutate(
        checkEntryIds = setOf(entry.id),
        successMessage = { _, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_added, entry.feedbackTitle()) },
    ) { VaultOps.add(it, entry) }
    fun updateEntry(entry: Entry) = mutate(
        checkEntryIds = setOf(entry.id),
        successMessage = { _, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_saved, entry.feedbackTitle()) },
    ) { VaultOps.update(it, entry) }
    fun deleteEntry(id: String) = mutate(
        metaOnly = true,
        successMessage = { old, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_deleted_entry, old.entryTitle(id)) },
    ) { VaultOps.delete(it, id) }
    fun deleteEntries(ids: Set<String>) = mutate(
        metaOnly = true,
        successMessage = { _, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_deleted_count, ids.size) },
    ) {
        VaultOps.deleteMany(it, ids)
    }
    fun updateEntryTags(ids: Set<String>, tags: List<String>, mode: String) =
        mutate(
            successMessage = { _, _ ->
                val label = getApplication<Application>().getString(
                    if (mode == "move") R.string.viewmodel_mutation_move else R.string.viewmodel_mutation_add,
                )
                getApplication<Application>().getString(R.string.viewmodel_mutation_tag, ids.size, label, tags.joinToString(", "))
            },
        ) {
            VaultOps.updateEntryTags(it, ids, tags, mode)
        }
    fun restoreEntry(id: String) = mutate(
        metaOnly = true,
        checkEntryIds = setOf(id),
        successMessage = { old, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_restored_entry, old.entryTitle(id)) },
    ) { VaultOps.restore(it, id) }
    fun restoreEntries(ids: Set<String>) = mutate(
        metaOnly = true,
        checkEntryIds = ids,
        successMessage = { _, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_restored_count, ids.size) },
    ) {
        VaultOps.restoreMany(it, ids)
    }
    fun purgeEntry(id: String) = mutate(
        metaOnly = true,
        successMessage = { old, _ -> "已彻底删除「${old.entryTitle(id)}」" },
    ) { VaultOps.purge(it, id) }
    fun purgeEntries(ids: Set<String>) = mutate(
        metaOnly = true,
        successMessage = { _, _ -> "已彻底删除 ${ids.size} 条" },
    ) {
        VaultOps.purgeMany(it, ids)
    }

    /**
     * 点击“清空回收站”后立即物理回收空间：
     * PMVE 追加写产生的历史 Block 成为垃圾，直接压缩（不受 AutoCompactPolicy
     * 门槛限制），并记录压缩进度保持维护统计一致。
     * 仅在批量清空时触发，单条/批量彻底删除不压缩，避免逐条删除导致整库反复重写。
     */
    private suspend fun compactAfterTrashPurge(oldPayload: VaultPayload, newPayload: VaultPayload) {
        val r = repo() ?: return
        if (!r.isPmvE()) return
        val purgedIds = (oldPayload.entries + oldPayload.trash).map { it.id }.toSet() -
            (newPayload.entries + newPayload.trash).map { it.id }.toSet()
        if (purgedIds.isEmpty()) return
        val name = _currentVault.value ?: return
        val rootSession = _state.value.rootKey ?: return
        val context = getApplication<Application>()
        withContext(Dispatchers.IO) {
            runCatching {
                rootSession.withRootKey(rootSession.identity) { key ->
                    val (revision, _) = r.pmveMaintenanceStats(key)
                    r.compactPmvE(key)
                    VaultMaintenancePref.recordCompact(context, name, revision, r.vaultFileSize())
                }
            }
        }
    }

    /**
     * 解锁时清理过期回收站后立即物理回收空间：
     * PMVE 直接压缩（不受 AutoCompactPolicy 门槛限制），并记录压缩进度，
     * 避免随后的自动压缩基于过期统计再次重写同一文件。
     * 返回是否执行了压缩。
     */
    private suspend fun compactAfterExpiredPurge(repository: VaultRepository): Boolean {
        val rootSession = _state.value.rootKey ?: return false
        val name = _currentVault.value ?: return false
        val context = getApplication<Application>()
        return withContext(Dispatchers.IO) {
            runCatching {
                rootSession.withRootKey(rootSession.identity) { key ->
                    val (revision, _) = repository.pmveMaintenanceStats(key)
                    repository.compactPmvE(key)
                    VaultMaintenancePref.recordCompact(context, name, revision, repository.vaultFileSize())
                }
            }.isSuccess
        }
    }

    /**
     * 媒体提交后机会式压缩：文件相对上次压缩增长超过阈值且距上次压缩超过最小间隔时，
     * 立即压缩回收追加写产生的死空间，避免“添加 55MB 后显示 109MB”的文件虚胖。
     */
    private suspend fun compactAfterLargeMediaCommit(repository: VaultRepository) {
        if (!repository.isPmvE()) return
        val name = _currentVault.value ?: return
        val rootSession = _state.value.rootKey ?: return
        val context = getApplication<Application>()
        if (System.currentTimeMillis() - VaultMaintenancePref.lastCompactAt(context, name) < 10 * 60 * 1000L) return
        val (revision, size) = rootSession.withRootKey(rootSession.identity) { key ->
            repository.pmveMaintenanceStats(key)
        }
        if (size - VaultMaintenancePref.lastCompactSize(context, name) < 32L * 1024 * 1024) return
        withContext(Dispatchers.IO) {
            runCatching {
                rootSession.withRootKey(rootSession.identity) { key -> repository.compactPmvE(key) }
                VaultMaintenancePref.recordCompact(context, name, revision, repository.vaultFileSize())
            }
        }
    }
    fun purgeAllTrash() = mutate(
        metaOnly = true,
        successMessage = { old, _ -> "已清空回收站 ${old.entries.count { it.deletedAt != null }} 条" },
        afterCommit = { old, new -> compactAfterTrashPurge(old, new) },
    ) {
        VaultOps.purgeAll(it)
    }
    fun renameTag(oldTag: String, newTag: String) {
        var affected = 0
        mutate(
            successMessage = { _, _ -> getApplication<Application>().getString(R.string.viewmodel_mutation_renamed_count, affected) },
        ) {
            val (p, n) = VaultOps.renameTag(it, oldTag, newTag)
            affected = n
            p
        }
        // 若用户调整过标签顺序，重命名后保留原位置（把旧名替换为新名）
        if (TagOrderPref.order.value.contains(oldTag)) {
            val swapped = TagOrderPref.order.value.map { if (it == oldTag) newTag else it }
            TagOrderPref.setOrder(getApplication(), swapped)
            _state.update { it.withPayload(it.payload) }
        }
    }

    /** 在自定义标签顺序中把 [tag] 直接移动到 [toIndex]（长按拖拽多位置落位）。 */
    fun reorderTag(tag: String, toIndex: Int) {
        val current = TagOrderPref.order.value
        val defaultOrder = _state.value.listIndex.tagsByType.values.flatten().distinct()
        val base = if (current.isNotEmpty()) current else defaultOrder
        val i = base.indexOf(tag)
        if (i < 0) return
        val j = toIndex.coerceIn(0, base.size - 1)
        if (j == i) return
        val reordered = base.toMutableList().apply { add(j, removeAt(i)) }
        TagOrderPref.setOrder(getApplication(), reordered)
        _state.update { it.withPayload(it.payload) }
    }

    fun changePassword(
        newPassword: String,
        recoverySecret: ByteArray,
        weakPasswordConfirmed: Boolean = false,
        onResult: (Boolean) -> Unit = {},
    ) = viewModelScope.launch {
        val recoveryCopy = recoverySecret.copyOf()
        recoverySecret.fill(0)
        val newPasswordUtf8 = newPassword.encodeToByteArray()
        var ownsBusy = false
        var operationToken = captureVaultSession()
        var opened: com.vault.storage.VaultUnlockResult? = null
        try {
            if (_state.value.busy || !acceptsNewMasterPassword(newPassword, weakPasswordConfirmed)) {
                onResult(false)
                return@launch
            }
            val r = repo() ?: run { onResult(false); return@launch }
            val password = _state.value.password ?: run { onResult(false); return@launch }
            ownsBusy = true
            _state.update { it.copy(busy = true) }
            val cloudConfig = loadCloudConfig()
            // Stop writers before replacing the encryption epoch. Late results may not republish.
            val writers = vaultSessionJobs.toList() + listOfNotNull(cloudDiskOperationJob, webDavOperationJob, autoCloudSyncJob, postUnlockJob, automaticLeakJob)
            pauseBackgroundWork()
            stopLanHost()
            invalidateVaultSession()
            val token = captureVaultSession()
            operationToken = token
            writers.forEach { it.join() }
            requireVaultSessionCurrent(token)
            opened = password.useBytesSuspend { old ->
                withContext(Dispatchers.IO) {
                    r.changePmvEPassword(old, newPasswordUtf8, recoveryCopy) { requireVaultSessionCurrent(token) }.also { opened = it }
                }
            }
            requireVaultSessionCurrent(token)
            val result = requireNotNull(opened)
            replacePmvESessionRoot(requireNotNull(result.rootKey), requireNotNull(result.identity))
            val previous = _state.value.credential
            val retainedKey = requireNotNull(previous?.sessionKey())
            _state.update { it.withPayload(sealPayload(result.payload)).copy(
                credential = VaultSessionCredential.Compound(VaultSessionCredential.Password(newPasswordUtf8), retainedKey),
                busy = false,
            ) }
            previous?.sessionPassword()?.close()
            biometric?.clear()
            cloudConfig?.let { config -> runCatching { saveCloudConfig(config) }.onFailure {
                emitError(getApplication<Application>().getString(R.string.cloud_rotation_credentials_failed))
            } }
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_password_updated))
            onResult(true)
        } catch (error: Exception) {
            if (error is kotlinx.coroutines.CancellationException) throw error
            emitError(getApplication<Application>().getString(R.string.viewmodel_password_change_failed,
                error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            onResult(false)
        } finally {
            opened?.rootKey?.fill(0)
            recoveryCopy.fill(0)
            newPasswordUtf8.fill(0)
            if (ownsBusy && isVaultSessionCurrent(operationToken)) _state.update { it.copy(busy = false) }
        }
    }

    // --- 搜索 ---

    fun setQuery(q: String) = _state.update { it.copy(query = q) }
    fun setTagFilter(tag: String?) = _state.update { it.copy(tagFilter = tag) }
    fun setTypeFilter(type: String?) = _state.update { it.copy(typeFilter = type, tagFilter = null) }
    fun clearListFilters() = _state.update { it.copy(query = "", tagFilter = null, typeFilter = null) }

    fun setExternalActionInProgress(active: Boolean) {
        _state.update { it.copy(isExternalActionInProgress = active) }
    }

    // --- 备份 ---

    fun backupContainsSyncablePasskeys(): Boolean =
        _state.value.payload?.let(::materializePayload)?.entries?.let(PasskeyBackupTransfer::containsSyncable) == true

    fun exportBackup(uri: Uri, exportPassword: String) = viewModelScope.launch {
        if (consumeSensitiveExportAuthorization("backup", uri) == null) {
            emitError(localizeUiTextFor(getApplication(), "导出授权已过期，请重新验证主密码")); return@launch
        }
        val r = repo() ?: return@launch
        val payload = _state.value.payload?.let(::materializePayload) ?: return@launch
        SyncForegroundService.beginTask(
            getApplication(),
            BACKUP_EXPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "加密备份导出"),
            localizeUiTextFor(getApplication(), "正在导出加密备份…"),
        )
        val syncable = PasskeyBackupTransfer.containsSyncable(payload.entries)
        if (syncable && !BackupPasswordPolicy.isStrong(exportPassword)) {
            emitError(localizeUiTextFor(getApplication(), "备份包含 Passkey，请使用至少 14 位且包含三类字符的强导出口令"))
            return@launch
        }
        // 备份保留全部 entries（含墓碑）—— 用于多端同步将删除事件一并带过去；
        // 同时携带 syncMeta 让对端能识别"是否同一份库"
        runCatching {
            withContext(Dispatchers.IO) {
                BackupCodec.exportTo(
                    getApplication(),
                    uri,
                    payload.entries,
                    exportPassword,
                    payload.syncMeta,
                    payload.purgeTombstones,
                    payload.autofillExclusions,
                    payload.deletionBaseline,
                )
            }
        }.onSuccess {
            val (backedUpEntries, markedCount) = PasskeyBackupTransfer.markBackedUp(payload.entries)
            if (markedCount > 0) {
                val updated = payload.copy(entries = backedUpEntries)
                runCatching { withContext(Dispatchers.IO) { saveCurrent(r, updated) } }
                    .onSuccess { _state.update { it.withPayload(sealPayload(updated)) } }
                    .onFailure {
                        emitError(localizeUiTextFor(getApplication(), "备份已写入，但备份状态未能保存：${it.message}"))
                    }
            }
            val aliveCount = payload.entries.count { it.deletedAt == null }
            SyncForegroundService.succeedTask(
                getApplication(),
                BACKUP_EXPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "加密备份已导出 $aliveCount 条"),
            )
            emitInfo(localizeUiTextFor(getApplication(), "加密备份已导出 ${aliveCount} 条"))
}.onFailure {
            SyncForegroundService.failTask(
                getApplication(),
                BACKUP_EXPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "备份失败：${it.message}"),
            )
            emitError("备份失败：${it.message}")
        }
    }

    /**
     * 加密备份（.pmbak）导入：走 Sync v2 LWW 合并（按 id + updatedAt）。
     *
     * 谱系护栏：incoming.syncMeta.deviceId 必须与本地相同才静默合并；不同 / 缺失 →
     * 暂停并等 UI 确认（防止跨账户误合并）。同秒并发冲突自动 KEEP_BOTH。
     */
    fun importBackup(
        activity: FragmentActivity?,
        uri: Uri,
        importPassword: String,
    ) = viewModelScope.launch {
        val sessionToken = captureVaultSession()
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        SyncForegroundService.beginTask(
            getApplication(),
            BACKUP_IMPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "加密备份导入"),
            localizeUiTextFor(getApplication(), "正在导入加密备份…"),
        )
        val decoded = runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(sessionToken)
                BackupCodec.importFrom(getApplication(), uri, importPassword)
            }
        }.getOrElse { error ->
            val msg = when (error) {
                is VaultCrypto.DecryptError -> "备份口令错误或文件已损坏"
                else -> error.message ?: "导入失败"
            }
            emitError(msg)
            return@launch
        }
        val incoming = decoded
        requireVaultSessionCurrent(sessionToken)
        if (_state.value.phase != Phase.UNLOCKED || _currentVault.value != sessionToken.vaultName) return@launch
        val latestPayload = _state.value.payload?.let(::materializePayload) ?: return@launch
        runCatching {
            val localLineage = latestPayload.syncMeta.deviceId
            val incomingLineage = incoming.syncMeta.deviceId
            val sameLineage = localLineage.isNotEmpty() && localLineage == incomingLineage
            if (sameLineage) {
                applyBackupMerge(latestPayload, incoming.entries, incoming.purgeTombstones, incoming.exportEpoch, r, incomingExclusions = incoming.autofillExclusions, incomingDeletionBaseline = incoming.deletionBaseline, sessionToken = sessionToken)
                SyncForegroundService.succeedTask(
                    getApplication(),
                    BACKUP_IMPORT_TASK_ID,
                    localizeUiTextFor(getApplication(), "加密备份已导入并合并"),
                )
            } else {
                _pendingCrossAccountImport.value = PendingCrossAccountImport(
                    incomingEntries = incoming.entries,
                    incomingPurgeTombstones = incoming.purgeTombstones,
                    incomingDeletionBaseline = incoming.deletionBaseline,
                    incomingExclusions = incoming.autofillExclusions,
                    incomingDeviceId = incomingLineage,
                    incomingExportEpoch = incoming.exportEpoch,
                    sourceLabel = getApplication<Application>().getString(R.string.viewmodel_source_backup),
                    targetVaultName = _currentVault.value,
                    targetSessionGeneration = sessionToken.generation,
                )
                SyncForegroundService.succeedTask(
                    getApplication(),
                    BACKUP_IMPORT_TASK_ID,
                    localizeUiTextFor(getApplication(), "已读取加密备份，等待确认合并"),
                )
            }
        }.onFailure {
            val msg = when (it) {
                is VaultCrypto.DecryptError -> getApplication<Application>().getString(R.string.viewmodel_backup_import_invalid)
                else -> getApplication<Application>().getString(
                    R.string.viewmodel_backup_import_failed,
                    it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                )
            }
            SyncForegroundService.failTask(
                getApplication(),
                BACKUP_IMPORT_TASK_ID,
                localizeUiTextFor(getApplication(), msg),
            )
            emitError(msg)
        }
    }

    fun startSync(serverUrl: String, pin: String) {
        val sessionToken = captureVaultSession()
        val job = viewModelScope.launch {
        if (!isVaultSessionCurrent(sessionToken)) return@launch
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        _syncResult.value = null
        _state.update { it.copy(syncRunning = true) }
        SyncForegroundService.beginTask(
            getApplication(),
            LAN_SYNC_TASK_ID,
            BackgroundTaskKind.CLOUD_SYNC,
            localizeUiTextFor(getApplication(), "局域网同步"),
            localizeUiTextFor(getApplication(), "正在连接并验证设备…"),
        )
        updateLanSyncProgress(LAN_SYNC_TASK_ID, localizeUiTextFor(getApplication(), "正在连接并验证设备…"))
        runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(sessionToken)
                // 设备授权必须先于任何数据交换：主机在拉取前校验设备是否已授权，
                // 否则会返回 403「设备尚未完成授权认证」。
                val syncDevice = if (r.isPmvE()) {
                    VaultDeviceIdentityStore(getApplication(), _currentVault.value.orEmpty()).loadOrCreate()
                } else null
                if (syncDevice != null) {
                    try {
                        val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
                        SyncClient.authenticateDevice(serverUrl, pin, rootSession.identity.vaultId, syncDevice, "read")
                        SyncClient.authenticateDevice(serverUrl, pin, rootSession.identity.vaultId, syncDevice, "write")
                    } finally {
                        syncDevice.close()
                    }
                }
                // 1. 分块流式拉取远程 .pmv 到临时文件（避免大库载入内存）
                val remoteFile = newSyncTempFile()
                SyncClient.pullToFile(
                    serverUrl,
                    pin,
                    remoteFile,
                    onProgress = { transferred, total ->
                        if (isVaultSessionCurrent(sessionToken)) {
                            updateLanSyncProgress(LAN_SYNC_TASK_ID, "正在接收另一台设备的数据…", transferred, total)
                        }
                    },
                    onIntegrityRetry = { attempt, maxAttempts ->
                        if (isVaultSessionCurrent(sessionToken)) {
                            updateLanSyncProgress(LAN_SYNC_TASK_ID, "数据检查未通过，正在自动重试 $attempt/$maxAttempts…")
                        }
                    },
                )
                requireVaultSessionCurrent(sessionToken)
                startLanSyncKeepAlive(serverUrl, pin)

                // PMVE uses only Store-authenticated File identities and Commit ancestry. It never
                // PMVE 使用 Store 认证的文件身份与提交谱系，不做整库字节级合并。
                if (r.isPmvE()) {
                    return@withContext syncPmvELan(r, payload, remoteFile, serverUrl, pin, sessionToken)
                }

                error("旧格式局域网同步已移除，仅支持 PMVE")
            }
        }.onSuccess { result ->
            if (!isVaultSessionCurrent(sessionToken)) {
                result.clearReplacementKey()
                return@onSuccess
            }
            val newPayload = result.payload
            val stats = result.stats
            // 这里已经不在外层 runCatching 的保护范围内（它在 .onSuccess 回调里执行），
            // 而块内有 replacePmvESessionRoot 的三处 error(...) 与 sealPayload
            // （会关掉旧条目密封区）。一旦抛出就会穿出协程无人接管，直接崩在界面上。
            // 改为自行捕获：发布失败按「未发布」处理，走下面的 published=false 分支。
            val published = try {
                vaultSessionFence.runIfCurrent(sessionToken, _currentVault.value) {
                    if (result.replacementRootKey != null && result.replacementIdentity != null) {
                        replacePmvESessionRoot(result.replacementRootKey, result.replacementIdentity)
                    }
                    _state.update { it.withPayload(sealPayload(newPayload)).copy(syncRunning = false) }
                    _syncResult.value = SyncResultState(
                        stats = stats,
                        source = getApplication<Application>().getString(R.string.viewmodel_source_lan),
                        localCount = payload.entries.size,
                        mergedCount = newPayload.entries.size,
                        uploaded = result.uploaded,
                        verified = result.verified,
                        remoteBytes = result.remoteBytes,
                        lineage = result.lineage,
                    )
                }
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Throwable) {
                android.util.Log.w(
                    "FAEVault",
                    localizeUiTextFor(getApplication(), "同步结果发布失败，已保留本地数据不动") +
                        ": ${error.message}",
                    error,
                )
                false
            } finally {
                result.clearReplacementKey()
            }
            if (!published) return@onSuccess
            markPasskeysBackedUpAfterExternalCopy()
            clearLanSyncProgress()
            SyncForegroundService.succeedTask(getApplication(), LAN_SYNC_TASK_ID, localizeUiTextFor(getApplication(), "局域网同步已完成"))
            if (result.keyConvergence != KeyConvergenceKind.NONE) {
                _keyConvergedNotice.value = KeyConvergedNotice(
                    result.keyConvergence,
                    keyConvergedMessage(result.keyConvergence),
                )
            } else {
                emitInfo(getApplication<Application>().getString(R.string.viewmodel_lan_sync_completed))
            }
        }.onFailure {
            if (it is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                // 取消也要清忙碌位：它有两条门禁含义，留着会让空闲超时不再锁库。
                _state.update { it.copy(syncRunning = false) }
                return@onFailure
            }
            cancelLanSyncSession()
            SyncForegroundService.failTask(getApplication(), LAN_SYNC_TASK_ID, localizeUiTextFor(getApplication(), lanSyncErrorMessage(it)))
            _state.update { it.copy(syncRunning = false) }
            clearLanSyncProgress()
            emitError(lanSyncErrorMessage(it))
        }
        }
        lanSyncJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            vaultSessionJobs.remove(job)
            if (lanSyncJob === job) lanSyncJob = null
        }
    }

    private fun lanHostReceiveErrorMessage(error: SyncServerHost.HostError): String = when {
        error.message.contains("不是同一份") ->
            getApplication<Application>().getString(R.string.viewmodel_lan_host_sync_reject_same)
        error.message.contains("格式") ->
            getApplication<Application>().getString(R.string.viewmodel_lan_host_sync_reject_format)
        error.message.contains("认证失败") ->
            getApplication<Application>().getString(R.string.viewmodel_lan_host_sync_reject_auth)
        error.message.contains("谱系") || error.message.contains("身份") ->
            getApplication<Application>().getString(R.string.viewmodel_lan_host_sync_reject_lineage)
        else -> getApplication<Application>().getString(
            R.string.viewmodel_lan_host_sync_receive_failed,
            error.message,
        )
    }

    private fun lanSyncErrorMessage(error: Throwable): String {
        val raw = generateSequence(error as Throwable?) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
        val lower = raw.lowercase()
        return when {
            // 配对/票据必须排在 403 之前：传输站对旧二维码、旧 PIN、错配 ticket 一律回 403
            // （PIN_ROTATE_INTERVAL_MS = 120s，配对成功即轮换），按状态码归类会把「重新
            // 扫码」误报成「对方尚未授权本设备」，把用户引去主机点允许同步。
            "pin" in lower || "配对" in raw || "票据" in raw || "连接地址已失效" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_pairing)
            "不是同一份" in raw || "不属于当前" in raw || "不属于本保险库" in raw ||
                "保险库 id 不一致" in lower ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_same_vault)
            "格式" in raw && ("不一致" in raw || "旧格式" in raw) ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_format)
            // 设备未授权要早于下面的「认证失败」：设备授权 403 的报文含「设备未授权或已撤销」，
            // 若让裸「认证失败」先命中，会把设备授权问题说成保险库密钥认证问题。
            "设备尚未" in raw || "未完成授权" in raw || "设备未授权" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_unauthorized)
            "身份认证失败" in raw || "文件认证失败" in raw || "认证失败" in raw || error is VaultCrypto.DecryptError ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_auth)
            "谱系" in raw || "identity" in lower || "签名" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_lineage)
            // 锁定与「等待确认」是两回事，且锁定态同样会用 423 上报
            // （HostError(423, "PMVE 会话已锁定")），必须先判锁定，否则会被下面的
            // 等待确认文案吞掉、给出「点一下允许」这种无效指引。
            "已锁定" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_locked)
            "http 423" in lower || "等待主机确认" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_pending)
            error is SyncClient.IntegrityException || "不完整" in raw || "校验" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_integrity)
            error.isLanReachabilityFailure() ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_unreachable)
            "timeout" in lower || "timed out" in lower || "超时" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_sync_error_timeout)
            // 不按 409 归类：两个服务端发出的 409 只有谱系不同、远端 PMVE 认证失败、
            // 格式不一致这几种，都已被上面的 same_vault / auth / format 档按正文接住；
            // 真落到这里的未知 409 会走下面的 SyncException 兜底，把原始原因透出来。
            error is SyncClient.SyncException ->
                getApplication<Application>().getString(
                    R.string.viewmodel_sync_error_failed,
                    raw.substringAfter('：', raw).ifBlank { getApplication<Application>().getString(R.string.viewmodel_unknown_error) },
                )
            else -> getApplication<Application>().getString(
                R.string.viewmodel_sync_error_unknown,
                raw.ifBlank { error.javaClass.simpleName },
            )
        }
    }

    private fun Throwable.isLanReachabilityFailure(): Boolean =
        generateSequence(this as Throwable?) { it.cause }.any {
            it is java.net.ConnectException ||
                it is java.net.NoRouteToHostException ||
                it is java.net.SocketTimeoutException ||
                it is java.net.UnknownHostException
        }

    /** 用户在跨账户合并确认弹窗里点了"仍然合并"。 */
    fun confirmCrossAccountImport() = viewModelScope.launch {
        val pending = _pendingCrossAccountImport.value ?: return@launch
        _pendingCrossAccountImport.value = null
        // 复核目标库：待确认导入是为某个库创建的，切库后不得把它并到别的库（H-10）。
        if (pending.targetVaultName != _currentVault.value || pending.targetSessionGeneration != captureVaultSession().generation || _state.value.phase != Phase.UNLOCKED) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_cross_account_import_vault_changed))
            return@launch
        }
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        val token = captureVaultSession()
        applyBackupMerge(
            payload,
            pending.incomingEntries,
            pending.incomingPurgeTombstones,
            pending.incomingExportEpoch,
            r,
            emitSummary = true,
            incomingExclusions = pending.incomingExclusions,
            incomingDeletionBaseline = pending.incomingDeletionBaseline,
            sessionToken = token,
        )
    }

    private suspend fun applyBackupMerge(
        payload: VaultPayload,
        incoming: List<Entry>,
        incomingPurgeTombstones: Map<String, Double>,
        incomingExportEpoch: Double?,
        r: VaultRepository,
        emitSummary: Boolean = true,
        incomingExclusions: com.vault.model.AutofillExclusions = com.vault.model.AutofillExclusions(),
        incomingDeletionBaseline: com.vault.model.DeletionBaseline = com.vault.model.DeletionBaseline(),
        sessionToken: VaultSessionFence.Token = captureVaultSession(),
    ): Pair<VaultPayload, VaultOps.LwwMergeStats> {
        requireVaultSessionCurrent(sessionToken)
        val latest = _state.value.payload?.let(::materializePayload)
            ?: error(localizeUiTextFor(getApplication(), "保险库会话已失效"))
        val rootSession = _state.value.credential.sessionRootKey()
            ?: error(localizeUiTextFor(getApplication(), "保险库身份已失效"))
        val expectedSequence = withContext(Dispatchers.IO) {
            authenticatedPayloadSequence(r, rootSession, latest)
        }
        requireVaultSessionCurrent(sessionToken)
        require(latest.syncMeta.deviceId == payload.syncMeta.deviceId) {
            localizeUiTextFor(getApplication(), "保险库在导入期间已变化，请重新导入")
        }
        val (newPayload, stats) = VaultOps.mergeLww(
            latest,
            incoming,
            incomingExportEpoch = incomingExportEpoch,
            incomingPurgeTombstones = incomingPurgeTombstones,
            incomingExclusions = incomingExclusions,
            incomingDeletionBaseline = incomingDeletionBaseline,
        )
        requireVaultSessionCurrent(sessionToken)
        val committed = withContext(Dispatchers.IO) { saveAndPublishForSession(sessionToken, r, newPayload, expectedSequence) }
        check(committed) { "保险库会话已失效" }
        if (emitSummary) {
            emitInfo(formatImportSummary(
                added = stats.added,
                updated = stats.takeRemote,
                skipped = stats.takeLocal,
                conflicts = stats.conflicts,
                identical = stats.identical,
            ))
        }
        return newPayload to stats
    }

    fun importPasswordManager(
        uri: Uri,
        resolver: (Entry, Entry) -> VaultOps.MergeAction,
    ) = viewModelScope.launch {
        val token = captureVaultSession()
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        SyncForegroundService.beginTask(
            getApplication(),
            PASSWORD_MANAGER_IMPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "导入"),
            localizeUiTextFor(getApplication(), "正在导入"),
        )
        runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(token)
                com.vault.storage.CsvImporter.read(getApplication(), uri)
            }
        }.onSuccess { result ->
            requireVaultSessionCurrent(token)
            if (_state.value.phase != Phase.UNLOCKED) return@onSuccess
            val latest = _state.value.payload?.let(::materializePayload) ?: return@onSuccess
            val rootSession = _state.value.credential.sessionRootKey() ?: return@onSuccess
            val expectedSequence = withContext(Dispatchers.IO) {
                authenticatedPayloadSequence(r, rootSession, latest)
            }
            val incoming = result.entries
            if (incoming.isEmpty()) {
                SyncForegroundService.failTask(
                    getApplication(),
                    PASSWORD_MANAGER_IMPORT_TASK_ID,
                    localizeUiTextFor(getApplication(), "导入文件中未识别到条目"),
                )
                emitError("导入文件中未识别到条目")
                return@launch
            }
            val (newPayload, stats) = VaultOps.merge(latest, incoming, resolver)
            requireVaultSessionCurrent(token)
            check(withContext(Dispatchers.IO) { saveAndPublishForSession(token, r, newPayload, expectedSequence) }) { "保险库会话已失效" }
            val summary = formatImportSummary(
                added = stats.added,
                updated = stats.overwritten,
                skipped = stats.skipped + result.skipped,
                conflicts = stats.keptBoth,
                identical = stats.identical,
            )
            SyncForegroundService.succeedTask(
                getApplication(),
                PASSWORD_MANAGER_IMPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "$summary。导入文件含明文密码，请确认后安全删除"),
            )
            emitInfo("${result.source}：$summary。导入文件含明文密码，请确认后安全删除")
        }.onFailure {
            SyncForegroundService.failTask(
                getApplication(),
                PASSWORD_MANAGER_IMPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "密码管理器数据导入失败：${it.message}"),
            )
            emitError("密码管理器数据导入失败：${it.message}")
        }
    }

    fun regenerateRecoveryKey(
        activity: FragmentActivity?,
        secret: ByteArray,
        onResult: (Boolean) -> Unit = {},
    ) = viewModelScope.launch {
        val r = repo() ?: run { onResult(false); return@launch }
        val password = _state.value.password ?: run { onResult(false); return@launch }
        runCatching {
            password.useBytesSuspend { passwordUtf8 ->
                withContext(Dispatchers.IO) { r.regeneratePmvERecoveryKey(passwordUtf8, secret) }
            }
        }
            .onSuccess {
                _state.value.payload?.let(::materializePayload)?.let { current ->
                    val bumped = current.copy(
                        syncMeta = current.syncMeta.copy(
                            keyRevision = current.syncMeta.keyRevision + 1,
                            keyUpdatedAt = nowSeconds(),
                        ),
                    )
                    _state.update { it.withPayload(sealPayload(bumped)) }
                }
                emitInfo(localizeUiTextFor(getApplication(), "恢复密钥已重新生成，旧密钥已失效"))
                onResult(true)
            }
            .onFailure { emitError(getApplication<Application>().getString(R.string.viewmodel_regenerate_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error))); onResult(false) }
        secret.fill(0)
    }

    /** 恢复密钥重新生成草稿：弹窗打开状态与一次性密钥，锁定/重进后流程可恢复。 */
    private val _recoveryRegenerationDraft = MutableStateFlow<Pair<ByteArray, String>?>(null)
    val recoveryRegenerationDraft: StateFlow<Pair<ByteArray, String>?> = _recoveryRegenerationDraft.asStateFlow()

    /** 打开重新生成恢复密钥流程（主密码验证通过后调用）；密钥只生成一次，锁定后重进保持一致。 */
    fun requestRecoveryRegeneration() {
        if (_recoveryRegenerationDraft.value == null) {
            _recoveryRegenerationDraft.value = com.vault.crypto.RecoveryKeyCodec.generateRecoveryKey()
        }
    }

    fun dismissRecoveryRegeneration() {
        _recoveryRegenerationDraft.value?.first?.fill(0)
        _recoveryRegenerationDraft.value = null
    }

    fun exportVaultRaw(uri: Uri) = viewModelScope.launch {
        if (consumeSensitiveExportAuthorization("raw", uri) == null) {
            emitError(localizeUiTextFor(getApplication(), "导出授权已过期，请重新验证主密码")); return@launch
        }
        val r = repo() ?: return@launch
        SyncForegroundService.beginTask(
            getApplication(),
            VAULT_RAW_EXPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "导出"),
            localizeUiTextFor(getApplication(), "正在导出保险库文件…"),
        )
        runCatching { withContext(Dispatchers.IO) { r.exportTo(uri) } }
            .onSuccess {
                SyncForegroundService.succeedTask(
                    getApplication(),
                    VAULT_RAW_EXPORT_TASK_ID,
                    localizeUiTextFor(getApplication(), "保险库文件已导出"),
                )
                emitInfo("保险库文件已导出")
            }
            .onFailure {
                SyncForegroundService.failTask(
                    getApplication(),
                    VAULT_RAW_EXPORT_TASK_ID,
                    localizeUiTextFor(getApplication(), "导出失败：${it.message}"),
                )
                emitError("导出失败：${it.message}")
            }
    }

    /**
     * 导出通用压缩包：AES-256 加密 ZIP（导出口令），内含 logins.csv + data.json +
     * images/attachments 明文媒体。媒体经 PMVE 对象流式写入，不落明文临时文件。
     */
    fun exportArchive(uri: Uri, exportPassword: String) = viewModelScope.launch {
        if (consumeSensitiveExportAuthorization("archive", uri) == null) {
            emitError(localizeUiTextFor(getApplication(), "导出授权已过期，请重新验证主密码")); return@launch
        }
        val r = repo() ?: return@launch
        val payload = _state.value.payload?.let(::materializePayload) ?: return@launch
        val alive = payload.entries.filter { it.deletedAt == null }
        val name = _currentVault.value ?: "vault"
        val rootSession = _state.value.rootKey ?: run { emitError("保险库会话已失效"); return@launch }
        SyncForegroundService.beginTask(
            getApplication(),
            ARCHIVE_EXPORT_TASK_ID,
            BackgroundTaskKind.DATA_IMPORT_EXPORT,
            localizeUiTextFor(getApplication(), "通用压缩包导出"),
            localizeUiTextFor(getApplication(), "正在导出压缩包…"),
        )
        runCatching {
            withContext(Dispatchers.IO) {
                rootSession.withRootKey(rootSession.identity) { key ->
                    com.vault.storage.ArchiveExporter.write(
                        context = getApplication(),
                        uri = uri,
                        vaultName = name,
                        password = exportPassword,
                        entries = alive,
                        media = object : com.vault.storage.ArchiveExporter.MediaSource {
                            override fun readPrefix(ref: PmvMediaRef.Ref, length: Int): ByteArray {
                                val n = minOf(length.toLong(), ref.size).toInt()
                                if (n <= 0) return ByteArray(0)
                                val buffer = java.io.ByteArrayOutputStream()
                                r.openPmvEMediaRange(ref, key, 0L, n.toLong(), buffer)
                                return buffer.toByteArray()
                            }

                            override fun readAll(ref: PmvMediaRef.Ref, output: java.io.OutputStream) {
                                r.openPmvEMedia(ref, key, output)
                            }
                        },
                    )
                }
            }
        }.onSuccess { stats ->
            SyncForegroundService.succeedTask(
                getApplication(),
                ARCHIVE_EXPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "压缩包已导出 ${stats.loginCount + stats.otherCount} 条，${stats.mediaCount} 个媒体"),
            )
            emitInfo("压缩包已导出 ${stats.loginCount + stats.otherCount} 条，${stats.mediaCount} 个媒体")
        }.onFailure {
            SyncForegroundService.failTask(
                getApplication(),
                ARCHIVE_EXPORT_TASK_ID,
                localizeUiTextFor(getApplication(), "压缩包导出失败：${it.message}"),
            )
            emitError("压缩包导出失败：${it.message}")
        }
    }

    fun overwriteCloudVault(uri: Uri, onResult: (Boolean) -> Unit = {}): Job {
        val sessionToken = captureVaultSession()
        val dismissedVersion = if (remoteAssociation("drive")?.uri == uri) com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vaultName(), "drive").pending else ""
        val job = viewModelScope.launch {
            if (!isVaultSessionCurrent(sessionToken)) return@launch
            val r = repo() ?: run { onResult(false); return@launch }
            _state.update { it.copy(cloudSyncRunning = true) }
            withExternalActionFlag(
                setActive = { active ->
                    if (isVaultSessionCurrent(sessionToken)) setExternalActionInProgress(active)
                },
            ) {
                markCloudBusy(
                    "drive",
                    getApplication<Application>().getString(R.string.viewmodel_cloud_drive),
                    getApplication<Application>().getString(R.string.viewmodel_cloud_busy_upload_validate),
                )
                SyncForegroundService.beginTask(
                    getApplication(),
                    CLOUD_DRIVE_UPLOAD_TASK_ID,
                    BackgroundTaskKind.CLOUD_SYNC,
                    localizeUiTextFor(getApplication(), "云端硬盘同步"),
                    localizeUiTextFor(getApplication(), "正在上传并校验云端保险库文件…"),
                )
                runCatching {
                    withContext(Dispatchers.IO) {
                        requireVaultSessionCurrent(sessionToken)
                        vaultOperationMutex.withLock {
                            requireVaultSessionCurrent(sessionToken)
                            _state.value.payload?.let(::materializePayload) ?: error("保险库会话已失效")
                            val snapshot = createSyncSnapshot(r)
                            try {
                                val before = runCatching { CloudTreeStorage.metadata(getApplication(), uri) }.getOrNull()
                                writeCloudFile(uri, snapshot)
                                val remoteModifiedAt = verifyCloudWrite(uri, snapshot.length(), before?.lastModified ?: 0L)
                                val proofFile = newCloudTempFile("overwrite-proof")
                                try {
                                    val observed = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                                    require(readCloudFileTo(uri, proofFile) > 0L) { localizeUiTextFor(getApplication(), "远端读回文件为空") }
                                    val root = _state.value.rootKey ?: error(localizeUiTextFor(getApplication(), "保险库会话已失效"))
                                    root.withRootKey(root.identity) { key ->
                                        require(r.authenticateExternalFileWithDeviceKey(snapshot, key).identity ==
                                            r.authenticateExternalFileWithDeviceKey(proofFile, key).identity) { localizeUiTextFor(getApplication(), "远端读回内容与上传不一致") }
                                    }
                                    val after = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                                    if (observed != null && after != null && observed.matches(after)) rememberRemoteUpdateProof("drive", uri.toString(), observed, consumedVersion = dismissedVersion)
                                } finally { proofFile.delete() }
                                if (remoteModifiedAt > 0L) r.syncFile().setLastModified(remoteModifiedAt)
                            } finally {
                                snapshot.delete()
                            }
                        }
                    }
                }.onSuccess {
                    if (!isVaultSessionCurrent(sessionToken)) return@onSuccess
                    _state.update { it.copy(cloudSyncRunning = false) }
                    finishCloudBusyOk("drive", getApplication<Application>().getString(R.string.viewmodel_cloud_drive))
                    SyncForegroundService.succeedTask(
                        getApplication(),
                        CLOUD_DRIVE_UPLOAD_TASK_ID,
                        localizeUiTextFor(getApplication(), "已写入云端并通过读回校验"),
                    )
                    emitInfo(localizeUiTextFor(getApplication(), "已写入云端并通过读回校验"))
                    onResult(true)
                }.onFailure {
                    if (it is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                        // 取消也要清忙碌位：它会挡住 AppRoot 的空闲超时锁库。
                        _state.update { state -> state.copy(cloudSyncRunning = false) }
                        return@onFailure
                    }
                    _state.update { state -> state.copy(cloudSyncRunning = false) }
                    SyncForegroundService.failTask(
                        getApplication(),
                        CLOUD_DRIVE_UPLOAD_TASK_ID,
                        localizeUiTextFor(getApplication(), "云端上传失败：${it.message}"),
                    )
                    failCloudSync("drive", "云端硬盘", "写入云端硬盘失败：${it.message}", false)
                    emitError("写入云端硬盘失败：${it.message}")
                    onResult(false)
                }
            }
        }
        cloudDiskOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            // 自动同步通过回调等待结果；任务因退后台/锁定被取消时也必须结束等待，
            // 否则会出现“持续上传回读、自动循环无法收敛”的假死状态。
            if (it != null) onResult(false)
            vaultSessionJobs.remove(job)
            if (cloudDiskOperationJob === job) cloudDiskOperationJob = null
        }
        return job
    }

    private fun transferUserMessage(error: Throwable, sending: Boolean): String {
        val raw = generateSequence(error as Throwable?) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
        val lower = raw.lowercase()
        return when {
        error is SyncClient.IntegrityException ->
            getApplication<Application>().getString(
                if (sending) R.string.viewmodel_transfer_integrity_send else R.string.viewmodel_transfer_integrity_receive,
            )
        error.isLanReachabilityFailure() -> getApplication<Application>().getString(R.string.viewmodel_transfer_unreachable)
        "10 gb" in lower || "10 tib" in lower || "过大" in raw -> getApplication<Application>().getString(R.string.viewmodel_transfer_too_large)
        "无法打开" in raw || "无法读取" in raw || "not found" in lower ->
            getApplication<Application>().getString(
                if (sending) R.string.viewmodel_transfer_source_missing else R.string.viewmodel_transfer_remote_missing,
            )
        "permission" in lower || "denied" in lower || "权限" in raw ->
            getApplication<Application>().getString(
                if (sending) R.string.viewmodel_transfer_source_permission else R.string.viewmodel_transfer_destination_permission,
            )
        "space" in lower || "enospc" in lower || "空间" in raw -> getApplication<Application>().getString(R.string.viewmodel_transfer_no_space)
        "broken pipe" in lower || "connection reset" in lower || "connection aborted" in lower ||
            "reset by peer" in lower || "closed by peer" in lower ->
            getApplication<Application>().getString(
                if (sending) R.string.viewmodel_transfer_peer_cancelled_send else R.string.viewmodel_transfer_peer_cancelled_receive,
            )
        "http 403" in lower || "未授权" in raw -> getApplication<Application>().getString(R.string.viewmodel_transfer_unauthorized)
        "http 404" in lower || "不存在" in raw -> getApplication<Application>().getString(R.string.viewmodel_transfer_not_found)
        "已关闭" in raw || "已断开" in raw -> getApplication<Application>().getString(R.string.viewmodel_transfer_peer_closed)
        else -> {
            val detail = raw.substringAfter('：', raw).trim().take(200)
            getApplication<Application>().getString(
                if (sending) R.string.viewmodel_transfer_failed_send else R.string.viewmodel_transfer_failed_receive,
                detail.ifBlank { getApplication<Application>().getString(R.string.viewmodel_unknown_error) },
            )
        }
        }
    }

    fun downloadOverwriteCloudVault(uri: Uri, onResult: (Boolean) -> Unit = {}): Job {
        val sessionToken = captureVaultSession()
        val job = viewModelScope.launch {
        if (!isVaultSessionCurrent(sessionToken)) return@launch
        val r = repo() ?: run { onResult(false); return@launch }
        _state.update { it.copy(cloudSyncRunning = true) }
        markCloudBusy(
            "drive",
            getApplication<Application>().getString(R.string.viewmodel_cloud_drive),
            getApplication<Application>().getString(R.string.viewmodel_cloud_busy_download_validate),
        )
        SyncForegroundService.beginTask(
            getApplication(),
            CLOUD_DRIVE_DOWNLOAD_TASK_ID,
            BackgroundTaskKind.CLOUD_SYNC,
            localizeUiTextFor(getApplication(), "云端硬盘同步"),
            localizeUiTextFor(getApplication(), "正在下载并校验云端保险库文件…"),
        )
        runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(sessionToken)
                vaultOperationMutex.withLock {
                    requireVaultSessionCurrent(sessionToken)
                    val local = _state.value.payload?.let(::materializePayload) ?: error("保险库会话已失效")
                    val remoteMetadata = CloudTreeStorage.metadata(getApplication(), uri)
                    val remoteFile = newCloudTempFile("download")
                    try {
                        require(readCloudFileTo(uri, remoteFile) > 0L) { "云端保险库文件为空" }
                        val downloadedVersion = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                        replaceCurrentFromRemoteFile(r, local, remoteFile).also {
                            if (remoteMetadata.lastModified > 0L) r.syncFile().setLastModified(remoteMetadata.lastModified)
                            if (downloadedVersion != null && remoteMetadata.toCloudFileVersion().matches(downloadedVersion)) rememberRemoteUpdateProof("drive", uri.toString(), downloadedVersion)
                        }
                    } finally {
                        remoteFile.delete()
                    }
                }
            }
        }.onSuccess { remote ->
            if (!isVaultSessionCurrent(sessionToken)) return@onSuccess
            _state.update { it.withPayload(sealPayload(remote)).copy(cloudSyncRunning = false) }
            clearSecurityReport()
            finishCloudBusyOk("drive", getApplication<Application>().getString(R.string.viewmodel_cloud_drive))
            SyncForegroundService.succeedTask(
                getApplication(),
                CLOUD_DRIVE_DOWNLOAD_TASK_ID,
                localizeUiTextFor(getApplication(), "已下载并验证远端保险库，本地文件已原子替换"),
            )
            emitInfo("已下载并验证远端保险库，本地文件已原子替换")
            onResult(true)
        }.onFailure {
            if (it is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                // 取消也要清忙碌位：它会挡住 AppRoot 的空闲超时锁库。
                // 同时复位 phase，否则 RUNNING 残留会永久挡死后续自动同步。
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                clearCloudBusy()
                return@onFailure
            }
            _state.update { state -> state.copy(cloudSyncRunning = false) }
            SyncForegroundService.failTask(
                getApplication(),
                CLOUD_DRIVE_DOWNLOAD_TASK_ID,
                localizeUiTextFor(getApplication(), "下载覆盖失败，本地数据已保留：${it.message}"),
            )
            failCloudSync("drive", "云端硬盘", "下载覆盖失败，本地数据已保留：${it.message}", false)
            emitError("下载覆盖失败，本地数据已保留：${it.message}")
            onResult(false)
        }
        }
        cloudDiskOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            vaultSessionJobs.remove(job)
            if (cloudDiskOperationJob === job) cloudDiskOperationJob = null
        }
        return job
    }

    fun syncCloudVault(
        uri: Uri,
        allowDifferentVault: Boolean = false,
        notifyUser: Boolean = true,
        onResult: (Boolean) -> Unit = {},
    ): Job {
        val sessionToken = captureVaultSession()
        val app = getApplication<Application>()
        // 幂等收尾：会话失效、取消、异常等提前退出都必须复位状态、释放前台任务并回调。
        // 否则 phase 停在 RUNNING、前台通知永不消失，且自动同步会被 RUNNING 门禁永久挡死
        // （表现就是"流程一直不结束"）。
        // claimed：beginCloudSync 置 RUNNING 成功后为 true，收尾必须复位 phase，
        // 否则 RUNNING 门禁会永久挡死后续自动同步（注意不能在 beginCloudSync 之前
        // 无条件清 phase——那会踩掉另一个正在进行的同步的状态）。
        // taskStarted：前台通知真正起来后为 true，收尾还要停掉通知。
        val claimed = AtomicBoolean(false)
        val taskStarted = AtomicBoolean(false)
        val settled = AtomicBoolean(false)
        val settle: () -> Unit = {
            if (settled.compareAndSet(false, true)) {
                onResult(false)
                if (claimed.compareAndSet(true, false)) {
                    _state.update { state -> state.copy(cloudSyncRunning = false) }
                    clearCloudBusy()
                }
                if (taskStarted.compareAndSet(true, false)) {
                    SyncForegroundService.failTask(
                        app,
                        CLOUD_DRIVE_SYNC_TASK_ID,
                        localizeUiTextFor(app, "同步已中断"),
                    )
                }
            }
        }
        val job = viewModelScope.launch {
            if (!isVaultSessionCurrent(sessionToken)) { onResult(false); return@launch }
            val r = repo() ?: run { onResult(false); return@launch }
            if (!beginCloudSync("drive", app.getString(R.string.viewmodel_cloud_drive))) {
                onResult(false)
                return@launch
            }
            claimed.set(true)
            if (notifyUser) {
                SyncForegroundService.beginTask(
                    app,
                    CLOUD_DRIVE_SYNC_TASK_ID,
                    BackgroundTaskKind.CLOUD_SYNC,
                    localizeUiTextFor(app, "云端硬盘同步"),
                    localizeUiTextFor(app, "正在下载并合并云端数据…"),
                )
                taskStarted.set(true)
            }
            markCloudBusy(
                "drive",
                getApplication<Application>().getString(R.string.viewmodel_cloud_drive),
                getApplication<Application>().getString(R.string.viewmodel_cloud_busy_download_verify),
            )
            var savedPayload: VaultPayload? = null
            var syncStats: VaultOps.LwwMergeStats? = null
            var keyConvergence = KeyConvergenceKind.NONE
            var remoteByteCount = 0L
            var aborted = false
            val merged = try {
                withContext<VaultPayload>(Dispatchers.IO) {
                    requireVaultSessionCurrent(sessionToken)
                    val remoteFile = newCloudTempFile("sync-download")
                    val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
                    val rootKey = rootSession.copyRootKey(rootSession.identity)
                    try {
                        var attempts = 0
                        var resultPayload: VaultPayload? = null
                        while (resultPayload == null) {
                            // 锁外：元数据 + 下载（纯网络/临时文件，不触碰保险库文件）
                            val remoteMetadata = CloudTreeStorage.metadata(getApplication(), uri)
                            remoteByteCount = readCloudFileTo(uri, remoteFile)
                            val downloadedVersion = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                            var local: VaultPayload? = null
                            // 锁内：本地快照、远端认证、谱系分类与可立即完成的安装
                            val (action, statePayloadBefore) = vaultOperationMutex.withLock {
                                requireVaultSessionCurrent(sessionToken)
                                local = _state.value.payload?.let(::materializePayload)
                                    ?: error("保险库会话已失效")
                                val stateBefore = _state.value.payload
                                if (!r.isPmvE()) error("旧格式云端同步已移除，仅支持 PMVE")
                                val preparedAction = syncPmvEDrive(
                                    repository = r,
                                    localPayload = local,
                                    uri = uri,
                                    downloadedFile = remoteFile,
                                    downloadedBytes = remoteByteCount,
                                    expectedRemote = remoteMetadata.toCloudFileVersion(),
                                    rootKey = rootKey,
                                )
                                // 会话根密钥替换与文件写同锁：避免并发编辑读到已关闭的旧密钥。
                                if (preparedAction is CloudSyncAction.Completed) {
                                    applyPmvEReplacement(preparedAction.result)
                                } else if (preparedAction is CloudSyncAction.UploadPending) {
                                    preparedAction.acceptedLocal?.let { accepted ->
                                        savedPayload = accepted.payload
                                        applyPmvEReplacement(accepted)
                                    }
                                }
                                preparedAction to stateBefore
                            }
                            if (action is CloudSyncAction.Completed) {
                                val result = action.result
                                if (downloadedVersion != null && remoteAssociation("drive")?.uri == uri && remoteMetadata.toCloudFileVersion().matches(downloadedVersion)) rememberRemoteUpdateProof("drive", uri.toString(), downloadedVersion)
                                syncStats = result.stats
                                keyConvergence = result.keyConvergence
                                if (result.payload !== local) savedPayload = result.payload
                                resultPayload = result.payload
                            } else {
                                val pending = action as CloudSyncAction.UploadPending
                                // 锁外：上传 + 回读校验
                                try {
                                    uploadDrivePmvEAndVerify(
                                        uri, pending.source, remoteMetadata.toCloudFileVersion(),
                                        r, rootKey, pending.expectedIdentity, pending.expectedRemoteIdentity,
                                    )
                                } catch (conflict: com.vault.storage.CloudFileConflict) {
                                    if (pending.source != remoteFile) pending.source.delete()
                                    if (++attempts >= MAX_CLOUD_SYNC_RETRY_ATTEMPTS) throw conflict
                                    markCloudBusy(
                                        "drive",
                                        getApplication<Application>().getString(R.string.viewmodel_cloud_drive),
                                        getApplication<Application>().getString(
                                            R.string.viewmodel_cloud_busy_retry_local,
                                            attempts + 1,
                                            MAX_CLOUD_SYNC_RETRY_ATTEMPTS,
                                        ),
                                    )
                                    delay(350L)
                                    continue
                                }
                                // 锁内：安装合并提交 / 收尾；上传期间本地被并发修改则重拉重合并
                                try {
                                    val finalized = vaultOperationMutex.withLock {
                                        requireVaultSessionCurrent(sessionToken)
                                        val done = finalizeCloudSyncAction(
                                            pending, r, rootKey, statePayloadBefore,
                                        ) { savedPayload = it }
                                        applyPmvEReplacement(done)
                                        done
                                    }
                                    pending.source.delete()
                                    syncStats = finalized.stats
                                    keyConvergence = finalized.keyConvergence
                                    if (finalized.payload !== local) savedPayload = finalized.payload
                                    resultPayload = finalized.payload
                                } catch (retry: CloudSyncRetryNeeded) {
                                    if (pending.source != remoteFile) pending.source.delete()
                                    if (++attempts >= MAX_CLOUD_SYNC_RETRY_ATTEMPTS) throw retry
                                    markCloudBusy(
                                        "drive",
                                        getApplication<Application>().getString(R.string.viewmodel_cloud_drive),
                                        getApplication<Application>().getString(
                                            R.string.viewmodel_cloud_busy_retry_local,
                                            attempts + 1,
                                            MAX_CLOUD_SYNC_RETRY_ATTEMPTS,
                                        ),
                                    )
                                    delay(350L)
                                }
                            }
                        }
                        requireNotNull(resultPayload)
                    } finally {
                        rootKey.fill(0)
                        remoteFile.delete()
                    }
                }
            } catch (error: Throwable) {
                if (error is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                    // 取消也要清忙碌位：它会挡住 AppRoot 的空闲超时锁库。
                    settle()
                    return@launch
                }
                val stablePayload = savedPayload
                if (stablePayload != null) {
                    // 失败前已合并/落盘：锁内把会话密封与索引重建放到后台线程，
                    // 避免主线程重建大库索引；锁保证与并发编辑串行，不破坏一致性。
                    val published = vaultOperationMutex.withLock {
                        withContext(Dispatchers.Default) {
                            publishPayloadForSession(sessionToken, stablePayload)
                        }
                    }
                    if (!published || !isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
                }
                val message = cloudSyncError("云端硬盘同步失败", error, stablePayload != null)
                failCloudSync("drive", "云端硬盘", message, stablePayload != null)
                SyncForegroundService.failTask(
                    getApplication(),
                    CLOUD_DRIVE_SYNC_TASK_ID,
                    localizeUiTextFor(getApplication(), message),
                )
                if (notifyUser) emitError(message)
                settled.set(true)
                onResult(false)
                return@launch
            }
            if (aborted) { settle(); return@launch }
            if (!isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
            // 成功：锁内把会话密封与索引重建放到后台线程，主线程只做轻量状态更新。
            val published = vaultOperationMutex.withLock {
                requireVaultSessionCurrent(sessionToken)
                withContext(Dispatchers.Default) {
                    publishPayloadForSession(sessionToken, merged)
                }
            }
            if (!published || !isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
            syncStats?.let {
                completeCloudSync(
                    "drive", getApplication<Application>().getString(R.string.viewmodel_cloud_drive), it,
                    uploaded = it.takeLocal > 0 || it.conflicts > 0,
                )
                SyncForegroundService.succeedTask(
                    getApplication(),
                    CLOUD_DRIVE_SYNC_TASK_ID,
                    localizeUiTextFor(getApplication(), cloudSyncCompletionMessage(it)),
                )
            }
            if (keyConvergence != KeyConvergenceKind.NONE) {
                // 密钥/主密码版本收敛提示不区分手动/自动同步：同库端都要自动对齐并获知。
                _keyConvergedNotice.value = KeyConvergedNotice(
                    keyConvergence,
                    keyConvergedMessage(keyConvergence),
                )
            } else if (notifyUser) {
                emitInfo(cloudSyncCompletionMessage(syncStats))
            }
            settled.set(true)
            onResult(true)
        }
        cloudDiskOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            // 兜底：自动同步靠回调等待结果。若协程在收尾前被取消（退后台、锁定、
            // ViewModel 清理），必须替它结束等待并释放状态，否则轮询会永久挂起。
            if (it != null) settle()
            vaultSessionJobs.remove(job)
            if (cloudDiskOperationJob === job) cloudDiskOperationJob = null
        }
        return job
    }

    fun inspectCloudFile(uri: Uri, onResult: (Boolean?) -> Unit) = viewModelScope.launch {
        _state.update { it.copy(cloudSyncRunning = true) }
        runCatching {
            withContext(Dispatchers.IO) {
                getApplication<Application>().contentResolver.openInputStream(uri)?.buffered()?.use {
                    it.read() >= 0
                } ?: error("无法读取云端文件")
            }
        }
            .onSuccess {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                onResult(it)
            }
            .onFailure {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                emitError(getApplication<Application>().getString(R.string.viewmodel_cloud_file_check_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
                onResult(null)
            }
    }

    /**
     * PMVE 分叉/快进同步前后的密钥收敛检测：比较两端头部密码槽与恢复密钥槽。
     * 密码槽变化 → PASSWORD（确认后锁定并用新密码解锁）；仅恢复密钥槽变化 →
     * KEY_ONLY（只提示不锁定）；均一致 → NONE。
     */
    private fun pmveKeyConvergenceKind(
        repository: VaultRepository,
        rootKey: ByteArray,
        remoteFile: File,
    ): KeyConvergenceKind {
        val localHeader = PmvVaultStore.openRootKey(repository.syncFile(), rootKey).use {
            PmvVaultHeaderCodec.decode(it.copyHeaderRaw())
        }
        val remoteHeader = PmvVaultStore.openRootKey(remoteFile, rootKey).use {
            PmvVaultHeaderCodec.decode(it.copyHeaderRaw())
        }
        val passwordChanged = !(
            localHeader.passwordEnvelope.nonce.contentEquals(remoteHeader.passwordEnvelope.nonce) &&
                localHeader.passwordEnvelope.ciphertext.contentEquals(remoteHeader.passwordEnvelope.ciphertext)
            )
        if (passwordChanged) return KeyConvergenceKind.PASSWORD
        val recoveryChanged = !(
            localHeader.recoveryEnvelope.nonce.contentEquals(remoteHeader.recoveryEnvelope.nonce) &&
                localHeader.recoveryEnvelope.ciphertext.contentEquals(remoteHeader.recoveryEnvelope.ciphertext)
            )
        return if (recoveryChanged) KeyConvergenceKind.KEY_ONLY else KeyConvergenceKind.NONE
    }

    /** 局域网同步采用固定双向流程（简化）：
     *  1. 传输站先推送数据库 → 连接方拉取并校验（身份/格式/完整性）；
     *  2. 连接方把数据合并采纳到本端后，再推送回传输站（传输站校验对方身份）；
     *  3. 传输站合并后主动断开连接。
     *  因此无论谱系关系如何，拉取之后都会执行一次回推，不做条件跳过。
     */
    private data class LanSyncAdoption(
        val payload: VaultPayload,
        val stats: VaultOps.LwwMergeStats,
        val replacementRootKey: ByteArray? = null,
        val replacementIdentity: VaultIdentity? = null,
        val keyConvergence: KeyConvergenceKind = KeyConvergenceKind.NONE,
    )

    private fun pushLanSyncVault(serverUrl: String, pin: String, file: java.io.File) {
        SyncClient.pushFromFile(
            serverUrl,
            pin,
            file,
            onIntegrityRetry = { attempt, max ->
                updateLanSyncProgress(LAN_SYNC_TASK_ID, "数据检查未通过，正在自动重试 $attempt/$max")
            },
            onProgress = { transferred, total ->
                updateLanSyncProgress(LAN_SYNC_TASK_ID, "正在发送数据给传输站…", transferred, total)
            },
        )
    }

    private fun syncPmvELan(
        repository: VaultRepository,
        localPayload: VaultPayload,
        remoteFile: File,
        serverUrl: String,
        pin: String,
        sessionToken: VaultSessionFence.Token,
    ): LanSyncResult {
        val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
        return try {
            // startSync 已在拉取任何数据之前完成 read + write 授权。这里必须复用同一
            // 配对会话，重复挑战会增加四次网络往返，并让短时局域网抖动更容易使扫码同步失败。
            rootSession.withRootKey(rootSession.identity) { rootKey ->
                if (VaultFileFormat.detect(remoteFile) != VaultFileFormat.PMVE) {
                    cancelLanSyncSession()
                    error("远端保险库格式与本地 PMVE 不一致，已取消同步")
                }
                val local = repository.currentAuthenticatedFile(rootKey)
                val remote = repository.authenticateExternalFileWithDeviceKey(remoteFile, rootKey)
                val relation = PmvELineageClassifier.classify(local.toPmvELineage(), remote.toPmvELineage())
                val adoption = when (relation) {
                    PmvELineageRelation.SAME -> {
                        var acceptedValue: VaultUnlockResult? = null
                        check(vaultSessionFence.runIfCurrent(sessionToken, _currentVault.value) {
                            acceptedValue = repository.acknowledgeDeletionCleanupCheckpoint(rootKey, requireNotNull(local.identity).sequence)
                        }) { "保险库会话已失效" }
                        val accepted = requireNotNull(acceptedValue)
                        try {
                            replacePmvESessionRoot(requireNotNull(accepted.rootKey), requireNotNull(accepted.identity))
                        } finally { accepted.rootKey?.fill(0) }
                        _state.update { it.withPayload(sealPayload(accepted.payload)) }
                        LanSyncAdoption(accepted.payload, VaultOps.LwwMergeStats(identical = accepted.payload.entries.size))
                    }
                    PmvELineageRelation.FAST_FORWARD -> {
                        val localIdentity = requireNotNull(local.identity)
                        val remoteIdentity = requireNotNull(remote.identity)
                        val keyConvergence = pmveKeyConvergenceKind(repository, rootKey, remoteFile)
                        var installedValue: VaultUnlockResult? = null
                        check(vaultSessionFence.runIfCurrent(sessionToken, _currentVault.value) {
                            installedValue = repository.replaceAuthenticatedFile(
                                candidate = remoteFile,
                                rootKey = rootKey,
                                expectedCurrent = localIdentity,
                                expectedRemote = remoteIdentity,
                            )
                        }) { "保险库会话已失效" }
                        val installed = requireNotNull(installedValue)
                        val installedRootKey = requireNotNull(installed.rootKey) { "PMVE 安装后未返回 RootKey" }
                        LanSyncAdoption(
                            payload = installed.payload,
                            stats = VaultOps.LwwMergeStats(takeRemote = installed.payload.entries.size),
                            replacementRootKey = installedRootKey,
                            replacementIdentity = requireNotNull(installed.identity),
                            keyConvergence = keyConvergence,
                        )
                    }
                    PmvELineageRelation.REMOTE_STALE -> LanSyncAdoption(
                        payload = localPayload,
                        stats = VaultOps.LwwMergeStats(takeLocal = localPayload.entries.size),
                    )
                    PmvELineageRelation.DIVERGED -> {
                        val remotePayload = remote.payload
                            ?: repository.decodeExternalFileWithRootKey(remoteFile, rootKey)
                        val (_, stats) = VaultOps.mergeDiverged(localPayload, remotePayload)
                        // 分叉收敛：以远端 Head 为基线提交合并内容（条目 LWW + 注册表 union），
                        // 原子采纳为本地库，再推送同一合并文件让远端快速前进。
                        val keyConvergence = pmveKeyConvergenceKind(repository, rootKey, remoteFile)
                        var installedValue: VaultUnlockResult? = null
                        check(vaultSessionFence.runIfCurrent(sessionToken, _currentVault.value) {
                            installedValue = repository.mergeAndAdoptAuthenticatedFile(
                                candidate = remoteFile,
                                rootKey = rootKey,
                                expectedRemote = requireNotNull(remote.identity),
                                mergeEntries = { local, incoming -> VaultOps.mergeDiverged(local, incoming).first },
                            )
                        }) { "保险库会话已失效" }
                        val installed = requireNotNull(installedValue)
                        LanSyncAdoption(
                            payload = installed.payload,
                            stats = stats,
                            replacementRootKey = installed.rootKey,
                            replacementIdentity = installed.identity,
                            keyConvergence = keyConvergence,
                        )
                    }
                    PmvELineageRelation.DIFFERENT -> {
                        cancelLanSyncSession()
                        error("两端不是同一份 PMVE 保险库，已取消同步")
                    }
                    PmvELineageRelation.INVALID -> {
                        cancelLanSyncSession()
                        error("远端 PMVE 身份或提交谱系无效，已取消同步")
                    }
                }
                // 拉取并采纳后，固定把稳定快照推送回传输站。禁止直接发送正在使用的
                // 库文件，否则摘要计算与实际发送之间发生一次保存就会造成假校验失败。
                requireVaultSessionCurrent(sessionToken)
                val outgoingSnapshot = repository.createSyncSnapshot()
                try {
                    pushLanSyncVault(serverUrl, pin, outgoingSnapshot)
                } finally {
                    outgoingSnapshot.delete()
                }
                LanSyncResult(
                    payload = adoption.payload,
                    stats = adoption.stats,
                    uploaded = true,
                    verified = true,
                    remoteBytes = remoteFile.length(),
                    lineage = relation.name.lowercase(java.util.Locale.ROOT),
                    replacementRootKey = adoption.replacementRootKey,
                    replacementIdentity = adoption.replacementIdentity,
                    keyConvergence = adoption.keyConvergence,
                )
            }
        } finally {
            remoteFile.delete()
            // 同步完成或失败后都主动通知传输站关闭并断开连接，避免会话残留。
            runCatching { SyncClient.cancelSession(serverUrl, pin) }
            stopLanSyncKeepAlive()
        }
    }

    private fun replacePmvESessionRoot(rootKey: ByteArray, identity: VaultIdentity) {
        val current = _state.value.credential ?: error("PMVE 会话已失效")
        val oldRoot = current.sessionRootKey() ?: error("PMVE RootKey 会话已失效")
        val replacement = VaultSessionCredential.RootKey(rootKey, identity.deviceBinding())
        val next = current.sessionPassword()?.let { VaultSessionCredential.Compound(it, replacement) } ?: replacement
        _state.update { it.copy(credential = next) }
        oldRoot.close()
        val name = _currentVault.value ?: error("当前保险库名称缺失")
        replacement.withRootKey(replacement.identity) { key ->
            PmvMediaUiSession.bind(getApplication(), name, key)
        }
    }

    private fun applyPmvEReplacement(result: LanSyncResult) {
        try {
            if (result.replacementRootKey != null && result.replacementIdentity != null) {
                replacePmvESessionRoot(result.replacementRootKey, result.replacementIdentity)
            }
        } finally {
            result.clearReplacementKey()
        }
    }

    private fun syncPmvEDrive(
        repository: VaultRepository,
        localPayload: VaultPayload,
        uri: Uri,
        downloadedFile: File,
        downloadedBytes: Long,
        expectedRemote: CloudFileVersion,
        rootKey: ByteArray,
    ): CloudSyncAction {
        CloudFileTransferGuard.requireUnchanged(
            expectedRemote,
            CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion(),
        )
        return prepareCloudSyncAction(
            repository = repository,
            localPayload = localPayload,
            downloadedFile = downloadedFile,
            hasRemote = downloadedBytes > 0L,
            rootKey = rootKey,
        )
    }

    private fun syncPmvEWebDav(
        repository: VaultRepository,
        localPayload: VaultPayload,
        config: WebDavConfig,
        downloadedFile: File,
        downloaded: com.vault.storage.WebDavRemoteFile?,
        expectedRemote: WebDavMetadata,
        rootKey: ByteArray,
    ): CloudSyncAction {
        // 远端内容以实际下载结果为准：谱系分类会对下载文件做密码学认证，
        // 写回由条件写入（If-Match）加读回校验保护。不再比较多次元数据请求
        // 之间的 ETag 表现差异，避免单设备在 HEAD/Range/完整 GET 返回不同
        // ETag 展示的服务上误报“已被其他设备更新”。
        return prepareCloudSyncAction(
            repository = repository,
            localPayload = localPayload,
            downloadedFile = downloadedFile,
            hasRemote = downloaded != null && downloaded.size > 0L,
            rootKey = rootKey,
        )
    }

    /** 云同步的锁内准备结果：可立即完成，或需锁外上传后再安装收尾。 */
    private sealed interface CloudSyncAction {
        data class Completed(val result: LanSyncResult) : CloudSyncAction
        data class UploadPending(
            val source: File,
            val expectedIdentity: VaultIdentity,
            val relation: PmvELineageRelation,
            val localPayload: VaultPayload,
            val keyConvergence: KeyConvergenceKind,
            val expectedCurrent: VaultIdentity? = null,
            val expectedMerged: VaultIdentity? = null,
            val expectedRemoteIdentity: VaultIdentity? = null,
            val acceptedLocal: LanSyncResult? = null,
        ) : CloudSyncAction
    }

    /** 上传期间本地被并发修改，需要重新下载合并的收敛信号。 */
    private class CloudSyncRetryNeeded : Exception("云端发布期间本地保险库已更新，等待重新合并")

    /**
     * 锁内执行的云同步准备：认证本地/远端、谱系分类、可立即完成的安装，
     * 以及需要上传时的快照/合并候选。网络上传与回读校验由调用方在锁外执行，
     * 避免下载/上传期间长时间占用互斥锁阻塞本地编辑等操作。
     */
    private fun prepareCloudSyncAction(
        repository: VaultRepository,
        localPayload: VaultPayload,
        downloadedFile: File,
        hasRemote: Boolean,
        rootKey: ByteArray,
    ): CloudSyncAction {
        val local = repository.currentAuthenticatedFile(rootKey)
        val currentOpened = repository.openPmvEWithRootKey(rootKey)
        val effectiveLocalPayload = currentOpened.payload
        currentOpened.rootKey?.fill(0)
        if (!hasRemote) {
            // 远端为空：上传本地快照，避免锁外上传时本地文件被并发替换。
            compactBeforeCloudSync(repository, rootKey)
            return CloudSyncAction.UploadPending(
                source = repository.createSyncSnapshot(),
                expectedIdentity = requireNotNull(local.identity),
                relation = PmvELineageRelation.REMOTE_STALE,
                localPayload = effectiveLocalPayload,
                keyConvergence = KeyConvergenceKind.NONE,
            )
        }
        require(VaultFileFormat.detect(downloadedFile) == VaultFileFormat.PMVE) {
            "远端保险库格式与本地 PMVE 不一致"
        }
        val remote = repository.authenticateExternalFileWithDeviceKey(downloadedFile, rootKey)
        return when (PmvELineageClassifier.classify(local.toPmvELineage(), remote.toPmvELineage())) {
            PmvELineageRelation.SAME -> {
                val accepted = repository.acknowledgeDeletionCleanupCheckpoint(rootKey, requireNotNull(local.identity).sequence)
                val result = LanSyncResult(accepted.payload, VaultOps.LwwMergeStats(identical = accepted.payload.entries.size),
                    uploaded = false, verified = true, replacementRootKey = accepted.rootKey, replacementIdentity = accepted.identity)
                if (accepted.identity != remote.identity) {
                    CloudSyncAction.UploadPending(repository.createSyncSnapshot(), requireNotNull(accepted.identity),
                        PmvELineageRelation.REMOTE_STALE, accepted.payload, KeyConvergenceKind.NONE,
                        expectedRemoteIdentity = remote.identity, acceptedLocal = result)
                } else CloudSyncAction.Completed(result)
            }
            PmvELineageRelation.FAST_FORWARD -> {
                val keyConvergence = pmveKeyConvergenceKind(repository, rootKey, downloadedFile)
                val installed = repository.replaceAuthenticatedFile(
                    candidate = downloadedFile,
                    rootKey = rootKey,
                    expectedCurrent = requireNotNull(local.identity),
                    expectedRemote = requireNotNull(remote.identity),
                )
                val result = LanSyncResult(installed.payload, VaultOps.LwwMergeStats(takeRemote = installed.payload.entries.size),
                    uploaded = false, verified = true, replacementRootKey = installed.rootKey,
                    replacementIdentity = installed.identity, keyConvergence = keyConvergence)
                if (installed.identity != remote.identity) {
                    CloudSyncAction.UploadPending(repository.createSyncSnapshot(), requireNotNull(installed.identity),
                        PmvELineageRelation.REMOTE_STALE, installed.payload, keyConvergence,
                        expectedRemoteIdentity = remote.identity, acceptedLocal = result)
                } else CloudSyncAction.Completed(result)
            }
            PmvELineageRelation.REMOTE_STALE -> {
                compactBeforeCloudSync(repository, rootKey)
                CloudSyncAction.UploadPending(
                    source = repository.createSyncSnapshot(),
                    expectedIdentity = requireNotNull(local.identity),
                    relation = PmvELineageRelation.REMOTE_STALE,
                    localPayload = effectiveLocalPayload,
                    keyConvergence = KeyConvergenceKind.NONE,
                    expectedRemoteIdentity = requireNotNull(remote.identity),
                )
            }
            PmvELineageRelation.DIVERGED -> {
                // 先只在下载候选上生成合并提交；远端发布和回读认证成功后，
                // 再以 expected-local 约束安装，发布失败绝不前进本地文件/会话。
                val keyConvergence = pmveKeyConvergenceKind(repository, rootKey, downloadedFile)
                val localIdentity = requireNotNull(local.identity)
                val prepared = repository.prepareMergedAuthenticatedFile(
                    candidate = downloadedFile,
                    rootKey = rootKey,
                    expectedCurrent = localIdentity,
                    expectedRemote = requireNotNull(remote.identity),
                    mergeEntries = { local, incoming ->
                        VaultOps.mergeLww(
                            local,
                            incoming.entries,
                            incomingExportEpoch = incoming.exportEpoch,
                            incomingPurgeTombstones = incoming.purgeTombstones,
                    incomingDeletionBaseline = incoming.deletionBaseline,
                            incomingExclusions = incoming.autofillExclusions,
                        ).first.copy(syncMeta = VaultOps.newerKeySyncMeta(local, incoming))
                    },
                )
                val mergedIdentity = requireNotNull(prepared.identity)
                prepared.rootKey?.fill(0)
                CloudSyncAction.UploadPending(
                    source = downloadedFile,
                    expectedIdentity = mergedIdentity,
                    relation = PmvELineageRelation.DIVERGED,
                    localPayload = effectiveLocalPayload,
                    keyConvergence = keyConvergence,
                    expectedCurrent = localIdentity,
                    expectedMerged = mergedIdentity,
                    expectedRemoteIdentity = requireNotNull(remote.identity),
                )
            }
            PmvELineageRelation.DIFFERENT -> error("远端不是同一份 PMVE 保险库")
            PmvELineageRelation.INVALID -> error("远端 PMVE 身份或提交谱系无效")
        }
    }

    /**
     * 上传成功后的锁内收尾：DIVERGED 安装合并提交，REMOTE_STALE 直接返回已上传结果。
     * 上传期间本地状态被并发修改时，抛 [CloudSyncRetryNeeded] 由调用方重新下载合并收敛，
     * 而不是把一次良性并发计入同步失败。
     */
    private fun finalizeCloudSyncAction(
        action: CloudSyncAction.UploadPending,
        repository: VaultRepository,
        rootKey: ByteArray,
        expectedStatePayload: VaultPayload?,
        onLocalSaved: (VaultPayload) -> Unit,
    ): LanSyncResult {
        // 上传期间本地被并发修改（_state 被新的密封 payload 替换）则放弃本次结果。
        if (_state.value.payload !== expectedStatePayload) throw CloudSyncRetryNeeded()
        return when (action.relation) {
            PmvELineageRelation.REMOTE_STALE -> LanSyncResult(
                action.localPayload,
                action.acceptedLocal?.stats ?: VaultOps.LwwMergeStats(takeLocal = action.localPayload.entries.size),
                uploaded = true,
                verified = true,
                keyConvergence = action.keyConvergence,
            )
            PmvELineageRelation.DIVERGED -> {
                val installed = repository.installPreparedMergedFile(
                    candidate = action.source,
                    rootKey = rootKey,
                    expectedCurrent = requireNotNull(action.expectedCurrent),
                    expectedMerged = requireNotNull(action.expectedMerged),
                )
                val stats = VaultOps.mergeLww(
                    action.localPayload,
                    installed.payload.entries,
                    incomingExportEpoch = installed.payload.exportEpoch,
                    incomingPurgeTombstones = installed.payload.purgeTombstones,
                    incomingDeletionBaseline = installed.payload.deletionBaseline,
                    incomingExclusions = installed.payload.autofillExclusions,
                    ).second
                onLocalSaved(installed.payload)
                LanSyncResult(
                    installed.payload,
                    stats,
                    uploaded = true,
                    verified = true,
                    replacementRootKey = installed.rootKey,
                    replacementIdentity = installed.identity,
                    keyConvergence = action.keyConvergence,
                )
            }
            else -> error("未知的上传同步关系")
        }
    }

    private fun uploadDrivePmvEAndVerify(
        uri: Uri,
        source: File,
        expectedRemote: CloudFileVersion,
        repository: VaultRepository,
        rootKey: ByteArray,
        expectedIdentity: VaultIdentity,
        expectedRemoteIdentity: VaultIdentity?,
    ) {
        markCloudBusy("drive", getApplication<Application>().getString(R.string.viewmodel_cloud_drive), getApplication<Application>().getString(R.string.viewmodel_cloud_busy_merge_upload))
        require(source.length() in 1..MAX_REMOTE_VAULT_BYTES) {
            "本地保险库大小为 0 或超过 1 GB 安全限制"
        }
        val before = CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion()
        CloudFileTransferGuard.requireUnchanged(expectedRemote, before)
        // SAF 云盘没有条件写入能力。即使服务商提供了 size/mtime，写入前仍需用
        // 已认证的保险库身份复核一次，避免元数据未及时刷新时覆盖其他设备的提交。
        verifyDriveRemoteIdentityBeforeWrite(uri, repository, rootKey, expectedRemoteIdentity)
        writeCloudFile(uri, source)
        val verification = newCloudTempFile("drive-pmve-verify")
        try {
            markCloudBusy("drive", getApplication<Application>().getString(R.string.viewmodel_cloud_drive), getApplication<Application>().getString(R.string.viewmodel_cloud_busy_readback))
            var lastFailure: Throwable? = null
            var matched = false
            for (waitMs in CLOUD_CONTENT_READBACK_DELAYS_MS) {
                if (waitMs > 0L) Thread.sleep(waitMs)
                val attempt = runCatching {
                    val observed = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                    require(readCloudFileTo(uri, verification) > 0L) { "云端回读文件为空" }
                    val verified = repository.authenticateExternalFileWithDeviceKey(verification, rootKey)
                    require(verified.identity == expectedIdentity) { "云端仍返回写入前版本" }
                    val after = runCatching { CloudTreeStorage.metadata(getApplication(), uri).toCloudFileVersion() }.getOrNull()
                    if (observed != null && after != null && observed.matches(after)) rememberRemoteUpdateProof("drive", uri.toString(), observed, expectedRemote)
                }
                if (attempt.isSuccess) {
                    matched = true
                    break
                }
                lastFailure = attempt.exceptionOrNull()
            }
            if (!matched) throw CloudFileConflict(
                getApplication<Application>().getString(R.string.viewmodel_remote_publish_failed, lastFailure?.message ?: getApplication<Application>().getString(R.string.viewmodel_cloud_not_published)),
            )
        } finally {
            verification.delete()
        }
    }

    private fun verifyDriveRemoteIdentityBeforeWrite(
        uri: Uri,
        repository: VaultRepository,
        rootKey: ByteArray,
        expectedRemoteIdentity: VaultIdentity?,
    ) {
        val current = newCloudTempFile("drive-prewrite")
        try {
            val bytes = readCloudFileTo(uri, current)
            if (expectedRemoteIdentity == null) {
                if (bytes > 0L) throw CloudFileConflict("远端文件已由其他设备写入")
                return
            }
            require(bytes > 0L) { "远端文件在同步期间变为空" }
            val authenticated = repository.authenticateExternalFileWithDeviceKey(current, rootKey)
            if (authenticated.identity != expectedRemoteIdentity) {
                throw CloudFileConflict("远端文件已由其他设备更新")
            }
        } catch (conflict: CloudFileConflict) {
            throw conflict
        } catch (error: Throwable) {
            throw CloudFileConflict(getApplication<Application>().getString(R.string.viewmodel_remote_verify_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_content_verification_failed)))
        } finally {
            current.delete()
        }
    }

    private fun uploadWebDavPmvEAndVerify(
        config: WebDavConfig,
        source: File,
        expectedRemote: WebDavMetadata,
        repository: VaultRepository,
        rootKey: ByteArray,
        expectedIdentity: VaultIdentity,
        expectedRemoteIdentity: VaultIdentity?,
    ) {
        markCloudBusy("webdav", config.label, getApplication<Application>().getString(R.string.viewmodel_cloud_busy_merge_upload))
        val hasAtomicVersion = !expectedRemote.exists || expectedRemote.etag?.startsWith('"') == true
        if (hasAtomicVersion) {
            WebDavCloud.uploadIfUnchanged(config, source, expectedRemote)
        } else {
            // 弱 ETag、仅 size/mtime 或完全无版本信息都不能构成可靠的条件写入。
            // 先解密认证当前远端，再在写后回读；若期间发生竞争，由外层重新下载合并。
            verifyWebDavRemoteIdentityBeforeWrite(config, repository, rootKey, expectedRemoteIdentity)
            WebDavCloud.uploadOverwrite(config, source)
        }
        val verification = newCloudTempFile("webdav-pmve-verify")
        try {
            markCloudBusy("webdav", config.label, getApplication<Application>().getString(R.string.viewmodel_cloud_busy_readback))
            var lastFailure: Throwable? = null
            var matched = false
            for (waitMs in CLOUD_CONTENT_READBACK_DELAYS_MS) {
                if (waitMs > 0L) Thread.sleep(waitMs)
                val attempt = runCatching {
                    val observed = runCatching { WebDavCloud.metadataOnly(config).toCloudFileVersion() }.getOrNull()
                    WebDavCloud.downloadTo(config, verification)
                    val verified = repository.authenticateExternalFileWithDeviceKey(verification, rootKey)
                    require(verified.identity == expectedIdentity) { "WebDAV 仍返回写入前版本" }
                    val after = runCatching { WebDavCloud.metadataOnly(config).toCloudFileVersion() }.getOrNull()
                    if (observed != null && after != null && observed.matches(after)) remoteAssociation("webdav")?.takeIf { it.config == config }?.let { rememberRemoteUpdateProof("webdav", it.identity, observed, expectedRemote.toCloudFileVersion()) }
                }
                if (attempt.isSuccess) {
                    matched = true
                    break
                }
                lastFailure = attempt.exceptionOrNull()
            }
            if (!matched) throw CloudFileConflict(
                getApplication<Application>().getString(R.string.viewmodel_remote_publish_failed, lastFailure?.message ?: getApplication<Application>().getString(R.string.viewmodel_server_not_published)),
            )
        } finally {
            verification.delete()
        }
    }

    private fun verifyWebDavRemoteIdentityBeforeWrite(
        config: WebDavConfig,
        repository: VaultRepository,
        rootKey: ByteArray,
        expectedRemoteIdentity: VaultIdentity?,
    ) {
        val current = newCloudTempFile("webdav-prewrite")
        try {
            val remote = WebDavCloud.downloadIfExistsTo(config, current)
            if (expectedRemoteIdentity == null) {
                if (remote != null && remote.size > 0L) throw CloudFileConflict("WebDAV 远端已由其他设备写入")
                return
            }
            require(remote != null && remote.size > 0L) { "WebDAV 远端文件在同步期间变为空" }
            val authenticated = repository.authenticateExternalFileWithDeviceKey(current, rootKey)
            if (authenticated.identity != expectedRemoteIdentity) {
                throw CloudFileConflict("WebDAV 远端已由其他设备更新")
            }
        } catch (conflict: CloudFileConflict) {
            throw conflict
        } catch (error: Throwable) {
            throw CloudFileConflict(getApplication<Application>().getString(R.string.viewmodel_remote_verify_failed, error.message ?: getApplication<Application>().getString(R.string.viewmodel_content_verification_failed)))
        } finally {
            current.delete()
        }
    }

    private fun cloudPreviewAssociationKey(provider: String, material: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("${cloudVaultKey()}\u0000$provider\u0000$material".toByteArray())
            .joinToString("") { "%02x".format(it) }
        return "$provider:$digest"
    }

    private fun webDavPreviewAssociationKey(config: WebDavConfig): String = cloudPreviewAssociationKey(
        "webdav",
        listOf(
            config.fileUrl,
            config.username,
            config.authMode,
            config.certificateSha256,
            config.password,
            config.bearerToken,
            config.cookie,
            config.clientCertificate,
        ).joinToString("\u0000"),
    )

    fun cachedCloudVaultPreview(uri: Uri): CloudSyncPreview? = cloudPreviewCache.cached(
        "drive",
        cloudPreviewAssociationKey("drive", uri.toString()),
    )

    fun cachedWebDavPreview(): CloudSyncPreview? {
        val config = loadCloudConfig() ?: return null
        return cloudPreviewCache.cached("webdav", webDavPreviewAssociationKey(config))
    }

    fun previewCloudVault(
        uri: Uri,
        force: Boolean = false,
        onResult: (CloudSyncPreview) -> Unit,
    ) = viewModelScope.launch {
        val associationKey = cloudPreviewAssociationKey("drive", uri.toString())
        if (!cloudPreviewCache.begin("drive", associationKey, force)) {
            cloudPreviewCache.await("drive", associationKey)?.let(onResult)
            return@launch
        }
        try {
            cloudDiskOperationJob?.join()
        val r = repo() ?: run {
            val result = CloudSyncPreview("error", cloudDisplayLabel("drive"), message = getApplication<Application>().getString(R.string.viewmodel_vault_locked))
            cloudPreviewCache.complete("drive", associationKey, result)
            onResult(result)
            return@launch
        }
        val result = runCatching {
            withContext(Dispatchers.IO) {
                vaultOperationMutex.withLock {
                    if (!r.isPmvE()) {
                        CloudSyncPreview(
                            "legacy", cloudDisplayLabel("drive"),
                            message = getApplication<Application>().getString(R.string.viewmodel_legacy_cloud_preview),
                        )
                    } else {
                        val root = _state.value.credential.sessionRootKey() ?: error("保险库会话已失效")
                        val remoteFile = newCloudTempFile("drive-preview")
                        val downloaded = runCatching {
                            CloudTreeStorage.metadata(getApplication(), uri)
                            readCloudFileTo(uri, remoteFile)
                        }.getOrNull()
                        try {
                            root.withRootKey(root.identity) { key ->
                                pmveCloudPreview(
                                    cloudDisplayLabel("drive"), r, key,
                                    remoteFile = if (downloaded != null) remoteFile else null,
                                    remoteMissing = downloaded == null,
                                    remoteBytes = downloaded ?: 0L,
                                )
                            }
                        } finally {
                            remoteFile.delete()
                        }
                    }
                }
            }
        }.getOrElse {
            CloudSyncPreview(
                "error",
                cloudDisplayLabel("drive"),
                message = getApplication<Application>().getString(
                    R.string.viewmodel_cloud_preview_operation_failed,
                    it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                ),
            )
        }
        cloudPreviewCache.complete("drive", associationKey, result)
        onResult(result)
        } finally {
            cloudPreviewCache.cancel("drive", associationKey)
        }
    }

    fun cloudVaultFileName(accountName: String): String = CloudTreeStorage.vaultFileName(accountName)

    fun inspectCloudDirectory(
        treeUri: Uri,
        expectedName: String,
        onResult: (CloudDirectoryInspection?) -> Unit,
    ) = viewModelScope.launch {
        _state.update { it.copy(cloudSyncRunning = true) }
        runCatching { withContext(Dispatchers.IO) { CloudTreeStorage.inspect(getApplication(), treeUri, expectedName) } }
            .onSuccess {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                onResult(it)
            }
            .onFailure {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                emitError(getApplication<Application>().getString(R.string.viewmodel_cloud_directory_check_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
                onResult(null)
            }
    }

    fun createCloudFile(
        treeUri: Uri,
        displayName: String,
        onResult: (Uri?) -> Unit,
    ) = viewModelScope.launch {
        _state.update { it.copy(cloudSyncRunning = true) }
        runCatching { withContext(Dispatchers.IO) { CloudTreeStorage.create(getApplication(), treeUri, displayName) } }
            .onSuccess {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                onResult(it)
            }
            .onFailure {
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                emitError(getApplication<Application>().getString(R.string.viewmodel_cloud_file_create_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
                onResult(null)
            }
    }

    fun checkCloudFileAssociation(
        treeUri: Uri,
        expectedName: String,
        currentFileUri: Uri,
        onResult: (CloudFileCheck?) -> Unit,
    ) = viewModelScope.launch {
        val result = runCatching {
            withContext(Dispatchers.IO) {
                CloudTreeStorage.check(getApplication(), treeUri, expectedName, currentFileUri)
            }
        }.getOrNull()
        onResult(result)
    }

    fun testWebDav(config: WebDavConfig, onResult: (Boolean, Boolean) -> Unit) = viewModelScope.launch {
        _state.update { it.copy(cloudSyncRunning = true) }
        runCatching { withContext(Dispatchers.IO) {
            val remote = WebDavCloud.inspectAssociation(config)
            remote.exists && remote.size != 0L
        } }
            .onSuccess { hasData ->
                _state.update { it.copy(cloudSyncRunning = false) }
                emitInfo(getApplication<Application>().getString(R.string.viewmodel_cloud_connected, config.label))
                onResult(true, hasData)
            }
            .onFailure {
                _state.update { it.copy(cloudSyncRunning = false) }
                emitError(getApplication<Application>().getString(R.string.viewmodel_connection_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
                onResult(false, false)
            }
    }

    fun overwriteWebDav(candidate: WebDavConfig? = null, onResult: (Boolean) -> Unit = {}): Job {
        val sessionToken = captureVaultSession()
        val job = viewModelScope.launch {
        if (!isVaultSessionCurrent(sessionToken)) return@launch
        val r = repo() ?: run { onResult(false); return@launch }
        val config = candidate ?: loadCloudConfig()
            ?: run { emitError(getApplication<Application>().getString(R.string.viewmodel_connect_webdav_first)); onResult(false); return@launch }
        val dismissedVersion = if (remoteAssociation("webdav")?.config == config) com.vault.storage.RemoteUpdatePrefs.load(getApplication(), vaultName(), "webdav").pending else ""
        _state.update { it.copy(cloudSyncRunning = true) }
        markCloudBusy(
            "webdav",
            config.label,
            getApplication<Application>().getString(R.string.viewmodel_cloud_busy_upload_target, config.label),
        )
        runCatching {
            withContext(Dispatchers.IO) {
                requireVaultSessionCurrent(sessionToken)
                vaultOperationMutex.withLock {
                    requireVaultSessionCurrent(sessionToken)
                    // 先连接 WebDAV：连接失败直接暴露真实原因，避免被“会话已失效”之类的提示掩盖。
                    val before = WebDavCloud.metadata(config)
                    val current = _state.value.payload?.let(::materializePayload)
                        ?: error("保险库会话已失效，请重新解锁后重试")
                    val snapshot = createSyncSnapshot(r)
                    try {
                        val verifiedUpload = WebDavCloud.uploadOverwrite(config, snapshot) { sent, total ->
                            if (total > 0L) {
                                updateCloudBusyProgress((sent.toFloat() / total).coerceIn(0f, 1f))
                            }
                        }
                        val remoteModifiedAt = verifiedUpload.lastModified
                        remoteAssociation("webdav")?.takeIf { it.config == config }?.let { rememberRemoteUpdateProof("webdav", it.identity, verifiedUpload.toCloudFileVersion(), consumedVersion = dismissedVersion) }
                        if (remoteModifiedAt > 0L) r.syncFile().setLastModified(remoteModifiedAt)
                    } finally {
                        snapshot.delete()
                    }
                }
            }
        }.onSuccess {
            if (!isVaultSessionCurrent(sessionToken)) return@onSuccess
            _state.update { it.copy(cloudSyncRunning = false) }
            setExternalActionInProgress(false)
            finishCloudBusyOk("webdav", config.label)
            emitInfo(getApplication<Application>().getString(R.string.viewmodel_remote_file_overwritten, config.label))
            onResult(true)
            }.onFailure {
                if (it is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                    // 取消也要清忙碌位：它会挡住 AppRoot 的空闲超时锁库。
                    // 同时复位 phase，否则 RUNNING 残留会永久挡死后续自动同步。
                    _state.update { it.copy(cloudSyncRunning = false) }
                    clearCloudBusy()
                    return@onFailure
            }
            _state.update { it.copy(cloudSyncRunning = false) }
            setExternalActionInProgress(false)
            failCloudSync("webdav", config.label, getApplication<Application>().getString(R.string.viewmodel_cloud_upload_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)), false)
            emitError(getApplication<Application>().getString(R.string.viewmodel_cloud_upload_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
            onResult(false)
        }
        }
        webDavOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            vaultSessionJobs.remove(job)
            if (webDavOperationJob === job) webDavOperationJob = null
        }
        return job
    }

    fun downloadOverwriteWebDav(candidate: WebDavConfig? = null, onResult: (Boolean) -> Unit = {}): Job {
        val sessionToken = captureVaultSession()
        val job = viewModelScope.launch {
        if (!isVaultSessionCurrent(sessionToken)) return@launch
        val r = repo() ?: run { onResult(false); return@launch }
        val config = candidate ?: loadCloudConfig()
            ?: run { emitError(getApplication<Application>().getString(R.string.viewmodel_connect_webdav_first)); onResult(false); return@launch }
        _state.update { it.copy(cloudSyncRunning = true) }
        markCloudBusy(
            "webdav",
            config.label,
            getApplication<Application>().getString(R.string.viewmodel_cloud_busy_download_target, config.label),
        )
        SyncForegroundService.beginTask(
            getApplication(),
            CLOUD_WEBDAV_DOWNLOAD_TASK_ID,
            BackgroundTaskKind.CLOUD_SYNC,
            localizeUiTextFor(getApplication(), "${config.label}同步"),
            localizeUiTextFor(getApplication(), "正在下载并校验 ${config.label} 远端文件…"),
        )
        runCatching {
            // finally 兜底释放外部操作豁免：取消/异常路径原先直接 return，标志会一直停在 true，
            // 之后退后台与空闲超时都不再锁库（H-04 的第三条泄漏路径）。
            withExternalActionFlag({ setExternalActionInProgress(it) }) {
                withContext(Dispatchers.IO) {
                    requireVaultSessionCurrent(sessionToken)
                    vaultOperationMutex.withLock {
                        requireVaultSessionCurrent(sessionToken)
                        val local = _state.value.payload?.let(::materializePayload) ?: error("保险库会话已失效")
                        val remoteMetadata = WebDavCloud.metadata(config)
                        val remoteFile = newCloudTempFile("webdav-download")
                        try {
                            val remote = WebDavCloud.downloadTo(config, remoteFile)
                            val downloadedVersion = if (!remote.etag.isNullOrBlank()) CloudFileVersion(true, remote.size, 0, remote.etag) else runCatching { WebDavCloud.metadataOnly(config).toCloudFileVersion().takeIf { remoteMetadata.toCloudFileVersion().matches(it) } }.getOrNull()
                            require(remote.size > 0L) { "WebDAV 保险库文件为空" }
                            replaceCurrentFromRemoteFile(r, local, remoteFile).also {
                                if (remoteMetadata.lastModified > 0L) r.syncFile().setLastModified(remoteMetadata.lastModified)
                                downloadedVersion?.let { version -> remoteAssociation("webdav")?.takeIf { it.config == config }?.let { rememberRemoteUpdateProof("webdav", it.identity, version) } }
                            }
                        } finally {
                            remoteFile.delete()
                        }
                    }
                }
            }
        }.onSuccess { remote ->
            if (!isVaultSessionCurrent(sessionToken)) return@onSuccess
            _state.update { it.withPayload(sealPayload(remote)).copy(cloudSyncRunning = false) }
            clearSecurityReport()
            finishCloudBusyOk("webdav", config.label)
            SyncForegroundService.succeedTask(
                getApplication(),
                CLOUD_WEBDAV_DOWNLOAD_TASK_ID,
                localizeUiTextFor(getApplication(), "已从 ${config.label} 下载并验证保险库，本地文件已原子替换"),
            )
            emitInfo("已从 WebDAV 下载并验证保险库，本地文件已原子替换")
            onResult(true)
        }.onFailure {
            if (it is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                // 取消/会话失效同样要收尾：cloudSyncRunning 会挡住 AppRoot 的空闲超时锁库
                // （见 AppRoot 的「云端同步进行中不锁库」判断），留着就再也不锁。
                // 外部操作豁免由 withExternalActionFlag 的 finally 负责释放。
                // 同时复位 phase，否则 RUNNING 残留会永久挡死后续自动同步。
                _state.update { state -> state.copy(cloudSyncRunning = false) }
                clearCloudBusy()
                return@onFailure
            }
            _state.update { state -> state.copy(cloudSyncRunning = false) }
            SyncForegroundService.failTask(
                getApplication(),
                CLOUD_WEBDAV_DOWNLOAD_TASK_ID,
                localizeUiTextFor(getApplication(), "下载覆盖失败，本地数据已保留：${it.message}"),
            )
            failCloudSync("webdav", config.label, "下载覆盖失败，本地数据已保留：${it.message}", false)
            emitError("下载覆盖失败，本地数据已保留：${it.message}")
            onResult(false)
        }
        }
        webDavOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            vaultSessionJobs.remove(job)
            if (webDavOperationJob === job) webDavOperationJob = null
        }
        return job
    }

    fun syncWebDav(
        candidate: WebDavConfig? = null,
        allowDifferentVault: Boolean = false,
        notifyUser: Boolean = true,
        onResult: (Boolean) -> Unit = {},
    ): Job {
        val sessionToken = captureVaultSession()
        val app = getApplication<Application>()
        // 与云端硬盘同步同构的幂等收尾：提前退出必须复位状态、释放前台任务并回调，
        // 否则 phase 停在 RUNNING 会把自动同步门禁永久挡死。
        val claimed = AtomicBoolean(false)
        val taskStarted = AtomicBoolean(false)
        val settled = AtomicBoolean(false)
        val settle: () -> Unit = {
            if (settled.compareAndSet(false, true)) {
                onResult(false)
                if (claimed.compareAndSet(true, false)) {
                    _state.update { state -> state.copy(cloudSyncRunning = false) }
                    clearCloudBusy()
                }
                if (taskStarted.compareAndSet(true, false)) {
                    SyncForegroundService.failTask(
                        app,
                        CLOUD_WEBDAV_SYNC_TASK_ID,
                        localizeUiTextFor(app, "同步已中断"),
                    )
                }
            }
        }
        val job = viewModelScope.launch {
            if (!isVaultSessionCurrent(sessionToken)) { onResult(false); return@launch }
            val r = repo() ?: run { onResult(false); return@launch }
            val config = candidate ?: loadCloudConfig()
                ?: run { emitError(app.getString(R.string.viewmodel_connect_webdav_first)); onResult(false); return@launch }
            if (!beginCloudSync("webdav", config.label)) {
                onResult(false)
                return@launch
            }
            claimed.set(true)
            if (notifyUser) {
                SyncForegroundService.beginTask(
                    app,
                    CLOUD_WEBDAV_SYNC_TASK_ID,
                    BackgroundTaskKind.CLOUD_SYNC,
                    localizeUiTextFor(app, "${config.label}同步"),
                    localizeUiTextFor(app, "正在下载并合并云端数据…"),
                )
                taskStarted.set(true)
            }
            markCloudBusy(
                "webdav",
                config.label,
                getApplication<Application>().getString(R.string.viewmodel_cloud_busy_download_verify),
            )
            var savedPayload: VaultPayload? = null
            var aborted = false
            var keyConvergence = KeyConvergenceKind.NONE
            val result = try {
                withContext(Dispatchers.IO) {
                    requireVaultSessionCurrent(sessionToken)
                    val remoteFile = newCloudTempFile("webdav-sync")
                    val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
                    val rootKey = rootSession.copyRootKey(rootSession.identity)
                    try {
                        var attempts = 0
                        var outcome: Pair<VaultPayload, VaultOps.LwwMergeStats>? = null
                        while (outcome == null) {
                            // 锁外：元数据 + 下载（纯网络/临时文件，不触碰保险库文件）
                            val before = WebDavCloud.metadata(config)
                            val downloaded = WebDavCloud.downloadIfExistsTo(config, remoteFile)
                            val downloadedVersion = downloaded?.let { file -> if (!file.etag.isNullOrBlank()) CloudFileVersion(true, file.size, 0, file.etag) else runCatching { WebDavCloud.metadataOnly(config).toCloudFileVersion().takeIf { before.toCloudFileVersion().matches(it) } }.getOrNull() }
                            // 每轮重取本端快照：与 drive 路径一致，CAS 冲突重试时用最新的本地
                            // 内容参与合并，不沿用首轮快照。materializePayload 只在内存中解密
                            // 密封条目，不产生额外网络或磁盘 I/O。
                            var local: VaultPayload? = null
                            // 锁内：快照、认证、分类、合并准备与可立即完成的安装
                            val (action, statePayloadBefore) = vaultOperationMutex.withLock {
                                requireVaultSessionCurrent(sessionToken)
                                local = _state.value.payload?.let(::materializePayload)
                                    ?: error("保险库会话已失效")
                                val stateBefore = _state.value.payload
                                if (!r.isPmvE()) error("旧格式云端同步已移除，仅支持 PMVE")
                                val preparedAction = syncPmvEWebDav(
                                    repository = r,
                                    localPayload = local,
                                    config = config,
                                    downloadedFile = remoteFile,
                                    downloaded = downloaded,
                                    expectedRemote = before,
                                    rootKey = rootKey,
                                )
                                // 会话根密钥替换与文件写同锁：避免并发编辑读到已关闭的旧密钥。
                                if (preparedAction is CloudSyncAction.Completed) {
                                    applyPmvEReplacement(preparedAction.result)
                                } else if (preparedAction is CloudSyncAction.UploadPending) {
                                    preparedAction.acceptedLocal?.let { accepted ->
                                        savedPayload = accepted.payload
                                        applyPmvEReplacement(accepted)
                                    }
                                }
                                preparedAction to stateBefore
                            }
                            if (action is CloudSyncAction.Completed) {
                                val result = action.result
                                downloadedVersion?.let { version -> remoteAssociation("webdav")?.takeIf { it.config == config }?.let { rememberRemoteUpdateProof("webdav", it.identity, version) } }
                                keyConvergence = result.keyConvergence
                                if (result.payload !== local) savedPayload = result.payload
                                outcome = result.payload to result.stats
                                break
                            }
                            val pending = action as CloudSyncAction.UploadPending
                            // 锁外：条件上传 + 回读校验；远端被其他设备更新则重拉重合并
                            try {
                                uploadWebDavPmvEAndVerify(
                                    config, pending.source, before, r, rootKey, pending.expectedIdentity,
                                    pending.expectedRemoteIdentity,
                                )
                            } catch (conflict: com.vault.storage.CloudFileConflict) {
                                if (pending.source != remoteFile) pending.source.delete()
                                if (++attempts >= MAX_WEBDAV_SYNC_ATTEMPTS) throw conflict
                                markCloudBusy(
                                    "webdav",
                                    config.label,
                                    getApplication<Application>().getString(
                                        R.string.viewmodel_cloud_busy_retry_remote,
                                        attempts + 1,
                                        MAX_WEBDAV_SYNC_ATTEMPTS,
                                    ),
                                )
                                delay(250L)
                                continue
                            } catch (conflict: com.vault.storage.WebDavConflict) {
                                if (pending.source != remoteFile) pending.source.delete()
                                if (++attempts >= MAX_WEBDAV_SYNC_ATTEMPTS) throw conflict
                                markCloudBusy(
                                    "webdav",
                                    config.label,
                                    getApplication<Application>().getString(
                                        R.string.viewmodel_cloud_busy_retry_remote,
                                        attempts + 1,
                                        MAX_WEBDAV_SYNC_ATTEMPTS,
                                    ),
                                )
                                delay(250L)
                                continue
                            }
                            // 锁内：安装合并提交 / 收尾；上传期间本地被并发修改则重拉重合并
                            try {
                                val finalized = vaultOperationMutex.withLock {
                                    requireVaultSessionCurrent(sessionToken)
                                    val done = finalizeCloudSyncAction(
                                        pending, r, rootKey, statePayloadBefore,
                                    ) { savedPayload = it }
                                    applyPmvEReplacement(done)
                                    done
                                }
                                pending.source.delete()
                                keyConvergence = finalized.keyConvergence
                                if (finalized.payload !== local) savedPayload = finalized.payload
                                outcome = finalized.payload to finalized.stats
                            } catch (retry: CloudSyncRetryNeeded) {
                                if (pending.source != remoteFile) pending.source.delete()
                                if (++attempts >= MAX_WEBDAV_SYNC_ATTEMPTS) throw retry
                                markCloudBusy(
                                    "webdav",
                                    config.label,
                                    getApplication<Application>().getString(
                                        R.string.viewmodel_cloud_busy_retry_local,
                                        attempts + 1,
                                        MAX_WEBDAV_SYNC_ATTEMPTS,
                                    ),
                                )
                                delay(250L)
                            }
                        }
                        requireNotNull(outcome)
                    } finally {
                        rootKey.fill(0)
                        remoteFile.delete()
                    }
                }
            } catch (error: Throwable) {
                if (error is kotlinx.coroutines.CancellationException || !isVaultSessionCurrent(sessionToken)) {
                    settle()
                    return@launch
                }
                val stablePayload = savedPayload
                if (stablePayload != null) {
                    // 失败前已合并/落盘：锁内把会话密封与索引重建放到后台线程。
                    val published = vaultOperationMutex.withLock {
                        withContext(Dispatchers.Default) {
                            publishPayloadForSession(sessionToken, stablePayload)
                        }
                    }
                    if (!published || !isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
                }
                val message = cloudSyncError(app.getString(R.string.viewmodel_cloud_sync_failed_prefix, config.label), error, stablePayload != null)
                failCloudSync("webdav", config.label, message, stablePayload != null)
                if (notifyUser) {
                    SyncForegroundService.failTask(
                        app,
                        CLOUD_WEBDAV_SYNC_TASK_ID,
                        localizeUiTextFor(app, message),
                    )
                }
                if (notifyUser) emitError(message)
                settled.set(true)
                onResult(false)
                return@launch
            }
            if (aborted) { settle(); return@launch }
            if (!isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
            // 成功：锁内把会话密封与索引重建放到后台线程，主线程只做轻量状态更新。
            val published = vaultOperationMutex.withLock {
                requireVaultSessionCurrent(sessionToken)
                withContext(Dispatchers.Default) {
                    publishPayloadForSession(sessionToken, result.first)
                }
            }
            if (!published || !isVaultSessionCurrent(sessionToken)) { settle(); return@launch }
            completeCloudSync(
                "webdav", config.label, result.second,
                uploaded = result.second.takeLocal > 0 || result.second.conflicts > 0,
            )
            if (notifyUser) {
                SyncForegroundService.succeedTask(
                    app,
                    CLOUD_WEBDAV_SYNC_TASK_ID,
                    localizeUiTextFor(app, cloudSyncCompletionMessage(result.second)),
                )
            }
            if (keyConvergence != KeyConvergenceKind.NONE) {
                // 密钥/主密码版本收敛提示不区分手动/自动同步：同库端都要自动对齐并获知。
                _keyConvergedNotice.value = KeyConvergedNotice(
                    keyConvergence,
                    keyConvergedMessage(keyConvergence),
                )
            } else if (notifyUser) {
                emitInfo(cloudSyncCompletionMessage(result.second))
            }
            settled.set(true)
            onResult(true)
        }
        webDavOperationJob = job
        vaultSessionJobs += job
        job.invokeOnCompletion {
            // 兜底：自动同步靠回调等待结果；协程被取消时必须替它结束等待。
            if (it != null) settle()
            vaultSessionJobs.remove(job)
            if (webDavOperationJob === job) webDavOperationJob = null
        }
        return job
    }

    fun previewWebDav(
        force: Boolean = false,
        onResult: (CloudSyncPreview) -> Unit,
    ) = viewModelScope.launch {
        val config = loadCloudConfig()
        if (config == null) {
            onResult(CloudSyncPreview("unlinked", cloudDisplayLabel("webdav"), message = getApplication<Application>().getString(R.string.viewmodel_cloud_unlinked)))
            return@launch
        }
        val associationKey = webDavPreviewAssociationKey(config)
        if (!cloudPreviewCache.begin("webdav", associationKey, force)) {
            cloudPreviewCache.await("webdav", associationKey)?.let(onResult)
            return@launch
        }
        try {
            webDavOperationJob?.join()
        val r = repo() ?: run {
            val result = CloudSyncPreview("error", cloudDisplayLabel("webdav"), message = getApplication<Application>().getString(R.string.viewmodel_vault_locked))
            cloudPreviewCache.complete("webdav", associationKey, result)
            onResult(result)
            return@launch
        }
        val result = runCatching {
            withContext(Dispatchers.IO) {
                vaultOperationMutex.withLock {
                    if (!r.isPmvE()) {
                        CloudSyncPreview(
                            "legacy", cloudDisplayLabel("webdav"),
                            message = getApplication<Application>().getString(R.string.viewmodel_legacy_cloud_preview),
                        )
                    } else {
                        val remote = WebDavCloud.metadata(config)
                        val root = _state.value.credential.sessionRootKey()
                            ?: error("保险库会话已失效，请重新解锁后重试")
                        val app = getApplication<Application>()
                        val cacheFile = File(
                            app.cacheDir,
                            "webdav-preview-${AutoCloudSyncPrefs.suffix(cloudVaultKey())}.pmv",
                        )
                        val downloaded = if (remote.exists) {
                            val cached = AutoCloudSyncPrefs.loadWebDavPreviewCache(app, cloudVaultKey())
                            if (remote.etag != null && cached.etag == remote.etag &&
                                cacheFile.isFile && cacheFile.length() == cached.size
                            ) {
                                // 远端未变化：复用上次检测的缓存文件，不再整包下载。
                                com.vault.storage.WebDavRemoteFile(cacheFile, remote.etag, cacheFile.length())
                            } else {
                                try {
                                    val fetched = WebDavCloud.downloadTo(config, cacheFile)
                                    if (remote.etag != null) {
                                        AutoCloudSyncPrefs.saveWebDavPreviewCache(
                                            app, cloudVaultKey(), remote.etag, fetched.size,
                                        )
                                    }
                                    fetched
                                } catch (failure: Throwable) {
                                    // 远端元数据存在但整包下载失败：报真实原因，不再误报“远端文件不存在”。
                                    val reason = failure.message?.ifBlank { null }
                                        ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)
                                    return@withLock CloudSyncPreview(
                                        "error", cloudDisplayLabel("webdav"),
                                        message = getApplication<Application>().getString(
                                            R.string.viewmodel_cloud_preview_download_failed,
                                            reason,
                                        ),
                                    )
                                }
                            }
                        } else null
                        root.withRootKey(root.identity) { key ->
                            pmveCloudPreview(
                                cloudDisplayLabel("webdav"), r, key,
                                remoteFile = downloaded?.file ?: null,
                                remoteMissing = downloaded == null,
                                remoteBytes = remote.size,
                            )
                        }
                    }
                }
            }
        }.getOrElse {
            CloudSyncPreview(
                "error",
                cloudDisplayLabel("webdav"),
                message = getApplication<Application>().getString(
                    R.string.viewmodel_cloud_preview_operation_failed,
                    it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                ),
            )
        }
        cloudPreviewCache.complete("webdav", associationKey, result)
        onResult(result)
        } finally {
            cloudPreviewCache.cancel("webdav", associationKey)
        }
    }

    /**
     * PMVE 云端预览：下载远端文件并认证，展示提交序号/密钥版本/谱系关系，
     * 明确报错；不再基于文件修改时间判断。
     */
    private fun pmveCloudPreview(
        source: String,
        repository: VaultRepository,
        rootKey: ByteArray,
        remoteFile: File?,
        remoteMissing: Boolean,
        remoteBytes: Long,
    ): CloudSyncPreview {
        val localAuth = repository.authenticateExternalFileWithDeviceKey(repository.syncFile(), rootKey)
        val localIdentity = requireNotNull(localAuth.identity) { "本地保险库身份缺失" }
        val localPayload = _state.value.payload?.let(::materializePayload)
        val localActive = localPayload?.entries?.count { it.deletedAt == null } ?: 0
        val localTrash = localPayload?.entries?.count { it.deletedAt != null } ?: 0
        // 真实密钥版本：元数据 sync_meta.key_revision（主密码/恢复密钥每次变更 +1），
        // 而非头部常量 key_revision（建库后固定为 1）。
        val localKeyRevision = localPayload?.syncMeta?.keyRevision?.toLong() ?: 0L
        if (remoteMissing || remoteFile == null || remoteBytes <= 0L) {
            return CloudSyncPreview(
                kind = "remote_missing", source = source,
                localActive = localActive, localTrash = localTrash,
                localSequence = localIdentity.sequence,
                localKeyRevision = localKeyRevision,
                message = getApplication<Application>().getString(R.string.viewmodel_cloud_preview_missing),
            )
        }
        val remoteAuth = runCatching {
            repository.authenticateExternalFileWithDeviceKey(remoteFile, rootKey)
        }.getOrElse { error ->
            return CloudSyncPreview(
                kind = "error", source = source,
                localActive = localActive, localTrash = localTrash,
                localSequence = localIdentity.sequence,
                localKeyRevision = localKeyRevision,
                message = getApplication<Application>().getString(
                    R.string.viewmodel_cloud_preview_auth_failed,
                    error.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
                ),
            )
        }
        val remoteIdentity = remoteAuth.identity
        if (remoteIdentity == null) {
            return CloudSyncPreview(
                kind = "error", source = source,
                localActive = localActive, localTrash = localTrash,
                localSequence = localIdentity.sequence,
                localKeyRevision = localKeyRevision,
                message = getApplication<Application>().getString(R.string.viewmodel_cloud_preview_invalid_pmve),
            )
        }
        // 读取远端提交的实际条目数（活跃/回收站）与真实密钥版本，避免“远端 0 项”的误判。
        val remoteStats = runCatching {
            PmvVaultStore.openRootKey(remoteFile, rootKey).use { session ->
                val entries = session.listSummaries().mapNotNull { session.readEntry(it.entryId) }
                val meta = session.readMetadata()
                val sync = meta["sync_meta"] as? JsonObject
                val raw = (sync?.get("key_revision") ?: meta["key_revision"]) as? JsonPrimitive
                Triple(
                    entries.count { it.deletedAt == null },
                    entries.count { it.deletedAt != null },
                    raw?.content?.toLongOrNull() ?: 0L,
                )
            }
        }.getOrNull()
        val (kind, relationship, relationText) = when (
            com.vault.storage.classifyAuthenticatedVaultFiles(localAuth, remoteAuth)
        ) {
            VaultFileRelationship.SAME ->
                Triple("same", "same", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_same))
            VaultFileRelationship.REMOTE_DESCENDANT ->
                Triple("remote_ahead", "descendant", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_remote_ahead))
            VaultFileRelationship.LOCAL_DESCENDANT ->
                Triple("local_ahead", "ancestor", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_local_ahead))
            VaultFileRelationship.DIVERGED ->
                Triple("diverged", "diverged", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_diverged))
            VaultFileRelationship.DIFFERENT_VAULT ->
                Triple("different", "different", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_different))
            VaultFileRelationship.INVALID ->
                Triple("error", "invalid", getApplication<Application>().getString(R.string.viewmodel_cloud_relation_invalid))
        }
        return CloudSyncPreview(
            kind = kind, source = source,
            localActive = localActive, localTrash = localTrash,
            remoteActive = remoteStats?.first ?: 0,
            remoteTrash = remoteStats?.second ?: 0,
            remoteBytes = remoteBytes.coerceAtLeast(0L),
            localSequence = localIdentity.sequence,
            remoteSequence = remoteIdentity.sequence,
            localKeyRevision = localKeyRevision,
            remoteKeyRevision = remoteStats?.third ?: 0L,
            relationship = relationship,
            message = relationText,
            remoteWriter = runCatching { repository.authenticatedDeviceWriter(remoteFile, rootKey) }.getOrNull(),
        )
    }

    private fun writeCloudFile(uri: Uri, bytes: ByteArray) {
        val resolver = getApplication<Application>().contentResolver
        resolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
            ?: error("无法写入云端文件")
    }

    private fun newCloudTempFile(prefix: String): File = File(
        getApplication<Application>().cacheDir,
        "cloud_sync/$prefix-${java.util.UUID.randomUUID()}.pmv",
    ).also { it.parentFile?.mkdirs() }

    private fun newSyncTempFile(): File = File(
        getApplication<Application>().cacheDir,
        "lan_sync/${java.util.UUID.randomUUID()}.pmv",
    ).also { it.parentFile?.mkdirs() }

    private fun readCloudFileTo(uri: Uri, target: File): Long {
        val resolver = getApplication<Application>().contentResolver
        try {
            var total = 0L
            resolver.openInputStream(uri)?.buffered()?.use { input ->
                FileOutputStream(target).use { fileOutput ->
                    val output = fileOutput.buffered()
                    val buffer = ByteArray(32 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= MAX_REMOTE_VAULT_BYTES) { "云端文件超过 1 GB 安全限制" }
                        output.write(buffer, 0, count)
                    }
                    output.flush()
                    fileOutput.fd.sync()
                }
            } ?: error("无法读取云端文件")
            return total
        } catch (error: Throwable) {
            target.delete()
            throw error
        }
    }

    private fun writeCloudFile(uri: Uri, source: File) {
        val resolver = getApplication<Application>().contentResolver
        resolver.openOutputStream(uri, "wt")?.buffered()?.use { output ->
            source.inputStream().buffered().use { input -> input.copyTo(output) }
        } ?: error("无法写入云端文件")
    }

    private fun createSyncSnapshot(repository: VaultRepository): File = repository.createSyncSnapshot()

    private fun replaceCurrentFromRemoteFile(
        repository: VaultRepository,
        local: VaultPayload,
        file: File,
    ): VaultPayload {
        val session = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
        return session.withRootKey(session.identity) { key ->
            repository.replaceFromRemoteFile(file, local.syncMeta.deviceId, key)
        }
    }

    private suspend fun verifyCloudWrite(uri: Uri, expectedSize: Long, previousModifiedAt: Long): Long {
        var lastError: Throwable? = null
        for (waitMs in REMOTE_METADATA_DELAYS_MS) {
            if (waitMs > 0) delay(waitMs)
            try {
                val metadata = CloudTreeStorage.metadata(getApplication(), uri)
                check(metadata.size < 0L || metadata.size == expectedSize) { "远端文件大小尚未更新" }
                check(metadata.lastModified <= 0L || previousModifiedAt <= 0L || metadata.lastModified >= previousModifiedAt) {
                    "远端文件修改时间尚未更新"
                }
                return metadata.lastModified
            } catch (error: Throwable) {
                lastError = error
            }
        }
        throw IllegalStateException(
            getApplication<Application>().getString(
                R.string.viewmodel_cloud_metadata_verify_failed,
                lastError?.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error),
            ),
            lastError,
        )
    }

    private fun saveCurrent(
        repository: VaultRepository,
        payload: VaultPayload,
        metaOnly: Boolean = false,
        registry: List<PmvSyncAuthorization.DeviceAuthorization>? = null,
    ) {
        val session = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
        val withExclusions = payload.copy(
            autofillExclusions = payload.autofillExclusions.merge(com.vault.autofill.AutofillExcludePref.snapshot(getApplication(), vaultName())),
        )
        // PMVE 的元数据与条目共享同一份认证提交，不存在单独的 meta-only 写路径。
        session.withRootKey(session.identity) { rootKey ->
            if (registry != null) {
                repository.savePmvEWithRegistry(withExclusions, rootKey, registry)
            } else {
                repository.savePmvE(withExclusions, rootKey)
            }
        }
        runCatching { performLocalBackup() }
    }

    /**
     * 本地定期备份：把当前保险库 .pmv 复制到用户选择的本地目录（覆盖）。
     *
     * 用户可见状态只有两种：
     *  - 设备未连接：静默，不备份、不通知；
     *  - 设备已连接并已触发备份：显示上次备份时间或本次结果（空间不足 / 绑定异常 /
     *    写入失败都归入这一类，如实带出结果而不是新增状态）。
     */
    fun performLocalBackup(force: Boolean = false) {
        val context = getApplication<Application>()
        if (!com.vault.security.LocalBackupPref.isEnabled(context, vaultName())) {
            _localBackupStatus.value = getApplication<Application>().getString(R.string.viewmodel_backup_disabled)
            return
        }
        val rawUri = com.vault.security.LocalBackupPref.treeUri(context, vaultName())
        if (rawUri.isNullOrBlank()) {
            _localBackupStatus.value = getApplication<Application>().getString(R.string.viewmodel_backup_directory_missing)
            return
        }
        if (localBackupRunning) return
        if (!com.vault.storage.LocalBackupRunGuard.tryAcquire()) return
        localBackupRunning = true
        _localBackupRunningFlow.value = true
        _localBackupStatus.value = getApplication<Application>().getString(R.string.viewmodel_backup_in_progress)
        viewModelScope.launch {
            try {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching {
                        val treeUri = Uri.parse(rawUri)
                        val interval = com.vault.security.LocalBackupPref.interval(context, vaultName())
                        if (!com.vault.storage.LocalBackupPolicy.shouldRun(
                                nowMillis = System.currentTimeMillis(),
                                lastBackupMillis = com.vault.security.LocalBackupPref.lastBackupAt(context, vaultName()),
                                intervalMillis = interval,
                                force = force,
                            )
                        ) {
                            return@runCatching "ok"
                        }
                        val expectedRaw = com.vault.security.LocalBackupPref.safId(context, vaultName())
                        val expectedUuid = com.vault.security.LocalBackupPref.deviceUuid(context, vaultName())
                        val currentRaw = currentVolumeIdentity(context, treeUri)
                        val expectedCore = com.vault.storage.StorageVolumeResolver.stableCore(expectedRaw)
                        val currentCore = com.vault.storage.StorageVolumeResolver.stableCore(currentRaw)
                        // 先探测目标卷是否真实可达：未连接 / 授权失效时 SAF 查询返回 null 或抛
                        // FileNotFoundException / “No root”。不可达即「备份设备未连接」；
                        // 可达但绑定/身份不符才为「备份设备状态异常」（见下方 evaluate）。
                        // 注意：query 在设备拔出时通常返回 null（而非抛异常），必须显式判空，
                        // 否则 ?.use{} 会把 null 当成成功而误判为已连接。
                        val probeRootId = runCatching {
                            android.provider.DocumentsContract.getTreeDocumentId(treeUri)
                        }.getOrNull() ?: return@runCatching "backup-device-not-connected"
                        val treeReachable = runCatching {
                            // 探测根文档本身是否可读，不看子目录列表：备份目录为空时
                            // 子目录 query 返回空 cursor，会被误判成设备未连接（而
                            // ExternalRealtimeBackupCopier 探的是根文档，空目录同样通过）。
                            val rootDocUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(
                                treeUri, probeRootId,
                            )
                            val cursor = context.contentResolver.query(
                                rootDocUri,
                                arrayOf(android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID),
                                null, null, null,
                            ) ?: return@runCatching false
                            cursor.use { it.moveToFirst() }
                            true
                        }.getOrElse { false }
                        if (!treeReachable) return@runCatching "backup-device-not-connected"
                        if (currentCore == null) {
                            // 目标 tree URI 无法解析为卷：授权失效或设备未连接。
                            return@runCatching "backup-device-not-connected"
                        }
                        if (expectedCore == null) {
                            // 已保存的卷身份缺失或不可解析：设备可达但无法确认同一设备，属异常状态。
                            return@runCatching "backup-device-abnormal"
                        }
                        val observedUuid = when (val marker = com.vault.storage.SafDeviceMarker.read(context, treeUri)) {
                            is com.vault.storage.SafDeviceMarker.ReadResult.Valid -> marker.deviceUuid
                            else -> null
                        }
                        val bindingState = com.vault.storage.StorageBindingPolicy.evaluate(
                            expectedUuid,
                            expectedCore,
                            observedUuid,
                            currentCore,
                        )
                        com.vault.storage.StorageBindingPolicy.blockedBackupToken(bindingState)?.let {
                            return@runCatching it
                        }
                        val rootId = runCatching {
                            android.provider.DocumentsContract.getTreeDocumentId(treeUri)
                        }.getOrNull() ?: return@runCatching "backup-device-not-connected"
                        val vaultName = _currentVault.value ?: return@runCatching "error"
                        val source = registry.fileFor(vaultName)
                        if (!source.isFile) return@runCatching "error"
                        val resolver = context.contentResolver
                        val rootUri = android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)
                        val targetName = "$vaultName.pmv"
                        val partialName = "$targetName.backup-partial"

                        // 1) 剩余空间预检（API 30+ 可通过卷目录 StatFs 获取；拿不到则跳过预检）
                        val volumeDir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            runCatching {
                                (context.getSystemService(android.content.Context.STORAGE_SERVICE) as android.os.storage.StorageManager)
                                    .getStorageVolume(treeUri)?.directory
                            }.getOrNull()
                        } else {
                            null
                        }
                        if (volumeDir != null) {
                            val available = android.os.StatFs(volumeDir.absolutePath).availableBytes
                            if (source.length() > available) return@runCatching "space"
                        }

                        fun findChild(name: String): Uri? {
                            val childrenUri = android.provider.DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId)
                            resolver.query(
                                childrenUri,
                                arrayOf(
                                    android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                                    android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                                ),
                                null,
                                null,
                                null,
                            )?.use { cursor ->
                                while (cursor.moveToNext()) {
                                    if (cursor.getString(1) == name) {
                                        return android.provider.DocumentsContract.buildDocumentUriUsingTree(
                                            treeUri,
                                            cursor.getString(0),
                                        )
                                    }
                                }
                            }
                            return null
                        }

                        // 2) 崩溃续传：partial 存在且日志匹配 → 跳过已复制前缀并回读前缀计入哈希
                        val digest = java.security.MessageDigest.getInstance("SHA-256")
                        var partialUri = findChild(partialName)
                        if (partialUri != null) {
                            // Size-only journals cannot authenticate the source prefix; restart safely.
                            runCatching { android.provider.DocumentsContract.deleteDocument(resolver, partialUri) }
                            partialUri = null
                        }
                        com.vault.security.LocalBackupPref.setJournal(context, vaultName(), source.length(), targetName, partialName)
                        if (partialUri == null) {
                            partialUri = android.provider.DocumentsContract.createDocument(
                                resolver,
                                rootUri,
                                "application/octet-stream",
                                partialName,
                            ) ?: return@runCatching "error"
                        }

                        // 3) 流式复制（8 MiB 缓冲）：从头或从断点追加，绝不整文件读入内存
                        resolver.openOutputStream(partialUri, "w")?.use { output ->
                            val fileOutput = output as? java.io.FileOutputStream
                            source.inputStream().buffered().use { input ->
                                val buffer = ByteArray(64 * 1024)
                                while (true) {
                                    val count = input.read(buffer)
                                    if (count < 0) break
                                    output.write(buffer, 0, count)
                                    digest.update(buffer, 0, count)
                                }
                            }
                            output.flush()
                            fileOutput?.fd?.sync()
                        } ?: return@runCatching "error"

                        // 4) 回读目标重新校验哈希与大小，杜绝半个文件伪装成完整备份
                        val verify = java.security.MessageDigest.getInstance("SHA-256")
                        val verifiedSize = resolver.openInputStream(partialUri)?.use { input ->
                            var total = 0L
                            val buffer = ByteArray(64 * 1024)
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                verify.update(buffer, 0, count)
                                total += count
                            }
                            total
                        } ?: 0L
                        val sourceHash = digest.digest()
                        if (verifiedSize != source.length() ||
                            !java.security.MessageDigest.isEqual(verify.digest(), sourceHash)
                        ) {
                            return@runCatching "error:" + context.getString(R.string.viewmodel_backup_verify_failed)
                        }

                        // 5) 原子改名为正式文件
                        findChild(targetName)?.let { existing ->
                            runCatching { android.provider.DocumentsContract.deleteDocument(resolver, existing) }
                        }
                        android.provider.DocumentsContract.renameDocument(resolver, partialUri, targetName)
                            ?: return@runCatching "error:" + context.getString(R.string.viewmodel_backup_rename_failed)

                        // 6) 备份清单
                        runCatching {
                            findChild("$targetName.manifest.json")?.let { existing ->
                                android.provider.DocumentsContract.deleteDocument(resolver, existing)
                            }
                            val manifestUri = android.provider.DocumentsContract.createDocument(
                                resolver,
                                rootUri,
                                "application/json",
                                "$targetName.manifest.json",
                            ) ?: return@runCatching Unit
                            resolver.openOutputStream(manifestUri, "w")?.use { output ->
                                output.write(
                                    org.json.JSONObject()
                                        .put("file", targetName)
                                        .put("size", source.length())
                                        .put(
                                            "sha256",
                                            sourceHash.joinToString("") { "%02x".format(it.toInt() and 0xff) },
                                        )
                                        .put("created_at", System.currentTimeMillis() / 1000.0)
                                        .put("resumed", false)
                                        .toString()
                                        .toByteArray(),
                                )
                            }
                        }
                        com.vault.security.LocalBackupPref.clearJournal(context, vaultName())
                        com.vault.security.LocalBackupPref.setLastBackupAt(context, vaultName(), System.currentTimeMillis())
                        // 清理过期清单与中断残留：只保留 vault.pmv 与 vault.pmv.manifest.json。
                        // 不能动 {target}.history.N——那是实时备份 Worker 轮转出来的历史代，
                        // 本路径与 Worker 共用同一目录，误删会让前台保存抹掉全部备份历史。
                        runCatching {
                            val childrenUri =
                                android.provider.DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId)
                            resolver.query(
                                childrenUri,
                                arrayOf(
                                    android.provider.DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                                    android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                                ),
                                null,
                                null,
                                null,
                            )?.use { cursor ->
                                while (cursor.moveToNext()) {
                                    val name = cursor.getString(1) ?: continue
                                    if (!name.startsWith(targetName)) continue
                                    if (name == targetName || name == "$targetName.manifest.json") continue
                                    if (name.startsWith("$targetName.history.")) continue
                                    val docId = cursor.getString(0) ?: continue
                                    runCatching {
                                        android.provider.DocumentsContract.deleteDocument(
                                            resolver,
                                            android.provider.DocumentsContract.buildDocumentUriUsingTree(treeUri, docId),
                                        )
                                    }
                                }
                            }
                        }
                        "copied"
                    }.getOrElse { error ->
                        // 设备已拔出/授权失效：SAF 文档提供者会抛 "No root for ..." 或
                        // FileNotFoundException，一律按“设备未连接”处理，不暴露原始异常文案。
                        val message = error.message.orEmpty()
                        val deviceMissing = error is java.io.FileNotFoundException ||
                            (error is IllegalArgumentException && message.contains("No root", ignoreCase = true))
                        if (deviceMissing) "backup-device-not-connected" else "error:${message.ifBlank { context.getString(R.string.viewmodel_unknown_error) }}"
                    }
                }
                // 只保留两种用户可见状态：
                //  - 设备未连接：静默不备份、不通知
                //  - 其余（已连接并已触发备份）：显示备份时间或本次结果
                // 空间不足、绑定异常、写入失败都属于"设备在、备份已尝试"，仍走这一支，
                // 只是把结果如实带出来，避免用户看到第三、第四种状态。
                _localBackupStatus.value = when {
                    outcome == "backup-device-not-connected" ->
                        localizeUiTextFor(context, "备份设备未连接")
                    outcome == "ok" || outcome == "copied" -> localizeUiTextFor(
                        context,
                        "已启用 · 上次备份 ${formatBackupTime(
                            com.vault.security.LocalBackupPref.lastBackupAt(context, vaultName()),
                        )}",
                    )
                    outcome == "backup-device-abnormal" -> localizeUiTextFor(context, "备份设备状态异常")
                    outcome == "space" -> localizeUiTextFor(context, "空间不足，已跳过本次备份")
                    outcome.startsWith("error") -> localizeUiTextFor(
                        context,
                        "备份失败：${outcome.removePrefix("error:")}",
                    )
                    else -> outcome
                }
                if (outcome == "copied") markPasskeysBackedUpAfterExternalCopy()
            } finally {
                com.vault.storage.LocalBackupRunGuard.release()
                localBackupRunning = false
                _localBackupRunningFlow.value = false
            }
        }
    }

    /**
     * 基于 StorageManager + StorageVolume + SAF 的存储卷识别（见 [StorageVolumeResolver]）。
     * 内部存储与外置设备统一走同一套稳定指纹逻辑，避免重复实现与行为分歧。
     */
    private fun currentVolumeIdentity(context: android.content.Context, treeUri: Uri): String? =
        com.vault.storage.StorageVolumeResolver.resolve(context, treeUri)?.identityKey

    /** 供设置页在用户选择备份目录时解析复合卷标识。 */
    fun localBackupVolumeId(uri: Uri): String? =
        com.vault.storage.StorageVolumeResolver.resolve(getApplication(), uri)?.identityKey

    /** 供设置页展示设备名称/ID/容量。 */
    fun localBackupDeviceLabel(uri: Uri): String? {
        val fingerprint = com.vault.storage.StorageVolumeResolver.resolve(getApplication(), uri) ?: return null
        return formatVolumeLabel(fingerprint)
    }

    private fun formatVolumeLabel(fingerprint: com.vault.storage.StorageVolumeResolver.VolumeFingerprint): String {
        val capacityText = when {
            fingerprint.capacityBytes >= 1024L * 1024 * 1024 * 1024 ->
                "${fingerprint.capacityBytes / (1024.0 * 1024 * 1024 * 1024)} TB"
            fingerprint.capacityBytes >= 1024L * 1024 * 1024 ->
                "${fingerprint.capacityBytes / (1024.0 * 1024 * 1024)} GB"
            else -> ""
        }
        // 卷名是解析器给的裸中文兜底（「备份设备」/「本机存储」），必须在这里本地化：
        // 整串 "名称（VOL-xxxx）" 表里没有，翻译表查不到就会原样漏出中文。
        val nameText = localizeUiTextFor(getApplication(), fingerprint.displayName)
        // 括号随语言走：中文用全角，英文用半角，否则英文行里会夹着两个全角括号。
        val tag = getApplication<Application>().resources.configuration.locales[0].toLanguageTag()
        val openParen = if (tag.startsWith("en", true)) "(" else "（"
        val closeParen = if (tag.startsWith("en", true)) ")" else "）"
        return buildString {
            append(nameText)
            append(openParen).append(fingerprint.displayId).append(closeParen)
            if (capacityText.isNotBlank()) append(" · ").append(capacityText)
        }
    }

    /**
     * 用户选择本地备份目录：持久化读写授权 → 后台识别卷身份 → 保存目标 → 立即执行首次备份。
     * 全程给出状态提示；识别失败只提示并拒绝保存，绝不写入未认证卷。
     */
    fun selectLocalBackupDirectory(uri: Uri, userConfirmed: Boolean) {
        if (!userConfirmed) return
        val context = getApplication<Application>()
        val persisted = runCatching {
            context.contentResolver.takePersistableUriPermission(
                uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }.isSuccess
        if (!persisted) {
            _localBackupStatus.value = getApplication<Application>().getString(R.string.viewmodel_backup_permission_missing)
            return
        }
        _localBackupStatus.value = getApplication<Application>().getString(R.string.viewmodel_backup_identifying_device)
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                val fingerprint = com.vault.storage.StorageVolumeResolver.resolve(context, uri)
                if (fingerprint == null) {
                    "backup-device-abnormal"
                } else {
                    val observedAccessId = com.vault.storage.StorageVolumeResolver.stableCore(fingerprint.identityKey)
                        ?: return@withContext "backup-device-abnormal"
                    val initialMarker = com.vault.storage.SafDeviceMarker.read(context, uri)
                    if (initialMarker is com.vault.storage.SafDeviceMarker.ReadResult.Invalid) {
                        return@withContext "backup-device-abnormal"
                    }
                    var observedUuid = (initialMarker as? com.vault.storage.SafDeviceMarker.ReadResult.Valid)?.deviceUuid
                    if (observedUuid == null) {
                        observedUuid = when (val created = com.vault.storage.SafDeviceMarker.create(context, uri)) {
                            is com.vault.storage.SafDeviceMarker.ReadResult.Valid -> created.deviceUuid
                            else -> return@withContext "backup-device-abnormal"
                        }
                    }
                    // 非 KNOWN 状态只能到达此显式确认入口；身份异常在后台始终被阻断，
                    // 用户重新选择并授权后才允许重建绑定，避免旧配置永久无法恢复。
                    com.vault.security.LocalBackupPref.setTarget(
                        context,
                        vaultName(),
                        uri.toString(),
                        observedAccessId,
                        checkNotNull(observedUuid),
                    )
                    com.vault.security.LocalBackupPref.setDeviceLabel(context, vaultName(), formatVolumeLabel(fingerprint))
                    "selected"
                }
            }
            _localBackupStatus.value = when (outcome) {
                "backup-device-abnormal" -> localizeUiTextFor(context, "备份设备状态异常")
                else -> getApplication<Application>().getString(R.string.viewmodel_backup_selected_first)
            }
            if (outcome == "selected") performLocalBackup(force = true)
        }
    }

    private fun formatBackupTime(epochMillis: Long): String {
        if (epochMillis <= 0L) return getApplication<Application>().getString(R.string.viewmodel_backup_never)
        return java.text.SimpleDateFormat(
            "MM-dd HH:mm",
            java.util.Locale.getDefault(),
        ).format(java.util.Date(epochMillis))
    }

    private fun cloudSyncError(prefix: String, error: Throwable, localWasMerged: Boolean): String {
        val raw = generateSequence(error as Throwable?) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
            .lowercase()
        val detail = when {
            error is VaultCrypto.DecryptError || "decrypt" in raw || "主密码不匹配" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_decrypt)
            "不是同一" in raw || "different" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_different)
            "identity" in raw || "签名" in raw || "身份" in raw || "谱系" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_identity)
            "conflict" in raw || "409" in raw || "其他设备更新" in raw || "发生变化" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_conflict)
            "timeout" in raw || "timed out" in raw || "超时" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_timeout)
            "certificate" in raw || "证书" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_certificate)
            "401" in raw || "403" in raw || "unauthorized" in raw || "forbidden" in raw ||
                "访问权限" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_auth)
            "space" in raw || "quota" in raw || "storage" in raw || "空间" in raw || "配额" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_space)
            "permission" in raw || "denied" in raw || "权限" in raw || "只读" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_permission)
            "回读" in raw || "read-back" in raw || "本次提交" in raw || "写入前版本" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_readback)
            "格式" in raw || "pmve" in raw ->
                getApplication<Application>().getString(R.string.viewmodel_cloud_error_format)
            else -> {
                val original = generateSequence(error as Throwable?) { it.cause }
                    .mapNotNull { it.message?.trim() }
                    .firstOrNull { it.isNotBlank() }
                    ?.take(240)
                    .orEmpty()
                if (original.isBlank()) getApplication<Application>().getString(R.string.viewmodel_cloud_error_unknown)
                else getApplication<Application>().getString(R.string.viewmodel_cloud_error_provider, original)
            }
        }
        return if (localWasMerged) {
            getApplication<Application>().getString(R.string.viewmodel_cloud_error_local_saved, detail)
        } else {
            getApplication<Application>().getString(R.string.viewmodel_cloud_error_prefixed, prefix, detail)
        }
    }

    fun cloudVaultKey(): String {
        val key = _state.value.payload?.syncMeta?.deviceId?.takeIf { it.isNotBlank() }
            ?: _currentVault.value.orEmpty()
        com.vault.security.CurrentVaultKey.install(vaultName())
        return key
    }

    /** 稳定的账户（保险库）标识，用于偏好隔离命名空间；跨设备一致，UI 与后台 worker 共用。 */
    fun vaultName(): String =
        _currentVault.value?.takeIf { it.isNotBlank() } ?: com.vault.security.CurrentVaultKey.DEFAULT

    /** Locked sessions deliberately cannot inspect or use WebDAV credential state. */
    fun hasCloudConfig(): Boolean {
        val root = _state.value.credential.sessionRootKey() ?: return false
        return CloudCredentialStore.hasCloudConfig(getApplication(), root.identity.vaultId.toString(), cloudVaultKey())
    }

    /**
     * 读取云同步凭据。凭据使用保险库派生密钥加密，因此只有在保险库解锁、根密钥驻留内存时
     * 才能解密；锁定后返回 null，满足审计发现 9 的「锁定状态只保留非敏感调度信息」。
     */
    fun loadCloudConfig(): WebDavConfig? {
        val root = _state.value.credential.sessionRootKey() ?: return null
        return root.withRootKey(root.identity) { raw ->
            CloudCredentialStore.load(getApplication(), root.identity.vaultId.toString(), raw, cloudVaultKey())
        }
    }

    fun saveCloudConfig(config: WebDavConfig) {
        val root = _state.value.credential.sessionRootKey() ?: return
        root.withRootKey(root.identity) { raw ->
            CloudCredentialStore.save(getApplication(), root.identity.vaultId.toString(), config, raw)
        }
        checkRemoteUpdates("webdav")
    }

    fun clearCloudConfig() {
        val root = _state.value.credential.sessionRootKey() ?: return
        CloudCredentialStore.clear(getApplication(), root.identity.vaultId.toString(), cloudVaultKey())
        com.vault.storage.RemoteUpdatePrefs.associate(getApplication(), vaultName(), "webdav", "")
        RemoteUpdateNotifications.cancel(getApplication(), vaultName(), "webdav")
        reloadRemoteUpdateStates()
    }

    // —— KDF 安全等级（审计发现 5）——
    private fun kdfTargetSuffix(vaultId: String): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(vaultId.toByteArray())
            .take(12).joinToString("") { "%02x".format(it) }

    /** 用户为该保险库选择的目标 KDF 等级（默认 STANDARD）。 */
    fun getKdfTargetProfile(): PmvKdfProfile {
        val vid = cloudVaultKey().takeIf { it.isNotBlank() } ?: return PmvKdfProfile.STANDARD
        val p = com.vault.security.SecurePreferences.get(getApplication(), "kdf_sync")
        val name = p.getString("profile_${kdfTargetSuffix(vid)}", "") ?: ""
        return runCatching { PmvKdfProfile.valueOf(name) }.getOrDefault(PmvKdfProfile.STANDARD)
    }

    fun setKdfTargetProfile(profile: PmvKdfProfile) {
        val vid = cloudVaultKey().takeIf { it.isNotBlank() } ?: return
        val p = com.vault.security.SecurePreferences.get(getApplication(), "kdf_sync")
        p.edit().putString("profile_${kdfTargetSuffix(vid)}", profile.name).apply()
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) { maybeAutoUpgradeKdf() }
    }

    /** 按本机性能校准推荐等级：对 HARDENED 参数计时三次，落在时间与内存预算内才推荐强化。 */
    fun recommendKdfProfile(
        availableBudgetKiB: Int = 262_144,
        onResult: (PmvKdfProfile) -> Unit,
    ): Job = viewModelScope.launch(kotlinx.coroutines.Dispatchers.Default) {
        val dummy = "kdf-calibration".encodeToByteArray()
        val salt = ByteArray(PmvKeySchedule.KDF_SALT_SIZE)
        val recommended = try {
            val times = (1..3).map {
                val t0 = System.nanoTime()
                PmvKeySchedule.derivePasswordKek(dummy, salt, PmvKdfProfile.HARDENED.parameters)
                    .also { it.fill(0) }
                (System.nanoTime() - t0) / 1_000_000
            }
            PmvKdfPolicy.recommendedProfile(times, availableBudgetKiB)
        } finally {
            dummy.fill(0)
            salt.fill(0)
        }
        withContext(kotlinx.coroutines.Dispatchers.Main) { onResult(recommended) }
    }

    fun currentKdfParameters(): PmvKdfParameters? {
        val root = _state.value.credential?.sessionRootKey() ?: return null
        return root.withRootKey(root.identity) { rk -> repo()?.currentKdfParameters(rk) }
    }

    fun kdfMigrationState(): KdfMigrationState {
        val cur = currentKdfParameters() ?: return KdfMigrationState.UNSUPPORTED
        return PmvKdfPolicy.migrationState(cur, getKdfTargetProfile())
    }

    /**
     * 当当前 KDF 参数低于目标等级、且主密码仍驻留会话时，在后台用更高强度参数重新包装密码槽。
     * 解锁后会自动调用，满足「解锁后自动重新包装到新参数」。
     */
    fun maybeAutoUpgradeKdf() {
        val target = getKdfTargetProfile()
        val current = currentKdfParameters() ?: return
        if (current == target.parameters) return
        val pw = _state.value.credential?.sessionPassword() ?: return
        pw.useBytes { pwBytes ->
            runCatching { repo()?.upgradeKdfProfile(pwBytes, target) }
        }
    }

    fun dedup(pwResolver: (List<Entry>) -> Entry?) = viewModelScope.launch {
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        val (newPayload, stats) = VaultOps.dedupEntries(payload, pwResolver)
        if (newPayload !== payload) {
            withContext(Dispatchers.IO) { saveCurrent(r, newPayload) }
            _state.update { it.withPayload(sealPayload(newPayload)) }
        }
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_dedup_summary, stats.exactMerged, stats.pwResolved, stats.pwSkipped))
    }

    fun mergeServiceEntries(entryIds: Set<String>, resolvedTitle: String, resolvedPassword: String, resolvedUsername: String = "") = viewModelScope.launch {
        val r = repo() ?: return@launch
        val s = _state.value
        val payload = s.payload?.let(::materializePayload) ?: return@launch
        val toMerge = payload.entries.filter { it.id in entryIds && it.deletedAt == null }
        if (toMerge.size < 2) {
            emitError(getApplication<Application>().getString(R.string.viewmodel_merge_min_entries))
            return@launch
        }
        val merged = VaultOps.mergeEntries(toMerge, resolvedTitle, resolvedPassword, resolvedUsername)
        val mergedId = merged.id
        val newEntries = payload.entries.filterNot { it.id in entryIds }
            .let { it + merged }
        val newPayload = payload.copy(entries = newEntries)
        withContext(Dispatchers.IO) { saveCurrent(r, newPayload) }
        _state.update { it.withPayload(sealPayload(newPayload)) }
        emitInfo(getApplication<Application>().getString(R.string.viewmodel_merged_entries, toMerge.size, merged.feedbackTitle()))
    }

    // --- 内部 ---

    private fun mutate(
        checkEntryIds: Set<String>? = null,
        successMessage: ((VaultPayload, VaultPayload) -> String?)? = null,
        metaOnly: Boolean = false,
        afterCommit: (suspend (VaultPayload, VaultPayload) -> Unit)? = null,
        transform: (VaultPayload) -> VaultPayload,
    ) = viewModelScope.launch {
        val r = repo() ?: return@launch
        vaultOperationMutex.withLock {
            val published = _state.value.payload ?: return@withLock
            val payload = materializePayload(published)
            val newPayload = transform(payload)
            // 无实际变更时跳过，避免触发 UI 全量重组。
            if (newPayload === payload) return@withLock
            // UI 先响应，磁盘写入与远端快照由同一把互斥锁串行，避免上传到旧文件。
            val newPublished = sealPayload(newPayload)
            _state.update { it.withPayload(newPublished) }
            var persistedPayload = newPayload
            runCatching {
                withContext(Dispatchers.IO) {
                    persistedPayload = persistPmvEEntryMediaIfNeeded(
                        repository = r,
                        oldPayload = payload,
                        newPayload = newPayload,
                        changedEntryIds = checkEntryIds,
                    ) ?: newPayload.also { saveCurrent(r, it, metaOnly) }
                }
            }
                .onFailure {
                    _state.update { cur ->
                        if (cur.payload === newPublished) cur.withPayload(sealPayload(payload)) else cur
                    }
                    emitError(getApplication<Application>().getString(R.string.viewmodel_save_failed, it.message ?: getApplication<Application>().getString(R.string.viewmodel_unknown_error)))
                }
                .onSuccess {
                    if (persistedPayload !== newPayload) {
                        val canonicalPublished = sealPayload(persistedPayload)
                        _state.update { current ->
                            if (current.payload === newPublished) current.withPayload(canonicalPublished) else current
                        }
                        // 媒体提交后按增长阈值机会式压缩，回收追加写产生的死空间
                        viewModelScope.launch {
                            compactAfterLargeMediaCommit(r)
                        }
                    }
                    successMessage?.invoke(payload, persistedPayload)?.let(::emitInfo)
                    afterCommit?.invoke(payload, persistedPayload)
                    if (checkEntryIds != null) {
                        viewModelScope.launch {
                            autoCheckLeaks(
                                payload = persistedPayload,
                                r = r,
                                ctx = getApplication(),
                                force = true,
                                targetIds = checkEntryIds,
                            )
                        }
                    }
                }
        }
    }

    /**
     * Publishes newly selected legacy/inline media and its Entry in one PMVE Commit.
     * Returns null when this mutation has no new media and should use the normal save path.
     */
    private fun persistPmvEEntryMediaIfNeeded(
        repository: VaultRepository,
        oldPayload: VaultPayload,
        newPayload: VaultPayload,
        changedEntryIds: Set<String>?,
    ): VaultPayload? {
        if (!repository.isPmvE()) return null
        val entryId = changedEntryIds?.singleOrNull() ?: return null
        val entry = (newPayload.entries + newPayload.trash).singleOrNull { it.id == entryId } ?: return null
        val pending = PmvMediaRef.scan(entry).filter {
            it.classification == PmvMediaRef.Classification.LEGACY_EXTERNAL ||
                it.classification == PmvMediaRef.Classification.INLINE
        }
        if (pending.isEmpty()) return null

        val rootSession = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
        return rootSession.withRootKey(rootSession.identity) { rootKey ->
            val identity = repository.currentIdentity(rootKey)
            val streams = mutableListOf<PmvMediaRef.LegacyStream>()
            val closeables = mutableListOf<AutoCloseable>()
            val stagedFiles = linkedSetOf<File>()
            try {
                pending.forEach { occurrence ->
                    val primitive = occurrence.raw as? JsonPrimitive
                        ?: error("待导入媒体必须是字符串引用")
                    val raw = primitive.content
                    val kind = occurrence.kind ?: error("无法判断待导入媒体类型")
                    val input: InputStream
                    val size: Long
                    when (occurrence.classification) {
                        PmvMediaRef.Classification.LEGACY_EXTERNAL -> {
                            val file = when (kind) {
                                PmvAttachmentCodec.Kind.IMAGE -> imageFileFromRef(getApplication(), raw)
                                PmvAttachmentCodec.Kind.ATTACHMENT -> attachmentFileFromRef(getApplication(), raw)
                            } ?: error("待导入媒体文件不存在")
                            stagedFiles += file
                            size = MediaCrypto.filePlaintextSize(file)
                            input = MediaCrypto.decryptStream(file.inputStream().buffered())
                        }
                        PmvMediaRef.Classification.INLINE -> {
                            error("旧格式内联媒体已不支持，仅支持 PMVE 媒体引用")
                        }
                        else -> error("媒体导入分类无效")
                    }
                    closeables += input
                    streams += PmvMediaRef.LegacyStream(
                        path = occurrence.path,
                        input = input,
                        expectedSize = size,
                        objectId = UUID.randomUUID(),
                        generation = Math.addExact(identity.sequence, 1L),
                        kind = kind,
                    )
                }
                val existed = oldPayload.entries.any { it.id == entryId } || oldPayload.trash.any { it.id == entryId }
                val saved = repository.savePmvEEntryWithMedia(
                    entry = entry,
                    expectedEntryRevision = identity.sequence.takeIf { existed },
                    streams = streams,
                    rootKey = rootKey,
                    expectedSequence = identity.sequence,
                )
                closeables.asReversed().forEach { runCatching { it.close() } }
                closeables.clear()
                stagedFiles.forEach { runCatching { it.delete() } }
                replacePayloadEntry(newPayload, saved.entry)
            } finally {
                closeables.asReversed().forEach { runCatching { it.close() } }
            }
        }
    }

    private fun replacePayloadEntry(payload: VaultPayload, entry: Entry): VaultPayload = payload.copy(
        entries = payload.entries.map { if (it.id == entry.id) entry else it },
        trash = payload.trash.map { if (it.id == entry.id) entry else it },
    )

    private fun VaultPayload.entryTitle(id: String): String =
        entries.firstOrNull { it.id == id }?.feedbackTitle() ?: "条目"

    private fun Entry.feedbackTitle(): String =
        title.ifEmpty { "无标题" }

    private fun formatImportSummary(
        added: Int,
        updated: Int,
        skipped: Int,
        conflicts: Int,
        identical: Int,
    ): String {
        if (added == 0 && updated == 0 && skipped == 0 && conflicts == 0 && identical > 0) {
            return getApplication<Application>().getString(R.string.viewmodel_import_no_changes)
        }
        return getApplication<Application>().getString(
            R.string.viewmodel_import_summary,
            added,
            updated,
            skipped,
            conflicts,
        )
    }

    override fun onCleared() {
        stopLanHost()
        stopLanSyncKeepAlive()
        lanTransferPollJob?.cancel()
        resetLargeTransferWarning()
        clearLanTransferTempFiles()
        _state.value.credential?.close()
        clearEntryStore()
        clearUnlockPipeline()
        pauseBackgroundWork()
        super.onCleared()
        _state.update { UiState(phase = Phase.NO_VAULT) }
    }

    private fun localizedNotification(msg: String): String {
        val locales = getApplication<Application>().resources.configuration.locales
        return localizeNotification(msg, locales[0].toLanguageTag())
    }

    private fun acceptsNewMasterPassword(password: String, weakPasswordConfirmed: Boolean): Boolean {
        val assessment = com.vault.security.MasterPasswordPolicy.assess(password) { candidate ->
            com.vault.security.LeakedPasswordCheck.isLeaked(getApplication(), candidate)
        }
        return assessment.permits(
            highSecurityMode = false,
            weakPasswordConfirmed = weakPasswordConfirmed,
        )
    }

    private fun emitError(msg: String, sticky: Boolean = false) {
        _events.value = UiEvent.Error(localizedNotification(msg), sticky)
    }
    private fun emitInfo(msg: String) { _events.value = UiEvent.Info(localizedNotification(msg)) }
    /** UI 层向用户反馈错误（不属于 VM 业务流程）。 */
    fun postError(msg: String) { _events.value = UiEvent.Error(localizedNotification(msg)) }
    /** UI 层向用户反馈信息（不属于 VM 业务流程）。 */
    fun postInfo(msg: String) { _events.value = UiEvent.Info(localizedNotification(msg)) }

    data class SyncResultState(
        val stats: VaultOps.LwwMergeStats,
        val source: String,
        val localCount: Int = 0,
        val mergedCount: Int = 0,
        val remoteBytes: Long = 0L,
        val uploaded: Boolean = false,
        val verified: Boolean = false,
        val host: Boolean = false,
        val lineage: String = "",
    )

    enum class CloudSyncPhase { IDLE, RUNNING, FAILED }

    data class CloudSyncUiState(
        val phase: CloudSyncPhase = CloudSyncPhase.IDLE,
        val targetKey: String = "",
        val target: String = "",
        val lastSuccessAt: Long = 0L,
        val changedCount: Int = 0,
        val message: String = "",
        val localChangesSaved: Boolean = false,
        val uploaded: Boolean = false,
        val verified: Boolean = false,
        /** 覆盖/下载/识别等操作的进行中说明（跨页面存活，避免退出后丢失）。 */
        val busyMessage: String = "",
        /** 上传等可量化操作的真实进度（0..1）；null 表示不确定进度。 */
        val progress: Float? = null,
    )

    private fun restoreCloudSyncState() {
        val stored = AutoCloudSyncPrefs.loadSyncStatus(getApplication(), cloudVaultKey())
        _cloudSyncState.value = CloudSyncUiState(
            phase = if (stored.error.isBlank()) CloudSyncPhase.IDLE else CloudSyncPhase.FAILED,
            targetKey = stored.target,
            target = when (stored.target) {
                "drive" -> getApplication<Application>().getString(R.string.viewmodel_cloud_drive)
                "webdav" -> getApplication<Application>().getString(R.string.viewmodel_webdav)
                else -> ""
            },
            lastSuccessAt = stored.lastSuccessAt,
            message = stored.error,
        )
    }

    private fun beginCloudSync(targetKey: String, target: String): Boolean {
        if (_cloudSyncState.value.phase == CloudSyncPhase.RUNNING) return false
        val stored = AutoCloudSyncPrefs.loadSyncStatus(getApplication(), cloudVaultKey())
        _cloudSyncState.value = CloudSyncUiState(
            phase = CloudSyncPhase.RUNNING,
            targetKey = targetKey,
            target = target,
            lastSuccessAt = stored.lastSuccessAt,
        )
        return true
    }

    private suspend fun completeCloudSync(
        targetKey: String,
        target: String,
        stats: VaultOps.LwwMergeStats,
        uploaded: Boolean = false,
        verified: Boolean = true,
    ) {
        acknowledgeRemoteUpdate(targetKey)
        if (verified) markPasskeysBackedUpAfterExternalCopy()
        val now = System.currentTimeMillis()
        AutoCloudSyncPrefs.success(
            getApplication(),
            cloudVaultKey(),
            getApplication<Application>().getString(R.string.viewmodel_auto_sync_completed),
            targetKey,
        )
        _cloudSyncState.value = CloudSyncUiState(
            targetKey = targetKey,
            target = target,
            lastSuccessAt = now,
            changedCount = cloudSyncChangedCount(stats),
            uploaded = uploaded,
            verified = verified,
        )
    }

    /** External PMV copy succeeded. This only updates WebAuthn backup-state metadata. */
    private suspend fun markPasskeysBackedUpAfterExternalCopy(): Int {
        val repository = repo() ?: return 0
        val current = _state.value.payload?.let(::materializePayload) ?: return 0
        val (entries, changed) = PasskeyBackupTransfer.markBackedUp(current.entries)
        if (changed == 0) return 0
        val updated = current.copy(entries = entries)
        return runCatching {
            withContext(Dispatchers.IO) {
                val session = _state.value.rootKey ?: error("PMVE RootKey 会话已失效")
                session.withRootKey(session.identity) { key -> repository.savePmvE(updated, key) }
            }
            _state.update { it.withPayload(sealPayload(updated)) }
            changed
        }.getOrElse { 0 }
    }

    private fun failCloudSync(targetKey: String, target: String, message: String, localChangesSaved: Boolean) {
        remoteUpdateProofs.remove(targetKey)
        AutoCloudSyncPrefs.recordFailure(getApplication(), cloudVaultKey(), targetKey, message)
        _cloudSyncState.value = _cloudSyncState.value.copy(
            phase = CloudSyncPhase.FAILED,
            targetKey = targetKey,
            target = target,
            message = message,
            localChangesSaved = localChangesSaved,
            uploaded = false,
            verified = false,
            busyMessage = "",
            progress = null,
        )
    }

    /** 覆盖/下载/识别等操作开始时置为“进行中”，进度条跨页面保留。 */
    private fun markCloudBusy(targetKey: String, target: String, busyMessage: String) {
        remoteUpdateProofs.remove(targetKey)
        remoteUpdateOperationGeneration++
        _cloudSyncState.value = _cloudSyncState.value.copy(
            phase = CloudSyncPhase.RUNNING,
            targetKey = targetKey,
            target = target,
            busyMessage = busyMessage,
            progress = null,
        )
    }

    private fun updateCloudBusyProgress(progress: Float) {
        _cloudSyncState.value = _cloudSyncState.value.copy(progress = progress)
    }

    /** 覆盖/下载成功：保留最近成功时间，清空进行中状态（不写入自动同步记录）。 */
    private fun finishCloudBusyOk(targetKey: String, target: String) {
        acknowledgeRemoteUpdate(targetKey)
        _cloudSyncState.value = CloudSyncUiState(
            targetKey = targetKey,
            target = target,
            lastSuccessAt = System.currentTimeMillis(),
        )
    }

    /** 预览/检测结束：恢复 IDLE，保留最近成功时间。 */
    private fun clearCloudBusy() {
        _cloudSyncState.value = _cloudSyncState.value.copy(
            phase = CloudSyncPhase.IDLE,
            busyMessage = "",
            progress = null,
            message = "",
        )
    }

    private fun cloudSyncChangedCount(stats: VaultOps.LwwMergeStats): Int =
        stats.added + stats.takeRemote + stats.takeLocal + stats.keptBoth + stats.purged + stats.coalesced

    private fun cloudSyncCompletionMessage(stats: VaultOps.LwwMergeStats?): String {
        val changed = stats?.let(::cloudSyncChangedCount) ?: 0
        return if (changed > 0) getApplication<Application>().getString(R.string.viewmodel_sync_changed, changed)
        else getApplication<Application>().getString(R.string.viewmodel_sync_up_to_date)
    }

    /** Compatibility fallback for exception text supplied by storage/network providers. */
    private fun localizeVmMessage(msg: String): String =
        localizeUiTextFor(getApplication(), msg)

    private fun cloudDisplayLabel(key: String): String = getApplication<Application>().getString(
        if (key == "drive") R.string.viewmodel_cloud_drive else R.string.viewmodel_webdav,
    )

    data class CloudSyncPreview(
        val kind: String,
        val source: String,
        val remoteWriter: com.vault.storage.DeviceActivityProfile? = null,
        val stats: VaultOps.LwwMergeStats = VaultOps.LwwMergeStats(),
        val localActive: Int = 0,
        val localTrash: Int = 0,
        val remoteActive: Int = 0,
        val remoteTrash: Int = 0,
        val localOnly: Int = 0,
        val remoteOnly: Int = 0,
        val remoteBytes: Long = 0L,
        val checkedAt: Long = System.currentTimeMillis(),
        val message: String = "",
        val localPurgeAhead: Int = 0,
        val remotePurgeAhead: Int = 0,
        val localSequence: Long = 0L,
        val remoteSequence: Long = 0L,
        val localKeyRevision: Long = 0L,
        val remoteKeyRevision: Long = 0L,
        /** PMVE 谱系关系：same / descendant / ancestor / diverged / different / invalid。 */
        val relationship: String = "",
    )
    fun dismissSyncResult() { _syncResult.value = null }

    /** 局域网同步页面进度：状态文案 + 字节级进度（与通知栏同源）。 */
    data class LanSyncProgress(
        val status: String = "",
        val transferred: Long = 0L,
        val total: Long = 0L,
        val active: Boolean = false,
    )
    private val _lanSyncProgress = MutableStateFlow(LanSyncProgress())
    val lanSyncProgress: StateFlow<LanSyncProgress> = _lanSyncProgress.asStateFlow()

    private fun updateLanSyncProgress(taskId: String, status: String, transferred: Long = 0L, total: Long = 0L) {
        _lanSyncProgress.value = LanSyncProgress(
            status = status,
            transferred = transferred,
            total = total,
            active = true,
        )
        // 与通知栏保持同源一致：页面与前台服务展示同一份状态与进度。
        SyncForegroundService.updateTask(getApplication(), taskId, status, transferred, total)
    }

    private fun clearLanSyncProgress() {
        _lanSyncProgress.value = LanSyncProgress()
    }

    // ── 同步后密钥/主密码自动收敛提示 ─────────────────────────────

    enum class KeyConvergenceKind { NONE, KEY_ONLY, PASSWORD }

    data class KeyConvergedNotice(val kind: KeyConvergenceKind, val message: String)

    private val _keyConvergedNotice = MutableStateFlow<KeyConvergedNotice?>(null)
    val keyConvergedNotice: StateFlow<KeyConvergedNotice?> = _keyConvergedNotice.asStateFlow()

    private fun keyConvergedMessage(kind: KeyConvergenceKind): String = when (kind) {
            KeyConvergenceKind.PASSWORD ->
            getApplication<Application>().getString(R.string.viewmodel_key_converged_password)
        KeyConvergenceKind.KEY_ONLY ->
            getApplication<Application>().getString(R.string.viewmodel_key_converged_recovery)
        KeyConvergenceKind.NONE -> ""
    }

    /** 红色警示弹窗只能确认、不可取消：主密码变化时确认后锁定，密钥变化仅关闭提示。 */
    fun confirmKeyConvergedNotice() {
        val notice = _keyConvergedNotice.value ?: return
        _keyConvergedNotice.value = null
        if (notice.kind == KeyConvergenceKind.PASSWORD) lock()
    }

    private fun clearUnlockPipeline() {
        unlockAttemptId += 1
        pendingUnlock?.credential?.close()
        pendingUnlock = null
        postUnlockJob?.cancel()
        postUnlockJob = null
        PmvMediaUiSession.clear()
    }

    private companion object {
        const val POST_UNLOCK_SETTLE_MS = 180L
        const val MAX_CLOUD_SYNC_RETRY_ATTEMPTS = 3
        const val MAX_REMOTE_VAULT_BYTES = 1024L * 1024L * 1024L
        const val MAX_RECONCILIATION_BYTES = 2L * 1024L * 1024L * 1024L
        const val MAX_TRANSFER_CLIPBOARD_BYTES = 1024L * 1024L
        /** 大文件提示阈值：>10 GiB 仅提示一次，不限制传输。 */
        const val LAN_TRANSFER_WARN_BYTES = 10L * 1024L * 1024L * 1024L
        /** 溢出护栏：与 PC 端对齐，10 TiB 以上拒绝。 */
        const val MAX_LAN_TRANSFER_FILE_BYTES = 10L * 1024L * 1024L * 1024L * 1024L
        const val MAX_LAN_TRANSFER_PIN_ATTEMPTS = 5
        /** WebDAV 同步冲突重试上限：冲突后重拉最新远端再合并，有界收敛。 */
        const val MAX_WEBDAV_SYNC_ATTEMPTS = 3
        val REMOTE_METADATA_DELAYS_MS = longArrayOf(0L, 250L, 600L, 1_200L, 2_500L)
        /** SAF 云盘常先提交本地缓存再异步发布；内容读回采用有界退避等待可见。 */
        val CLOUD_CONTENT_READBACK_DELAYS_MS = longArrayOf(0L, 300L, 800L, 1_500L, 3_000L)

        // ── 后台任务通知 id（与 BackgroundTaskNotifierTest 的 approved task ids 一致） ──
        const val LAN_SYNC_TASK_ID = "lan-sync"
        const val LAN_TRANSFER_TASK_ID = "lan-transfer"
        const val LAN_HOST_TASK_ID = "lan-host"
        const val CLOUD_DRIVE_SYNC_TASK_ID = "cloud-drive"
        const val CLOUD_DRIVE_UPLOAD_TASK_ID = "cloud-drive-upload"
        const val CLOUD_DRIVE_DOWNLOAD_TASK_ID = "cloud-drive-download"
        const val CLOUD_WEBDAV_SYNC_TASK_ID = "cloud-webdav"
        const val CLOUD_WEBDAV_UPLOAD_TASK_ID = "cloud-webdav-upload"
        const val CLOUD_WEBDAV_DOWNLOAD_TASK_ID = "cloud-webdav-download"
        const val BACKUP_EXPORT_TASK_ID = "backup-export"
        const val BACKUP_IMPORT_TASK_ID = "backup-import"
        const val ARCHIVE_EXPORT_TASK_ID = "archive-export"
        const val PASSWORD_MANAGER_IMPORT_TASK_ID = "password-manager-import"
        const val VAULT_RAW_EXPORT_TASK_ID = "vault-raw-export"
    const val VAULT_ACCOUNT_IMPORT_TASK_ID = "vault-account-import"
    const val BREACH_CHECK_TASK_ID = "breach-check"
        const val APP_UPDATE_TASK_ID = "app-update"
    }

}

private fun UiState.withPayload(payload: VaultPayload?): UiState =
    copy(payload = payload, listIndex = VaultListIndex.from(payload))

private fun VaultIdentity.deviceBinding(): VaultKeyIdentity {
    val publicKey = signingPublicKey
    return try { VaultKeyIdentity(vaultId, keyRevision, publicKey) } finally { publicKey.fill(0) }
}

private fun CloudDocumentMetadata.toCloudFileVersion(): CloudFileVersion = CloudFileVersion(
    exists = true,
    size = size,
    lastModified = lastModified,
)

private fun WebDavMetadata.toCloudFileVersion(): CloudFileVersion = CloudFileVersion(
    exists = exists,
    size = size,
    lastModified = lastModified,
    etag = etag,
)

private fun sessionCredential(
    passwordUtf8: ByteArray? = null,
    rootKey: ByteArray? = null,
    identity: VaultIdentity? = null,
): VaultSessionCredential? {
    val key = when {
        rootKey != null -> VaultSessionCredential.RootKey(rootKey, requireNotNull(identity).deviceBinding())
        else -> null
    }
    val passwordCredential = passwordUtf8?.let { VaultSessionCredential.Password(it) }
    return when {
        passwordCredential != null && key != null -> VaultSessionCredential.Compound(passwordCredential, key)
        passwordCredential != null -> passwordCredential
        else -> key
    }
}

private fun VaultSessionCredential?.sessionPassword(): VaultSessionCredential.Password? = when (this) {
    is VaultSessionCredential.Password -> this
    is VaultSessionCredential.Compound -> password
    else -> null
}

private fun VaultSessionCredential?.sessionRootKey(): VaultSessionCredential.RootKey? = when (this) {
    is VaultSessionCredential.RootKey -> this
    is VaultSessionCredential.Compound -> key as? VaultSessionCredential.RootKey
    else -> null
}

private fun VaultSessionCredential.sessionKey(): VaultSessionCredential? = when (this) {
    is VaultSessionCredential.RootKey -> this
    is VaultSessionCredential.Compound -> key
    is VaultSessionCredential.Password -> null
}

/** 最终提交时把事务私有占位符替换成提升后的真实媒体引用。纯函数供事务单测覆盖。 */
internal fun remapQuarantineRefs(payload: VaultPayload, refs: Map<String, String>): VaultPayload {
    if (refs.isEmpty()) return payload
    fun remap(node: JsonElement): JsonElement = when (node) {
        is JsonPrimitive -> node.contentOrNull?.let(refs::get)?.let(::JsonPrimitive) ?: node
        is JsonArray -> JsonArray(node.map(::remap))
        is JsonObject -> JsonObject(node.mapValues { (_, value) -> remap(value) })
        is JsonNull -> node
    }
    fun remapEntry(entry: Entry): Entry = entry.copy(
        fields = entry.fields.mapValues { (_, value) -> remap(value) },
    )
    return payload.copy(
        entries = payload.entries.map(::remapEntry),
        trash = payload.trash.map(::remapEntry),
    )
}

enum class Phase { NO_VAULT, LOCKED, UNLOCKED }

/** 恢复密钥解锁后的强制流程（均不可关闭）：先重置主密码，再重发恢复密钥。 */
enum class RecoveryFlowStep { NONE, RESET_PASSWORD, REISSUE }

@androidx.compose.runtime.Immutable
data class UiState(
    val phase: Phase = Phase.NO_VAULT,
    val payload: VaultPayload? = null,
    val listIndex: VaultListIndex = VaultListIndex.EMPTY,
    val credential: VaultSessionCredential? = null,
    val query: String = "",
    val tagFilter: String? = null,
    val typeFilter: String? = com.vault.model.SecretType.LOGIN,
    val busy: Boolean = false,
    val isExternalActionInProgress: Boolean = false,
    val leakCheckRunning: Boolean = false,
    val leakCheckChecked: Int = 0,
    val leakCheckTotal: Int = 0,
    val autoLocked: Boolean = false,
    // 解锁成功的瞬态标记：在 phase 切到 UNLOCKED 之前短暂保持 true，
    // 让 UnlockScreen 有窗口展示打勾动画
    val unlockSuccess: Boolean = false,
    val syncRunning: Boolean = false,
    val lanTransferActive: Boolean = false,
    val lanTransferConnecting: Boolean = false,
    val lanTransferDisconnected: Boolean = false,
    val lanTransferItems: List<LanTransferItem> = emptyList(),
    val lanTransferError: String? = null,
    val cloudSyncRunning: Boolean = false,
) {
    val password: VaultSessionCredential.Password? get() = credential.sessionPassword()
    val rootKey: VaultSessionCredential.RootKey? get() = credential.sessionRootKey()
}

enum class LanTransferDirection { RECEIVED, SENT }

/** Stable transfer state for logic; [LanTransferItem.status] remains a localized display string for compatibility. */
enum class LanTransferStatusCode {
    WAITING_RECEIVE,
    RECEIVING,
    SAVING,
    CANCELLED,
    RECEIVED,
    SENDING,
    SENT,
    RETRYING,
    INTERRUPTED,
    FAILED,
    REJECTED,
    UNKNOWN,
}

@androidx.compose.runtime.Immutable
data class LanTransferItem(
    val remoteId: String,
    val name: String,
    val mime: String,
    val kind: String = "file",
    val size: Long,
    val direction: LanTransferDirection,
    val status: String,
    val statusCode: LanTransferStatusCode = LanTransferStatusCode.UNKNOWN,
    val progress: Float = 0f,
    val path: String = "",
    val localPath: String = "",
    val openUri: String = "",
    val textPreview: String = "",
)

@androidx.compose.runtime.Immutable
data class LanTransferConnectResult(
    val connected: Boolean,
    val pinRejected: Boolean = false,
    val remainingPinAttempts: Int = 5,
    val message: String = "",
)

@androidx.compose.runtime.Immutable
data class VaultListIndex(
    val activeCountsByType: Map<String, Int> = emptyMap(),
    val entriesByType: Map<String, List<Entry>> = emptyMap(),
    val leakedIdsByType: Map<String, Set<String>> = emptyMap(),
    /** 各类型的标签列表，供列表页筛选/切换/展示。 */
    val tagsByType: Map<String, List<String>> = emptyMap(),
    /** 存在“无标签”条目的类型集合。 */
    val hasUntaggedByType: Set<String> = emptySet(),
) {
    companion object {
        val EMPTY = VaultListIndex()

        fun from(payload: VaultPayload?): VaultListIndex {
            val entries = payload?.entries ?: return EMPTY
            val alive = entries.filter { it.deletedAt == null }
            if (alive.isEmpty()) return EMPTY

            val byType = alive.groupBy { it.secretType }
            val sortedByType = byType.mapValues { (_, items) -> VaultOps.sortedByTitle(items) } +
                (NavOrderPref.PASSKEY_CATEGORY to VaultOps.sortedByTitle(byType[SecretType.PASSKEY].orEmpty()))
            val leakedByType = if (LeakCheckEnabledPref.enabled.value) {
                alive.asSequence()
                    .filter { it.hasCurrentLeakCache() && (it.leakCommonWeak || (it.leakPwnedCount ?: 0) > 0) }
                    .groupBy { it.secretType }
                    .mapValues { (_, items) -> items.mapTo(linkedSetOf()) { it.id } }
            } else {
                emptyMap()
            }
            // 标签索引覆盖全部类型（含 Passkey）：筛选与「无标签」统计要和列表里
            // 实际能看到的条目一致，否则 Passkey 类目永远不出现筛选条。
            val tagsByType = sortedByType.mapValues { (_, items) ->
                orderTags(items.asSequence().flatMap { it.tags.asSequence() }.distinct().toList())
            }
            val hasUntaggedByType = sortedByType
                .filterValues { items -> items.any { it.tags.isEmpty() } }
                .keys

            return VaultListIndex(
                activeCountsByType = alive.groupingBy { it.secretType }.eachCount(),
                entriesByType = sortedByType,
                leakedIdsByType = leakedByType,
                tagsByType = tagsByType,
                hasUntaggedByType = hasUntaggedByType,
            )
        }

        /** 应用用户自定义标签顺序；未记录或新出现的标签按字母序排到末尾。 */
        private fun orderTags(all: List<String>): List<String> {
            val preferred = TagOrderPref.order.value
            if (preferred.isEmpty()) return all.sorted()
            val known = preferred.filter(all::contains)
            return known + all.filterNot(known::contains).sorted()
        }
    }
}

sealed interface UiEvent {
    /**
     * @param sticky 通知条常驻不自动消失。用于"锁库 + 冷却倒计时"这类用户必须等到
     *   条件解除才能继续操作的提示——普通错误提示 4 秒就消失就够了。
     */
    data class Error(val message: String, val sticky: Boolean = false) : UiEvent
    data class Info(val message: String) : UiEvent
}
