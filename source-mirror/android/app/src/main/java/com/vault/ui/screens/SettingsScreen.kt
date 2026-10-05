package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import java.util.UUID
import android.app.Activity
import android.app.LocaleManager
import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.LocaleList
import android.util.Base64
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.content.ReceiveContentListener
import androidx.compose.foundation.content.TransferableContent
import androidx.compose.foundation.content.consume
import androidx.compose.foundation.content.contentReceiver
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.imeAnimationTarget
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import com.vault.ui.vaultHorizontalScroll as horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldDecorator
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.filled.Cast
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.HealthAndSafety
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Checkbox
import com.vault.ui.BreathingRing
import com.vault.ui.CapsuleOption
import com.vault.ui.CapsuleSegmentedControl
import com.vault.ui.MasterPasswordPolicyControls
import com.vault.ui.WeakMasterPasswordConfirmDialog
import com.vault.ui.rememberMasterPasswordAssessment
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.Surface
import com.vault.ui.VaultSwitch
import androidx.compose.material3.TextButton
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.zIndex
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.layout.RowScope
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.vault.ui.uiText
import com.vault.ui.localizeUiTextFor
import com.vault.ui.uiTabText
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.vault.autofill.AutofillExcludePref
import com.vault.autofill.AutofillSetup
import com.vault.autofill.AutofillSupportState
import com.vault.passkeys.PasskeyCreationPreference
import com.vault.passkeys.PasskeyModePref
import com.vault.R
import com.vault.model.VaultOps
import com.vault.model.Entry
import com.vault.security.MasterPasswordRisk
import com.vault.security.PasswordFinding
import com.vault.security.PasswordHealth
import com.vault.security.PasswordHealthReport
import com.vault.security.AutoHidePref
import com.vault.security.BackgroundHidePref
import com.vault.security.WindowSecurity
import com.vault.security.LocalBackupPref
import com.vault.security.IdleLockPref
import com.vault.security.CloudCredentialStore
import com.vault.storage.ClipboardTtlPref
import com.vault.storage.AutoCloudSyncPrefs
import com.vault.storage.AutoCloudSyncSettings
import com.vault.storage.TrashRetentionPref
import com.vault.storage.WebDavConfig
import com.vault.storage.WebDavCloud
import com.vault.storage.VaultLogicalRevision
import com.vault.storage.SyncServerHost
import com.vault.storage.SyncClient
import com.vault.storage.LocalBackupPolicy
import com.vault.storage.SyncForegroundService
import com.vault.storage.BackgroundTaskKind
import com.vault.ui.IdleTracker
import com.vault.ui.InputFilters
import com.vault.ui.NavOrderPref
import com.vault.ui.HomeLayoutMode
import com.vault.ui.HomeLayoutPref
import com.vault.ui.ThemeMode
import com.vault.ui.ThemePref
import com.vault.ui.ThemeSwitch
import com.vault.ui.TypeColors
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.VaultViewModel
import com.vault.ui.cloudSyncBusyChanges
import com.vault.ui.LanTransferConnectResult
import com.vault.ui.LanSyncResultStatus
import com.vault.ui.media.QrImage
import com.vault.ui.LanGearChannels
import com.vault.ui.LanTransferDirection
import com.vault.ui.resolveLanGearState
import com.vault.ui.transferDisplayName
import com.vault.ui.LanTransferItem
import com.vault.ui.LanTransferStatusCode
import com.vault.ui.UiState
import com.vault.ui.copySensitive
import com.vault.ui.scan.QrLiveScanActivity
import com.vault.ui.scan.QrPayloadPolicy
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.collect
import kotlin.math.atan2
import kotlin.math.roundToInt
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import com.vault.ui.VaultShape

@OptIn(ExperimentalMaterial3Api::class)
enum class SettingsContentMode { SETTINGS, TRANSFER }

/**
 * 【特色功能，勿删】设置类页面焦点手风琴：
 * 展开某张卡片时，其余卡片带淡出+收起动画整体隐藏，呈现单卡聚焦视图；
 * 再次点击该卡头部或触发回顶信号后恢复全部卡片。
 * 该状态必须保存在页面本地（remember）而非 ViewModel——
 * 键为本地化标题，跨语言/跨重建残留会导致全部卡片失配折叠（历史空白页 bug）。
 */
internal val LocalFocusedSettingsCard = compositionLocalOf<Pair<String?, (String?) -> Unit>?> { null }

private data class PendingCloudAssociation(
    val newFileUri: String,
    val previousFileUri: String,
    val newTreeUri: String = "",
    val previousTreeUri: String = "",
)

private data class PendingCloudCreation(val treeUri: String, val displayName: String)
private data class PendingDownloadOverwrite(val target: String, val action: () -> Unit, val step: Int = 1)
private class CertificateTooLargeException : Exception()

/**
 * 云端同步相关设置的加密存储快照：一次性在后台读取，避免进入设置/同步页的首帧组合期间
 * 在主线程连续执行 AndroidKeyStore 解密（WebDAV 凭据、自动同步设置、云端偏好）导致卡顿。
 */
private data class SettingsCloudSnapshot(
    val enabled: Boolean = false,
    val provider: String = "",
    val mode: String = "",
    val diskUri: String = "",
    val diskTreeUri: String = "",
    val diskStatus: String = "",
    val diskSize: Long = -1L,
    val diskModified: Long = 0L,
    val diskLogicalRevision: String = "",
    val webDav: WebDavConfig? = null,
    val webDavStatus: String = "",
    val auto: AutoCloudSyncSettings? = null,
)

private data class LocalBackupUiSnapshot(
    val treeUri: String? = null,
    val deviceLabel: String? = null,
)

private fun loadSettingsCloudSnapshot(ctx: Context, vaultId: String): SettingsCloudSnapshot {
    val p = com.vault.security.SecurePreferences.get(ctx, "cloud_sync")
    val suffix = java.security.MessageDigest.getInstance("SHA-256")
        .digest(vaultId.toByteArray()).take(12).joinToString("") { "%02x".format(it) }
    fun key(name: String) = "${name}_$suffix"
    val uri = p.getString(key("uri"), "").orEmpty()
    val webDav = try {
            CloudCredentialStore.load(ctx, vaultId, ByteArray(32))
        } catch (_: Exception) {
            null
        }
    return SettingsCloudSnapshot(
        enabled = p.getBoolean(key("enabled"), false),
        provider = p.getString(key("provider"), "").orEmpty(),
        mode = p.getString(key("mode"), "").orEmpty(),
        diskUri = uri,
        diskTreeUri = p.getString(key("tree_uri"), "").orEmpty(),
        diskStatus = p.getString(key("disk_status"), if (uri.isBlank()) "" else "ok").orEmpty(),
        diskSize = p.getLong(key("disk_size"), -1L),
        diskModified = p.getLong(key("disk_modified"), 0L),
        diskLogicalRevision = p.getString(key("disk_logical_revision"), "").orEmpty(),
        webDav = webDav,
        webDavStatus = p.getString(key("webdav_status"), if (webDav == null) "" else "ok").orEmpty(),
        auto = AutoCloudSyncPrefs.load(ctx, vaultId),
    )
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun SettingsScreen(
    vm: VaultViewModel,
    isActive: Boolean = true,
    contentMode: SettingsContentMode = SettingsContentMode.SETTINGS,
    onOpenEntry: (Entry) -> Unit = {},
    scrollToTopSignal: Int = 0,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
) {
    val ctx = LocalContext.current
    val securityChangePasswordGuard = stringResource(R.string.settings_remaining_change_password_guard)
    val securityRegenerateRecoveryGuard = stringResource(R.string.settings_remaining_regenerate_recovery_guard)
    val securityDisableBiometricGuard = stringResource(R.string.settings_remaining_disable_biometric_guard)
    val securityEnableBiometricGuard = stringResource(R.string.settings_remaining_enable_biometric_guard)
    val biometricEnabledMessage = stringResource(R.string.settings_remaining_biometric_enabled)
    val biometricUnavailableMessage = stringResource(R.string.settings_remaining_biometric_unavailable)
    val biometricEnableFailedMessage = stringResource(R.string.settings_remaining_biometric_enable_failed)
    val cloudAssociationReadError = stringResource(R.string.settings_remaining_cloud_association_read_error)
    val cloudFileMissingMessage = stringResource(R.string.settings_remaining_cloud_file_missing)
    val cloudFileReplacedMessage = stringResource(R.string.settings_remaining_cloud_file_replaced)
    val cloudFileAmbiguousMessage = stringResource(R.string.settings_remaining_cloud_file_ambiguous)
    val cloudFileInvalidMessage = stringResource(R.string.settings_remaining_cloud_file_invalid)
    val cloudPermissionMissingMessage = stringResource(R.string.settings_remaining_cloud_file_permission_missing)
    val cloudDirectoryPermissionMissingMessage = stringResource(R.string.settings_remaining_cloud_directory_permission_missing_error)
    val cloudMultipleFilesFormat = stringResource(R.string.settings_remaining_cloud_multiple_files_error)
    val certificateTooLargeMessage = stringResource(R.string.settings_remaining_certificate_too_large)
    val certificateReadFailedMessage = stringResource(R.string.settings_remaining_certificate_read_failed)
    val biometricUnknownErrorMessage = stringResource(R.string.settings_remaining_biometric_unknown_error)
    val invalidQrPairingMessage = stringResource(R.string.settings_remaining_invalid_qr_pairing)
    val webDavInvalidUrlMessage = stringResource(R.string.settings_remaining_webdav_invalid_url)
    val webDavConfigInvalidMessage = stringResource(R.string.settings_remaining_webdav_config_invalid)
    val renameAccountGuard = stringResource(R.string.settings_remaining_rename_account_guard)
    val activity = ctx as? FragmentActivity
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    val settingsListState = rememberLazyListState()

    val currentVault by vm.currentVault.collectAsStateWithLifecycle()
    val state by vm.state.collectAsStateWithLifecycle()
    // 使用稳定 ID 保存手风琴焦点，语言切换后本地化标题变化也不会导致展开状态失配。
    var focusedSettingsCardTitle by rememberSaveable { mutableStateOf<String?>(null) }
    val setFocusedSettingsCard: (String?) -> Unit = { focusedSettingsCardTitle = it }
    // 同步页大卡（transferPanels）内分区的展开 ID：手风琴单开，导航二次点击复位
    var transferExpandedSection by rememberSaveable { mutableStateOf<String?>(null) }
    // 设置页大卡（settingsPanels）内分区（账户/安全/外观/关于）的展开 ID：手风琴单开，导航二次点击复位
    var settingsExpandedSection by rememberSaveable { mutableStateOf<String?>(null) }
    val cloudSyncBusy by remember(vm) {
        cloudSyncBusyChanges(vm.cloudSyncState)
    }.collectAsStateWithLifecycle(initialValue = false)
    val lanHostState by vm.lanHostState.collectAsStateWithLifecycle()
    val lanSyncResult by vm.syncResult.collectAsStateWithLifecycle()
    val lanHostExportPending by vm.lanHostExportPending.collectAsStateWithLifecycle()
    val lanHostExportPendingDevice by vm.lanHostExportPendingDevice.collectAsStateWithLifecycle()
    val lanHostExportApprovalToken by vm.lanHostExportApprovalToken.collectAsStateWithLifecycle()
    val lanHostSyncPending by vm.lanHostSyncPending.collectAsStateWithLifecycle()
    val lanHostSyncPendingDevice by vm.lanHostSyncPendingDevice.collectAsStateWithLifecycle()
    val lanHostSyncApprovalToken by vm.lanHostSyncApprovalToken.collectAsStateWithLifecycle()
    val lanHostTransferPending by vm.lanHostTransferPending.collectAsStateWithLifecycle()
    val lanHostTransferPendingDevice by vm.lanHostTransferPendingDevice.collectAsStateWithLifecycle()
    val lanHostTransferApprovalToken by vm.lanHostTransferApprovalToken.collectAsStateWithLifecycle()
    val localBackupStatus by vm.localBackupStatus.collectAsStateWithLifecycle()
    val lanSyncProgress by vm.lanSyncProgress.collectAsStateWithLifecycle()
    val localBackupRunning by vm.localBackupRunningFlow.collectAsStateWithLifecycle()
    val latestIsActive by rememberUpdatedState(isActive)

    // 备份目录与设备名称是加密字段：后台读取为轻量快照，Compose 重组只访问内存。
    // 目录选择完成后状态文本会变化，从而刷新一次快照，不在每次重组时重复解密。
    var localBackupSnapshot by remember { mutableStateOf(LocalBackupUiSnapshot()) }
    LaunchedEffect(contentMode, localBackupStatus, currentVault) {
        if (contentMode != SettingsContentMode.TRANSFER) return@LaunchedEffect
        val vaultKey = currentVault ?: ""
        localBackupSnapshot = withContext(Dispatchers.IO) {
            LocalBackupUiSnapshot(
                treeUri = LocalBackupPref.treeUri(ctx, vaultKey),
                deviceLabel = LocalBackupPref.deviceLabel(ctx, vaultKey),
            )
        }
    }

    var showChangePw by remember { mutableStateOf(false) }
    val passkeyModePref = remember { PasskeyModePref(ctx) }
    var passkeyCreationPreference by remember { mutableStateOf(passkeyModePref.creationPreference) }
    var passkeyModeButtonWidthPx by remember { mutableIntStateOf(0) }
    val passkeyModeButtonWidth = with(LocalDensity.current) { passkeyModeButtonWidthPx.toDp() }
    var pendingExportBakUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pendingImportBakUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pendingImportCsvUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var pendingExportArchiveUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var passkeyModeMenuExpanded by remember { mutableStateOf(false) }
    val cloudPrefs = remember { com.vault.security.SecurePreferences.get(ctx, "cloud_sync") }
    val cloudSuffix = remember(currentVault) {
        java.security.MessageDigest.getInstance("SHA-256").digest(vm.cloudVaultKey().toByteArray())
            .take(12).joinToString("") { "%02x".format(it) }
    }
    fun cloudKey(name: String) = "${name}_$cloudSuffix"
    // 云端/自动同步/WebDAV 凭据统一在后台线程加载：避免首帧组合期间在主线程多次执行
    // AndroidKeyStore 解密，导致进入设置/同步页时明显卡顿。首帧先展示默认值，加载完成后再写入。
    var cloudSnapshot by remember(currentVault) { mutableStateOf<SettingsCloudSnapshot?>(null) }
    LaunchedEffect(currentVault) {
        cloudSnapshot = withContext(Dispatchers.IO) {
            loadSettingsCloudSnapshot(ctx, vm.cloudVaultKey())
        }
    }
    var cloudEnabled by remember(currentVault) { mutableStateOf(false) }
    var cloudProvider by remember(currentVault) { mutableStateOf("") }
    var cloudMode by remember(currentVault) { mutableStateOf("") }
    var cloudDiskUri by remember(currentVault) { mutableStateOf("") }
    var cloudDiskTreeUri by remember(currentVault) { mutableStateOf("") }
    var cloudDiskStatus by remember(currentVault) { mutableStateOf("") }
    var cloudDiskSize by remember(currentVault) { mutableStateOf(-1L) }
    var cloudDiskModified by remember(currentVault) { mutableStateOf(0L) }
    var cloudDiskLogicalRevision by remember(currentVault) { mutableStateOf("") }
    var webDavAssociated by remember(currentVault) { mutableStateOf(false) }
    // 云端同步二档滑块：云端硬盘 / WebDAV（默认优先已关联的一端，其次云端硬盘）
    var cloudProviderMode by rememberSaveable(currentVault) { mutableStateOf("drive") }
    var webDavStatus by remember(currentVault) { mutableStateOf("") }
    var showWebDavDialog by rememberSaveable { mutableStateOf(false) }
    var webDavLabel by rememberSaveable(currentVault) { mutableStateOf("WebDAV") }
    var webDavUrl by rememberSaveable(currentVault) { mutableStateOf("") }
    var webDavUsername by rememberSaveable(currentVault) { mutableStateOf("") }
    var webDavPassword by remember(currentVault) { mutableStateOf("") }
    var webDavAuthMode by rememberSaveable(currentVault) { mutableStateOf("basic") }
    var webDavBearerToken by remember(currentVault) { mutableStateOf("") }
    var webDavCertificate by rememberSaveable(currentVault) { mutableStateOf("") }
    var webDavCreateDirectories by rememberSaveable(currentVault) { mutableStateOf(false) }
    var webDavCookie by remember(currentVault) { mutableStateOf("") }
    var webDavClientCertificate by remember(currentVault) { mutableStateOf("") }
    var webDavClientCertificatePassword by remember(currentVault) { mutableStateOf("") }
    var webDavDomain by rememberSaveable(currentVault) { mutableStateOf("") }
    var autoSyncEnabled by remember(currentVault) { mutableStateOf(false) }
    var autoSyncTarget by remember(currentVault) { mutableStateOf("") }
    var autoSyncInterval by remember(currentVault) { mutableIntStateOf(60) }
    // 自动同步下次运行时间基准（enabled_at / last_success 的最大值），后台加载，避免组合期读加密偏好。
    var autoNextRunBase by remember(currentVault) { mutableLongStateOf(0L) }
    var autoSyncStatus by remember(currentVault) { mutableStateOf("") }
    var autoSyncFailures by remember(currentVault) { mutableIntStateOf(0) }
    /** 自动同步开关：目标已关联才允许开启；存储值残留开启时强制关闭并持久化，避免未关联却自动开启。 */
    fun applyAutoSyncEnabled(rawEnabled: Boolean, targetAvailable: Boolean) {
        autoSyncEnabled = rawEnabled && targetAvailable
        if (rawEnabled && !targetAvailable) {
            AutoCloudSyncPrefs.save(ctx, vm.cloudVaultKey(), false, cloudProviderMode, autoSyncInterval)
        }
    }
    // 后台快照到达后一次性写入云端相关状态。
    LaunchedEffect(cloudSnapshot) {
        val s = cloudSnapshot ?: return@LaunchedEffect
        cloudEnabled = s.enabled
        cloudProvider = s.provider
        cloudMode = s.mode
        cloudDiskUri = s.diskUri
        cloudDiskTreeUri = s.diskTreeUri
        cloudDiskStatus = s.diskStatus
        cloudDiskSize = s.diskSize
        cloudDiskModified = s.diskModified
        cloudDiskLogicalRevision = s.diskLogicalRevision
        webDavAssociated = s.webDav != null
        webDavStatus = s.webDavStatus
        s.webDav?.let { w ->
            webDavLabel = w.label
            webDavUrl = runCatching { WebDavCloud.directoryUrl(w.fileUrl) }.getOrDefault(w.fileUrl)
            webDavUsername = w.username
            webDavPassword = w.password
            webDavAuthMode = w.authMode.takeIf { it !in setOf("ntlm", "kerberos") } ?: "basic"
            webDavBearerToken = w.bearerToken
            webDavCertificate = w.certificateSha256
            webDavCreateDirectories = w.createDirectories
            webDavCookie = w.cookie
            webDavClientCertificate = w.clientCertificate
            webDavClientCertificatePassword = w.clientCertificatePassword
            webDavDomain = w.domain
        }
        // 未关联云端硬盘时，优先展示已关联的 WebDAV（与原来的默认值选择一致）。
        if (cloudProviderMode == "drive" && s.diskUri.isBlank() && s.webDav != null) {
            cloudProviderMode = "webdav"
        }
    }
    // 滑块切换云端硬盘/WebDAV 时，加载对应目标的自动同步设置（分离处理，不再用目标下拉框）
    LaunchedEffect(cloudProviderMode, currentVault, cloudSnapshot, state.cloudSyncRunning) {
        val snapshot = cloudSnapshot ?: return@LaunchedEffect
        val vaultKey = vm.cloudVaultKey()
        val loaded = withContext(Dispatchers.IO) {
            val p = com.vault.security.SecurePreferences.get(ctx, "cloud_sync")
            val mode = cloudProviderMode
            val enabledKey = AutoCloudSyncPrefs.key(vaultKey, "${mode}_enabled")
            val hasModeKey = p.contains(enabledKey)
            var enabled = p.getBoolean(enabledKey, false)
            val intKey = AutoCloudSyncPrefs.key(vaultKey, "${cloudProviderMode}_interval")
            val interval = p.getInt(intKey, 60).takeIf { it in AutoCloudSyncPrefs.intervals } ?: 60
            // 旧版只写共享 auto_enabled/auto_target：属于本目标时迁移为本目标独立键，
            // 之后本目标开关不再受另一个目标影响。
            if (!hasModeKey &&
                p.getBoolean(AutoCloudSyncPrefs.key(vaultKey, "auto_enabled"), false) &&
                p.getString(AutoCloudSyncPrefs.key(vaultKey, "auto_target"), "") == mode
            ) {
                AutoCloudSyncPrefs.save(ctx, vaultKey, true, mode, interval)
                enabled = true
            }
            val base = maxOf(
                p.getLong(AutoCloudSyncPrefs.key(vaultKey, "${mode}_enabled_at"), 0L),
                p.getLong(AutoCloudSyncPrefs.key(vaultKey, "${cloudProviderMode}_last_success"), 0L),
            )
            Triple(enabled, interval, Pair(base, AutoCloudSyncPrefs.loadTargetStatus(ctx, vaultKey, mode)))
        }
        val targetAvailable =
            if (cloudProviderMode == "drive") snapshot.diskUri.isNotBlank() else snapshot.webDav != null
        autoSyncEnabled = loaded.first && targetAvailable
        if (loaded.first && !targetAvailable) {
            AutoCloudSyncPrefs.save(ctx, vm.cloudVaultKey(), false, cloudProviderMode, loaded.second)
        }
        autoSyncInterval = loaded.second
        autoNextRunBase = loaded.third.first
        autoSyncStatus = loaded.third.second.status
        autoSyncFailures = loaded.third.second.failures
    }
    var cloudDiskPreview by remember(currentVault, cloudDiskUri) {
        mutableStateOf(
            cloudDiskUri.takeIf(String::isNotBlank)
                ?.let { vm.cachedCloudVaultPreview(android.net.Uri.parse(it)) },
        )
    }
    // WebDAV 预览由后台异步检测填充，避免在主线程同步解密凭据。
    var webDavPreview by remember(currentVault) {
        mutableStateOf<VaultViewModel.CloudSyncPreview?>(null)
    }
    var pendingCloudOverwrite by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var showAllowScreenCaptureRisk by remember { mutableStateOf(false) }
    var pendingDownloadOverwrite by remember { mutableStateOf<PendingDownloadOverwrite?>(null) }
    var pendingCloudAssociation by remember { mutableStateOf<PendingCloudAssociation?>(null) }
    var pendingCloudCreation by remember { mutableStateOf<PendingCloudCreation?>(null) }
    var cloudAssociationProgress by remember(currentVault) { mutableStateOf<String?>(null) }
    var pendingWebDavAssociation by remember { mutableStateOf<WebDavConfig?>(null) }
    var showCloudEnableAcknowledgement by remember { mutableStateOf(false) }
    var pendingAssociationCancel by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var showCloudAssociationSource by remember { mutableStateOf(false) }
    var pendingDirectCloudFileUri by remember { mutableStateOf<String?>(null) }
    var pendingFileOnlyCloudUri by remember { mutableStateOf<String?>(null) }
    var renameTarget by remember { mutableStateOf<String?>(null) }
    var deleteTarget by remember { mutableStateOf<String?>(null) }
    // 自动填充状态与排除列表（含加密偏好解密）移到后台线程读取，避免首帧组合卡顿。
    var autofillState by remember { mutableStateOf(AutofillSupportState.UNSUPPORTED) }
    var autofillSettingsInProgress by remember { mutableStateOf(false) }
    var credentialProviderState by remember { mutableStateOf(AutofillSupportState.UNSUPPORTED) }
    val credentialProviderExternalActionGuard = remember(vm) {
        CredentialProviderExternalActionGuard(vm::setExternalActionInProgress)
    }
    var excludedPackages by remember { mutableStateOf(emptySet<String>()) }
    var excludedHosts by remember { mutableStateOf(emptySet<String>()) }
    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) {
            AutofillSetup.supportState(ctx) to AutofillSetup.credentialProviderState(ctx)
        }
        autofillState = loaded.first
        credentialProviderState = loaded.second
    }
    LaunchedEffect(currentVault, state.payload?.autofillExclusions) {
        val loaded = withContext(Dispatchers.IO) {
            AutofillExcludePref.excludedPackages(ctx) to AutofillExcludePref.excludedHosts(ctx)
        }
        excludedPackages = loaded.first
        excludedHosts = loaded.second
    }
    var showExclusionEditor by remember { mutableStateOf(false) }
    val autofillSettingsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        autofillSettingsInProgress = false
        vm.setExternalActionInProgress(false)
        autofillState = AutofillSetup.supportState(ctx)
        credentialProviderState = AutofillSetup.credentialProviderState(ctx)
    }
    val credentialProviderLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        credentialProviderExternalActionGuard.finish()
        credentialProviderState = AutofillSetup.credentialProviderState(ctx)
    }
    DisposableEffect(lifecycleOwner, isActive) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && isActive) {
                if (autofillSettingsInProgress) {
                    autofillSettingsInProgress = false
                    vm.setExternalActionInProgress(false)
                }
                credentialProviderExternalActionGuard.finish()
                autofillState = AutofillSetup.supportState(ctx)
                credentialProviderState = AutofillSetup.credentialProviderState(ctx)
                excludedPackages = AutofillExcludePref.excludedPackages(ctx)
                excludedHosts = AutofillExcludePref.excludedHosts(ctx)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            credentialProviderExternalActionGuard.finish()
        }
    }

    val bio = remember(currentVault) { currentVault?.let { vm.biometricFor(it) } }
    var bioEnabled by remember(currentVault) { mutableStateOf(bio?.isEnrolled() == true) }

    // 敏感操作使用全局 5 分钟提升会话；锁定或超时后自动失效。
    var pendingGuarded by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    LaunchedEffect(isActive) {
        if (!isActive) {
            pendingGuarded = null
        }
    }
    // force=true 时即便本会话已验证过，仍要再弹一次主密码框 —— 用于"删除账户"这类不可逆操作
    fun guard(reason: String, force: Boolean = false, action: () -> Unit) {
        if (vm.hasSecuritySession() && !force) action() else pendingGuarded = reason to action
    }

    // 与自动填充设置一致：拉起外部界面（文件选择器/扫码/系统设置）前标记外部操作，
    // 返回主页面时由 launcher 回调复位，期间不触发无操作/退后台自动锁定。
    fun launchExternal(block: () -> Unit) {
        vm.setExternalActionInProgress(true)
        block()
    }

    fun saveAutoSyncPrefs() {
        autoSyncTarget = cloudProviderMode
        AutoCloudSyncPrefs.save(ctx, vm.cloudVaultKey(), autoSyncEnabled, autoSyncTarget, autoSyncInterval)
    }

    fun saveAutoSyncSettings() {
        saveAutoSyncPrefs()
        vm.refreshAutoCloudSyncSchedule()
    }

    fun releaseCloudAccess(fileUri: String, treeUri: String = "") {
        val value = treeUri.ifBlank { fileUri }
        if (value.isBlank()) return
        runCatching {
            ctx.contentResolver.releasePersistableUriPermission(
                android.net.Uri.parse(value),
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
    }

    fun persistCloudCheck(check: com.vault.storage.CloudFileCheck, updateBaseline: Boolean) {
        val metadata = check.metadata
        cloudDiskStatus = when (check.state) {
            com.vault.storage.CloudFileState.PRESENT -> {
                val changed = !updateBaseline && cloudDiskModified > 0L &&
                    metadata != null && metadata.lastModified > 0L &&
                    cloudDiskModified != metadata.lastModified
                if (changed) "changed" else "ok"
            }
            com.vault.storage.CloudFileState.MISSING -> "missing"
            com.vault.storage.CloudFileState.REPLACED -> "replaced"
            com.vault.storage.CloudFileState.AMBIGUOUS -> "ambiguous"
        }
        if (updateBaseline && metadata != null) {
            cloudDiskSize = metadata.size
            cloudDiskModified = metadata.lastModified
            cloudDiskLogicalRevision = ""
        }
        cloudPrefs.edit()
            .putString(cloudKey("disk_status"), cloudDiskStatus)
            .putLong(cloudKey("disk_size"), cloudDiskSize)
            .putLong(cloudKey("disk_modified"), cloudDiskModified)
            .putString(cloudKey("disk_logical_revision"), cloudDiskLogicalRevision)
            .apply()
    }

    fun checkAssociatedCloudFile(updateBaseline: Boolean = false, onReady: (() -> Unit)? = null) {
        if (cloudDiskUri.isBlank() || cloudDiskTreeUri.isBlank()) {
            onReady?.invoke()
            return
        }
        vm.checkCloudFileAssociation(
            android.net.Uri.parse(cloudDiskTreeUri),
            vm.cloudVaultFileName(currentVault ?: "vault"),
            android.net.Uri.parse(cloudDiskUri),
        ) { check ->
            if (check == null) {
                cloudDiskStatus = "failed"
                cloudPrefs.edit().putString(cloudKey("disk_status"), cloudDiskStatus).apply()
                if (onReady != null) vm.postError(cloudAssociationReadError)
            } else {
                persistCloudCheck(check, updateBaseline)
                if (check.state == com.vault.storage.CloudFileState.PRESENT) {
                    onReady?.invoke()
                } else if (onReady != null) {
                    val message = when (check.state) {
                        com.vault.storage.CloudFileState.MISSING -> cloudFileMissingMessage
                        com.vault.storage.CloudFileState.REPLACED -> cloudFileReplacedMessage
                        com.vault.storage.CloudFileState.AMBIGUOUS -> cloudFileAmbiguousMessage
                        else -> cloudFileInvalidMessage
                    }
                    vm.postError(message)
                }
            }
        }
    }

    fun finishCloudAssociation(candidate: PendingCloudAssociation, success: Boolean) {
        cloudAssociationProgress = null
        if (!success) {
            if (candidate.newFileUri != candidate.previousFileUri || candidate.newTreeUri != candidate.previousTreeUri) {
                releaseCloudAccess(candidate.newFileUri, candidate.newTreeUri)
            }
            return
        }
        cloudDiskUri = candidate.newFileUri
        cloudDiskTreeUri = candidate.newTreeUri
        cloudDiskStatus = "ok"
        if (candidate.previousFileUri != candidate.newFileUri || candidate.previousTreeUri != candidate.newTreeUri) {
            cloudDiskLogicalRevision = ""
        }
        cloudPrefs.edit()
            .putString(cloudKey("uri"), candidate.newFileUri)
            .putString(cloudKey("tree_uri"), candidate.newTreeUri)
            .putString(cloudKey("disk_status"), "ok")
            .putString(cloudKey("disk_logical_revision"), cloudDiskLogicalRevision)
            .apply()
        if ((candidate.previousFileUri.isNotBlank() || candidate.previousTreeUri.isNotBlank()) &&
            (candidate.previousFileUri != candidate.newFileUri || candidate.previousTreeUri != candidate.newTreeUri)
        ) {
            releaseCloudAccess(candidate.previousFileUri, candidate.previousTreeUri)
        }
        checkAssociatedCloudFile(updateBaseline = true)
    }

    fun finishWebDavAssociation(config: WebDavConfig, success: Boolean) {
        if (!success) return
        vm.saveCloudConfig(config)
        webDavAssociated = true
        webDavStatus = "ok"
        cloudMode = "webdav"
        cloudProvider = config.label
        cloudPrefs.edit()
            .putString(cloudKey("mode"), cloudMode)
            .putString(cloudKey("provider"), cloudProvider)
            .putString(cloudKey("webdav_status"), "ok")
            .apply()
        // 关联成功后立即识别远端文件并展示结果，避免“创建/连接成功但没有反馈”。
        webDavPreview = VaultViewModel.CloudSyncPreview(
            "checking",
            "WebDAV",
            message = "正在识别远端保险库文件…",
        )
        vm.previewWebDav { if (latestIsActive) webDavPreview = it }
    }

    fun handleCloudSelection(uri: android.net.Uri?, treeUri: String = "") {
        if (uri == null) {
            cloudAssociationProgress = null
            vm.setExternalActionInProgress(false)
            return
        }
        val candidate = PendingCloudAssociation(
            newFileUri = uri.toString(),
            previousFileUri = cloudDiskUri,
            newTreeUri = treeUri,
            previousTreeUri = cloudDiskTreeUri,
        )
        val persisted = treeUri.isNotBlank() || runCatching {
                ctx.contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }.isSuccess
        if (!persisted) {
            cloudAssociationProgress = null
            vm.setExternalActionInProgress(false)
            vm.postError(cloudPermissionMissingMessage)
            return
        }
        cloudAssociationProgress = "正在读取并验证所选保险库文件…"
        vm.inspectCloudFile(uri) { hasData ->
            vm.setExternalActionInProgress(false)
            when (hasData) {
                true -> {
                    cloudAssociationProgress = null
                    pendingCloudAssociation = candidate
                }
                false -> {
                    cloudAssociationProgress = "正在写入加密保险库文件…"
                    vm.overwriteCloudVault(uri) { success ->
                        finishCloudAssociation(candidate, success)
                    }
                }
                null -> finishCloudAssociation(candidate, false)
            }
        }
    }

    val exportBakLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
        vm.setExternalActionInProgress(false)
        if (it != null) pendingExportBakUri = it
    }
    val importBakLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        vm.setExternalActionInProgress(false)
        if (it != null) pendingImportBakUri = it
    }
    val exportRawLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
        vm.setExternalActionInProgress(false)
        if (it != null) guard("导出原始保险库文件需要验证当前主密码。", force = true) {
            vm.authorizeSensitiveExport("raw", it)
            vm.exportVaultRaw(it)
        }
    }
    val exportArchiveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) {
        vm.setExternalActionInProgress(false)
        if (it != null) pendingExportArchiveUri = it
    }
    val localBackupDirLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        vm.setExternalActionInProgress(false)
        if (uri != null) {
            // 持久化授权 + 后台识别卷身份 + 立即首次备份，均由 ViewModel 完成并给出状态提示
            vm.selectLocalBackupDirectory(uri, true)
        }
    }
    val clientCertificateLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        vm.setExternalActionInProgress(false)
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val bytes = ctx.contentResolver.openInputStream(uri)?.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > 1024 * 1024) throw CertificateTooLargeException()
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            } ?: error(certificateReadFailedMessage)
            webDavClientCertificate = Base64.encodeToString(bytes, Base64.NO_WRAP)
        }.onFailure { error ->
            vm.postError(if (error is CertificateTooLargeException) certificateTooLargeMessage else certificateReadFailedMessage)
        }
    }
    val cloudTreeLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { treeUri ->
        val directFileValue = pendingDirectCloudFileUri
        pendingDirectCloudFileUri = null
        if (directFileValue != null) {
            val directFileUri = android.net.Uri.parse(directFileValue)
            if (treeUri == null) {
                vm.setExternalActionInProgress(false)
                pendingFileOnlyCloudUri = directFileValue
                return@rememberLauncherForActivityResult
            }
            val treeValue = treeUri.toString()
            val persisted = runCatching {
                ctx.contentResolver.takePersistableUriPermission(
                    treeUri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }.isSuccess
            if (!persisted) {
                vm.setExternalActionInProgress(false)
                pendingFileOnlyCloudUri = directFileValue
                vm.postError(cloudDirectoryPermissionMissingMessage)
                return@rememberLauncherForActivityResult
            }
            handleCloudSelection(directFileUri, treeValue)
            return@rememberLauncherForActivityResult
        }
        if (treeUri == null) {
            vm.setExternalActionInProgress(false)
            return@rememberLauncherForActivityResult
        }
        val treeValue = treeUri.toString()
        val persisted = runCatching {
            ctx.contentResolver.takePersistableUriPermission(
                treeUri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }.isSuccess
        if (!persisted) {
            cloudAssociationProgress = null
            vm.setExternalActionInProgress(false)
            vm.postError(cloudDirectoryPermissionMissingMessage)
        } else {
            val displayName = vm.cloudVaultFileName(currentVault ?: "vault")
            cloudAssociationProgress = "正在检查所选云端目录…"
            vm.inspectCloudDirectory(treeUri, displayName) { inspection ->
                when {
                    inspection == null -> {
                        cloudAssociationProgress = null
                        vm.setExternalActionInProgress(false)
                        if (treeValue != cloudDiskTreeUri) releaseCloudAccess("", treeValue)
                    }
                    inspection.exactMatches.size == 1 -> handleCloudSelection(inspection.exactMatches.single().uri, treeValue)
                    inspection.pmvCount > 0 -> {
                        cloudAssociationProgress = null
                        vm.setExternalActionInProgress(false)
                        if (treeValue != cloudDiskTreeUri) releaseCloudAccess("", treeValue)
                        vm.postError(cloudMultipleFilesFormat.format(inspection.pmvCount))
                    }
                    else -> {
                        cloudAssociationProgress = null
                        vm.setExternalActionInProgress(false)
                        pendingCloudCreation = PendingCloudCreation(treeValue, displayName)
                    }
                }
            }
        }
    }
    val cloudOpenLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            vm.setExternalActionInProgress(false)
            return@rememberLauncherForActivityResult
        }
        val persisted = runCatching {
            ctx.contentResolver.takePersistableUriPermission(
                uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }.isSuccess
        if (!persisted) {
            vm.setExternalActionInProgress(false)
            vm.postError(cloudPermissionMissingMessage)
            return@rememberLauncherForActivityResult
        }
        pendingDirectCloudFileUri = uri.toString()
        runCatching { cloudTreeLauncher.launch(uri) }.onFailure {
            pendingDirectCloudFileUri = null
            pendingFileOnlyCloudUri = uri.toString()
            vm.setExternalActionInProgress(false)
        }
    }
    LaunchedEffect(currentVault, cloudMode) {
        if (cloudMode in setOf("google", "microsoft", "saf")) {
            cloudMode = ""
            cloudProvider = ""
            cloudPrefs.edit()
                .remove(cloudKey("mode"))
                .remove(cloudKey("provider"))
                .apply()
        }
    }
    // 云同步卡展开状态以稳定 ID 判断，避免语言切换时标题变化导致检查流程中断。
    val cloudSyncTitle = stringResource(R.string.settings_remaining_cloud_sync)
    val cloudSyncCardExpanded = transferExpandedSection == "transfer-cloud-sync"
    LaunchedEffect(
        currentVault,
        isActive,
        contentMode,
        cloudEnabled,
        cloudSyncCardExpanded,
        cloudDiskUri,
        cloudDiskTreeUri,
        webDavAssociated,
    ) {
        if (!isActive || contentMode != SettingsContentMode.TRANSFER || !cloudEnabled || !cloudSyncCardExpanded) {
            return@LaunchedEffect
        }
        fun inspectWebDav() {
            if (webDavAssociated) {
                // 直接走异步检测：previewWebDav 内部在 IO 线程复用缓存，
                // 避免在主线程同步解密 WebDAV 凭据造成卡顿。
                webDavPreview = VaultViewModel.CloudSyncPreview("checking", "WebDAV", message = localizeUiTextFor(ctx, "正在检测远端数据…"))
                vm.previewWebDav { if (latestIsActive) webDavPreview = it }
            } else webDavPreview = null
        }
        if (cloudDiskUri.isNotBlank()) {
            if (cloudDiskTreeUri.isNotBlank()) checkAssociatedCloudFile()
            val uri = android.net.Uri.parse(cloudDiskUri)
            val cached = vm.cachedCloudVaultPreview(uri)
            if (cached != null) {
                cloudDiskPreview = cached
                inspectWebDav()
            } else {
                cloudDiskPreview = VaultViewModel.CloudSyncPreview("checking", "云端硬盘", message = localizeUiTextFor(ctx, "正在检测远端数据…"))
                vm.previewCloudVault(uri) {
                    if (latestIsActive) {
                        cloudDiskPreview = it
                        inspectWebDav()
                    }
                }
            }
        } else {
            cloudDiskPreview = null
            inspectWebDav()
        }
    }
    // 轮询只读取当前模式（云端硬盘/WebDAV）的独立自动同步设置，
    // 避免共享 auto_target 把另一个目标的开关状态带到当前页面、反复改写开关。
    LaunchedEffect(currentVault, isActive, contentMode, cloudEnabled, cloudProviderMode) {
        while (isActive && contentMode == SettingsContentMode.TRANSFER && cloudEnabled) {
            val mode = cloudProviderMode
            val latest = withContext(Dispatchers.IO) {
                val p = com.vault.security.SecurePreferences.get(ctx, "cloud_sync")
                val vaultKey = vm.cloudVaultKey()
                val enabled = p.getBoolean(AutoCloudSyncPrefs.key(vaultKey, "${mode}_enabled"), false)
                val interval = p.getInt(AutoCloudSyncPrefs.key(vaultKey, "${mode}_interval"), 60)
                    .takeIf { it in AutoCloudSyncPrefs.intervals } ?: 60
                val base = maxOf(
                    p.getLong(AutoCloudSyncPrefs.key(vaultKey, "${mode}_enabled_at"), 0L),
                    p.getLong(AutoCloudSyncPrefs.key(vaultKey, "${mode}_last_success"), 0L),
                )
                Triple(enabled, interval, base)
            }
            applyAutoSyncEnabled(
                latest.first,
                if (mode == "drive") cloudDiskUri.isNotBlank() else webDavAssociated,
            )
            autoSyncInterval = latest.second
            autoNextRunBase = latest.third
            delay(5_000L)
        }
    }
    val importCsvLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        vm.setExternalActionInProgress(false)
        if (it != null) pendingImportCsvUri = it
    }
    var showManualLanInput by remember { mutableStateOf(false) }
    var manualLanUrl by remember { mutableStateOf("") }
    var showLanHostConfirm by remember { mutableStateOf(false) }
    var scannedLanUrl by remember { mutableStateOf<String?>(null) }
    var scannedLanPinSubmitting by remember { mutableStateOf(false) }
    var scannedLanPinAttempts by rememberSaveable { mutableIntStateOf(0) }
    var scannedLanPinError by rememberSaveable { mutableStateOf("") }
    var lanUiMode by rememberSaveable { mutableStateOf(LanUiMode.SYNC) }
    // 页面状态属于同步页本身，折叠局域网卡片不能销毁它。
    var transferView by rememberSaveable(
        stateSaver = androidx.compose.runtime.saveable.listSaver<com.vault.ui.LanTransferViewState, Any>(
            save = { listOf(it.open, it.host, it.pairSeq) },
            restore = { com.vault.ui.LanTransferViewState(it[0] as Boolean, it[1] as Boolean, it[2] as Int) },
        ),
    ) { mutableStateOf(com.vault.ui.LanTransferViewState()) }
    var syncViewOpen by rememberSaveable { mutableStateOf(false) }
    // 同步进行中断开要二次确认：中断的是合并写回，可能停在半合并状态。
    var confirmSyncDisconnect by remember { mutableStateOf(false) }
    val isHostTransferSession = lanHostState.running && lanHostState.paired &&
        lanHostState.op == SyncServerHost.TRANSFER_OP
    val transferLive = isHostTransferSession || com.vault.ui.connectorTransferSessionLive(
        state.lanTransferActive, state.lanTransferConnecting, state.lanTransferDisconnected,
    )
    // 启动条件走 shouldStart：仅在「尚未打开」且「配对序号确实变了」时开启。
    // 原来只要 transferLive 为真就 sessionStarted，close() 之后该 effect
    // 因 lanHostState.pairSeq 变化重跑，页面立刻自己回来（常驻无法关闭）。
    LaunchedEffect(lanHostState.pairSeq, transferLive) {
        if (transferLive &&
            transferView.shouldStart(isHostTransferSession, lanHostState.pairSeq)
        ) {
            transferView = transferView.sessionStarted(isHostTransferSession, lanHostState.pairSeq)
        }
    }
    // 只在没有待用户关闭的传输记录页时自动展示同步结果。
    LaunchedEffect(lanSyncResult) {
        if (lanSyncResult != null && !transferView.open) {
            transferExpandedSection = "transfer-lan"
            lanUiMode = LanUiMode.SYNC
        }
    }
    // 实时扫码同步：CameraX + ZXing 实时解码
    val qrSyncLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        vm.setExternalActionInProgress(false)
        if (res.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        IdleTracker.touch()
        val raw = res.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT) ?: return@rememberLauncherForActivityResult
        val pairing = QrPayloadPolicy.parseSync(raw)
        if (pairing == null) {
            vm.postError(invalidQrPairingMessage)
        } else if (pairing.pin != null) {
            // 同步二维码已内嵌一次性 PIN：扫码即完成身份识别，免输 PIN 直接连接
            IdleTracker.touch()
            Toast.makeText(ctx, localizeUiTextFor(ctx, "已识别二维码内嵌 PIN，自动连接"), Toast.LENGTH_SHORT).show()
            if (lanUiMode == LanUiMode.TRANSFER) {
                vm.startLanDataTransfer(pairing.baseUrl, pairing.pin) { result: LanTransferConnectResult ->
                    if (!result.connected) {
                        scannedLanUrl = null
                        Toast.makeText(
                            ctx,
                            localizeUiTextFor(ctx, result.message.ifBlank { "连接失败，请重试" }),
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }
            } else {
                scannedLanUrl = null
                vm.startSync(pairing.baseUrl, pairing.pin)
            }
        } else {
            scannedLanUrl = pairing.baseUrl
            scannedLanPinSubmitting = false
            scannedLanPinAttempts = 0
            scannedLanPinError = ""
        }
    }

    // 本机作为传输站被连接后按通道跳转/弹窗：
    // transfer → 自动切到「文件传输」页内嵌面板（传输站信息随之隐藏）；
    // sync → 自动切到「局域网同步」页并展示同步状态/进度（确认弹窗在卡片层接管）；
    // export → 由「确认导出数据」弹窗接管。
    LaunchedEffect(lanHostState.paired, lanHostState.op, vm.lanHostConnectSignal.value) {
        if (lanHostState.running && lanHostState.paired) {
            when (lanHostState.op) {
                SyncServerHost.TRANSFER_OP -> lanUiMode = LanUiMode.TRANSFER
                SyncServerHost.SYNC_OP -> if (!transferView.open) lanUiMode = LanUiMode.SYNC
                else -> {}
            }
        }
    }

    // ── 扫码相机权限 ───────────────────────────────────────────────
    var pendingCameraAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    var showPermissionSettings by remember { mutableStateOf(false) }
    val requestCameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) pendingCameraAction?.invoke()
        else {
            vm.setExternalActionInProgress(false)
            if (!ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, Manifest.permission.CAMERA)) {
                showPermissionSettings = true
            } else {
                Toast.makeText(ctx, localizeUiTextFor(ctx, "需要相机权限才能扫码"), Toast.LENGTH_SHORT).show()
            }
        }
        pendingCameraAction = null
    }

    val recoveryRegenerationDraft by vm.recoveryRegenerationDraft.collectAsStateWithLifecycle()
    if (showExclusionEditor) {
        // 恢复密钥弹窗同款 VaultDialog：标题+关闭、内容滚动、确认按钮
        AutofillExclusionEditor(
            ctx = ctx,
            excludedPackages = excludedPackages,
            excludedHosts = excludedHosts,
            onUpdate = {
                vm.saveAutofillExclusions()
                excludedPackages = AutofillExcludePref.excludedPackages(ctx)
                excludedHosts = AutofillExcludePref.excludedHosts(ctx)
            },
            onBack = { showExclusionEditor = false },
        )
    }
    run {
        // 记录上一次已消费的置顶信号：页面重建（返回/切换）时旧信号不重复触发置顶，
        // 避免进入页面后自动回到顶部。
        var lastScrollSignal by remember { mutableIntStateOf(scrollToTopSignal) }
        LaunchedEffect(scrollToTopSignal) {
            if (scrollToTopSignal > lastScrollSignal) {
                lastScrollSignal = scrollToTopSignal
                // 二次点击设置/同步 tab：退出焦点手风琴并回顶
                setFocusedSettingsCard(null)
                transferExpandedSection = null
                settingsExpandedSection = null
                settingsListState.animateScrollToItem(0)
            }
        }

        // 【特色功能】提供焦点手风琴上下文：展开一张卡片时其余卡片动画隐藏
        CompositionLocalProvider(LocalFocusedSettingsCard provides (focusedSettingsCardTitle to setFocusedSettingsCard)) {
        LazyColumn(
            state = settingsListState,
            modifier = modifier.vaultBackdropSource().fillMaxSize().imePadding(),
            contentPadding = PaddingValues(
                start = 16.dp,
                top = contentPadding.calculateTopPadding(),
                end = 16.dp,
                bottom = contentPadding.calculateBottomPadding() + 8.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
        item {
            Spacer(Modifier.height(8.dp))
        }
        if (contentMode == SettingsContentMode.TRANSFER) {
            item(contentType = "transferOverview") {
                PageHeaderCard(
                    title = stringResource(R.string.settings_remaining_sync_and_migration),
                    subtitle = if (state.syncRunning) stringResource(R.string.settings_remaining_syncing_with_peer) else stringResource(R.string.settings_remaining_connect_or_transfer),
                    icon = Icons.Filled.Sync,
                )
            }
        }
        // --- 设置页大卡：账户 / 安全 / 外观 / 关于 ---
        if (contentMode == SettingsContentMode.SETTINGS) item(contentType = "settingsPanels") {
            Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.fillMaxWidth()) {
                    val accountSettingsTitle = stringResource(R.string.settings_remaining_account_settings)
                    val securitySettingsTitle = stringResource(R.string.settings_remaining_security_settings)
                    val appearanceSettingsTitle = stringResource(R.string.settings_remaining_appearance)
                    val aboutSettingsTitle = stringResource(R.string.settings_remaining_about)
                    fun toggleSettings(sectionId: String) {
                        settingsExpandedSection = if (settingsExpandedSection == sectionId) null else sectionId
                    }
                    SettingsAccordion(
                        title = accountSettingsTitle,
                        expanded = settingsExpandedSection == "settings-account",
                        activeTitle = settingsExpandedSection,
                        onToggle = { toggleSettings("settings-account") },
                    ) {
                        currentVault?.let { name ->
                            AccountRow(
                                name = name,
                                onRename = { guard(renameAccountGuard) { renameTarget = name } },
                                onDelete = { deleteTarget = name },
                            )
                        } ?: Text(
                            uiText("暂无账户"),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
// 其他账户的切换 / 新建 / 恢复由登录页负责；
                // 重命名 / 删除 / 导入需在对应账户解锁后操作，避免越权
                    }
                    SettingsAccordion(
                        title = securitySettingsTitle,
                        expanded = settingsExpandedSection == "settings-security",
                        activeTitle = settingsExpandedSection,
                        onToggle = { toggleSettings("settings-security") },
                    ) {
                        SettingsSubsectionTitle("修改主密码", topPadding = 0.dp)
                SettingsOutlinedButton(onClick = {
                    guard(securityChangePasswordGuard, force = true) { showChangePw = true }
                }) { Text(uiText("修改主密码")) }
                SettingsSubsectionTitle("紧急恢复密钥")
                val keyRevision = state.payload?.syncMeta?.keyRevision ?: 0
                val keyUpdatedAt = state.payload?.syncMeta?.keyUpdatedAt ?: 0.0
                VaultKeyInfoRow("密钥版本", "v$keyRevision")
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                VaultKeyInfoRow("密钥更新时间", formatEpochSeconds(keyUpdatedAt))
                Spacer(Modifier.height(8.dp))
                SettingsOutlinedButton(onClick = {
                    guard(securityRegenerateRecoveryGuard, force = true) {
                        vm.requestRecoveryRegeneration()
                    }
                }) { Text(uiText("恢复密钥泄露/丢失？重新生成")) }
                if (activity != null && bio != null && bio.canAuthenticate(ctx)) {
                    SettingsSubsectionTitle(
                        "生物识别解锁",
                        help = uiText("设备中登记的所有强生物特征均可解锁此保险库。多人共用设备时，建议仅使用主密码。"),
                    )
                    VaultActionButton(
                        onClick = {
                            if (bioEnabled) {
                                guard(securityDisableBiometricGuard) {
                                    bio.clear(); bioEnabled = false
                                }
                            } else {
                                guard(
                                    securityEnableBiometricGuard,
                                    force = true,
                                ) {
                                    scope.launch {
                                        val dek = vm.currentDekForBiometric() ?: return@launch
                                        runCatching { bio.enroll(activity, dek) }
                                            .onSuccess {
                                                bioEnabled = true
                                                vm.postInfo(biometricEnabledMessage)
                                            }
                                            .onFailure { e ->
                                                when (e) {
                                                    is com.vault.security.BiometricVault.BiometricCancelled -> { /* 用户取消 */ }
                                                    is com.vault.security.BiometricVault.BiometricKeyInvalidated ->
                                                        vm.postError(biometricUnavailableMessage)
                                                    else -> vm.postError(biometricUnknownErrorMessage)
                                                }
                                            }
                                        dek.fill(0)
                                    }
                                }
                            }
                        },
                        style = if (bioEnabled) VaultActionStyle.NEUTRAL else VaultActionStyle.PRIMARY,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(if (bioEnabled) stringResource(R.string.settings_remaining_disable_biometric) else stringResource(R.string.settings_remaining_enable_biometric)) }
                }
                SettingsSubsectionTitle("自动填充")
                Text(
                    when (autofillState) {
                        AutofillSupportState.ENABLED -> stringResource(R.string.settings_remaining_autofill_enabled)
                        AutofillSupportState.DISABLED -> stringResource(R.string.settings_remaining_autofill_disabled)
                        AutofillSupportState.UNSUPPORTED -> stringResource(R.string.settings_remaining_autofill_unsupported)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                SettingsOutlinedButton(
                    onClick = {
                        autofillSettingsInProgress = true
                        vm.setExternalActionInProgress(true)
                        runCatching {
                            autofillSettingsLauncher.launch(AutofillSetup.requestEnableIntent(ctx))
                        }.onFailure {
                            autofillSettingsInProgress = false
                            vm.setExternalActionInProgress(false)
                            Toast.makeText(ctx, localizeUiTextFor(ctx, "无法打开自动填充设置，请在系统设置中搜索“自动填充”"), Toast.LENGTH_LONG).show()
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (autofillState == AutofillSupportState.ENABLED) uiText("管理自动填充") else uiText("启用自动填充"))
                }
                if (credentialProviderState != AutofillSupportState.UNSUPPORTED) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        when (credentialProviderState) {
                            AutofillSupportState.ENABLED -> uiText("通行密钥服务：已启用")
                            AutofillSupportState.DISABLED -> uiText("通行密钥服务：未启用")
                            else -> ""
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    SettingsOutlinedButton(
                        onClick = {
                            val launched = credentialProviderExternalActionGuard.launch {
                                credentialProviderLauncher.launch(AutofillSetup.credentialProviderIntent(ctx))
                            }
                            if (!launched) {
                                Toast.makeText(ctx, localizeUiTextFor(ctx, "无法打开通行密钥设置，请在系统设置中搜索“密码与帐号”"), Toast.LENGTH_LONG).show()
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (credentialProviderState == AutofillSupportState.ENABLED) stringResource(R.string.settings_remaining_manage_passkeys) else stringResource(R.string.settings_remaining_enable_passkeys))
                    }
                }
                SettingsSubsectionTitle(
                    uiText("自动填充排除"),
                    help = uiText("添加后，排除的应用或网站将不显示自动填充建议"),
                )
                val totalExcluded = excludedPackages.size + excludedHosts.size
                SettingsOutlinedButton(
                    onClick = { showExclusionEditor = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (totalExcluded == 0) uiText("管理排除项")
                        else uiText("已排除 $totalExcluded 项，点击管理"),
                    )
                }
                SettingsSubsectionTitle(
                    uiText("Passkey 默认存储模式"),
                    help = uiText("同步型 Passkey 在同步到新设备后即可使用；高安全性模式的私钥只存在于当前设备。"),
                )
                val passkeyModeLabel = when (passkeyCreationPreference) {
                    PasskeyCreationPreference.ASK_EVERY_TIME -> uiText("每次创建均确认")
                    PasskeyCreationPreference.SYNCABLE -> uiText("PMV 同步型（推荐）")
                    PasskeyCreationPreference.DEVICE_BOUND -> uiText("本设备高安全性")
                }
                Text(
                    when (passkeyCreationPreference) {
                        PasskeyCreationPreference.ASK_EVERY_TIME -> uiText("每次创建 Passkey 时选择同步型或本设备高安全性。")
                        PasskeyCreationPreference.SYNCABLE -> uiText("私钥随加密保险库同步，新设备打开同一数据库后可直接使用。")
                        PasskeyCreationPreference.DEVICE_BOUND -> uiText("Android Keystore 私钥不可导出；设备损坏或重置后无法恢复。")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                Box(Modifier.fillMaxWidth()) {
                    VaultActionButton(
                        onClick = { passkeyModeMenuExpanded = true },
                        style = VaultActionStyle.NEUTRAL,
                        modifier = Modifier
                            .fillMaxWidth()
                            .onSizeChanged { passkeyModeButtonWidthPx = it.width },
                    ) {
                        Box(Modifier.fillMaxWidth()) {
                            Text(passkeyModeLabel, modifier = Modifier.align(Alignment.Center), textAlign = TextAlign.Center)
                            Icon(
                                if (passkeyModeMenuExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = null,
                                modifier = Modifier.align(Alignment.CenterEnd),
                            )
                        }
                    }
                    com.vault.ui.VaultDropdownMenu(
                        expanded = passkeyModeMenuExpanded,
                        onDismissRequest = { passkeyModeMenuExpanded = false },
                        modifier = if (passkeyModeButtonWidthPx > 0) {
                            Modifier.width(passkeyModeButtonWidth)
                        } else {
                            Modifier
                        },
                        containerColor = popupMenuSurface(),
                    ) {
                        listOf(
                            PasskeyCreationPreference.ASK_EVERY_TIME to uiText("每次创建均确认"),
                            PasskeyCreationPreference.SYNCABLE to uiText("PMV 同步型（推荐）"),
                            PasskeyCreationPreference.DEVICE_BOUND to uiText("本设备高安全性"),
                        ).forEach { (preference, label) ->
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(label, fontWeight = if (preference == passkeyCreationPreference) FontWeight.SemiBold else FontWeight.Normal) },
                                onClick = {
                                    passkeyCreationPreference = preference
                                    passkeyModePref.creationPreference = preference
                                    passkeyModeMenuExpanded = false
                                },
                                trailingIcon = if (preference == passkeyCreationPreference) {
                                    { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                                } else null,
                            )
                        }
                    }
                }
                SettingsSubsectionTitle(uiText("后台界面隐藏"))
                BackgroundHideSection(ctx)
                val screenCaptureAllowed by com.vault.security.ScreenCapturePermission.allowed
                SettingsSubsectionTitle(
                    uiText("允许截屏"),
                    help = uiText(
                        if (!screenCaptureAllowed) "当前不允许系统截图、录屏和大多数投屏捕获。"
                        else "已允许系统截图和录屏；敏感内容可能被其他应用或旁观者保存。",
                    ),
                )
                ScreenCapturePermissionSection(ctx) { reason ->
                    guard(reason, force = true) {
                        showAllowScreenCaptureRisk = true
                    }
                }
                SettingsSubsectionTitle(
                    uiText("敏感内容二次保护"),
                    help = uiText("操作登录、WI-FI以外的条目时需要验证主密码"),
                )
                SensitiveGuardSection(ctx, embedded = true) { r, a -> guard(r, action = a) }
                SettingsSubsectionTitle(
                    uiText("图像模糊"),
                    help = uiText("所有图像显示均进行模糊处理，保护图像隐私。"),
                )
                PhotoBlurSection(ctx, embedded = true) { reason, action -> guard(reason, force = true, action = action) }
                SettingsSubsectionTitle("自动锁定")
                AutoLockSection(
                    ctx = ctx,
                    embedded = true,
                    onDisable = { guard("关闭自动锁定后，手动锁定前设备将保持解锁状态。如需保护，建议保持开启。") { IdleLockPref.setEnabled(ctx, false) } },
                )
                SettingsSubsectionTitle(
                    "剪贴板自动清理",
                    help = uiText("敏感内容复制后，到时间会自动清理剪贴板，避免久留泄露。"),
                )
                ClipboardTtlSection(ctx, embedded = true)
                SettingsSubsectionTitle(
                    "显示后自动隐藏",
                    help = uiText("密码、卡号等敏感内容点击显示后，到时间会自动重新隐藏。"),
                )
                AutoHideSection(ctx, embedded = true)
                    }
                    SettingsAccordion(
                        title = appearanceSettingsTitle,
                        expanded = settingsExpandedSection == "settings-appearance",
                        activeTitle = settingsExpandedSection,
                        onToggle = { toggleSettings("settings-appearance") },
                    ) {
                        AppearanceSection(ctx, embedded = true)
                    }
                    SettingsAccordion(
                        title = aboutSettingsTitle,
                        expanded = settingsExpandedSection == "settings-about",
                        activeTitle = settingsExpandedSection,
                        onToggle = { toggleSettings("settings-about") },
                    ) {
                        AboutSection(ctx, embedded = true)
                    }
                }
            }
        }

        // 赞助入口常驻于设置大卡之外，独立成项，不随「关于」手风琴折叠隐藏
        if (contentMode == SettingsContentMode.SETTINGS) item(contentType = "sponsor") {
            SettingsOutlinedButton(
                onClick = {
                    runCatching {
                        val uri = android.net.Uri.parse(sponsorSupportTarget())
                        ctx.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, uri))
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text(uiText("赞助支持")) }
        }

        // --- 导入与导出 ---
        if (contentMode == SettingsContentMode.TRANSFER) item(contentType = "transferPanels") {
            Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.fillMaxWidth()) {
                val importExportTitle = stringResource(R.string.settings_remaining_import_export)
                val lanTitle = stringResource(R.string.settings_remaining_lan)
                val localBackupTitle = uiText("本地备份")
                fun toggleTransfer(sectionId: String) {
                    transferExpandedSection = if (transferExpandedSection == sectionId) null else sectionId
                }
                SettingsAccordion(
                    title = importExportTitle,
                    expanded = transferExpandedSection == "transfer-import-export",
                    activeTitle = transferExpandedSection,
                    onToggle = { toggleTransfer("transfer-import-export") },
                ) {
                SettingsSubsectionTitle("导出", topPadding = 0.dp)
                SettingsOutlinedButton(onClick = {
                    vm.setExternalActionInProgress(true)
                    exportBakLauncher.launch("backup.pmbak")
                }) { Text(uiText("导出加密备份 .pmbak")) }
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                SettingsOutlinedButton(onClick = {
                    vm.setExternalActionInProgress(true)
                    exportRawLauncher.launch("${currentVault ?: "vault"}.pmv")
                }) { Text(uiText("导出原始 .pmv")) }
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                SettingsOutlinedButton(onClick = {
                    vm.setExternalActionInProgress(true)
                    exportArchiveLauncher.launch(
                        com.vault.storage.ArchiveExporter.suggestedFileName(currentVault ?: "vault"),
                    )
                }) { Text(uiText("导出压缩包")) }
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                SettingsSubsectionTitle("导入")
                // 导入：不要求验证主密码（备份文件本身有独立导出口令兜底）
                SettingsOutlinedButton(onClick = {
                    vm.setExternalActionInProgress(true)
                    importBakLauncher.launch(arrayOf("*/*"))
                }) { Text(uiText("导入加密备份并合并")) }
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                SettingsOutlinedButton(onClick = {
                    vm.setExternalActionInProgress(true)
                    importCsvLauncher.launch(arrayOf("text/csv", "text/comma-separated-values", "application/json", "*/*"))
                }) { Text(uiText("导入其他加密数据")) }
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                Text(
                    uiText("支持主流密码管理器、CSV、JSON 导入后合并"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                }

                // --- 本地备份 ---
                SettingsAccordion(
                    title = localBackupTitle,
                    expanded = transferExpandedSection == "transfer-local-backup",
                    activeTitle = transferExpandedSection,
                    onToggle = { toggleTransfer("transfer-local-backup") },
                ) {
                val localBackupEnabled by LocalBackupPref.enabled
                val localBackupInterval by LocalBackupPref.intervalMillis
                var intervalPreview by remember(localBackupInterval) {
                    mutableLongStateOf(localBackupInterval)
                }
                val backupTargetAvailable = !localBackupSnapshot.treeUri.isNullOrBlank()
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(uiText("启用本地备份"), style = MaterialTheme.typography.bodyMedium)
                        Text(
                            uiText("目录不可用或未连接时自动等待，不报错"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    VaultSwitch(
                        checked = localBackupEnabled,
                        onCheckedChange = { LocalBackupPref.setEnabled(ctx, currentVault ?: "", it) },
                        enabled = !localBackupRunning,
                    )
                }
                Spacer(Modifier.height(8.dp))
                SettingsOutlinedButton(
                    onClick = {
                        vm.setExternalActionInProgress(true)
                        localBackupDirLauncher.launch(null)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = localBackupEnabled && !localBackupRunning,
                ) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (!backupTargetAvailable) uiText("选择备份目录")
                        else uiText("更换备份目录"),
                    )
                }
                localBackupSnapshot.deviceLabel?.takeIf { it.isNotBlank() }?.let { device ->
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    Text(
                        device,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (localBackupEnabled) {
                    Text(
                        localBackupStatus,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (localBackupRunning) {
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        LinearProgressIndicator(
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    SettingsButton(
                        onClick = { vm.performLocalBackup(force = true) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = backupTargetAvailable && !localBackupRunning,
                        shape = VaultShape,
                    ) { Text(uiText("立即备份")) }
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    Text(
                        uiText("备份周期：${uiText(LocalBackupPolicy.label(intervalPreview))}"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    VaultSlider(
                        value = LocalBackupPolicy.indexOf(intervalPreview).toFloat(),
                        onValueChange = {
                            intervalPreview = LocalBackupPolicy.intervalAt(it.roundToInt())
                        },
                        onValueChangeFinished = {
                            LocalBackupPref.setInterval(ctx, currentVault ?: "", intervalPreview)
                        },
                        enabled = backupTargetAvailable && !localBackupRunning,
                        valueRange = 0f..(LocalBackupPolicy.INTERVALS.size - 1).toFloat(),
                        steps = LocalBackupPolicy.INTERVALS.size - 2,
                    )
                }
                }

                // --- 局域网（传输站 / 局域网同步 / 文件传输） ---
                SettingsAccordion(
                    title = lanTitle,
                    expanded = transferExpandedSection == "transfer-lan",
                    activeTitle = transferExpandedSection,
                    onToggle = { toggleTransfer("transfer-lan") },
                ) {
                LanModeSlider(
                    mode = lanUiMode,
                    // 同步/传输进行中也允许切档：早先按活动状态锁死滑块，用户被钉在
                    // 当前挡位，既看不了另一个通道、也没有就地中断的入口。改为可切，
                    // 由没在跑的那一挡自己说明「正在进行 X，不可进行其他操作」。
                    enabled = true,
                    onModeChange = { lanUiMode = it },
                )
                Spacer(Modifier.height(SettingsSpacing.withinItem))
                // HOST 也要如实传进去：它不属于任何通道，不能被「正在进行 X」覆盖掉。
                val currentChannel = when (lanUiMode) {
                    LanUiMode.TRANSFER -> LanGearChannels.TRANSFER
                    LanUiMode.SYNC -> LanGearChannels.SYNC
                    LanUiMode.HOST -> LanGearChannels.HOST
                }
                // 当前这一挡该显示什么，全部由 LanGearState 决定；composable 只负责按
                // 结果渲染，不再自己判条件——判据与渲染混在一起时，回归是测不出来的。
                val gear = resolveLanGearState(
                    mode = currentChannel,
                    hostRunning = lanHostState.running,
                    hostPaired = lanHostState.paired,
                    hostOp = lanHostState.op,
                    connectorSyncRunning = state.syncRunning,
                    connectorTransferActive = state.lanTransferActive,
                    connectorTransferConnecting = state.lanTransferConnecting,
                    connectorTransferDisconnected = state.lanTransferDisconnected,
                    transferViewExited = false,
                    hasSyncResult = lanSyncResult != null,
                )
                LaunchedEffect(gear.syncLive) {
                    if (gear.syncLive) syncViewOpen = true
                }
    // 另一个通道正在跑时的说明：只讲情况，不提供任何操作。
    @Composable
    fun LanChannelBusyNotice(busyChannel: String?) {
        // 没有通道在跑时什么都不显示。这条守卫是必须的：调用点若漏判，空闲状态下
        // 也会渲染出「当前正在进行…」，看起来像一直在同步。
        if (busyChannel == null) return
        // 另一个通道正在跑：只说明情况，不提供任何操作。
        // 不加这一段时，连接控件已被隐藏、传输面板又不显示，
        // 这一挡会整个空白，用户不知道发生了什么。
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                stringResource(
                    if (busyChannel == SyncServerHost.TRANSFER_OP) {
                        R.string.lan_channel_busy_transfer
                    } else {
                        R.string.lan_channel_busy_sync
                    },
                ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    // 连接控件：两挡 UI 完全相同，只有文案与动作不同，抽成本地 composable 复用。
    // local @Composable 可直接捕获外层的相机权限 launcher、扫码 launcher 与手动输入状态。
    @Composable
    fun LanConnectorControls(mode: Boolean, visible: Boolean) {
        // visible 是唯一判据，由 LanGearState.showConnectorControls() 给出。
        // 这里不再叠加任何本地条件——上次就是这里多判了几个标志，导致忙时仍出扫码入口。
        AnimatedVisibility(visible = visible) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                if (mode) {
                    stringResource(R.string.settings_remaining_scan_transfer_desc)
                } else {
                    stringResource(R.string.settings_remaining_scan_sync_desc)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SettingsOutlinedButton(
                onClick = {
                    if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                        pendingCameraAction = {
                            vm.setExternalActionInProgress(true)
                            IdleTracker.touch()
                            qrSyncLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_SYNC))
                        }
                        requestCameraPermission.launch(Manifest.permission.CAMERA)
                        return@SettingsOutlinedButton
                    }
                    vm.setExternalActionInProgress(true)
                    IdleTracker.touch()
                    qrSyncLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_SYNC))
                },
                enabled = !state.syncRunning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(
                    if (mode) stringResource(R.string.settings_remaining_scan_qr_transfer) else stringResource(R.string.settings_remaining_scan_qr_sync),
                )
            }
            SettingsOutlinedButton(
                onClick = { showManualLanInput = !showManualLanInput },
                modifier = Modifier.fillMaxWidth(),
                enabled = !state.syncRunning,
            ) {
                Icon(Icons.Filled.Sync, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(uiText("手动输入地址"))
            }
            if (showManualLanInput) {
                val manualInputRequester = remember { BringIntoViewRequester() }
                fun bringManualInputIntoView() {
                    scope.launch {
                        kotlinx.coroutines.delay(220)
                        manualInputRequester.bringIntoView()
                    }
                }
                OutlinedTextField(
                    value = manualLanUrl,
                    onValueChange = { manualLanUrl = it },
                    label = { Text(uiText("服务器地址")) },
                    placeholder = {
                        Text("https://192.168.1.100:18765/api/sync/vault?ticket=…&pin=…")
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                        .bringIntoViewRequester(manualInputRequester)
                        .onFocusChanged { if (it.isFocused) bringManualInputIntoView() },
                )
                SettingsButton(
                    onClick = {
                        val url = manualLanUrl.trimEnd('/')
                        // 传输站地址统一包含 PIN，手动输入只接受完整地址，不再单独输入 PIN
                        val pin = com.vault.storage.SyncClient.embeddedPin(url).orEmpty()
                        if (pin.length != 6) {
                            Toast.makeText(ctx, localizeUiTextFor(ctx, "地址未包含有效 PIN，请粘贴传输站的完整地址"), Toast.LENGTH_LONG).show()
                            return@SettingsButton
                        }
                        if (mode) vm.startLanDataTransfer(url, pin)
                        else vm.startSync(url, pin)
                    },
                    enabled = manualLanUrl.startsWith("https://") &&
                        com.vault.storage.SyncClient.embeddedPin(manualLanUrl.trimEnd('/')) != null &&
                        !state.syncRunning,
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        if (mode) stringResource(R.string.settings_remaining_start_transfer) else uiText("开始同步"),
                    )
                }
            }
        }
    }
    }

                when (lanUiMode) {
                    LanUiMode.HOST -> {                        // 建立传输站：只提供二维码、PIN、服务器地址
                        if (!lanHostState.running) {
                            Text(
                                uiText("开启后本机将在局域网开放连接，其他设备扫码或输入地址与 PIN 后，按对方的连接类型执行同步、文件互传或导出确认。"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.height(8.dp))
                        }
                        // 建立与关闭互斥：早先两个按钮同时渲染，开站后「建立传输站」
                        // 只是被禁用，「停止传输站」又出现在它下方，两个入口摆在一起
                        // 会让人以为还能再开一个站。
                        if (!lanHostState.running) {
                            SettingsOutlinedButton(
                                onClick = { showLanHostConfirm = true },
                                modifier = Modifier.fillMaxWidth(),
                                enabled = !state.syncRunning && !state.lanTransferActive,
                            ) {
                                Icon(Icons.Filled.Cast, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(uiText("建立传输站"))
                            }
                        }
                        if (lanHostState.running) {
                            Spacer(Modifier.height(8.dp))
                            LanHostActiveView(
                                status = lanHostState,
                                vm = vm,
                                onStop = { vm.stopLanHost() },
                            )
                        }
                        if (lanHostExportPending) {
                            VaultDialog(
                                onDismissRequest = { vm.rejectLanHostExport(lanHostExportApprovalToken) },
                                dismissOnOutsideClick = false,
                                properties = DialogProperties(decorFitsSystemWindows = false),
                                onClose = { vm.rejectLanHostExport(lanHostExportApprovalToken) },
                                title = { Text(stringResource(R.string.settings_remaining_allow_send_account_data)) },
                                text = {
                                    Column(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalArrangement = Arrangement.spacedBy(10.dp),
                                    ) {
                                        Text(
                                            stringResource(R.string.settings_remaining_send_account_data_desc),
                                            style = MaterialTheme.typography.bodyMedium,
                                        )
                                        Text(
                                            stringResource(R.string.settings_remaining_lan_device_id, lanHostExportPendingDevice),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                        Text(
                                            stringResource(R.string.settings_remaining_one_time_transfer_warning),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                        Column(
                                            modifier = Modifier.fillMaxWidth(),
                                            verticalArrangement = Arrangement.spacedBy(8.dp),
                                        ) {
                                            SettingsButton(
                                                onClick = { vm.approveLanHostExport(lanHostExportApprovalToken) },
                                                modifier = Modifier.fillMaxWidth(),
                                            ) { Text(uiText("允许本次发送")) }
                                            SettingsOutlinedButton(
                                                onClick = { vm.rejectLanHostExport(lanHostExportApprovalToken) },
                                                modifier = Modifier.fillMaxWidth(),
                                            ) { Text(uiText("不是我，断开")) }
                                        }
                                    }
                                },
                            )
                        }
                    }
                    LanUiMode.SYNC -> {
                        // 另一个通道在跑时只显示说明；同步内容与结果卡都属于本挡。
                        if (gear.showBusyNotice()) LanChannelBusyNotice(gear.busyChannel)
                        if (!gear.channelBusyElsewhere) {
                            if (gear.syncLive || lanSyncResult != null || syncViewOpen) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(uiText("局域网同步"), modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                                    // 固定位置的同一按钮：连接中断开，结束后关闭本页。
                                    SettingsOutlinedButton(
                                        // 同步进行中要二次确认：中断的是合并写回，
                                        // 可能停在半合并状态，代价比传输中断大。
                                        onClick = {
                                            if (gear.syncLive) {
                                                confirmSyncDisconnect = true
                                            } else {
                                                vm.dismissSyncResult()
                                                syncViewOpen = false
                                            }
                                        },
                                        centered = false,
                                    ) {
                                        Text(if (gear.syncLive) stringResource(R.string.lan_disconnect) else uiText("关闭页面"))
                                    }
                                }
                            }
                            // 只有真的在同步时才显示会话面板，否则每次进入这一挡
                            // 都会出现一个不确定态进度条和「断开连接」。
                            if (gear.showSyncPanel()) {
                                LanSyncSessionPanel(
                                    hostStatus = if (gear.showSyncPanel()) lanHostState else null,
                                    progress = lanSyncProgress,
                                )
                            }
                            // 结果与「已断开」互斥，判定交给 lanSyncViewMode：
                            // 只认 lanSyncResult 本身，不掺 channelBusyElsewhere，
                            // 免得 syncRunning 归零与 _syncResult 写入之间的重组窗口
                            // 让某一侧退化成「已关闭」。
                            val result = lanSyncResult
                            when (com.vault.ui.lanSyncViewMode(
                                syncLive = gear.syncLive,
                                hasSyncResult = result != null,
                                viewOpen = syncViewOpen,
                            )) {
                                com.vault.ui.LanSyncViewMode.RESULT ->
                                    if (result != null) {
                                        LanSyncResultStatus(result = result)
                                    }
                                com.vault.ui.LanSyncViewMode.DISCONNECTED ->
                                    Text(uiText("已断开连接"), style = MaterialTheme.typography.bodyMedium)
                                // 进行中：会话面板已经显示状态与进度，再补一句「已断开」是错的
                                com.vault.ui.LanSyncViewMode.LIVE,
                                com.vault.ui.LanSyncViewMode.IDLE -> Unit
                            }
                        }
                        LanConnectorControls(
                                mode = false,
                                visible = gear.showConnectorControls() && !syncViewOpen,
                            )
                    }

                    LanUiMode.TRANSFER -> {
                        // 本机作为传输站被「文件互传」通道连接时：进文件传输页的内嵌面板。
                        if (gear.showBusyNotice()) LanChannelBusyNotice(gear.busyChannel)

                        val hostSideLive = lanHostState.running && lanHostState.paired &&
                            lanHostState.op == SyncServerHost.TRANSFER_OP
                        val connectorLive = com.vault.ui.connectorTransferSessionLive(
                            state.lanTransferActive, state.lanTransferConnecting, state.lanTransferDisconnected,
                        )
                        val sessionLive = hostSideLive || connectorLive
                        val showPanel = !gear.channelBusyElsewhere && transferView.visible(sessionLive)
                        if (showPanel) {
                            LanTransferPanel(
                                vm = vm,
                                state = state,
                                host = if (sessionLive) hostSideLive else transferView.host,
                                sessionLive = sessionLive,
                                onDisconnect = {
                                    // 断开不等于新会话：角色与配对序号都保持现状，
                                    // 只让 sessionLive 归零。原先这里调 sessionStarted 会把
                                    // 尚未刷新的 hostSideLive 固化成角色，断线后视图就串了。
                                    if (hostSideLive) vm.disconnectLanHostPeer()
                                    else vm.endLanDataTransfer()
                                },
                                onExitTransfer = { transferView = transferView.close() },
                            )
                        }
                        LanConnectorControls(
                            mode = true,
                            visible = !gear.channelBusyElsewhere && !showPanel,
                        )
                    }
                }
                if (confirmSyncDisconnect) {
                    // 同步进行中断开要二次确认：中断的是合并写回，可能停在半合并状态。
                    VaultDialog(
                        onDismissRequest = { confirmSyncDisconnect = false },
                        dismissOnOutsideClick = false,
                        title = { Text(stringResource(R.string.lan_disconnect)) },
                        text = { Text(uiText("同步仍在进行，中断会放弃本次合并与回传，尚未完成的部分需要重新同步。确定要断开吗？")) },
                        confirmButton = {
                            VaultActionButton(onClick = { confirmSyncDisconnect = false }, style = VaultActionStyle.NEUTRAL) {
                                Text(uiText("取消"))
                            }
                        },
                        dismissButton = {
                            VaultActionButton(
                                onClick = {
                                    confirmSyncDisconnect = false
                                    syncViewOpen = true
                                    if (lanHostState.running && lanHostState.paired &&
                                        lanHostState.op == SyncServerHost.SYNC_OP
                                    ) vm.disconnectLanHostPeer() else vm.stopSync()
                                },
                                style = VaultActionStyle.DANGER,
                            ) { Text(stringResource(R.string.lan_disconnect)) }
                        },
                    )
                }
                if (lanHostSyncPending) {
                VaultDialog(
                    onDismissRequest = { vm.rejectLanHostSync(lanHostSyncApprovalToken) },
                    dismissOnOutsideClick = false,
                    properties = DialogProperties(decorFitsSystemWindows = false),
                    onClose = { vm.rejectLanHostSync(lanHostSyncApprovalToken) },
                    title = { Text(stringResource(R.string.settings_remaining_allow_device_sync)) },
                    text = {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Text(
                                stringResource(R.string.settings_remaining_device_sync_desc),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                stringResource(R.string.settings_remaining_lan_device_id, lanHostSyncPendingDevice),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                stringResource(R.string.settings_remaining_one_time_sync_warning),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                SettingsButton(
                                    onClick = { vm.approveLanHostSync(lanHostSyncApprovalToken) },
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text(uiText("允许本次同步")) }
                                SettingsOutlinedButton(
                                    onClick = { vm.rejectLanHostSync(lanHostSyncApprovalToken) },
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text(uiText("不是我，断开")) }
                            }
                        }
                     },
                )
                }
                if (lanHostTransferPending) {
                    VaultDialog(
                        onDismissRequest = { vm.rejectLanHostTransfer(lanHostTransferApprovalToken) },
                        dismissOnOutsideClick = false,
                        properties = DialogProperties(decorFitsSystemWindows = false),
                        onClose = { vm.rejectLanHostTransfer(lanHostTransferApprovalToken) },
                        title = { Text(stringResource(R.string.settings_remaining_allow_lan_transfer)) },
                        text = {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                verticalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                Text(stringResource(R.string.settings_remaining_allow_lan_transfer_desc))
                                Text(
                                    stringResource(R.string.settings_remaining_lan_device_id, lanHostTransferPendingDevice),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    stringResource(R.string.settings_remaining_lan_transfer_identity_note),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Column(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    SettingsButton(
                                        onClick = { vm.approveLanHostTransfer(lanHostTransferApprovalToken) },
                                        modifier = Modifier.fillMaxWidth(),
                                    ) { Text(stringResource(R.string.settings_remaining_allow_once)) }
                                    SettingsOutlinedButton(
                                        onClick = { vm.rejectLanHostTransfer(lanHostTransferApprovalToken) },
                                        modifier = Modifier.fillMaxWidth(),
                                    ) { Text(uiText("不是我，断开")) }
                                }
                            }
                        },
                    )
                }
                }

                // --- 云端同步 ---
                SettingsAccordion(
                    title = cloudSyncTitle,
                    expanded = transferExpandedSection == "transfer-cloud-sync",
                    activeTitle = transferExpandedSection,
                    onToggle = { toggleTransfer("transfer-cloud-sync") },
                ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(uiText("启用联网同步"), style = MaterialTheme.typography.bodyMedium)
                        Text(uiText("默认关闭，仅在主动操作时连接云端"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    VaultSwitch(
                        checked = cloudEnabled,
                        onCheckedChange = { enabled ->
                            if (enabled) {
                                guard("启用联网同步需要验证当前主密码。") {
                                    showCloudEnableAcknowledgement = true
                                }
                            } else {
                                cloudEnabled = false
                                cloudPrefs.edit().putBoolean(cloudKey("enabled"), false).apply()
                            }
                        },
                    )
                }
                if (cloudEnabled) {
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    HorizontalDivider()
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    CloudSyncStatusLine(vm)
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    CloudProviderSlider(
                        mode = cloudProviderMode,
                        // 数据检测/同步期间不禁止切换，用户可随时在云端硬盘与 WebDAV 之间切换查看。
                        enabled = true,
                        onModeChange = { cloudProviderMode = it },
                    )
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    // 与局域网同款切换逻辑：按当前模式条件渲染对应面板。
                    when (cloudProviderMode) {
                    "drive" -> {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                        Text(uiText("云端硬盘"), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
                        if (cloudDiskUri.isNotBlank() && cloudDiskStatus.isNotBlank()) {
                            CloudAssociationStatus(
                                success = cloudDiskStatus == "ok" || cloudDiskStatus == "changed",
                                text = if (cloudDiskStatus == "ok" || cloudDiskStatus == "changed") uiText("正常") else uiText("异常"),
                            )
                        }
                    }
                    Text(uiText("通过系统文件选择器关联云端文件；同步会先拉取合并，再上传并读回校验。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    cloudDiskPreview?.let { CloudSyncPreviewSummary(it) }
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    cloudAssociationProgress?.let { message ->
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        Text(
                            text = uiText(message),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                    }
                    if (cloudDiskUri.isBlank()) {
                        SettingsOutlinedButton(onClick = {
                            showCloudAssociationSource = true
                        }, enabled = cloudAssociationProgress == null && !state.cloudSyncRunning) {
                            Text(uiText(if (cloudAssociationProgress == null) "关联云端硬盘" else "正在关联…"))
                        }
                    } else {
                        SettingsOutlinedButton(onClick = {
                            cloudDiskPreview = VaultViewModel.CloudSyncPreview("checking", "云端硬盘", message = localizeUiTextFor(ctx, "正在检测远端数据…"))
                            vm.previewCloudVault(android.net.Uri.parse(cloudDiskUri), force = true) { cloudDiskPreview = it }
                        }, enabled = !state.cloudSyncRunning && !cloudSyncBusy) {
                            Icon(Icons.Default.Sync, null); Spacer(Modifier.width(6.dp)); Text(uiText("重新检测"))
                        }
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        VaultButton(
                            onClick = {
                                checkAssociatedCloudFile {
                                    vm.syncCloudVault(android.net.Uri.parse(cloudDiskUri)) { success ->
                                        if (success && cloudDiskTreeUri.isNotBlank()) {
                                            checkAssociatedCloudFile(updateBaseline = true) {
                                                vm.previewCloudVault(android.net.Uri.parse(cloudDiskUri), force = true) { cloudDiskPreview = it }
                                            }
                                        } else {
                                            cloudDiskStatus = if (success) "ok" else "failed"
                                            cloudPrefs.edit().putString(cloudKey("disk_status"), cloudDiskStatus).apply()
                                            if (success) vm.previewCloudVault(android.net.Uri.parse(cloudDiskUri), force = true) { cloudDiskPreview = it }
                                        }
                                    }
                                }
                            },
                            enabled = !state.cloudSyncRunning && !cloudSyncBusy,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(uiText("同步")) }
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        val cloudMoreExpanded = remember { mutableStateOf(false) }
                        Row(
                            modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable { cloudMoreExpanded.value = !cloudMoreExpanded.value },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(uiText("更多操作"), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            Icon(
                                imageVector = if (cloudMoreExpanded.value) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = if (cloudMoreExpanded.value) uiText("收起") else uiText("展开"),
                            )
                        }
                        AnimatedVisibility(
                            visible = cloudMoreExpanded.value,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                HorizontalDivider()
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    pendingCloudOverwrite = "云端硬盘" to {
                                        checkAssociatedCloudFile {
                                            vm.overwriteCloudVault(android.net.Uri.parse(cloudDiskUri)) { success ->
                                                if (success && cloudDiskTreeUri.isNotBlank()) checkAssociatedCloudFile(updateBaseline = true)
                                                else {
                                                    cloudDiskStatus = if (success) "ok" else "failed"
                                                    cloudPrefs.edit().putString(cloudKey("disk_status"), cloudDiskStatus).apply()
                                                }
                                                if (success) vm.previewCloudVault(android.net.Uri.parse(cloudDiskUri), force = true) { cloudDiskPreview = it }
                                            }
                                        }
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("上传覆盖云端")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    pendingDownloadOverwrite = PendingDownloadOverwrite("云端硬盘", action = {
                                        checkAssociatedCloudFile {
                                            vm.downloadOverwriteCloudVault(android.net.Uri.parse(cloudDiskUri)) { success ->
                                                cloudDiskStatus = if (success) "ok" else "failed"
                                                cloudPrefs.edit().putString(cloudKey("disk_status"), cloudDiskStatus).apply()
                                                if (success) vm.previewCloudVault(android.net.Uri.parse(cloudDiskUri), force = true) { cloudDiskPreview = it }
                                            }
                                        }
                                    })
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("下载覆盖本地")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    guard(localizeUiTextFor(ctx, "重新关联云端硬盘需要验证当前主密码。")) {
                                        showCloudAssociationSource = true
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("重新关联")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    guard(localizeUiTextFor(ctx, "取消云端硬盘关联需要验证当前主密码。")) {
                                        pendingAssociationCancel = "云端硬盘" to {
                                            releaseCloudAccess(cloudDiskUri, cloudDiskTreeUri)
                                            cloudDiskUri = ""
                                            cloudDiskTreeUri = ""
                                            cloudDiskStatus = ""
                                            cloudDiskSize = -1L
                                            cloudDiskModified = 0L
                                            cloudDiskLogicalRevision = ""
                                            cloudDiskPreview = null
                                            cloudPrefs.edit()
                                                .remove(cloudKey("uri"))
                                                .remove(cloudKey("tree_uri"))
                                                .remove(cloudKey("disk_status"))
                                                .remove(cloudKey("disk_size"))
                                                .remove(cloudKey("disk_modified"))
                                                .remove(cloudKey("disk_logical_revision"))
                                                .apply()
                                        }
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("取消关联")) }
                            }
                        }
                    }
                    }
                    "webdav" -> {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                        Text("WebDAV", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
                        if (webDavAssociated && webDavStatus.isNotBlank()) {
                            CloudAssociationStatus(
                                success = webDavStatus == "ok",
                                text = if (webDavStatus == "ok") uiText("正常") else uiText("异常"),
                            )
                        }
                    }
                    Text(uiText("适用于群晖、威联通、Nextcloud、ownCloud 及其他 WebDAV 服务。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    webDavPreview?.let { CloudSyncPreviewSummary(it) }
                    Spacer(Modifier.height(SettingsSpacing.withinItem))
                    if (!webDavAssociated) {
                        SettingsOutlinedButton(onClick = {
                            webDavLabel = "WebDAV"
                            showWebDavDialog = true
                        }, enabled = !state.cloudSyncRunning) { Text(uiText("关联 WebDAV")) }
                    } else {
                        SettingsOutlinedButton(onClick = {
                            webDavPreview = VaultViewModel.CloudSyncPreview("checking", "WebDAV", message = localizeUiTextFor(ctx, "正在检测远端数据…"))
                            vm.previewWebDav(force = true) { webDavPreview = it }
                        }, enabled = !state.cloudSyncRunning && !cloudSyncBusy) {
                            Icon(Icons.Default.Sync, null); Spacer(Modifier.width(6.dp)); Text(uiText("重新检测"))
                        }
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        VaultButton(
                            onClick = {
                                vm.syncWebDav { success ->
                                    if (success) vm.previewWebDav(force = true) { webDavPreview = it }
                                    webDavStatus = if (success) "ok" else "failed"
                                    cloudPrefs.edit().putString(cloudKey("webdav_status"), webDavStatus).apply()
                                }
                            },
                            enabled = !state.cloudSyncRunning && !cloudSyncBusy,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(uiText("同步")) }
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        val webdavMoreExpanded = remember { mutableStateOf(false) }
                        Row(
                            modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable { webdavMoreExpanded.value = !webdavMoreExpanded.value },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(uiText("更多操作"), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                            Icon(
                                imageVector = if (webdavMoreExpanded.value) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                contentDescription = if (webdavMoreExpanded.value) uiText("收起") else uiText("展开"),
                            )
                        }
                        AnimatedVisibility(
                            visible = webdavMoreExpanded.value,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                HorizontalDivider()
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    pendingCloudOverwrite = "WebDAV" to {
                                        vm.overwriteWebDav { success ->
                                            webDavStatus = if (success) "ok" else "failed"
                                            cloudPrefs.edit().putString(cloudKey("webdav_status"), webDavStatus).apply()
                                            if (success) {
                                                webDavPreview = VaultViewModel.CloudSyncPreview(
                                                    "same",
                                                    "WebDAV",
                                                    message = localizeUiTextFor(ctx, "上传覆盖完成，远端文件已通过读回校验"),
                                                )
                                            }
                                        }
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("上传覆盖云端")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    pendingDownloadOverwrite = PendingDownloadOverwrite("WebDAV", action = {
                                        vm.downloadOverwriteWebDav { success ->
                                            webDavStatus = if (success) "ok" else "failed"
                                            cloudPrefs.edit().putString(cloudKey("webdav_status"), webDavStatus).apply()
                                            if (success) {
                                                webDavPreview = VaultViewModel.CloudSyncPreview(
                                                    "same",
                                                    "WebDAV",
                                                    message = localizeUiTextFor(ctx, "下载覆盖完成，本地文件已通过写入校验"),
                                                )
                                            }
                                        }
                                    })
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("下载覆盖本地")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    guard(localizeUiTextFor(ctx, "重新关联 WebDAV 需要验证当前主密码。")) {
                                        showWebDavDialog = true
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("重新关联")) }
                                Spacer(Modifier.height(SettingsSpacing.withinItem))
                                SettingsOutlinedButton(onClick = {
                                    guard(localizeUiTextFor(ctx, "取消 WebDAV 关联需要验证当前主密码。")) {
                                        pendingAssociationCancel = "WebDAV" to {
                                            vm.clearCloudConfig()
                                            webDavAssociated = false
                                            webDavStatus = ""
                                            webDavPreview = null
                                            cloudMode = ""
                                            cloudProvider = ""
                                            cloudPrefs.edit().remove(cloudKey("mode")).remove(cloudKey("provider")).remove(cloudKey("webdav_status")).apply()
                                        }
                                    }
                                }, enabled = !state.cloudSyncRunning) { Text(uiText("取消关联")) }
                            }
                            }
                        }
                    }
                    }
                    // 目标名要自己先本地化：外层 uiText("...$autoTargetLabel...") 拿到的是
                    // 插值后的整串，表里没有这条，只会原样输出，于是英文界面里
                    // 会出现「自动同步周期 · 云端硬盘 · 每天」。
                    val autoTargetLabel = if (cloudProviderMode == "drive") uiText("云端硬盘") else "WebDAV"
                    val autoTargetAvailable = if (cloudProviderMode == "drive") cloudDiskUri.isNotBlank() else webDavAssociated
                    if (autoTargetAvailable) {
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        HorizontalDivider()
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        Column {
                            Text(uiText("自动云端同步"), style = MaterialTheme.typography.bodyMedium)
                            Text(uiText("仅在保险库解锁期间运行"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Spacer(Modifier.height(8.dp))
                        // 滑条最左端为「关闭」档（默认位置）：滑动到该档即停用自动同步；其余档位对应同步周期。
                        val intervalIndex = if (!autoSyncEnabled) 0 else (AutoCloudSyncPrefs.intervals.indexOf(autoSyncInterval).coerceAtLeast(0) + 1)
                        val intervalLabel = if (intervalIndex == 0) uiText("关闭") else uiText(AutoCloudSyncPrefs.labels[intervalIndex - 1])
                        Text(
                            uiText("自动同步周期 · $autoTargetLabel · $intervalLabel"),
                            style = MaterialTheme.typography.labelMedium,
                            color = if (autoSyncEnabled) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
                        )
                        VaultSlider(
                            value = intervalIndex.toFloat().coerceIn(0f, AutoCloudSyncPrefs.intervals.size.toFloat()),
                            onValueChange = { value ->
                                val index = value.roundToInt().coerceIn(0, AutoCloudSyncPrefs.intervals.size)
                                if (index == 0) {
                                    autoSyncEnabled = false
                                } else {
                                    autoSyncEnabled = true
                                    autoSyncInterval = AutoCloudSyncPrefs.intervals[index - 1]
                                }
                            },
                            onValueChangeFinished = { saveAutoSyncSettings() },
                            valueRange = 0f..(AutoCloudSyncPrefs.intervals.size.toFloat()),
                            steps = AutoCloudSyncPrefs.intervals.size - 1,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        val nextRun = if (autoSyncEnabled && autoNextRunBase > 0L) {
                            java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.getDefault())
                                .format(java.util.Date(autoNextRunBase + autoSyncInterval * 60_000L))
                        } else null
                        val localizedNextRun = nextRun?.let { uiText("下次预计：$it") }
                        if (localizedNextRun != null) Text(
                            localizedNextRun,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (autoSyncStatus.isNotBlank()) Text(
                            uiText("状态：$autoSyncStatus"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (autoSyncFailures > 0) Text(
                            uiText("连续失败：$autoSyncFailures 次"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                }
                }
            }
        }

        }
    }

if (showLanHostConfirm) {
    VaultDialog(
        onDismissRequest = { showLanHostConfirm = false },
        title = stringResource(R.string.settings_remaining_start_transfer_station),
        text = stringResource(R.string.settings_remaining_start_transfer_station_desc),
        confirmText = stringResource(R.string.settings_remaining_enable),
        onConfirm = {
            showLanHostConfirm = false
            vm.startLanHost()
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
        onDismiss = { showLanHostConfirm = false },
    )
}

scannedLanUrl?.let { serverUrl ->
    LanSyncPinDialog(
        submitting = scannedLanPinSubmitting,
        attempts = scannedLanPinAttempts,
        errorMessage = scannedLanPinError,
        onCancel = { if (!scannedLanPinSubmitting) scannedLanUrl = null },
        onPinComplete = { pin ->
            if (lanUiMode == LanUiMode.TRANSFER) {
                scannedLanPinSubmitting = true
                scannedLanPinError = ""
                vm.startLanDataTransfer(serverUrl, pin) { result: LanTransferConnectResult ->
                    scannedLanPinSubmitting = false
                    when {
                        result.connected -> scannedLanUrl = null
                        result.pinRejected && result.remainingPinAttempts == 0 -> {
                            scannedLanUrl = null
                            Toast.makeText(ctx, localizeUiTextFor(ctx, result.message), Toast.LENGTH_LONG).show()
                        }
                        else -> {
                            if (result.pinRejected) scannedLanPinAttempts += 1
                            scannedLanPinError = result.message
                        }
                    }
                }
            } else {
                scannedLanUrl = null
                vm.startSync(serverUrl, pin)
            }
        },
    )
}

if (showWebDavDialog) {
    var authMenuExpanded by remember { mutableStateOf(false) }
    var authButtonWidthPx by remember { mutableIntStateOf(0) }
    var webDavConnectSubmitting by remember { mutableStateOf(false) }
    val webDavFormLocked = state.cloudSyncRunning || webDavConnectSubmitting
    val authButtonWidth = with(androidx.compose.ui.platform.LocalDensity.current) { authButtonWidthPx.toDp() }
    val authOptions = listOf(
        "basic" to "Basic",
        "digest" to "Digest",
        "bearer" to "Bearer Token",
        "oauth2" to stringResource(R.string.settings_remaining_oauth_access_token),
        "mtls" to stringResource(R.string.settings_remaining_client_certificate_mtls),
        "cookie" to "Cookie / Session",
        "none" to stringResource(R.string.settings_remaining_no_authentication),
    )
    val authLabel = authOptions.firstOrNull { it.first == webDavAuthMode }?.second ?: "Basic"
    val collapseAuthText = stringResource(R.string.settings_remaining_collapse_authentication)
    val chooseAuthText = stringResource(R.string.settings_remaining_choose_authentication)
    VaultDialog(
        onDismissRequest = { if (!webDavFormLocked) showWebDavDialog = false },
        title = { Text(uiText("连接 WebDAV")) },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 500.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(uiText("填写 WebDAV 文件夹地址，程序会在其中使用当前账户对应的加密保险库文件。"), style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    value = webDavUrl,
                    onValueChange = { webDavUrl = it },
                    enabled = !webDavFormLocked,
                    label = { Text(uiText("WebDAV 文件夹地址")) },
                    placeholder = { Text("https://server.example/dav/vault") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Box(modifier = Modifier.fillMaxWidth()) {
                    VaultActionButton(
                        onClick = { authMenuExpanded = true },
                        enabled = !webDavFormLocked,
                        style = VaultActionStyle.NEUTRAL,
                        modifier = Modifier.fillMaxWidth().height(52.dp).onSizeChanged { authButtonWidthPx = it.width },
                    ) {
                        Text(uiText("认证方式：$authLabel"), modifier = Modifier.weight(1f), textAlign = TextAlign.Start)
                        Icon(
                            if (authMenuExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                            contentDescription = if (authMenuExpanded) collapseAuthText else chooseAuthText,
                        )
                    }
                    com.vault.ui.VaultDropdownMenu(
                        expanded = authMenuExpanded && !webDavFormLocked,
                        onDismissRequest = { authMenuExpanded = false },
                        modifier = if (authButtonWidthPx > 0) Modifier.width(authButtonWidth) else Modifier,
                        containerColor = popupMenuSurface(),
                    ) {
                        authOptions.forEach { (mode, label) ->
                            androidx.compose.material3.DropdownMenuItem(
                                text = { Text(label, fontWeight = if (mode == webDavAuthMode) FontWeight.SemiBold else FontWeight.Normal) },
                                enabled = !webDavFormLocked,
                                onClick = {
                                    webDavAuthMode = mode
                                    authMenuExpanded = false
                                },
                                trailingIcon = if (mode == webDavAuthMode) {
                                    { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                                } else null,
                            )
                        }
                    }
                }
                if (webDavAuthMode == "basic" || webDavAuthMode == "digest") {
                    OutlinedTextField(
                        value = webDavUsername,
                        onValueChange = { webDavUsername = it },
                        enabled = !webDavFormLocked,
                        label = { Text(uiText("用户名")) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = webDavPassword,
                        onValueChange = { webDavPassword = it },
                        enabled = !webDavFormLocked,
                        label = { Text(uiText("密码或应用专用密码")) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else if (webDavAuthMode == "bearer" || webDavAuthMode == "oauth2") {
                    OutlinedTextField(
                        value = webDavBearerToken,
                        onValueChange = { webDavBearerToken = it },
                        enabled = !webDavFormLocked,
                        label = { Text(stringResource(R.string.settings_remaining_bearer_token)) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else if (webDavAuthMode == "cookie") {
                    OutlinedTextField(
                        value = webDavCookie,
                        onValueChange = { webDavCookie = it.take(8192) },
                        enabled = !webDavFormLocked,
                        label = { Text(stringResource(R.string.settings_remaining_cookie_session)) },
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else if (webDavAuthMode == "mtls") {
                    VaultActionButton(
                        onClick = {
                            vm.setExternalActionInProgress(true)
                            clientCertificateLauncher.launch(arrayOf("application/x-pkcs12", "application/octet-stream"))
                        },
                        enabled = !webDavFormLocked,
                        style = VaultActionStyle.NEUTRAL,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(if (webDavClientCertificate.isBlank()) stringResource(R.string.settings_remaining_select_client_certificate) else stringResource(R.string.settings_remaining_reselect_client_certificate)) }
                    OutlinedTextField(
                        value = webDavClientCertificatePassword,
                        onValueChange = { webDavClientCertificatePassword = it },
                        enabled = !webDavFormLocked,
                        label = { Text(uiText("客户端证书密码")) },
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else if (webDavAuthMode == "ntlm") {
                    OutlinedTextField(
                        value = webDavDomain,
                        onValueChange = { webDavDomain = it },
                        enabled = !webDavFormLocked,
                        label = { Text(uiText("Windows 域")) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(uiText("Android 不提供通用的 Windows 域凭据接口，此模式会在验证时明确拒绝。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                } else if (webDavAuthMode == "kerberos") {
                    Text(uiText("Android 不提供系统 Kerberos 票据接口，此模式会在验证时明确拒绝。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                OutlinedTextField(
                    value = webDavCertificate,
                    onValueChange = {
                        webDavCertificate = it.filter { ch -> ch in '0'..'9' || ch in 'a'..'f' || ch in 'A'..'F' }
                            .lowercase()
                            .take(64)
                    },
                    enabled = !webDavFormLocked,
                    label = { Text(uiText("自签名证书 SHA-256 指纹")) },
                    supportingText = { Text("${webDavCertificate.length}/64") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(uiText("自动创建远端目录"), modifier = Modifier.weight(1f))
                    VaultSwitch(
                        checked = webDavCreateDirectories,
                        onCheckedChange = { webDavCreateDirectories = it },
                        enabled = !webDavFormLocked,
                    )
                }
                if (webDavFormLocked) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Text(
                        uiText("正在验证 WebDAV 连接，请稍候…"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                Text(uiText("配置按当前保险库隔离，并由 Android Keystore 加密。自签名证书必须填写准确指纹。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = {
            VaultActionButton(
                onClick = connect@{
                    authMenuExpanded = false
                    val directoryConfig = WebDavConfig(
                        webDavLabel,
                        webDavUrl.trim(),
                        webDavUsername,
                        webDavPassword,
                        webDavAuthMode,
                        webDavBearerToken,
                        webDavCertificate,
                        webDavCreateDirectories,
                        webDavCookie,
                        webDavClientCertificate,
                        webDavClientCertificatePassword,
                        webDavDomain,
                    )
                    val config = runCatching {
                        WebDavCloud.configForDirectory(
                            directoryConfig,
                            vm.cloudVaultFileName(currentVault ?: "vault"),
                        )
                    }.getOrElse { error ->
                        val isAddressError = error.message.orEmpty().any { it == '\u5730' || it == '\u5740' }
                        vm.postError(if (isAddressError) webDavInvalidUrlMessage else webDavConfigInvalidMessage)
                        return@connect
                    }
                    webDavConnectSubmitting = true
                    vm.testWebDav(config) { success, hasData ->
                        webDavConnectSubmitting = false
                        if (success) {
                            showWebDavDialog = false
                            if (hasData) {
                                pendingWebDavAssociation = config
                            } else {
                                vm.overwriteWebDav(config) { uploaded ->
                                    finishWebDavAssociation(config, uploaded)
                                }
                            }
                        }
                    }
                },
                style = VaultActionStyle.PRIMARY,
                enabled = webDavUrl.isNotBlank() && !webDavFormLocked,
            ) { Text(if (webDavFormLocked) stringResource(R.string.settings_remaining_verifying) else stringResource(R.string.settings_remaining_verify_and_connect)) }
        },
        dismissButton = { VaultActionButton(onClick = { showWebDavDialog = false }, enabled = !webDavFormLocked, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}

// 敏感动作主密码门禁
pendingGuarded?.let { (reason, action) ->
    MasterPasswordDialog(
        reason = reason,
        verify = vm::verifySessionPassword,
        coolingRemainingMs = { com.vault.security.LockoutPref.coolingRemainingMs(ctx) },
        onCancel = { pendingGuarded = null },
        onSuccess = {
            pendingGuarded = null
            vm.elevateSecuritySession()
            action()
        },
    )
}

pendingCloudOverwrite?.let { (target, action) ->
    VaultDialog(
        onDismissRequest = { pendingCloudOverwrite = null },
        title = stringResource(R.string.settings_remaining_confirm_upload_overwrite),
        text = stringResource(R.string.settings_remaining_upload_overwrite_desc, target),
        confirmText = stringResource(R.string.settings_remaining_continue_overwrite),
        onConfirm = {
            pendingCloudOverwrite = null
            action()
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
    )
}

if (showAllowScreenCaptureRisk) {
    VaultDialog(
        onDismissRequest = { showAllowScreenCaptureRisk = false },
        title = uiText("允许截屏？"),
        text = uiText("开启后，保险库内容可能出现在截图、录屏、投屏画面和最近任务预览中。恶意应用或他人也可能保存敏感信息。仅在确有需要且环境可信时开启。"),
        confirmText = uiText("我已了解风险，仍要允许"),
        confirmStyle = VaultActionStyle.DANGER,
        onConfirm = {
            showAllowScreenCaptureRisk = false
            com.vault.security.ScreenCapturePermission.setAllowed(ctx, true)
            WindowSecurity.applyTo(ctx as? android.app.Activity)
        },
        dismissText = uiText("保持禁止"),
    )
}

pendingDownloadOverwrite?.let { pending ->
    VaultDialog(
        onDismissRequest = { pendingDownloadOverwrite = null },
        title = { Text(if (pending.step == 1) stringResource(R.string.settings_remaining_confirm_download_overwrite) else stringResource(R.string.settings_remaining_confirm_local_data_risk)) },
        text = {
            Text(
                if (pending.step == 1)
                    stringResource(R.string.settings_remaining_download_overwrite_desc, pending.target)
                else
                    stringResource(R.string.settings_remaining_local_data_risk_desc),
            )
        },
        confirmButton = {
            VaultActionButton(onClick = {
                if (pending.step == 1) {
                    pendingDownloadOverwrite = pending.copy(step = 2)
                } else {
                    pendingDownloadOverwrite = null
                    pending.action()
                }
            }, style = VaultActionStyle.PRIMARY) { Text(if (pending.step == 1) stringResource(R.string.settings_remaining_continue) else stringResource(R.string.settings_remaining_confirm_local_overwrite)) }
        },
        dismissButton = { VaultActionButton(onClick = { pendingDownloadOverwrite = null }, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}

if (showCloudEnableAcknowledgement) {
    VaultDialog(
        onDismissRequest = { showCloudEnableAcknowledgement = false },
        title = stringResource(R.string.settings_remaining_confirm_enable_cloud_sync),
        text = stringResource(R.string.settings_remaining_enable_cloud_sync_desc),
        confirmText = stringResource(R.string.settings_remaining_acknowledge_enable),
        onConfirm = {
            showCloudEnableAcknowledgement = false
            cloudEnabled = true
            cloudPrefs.edit().putBoolean(cloudKey("enabled"), true).apply()
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
    )
}

pendingAssociationCancel?.let { (target, action) ->
    VaultDialog(
        onDismissRequest = { pendingAssociationCancel = null },
        title = stringResource(R.string.settings_remaining_confirm_unlink),
        text = stringResource(R.string.settings_remaining_unlink_desc, target),
        confirmText = stringResource(R.string.settings_remaining_unlink),
        onConfirm = {
            pendingAssociationCancel = null
            action()
        },
        dismissText = stringResource(R.string.settings_remaining_back),
    )
}

if (showCloudAssociationSource) {
    VaultDialog(
        onDismissRequest = { showCloudAssociationSource = false },
        title = { Text(if (cloudDiskUri.isBlank()) uiText("关联云端硬盘") else uiText("重新关联云端硬盘")) },
        text = { Text(uiText("选择云端目录后，程序会自动查找保险库文件。直接选择已有文件时，将继续请求其所在目录权限，以便检测远端文件被删除、替换或出现同名冲突。")) },
        confirmButton = {
            Column(modifier = Modifier.fillMaxWidth()) {
                VaultActionButton(
                    onClick = {
                        showCloudAssociationSource = false
                        vm.setExternalActionInProgress(true)
                        cloudTreeLauncher.launch(null)
                    },
                    style = VaultActionStyle.PRIMARY,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("选择云端目录")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        showCloudAssociationSource = false
                        vm.setExternalActionInProgress(true)
                        cloudOpenLauncher.launch(arrayOf("*/*"))
                    },
                    style = VaultActionStyle.NEUTRAL,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("选择已有文件")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = { showCloudAssociationSource = false },
                    style = VaultActionStyle.NEUTRAL,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("取消")) }
            }
        },
    )
}

pendingFileOnlyCloudUri?.let { fileValue ->
    VaultDialog(
        onDismissRequest = {
            pendingFileOnlyCloudUri = null
            if (fileValue != cloudDiskUri) releaseCloudAccess(fileValue)
        },
        title = stringResource(R.string.settings_remaining_cloud_directory_permission_missing),
        text = stringResource(R.string.settings_remaining_cloud_file_only_desc),
        confirmText = stringResource(R.string.settings_remaining_link_file_only),
        onConfirm = {
            pendingFileOnlyCloudUri = null
            handleCloudSelection(android.net.Uri.parse(fileValue))
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
        onDismiss = {
            pendingFileOnlyCloudUri = null
            if (fileValue != cloudDiskUri) releaseCloudAccess(fileValue)
        },
    )
}

pendingCloudCreation?.let { pending ->
    VaultDialog(
        onDismissRequest = {
            pendingCloudCreation = null
            if (pending.treeUri != cloudDiskTreeUri) releaseCloudAccess("", pending.treeUri)
        },
        title = stringResource(R.string.settings_remaining_create_cloud_vault_file),
        text = stringResource(R.string.settings_remaining_create_cloud_vault_desc, pending.displayName),
        confirmText = stringResource(R.string.settings_remaining_confirm_create),
        onConfirm = {
            pendingCloudCreation = null
            val tree = android.net.Uri.parse(pending.treeUri)
            cloudAssociationProgress = "正在创建云端保险库文件…"
            vm.createCloudFile(tree, pending.displayName) { fileUri ->
                if (fileUri != null) handleCloudSelection(fileUri, pending.treeUri)
                else {
                    cloudAssociationProgress = null
                    if (pending.treeUri != cloudDiskTreeUri) releaseCloudAccess("", pending.treeUri)
                }
            }
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
        onDismiss = {
            pendingCloudCreation = null
            if (pending.treeUri != cloudDiskTreeUri) releaseCloudAccess("", pending.treeUri)
        },
    )
}

pendingCloudAssociation?.let { candidate ->
    VaultDialog(
        onDismissRequest = {
            pendingCloudAssociation = null
            finishCloudAssociation(candidate, false)
        },
        title = { Text(uiText("云端已有保险库数据")) },
        text = { Text(uiText("请选择先拉取并合并双方数据，或上传覆盖远端，亦或下载远端文件覆盖本地。")) },
        confirmButton = {
            Column(modifier = Modifier.fillMaxWidth()) {
                VaultActionButton(
                    onClick = {
                        pendingCloudAssociation = null
                        cloudAssociationProgress = "正在同步并关联云端保险库…"
                        vm.syncCloudVault(android.net.Uri.parse(candidate.newFileUri), allowDifferentVault = true) { success ->
                            finishCloudAssociation(candidate, success)
                        }
                    },
                    style = VaultActionStyle.PRIMARY,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("同步合并")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        pendingCloudAssociation = null
                        cloudAssociationProgress = "正在上传并关联云端保险库…"
                        vm.overwriteCloudVault(android.net.Uri.parse(candidate.newFileUri)) { success ->
                            finishCloudAssociation(candidate, success)
                        }
                    },
                    style = VaultActionStyle.DANGER,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("上传覆盖云端")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        pendingCloudAssociation = null
                        cloudAssociationProgress = "正在下载并关联云端保险库…"
                        vm.downloadOverwriteCloudVault(android.net.Uri.parse(candidate.newFileUri)) { success ->
                            finishCloudAssociation(candidate, success)
                        }
                    },
                    style = VaultActionStyle.DANGER,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("下载覆盖本地")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        pendingCloudAssociation = null
                        finishCloudAssociation(candidate, false)
                    },
                    style = VaultActionStyle.NEUTRAL,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("取消")) }
            }
        },
    )
}

pendingWebDavAssociation?.let { config ->
    VaultDialog(
        onDismissRequest = { pendingWebDavAssociation = null },
        title = { Text(uiText("WebDAV 已有保险库数据")) },
        text = { Text(uiText("请选择先拉取并合并双方数据，或上传覆盖远端，亦或下载远端文件覆盖本地。")) },
        confirmButton = {
            Column(modifier = Modifier.fillMaxWidth()) {
                VaultActionButton(
                    onClick = {
                        pendingWebDavAssociation = null
                        vm.syncWebDav(config, allowDifferentVault = true) { success -> finishWebDavAssociation(config, success) }
                    },
                    style = VaultActionStyle.PRIMARY,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("同步合并")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        pendingWebDavAssociation = null
                        vm.overwriteWebDav(config) { success -> finishWebDavAssociation(config, success) }
                    },
                    style = VaultActionStyle.DANGER,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("上传覆盖云端")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = {
                        pendingWebDavAssociation = null
                        vm.downloadOverwriteWebDav(config) { success -> finishWebDavAssociation(config, success) }
                    },
                    style = VaultActionStyle.DANGER,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("下载覆盖本地")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(
                    onClick = { pendingWebDavAssociation = null },
                    style = VaultActionStyle.NEUTRAL,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(uiText("取消")) }
            }
        },
    )
}

recoveryRegenerationDraft?.let { draft ->
    // 弹窗期间暂停无操作自动锁定；关闭时恢复，锁定/重进后草稿仍在，可继续流程。
    LaunchedEffect(Unit) { vm.setExternalActionInProgress(true) }
    DisposableEffect(Unit) { onDispose { vm.setExternalActionInProgress(false) } }
    RecoveryKeyConfirmDialog(
        title = stringResource(R.string.settings_remaining_regenerate_recovery_key),
        message = stringResource(R.string.settings_remaining_regenerate_recovery_key_desc),
        keyVersion = (state.payload?.syncMeta?.keyRevision ?: 0) + 1,
        accountName = currentVault.orEmpty(),
        draft = draft,
        onCancel = { vm.dismissRecoveryRegeneration() },
        onConfirmed = { secret ->
            vm.regenerateRecoveryKey(activity, secret) { success ->
                if (success) vm.dismissRecoveryRegeneration()
            }
        },
    )
}

if (showChangePw) ChangePasswordDialog(
    keyVersion = (state.payload?.syncMeta?.keyRevision ?: 0) + 1,
    accountName = currentVault.orEmpty(),
    onCancel = { showChangePw = false },
    onConfirm = { pw, weakConfirmed, recovery ->
        vm.changePassword(pw, recovery, weakPasswordConfirmed = weakConfirmed) { success ->
            if (success) {
                showChangePw = false
                bioEnabled = false
            }
        }
    },
)

// 国产 ROM 永久拒绝引导弹窗：跳转系统设置页手动授权
if (showPermissionSettings) {
    VaultDialog(
        onDismissRequest = { showPermissionSettings = false },
        title = { Text(uiText("需要相机权限")) },
        text = { Text(uiText("相机权限已被永久拒绝，请前往系统设置手动授予相机权限。")) },
        confirmButton = {
            VaultActionButton(
                onClick = {
                    showPermissionSettings = false
                    try {
                        val intent = android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = android.net.Uri.fromParts("package", ctx.packageName, null)
                        }
                        ctx.startActivity(intent)
                    } catch (_: Exception) {
                        Toast.makeText(ctx, localizeUiTextFor(ctx, "无法打开系统设置，请手动前往设置 → 应用管理 → 本应用 → 权限"), Toast.LENGTH_LONG).show()
                    }
                },
                style = VaultActionStyle.PRIMARY,
            ) { Text(uiText("前往设置")) }
        },
        dismissButton = {
            VaultActionButton(onClick = { showPermissionSettings = false }, style = VaultActionStyle.NEUTRAL) {
                Text(uiText("取消"))
            }
        },
    )
}

pendingExportBakUri?.let { uri ->
    ExportBackupDialog(
        requireStrongPassphrase = vm.backupContainsSyncablePasskeys(),
        onCancel = { pendingExportBakUri = null },
        onConfirm = { pw ->
            guard("导出加密备份需要验证当前主密码。", force = true) {
                pendingExportBakUri = null
                vm.authorizeSensitiveExport("backup", uri)
                vm.exportBackup(uri, pw)
            }
        },
    )
}
pendingExportArchiveUri?.let { uri ->
    ExportBackupDialog(
        onCancel = { pendingExportArchiveUri = null },
        onConfirm = { pw ->
            guard("导出压缩包需要验证当前主密码。", force = true) {
                pendingExportArchiveUri = null
                vm.authorizeSensitiveExport("archive", uri)
                vm.exportArchive(uri, pw)
            }
        },
    )
}
pendingImportBakUri?.let { uri ->
    ImportBackupDialog(
        onCancel = { pendingImportBakUri = null },
        onNext = { pw ->
            pendingImportBakUri = null
            // Sync v2：LWW 合并不再需要用户选冲突策略，按时间戳自动取胜
            vm.importBackup(activity, uri, pw)
        },
    )
}

// 谱系不匹配：备份或局域网同步来自其它账户库 / 缺失谱系信息 → 二次确认
val pendingCross by vm.pendingCrossAccountImport.collectAsStateWithLifecycle()
if (contentMode == SettingsContentMode.TRANSFER && isActive) pendingCross?.let { p ->
    CrossAccountMergeWarningDialog(
        sourceLabel = p.sourceLabel,
        incomingDeviceId = p.incomingDeviceId,
        incomingCount = p.incomingEntries.count { it.deletedAt == null },
        onCancel = { vm.cancelCrossAccountImport() },
        onConfirm = { vm.confirmCrossAccountImport() },
    )
}

pendingImportCsvUri?.let { uri ->
    ImportPolicyDialog(
        onCancel = { pendingImportCsvUri = null },
        onPick = { action ->
            pendingImportCsvUri = null
            vm.importPasswordManager(uri) { _, _ -> action }
        },
    )
}

renameTarget?.let { old ->
    RenameAccountDialog(
        oldName = old,
        onCancel = { renameTarget = null },
        onConfirm = { newName -> renameTarget = null; vm.renameVault(old, newName) },
    )
}
deleteTarget?.let { name ->
    VaultDialog(
        onDismissRequest = { deleteTarget = null },
        title = stringResource(R.string.settings_remaining_delete_account),
        text = stringResource(R.string.settings_remaining_delete_account_desc, name),
        confirmText = stringResource(R.string.settings_remaining_delete),
        confirmStyle = VaultActionStyle.DANGER,
        onConfirm = {
            val target = name
            deleteTarget = null
            // 设置页只允许操作当前账户，必须先通过当前主密码二次验证
            guard("删除「$target」是软删除，但仍需再次验证当前主密码。", force = true) { vm.deleteVault(target) }
        },
        dismissText = stringResource(R.string.settings_remaining_cancel),
    )
}
}
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AutofillExclusionEditor(
    ctx: android.content.Context,
    excludedPackages: Set<String>,
    excludedHosts: Set<String>,
    onUpdate: () -> Unit,
    onBack: () -> Unit,
) {
    var newText by remember { mutableStateOf("") }
    var showAppPicker by remember { mutableStateOf(false) }
    fun applyChange(change: () -> Unit): Boolean = runCatching {
        change()
        onUpdate()
    }.onFailure {
        Toast.makeText(ctx, localizeUiTextFor(ctx, "保存失败：${it.message ?: "未知错误"}"), Toast.LENGTH_LONG).show()
    }.isSuccess

    VaultDialog(
        onDismissRequest = onBack,
        dismissOnOutsideClick = false,
        onClose = onBack,
        title = { Text(uiText("自动填充排除")) },
        text = {
            Column(Modifier.fillMaxWidth()) {
                Text(
                    uiText("添加后，排除的应用或网站将不显示自动填充建议"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp),
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    OutlinedTextField(
                        value = newText,
                        onValueChange = { newText = it.take(200) },
                        placeholder = { Text(uiText("应用包名/网址")) },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        shape = VaultShape,
                    )
                    Spacer(Modifier.width(8.dp))
                    VaultButton(
                        onClick = {
                            val input = newText.trim().lowercase()
                            if (input.isEmpty()) return@VaultButton
                            // Domains with several labels (e.g. login.example.com) are
                            // not package names. Installed applications are unambiguous.
                            val isPackage = runCatching { ctx.packageManager.getApplicationInfo(input, 0) }.isSuccess
                            if (!isPackage && com.vault.autofill.normalizeExcludedHost(input) == null) return@VaultButton
                            if (applyChange {
                                if (isPackage) AutofillExcludePref.addPackage(ctx, input)
                                else AutofillExcludePref.addHost(ctx, input)
                            }) newText = ""
                        },
                        shape = VaultShape,
                    ) { Text(uiText("添加")) }
                }

                Spacer(Modifier.height(8.dp))

                OutlinedButton(
                    onClick = { showAppPicker = true },
                    modifier = Modifier.fillMaxWidth(),
                    shape = VaultShape,
                ) {
                    Icon(
                        Icons.Filled.Apps,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(uiText("选择应用"))
                }

                Spacer(Modifier.height(12.dp))

                val allExcluded = buildList {
                    excludedPackages.sorted().forEach { add("app" to it) }
                    excludedHosts.sorted().forEach { add("web" to it) }
                }

                if (allExcluded.isEmpty()) {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            uiText("暂未排除任何应用或网站"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.outline,
                        )
                    }
                } else {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .heightIn(min = 320.dp, max = 320.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        allExcluded.forEach { (kind, value) ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                            ) {
                                Surface(
                                    shape = VaultShape,
                                    color = if (kind == "app") MaterialTheme.colorScheme.primaryContainer
                                    else MaterialTheme.colorScheme.tertiaryContainer,
                                ) {
                                    Text(
                                        if (kind == "app") "App" else "Web",
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (kind == "app") MaterialTheme.colorScheme.onPrimaryContainer
                                        else MaterialTheme.colorScheme.onTertiaryContainer,
                                    )
                                }
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    value,
                                    modifier = Modifier.weight(1f),
                                    style = MaterialTheme.typography.bodySmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                IconButton(
                                    onClick = {
                                        applyChange {
                                            if (kind == "app") AutofillExcludePref.removePackage(ctx, value)
                                            else AutofillExcludePref.removeHost(ctx, value)
                                        }
                                    },
                                    modifier = Modifier.size(32.dp),
                                ) {
                                    Icon(
                                        Icons.Filled.Delete,
                                        contentDescription = uiText("移除"),
                                        modifier = Modifier.size(16.dp),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            VaultActionButton(onClick = onBack, style = VaultActionStyle.PRIMARY) { Text(uiText("完成")) }
        },
    )

    if (showAppPicker) {
        AppPickerSheet(
            onDismiss = { showAppPicker = false },
            onAppSelected = { label, packageName ->
                if (applyChange { AutofillExcludePref.addPackage(ctx, packageName) }) showAppPicker = false
            },
        )
    }
}

@Composable
private fun AutoLockSection(ctx: android.content.Context, embedded: Boolean = false, onDisable: () -> Unit) {
    val lockEnabled by IdleLockPref.enabled
    val lockSeconds by IdleLockPref.seconds
    var sliderIndex by remember(lockEnabled, lockSeconds) {
        mutableIntStateOf(if (lockEnabled) IdleLockPref.indexForSeconds(lockSeconds) else 0)
    }
    SettingsCard(title = stringResource(R.string.settings_remaining_auto_lock), embedded = embedded) {
        Text(
            uiText("无操作超时后自动锁定"),
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        val previewSeconds = IdleLockPref.secondsForIndex(sliderIndex)
        val label = uiText(if (previewSeconds < 60) "$previewSeconds 秒"
            else if (previewSeconds % 60 == 0) "${previewSeconds / 60} 分钟"
            else "${previewSeconds / 60} 分 ${previewSeconds % 60} 秒")
        Text(
            if (sliderIndex == 0) uiText("自动锁定已关闭，手动锁定前设备将保持解锁状态")
            else uiText("空闲 $label 后锁定"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        VaultSlider(
            value = sliderIndex.toFloat(),
            onValueChange = {
                sliderIndex = it.roundToInt().coerceIn(0, IdleLockPref.PRESET_SECONDS.lastIndex)
            },
            onValueChangeFinished = {
                val idx = sliderIndex.coerceIn(0, IdleLockPref.PRESET_SECONDS.lastIndex)
                if (idx == 0) {
                    if (lockEnabled) onDisable()
                    sliderIndex = if (lockEnabled) IdleLockPref.indexForSeconds(lockSeconds) else 0
                } else {
                    IdleLockPref.setEnabled(ctx, true)
                    IdleLockPref.setSeconds(ctx, IdleLockPref.secondsForIndex(idx))
                }
            },
            valueRange = 0f..(IdleLockPref.PRESET_SECONDS.size - 1).toFloat(),
            steps = IdleLockPref.PRESET_SECONDS.size - 2,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun TrashRetentionSection(ctx: android.content.Context, embedded: Boolean = false) {
    val days by TrashRetentionPref.days
    var sliderDays by remember(days) { mutableIntStateOf(days) }
    SettingsCard(
        title = stringResource(R.string.settings_remaining_trash_auto_cleanup),
        embedded = embedded,
    ) {
        val label =
            if (sliderDays >= 365) uiText("${sliderDays / 365} 年")
            else if (sliderDays >= 30 && sliderDays % 30 == 0) uiText("${sliderDays / 30} 个月")
            else if (sliderDays in 7..29 && sliderDays % 7 == 0) uiText("${sliderDays / 7} 周")
            else uiText("$sliderDays 天")
        Text(
            uiText("超过 $label 的条目将被自动彻底删除"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        VaultSlider(
            value = TrashRetentionPref.indexForDays(sliderDays).toFloat(),
            onValueChange = { sliderDays = TrashRetentionPref.daysForIndex(it.roundToInt()) },
            onValueChangeFinished = { TrashRetentionPref.setDays(ctx, sliderDays) },
            valueRange = 0f..(TrashRetentionPref.PRESET_DAYS.size - 1).toFloat(),
            steps = TrashRetentionPref.PRESET_DAYS.size - 2,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun LeakCheckIntervalSection(
    ctx: android.content.Context,
    state: com.vault.ui.UiState,
    onManualCheck: () -> Unit,
) {
    val days by com.vault.security.LeakCheckIntervalPref.days
    var sliderDays by remember(days) { mutableIntStateOf(days) }
    val checkEnabled by com.vault.security.LeakCheckEnabledPref.enabled
    val onlineEnabled by com.vault.security.LeakOnlineCheckPref.enabled
    Column {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.weight(1f)) {
                Text(uiText("启用密码检测"), style = MaterialTheme.typography.bodyMedium)
                Text(uiText("关闭后不再检测、标记或置顶泄露条目。"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            VaultSwitch(
                checked = checkEnabled,
                onCheckedChange = { com.vault.security.LeakCheckEnabledPref.setEnabled(ctx, it) },
            )
        }

        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.weight(1f)) {
                Text(uiText("联网检测密码泄露"), style = MaterialTheme.typography.bodyMedium)
                Text(uiText("使用密码哈希前5位查询"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            VaultSwitch(
                checked = onlineEnabled,
                enabled = checkEnabled,
                onCheckedChange = { com.vault.security.LeakOnlineCheckPref.setEnabled(ctx, it) },
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(uiText("自动检测周期"), style = MaterialTheme.typography.bodyMedium)
        val label = uiText(if (sliderDays == 0) "关闭"
            else if (sliderDays >= 30 && sliderDays % 30 == 0) "每 ${sliderDays / 30} 个月"
            else if (sliderDays in 7..29 && sliderDays % 7 == 0) "每 ${sliderDays / 7} 周"
            else "每 $sliderDays 天")
        Text(
            if (sliderDays == 0) "自动检测已关闭"
            else "超过 $label 后重新检测",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val stepsCount = com.vault.security.LeakCheckIntervalPref.MAX_DAYS -
            com.vault.security.LeakCheckIntervalPref.MIN_DAYS - 1
        VaultSlider(
            value = sliderDays.toFloat(),
            onValueChange = { sliderDays = it.roundToInt() },
            onValueChangeFinished = {
                com.vault.security.LeakCheckIntervalPref.setDays(ctx, sliderDays)
            },
            enabled = checkEnabled,
            valueRange = com.vault.security.LeakCheckIntervalPref.MIN_DAYS.toFloat()..
                com.vault.security.LeakCheckIntervalPref.MAX_DAYS.toFloat(),
            steps = stepsCount,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(SettingsSpacing.betweenItems))
        VaultActionButton(
            onClick = onManualCheck,
            enabled = checkEnabled && !state.leakCheckRunning,
            style = VaultActionStyle.PRIMARY,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (state.leakCheckRunning) stringResource(R.string.settings_remaining_checking) else stringResource(R.string.settings_remaining_check_now))
        }
        if (state.leakCheckRunning || state.leakCheckTotal > 0) {
            Spacer(Modifier.height(8.dp))
            val progress = if (state.leakCheckTotal > 0) {
                state.leakCheckChecked.toFloat() / state.leakCheckTotal.toFloat()
            } else {
                0f
            }
            Text(
                if (state.leakCheckRunning) {
                    "正在检测 ${state.leakCheckChecked}/${state.leakCheckTotal}"
                } else {
                    "检测完成 ${state.leakCheckTotal}/${state.leakCheckTotal}"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun SecurityCenterScreen(
    vm: com.vault.ui.VaultViewModel,
    onOpenFilter: (String) -> Unit,
    scrollToTopSignal: Int = 0,
    animationSignal: Int = 0,
) {
    val ctx = LocalContext.current
    val state by vm.state.collectAsStateWithLifecycle()
    val securityReport by vm.securityReport.collectAsStateWithLifecycle()
    val localScanRunning by vm.securityScanRunning.collectAsStateWithLifecycle()
    val localScanProgress by vm.securityScanProgress.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    var lastScrollSignal by remember { mutableIntStateOf(scrollToTopSignal) }
    var collapseSignal by remember { mutableIntStateOf(0) }
    LaunchedEffect(scrollToTopSignal) {
        if (scrollToTopSignal > lastScrollSignal) {
            collapseSignal++
            listState.animateScrollToItem(0)
        }
        lastScrollSignal = scrollToTopSignal
    }
    val scanRunning = localScanRunning || state.leakCheckRunning
    val scanProgress = if (localScanRunning) {
        localScanProgress
    } else if (state.leakCheckTotal > 0) {
        state.leakCheckChecked.toFloat() / state.leakCheckTotal
    } else 0f
    val darkTheme = MaterialTheme.colorScheme.background.luminance() < 0.5f
    LazyColumn(
        state = listState,
        modifier = Modifier.vaultBackdropSource().fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 0.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Spacer(Modifier.height(8.dp)) }
        item {
            PageHeaderCard(
                title = stringResource(R.string.settings_remaining_password_security),
                subtitle = if (scanRunning) stringResource(R.string.settings_remaining_scanning_password_risk) else stringResource(R.string.settings_remaining_password_security_desc),
                icon = Icons.Filled.HealthAndSafety,
                accent = com.vault.ui.SuccessColors.headerAccent(darkTheme),
                containerColor = com.vault.ui.SuccessColors.headerContainer(darkTheme),
                contentColor = com.vault.ui.SuccessColors.headerContent(darkTheme),
            )
        }
        item {
            // 检测设置是“操作入口”（立即检测/扫描进度），放在大圆环上方：
            // 预留折叠卡片高度，展开内容越界覆盖概览而不推动后续列表项。
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .zIndex(1f),
            ) {
                Box(Modifier.wrapContentHeight(unbounded = true, align = Alignment.Top)) {
                    SettingsCard(
                        title = stringResource(R.string.settings_remaining_detection_settings),
                        collapseSignal = collapseSignal,
                        contentExpandFrom = Alignment.Top,
                    ) {
                        LeakCheckIntervalSection(ctx = ctx, state = state, onManualCheck = vm::runManualLeakCheck)
                    }
                }
            }
        }
        item {
            SecurityOverviewDonut(
                report = securityReport,
                scanning = scanRunning,
                scanProgress = scanProgress,
                animationSignal = animationSignal,
                onSelect = onOpenFilter,
            )
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(uiText("高风险检测"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                PasswordFinding.entries.filter(PasswordFinding::highRisk).chunked(2).forEach { rowItems ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        rowItems.forEach { finding ->
                            PasswordRiskDonut(
                                finding = finding,
                                count = securityReport.findings[finding].orEmpty().size,
                                total = securityReport.total,
                                color = MaterialTheme.colorScheme.error,
                                animationSignal = animationSignal,
                                modifier = Modifier.weight(1f),
                            ) { onOpenFilter(finding.key) }
                        }
                        if (rowItems.size == 1) Spacer(Modifier.weight(1f))
                    }
                }
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(uiText("建议改进"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                PasswordFinding.entries.filterNot(PasswordFinding::highRisk).chunked(2).forEach { rowItems ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        rowItems.forEach { finding ->
                            PasswordRiskDonut(
                                finding = finding,
                                count = securityReport.findings[finding].orEmpty().size,
                                total = securityReport.total,
                                color = MaterialTheme.colorScheme.primary,
                                animationSignal = animationSignal,
                                modifier = Modifier.weight(1f),
                            ) { onOpenFilter(finding.key) }
                        }
                        if (rowItems.size == 1) Spacer(Modifier.weight(1f))
                    }
                }
            }
        }
        if (securityReport.highRisk.isEmpty() && securityReport.improvement.isEmpty() && !scanRunning) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                ) {
                    Icon(
                        painterResource(R.drawable.ic_nav_security),
                        contentDescription = null,
                        tint = com.vault.ui.SuccessColors.Indicator,
                        modifier = Modifier.size(22.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(uiText("未发现问题"), color = com.vault.ui.SuccessColors.Label, fontWeight = FontWeight.SemiBold)
                }
            }
        }

        item { Spacer(Modifier.height(16.dp)) }
    }
}

@Composable
private fun SecurityOverviewDonut(
    report: PasswordHealthReport,
    scanning: Boolean,
    scanProgress: Float,
    animationSignal: Int,
    onSelect: (String) -> Unit,
) {
    val total = report.total.coerceAtLeast(1)
    val high by animateFloatAsState(report.highRisk.size.toFloat() / total, label = "security-high")
    val improvement by animateFloatAsState(report.improvement.size.toFloat() / total, label = "security-improvement")
    val healthy by animateFloatAsState(report.healthy.size.toFloat() / total, label = "security-healthy")
    val animatedProgress by animateFloatAsState(scanProgress.coerceIn(0f, 1f), label = "security-scan-progress")
    val reveal = remember { Animatable(1f) }
    var pressedSegment by remember { mutableStateOf<String?>(null) }
    val highExpansion by animateFloatAsState(
        targetValue = if (pressedSegment == "high") 1f else 0f,
        animationSpec = spring(dampingRatio = 0.58f, stiffness = 620f),
        label = "security-high-expansion",
    )
    val improvementExpansion by animateFloatAsState(
        targetValue = if (pressedSegment == "improvement") 1f else 0f,
        animationSpec = spring(dampingRatio = 0.58f, stiffness = 620f),
        label = "security-improvement-expansion",
    )
    val healthyExpansion by animateFloatAsState(
        targetValue = if (pressedSegment == "healthy") 1f else 0f,
        animationSpec = spring(dampingRatio = 0.58f, stiffness = 620f),
        label = "security-healthy-expansion",
    )
    LaunchedEffect(animationSignal) {
        reveal.snapTo(0f)
        reveal.animateTo(1f, animationSpec = tween(650, easing = FastOutSlowInEasing))
    }
    val rotation = if (scanning) {
        val transition = androidx.compose.animation.core.rememberInfiniteTransition(label = "security-scan")
        val animatedRotation by transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = androidx.compose.animation.core.infiniteRepeatable(
                animation = androidx.compose.animation.core.tween(1050, easing = androidx.compose.animation.core.LinearEasing),
            ),
            label = "security-scan-rotation",
        )
        animatedRotation
    } else {
        0f
    }
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(196.dp)
                    .pointerInput(high, improvement, healthy) {
                        fun segmentAt(offset: Offset): String? {
                            val center = size.width / 2f
                            val dx = offset.x - center
                            val dy = offset.y - center
                            val radius = kotlin.math.sqrt(dx * dx + dy * dy)
                            if (radius < size.width * 0.34f || radius > size.width * 0.51f) return null
                            val fraction = ((Math.toDegrees(atan2(dy.toDouble(), dx.toDouble())) + 90.0 + 360.0) % 360.0 / 360.0).toFloat()
                            return when {
                                fraction < high -> "high"
                                fraction < high + improvement -> "improvement"
                                else -> "healthy"
                            }
                        }
                        detectTapGestures(
                            onPress = { offset ->
                                val segment = segmentAt(offset)
                                pressedSegment = segment
                                if (segment != null) {
                                    try {
                                        tryAwaitRelease()
                                    } finally {
                                        pressedSegment = null
                                    }
                                }
                            },
                            onLongPress = { /* 长按仅保留分区外扩反馈。 */ },
                            onTap = { offset -> segmentAt(offset)?.let(onSelect) },
                        )
                    },
            ) {
                val track = MaterialTheme.colorScheme.outlineVariant
                val highColor = MaterialTheme.colorScheme.error
                val improvementColor = MaterialTheme.colorScheme.tertiary
                val healthyColor = com.vault.ui.SuccessColors.Indicator
                val scanColor = MaterialTheme.colorScheme.primary
                Canvas(Modifier.fillMaxSize()) {
                    val baseInset = 16.dp.toPx()
                    val baseStroke = 14.dp.toPx()
                    fun drawSegment(color: Color, start: Float, sweep: Float, expansion: Float) {
                        val expanded = expansion.coerceIn(-0.12f, 1.08f)
                        val inset = baseInset - 6.dp.toPx() * expanded
                        val strokeWidth = baseStroke + 4.dp.toPx() * expanded
                        drawArc(
                            color = color,
                            startAngle = start,
                            sweepAngle = sweep,
                            useCenter = false,
                            topLeft = Offset(inset, inset),
                            size = Size(size.width - inset * 2f, size.height - inset * 2f),
                            style = Stroke(width = strokeWidth, cap = StrokeCap.Butt),
                        )
                    }
                    drawArc(
                        color = track,
                        startAngle = -90f,
                        sweepAngle = 360f,
                        useCenter = false,
                        topLeft = Offset(baseInset, baseInset),
                        size = Size(size.width - baseInset * 2f, size.height - baseInset * 2f),
                        style = Stroke(width = baseStroke, cap = StrokeCap.Butt),
                    )
                    var start = -90f
                    if (high > 0f) {
                        drawSegment(highColor, start, high * 360f * reveal.value, highExpansion)
                        start += high * 360f * reveal.value
                    }
                    if (improvement > 0f) {
                        drawSegment(improvementColor, start, improvement * 360f * reveal.value, improvementExpansion)
                        start += improvement * 360f * reveal.value
                    }
                    if (healthy > 0f) drawSegment(healthyColor, start, healthy * 360f * reveal.value, healthyExpansion)
                    if (scanning) {
                        val ringSize = Size(size.width - baseInset * 2f, size.height - baseInset * 2f)
                        val ringOffset = Offset(baseInset, baseInset)
                        drawArc(
                            scanColor.copy(alpha = 0.28f),
                            -90f,
                            animatedProgress * 360f,
                            false,
                            topLeft = ringOffset,
                            size = ringSize,
                            style = Stroke(8.dp.toPx(), cap = StrokeCap.Round),
                        )
                        drawArc(
                            scanColor,
                            rotation - 90f,
                            68f,
                            false,
                            topLeft = ringOffset,
                            size = ringSize,
                            style = Stroke(4.dp.toPx(), cap = StrokeCap.Round),
                        )
                    }
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        if (scanning) "${(animatedProgress * 100).toInt()}%"
                        else if (report.total > 0) "${(report.healthy.size * 100 / report.total)}%" else "--",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        uiText(if (scanning) "正在扫描" else "密码安全性"),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (!scanning) Text(
                        uiText("${report.healthy.size} 个未发现问题"),
                        style = MaterialTheme.typography.labelSmall,
                        color = com.vault.ui.SuccessColors.Label,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                SecurityLegend("高风险", report.highRisk.size, MaterialTheme.colorScheme.error) { onSelect("high") }
                SecurityLegend("需改进", report.improvement.size, MaterialTheme.colorScheme.tertiary) { onSelect("improvement") }
                SecurityLegend("安全", report.healthy.size, com.vault.ui.SuccessColors.Indicator) { onSelect("healthy") }
            }
            Spacer(Modifier.height(6.dp))
            Text(uiText("共检测 ${report.total} 个含密码条目"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (scanning) {
                Spacer(Modifier.height(8.dp))
                @Suppress("DEPRECATION")
                androidx.compose.material3.LinearProgressIndicator(
                    progress = animatedProgress,
                    modifier = Modifier.fillMaxWidth().height(4.dp),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                )
            }
        }
        }
    }

@Composable
private fun SecurityLegend(label: String, count: Int, color: Color, onClick: () -> Unit) {
    Row(
        modifier = Modifier.clickable(onClick = onClick).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Box(Modifier.size(8.dp).background(color, CircleShape))
        Text("${uiText(label)} $count", style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun PasswordRiskDonut(
    finding: PasswordFinding,
    count: Int,
    total: Int,
    color: Color,
    animationSignal: Int,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val fraction = if (total > 0) count.toFloat() / total else 0f
    val animatedFraction = remember { Animatable(0f) }
    LaunchedEffect(fraction, animationSignal) {
        animatedFraction.snapTo(0f)
        animatedFraction.animateTo(
            fraction.coerceIn(0f, 1f),
            animationSpec = tween(600, easing = FastOutSlowInEasing),
        )
    }
    Surface(
        onClick = onClick,
        modifier = modifier,
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(64.dp)) {
                val trackColor = MaterialTheme.colorScheme.outlineVariant
                Canvas(Modifier.fillMaxSize()) {
                    val strokeWidth = 7.dp.toPx()
                    val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    val inset = strokeWidth / 2f
                    val arcSize = Size(size.width - strokeWidth, size.height - strokeWidth)
                    drawArc(trackColor, -90f, 360f, false, topLeft = Offset(inset, inset), size = arcSize, style = stroke)
                    if (animatedFraction.value > 0f) {
                        drawArc(color, -90f, 360f * animatedFraction.value, false, topLeft = Offset(inset, inset), size = arcSize, style = stroke)
                    }
                }
                Text(count.toString(), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(8.dp))
            Text(uiText(finding.label), style = MaterialTheme.typography.labelMedium, maxLines = 1)
        }
    }
}

@Composable
private fun ImprovementDonutRow(
    finding: PasswordFinding,
    count: Int,
    total: Int,
    animationSignal: Int,
    onClick: () -> Unit,
) {
    val fraction = if (total > 0) count.toFloat() / total else 0f
    val animated = remember { Animatable(0f) }
    LaunchedEffect(fraction, animationSignal) {
        animated.snapTo(0f)
        animated.animateTo(
            fraction.coerceIn(0f, 1f),
            animationSpec = tween(600, easing = FastOutSlowInEasing),
        )
    }
    Row(
        modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable(onClick = onClick).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(50.dp).padding(2.dp)) {
            val color = MaterialTheme.colorScheme.tertiary
            val track = MaterialTheme.colorScheme.outlineVariant
            val background = MaterialTheme.colorScheme.background
            Canvas(Modifier.fillMaxSize()) {
                val radius = minOf(size.width, size.height) / 2f
                val center = Offset(size.width / 2f, size.height / 2f)
                val arcSize = Size(radius * 2f, radius * 2f)
                val arcTopLeft = Offset(center.x - radius, center.y - radius)
                drawCircle(track, radius, center)
                if (animated.value > 0f) {
                    drawArc(
                        color = color,
                        startAngle = -90f,
                        sweepAngle = animated.value * 360f,
                        useCenter = true,
                        topLeft = arcTopLeft,
                        size = arcSize,
                    )
                }
                // 中心抠小圆、露出背景色，形成一圈浅环形边距，但空隙控制在小比例、不过大。
                drawCircle(background, radius * 0.26f, center)
            }
        }
        Spacer(Modifier.width(12.dp))
        Text(uiText(finding.label), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text("$count / $total", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SecurityRiskRow(entry: Entry, issues: List<PasswordFinding>, onClick: () -> Unit) {
    val tint = categoryIconBackground(entry.secretType)
    Row(
        modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable(onClick = onClick).padding(vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier.size(42.dp).clip(CircleShape).background(tint.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(painterResource(categoryIconRes(entry.secretType)), null, tint = tint, modifier = Modifier.size(24.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(entry.title.ifBlank { stringResource(R.string.settings_remaining_untitled_entry) }, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(5.dp),
            ) {
                issues.forEach { finding ->
                    Text(
                        uiText(finding.label),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (finding.highRisk) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.background(
                            (if (finding.highRisk) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary).copy(alpha = 0.10f),
                            VaultShape,
                        ).padding(horizontal = 5.dp, vertical = 2.dp),
                    )
                }
            }
        }
    }
}

private fun formatEpoch(epoch: Double): String = java.text.SimpleDateFormat(
    "yyyy-MM-dd HH:mm",
    java.util.Locale.getDefault(),
).format(java.util.Date((epoch * 1000).toLong()))

@Composable
private fun AboutSection(ctx: android.content.Context, embedded: Boolean = false) {
    // 更新状态与下载作业都在进程级协调器里：这一节会被折叠、滚出视口、切页、旋转销毁，
    // 放在这里 remember 的话下载会被取消、已发现的更新也会无声消失。
    val update by com.vault.updates.UpdateCoordinator.state.collectAsState()
    val version = com.vault.BuildConfig.VERSION_NAME
    val email = "2123696066@qq.com"
    val emailCopiedText = uiText("邮箱已复制")
    val upToDateText = uiText("当前已是最新版本")
    val needPermissionText = uiText("需要允许安装未知应用后才能安装更新")
    val installStartedText = uiText("已开始安装，完成后请重新打开保险库")
    val busyUpdate = update.busy

    val installPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        com.vault.updates.UpdateCoordinator.onInstallPermissionResult(
            ctx,
            ctx.packageManager.canRequestPackageInstalls(),
        )
    }

    SettingsCard(title = stringResource(R.string.settings_remaining_about), embedded = embedded) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(uiText("保险库  v$version"), style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(2.dp))
                Text(
                    uiText("开发者：FAE"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                uiText("联系：$email"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            SettingsOutlinedButton(
                onClick = {
                    val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("email", email))
                    android.widget.Toast.makeText(ctx, emailCopiedText, android.widget.Toast.LENGTH_SHORT).show()
                },
                centered = false,
            ) { Text(uiText("复制")) }
        }
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SettingsOutlinedButton(
                onClick = {
                    openOfficialSite(ctx, "#privacy")
                },
                modifier = Modifier.weight(1f),
                centered = false,
            ) { Text(stringResource(R.string.settings_remaining_privacy_policy)) }
            SettingsOutlinedButton(
                onClick = {
                    openOfficialSite(ctx, "#changelog")
                },
                modifier = Modifier.weight(1f),
                centered = false,
            ) { Text(stringResource(R.string.settings_remaining_changelog)) }
        }
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        SettingsOutlinedButton(
            // 闸门在协调器内部按状态对象判定，这里不再重复判 checkingUpdate。
            onClick = { com.vault.updates.UpdateCoordinator.check(ctx, version) },
            enabled = !update.checking,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(uiText(if (update.checking) "正在检查…" else "检查更新")) }
    }

    // 「已是最新」只在结论刚落地时提示一次：写在组合体里会每次重组都弹一次 Toast，
    // 而 dismiss() 是状态写入，在组合期间调用也不安全。
    LaunchedEffect(update.upToDate) {
        if (update.upToDate) {
            Toast.makeText(ctx, upToDateText, Toast.LENGTH_SHORT).show()
            com.vault.updates.UpdateCoordinator.dismiss()
        }
    }

    update.info?.let { info ->
        VaultDialog(
            onDismissRequest = { if (!busyUpdate) com.vault.updates.UpdateCoordinator.dismiss() },
            onClose = { if (!busyUpdate) com.vault.updates.UpdateCoordinator.dismiss() },
            title = { Text(uiText("发现新版本") + " v${info.version}") },
            text = {
                // 各状态替换内容，进度与文案在同一个纵向容器内重新测量。
                Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (!busyUpdate && !update.needsInstallPermission && update.failure == null) {
                    // AlertDialog 的 text 槽没有滚动（Box + weight(1f, fill = false)），
                    // 更新说明一长就把卡片撑到接近满屏，而且超出部分不可达；这里给它
                    // 一个有上限的可滚动容器。MarkdownText 根是普通 Column，不会形成
                    // 同轴嵌套的 lazy 容器，所以可以安全地套一层纵向滚动。
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .heightIn(max = 320.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        com.vault.ui.MarkdownText(raw = info.notes.ifBlank { stringResource(R.string.settings_remaining_no_update_notes) })
                        if (info.sha256 == null) Text(
                            uiText("此版本未提供下载文件的 SHA-256 校验值；安装前仍会校验 APK 签名与当前应用一致。"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                when {
                    update.needsInstallPermission -> {
                        Spacer(Modifier.height(10.dp))
                        Text(
                            needPermissionText,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    busyUpdate -> {
                        Spacer(Modifier.height(12.dp))
                        val received = update.received
                        val total = update.total
                        if (update.verifying || update.installing || total <= 0L) {
                            @Suppress("DEPRECATION")
                            LinearProgressIndicator(
                                modifier = Modifier.fillMaxWidth().height(4.dp),
                                color = MaterialTheme.colorScheme.primary,
                                trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                            )
                        } else {
                            @Suppress("DEPRECATION")
                            LinearProgressIndicator(
                                progress = (received.toFloat() / total).coerceIn(0f, 1f),
                                modifier = Modifier.fillMaxWidth().height(4.dp),
                                color = MaterialTheme.colorScheme.primary,
                                trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            when {
                                update.verifying -> uiText("正在校验安装包…")
                                update.installing -> uiText("正在准备安装…")
                                total > 0L -> uiText("正在下载更新…") + " ${received / 1048576} / ${total / 1048576} MB"
                                else -> uiText("正在下载更新…")
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    update.failure != null -> {
                        Spacer(Modifier.height(10.dp))
                        Text(
                            updateFailureText(update),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                }
            },
            confirmButton = {
                when {
                    update.needsInstallPermission -> TextButton(
                        onClick = {
                            com.vault.updates.UpdateCoordinator.markLaunchingPermissionSettings()
                            installPermissionLauncher.launch(
                                com.vault.updates.AppUpdater.installPermissionSettingsIntent(ctx),
                            )
                        },
                        enabled = !update.launchingPermissionSettings,
                    ) { Text(uiText(if (update.launchingPermissionSettings) "正在打开设置…" else "去开启")) }
                    update.failure != null -> TextButton(
                        onClick = { com.vault.updates.UpdateCoordinator.retryUpdate(ctx) },
                        enabled = !busyUpdate,
                    ) { Text(uiText("重试")) }
                    !busyUpdate -> TextButton(
                        onClick = { com.vault.updates.UpdateCoordinator.startUpdate(ctx) },
                    ) { Text(uiText("下载更新")) }
                }
            },
            dismissButton = {
                if (!busyUpdate) {
                    TextButton(onClick = { com.vault.updates.UpdateCoordinator.dismiss() }) { Text(uiText("稍后")) }
                }
            },
        )
    }
}

/** 把协调器给出的失败原因翻成当前语言的文案；动态细节（HTTP 码、异常消息）跟在后面。 */
@Composable
private fun updateFailureText(state: com.vault.updates.UpdateCoordinator.State): String {
    val detail = state.failureDetail
    return when (state.failure) {
        com.vault.updates.UpdateCoordinator.Failure.CHECK ->
            if (detail.isBlank()) uiText("检查更新失败") else uiText("检查更新失败") + "：$detail"
        com.vault.updates.UpdateCoordinator.Failure.DOWNLOAD ->
            if (detail.isBlank()) uiText("下载更新失败") else uiText("下载更新失败") + "：$detail"
        com.vault.updates.UpdateCoordinator.Failure.SIGNATURE_MISMATCH ->
            uiText("安装包签名与当前版本不一致，已取消安装")
        com.vault.updates.UpdateCoordinator.Failure.INVALID_PACKAGE -> uiText("安装包信息无效")
        com.vault.updates.UpdateCoordinator.Failure.INVALID_VERSION -> uiText("更新包版本无效")
        com.vault.updates.UpdateCoordinator.Failure.NO_INSTALLER -> uiText("未找到可安装 APK 的应用")
        com.vault.updates.UpdateCoordinator.Failure.INSTALL_BLOCKED ->
            if (detail.isBlank()) uiText("无法启动安装器，请回到应用后重试")
            else uiText("无法启动安装器，请回到应用后重试") + "：$detail"
        null -> ""
    }
}

internal fun sponsorSupportTarget(): String =
    "https://faegit.github.io/faevault-site/zh-cn/support/"

/**
 * 打开官网关于页对应分区。隐私政策与更新日志已迁移到官网「关于」页面，
 * App 不再内嵌文档，直接以外部浏览器打开并按界面语言选择中/英文版。
 */
internal fun openOfficialSite(ctx: android.content.Context, fragment: String) {
    val locales = ctx.resources.configuration.locales
    val english = locales[0].toLanguageTag().startsWith("en", true)
    val lang = if (english) "en" else "zh-cn"
    val uri = android.net.Uri.parse("https://faegit.github.io/faevault-site/$lang/about/$fragment")
    runCatching { ctx.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, uri)) }
}

@Composable
private fun SensitiveGuardSection(
    ctx: android.content.Context,
    embedded: Boolean = false,
    guard: (String, () -> Unit) -> Unit,
) {
    val enabled by com.vault.security.SensitiveGuardPref.enabled
    SettingsCard(title = stringResource(R.string.settings_remaining_sensitive_guard), embedded = embedded) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                uiText("操作敏感内容前验证主密码"),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            VaultSwitch(
                checked = enabled,
                // 开启 = 提高安全等级，直接生效；关闭 = 降低安全等级，必须先验证主密码
                onCheckedChange = { newValue ->
                    if (newValue) {
                        com.vault.security.SensitiveGuardPref.setEnabled(ctx, true)
                    } else {
                        guard("关闭「敏感内容二次保护」会降低保护等级，需要验证当前主密码。") {
                            com.vault.security.SensitiveGuardPref.setEnabled(ctx, false)
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun PhotoBlurSection(ctx: android.content.Context, embedded: Boolean = false, guard: (String, () -> Unit) -> Unit) {
    val enabled by com.vault.security.PhotoBlurPref.enabled
    SettingsCard(title = uiText("图像模糊"), embedded = embedded) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                uiText("所有图像自动模糊处理"),
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            VaultSwitch(
                checked = enabled,
                onCheckedChange = { checked ->
                    if (checked) com.vault.security.PhotoBlurPref.setEnabled(ctx, true)
                    else guard(localizeUiTextFor(ctx, "关闭图像模糊需要验证当前主密码。")) {
                        com.vault.security.PhotoBlurPref.setEnabled(ctx, false)
                    }
                },
            )
        }
    }
}

@Composable
private fun BackgroundHideSection(ctx: android.content.Context) {
    val enabled by BackgroundHidePref.enabled
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            uiText("切到后台时从最近任务中隐藏"),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
        )
        VaultSwitch(
            checked = enabled,
            onCheckedChange = {
                BackgroundHidePref.setEnabled(ctx, it)
                WindowSecurity.applyTo(ctx as? android.app.Activity)
            },
        )
    }
}

@Composable
private fun ScreenCapturePermissionSection(
    ctx: android.content.Context,
    requestAllow: (String) -> Unit,
) {
    val allowed by com.vault.security.ScreenCapturePermission.allowed
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            uiText("允许截屏"),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
        )
        // 默认不允许截屏（开关关）。打开需主密码确认；关闭直接生效。
        VaultSwitch(
            checked = allowed,
            onCheckedChange = { newValue ->
                if (newValue) {
                    requestAllow(localizeUiTextFor(ctx, "允许截屏会使保险库内容暴露在截图、录屏和投屏中，需要验证当前主密码。"))
                } else {
                    com.vault.security.ScreenCapturePermission.setAllowed(ctx, false)
                    WindowSecurity.applyTo(ctx as? android.app.Activity)
                }
            },
        )
    }
}

@Composable
private fun ClipboardTtlSection(ctx: android.content.Context, embedded: Boolean = false) {
    val sec by ClipboardTtlPref.seconds
    val presets = remember { listOf(0, 15, 30, 60, 120, 180, 300, 600) }
    val persistedIndex = presets.indexOf(sec).let {
        if (it < 0) presets.indexOf(ClipboardTtlPref.DEFAULT_SECONDS) else it
    }
    var sliderIndex by remember(persistedIndex) { mutableIntStateOf(persistedIndex) }
    val previewSeconds = presets[sliderIndex]
    SettingsCard(title = stringResource(R.string.settings_remaining_clipboard_auto_clear), embedded = embedded) {
        val label = when {
            previewSeconds <= 0 -> stringResource(R.string.settings_remaining_clipboard_no_auto_clear)
            previewSeconds % 60 == 0 -> stringResource(R.string.settings_remaining_clipboard_clear_after_minutes, previewSeconds / 60)
            else -> stringResource(R.string.settings_remaining_clipboard_clear_after_seconds, previewSeconds)
        }
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        // 0/15/30/60/120/180/300/600 秒
        VaultSlider(
            value = sliderIndex.toFloat(),
            onValueChange = { sliderIndex = it.roundToInt().coerceIn(presets.indices) },
            onValueChangeFinished = { ClipboardTtlPref.setSeconds(ctx, previewSeconds) },
            valueRange = 0f..(presets.size - 1).toFloat(),
            steps = presets.size - 2,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun AutoHideSection(ctx: android.content.Context, embedded: Boolean = false) {
    val sec by AutoHidePref.seconds
    val presets = remember { listOf(2, 5, 10, 15, 30, 60, 120) }
    val persistedIndex = presets.indexOf(sec).let {
        if (it < 0) presets.indexOf(AutoHidePref.DEFAULT_SECONDS) else it
    }
    var sliderIndex by remember(persistedIndex) { mutableIntStateOf(persistedIndex) }
    val previewSeconds = presets[sliderIndex]
    SettingsCard(title = stringResource(R.string.settings_remaining_auto_hide_after_display), embedded = embedded) {
        val label = when {
            previewSeconds < 60 -> stringResource(R.string.settings_remaining_hide_after_seconds, previewSeconds)
            else -> stringResource(R.string.settings_remaining_hide_after_minutes, previewSeconds / 60)
        }
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(SettingsSpacing.withinItem))
        VaultSlider(
            value = sliderIndex.toFloat(),
            onValueChange = { sliderIndex = it.roundToInt().coerceIn(presets.indices) },
            onValueChangeFinished = { AutoHidePref.setSeconds(ctx, previewSeconds) },
            valueRange = 0f..(presets.size - 1).toFloat(),
            steps = presets.size - 2,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun AppearanceSection(ctx: android.content.Context, embedded: Boolean = false) {
    val mode = ThemePref.mode.value
    val homeLayoutMode = HomeLayoutPref.mode.value
    val localeTag = androidx.compose.ui.platform.LocalConfiguration.current.locales.toLanguageTags()
    var expanded by remember(localeTag) { mutableStateOf(false) }
    var languageExpanded by remember(localeTag) { mutableStateOf(false) }
    val options = listOf(
        ThemeMode.SYSTEM to stringResource(R.string.settings_remaining_follow_system),
        ThemeMode.LIGHT to stringResource(R.string.settings_remaining_light),
        ThemeMode.DARK to stringResource(R.string.settings_remaining_dark),
    )
    val currentLabel = options.first { it.first == mode }.second
    // 深浅切换的圆形扩散：依据「生效配色」是否真的变化决定是否播放动画
    val systemDark = androidx.compose.foundation.isSystemInDarkTheme()
    val themeScope = rememberCoroutineScope()
    fun effectiveDark(m: ThemeMode): Boolean =
        m == ThemeMode.DARK || (m == ThemeMode.SYSTEM && systemDark)
    // 测量按钮真实宽度，DropdownMenu 用同样的宽度显示，避免默认 "intrinsic" 宽度比按钮窄
    var buttonWidthPx by remember { mutableIntStateOf(0) }
    var languageButtonWidthPx by remember { mutableIntStateOf(0) }
    val density = androidx.compose.ui.platform.LocalDensity.current
    val buttonWidthDp = with(density) { buttonWidthPx.toDp() }
    val languageButtonWidthDp = with(density) { languageButtonWidthPx.toDp() }
    SettingsCard(title = stringResource(R.string.settings_remaining_appearance), embedded = embedded) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val localeManager = ctx.getSystemService(LocaleManager::class.java)
            val languageOptions = listOf(
                "" to stringResource(R.string.settings_remaining_follow_system),
                "zh-Hans" to stringResource(R.string.settings_remaining_simplified_chinese),
                "en" to "English",
            )
            val currentLanguageTag = localeManager.applicationLocales.toLanguageTags()
            val currentLanguageLabel = languageOptions.firstOrNull { (tag, _) ->
                if (tag.isEmpty()) currentLanguageTag.isEmpty()
                else currentLanguageTag.startsWith(tag, ignoreCase = true)
            }?.second ?: stringResource(R.string.settings_remaining_follow_system)

            SettingsSubsectionTitle(stringResource(R.string.settings_remaining_app_language), topPadding = 0.dp)
            Text(
                uiText("选择程序使用的语言"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Box(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { languageExpanded = true },
                    shape = VaultShape,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                        .onSizeChanged { languageButtonWidthPx = it.width },
                ) {
                    Text(currentLanguageLabel, modifier = Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.Start)
                    Icon(
                        if (languageExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                    )
                }
                com.vault.ui.VaultDropdownMenu(
                    expanded = languageExpanded,
                    onDismissRequest = { languageExpanded = false },
                    modifier = if (languageButtonWidthPx > 0) {
                        Modifier.width(languageButtonWidthDp)
                    } else {
                        Modifier
                    },
                    containerColor = popupMenuSurface(),
                ) {
                    for ((tag, label) in languageOptions) {
                        val selected = if (tag.isEmpty()) currentLanguageTag.isEmpty()
                        else currentLanguageTag.startsWith(tag, ignoreCase = true)
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text(label, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal) },
                            onClick = {
                                languageExpanded = false
                                expanded = false
                                localeManager.applicationLocales = LocaleList.forLanguageTags(tag)
                            },
                            trailingIcon = if (selected) {
                                { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                            } else null,
                        )
                    }
                }
            }
            SettingsSubsectionTitle(stringResource(R.string.settings_remaining_display))
        } else {
            SettingsSubsectionTitle(stringResource(R.string.settings_remaining_display), topPadding = 0.dp)
        }
        Text(
            stringResource(R.string.settings_remaining_theme_description),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Box(modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { expanded = true },
                shape = VaultShape,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .onSizeChanged { buttonWidthPx = it.width },
            ) {
                Text(currentLabel, modifier = Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.Start)
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = null,
                )
            }
            com.vault.ui.VaultDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                modifier = if (buttonWidthPx > 0) Modifier.width(buttonWidthDp) else Modifier,
                containerColor = popupMenuSurface(),
            ) {
                for ((m, label) in options) {
                    androidx.compose.material3.DropdownMenuItem(
                        text = { Text(label, fontWeight = if (m == mode) FontWeight.SemiBold else FontWeight.Normal) },
                        onClick = {
                            expanded = false
                            themeScope.launch {
                                ThemeSwitch.run(ctx, m, effectiveDark(mode) != effectiveDark(m))
                            }
                        },
                        trailingIcon = if (m == mode) {
                            { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                        } else null,
                    )
                }
            }
        }
            SettingsSubsectionTitle(stringResource(R.string.settings_remaining_layout))
            Text(
                uiText("选择主页布局模式"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ThemeChoice(
                label = stringResource(R.string.settings_remaining_items),
                selected = homeLayoutMode == HomeLayoutMode.ITEMS,
                modifier = Modifier.weight(1f),
                onClick = { HomeLayoutPref.set(ctx, HomeLayoutMode.ITEMS) },
            )
            ThemeChoice(
                label = stringResource(R.string.settings_remaining_two_columns),
                selected = homeLayoutMode == HomeLayoutMode.TWO_COLUMNS,
                modifier = Modifier.weight(1f),
                onClick = { HomeLayoutPref.set(ctx, HomeLayoutMode.TWO_COLUMNS) },
            )
        }
    }
}

@Composable
private fun ThemeChoice(label: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    SettingsOutlinedButton(onClick = onClick, modifier = modifier, centered = false) {
        Text(label, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
        if (selected) {
            Spacer(Modifier.width(6.dp))
            Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape))
        }
    }
}

@Composable
private fun SettingsOutlinedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    centered: Boolean = true,
    enabled: Boolean = true,
    content: @Composable () -> Unit,
) {
    val sized = if (centered) modifier.fillMaxWidth() else modifier
    VaultButton(
        onClick = onClick,
        enabled = enabled,
        shape = VaultShape,
        modifier = sized,
        variant = VaultButtonVariant.NEUTRAL,
    ) { content() }
}

@Composable
private fun OutlinedButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = VaultShape,
    content: @Composable RowScope.() -> Unit,
) {
    VaultButton(
        onClick = onClick,
        enabled = enabled,
        shape = shape,
        modifier = modifier,
        variant = VaultButtonVariant.NEUTRAL,
        content = content,
    )
}

@Composable
private fun SettingsButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    centered: Boolean = true,
    enabled: Boolean = true,
    shape: Shape = VaultShape,
    content: @Composable () -> Unit,
) {
    val sized = if (centered) modifier.fillMaxWidth() else modifier
    VaultButton(
        onClick = onClick,
        enabled = enabled,
        shape = shape,
        modifier = sized,
        variant = VaultButtonVariant.NEUTRAL,
    ) { content() }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun SettingsCard(
    title: String,
    description: String = "",
    help: String? = null,
    embedded: Boolean = false,
    clickAction: (() -> Unit)? = null,
    collapseSignal: Int = 0,
    contentExpandFrom: Alignment.Vertical = Alignment.Bottom,
    onExpanded: (() -> Unit)? = null,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    if (embedded) {
        Column(modifier = Modifier.fillMaxWidth(), content = content)
        return
    }
    val focusedCard = LocalFocusedSettingsCard.current
    val focusedTitle = focusedCard?.first
    val onSetFocused = focusedCard?.second
    var localExpanded by remember(title) { mutableStateOf(false) }
    val expanded = focusedTitle == title || (focusedCard == null && localExpanded)
    val enterDescription = stringResource(R.string.settings_remaining_enter)
    val collapseDescriptionFormat = stringResource(R.string.settings_remaining_collapse)
    val expandDescriptionFormat = stringResource(R.string.settings_remaining_expand)
    // 外部收起信号：保留 expanded 让 AnimatedVisibility 播放退出动画后再重置
    LaunchedEffect(collapseSignal) {
        if (collapseSignal > 0 && expanded) {
            localExpanded = false
        }
    }
    // 【特色功能】焦点模式下仅显示当前卡片，其余卡片淡出+收起；无焦点时全部照常展示
    val visible = focusedTitle.let { it == null || it == title }
    LaunchedEffect(expanded) {
        if (expanded) {
            onExpanded?.invoke()
        }
    }

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
        exit = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top),
    ) {
        Column {
            Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(VaultShape)
                            .clickable {
                                if (clickAction != null) {
                                    clickAction()
                                } else if (focusedCard != null) {
                                    onSetFocused?.invoke(if (expanded) null else title)
                                } else {
                                    localExpanded = !localExpanded
                                }
                            }
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            uiText(title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                        )
                        if (help == null && description.isNotEmpty()) {
                            Text(
                                description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                    if (help != null) {
                        SettingsHelpIcon(help)
                    }
                    Spacer(Modifier.width(8.dp))
                    Icon(
                        imageVector = if (clickAction != null) Icons.Default.ChevronRight
                            else if (expanded) Icons.Default.KeyboardArrowUp
                            else Icons.Default.KeyboardArrowDown,
                        contentDescription = if (clickAction != null) enterDescription
                            else if (expanded) collapseDescriptionFormat.format(title)
                            else expandDescriptionFormat.format(title),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp),
                    )
                }
                AnimatedVisibility(
                    visible = expanded,
                    enter = expandVertically(expandFrom = contentExpandFrom) + fadeIn(),
                    exit = shrinkVertically(shrinkTowards = contentExpandFrom) + fadeOut(),
                ) {
                    Column(modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)) {
                        HorizontalDivider()
                        Spacer(Modifier.height(SettingsSpacing.withinItem))
                        content()
                    }
                }
            }
        }
    }
}
}

private object SettingsSpacing {
    /** 同一设置项内：标题→内容、内容→内容的垂直间距 */
    val withinItem = 8.dp

    /** 不同设置项之间：上一设置项内容 → 本设置项标题 */
    val betweenItems = 16.dp
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsHelpIcon(help: String, modifier: Modifier = Modifier) {
    val tooltipState = rememberTooltipState(isPersistent = true)
    val scope = rememberCoroutineScope()
    TooltipBox(
        positionProvider = TooltipDefaults.rememberPlainTooltipPositionProvider(),
        tooltip = {
            PlainTooltip(
                modifier = Modifier.semantics {
                    liveRegion = LiveRegionMode.Assertive
                    paneTitle = help
                },
            ) {
                Text(help)
            }
        },
        state = tooltipState,
        modifier = modifier,
    ) {
        Icon(
            Icons.AutoMirrored.Outlined.HelpOutline,
            contentDescription = uiText("帮助"),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .size(16.dp)
                .clip(CircleShape)
                .clickable {
                    scope.launch { tooltipState.show() }
                },
        )
    }
}

@Composable
internal fun SettingsSubsectionTitle(
    title: String,
    topPadding: androidx.compose.ui.unit.Dp = SettingsSpacing.betweenItems,
    help: String? = null,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = topPadding, bottom = SettingsSpacing.withinItem),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = uiText(title),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.SemiBold,
        )
        if (help != null) {
            Spacer(Modifier.width(4.dp))
            SettingsHelpIcon(help)
        }
    }
}

@Composable
internal fun SettingsAccordion(
    title: String,
    help: String? = null,
    expanded: Boolean = false,
    activeTitle: String? = null,
    onToggle: (() -> Unit)? = null,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    var localExpanded by remember { mutableStateOf(expanded) }
    val isExpanded = if (onToggle != null) expanded else localExpanded
    val collapseDescription = stringResource(R.string.settings_remaining_collapse)
    val expandDescription = stringResource(R.string.settings_remaining_expand)
    val toggle: () -> Unit = onToggle ?: { localExpanded = !localExpanded }
    // 单开手风琴：同一张卡内已有其他分区展开时，本分区(含标题行)整块隐藏，只保留当前展开的分区。
    val blockVisible = activeTitle == null || expanded
    AnimatedVisibility(
        visible = blockVisible,
        enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
        exit = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top),
    ) {
        Column(Modifier.fillMaxWidth()) {
            // 标题行点击区占满卡片左右全宽（涟漪延伸到卡片边缘），文字经行内 padding 内缩。
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(VaultShape)
                    .clickable(onClick = toggle)
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    uiText(title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                if (help != null) {
                    SettingsHelpIcon(help)
                    Spacer(Modifier.width(8.dp))
                }
                Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = if (isExpanded) collapseDescription.format(title) else expandDescription.format(title),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp),
                )
            }
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut(),
            ) {
                Column(Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp)) {
                    HorizontalDivider()
                    Spacer(Modifier.height(8.dp))
                    content()
                }
            }
        }
    }
}

@Composable
private fun CloudSyncStatusLine(vm: VaultViewModel) {
    val state by vm.cloudSyncState.collectAsStateWithLifecycle()
    val statusText = when {
        state.busyMessage.isNotBlank() -> state.busyMessage
        state.phase == VaultViewModel.CloudSyncPhase.RUNNING -> "正在同步到 ${state.target}…"
        state.phase == VaultViewModel.CloudSyncPhase.FAILED -> if (state.localChangesSaved) {
            "同步未完成，本地数据已安全保留"
        } else {
            "${state.target.ifBlank { "云端" }}同步失败 · 请重试"
        }
        else -> if (state.lastSuccessAt > 0L) {
            val time = java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.getDefault())
                .format(java.util.Date(state.lastSuccessAt))
            buildString {
                append(if (state.verified) "已同步并通过安全校验 · $time" else "已同步 · $time")
                if (state.changedCount > 0) append(" · 更新 ${state.changedCount} 项")
                if (state.uploaded) append(" · 已更新云端")
            }
        } else {
            "尚未同步"
        }
    }
    val statusControlColor = when {
        state.busyMessage.isNotBlank() || state.phase == VaultViewModel.CloudSyncPhase.RUNNING ->
            MaterialTheme.colorScheme.primary
        state.phase == VaultViewModel.CloudSyncPhase.FAILED -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val statusTextColor = if (
        state.busyMessage.isNotBlank() || state.phase == VaultViewModel.CloudSyncPhase.RUNNING
    ) MaterialTheme.colorScheme.primary else statusControlColor
    val showProgress = state.busyMessage.isNotBlank() ||
        state.phase == VaultViewModel.CloudSyncPhase.RUNNING
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(Modifier.size(9.dp).background(statusControlColor, CircleShape))
            Text(uiText(statusText), style = MaterialTheme.typography.bodyMedium, color = statusTextColor)
        }
        if (showProgress) {
            Spacer(Modifier.height(8.dp))
            val progress = state.progress
            if (progress != null) {
                LinearProgressIndicator(
                    progress = progress,
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                )
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
private fun CloudSyncPreviewSummary(preview: VaultViewModel.CloudSyncPreview) {
    val title = when (preview.kind) {
        "same" -> uiText("双方内容一致")
        "remote_ahead" -> uiText("远端有新版本，可拉取")
        "local_ahead" -> uiText("本地有新版本，可上传")
        "diverged" -> uiText("双方均有修改，可自动合并")
        "conflict" -> uiText("检测到同步冲突")
        "remote_missing" -> uiText("远端文件不存在")
        "different" -> uiText("远端不是同一份保险库")
        "legacy" -> uiText("旧格式不支持云同步预览")
        "unlinked" -> uiText("尚未关联")
        "error" -> uiText("远端检测失败")
        else -> preview.message.ifBlank { uiText("等待检测") }
    }
    val color = when (preview.kind) {
        "same" -> MaterialTheme.colorScheme.primary
        "error", "conflict", "remote_missing", "different" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.tertiary
    }
    Column(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(title, style = MaterialTheme.typography.labelLarge, color = color)
        // PMVE 提交版本信息（不再展示文件修改时间）
        if (preview.localSequence > 0L || preview.remoteSequence > 0L) {
            val localVer = if (preview.localSequence > 0L) {
                uiText("本地提交 #${preview.localSequence}，密钥 v${preview.localKeyRevision}")
            } else null
            val remoteVer = if (preview.remoteSequence > 0L) {
                uiText("远端提交 #${preview.remoteSequence}，密钥 v${preview.remoteKeyRevision}")
            } else null
            Text(
                listOfNotNull(localVer, remoteVer).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (preview.kind !in setOf("error", "different", "legacy", "unlinked", "remote_missing")) {
            Text(
                uiText("本地 ${preview.localActive} 项，回收站 ${preview.localTrash} · 远端 ${preview.remoteActive} 项，回收站 ${preview.remoteTrash}"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val changes = buildList {
                if (preview.remoteOnly > 0) add(uiText("远端新增 ${preview.remoteOnly}"))
                if (preview.stats.takeRemote > 0) add(uiText("采用远端 ${preview.stats.takeRemote}"))
                if (preview.localOnly > 0) add(uiText("本地待上传 ${preview.localOnly}"))
                if (preview.stats.takeLocal > 0) add(uiText("保留本地 ${preview.stats.takeLocal}"))
                if (preview.stats.purged > 0) add(uiText("删除传播 ${preview.stats.purged}"))
                if (preview.remotePurgeAhead > 0) add(uiText("远端删除日志 ${preview.remotePurgeAhead}"))
                if (preview.localPurgeAhead > 0) add(uiText("本地删除日志待上传 ${preview.localPurgeAhead}"))
                if (preview.stats.conflicts > 0) add(uiText("冲突 ${preview.stats.conflicts}"))
            }
            Text(
                if (changes.isEmpty()) uiText("已核对条目、回收站与删除日志，无需合并或覆盖") else changes.joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (preview.message.isNotBlank()) {
            Text(
                uiText(preview.message),
                style = MaterialTheme.typography.bodySmall,
                color = if (preview.kind in setOf("error", "different", "conflict", "legacy")) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        val checked = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date(preview.checkedAt))
        Text(uiText("最近检测：$checked"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
    }
}

@Composable
private fun CloudAssociationStatus(success: Boolean, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Box(
            Modifier.size(9.dp).background(
                if (success) com.vault.ui.SuccessColors.ToastDot else MaterialTheme.colorScheme.error,
                CircleShape,
            ),
        )
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun AccountRow(
    name: String,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            name,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
        )
        IconButton(onClick = onRename) { Icon(Icons.Default.Edit, stringResource(R.string.settings_remaining_rename_account)) }
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, stringResource(R.string.settings_remaining_delete_account_action)) }
    }
}

@Composable
private fun VaultKeyInfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            uiText(label),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
        )
    }
}

private fun formatEpochSeconds(ts: Double): String {
    if (ts <= 0.0) return "—"
    return Instant.ofEpochMilli((ts * 1000).toLong())
        .atZone(ZoneId.systemDefault())
        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
}

@Composable
private fun LanTransferPanel(
    vm: VaultViewModel,
    state: com.vault.ui.UiState,
    host: Boolean = false,
    sessionLive: Boolean = false,
    onDisconnect: () -> Unit = {},
    onExitTransfer: () -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val isHost = host
    // 内嵌面板：不再做两阶段输入法避让，键盘避让交由外层页面滚动与 imePadding 统一处理
    val transferListHeight = if (!isHost && state.lanTransferDisconnected) 300.dp else 220.dp
    var confirmDisconnect by remember { mutableStateOf(false) }
    val pendingLargeTransfer by vm.pendingLargeTransfer.collectAsStateWithLifecycle()
    pendingLargeTransfer?.let { _ ->
        VaultDialog(
            onDismissRequest = { vm.confirmLargeTransferSend(false) },
            dismissOnOutsideClick = false,
            properties = DialogProperties(decorFitsSystemWindows = false),
            onClose = { vm.confirmLargeTransferSend(false) },
            title = { Text(stringResource(R.string.settings_remaining_large_file_transfer)) },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        uiText("局域网传输速度较慢，是否继续传输大文件？"),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        uiText("继续后将立即开始传输，本次会话不再提示。"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        SettingsButton(
                            onClick = { vm.confirmLargeTransferSend(true) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(uiText("继续传输"))
                        }
                        SettingsOutlinedButton(
                            onClick = { vm.confirmLargeTransferSend(false) },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(uiText("取消"))
                        }
                    }
                }
            },
        )
    }
    // 记录由传输线程持续更新；窗口必须直接订阅 StateFlow，不能只读取一次 value。
    val hostStatus by vm.lanHostState.collectAsStateWithLifecycle()
    val transferItems = if (isHost) emptyList<LanTransferItem>() else state.lanTransferItems.asReversed()
    val hostItems = if (isHost) hostStatus.items.asReversed() else emptyList()

    fun activate(item: LanTransferItem) {
        if (isHost) return
        scope.launch {
            runCatching {
                if (item.kind == "text" && item.size <= MAX_COPYABLE_TRANSFER_TEXT_BYTES) {
                    val value = withContext(Dispatchers.IO) { readLanTransferText(context, item) }
                    copySensitive(context, "传输文本", value)
                } else {
                    openLanTransferFile(context, item)
                }
            }.onFailure { error ->
                Toast.makeText(context, localizeUiTextFor(context, "操作失败：${error.message ?: "未知错误"}"), Toast.LENGTH_LONG).show()
            }
        }
    }

    val sendText = stringResource(R.string.settings_remaining_send)
    val receiveText = stringResource(R.string.settings_remaining_receive)
    val copyText = stringResource(R.string.settings_remaining_copy_text)
    val openFileText = stringResource(R.string.settings_remaining_open_file)
    // 主机与连接方共用同一份“传输记录”渲染：把两种条目投影为统一行模型。
    val hostRows = hostItems.map { item ->
        val statusCode = when (item.status) {
            "等待接收" -> LanTransferStatusCode.WAITING_RECEIVE
            "接收中" -> LanTransferStatusCode.RECEIVING
            "已接收" -> LanTransferStatusCode.RECEIVED
            "接收失败" -> LanTransferStatusCode.FAILED
            "发送中" -> LanTransferStatusCode.SENDING
            "发送中断" -> LanTransferStatusCode.INTERRUPTED
            "已发送" -> LanTransferStatusCode.SENT
            "已取消" -> LanTransferStatusCode.CANCELLED
            else -> LanTransferStatusCode.UNKNOWN
        }
        val cancellable = statusCode in setOf(LanTransferStatusCode.WAITING_RECEIVE, LanTransferStatusCode.SENDING, LanTransferStatusCode.RECEIVING)
        TransferRecordRow(
            key = item.id,
            name = transferDisplayName(item.kind, item.name, item.textPreview),
            size = item.size,
            directionLabel = if (item.direction == "outgoing") sendText else receiveText,
            status = uiText(item.status),
            statusCode = statusCode,
            progress = if (statusCode in setOf(LanTransferStatusCode.SENDING, LanTransferStatusCode.RECEIVING) && item.size > 0L) {
                (item.transferred.toFloat() / item.size.toFloat()).coerceIn(0f, 1f)
            } else null,
            path = item.path,
            cancellable = cancellable,
            onCancel = if (cancellable) ({ vm.cancelLanHostTransfer(item.id) }) else null,
        )
    }
    val connectorRows = transferItems.map { item ->
        val actionable = item.localPath.isNotBlank() || item.openUri.isNotBlank()
        val cancellable = item.statusCode in setOf(LanTransferStatusCode.WAITING_RECEIVE, LanTransferStatusCode.RECEIVING, LanTransferStatusCode.SENDING)
        TransferRecordRow(
            key = "${item.direction}:${item.remoteId}",
            name = transferDisplayName(item.kind, item.name, item.textPreview),
            size = item.size,
            directionLabel = if (item.direction == LanTransferDirection.RECEIVED) receiveText else sendText,
            status = item.status,
            statusCode = item.statusCode,
            progress = item.progress.takeIf { item.statusCode in setOf(LanTransferStatusCode.SENDING, LanTransferStatusCode.RECEIVING) }?.coerceIn(0f, 1f),
            path = item.path,
            actionLabel = if (actionable) {
                if (item.kind == "text" && item.size <= MAX_COPYABLE_TRANSFER_TEXT_BYTES) copyText else openFileText
            } else null,
            onClick = if (actionable) ({ activate(item) }) else null,
            cancellable = cancellable,
            onCancel = if (cancellable) ({ vm.cancelLanTransferItem(item.remoteId, item.direction) }) else null,
        )
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            // 顶部一行「对方设备：<id>」，与桌面端传输页一致。
            // 没有设备身份字段时（连接方拿不到对端 device_id）整行不出现。
            if (isHost && hostStatus.peerDeviceId.isNullOrBlank().not()) {
                Text(
                    stringResource(
                        R.string.settings_remaining_lan_peer_device_line,
                        hostStatus.peerDeviceId.orEmpty().take(8),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Text(uiText("文件传输"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.weight(1f))
                // 一颗按钮两种状态：连接中=断开连接（要确认，中断的是在途传输），
                // 已断开=关闭页面（只是收起视图，无不可逆后果，不再确认）。
                SettingsOutlinedButton(
                    onClick = { if (sessionLive) confirmDisconnect = true else onExitTransfer() },
                    enabled = !state.lanTransferConnecting,
                    centered = false,
                ) {
                    Text(
                        stringResource(
                            if (sessionLive) R.string.lan_disconnect else R.string.lan_exit_transfer,
                        ),
                    )
                }
            }
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        when {
                            isHost -> stringResource(R.string.settings_remaining_file_transfer_connected)
                            state.lanTransferDisconnected -> stringResource(R.string.settings_remaining_peer_closed_transfer)
                            state.lanTransferConnecting -> stringResource(R.string.settings_remaining_connecting_encrypted_lan)
                            else -> stringResource(R.string.settings_remaining_transfer_connection_open)
                        },
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (!isHost && state.lanTransferConnecting) {
                        BreathingRing(Modifier.size(22.dp), strokeWidth = 2.5.dp)
                    }
                }
                if (!isHost) state.lanTransferError?.let { message ->
                    Surface(shape = VaultShape, color = MaterialTheme.colorScheme.errorContainer) {
                        Text(
                            message,
                            modifier = Modifier.fillMaxWidth().padding(10.dp),
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }

                TransferRecordList(
                    rows = if (isHost) hostRows else connectorRows,
                    receivedCount = if (isHost) {
                        hostItems.count { it.direction == "incoming" }
                    } else {
                        transferItems.count { it.direction == LanTransferDirection.RECEIVED }
                    },
                    height = if (isHost) 220.dp else transferListHeight,
                )

                AnimatedVisibility(
                    // 断开后只保留传输记录供查看，发送区收起——主机/连接方一致。
                    // 不用 lanTransferDisconnected：用户主动断开只清 lanTransferActive、
                    // 不置该标志；主机侧则根本不查它。
                    visible = sessionLive,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically(),
                ) {
                    LanTransferComposer(
                        vm = vm,
                        host = isHost,
                        enabled = if (isHost) true else !state.lanTransferConnecting && !state.lanTransferDisconnected,
                    )
                }
            }
        }

    LaunchedEffect(sessionLive) {
        if (!sessionLive) confirmDisconnect = false
    }
    if (confirmDisconnect && sessionLive) {
        // 「断开连接」：不论主机还是连接方都真的断开对方，但页面保留、记录可看。
        VaultDialog(
            onDismissRequest = { confirmDisconnect = false },
            dismissOnOutsideClick = false,
            title = { Text(stringResource(R.string.lan_disconnect)) },
            text = { Text(stringResource(R.string.lan_disconnect_confirm_desc)) },
            confirmButton = {
                VaultActionButton(onClick = { confirmDisconnect = false }, style = VaultActionStyle.NEUTRAL) {
                    Text(uiText("取消"))
                }
            },
            dismissButton = {
                VaultActionButton(
                    onClick = {
                        confirmDisconnect = false
                        onDisconnect()
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(stringResource(R.string.lan_disconnect)) }
            },
        )
    }


}


/** 传输记录列表：主机与连接方共用同一份渲染（行模型来自 TransferRecordRow 投影）。
 *  receivedCount 用于检测「收到新信息」：只要该值增长，记录列表就自动滚到顶层（列表为倒序，最新在最上）。 */
@Composable
private fun TransferRecordList(
    rows: List<TransferRecordRow>,
    height: Dp,
    receivedCount: Int = 0,
) {
    val listState = rememberLazyListState()
    var lastReceivedCount by remember { mutableIntStateOf(receivedCount) }
    LaunchedEffect(receivedCount) {
        if (receivedCount > lastReceivedCount) {
            lastReceivedCount = receivedCount
            listState.animateScrollToItem(0)
        } else {
            lastReceivedCount = receivedCount
        }
    }
    Surface(
        modifier = Modifier.fillMaxWidth().height(height),
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(Modifier.fillMaxSize().padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(uiText("传输记录"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.weight(1f))
                Text(
                    uiText("${rows.size} 项"),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(6.dp))
            if (rows.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(uiText("尚无传输记录"), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.vaultBackdropSource().fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(rows.takeLast(20), key = { it.key }) { row ->
                        Surface(
                            shape = VaultShape,
                            color = MaterialTheme.colorScheme.surfaceContainer,
                            modifier = Modifier
                                .fillMaxWidth()
                                .then(if (row.onClick != null) Modifier.clickable { row.onClick() } else Modifier),
                        ) {
                            Column(Modifier.fillMaxWidth().padding(10.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        row.name,
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodyLarge,
                                        fontWeight = FontWeight.Medium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        row.directionLabel,
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                }
                                Spacer(Modifier.height(2.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Text(
                                        "${transferSize(row.size)} · ${row.status}",
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    if (row.actionLabel != null) {
                                        Text(
                                            row.actionLabel,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                    }
                                    if (row.cancellable && row.onCancel != null) {
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            uiText("取消"),
                                            modifier = Modifier
                                                .clip(VaultShape)
                                                .clickable { row.onCancel() }
                                                .padding(horizontal = 8.dp, vertical = 3.dp),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Medium,
                                            color = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                                val progress = row.progress
                                if (progress != null && row.statusCode in setOf(LanTransferStatusCode.SENDING, LanTransferStatusCode.RECEIVING)) {
                                    Spacer(Modifier.height(6.dp))
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        LinearProgressIndicator(
                                            progress = { progress },
                                            modifier = Modifier.weight(1f).height(4.dp),
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        Text(
                                            "${(progress * 100).roundToInt()}%",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }
                                if (row.path.isNotBlank()) {
                                    val directoryPath = row.path.substringBeforeLast('/', row.path)
                                    Text(
                                        uiText("传输目录：$directoryPath"),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

internal class CredentialProviderExternalActionGuard(
    private val setExternalActionInProgress: (Boolean) -> Unit,
) {
    var isInProgress: Boolean = false
        private set

    fun start() {
        if (isInProgress) return
        isInProgress = true
        setExternalActionInProgress(true)
    }

    fun finish() {
        if (!isInProgress) return
        isInProgress = false
        setExternalActionInProgress(false)
    }

    fun launch(block: () -> Unit): Boolean {
        start()
        return try {
            block()
            true
        } catch (_: Exception) {
            finish()
            false
        }
    }
}

private data class TransferRecordRow(
    val key: String,
    val name: String,
    val size: Long,
    val directionLabel: String,
    val status: String,
    val statusCode: LanTransferStatusCode,
    val progress: Float?,
    val path: String,
    val actionLabel: String? = null,
    val onClick: (() -> Unit)? = null,
    val cancellable: Boolean = false,
    val onCancel: (() -> Unit)? = null,
)

/** 文件传输共用发送区：文本走系统原生编辑（长按粘贴/选择由系统接管），
 *  剪贴板/输入法中的富内容（图片、视频、文件等非纯文本 URI）经 [contentReceiver] 进入文件发送核心。 */
@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun LanTransferComposer(
    vm: VaultViewModel,
    host: Boolean = false,
    enabled: Boolean = true,
) {
    val context = LocalContext.current
    val textFieldState = rememberTextFieldState()
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        vm.setExternalActionInProgress(false)
        if (host) uris.forEach(vm::hostQueueTransferFile) else uris.forEach(vm::sendLanTransferFile)
    }
    // 富内容接收：只消费非纯文本类型的 URI 项并交给文件发送；文本与 text 类型内容原样返回给输入框，
    // 由系统继续原生粘贴（不会自行消费长按手势，原生长按操作器保持可用）。
    val contentListener = remember(vm, host, enabled) {
        object : ReceiveContentListener {
            override fun onReceive(content: TransferableContent): TransferableContent? {
                if (!enabled) return content
                val linkUri = content.platformTransferableContent?.linkUri
                return content.consume { item ->
                    val uri = item.uri ?: linkUri
                    if (uri == null) return@consume false
                    val mime = runCatching { context.contentResolver.getType(uri) }.getOrNull()
                    if (mime?.startsWith("text/", ignoreCase = true) == true) return@consume false
                    vm.enqueueLanTransferContent(uri, host, source = "paste")
                    true
                }
            }
        }
    }
    val interactionSource = remember { MutableInteractionSource() }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(Modifier.fillMaxWidth().padding(10.dp)) {
            Text(uiText("发送内容"), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            BasicTextField(
                state = textFieldState,
                modifier = Modifier
                    .fillMaxWidth()
                    .contentReceiver(contentListener),
                enabled = enabled,
                // BasicTextField 不读 LocalContentColor：textStyle.color 为
                // Unspecified 时 TextPainter 直接落回 Color.Black，深色模式下变黑字。
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    color = MaterialTheme.colorScheme.onSurface,
                ),
                // 同理，BasicTextFieldDefaults.cursorBrush 硬编码 SolidColor(Color.Black)，
                // 光标颜色不会跟随主题，必须显式指定。
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                inputTransformation = InputTransformation {
                    if (length > MAX_COMPOSER_TEXT) {
                        replace(MAX_COMPOSER_TEXT, length, "")
                    }
                },
                lineLimits = TextFieldLineLimits.MultiLine(minHeightInLines = 1, maxHeightInLines = 4),
                interactionSource = interactionSource,
                decorator = TextFieldDecorator { innerTextField ->
                    OutlinedTextFieldDefaults.DecorationBox(
                        value = textFieldState.text.toString(),
                        innerTextField = innerTextField,
                        enabled = enabled,
                        singleLine = false,
                        visualTransformation = VisualTransformation.None,
                        interactionSource = interactionSource,
                        label = { Text(uiText("发送内容")) },
                        placeholder = { Text(uiText("输入文本，长按可粘贴剪贴板内容")) },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedContainerColor = MaterialTheme.colorScheme.surface,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                            disabledContainerColor = MaterialTheme.colorScheme.surface,
                            // 正文由外层 BasicTextField 绘制（textStyle/cursorBrush 决定），
                            // 这里只管 label / placeholder / 光标等装饰性文字，同样需跟随主题。
                            focusedLabelColor = MaterialTheme.colorScheme.onSurface,
                            unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            focusedPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unfocusedPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            disabledPlaceholderColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            cursorColor = MaterialTheme.colorScheme.primary,
                        ),
                    )
                },
            )
            Spacer(Modifier.height(8.dp))
            val text = textFieldState.text.toString()
            VaultActionButton(
                onClick = {
                    if (host) vm.hostQueueTransferText(text) else vm.sendLanTransferText(text)
                    textFieldState.clearText()
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled && text.isNotBlank(),
            ) { Text(uiText("发送")) }
            Spacer(Modifier.height(6.dp))
            SettingsOutlinedButton(
                onClick = {
                    vm.setExternalActionInProgress(true)
                    filePicker.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = enabled,
            ) { Text(uiText("发送文件")) }
        }
    }
}

private const val MAX_COMPOSER_TEXT = 200_000
private const val MAX_COPYABLE_TRANSFER_TEXT_BYTES = 1024L * 1024L

private fun readLanTransferText(context: Context, item: LanTransferItem): String {
    require(item.size <= MAX_COPYABLE_TRANSFER_TEXT_BYTES) {
        localizeUiTextFor(context, "文本超过 1 MB，请作为文件打开")
    }
    val input = when {
        item.localPath.isNotBlank() -> File(item.localPath).inputStream()
        item.openUri.isNotBlank() -> context.contentResolver.openInputStream(android.net.Uri.parse(item.openUri))
            ?: error("无法读取文本")
        else -> return item.textPreview
    }
    return input.bufferedReader(Charsets.UTF_8).use { it.readText() }
}

private fun openLanTransferFile(context: Context, item: LanTransferItem) {
    val uri = when {
        item.openUri.startsWith("content://") -> android.net.Uri.parse(item.openUri)
        item.localPath.isNotBlank() -> FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            File(item.localPath),
        )
        item.openUri.isNotBlank() -> android.net.Uri.parse(item.openUri)
        else -> error("文件尚未传输完成")
    }
    val mime = item.mime.substringBefore(';').ifBlank { "application/octet-stream" }
    context.startActivity(
        Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        },
    )
}

private fun transferSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L * 1024L -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    bytes >= 1024L * 1024L -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

@Composable
private fun LanSyncPinDialog(
    submitting: Boolean,
    attempts: Int,
    errorMessage: String,
    onCancel: () -> Unit,
    onPinComplete: (String) -> Unit,
) {
    var pin by remember(attempts) { mutableStateOf("") }
    val focus = remember { FocusRequester() }

    LaunchedEffect(attempts) { runCatching { focus.requestFocus() } }
    LaunchedEffect(pin, submitting) {
        if (pin.length == 6 && !submitting) onPinComplete(pin)
    }

    VaultDialog(
        onDismissRequest = { if (!submitting) onCancel() },
        onClose = { if (!submitting) onCancel() },
        title = { Text(uiText("PIN 码")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = pin,
                    onValueChange = { if (!submitting) pin = it.filter(Char::isDigit).take(6) },
                    label = { Text(uiText("PIN 码")) },
                    singleLine = true,
                    enabled = !submitting,
                    isError = errorMessage.isNotBlank(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = KeyboardType.NumberPassword,
                    ),
                    modifier = Modifier.fillMaxWidth().focusRequester(focus),
                )
                if (submitting) {
                    Text(uiText("正在验证 PIN 码…"), style = MaterialTheme.typography.bodySmall)
                } else if (errorMessage.isNotBlank()) {
                    Text(
                        errorMessage,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
    )
}

/**
 * 同步进行中的会话面板：设备信息（仅主机侧）+ 同步状态 + 断开连接。
 *
 * 主机侧（别人连我）与连接方（我连别人）共用同一个 lanSyncProgress——主机的收发
 * 回调也往里写字节数。但只有主机侧拿得到对端身份，连接方拿不到，故设备信息卡仅在
 * 主机侧出现。
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LanSyncSessionPanel(
    hostStatus: SyncServerHost.HostStatus?,
    progress: VaultViewModel.LanSyncProgress,
) {
    // 连接时长只有主机侧有依据（认证时刻），连接方没有该时间，就不显示这一行。
    val connectedAt = hostStatus?.peerConnectedAtMillis ?: 0L
    var nowMillis: Long by remember(connectedAt) { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(connectedAt) {
        while (connectedAt > 0L) {
            nowMillis = System.currentTimeMillis()
            delay(1_000)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        val peerId = hostStatus?.peerDeviceId
        if (!peerId.isNullOrBlank()) {
            LanInfoCard(stringResource(R.string.lan_peer_device)) {
                LanInfoRow(stringResource(R.string.lan_device_id), peerId.take(8))
                val fingerprint = hostStatus?.peerFingerprint.orEmpty()
                if (fingerprint.isNotBlank()) {
                    LanInfoRow(stringResource(R.string.lan_key_fingerprint), fingerprint)
                }
                val address = hostStatus?.peerAddress.orEmpty()
                if (address.isNotBlank()) {
                    LanInfoRow(stringResource(R.string.lan_peer_address), address)
                }
            }
        }
        LanInfoCard(stringResource(R.string.lan_sync_state)) {
            if (progress.status.isNotBlank()) {
                LanInfoRow(stringResource(R.string.lan_sync_state), progress.status)
            }
            if (progress.total > 0L) {
                LanInfoRow(
                    stringResource(R.string.lan_sync_volume),
                    "${transferSize(progress.transferred)} / ${transferSize(progress.total)}",
                )
            }
            if (connectedAt > 0L) {
                val seconds = ((nowMillis - connectedAt) / 1_000L).coerceAtLeast(0L)
                LanInfoRow(
                    stringResource(R.string.lan_connected_for),
                    stringResource(R.string.lan_connected_for_value, seconds / 60, seconds % 60),
                )
            }
            Spacer(Modifier.height(2.dp))
            if (progress.total > 0L) {
                LinearProgressIndicator(
                    progress = {
                        (progress.transferred.toFloat() / progress.total.toFloat()).coerceIn(0f, 1f)
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

/**
 * 传输站接入后的两张信息卡：对方设备 / 本次连接。
 *
 * 指纹取自授权记录里那把**被保险库签名过**的公钥（见
 * SyncServerHost.peerIdentity），不是对端在挑战请求里自报的值，所以两端可以互相核对。
 * 这一对字段取代了原先只显示一行「● 已连接设备」的状态。
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LanPeerCards(
    status: SyncServerHost.HostStatus,
    channelLabel: String,
) {
    // 连接时长要秒级走动：HostStatus 给的是认证时刻，这里用最小计时源驱动重绘。
    var nowMillis by remember(status.peerConnectedAtMillis) {
        mutableLongStateOf(System.currentTimeMillis())
    }
    LaunchedEffect(status.peerConnectedAtMillis) {
        while (status.peerConnectedAtMillis > 0L) {
            nowMillis = System.currentTimeMillis()
            delay(1_000)
        }
    }
    val seconds = if (status.peerConnectedAtMillis > 0L) {
        ((nowMillis - status.peerConnectedAtMillis) / 1_000L).coerceAtLeast(0L)
    } else 0L

    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        LanInfoCard(stringResource(R.string.lan_peer_device)) {
            // 设备 ID 只显示前 8 位：够用户核对，也够窄。
            LanInfoRow(stringResource(R.string.lan_device_id), status.peerDeviceId.orEmpty().take(8))
            if (status.peerFingerprint.isNotBlank()) {
                LanInfoRow(stringResource(R.string.lan_key_fingerprint), status.peerFingerprint)
            }
            if (status.peerAddress.isNotBlank()) {
                LanInfoRow(stringResource(R.string.lan_peer_address), status.peerAddress)
            }
        }
        LanInfoCard(stringResource(R.string.lan_this_connection)) {
            LanInfoRow(stringResource(R.string.lan_channel), channelLabel)
            if (status.peerConnectedAtMillis > 0L) {
                LanInfoRow(
                    stringResource(R.string.lan_connected_for),
                    stringResource(
                        R.string.lan_connected_for_value,
                        seconds / 60,
                        seconds % 60,
                    ),
                )
            }
        }
    }
}

@Composable
private fun LanInfoCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = VaultShape,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            content()
        }
    }
}

@Composable
private fun LanInfoRow(label: String, value: String) {
    if (value.isBlank()) return
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(84.dp),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** 传输站激活态视图：二维码 + PIN + 地址 + 传输列表 + 停止按钮。 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LanHostActiveView(
    status: SyncServerHost.HostStatus,
    vm: VaultViewModel,
    onStop: () -> Unit,
) {
    val ctx = LocalContext.current
    val transferChannel = status.paired && status.op == SyncServerHost.TRANSFER_OP
    var confirmStop by remember { mutableStateOf(false) }
    val channelLabel = when (status.op) {
        SyncServerHost.SYNC_OP -> stringResource(R.string.settings_remaining_lan_sync_channel)
        SyncServerHost.TRANSFER_OP -> stringResource(R.string.settings_remaining_file_transfer_channel)
        SyncServerHost.EXPORT_OP -> stringResource(R.string.settings_remaining_data_import_export_channel)
        else -> ""
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        if (status.paired) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Text(
                    uiText("● 已连接设备"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                )
                if (channelLabel.isNotBlank()) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "· $channelLabel",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            // 与桌面端对齐：接入后不再只有一行「已连接」，而是给出对方身份与本次连接两张卡。
            // 不放进度——进度在同步/文件传输各自那一挡已经有一份，同屏两份会让人怀疑对不上。
            LanPeerCards(status = status, channelLabel = channelLabel)
        } else {
            Text(
                uiText("等待其他设备扫码连接"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        // 连接后自动隐藏传输站信息（二维码/地址），只保留连接状态与对应操作
        AnimatedVisibility(visible = !status.paired) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    QrImage(content = status.url)
                }
                Text(
                    status.url,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(VaultShape)
                        .clickable(
                            onClick = {
                                val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText(localizeUiTextFor(ctx, "传输站地址"), status.url))
                                Toast.makeText(ctx, localizeUiTextFor(ctx, "地址已复制，可粘贴到另一台设备"), Toast.LENGTH_SHORT).show()
                            },
                        ),
                )
                Text(
                    uiText("让另一台设备扫描上方二维码，或手动输入地址和 PIN 连接"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        SettingsOutlinedButton(
            onClick = { if (transferChannel) confirmStop = true else onStop() },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.lan_close_station))
        }
    }
    if (confirmStop) {
        VaultDialog(
            onDismissRequest = { confirmStop = false },
            dismissOnOutsideClick = false,
            title = { Text(uiText("确认关闭传输站？")) },
            text = { Text(uiText("文件传输连接将立即关闭，尚未完成的发送或接收会被中断。")) },
            confirmButton = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    VaultActionButton(
                        onClick = { confirmStop = false },
                        style = VaultActionStyle.NEUTRAL,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(uiText("继续传输")) }
                    VaultActionButton(
                        onClick = {
                            confirmStop = false
                            onStop()
                        },
                        style = VaultActionStyle.DANGER,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(uiText("确认关闭")) }
                }
            },
        )
    }
}

/** 局域网三档滑块：左侧=建立传输站，中间=局域网同步（默认），右侧=文件传输。 */
enum class LanUiMode { HOST, SYNC, TRANSFER }

private data class SyncSegmentedControlVisuals(
    val selectedContainerColor: Color,
    val selectedContentColor: Color,
    val unselectedContainerColor: Color,
    val unselectedContentColor: Color,
    val controlAlpha: Float,
)

@Composable
private fun syncSegmentedControlVisuals(enabled: Boolean): SyncSegmentedControlVisuals {
    // 选中段填充与所在卡片同色（surface），明暗模式一致：像浅色那样“嵌在”轨道里，
    // 而不是深色模式用 primary 填充。
    return SyncSegmentedControlVisuals(
        selectedContainerColor = MaterialTheme.colorScheme.surface,
        selectedContentColor = MaterialTheme.colorScheme.onSurface,
        unselectedContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        unselectedContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        controlAlpha = if (enabled) 1f else 0.56f,
    )
}

@Composable
private fun LanModeSlider(
    mode: LanUiMode,
    enabled: Boolean,
    onModeChange: (LanUiMode) -> Unit,
) {
    val labels = listOf(
        LanUiMode.HOST to uiTabText("建立传输站"),
        LanUiMode.SYNC to uiTabText("局域网同步"),
        LanUiMode.TRANSFER to uiTabText("文件传输"),
    )
    val visuals = syncSegmentedControlVisuals(enabled)
    val selectedIndex = labels.indexOfFirst { it.first == mode }.coerceAtLeast(0)
    val capsuleShape = RoundedCornerShape(percent = 50)
    BoxWithConstraints(Modifier.fillMaxWidth().height(52.dp).alpha(visuals.controlAlpha)) {
        val segmentWidth = maxWidth / labels.size
        val thumbOffset by animateDpAsState(
            targetValue = segmentWidth * selectedIndex,
            animationSpec = tween(durationMillis = 220, easing = FastOutSlowInEasing),
            label = "lan-mode-thumb",
        )
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .clip(capsuleShape)
                .background(visuals.unselectedContainerColor),
        ) {
            Box(
                modifier = Modifier
                    .offset(x = thumbOffset)
                    .width(segmentWidth)
                    .fillMaxHeight()
                    .padding(4.dp)
                    .clip(capsuleShape)
                    .background(visuals.selectedContainerColor),
            )
            Row(Modifier.fillMaxSize()) {
                labels.forEach { (value, label) ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            // 与 CapsuleSegmentedControl（markdown/云端同步）一致：切换只滑动 thumb。
                            .clickable(
                                enabled = enabled && value != mode,
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                            ) { onModeChange(value) },
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            label,
                            style = MaterialTheme.typography.labelLarge.copy(
                                fontWeight = if (value == mode) FontWeight.SemiBold else FontWeight.Normal,
                            ),
                            textAlign = TextAlign.Center,
                            softWrap = false,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            color = if (value == mode) {
                                visuals.selectedContentColor
                            } else {
                                visuals.unselectedContentColor
                            },
                            modifier = Modifier.padding(horizontal = 2.dp),
                        )
                    }
                }
            }
        }
    }
}

/** 云端同步二档胶囊：左侧=云端硬盘，右侧=WebDAV。 */
@Composable
private fun CloudProviderSlider(
    mode: String,
    enabled: Boolean,
    onModeChange: (String) -> Unit,
) {
    CapsuleSegmentedControl(
        options = listOf(CapsuleOption(uiTabText("云端硬盘")), CapsuleOption("WebDAV")),
        selectedIndex = if (mode == "drive") 0 else 1,
        onSelected = { index -> onModeChange(if (index == 0) "drive" else "webdav") },
        enabled = enabled,
    )
}

@Composable
private fun RenameAccountDialog(
    oldName: String,
    onCancel: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var name by remember { mutableStateOf(oldName) }
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("重命名账户")) },
        text = {
            OutlinedTextField(value = name, onValueChange = { name = InputFilters.capLength(InputFilters.noWhitespace(it), 40) }, label = { Text(uiText("新账户名")) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        },
        confirmButton = { VaultActionButton(onClick = { onConfirm(name.trim()) }, style = VaultActionStyle.PRIMARY, enabled = name.isNotBlank() && name != oldName) { Text(uiText("确认")) } },
        dismissButton = { VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}

@Composable
private fun ChangePasswordDialog(
    keyVersion: Int,
    accountName: String,
    onCancel: () -> Unit,
    onConfirm: (String, Boolean, ByteArray) -> Unit,
) {
    var pendingWeak by remember { mutableStateOf<Boolean?>(null) }
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var showPw by remember { mutableStateOf(false) }
    var showPw2 by remember { mutableStateOf(false) }
    var highSecurityMode by remember { mutableStateOf(true) }
    var showWeakConfirmation by remember { mutableStateOf(false) }
    val assessment = rememberMasterPasswordAssessment(pw)
    val ok = pw.length >= InputFilters.MIN_MASTER_PASSWORD_LENGTH && pw == pw2 &&
        assessment.risk != MasterPasswordRisk.BLOCKED &&
        (!highSecurityMode || assessment.risk == MasterPasswordRisk.STRONG)
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    pendingWeak?.let { weak ->
        RecoveryKeyConfirmDialog(
            keyVersion = keyVersion,
            accountName = accountName,
            message = stringResource(R.string.password_rotation_recovery_message),
            onCancel = { pendingWeak = null },
            onConfirmed = { secret -> onConfirm(pw, weak, secret) },
        )
        return
    }
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("修改主密码")) },
        text = {
            Column {
                OutlinedTextField(value = pw, onValueChange = { pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128); showWeakConfirmation = false }, label = { Text(uiText("新主密码")) }, visualTransformation = if (showPw) VisualTransformation.None else PasswordVisualTransformation(), singleLine = true, modifier = Modifier.fillMaxWidth().focusRequester(focus), trailingIcon = { VaultVisibilityButton(visible = showPw, onClick = { showPw = !showPw }) })
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = pw2, onValueChange = { pw2 = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) }, label = { Text(uiText("再次输入")) }, visualTransformation = if (showPw2) VisualTransformation.None else PasswordVisualTransformation(), singleLine = true, isError = pw2.isNotEmpty() && pw2 != pw, modifier = Modifier.fillMaxWidth(), trailingIcon = { VaultVisibilityButton(visible = showPw2, onClick = { showPw2 = !showPw2 }) })
                Spacer(Modifier.height(8.dp))
                MasterPasswordPolicyControls(
                    assessment = assessment,
                    highSecurityMode = highSecurityMode,
                    onHighSecurityModeChange = {
                        highSecurityMode = it
                        showWeakConfirmation = false
                    },
                )
            }
        },
        confirmButton = {
            VaultActionButton(
                onClick = {
                    if (assessment.risk == MasterPasswordRisk.WEAK) {
                        showWeakConfirmation = true
                    } else {
                        pendingWeak = false
                    }
                },
                style = VaultActionStyle.PRIMARY,
                enabled = ok,
            ) { Text(uiText("确认")) }
        },
        dismissButton = { VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
    if (showWeakConfirmation) {
        WeakMasterPasswordConfirmDialog(
            onCancel = { showWeakConfirmation = false },
            onConfirm = {
                showWeakConfirmation = false
                pendingWeak = true
            },
        )
    }
}

@Composable
private fun ExportBackupDialog(
    requireStrongPassphrase: Boolean = false,
    onCancel: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    val strongEnough = com.vault.storage.BackupPasswordPolicy.isStrong(pw)
    val ok = pw == pw2 && strongEnough
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("设置导出口令")) },
        text = {
            Column {
                Text(uiText("加密备份使用独立的导出口令；与主密码无关。"), style = MaterialTheme.typography.bodySmall)
                if (requireStrongPassphrase) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        uiText("此备份包含 Passkey。导出口令至少 14 位并包含大小写字母、数字、符号中的三类。"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        uiText("导出口令至少 14 位并包含大小写字母、数字、符号中的三类。"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = pw, onValueChange = { pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) }, label = { Text(uiText("导出口令")) }, visualTransformation = PasswordVisualTransformation(), singleLine = true, modifier = Modifier.fillMaxWidth().focusRequester(focus))
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = pw2, onValueChange = { pw2 = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) }, label = { Text(uiText("再次输入")) }, visualTransformation = PasswordVisualTransformation(), singleLine = true, isError = pw2.isNotEmpty() && pw2 != pw, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = { VaultActionButton(onClick = { onConfirm(pw) }, style = VaultActionStyle.PRIMARY, enabled = ok) { Text(uiText("导出")) } },
        dismissButton = { VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}

@Composable
private fun ImportBackupDialog(onCancel: () -> Unit, onNext: (String) -> Unit) {
    var pw by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("输入备份口令")) },
        text = {
            Column {
                OutlinedTextField(value = pw, onValueChange = { pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) }, label = { Text(uiText("备份口令")) }, visualTransformation = PasswordVisualTransformation(), singleLine = true, modifier = Modifier.fillMaxWidth().focusRequester(focus))
            }
        },
        confirmButton = { VaultActionButton(onClick = { onNext(pw) }, style = VaultActionStyle.PRIMARY, enabled = pw.isNotEmpty()) { Text(uiText("下一步")) } },
        dismissButton = { VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}

@Composable
private fun ImportPolicyDialog(onCancel: () -> Unit, onPick: (VaultOps.MergeAction) -> Unit) {
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("冲突处理")) },
        text = { Text(uiText("当同名+同用户名条目内容不一致时，统一采用哪种策略？")) },
        confirmButton = {
            // M3 AlertDialog 会把 confirm/dismiss 横向排版，竖排三按钮 + 右下角 dismiss 会重叠；
            // 把全部 4 个动作统一放进 confirmButton 的 Column，dismissButton 留空
            Column(modifier = Modifier.fillMaxWidth()) {
                VaultActionButton(onClick = { onPick(VaultOps.MergeAction.OVERWRITE) }, style = VaultActionStyle.PRIMARY, modifier = Modifier.fillMaxWidth()) { Text(uiText("覆盖现有")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(onClick = { onPick(VaultOps.MergeAction.KEEP_BOTH) }, style = VaultActionStyle.NEUTRAL, modifier = Modifier.fillMaxWidth()) { Text(uiText("保留副本")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(onClick = { onPick(VaultOps.MergeAction.SKIP) }, style = VaultActionStyle.NEUTRAL, modifier = Modifier.fillMaxWidth()) { Text(uiText("跳过冲突")) }
                Spacer(Modifier.height(6.dp))
                VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL, modifier = Modifier.fillMaxWidth()) { Text(uiText("取消")) }
            }
        },
    )
}

@Composable
private fun CrossAccountMergeWarningDialog(
    sourceLabel: String,
    incomingDeviceId: String,
    incomingCount: Int,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
) {
    val lineageHint = if (incomingDeviceId.isEmpty())
        stringResource(R.string.settings_remaining_lineage_missing, sourceLabel)
    else
        stringResource(R.string.settings_remaining_lineage_mismatch, sourceLabel, incomingDeviceId.take(8))
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.settings_remaining_cross_account_merge_warning)) },
        text = {
            Column {
                Text(
                    uiText("这份${sourceLabel}数据看起来不是当前账户的同一份库。"),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    lineageHint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.settings_remaining_merge_risk, incomingCount),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    uiText("建议：仅在确认这两份库本就属于同一账户时继续；否则请取消，改用「在登录页新建账户后再导入」。"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { VaultActionButton(onClick = onConfirm, style = VaultActionStyle.PRIMARY) { Text(uiText("仍然合并")) } },
        dismissButton = { VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) { Text(uiText("取消")) } },
    )
}
