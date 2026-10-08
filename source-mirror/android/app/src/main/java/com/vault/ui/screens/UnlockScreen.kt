package com.vault.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.ui.BiasAlignment
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.shape.CircleShape
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import com.vault.ui.VaultDropdownMenu as DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.BlurredEdgeTreatment
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vault.R
import com.vault.model.Entry
import com.vault.model.VaultOps
import com.vault.ui.uiText
import com.vault.security.LockoutPref
import com.vault.ui.InputFilters
import com.vault.ui.VaultViewModel
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.scan.QrLiveScanActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import com.vault.ui.vaultShadow
import com.vault.ui.vaultBackdrop
import com.vault.ui.vaultBackdropSource
import com.vault.ui.VaultShape
import com.vault.ui.ThreeDotMotion

private fun pmvDisplayName(ctx: android.content.Context, uri: android.net.Uri): String {
    val name = ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        if (i >= 0 && c.moveToFirst()) c.getString(i) else null
    } ?: return ctx.getString(R.string.default_name)
    // 导入命名统一：去掉后缀后即为账户名，不再处理 vault_ 前缀。
    return name.removeSuffix(".pmv").ifEmpty { ctx.getString(R.string.default_name) }
}
@Composable
fun UnlockScreen(vm: VaultViewModel) {
    val ctx = LocalContext.current
    val focusManager = androidx.compose.ui.platform.LocalFocusManager.current
    val keyboardController = androidx.compose.ui.platform.LocalSoftwareKeyboardController.current
    val activity = ctx as? FragmentActivity
    val scope = rememberCoroutineScope()
    val state by vm.state.collectAsStateWithLifecycle()
    val currentVault by vm.currentVault.collectAsStateWithLifecycle()
    val vaults by vm.vaults.collectAsStateWithLifecycle()
    var pw by remember { mutableStateOf("") }
    var showPw by remember { mutableStateOf(false) }
    var showRecoveryAsk by remember { mutableStateOf(false) }
    var showCreate by remember { mutableStateOf(false) }
    val hasRecovery = remember(currentVault) { currentVault?.let(vm::hasRecoveryKey) == true }
    var addMenu by remember { mutableStateOf(false) }
    var addButtonWidthPx by remember { mutableIntStateOf(0) }
    var addButtonBoxLeftPx by remember { mutableFloatStateOf(0f) }
    var addButtonIconLeftPx by remember { mutableFloatStateOf(0f) }
    val addMenuDensity = LocalDensity.current
    val addButtonWidth = with(addMenuDensity) { addButtonWidthPx.toDp() }
    val addMenuIconOffset = with(addMenuDensity) {
        (addButtonIconLeftPx - addButtonBoxLeftPx).coerceIn(0f, Float.MAX_VALUE).toDp()
    }
    var pendingImportUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var bioInProgress by remember(currentVault) { mutableStateOf(false) }
    // 生物识别绑定一旦在本次会话被检测到失效（用户增删生物识别模板），立即隐藏按钮，避免重复点击
    var bioInvalidated by remember(currentVault) { mutableStateOf(false) }
    val bio = remember(currentVault) { currentVault?.let { vm.biometricFor(it) } }
    var bioAvailable by remember(currentVault, bioInvalidated) { mutableStateOf(false) }
    LaunchedEffect(currentVault, bioInvalidated) {
        bioAvailable = withContext(Dispatchers.IO) {
            !bioInvalidated && bio != null && bio.canAuthenticate(ctx) && bio.isEnrolled()
        }
    }

    // 冷却倒计时：每秒重算一次剩余秒数
    var cooldownSec by remember(currentVault) { mutableStateOf(0) }
    LaunchedEffect(currentVault) {
        while (true) {
            cooldownSec = withContext(Dispatchers.IO) {
                LockoutPref.remainingSeconds(LockoutPref.coolingRemainingMs(ctx))
            }
            delay(200L)
        }
    }
    val cooling = cooldownSec > 0
    val unlockBackground = remember { dev.chrisbanes.haze.HazeState() }
    val completed = state.unlockSuccess || state.phase == com.vault.ui.Phase.UNLOCKED
    val busy = bioInProgress || state.busy || completed
    // 生物识别弹窗期间不显示解锁进度容器/图标，只保留背景模糊模板；生物识别完成后才出现图标动画
    val showUnlockOverlay = state.busy || completed
    val blurAlpha by animateFloatAsState(if (busy) 1f else 0f, tween(220), label = "unlockBlur")
    val overlayAlpha by animateFloatAsState(if (showUnlockOverlay) 1f else 0f, tween(220), label = "unlockOverlay")

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        if (it != null) vm.validateImportFile(it) { pendingImportUri = it }
    }

    var showLanImportMethod by remember { mutableStateOf(false) }
    var pendingCameraAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val requestCameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) pendingCameraAction?.invoke()
        else {
            val host = ctx as? Activity
            val permanentlyDenied = host == null ||
                !ActivityCompat.shouldShowRequestPermissionRationale(host, Manifest.permission.CAMERA)
            Toast.makeText(
                ctx,
                if (permanentlyDenied) {
                    ctx.getString(R.string.camera_permission_denied)
                } else {
                    ctx.getString(R.string.camera_permission_required)
                },
                Toast.LENGTH_LONG,
            ).show()
        }
        pendingCameraAction = null
    }
    val qrImportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val raw = res.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT)
            ?: return@rememberLauncherForActivityResult
        vm.lanImportFromQr(raw)
    }

    LaunchedEffect(currentVault, bioAvailable) {
        if (bioAvailable && activity != null && bio != null && !bioInProgress) {
            bioInProgress = true
            runCatching { bio.unlock(activity) }
                .onSuccess { vm.unlockWithBiometric(it) }
                .onFailure { handleBioFailure(ctx, it, vm) { bioInvalidated = true } }
            bioInProgress = false
        }
    }

    // Follow IME insets directly; avoid a second animation lagging behind the keyboard.
    val loginDensity = LocalDensity.current
    val imeHeight = with(loginDensity) { WindowInsets.ime.getBottom(this).toDp() }
    val keyboardContentBias = (imeHeight.value / 280f).coerceIn(0f, 1f) * 0.2f
    Box(modifier = Modifier.fillMaxSize()) {
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                // 保留完整键盘避让；下方布局在剩余空间略偏下，减少整组内容的上移幅度。
                // 否则 edge-to-edge 下 adjustResize 不再生效，主密码输入框会被键盘盖住。
                .vaultBackdropSource(unlockBackground)
                .background(MaterialTheme.colorScheme.background)
                .imePadding(),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .vaultBackdropSource()
                    .heightIn(min = maxHeight)
                    .padding(horizontal = 28.dp)
                    ,
                verticalArrangement = Arrangement.spacedBy(0.dp, BiasAlignment.Vertical(keyboardContentBias)),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
            Icon(painterResource(R.drawable.ic_launcher), null, tint = Color.Unspecified, modifier = Modifier.size(64.dp))
            Spacer(Modifier.height(16.dp))
            Text(stringResource(R.string.unlock_vault), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)

            Spacer(Modifier.height(24.dp))

            Surface(
                shape = VaultShape,
                color = MaterialTheme.colorScheme.surface,
                tonalElevation = 0.dp,
                // 阴影与悬浮按钮（VaultFloatingBar）同款；无边框
                shadowElevation = 0.dp,
                modifier = Modifier.fillMaxWidth().vaultShadow(8.dp),
            ) {
                Column(Modifier.padding(16.dp)) {
                    // 用户选择 + ＋添加用户（对齐桌面端 user_combo + add_btn）
                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        UserDropdown(
                            current = currentVault,
                            users = vaults,
                            enabled = !busy,
                            onPick = { name -> if (name != currentVault) { pw = ""; vm.switchTo(name) } },
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(8.dp))
                        Box(
                            modifier = Modifier.onGloballyPositioned { addButtonBoxLeftPx = it.boundsInRoot().left },
                        ) {
                            VaultButton(
                                onClick = { addMenu = true },
                                enabled = !busy,
                                variant = VaultButtonVariant.TEXT,
                                shape = VaultShape,
                                modifier = Modifier
                                    .height(56.dp)
                                    .onSizeChanged { addButtonWidthPx = it.width },
                            ) {
                                Icon(
                                    Icons.Default.Add,
                                    null,
                                    modifier = Modifier
                                        .size(18.dp)
                                        .onGloballyPositioned { addButtonIconLeftPx = it.boundsInRoot().left },
                                )
                                Spacer(Modifier.width(4.dp))
                                Text(
                                    stringResource(R.string.add_account),
                                )
                            }
                            DropdownMenu(
                                expanded = addMenu,
                                onDismissRequest = { addMenu = false },
                                containerColor = popupMenuSurface(),
                                modifier = Modifier.width(addButtonWidth),
                            ) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.create_account)) },
                                    onClick = { addMenu = false; showCreate = true },
                                    contentPadding = PaddingValues(start = addMenuIconOffset, end = 12.dp),
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.import_pmv)) },
                                    onClick = { addMenu = false; importLauncher.launch(arrayOf("*/*")) },
                                    contentPadding = PaddingValues(start = addMenuIconOffset, end = 12.dp),
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.lan_import)) },
                                    onClick = { addMenu = false; showLanImportMethod = true },
                                    contentPadding = PaddingValues(start = addMenuIconOffset, end = 12.dp),
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = pw,
                            onValueChange = { pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) },
                            visualTransformation = if (showPw) VisualTransformation.None else PasswordVisualTransformation(),
                            placeholder = { Text(stringResource(R.string.master_password)) },
                            singleLine = true,
                            enabled = !busy && currentVault != null,
                            shape = VaultShape,
                            trailingIcon = {
                                VaultVisibilityButton(
                                    visible = showPw,
                                    onClick = { showPw = !showPw },
                                    enabled = currentVault != null && !busy,
                                )
                            },
                            modifier = Modifier.weight(1f),
                        )
                        if (bioAvailable && activity != null && bio != null) {
                            Spacer(Modifier.width(8.dp))
                            Box(
                                modifier = Modifier
                                    .size(50.dp)
                                    .clip(CircleShape)
                                    .background(Color.Transparent)
                                    .clickable(enabled = !busy) {
                                        if (bioInProgress) return@clickable
                                        bioInProgress = true
                                        scope.launch {
                                            runCatching { bio.unlock(activity) }
                                                .onSuccess { vm.unlockWithBiometric(it) }
                                                .onFailure { handleBioFailure(ctx, it, vm) { bioInvalidated = true } }
                                            bioInProgress = false
                                        }
                                    },
                                contentAlignment = Alignment.Center,
                            ) {
                                if (bioInProgress) {
                                    CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.dp)
                                } else {
                                Icon(
                                    painterResource(R.drawable.ic_biometric_tap),
                                    contentDescription = stringResource(R.string.unlock_biometric),
                                    // 矢量为单色图形：保持原始颜色，不做主题染色
                                    tint = Color.Unspecified,
                                    modifier = Modifier.size(46.dp),
                                )
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
            VaultButton(
                onClick = {
                    focusManager.clearFocus(force = true)
                    keyboardController?.hide()
                    val submitted = pw
                    pw = ""
                    vm.unlock(submitted)
                },
                enabled = pw.isNotEmpty() && !busy && !cooling && currentVault != null,
                shape = VaultShape,
                modifier = Modifier.fillMaxWidth().height(50.dp),
            ) {
                Text(
                    if (cooling) stringResource(R.string.cooling_retry_button, cooldownSec)
                    else stringResource(if (state.busy) R.string.unlocking_progress else R.string.unlock),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            Spacer(Modifier.height(8.dp))
            if (hasRecovery) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    TextButton(onClick = { showRecoveryAsk = true }, enabled = !busy && currentVault != null) {
                        Text(stringResource(R.string.forgot_password))
                    }
                }
            }
            // 解锁前不提供"删除账户"入口：
            // 该入口在解锁前可达，攻击者拿到设备即可清空整个保险库，风险大于收益。
            // 用户若确需清库，请到设置页（已解锁后）进行账户删除。
        }
        }

        if (busy || blurAlpha > 0f) {
            Box(Modifier.fillMaxSize().graphicsLayer { alpha = blurAlpha }
                .vaultBackdrop(shape = androidx.compose.ui.graphics.RectangleShape,
                    baseColor = MaterialTheme.colorScheme.background, state = unlockBackground))
        }
        if (showUnlockOverlay || overlayAlpha > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .graphicsLayer { alpha = overlayAlpha }
                    .background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.3f))
                    .pointerInput(showUnlockOverlay) { detectTapGestures { /* 吞掉点击 */ } },
                contentAlignment = Alignment.Center,
            ) {
                // 三点等待 / 成功对勾共用小尺寸白色圆角卡片。
                // 固定指示区域和安全内边距，避免变换时卡片抖动或裁切。
                val dark = MaterialTheme.colorScheme.background.luminance() < 0.5f
                val indicatorWidth = 54.dp
                val indicatorHeight = 40.dp
                Surface(
                    shape = VaultShape,
                    color = if (dark) Color.Black else Color.White,
                    tonalElevation = 0.dp,
                    modifier = Modifier.vaultShadow(6.dp),
                    shadowElevation = 0.dp,
                ) {
                    Box(
                        modifier = Modifier
                            .wrapContentSize()
                            .padding(horizontal = 12.dp, vertical = 12.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        UnlockProgressIndicator(
                            success = completed,
                            onSuccessAnimationFinished = vm::completeUnlockAnimation,
                            width = indicatorWidth,
                            height = indicatorHeight,
                        )
                    }
                }
            }
        }
    }

    if (showRecoveryAsk) {
        RecoveryKeyUnlockDialog(
            onCancel = { showRecoveryAsk = false },
            onConfirm = { key ->
                showRecoveryAsk = false
                vm.unlockViaRecoveryKey(key)
            },
        )
    }

    // 两步串行：账户名+主密码 → 恢复密钥。在第二步完成前不调用 createNewVault，
    // 避免 phase 变化导致 UnlockScreen 卸载、对话框消失。
    var pendingNewAccount by remember { mutableStateOf<Pair<String, String>?>(null) }
    if (showCreate) NameAndPasswordDialog(
        title = stringResource(R.string.create_account),
        confirmLabel = stringResource(R.string.next_step),
        forName = if (vaults.isEmpty()) {
            stringResource(R.string.default_name)
        } else {
            stringResource(R.string.account_index_name, vaults.size + 1)
        },
        askPassword = true,
        onCancel = { showCreate = false },
        onConfirm = { name, p, _ -> showCreate = false; pendingNewAccount = name to p!! },
        isNameInTrash = { vm.isTrashed(it) },
        onRestore = { name -> showCreate = false; vm.restoreVault(name) },
    )
    pendingNewAccount?.let { (name, pw) ->
        RecoveryKeyConfirmDialog(
            keyVersion = 1,
            accountName = name,
            onCancel = { pendingNewAccount = null },
            onConfirmed = { secret ->
                pendingNewAccount = null
                vm.createNewVault(name, pw, secret)
            },
        )
    }
    var restoreTrashedName by remember { mutableStateOf<String?>(null) }
    pendingImportUri?.let { uri ->
        NameAndPasswordDialog(
            title = stringResource(R.string.import_to_new_vault),
            confirmLabel = stringResource(R.string.import_action),
            forName = pmvDisplayName(ctx, uri),
            askPassword = false,
            isNameInTrash = { vm.isTrashed(it) },
            validateName = vm::importAccountNameError,
            onRestore = { name -> restoreTrashedName = name },
            onCancel = { pendingImportUri = null },
            onConfirm = { name, _, _ -> pendingImportUri = null; vm.importVaultAs(name, uri) },
        )
    }
    val restoreName = restoreTrashedName
    if (restoreName != null && pendingImportUri != null) {
        var restorePw by remember(restoreName) { mutableStateOf("") }
        VaultDialog(
            onDismissRequest = { restoreTrashedName = null },
            title = { Text(stringResource(R.string.verify_deleted_vault)) },
            text = {
                Column {
                    Text(
                        stringResource(R.string.deleted_vault_verify_text, restoreName),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = restorePw,
                        onValueChange = { restorePw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) },
                        label = { Text(stringResource(R.string.original_master_password)) },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        val pw = restorePw
                        val nm = restoreName
                        val u = pendingImportUri
                        restoreTrashedName = null
                        pendingImportUri = null
                        vm.importVaultAsOverTrash(nm, pw, u!!)
                    },
                    enabled = restorePw.isNotEmpty(),
                    style = VaultActionStyle.PRIMARY,
                ) { Text(stringResource(R.string.verify_and_import)) }
            },
            dismissButton = {
                VaultActionButton(
                    onClick = { restoreTrashedName = null },
                ) { Text(stringResource(R.string.cancel)) }
            },
        )
    }

    // 局域网导入：方法选择 + 接收流程（安全验证 → 校验码 → 下载 → 预览/冲突 → 创建新账户）
    if (showLanImportMethod) {
        LanImportMethodDialog(
            onDismiss = { showLanImportMethod = false },
            onScan = {
                showLanImportMethod = false
                if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    pendingCameraAction = {
                        qrImportLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_IMPORT))
                    }
                    requestCameraPermission.launch(Manifest.permission.CAMERA)
                } else {
                    qrImportLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_IMPORT))
                }
            },
            onManual = { address ->
                showLanImportMethod = false
                vm.lanImportManual(address)
            },
        )
    }
    LanImportProgressDialog(vm)

}

/**
 * 生物识别解锁失败统一处理：
 *  - [com.vault.security.BiometricVault.BiometricKeyInvalidated] → 用户增删生物识别模板后旧密钥已失效，
 *    `bio.unlock` 内部已自动 clear，本层把按钮藏起 + 提示让用户回落到主密码或去设置重启
 *  - [com.vault.security.BiometricVault.BiometricCancelled] → 用户主动取消 / 系统弹窗超时，静默
 *  - 其他异常 → 兜底文案
 */
private fun handleBioFailure(
    ctx: android.content.Context,
    cause: Throwable,
    vm: VaultViewModel,
    onInvalidated: () -> Unit,
) {
    when (cause) {
        is com.vault.security.BiometricVault.BiometricKeyInvalidated -> {
            onInvalidated()
            vm.postError(ctx.getString(R.string.biometric_changed_error))
        }
        is com.vault.security.BiometricVault.BiometricCancelled -> {
            // 用户取消生物提示——什么都不做，回到主密码输入即可
        }
        else -> vm.postError(cause.message ?: ctx.getString(R.string.biometric_unlock_failed))
    }
}

/** 等待时三点从左向右呼吸；成功时点淡出，仅绘制对勾，并交接首屏。 */
@Composable
private fun UnlockProgressIndicator(success: Boolean, onSuccessAnimationFinished: () -> Unit, width: Dp = 54.dp, height: Dp = 40.dp) {
    // 每帧只更新三点的绘制，白色容器和背景保持固定。
    var elapsedMillis by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(success) {
        var lastNanos = withFrameNanos { it }
        while (!success) {
            val now = withFrameNanos { it }
            elapsedMillis = (elapsedMillis + (now - lastNanos) / 1_000_000f) % ThreeDotMotion.PERIOD_MS
            lastNanos = now
        }
    }
    val dotsAlpha = remember { androidx.compose.animation.core.Animatable(if (success) 0f else 1f) }
    val checkAnim = remember { androidx.compose.animation.core.Animatable(0f) }
    val latestOnFinished by rememberUpdatedState(onSuccessAnimationFinished)
    LaunchedEffect(success) {
        checkAnim.snapTo(0f)
        if (!success) dotsAlpha.snapTo(1f)
        if (success) {
            // 等待点淡出；成功图形只保留对勾。
            if (dotsAlpha.value > 0f) dotsAlpha.animateTo(0f, tween(100))
            checkAnim.animateTo(
                targetValue = 1f,
                animationSpec = androidx.compose.animation.core.tween(
                    durationMillis = 240,
                    easing = androidx.compose.animation.core.FastOutSlowInEasing,
                ),
            )
            // 保留完整对勾至少一帧以上，再通知 ViewModel 挂载主页。
            delay(60)
            latestOnFinished()
        }
    }
    val primary = MaterialTheme.colorScheme.primary
    androidx.compose.foundation.Canvas(modifier = Modifier.size(width, height)) {
        // 逐帧状态只在绘制阶段读取，避免解锁关键路径上的整组件逐帧重组。
        val restingDotRadius = minOf(size.height / 6f, size.width / 15f)
        val stroke = androidx.compose.ui.graphics.drawscope.Stroke(
            width = 5.dp.toPx(),
            cap = androidx.compose.ui.graphics.StrokeCap.Round,
            join = androidx.compose.ui.graphics.StrokeJoin.Round,
        )
        if (dotsAlpha.value > 0f) {
            val radius = restingDotRadius
            repeat(3) { index ->
                drawCircle(
                    color = primary.copy(alpha = dotsAlpha.value),
                    radius = radius * ThreeDotMotion.scale(elapsedMillis, index),
                    center = androidx.compose.ui.geometry.Offset(size.width * (index + 0.5f) / 3f, size.height / 2f),
                )
            }
        }
        if (success) {
            val tickFrac = checkAnim.value.coerceIn(0f, 1f)
            if (tickFrac > 0f) {
                val w = minOf(size.width, size.height)
                val h = size.height
                val inset = (size.width - w) / 2f
                val p0 = androidx.compose.ui.geometry.Offset(inset + w * 0.24f, h * 0.52f)
                val p1 = androidx.compose.ui.geometry.Offset(inset + w * 0.43f, h * 0.70f)
                val p2 = androidx.compose.ui.geometry.Offset(inset + w * 0.80f, h * 0.32f)
                val seg1Len = (p1 - p0).getDistance()
                val seg2Len = (p2 - p1).getDistance()
                val total = seg1Len + seg2Len
                val drawn = total * tickFrac
                val path = androidx.compose.ui.graphics.Path().apply {
                    moveTo(p0.x, p0.y)
                    if (drawn <= seg1Len) {
                        val t = drawn / seg1Len
                        lineTo(p0.x + (p1.x - p0.x) * t, p0.y + (p1.y - p0.y) * t)
                    } else {
                        lineTo(p1.x, p1.y)
                        val t = (drawn - seg1Len) / seg2Len
                        lineTo(p1.x + (p2.x - p1.x) * t, p1.y + (p2.y - p1.y) * t)
                    }
                }
                drawPath(
                    path = path,
                    color = primary,
                    style = stroke,
                )
            }
        }
    }
}

/** 用户下拉选择器：仿桌面端 QComboBox。只读 OutlinedTextField + 透明点击层 + DropdownMenu。 */
@Composable
private fun UserDropdown(
    current: String?,
    users: List<String>,
    enabled: Boolean,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    val canChooseUser = enabled && users.size > 1
    LaunchedEffect(canChooseUser) { if (!canChooseUser) expanded = false }
    BoxWithConstraints(modifier = modifier) {
        // 用户名只作纯文字展示，无输入框底色/描边/下划线外框（容器透明），点击仍可展开账户选择。
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp)
                .padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Default.Person, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.width(10.dp))
            Text(
                current ?: stringResource(R.string.no_vault),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            if (users.size > 1) {
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Box(
            modifier = Modifier
                .matchParentSize()
                .clip(VaultShape)
                .clickable(enabled = canChooseUser) { expanded = true },
        )
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            // 下拉框至少与用户名按钮同宽，同时保留公共最大宽度限制。
            modifier = Modifier.wrapContentWidth().widthIn(min = minOf(maxWidth, 320.dp), max = 320.dp),
            containerColor = popupMenuSurface(),
        ) {
            if (users.isEmpty()) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.no_vault_hint), color = MaterialTheme.colorScheme.onSurfaceVariant) },
                    onClick = { expanded = false },
                )
            } else {
                for (u in users) {
                    DropdownMenuItem(
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Person, null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(u, fontWeight = if (u == current) FontWeight.Bold else FontWeight.Normal)
                            }
                        },
                        onClick = { expanded = false; onPick(u) },
                        trailingIcon = if (u == current) {
                            { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                        } else null,
                    )
                }
            }
        }
    }
}

// ── 局域网导入（登录页·接收端） ─────────────────────────────────

/** 选择导入方式：扫码或手动输入发送端地址与一次性连接码。 */
@Composable
internal fun LanImportMethodDialog(
    onDismiss: () -> Unit,
    onScan: () -> Unit,
    onManual: (address: String) -> Unit,
) {
    var address by remember { mutableStateOf("") }
    VaultDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.lan_import)) },
        text = {
            Column(Modifier.fillMaxWidth()) {
                VaultActionButton(
                    onClick = onScan,
                    style = VaultActionStyle.PRIMARY,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Default.QrCodeScanner, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.scan_qr_import))
                }
                Spacer(Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.manual_station_address), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it.take(200) },
                    label = { Text(stringResource(R.string.station_address)) },
                    placeholder = { Text("https://192.168.1.10:18765/api/sync/vault?ticket=…&pin=…") },
                    singleLine = true,
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
            }
        },
        confirmButton = {
            VaultActionButton(
                onClick = { onManual(address) },
                enabled = address.isNotBlank() &&
                    com.vault.storage.SyncClient.embeddedPin(address.trim()) != null,
                style = VaultActionStyle.PRIMARY,
            ) { Text(stringResource(R.string.start_import)) }
        },
        dismissButton = {
            VaultActionButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}
