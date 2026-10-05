package com.vault.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vault.R
import com.vault.security.MasterPasswordRisk
import com.vault.ui.InputFilters
import com.vault.ui.MasterPasswordPolicyControls
import com.vault.ui.VaultViewModel
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.WeakMasterPasswordConfirmDialog
import com.vault.ui.rememberMasterPasswordAssessment
import com.vault.ui.uiText
import com.vault.ui.scan.QrLiveScanActivity
import com.vault.ui.VaultShape

private fun pmvDisplayName(ctx: android.content.Context, uri: android.net.Uri): String {
    val name = ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        if (i >= 0 && c.moveToFirst()) c.getString(i) else null
    } ?: return ctx.getString(R.string.default_name)
    // 导入命名统一：去掉后缀后即为账户名，不再处理 vault_/vault- 前缀。
    return name.removeSuffix(".pmv").ifEmpty { ctx.getString(R.string.default_name) }
}

@Composable
fun WelcomeScreen(vm: VaultViewModel) {
    val ctx = LocalContext.current
    var showCreate by remember { mutableStateOf(false) }
    var showLanImportMethod by remember { mutableStateOf(false) }
    var pendingImportUri by remember { mutableStateOf<android.net.Uri?>(null) }
    var importPw by remember { mutableStateOf("") }
    var restoreTrashedName by remember { mutableStateOf<String?>(null) }
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        if (it != null) vm.validateImportFile(it) { pendingImportUri = it }
    }
    var pendingCameraAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val requestCameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) pendingCameraAction?.invoke()
        else {
            val host = ctx as? android.app.Activity
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
        vm.setExternalActionInProgress(false)
        if (res.resultCode != android.app.Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val raw = res.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT) ?: return@rememberLauncherForActivityResult
        if (com.vault.ui.scan.QrPayloadPolicy.parseSync(raw) != null) {
            vm.lanImportFromQr(raw)
        } else {
            Toast.makeText(ctx, ctx.getString(R.string.invalid_station_qr), Toast.LENGTH_SHORT).show()
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            painterResource(R.drawable.ic_launcher),
            contentDescription = null,
            tint = Color.Unspecified,
            modifier = Modifier.size(80.dp),
        )
        Spacer(Modifier.height(20.dp))
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            stringResource(R.string.local_encrypted_desktop),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(40.dp))
        VaultButton(
            onClick = { showCreate = true },
            shape = VaultShape,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text(stringResource(R.string.create_empty_vault), style = MaterialTheme.typography.titleMedium) }
        Spacer(Modifier.height(12.dp))
        VaultButton(
            onClick = { pickFile.launch(arrayOf("*/*")) },
            variant = VaultButtonVariant.OUTLINED,
            shape = VaultShape,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text(stringResource(R.string.import_pmv), style = MaterialTheme.typography.titleMedium) }
        Spacer(Modifier.height(12.dp))
        VaultButton(
            onClick = { showLanImportMethod = true },
            variant = VaultButtonVariant.OUTLINED,
            shape = VaultShape,
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) { Text(stringResource(R.string.lan_import), style = MaterialTheme.typography.titleMedium) }
    }

    if (showLanImportMethod) {
        LanImportMethodDialog(
            onDismiss = { showLanImportMethod = false },
            onScan = {
                showLanImportMethod = false
                if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                    pendingCameraAction = {
                        vm.setExternalActionInProgress(true)
                        qrImportLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_IMPORT))
                    }
                    requestCameraPermission.launch(Manifest.permission.CAMERA)
                } else {
                    vm.setExternalActionInProgress(true)
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

    // 恢复密钥确认前不创建库，因此不存在没有紧急槽位的账户。
    var pendingNew by remember { mutableStateOf<Triple<String, String, Boolean>?>(null) }
    if (showCreate) NameAndPasswordDialog(
        title = stringResource(R.string.create_account),
        confirmLabel = stringResource(R.string.next_step),
        forName = stringResource(R.string.default_name),
        askPassword = true,
        onCancel = { showCreate = false },
        onConfirm = { name, pw, weakConfirmed ->
            showCreate = false
            pendingNew = Triple(name, pw!!, weakConfirmed)
        },
        isNameInTrash = { vm.isTrashed(it) },
        onRestore = { name -> showCreate = false; vm.restoreVault(name) },
    )
    pendingNew?.let { (name, pw, weakConfirmed) ->
        RecoveryKeyConfirmDialog(
            keyVersion = 1,
            accountName = name,
            onCancel = { pendingNew = null },
            onConfirmed = { secret ->
                pendingNew = null
                vm.createNewVault(name, pw, secret, weakPasswordConfirmed = weakConfirmed)
            },
        )
    }

    pendingImportUri?.let { uri ->
        NameAndPasswordDialog(
            title = stringResource(R.string.import_to_new_vault),
            confirmLabel = stringResource(R.string.import_action),
            forName = pmvDisplayName(ctx, uri),
            askPassword = false,
            isNameInTrash = { vm.isTrashed(it) },
            validateName = vm::importAccountNameError,
            onRestore = { name -> restoreTrashedName = name },
            onCancel = { pendingImportUri = null; importPw = "" },
            onConfirm = { name, _, _ -> pendingImportUri = null; importPw = ""; vm.importVaultAs(name, uri) },
        )
    }
    val restoreName = restoreTrashedName
    if (restoreName != null) {
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
                        importPw = ""
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
}

/** 从另一台设备接收账户数据的进度弹窗（欢迎页与解锁页共用）。 */
@Composable
internal fun LanImportProgressDialog(vm: VaultViewModel) {
    val importState by vm.lanImportState.collectAsStateWithLifecycle()
    val retry by vm.lanImportIntegrityRetry.collectAsStateWithLifecycle()
    val conflict by vm.lanImportConflict.collectAsStateWithLifecycle()
    val state = importState
    if (state == null && retry == null && conflict == null) return
    if (state != null) {
        val title = when (state) {
            VaultViewModel.LanImportState.WaitingForExport -> stringResource(R.string.waiting_other_device)
            is VaultViewModel.LanImportState.Downloading -> stringResource(R.string.receiving_vault_data)
            VaultViewModel.LanImportState.Checking -> stringResource(R.string.checking_received_data)
            VaultViewModel.LanImportState.Saving -> stringResource(R.string.saving_vault)
        }
        VaultDialog(
            onDismissRequest = { vm.cancelLanImport() },
            dismissOnOutsideClick = false,
            properties = DialogProperties(decorFitsSystemWindows = false),
            onClose = { vm.cancelLanImport() },
            title = { Text(title) },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    when (state) {
                        VaultViewModel.LanImportState.WaitingForExport -> {
                            Text(
                                stringResource(R.string.confirm_on_other_device),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(
                                stringResource(R.string.copy_only_note),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                        is VaultViewModel.LanImportState.Downloading -> {
                            val percent = if (state.total > 0) {
                                (state.transferred.coerceIn(0L, state.total) * 100L / state.total).toInt()
                            } else null
                            Text(
                                if (percent != null) {
                                    stringResource(R.string.receiving_progress, percent)
                                } else {
                                    stringResource(R.string.receiving)
                                },
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            LinearProgressIndicator(
                                progress = (percent ?: 0).coerceIn(0, 100) / 100f,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        VaultViewModel.LanImportState.Checking -> {
                            Text(stringResource(R.string.verifying_received_data), style = MaterialTheme.typography.bodyMedium)
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                        VaultViewModel.LanImportState.Saving -> {
                            Text(stringResource(R.string.verified_adding), style = MaterialTheme.typography.bodyMedium)
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                VaultActionButton(onClick = { vm.cancelLanImport() }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
    retry?.let { r ->
        VaultDialog(
            onDismissRequest = { vm.cancelLanImportRetry() },
            dismissOnOutsideClick = false,
            properties = DialogProperties(decorFitsSystemWindows = false),
            onClose = { vm.cancelLanImportRetry() },
            title = { Text(stringResource(R.string.incomplete_data_title)) },
            text = {
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        stringResource(R.string.corrupted_data_note),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        stringResource(R.string.retry_receive_note, r.attempt, r.maxAttempts),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                VaultActionButton(onClick = { vm.confirmLanImportRetry() }, style = VaultActionStyle.PRIMARY) {
                    Text(stringResource(R.string.retry_receive))
                }
            },
            dismissButton = {
                VaultActionButton(onClick = { vm.cancelLanImportRetry() }) { Text(stringResource(R.string.stop_receiving)) }
            },
        )
    }
    conflict?.let { value ->
        VaultDialog(
            onDismissRequest = { vm.cancelLanImportConflict() },
            dismissOnOutsideClick = false,
            properties = DialogProperties(decorFitsSystemWindows = false),
            onClose = { vm.cancelLanImportConflict() },
            title = { Text(if (value.sameVault) {
                        stringResource(R.string.same_vault_title)
                    } else {
                        stringResource(R.string.vault_name_conflict)
                    }) },
            text = {
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        if (value.sameVault) {
                            stringResource(R.string.same_vault_note, value.sourceName, value.existingName)
                        } else {
                            stringResource(R.string.existing_vault_note, value.existingName)
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        stringResource(R.string.import_separately_note, value.suggestedName),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                VaultActionButton(onClick = { vm.confirmLanImportConflict() }, style = VaultActionStyle.PRIMARY) {
                    Text(stringResource(R.string.import_anyway))
                }
            },
            dismissButton = {
                VaultActionButton(onClick = { vm.cancelLanImportConflict() }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
}

@Composable
fun NameAndPasswordDialog(
    title: String,
    confirmLabel: String,
    forName: String,
    askPassword: Boolean,
    onCancel: () -> Unit,
    onConfirm: (String, String?, Boolean) -> Unit,
    validateName: (String) -> String? = { null },
    // 实时检测：若返回 true 表示该名字处于回收站，主密码栏置灰，按钮变"恢复账户"
    isNameInTrash: (String) -> Boolean = { false },
    onRestore: ((String) -> Unit)? = null,
) {
    var name by remember { mutableStateOf(forName) }
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var showPw by remember { mutableStateOf(false) }
    var showPw2 by remember { mutableStateOf(false) }
    var highSecurityMode by remember { mutableStateOf(true) }
    var showWeakConfirmation by remember { mutableStateOf(false) }
    val assessment = rememberMasterPasswordAssessment(pw)
    val trimmed = name.trim()
    val trashed = trimmed.isNotEmpty() && onRestore != null && isNameInTrash(trimmed)
    val nameError = validateName(trimmed)
    val nameOk = trimmed.isNotEmpty() && nameError == null
    val pwOk = !askPassword || (
        pw == pw2 && assessment.risk != MasterPasswordRisk.BLOCKED &&
            (!highSecurityMode || assessment.risk == MasterPasswordRisk.STRONG)
        )
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = InputFilters.capLength(InputFilters.noWhitespace(it), 40) },
                    label = { Text(stringResource(R.string.account_name_label)) },
                    singleLine = true,
                    isError = trashed || nameError != null,
                    supportingText = nameError?.let { error -> { Text(error) } },
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (trashed) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        stringResource(R.string.deleted_vault_restore_hint, trimmed),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (askPassword) {
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = pw,
                        onValueChange = {
                            pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128)
                            showWeakConfirmation = false
                        },
                        label = { Text(stringResource(R.string.master_password_min)) },
                        visualTransformation = if (showPw) VisualTransformation.None else PasswordVisualTransformation(),
                        singleLine = true,
                        enabled = !trashed,
                        trailingIcon = {
                            VaultVisibilityButton(
                                visible = showPw,
                                onClick = { showPw = !showPw },
                                enabled = !trashed,
                            )
                        },
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = pw2,
                        onValueChange = { pw2 = InputFilters.capLength(InputFilters.asciiPrintable(it), 128) },
                        label = { Text(stringResource(R.string.confirm_password_again)) },
                        visualTransformation = if (showPw2) VisualTransformation.None else PasswordVisualTransformation(),
                        singleLine = true,
                        enabled = !trashed,
                        isError = pw2.isNotEmpty() && pw2 != pw,
                        trailingIcon = {
                            VaultVisibilityButton(
                                visible = showPw2,
                                onClick = { showPw2 = !showPw2 },
                                enabled = !trashed,
                            )
                        },
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (!trashed) {
                        MasterPasswordPolicyControls(
                            assessment = assessment,
                            highSecurityMode = highSecurityMode,
                            onHighSecurityModeChange = {
                                highSecurityMode = it
                                showWeakConfirmation = false
                            },
                        )
                    }
                } else {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        stringResource(R.string.unlock_with_desktop_password),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            if (trashed) {
                VaultActionButton(
                    onClick = { onRestore!!(trimmed) },
                    enabled = nameOk,
                    style = VaultActionStyle.PRIMARY,
                ) { Text(stringResource(R.string.restore_vault)) }
            } else {
                VaultActionButton(
                    onClick = {
                        if (askPassword && assessment.risk == MasterPasswordRisk.WEAK) {
                            showWeakConfirmation = true
                        } else {
                            onConfirm(trimmed, if (askPassword) pw else null, false)
                        }
                    },
                    enabled = nameOk && pwOk,
                    style = VaultActionStyle.PRIMARY,
                ) { Text(confirmLabel) }
            }
        },
        dismissButton = { VaultActionButton(onClick = onCancel) { Text(stringResource(R.string.cancel)) } },
    )
    if (showWeakConfirmation) {
        WeakMasterPasswordConfirmDialog(
            onCancel = { showWeakConfirmation = false },
            onConfirm = {
                showWeakConfirmation = false
                onConfirm(trimmed, pw, true)
            },
        )
    }
}
