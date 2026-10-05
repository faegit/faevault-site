package com.vault.ui.screens

import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import com.vault.ui.VaultDropdownMenu as DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.size
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import com.vault.crypto.RecoveryKeyCodec
import com.vault.R
import com.vault.ui.InputFilters
import com.vault.ui.copySensitive
import com.vault.ui.localizeUiTextFor
import com.vault.ui.uiText
import com.vault.ui.VaultShape

/** 只有完成随机三组复核后才会把新密钥交给调用方落盘。 */
@Composable
fun RecoveryKeyConfirmDialog(
    title: String? = null,
    message: String? = null,
    // 该恢复密钥生效后所属的保险库密钥版本（新建为 1，重新生成为当前版本 +1）。
    keyVersion: Int = 0,
    // 「用户名」= 当前账户名：恢复单标题与文件名用账户名前缀替代「保险库」，空账户回退「保险库」。
    accountName: String = "",
    onCancel: () -> Unit,
    onConfirmed: (ByteArray) -> Unit,
    // 外部提供草稿则复用，不重新生成：锁定/重进弹窗后密钥保持一致，流程可恢复。
    draft: Pair<ByteArray, String>? = null,
) {
    val context = LocalContext.current
    val dialogTitle = title ?: stringResource(R.string.settings_remaining_save_recovery_key)
    val dialogMessage = message ?: stringResource(R.string.settings_remaining_recovery_warning)
    val generated = remember { draft ?: RecoveryKeyCodec.generateRecoveryKey() }
    val groups = remember(generated.second) { generated.second.removePrefix("${RecoveryKeyCodec.RECOVERY_PREFIX}-").split('-') }
    val checks = remember(generated.second) { groups.indices.shuffled().take(3).sorted() }
    val candidates = remember(generated.second, checks) {
        checks.associateWith { index ->
            (groups.distinct().filter { it != groups[index] }.shuffled().take(4) + groups[index]).shuffled()
        }
    }
    var answers by remember { mutableStateOf(checks.associateWith { "" }) }
    var expandedFor by remember { mutableStateOf<Int?>(null) }
    var savedWith by remember { mutableStateOf<String?>(null) }
    var wrongCount by remember { mutableStateOf(0) }
    var wrongMessage by remember { mutableStateOf<String?>(null) }
    // 三个下拉框都作答即可点击统一验证；对错在点击「完成核对并继续」时一并判定。
    val answeredAll = checks.all { !answers[it].isNullOrEmpty() }
    val verificationRestartMessage = stringResource(R.string.settings_remaining_recovery_verify_restarted)
    val verificationWrongFormat = stringResource(R.string.settings_remaining_recovery_verify_wrong)
    val verificationGroupFormat = stringResource(R.string.settings_remaining_recovery_verify_group)
    // 账户名优先：新建库用账户名，重新生成/重发用当前账户名；为空则回退「保险库」
    val keyOwner = accountName.ifBlank { uiText("保险库") }
    val recoverySheetTitle = "${uiText("${keyOwner}紧急恢复密钥")} v$keyVersion"
    val recoverySheetDate = uiText(
        "保存日期：${java.time.LocalDate.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd"))}",
    )
    val recoverySheetWarning = uiText("请离线保存，不要与主密码放在一起。")
    val recoveryKeyLabel = uiText("恢复密钥")
    val recoveryFileName = uiText("${keyOwner}恢复密钥") + ".txt"
    val copiedKeyText = uiText("复制密钥")
    val savedSheetText = uiText("保存恢复单")
    val copiedDoneText = uiText("已复制")
    val recoverySheetText = "$recoverySheetTitle\n$recoverySheetDate\n\n${generated.second}\n\n$recoverySheetWarning"
    val saveRecoveryLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                    output.write(recoverySheetText.toByteArray(Charsets.UTF_8))
                } ?: error("无法写入恢复单文件")
                savedWith = savedSheetText
            }.onFailure { error ->
                Toast.makeText(
                    context,
                    localizeUiTextFor(context, "保存恢复单失败：${error.message ?: "未知错误"}"),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    VaultDialog(
        onDismissRequest = onCancel,
        dismissOnOutsideClick = false,
        // 不可被返回键/选择器往返关闭：去保存恢复单再回来时弹窗与密钥数据必须保留，
        // 取消统一走标题栏 X 按钮或明确操作。
        properties = DialogProperties(decorFitsSystemWindows = false, dismissOnBackPress = false),
        onClose = onCancel,
        title = { Text(dialogTitle) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(dialogMessage, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                Spacer(Modifier.height(12.dp))
                Surface(
                    color = MaterialTheme.colorScheme.surfaceContainer,
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(14.dp)) {
                        Text(uiText("仅显示一次"), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.height(6.dp))
                        if (savedWith != null) {
                            Text(
                                uiText("密钥内容已隐藏，请从你保存的位置参考。"),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        } else {
                            Text(
                                generated.second,
                                style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                            )
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    VaultActionButton(
                        onClick = {
                            // 复制完整恢复单（标题 + 密钥 + 用途说明），避免之后忘记该密钥用途；
                            // 走敏感剪贴板：自动按 TTL 清空并标记系统敏感。
                            copySensitive(context, recoveryKeyLabel, recoverySheetText)
                            savedWith = copiedKeyText
                        },
                        modifier = Modifier.weight(1f),
                    ) { Text(if (savedWith == copiedKeyText) copiedDoneText else copiedKeyText) }
                    VaultActionButton(
                        onClick = { saveRecoveryLauncher.launch(recoveryFileName) },
                        modifier = Modifier.weight(1f),
                        style = VaultActionStyle.PRIMARY,
                    ) { Text(uiText("保存恢复单")) }
                }
                if (wrongMessage != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        uiText(wrongMessage.orEmpty()),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(10.dp))
                AnimatedVisibility(visible = savedWith != null) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceContainer,
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(14.dp)) {
                            Text(uiText("第 2 步 · 核对已保存内容"), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(4.dp))
                            Text(
                                if (savedWith == copiedKeyText) stringResource(R.string.settings_remaining_copied_verify_help)
                                else stringResource(R.string.settings_remaining_saved_verify_help),
                                style = MaterialTheme.typography.bodySmall,
                            )
                            checks.forEach { index ->
                                Spacer(Modifier.height(8.dp))
                                Box(Modifier.fillMaxWidth()) {
                                    VaultActionButton(
                                        onClick = { expandedFor = index },
                                        style = VaultActionStyle.PRIMARY,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(
                                            answers[index]?.takeIf { it.isNotEmpty() }
                                                ?.let { stringResource(R.string.settings_remaining_group_selected, index + 2, it) }
                                                ?: stringResource(R.string.settings_remaining_group_select, index + 2),
                                        )
                                    }
                                    DropdownMenu(
                                        expanded = expandedFor == index,
                                        onDismissRequest = { expandedFor = null },
                                        containerColor = popupMenuSurface(),
                                    ) {
                                        candidates[index].orEmpty().forEach { candidate ->
                                            DropdownMenuItem(
                                                text = { Text(candidate, fontFamily = FontFamily.Monospace) },
                                                onClick = {
                                                    // 选择阶段不提示对错：三个下拉框全部选完后再统一验证。
                                                    answers = answers + (index to candidate)
                                                    expandedFor = null
                                                },
                                                trailingIcon = if (answers[index] == candidate) {
                                                    { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                                                } else null,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (savedWith != null) {
                VaultActionButton(
                    onClick = {
                        val wrongGroups = checks.filter { answers[it] != groups[it] }
                        if (wrongGroups.isEmpty()) {
                            onConfirmed(generated.first.copyOf())
                            return@VaultActionButton
                        }
                        val next = wrongCount + 1
                        if (next >= 5) {
                            // 连续 5 次验证错误：重新走保存流程（密钥重新展示，需重新保存并核对）。
                            answers = checks.associateWith { "" }
                            savedWith = null
                            wrongCount = 0
                            wrongMessage = verificationRestartMessage
                        } else {
                            wrongCount = next
                            val labels = wrongGroups.joinToString(", ") { verificationGroupFormat.format(it + 2) }
                            wrongMessage = verificationWrongFormat.format(labels)
                        }
                    },
                    enabled = answeredAll,
                    style = VaultActionStyle.PRIMARY,
                ) { Text(uiText("完成核对并继续")) }
            }
        },
    )
}
@Composable
fun RecoveryKeyUnlockDialog(
    onCancel: () -> Unit,
    onConfirm: (key: String) -> Unit,
) {
    var key by remember { mutableStateOf("") }
    val valid = runCatching { RecoveryKeyCodec.decodeRecoveryKey(key) }.isSuccess
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("使用恢复密钥")) },
        text = {
            Column {
                Text(
                    uiText("输入完整恢复密钥以解锁。解锁后将立即进入「重新保存恢复密钥」和「设置新主密码」流程，请按提示完成。"),
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = key,
                    onValueChange = { key = InputFilters.capLength(it, 100) },
                    label = { Text(uiText("恢复密钥")) },
                    minLines = 2,
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = { VaultActionButton(onClick = { onConfirm(key) }, enabled = valid, style = VaultActionStyle.PRIMARY) { Text(uiText("验证并解锁")) } },
        dismissButton = { VaultActionButton(onClick = onCancel) { Text(uiText("取消")) } },
    )
}
