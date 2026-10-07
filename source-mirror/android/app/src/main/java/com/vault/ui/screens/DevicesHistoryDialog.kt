package com.vault.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.vault.storage.DeviceActivityProfile
import com.vault.storage.VaultHistoryRecord
import com.vault.storage.VaultHistoryPreview
import com.vault.ui.VaultViewModel
import com.vault.ui.localizeUiTextFor
import com.vault.ui.uiText
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/** Only authenticated preview entries enter the selection state; dismissal cancels pending work. */
@Composable
internal fun DevicesHistoryDialog(vm: VaultViewModel, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf(emptyList<DeviceActivityProfile>()) }
    var history by remember { mutableStateOf(emptyList<VaultHistoryRecord>()) }
    var selectedRecord by remember { mutableStateOf<VaultHistoryRecord?>(null) }
    var preview by remember { mutableStateOf<VaultHistoryPreview?>(null) }
    var selectedIds by remember { mutableStateOf(emptySet<String>()) }
    var password by remember { mutableStateOf("") }
    var previewPassword by remember { mutableStateOf<String?>(null) }
    var currentSequence by remember { mutableStateOf(0L) }
    var nickname by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var feedback by remember { mutableStateOf("") }
    var confirmRestore by remember { mutableStateOf(false) }
    val vaultState by vm.state.collectAsState()
    LaunchedEffect(vaultState.payload) {
        // A local edit invalidates the selection before a stale preview can be submitted.
        preview = null
        previewPassword = null
        selectedIds = emptySet()
        confirmRestore = false
    }
    fun runAction(action: suspend () -> Unit) {
        if (busy) return
        busy = true
        feedback = ""
        scope.launch {
            try { action() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) { feedback = localizeUiTextFor(context, error.message ?: "操作失败") }
            finally { busy = false }
        }
    }
    LaunchedEffect(vm) {
        busy = true
        try {
            devices = vm.deviceProfiles()
            nickname = devices.firstOrNull { it.isCurrent }?.name.orEmpty()
            history = vm.listHistory()
            currentSequence = vm.currentCommitSequence()
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (error: Exception) { feedback = localizeUiTextFor(context, error.message ?: "操作失败") }
        finally { busy = false }
    }
    VaultDialog(
        onDismissRequest = onDismiss,
        title = { Text(uiText("设备与历史版本")) },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(uiText("设备记录来自已认证的保险库。此处不提供服务器端设备撤销。"), style = MaterialTheme.typography.bodySmall)
                devices.forEach { device ->
                    Text(device.name.ifBlank { device.deviceId }, style = MaterialTheme.typography.titleSmall)
                    Text(listOf(device.platform, if (device.isCurrent) uiText("当前设备") else uiText("已认证设备记录"), if (device.lastSeenAt > 0) historyDisplayTime(device.lastSeenAt) else uiText("活动时间未知")).filter { it.isNotBlank() }.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                    Text(when (device.authorizationStatus) {
                        "authorized" -> uiText("签名授权有效")
                        "expired" -> uiText("签名授权已过期")
                        "revoked" -> uiText("保险库记录中授权已撤销")
                        else -> uiText("无已验证授权记录")
                    }, style = MaterialTheme.typography.bodySmall)
                }
                if (devices.any { it.isCurrent }) {
                    OutlinedTextField(nickname, { nickname = it.take(64) }, label = { Text(uiText("本机昵称")) }, singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
                    VaultActionButton(onClick = { runAction { vm.renameDevice(nickname.trim()); devices = vm.deviceProfiles(); currentSequence = vm.currentCommitSequence(); history = vm.listHistory(); preview = null; previewPassword = null; selectedIds = emptySet(); feedback = localizeUiTextFor(context, "设备昵称已保存") } }, enabled = !busy && nickname.isNotBlank()) { Text(uiText("保存昵称")) }
                }
                HorizontalDivider()
                Text(uiText("本地加密历史（20个常规版本与恢复前安全版本）"), style = MaterialTheme.typography.titleSmall)
                Text(uiText("历史仅保存在本机应用私有空间。恢复所选条目会创建新提交，并先保存恢复前版本；当前新增条目会保留。"), style = MaterialTheme.typography.bodySmall)
                VaultActionButton(onClick = { runAction { vm.createHistorySnapshot(); history = vm.listHistory(); currentSequence = vm.currentCommitSequence(); feedback = localizeUiTextFor(context, "历史版本已创建") } }, enabled = !busy) { Text(uiText("创建版本")) }
                Text(uiText("历史恢复暂不支持通行密钥和已永久删除的条目"), style = MaterialTheme.typography.bodySmall)
                if (history.isEmpty() && !busy) Text(uiText("暂无历史版本"))
                history.forEach { record ->
                    VaultActionButton(onClick = { selectedRecord = record; preview = null; previewPassword = null; selectedIds = emptySet(); password = ""; feedback = "" }, enabled = !busy, style = if (selectedRecord?.id == record.id) VaultActionStyle.PRIMARY else VaultActionStyle.NEUTRAL, modifier = Modifier.fillMaxWidth()) {
                        Text(historyDisplayTime(record.createdAt) + " · #" + record.sequence + " · " + if (record.sequence == currentSequence) uiText("当前版本") else uiText("历史快照"))
                    }
                }
                selectedRecord?.let { record ->
                    Text(uiText("历史版本预览需验证；若主密码已更改，请输入该版本使用的密码。"), style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(password, { password = it.take(128) }, label = { Text(uiText("历史主密码（可选）")) }, visualTransformation = PasswordVisualTransformation(), singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
                    VaultActionButton(onClick = { preview = null; previewPassword = null; selectedIds = emptySet(); val suppliedPassword = password.takeIf { it.isNotEmpty() }; password = ""; runAction { preview = vm.previewHistory(record.id, suppliedPassword); previewPassword = suppliedPassword } }, enabled = !busy) { Text(uiText("验证并预览")) }
                }
                preview?.let { authenticated ->
                    Text(uiText("选择要恢复的条目") + " (" + authenticated.entries.size + ")", style = MaterialTheme.typography.titleSmall)
                    if (authenticated.entries.isEmpty()) Text(uiText("此版本没有可恢复条目"))
                    authenticated.entries.forEach { entry ->
                        Row(Modifier.fillMaxWidth()) {
                            Checkbox(checked = entry.id in selectedIds, onCheckedChange = { checked -> selectedIds = if (checked) selectedIds + entry.id else selectedIds - entry.id }, enabled = !busy)
                            Column(Modifier.weight(1f).padding(top = 8.dp)) {
                                Text(entry.title.ifBlank { uiText("无标题") })
                                if (entry.username.isNotBlank()) Text(entry.username, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                    VaultActionButton(onClick = { confirmRestore = true }, enabled = !busy && selectedIds.isNotEmpty(), style = VaultActionStyle.PRIMARY) { Text(uiText("恢复所选条目")) }
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (feedback.isNotBlank()) Text(feedback, style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { VaultActionButton(onClick = onDismiss) { Text(uiText("关闭")) } },
    )
    if (confirmRestore) VaultDialog(
        onDismissRequest = { confirmRestore = false },
        title = { Text(uiText("确认恢复所选条目")) },
        text = { Text(uiText("同ID条目将以历史内容恢复。会先保存恢复前版本，并保留当前其他条目。")) },
        confirmButton = {
            VaultActionButton(onClick = {
                confirmRestore = false
                val authenticated = preview ?: return@VaultActionButton
                val ids = selectedIds
                runAction {
                    vm.restoreHistory(authenticated, ids, previewPassword)
                    preview = null; previewPassword = null; selectedIds = emptySet(); selectedRecord = null
                    history = vm.listHistory()
                    currentSequence = vm.currentCommitSequence()
                    feedback = localizeUiTextFor(context, "所选条目已恢复，恢复前版本已保存")
                }
            }, enabled = !busy && preview != null && selectedIds.isNotEmpty(), style = VaultActionStyle.PRIMARY) { Text(uiText("确认恢复")) }
        },
        dismissButton = { VaultActionButton(onClick = { confirmRestore = false }) { Text(uiText("取消")) } },
    )
}

internal fun historyDisplayTime(epochMillis: Long): String = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(epochMillis))
