package com.vault.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import com.vault.storage.DeviceActivityProfile
import com.vault.ui.VaultViewModel
import com.vault.ui.localizeUiTextFor
import com.vault.ui.uiText
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@Composable
internal fun DevicesDialog(vm: VaultViewModel, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // Reserve the viewport before IO completes; growing content must not recenter the entering card.
    val bodyHeight = (LocalConfiguration.current.screenHeightDp.dp - 200.dp).coerceIn(120.dp, 360.dp)
    var devices by remember { mutableStateOf(emptyList<DeviceActivityProfile>()) }
    val state by vm.state.collectAsState()
    val vault by vm.currentVault.collectAsState()
    var selectedRoot by remember { mutableStateOf<com.vault.security.VaultSessionCredential.RootKey?>(null) }
    var selected by remember { mutableStateOf<DeviceActivityProfile?>(null) }
    var busy by remember { mutableStateOf(true) }
    var loading by remember { mutableStateOf(false) }
    var feedback by remember { mutableStateOf("") }
    suspend fun load() {
        if (loading || selected != null) return
        loading = true
        selected = null
        busy = true
        feedback = ""
        val rootAtLoad = vm.state.value.rootKey
        try {
            val loaded = vm.deviceProfiles()
            if (vm.state.value.rootKey === rootAtLoad && vm.state.value.phase == com.vault.ui.Phase.UNLOCKED) devices = loaded
        }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (error: Exception) { feedback = localizeUiTextFor(context, error.message ?: "操作失败") }
        finally { busy = false; loading = false }
    }
    LaunchedEffect(state.phase, vault, state.rootKey) {
        selected = null
        if (state.phase != com.vault.ui.Phase.UNLOCKED) { devices = emptyList(); onDismiss() }
    }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, vm) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) scope.launch { load() }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    VaultDialog(
        onDismissRequest = onDismiss,
        title = { Text(uiText("设备记录")) },
        text = {
            Column(
                Modifier.fillMaxWidth().height(bodyHeight).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(uiText("设备名称自动读取系统设置；其他设备显示其最近同步的名称。"), style = MaterialTheme.typography.bodySmall)
                devices.forEach { device ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(device.name.ifBlank { uiText("未知设备") }, style = MaterialTheme.typography.titleSmall)
                            Text(listOf(device.platform, if (device.isCurrent) uiText("当前设备") else uiText("已认证设备记录"),
                                if (device.lastSeenAt > 0) deviceActivityDisplayTime(device.lastSeenAt) else uiText("活动时间未知"))
                                .filter { it.isNotBlank() }.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                            Text(when (device.authorizationStatus) {
                                "authorized" -> uiText("签名授权有效")
                                "expired" -> uiText("签名授权已过期")
                                "revoked" -> uiText("保险库记录中授权已撤销")
                                else -> uiText("无已验证授权记录")
                            }, style = MaterialTheme.typography.bodySmall)
                            if (!device.isCurrent) VaultActionButton(onClick = { selectedRoot = state.rootKey; selected = device }, enabled = !busy) { Text(uiText("移除设备")) }
                        }
                    }
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                else if (devices.isEmpty() && feedback.isBlank()) Text(uiText("暂无有效授权设备记录"))
                if (feedback.isNotBlank()) Text(feedback, style = MaterialTheme.typography.bodySmall)
                Text(uiText("移除设备会撤销其应用同步授权；不会删除对方本地保险库，也不会撤销其云服务登录凭据。"), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { VaultActionButton(onClick = onDismiss) { Text(uiText("关闭")) } },
        dismissButton = { VaultActionButton(onClick = { scope.launch { load() } }, enabled = !busy) { Text(uiText("刷新")) } },
    )
    selected?.let { device ->
        VaultDialog(
            onDismissRequest = { if (!busy) selected = null },
            title = { Text(uiText("移除设备")) },
            text = { Text(uiText("移除设备会撤销其应用同步授权并删除设备记录；不会删除对方本地保险库，也不会撤销其云服务登录凭据。") + "\n" + device.name.ifBlank { uiText("未知设备") }) },
            confirmButton = { VaultActionButton(enabled = !busy, onClick = {
                if (vm.state.value.rootKey !== selectedRoot || vm.state.value.phase != com.vault.ui.Phase.UNLOCKED) { selected = null; return@VaultActionButton }
                busy = true
                scope.launch {
                    try {
                        if (vm.state.value.rootKey !== selectedRoot) throw CancellationException("Vault session changed")
                        vm.removeDevice(device.deviceId)
                        selected = null
                        devices = vm.deviceProfiles()
                        feedback = localizeUiTextFor(context, "设备已移除")
                    } catch (cancelled: CancellationException) { selected = null; throw cancelled }
                    catch (error: Exception) { selected = null; feedback = localizeUiTextFor(context, error.message ?: "操作失败") }
                    finally { busy = false }
                }
            }) { Text(uiText("移除")) } },
            dismissButton = { VaultActionButton(enabled = !busy, onClick = { selected = null }) { Text(uiText("取消")) } },
        )
    }

}

internal fun deviceActivityDisplayTime(epochMillis: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(epochMillis))
