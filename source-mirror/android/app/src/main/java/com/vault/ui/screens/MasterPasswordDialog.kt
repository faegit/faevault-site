package com.vault.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.vault.R
import com.vault.ui.InputFilters
import com.vault.ui.uiText
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import androidx.compose.runtime.rememberCoroutineScope
import com.vault.ui.VaultShape

/**
 * 二次验证主密码：查看 credit_card / id_card / api_key 的敏感字段或原图前调用。
 * @param verify  传入用户输入的密码，返回是否匹配（在 ViewModel 中以内存比对 state.password）。
 * @param coolingRemainingMs 剩余冷却毫秒数；> 0 时副标题行改显倒计时并禁用确认键。
 * @param onSuccess 验证通过回调；调用方可缓存 verified 状态以减少重复输入。
 */
@Composable
fun MasterPasswordDialog(
    reason: String,
    verify: (String) -> Boolean,
    coolingRemainingMs: () -> Long = { 0L },
    onSuccess: () -> Unit,
    onCancel: () -> Unit,
) {
    var pw by remember { mutableStateOf("") }
    var showPw by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var cooldownMs by remember { mutableLongStateOf(0L) }
    val focus = remember { FocusRequester() }
    val scope = rememberCoroutineScope()
    val incorrectPasswordText = stringResource(R.string.settings_remaining_incorrect_master_password)
    // 弹窗一出来就把光标放进密码框，免去用户再点一次
    LaunchedEffect(Unit) {
        runCatching { focus.requestFocus() }
    }
    LaunchedEffect(Unit) {
        while (true) {
            cooldownMs = withContext(Dispatchers.IO) { coolingRemainingMs() }
            delay(200)
        }
    }
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("验证主密码")) },
        text = {
            Column {
                // 副标题行兼作状态行：冷却期直接改写这里的文案，不再另起一条红色提示。
                // 每段各自 uiText 包一层：整句拼进外层 uiText( 时守卫读不到，会当成硬编码。
                val coolingSec = if (cooldownMs > 0L) ((cooldownMs + 999) / 1000L).coerceAtLeast(1L) else 0L
                Text(
                    if (coolingSec > 0L) {
                        "${uiText("验证已冷却，请")} $coolingSec ${uiText("秒后重试")}"
                    } else {
                        uiText(reason)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (coolingSec > 0L) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = pw,
                    onValueChange = { pw = InputFilters.capLength(InputFilters.asciiPrintable(it), 128); error = null },
                    label = { Text(uiText("当前主密码")) },
                    visualTransformation = if (showPw) VisualTransformation.None else PasswordVisualTransformation(),
                    singleLine = true,
                    isError = error != null,
                    supportingText = error?.takeIf { cooldownMs <= 0L }?.let { { Text(it, color = MaterialTheme.colorScheme.error) } },
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth().focusRequester(focus),
                enabled = !busy,
                    trailingIcon = {
                        VaultVisibilityButton(
                            visible = showPw,
                            onClick = { showPw = !showPw },
                        )
                    },
                )
            }
        },
        confirmButton = {
            VaultActionButton(
                onClick = {
                    if (busy || cooldownMs > 0L) return@VaultActionButton
                    busy = true
                    scope.launch {
                        try {
                            val submitted = pw
                            // 仍在提交时读取真实截止时间；轮询值只控制显示。
                            cooldownMs = withContext(Dispatchers.IO) { coolingRemainingMs() }
                            if (cooldownMs > 0L) return@launch
                            val ok = withContext(Dispatchers.IO) { verify(submitted) }
                            cooldownMs = withContext(Dispatchers.IO) { coolingRemainingMs() }
                            if (ok) onSuccess()
                            else error = incorrectPasswordText
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = pw.isNotEmpty() && !busy && cooldownMs <= 0L,
                style = VaultActionStyle.PRIMARY,
            ) {
                if (busy) {
                    androidx.compose.material3.CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                } else {
                    Text(uiText("验证"))
                }
            }
        },
        dismissButton = {
            VaultActionButton(onClick = onCancel, enabled = !busy) { Text(uiText("取消")) }
        },
    )
}
