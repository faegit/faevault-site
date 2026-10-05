package com.vault.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.vault.ui.screens.VaultVisibilityButton
import com.vault.R

/**
 * 自动填充与通行密钥共用的弹窗式解锁 UI：
 * 应用图标 + 标题（按场景传入，中英文案见 UiText）+ 可选来源徽标 + 关闭按钮。
 * 内容区由调用方填充（选择保险库 / 解锁面板 / 流程内容）。
 */
@Composable
internal fun VaultUnlockCard(
    title: String,
    originText: String?,
    onClose: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(
        Modifier
            .fillMaxSize()
            .imePadding(),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp).vaultShadow(12.dp),
            shape = VaultShape,
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        ) {
            Box {
                Column(
                    Modifier.padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Image(
                        painter = painterResource(R.drawable.ic_launcher),
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                    if (originText != null) {
                        Spacer(Modifier.height(8.dp))
                        Surface(
                            shape = VaultShape,
                            color = vaultDialogInsetColor(),
                        ) {
                            Row(
                                Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    Icons.Filled.Key,
                                    contentDescription = null,
                                    modifier = Modifier.size(14.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.width(6.dp))
                                Text(
                                    originText,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                    content()
                }
                com.vault.ui.screens.VaultDialogCloseButton(
                    onClose = onClose,
                    modifier = Modifier.align(Alignment.TopEnd).padding(8.dp),
                )
            }
        }
    }
}

/** 解锁面板：保险库名、主密码输入、错误提示、切换/解锁/生物识别（笑脸图标）。 */
@Composable
internal fun VaultUnlockPanel(
    vaultName: String,
    password: String,
    onPasswordChange: (String) -> Unit,
    message: String,
    busy: Boolean,
    retrySeconds: Int,
    hasBiometric: Boolean,
    onUnlock: () -> Unit,
    onBiometric: () -> Unit,
    onSwitch: () -> Unit,
) {
    var showPw by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        // 保险库名称居中显示（与上方卡片标题对齐）
        Text(
            vaultName,
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
            label = { Text(uiText("主密码")) },
            singleLine = true,
            visualTransformation = if (showPw) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            enabled = !busy && retrySeconds == 0,
            modifier = Modifier.fillMaxWidth(),
            shape = VaultShape,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outline,
            ),
            trailingIcon = {
                VaultVisibilityButton(
                    visible = showPw,
                    onClick = { showPw = !showPw },
                )
            },
        )
        if (message.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Surface(
                shape = VaultShape,
                color = MaterialTheme.colorScheme.errorContainer,
            ) {
                Text(
                    uiText(message),
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            VaultButton(
                onClick = onSwitch,
                enabled = !busy,
                modifier = Modifier.weight(1f),
                variant = VaultButtonVariant.OUTLINED,
                shape = VaultShape,
            ) { Text(uiText("切换")) }
            VaultButton(
                onClick = onUnlock,
                enabled = !busy && password.isNotEmpty() && retrySeconds == 0,
                modifier = Modifier.weight(if (hasBiometric) 1f else 2f),
                shape = VaultShape,
            ) { Text(if (retrySeconds > 0) uiText("等待 ${retrySeconds}s") else uiText("解锁")) }
            if (hasBiometric) {
                // 【登录页同款】生物识别按钮，四层尺寸关系：
                //   布局区域 weight(1f) × 48dp 高 → 实际点击区 48dp 圆 → 视觉背景 40dp 圆 → 图标 38dp
                // 全部通过 contentAlignment 居中；点击区扩大到 48dp 提升触控容错，
                // 视觉外观（40dp 圆 + 38dp 图标）与之前完全一致。
                val bioEnabled = !busy && retrySeconds == 0
                val bioAlpha = if (bioEnabled) 1f else 0.38f
                Box(
                    modifier = Modifier.weight(1f).height(48.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .alpha(bioAlpha)
                            .clip(CircleShape)
                            .clickable(enabled = bioEnabled, onClick = onBiometric),
                    )
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .alpha(bioAlpha)
                            .clip(CircleShape)
                            .background(vaultDialogInsetColor()),
                    )
                    if (busy) {
                        CircularProgressIndicator(modifier = Modifier.size(22.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            painter = painterResource(R.drawable.ic_biometric_tap),
                            contentDescription = uiText("生物识别"),
                            // 与登录页同款单色矢量原色，不做主题染色
                            tint = androidx.compose.ui.graphics.Color.Unspecified,
                            modifier = Modifier.size(38.dp).alpha(bioAlpha),
                        )
                    }
                }
            }
        }
    }
}

@Composable
internal fun VaultUnlockLoading(isComplete: Boolean) {
    Text(
        if (isComplete) uiText("解锁成功") else uiText("正在解密…"),
        modifier = Modifier.fillMaxWidth(),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
}

@Composable
internal fun VaultChooserList(vaults: List<String>, onChoose: (String) -> Unit) {
    Text(uiText("选择要解锁的保险库"), style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(12.dp))
    vaults.forEach { vault ->
        Card(
            modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable { onChoose(vault) },
            shape = VaultShape,
            colors = CardDefaults.cardColors(containerColor = vaultDialogInsetColor()),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        ) {
            Row(
                Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(24.dp), tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.width(12.dp))
                Text(vault.take(40), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}
