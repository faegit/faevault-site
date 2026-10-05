package com.vault.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.vault.security.LeakedPasswordCheck
import com.vault.security.MasterPasswordAssessment
import com.vault.security.MasterPasswordIssue
import com.vault.security.MasterPasswordPolicy
import com.vault.security.MasterPasswordRisk
import com.vault.ui.screens.VaultActionButton
import com.vault.ui.screens.VaultActionStyle
import com.vault.ui.screens.VaultDialog
import kotlin.math.roundToInt

@Composable
internal fun rememberMasterPasswordAssessment(password: String): MasterPasswordAssessment {
    val context = LocalContext.current
    return remember(password) {
        MasterPasswordPolicy.assess(password) { candidate ->
            LeakedPasswordCheck.isLeaked(context, candidate)
        }
    }
}

@Composable
internal fun MasterPasswordPolicyControls(
    assessment: MasterPasswordAssessment,
    highSecurityMode: Boolean,
    onHighSecurityModeChange: (Boolean) -> Unit,
) {
    Spacer(Modifier.height(8.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = highSecurityMode, onCheckedChange = onHighSecurityModeChange)
        Column {
            Text(uiText("主密码高安全模式"), style = MaterialTheme.typography.bodyMedium)
            Text(
                uiText("开启后只允许60bit及以上强度密码"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    if (assessment.estimatedEntropyBits == 0.0) {
        return
    }
    val message = when (assessment.risk) {
        MasterPasswordRisk.BLOCKED -> when (assessment.issue) {
            MasterPasswordIssue.COMMON_PASSWORD -> uiText("该主密码命中本地常见或泄露密码词典，不能使用。")
            else -> uiText("该主密码太容易被离线猜中，不能使用。请改用随机密码或至少 5 个无关单词。")
        }
        MasterPasswordRisk.WEAK -> if (highSecurityMode) {
            uiText("未达到推荐强度，高安全模式下不能使用。")
        } else {
            uiText("该主密码偏弱，继续时必须再次确认风险。")
        }
        MasterPasswordRisk.STRONG -> uiText("已达到推荐强度。")
    }
    Text(
        "$message ${uiText("估计抗猜强度")} ${assessment.estimatedEntropyBits.roundToInt()} bit",
        style = MaterialTheme.typography.bodySmall,
        color = when (assessment.risk) {
            MasterPasswordRisk.BLOCKED -> MaterialTheme.colorScheme.error
            MasterPasswordRisk.WEAK -> MaterialTheme.colorScheme.tertiary
            MasterPasswordRisk.STRONG -> MaterialTheme.colorScheme.primary
        },
    )
}

@Composable
internal fun WeakMasterPasswordConfirmDialog(
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
) {
    VaultDialog(
        onDismissRequest = onCancel,
        title = { Text(uiText("确认使用偏弱主密码")) },
        text = {
            Text(
                uiText("复制保险库文件后可离线猜测主密码，应用内冷却无法阻止这种攻击。建议返回并改用随机密码或至少 5 个无关单词。"),
            )
        },
        confirmButton = {
            VaultActionButton(onClick = onConfirm, style = VaultActionStyle.DANGER) {
                Text(uiText("仍然使用"))
            }
        },
        dismissButton = {
            VaultActionButton(onClick = onCancel, style = VaultActionStyle.NEUTRAL) {
                Text(uiText("返回修改"))
            }
        },
    )
}
