package com.vault.ui.screens

import com.vault.ui.uiText
import com.vault.ui.vaultPopupCardSurface
import com.vault.ui.VaultModalBackdrop
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import com.vault.R
import com.vault.ui.VaultShape

private const val DEFAULT_DISMISS_TEXT_SENTINEL = "\u0000vault-default-dismiss"

/**
 * 统一弹出对话框模板。
 * 按钮使用 [VaultActionButton]（按压 0.97 弹簧缩放动效），
 * 红色危险操作用 [VaultActionStyle.DANGER]。
 *
 * 简易用法（纯文字）：
 *   VaultDialog(
 *       onDismissRequest = { ... },
 *       title = "删除确认",
 *       text = "确定要删除吗？",
 *       confirmText = "删除",
 *       confirmStyle = VaultActionStyle.DANGER,
 *       onConfirm = { ... },
 *       dismissText = "取消",
 *       onDismiss = { ... },
 *   )
 *
 * 自定义内容用法：
 *   VaultDialog(
 *       onDismissRequest = { ... },
 *       title = { Text("自定义标题") },
 *       text = { MyCustomContent() },
 *       confirmButton = VaultDialogButton("确认") { ... },
 *       dismissButton = VaultDialogButton("取消") { ... },
 *   )
 */

// ── 便捷函数：创建标准确认/取消按钮 ────────────────────────────

@Composable
internal fun VaultDialogButton(
    text: String,
    onClick: () -> Unit,
    style: VaultActionStyle = VaultActionStyle.NEUTRAL,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
): @Composable () -> Unit = {
    VaultActionButton(
        onClick = onClick,
        enabled = enabled,
        style = style,
        modifier = modifier,
    ) { Text(text) }
}

/** A single unfilled close icon shared by popup surfaces. */
@Composable
internal fun VaultDialogCloseButton(onClose: () -> Unit, modifier: Modifier = Modifier) {
    IconButton(onClick = onClose, modifier = modifier.size(48.dp)) {
        Icon(Icons.Default.Close, contentDescription = uiText("关闭"),
            tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ── 简易文本对话框 ────────────────────────────────────────────

@Composable
internal fun VaultDialog(
    onDismissRequest: () -> Unit,
    title: String,
    text: String,
    confirmText: String,
    onConfirm: () -> Unit,
    confirmStyle: VaultActionStyle = VaultActionStyle.PRIMARY,
    confirmEnabled: Boolean = true,
    dismissText: String? = DEFAULT_DISMISS_TEXT_SENTINEL,
    onDismiss: (() -> Unit)? = null,
    shape: Shape = VaultShape,
    containerColor: Color? = null,
    onClose: (() -> Unit)? = null,
) {
    val resolvedDismissText = if (dismissText == DEFAULT_DISMISS_TEXT_SENTINEL) {
        stringResource(R.string.general_remaining_cancel)
    } else {
        dismissText
    }
    VaultDialog(
        onDismissRequest = onDismissRequest,
        shape = shape,
        containerColor = containerColor,
        onClose = onClose,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            VaultActionButton(onClick = onConfirm, style = confirmStyle, enabled = confirmEnabled) {
                Text(confirmText)
            }
        },
        dismissButton = resolvedDismissText?.let { textValue ->
            { VaultActionButton(onClick = onDismiss ?: onDismissRequest, style = VaultActionStyle.NEUTRAL) { Text(textValue) } }
        },
    )
}

// ── 自定义内容对话框 ──────────────────────────────────────────

@Composable
internal fun VaultDialog(
    onDismissRequest: () -> Unit,
    title: @Composable (() -> Unit)? = null,
    text: @Composable (() -> Unit)? = null,
    confirmButton: @Composable () -> Unit = {},
    dismissButton: @Composable (() -> Unit)? = null,
    shape: Shape = VaultShape,
    containerColor: Color? = null,
    onClose: (() -> Unit)? = null,
    dismissOnOutsideClick: Boolean = true,
    properties: DialogProperties = DialogProperties(),
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = generateSequence(context) { (it as? android.content.ContextWrapper)?.baseContext }
        .filterIsInstance<android.app.Activity>().firstOrNull()
    val externalAuth = activity is com.vault.autofill.AutofillAuthActivity ||
        activity is com.vault.passkeys.PasskeyCredentialActivity
    if (!externalAuth) VaultModalBackdrop()
    AlertDialog(
        onDismissRequest = onDismissRequest,
        properties = DialogProperties(
            dismissOnBackPress = properties.dismissOnBackPress,
            dismissOnClickOutside = dismissOnOutsideClick && properties.dismissOnClickOutside,
            securePolicy = properties.securePolicy,
            usePlatformDefaultWidth = properties.usePlatformDefaultWidth,
            decorFitsSystemWindows = properties.decorFitsSystemWindows,
        ),
        shape = shape,
        modifier = Modifier.vaultPopupCardSurface(
            shape = shape,
            color = containerColor ?: MaterialTheme.colorScheme.surface,
            opaque = externalAuth,
        ),
        containerColor = Color.Transparent,
        tonalElevation = 0.dp,
        title = if (title == null && onClose == null) null else {
            {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    androidx.compose.foundation.layout.Box(Modifier.weight(1f)) { title?.invoke() }
                    if (onClose != null) VaultDialogCloseButton(onClose)
                }
            }
        },
        text = text,
        confirmButton = {
            VaultDialogWindow()
            confirmButton()
        },
        dismissButton = dismissButton,
    )
}

/** Compose dialogs enable platform dimming by default; cards use only the shared blur. */
@Composable
internal fun VaultDialogWindow() {
    val view = androidx.compose.ui.platform.LocalView.current
    androidx.compose.runtime.SideEffect {
        (view.parent as? androidx.compose.ui.window.DialogWindowProvider)?.window
            ?.clearFlags(android.view.WindowManager.LayoutParams.FLAG_DIM_BEHIND)
    }
}
