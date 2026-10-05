package com.vault.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.ripple
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

internal enum class VaultButtonVariant {
    PRIMARY,
    NEUTRAL,
    OUTLINED,
    TEXT,
    DANGER,
}

internal data class VaultButtonGeometry(
    val minWidth: Dp,
    val minHeight: Dp,
)

internal val SharedVaultButtonGeometry = VaultButtonGeometry(
    minWidth = ButtonDefaults.MinWidth,
    minHeight = ButtonDefaults.MinHeight,
)

internal fun vaultButtonGeometry(variant: VaultButtonVariant): VaultButtonGeometry = SharedVaultButtonGeometry

/**
 * 普通文字动作的统一入口。
 */
@Composable
internal fun VaultButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    variant: VaultButtonVariant = VaultButtonVariant.PRIMARY,
    shape: Shape = VaultShape,
    containerColor: Color? = null,
    contentColor: Color? = null,
    disabledContainerColor: Color? = null,
    contentPadding: PaddingValues = ButtonDefaults.ContentPadding,
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    // 历史调用可用 minimalPress 仅保留缩放按压反馈，不绘制涟漪。
    minimalPress: Boolean = false,
    content: @Composable RowScope.() -> Unit,
) {
    val disabledContainer = disabledContainerColor ?: MaterialTheme.colorScheme.surfaceContainer
    val disabledContent = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    val resolvedContainer = when {
        !enabled -> disabledContainer
        variant == VaultButtonVariant.DANGER -> MaterialTheme.colorScheme.errorContainer
        variant == VaultButtonVariant.NEUTRAL -> MaterialTheme.colorScheme.surfaceContainerHighest
        variant == VaultButtonVariant.OUTLINED -> containerColor ?: Color.Transparent
        variant == VaultButtonVariant.TEXT -> Color.Transparent
        containerColor != null -> containerColor
        else -> MaterialTheme.colorScheme.primary
    }
    val resolvedContent = when {
        !enabled -> disabledContent
        variant == VaultButtonVariant.DANGER -> MaterialTheme.colorScheme.error
        variant == VaultButtonVariant.NEUTRAL -> MaterialTheme.colorScheme.onSurface
        variant == VaultButtonVariant.OUTLINED -> contentColor ?: MaterialTheme.colorScheme.primary
        variant == VaultButtonVariant.TEXT -> contentColor ?: MaterialTheme.colorScheme.primary
        contentColor != null -> contentColor
        else -> MaterialTheme.colorScheme.onPrimary
    }
    val resolvedBackground = Modifier.background(resolvedContainer)
    val resolvedBorder = if (variant == VaultButtonVariant.OUTLINED && enabled) {
        Modifier.border(BorderStroke(1.dp, MaterialTheme.colorScheme.outline), shape)
    } else {
        Modifier
    }
    val pressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (pressed) 0.95f else 1f,
        animationSpec = spring(dampingRatio = 0.72f),
        label = "vaultButtonScale",
    )
    // 按压反馈：已 clip(shape)，Material ripple 跟随圆角，不会出现矩形色块
    Row(
        modifier = modifier
            .scale(scale)
            .minimumInteractiveComponentSize()
            .defaultMinSize(
                minWidth = SharedVaultButtonGeometry.minWidth,
                minHeight = SharedVaultButtonGeometry.minHeight,
            )
            .clip(shape)
            .then(resolvedBackground)
            .then(resolvedBorder)
            .clickable(
                interactionSource = interactionSource,
                indication = if (minimalPress) null else ripple(color = if (resolvedContent == MaterialTheme.colorScheme.error || variant == VaultButtonVariant.DANGER) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary),
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
            )
            .padding(contentPadding),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CompositionLocalProvider(
            LocalContentColor provides resolvedContent,
            LocalTextStyle provides MaterialTheme.typography.labelLarge,
        ) {
            content()
        }
    }
}
