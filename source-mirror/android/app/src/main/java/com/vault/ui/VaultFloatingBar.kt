package com.vault.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.ripple
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * 独立悬浮的操作条：浅色投影、深色柔光，无底栏容器背景。
 * 供二级页底部操作、详情页编辑/删除、更多操作页全选/删除等场景统一使用。
 * 默认从 VaultBackdropHost 取完整底图；页面无需为空列表或加载态补建模糊源。
 *
 * 默认中性灰：浅色模式固定 #E5E5E5，深色模式回落主题 surfaceContainerHighest；
 * 显式传 containerColor 时（如 primary / errorContainer）不受此规则影响。
 */
@Composable
internal fun VaultFloatingBar(
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onClick: (() -> Unit)? = null,
    containerColor: Color? = null,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    shape: Shape = VaultShape,
    elevation: Dp = 8.dp,
    contentPadding: PaddingValues? = null,
    rippleEnabled: Boolean = true,
    backdropEnabled: Boolean = true,
    containerAlpha: Float = 0.5f,
    content: @Composable RowScope.() -> Unit,
) {
    val neutralGray = vaultFloatingSurfaceColor()
    val resolvedContainer = if (enabled) (containerColor ?: neutralGray) else MaterialTheme.colorScheme.surfaceContainer
    val resolvedContent = if (enabled) contentColor else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    val interactionSource = remember { MutableInteractionSource() }
    val pressed by interactionSource.collectIsPressedAsState()
    val effContentPadding = contentPadding ?: if (onClick != null) {
        PaddingValues(12.dp)
    } else {
        PaddingValues(horizontal = 4.dp)
    }
    val contentScale by animateFloatAsState(
        targetValue = if (pressed) 0.95f else 1f,
        animationSpec = spring(dampingRatio = 0.72f),
        label = "vaultFloatingBarScale",
    )
    val decoratedModifier = modifier
        .then(if (onClick != null) Modifier.heightIn(min = 48.dp) else Modifier)
        .vaultShadow(elevation, shape)
        .then(if (backdropEnabled) Modifier.vaultBackdrop(shape) else Modifier)
        .background(resolvedContainer.copy(alpha = resolvedContainer.alpha * containerAlpha), shape)
        .clip(shape)
    val clickModifier = if (onClick != null) {
        decoratedModifier
            .clip(shape)
            .clickable(
                interactionSource = interactionSource,
                indication = if (rippleEnabled) ripple(color = if (contentColor == MaterialTheme.colorScheme.error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary) else null,
                enabled = enabled,
                role = Role.Button,
                onClick = onClick,
            )
    } else {
        decoratedModifier
    }
    Surface(
        modifier = clickModifier,
        color = Color.Transparent,
        contentColor = resolvedContent,
        shape = shape,
    ) {
        Row(
            modifier = Modifier.padding(effContentPadding).graphicsLayer { scaleX = contentScale; scaleY = contentScale },
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            content()
        }
    }
}

/** 灰色功能按钮的统一中性底色（批量栏、恢复/删除等非主操作胶囊）。 */
private val FloatingBarNeutral = Color(0xFFF0F0F0)

@Composable
internal fun vaultFloatingSurfaceColor(): Color =
    if (MaterialTheme.colorScheme.background.luminance() > 0.5f) FloatingBarNeutral
    else MaterialTheme.colorScheme.surfaceContainerHighest
