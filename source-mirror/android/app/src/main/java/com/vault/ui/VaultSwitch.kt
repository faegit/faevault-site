package com.vault.ui

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/**
 * 全应用统一的布尔开关。不用 material3 的 Switch：其内部把手尺寸按状态放大
 * （关闭 16dp → 开启 24dp，按下 28dp），由 tokens 硬编码，无法用 colors 关掉。
 * 这里自绘：轨道 52×32，圆钮两态恒定 20dp（开启挡位大小），仅水平滑移、不变大小。
 *
 * 圆钮颜色按主题统一：浅色模式两态均白，深色模式两态均取 onSurfaceVariant（浅灰），
 * 不做状态换色；轨道开启 primary、关闭 surfaceContainerHighest，靠轨道区分状态。
 */
@Composable
fun VaultSwitch(
    checked: Boolean,
    onCheckedChange: ((Boolean) -> Unit)?,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val c = MaterialTheme.colorScheme
    val lightTheme = c.background.luminance() > 0.5f
    // 轨道/圆钮色调：开启固定浅色品牌蓝 BrandPrimary（深浅色主题一致），关闭 surfaceContainerHighest；
    // 禁用统一降为 onSurface 灰阶。
    val trackColor = when {
        !enabled -> c.onSurface.copy(alpha = 0.38f)
        checked -> BrandPrimary
        else -> c.surfaceContainerHighest
    }
    val thumbColor = when {
        !enabled -> c.onSurface.copy(alpha = 0.38f)
        lightTheme -> Color.White
        else -> c.onSurfaceVariant
    }
    val interactionSource = remember { MutableInteractionSource() }
    // 圆钮两态恒为 20dp，只做水平位移动画，终点按开启态对齐右侧内边距。
    val offsetX by animateDpAsState(
        targetValue = if (checked) TrackWidth - TrackPadding * 2 - ThumbSize else 0.dp,
        animationSpec = tween(durationMillis = 160, easing = FastOutSlowInEasing),
        label = "vaultSwitchOffset",
    )

    Box(
        modifier = modifier
            .size(TrackWidth, TrackHeight)
            .clip(CircleShape)
            .background(trackColor)
            .let { m ->
                // onCheckedChange 为 null 时仅展示不可交互（语义上等价于 M3 Switch 的禁用态用法）
                onCheckedChange?.let { onChange ->
                    m.toggleable(
                        value = checked,
                        onValueChange = onChange,
                        enabled = enabled,
                        role = Role.Switch,
                        interactionSource = interactionSource,
                        indication = LocalIndication.current,
                    )
                } ?: m
            },
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = TrackPadding),
            contentAlignment = Alignment.CenterStart,
        ) {
            Box(
                modifier = Modifier
                    .size(ThumbSize)
                    .offset { androidx.compose.ui.unit.IntOffset(offsetX.roundToPx(), 0) }
                    .background(thumbColor, CircleShape),
            )
        }
    }
}

private val TrackWidth = 52.dp
private val TrackHeight = 32.dp
private val ThumbSize = 20.dp
private val TrackPadding = 8.dp
