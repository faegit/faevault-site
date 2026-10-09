package com.vault.ui

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.IntOffset

/** 胶囊分段控件的一段。 */
data class CapsuleOption(val label: String)

/**
 * 两段圆形胶囊分段控件：两端半圆、滑动 thumb、无按压涟漪。
 * 选中段填充与所在卡片同色（surface）+ onSurface 文字，明暗模式一致。
 */
@Composable
fun CapsuleSegmentedControl(
    options: List<CapsuleOption>,
    selectedIndex: Int,
    onSelected: (Int) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    height: Dp = 48.dp,
) {
    require(options.size == 2) { "CapsuleSegmentedControl supports exactly two segments" }
    val selectedContainer = MaterialTheme.colorScheme.surface
    val selectedContent = MaterialTheme.colorScheme.onSurface
    val capsuleShape = RoundedCornerShape(percent = 50)
    val clampedIndex = selectedIndex.coerceIn(options.indices)

    BoxWithConstraints(
        modifier
            .fillMaxWidth()
            .height(height)
            .alpha(if (enabled) 1f else 0.56f),
    ) {
        val segmentWidth = maxWidth / options.size
        val thumbOffset by animateDpAsState(
            targetValue = segmentWidth * clampedIndex,
            animationSpec = tween(durationMillis = 220, easing = FastOutSlowInEasing),
            label = "capsule-thumb",
        )
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(height)
                .clip(capsuleShape)
                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
        ) {
            Box(
                modifier = Modifier
                    .offset { IntOffset(thumbOffset.roundToPx(), 0) }
                    .width(segmentWidth)
                    .fillMaxHeight()
                    .padding(4.dp)
                    .clip(capsuleShape)
                    .background(selectedContainer),
            )
            Row(Modifier.fillMaxSize()) {
                options.forEachIndexed { index, option ->
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                            ) {
                                if (enabled && index != clampedIndex) onSelected(index)
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            option.label,
                            style = MaterialTheme.typography.labelLarge.copy(
                                fontWeight = if (index == clampedIndex) FontWeight.SemiBold else FontWeight.Normal,
                            ),
                            textAlign = TextAlign.Center,
                            softWrap = false,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            color = if (index == clampedIndex) {
                                selectedContent
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.padding(horizontal = 2.dp),
                        )
                    }
                }
            }
        }
    }
}
