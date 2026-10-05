package com.vault.ui.screens

import com.vault.ui.vaultShadow
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun VaultSlider(
    value: Float,
    onValueChange: (Float) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    valueRange: ClosedFloatingPointRange<Float> = 0f..1f,
    steps: Int = 0,
    onValueChangeFinished: (() -> Unit)? = null,
) {
    val activeColor = MaterialTheme.colorScheme.primary.copy(alpha = if (enabled) 1f else 0.38f)
    val inactiveColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = if (enabled) 1f else 0.55f)
    val thumbRing = MaterialTheme.colorScheme.surface

    Slider(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        enabled = enabled,
        valueRange = valueRange,
        steps = steps,
        onValueChangeFinished = onValueChangeFinished,
        thumb = {
            Surface(
                modifier = Modifier.size(20.dp).vaultShadow(if (enabled) 2.dp else 0.dp, CircleShape),
                shape = CircleShape,
                color = activeColor,
                border = BorderStroke(3.dp, thumbRing),
                shadowElevation = 0.dp,
            ) {}
        },
        track = { state ->
            val range = state.valueRange
            val fraction = if (range.endInclusive > range.start) {
                ((state.value - range.start) / (range.endInclusive - range.start)).coerceIn(0f, 1f)
            } else 0f
            Canvas(Modifier.fillMaxWidth().height(20.dp)) {
                val trackHeight = 4.dp.toPx()
                val top = (size.height - trackHeight) / 2f
                drawRoundRect(
                    color = inactiveColor,
                    topLeft = Offset(0f, top),
                    size = Size(size.width, trackHeight),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(trackHeight / 2f),
                )
                val activeWidth = size.width * fraction
                if (activeWidth > 0f) {
                    drawLine(
                        color = activeColor,
                        start = Offset(0f, size.height / 2f),
                        end = Offset(activeWidth, size.height / 2f),
                        strokeWidth = trackHeight,
                        cap = StrokeCap.Round,
                    )
                }
                if (steps in 1..20) {
                    repeat(steps + 2) { index ->
                        val x = size.width * index / (steps + 1f)
                        drawCircle(
                            color = if (x <= activeWidth) activeColor else inactiveColor,
                            radius = 1.5.dp.toPx(),
                            center = Offset(x, size.height / 2f),
                        )
                    }
                }
            }
        },
    )
}
