package com.vault.ui

import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.width
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp

/** Fade the scroll viewport rather than covering tags with rigid end caps. */
internal fun Modifier.vaultHorizontalFeather(
    canScrollBack: () -> Boolean,
    canScrollForward: () -> Boolean,
): Modifier = graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }.drawWithContent {
    drawContent()
    val edge = (16.dp.toPx() / size.width.coerceAtLeast(1f)).coerceAtMost(0.5f)
    drawRect(
        brush = Brush.horizontalGradient(
            0f to if (canScrollBack()) Color.Transparent else Color.Black,
            edge to Color.Black,
            (1f - edge) to Color.Black,
            1f to if (canScrollForward()) Color.Transparent else Color.Black,
        ),
        blendMode = BlendMode.DstIn,
    )
}

/** Fixed, low-contrast obtuse chevrons signal content beyond a small viewport. */
internal fun Modifier.vaultScrollHints(
    canScrollBack: () -> Boolean,
    canScrollForward: () -> Boolean,
): Modifier = composed {
    val tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
    drawWithContent {
        drawContent()
        val halfWidth = 8.dp.toPx()
        val rise = 3.dp.toPx()
        fun arrow(y: Float, up: Boolean) {
            val path = Path().apply {
                moveTo(size.width / 2 - halfWidth, y)
                lineTo(size.width / 2, y + if (up) -rise else rise)
                lineTo(size.width / 2 + halfWidth, y)
            }
            drawPath(path, tint, style = Stroke(width = 1.5.dp.toPx()))
        }
        if (canScrollBack()) arrow(7.dp.toPx(), true)
        if (canScrollForward()) arrow(size.height - 7.dp.toPx(), false)
    }
}

/** Bottom actions start at half the window width and grow to fit content within safe edges. */
internal fun Modifier.vaultBottomActionWidth(): Modifier = composed {
    val windowWidth = LocalConfiguration.current.screenWidthDp.dp
    val maxWidth = (windowWidth - 32.dp).coerceAtLeast(0.dp)
    widthIn(min = (windowWidth / 2).coerceAtMost(maxWidth), max = maxWidth)
        .width(IntrinsicSize.Max)
}
