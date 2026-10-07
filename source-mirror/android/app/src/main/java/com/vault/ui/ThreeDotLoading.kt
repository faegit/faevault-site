package com.vault.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** Fixed bounds contain every dot at peak scale; animation only invalidates drawing. */
@Composable
internal fun ThreeDotLoading(
    modifier: Modifier = Modifier.size(width = 32.dp, height = 18.dp),
    color: Color = MaterialTheme.colorScheme.onPrimary,
    description: String? = null,
) {
    var elapsed by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(Unit) {
        var previous = withFrameNanos { it }
        while (true) {
            val now = withFrameNanos { it }
            elapsed = (elapsed + (now - previous) / 1_000_000f) % ThreeDotMotion.PERIOD_MS
            previous = now
        }
    }
    Canvas(modifier.semantics { description?.let { contentDescription = it } }) {
        val radius = minOf(size.height / 6f, size.width / 15f)
        repeat(3) { index ->
            drawCircle(color, radius * ThreeDotMotion.scale(elapsed, index),
                Offset(size.width * (index + 0.5f) / 3f, size.height / 2f))
        }
    }
}
