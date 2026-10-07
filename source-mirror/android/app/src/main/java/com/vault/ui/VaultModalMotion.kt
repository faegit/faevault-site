package com.vault.ui

import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp

/** Animate the card only; the window-wide backdrop remains stationary. */
@Composable
internal fun vaultModalEnter(): androidx.compose.animation.EnterTransition {
    val distance = with(LocalDensity.current) { 48.dp.roundToPx() }
    return fadeIn(tween(180)) +
        slideInVertically(tween(220, easing = FastOutSlowInEasing)) { distance }
}

@Composable
internal fun vaultModalExit(): androidx.compose.animation.ExitTransition {
    val distance = with(LocalDensity.current) { 48.dp.roundToPx() }
    return fadeOut(tween(120)) +
        slideOutVertically(tween(160, easing = FastOutSlowInEasing)) { distance }
}

/** Dialog callers remove their content immediately, so dismissal remains immediate. */
@Composable
internal fun Modifier.vaultModalRise(): Modifier {
    val progress = remember { Animatable(0f) }
    val distance = with(LocalDensity.current) { 48.dp.toPx() }
    LaunchedEffect(progress) {
        progress.animateTo(1f, tween(220, easing = FastOutSlowInEasing))
    }
    return graphicsLayer {
        translationY = distance * (1f - progress.value)
        alpha = progress.value
    }
}
