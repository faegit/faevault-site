package com.vault.ui

import kotlin.math.PI
import kotlin.math.sin

internal object ThreeDotMotion {
    const val PERIOD_MS = 1200f
    const val MAX_SCALE = 1.65f

    fun scale(elapsedMillis: Float, index: Int): Float {
        require(index in 0..2)
        val shifted = elapsedMillis - index * 180f
        if (shifted < 0f) return 1f
        val phase = shifted % PERIOD_MS
        if (phase >= 720f) return 1f
        val wave = sin(PI.toFloat() * phase / 720f)
        return 1f + (MAX_SCALE - 1f) * wave * wave
    }
}
