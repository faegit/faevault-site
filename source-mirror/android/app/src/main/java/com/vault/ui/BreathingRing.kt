package com.vault.ui

import androidx.compose.runtime.withFrameNanos
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

/**
 * 呼吸圆环加载动画 — 单段圆弧的追逐-呼吸循环。
 *
 * 弧长按余弦波形呼吸：min → max → min，位置与速度在边界连续，
 * 无静止、跳变或重置。旋转速度叠加正弦调制：拉伸阶段整体稍慢
 * 突显前端拉开，收缩阶段整体稍快突显后端追赶。
 *
 * 前端速度 = 平均转速 + 速度调制 + 弧长导数/2
 * 后端速度 = 平均转速 + 速度调制 - 弧长导数/2
 */
@Composable
fun BreathingRing(
    modifier: Modifier = Modifier.size(48.dp),
    color: Color = MaterialTheme.colorScheme.primary,
    strokeWidth: Dp = 3.5.dp,
    minSweep: Float = 30f,
    maxSweep: Float = 300f,
    turnsPerPeriod: Int = 2,
    periodMillis: Int = 1600,
) {
    var elapsedMillis by remember { mutableFloatStateOf(0f) }

    LaunchedEffect(Unit) {
        var lastNanos = withFrameNanos { it }
        while (true) {
            val now = withFrameNanos { it }
            val deltaMs = (now - lastNanos) / 1_000_000f
            elapsedMillis += deltaMs
            lastNanos = now
        }
    }

    Canvas(modifier = modifier) {
        // 在绘制阶段读取逐帧状态，只触发 Canvas 重绘，避免整个 Composable 每帧重组。
        val periodMs = periodMillis.toFloat()
        val t = (elapsedMillis % periodMs) / periodMs
        val omega = 2f * PI.toFloat() * t
        val sweep = minSweep + (maxSweep - minSweep) * (1f - cos(omega)) / 2f
        // 线性旋转 + 正弦速度调制：延伸时稍慢，收缩时稍快
        val speedWobbleAmplitude = 25f // 度/周期
        val linearRotation = turnsPerPeriod * 360f * (elapsedMillis / periodMs)
        val wobble = speedWobbleAmplitude * sin(omega)
        val totalRotation = linearRotation - wobble
        val startAngle = totalRotation - sweep / 2f
        drawArc(
            color = color,
            startAngle = startAngle,
            sweepAngle = sweep,
            useCenter = false,
            style = Stroke(width = strokeWidth.toPx(), cap = StrokeCap.Round),
        )
    }
}
