package com.vault.ui

import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Path as AndroidPath
import android.graphics.RectF
import android.os.Handler
import android.os.Looper
import android.view.PixelCopy
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.core.graphics.createBitmap
import androidx.core.graphics.withSave
import androidx.compose.ui.unit.dp
import kotlin.coroutines.resume
import kotlin.math.hypot
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * 深浅色主题切换的圆形扩散过渡。
 *
 * 原理：手动切换前用 PixelCopy 抓一帧当前整屏（旧配色），切换配色后在最顶层铺一层
 * 旧帧快照，并用一个以屏幕中心为圆心、半径不断增长的圆（clipOutPath）把快照“挖掉”：
 * 圆内透出新主题、圆外仍是旧主题，从而形成从中心向四周铺开的圆形颜色过渡，约 420ms。
 *
 * 只覆盖「手动点选」造成的配色变化（浅色/深色/跟随系统）；系统自动跟随的翻转发生在
 * 无用户点击处、无法预抓旧帧，因此不做动画，直接切换。
 */
object ThemeSwitch {
    /** 揭示动画进行中：FAEVaultTheme 期间据此保持旧的状态栏/导航栏图标深浅。 */
    var revealActive by mutableStateOf(false)

    /** 最近一次「生效中」的深色状态；动画期间冻结为切换前的旧值。 */
    var oldDark by mutableStateOf(false)

    private class Reveal(val native: Bitmap)

    private var overlay: Reveal? by mutableStateOf(null)

    /** 每次 FAEVaultTheme 组合上报当前生效深色；动画期间冻结旧值，动画结束后翻新。 */
    fun reportDark(dark: Boolean) {
        if (!revealActive && oldDark != dark) oldDark = dark
    }

    /**
     * 手动选择主题模式的统一入口（替换直接的 ThemePref.set）。
     * @param visualChange 新旧配色是否真的不同——不同才播放扩散动画；
     *   相同（如「跟随系统」→「深色」而系统本就深色）仅落盘选择、直接切换。
     */
    suspend fun run(context: Context, target: ThemeMode, visualChange: Boolean) {
        try {
            if (!visualChange) return
            // 让刚关闭的下拉浮层先脱离，再抓旧画面
            withFrameNanos { }
            withFrameNanos { }
            val native = snapshotWindow(context as? Activity) ?: return
            // 先放好覆盖层再改配色：同帧重组后下层已是新配色、上层仍是旧快照
            overlay = Reveal(native)
            revealActive = true
        } finally {
            // 无论抓帧成败/协程是否被取消，选择都必须落盘
            ThemePref.set(context, target)
        }
    }

    private suspend fun snapshotWindow(activity: Activity?): Bitmap? {
        if (activity == null) return null
        val window = activity.window ?: return null
        val decor = window.decorView
        val w = decor.width
        val h = decor.height
        if (w <= 0 || h <= 0) return null
        val out = createBitmap(w, h, Bitmap.Config.ARGB_8888)
        return try {
            suspendCancellableCoroutine { cont ->
                val listener = PixelCopy.OnPixelCopyFinishedListener { result ->
                    if (cont.isActive) {
                        cont.resume(if (result == PixelCopy.SUCCESS) out else null)
                    } else {
                        out.recycle()
                    }
                }
                try {
                    PixelCopy.request(window, out, listener, Handler(Looper.getMainLooper()))
                } catch (t: Throwable) {
                    if (cont.isActive) cont.resume(null) else out.recycle()
                }
            }
        } catch (t: Throwable) {
            out.recycle()
            null
        }
    }

    /** 动画结束：移出覆盖层、恢复图标深浅、释放抓帧位图。 */
    fun finishReveal() {
        val old = overlay
        overlay = null
        revealActive = false
        // 延迟一帧再回收：避免正在展示/在途的帧仍引用该位图
        if (old != null) {
            Handler(Looper.getMainLooper()).post { old.native.recycle() }
        }
    }

    /** 顶层覆盖层：仅在有揭示任务时组合。画旧快照 + 中心扩散圆挖孔。 */
    @Composable
    fun Overlay(modifier: Modifier = Modifier) {
        val reveal = overlay ?: return
        val anim = remember { Animatable(0f) }
        LaunchedEffect(reveal) {
            anim.snapTo(0f)
            anim.animateTo(
                targetValue = 1f,
                animationSpec = tween(durationMillis = 420, easing = FastOutSlowInEasing),
            )
            finishReveal()
        }
        val native = reveal.native
        // 扩散圆心：顶部标题文字区域（顶中），而不是屏幕正中
        val originY = with(LocalDensity.current) { 64.dp.toPx() }
        Box(
            modifier = modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    // 动画期间吞掉触摸，避免误触到下层控件
                    awaitEachGesture {
                        val down = awaitFirstDown(requireUnconsumed = false)
                        down.consume()
                        do {
                            val event = awaitPointerEvent()
                            event.changes.forEach { it.consume() }
                        } while (event.changes.any { it.pressed })
                    }
                }
                .drawBehind {
                    val fraction = anim.value
                    val cx = size.width / 2f
                    val cy = originY.coerceAtMost(size.height * 0.25f)
                    val maxDist = hypot(size.width / 2f, (size.height - cy).coerceAtLeast(0f))
                    val radius = fraction * maxDist
                    val dst = RectF(0f, 0f, size.width, size.height)
                    drawIntoCanvas { canvas ->
                        val nativeCanvas = canvas.nativeCanvas
                        nativeCanvas.withSave {
                            if (radius > 0f) {
                                clipOutPath(
                                    AndroidPath().apply {
                                        addCircle(cx, cy, radius, AndroidPath.Direction.CW)
                                    },
                                )
                            }
                            drawBitmap(native, null, dst, null)
                        }
                    }
                },
        ) {}
    }
}
