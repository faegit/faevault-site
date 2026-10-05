package com.vault.ui

import androidx.compose.animation.core.animate
import androidx.compose.animation.core.spring
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.gestures.FlingBehavior
import androidx.compose.foundation.gestures.ScrollableDefaults
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.grid.*
import androidx.compose.foundation.verticalScroll as platformVerticalScroll
import androidx.compose.foundation.horizontalScroll as platformHorizontalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.clipRect
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.input.nestedscroll.*
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlin.math.abs

/**
 * Visual edge displacement never consumes a delta before the scrolling child handles it.
 *
 * [allowTopPull]：最顶部继续下拉时**不消费**这段位移，交给上层的下拉组件（如
 * PullToRefreshBox）接管；底部边缘的回弹不受影响。首页下拉开回收站用的是这个模式。
 */
internal fun Modifier.vaultEdgeBounce(
    horizontal: Boolean = false,
    enabled: Boolean = true,
    allowTopPull: Boolean = false,
): Modifier = composed {
    if (!enabled) return@composed this
    val scope = rememberCoroutineScope()
    val limit = with(LocalDensity.current) { 40.dp.toPx() }
    val state = remember(horizontal, limit) { EdgeBounceState(limit) }
    var returning by remember { mutableStateOf<Job?>(null) }
    var touching by remember { mutableStateOf(false) }
    fun stop() { returning?.cancel(); returning = null }
    fun release() {
        // 按住期间定格，只有松手才回弹。放在函数内部而不是各个调用点，
        // 避免以后新增调用点又漏掉这个条件（曾因此在不松手时提前弹回并产生反向位移）。
        if (!canRelease(touching)) return
        // 收尾阶段每次滚动事件都会调到这里；已在回弹途中就不要再重启，否则动画会被反复打断。
        if (returning?.isActive == true) return
        stop()
        if (abs(state.offset) < 0.5f) { state.offset = 0f; return }
        returning = scope.launch {
            animate(state.offset, 0f, animationSpec = spring(dampingRatio = 0.85f, stiffness = 450f)) { value, _ ->
                state.offset = value
            }
            state.offset = 0f
        }
    }
    val connection = remember(state, horizontal, allowTopPull) {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (source == NestedScrollSource.UserInput) stop()
                return Offset.Zero
            }
            override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                val used = if (horizontal) consumed.x else consumed.y
                val rest = if (horizontal) available.x else available.y
                // 离开边缘要收尾——但必须用动画。之前这里直接 state.offset = 0f，
                // 松手后残余滚动事件触发时会硬跳回原位（拖得越远越明显，表现为"闪现回去"）。
                if (shouldSettle(touching, used)) release()
                if (source == NestedScrollSource.UserInput && touching && abs(rest) > 0.01f) {
                    // 顶部（向下、rest > 0）让位给上层下拉时：既不回弹也不消费。
                    if (allowTopPull && rest > 0f) return Offset.Zero
                    state.pull(rest)
                    return if (horizontal) Offset(rest, 0f) else Offset(0f, rest)
                }
                return Offset.Zero
            }
            override suspend fun onPostFling(consumed: Velocity, available: Velocity): Velocity {
                val remaining = if (horizontal) available.x else available.y
                // 顶部下拉已经交给外层组件时，正向剩余速度也必须继续向上传递，不能在这里吃掉。
                if (!horizontal && allowTopPull && remaining > 0f) {
                    if (!touching) release()
                    return Velocity.Zero
                }
                if (!touching) {
                    if (abs(remaining) > 1f && abs(state.offset) < 0.5f) state.pull(remaining * 0.015f)
                    release()
                }
                return if (horizontal) Velocity(available.x, 0f) else Velocity(0f, available.y)
            }
        }
    }
    DisposableEffect(state) { onDispose { returning?.cancel() } }
    this
        .drawWithContent {
            clipRect {
                translate(left = if (horizontal) state.offset else 0f, top = if (horizontal) 0f else state.offset) {
                    this@drawWithContent.drawContent()
                }
            }
        }
        .pointerInput(state) {
            awaitEachGesture {
                awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                touching = true
                stop()
                state.offset = 0f
                try {
                    do {
                        val event = awaitPointerEvent(PointerEventPass.Final)
                    } while (event.changes.any { it.pressed })
                } finally {
                    touching = false
                    release()
                }
            }
        }
        .nestedScroll(connection)
}

internal class EdgeBounceState(private val limit: Float) {
    var offset by mutableFloatStateOf(0f)
    fun pull(delta: Float) {
        offset = edgeBounceOffset(offset, delta, limit)
    }
}

/** 只有松开手指后才允许回弹：按住期间位移必须定格。 */
internal fun canRelease(touching: Boolean): Boolean = !touching

/**
 * 位移何时收尾：子级消费了位移说明已经离开边缘，但**按住期间不收尾**——
 * 否则会在不松手时瞬间弹回，随后继续外推又拉起，形成来回抖动与反向滑动。
 *
 * 收尾动作必须是**动画回弹**（[release]），不是硬置 0：松手后残余的滚动事件
 * 也会命中这里，硬置会在视觉上"闪现回去"。
 */
internal fun shouldSettle(touching: Boolean, consumed: Float): Boolean =
    !touching && abs(consumed) > 0.01f

internal fun edgeBounceOffset(current: Float, delta: Float, limit: Float): Float =
    (current + delta * 0.25f * (1f - abs(current) / limit)).coerceIn(-limit, limit)

internal fun Modifier.vaultVerticalScroll(state: ScrollState, enabled: Boolean = true,
    flingBehavior: FlingBehavior? = null, reverseScrolling: Boolean = false): Modifier =
    vaultEdgeBounce(enabled = enabled).platformVerticalScroll(state, enabled, flingBehavior, reverseScrolling)

internal fun Modifier.vaultHorizontalScroll(state: ScrollState, enabled: Boolean = true,
    flingBehavior: FlingBehavior? = null, reverseScrolling: Boolean = false): Modifier =
    vaultEdgeBounce(horizontal = true, enabled = enabled).platformHorizontalScroll(state, enabled, flingBehavior, reverseScrolling)

@Composable
internal fun VaultLazyColumn(modifier: Modifier = Modifier, state: LazyListState = rememberLazyListState(),
    contentPadding: PaddingValues = PaddingValues(0.dp), reverseLayout: Boolean = false,
    verticalArrangement: Arrangement.Vertical = if (!reverseLayout) Arrangement.Top else Arrangement.Bottom,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    flingBehavior: FlingBehavior = ScrollableDefaults.flingBehavior(), userScrollEnabled: Boolean = true,
    content: LazyListScope.() -> Unit) {
    androidx.compose.foundation.lazy.LazyColumn(modifier.vaultEdgeBounce(enabled = userScrollEnabled), state,
        contentPadding, reverseLayout, verticalArrangement, horizontalAlignment, flingBehavior, userScrollEnabled, content)
}

@Composable
internal fun VaultLazyRow(modifier: Modifier = Modifier, state: LazyListState = rememberLazyListState(),
    contentPadding: PaddingValues = PaddingValues(0.dp), reverseLayout: Boolean = false,
    horizontalArrangement: Arrangement.Horizontal = if (!reverseLayout) Arrangement.Start else Arrangement.End,
    verticalAlignment: Alignment.Vertical = Alignment.Top,
    flingBehavior: FlingBehavior = ScrollableDefaults.flingBehavior(), userScrollEnabled: Boolean = true,
    content: LazyListScope.() -> Unit) {
    androidx.compose.foundation.lazy.LazyRow(modifier.vaultEdgeBounce(horizontal = true, enabled = userScrollEnabled), state,
        contentPadding, reverseLayout, horizontalArrangement, verticalAlignment, flingBehavior, userScrollEnabled, content)
}

@Composable
internal fun VaultLazyVerticalGrid(columns: GridCells, modifier: Modifier = Modifier,
    state: LazyGridState = rememberLazyGridState(), contentPadding: PaddingValues = PaddingValues(0.dp),
    reverseLayout: Boolean = false,
    verticalArrangement: Arrangement.Vertical = if (!reverseLayout) Arrangement.Top else Arrangement.Bottom,
    horizontalArrangement: Arrangement.Horizontal = Arrangement.Start,
    flingBehavior: FlingBehavior = ScrollableDefaults.flingBehavior(), userScrollEnabled: Boolean = true,
    allowTopPull: Boolean = false,
    content: LazyGridScope.() -> Unit) {
    LazyVerticalGrid(columns, modifier.vaultEdgeBounce(enabled = userScrollEnabled, allowTopPull = allowTopPull), state,
        contentPadding, reverseLayout, verticalArrangement, horizontalArrangement, flingBehavior, userScrollEnabled, content)
}
