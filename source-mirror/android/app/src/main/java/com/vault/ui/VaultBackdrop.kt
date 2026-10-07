package com.vault.ui

import android.os.Build
import android.view.View
import android.view.ViewTreeObserver
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import dev.chrisbanes.haze.HazeInputScale
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.HazeTint
import dev.chrisbanes.haze.hazeEffect
import dev.chrisbanes.haze.hazeSource

internal val LocalVaultBackdrop = staticCompositionLocalOf<HazeState?> { null }

/** Full-window source for dialog surfaces; independent of individual scrollable pages. */
internal val LocalVaultModalSource = staticCompositionLocalOf<HazeState?> { null }

/**
 * Shared popup chrome. The bottom tint fades smoothly without changing content layout.
 * 仅用于自身就是卡片、且绘制范围等于卡片范围的面（Dialog / 居中的 Card）。
 * 不要用在 ModalBottomSheet 的 modifier 上：那条 modifier 挂在 draggableAnchors 节点，
 * 该节点尺寸是卡片尺寸却停在屏幕顶部，内容靠 place(offset) 下移，
 * 于是 background/clip 会画成屏幕顶部的一块矩形（顶部白块 + 底部缺失）。
 * 底部弹窗的卡片底色请交给 containerColor。
 */
@Composable
internal fun Modifier.vaultPopupCardSurface(
    shape: Shape = VaultShape,
    color: Color = MaterialTheme.colorScheme.surface,
    opaque: Boolean = false,
    animateEntry: Boolean = true,
): Modifier {
    val source = LocalVaultModalSource.current
    val canBlur = !opaque && source != null && Build.VERSION.SDK_INT >= 31
    val surface = (if (animateEntry) vaultModalRise() else this).vaultShadow(12.dp, shape)
    if (!canBlur) return surface.background(color, shape).clip(shape)
    return surface
        .vaultBackdrop(shape = shape, baseColor = color, state = source)
        .background(
            androidx.compose.ui.graphics.Brush.verticalGradient(
                0f to color.copy(alpha = 0.96f),
                0.65f to color.copy(alpha = 0.94f),
                1f to color.copy(alpha = 0.76f),
            ),
            shape,
        )
        .clip(shape)
}

/** Shared backdrop scope: a persistent floor plus the page's detailed content sources.
 * The floor is a sibling, so floating controls never capture themselves recursively.
 * It also survives empty/loading results and covers gaps outside a scrollable source.
 */
@Composable
internal fun VaultBackdropHost(
    state: HazeState = remember { HazeState() },
    backgroundColor: Color = MaterialTheme.colorScheme.background,
    content: @Composable () -> Unit,
) {
    androidx.compose.runtime.CompositionLocalProvider(LocalVaultBackdrop provides state) {
        Box(propagateMinConstraints = true) {
            Box(Modifier.matchParentSize()
                .vaultBackdropSource(state, zIndex = -1f)
                .background(backgroundColor))
            content()
        }
    }
}

/** Capture scrollable content once; floating controls never become their own input. */
@Composable
internal fun Modifier.vaultBackdropSource(state: HazeState? = LocalVaultBackdrop.current, zIndex: Float = 0f): Modifier {
    state ?: return this
    return if (Build.VERSION.SDK_INT >= 31) hazeSource(state, zIndex = zIndex) else this
}

/** GPU-only local blur, half-resolution input, no noise or progressive passes. */
@OptIn(dev.chrisbanes.haze.ExperimentalHazeApi::class)
@Composable
internal fun Modifier.vaultBackdrop(shape: Shape = VaultShape, baseColor: Color? = null, state: HazeState? = LocalVaultBackdrop.current): Modifier {
    state ?: return this
    if (Build.VERSION.SDK_INT < 31) return this
    val base = baseColor ?: MaterialTheme.colorScheme.surface
    return clip(shape).hazeEffect(state) {
        backgroundColor = base
        tints = listOf(HazeTint(Color.Transparent))
        blurRadius = 12.dp
        noiseFactor = 0f
        inputScale = HazeInputScale.Fixed(0.5f)
    }
}

@Composable
internal fun Modifier.vaultFrostedSurface(
    shape: Shape = VaultShape,
    containerColor: Color = MaterialTheme.colorScheme.surface,
    containerAlpha: Float = 0.9f,
    elevation: Dp = 0.dp,
): Modifier = this
    .then(if (elevation > 0.dp) Modifier.vaultShadow(elevation, shape) else Modifier)
    .vaultBackdrop(shape, containerColor)
    .background(containerColor.copy(alpha = containerColor.alpha * containerAlpha), shape)
    .clip(shape)

/**
 * 跨窗口悬浮菜单：用 Popup 承载，配合 [vaultBackdrop] 实现跨窗口模糊。
 * [offset] 为相对调用处父容器的像素位置，沿用原菜单定位。
 * [baseColor] 为模糊层的底衬色：透明可避免与上层半透明填色叠加成灰。
 */
@Composable
internal fun VaultHazePopup(
    onDismissRequest: () -> Unit,
    offset: IntOffset,
    containerColor: Color,
    maxHeight: Dp = Dp.Unspecified,
    minWidth: Dp = 0.dp,
    baseColor: Color = Color.Transparent,
    content: @Composable ColumnScope.() -> Unit,
) {
    val sourceView = LocalView.current
    val popupScroll = rememberScrollState()
    val properties = PopupProperties(focusable = true, clippingEnabled = true)
    Popup(
        onDismissRequest = onDismissRequest,
        offset = offset,
        properties = properties,
    ) {
        Column(
            modifier = Modifier
                .width(IntrinsicSize.Max)
                .then(if (minWidth > 0.dp) Modifier.widthIn(min = minWidth) else Modifier)
                .then(
                    if (maxHeight != Dp.Unspecified) {
                        Modifier.heightIn(max = maxHeight)
                            .vaultScrollHints({ popupScroll.canScrollBackward }, { popupScroll.canScrollForward })
                            .verticalScroll(popupScroll)
                    } else {
                        Modifier
                    },
                )
                .vaultShadow(8.dp)
                .vaultPopupBackdrop(sourceView)
                .background(vaultFloatingSurfaceColor().copy(alpha = 0.50f), VaultShape)
                .clip(VaultShape)
                .pointerInput(Unit) { detectTapGestures { } },
            ) {
                content()
}
    }
}

/** Redraw a popup when its source window draws; no timer or idle frame loop. */
internal fun Modifier.vaultPopupBackdrop(sourceView: View): Modifier = composed {
    val redraw = remember(sourceView) { mutableIntStateOf(0) }
    DisposableEffect(sourceView) {
        val observer = sourceView.viewTreeObserver
        val listener = ViewTreeObserver.OnPreDrawListener {
            redraw.intValue++
            true
        }
        observer.addOnPreDrawListener(listener)
        onDispose {
            val currentObserver = if (observer.isAlive) observer else sourceView.viewTreeObserver
            if (currentObserver.isAlive) currentObserver.removeOnPreDrawListener(listener)
        }
    }
    drawWithContent {
        // Observe in draw only, so a source update never recomposes menu items.
        redraw.intValue
        drawContent()
    }.vaultBackdrop()
}
