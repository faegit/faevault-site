package com.vault.ui.media

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.BitmapRegionDecoder
import android.graphics.Rect as AndroidRect
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.util.Base64
import android.util.Base64InputStream
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.size
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.isSpecified
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import com.vault.storage.MediaCrypto
import com.vault.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import java.io.File
import java.io.ByteArrayInputStream
import java.io.FileOutputStream
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import java.util.concurrent.Executors
import com.vault.ui.VaultShape

/**
 * 全屏超高清图片查看器（单预览 + 静止后区域解码）：
 *  - 保险库图片只顺序读取/解密一次，后续区域解码不再访问数据库；
 *  - 手势期间仅变换 GPU 图层，抬手稳定后才解码一次当前可视区域；
 *  - 捏合缩放围绕手势中心点定位，平移自动限位；
 *  - 双击在适配视图与稳定的高清倍率之间切换，横竖图行为一致；
 *  - 只保留一张屏幕预览和一个高清区域，移除多采样瓦片带来的 I/O、GC 与重组抖动。
 */
@Composable
fun ImageViewerDialog(b64: String, onClose: () -> Unit) {
    ImageViewerDialog(images = listOf(b64), initialIndex = 0, onClose = onClose)
}

/**
 * 多图查看器：非放大模式下左右滑动切换图像；放大模式下捏合缩放/平移。
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ImageViewerDialog(images: List<String>, initialIndex: Int = 0, onClose: () -> Unit) {
    val safeImages = images.ifEmpty { listOf("") }
    val pagerState = rememberPagerState(
        initialPage = initialIndex.coerceIn(0, safeImages.lastIndex.coerceAtLeast(0)),
        pageCount = { safeImages.size },
    )
    val index = pagerState.settledPage.coerceIn(0, safeImages.lastIndex)
    val b64 = safeImages.getOrNull(index).orEmpty()
    val context = LocalContext.current
    val session = remember(b64) { RegionImageSession() }
    val collectedSnapshot by session.snapshot.collectAsState()
    val snapshot = currentImageSessionValue(
        expectedSessionId = session.id,
        collectedSessionId = collectedSnapshot.sessionId,
        collected = collectedSnapshot,
        current = session.snapshot.value,
    )

    var zoom by remember(session) { mutableFloatStateOf(1f) }
    var offset by remember(session) { mutableStateOf(Offset.Zero) }
    var viewport by remember { mutableStateOf(IntSize.Zero) }
    // 稳定适配视口：只跟随真实尺寸变化（旋转/分屏/折叠）更新，
    // 忽略系统栏隐藏/显示造成的窗口重排，避免图片在进入/退出全屏时跳动。
    var fitViewport by remember { mutableStateOf(IntSize.Zero) }
    var previousViewport by remember(session) { mutableStateOf(IntSize.Zero) }
    var fitScale by remember(session) { mutableFloatStateOf(0f) }
    var controlsVisible by remember { mutableStateOf(true) }
    val animationScope = rememberCoroutineScope()
    var zoomAnimation by remember(session) { mutableStateOf<Job?>(null) }
    var zoomAnimating by remember(session) { mutableStateOf(false) }
    var gestureActive by remember(session) { mutableStateOf(false) }
    var gestureCentroid by remember(session) { mutableStateOf(Offset.Unspecified) }
    var fullscreenContentReady by remember { mutableStateOf(false) }
    // 等待实际窗口视口稳定，不要求系统栏 Insets 归零。
    LaunchedEffect(viewport) {
        if (viewport.width > 0 && viewport.height > 0) {
            withFrameNanos { }
            fullscreenContentReady = true
        }
    }

    /** 图片在当前缩放下的居中偏移。 */
    fun centeredOffset(ready: RegionImageSession.Phase.Ready, viewport: IntSize, fit: Float, currentZoom: Float): Offset {
        val width = ready.width * fit * currentZoom
        val height = ready.height * fit * currentZoom
        return Offset(
            (viewport.width - width) / 2f,
            (viewport.height - height) / 2f,
        )
    }

    fun clampOffsetFor(
        ready: RegionImageSession.Phase.Ready,
        targetViewport: IntSize,
        targetFitScale: Float,
        targetZoom: Float,
        proposed: Offset,
    ): Offset {
        val width = ready.width * targetFitScale * targetZoom
        val height = ready.height * targetFitScale * targetZoom
        val xRange = if (width <= targetViewport.width) {
            val c = (targetViewport.width - width) / 2f
            c..c
        } else {
            (targetViewport.width - width)..0f
        }
        val yRange = if (height <= targetViewport.height) {
            val c = (targetViewport.height - height) / 2f
            c..c
        } else {
            (targetViewport.height - height)..0f
        }
        return Offset(proposed.x.coerceIn(xRange), proposed.y.coerceIn(yRange))
    }

    /** 平移限位：图片小于屏幕时保持居中，大于屏幕时可在边界内平移。 */
    fun clampOffset(proposed: Offset): Offset {
        // 手势回调可能在 Loading→Ready 之前创建并捕获旧快照；这里始终读取会话当前快照，
        // 避免双击/捏合在图片就绪后仍被旧快照拦截。
        val ready = session.snapshot.value.phase as? RegionImageSession.Phase.Ready ?: return proposed
        return clampOffsetFor(ready, viewport, fitScale, zoom, proposed)
    }

    val transformState = rememberTransformableState { gestureZoom, pan, _ ->
        val ready = session.snapshot.value.phase as? RegionImageSession.Phase.Ready
            ?: return@rememberTransformableState
        val newZoom = (zoom * gestureZoom).coerceIn(1f, maximumZoomFor(fitScale))
        if (newZoom <= 1.0001f) {
            zoom = 1f
            offset = centeredOffset(ready, fitViewport, fitScale, 1f)
            return@rememberTransformableState
        }
        val focalPoint = gestureCentroid.takeIf { it.isSpecified }
            ?: Offset(viewport.width / 2f, viewport.height / 2f)
        val ratio = newZoom / zoom
        zoom = newZoom
        offset = clampOffset((offset - focalPoint) * ratio + focalPoint + pan)
    }

    DisposableEffect(session) {
        onDispose { zoomAnimation?.cancel(); session.close() }
    }

    LaunchedEffect(session, viewport) {
        if (viewport.width > 0 && viewport.height > 0) {
            session.open(context, b64, viewport)
        }
    }

    val phase = snapshot.phase
    // 图片就绪后计算“适配屏幕”的基准比例（基于稳定适配视口，避免全屏切换时跳动）。
    LaunchedEffect(phase, fitViewport) {
        val ready = phase as? RegionImageSession.Phase.Ready ?: return@LaunchedEffect
        if (fitViewport.width > 0 && fitViewport.height > 0) {
            val newFitScale = min(
                fitViewport.width.toFloat() / ready.width,
                fitViewport.height.toFloat() / ready.height,
            )
            if (zoom > 1.0001f && previousViewport.width > 0 && previousViewport.height > 0) {
                // 小窗、分屏或旋转改变窗口尺寸时，同时保留原图显示密度和视口中心对应的原图像素。
                val oldDisplayScale = fitScale * zoom
                val newZoom = (oldDisplayScale / newFitScale)
                    .coerceIn(1f, maximumZoomFor(newFitScale))
                val proposed = offsetKeepingViewportCenter(
                    oldViewport = previousViewport,
                    newViewport = fitViewport,
                    oldOffset = offset,
                    oldDisplayScale = oldDisplayScale,
                    newDisplayScale = newFitScale * newZoom,
                )
                fitScale = newFitScale
                zoom = newZoom
                offset = clampOffsetFor(ready, fitViewport, newFitScale, newZoom, proposed)
            } else {
                fitScale = newFitScale
                zoom = 1f
                // 默认居中：适配后图片小于屏幕时上下/左右留白居中。
                offset = centeredOffset(ready, fitViewport, newFitScale, 1f)
            }
            previousViewport = fitViewport
        }
    }
    // 手势期间不产生任何解码请求；抬手后等待状态稳定，再合并成一次可视区域解码。
    LaunchedEffect(session, phase) {
        snapshotFlow {
            if (gestureActive || zoomAnimating || phase !is RegionImageSession.Phase.Ready) null
            else ImageViewportRequest(viewport, zoom, offset, fitScale).settled()
        }
            .distinctUntilChanged()
            .collectLatest { request ->
                if (request == null) return@collectLatest
                kotlinx.coroutines.delay(DETAIL_DECODE_SETTLE_MS)
                session.updateViewport(
                    request.viewport,
                    request.zoom,
                    request.offset,
                    request.fitScale,
                )
            }
    }

    FullscreenViewerHost(onClose = onClose) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black)
                .onSizeChanged { size ->
                    viewport = size
                    fitViewport = size
                },
            contentAlignment = Alignment.Center,
        ) {
            if (fullscreenContentReady) {
                HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize().clipToBounds(),
                beyondViewportPageCount = 1,
                userScrollEnabled = safeImages.size > 1 && imagePagingEnabled(zoom),
                key = { page -> "$page:${safeImages[page].hashCode()}" },
            ) { page ->
                val currentPage = page == index
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .then(
                            if (!currentPage) Modifier
                            else Modifier
                                .pointerInput(session) {
                                    detectTapGestures(
                                        onTap = { controlsVisible = !controlsVisible },
                                        onDoubleTap = { position ->
                                            val ready = session.snapshot.value.phase
                                                as? RegionImageSession.Phase.Ready
                                                ?: return@detectTapGestures
                                            val shortFill = shortSideFillZoom(
                                                ready.width,
                                                ready.height,
                                                viewport,
                                                fitScale,
                                            )
                                            val target = doubleTapTargetZoom(zoom, fitScale, shortFill)
                                            zoomAnimation?.cancel()
                                            val startZoom = zoom
                                            val startOffset = offset
                                            val endOffset = if (target <= 1f) centeredOffset(ready, viewport, fitScale, 1f)
                                                else clampOffsetFor(ready, viewport, fitScale, target, (offset - position) * (target / zoom) + position)
                                            zoomAnimation = animationScope.launch {
                                                zoomAnimating = true
                                                session.pauseDetailDecoding()
                                                try {
                                                    animate(0f, 1f, animationSpec = tween(200)) { fraction, _ ->
                                                        zoom = startZoom + (target - startZoom) * fraction
                                                        offset = startOffset + (endOffset - startOffset) * fraction
                                                    }
                                                } finally { zoomAnimating = false }
                                            }
                                        },
                                    )
                                }
                                .pointerInput(session) {
                                    awaitEachGesture {
                                        awaitFirstDown(requireUnconsumed = false)
                                        zoomAnimation?.cancel()
                                        gestureActive = true
                                        session.pauseDetailDecoding()
                                        try {
                                            do {
                                                val event = awaitPointerEvent()
                                                val centroid = event.calculateCentroid()
                                                if (centroid.isSpecified) gestureCentroid = centroid
                                            } while (event.changes.any { it.pressed })
                                        } finally {
                                            gestureActive = false
                                            gestureCentroid = Offset.Unspecified
                                        }
                                    }
                                }
                                .transformable(
                                    state = transformState,
                                    canPan = { !imagePagingEnabled(zoom) },
                                    lockRotationOnZoomPan = true,
                                ),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    // 缩略图底层：相邻页复用它保证拖动随手进入；当前页在预览就绪前也保留它作占位，
                    // 避免「缩略图 → 加载图标 → 清晰图」的硬切换闪烁。
                    Base64Image(
                        b64 = safeImages[page],
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Fit,
                        maxDecodePx = 512,
                    )
                    if (currentPage) {
                        when (val ready = phase) {
                            is RegionImageSession.Phase.Ready -> {
                                // 手势缩放/平移只通过 graphicsLayer 的绘制阶段变换生效。
                                val renderGeometry = resolveImageRenderGeometry(
                                    ready.width,
                                    ready.height,
                                    viewport,
                                    fitScale,
                                    offset,
                                )
                                val renderFitScale = renderGeometry.fitScale
                                val renderOffset = renderGeometry.offset
                                val fitOffset = centeredOffset(ready, viewport, renderFitScale, 1f)
                                // 高清区域淡入覆盖预览，避免预览→清晰的一帧硬跳变造成闪烁。
                                val detailAlpha by animateFloatAsState(
                                    targetValue = if (snapshot.detail != null) 1f else 0f,
                                    animationSpec = tween(180),
                                    label = "detailAlpha",
                                )
                                Canvas(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .graphicsLayer {
                                            translationX = renderOffset.x - zoom * fitOffset.x
                                            translationY = renderOffset.y - zoom * fitOffset.y
                                            scaleX = zoom
                                            scaleY = zoom
                                            transformOrigin = TransformOrigin(0f, 0f)
                                        },
                                ) {
                                    val viewportRect = Rect(0f, 0f, size.width, size.height)
                                    snapshot.preview?.let { preview ->
                                        drawImageInLayerRect(
                                            preview,
                                            imageLayerRect(
                                                Rect(0f, 0f, ready.width.toFloat(), ready.height.toFloat()),
                                                renderFitScale,
                                                fitOffset,
                                            ),
                                        )
                                    }
                                    snapshot.detail?.let { detail ->
                                        val layerRect = imageLayerRect(detail.origRect, renderFitScale, fitOffset)
                                        if (layerRect.right > viewportRect.left &&
                                            layerRect.bottom > viewportRect.top &&
                                            layerRect.left < viewportRect.right &&
                                            layerRect.top < viewportRect.bottom
                                        ) {
                                            drawImageInLayerRect(detail.image, layerRect, alpha = detailAlpha)
                                        }
                                    }
                                }
                            }
                            is RegionImageSession.Phase.Failed -> Text(
                                ready.message,
                                color = Color.White,
                                modifier = Modifier.padding(24.dp),
                            )
                            // 预览未就绪时由底层缩略图占位，不再叠加加载图标造成硬切换。
                            is RegionImageSession.Phase.Loading -> Unit
                        }
                    }
                }
            }
            }
            run {
                // 页码跟随当前滚动位置：用 currentPage + offset 四舍五入，
                // 滑动过半立即更新，而不是等 settledPage 停稳后才变化。
                val liveIndex = (pagerState.currentPage + pagerState.currentPageOffsetFraction)
                    .roundToInt()
                    .coerceIn(0, safeImages.lastIndex)
                Text(
                    "${liveIndex + 1} / ${safeImages.size}",
                    color = Color.White,
                    fontSize = 13.sp,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 12.dp)
                        .background(Color(0x80000000), VaultShape)
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
            if (controlsVisible) {
                IconButton(
                    onClick = onClose,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(8.dp),
                ) {
                    Icon(Icons.Default.Close, stringResource(R.string.system_media_close), tint = Color.White)
                }
            }
        }
    }
}

/** 穿透 ContextWrapper 找到所属 Activity，用于判断 multi-window 状态。 */
private tailrec fun findActivity(context: Context): Activity? = when (context) {
    is Activity -> context
    is ContextWrapper -> findActivity(context.baseContext)
    else -> null
}

/** A modal overlay in the activity's actual content bounds; no second window or screen-size estimates. */
@Composable
private fun FullscreenViewerHost(
    onClose: () -> Unit,
    content: @Composable () -> Unit,
) {
    val activity = findActivity(LocalContext.current) ?: return
    val parent = activity.findViewById<android.view.ViewGroup>(android.R.id.content)
    val composition = androidx.compose.runtime.rememberCompositionContext()
    val latestContent by androidx.compose.runtime.rememberUpdatedState(content)
    val latestClose by androidx.compose.runtime.rememberUpdatedState(onClose)
    DisposableEffect(parent, composition) {
        val coveredViews = (0 until parent.childCount).map { parent.getChildAt(it) }
        val accessibility = coveredViews.map { it.importantForAccessibility }
        coveredViews.forEach { it.importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS }
        val overlay = androidx.compose.ui.platform.ComposeView(activity).apply {
            alpha = 0f
            scaleX = 0.97f
            scaleY = 0.97f
            setParentCompositionContext(composition)
            setBackgroundColor(android.graphics.Color.BLACK)
            setContent {
                androidx.activity.compose.BackHandler { latestClose() }
                Box(
                    Modifier.fillMaxSize()
                        .background(Color.Black)
                        .clipToBounds()
                        .pointerInput(Unit) { detectTapGestures(onTap = {}) },
                ) { latestContent() }
            }
        }
        // This is a new native overlay, so apply its own system insets instead of inheriting
        // already-consumed Compose insets from the thumbnail's composition.
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(overlay) { view, insets ->
            val safe = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars() or
                androidx.core.view.WindowInsetsCompat.Type.displayCutout())
            view.setPadding(safe.left, safe.top, safe.right, safe.bottom)
            insets
        }
        parent.addView(overlay, android.view.ViewGroup.LayoutParams(
            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
        ))
        androidx.core.view.ViewCompat.requestApplyInsets(overlay)
        overlay.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(180L)
            .setInterpolator(android.view.animation.DecelerateInterpolator()).start()
        onDispose {
            overlay.animate().cancel()
            androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(overlay, null)
            parent.removeView(overlay)
            overlay.disposeComposition()
            coveredViews.forEachIndexed { index, view -> view.importantForAccessibility = accessibility[index] }
        }
    }
}

private const val DETAIL_DECODE_SETTLE_MS = 120L
private const val DETAIL_OFFSET_BUCKET_PX = 2f
private const val DETAIL_ZOOM_BUCKETS_PER_UNIT = 500f

/** 适配视图交给分页器处理横向手势；放大后改由图片自身平移。 */
internal fun imagePagingEnabled(zoom: Float): Boolean = zoom <= 1.0001f

/** 屏幕预览已不足以覆盖当前显示密度时，才补充一个高清可视区域。 */
internal fun shouldDecodeDetailRegion(fitScale: Float, zoom: Float, previewSample: Int): Boolean {
    if (fitScale <= 0f || zoom <= 0f || previewSample <= 0) return false
    if (previewSample == 1) return false
    return fitScale * zoom > 1f / previewSample
}

/** 窗口尺寸变化后，让新旧视口中心继续指向同一个原图坐标。 */
internal fun offsetKeepingViewportCenter(
    oldViewport: IntSize,
    newViewport: IntSize,
    oldOffset: Offset,
    oldDisplayScale: Float,
    newDisplayScale: Float,
): Offset {
    if (oldDisplayScale <= 0f || newDisplayScale <= 0f) return oldOffset
    val imageCenter = Offset(
        (oldViewport.width / 2f - oldOffset.x) / oldDisplayScale,
        (oldViewport.height / 2f - oldOffset.y) / oldDisplayScale,
    )
    return Offset(
        newViewport.width / 2f - imageCenter.x * newDisplayScale,
        newViewport.height / 2f - imageCenter.y * newDisplayScale,
    )
}

/**
 * 双击第一阶段缩放：让图片“最短边”铺满屏幕。
 *  - 横图（宽 >= 高）：高度铺满屏幕高度（16:9 中 9 边铺满高度）；
 *  - 竖图（宽 < 高）：宽度铺满屏幕宽度（9:16 中 9 边铺满宽度）。
 * 返回值是相对 [fitScale] 的倍率；最短边在适配视图下已铺满时返回 1f。
 */
internal fun shortSideFillZoom(
    imageWidth: Int,
    imageHeight: Int,
    viewport: IntSize,
    fitScale: Float,
): Float {
    if (fitScale <= 0f || imageWidth <= 0 || imageHeight <= 0 ||
        viewport.width <= 0 || viewport.height <= 0
    ) {
        return 1f
    }
    val absoluteScale = if (imageWidth >= imageHeight) {
        viewport.height.toFloat() / imageHeight
    } else {
        viewport.width.toFloat() / imageWidth
    }
    return max(1f, absoluteScale / fitScale)
}

/**
 * 双击第二阶段缩放：在“最短边铺满”基础上继续放大，
 * 保证至少到达原图 1:1（或铺满倍率的两倍），使可视区域按最大分辨率解码。
 */
internal fun secondDoubleTapZoomFor(fitScale: Float, shortFillZoom: Float): Float {
    val nativeZoom = if (fitScale <= 0f) 1f else 1f / fitScale
    val target = max(shortFillZoom * 2f, nativeZoom)
    return min(target, maximumZoomFor(fitScale))
}

/**
 * 双击遵循平台常见 2x 行为：
 * - 普通照片：适配 -> 2x -> 适配；
 * - 2x 后仍低于原图 1:1 的高清图：适配 -> 2x -> 原图 1:1 -> 适配。
 */
internal fun doubleTapTargetZoom(currentZoom: Float, fitScale: Float, shortFillZoom: Float): Float {
    val maximum = maximumZoomFor(fitScale)
    if (maximum <= 1f) return 1f
    val twoTimesZoom = min(2f, maximum)
    val nativeZoom = max(1f, if (fitScale <= 0f) 1f else 1f / fitScale)
    val hasNativeStage = fitScale > 0f && fitScale * twoTimesZoom < 1f - 0.001f
    return when {
        currentZoom <= 1.001f -> twoTimesZoom
        hasNativeStage && currentZoom < nativeZoom - 0.001f -> nativeZoom
        else -> 1f
    }
}

/** 最大缩放为原图 1:1 显示倍率的四倍。 */
internal fun maximumZoomFor(fitScale: Float): Float {
    if (fitScale <= 0f) return 1f
    return max(1f, 4f / fitScale)
}

/** 为单个可视区域选择不低于屏幕显示密度的最大 2 次幂采样率。 */
internal fun detailSampleForDisplayScale(displayScale: Float): Int {
    if (displayScale <= 0f) return 1
    var sample = 1
    while (sample <= Int.MAX_VALUE / 2 && sample * 2f * displayScale <= 1f) sample *= 2
    return sample
}

internal data class ImageRenderGeometry(val fitScale: Float, val offset: Offset)

/** 新图片首次 Ready 时不等待副作用，直接使用它自己的适配比例与居中位置。 */
internal fun resolveImageRenderGeometry(
    imageWidth: Int,
    imageHeight: Int,
    viewport: IntSize,
    storedFitScale: Float,
    storedOffset: Offset,
): ImageRenderGeometry {
    if (imageWidth <= 0 || imageHeight <= 0 || viewport.width <= 0 || viewport.height <= 0) {
        return ImageRenderGeometry(storedFitScale.coerceAtLeast(0f), storedOffset)
    }
    if (storedFitScale > 0f) return ImageRenderGeometry(storedFitScale, storedOffset)
    val fit = min(
        viewport.width.toFloat() / imageWidth,
        viewport.height.toFloat() / imageHeight,
    )
    return ImageRenderGeometry(
        fit,
        Offset(
            (viewport.width - imageWidth * fit) / 2f,
            (viewport.height - imageHeight * fit) / 2f,
        ),
    )
}

/** 预览层与高清层共用同一套浮点源坐标到图层坐标映射，避免独立取整造成跳动。 */
internal fun imageLayerRect(source: Rect, fitScale: Float, fitOffset: Offset): Rect = Rect(
    left = fitOffset.x + source.left * fitScale,
    top = fitOffset.y + source.top * fitScale,
    right = fitOffset.x + source.right * fitScale,
    bottom = fitOffset.y + source.bottom * fitScale,
)

private fun DrawScope.drawImageInLayerRect(image: ImageBitmap, destination: Rect, alpha: Float = 1f) {
    if (alpha <= 0.001f) return
    if (destination.width <= 0f || destination.height <= 0f || image.width <= 0 || image.height <= 0) return
    withTransform({
        translate(destination.left, destination.top)
        scale(
            scaleX = destination.width / image.width,
            scaleY = destination.height / image.height,
            pivot = Offset.Zero,
        )
    }) {
        drawImage(image, topLeft = Offset.Zero, alpha = alpha)
    }
}

/**
 * 按官方推荐让预览位图匹配实际显示区域：选择最大的 2 次幂采样值，
 * 但确保采样后的宽高仍不小于图片按比例适配视口后的尺寸。
 */
internal fun previewSampleFor(width: Int, height: Int, viewport: IntSize): Int {
    if (width <= 0 || height <= 0 || viewport.width <= 0 || viewport.height <= 0) return 1
    val fitScale = min(
        viewport.width.toFloat() / width,
        viewport.height.toFloat() / height,
    ).coerceAtMost(1f)
    val requiredWidth = max(1f, width * fitScale)
    val requiredHeight = max(1f, height * fitScale)
    var sample = 1
    while (sample <= Int.MAX_VALUE / 2 &&
        width / (sample * 2f) >= requiredWidth &&
        height / (sample * 2f) >= requiredHeight
    ) {
        sample *= 2
    }
    return sample
}

internal data class ImageDetailDecodeSpec(
    val left: Int,
    val top: Int,
    val right: Int,
    val bottom: Int,
    val sample: Int,
)

/**
 * 把最终稳定视口映射为一个原图矩形。只增加很小的预取边距，确保一次解码约等于一屏，
 * 不再生成几十个不同采样率的瓦片，也不会在手势移动期间滚动读取保险库。
 */
internal fun imageDetailDecodeSpec(
    imageWidth: Int,
    imageHeight: Int,
    viewport: IntSize,
    zoom: Float,
    offset: Offset,
    fitScale: Float,
    marginRatio: Float = 0.08f,
    maxDecodedPixels: Long = 8L * 1024L * 1024L,
): ImageDetailDecodeSpec? {
    if (imageWidth <= 0 || imageHeight <= 0 || viewport.width <= 0 || viewport.height <= 0 ||
        zoom <= 0f || fitScale <= 0f || marginRatio < 0f || maxDecodedPixels <= 0L
    ) return null
    val scale = fitScale * zoom
    val visibleLeft = (-offset.x / scale).coerceIn(0f, imageWidth.toFloat())
    val visibleTop = (-offset.y / scale).coerceIn(0f, imageHeight.toFloat())
    val visibleRight = ((viewport.width - offset.x) / scale).coerceIn(0f, imageWidth.toFloat())
    val visibleBottom = ((viewport.height - offset.y) / scale).coerceIn(0f, imageHeight.toFloat())
    if (visibleRight <= visibleLeft || visibleBottom <= visibleTop) return null

    val marginX = (visibleRight - visibleLeft) * marginRatio
    val marginY = (visibleBottom - visibleTop) * marginRatio
    val requestedLeft = floor(visibleLeft - marginX).toInt().coerceAtLeast(0)
    val requestedTop = floor(visibleTop - marginY).toInt().coerceAtLeast(0)
    val requestedRight = ceil(visibleRight + marginX).toInt().coerceAtMost(imageWidth)
    val requestedBottom = ceil(visibleBottom + marginY).toInt().coerceAtMost(imageHeight)
    if (requestedRight <= requestedLeft || requestedBottom <= requestedTop) return null
    var sample = detailSampleForDisplayScale(scale)
    while (true) {
        val left = requestedLeft / sample * sample
        val top = requestedTop / sample * sample
        // Math.ceilDiv requires a newer JVM than the Java 17 used by our build and tests.
        val right = min(imageWidth.toLong(), ((requestedRight.toLong() + sample - 1L) / sample) * sample).toInt()
        val bottom = min(imageHeight.toLong(), ((requestedBottom.toLong() + sample - 1L) / sample) * sample).toInt()
        val decodedPixels = ((right - left).toLong() + sample - 1L) / sample *
            (((bottom - top).toLong() + sample - 1L) / sample)
        if (decodedPixels <= maxDecodedPixels || sample > Int.MAX_VALUE / 2) {
            return ImageDetailDecodeSpec(left, top, right, bottom, sample)
        }
        sample *= 2
    }
}

internal fun imageDetailPixelBudget(maxHeapBytes: Long): Long {
    val pixelsByHeap = maxHeapBytes / 8L / 4L
    return pixelsByHeap.coerceIn(2L * 1024L * 1024L, 8L * 1024L * 1024L)
}

/** collectAsState 切换 Flow 时可能保留旧值一帧；只有当前会话自己的快照允许进入绘制。 */
internal fun <T> currentImageSessionValue(
    expectedSessionId: Long,
    collectedSessionId: Long,
    collected: T,
    current: T,
): T = if (collectedSessionId == expectedSessionId) collected else current

private data class ImageViewportRequest(
    val viewport: IntSize,
    val zoom: Float,
    val offset: Offset,
    val fitScale: Float,
) {
    fun settled(): ImageViewportRequest = copy(
        zoom = (zoom * DETAIL_ZOOM_BUCKETS_PER_UNIT).roundToInt() / DETAIL_ZOOM_BUCKETS_PER_UNIT,
        offset = Offset(
            (offset.x / DETAIL_OFFSET_BUCKET_PX).roundToInt() * DETAIL_OFFSET_BUCKET_PX,
            (offset.y / DETAIL_OFFSET_BUCKET_PX).roundToInt() * DETAIL_OFFSET_BUCKET_PX,
        ),
    )
}

/**
 * 查看器会话：数据库只参与一次顺序物化，手势生命周期内不再读取数据库。
 * 解码固定在单个后台低优先级线程，避免与 Compose 主线程及通用 Default 池争抢 CPU。
 */
private class RegionImageSession {
    val id = nextId.getAndIncrement()

    sealed interface Phase {
        data object Loading : Phase
        data class Ready(val width: Int, val height: Int) : Phase
        data class Failed(val message: String) : Phase
    }

    data class Snapshot(
        val sessionId: Long,
        val phase: Phase,
        val preview: ImageBitmap?,
        val detail: DetailRegion?,
    )

    data class DetailRegion(val image: ImageBitmap, val origRect: Rect)

    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread({
            runCatching { Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND) }
            task.run()
        }, "vault-image-decode").apply { isDaemon = true }
    }
    private val dispatcher = executor.asCoroutineDispatcher()
    private val scopeJob = SupervisorJob()
    private val scope = kotlinx.coroutines.CoroutineScope(scopeJob + dispatcher)
    private val _snapshot = MutableStateFlow(Snapshot(id, Phase.Loading, null, null))
    val snapshot: StateFlow<Snapshot> = _snapshot.asStateFlow()

    private var decoder: BitmapRegionDecoder? = null
    private var source: Source? = null
    private var openStarted = false
    @Volatile
    private var closed = false
    private var previewSample = 1
    private var detailJob: Job? = null
    @Volatile
    private var requestEpoch = 0L
    @Volatile
    private var publishedSpec: ImageDetailDecodeSpec? = null
    private val detailPixelBudget = imageDetailPixelBudget(Runtime.getRuntime().maxMemory())

    private sealed interface Source {
        val orientation: Int
        fun newDecoder(): BitmapRegionDecoder
        fun close()
    }

    private class FdSource(private val pfd: ParcelFileDescriptor) : Source {
        override val orientation: Int = runCatching {
            android.media.ExifInterface(pfd.fileDescriptor).getAttributeInt(android.media.ExifInterface.TAG_ORIENTATION, 1)
        }.getOrDefault(1)
        override fun newDecoder(): BitmapRegionDecoder =
            BitmapRegionDecoder.newInstance(pfd.fileDescriptor, false)

        override fun close() {
            runCatching { pfd.close() }
        }
    }

    fun open(context: Context, value: String, viewport: IntSize) {
        if (openStarted || closed || viewport.width <= 0 || viewport.height <= 0) return
        openStarted = true
        scope.launch {
            val src = try {
                materializeSource(context, value)
            } catch (t: Throwable) {
                if (!closed) _snapshot.value = Snapshot(
                    id,
                    Phase.Failed(
                        when (t) {
                            is PmvMediaSessionLockedException ->
                                context.getString(R.string.system_media_session_locked)
                            else -> t.message ?: context.getString(R.string.system_media_image_read_failed)
                        },
                    ),
                    null,
                    null,
                )
                return@launch
            }
            if (closed) {
                src.close()
                return@launch
            }
            source = src
            val opened = try {
                src.newDecoder()
            } catch (t: Throwable) {
                src.close()
                source = null
                _snapshot.value = Snapshot(
                    id,
                    Phase.Failed(
                        context.getString(
                            R.string.system_media_image_decode_failed,
                            t.message ?: context.getString(R.string.system_media_image_format_unsupported),
                        ),
                    ),
                    null,
                    null,
                )
                return@launch
            }
            if (closed) {
                opened.recycle()
                src.close()
                source = null
                return@launch
            }
            decoder = opened
            val preview = try {
                previewSample = previewSampleFor(
                    if (orientationSwapsAxes(src.orientation)) opened.height else opened.width,
                    if (orientationSwapsAxes(src.orientation)) opened.width else opened.height, viewport)
                val options = BitmapFactory.Options().apply {
                    inSampleSize = previewSample
                    inPreferredConfig = Bitmap.Config.ARGB_8888
                }
                opened.decodeRegion(AndroidRect(0, 0, opened.width, opened.height), options)
                    ?.oriented(src.orientation)?.asImageBitmap() ?: error(context.getString(R.string.system_media_image_preview_decode_failed))
            } catch (t: Throwable) {
                if (!closed) {
                    _snapshot.value = Snapshot(
                        id,
                        Phase.Failed(
                            context.getString(
                                R.string.system_media_image_preview_failed,
                                t.message ?: context.getString(R.string.system_media_image_format_unsupported),
                            ),
                        ),
                        null,
                        null,
                    )
                }
                return@launch
            }
            if (!closed) _snapshot.value = Snapshot(id, Phase.Ready(
                if (orientationSwapsAxes(src.orientation)) opened.height else opened.width,
                if (orientationSwapsAxes(src.orientation)) opened.width else opened.height), preview, null)
        }
    }

    /**
     * 所有来源都只顺序读取一次到私有缓存文件，然后持有 FD 并立即删除目录项。
     * PMVE 因而只打开一次 Vault session、顺序认证一次 Chunk；之后 BitmapRegionDecoder
     * 的随机读取完全发生在已打开的本地 FD 上，既不保留可见明文文件，也不回查数据库。
     */
    private fun materializeSource(context: Context, value: String): Source {
        val directory = File(context.cacheDir, "viewer").also { dir ->
            check(dir.mkdirs() || dir.isDirectory) {
                context.getString(R.string.system_media_viewer_cache_directory_failed)
            }
            // 上次进程若在顺序物化中崩溃，缓存文件尚未来得及 unlink；下次打开时立即清理。
            dir.listFiles().orEmpty().filter(File::isFile).forEach(File::delete)
        }
        val target = File(directory, "${Process.myPid()}_${System.nanoTime()}.img")
        var pfd: ParcelFileDescriptor? = null
        try {
            pfd = ParcelFileDescriptor.open(
                target,
                ParcelFileDescriptor.MODE_CREATE or
                    ParcelFileDescriptor.MODE_TRUNCATE or
                    ParcelFileDescriptor.MODE_READ_WRITE,
            )
            // 先 unlink 再写明文：即使进程在物化中崩溃，文件也会由内核随 FD 关闭而回收。
            check(target.delete()) { context.getString(R.string.system_media_viewer_cache_hide_failed) }
            ParcelFileDescriptor.dup(pfd.fileDescriptor).use { writeFd ->
                FileOutputStream(writeFd.fileDescriptor).buffered().use { output ->
                when {
                    isPmvEMediaRef(value) -> PmvMediaUiSession.copyTo(value, output)
                    value.startsWith(IMAGE_FILE_PREFIX) -> {
                        val file = imageFileFromRef(context, value)
                            ?: error(context.getString(R.string.system_media_image_file_missing))
                        file.inputStream().buffered().use { input ->
                            MediaCrypto.decryptStream(input).use { plain -> plain.copyTo(output) }
                        }
                    }
                    else -> {
                        val clean = if (value.contains(",")) value.substringAfter(",") else value
                        ByteArrayInputStream(clean.toByteArray(Charsets.US_ASCII)).use { encoded ->
                            Base64InputStream(encoded, Base64.DEFAULT).use { decoded -> decoded.copyTo(output) }
                        }
                    }
                }
            }
            }
            check(pfd.statSize > 0L) { context.getString(R.string.system_media_image_data_empty) }
            Os.lseek(pfd.fileDescriptor, 0L, OsConstants.SEEK_SET)
            return FdSource(pfd)
        } catch (t: Throwable) {
            runCatching { pfd?.close() }
            target.delete()
            throw t
        }
    }

    fun updateViewport(
        viewport: IntSize,
        zoom: Float,
        offset: Offset,
        fitScale: Float,
    ) {
        val ready = _snapshot.value.phase as? Phase.Ready ?: return
        val epoch = ++requestEpoch
        detailJob?.cancel()
        detailJob = null

        if (!shouldDecodeDetailRegion(fitScale, zoom, previewSample)) {
            publishedSpec = null
            _snapshot.value = _snapshot.value.copy(detail = null)
            return
        }
        val spec = imageDetailDecodeSpec(
            ready.width,
            ready.height,
            viewport,
            zoom,
            offset,
            fitScale,
            maxDecodedPixels = detailPixelBudget,
        ) ?: return
        if (spec == publishedSpec) return

        detailJob = scope.launch {
            val dec = decoder ?: return@launch
            val orientation = source?.orientation ?: 1
            val raw = rawImageRegion(Rect(spec.left.toFloat(), spec.top.toFloat(), spec.right.toFloat(), spec.bottom.toFloat()), dec.width, dec.height, orientation)
            val bitmap = try {
                dec.decodeRegion(
                    AndroidRect(raw.left.toInt(), raw.top.toInt(), raw.right.toInt(), raw.bottom.toInt()),
                    BitmapFactory.Options().apply {
                        inSampleSize = spec.sample
                        inPreferredConfig = Bitmap.Config.ARGB_8888
                    },
                )?.oriented(orientation) ?: return@launch
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Throwable) {
                return@launch
            }
            if (closed || requestEpoch != epoch) {
                bitmap.recycle()
                return@launch
            }
            publishedSpec = spec
            _snapshot.value = _snapshot.value.copy(
                detail = DetailRegion(
                    bitmap.asImageBitmap(),
                    Rect(
                        spec.left.toFloat(),
                        spec.top.toFloat(),
                        spec.right.toFloat(),
                        spec.bottom.toFloat(),
                    ),
                ),
            )
            detailJob = null
        }
    }

    fun pauseDetailDecoding() {
        requestEpoch++
        detailJob?.cancel()
        detailJob = null
    }

    fun close() {
        if (closed) return
        closed = true
        requestEpoch++
        detailJob?.cancel()
        scopeJob.cancel()
        executor.execute {
            decoder?.recycle()
            decoder = null
            source?.close()
            source = null
        }
        executor.shutdown()
    }

    private companion object {
        val nextId = java.util.concurrent.atomic.AtomicLong(1L)
    }
}
