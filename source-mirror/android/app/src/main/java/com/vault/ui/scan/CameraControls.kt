package com.vault.ui.scan

import android.view.GestureDetector
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import androidx.camera.core.Camera
import androidx.camera.core.FocusMeteringAction
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import java.util.concurrent.TimeUnit

/**
 * FIT_CENTER（与 PreviewView.ScaleType.FIT_CENTER 同规则）下预览画面在视图中的显示矩形。
 * 相机帧比屏幕更方时上下留黑边，叠加层必须按这个矩形而不是整屏来定位。[rotationDegrees]
 * 为图像相对屏幕的旋转角；尺寸未知（首帧到达前）时返回 null。
 */
internal fun previewDisplayRect(
    srcW: Int, srcH: Int, rotationDegrees: Int, viewW: Float, viewH: Float,
): Rect? {
    if (srcW <= 0 || srcH <= 0 || viewW <= 0f || viewH <= 0f) return null
    val r = ((rotationDegrees % 360) + 360) % 360
    val dw = if (r == 90 || r == 270) srcH else srcW
    val dh = if (r == 90 || r == 270) srcW else srcH
    val scale = minOf(viewW / dw, viewH / dh)
    val shownW = dw * scale
    val shownH = dh * scale
    val ox = (viewW - shownW) / 2f
    val oy = (viewH - shownH) / 2f
    return Rect(ox, oy, ox + shownW, oy + shownH)
}

/** PreviewView's metering factory accounts for crop, rotation and sensor coordinates. */
@Composable
internal fun CameraGestures(preview: PreviewView, camera: Camera?, onZoom: (Float) -> Unit): Offset? {
    var focus by remember { mutableStateOf<Offset?>(null) }
    val latestZoom by rememberUpdatedState(onZoom)
    LaunchedEffect(focus) { if (focus != null) { delay(900); focus = null } }
    DisposableEffect(preview, camera) {
        var multiTouch = false
        var ratio = camera?.cameraInfo?.zoomState?.value?.zoomRatio ?: 1f
        val scale = ScaleGestureDetector(preview.context, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScaleBegin(detector: ScaleGestureDetector): Boolean {
                ratio = camera?.cameraInfo?.zoomState?.value?.zoomRatio ?: 1f
                multiTouch = true
                return true
            }
            override fun onScale(detector: ScaleGestureDetector): Boolean {
                val zoom = camera?.cameraInfo?.zoomState?.value ?: return false
                ratio = (ratio * detector.scaleFactor).coerceIn(zoom.minZoomRatio, zoom.maxZoomRatio)
                camera.cameraControl.setZoomRatio(ratio)
                latestZoom(ratio)
                return true
            }
        })
        val taps = GestureDetector(preview.context, object : GestureDetector.SimpleOnGestureListener() {
            override fun onDown(event: MotionEvent) = true
            override fun onSingleTapUp(event: MotionEvent): Boolean {
                val cam = camera ?: return false
                if (multiTouch) return false
                val point = preview.meteringPointFactory.createPoint(event.x, event.y)
                val action = FocusMeteringAction.Builder(point, FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE)
                    .setAutoCancelDuration(3, TimeUnit.SECONDS).build()
                if (cam.cameraInfo.isFocusMeteringSupported(action)) {
                    cam.cameraControl.startFocusAndMetering(action)
                    focus = Offset(event.x, event.y)
                }
                preview.performClick()
                return true
            }
        })
        preview.setOnTouchListener { _, event ->
            if (event.actionMasked == MotionEvent.ACTION_DOWN) multiTouch = false
            if (event.pointerCount > 1) multiTouch = true
            scale.onTouchEvent(event)
            taps.onTouchEvent(event)
            true
        }
        onDispose { preview.setOnTouchListener(null) }
    }
    return focus
}

@Composable
internal fun CameraFocusIndicator(point: Offset?) {
    if (point != null) Canvas(Modifier.fillMaxSize()) {
        drawCircle(Color.White.copy(alpha = 0.9f), radius = 26.dp.toPx(), center = point, style = Stroke(1.5.dp.toPx()))
        drawCircle(Color.White, radius = 2.dp.toPx(), center = point)
    }
}

/**
 * 倍率控件：单个胶囊显示当前倍率，点击在近/远两档之间切换。
 *
 * 此前是 0.5x/1x/2x 三个并排圆点，而多数设备的 minZoomRatio 就是 1.0，0.5x 会被过滤掉，
 * 实际只剩 1x 与 2x 两颗——两档却摆两颗按钮，不如合成一个：默认 1x，点一下到 2x，再点回来。
 *
 * 显示的是**实时倍率**而不是档位名：双指缩放过程中 [CameraGestures] 每帧回报 zoomRatio，
 * 指示器必须跟着手指走，否则用户捏到 1.4x 却仍显示 1x。点击目标按当前值落在两档的哪一侧决定。
 *
 * 设备不支持二倍变焦（maxZoomRatio 不足）时整体不显示——此时这颗按钮没有意义。
 */
@Composable
internal fun CameraZoomControls(camera: Camera?, ratio: Float, onZoom: (Float) -> Unit, modifier: Modifier = Modifier) {
    val zoom = camera?.cameraInfo?.zoomState?.value ?: return
    // 1x 不可达时退到设备最小倍率，2x 不可达时退到设备上限。
    val near = maxOf(1f, zoom.minZoomRatio)
    val far = minOf(2f, zoom.maxZoomRatio)
    // 两档几乎重合（设备不支持变焦）就没有切换的意义，直接不画。
    if (far - near < 0.15f) return
    val target = if (ratio < (near + far) / 2f) far else near
    Box(
        modifier = modifier
            .background(Color.Black.copy(alpha = 0.45f), CircleShape)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) {
                camera.cameraControl.setZoomRatio(target)
                onZoom(target)
            },
        contentAlignment = Alignment.Center,
    ) {
        // min 宽度固定，1x → 1.5x 的位数变化不会让胶囊左右抖动。
        Text(
            // 整数档去掉 ".0"：1x 而不是 1.0x，与原来的按钮文案一致。
            String.format(java.util.Locale.ROOT, "%.1f×", ratio).removeSuffix(".0×"),
            color = Color.White,
            fontSize = 14.sp,
            modifier = Modifier.widthIn(min = 56.dp).padding(horizontal = 16.dp, vertical = 10.dp),
            textAlign = TextAlign.Center,
        )
    }
}
