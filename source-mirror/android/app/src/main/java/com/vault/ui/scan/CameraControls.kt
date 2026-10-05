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
import androidx.compose.ui.unit.dp
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

@Composable
internal fun CameraZoomControls(camera: Camera?, ratio: Float, onZoom: (Float) -> Unit, modifier: Modifier = Modifier) {
    val zoom = camera?.cameraInfo?.zoomState?.value ?: return
    val choices = listOf(0.5f, 1f, 2f).filter { it in zoom.minZoomRatio..zoom.maxZoomRatio }
    Row(modifier.background(Color.Black.copy(alpha = 0.45f), CircleShape).padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
        choices.forEach { value ->
            val selected = kotlin.math.abs(value - ratio) < 0.1f
            Box(Modifier.size(40.dp).background(if (selected) Color.White.copy(alpha = 0.2f) else Color.Transparent, CircleShape)
                // 倍率按钮是圆形，默认 ripple 会被裁成矩形色块，这里只保留圆形背景高亮。
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                ) {
                    camera.cameraControl.setZoomRatio(value)
                    onZoom(value)
                }, contentAlignment = Alignment.Center) {
                Text(if (selected) String.format(java.util.Locale.ROOT, "%.1f×", ratio) else "${value.toString().removeSuffix(".0")}×",
                    color = if (selected) com.vault.ui.BrandPrimary else Color.White)
            }
        }
    }
}
