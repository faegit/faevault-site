package com.vault.ui.scan

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.util.Size
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import com.vault.ui.BreathingRing
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import com.vault.ui.localizeUiText
import com.vault.ui.uiText
import com.vault.R
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.common.util.concurrent.ListenableFuture
import com.vault.ocr.DocCrop
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.abs
import kotlin.math.roundToInt

private suspend fun <T> ListenableFuture<T>.awaitFuture(): T = suspendCancellableCoroutine { cont ->
    addListener({
        try { cont.resume(get()) } catch (t: Throwable) { cont.resumeWithException(t) }
    }, Runnable::run)
}

private data class NormalizedQuad(
    val p0: Offset,
    val p1: Offset,
    val p2: Offset,
    val p3: Offset,
)

/**
 * 自写文档扫描相机。两段式流程：
 *  1) 取景：Preview + ImageAnalysis 实时跑 [DocCrop.detectQuadFromGray]，画黄色四边形提示
 *  2) 复核裁剪：以实时检测到的四边形的外接矩形为初始 ROI，进入可拖四角调整的复核屏；
 *     用户确认后写入裁剪后的 JPEG，返回 FileProvider URI。
 *
 * 取消复核会回到第一段重新取景，相机不重启。
 */
class CameraScanActivity : ComponentActivity() {

    private lateinit var analysisExecutor: ExecutorService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_SECURE,
        )
        analysisExecutor = Executors.newSingleThreadExecutor()
        setContent {
            // 两段式状态：null 时显示取景屏；非 null 时显示复核屏
            var pending by remember { mutableStateOf<PendingCapture?>(null) }
            val capturedState = pending
            if (capturedState == null) {
                ScanScreen(
                    onClose = { setResult(Activity.RESULT_CANCELED); finish() },
                    onCaptured = { file, initialQuad ->
                        pending = PendingCapture(file, initialQuad)
                    },
                )
            } else {
                ReviewScreen(
                    file = capturedState.file,
                    initialNormalizedQuad = capturedState.initialQuad,
                    onCancel = {
                        // 放弃这张，回到取景；删除中间文件防止 cache 堆积
                        runCatching { capturedState.file.delete() }
                        pending = null
                    },
                    onConfirm = { uri ->
                        val data = Intent().apply {
                            setData(uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        setResult(Activity.RESULT_OK, data)
                        finish()
                    },
                )
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
    }

    private data class PendingCapture(val file: File, val initialQuad: NormalizedQuad?)

    // ─── 取景屏 ────────────────────────────────────────────────────

    @Composable
    private fun ScanScreen(
        onClose: () -> Unit,
        onCaptured: (file: File, initialQuad: NormalizedQuad?) -> Unit,
    ) {
        val ctx = LocalContext.current
        val lifecycleOwner = LocalLifecycleOwner.current
        val previewView = remember {
            PreviewView(ctx).apply {
                scaleType = PreviewView.ScaleType.FIT_CENTER
                implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            }
        }

        var torchOn by remember { mutableStateOf(false) }
        var camera by remember { mutableStateOf<Camera?>(null) }
        var zoomRatio by remember { mutableStateOf(1f) }
        val focusPoint = CameraGestures(previewView, camera) { zoomRatio = it }
        val torchIcon = if (torchOn) Icons.Filled.FlashOn else Icons.Filled.FlashOff

        var quad by remember { mutableStateOf<DocCrop.QuadBox?>(null) }
        var analysisW by remember { mutableIntStateOf(0) }
        var analysisH by remember { mutableIntStateOf(0) }
        var rotation by remember { mutableIntStateOf(0) }
        var overlaySize by remember { mutableStateOf(IntSize.Zero) }
        var capturing by remember { mutableStateOf(false) }
        var imageCapture by remember { mutableStateOf<ImageCapture?>(null) }

        LaunchedEffect(Unit) {
            val provider = ProcessCameraProvider.getInstance(ctx).awaitFuture()
            val preview = Preview.Builder().build().also {
                it.surfaceProvider = previewView.surfaceProvider
            }
            val resSelector = ResolutionSelector.Builder()
                .setResolutionStrategy(
                    ResolutionStrategy(Size(640, 480), ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER)
                ).build()
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                .setResolutionSelector(resSelector)
                .build().also { ia ->
                    ia.setAnalyzer(analysisExecutor) { proxy ->
                        try {
                            val width = proxy.width
                            val height = proxy.height
                            val degrees = proxy.imageInfo.rotationDegrees
                            val detected = runCatching { analyzeFrame(proxy) }.getOrNull()
                            previewView.post {
                                analysisW = width
                                analysisH = height
                                rotation = degrees
                                quad = detected
                            }
                        } finally {
                            proxy.close()
                        }
                    }
                }
            // 证件/文档拍摄要的是清晰度，不是快门速度：
            // CAPTURE_MODE_MINIMIZE_LATENCY 在 AOSP 里会关掉 3A 收敛检查（不触发 AF、不等 AE/AWB），
            // 按下快门取的是"当下那一帧"，常常还没合焦，拍出来就是糊的。
            // 显式锁定 4:3 + 优先分辨率：与预览/分析同比例，且不让 CameraX 为帧率挑小画幅。
            val captureSelector = ResolutionSelector.Builder()
                .setAspectRatioStrategy(AspectRatioStrategy.RATIO_4_3_FALLBACK_AUTO_STRATEGY)
                .setAllowedResolutionMode(ResolutionSelector.PREFER_HIGHER_RESOLUTION_OVER_CAPTURE_RATE)
                .build()
            val capture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MAXIMIZE_QUALITY)
                .setResolutionSelector(captureSelector)
                .build()
            imageCapture = capture
            try {
                provider.unbindAll()
                val cam = provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview, analysis, capture,
                )
                camera = cam
            } catch (t: Throwable) {
            Toast.makeText(ctx, ctx.getString(R.string.scan_camera_start_failed, t.message), Toast.LENGTH_LONG).show()
                onClose()
            }
        }

        Box(
            Modifier
                .fillMaxSize()
                .background(Color.Black)
        ) {
            AndroidView(
                factory = { previewView },
                modifier = Modifier
                    .fillMaxSize()
                    .onSizeChanged { overlaySize = it },
            )

            CameraFocusIndicator(focusPoint)
            // FIT_CENTER 下预览画面两侧/上下会有黑边，倍率按钮按画面底边定位才能落在画面内；
            // 画面几乎铺满屏幕时退回快门上方的原位，避免与快门重叠。
            val density = LocalDensity.current
            val previewRect = previewDisplayRect(analysisW, analysisH, rotation, overlaySize.width.toFloat(), overlaySize.height.toFloat())
            val zoomBottomPadding = with(density) {
                val barsInset = WindowInsets.systemBars.getBottom(this).toDp()
                val imageInset = previewRect?.let { (overlaySize.height - it.bottom).coerceAtLeast(0f).toDp() }
                maxOf(barsInset + 132.dp, (imageInset ?: 0.dp) + 12.dp)
            }
            CameraZoomControls(camera, zoomRatio, { zoomRatio = it },
                Modifier.align(Alignment.BottomCenter).padding(bottom = zoomBottomPadding))

            // 实时四边聚焦框（黄线）
            Canvas(modifier = Modifier.fillMaxSize()) {
                val q = quad ?: return@Canvas
                if (overlaySize.width == 0 || overlaySize.height == 0) return@Canvas
                if (analysisW == 0 || analysisH == 0) return@Canvas
                val pts = mapQuadToOverlayPoints(
                    q, analysisW, analysisH, rotation,
                    overlaySize.width.toFloat(), overlaySize.height.toFloat(),
                ) ?: return@Canvas
                val path = Path().apply {
                    moveTo(pts[0], pts[1])
                    lineTo(pts[2], pts[3])
                    lineTo(pts[4], pts[5])
                    lineTo(pts[6], pts[7])
                    close()
                }
                drawPath(path, color = Color(0xFFFFC107), style = Stroke(width = 6f))
            }

            // 顶部关闭 + 闪光灯 + 提示
            Row(
                Modifier
                    .fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.systemBars)
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onClose) {
                Icon(Icons.Filled.Close, contentDescription = uiText("关闭"), tint = Color.White)
                }
                Spacer(Modifier.size(8.dp))
                Text(
                    text = uiText(if (quad != null) "已检测到文档，按下方按钮拍摄" else "把文档放进画面，会自动框选"),
                    color = Color.White,
                    fontSize = 14.sp,
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = {
                        torchOn = !torchOn
                        camera?.cameraControl?.enableTorch(torchOn)
                    }
                ) {
                Icon(torchIcon, contentDescription = uiText("闪光灯"), tint = Color.White)
                }
            }

            // 底部快门
            Column(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.systemBars)
                    .padding(bottom = 28.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Bottom,
            ) {
                Box(
                    Modifier
                        .size(72.dp)
                                    .clip(CircleShape)
                        .background(if (capturing) Color(0xFF888888) else Color.White, CircleShape)
                        .clickable(enabled = !capturing) {
                            val cap = imageCapture ?: return@clickable
                            capturing = true
                            val outFile = File(
                                File(ctx.cacheDir, "img_capture").also { it.mkdirs() },
                                "scan_${System.currentTimeMillis()}.jpg",
                            )
                            // 抢拍前快照当前四边形 / 旋转角，避免快门按下后帧分析回调把 quad 清掉
                            val snapshotQuad = quad
                            val snapshotRot = rotation
                            val snapshotAw = analysisW
                            val snapshotAh = analysisH
                            val opts = ImageCapture.OutputFileOptions.Builder(outFile).build()
                            cap.takePicture(
                                opts,
                                analysisExecutor,
                                object : ImageCapture.OnImageSavedCallback {
                                    override fun onImageSaved(results: ImageCapture.OutputFileResults) {
                                        val normalized = if (snapshotQuad != null && snapshotAw > 0 && snapshotAh > 0)
                                            quadToNormalizedQuad(snapshotQuad, snapshotAw, snapshotAh, snapshotRot)
                                        else null
                                        // 切回 main 线程更新 Compose 状态
                                        previewView.post {
                                            capturing = false
                                            onCaptured(outFile, normalized)
                                        }
                                    }
                                    override fun onError(exc: androidx.camera.core.ImageCaptureException) {
                                        previewView.post {
                                            capturing = false
                Toast.makeText(ctx, ctx.getString(R.string.scan_capture_failed, exc.message), Toast.LENGTH_LONG).show()
                                        }
                                    }
                                },
                            )
                        },
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = uiText("拍摄"),
                    color = Color.White,
                    fontSize = 13.sp,
                )
            }
        }
    }

    // ─── 复核 / 手动裁剪屏 ──────────────────────────────────────────

    @Composable
    private fun ReviewScreen(
        file: File,
        initialNormalizedQuad: NormalizedQuad?,
        onCancel: () -> Unit,
        onConfirm: (Uri) -> Unit,
    ) {
        val ctx = LocalContext.current
        val scope = rememberCoroutineScope()
        var bmp by remember(file) { mutableStateOf<Bitmap?>(null) }
        var detectedQuad by remember(file) { mutableStateOf<NormalizedQuad?>(null) }
        var imageBitmap by remember(file) { mutableStateOf<ImageBitmap?>(null) }
        LaunchedEffect(file) {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = file.readBytes()
                    // 1800 太紧：decodeOriented 用 2 的幂采样，4000px 采集会被一刀切到 1000px。
                    // 3000 时同样的采集走 sample=2 → 2000px，细节翻倍（内存峰值 ~2000×1500×4B ≈ 12MB）。
                    DocCrop.decodeOriented(bytes, maxSide = 3000)
                }.getOrNull()
            }
            detectedQuad = loaded?.let { image ->
                withContext(Dispatchers.Default) {
                    runCatching { DocCrop.detectQuad(image)?.let { quadToNormalizedQuad(it, image.width, image.height, 0) } }.getOrNull()
                }
            }
            bmp = loaded
            imageBitmap = loaded?.asImageBitmap()
        }

        val bitmap = bmp
        val imgBitmap = imageBitmap
        if (bitmap == null || imgBitmap == null) {
            Box(Modifier.fillMaxSize().background(Color.Black), contentAlignment = Alignment.Center) {
                BreathingRing(color = Color.White)
            }
            return
        }

        // 初始四边形：优先用实时检测到的预选框；否则给中央 80%，保证复核页始终有可调整框。
        var cropQuad by remember(bitmap) {
            mutableStateOf(
                (detectedQuad ?: initialNormalizedQuad)?.sanitize() ?: NormalizedQuad(
                    Offset(0.1f, 0.1f),
                    Offset(0.9f, 0.1f),
                    Offset(0.9f, 0.9f),
                    Offset(0.1f, 0.9f),
                )
            )
        }
        var containerSize by remember { mutableStateOf(IntSize.Zero) }
        var saving by remember { mutableStateOf(false) }

        Box(Modifier.fillMaxSize().background(Color.Black)) {
            Box(
                Modifier
                    .fillMaxSize()
                    .onSizeChanged { containerSize = it }
            ) {
                Image(
                    bitmap = imgBitmap,
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize(),
                )
                if (containerSize.width > 0 && containerSize.height > 0) {
                    CropOverlay(
                        bmpWidth = bitmap.width,
                        bmpHeight = bitmap.height,
                        containerSize = containerSize,
                        cropQuad = cropQuad,
                        onCropChange = { cropQuad = it },
                    )
                }
            }

            // 顶部：取消 + 提示
            Row(
                Modifier
                    .fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.systemBars)
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onCancel, enabled = !saving) {
                Icon(Icons.Filled.Close, contentDescription = uiText("重拍"), tint = Color.White)
                }
                Spacer(Modifier.size(8.dp))
                Text(
                    text = uiText("拖动四角调整裁剪范围"),
                    color = Color.White,
                    fontSize = 14.sp,
                )
            }

            // 底部：确认按钮
            Box(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .windowInsetsPadding(WindowInsets.systemBars)
                    .padding(bottom = 28.dp),
                contentAlignment = Alignment.Center,
            ) {
                Box(
                    Modifier
                        .size(72.dp)
                                    .clip(CircleShape)
                        .background(if (saving) Color(0xFF888888) else Color.White, CircleShape)
                        .clickable(enabled = !saving) {
                            saving = true
                            scope.launch {
                                val outFile = withContext(Dispatchers.IO) {
                                    saveCrop(file, bitmap, cropQuad)
                                }
                                saving = false
                                if (outFile != null) {
                                    val uri = runCatching {
                                        FileProvider.getUriForFile(
                                            ctx, "${ctx.packageName}.fileprovider", outFile,
                                        )
                                    }.getOrNull()
                                    if (uri != null) onConfirm(uri)
                else Toast.makeText(ctx, ctx.getString(R.string.scan_no_crop_result), Toast.LENGTH_LONG).show()
                                } else {
                Toast.makeText(ctx, ctx.getString(R.string.scan_crop_save_failed), Toast.LENGTH_LONG).show()
                                }
                            }
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Filled.Check,
                contentDescription = uiText("确认"),
                        tint = com.vault.ui.BrandPrimary,
                        modifier = Modifier.size(36.dp),
                    )
                }
            }
        }
    }

    private fun saveCrop(srcFile: File, bmp: Bitmap, normalizedQuad: NormalizedQuad): File? {
        return runCatching {
            val w = bmp.width
            val h = bmp.height

            // 使用用户最终确认的四点做透视校正；失败时退回四点外接矩形裁剪。
            val pixelQuad = normalizedQuad.toPixelQuad(w, h)
            val cropped = DocCrop.cropQuad(bmp, pixelQuad) ?: fallbackCrop(bmp, normalizedQuad.bounds(), w, h)
            val baos = ByteArrayOutputStream()
            cropped.compress(Bitmap.CompressFormat.JPEG, 90, baos)
            if (cropped !== bmp) cropped.recycle()
            val outFile = File(srcFile.parentFile, "cropped_${srcFile.name}")
            outFile.writeBytes(baos.toByteArray())
            runCatching { srcFile.delete() }
            outFile
        }.getOrNull()
    }

    private fun fallbackCrop(bmp: Bitmap, normalizedRect: Rect, w: Int, h: Int): Bitmap {
        val l = (normalizedRect.left * w).toInt().coerceIn(0, w - 2)
        val t = (normalizedRect.top * h).toInt().coerceIn(0, h - 2)
        val r = (normalizedRect.right * w).toInt().coerceIn(l + 1, w)
        val b = (normalizedRect.bottom * h).toInt().coerceIn(t + 1, h)
        return Bitmap.createBitmap(bmp, l, t, r - l, b - t)
    }

    // ─── 帧分析 ────────────────────────────────────────────────────

    @androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
    private fun analyzeFrame(proxy: ImageProxy): DocCrop.QuadBox? {
        val image = proxy.image ?: return null
        val yPlane = image.planes.getOrNull(0) ?: return null
        val buf = yPlane.buffer
        val bytes = ByteArray(buf.remaining())
        buf.get(bytes)
        return DocCrop.detectQuadFromGray(
            y = bytes,
            width = proxy.width,
            height = proxy.height,
            rowStride = yPlane.rowStride,
        )
    }

    // ─── 坐标变换辅助 ──────────────────────────────────────────────

    /**
     * 将检测到的四边形的 4 个角点（分析分辨率坐标）映射到屏幕 overlay 坐标。
     * 返回 `FloatArray`：[x0, y0, x1, y1, x2, y2, x3, y3] 或 null。
     */
    private fun mapQuadToOverlayPoints(
        quad: DocCrop.QuadBox,
        aw: Int, ah: Int, rot: Int,
        vw: Float, vh: Float,
    ): FloatArray? {
        if (aw == 0 || ah == 0 || vw == 0f || vh == 0f) return null
        val r = ((rot % 360) + 360) % 360
        // 原始角点
        val corners = arrayOf(
            intArrayOf(quad.x0, quad.y0),
            intArrayOf(quad.x1, quad.y1),
            intArrayOf(quad.x2, quad.y2),
            intArrayOf(quad.x3, quad.y3),
        )
        // 旋转到预览屏朝向
        val rotCorners = when (r) {
            0 -> corners
            90 -> corners.map { intArrayOf(ah - it[1], it[0]) }.toTypedArray()
            180 -> corners.map { intArrayOf(aw - it[0], ah - it[1]) }.toTypedArray()
            270 -> corners.map { intArrayOf(it[1], aw - it[0]) }.toTypedArray()
            else -> corners
        }
        // 计算旋转后的画幅尺寸
        val dw = if (r == 90 || r == 270) ah else aw
        val dh = if (r == 90 || r == 270) aw else ah
        if (dw == 0 || dh == 0) return null
        val rect = previewDisplayRect(aw, ah, r, vw, vh) ?: return null
        val scale = rect.width / dw

        val out = FloatArray(8)
        for (i in 0..3) {
            out[i * 2] = rect.left + rotCorners[i][0] * scale
            out[i * 2 + 1] = rect.top + rotCorners[i][1] * scale
        }
        return out
    }

    /**
     * 从分析帧四边形计算归一化四点坐标（传给复核屏的初始裁剪）。
     */
    private fun quadToNormalizedQuad(
        quad: DocCrop.QuadBox, aw: Int, ah: Int, rot: Int,
    ): NormalizedQuad {
        val r = ((rot % 360) + 360) % 360
        val corners = listOf(
            intArrayOf(quad.x0, quad.y0),
            intArrayOf(quad.x1, quad.y1),
            intArrayOf(quad.x2, quad.y2),
            intArrayOf(quad.x3, quad.y3),
        )
        val rotCorners = when (r) {
            0 -> corners
            90 -> corners.map { intArrayOf(ah - it[1], it[0]) }
            180 -> corners.map { intArrayOf(aw - it[0], ah - it[1]) }
            270 -> corners.map { intArrayOf(it[1], aw - it[0]) }
            else -> corners
        }
        val dw = if (r == 90 || r == 270) ah else aw
        val dh = if (r == 90 || r == 270) aw else ah
        if (dw == 0 || dh == 0) {
            return NormalizedQuad(
                Offset(0.1f, 0.1f),
                Offset(0.9f, 0.1f),
                Offset(0.9f, 0.9f),
                Offset(0.1f, 0.9f),
            )
        }
        return NormalizedQuad(
            Offset(rotCorners[0][0].toFloat() / dw, rotCorners[0][1].toFloat() / dh),
            Offset(rotCorners[1][0].toFloat() / dw, rotCorners[1][1].toFloat() / dh),
            Offset(rotCorners[2][0].toFloat() / dw, rotCorners[2][1].toFloat() / dh),
            Offset(rotCorners[3][0].toFloat() / dw, rotCorners[3][1].toFloat() / dh),
        ).sanitize()
    }

    private fun NormalizedQuad.sanitize(): NormalizedQuad {
        val points = listOf(p0, p1, p2, p3).map { Offset(it.x.coerceIn(0f, 1f), it.y.coerceIn(0f, 1f)) }
        val area = polygonArea(points)
        if (area < 0.01f) {
            return NormalizedQuad(
                Offset(0.1f, 0.1f),
                Offset(0.9f, 0.1f),
                Offset(0.9f, 0.9f),
                Offset(0.1f, 0.9f),
            )
        }
        return NormalizedQuad(points[0], points[1], points[2], points[3])
    }

    private fun NormalizedQuad.toPixelQuad(w: Int, h: Int): DocCrop.QuadBox = sanitize().let {
        DocCrop.QuadBox(
            x0 = (it.p0.x * w).roundToInt().coerceIn(0, w - 1),
            y0 = (it.p0.y * h).roundToInt().coerceIn(0, h - 1),
            x1 = (it.p1.x * w).roundToInt().coerceIn(0, w - 1),
            y1 = (it.p1.y * h).roundToInt().coerceIn(0, h - 1),
            x2 = (it.p2.x * w).roundToInt().coerceIn(0, w - 1),
            y2 = (it.p2.y * h).roundToInt().coerceIn(0, h - 1),
            x3 = (it.p3.x * w).roundToInt().coerceIn(0, w - 1),
            y3 = (it.p3.y * h).roundToInt().coerceIn(0, h - 1),
        )
    }

    private fun NormalizedQuad.bounds(): Rect {
        val xs = listOf(p0.x, p1.x, p2.x, p3.x)
        val ys = listOf(p0.y, p1.y, p2.y, p3.y)
        return Rect(xs.minOrNull() ?: 0.1f, ys.minOrNull() ?: 0.1f, xs.maxOrNull() ?: 0.9f, ys.maxOrNull() ?: 0.9f)
    }

    private fun polygonArea(points: List<Offset>): Float {
        var sum = 0f
        for (i in points.indices) {
            val a = points[i]
            val b = points[(i + 1) % points.size]
            sum += a.x * b.y - b.x * a.y
        }
        return abs(sum) / 2f
    }
}

// ─── 裁剪 overlay：4 角可自由拖动 + 中央可整体平移 ─────────────────

internal enum class DragMode { NONE, TL, TR, BL, BR }

@Composable
private fun CropOverlay(
    bmpWidth: Int,
    bmpHeight: Int,
    containerSize: IntSize,
    cropQuad: NormalizedQuad,
    onCropChange: (NormalizedQuad) -> Unit,
) {
    val cw = containerSize.width.toFloat()
    val ch = containerSize.height.toFloat()
    val scale = minOf(cw / bmpWidth, ch / bmpHeight)
    val dispW = bmpWidth * scale
    val dispH = bmpHeight * scale
    val ox = (cw - dispW) / 2f
    val oy = (ch - dispH) / 2f

    fun toScreen(p: Offset): Offset = Offset(ox + p.x * dispW, oy + p.y * dispH)
    val s0 = toScreen(cropQuad.p0)
    val s1 = toScreen(cropQuad.p1)
    val s2 = toScreen(cropQuad.p2)
    val s3 = toScreen(cropQuad.p3)

    val handleHitRadius = with(LocalDensity.current) { 44.dp.toPx() }  // 触摸命中半径：手指大小，角周围一圈都能拖
    val handleDrawRadius = 14f      // 未激活时画出来的小圆半径
    val handleActiveScale = 1.7f    // 按下的那个角放大倍数
    val minAreaNorm = 0.01f         // 四边形最小面积（归一化）

    // pointerInput 协程跨越 recomposition 存活，闭包会捕获首次 composition 的 cropQuad /
    // cl / dispW 等，造成"拖角不听使唤"。用 rememberUpdatedState 让 gesture 回调始终读最新值。
    val latestQuad by rememberUpdatedState(cropQuad)
    val latestOx by rememberUpdatedState(ox)
    val latestOy by rememberUpdatedState(oy)
    val latestDispW by rememberUpdatedState(dispW)
    val latestDispH by rememberUpdatedState(dispH)
    val latestOnChange by rememberUpdatedState(onCropChange)

    var dragMode by remember(bmpWidth, bmpHeight) { mutableStateOf(DragMode.NONE) }

    Canvas(
        modifier = Modifier
            .fillMaxSize()
            .pointerInput(bmpWidth, bmpHeight, containerSize) {
                // 不用 detectDragGestures：它要越过 touch slop 才回调 onDragStart，
                // 按下瞬间无法给出反馈。这里按到角附近立刻接管，松手前每帧都跟手。
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false)
                    // 用当前帧的 rect 推 4 角屏幕坐标后再做命中检测
                    val q = latestQuad
                    val w = latestDispW
                    val h = latestDispH
                    val p0 = Offset(latestOx + q.p0.x * w, latestOy + q.p0.y * h)
                    val p1 = Offset(latestOx + q.p1.x * w, latestOy + q.p1.y * h)
                    val p2 = Offset(latestOx + q.p2.x * w, latestOy + q.p2.y * h)
                    val p3 = Offset(latestOx + q.p3.x * w, latestOy + q.p3.y * h)
                    val mode = decideMode(down.position, p0, p1, p2, p3, handleHitRadius)
                    // 没按到角附近就不接管，交给其它交互。
                    if (mode == DragMode.NONE) return@awaitEachGesture
                    dragMode = mode
                    down.consume()
                    while (true) {
                        val event = awaitPointerEvent()
                        val change = event.changes.firstOrNull { it.id == down.id } ?: break
                        if (!change.pressed) { change.consume(); break }
                        val drag = change.position - change.previousPosition
                        change.consume()
                        if (drag == Offset.Zero) continue
                        if (w <= 0f || h <= 0f) continue
                        latestOnChange(applyDrag(latestQuad, mode, drag.x / w, drag.y / h, minAreaNorm))
                    }
                    dragMode = DragMode.NONE
                }
            },
    ) {
        val path = Path().apply {
            moveTo(s0.x, s0.y)
            lineTo(s1.x, s1.y)
            lineTo(s2.x, s2.y)
            lineTo(s3.x, s3.y)
            close()
        }
        val dimPath = Path().apply {
            fillType = PathFillType.EvenOdd
            addRect(Rect(0f, 0f, size.width, size.height))
            addPath(path)
        }
        drawPath(dimPath, color = Color(0x99000000))
        drawPath(path, color = Color(0xFFFFC107), style = Stroke(width = 4f))

        // 4 角手柄（白填 + 黄边）。正在拖的那个角最后画并放大，给出明确的抓取反馈。
        val handles = listOf(DragMode.TL to s0, DragMode.TR to s1, DragMode.BR to s2, DragMode.BL to s3)
        for ((mode, p) in handles) if (mode != dragMode) drawCropHandle(p, handleDrawRadius, active = false)
        handles.firstOrNull { it.first == dragMode }?.let {
            drawCropHandle(it.second, handleDrawRadius * handleActiveScale, active = true)
        }
    }
}

private fun DrawScope.drawCropHandle(center: Offset, radius: Float, active: Boolean) {
    // 放大态掏空填充：大圆实心会盖住底下的画面，拖到哪儿就看不见哪儿。
    if (!active) drawCircle(color = Color.White, center = center, radius = radius)
    drawCircle(color = Color(0xFFFFC107), center = center, radius = radius, style = Stroke(width = 3f))
}

internal fun decideMode(
    pos: Offset,
    p0: Offset, p1: Offset, p2: Offset, p3: Offset,
    hit: Float,
): DragMode {
    var best = DragMode.NONE
    var bestDist = hit * hit
    fun consider(mode: DragMode, p: Offset) {
        val dx = pos.x - p.x; val dy = pos.y - p.y
        val d = dx * dx + dy * dy
        if (d <= bestDist) { bestDist = d; best = mode }
    }
    // 取最近的那个角。命中范围放大后相邻两角会重叠，按固定顺序检测会让先检测的角一直抢到手势。
    consider(DragMode.TL, p0)
    consider(DragMode.TR, p1)
    consider(DragMode.BR, p2)
    consider(DragMode.BL, p3)
    return best
}

private fun applyDrag(
    quad: NormalizedQuad,
    mode: DragMode,
    dx: Float,
    dy: Float,
    minArea: Float,
): NormalizedQuad {
    val delta = Offset(dx, dy)
    val next = when (mode) {
        DragMode.NONE -> quad
        DragMode.TL -> quad.copy(p0 = clamp01(quad.p0 + delta))
        DragMode.TR -> quad.copy(p1 = clamp01(quad.p1 + delta))
        DragMode.BR -> quad.copy(p2 = clamp01(quad.p2 + delta))
        DragMode.BL -> quad.copy(p3 = clamp01(quad.p3 + delta))
    }
    val area = polygonArea(listOf(next.p0, next.p1, next.p2, next.p3))
    return if (area >= minArea && isConvex(next)) next else quad
}

private fun clamp01(p: Offset): Offset = Offset(p.x.coerceIn(0f, 1f), p.y.coerceIn(0f, 1f))

private fun polygonArea(points: List<Offset>): Float {
    var sum = 0f
    for (i in points.indices) {
        val a = points[i]
        val b = points[(i + 1) % points.size]
        sum += a.x * b.y - b.x * a.y
    }
    return abs(sum) / 2f
}

private fun isConvex(q: NormalizedQuad): Boolean {
    val pts = listOf(q.p0, q.p1, q.p2, q.p3)
    var sign = 0f
    for (i in pts.indices) {
        val a = pts[i]
        val b = pts[(i + 1) % pts.size]
        val c = pts[(i + 2) % pts.size]
        val cross = (b.x - a.x) * (c.y - b.y) - (b.y - a.y) * (c.x - b.x)
        if (abs(cross) < 0.0001f) continue
        if (sign == 0f) sign = cross
        else if (sign * cross < 0f) return false
    }
    return true
}
