package com.vault.ui.scan

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Size as AndroidSize
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.FocusMeteringAction
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FlashOff
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import com.vault.os.WifiQr
import com.vault.R
import com.vault.ui.uiText
import com.vault.ui.VaultButton
import androidx.compose.ui.res.stringResource
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.GenericMultipleBarcodeReader
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.Executors
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import com.vault.ui.VaultShape

class QrLiveScanActivity : ComponentActivity() {

    companion object {
        const val EXTRA_RESULT = "qr_result"
        const val EXTRA_PURPOSE = "qr_purpose"
        const val PURPOSE_ANY = "any"
        const val PURPOSE_WIFI = "wifi"
        const val PURPOSE_OTP = "otp"
        const val PURPOSE_SYNC = "sync"
        const val PURPOSE_IMPORT = "import"

        fun result(raw: String): Intent = Intent().putExtra(EXTRA_RESULT, raw)

        fun intent(context: android.content.Context, purpose: String): Intent =
            Intent(context, QrLiveScanActivity::class.java).putExtra(EXTRA_PURPOSE, purpose)
    }

    private val analysisExecutor = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val purpose = intent.getStringExtra(EXTRA_PURPOSE) ?: PURPOSE_ANY
        setContent { QrScanUi(purpose = purpose, analysisExecutor = analysisExecutor, onClose = { finish() }) }
    }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
    }
}

@Composable
private fun QrScanUi(purpose: String, analysisExecutor: Executor, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var camera by remember { mutableStateOf<Camera?>(null) }
    var torchOn by remember { mutableStateOf(false) }
    var ambiguous by remember { mutableStateOf(false) }
    var rejectedHint by remember { mutableStateOf(false) }
    var detected by remember { mutableStateOf(false) }
    var zoomRatio by remember { mutableFloatStateOf(1f) }
    val previewView = remember {
        PreviewView(ctx).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    val focusPoint = CameraGestures(previewView, camera) { zoomRatio = it }
    val delivered = remember { AtomicBoolean(false) }
    val scope = rememberCoroutineScope()
    var pickingImage by remember { mutableStateOf(false) }
    var galleryHint by remember { mutableStateOf<String?>(null) }
    val galleryLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        pickingImage = false
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val found = withContext(Dispatchers.IO) {
                runCatching { WifiQr.scanAllFromUri(ctx, uri) }
                    .getOrDefault(emptyList())
                    .firstOrNull { QrPayloadPolicy.accepts(purpose, it) }
            }
            if (found != null && delivered.compareAndSet(false, true)) {
                (ctx as? QrLiveScanActivity)?.setResult(Activity.RESULT_OK, QrLiveScanActivity.result(found))
                (ctx as? QrLiveScanActivity)?.finish()
            } else {
                galleryHint = when (purpose) {
                    QrLiveScanActivity.PURPOSE_WIFI -> ctx.getString(R.string.scan_qr_no_wifi)
                    QrLiveScanActivity.PURPOSE_OTP -> ctx.getString(R.string.scan_qr_no_otp)
                    else -> ctx.getString(R.string.scan_qr_no_valid)
                }
            }
        }
    }

    val scanLineProgress = rememberInfiniteTransition(label = "scanLine")
    val scanLineY by scanLineProgress.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ), label = "scanLineY",
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black)
    ) {
        AndroidView(
            factory = { context ->
                val cameraProviderFuture = ProcessCameraProvider.getInstance(context)
                cameraProviderFuture.addListener({
                    val cameraProvider = cameraProviderFuture.get()
                    val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
                    val resolution = ResolutionSelector.Builder()
                        .setResolutionStrategy(
                            ResolutionStrategy(
                                AndroidSize(1280, 720),
                                ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                            ),
                        )
                        .build()
                    val analysis = ImageAnalysis.Builder()
                        .setResolutionSelector(resolution)
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                        .build()
                    analysis.setAnalyzer(
                        analysisExecutor,
                        QrImageAnalyzer(
                            purpose = purpose,
                            onDetected = { raw ->
                                if (delivered.compareAndSet(false, true)) {
                                    (ctx as? QrLiveScanActivity)?.runOnUiThread {
                                        detected = true
                                        ctx.setResult(Activity.RESULT_OK, QrLiveScanActivity.result(raw))
                                        ctx.finish()
                                    }
                                }
                            },
                            onAmbiguous = { value ->
                                (ctx as? QrLiveScanActivity)?.runOnUiThread { ambiguous = value }
                            },
                            onRejected = {
                                (ctx as? QrLiveScanActivity)?.runOnUiThread { rejectedHint = true }
                            },
                        )
                    )
                    val selector = CameraSelector.Builder()
                        .requireLensFacing(CameraSelector.LENS_FACING_BACK)
                        .build()
                    cameraProvider.unbindAll()
                    val cam = cameraProvider.bindToLifecycle(lifecycleOwner, selector, preview, analysis)
                    camera = cam
                    previewView.post {
                        if (previewView.width <= 0 || previewView.height <= 0) return@post
                        val point = previewView.meteringPointFactory.createPoint(
                            previewView.width / 2f,
                            previewView.height / 2f,
                        )
                        cam.cameraControl.startFocusAndMetering(
                            FocusMeteringAction.Builder(
                                point,
                                FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE,
                            ).setAutoCancelDuration(3, TimeUnit.SECONDS).build(),
                        )
                    }
                }, ContextCompat.getMainExecutor(context))
                previewView
            },
            modifier = Modifier.fillMaxSize()
        )

        // 半透明遮罩 + 扫码框 + 扫描线
        ScanOverlay(
            scanLineY = scanLineY,
            modifier = Modifier.fillMaxSize()
        )

        CameraFocusIndicator(focusPoint)
        Row(
            Modifier.align(Alignment.TopCenter).fillMaxWidth().statusBarsPadding()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose, modifier = Modifier.size(48.dp)
                .background(Color.White.copy(alpha = 0.12f), CircleShape)) {
                Icon(Icons.Filled.Close, uiText("关闭"), tint = Color.White)
            }
            Text(uiText("扫码"), color = Color.White, fontSize = 20.sp,
                fontWeight = FontWeight.Medium, textAlign = TextAlign.Center, modifier = Modifier.weight(1f))
            IconButton(onClick = {
                torchOn = !torchOn
                camera?.cameraControl?.enableTorch(torchOn)
            }, modifier = Modifier.size(48.dp).background(Color.White.copy(alpha = 0.12f), CircleShape)) {
                Icon(if (torchOn) Icons.Filled.FlashOn else Icons.Filled.FlashOff,
                    uiText(if (torchOn) "关闭闪光灯" else "打开闪光灯"),
                    tint = if (torchOn) com.vault.ui.BrandPrimary else Color.White)
            }
        }

        // 顶部提示，避开关闭和闪光灯控件。
        Text(
            when {
                detected -> stringResource(R.string.scan_detected_jumping)
                ambiguous -> stringResource(R.string.scan_multiple_qr)
                rejectedHint -> when (purpose) {
                    QrLiveScanActivity.PURPOSE_IMPORT ->
                        stringResource(R.string.scan_not_lan_import)
                    else -> stringResource(R.string.scan_not_valid_sync)
                }
                else -> stringResource(R.string.scan_aim_qr)
            },
            color = Color.White.copy(alpha = 0.85f),
            fontSize = 14.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .align(Alignment.TopCenter)
                .statusBarsPadding()
                .padding(top = 80.dp, start = 32.dp, end = 32.dp)
                .fillMaxWidth()
                .padding(vertical = 8.dp),
        )

        // 从相册选择二维码图片（并入扫码 UI，不再单独设置入口按钮）
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 32.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            CameraZoomControls(camera, zoomRatio, { zoomRatio = it })
            Spacer(Modifier.height(16.dp))
            galleryHint?.let {
                Spacer(Modifier.height(4.dp))
                Text(
                    it,
                    color = Color(0xFFFFD54F),
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
                )
            }
            Text(uiText("轻触画面对焦 · 双指缩放"), color = Color.White.copy(alpha = 0.7f), fontSize = 12.sp)
            Spacer(Modifier.height(14.dp))
            VaultButton(
                onClick = {
                    galleryHint = null
                    pickingImage = true
                    galleryLauncher.launch("image/*")
                },
                enabled = !pickingImage,
                containerColor = com.vault.ui.BrandPrimary.copy(alpha = 0.8f),
                contentColor = Color.White,
                modifier = Modifier.widthIn(min = 168.dp).height(52.dp),
                shape = CircleShape,
            ) {
                Icon(Icons.Default.AddPhotoAlternate, null, tint = Color.White)
                Spacer(Modifier.size(6.dp))
                Text(
                    if (pickingImage) stringResource(R.string.scan_picking)
                    else stringResource(R.string.scan_pick_from_gallery),
                    color = Color.White,
                )
            }
        }

        LaunchedEffect(rejectedHint) {
            if (rejectedHint) {
                delay(2500)
                rejectedHint = false
            }
        }
    }
}

@Composable
private fun ScanOverlay(scanLineY: Float, modifier: Modifier = Modifier) {
    val frameRatio = 0.74f
    val cornerColor = com.vault.ui.BrandPrimary

    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val frameW = minOf(w * frameRatio, h * 0.5f)
        val frameH = frameW
        val left = (w - frameW) / 2f
        val top = (h - frameH) / 2f
        val cornerLen = frameW * 0.08f
        val strokeW = 3.dp.toPx()
        val radius = 12.dp.toPx()

        // 1) 四边半透明遮罩
        drawRect(color = Color(0x66000000), topLeft = Offset.Zero, size = Size(w, top))
        drawRect(color = Color(0x66000000), topLeft = Offset(0f, top + frameH), size = Size(w, h - top - frameH))
        drawRect(color = Color(0x66000000), topLeft = Offset(0f, top), size = Size(left, frameH))
        drawRect(color = Color(0x66000000), topLeft = Offset(left + frameW, top), size = Size(w - left - frameW, frameH))

        // 2) 框线（圆角矩形）
        drawRoundRect(
            color = Color.White.copy(alpha = 0.25f),
            topLeft = Offset(left, top),
            size = Size(frameW, frameH),
            cornerRadius = CornerRadius(radius, radius),
            style = Stroke(width = 1.dp.toPx()),
        )

        // 3) 四角装饰
        val corners = listOf(
            listOf(Offset(left, top + cornerLen) to Offset(left, top), Offset(left, top) to Offset(left + cornerLen, top)),
            listOf(Offset(left + frameW - cornerLen, top) to Offset(left + frameW, top), Offset(left + frameW, top) to Offset(left + frameW, top + cornerLen)),
            listOf(Offset(left, top + frameH - cornerLen) to Offset(left, top + frameH), Offset(left, top + frameH) to Offset(left + cornerLen, top + frameH)),
            listOf(Offset(left + frameW - cornerLen, top + frameH) to Offset(left + frameW, top + frameH), Offset(left + frameW, top + frameH - cornerLen) to Offset(left + frameW, top + frameH)),
        )
        for (corner in corners) {
            for ((from, to) in corner) {
                drawLine(cornerColor, from, to, strokeWidth = strokeW, cap = StrokeCap.Round)
            }
        }

        // 4) 扫描线（在框内上下移动）
        val lineY = top + cornerLen + (frameH - 2 * cornerLen) * scanLineY
        drawLine(
            color = cornerColor.copy(alpha = 0.7f),
            start = Offset(left + 8.dp.toPx(), lineY),
            end = Offset(left + frameW - 8.dp.toPx(), lineY),
            strokeWidth = 2.dp.toPx(),
            cap = StrokeCap.Round,
        )
    }
}

private class QrImageAnalyzer(
    private val purpose: String,
    private val onDetected: (String) -> Unit,
    private val onAmbiguous: (Boolean) -> Unit,
    private val onRejected: () -> Unit,
) : ImageAnalysis.Analyzer {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.ALSO_INVERTED to true,
    )
    private val reader = MultiFormatReader().apply {
        setHints(hints)
    }
    private var lastAnalyzed = 0L
    private val minInterval = 120L
    private var lastCandidate: String? = null
    private var stableFrames = 0

    override fun analyze(image: ImageProxy) {
        val now = System.currentTimeMillis()
        if (now - lastAnalyzed < minInterval) {
            image.close(); return
        }
        lastAnalyzed = now
        val bytes = image.copyLuminancePlane()
        // Keep a broad center crop so FILL_CENTER preview mapping and hand movement do not exclude the code.
        val cropSize = (minOf(image.width, image.height) * 0.86f).toInt().coerceAtLeast(1)
        val cropLeft = (image.width - cropSize) / 2
        val cropTop = (image.height - cropSize) / 2
        val source = PlanarYUVLuminanceSource(
            bytes, image.width, image.height,
            cropLeft, cropTop, cropSize, cropSize, false
        )
        val binary = BinaryBitmap(HybridBinarizer(source))
        try {
            val results = runCatching {
                GenericMultipleBarcodeReader(reader).decodeMultiple(binary, hints)
            }.getOrElse {
                arrayOf(reader.decodeWithState(binary))
            }
            val candidates = results.map { it.text.trim() }
                .filter { QrPayloadPolicy.accepts(purpose, it) }
                .distinct()
            onAmbiguous(candidates.size > 1)
            if (candidates.size == 1) {
                val candidate = candidates.single()
                stableFrames = if (candidate == lastCandidate) stableFrames + 1 else 1
                lastCandidate = candidate
                // Two matching frames prevent a transient partial/misdecode from closing the scanner.
                if (stableFrames >= 2) onDetected(candidate)
            } else {
                if (results.isNotEmpty() && candidates.isEmpty()) {
                    // 识别到二维码，但不属于当前用途：给出提示而不是静默忽略。
                    onRejected()
                }
                lastCandidate = null
                stableFrames = 0
            }
        } catch (_: Exception) {
            onAmbiguous(false)
            lastCandidate = null
            stableFrames = 0
        } finally {
            reader.reset()
            image.close()
        }
    }

    private fun ImageProxy.copyLuminancePlane(): ByteArray {
        val plane = planes[0]
        val buffer: ByteBuffer = plane.buffer
        val rowStride = plane.rowStride
        val pixelStride = plane.pixelStride
        if (pixelStride == 1 && rowStride == width && buffer.remaining() >= width * height) {
            return ByteArray(width * height).also { buffer.get(it) }
        }
        val output = ByteArray(width * height)
        val row = ByteArray(rowStride)
        var outputOffset = 0
        for (y in 0 until height) {
            val available = minOf(rowStride, buffer.remaining())
            buffer.get(row, 0, available)
            for (x in 0 until width) {
                val sourceIndex = x * pixelStride
                output[outputOffset++] = if (sourceIndex < available) row[sourceIndex] else 0
            }
        }
        return output
    }
}

internal object QrPayloadPolicy {
    data class SyncPairing(val baseUrl: String, val pin: String?)

    fun accepts(purpose: String, raw: String): Boolean = when (purpose) {
        QrLiveScanActivity.PURPOSE_WIFI -> com.vault.os.WifiQr.parse(raw) != null
        QrLiveScanActivity.PURPOSE_OTP -> com.vault.model.OtpUtils.parseOtpAuthUri(raw) != null
        QrLiveScanActivity.PURPOSE_SYNC -> parseSync(raw) != null
        QrLiveScanActivity.PURPOSE_IMPORT -> parseSync(raw) != null
        else -> raw.isNotBlank() && raw.length <= 8192
    }

    fun parseSync(raw: String): SyncPairing? = runCatching {
        val url = java.net.URI(raw.trim())
        if (url.scheme != "https" || url.host.isNullOrBlank()) return null
        val query = url.rawQuery.orEmpty().split('&').mapNotNull { part ->
            val pair = part.split('=', limit = 2)
            if (pair.size == 2) pair[0] to pair[1] else null
        }
        val ticket = query.filter { it.first == "ticket" }.map { it.second }.singleOrNull()
            ?.takeIf { it.length >= 12 } ?: return null
        // 同步二维码已内嵌一次性 6 位 PIN：扫码即可免输入连接
        val pin = query.filter { it.first == "pin" }.map { it.second }.singleOrNull()
            ?.takeIf { it.length == 6 && it.all(Char::isDigit) }
        val port = if (url.port >= 0) ":${url.port}" else ""
        SyncPairing("${url.scheme}://${url.host}$port?ticket=$ticket", pin)
    }.getOrNull()
}
