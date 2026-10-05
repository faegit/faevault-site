package com.vault.ocr

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import java.io.InputStream
import kotlin.math.*
import org.opencv.android.OpenCVLoader
import org.opencv.android.Utils
import org.opencv.core.*
import org.opencv.imgproc.Imgproc

/** Offline OpenCV contour detection and perspective correction. No Play Services required. */
object DocCrop {
    private val loaded by lazy { runCatching { OpenCVLoader.initLocal() }.getOrDefault(false) }

    /** 从 InputStream 读图并按 EXIF 校正方向，最长边限制到 [maxSide] 像素。 */
    fun decodeOriented(input: ByteArray, maxSide: Int = 2048): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(input, 0, input.size, bounds)
        var sample = 1
        val longest = max(bounds.outWidth, bounds.outHeight)
        while (longest / sample > maxSide) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        val bmp = BitmapFactory.decodeByteArray(input, 0, input.size, opts) ?: return null
        val rot = exifRotationDegrees(input)
        if (rot == 0) return bmp
        val m = Matrix().apply { postRotate(rot.toFloat()) }
        return try {
            Bitmap.createBitmap(bmp, 0, 0, bmp.width, bmp.height, m, true).also {
                if (it !== bmp) bmp.recycle()
            }
        } catch (_: Throwable) { bmp }
    }

    /** 需要按 EXIF 旋转的角度（0/90/180/270）。供调用方判断能否跳过重新编码。 */
    internal fun exifRotationDegrees(bytes: ByteArray): Int = runCatching {
        val exif = ExifInterface(bytes.inputStream() as InputStream)
        when (exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)) {
            ExifInterface.ORIENTATION_ROTATE_90 -> 90
            ExifInterface.ORIENTATION_ROTATE_180 -> 180
            ExifInterface.ORIENTATION_ROTATE_270 -> 270
            else -> 0
        }
    }.getOrDefault(0)


    data class QuadBox(
        val x0: Int, val y0: Int, val x1: Int, val y1: Int,
        val x2: Int, val y2: Int, val x3: Int, val y3: Int,
    )

    /** Copy the Y plane with its real stride; bound analysis to a 640px long edge. */
    fun detectQuadFromGray(y: ByteArray, width: Int, height: Int, rowStride: Int = width): QuadBox? {
        if (width < 32 || height < 32 || rowStride < width ||
            y.size.toLong() < (height - 1L) * rowStride + width || !loaded) return null
        val scale = min(1.0, 640.0 / max(width, height))
        val sw = max(1, (width * scale).roundToInt())
        val sh = max(1, (height * scale).roundToInt())
        val packed = ByteArray(sw * sh) { index ->
            val sy = (index / sw / scale).toInt().coerceAtMost(height - 1)
            val sx = (index % sw / scale).toInt().coerceAtMost(width - 1)
            y[sy * rowStride + sx]
        }
        val gray = Mat(sh, sw, CvType.CV_8UC1)
        return try {
            gray.put(0, 0, packed)
            detect(gray)?.let { points ->
                val xy = points.flatMap { p -> listOf(
                    (p.x / scale).roundToInt().coerceIn(0, width - 1),
                    (p.y / scale).roundToInt().coerceIn(0, height - 1)) }
                QuadBox(xy[0], xy[1], xy[2], xy[3], xy[4], xy[5], xy[6], xy[7])
            }
        } finally { gray.release(); packed.fill(0) }
    }

    fun detectQuad(src: Bitmap): QuadBox? {
        val scale = min(1.0, 640.0 / max(src.width, src.height))
        val sw = (src.width * scale).roundToInt().coerceAtLeast(1)
        val sh = (src.height * scale).roundToInt().coerceAtLeast(1)
        val small = Bitmap.createScaledBitmap(src, sw, sh, true)
        val pixels = IntArray(sw * sh)
        small.getPixels(pixels, 0, sw, 0, 0, sw, sh)
        if (small !== src) small.recycle()
        val gray = ByteArray(pixels.size) { i ->
            val c = pixels[i]
            (((c shr 16 and 255) * 299 + (c shr 8 and 255) * 587 + (c and 255) * 114) / 1000).toByte()
        }
        return try {
            detectQuadFromGray(gray, sw, sh)?.let { q ->
                QuadBox((q.x0 / scale).roundToInt(), (q.y0 / scale).roundToInt(),
                    (q.x1 / scale).roundToInt(), (q.y1 / scale).roundToInt(),
                    (q.x2 / scale).roundToInt(), (q.y2 / scale).roundToInt(),
                    (q.x3 / scale).roundToInt(), (q.y3 / scale).roundToInt())
            }
        } finally { gray.fill(0); pixels.fill(0) }
    }

    private fun detect(gray: Mat): List<Point>? {
        val blurred = Mat(); val edges = Mat(); val hierarchy = Mat()
        val kernel = Imgproc.getStructuringElement(Imgproc.MORPH_RECT, Size(3.0, 3.0))
        val contours = ArrayList<MatOfPoint>()
        var best: List<Point>? = null
        var bestArea = gray.total() * 0.025
        try {
            Imgproc.GaussianBlur(gray, blurred, Size(5.0, 5.0), 0.0)
            // Edge and intensity passes cover both printed cards and low-texture documents.
            for (pass in 0..2) {
                when (pass) {
                    0 -> Imgproc.Canny(blurred, edges, 20.0, 60.0)
                    1 -> Imgproc.threshold(blurred, edges, 0.0, 255.0, Imgproc.THRESH_BINARY or Imgproc.THRESH_OTSU)
                    else -> Imgproc.adaptiveThreshold(blurred, edges, 255.0, Imgproc.ADAPTIVE_THRESH_GAUSSIAN_C, Imgproc.THRESH_BINARY, 31, 5.0)
                }
                Imgproc.morphologyEx(edges, edges, Imgproc.MORPH_CLOSE, kernel)
                Imgproc.findContours(edges, contours, hierarchy, Imgproc.RETR_LIST, Imgproc.CHAIN_APPROX_SIMPLE)
                for (contour in contours) {
                    val curve = MatOfPoint2f(*contour.toArray()); val approx = MatOfPoint2f()
                    try {
                        Imgproc.approxPolyDP(curve, approx, 0.02 * Imgproc.arcLength(curve, true), true)
                        if (approx.total() != 4L) continue
                        val polygon = MatOfPoint(*approx.toArray())
                        try {
                            val area = abs(Imgproc.contourArea(polygon))
                            if (area <= bestArea || area > gray.total() * 0.97 || !Imgproc.isContourConvex(polygon)) continue
                            val points = approx.toArray().toList()
                            val cx = points.sumOf { it.x } / 4; val cy = points.sumOf { it.y } / 4
                            val ordered = points.sortedBy { atan2(it.y - cy, it.x - cx) }
                            val first = ordered.indices.minBy { ordered[it].x + ordered[it].y }
                            best = List(4) { ordered[(first + it) % 4] }
                            bestArea = area
                        } finally { polygon.release() }
                    } finally { curve.release(); approx.release() }
                }
                contours.forEach { it.release() }; contours.clear()
            }
            return best
        } finally {
            contours.forEach { it.release() }
            blurred.release(); edges.release(); hierarchy.release(); kernel.release()
        }
    }

    /** Warp the user's final four corners, preserving perspective rather than a bounding box. */
    fun cropQuad(src: Bitmap, quad: QuadBox): Bitmap? {
        if (!loaded) return null
        val points = arrayOf(Point(quad.x0.toDouble(), quad.y0.toDouble()), Point(quad.x1.toDouble(), quad.y1.toDouble()),
            Point(quad.x2.toDouble(), quad.y2.toDouble()), Point(quad.x3.toDouble(), quad.y3.toDouble()))
        fun distance(a: Point, b: Point) = hypot(a.x - b.x, a.y - b.y)
        val width = max(distance(points[0], points[1]), distance(points[3], points[2])).roundToInt().coerceIn(32, 4096)
        val height = max(distance(points[0], points[3]), distance(points[1], points[2])).roundToInt().coerceIn(32, 4096)
        val source = Mat(); val output = Mat(); val from = MatOfPoint2f(*points)
        val to = MatOfPoint2f(Point(0.0, 0.0), Point(width - 1.0, 0.0), Point(width - 1.0, height - 1.0), Point(0.0, height - 1.0))
        var transform: Mat? = null
        return try {
            Utils.bitmapToMat(src, source)
            transform = Imgproc.getPerspectiveTransform(from, to)
            Imgproc.warpPerspective(source, output, transform, Size(width.toDouble(), height.toDouble()), Imgproc.INTER_LINEAR, Core.BORDER_REPLICATE)
            Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also { Utils.matToBitmap(output, it) }
        } finally { source.release(); output.release(); from.release(); to.release(); transform?.release() }
    }
}
