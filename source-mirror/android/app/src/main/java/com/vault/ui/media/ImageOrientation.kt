package com.vault.ui.media

import android.graphics.Bitmap
import android.graphics.Matrix
import android.media.ExifInterface
import androidx.compose.ui.geometry.Rect
import java.io.InputStream

internal fun readImageOrientation(input: InputStream): Int = runCatching {
    ExifInterface(input).getAttributeInt(ExifInterface.TAG_ORIENTATION, 1)
}.getOrDefault(1)

internal fun orientationSwapsAxes(orientation: Int): Boolean = orientation in 5..8

/** Map an upright viewport region back to the encoded image, before region decoding. */
internal fun rawImageRegion(rect: Rect, width: Int, height: Int, orientation: Int): Rect {
    fun point(x: Float, y: Float): Pair<Float, Float> = when (orientation) {
        2 -> width - x to y
        3 -> width - x to height - y
        4 -> x to height - y
        5 -> y to x
        6 -> y to height - x
        7 -> width - y to height - x
        8 -> width - y to x
        else -> x to y
    }
    val points = listOf(point(rect.left, rect.top), point(rect.right, rect.top),
        point(rect.left, rect.bottom), point(rect.right, rect.bottom))
    return Rect(points.minOf { it.first }, points.minOf { it.second },
        points.maxOf { it.first }, points.maxOf { it.second })
}

/** Transform only the decoded preview/tile, never allocate a full-size rotated image. */
internal fun Bitmap.oriented(orientation: Int): Bitmap {
    val values = when (orientation) {
        2 -> floatArrayOf(-1f, 0f, 0f, 0f, 1f, 0f, 0f, 0f, 1f)
        3 -> floatArrayOf(-1f, 0f, 0f, 0f, -1f, 0f, 0f, 0f, 1f)
        4 -> floatArrayOf(1f, 0f, 0f, 0f, -1f, 0f, 0f, 0f, 1f)
        5 -> floatArrayOf(0f, 1f, 0f, 1f, 0f, 0f, 0f, 0f, 1f)
        6 -> floatArrayOf(0f, -1f, 0f, 1f, 0f, 0f, 0f, 0f, 1f)
        7 -> floatArrayOf(0f, -1f, 0f, -1f, 0f, 0f, 0f, 0f, 1f)
        8 -> floatArrayOf(0f, 1f, 0f, -1f, 0f, 0f, 0f, 0f, 1f)
        else -> return this
    }
    val result = Bitmap.createBitmap(this, 0, 0, width, height, Matrix().apply { setValues(values) }, true)
    if (result !== this) recycle()
    return result
}
