package com.vault.ocr

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.math.abs

@RunWith(AndroidJUnit4::class)
class DocCropTest {
    @Test fun detectsPerspectiveDocumentAndWarpsCorners() {
        val bitmap = Bitmap.createBitmap(640, 480, Bitmap.Config.ARGB_8888)
        try {
            val canvas = Canvas(bitmap)
            canvas.drawColor(Color.BLACK)
            val path = Path().apply {
                moveTo(100f, 80f); lineTo(550f, 110f); lineTo(500f, 400f); lineTo(130f, 380f); close()
            }
            canvas.drawPath(path, Paint().apply { color = Color.WHITE })
            val quad = DocCrop.detectQuad(bitmap)
            assertNotNull(quad)
            quad!!
            assertTrue(abs(quad.x0 - 100) < 12 && abs(quad.y0 - 80) < 12)
            assertTrue(abs(quad.x2 - 500) < 12 && abs(quad.y2 - 400) < 12)
            val cropped = DocCrop.cropQuad(bitmap, quad)
            assertNotNull(cropped)
            cropped!!
            assertTrue(cropped.width in 430..470)
            assertTrue(cropped.height in 280..325)
            assertTrue(Color.red(cropped.getPixel(cropped.width / 2, cropped.height / 2)) > 240)
            cropped.recycle()
        } finally { bitmap.recycle() }
    }
    @Test fun detectsSmallLowContrastCards() {
        val width = 640; val height = 480
        val gray = ByteArray(width * height) { 105 }
        for (y in 150..269) for (x in 210..369) gray[y * width + x] = 135.toByte()
        val quad = DocCrop.detectQuadFromGray(gray, width, height)
        assertNotNull(quad)
        assertTrue(abs(quad!!.x0 - 210) < 12 && abs(quad.y0 - 150) < 12)
    }
    @Test fun uniformImageDoesNotInventDocument() {
        assertNull(DocCrop.detectQuadFromGray(ByteArray(640 * 480), 640, 480))
    }
    @Test fun handlesPaddedYPlaneAndRejectsTruncatedPlane() {
        val stride = 672
        val gray = ByteArray(stride * 480)
        for (y in 80..399) for (x in 100..539) gray[y * stride + x] = 255.toByte()
        assertNotNull(DocCrop.detectQuadFromGray(gray, 640, 480, stride))
        assertNull(DocCrop.detectQuadFromGray(gray.copyOf(100), 640, 480, stride))
    }
}
