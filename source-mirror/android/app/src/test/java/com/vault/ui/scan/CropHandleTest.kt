package com.vault.ui.scan

import androidx.compose.ui.geometry.Offset
import org.junit.Assert.assertEquals
import org.junit.Test

class CropHandleTest {
    private val points = arrayOf(Offset(10f, 10f), Offset(110f, 10f), Offset(110f, 90f), Offset(10f, 90f))
    private fun mode(x: Float, y: Float) = decideMode(Offset(x, y), points[0], points[1], points[2], points[3], 12f)
    @Test fun centerEdgesAndOutsideNeverMoveTheRectangle() {
        assertEquals(DragMode.NONE, mode(60f, 50f))
        assertEquals(DragMode.NONE, mode(60f, 10f))
        assertEquals(DragMode.NONE, mode(10f, 50f))
        assertEquals(DragMode.NONE, mode(160f, 150f))
    }
    @Test fun onlyCornerHandlesAreDraggable() {
        assertEquals(DragMode.TL, mode(13f, 13f))
        assertEquals(DragMode.TR, mode(108f, 13f))
        assertEquals(DragMode.BR, mode(108f, 88f))
        assertEquals(DragMode.BL, mode(13f, 88f))
    }
    @Test fun grabAreaFollowsTheHitRadiusBeyondTheDrawnCircle() {
        val near = Offset(17.8f, 17.8f)   // 距左上角约 11px，手指落在圆外的空白处
        assertEquals(DragMode.NONE, decideMode(near, points[0], points[1], points[2], points[3], 5f))
        assertEquals(DragMode.TL, decideMode(near, points[0], points[1], points[2], points[3], 12f))
    }
    @Test fun nearestCornerWinsWhenTouchRangesOverlap() {
        val a = Offset(0f, 0f); val b = Offset(10f, 0f); val c = Offset(10f, 10f); val d = Offset(0f, 10f)
        assertEquals(DragMode.TL, decideMode(Offset(2f, 2f), a, b, c, d, 12f))
        assertEquals(DragMode.TR, decideMode(Offset(8f, 2f), a, b, c, d, 12f))
        assertEquals(DragMode.BR, decideMode(Offset(8f, 8f), a, b, c, d, 12f))
        assertEquals(DragMode.BL, decideMode(Offset(2f, 8f), a, b, c, d, 12f))
    }
}
