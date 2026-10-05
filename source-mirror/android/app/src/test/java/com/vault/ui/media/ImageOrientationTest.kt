package com.vault.ui.media

import androidx.compose.ui.geometry.Rect
import org.junit.Assert.assertEquals
import org.junit.Test

class ImageOrientationTest {
    @Test fun allOrientationsMapFullViewportToFullEncodedImage() {
        for (orientation in 1..8) {
            val viewport = if (orientationSwapsAxes(orientation)) Rect(0f, 0f, 60f, 100f) else Rect(0f, 0f, 100f, 60f)
            assertEquals(Rect(0f, 0f, 100f, 60f), rawImageRegion(viewport, 100, 60, orientation))
        }
    }
    @Test fun asymmetricTileMapsCorrectlyForRotationAndMirroring() {
        val tile = Rect(10f, 5f, 30f, 20f)
        val expected = listOf(
            Rect(10f, 5f, 30f, 20f), Rect(70f, 5f, 90f, 20f),
            Rect(70f, 40f, 90f, 55f), Rect(10f, 40f, 30f, 55f),
            Rect(5f, 10f, 20f, 30f), Rect(5f, 30f, 20f, 50f),
            Rect(80f, 30f, 95f, 50f), Rect(80f, 10f, 95f, 30f))
        for (orientation in 1..8) assertEquals(expected[orientation - 1], rawImageRegion(tile, 100, 60, orientation))
    }
}
