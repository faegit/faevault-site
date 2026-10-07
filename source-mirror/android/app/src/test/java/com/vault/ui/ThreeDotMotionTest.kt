package com.vault.ui

import org.junit.Assert.*
import org.junit.Test

class ThreeDotMotionTest {
    @Test fun peaksAdvanceLeftToRightAndReturnToRest() {
        repeat(3) { index ->
            assertEquals(1f, ThreeDotMotion.scale(index * 180f, index), 0.0001f)
            assertEquals(ThreeDotMotion.MAX_SCALE, ThreeDotMotion.scale(360f + index * 180f, index), 0.0001f)
            assertEquals(1f, ThreeDotMotion.scale(720f + index * 180f, index), 0.0001f)
        }
    }

    @Test fun peakDotsRemainInsideFixedButtonAndLoginBounds() {
        listOf(32f to 18f, 36f to 24f, 24f to 12f).forEach { (width, height) ->
            val radius = minOf(height / 6f, width / 15f) * ThreeDotMotion.MAX_SCALE
            assertTrue(radius < height / 2f)
            assertTrue(width / 6f - radius > 0f)
            assertTrue(width * 5f / 6f + radius < width)
        }
    }

    @Test fun everyCycleStaysWithinScaleBounds() {
        for (time in 0..3600 step 13) repeat(3) { index ->
            assertTrue(ThreeDotMotion.scale(time.toFloat(), index) in 1f..ThreeDotMotion.MAX_SCALE)
        }
    }
}
