package com.vault.ui.media

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.unit.IntSize
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ImageDecodePolicyTest {
    @Test
    fun imagePagingIsEnabledOnlyAtFitZoom() {
        assertTrue(imagePagingEnabled(1f))
        assertTrue(imagePagingEnabled(1.0001f))
        assertFalse(imagePagingEnabled(1.01f))
        assertFalse(imagePagingEnabled(2f))
    }

    @Test
    fun highResolutionImageDoubleTapCyclesFitTwoTimesNativeThenFit() {
        val fitScale = 0.10f
        val oneToOne = 10f

        assertEquals(2f, doubleTapTargetZoom(1f, fitScale, shortFillZoom = 4f))
        assertEquals(oneToOne, doubleTapTargetZoom(2f, fitScale, shortFillZoom = 4f))
        assertEquals(1f, doubleTapTargetZoom(oneToOne, fitScale, shortFillZoom = 4f))
    }

    @Test
    fun ordinaryImageDoubleTapOnlyTogglesFitAndTwoTimes() {
        val fitScale = 0.75f

        assertEquals(2f, doubleTapTargetZoom(1f, fitScale, shortFillZoom = 1f))
        assertEquals(1f, doubleTapTargetZoom(2f, fitScale, shortFillZoom = 1f))
    }

    @Test
    fun settledViewportDecodesOneBoundedRegionWithMargin() {
        val spec = imageDetailDecodeSpec(
            imageWidth = 6000,
            imageHeight = 4000,
            viewport = IntSize(1000, 800),
            zoom = 4f,
            offset = Offset(-1000f, -400f),
            fitScale = 0.20f,
            marginRatio = 0.08f,
        )

        requireNotNull(spec)
        assertTrue(spec.left in 0 until spec.right)
        assertTrue(spec.top in 0 until spec.bottom)
        assertTrue(spec.right <= 6000)
        assertTrue(spec.bottom <= 4000)
    }

    @Test
    fun detailRegionStaysOnTheWholeImageSamplingGrid() {
        val spec = imageDetailDecodeSpec(
            imageWidth = 12000,
            imageHeight = 8000,
            viewport = IntSize(1080, 2000),
            zoom = 3f,
            offset = Offset(-939f, -419f),
            fitScale = 0.09f,
            marginRatio = 0.08f,
        )

        requireNotNull(spec)
        assertEquals(2, spec.sample)
        assertEquals(0, spec.left % spec.sample)
        assertEquals(0, spec.top % spec.sample)
        assertEquals(0, spec.right % spec.sample)
        assertEquals(0, spec.bottom % spec.sample)
    }

    @Test
    fun previewAndDetailUseTheSameFloatingPointLayerCoordinates() {
        val fitOffset = Offset(0.35f, 137.75f)
        val sourceRect = androidx.compose.ui.geometry.Rect(1234f, 567f, 2345f, 1678f)

        val layerRect = imageLayerRect(sourceRect, fitScale = 0.137f, fitOffset = fitOffset)

        assertEquals(fitOffset.x + sourceRect.left * 0.137f, layerRect.left, 0.0001f)
        assertEquals(fitOffset.y + sourceRect.top * 0.137f, layerRect.top, 0.0001f)
        assertEquals(sourceRect.width * 0.137f, layerRect.width, 0.0001f)
        assertEquals(sourceRect.height * 0.137f, layerRect.height, 0.0001f)
    }

    @Test
    fun newImageFirstReadyFrameUsesItsOwnFitAndCenteredOffset() {
        val viewport = IntSize(1200, 2670)

        val geometry = resolveImageRenderGeometry(
            imageWidth = 4000,
            imageHeight = 3000,
            viewport = viewport,
            storedFitScale = 0f,
            storedOffset = Offset(-900f, -600f),
        )

        assertEquals(0.3f, geometry.fitScale, 0.0001f)
        assertEquals(0f, geometry.offset.x, 0.0001f)
        assertEquals(885f, geometry.offset.y, 0.0001f)
    }

    @Test
    fun imageSwitchRejectsThePreviousSessionsCollectedSnapshot() {
        assertEquals(
            "new-loading",
            currentImageSessionValue(
                expectedSessionId = 2L,
                collectedSessionId = 1L,
                collected = "old-ready",
                current = "new-loading",
            ),
        )
        assertEquals(
            "new-ready",
            currentImageSessionValue(
                expectedSessionId = 2L,
                collectedSessionId = 2L,
                collected = "new-ready",
                current = "new-loading",
            ),
        )
    }

    @Test
    fun previewIsKeptUntilItsSampledResolutionIsExceeded() {
        assertFalse(shouldDecodeDetailRegion(fitScale = 0.10f, zoom = 1f, previewSample = 8))
        assertTrue(shouldDecodeDetailRegion(fitScale = 0.20f, zoom = 1f, previewSample = 8))
        assertFalse(shouldDecodeDetailRegion(fitScale = 2f, zoom = 4f, previewSample = 1))
    }

    @Test
    fun originalResolutionIsDecodedNearOneToOne() {
        assertEquals(1, detailSampleForDisplayScale(0.99f))
        assertEquals(1, detailSampleForDisplayScale(1f))
        assertEquals(1, detailSampleForDisplayScale(1.25f))
    }

    @Test
    fun previewSamplingMatchesTheFittedViewport() {
        val phoneViewport = IntSize(1080, 2340)

        assertEquals(1, previewSampleFor(1200, 800, phoneViewport))
        assertEquals(4, previewSampleFor(6000, 4000, phoneViewport))
        assertEquals(8, previewSampleFor(12000, 8000, phoneViewport))
        assertEquals(1, previewSampleFor(6000, 4000, IntSize.Zero))
    }

    @Test
    fun detailRegionRaisesSamplingToStayWithinTheDecodeBudget() {
        val spec = imageDetailDecodeSpec(
            imageWidth = 12000,
            imageHeight = 8000,
            viewport = IntSize(12000, 8000),
            zoom = 1f,
            offset = Offset.Zero,
            fitScale = 1f,
            marginRatio = 0f,
            maxDecodedPixels = 8L * 1024L * 1024L,
        )

        requireNotNull(spec)
        val decodedPixels = (spec.right - spec.left).toLong() / spec.sample *
            ((spec.bottom - spec.top).toLong() / spec.sample)
        assertTrue(decodedPixels <= 8L * 1024L * 1024L)
    }

    @Test
    fun detailDecodeBudgetAdaptsToTheApplicationHeap() {
        val mib = 1024L * 1024L

        assertEquals(2L * mib, imageDetailPixelBudget(64L * mib))
        assertEquals(4L * mib, imageDetailPixelBudget(128L * mib))
        assertEquals(8L * mib, imageDetailPixelBudget(512L * mib))
    }

    @Test
    fun tileSamplingNeverUndershootsTheDisplayedResolution() {
        assertEquals(4, detailSampleForDisplayScale(0.20f))
        assertEquals(2, detailSampleForDisplayScale(0.50f))
        assertEquals(1, detailSampleForDisplayScale(0.51f))
        assertEquals(1, detailSampleForDisplayScale(1f))
    }

    @Test
    fun maximumZoomAllowsFourTimesBeyondNativeResolution() {
        assertEquals(16f, maximumZoomFor(fitScale = 0.25f))
        assertEquals(40f, maximumZoomFor(fitScale = 0.10f))
        assertEquals(4f, maximumZoomFor(fitScale = 1f))
        // 小图适配屏幕时已经是原图 2:1，还可继续到原图 4:1。
        assertEquals(2f, maximumZoomFor(fitScale = 2f))
    }

    @Test
    fun shortSideFillZoomsLandscapeByHeightAndPortraitByWidth() {
        val viewport = IntSize(1080, 2340)
        // 16:9 横图：9 边（高度）铺满屏幕高度。
        val landscape = shortSideFillZoom(4000, 2250, viewport, fitScale = 0.27f)
        assertTrue(landscape > 1f)
        assertEquals(2340f / 2250f / 0.27f, landscape, 0.01f)
        // 9:16 竖图：9 边（宽度）铺满屏幕宽度（适配视图已铺满时为 1）。
        val portrait = shortSideFillZoom(2250, 4000, viewport, fitScale = 0.48f)
        assertEquals(1f, portrait, 0.01f)
        // 无效输入回退为 1。
        assertEquals(1f, shortSideFillZoom(0, 4000, viewport, fitScale = 0.48f))
        assertEquals(1f, shortSideFillZoom(2250, 4000, IntSize.Zero, fitScale = 0.48f))
    }

    @Test
    fun secondDoubleTapReachesAtLeastNativeResolution() {
        // 横图“最短边铺满”后再次双击：放大到至少原图 1:1，保证最大分辨率解码。
        val target = secondDoubleTapZoomFor(fitScale = 0.27f, shortFillZoom = 3.85f)
        assertEquals(3.85f * 2f, target, 0.01f)
        assertTrue(target <= maximumZoomFor(0.27f))
        // 竖图（铺满倍率为 1）：至少到达 1:1。
        val portrait = secondDoubleTapZoomFor(fitScale = 0.48f, shortFillZoom = 1f)
        assertTrue(portrait >= 1f / 0.48f - 0.01f)
        // 极限大图：目标为 1:1，不超上限。
        val huge = secondDoubleTapZoomFor(fitScale = 0.025f, shortFillZoom = 4.32f)
        assertEquals(1f / 0.025f, huge, 0.01f)
    }

    @Test
    fun windowResizeKeepsTheSameImagePointAtTheViewportCenter() {
        val oldViewport = IntSize(1000, 800)
        val newViewport = IntSize(600, 400)
        val oldOffset = Offset(-500f, -300f)

        val resizedOffset = offsetKeepingViewportCenter(
            oldViewport = oldViewport,
            newViewport = newViewport,
            oldOffset = oldOffset,
            oldDisplayScale = 2f,
            newDisplayScale = 2f,
        )

        assertEquals(-700f, resizedOffset.x, 0.01f)
        assertEquals(-500f, resizedOffset.y, 0.01f)
    }
}
