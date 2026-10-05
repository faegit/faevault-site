package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MarkdownRenderPipelineTest {
    @Test
    fun nextBlockCountHonorsBothBudgetsAndAlwaysMakesProgress() {
        val weights = intArrayOf(2_000, 2_000, 20_000, 1, 1)

        assertEquals(2, nextMarkdownBlockCount(weights, 0, maxBlocks = 12, maxChars = 12_000))
        assertEquals(3, nextMarkdownBlockCount(weights, 2, maxBlocks = 12, maxChars = 12_000))
        assertEquals(5, nextMarkdownBlockCount(weights, 3, maxBlocks = 12, maxChars = 12_000))
        assertEquals(5, nextMarkdownBlockCount(weights, 5, maxBlocks = 12, maxChars = 12_000))
    }

    @Test
    fun cacheEvictsByEntryCountAndCharacterBudget() {
        val cache = MarkdownRenderCache(maxEntries = 2, maxSourceChars = 8, renderer = ::renderedMarkdown)

        cache.compute("aaaa")
        val second = cache.compute("bbbb")
        val latest = cache.compute("cc")

        assertNull(cache.lookup("aaaa"))
        assertSame(second, cache.lookup("bbbb"))
        assertSame(latest, cache.lookup("cc"))
    }

    @Test
    fun oversizedDocumentIsReturnedButNotCached() {
        val cache = MarkdownRenderCache(maxEntries = 8, maxSourceChars = 4, renderer = ::renderedMarkdown)

        val rendered = cache.compute("12345")

        assertEquals(5, rendered.sourceLength)
        assertNull(cache.lookup("12345"))
    }

    @Test
    fun lookupDoesNotWaitForBackgroundRendering() {
        val started = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        val cache = MarkdownRenderCache(maxEntries = 8, maxSourceChars = 100) { source ->
            started.countDown()
            assertTrue(finish.await(5, TimeUnit.SECONDS))
            renderedMarkdown(source)
        }

        try {
            val renderFuture = executor.submit<MarkdownRenderResult> { cache.compute("slow") }
            assertTrue(started.await(1, TimeUnit.SECONDS))
            val lookupFuture = executor.submit<MarkdownRenderResult?> { cache.lookup("other") }
            assertNull(lookupFuture.get(1, TimeUnit.SECONDS))
            assertFalse(renderFuture.isDone)
            finish.countDown()
            assertEquals(4, renderFuture.get(1, TimeUnit.SECONDS).sourceLength)
        } finally {
            finish.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun repeatedBatchExpansionReachesEveryBlock() {
        val weights = IntArray(31) { if (it % 5 == 0) 8_000 else 500 }
        val counts = mutableListOf<Int>()
        var current = 0
        while (current < weights.size) {
            current = nextMarkdownBlockCount(weights, current)
            counts += current
        }

        assertEquals(weights.size, counts.last())
        assertTrue(counts.zipWithNext().all { (before, after) -> after > before })
    }

    @Test
    fun codeChunksPreserveEveryLineInOrder() {
        val code = (1..401).joinToString("\n") { "line-$it" }

        val chunks = markdownCodeChunks(code, linesPerChunk = 160)

        assertEquals(listOf(160, 160, 81), chunks.map { it.lineSequence().count() })
        assertEquals(code, chunks.joinToString("\n"))
    }

    @Test
    fun backgroundResultKeepsDuplicateHeadingAnchorsAndBlockIndexes() {
        val rendered = renderedMarkdown("# Same\n\nBody\n\n# Same\n\nEnd")

        assertEquals(listOf("same", "same-1"), rendered.anchorIds)
        assertEquals(listOf(0, 2), rendered.anchorIds.map(rendered.blockIndexByAnchor::getValue))
    }
}


