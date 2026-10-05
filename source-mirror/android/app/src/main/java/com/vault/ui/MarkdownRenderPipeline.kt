package com.vault.ui

import com.vault.ui.markdown.ControlledHtmlDocument
import com.vault.ui.markdown.ControlledMarkdownHtml
import com.vault.ui.markdown.MarkdownEngines
import com.vault.ui.markdown.childNodes
import org.commonmark.node.Code
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.HtmlBlock
import org.commonmark.node.Heading
import org.commonmark.node.Node
import org.commonmark.node.Text
import java.util.LinkedHashMap

enum class MarkdownRenderPolicy { EDITOR_ADAPTIVE, DETAIL_PROGRESSIVE }

internal const val MARKDOWN_SYNC_PARSE_CHAR_LIMIT = 20_000

internal data class MarkdownRenderResult(
    val controlled: ControlledHtmlDocument,
    val document: Node,
    val blocks: List<Node>,
    val blockWeights: IntArray,
    val headings: List<Heading>,
    val anchorIds: List<String>,
    val blockIndexByAnchor: Map<String, Int>,
    val sourceLength: Int,
)

internal fun renderedMarkdown(source: String): MarkdownRenderResult {
    val controlled = ControlledMarkdownHtml.normalize(source)
    val document = MarkdownEngines.parse(controlled.markdown)
    val blocks = document.childNodes()
    val headings = markdownHeadings(document)
    val anchorIds = markdownHeadingAnchors(headings.map(::markdownPlainText))
    val topLevelIndexes = blocks.withIndex().associate { (index, node) -> node to index }
    val blockIndexByAnchor = headings.zip(anchorIds).associate { (heading, anchor) ->
        var root: Node = heading
        while (root.parent != null && root.parent !== document) root = root.parent
        anchor to topLevelIndexes.getValue(root)
    }
    return MarkdownRenderResult(
        controlled = controlled,
        document = document,
        blocks = blocks,
        blockWeights = blocks.map(::markdownNodeWeight).toIntArray(),
        headings = headings,
        anchorIds = anchorIds,
        blockIndexByAnchor = blockIndexByAnchor,
        sourceLength = source.length,
    )
}

internal fun markdownNodeWeight(root: Node): Int {
    var weight = 0

    fun visit(node: Node) {
        weight += when (node) {
            is Text -> node.literal.length
            is Code -> node.literal.length
            is FencedCodeBlock -> node.literal.length
            is HtmlBlock -> node.literal.length
            else -> 0
        }
        node.childNodes().forEach(::visit)
    }

    visit(root)
    return weight.coerceAtLeast(1)
}

internal fun nextMarkdownBlockCount(
    weights: IntArray,
    current: Int,
    maxBlocks: Int = 8,
    maxChars: Int = 8_000,
): Int {
    if (current >= weights.size) return weights.size
    var next = current
    var chars = 0
    while (next < weights.size && next - current < maxBlocks) {
        val weight = weights[next].coerceAtLeast(1)
        if (next > current && chars + weight > maxChars) break
        chars += weight
        next++
    }
    return next
}

internal fun markdownCodeChunks(code: String, linesPerChunk: Int = 160): List<String> {
    require(linesPerChunk > 0)
    return code.lineSequence().chunked(linesPerChunk).map { it.joinToString("\n") }.toList()
}

internal class MarkdownRenderCache(
    private val maxEntries: Int = 8,
    private val maxSourceChars: Int = 512_000,
    private val renderer: (String) -> MarkdownRenderResult = ::renderedMarkdown,
) {
    private val documents = LinkedHashMap<String, MarkdownRenderResult>(maxEntries, 0.75f, true)
    private var sourceChars = 0

    @Synchronized
    fun lookup(source: String): MarkdownRenderResult? = documents[source]

    fun compute(source: String): MarkdownRenderResult {
        lookup(source)?.let { return it }
        val rendered = renderer(source)
        if (source.length > maxSourceChars) return rendered
        return synchronized(this) {
            documents[source]?.let { return@synchronized it }
            documents[source] = rendered
            sourceChars += source.length
            trimToBudget()
            rendered
        }
    }

    private fun trimToBudget() {
        val iterator = documents.entries.iterator()
        while ((documents.size > maxEntries || sourceChars > maxSourceChars) && iterator.hasNext()) {
            val eldest = iterator.next()
            sourceChars -= eldest.key.length
            iterator.remove()
        }
    }
}

internal val SharedMarkdownDocumentCache = MarkdownRenderCache()





