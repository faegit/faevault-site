package com.vault.ui

import com.vault.ui.markdown.MarkdownEngines
import com.vault.ui.markdown.childNodes
import com.vault.ui.markdown.isMermaidAssetRequest
import com.vault.ui.markdown.mermaidJsString
import com.vault.ui.markdown.mathHtml
import org.commonmark.ext.footnotes.FootnoteReference
import org.commonmark.ext.gfm.strikethrough.Strikethrough
import org.commonmark.ext.gfm.tables.TableBlock
import org.commonmark.ext.gfm.tables.TableCell
import org.commonmark.ext.gfm.tables.TableHead
import org.commonmark.ext.gfm.tables.TableRow
import org.commonmark.ext.ins.Ins
import org.commonmark.ext.task.list.items.TaskListItemMarker
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.Emphasis
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.Heading
import org.commonmark.node.HtmlInline
import org.commonmark.node.Link
import org.commonmark.node.ListItem
import org.commonmark.node.Node
import org.commonmark.node.OrderedList
import org.commonmark.node.Paragraph
import org.commonmark.node.StrongEmphasis
import org.commonmark.node.ThematicBreak
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class MarkdownTextTest {

    private fun parse(src: String) = MarkdownEngines.parse(src)

    @Test
    fun parsesHeadingLevels() {
        val doc = parse("# 一级\n## 二级\n### 三级\n")
        val headings = doc.childNodes().filterIsInstance<Heading>()

        assertEquals(listOf(1, 2, 3), headings.map { it.level })
    }

    @Test
    fun headingAnchorsSupportChineseDuplicatesAndEncodedDestinations() {
        assertEquals(
            listOf("快速开始", "快速开始-1", "api-reference"),
            markdownHeadingAnchors(listOf("快速开始", "快速开始", "API Reference")),
        )
        assertEquals("快速开始", markdownAnchorDestination("#%E5%BF%AB%E9%80%9F%E5%BC%80%E5%A7%8B"))
        assertEquals("api-reference", markdownAnchorDestination("#API%20Reference"))
        assertEquals(null, markdownAnchorDestination("other.md#section"))
        assertEquals(null, markdownAnchorDestination("https://example.com"))
    }

    @Test
    fun linkTargetsOnlyAllowAnchorsAndWebUrls() {
        assertEquals(MarkdownLinkTarget.Anchor, markdownLinkTarget("#section"))
        assertEquals(MarkdownLinkTarget.External, markdownLinkTarget("https://example.com/docs"))
        assertEquals(MarkdownLinkTarget.External, markdownLinkTarget("HTTP://example.com"))
        assertEquals(MarkdownLinkTarget.Unsupported, markdownLinkTarget("guide.md#section"))
        assertEquals(MarkdownLinkTarget.Unsupported, markdownLinkTarget("file:///tmp/a.md"))
        assertEquals(MarkdownLinkTarget.Unsupported, markdownLinkTarget("javascript:alert(1)"))
    }

    @Test
    fun parsesNestedBulletLists() {
        val doc = parse("- top\n  - child\n")
        val outer = doc.childNodes().filterIsInstance<BulletList>()

        assertEquals(1, outer.size)
        val item = outer[0].childNodes().filterIsInstance<ListItem>().single()
        val nested = item.childNodes().filterIsInstance<BulletList>()
        assertEquals(1, nested.size)
        assertEquals("child", nested[0].firstChild?.firstChild?.firstChild?.let {
            (it as? org.commonmark.node.Text)?.literal
        })
    }

    @Test
    fun parsesOrderedList() {
        val doc = parse("1. first\n2. second\n")
        val list = doc.childNodes().filterIsInstance<OrderedList>().single()

        assertEquals(2, list.childNodes().size)
        assertEquals(1, list.startNumber)
    }

    @Test
    fun parsesGfmTableWithAlignment() {
        val doc = parse("| 左 | 中 | 右 |\n|---|:-:|--:|\n| a | b | c |\n")
        val table = doc.childNodes().filterIsInstance<TableBlock>().single()
        val head = table.firstChild as? TableHead
        val row = head?.firstChild as? TableRow

        assertNotNull(row)
        val cells = row!!.childNodes().filterIsInstance<TableCell>()
        assertEquals(3, cells.size)
        assertEquals(TableCell.Alignment.CENTER, cells[1].alignment)
        assertEquals(TableCell.Alignment.RIGHT, cells[2].alignment)
    }

    @Test
    fun parsesGfmStrikethroughInsAndEmphasis() {
        val doc = parse("~~删~~ ++下++ **粗** *斜*\n")
        val para = doc.childNodes().filterIsInstance<Paragraph>().single()

        assertNotNull(para.firstChild?.let { findNode(it, Strikethrough::class.java) })
        assertNotNull(findNode(para, Ins::class.java))
        assertNotNull(findNode(para, StrongEmphasis::class.java))
        assertNotNull(findNode(para, Emphasis::class.java))
    }

    @Test
    fun htmlUnderlineIsNormalizedToUnderlineNode() {
        val doc = parse(normalizeUnderlineHtml("<u>下划线</u>\n"))
        assertNotNull(findIn(doc, Ins::class.java))
    }

    @Test
    fun controlledHtmlMarkersBecomeTypedSegments() {
        val open = com.vault.ui.markdown.ControlledMarkdownHtml.MARKER_OPEN
        val close = com.vault.ui.markdown.ControlledMarkdownHtml.MARKER_CLOSE
        assertEquals(
            listOf(
                HtmlSpanSegment("a", HtmlSpanKind.PLAIN),
                HtmlSpanSegment("b", HtmlSpanKind.MARK),
                HtmlSpanSegment("c", HtmlSpanKind.PLAIN),
            ),
            controlledHtmlSegments("a${open}MARK${close}b${open}/MARK${close}c"),
        )
        assertEquals(HtmlSpanKind.SUB, controlledHtmlSegments("${open}SUB${close}2${open}/SUB${close}").single().kind)
        assertEquals(HtmlSpanKind.SUP, controlledHtmlSegments("${open}SUP${close}2${open}/SUP${close}").single().kind)
        assertEquals(HtmlSpanKind.KBD, controlledHtmlSegments("${open}KBD${close}Ctrl${open}/KBD${close}").single().kind)
    }

    @Test
    fun parsesTaskListCheckbox() {
        val doc = parse("- [x] 已完成\n- [ ] 未完成\n")
        val items = doc.childNodes().filterIsInstance<BulletList>().single()
            .childNodes().filterIsInstance<ListItem>()

        assertEquals(true, taskCheckboxOf(items[0]))
        assertEquals(false, taskCheckboxOf(items[1]))
    }

    // 旧 taskMarkerSizeDp 公式已删除：图标尺寸改为跟随 bodySmall.lineHeight
    // （随系统字体缩放同步，无固定下限），尺寸计算移入组合层，纯 JVM 无法断言。

    @Test
    fun nestedTaskListKeepsCheckboxState() {
        val doc = parse("- [ ] 主任务\n  - [x] 子任务 A\n  - [ ] 子任务 B\n")
        val outerItem = doc.childNodes().filterIsInstance<BulletList>().single()
            .childNodes().filterIsInstance<ListItem>().single()
        val nestedItems = outerItem.childNodes().filterIsInstance<BulletList>().single()
            .childNodes().filterIsInstance<ListItem>()

        assertEquals(false, taskCheckboxOf(outerItem))
        assertEquals(true, taskCheckboxOf(nestedItems[0]))
        assertEquals(false, taskCheckboxOf(nestedItems[1]))
    }

    @Test
    fun autolinkProducesLinkNode() {
        val doc = parse("访问 https://example.com 获取\n")
        val link = findIn(doc, Link::class.java)

        assertNotNull(link)
        assertEquals("https://example.com", link!!.destination)
    }

    @Test
    fun explicitLinkKeepsDestination() {
        val doc = parse("[GitHub](https://github.com)\n")
        val link = findIn(doc, Link::class.java)!!

        assertEquals("https://github.com", link.destination)
    }

    @Test
    fun fencedCodeBlockKeepsInfoAndLiteral() {
        val doc = parse("```kotlin\nval a = 1\n```\n")
        val code = doc.childNodes().filterIsInstance<FencedCodeBlock>().single()

        assertEquals("kotlin", code.info)
        assertEquals("val a = 1\n", code.literal)
    }

    @Test
    fun fencedXmlBlockPreservesRawMarkupForPlainTextRendering() {
        val src = """
            ```xml
            <?xml version="1.0"?>
            <shape xmlns:x="http://example.com/schema">
                <line x:width="2" />
            </shape>
            ```
        """.trimIndent()
        val doc = parse(src)
        val code = doc.childNodes().filterIsInstance<FencedCodeBlock>().single()

        assertEquals("xml", code.info?.trim()?.lowercase())
        assertTrue(code.literal.contains("<?xml version=\"1.0\"?>"))
        assertTrue(code.literal.contains("<shape"))
        assertTrue(code.literal.contains("<line x:width=\"2\" />"))
        assertFalse(code.literal.contains("```"))
    }

    @Test
    fun mermaidFencePreservedAsFencedCode() {
        val doc = parse("```mermaid\nflowchart LR\n    A --> B\n```\n")
        val code = doc.childNodes().filterIsInstance<FencedCodeBlock>().single()

        assertEquals("mermaid", code.info)
        assertTrue(code.literal.contains("A --> B"))
    }

    @Test
    fun mermaidAssetRequestsIgnoreTheMainDocumentUrl() {
        assertTrue(isMermaidAssetRequest("https://appassets.androidplatform.net/assets/markdown/mermaid.min.js"))
        assertFalse(isMermaidAssetRequest("https://appassets.androidplatform.net/assets/markdown/"))
    }

    @Test
    fun mermaidViewerIsAStaticLocalAssetWithVisibleFailure() {
        val html = sequenceOf(
            File("src/main/assets/markdown/mermaid-viewer.html"),
            File("app/src/main/assets/markdown/mermaid-viewer.html"),
        ).first { it.isFile }.readText()

        assertTrue(html.contains("mermaid.min.js"))
        assertTrue(html.contains("mermaid.render"))
        assertTrue(html.contains("Mermaid 图表无法渲染"))
        assertFalse(html.contains("http://"))
        assertFalse(html.contains("https://"))
    }

    @Test
    fun mermaidSourceCannotBreakOutOfLocalScript() {
        val literal = mermaidJsString("A[</script>] --> B\\n")

        assertFalse(literal.contains("</script>"))
        assertTrue(literal.contains("\\u003c/script\\u003e"))
    }

    @Test
    fun mathHtmlLoadsOnlyBundledKatexAssets() {
        val html = mathHtml("\\frac{a}{b}", displayMode = true, textColor = "#F8FAFC")

        assertTrue(html.contains("katex/katex.min.css"))
        assertTrue(html.contains("katex/katex.min.js"))
        assertFalse(html.contains("cdn.jsdelivr.net"))
        assertTrue(html.contains("displayMode: true"))
        assertTrue(html.contains("color: #F8FAFC"))
    }

    @Test
    fun inlineCodeParsesAsCodeNode() {
        val doc = parse("前 `code` 后\n")
        val code = findIn(doc, Code::class.java)

        assertEquals("code", code!!.literal)
    }

    @Test
    fun footnoteReferenceParses() {
        val doc = parse("注[^1]\n\n[^1]: 来源\n")
        val ref = findIn(doc, FootnoteReference::class.java)

        assertEquals("1", ref!!.label)
    }

    @Test
    fun thematicBreakParses() {
        val doc = parse("上\n\n---\n\n下\n")

        assertTrue(doc.childNodes().any { it is ThematicBreak })
    }

    @Test
    fun softLineBreakStaysInsideParagraph() {
        val doc = parse("line1\nline2\n")
        val para = doc.childNodes().filterIsInstance<Paragraph>().single()

        assertEquals(1, doc.childNodes().count { it is Paragraph })
        assertTrue(para.childNodes().size >= 3)
    }

    @Test
    fun htmlBlockDoesNotCrashParse() {
        val doc = parse("<div>\nraw html\n</div>\n")

        assertEquals(1, doc.childNodes().size)
    }

    private fun <T : Node> findIn(root: Node, type: Class<T>): T? = root.firstChild?.let { findNode(it, type) }

    private fun <T : Node> findNode(start: Node, type: Class<T>): T? {
        var n: Node? = start
        while (n != null) {
            if (type.isInstance(n)) return type.cast(n)
            n.firstChild?.let { child -> findNode(child, type)?.let { return it } }
            n = n.next
        }
        return null
    }

    private fun taskCheckboxOf(item: ListItem): Boolean {
        val marker = findIn(item, TaskListItemMarker::class.java)
        return marker?.isChecked == true
    }
}
