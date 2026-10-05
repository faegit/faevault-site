package com.vault.ui.markdown

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ControlledMarkdownHtmlTest {
    @Test
    fun convertsSupportedInlineTagsWithoutAWebView() {
        assertEquals("**bold**", normalize("<strong>bold</strong>"))
        assertEquals("**bold**", normalize("<b>bold</b>"))
        assertEquals("*italic*", normalize("<em>italic</em>"))
        assertEquals("~~gone~~", normalize("<del>gone</del>"))
        assertEquals("++under++", normalize("<u>under</u>"))
        assertEquals("line\nbreak", normalize("line<br>break"))
    }

    @Test
    fun emitsPrivateMarkersForComposeOnlyStyles() {
        val markdown = normalize("<mark>hot</mark> <sub>2</sub> <sup>x</sup> <kbd>Ctrl</kbd>")
        assertTrue(markdown.contains("${ControlledMarkdownHtml.MARKER_OPEN}MARK${ControlledMarkdownHtml.MARKER_CLOSE}hot"))
        assertTrue(markdown.contains("${ControlledMarkdownHtml.MARKER_OPEN}SUB${ControlledMarkdownHtml.MARKER_CLOSE}2"))
        assertTrue(markdown.contains("${ControlledMarkdownHtml.MARKER_OPEN}SUP${ControlledMarkdownHtml.MARKER_CLOSE}x"))
        assertTrue(markdown.contains("${ControlledMarkdownHtml.MARKER_OPEN}KBD${ControlledMarkdownHtml.MARKER_CLOSE}Ctrl"))
    }

    @Test
    fun preservesEscapedTagsAndStripsUnsupportedMarkup() {
        assertEquals("\\<strong>literal\\</strong>", normalize("\\<strong>literal\\</strong>"))
        assertEquals("safe", normalize("<script>safe</script>"))
        assertEquals("text", normalize("<iframe src=\"https://example.com\">text</iframe>"))
        assertFalse(normalize("<img src=\"https://example.com/x.png\">").contains("https://"))
    }

    @Test
    fun extractsDetailsAndRetainsMarkdownBody() {
        val source = """
            <details>
            <summary>点击展开 Details</summary>

            - 列表
            - **粗体**
            - `code`
            </details>
        """.trimIndent()

        val document = ControlledMarkdownHtml.normalize(source)
        val block = document.details.getValue("details-0")
        assertEquals("点击展开 Details", block.summary)
        assertTrue(block.body.contains("- 列表"))
        assertTrue(block.body.contains("**粗体**"))
        assertTrue(block.body.contains("`code`"))
        assertTrue(document.markdown.contains("```vault-details\ndetails-0\n```"))
    }

    @Test
    fun malformedDetailsDegradesToVisibleText() {
        val markdown = normalize("<details><summary>标题</summary>正文")
        assertTrue(markdown.contains("标题"))
        assertTrue(markdown.contains("正文"))
        assertFalse(markdown.contains("<details>"))
    }

    @Test
    fun fencedCodeBlocksSurviveTagStrippingVerbatim() {
        val source = """
            # 标题

            ```xml
            <vector xmlns:android="http://schemas.android.com/apk/res/android">
                <path android:fillColor="#FFFFFF" />
            </vector>
            ```

            **粗体**
        """.trimIndent()

        val document = ControlledMarkdownHtml.normalize(source)
        assertTrue(document.markdown.contains("<vector xmlns:android=\"http://schemas.android.com/apk/res/android\">"))
        assertTrue(document.markdown.contains("<path android:fillColor=\"#FFFFFF\" />"))
        assertTrue(document.markdown.contains("</vector>"))
        assertEquals("**粗体**", document.markdown.substringAfterLast('\n').trim())
    }

    @Test
    fun unclosedFenceProtectsRestOfDocument() {
        val source = "```xml\n<a>\n<b>text</b>"

        val document = ControlledMarkdownHtml.normalize(source)
        assertTrue(document.markdown.contains("<a>"))
        assertTrue(document.markdown.contains("<b>text</b>"))
    }

    @Test
    fun detailsInsideFenceIsNotExtracted() {
        val source = "```\n<details><summary>s</summary>b</details>\n```"

        val document = ControlledMarkdownHtml.normalize(source)
        assertTrue(document.details.isEmpty())
        assertTrue(document.markdown.contains("<details>"))
    }

    private fun normalize(source: String): String = ControlledMarkdownHtml.normalize(source).markdown
}
