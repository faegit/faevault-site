package com.vault.ui.markdown

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MathWebViewTest {
    @Test
    fun formulaCannotBreakOutOfInlineScript() {
        val source = "</script><script>window.injected=true</script>&\u2028\u2029"

        val html = mathHtml(source, displayMode = false)

        assertFalse(html.contains(source))
        assertTrue(
            html.contains(
                "\\u003c/script\\u003e\\u003cscript\\u003ewindow.injected=true" +
                    "\\u003c/script\\u003e\\u0026\\u2028\\u2029",
            ),
        )
    }

    @Test
    fun katexRenderingDoesNotTrustFormulaCommands() {
        val html = mathHtml("\\href{https://example.com}{link}", displayMode = true)

        assertTrue(html.contains("trust: false"))
    }

    @Test
    fun webViewOnlyAllowsBundledMathAssets() {
        assertTrue(
            isMathAssetRequest(
                "https://appassets.androidplatform.net/assets/markdown/katex/katex.min.css",
            ),
        )
        assertTrue(
            isMathAssetRequest(
                "https://appassets.androidplatform.net/assets/markdown/katex/fonts/KaTeX_Main.woff2",
            ),
        )
        assertFalse(isMathAssetRequest("https://example.com/tracker.js"))
        assertFalse(
            isMathAssetRequest(
                "https://appassets.androidplatform.net.evil.example/assets/markdown/katex/katex.min.js",
            ),
        )
        assertFalse(isMathAssetRequest("javascript:alert(1)"))
    }
}
