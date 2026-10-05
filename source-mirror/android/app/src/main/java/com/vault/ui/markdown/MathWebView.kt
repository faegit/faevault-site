package com.vault.ui.markdown

import android.annotation.SuppressLint
import android.graphics.Color as AndroidColor
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewAssetLoader.AssetsPathHandler
import java.io.ByteArrayInputStream

private const val MATH_BASE_URL = "https://appassets.androidplatform.net/assets/markdown/"

internal fun isMathAssetRequest(url: String): Boolean =
    url.startsWith(MATH_BASE_URL) && url.length > MATH_BASE_URL.length

private fun blockedWebResourceResponse(): WebResourceResponse =
    WebResourceResponse("text/plain", "UTF-8", ByteArrayInputStream(ByteArray(0)))

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun MathWebView(source: String, modifier: Modifier = Modifier, displayMode: Boolean = false) {
    val contentColor = MaterialTheme.colorScheme.onSurface.toArgb()
    val html = remember(source, displayMode, contentColor) {
        mathHtml(source, displayMode, "#%06X".format(contentColor and 0xFFFFFF))
    }
    AndroidView(
        modifier = modifier.fillMaxWidth().heightIn(min = 28.dp, max = 220.dp),
        factory = { context ->
            WebView(context).apply {
                setBackgroundColor(AndroidColor.TRANSPARENT)
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = false
                settings.allowFileAccess = false
                settings.allowContentAccess = false
                settings.blockNetworkLoads = true
                settings.cacheMode = WebSettings.LOAD_NO_CACHE
                settings.setSupportZoom(false)
                settings.builtInZoomControls = false
                settings.displayZoomControls = false
                settings.useWideViewPort = true
                settings.loadWithOverviewMode = false
                val assetLoader = WebViewAssetLoader.Builder()
                    .addPathHandler("/assets/", AssetsPathHandler(context))
                    .build()
                webViewClient = object : WebViewClient() {
                    override fun shouldInterceptRequest(
                        view: WebView,
                        request: WebResourceRequest,
                    ): WebResourceResponse = if (isMathAssetRequest(request.url.toString())) {
                        assetLoader.shouldInterceptRequest(request.url) ?: blockedWebResourceResponse()
                    } else {
                        blockedWebResourceResponse()
                    }

                    override fun shouldOverrideUrlLoading(
                        view: WebView,
                        request: WebResourceRequest,
                    ): Boolean = true
                }
                tag = html
                loadDataWithBaseURL(MATH_BASE_URL, html, "text/html", "UTF-8", null)
            }
        },
        update = { webView ->
            if (webView.tag != html) {
                webView.tag = html
                webView.loadDataWithBaseURL(MATH_BASE_URL, html, "text/html", "UTF-8", null)
            }
        },
    )
}

internal fun mathHtml(source: String, displayMode: Boolean, textColor: String = "#1f2937"): String {
    val escaped = jsString(source)
    val mode = displayMode.toString()
    return """
        <!doctype html>
        <html>
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
          <link rel="stylesheet" href="katex/katex.min.css">
          <style>
            html, body {
              margin: 0;
              padding: 0;
              background: transparent;
              color: $textColor;
              font-family: sans-serif;
            }
            .formula {
              width: 100%;
              overflow-x: auto;
              overflow-y: hidden;
              padding: 4px 0;
              word-break: keep-all;
            }
            .formula .katex {
              color: $textColor;
            }
            .formula .katex-display {
              margin: 0.3em 0;
              text-align: left;
            }
          </style>
        </head>
        <body>
          <div id="formula" class="formula"></div>
          <script src="katex/katex.min.js"></script>
          <script>
            window.addEventListener('DOMContentLoaded', function () {
              try {
                if (window.katex) {
                  katex.render($escaped, document.getElementById('formula'), {
                    throwOnError: false,
                    trust: false,
                    displayMode: $mode,
                    output: 'htmlAndMathml'
                  });
                } else {
                  document.getElementById('formula').textContent = $escaped;
                }
              } catch (error) {
                document.getElementById('formula').textContent = $escaped;
              }
            });
          </script>
        </body>
        </html>
    """.trimIndent()
}

private fun jsString(value: String): String = buildString {
    append('"')
    value.forEach { ch ->
        when (ch) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            '<' -> append("\\u003c")
            '>' -> append("\\u003e")
            '&' -> append("\\u0026")
            '\u2028' -> append("\\u2028")
            '\u2029' -> append("\\u2029")
            else -> append(ch)
        }
    }
    append('"')
}
