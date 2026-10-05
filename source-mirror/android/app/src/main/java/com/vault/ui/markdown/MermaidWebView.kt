package com.vault.ui.markdown

import android.annotation.SuppressLint
import android.graphics.Color
import android.view.MotionEvent
import android.view.View
import android.view.GestureDetector
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewAssetLoader.AssetsPathHandler
import com.vault.storage.MediaCrypto
import java.security.MessageDigest
import java.util.LinkedHashMap

private const val MARKDOWN_ASSET_BASE = "https://appassets.androidplatform.net/assets/markdown/"
private const val MERMAID_VIEWER_URL = "${MARKDOWN_ASSET_BASE}mermaid-viewer.html"

internal fun isMermaidAssetRequest(url: String): Boolean =
    url.trim().startsWith(MARKDOWN_ASSET_BASE) && url.removePrefix(MARKDOWN_ASSET_BASE).isNotBlank()

/**
 * SVG 磁盘编解码抽象：生产实现走 [MediaCrypto]（VMED 格式 AES-256-GCM，
 * 密钥由库 DEK 经 HKDF 派生，与 PC 端媒体文件加密一致）；测试可注入直通实现。
 * 未解锁会话（无媒体密钥）时 encode/decode 返回 null——只留内存缓存、绝不落明文盘。
 */
internal interface MermaidSvgDiskCodec {
    /** 返回 null 表示当前不可落盘（如媒体会话未解锁）。 */
    fun encode(plain: String): ByteArray?

    /** 返回 null 表示不可读（未解锁或密文损坏）。 */
    fun decode(raw: ByteArray): String?
}

internal object MediaCryptoMermaidSvgCodec : MermaidSvgDiskCodec {
    override fun encode(plain: String): ByteArray? {
        if (!MediaCrypto.isActive()) return null
        return runCatching { MediaCrypto.encrypt(plain.toByteArray(Charsets.UTF_8)) }.getOrNull()
    }

    override fun decode(raw: ByteArray): String? {
        if (!MediaCrypto.isActive()) return null
        // decrypt 对无 VMED 头的旧明文缓存原样返回，天然兼容升级前的历史文件
        return runCatching { MediaCrypto.decrypt(raw).toString(Charsets.UTF_8) }.getOrNull()
    }
}

/**
 * 已渲染 Mermaid SVG 缓存：键为图表源码摘要。
 * 两级结构：内存 LRU（会话内复用）+ 可选磁盘目录（跨进程/重启持久保留，按需读取）。
 * 磁盘内容经 [MermaidSvgDiskCodec] 加密（默认 VMED/AES-256-GCM），明文永不落盘；
 * 解密失败/超限的磁盘条目直接删除（异库残留或损坏时避免无限堆积）。
 * put 时同步写盘（SVG 通常几 KB～几十 KB）；get 先查内存、未命中回源磁盘并回填内存。
 */
internal class MermaidSvgCache(
    private val maxEntries: Int = 24,
    private val maxSvgChars: Int = 400_000,
    private val diskDir: java.io.File? = null,
    private val codec: MermaidSvgDiskCodec? = MediaCryptoMermaidSvgCodec,
) {
    private val lru = LinkedHashMap<String, String>(16, 0.75f, true)

    @Synchronized
    fun get(key: String): String? {
        lru[key]?.let { return it }
        val dir = diskDir ?: return null
        val diskCodec = codec ?: return null
        if (key.isEmpty()) return null
        val file = java.io.File(dir, "$key.svg")
        if (!file.isFile) return null
        val svg = runCatching { diskCodec.decode(file.readBytes()) }.getOrNull()
        if (svg == null || svg.isEmpty() || svg.length > maxSvgChars) {
            runCatching { file.delete() }
            return null
        }
        lru[key] = svg
        trimMemory()
        return svg
    }

    @Synchronized
    fun put(key: String, svg: String) {
        if (key.isEmpty() || svg.isEmpty() || svg.length > maxSvgChars) return
        lru[key] = svg
        trimMemory()
        val dir = diskDir ?: return
        val diskCodec = codec ?: return
        val encoded = runCatching { diskCodec.encode(svg) }.getOrNull() ?: return
        runCatching {
            val tmp = java.io.File(dir, "$key.svg.tmp")
            tmp.writeBytes(encoded)
            encoded.fill(0)
            val target = java.io.File(dir, "$key.svg")
            if (!tmp.renameTo(target)) {
                target.writeBytes(encoded)
                tmp.delete()
            }
        }
    }

    private fun trimMemory() {
        val iterator = lru.entries.iterator()
        while (lru.size > maxEntries && iterator.hasNext()) {
            iterator.next()
            iterator.remove()
        }
    }
}

/** 进程共享实例；由 installMermaidSvgCache 注入磁盘目录后重建。 */
internal var SharedMermaidSvgCache: MermaidSvgCache = MermaidSvgCache()

/** 注入磁盘持久化目录（cacheDir/mermaid_svg）。幂等；在宿主 Activity/Service onCreate 调用。 */
internal fun installMermaidSvgCache(context: android.content.Context) {
    val dir = java.io.File(context.applicationContext.cacheDir, "mermaid_svg")
    runCatching { dir.mkdirs() }
    SharedMermaidSvgCache = MermaidSvgCache(diskDir = dir)
}

internal fun mermaidSvgCacheKey(source: String): String =
    MessageDigest.getInstance("SHA-256").digest(source.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

/** 接收 viewer 页上报的渲染结果；页面为本地可信资产，接口面仅暴露该方法。 */
internal class MermaidRenderBridge(private val cache: MermaidSvgCache) {
    @JavascriptInterface
    fun onRendered(key: String?, svg: String?) {
        if (!key.isNullOrEmpty() && !svg.isNullOrEmpty()) cache.put(key, svg)
    }
}

/** 固定本地页面负责渲染，平移和缩放直接使用 WebView 原生能力。 */
@SuppressLint("SetJavaScriptEnabled", "ClickableViewAccessibility")
@Composable
fun MermaidWebView(source: String, modifier: Modifier = Modifier) {
    val sourceLiteral = remember(source) { mermaidJsString(source) }
    val cacheKey = remember(source) { mermaidSvgCacheKey(source) }
    AndroidView(
        modifier = modifier.fillMaxWidth().height(300.dp),
        factory = { context ->
            val assetLoader = WebViewAssetLoader.Builder()
                .addPathHandler("/assets/", AssetsPathHandler(context))
                .build()
            WebView(context).apply {
                val webView = this
                val gestureDetector = GestureDetector(context, object : GestureDetector.SimpleOnGestureListener() {
                    override fun onDown(event: MotionEvent): Boolean = false

                    override fun onDoubleTap(event: MotionEvent): Boolean {
                        webView.loadUrl(MERMAID_VIEWER_URL)
                        return true
                    }
                })
                setBackgroundColor(Color.TRANSPARENT)
                overScrollMode = View.OVER_SCROLL_NEVER
                settings.apply {
                    javaScriptEnabled = true
                    domStorageEnabled = false
                    allowFileAccess = false
                    allowContentAccess = false
                    // 与 MathWebView 一致：渲染只允许读 assets，禁止任何网络加载。
                    // 此前仅有导航阻断 + 资源白名单，非 asset 请求会落到 WebView 默认处理；
                    // 隐私政策承诺「渲染全本地」，这一行把它变成硬保证。
                    blockNetworkLoads = true
                    setSupportZoom(true)
                    builtInZoomControls = true
                    displayZoomControls = false
                    useWideViewPort = true
                    loadWithOverviewMode = false
                }
                isVerticalScrollBarEnabled = false
                isHorizontalScrollBarEnabled = false
                setOnTouchListener { view, event ->
                    if (gestureDetector.onTouchEvent(event)) return@setOnTouchListener true
                    when (event.actionMasked) {
                        MotionEvent.ACTION_DOWN, MotionEvent.ACTION_POINTER_DOWN, MotionEvent.ACTION_MOVE ->
                            view.parent?.requestDisallowInterceptTouchEvent(true)
                        MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                            view.parent?.requestDisallowInterceptTouchEvent(false)
                    }
                    false
                }
                webViewClient = object : WebViewClient() {
                    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                        assetLoader.shouldInterceptRequest(request.url)

                    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean = true

                    override fun onPageFinished(view: WebView, url: String) {
                        super.onPageFinished(view, url)
                        val pageTag = view.tag as? MermaidPageTag ?: return
                        val cached = SharedMermaidSvgCache.get(pageTag.cacheKey)
                        if (cached != null) {
                            view.evaluateJavascript("window.showCachedSvg(${mermaidJsString(cached)})", null)
                        } else {
                            view.evaluateJavascript(
                                "window.renderMermaid(${pageTag.sourceLiteral}, ${mermaidJsString(pageTag.cacheKey)})",
                                null,
                            )
                        }
                    }
                }
                addJavascriptInterface(MermaidRenderBridge(SharedMermaidSvgCache), "FAEVaultMermaid")
                tag = MermaidPageTag(cacheKey, sourceLiteral)
                loadUrl(MERMAID_VIEWER_URL)
            }
        },
        update = { webView ->
            val pageTag = webView.tag as? MermaidPageTag
            if (pageTag != null && pageTag.sourceLiteral != sourceLiteral) {
                val newTag = MermaidPageTag(cacheKey, sourceLiteral)
                webView.tag = newTag
                if (webView.progress == 100) {
                    val cached = SharedMermaidSvgCache.get(cacheKey)
                    if (cached != null) {
                        webView.evaluateJavascript("window.showCachedSvg(${mermaidJsString(cached)})", null)
                    } else {
                        webView.evaluateJavascript(
                            "window.renderMermaid($sourceLiteral, ${mermaidJsString(cacheKey)})",
                            null,
                        )
                    }
                }
            }
        },
        onRelease = { webView ->
            webView.stopLoading()
            webView.loadUrl("about:blank")
            webView.removeAllViews()
            webView.destroy()
        },
    )
}

private class MermaidPageTag(val cacheKey: String, val sourceLiteral: String)

/** JS 字符串字面量，同时阻止源码跳出 script 调用。 */
internal fun mermaidJsString(value: String): String = buildString {
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
            else -> append(ch)
        }
    }
    append('"')
}
