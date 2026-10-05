package com.vault.ui.screens

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.vault.ui.MarkdownRenderPolicy
import com.vault.ui.MarkdownText

/**
 * Markdown 只读渲染入口：commonmark-java 官方解析 + Compose 原生渲染。
 *
 * 支持 CommonMark 全量语法与 GFM 扩展；```mermaid 围栏块原生渲染为图表
 * （flowchart/sequence/pie），其余类型回退为源码展示。无 WebView。
 */
@Composable
fun MarkdownView(
    markdown: String,
    modifier: Modifier = Modifier,
    renderPolicy: MarkdownRenderPolicy = MarkdownRenderPolicy.EDITOR_ADAPTIVE,
    onRenderComplete: () -> Unit = {},
) {
    MarkdownText(
        raw = markdown,
        modifier = modifier,
        renderPolicy = renderPolicy,
        onRenderComplete = onRenderComplete,
    )
}
