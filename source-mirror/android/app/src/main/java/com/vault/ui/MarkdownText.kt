@file:OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)

package com.vault.ui

import android.content.Intent
import android.graphics.drawable.PictureDrawable
import android.net.Uri
import android.widget.ImageView
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.LazyListState
import com.vault.ui.vaultHorizontalScroll as horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.CheckBoxOutlineBlank
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.viewinterop.AndroidView
import com.caverock.androidsvg.SVG
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.BaselineShift
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.isSpecified
import androidx.compose.ui.unit.sp
import com.vault.R
import com.vault.ui.markdown.MathWebView
import com.vault.ui.markdown.MermaidWebView
import com.vault.ui.markdown.ControlledDetailsBlock
import com.vault.ui.markdown.ControlledMarkdownHtml
import com.vault.ui.markdown.childNodes
import org.commonmark.ext.footnotes.FootnoteReference
import org.commonmark.ext.gfm.strikethrough.Strikethrough
import org.commonmark.ext.gfm.tables.TableBody
import org.commonmark.ext.gfm.tables.TableCell
import org.commonmark.ext.gfm.tables.TableHead
import org.commonmark.ext.gfm.tables.TableRow
import org.commonmark.ext.ins.Ins
import org.commonmark.ext.task.list.items.TaskListItemMarker
import org.commonmark.node.BlockQuote
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.Emphasis
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.HardLineBreak
import org.commonmark.node.Heading
import org.commonmark.node.HtmlBlock
import org.commonmark.node.HtmlInline
import org.commonmark.node.Image
import org.commonmark.node.IndentedCodeBlock
import org.commonmark.node.Link
import org.commonmark.node.ListItem
import org.commonmark.node.Node
import org.commonmark.node.OrderedList
import org.commonmark.node.Paragraph
import org.commonmark.node.SoftLineBreak
import org.commonmark.node.StrongEmphasis
import org.commonmark.node.Text
import org.commonmark.node.ThematicBreak
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.text.Normalizer
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import androidx.compose.runtime.withFrameNanos
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Markdown 渲染（commonmark-java 官方解析 + Compose 原生渲染）。
 *
 * 支持：CommonMark 全量语法 + GFM 表格/删除线/任务列表、自动链接、脚注、++下划线++；
 * ```mermaid 围栏块渲染为原生图表（flowchart/sequence/pie），其余类型回退为源码展示。
 */
@Composable
fun MarkdownText(
    raw: String,
    modifier: Modifier = Modifier,
    renderPolicy: MarkdownRenderPolicy = MarkdownRenderPolicy.EDITOR_ADAPTIVE,
    onRenderComplete: () -> Unit = {},
) {
    val context = LocalContext.current
    // 解析只读取现有缓存；缓存未命中时统一放到后台线程，避免组合阶段阻塞主线程。
    val initial = remember(raw, renderPolicy) { SharedMarkdownDocumentCache.lookup(raw) }
    var rendered by remember(raw, renderPolicy) { mutableStateOf(initial) }
    var parseFailed by remember(raw, renderPolicy) { mutableStateOf(false) }
    LaunchedEffect(raw, renderPolicy) {
        if (rendered == null) {
            try {
                rendered = withContext(Dispatchers.Default) { SharedMarkdownDocumentCache.compute(raw) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                android.util.Log.e("MdParse", "markdown parse failed len=${raw.length}", error)
                parseFailed = true
            }
        }
    }
    if (parseFailed) {
        LaunchedEffect(raw) { onRenderComplete() }
        Text(
            text = raw,
            modifier = modifier,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }
    val current = rendered
    if (current == null) {
        Box(
            modifier = modifier.heightIn(min = 96.dp),
            contentAlignment = Alignment.Center,
        ) {
            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
        }
        return
    }
    // 渲染完成条件 = AST 解析完成（后台线程已完成）；不再以"所有 Block 已 Compose"为准
    LaunchedEffect(current) { onRenderComplete() }
    val headings = current.headings
    val anchorIds = current.anchorIds
    val requesters = remember(current) { anchorIds.associateWith { BringIntoViewRequester() } }
    val scope = rememberCoroutineScope()
    val navigation = remember(current, requesters, scope, context) {
        MarkdownAnchorNavigation(
            requesterByHeading = headings.zip(anchorIds).associate { it.first to requesters.getValue(it.second) },
            navigate = { destination ->
                when (markdownLinkTarget(destination)) {
                    MarkdownLinkTarget.Anchor -> {
                        val anchor = markdownAnchorDestination(destination)
                        val requester = anchor?.let(requesters::get)
                        if (requester != null) {
                            scope.launch { requester.bringIntoView() }
                        }
                    }
                    MarkdownLinkTarget.External -> runCatching {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(destination)))
                    }
                    MarkdownLinkTarget.Unsupported -> Unit
                }
            },
        )
    }
    CompositionLocalProvider(
        LocalMarkdownAnchorNavigation provides navigation,
        LocalControlledDetails provides current.controlled.details,
    ) {
        Column(modifier = modifier) {
            current.blocks.forEachIndexed { index, block ->
                key(index) { MdBlock(block) }
            }
        }
    }
}

private data class MarkdownAnchorNavigation(
    val requesterByHeading: Map<Heading, BringIntoViewRequester> = emptyMap(),
    val navigate: (String) -> Unit = {},
)

private val LocalMarkdownAnchorNavigation = staticCompositionLocalOf { MarkdownAnchorNavigation() }
private val LocalControlledDetails = staticCompositionLocalOf<Map<String, ControlledDetailsBlock>> { emptyMap() }

internal fun markdownHeadings(root: Node): List<Heading> = buildList {
    fun collect(node: Node) {
        if (node is Heading) add(node)
        node.childNodes().forEach(::collect)
    }
    collect(root)
}

internal fun markdownPlainText(node: Node): String = buildString {
    fun appendNode(current: Node) {
        when (current) {
            is Text -> append(current.literal)
            is Code -> append(current.literal)
            is SoftLineBreak, is HardLineBreak -> append(' ')
            else -> current.childNodes().forEach(::appendNode)
        }
    }
    appendNode(node)
}

/** 生成与常见 Markdown 查看器一致的 Unicode 标题锚点，并为重复标题追加序号。 */
internal fun markdownHeadingAnchors(headings: List<String>): List<String> {
    val occurrences = mutableMapOf<String, Int>()
    return headings.map { heading ->
        val base = markdownAnchorSlug(heading)
        val occurrence = occurrences.getOrDefault(base, 0)
        occurrences[base] = occurrence + 1
        if (occurrence == 0) base else "$base-$occurrence"
    }
}

internal fun markdownAnchorSlug(value: String): String {
    val normalized = Normalizer.normalize(value, Normalizer.Form.NFKC).trim().lowercase(Locale.ROOT)
    val slug = buildString {
        var pendingDash = false
        normalized.forEach { ch ->
            when {
                ch.isLetterOrDigit() || ch == '_' -> {
                    if (pendingDash && isNotEmpty() && last() != '-') append('-')
                    append(ch)
                    pendingDash = false
                }
                ch == '-' || ch.isWhitespace() -> pendingDash = true
            }
        }
    }.trim('-')
    return slug.ifEmpty { "section" }
}

internal fun markdownAnchorDestination(destination: String): String? {
    if (!destination.startsWith('#')) return null
    val encoded = destination.drop(1)
    if (encoded.isBlank()) return null
    val decoded = runCatching {
        URLDecoder.decode(encoded.replace("+", "%2B"), StandardCharsets.UTF_8.name())
    }.getOrElse { encoded }
    return markdownAnchorSlug(decoded)
}

internal enum class MarkdownLinkTarget { Anchor, External, Unsupported }

internal fun markdownLinkTarget(destination: String): MarkdownLinkTarget = when {
    destination.startsWith('#') -> MarkdownLinkTarget.Anchor
    destination.startsWith("https://", ignoreCase = true) ||
        destination.startsWith("http://", ignoreCase = true) -> MarkdownLinkTarget.External
    else -> MarkdownLinkTarget.Unsupported
}

private val UNDERLINE_HTML_REGEX = Regex(
    "<u>(.*?)</u>",
    setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
)

internal fun normalizeUnderlineHtml(source: String): String =
    source.replace(UNDERLINE_HTML_REGEX, "++$1++")

@Composable
private fun MdBlock(node: Node) {
    when (node) {
        is Heading -> {
            val anchorModifier = LocalMarkdownAnchorNavigation.current.requesterByHeading[node]
                ?.let { Modifier.bringIntoViewRequester(it) }
                ?: Modifier
            Spacer(Modifier.height(if (node.level == 1) 8.dp else 12.dp))
            Text(
                text = inlineAnnotated(node),
                modifier = anchorModifier,
                style = when (node.level) {
                    1 -> MaterialTheme.typography.titleLarge
                    2 -> MaterialTheme.typography.titleMedium
                    3 -> MaterialTheme.typography.titleSmall
                    else -> MaterialTheme.typography.titleSmall
                },
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
        }
        is Paragraph -> {
            FormulaParagraph(node)
            Spacer(Modifier.height(6.dp))
        }
                    is BulletList -> BulletListItems(node, ordered = false)
                is OrderedList -> BulletListItems(node, ordered = true)
        is BlockQuote -> {
            val quoteColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f)
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 2.dp)
                    .drawBehind {
                        drawRect(
                            color = quoteColor,
                            size = Size(width = 4.dp.toPx(), height = size.height),
                        )
                    }
                    .padding(start = 14.dp),
            ) {
                for (child in node.childNodes()) MdBlock(child)
            }
        }
        is ThematicBreak -> {
            Spacer(Modifier.height(8.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Spacer(Modifier.height(8.dp))
        }
        is FencedCodeBlock -> CodeBlockUi(node.info?.trim()?.lowercase(), node.literal)
        is IndentedCodeBlock -> CodeBlockUi(null, node.literal)
        is HtmlBlock -> HtmlBlockUi(node)
        is TableBlockNode -> TableUi(node)
        else -> Unit
    }
}

//---HTML/SVG---

@Composable
private fun HtmlBlockUi(node: HtmlBlock) {
    val raw = remember(node) { node.literal.trim() }
    val picture = remember(raw) { parseSvgPicture(raw) }
    if (picture != null) {
        AndroidView(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 24.dp, max = 480.dp),
            factory = { context ->
                ImageView(context).apply {
                    adjustViewBounds = true
                    scaleType = ImageView.ScaleType.FIT_CENTER
                    setImageDrawable(PictureDrawable(picture))
                }
            },
        )
    } else {
        Text(
            text = raw,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    Spacer(Modifier.height(6.dp))
}

private fun parseSvgPicture(raw: String): android.graphics.Picture? {
    val source = when {
        raw.startsWith("<svg", ignoreCase = true) -> raw
        raw.startsWith("data:image/svg+xml", ignoreCase = true) -> decodeSvgDataUri(raw)
        else -> null
    } ?: return null
    return runCatching { SVG.getFromString(source).renderToPicture() }.getOrNull()
}

private fun decodeSvgDataUri(value: String): String? {
    val metadata = value.substringBefore(',', missingDelimiterValue = "")
    val content = value.substringAfter(',', missingDelimiterValue = "")
    if (metadata.isEmpty() || content.isEmpty()) return null
    return runCatching {
        if (metadata.contains(";base64", ignoreCase = true)) {
            String(android.util.Base64.decode(content, android.util.Base64.DEFAULT), Charsets.UTF_8)
        } else {
            URLDecoder.decode(content.replace("+", "%2B"), StandardCharsets.UTF_8.name())
        }
    }.getOrNull()
}

//---段落与列表---

/** 仅将独占段落的 LaTeX 公式交给本地 KaTeX，避免把金额等普通 `$` 文本误判为公式。 */
@Composable
private fun FormulaParagraph(node: Paragraph) {
    val source = remember(node) {
        node.childNodes().filterIsInstance<Text>().joinToString("") { it.literal }.trim()
    }
    val displayFormula = source.takeIf { it.startsWith("$$") && it.endsWith("$$") && it.length > 4 }
        ?.removePrefix("$$")?.removeSuffix("$$")?.trim()
    val inlineFormula = source.takeIf {
        displayFormula == null && it.startsWith('$') && it.endsWith('$') && !it.startsWith("$$") && it.length > 2
    }?.removePrefix("$")?.removeSuffix("$")?.trim()
    when {
        !displayFormula.isNullOrBlank() -> MathWebView(displayFormula, displayMode = true)
        !inlineFormula.isNullOrBlank() -> MathWebView(inlineFormula, displayMode = false)
        else -> Text(
            text = inlineAnnotated(node),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** commonmark 表格扩展节点类型别名（避免 import 冲突的包装）。 */
private typealias TableBlockNode = org.commonmark.ext.gfm.tables.TableBlock

@Composable
private fun BulletListItems(list: Node, ordered: Boolean) {
    val startNumber = (list as? OrderedList)?.startNumber ?: 1
    // ── 尺寸体系基准：正文字体行高（随系统字体缩放同步）──
    val bodyStyle = MaterialTheme.typography.bodySmall
    val density = LocalDensity.current
    val markerBaseSize = with(density) {
        if (bodyStyle.lineHeight.isSpecified) bodyStyle.lineHeight.toDp() else bodyStyle.fontSize.toDp()
    }
    val taskMarkerSize = markerBaseSize
    // 槽位宽度：最小 22dp，随任务图标放大；有序列表按最大序号文本实测宽度扩展，
    // 保证 "99./100./1000." 不挤压正文，且同一列表正文起点处于同一垂直线
    val markerGutterWidth = maxOf(MIN_MARKER_GUTTER_WIDTH, taskMarkerSize)
    val orderedGutterWidth = if (ordered) {
        val textMeasurer = rememberTextMeasurer()
        val count = list.childNodes().count { it is ListItem }
        val widestLabel = "${startNumber + count - 1}."
        val measured = textMeasurer.measure(widestLabel, bodyStyle).size.width
        maxOf(MIN_MARKER_GUTTER_WIDTH, with(density) { measured.toDp() })
    } else {
        markerGutterWidth
    }
    var index = 0
    for (item in list.childNodes()) {
        if (item !is ListItem) continue
        index++
        val numberLabel = if (ordered) "${startNumber + index - 1}." else null
        val taskState = taskCheckboxOf(item)

        Row(
            Modifier
                .fillMaxWidth()
                .padding(top = 2.dp, bottom = 2.dp),
            verticalAlignment = Alignment.Top,
        ) {
            // 多行任务时图标必须与第一行垂直居中：容器高度=行高，Top 对齐 + 内部 Center
            Box(
                modifier = Modifier
                    .width(if (ordered) orderedGutterWidth else markerGutterWidth)
                    .height(markerBaseSize),
                contentAlignment = Alignment.Center,
            ) {
                when {
                    taskState != null -> Icon(
                        imageVector = if (taskState) Icons.Filled.CheckBox else Icons.Filled.CheckBoxOutlineBlank,
                        contentDescription = uiText(if (taskState) "已完成" else "未完成"),
                        modifier = Modifier.size(taskMarkerSize),
                        tint = if (taskState) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                    numberLabel != null -> Text(
                        text = numberLabel,
                        style = bodyStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.End,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    else -> Text(
                        text = "•",
                        style = bodyStyle,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Spacer(Modifier.width(8.dp))
            Column(
                Modifier.weight(1f),
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.Top,
            ) {
                var firstBlock = true
                for (child in item.childNodes()) {
                    val isNestedList = child is BulletList || child is OrderedList
                    if (isNestedList) {
                        // 嵌套列表依靠父级正文 Column 的位置自然形成一级缩进，不再叠加 depth 偏移
                        BulletListItems(child, child is OrderedList)
                    } else {
                        if (!firstBlock || taskState == null) {
                            MdBlock(child)
                        } else {
                            InlineOnlyParagraph(child, checked = taskState)
                        }
                    }
                    firstBlock = false
                }
            }
        }
    }
}

/** 列表 marker 槽位的最小宽度；实际宽度会随行高/序号文本扩展。 */
private val MIN_MARKER_GUTTER_WIDTH = 22.dp


/** 任务列表项的首个 checkbox 状态；非任务项返回 null。 */
internal fun taskCheckboxOf(item: ListItem): Boolean? {
    fun findMarker(node: Node?): TaskListItemMarker? {
        var current = node
        while (current != null) {
            if (current is TaskListItemMarker) return current
            findMarker(current.firstChild)?.let { return it }
            current = current.next
        }
        return null
    }

    return findMarker(item.firstChild)?.isChecked
}

/** 任务项首段：checkbox 已单独渲染，段落本身只输出行内内容（去掉缩进多余的空段）；已完成项加删除线并调暗。 */
@Composable
private fun InlineOnlyParagraph(node: Node, checked: Boolean) {
    if (node is Paragraph) {
        Text(
            text = inlineAnnotated(node),
            style = MaterialTheme.typography.bodySmall,
            color = if (checked) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.onSurface
            },
            textDecoration = if (checked) TextDecoration.LineThrough else null,
        )
    } else {
        MdBlock(node)
    }
}

@Composable
private fun CodeBlockUi(info: String?, literal: String) {
    val context = LocalContext.current
    val code = literal.trimEnd('\n')
    if (info == "vault-details") {
        val id = code.trim()
        LocalControlledDetails.current[id]?.let { DetailsBlockUi(id, it) }
            ?: Text(code, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(6.dp))
    } else if (info == "mermaid") {
        Column(Modifier.fillMaxWidth()) {
            CodeBlockToolbar(info, code) { copySensitive(context, "代码", code) }
            MermaidFenceUi(literal)
        }
        Spacer(Modifier.height(6.dp))
    } else {
        // 普通代码块保持完整内容，外层 LazyColumn 只负责块级虚拟化，避免破坏复制和代码语义
        PlainCodeUi(info = info, fullCode = code, display = code)
    }
}

/** 纯文本代码块的视觉容器：工具栏（语言标签 + 复制）+ 横向滚动不换行文本。 */
@Composable
private fun PlainCodeUi(info: String?, fullCode: String, display: String) {
    Spacer(Modifier.height(4.dp))
    val context = LocalContext.current
    Column(
        Modifier
            .fillMaxWidth()
            .clip(VaultShape)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        CodeBlockToolbar(info, fullCode) { copySensitive(context, "代码", fullCode) }
        Text(
            text = display,
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
            softWrap = false,
        )
    }
    Spacer(Modifier.height(6.dp))
}

@Composable
private fun DetailsBlockUi(id: String, block: ControlledDetailsBlock) {
    var expanded by rememberSaveable(id) { mutableStateOf(false) }
    Column(
        Modifier
            .fillMaxWidth()
            .clip(VaultShape)
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
    ) {
        Row(
            Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded }
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = if (expanded) "▾" else "▸",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = block.summary,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        if (expanded) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            // Details 展开内容为普通 Column 渲染（禁止嵌套同方向 LazyColumn）；
            // 详情页 Lazy 路径下 Details 整体是一个 item，展开只改变该 item 高度一次
            MarkdownText(
                raw = block.body,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
        }
    }
}

@Composable
private fun CodeBlockToolbar(info: String?, code: String, onCopy: () -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        info?.takeIf { it.isNotBlank() }?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
        } ?: Spacer(Modifier.weight(1f))
        IconButton(
            onClick = onCopy,
            enabled = code.isNotEmpty(),
            modifier = Modifier.size(30.dp),
        ) {
            Icon(
                painter = painterResource(R.drawable.ic_action_copy_custom),
                contentDescription = uiText("复制代码"),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

@Composable
private fun MermaidFenceUi(source: String) {
    MermaidWebView(
        source = source,
        modifier = Modifier
            .fillMaxWidth()
            .height(300.dp),
    )
}

@Composable
private fun TableUi(table: TableBlockNode) {
    val model = remember(table) { buildTableModel(table) }
    if (model.columns.isEmpty()) return

    Spacer(Modifier.height(4.dp))
    val tableWidth = model.columns.sumOf { it.width.value.toDouble() }.toFloat().dp + 16.dp
    Box(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
        Column(
            Modifier
                .width(tableWidth)
                .clip(VaultShape)
                .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)),
        ) {
            if (model.headerCells.isNotEmpty()) {
                TableRowUi(model.headerCells, model.columns, bold = true)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            for ((ri, cells) in model.bodyCells.withIndex()) {
                key(ri) {
                    TableRowUi(cells, model.columns, bold = false)
                    if (ri != model.bodyCells.lastIndex) {
                        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f))
                    }
                }
            }
        }
    }
    Spacer(Modifier.height(6.dp))
}

private data class TableModel(
    val headerCells: List<TableCell>,
    val bodyCells: List<List<TableCell>>,
    val columns: List<Col>,
)

private fun buildTableModel(table: TableBlockNode): TableModel {
    val head = table.childNodes().filterIsInstance<TableHead>().firstOrNull()
    val body = table.childNodes().filterIsInstance<TableBody>().firstOrNull()
    val headerRow = head?.childNodes()?.filterIsInstance<TableRow>()?.firstOrNull()
    val headerCells = headerRow?.childNodes()?.filterIsInstance<TableCell>().orEmpty()
    val bodyCells = body
        ?.childNodes()
        ?.filterIsInstance<TableRow>()
        ?.map { row -> row.childNodes().filterIsInstance<TableCell>() }
        .orEmpty()
    val columns = buildList {
        headerCells.forEach { cell -> add(Col(alignOf(cell.alignment), cellWidth(cell))) }
        if (isEmpty()) {
            bodyCells.firstOrNull()?.forEach { cell -> add(Col(null, cellWidth(cell))) }
        }
    }
    return TableModel(headerCells, bodyCells, columns)
}

/** 表格列描述：对齐方式与按内容长度加权的列宽。 */
private data class Col(val align: TextAlign?, val width: androidx.compose.ui.unit.Dp)

private fun alignOf(a: TableCell.Alignment?): TextAlign? = when (a) {
    TableCell.Alignment.CENTER -> TextAlign.Center
    TableCell.Alignment.RIGHT -> TextAlign.Right
    else -> null
}

private fun cellWidth(cell: TableCell): androidx.compose.ui.unit.Dp {
    val textLen = markdownPlainText(cell).length.coerceIn(4, 40)
    return (textLen * 10 + 28).dp.coerceIn(120.dp, 428.dp)
}

@Composable
private fun TableRowUi(cells: List<TableCell>, columns: List<Col>, bold: Boolean) {
    Row(Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
        cells.forEachIndexed { i, cell ->
            if (i >= columns.size) return@forEachIndexed
            if (i > 0) Spacer(Modifier.width(8.dp))
            Text(
                text = inlineAnnotated(cell),
                modifier = Modifier.width(columns[i].width),
                style = MaterialTheme.typography.labelSmall,
                softWrap = true,
                textAlign = columns[i].align,
                fontWeight = if (bold) FontWeight.SemiBold else FontWeight.Normal,
                color = if (bold) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---------- 行内渲染：AST → AnnotatedString ----------

@Composable
private fun inlineAnnotated(parent: Node): AnnotatedString {
    val colors = MaterialTheme.colorScheme
    val imageWord = uiText("图片")
    val onLinkClick = LocalMarkdownAnchorNavigation.current.navigate
    return remember(parent, colors, imageWord, onLinkClick) {
        buildAnnotatedString {
            appendInlineChildren(parent, colors, imageWord, onLinkClick)
        }
    }
}

private fun AnnotatedString.Builder.appendInlineChildren(
    parent: Node,
    colors: androidx.compose.material3.ColorScheme,
    imageWord: String,
    onLinkClick: (String) -> Unit,
) {
    for (node in parent.childNodes()) {
        appendInline(node, colors, imageWord, onLinkClick)
    }
}

private fun AnnotatedString.Builder.appendInline(
    node: Node,
    colors: androidx.compose.material3.ColorScheme,
    imageWord: String,
    onLinkClick: (String) -> Unit,
) {
    when (node) {
        is Text -> appendControlledHtml(node.literal, colors)
        is SoftLineBreak, is HardLineBreak -> append('\n')
        is StrongEmphasis -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { appendInlineChildren(node, colors, imageWord, onLinkClick) }
        is Emphasis -> withStyle(SpanStyle(fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)) { appendInlineChildren(node, colors, imageWord, onLinkClick) }
        is Strikethrough -> withStyle(SpanStyle(textDecoration = TextDecoration.LineThrough)) { appendInlineChildren(node, colors, imageWord, onLinkClick) }
        is Ins -> withStyle(SpanStyle(textDecoration = TextDecoration.Underline)) { appendInlineChildren(node, colors, imageWord, onLinkClick) }
        is Code -> withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = colors.surfaceVariant)) { append(node.literal) }
        is Link -> withLink(
            LinkAnnotation.Clickable(
                tag = node.destination,
                styles = TextLinkStyles(style = SpanStyle(color = colors.primary, textDecoration = TextDecoration.Underline)),
                linkInteractionListener = { onLinkClick(node.destination) },
            ),
        ) { appendInlineChildren(node, colors, imageWord, onLinkClick) }
        is Image -> withStyle(SpanStyle(color = colors.onSurfaceVariant, textDecoration = TextDecoration.Underline)) {
            append("[$imageWord:${node.childNodes().filterIsInstance<Text>().joinToString("") { it.literal }}]")
        }
        is FootnoteReference -> withStyle(SpanStyle(baselineShift = BaselineShift.Superscript, fontSize = 10.sp, color = colors.primary)) {
            append("[${node.label}]")
        }
        is HtmlInline -> {
            val lit = node.literal.trim().lowercase()
            when {
                lit == "<br>" || lit == "<br/>" || lit == "<br />" -> append('\n')
                !lit.startsWith("<") -> append(node.literal)
                else -> Unit // 其余内联 HTML 标签静默丢弃，不执行；任务勾选框由 TaskListItemMarker 渲染
            }
        }
        else -> appendInlineChildren(node, colors, imageWord, onLinkClick)
    }
}

internal enum class HtmlSpanKind { PLAIN, MARK, SUB, SUP, KBD }

internal data class HtmlSpanSegment(val text: String, val kind: HtmlSpanKind)

private val CONTROLLED_HTML_MARKER_REGEX = Regex(
    "${Regex.escape(ControlledMarkdownHtml.MARKER_OPEN.toString())}(/?)(MARK|SUB|SUP|KBD)${Regex.escape(ControlledMarkdownHtml.MARKER_CLOSE.toString())}",
)

internal fun controlledHtmlSegments(value: String): List<HtmlSpanSegment> {
    val result = mutableListOf<HtmlSpanSegment>()
    var kind = HtmlSpanKind.PLAIN
    var cursor = 0
    CONTROLLED_HTML_MARKER_REGEX.findAll(value).forEach { match ->
        if (match.range.first > cursor) result += HtmlSpanSegment(value.substring(cursor, match.range.first), kind)
        val closing = match.groupValues[1].isNotEmpty()
        val target = runCatching { HtmlSpanKind.valueOf(match.groupValues[2]) }.getOrDefault(HtmlSpanKind.PLAIN)
        kind = if (closing) HtmlSpanKind.PLAIN else target
        cursor = match.range.last + 1
    }
    if (cursor < value.length) result += HtmlSpanSegment(value.substring(cursor), kind)
    if (result.isEmpty() && value.isNotEmpty()) result += HtmlSpanSegment(value, HtmlSpanKind.PLAIN)
    return result
}

private fun AnnotatedString.Builder.appendControlledHtml(
    value: String,
    colors: androidx.compose.material3.ColorScheme,
) {
    controlledHtmlSegments(value).forEach { segment ->
        val style = when (segment.kind) {
            HtmlSpanKind.PLAIN -> SpanStyle()
            HtmlSpanKind.MARK -> SpanStyle(background = colors.tertiaryContainer, color = colors.onTertiaryContainer)
            HtmlSpanKind.SUB -> SpanStyle(fontSize = 10.sp, baselineShift = BaselineShift.Subscript)
            HtmlSpanKind.SUP -> SpanStyle(fontSize = 10.sp, baselineShift = BaselineShift.Superscript)
            HtmlSpanKind.KBD -> SpanStyle(fontFamily = FontFamily.Monospace, background = colors.surfaceVariant)
        }
        withStyle(style) { append(segment.text) }
    }
}


//---块级懒加载与锚点---

/** 单个顶层 Block 的稳定描述：Key = 类型:内容指纹8:索引，不随滚动/组合状态变化。 */
internal class MarkdownBlockSpec(
    val index: Int,
    val type: String,
    val key: String,
    val node: Node,
    /** 该块拥有的标题锚点（通常 0 或 1 个）。 */
    val anchors: List<String>,
) {
    val isHeavyMermaid: Boolean
        get() = node is FencedCodeBlock && node.info?.trim()?.lowercase() == "mermaid"
}

/**
 * 锚点注册表：anchorId → 标题块的 BringIntoViewRequester。
 * 标题 item 进入组合时注册；跨 item 内联链接在点击时读取。
 * 目标未组合时表中无值，跳转控制器先粗定位再等待注册（两阶段）。
 */
internal class MarkdownAnchorRegistry {
    val requesters = mutableMapOf<String, BringIntoViewRequester>()
}

/**
 * 兼容旧调用方的重内容门控接口。
 * 实际虚拟化统一交给 LazyColumn，避免重复调度和滚动状态写入。
 */
@Suppress("UNUSED_PARAMETER")
internal class MarkdownHeavyGate {
    val readyKeys: Set<String> = emptySet()
    val forcedKeys = mutableMapOf<String, Boolean>()

    fun update(
        items: List<Triple<String, Int, String>>,
        firstVisibleIndex: Int,
        windowAhead: Int = 24,
        windowBehind: Int = 6,
    ) = Unit

    fun isReady(spec: MarkdownBlockSpec): Boolean = true

    fun forceAround(anchorId: String, specs: List<MarkdownBlockSpec>) = Unit
}

internal fun isHeavyBlockSpec(spec: MarkdownBlockSpec): Boolean =
    spec.isHeavyMermaid || spec.type == "MathParagraph"

/** 数学段落识别：整段仅包含 $$..$$ 显示公式。 */
internal fun isDisplayMathParagraph(node: Node): Boolean {
    if (node !is Paragraph) return false
    val text = node.childNodes().filterIsInstance<org.commonmark.node.Text>().joinToString("") { it.literal }.trim()
    return text.startsWith("$$") && text.endsWith("$$") && text.length > 4
}
internal class MarkdownJumpController(private val scope: CoroutineScope) {
    private var job: Job? = null

    fun jump(
        anchorId: String,
        specs: List<MarkdownBlockSpec>,
        basePos: Int?,
        registry: MarkdownAnchorRegistry,
        state: LazyListState,
    ) {
        job?.cancel()
        job = scope.launch {
            val specIndex = specs.indexOfFirst { anchorId in it.anchors }
            if (specIndex < 0) return@launch
            basePos?.let { base ->
                runCatching { state.scrollToItem(base + specIndex) }
            }
            // 粗定位已经对齐目标块；下一帧若标题已组合，再做一次精确定位。
            withFrameNanos { }
            registry.requesters[anchorId]?.bringIntoView()
        }
    }
}

/** 构建稳定 Block Specs；同步收集每块拥有的标题锚点。 */
internal fun buildMarkdownBlockSpecs(rendered: MarkdownRenderResult): List<MarkdownBlockSpec> {
    val anchorByIndex = rendered.blockIndexByAnchor.entries.groupBy({ it.value }, { it.key })
    return rendered.blocks.mapIndexed { index, node ->
        val rawType = node::class.java.simpleName
        val type = if (rawType == "Paragraph" && isDisplayMathParagraph(node)) "MathParagraph" else rawType
        val fingerprintSource = when (node) {
            is FencedCodeBlock -> node.literal
            is HtmlBlock -> node.literal
            is Heading, is Paragraph -> markdownPlainText(node)
            else -> ""
        }
        val hash = (if (fingerprintSource.isNotEmpty()) fingerprintSource.hashCode() else node.hashCode())
            .toUInt()
            .toString(16)
        MarkdownBlockSpec(
            index = index,
            type = type,
            key = "$type:$hash:$index",
            node = node,
            anchors = anchorByIndex[index].orEmpty(),
        )
    }
}

/**
 * 页面级 LazyColumn 条目扩展：按 specs 平铺 Block items。
 *
 * @param basePosForPrefix 返回该模块首个 md item 在页面 LazyColumn 中的位置；
 *   由调用方依据「静态前缀 item 数 + 前序已解析模块(header+blocks)」计算，供粗定位使用。
 * @param surfaceColor 非 null 时拼成连续卡片样式。
 * @param attachToPrevious true 表示顶部圆角由前一个 Lazy item 提供。
 */
@Suppress("UNUSED_PARAMETER")
internal fun LazyListScope.markdownBlockItems(
    specs: List<MarkdownBlockSpec>,
    keyPrefix: String,
    registry: MarkdownAnchorRegistry,
    controller: MarkdownJumpController,
    listState: LazyListState,
    basePosForPrefix: (String) -> Int?,
    surfaceColor: androidx.compose.ui.graphics.Color? = null,
    attachToPrevious: Boolean = false,
    heavyGate: MarkdownHeavyGate? = null,
    blockHeights: MutableMap<String, Int>? = null,
    heavyPlaceholder: (@Composable (MarkdownBlockSpec, Modifier) -> Unit)? = null,
) {
    val lastIdx = specs.lastIndex
    fun itemModifier(pos: Int): Modifier {
        if (surfaceColor == null) return Modifier
        val roundTop = pos == 0 && !attachToPrevious
        val roundBottom = pos == lastIdx
        val shape = RoundedCornerShape(
            topStart = if (roundTop) VaultCornerRadius else 0.dp,
            topEnd = if (roundTop) VaultCornerRadius else 0.dp,
            bottomStart = if (roundBottom) VaultCornerRadius else 0.dp,
            bottomEnd = if (roundBottom) VaultCornerRadius else 0.dp,
        )
        return Modifier
            .fillMaxWidth()
            .background(color = surfaceColor, shape = shape)
            .padding(
                start = 16.dp,
                end = 16.dp,
                top = if (roundTop) 8.dp else 0.dp,
                bottom = if (roundBottom) 8.dp else 0.dp,
            )
    }
    specs.forEachIndexed { pos, spec ->
        item(key = "$keyPrefix:${spec.key}", contentType = spec.type) {
            val context = LocalContext.current
            val headingRequester = if (spec.anchors.isNotEmpty() && spec.node is Heading) {
                remember(spec.key) { BringIntoViewRequester() }
            } else {
                null
            }
            if (headingRequester != null) {
                DisposableEffect(spec.key, headingRequester) {
                    spec.anchors.forEach { registry.requesters[it] = headingRequester }
                    onDispose {
                        spec.anchors.forEach { anchor ->
                            if (registry.requesters[anchor] === headingRequester) {
                                registry.requesters.remove(anchor)
                            }
                        }
                    }
                }
            }
            val navigation = remember(
                spec.key,
                headingRequester,
                specs,
                keyPrefix,
                registry,
                controller,
                listState,
                basePosForPrefix,
                context,
            ) {
                MarkdownAnchorNavigation(
                    requesterByHeading = if (spec.node is Heading && headingRequester != null) {
                        mapOf(spec.node as Heading to headingRequester)
                    } else {
                        emptyMap()
                    },
                    navigate = { destination ->
                        when (markdownLinkTarget(destination)) {
                            MarkdownLinkTarget.Anchor -> {
                                markdownAnchorDestination(destination)?.let { anchor ->
                                    controller.jump(anchor, specs, basePosForPrefix(keyPrefix), registry, listState)
                                }
                            }
                            MarkdownLinkTarget.External -> runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(destination)))
                            }
                            MarkdownLinkTarget.Unsupported -> Unit
                        }
                    },
                )
            }
            // LazyColumn 已负责可见块虚拟化，这里只渲染当前 item，避免第二套视口门控。
            CompositionLocalProvider(LocalMarkdownAnchorNavigation provides navigation) {
                Column(modifier = itemModifier(pos)) {
                    MdBlock(spec.node)
                }
            }
        }
    }
}

