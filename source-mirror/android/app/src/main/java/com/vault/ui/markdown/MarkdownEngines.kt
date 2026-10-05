package com.vault.ui.markdown

import org.commonmark.ext.autolink.AutolinkExtension
import org.commonmark.ext.footnotes.FootnotesExtension
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension
import org.commonmark.ext.gfm.tables.TablesExtension
import org.commonmark.ext.ins.InsExtension
import org.commonmark.ext.task.list.items.TaskListItemsExtension
import org.commonmark.node.Node
import org.commonmark.parser.Parser

/**
 * commonmark-java 官方参考实现 + 全部官方扩展。
 * 覆盖：CommonMark 1.0 规范全量语法、GFM 表格/删除线/任务列表、URL 自动链接、脚注、下划线 ++。
 */
object MarkdownEngines {

    val extensions = listOf(
        TablesExtension.create(),
        StrikethroughExtension.create(),
        TaskListItemsExtension.create(),
        AutolinkExtension.create(),
        FootnotesExtension.create(),
        InsExtension.create(),
    )

    private val parser: Parser = Parser.builder().extensions(extensions).build()

    fun parse(source: String): Node = parser.parse(source)
}

/** 遍历 AST 子节点的 Kotlin 友好封装。 */
fun Node.childNodes(): List<Node> {
    val out = mutableListOf<Node>()
    var child = firstChild
    while (child != null) {
        out += child
        child = child.next
    }
    return out
}
