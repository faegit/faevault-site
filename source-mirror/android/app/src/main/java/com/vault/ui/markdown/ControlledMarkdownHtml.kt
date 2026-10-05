package com.vault.ui.markdown

internal data class ControlledHtmlDocument(
    val markdown: String,
    val details: Map<String, ControlledDetailsBlock>,
)

internal data class ControlledDetailsBlock(
    val summary: String,
    val body: String,
)

internal object ControlledMarkdownHtml {
    const val MARKER_OPEN = '\uE000'
    const val MARKER_CLOSE = '\uE001'

    private const val ESCAPED_LT = "\uE010VAULT_ESCAPED_LT\uE011"
    private const val FENCE_PREFIX = "\uE020VAULT_FENCE_"
    private const val FENCE_SUFFIX = "_VAULT_FENCE\uE021"
    private val detailsRegex = Regex(
        "<details\\s*>(.*?)</details\\s*>",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val summaryRegex = Regex(
        "<summary\\s*>(.*?)</summary\\s*>",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val anyTagRegex = Regex("</?[A-Za-z][^>]*>")

    fun normalize(source: String): ControlledHtmlDocument {
        val protected = source.replace("\\<", ESCAPED_LT)
        // 代码围栏整体保护：标签剥离/受控 HTML 转换只应作用于围栏外文本，
        // 否则 ```xml 等块内的 <tag> 会被 anyTagRegex 删除，导致显示与复制均为空白。
        val fences = mutableListOf<String>()
        val details = linkedMapOf<String, ControlledDetailsBlock>()
        val withoutDetails = detailsRegex.replace(protectFences(protected, fences)) { match ->
            val content = match.groupValues[1]
            val summaryMatch = summaryRegex.find(content)
            val summary = summaryMatch?.groupValues?.get(1)
                ?.let(::normalizeInline)
                ?.let(::plainText)
                ?.trim()
                .orEmpty()
                .ifBlank { "Details" }
            val body = summaryMatch?.let { content.removeRange(it.range) } ?: content
            val id = "details-${details.size}"
            details[id] = ControlledDetailsBlock(summary, restoreEscaped(body.trim()))
            "\n```vault-details\n$id\n```\n"
        }
        return ControlledHtmlDocument(
            markdown = restoreEscaped(restoreFences(normalizeInline(withoutDetails), fences)),
            details = details,
        )
    }

    /** 将围栏（``` / ~~~）逐行替换为占位符并原样存入 [fences]；未闭合围栏保护到文末。 */
    private fun protectFences(source: String, fences: MutableList<String>): String {
        if (!source.contains("```") && !source.contains("~~~")) return source
        val out = StringBuilder(source.length)
        var openMarker: String? = null
        source.split("\n").forEachIndexed { index, line ->
            if (index > 0) out.append('\n')
            val trimmed = line.trimStart(' ', '\t')
            val marker = openMarker
            if (marker == null) {
                val open = Regex("^(`{3,}|~{3,})").find(trimmed)
                if (open != null) {
                    openMarker = open.groupValues[1]
                    fences += line
                    out.append(FENCE_PREFIX).append(fences.size - 1).append(FENCE_SUFFIX)
                } else {
                    out.append(line)
                }
            } else {
                val rest = trimmed.drop(marker.length)
                val isClose = trimmed.startsWith(marker) &&
                    (rest.isBlank() || rest.all { it == marker[0] })
                fences += line
                if (isClose) openMarker = null
                out.append(FENCE_PREFIX).append(fences.size - 1).append(FENCE_SUFFIX)
            }
        }
        return out.toString()
    }

    private fun restoreFences(source: String, fences: List<String>): String =
        Regex(Regex.escape(FENCE_PREFIX) + "(\\d+)" + Regex.escape(FENCE_SUFFIX))
            .replace(source) { match -> fences[match.groupValues[1].toInt()] }

    private fun normalizeInline(source: String): String {
        var result = source
        result = replacePair(result, listOf("strong", "b"), "**")
        result = replacePair(result, listOf("em", "i"), "*")
        result = replacePair(result, listOf("del", "s"), "~~")
        result = replacePair(result, listOf("u"), "++")
        for (tag in listOf("mark", "sub", "sup", "kbd")) {
            val name = tag.uppercase()
            val regex = Regex(
                "<$tag\\s*>(.*?)</$tag\\s*>",
                setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
            )
            result = regex.replace(result) {
                "$MARKER_OPEN$name$MARKER_CLOSE${it.groupValues[1]}$MARKER_OPEN/$name$MARKER_CLOSE"
            }
        }
        result = result.replace(Regex("<br\\s*/?\\s*>", RegexOption.IGNORE_CASE), "\n")
        return result.replace(anyTagRegex, "")
    }

    private fun replacePair(source: String, tags: List<String>, marker: String): String {
        var result = source
        tags.forEach { tag ->
            result = Regex(
                "<$tag\\s*>(.*?)</$tag\\s*>",
                setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
            ).replace(result) { "$marker${it.groupValues[1]}$marker" }
        }
        return result
    }

    private fun plainText(source: String): String = source
        .replace(Regex("[\uE000\uE001]"), "")
        .replace(Regex("/?(?:MARK|SUB|SUP|KBD)"), "")
        .replace(Regex("[*+~`]"), "")
        .replace(anyTagRegex, "")

    private fun restoreEscaped(source: String): String = source.replace(ESCAPED_LT, "\\<")
}
