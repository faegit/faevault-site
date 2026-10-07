package com.vault.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.regex.Pattern

/**
 * 硬编码中文残留兜底：扫描 UI 相关源码，凡是未经过 uiText()/localizeUiText()/uiTabText()
 * 包装的中文字面量（不含翻译表文件与注释），都不允许超出基线清单。
 *
 * 基线：src/test/resources/hardcoded_chinese_baseline.txt（file<TAB>string 一行一条）。
 * 处理存量未翻译文案时，应把它包装进翻译表（uiText/localizeUiText/uiTabText）
 * 或 Android 标准资源（stringResource/getString + values-en）并从基线中删除对应条目；
 * 若确实需要临时豁免，需同步更新基线（通常不建议）。
 */
class HardcodedChineseGuardTest {
    @Test
    fun `no new hardcoded chinese literals without translation wrapper`() {
        val baseline = loadBaseline()
        val current = scanUnwrapped()
        val added = (current - baseline)
            .sortedWith(compareBy<Pair<String, String>> { it.first }.thenBy { it.second })
        assertTrue(
            "发现 ${added.size} 处新增未翻译的中文硬编码（英文模式下仍会显示中文）。" +
                "请用 uiText()/localizeUiText() 包装并补齐英文翻译，或确认后更新基线。\n" +
                added.joinToString("\n") { "${it.first}: ${it.second}" },
            added.isEmpty(),
        )
    }

    private fun loadBaseline(): Set<Pair<String, String>> {
        val stream = checkNotNull(javaClass.getResourceAsStream("/hardcoded_chinese_baseline.txt")) {
            "缺少基线资源 hardcoded_chinese_baseline.txt"
        }
        return stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.mapNotNull { line ->
                val idx = line.indexOf('\t')
                if (idx < 0) null else line.substring(0, idx) to line.substring(idx + 1)
            }.toSet()
        }
    }

    private fun scanUnwrapped(): Set<Pair<String, String>> {
        val vaultRoot = File("src/main/java/com/vault")
        val dirs = listOf("ui", "autofill", "passkeys", "scan")
        val skipFiles = setOf(
            "UiText.kt",
            "UiCopyExtra.kt",
            "NotificationLocalizer.kt",
            "CloudSyncUiProjection.kt",
            // Matching stop words are locale-independent input data, never UI copy.
            "AutofillMatchingPolicy.kt",
        )
        val cjkPattern = Pattern.compile("\"([^\"\\n]*[\\u4e00-\\u9fff][^\"\\n]*)\"")
        val wrapper = Regex(
            "uiText\\(|localizeUiText(?:For)?\\(|uiTabText\\(|" +
                "stringResource\\(R\\.string\\.\\w+|getString\\(R\\.string\\.\\w+"
        )
        val result = linkedSetOf<Pair<String, String>>()
        for (dir in dirs) {
            val base = File(vaultRoot, dir)
            if (!base.isDirectory) continue
            base.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .forEach { file ->
                    if (file.name in skipFiles) return@forEach
                    val rel = file.relativeTo(vaultRoot).invariantSeparatorsPath
                    val lines = file.readLines()
                    var prevTail = ""
                    for (line in lines) {
                        val trimmed = line.trimStart()
                        if (trimmed.isEmpty()) continue
                        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
                            // 注释既不产出字面量，也不该打断「上一行代码」的 wrapper 上下文：
                            // 否则加一条注释就会让下一行的中文命中与否发生翻转。
                            continue
                        }
                        val matcher = cjkPattern.matcher(line)
                        while (matcher.find()) {
                            val text: String = matcher.group(1) ?: continue
                            val before = prevTail + line.substring(0, matcher.start())
                            if (wrapper.containsMatchIn(before)) continue
                            result.add(rel to text)
                        }
                        prevTail = line.takeLast(60)
                    }
                }
        }
        return result
    }
}
