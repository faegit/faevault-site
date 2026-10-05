package com.vault.model

import android.os.Build
import androidx.annotation.RequiresApi

/**
 * 中文 → 拼音转换。基于 Android API 29+ 内置的 ICU Transliterator，
 *  - "Han-Latin"：汉字转带声调拉丁拼音（如 "你好" → "nǐ hǎo"）
 *  - "Latin-ASCII"：剥离变音符号（"nǐ hǎo" → "ni hao"）
 *  - "Lower"：统一小写
 *
 * 用途：
 *  - [sortKey]：作为 sortedBy 的键，让中文 + 拉丁字符按拼音序混排
 *  - [firstLetter]：侧边字母索引基于条目的第一个字符：数字/符号开头归入 '#'，
 *    中文取拼音首字母、英文取自身字母
 *
 * API 29 以下回退到逐字符降级：不做拼音转换，仅对 ASCII 字母做排序键。
 */
object Pinyin {
    /** 惰性缓存（Any 占位，避免在 API<29 的设备上解析 ICU 类）。 */
    private var cachedHan2Ascii: Any? = null

    @get:RequiresApi(29)
    private val han2Ascii: android.icu.text.Transliterator
        get() {
            cachedHan2Ascii?.let { return it as android.icu.text.Transliterator }
            val t = android.icu.text.Transliterator.getInstance("Han-Latin; Latin-ASCII; Lower")
            cachedHan2Ascii = t
            return t
        }

    /** 用于排序：把整个字符串映射成可比较的 ASCII 拼音串（含空格分隔的汉字音节）。 */
    fun sortKey(s: String): String {
        if (Build.VERSION.SDK_INT >= 29) return han2Ascii.transliterate(s)
        return s.lowercase()
    }

    /**
     * 侧边索引用：基于条目的第一个字符。
     * 数字/符号开头 → '#'；中文取拼音首字母（"苹果" → 'P'）；英文取自身（"amazon" → 'A'）。
     */
    fun firstLetter(s: String): Char {
        val trimmed = s.trimStart()
        if (trimmed.isEmpty()) return '#'
        val first = trimmed.first()
        if (first.isDigit() || !first.isLetter()) return '#'
        val raw = if (Build.VERSION.SDK_INT >= 29) {
            han2Ascii.transliterate(trimmed)
        } else {
            trimmed.lowercase()
        }
        val ch = raw.firstOrNull { it in 'a'..'z' } ?: return '#'
        return ch.uppercaseChar()
    }
}
