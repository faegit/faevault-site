package com.vault.ui

import com.vault.model.EntryModules.CARD_LONG_TERM
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation

/** 输入框文本变换/限制工具集，与桌面端 ui/dialogs.py 的 _fmt_/_restrict_ 函数语义一致。 */
object InputFilters {
    const val MIN_MASTER_PASSWORD_LENGTH = 6

    /** 截到最大长度。 */
    fun capLength(s: String, max: Int): String =
        if (s.length <= max) s else s.take(max)

    /** 只保留数字字符。 */
    fun digitsOnly(s: String, max: Int = Int.MAX_VALUE): String =
        s.filter { it.isDigit() }.take(max)

    /** 去掉所有空白字符（空格 / Tab / 换行 / 全角空格）。 */
    fun noWhitespace(s: String): String =
        s.filterNot { it.isWhitespace() }

    /**
     * 只保留可见 ASCII（0x20-0x7E）—— 主密码 / 备份口令等用。
     * 保留空格以支持长密码短语，同时防止输入法混入跨端不稳定的控制字符。
     */
    fun asciiPrintable(s: String): String =
        s.filter { it.code in 0x20..0x7E }

    /**
     * 有效期：仅保留数字，最长 4 位，输满 4 位后才插入 "/" 分隔（MM/YY）。
     * 配合 onFocusChanged 确保失焦时也格式化。
     */
    fun formatExpiryMMYY(s: String): String {
        val digits = s.filter { it.isDigit() }.take(4)
        return when {
            digits.length == 4 -> "${digits.substring(0, 2)}/${digits.substring(2)}"
            else -> digits
        }
    }

    /**
     * 银行卡号 VisualTransformation：每 4 位插入一个空格（仅显示用，不影响存储值）。
     */
    val CardNumberSpacing: VisualTransformation = VisualTransformation { text ->
        val raw = text.text.filter { it.isDigit() }
        val formatted = buildString {
            raw.forEachIndexed { i, c ->
                if (i > 0 && i % 4 == 0) append(' ')
                append(c)
            }
        }
        TransformedText(AnnotatedString(formatted), object : OffsetMapping {
            override fun originalToTransformed(offset: Int): Int {
                if (offset >= raw.length) return formatted.length
                return offset + offset / 4
            }

            override fun transformedToOriginal(offset: Int): Int {
                if (offset >= formatted.length) return raw.length
                return offset - formatted.take(offset).count { it == ' ' }
            }
        })
    }

    /** Only ASCII date digits are accepted; eight digits become ISO date text. */
    fun formatDate(s: String, allowFree: Boolean = false): String {
        if (allowFree && s in setOf(CARD_LONG_TERM.take(1), CARD_LONG_TERM)) return s
        val digits = s.filter { it in '0'..'9' }.take(8)
        return if (digits.length == 8) {
            "${digits.take(4)}-${digits.substring(4, 6)}-${digits.substring(6)}"
        } else digits
    }

    fun isValidDate(s: String, allowLongTerm: Boolean = false): Boolean =
        s.isBlank() || (allowLongTerm && s == CARD_LONG_TERM) ||
            (s.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}")) &&
                runCatching { java.time.LocalDate.parse(s).year in 1..9999 }.getOrDefault(false))
}
