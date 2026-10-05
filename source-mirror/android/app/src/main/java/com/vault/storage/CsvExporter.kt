package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.getStringField
import java.io.OutputStream

/**
 * 为加密压缩包生成内部 CSV 条目。独立明文 CSV 导出入口已移除。
 */
object CsvExporter {
    private val headers = listOf(
        "type", "title", "username", "password", "url", "notes", "tags",
        "card_number", "card_expiry", "cvv", "cardholder", "bank",
        "id_type", "id_number", "full_name",
        "ssid", "wifi_password", "security_type",
        "service", "api_key", "api_secret", "base_url",
        "leak_check_revision", "leak_pwned_count", "leak_common_weak", "leak_checked_at",
    )

    fun writeTo(output: OutputStream, entries: List<Entry>, guardFormulas: Boolean = false) {
        val sb = StringBuilder()
        sb.append('\uFEFF') // BOM 便于 Excel 识别 UTF-8
        sb.append(headers.joinToString(",")).append("\r\n")
        for (e in entries) {
            val row = listOf(
                typeLabel(e.secretType),
                e.title, e.username, e.password, e.url, e.notes,
                e.tags.joinToString(";"),
                e.getStringField("card_number"),
                e.getStringField("expiry"),
                e.getStringField("cvv"),
                e.getStringField("cardholder"),
                e.getStringField("bank"),
                e.getStringField("id_type"),
                e.getStringField("id_number"),
                e.getStringField("full_name"),
                e.getStringField("ssid"),
                e.getStringField("wifi_password"),
                e.getStringField("security_type"),
                e.getStringField("service"),
                e.getStringField("api_key"),
                e.getStringField("api_secret"),
                e.getStringField("base_url"),
                e.leakCheckRevision?.toString().orEmpty(),
                e.leakPwnedCount?.toString().orEmpty(),
                e.leakCommonWeak.toString(),
                e.leakCheckedAt?.toString().orEmpty(),
            )
            sb.append(row.joinToString(",") { csvCell(it, guardFormulas) }).append("\r\n")
        }
        output.write(sb.toString().toByteArray(Charsets.UTF_8))
    }

    private fun typeLabel(t: String): String = when (t) {
        SecretType.LOGIN -> "login"
        SecretType.CARD_DOCUMENT -> "card_document"
        SecretType.WIFI -> "wifi"
        SecretType.API_KEY -> "api_key"
        SecretType.OTP -> "otp"
        SecretType.SECURE_NOTE -> "secure_note"
        SecretType.SERVER -> "server"
        SecretType.CUSTOM -> "custom"
        else -> t
    }

    /**
     * [guardFormulas] 为真时，给 `= + - @`（含 tab/CR）开头的值加前导单引号，
     * 避免条目内容在 Excel / LibreOffice 打开时被当作公式执行（CSV 公式注入，M-10）。
     * Excel 会把前导单引号识别为“文本”标记而不显示，界面观感不变；
     * [CsvImporter] 会剥掉这个前缀，保证本应用导出再导入不丢字符。
     */
    private fun csvCell(s: String, guardFormulas: Boolean): String {
        if (s.isEmpty()) return ""
        val guarded = if (guardFormulas && startsWithFormulaTrigger(s)) "'$s" else s
        val needsQuote = guarded.any { it == ',' || it == '"' || it == '\n' || it == '\r' }
        val escaped = guarded.replace("\"", "\"\"")
        return if (needsQuote) "\"$escaped\"" else escaped
    }

    private fun startsWithFormulaTrigger(s: String): Boolean =
        s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r'
}
