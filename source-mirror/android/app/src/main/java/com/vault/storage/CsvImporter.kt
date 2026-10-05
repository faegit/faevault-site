package com.vault.storage

import android.content.Context
import android.net.Uri
import com.vault.model.Entry
import com.vault.model.OtpUtils
import com.vault.model.SecretType
import com.vault.model.newEntry
import com.vault.model.withCurrentLeakRevision
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.InputStream
import java.io.ByteArrayOutputStream

/**
 * 多格式 CSV 导入器。
 * 兼容 CsvExporter 原生格式以及来自其他密码管理器的常见 CSV 格式。
 * 自动检测分隔符（逗号 / 分号 / Tab），支持中英文列名别名。
 */
object CsvImporter {

    internal const val MAX_IMPORT_BYTES: Long = 64L * 1024L * 1024L
    private const val MAX_IMPORT_ROWS = 100_000
    private const val MAX_IMPORT_CELL_CHARS = 1_000_000

    data class ImportResult(
        val entries: List<Entry>,
        val source: String,
        val skipped: Int = 0,
    )

    /** 标准列名表：别名 → 内部键。优先精确匹配，再按前缀匹配。 */
    private val COLUMN_ALIASES = mapOf(
        "type" to listOf("type", "类型", "类别", "kind", "category", "group"),
        "title" to listOf("title", "标题", "名称", "name", "label", "site", "login name", "login_name"),
        "username" to listOf("username", "用户名", "user", "账户", "account", "email", "e-mail", "login_username"),
        "password" to listOf("password", "密码", "passwd", "pass", "master password", "master_password", "login_password"),
        "url" to listOf("url", "网址", "website", "site", "link", "address", "login_uri", "uri"),
        "notes" to listOf("notes", "备注", "note", "description", "备注说明", "comment", "备注信息", "extra"),
        "tags" to listOf("tags", "标签", "tag", "grouping", "folder", "group"),
        "otp_uri" to listOf("otpauth", "otp_auth", "otpauth_uri", "otp uri"),
        "otp_secret" to listOf("login_totp", "totp", "totp_secret", "otp secret"),
        "custom_fields" to listOf("fields", "custom_fields", "custom fields"),
        "card_number" to listOf("card_number", "cardno", "卡号", "银行卡号", "cc_number", "card number"),
        "card_expiry" to listOf("card_expiry", "expiry", "card_expire", "有效期", "exp", "exp_date", "expiry date"),
        "cvv" to listOf("cvv", "cvc", "cvn", "安全码", "card_cvv"),
        "cardholder" to listOf("cardholder", "持卡人", "card holder", "name on card"),
        "bank" to listOf("bank", "开户行", "银行", "bank name", "issuer"),
        "id_type" to listOf("id_type", "证件类型", "id type", "document type"),
        "id_number" to listOf("id_number", "证件号", "id", "身份证号", "id number", "identification number"),
        "full_name" to listOf("full_name", "姓名", "fullname", "全名"),
        "ssid" to listOf("ssid", "ssid", "network name", "网络名称"),
        "wifi_password" to listOf("wifi_password", "wifi password", "network password", "wireless key", "psk"),
        "security_type" to listOf("security_type", "security type", "加密类型", "encryption"),
        "service" to listOf("service", "服务名称", "服务", "service name", "app name"),
        "api_key" to listOf("api_key", "api key", "apikey", "token", "access key"),
        "api_secret" to listOf("api_secret", "api secret", "apisecret", "secret key"),
        "base_url" to listOf("base_url", "base url", "baseurl", "endpoint", "api url"),
        "scopes" to listOf("scopes", "scope", "permissions"),
        "secret" to listOf("secret", "key", "otp_secret", "totp_secret"),
        "algorithm" to listOf("algorithm", "algo"),
        "digits" to listOf("digits", "digit"),
        "period" to listOf("period", "period"),
        "issuer" to listOf("issuer", "发行方", "issuer", "company"),
        "label" to listOf("label", "账户名", "account name"),
        "counter" to listOf("counter", "counter", "count"),
        "leak_check_revision" to listOf("leak_check_revision"),
        "leak_pwned_count" to listOf("leak_pwned_count", "_leak_pwned_count", "_breach_count"),
        "leak_common_weak" to listOf("leak_common_weak", "_leak_common_weak"),
        "leak_checked_at" to listOf("leak_checked_at", "_leak_checked_at"),
    )

    /** 中文 / 英文类型名称 → SecretType */
    private val TYPE_ALIASES = mapOf(
        "登录" to SecretType.LOGIN, "login" to SecretType.LOGIN,
        "登录凭证" to SecretType.LOGIN, "logins" to SecretType.LOGIN,
        "密码" to SecretType.LOGIN, "credential" to SecretType.LOGIN,
        "银行卡" to SecretType.CARD_DOCUMENT, "卡类" to SecretType.CARD_DOCUMENT, "credit_card" to SecretType.CARD_DOCUMENT,
        "credit card" to SecretType.CARD_DOCUMENT, "信用卡" to SecretType.CARD_DOCUMENT,
        "card" to SecretType.CARD_DOCUMENT, "debit card" to SecretType.CARD_DOCUMENT,
        "卡证" to SecretType.CARD_DOCUMENT, "card_document" to SecretType.CARD_DOCUMENT,
        "证件" to SecretType.CARD_DOCUMENT, "id_card" to SecretType.CARD_DOCUMENT,
        "id card" to SecretType.CARD_DOCUMENT, "id" to SecretType.CARD_DOCUMENT,
        "身份证" to SecretType.CARD_DOCUMENT, "identity" to SecretType.CARD_DOCUMENT,
        "护照" to SecretType.CARD_DOCUMENT, "passport" to SecretType.CARD_DOCUMENT,
        "wifi" to SecretType.WIFI, "wi-fi" to SecretType.WIFI,
        "wireless" to SecretType.WIFI, "网络" to SecretType.WIFI,
        "密钥" to SecretType.API_KEY, "api_key" to SecretType.API_KEY,
        "api" to SecretType.API_KEY, "api key" to SecretType.API_KEY,
        "token" to SecretType.API_KEY,
        "otp" to SecretType.OTP, "totp" to SecretType.OTP,
        "hotp" to SecretType.OTP, "动态码" to SecretType.OTP,
        "2fa" to SecretType.OTP, "mfa" to SecretType.OTP,
        "one time password" to SecretType.OTP,
        "安全笔记" to SecretType.SECURE_NOTE, "secure_note" to SecretType.SECURE_NOTE,
        "secure note" to SecretType.SECURE_NOTE,
        "服务器" to SecretType.SERVER, "server" to SecretType.SERVER,
        "自定义" to SecretType.CUSTOM, "custom" to SecretType.CUSTOM,
    )

    class ParseException(msg: String) : RuntimeException(msg)

    fun read(context: Context, uri: Uri): ImportResult {
        val text = context.contentResolver.openInputStream(uri)?.use { input ->
            val bytes = input.readBounded(MAX_IMPORT_BYTES)
            try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
        } ?: throw ParseException("无法读取导入文件")

        return parse(text)
    }

    internal fun parse(text: String): ImportResult {
        val raw = text.trimStart('\uFEFF', ' ', '\t', '\r', '\n')
        return if (raw.startsWith("{")) parseBitwardenJson(raw) else {
            val entries = parseText(raw)
            ImportResult(entries, detectCsvSource(raw))
        }
    }

    internal fun parseText(text: String): List<Entry> {
        if (text.length > MAX_IMPORT_BYTES) throw ParseException("导入文件超过 64 MiB 安全上限")
        val raw = text.trimStart('\uFEFF') // strip BOM
        val delimiter = detectDelimiter(raw)
        val rows = parseCsv(raw, delimiter)
        if (rows.isEmpty()) return emptyList()
        if (rows.size > MAX_IMPORT_ROWS) throw ParseException("导入文件超过 100,000 行安全上限")
        if (rows.any { row -> row.any { it.length > MAX_IMPORT_CELL_CHARS } }) {
            throw ParseException("导入文件单元格过大")
        }

        val header = rows.first().map { it.trim().lowercase() }
        val idx = resolveColumnIndex(header)

        if (idx["type"] == null && idx["title"] == null && idx["password"] == null) {
            throw ParseException("CSV 表头不匹配，无法识别列，需要 type/title/password 之一")
        }

        return rows.drop(1)
            .filter { it.any { c -> c.isNotBlank() } }
            .map { row -> toEntry(row, idx, header) }
    }

    private fun InputStream.readBounded(limit: Long): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(32 * 1024)
        var total = 0L
        while (true) {
            val count = read(buffer)
            if (count < 0) break
            total += count
            if (total > limit) throw ParseException("导入文件超过 64 MiB 安全上限")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    /**
     * 智能列名匹配：对每个标准键，逐一测试其别名，取第一个成功匹配的。
     * 同时兼容 CsvExporter 的原始列名和常见第三方格式。
     */
    private fun resolveColumnIndex(header: List<String>): Map<String, Int> {
        val result = mutableMapOf<String, Int>()
        for ((standardKey, aliases) in COLUMN_ALIASES) {
            for (alias in aliases) {
                val idx = header.indexOfFirst { h ->
                    h == alias || h.replace(" ", "_") == alias || h.replace("_", " ") == alias
                }
                if (idx >= 0) {
                    result[standardKey] = idx
                    break
                }
            }
        }
        return result
    }

    /**
     * 自动探测分隔符：读取前几行，统计逗号 / 分号 / Tab 的列数一致性。
     * 先试逗号，再看分号，最后 Tab。
     */
    private fun detectDelimiter(text: String): Char {
        val lines = text.lines().filter { it.isNotBlank() }.take(5)
        if (lines.isEmpty()) return ','

        val candidates = listOf(',', ';', '\t')
        val scores = candidates.map { d ->
            lines.sumOf { line ->
                val cols = parseRow(line, d)
                if (cols.size >= 2) cols.size else 0
            }
        }
        val best = scores.withIndex().maxByOrNull { it.value }
        return if (best != null && best.value > 0) candidates[best.index] else ','
    }

    private fun toEntry(row: List<String>, idx: Map<String, Int>, header: List<String>): Entry {
        fun col(k: String): String = idx[k]?.let { row.getOrNull(it).orEmpty() } ?: ""

        val rawType = col("type").lowercase().trim()
        val type = TYPE_ALIASES[rawType] ?: guessTypeFromFields(row, idx)
        val otpFromUrl = OtpUtils.parseOtpAuthUri(col("url"))

        // 类型内检查：如果明确了是 OTP / WIFI / API_KEY 等，就不再从 login 兜底
        val resolvedType = when {
            type != SecretType.LOGIN -> type
            otpFromUrl != null -> SecretType.OTP
            col("secret").isNotEmpty() -> SecretType.OTP
            col("api_key").isNotEmpty() || col("service").isNotEmpty() -> SecretType.API_KEY
            col("ssid").isNotEmpty() -> SecretType.WIFI
            col("card_number").isNotEmpty() || col("card_expiry").isNotEmpty() -> SecretType.CARD_DOCUMENT
            col("id_number").isNotEmpty() || col("id_type").isNotEmpty() -> SecretType.CARD_DOCUMENT
            else -> SecretType.LOGIN
        }

        val tags = col("tags").split(';', ',', '，', ';', '|')
            .map { it.trim() }.filter { it.isNotEmpty() }

        val extraStandardKeys = setOf(
            "type", "title", "username", "password", "url", "notes", "tags",
            "otp_uri", "otp_secret", "custom_fields",
            "leak_check_revision", "leak_pwned_count", "leak_common_weak", "leak_checked_at",
        )
        val fields = mutableMapOf<String, kotlinx.serialization.json.JsonElement>()
        for ((key, _) in idx) {
            if (key in extraStandardKeys) continue
            val v = col(key)
            if (v.isNotEmpty()) {
                val mappedKey = mapColumnKey(key)
                fields[mappedKey] = JsonPrimitive(v)
            }
        }
        val recognizedIndexes = idx.values.toSet()
        header.forEachIndexed { index, rawKey ->
            val value = row.getOrNull(index).orEmpty()
            if (index !in recognizedIndexes && value.isNotBlank()) {
                fields.putIfAbsent(uniqueFieldKey(rawKey, fields), JsonPrimitive(value))
            }
        }
        col("otp_uri").takeIf(String::isNotBlank)?.let { fields["otp_uri"] = JsonPrimitive(it) }
        if (otpFromUrl != null) {
            fields.putIfAbsent("otp_uri", JsonPrimitive(col("url")))
            fields.putIfAbsent("secret", JsonPrimitive(otpFromUrl.second!!))
            fields.putIfAbsent("type", JsonPrimitive(otpFromUrl.first!!))
            for (key in listOf("issuer", "label", "algorithm", "digits", "period", "counter")) {
                otpFromUrl.third[key]?.let { fields.putIfAbsent(key, JsonPrimitive(it)) }
            }
        }
        col("otp_secret").takeIf(String::isNotBlank)?.let { fields["otp_secret"] = JsonPrimitive(it) }
        val customFields = col("custom_fields").trim()
        val parsedCustomFields = runCatching { Json.parseToJsonElement(customFields) as? JsonObject }.getOrNull()
        if (parsedCustomFields != null) {
            parsedCustomFields.forEach { (key, value) -> fields.putIfAbsent(key, value) }
        } else if (customFields.isNotEmpty()) {
            fields["imported_custom_fields"] = JsonPrimitive(customFields)
        }

        // 如果 type 列在 idx 中但无值，不覆盖自动检测结果
        val entryType = if (rawType.isNotEmpty() && rawType in TYPE_ALIASES) TYPE_ALIASES[rawType]!! else resolvedType

        val baseNotes = col("notes")
        val notes = if (customFields.isEmpty() || parsedCustomFields != null || baseNotes.contains(customFields)) baseNotes else {
            listOf(baseNotes, "导入的其他字段：\n$customFields").filter(String::isNotBlank).joinToString("\n\n")
        }
        val imported = newEntry(entryType).copy(
            title = col("title").ifBlank { titleFromUrl(col("url")) },
            username = col("username"),
            password = col("password"),
            url = col("url"),
            notes = notes,
            tags = tags,
            fields = fields,
            leakCheckRevision = parseDouble(col("leak_check_revision")),
            leakPwnedCount = parseInt(col("leak_pwned_count")),
            leakCommonWeak = parseBool(col("leak_common_weak")),
            leakCheckedAt = parseDouble(col("leak_checked_at")),
        )
        return if (imported.leakPwnedCount != null || imported.leakCommonWeak) {
            imported.withCurrentLeakRevision()
        } else {
            imported
        }
    }

    /** 根据存在的字段推断类型（CSV 无 type 列时使用）。 */
    private fun guessTypeFromFields(row: List<String>, idx: Map<String, Int>): String {
        fun has(k: String) = idx.containsKey(k) && row.getOrNull(idx[k]!!).orEmpty().isNotEmpty()
        return when {
            has("secret") || has("totp_secret") -> SecretType.OTP
            has("api_key") -> SecretType.API_KEY
            has("ssid") -> SecretType.WIFI
            has("card_number") || has("card_expiry") -> SecretType.CARD_DOCUMENT
            has("id_number") || has("full_name") -> SecretType.CARD_DOCUMENT
            else -> SecretType.LOGIN
        }
    }

    /** 兼容历史列名：CsvExporter 把 expiry 写到 card_expiry 列 */
    private fun mapColumnKey(key: String): String = when (key) {
        "card_expiry" -> "expiry"
        else -> key
    }

    private fun parseInt(value: String): Int? = value.trim().takeIf { it.isNotEmpty() }?.toIntOrNull()

    private fun parseDouble(value: String): Double? = value.trim().takeIf { it.isNotEmpty() }?.toDoubleOrNull()

    private fun parseBool(value: String): Boolean {
        return when (value.trim().lowercase()) {
            "true", "1", "yes", "y", "是" -> true
            else -> false
        }
    }

    private fun detectCsvSource(text: String): String {
        val header = parseRow(text.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty(), detectDelimiter(text))
            .map { it.trim().lowercase() }.toSet()
        return when {
            setOf("folder", "favorite", "login_uri", "login_username", "login_password").all(header::contains) -> "Bitwarden CSV"
            setOf("url", "username", "password", "extra", "name", "grouping", "fav").all(header::contains) -> "LastPass CSV"
            "otpauth" in header && "archived" in header -> "1Password CSV"
            "group" in header && "title" in header -> "KeePass CSV"
            "httprealm" in header || "formactionorigin" in header -> "Firefox CSV"
            setOf("name", "url", "username", "password").all(header::contains) -> "Chromium CSV"
            else -> "Vault CSV"
        }
    }

    private fun parseBitwardenJson(text: String): ImportResult {
        val root = runCatching { Json.parseToJsonElement(text).jsonObject }
            .getOrElse { throw ParseException("JSON 文件格式无效：${it.message}") }
        if (root["encrypted"]?.jsonPrimitive?.contentOrNull.equals("true", ignoreCase = true)) {
            throw ParseException("暂不支持 Bitwarden 加密 JSON，请导出未加密 JSON")
        }
        val folders = (root["folders"] as? JsonArray).orEmpty().mapNotNull { element ->
            val obj = element as? JsonObject ?: return@mapNotNull null
            val id = obj.string("id")
            val name = obj.string("name")
            if (id.isBlank() || name.isBlank()) null else id to name
        }.toMap()
        var skipped = 0
        val entries = (root["items"] as? JsonArray).orEmpty().mapNotNull { element ->
            val item = element as? JsonObject
            if (item == null) { skipped++; return@mapNotNull null }
            runCatching { bitwardenItem(item, folders) }.getOrElse { skipped++; null }
        }
        if (entries.isEmpty() && skipped == 0) throw ParseException("Bitwarden JSON 中未找到条目")
        return ImportResult(entries, "Bitwarden JSON", skipped)
    }

    private fun bitwardenItem(item: JsonObject, folders: Map<String, String>): Entry {
        val kind = item["type"]?.jsonPrimitive?.intOrNull ?: 1
        val login = item["login"] as? JsonObject
        val card = item["card"] as? JsonObject
        val identity = item["identity"] as? JsonObject
        val secureType = when (kind) {
            2 -> SecretType.SECURE_NOTE
            3 -> SecretType.CARD_DOCUMENT
            4 -> SecretType.CARD_DOCUMENT
            else -> SecretType.LOGIN
        }
        val fields = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        login?.string("totp")?.takeIf(String::isNotBlank)?.let { fields["otp_secret"] = JsonPrimitive(it) }
        card?.forEach { (key, value) -> value.jsonPrimitive.contentOrNull?.takeIf(String::isNotBlank)?.let { fields[mapBitwardenCardKey(key)] = JsonPrimitive(it) } }
        identity?.forEach { (key, value) -> value.jsonPrimitive.contentOrNull?.takeIf(String::isNotBlank)?.let { fields[key] = JsonPrimitive(it) } }
        val customLines = mutableListOf<String>()
        (item["fields"] as? JsonArray).orEmpty().forEachIndexed { index, element ->
            val custom = element as? JsonObject ?: return@forEachIndexed
            val name = custom.string("name").ifBlank { "custom_${index + 1}" }
            val value = custom.string("value")
            if (value.isNotBlank()) {
                fields[uniqueFieldKey(name, fields)] = JsonPrimitive(value)
                customLines += "$name: $value"
            }
        }
        val notes = listOf(item.string("notes"), customLines.joinToString("\n"))
            .filter(String::isNotBlank).joinToString("\n\n")
        val uri = ((login?.get("uris") as? JsonArray)?.firstOrNull() as? JsonObject)?.string("uri").orEmpty()
        val tags = folders[item.string("folderId")]?.let(::listOf).orEmpty()
        return newEntry(secureType).copy(
            title = item.string("name").ifBlank { titleFromUrl(uri) },
            username = login?.string("username").orEmpty(),
            password = login?.string("password").orEmpty(),
            url = uri,
            notes = notes,
            tags = tags,
            fields = fields,
        )
    }

    private fun JsonObject.string(key: String): String = this[key]?.jsonPrimitive?.contentOrNull.orEmpty()

    private fun mapBitwardenCardKey(key: String): String = when (key) {
        "number" -> "card_number"
        "cardholderName" -> "cardholder"
        "expMonth" -> "expiry_month"
        "expYear" -> "expiry_year"
        "code" -> "cvv"
        else -> key
    }

    private fun uniqueFieldKey(name: String, fields: Map<String, *>): String {
        val base = name.trim().lowercase().replace(Regex("[^a-z0-9_\\u4e00-\\u9fff]+"), "_").trim('_').ifBlank { "custom" }
        var key = base
        var suffix = 2
        while (key in fields) key = "${base}_${suffix++}"
        return key
    }

    private fun titleFromUrl(url: String): String = runCatching {
        java.net.URI(url).host?.removePrefix("www.").orEmpty()
    }.getOrDefault("").ifBlank { url.substringAfter("://", url).substringBefore('/').substringBefore(':') }

    /**
     * CSV 解析：支持引号包裹、内部转义、以及自动选择的分隔符。
     * 比严格 RFC 宽松一些以兼容不规范的第三方导出。
     */
    /**
     * 反解 [CsvExporter] 的公式注入防护：导出时给 `= + - @` 开头的值加了前导单引号（M-10），
     * 这里剥掉，否则本应用导出的文件再导入会凭空多出一个引号。
     */
    private fun stripFormulaGuard(value: String): String =
        if (value.length >= 2 && value[0] == '\'' && value[1] in "=+-@\t\r") value.substring(1) else value

    private fun parseCsv(text: String, delimiter: Char): List<List<String>> {
        val rows = mutableListOf<List<String>>()
        val row = mutableListOf<String>()
        val cell = StringBuilder()
        var inQuotes = false
        var i = 0
        fun finishCell() { row += stripFormulaGuard(cell.toString()); cell.clear() }
        fun finishRow() {
            finishCell()
            if (row.any(String::isNotBlank) || rows.isNotEmpty()) rows += row.toList()
            row.clear()
        }
        while (i < text.length) {
            val c = text[i]
            when {
                inQuotes && c == '"' && i + 1 < text.length && text[i + 1] == '"' -> { cell.append('"'); i++ }
                c == '"' -> inQuotes = !inQuotes
                !inQuotes && c == delimiter -> finishCell()
                !inQuotes && (c == '\n' || c == '\r') -> {
                    if (c == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++
                    finishRow()
                }
                else -> cell.append(c)
            }
            i++
        }
        if (cell.isNotEmpty() || row.isNotEmpty()) finishRow()
        if (inQuotes) throw ParseException("CSV 中存在未闭合的引号")
        return rows
    }

    private fun parseRow(line: String, delimiter: Char): List<String> {
        val cols = mutableListOf<String>()
        val cell = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                inQuotes -> {
                    if (c == '"') {
                        if (i + 1 < line.length && line[i + 1] == '"') {
                            cell.append('"'); i++
                        } else {
                            inQuotes = false
                        }
                    } else {
                        cell.append(c)
                    }
                }
                c == '"' -> inQuotes = true
                c == delimiter -> { cols.add(cell.toString()); cell.clear() }
                else -> cell.append(c)
            }
            i++
        }
        cols.add(cell.toString())
        return cols
    }
}
