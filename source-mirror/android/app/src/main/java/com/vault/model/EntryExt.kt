package com.vault.model

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.contentOrNull
import java.time.LocalDate
import java.time.YearMonth
import java.util.UUID

/** Entry 业务扩展——与桌面端 core/models.py 的方法语义对齐。 */

fun Entry.getStringField(key: String, default: String = ""): String {
    val v = fields[key] ?: return default
    return (v as? JsonPrimitive)?.contentOrNull ?: default
}

/** 统一读取新版动态码模块与旧版顶层字段。 */
fun Entry.getOtpField(key: String, default: String = ""): String {
    val moduleValue = entryModules()
        .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.OTP }
        ?.get("value") as? JsonObject
    return EntryModules.primitive(moduleValue?.get(key))
        .ifEmpty { getStringField(key, default) }
}

/** 是否携带可用的动态码（模块或旧版顶层字段）。只探测密钥存在，不计算码值。 */
fun Entry.hasOtp(): Boolean = getOtpField("secret").ifEmpty { getStringField("otp_secret") }.isNotBlank()

/** 登录条目内绑定独立动态码条目的字段键（值 = 独立 OTP 条目 id）。 */
const val OTP_BINDING_KEY = "bound_otp_id"

/** 登录条目绑定的独立动态码条目 id；未绑定返回 null。 */
fun Entry.otpBindingId(): String? = getStringField(OTP_BINDING_KEY).takeIf(String::isNotBlank)

fun Entry.withOtpBinding(otpId: String): Entry = copy(fields = fields + (OTP_BINDING_KEY to JsonPrimitive(otpId)))

fun Entry.withoutOtpBinding(): Entry = copy(fields = fields - OTP_BINDING_KEY)

/** 是否为 HOTP（每次使用后需推进计数器）。 */
fun Entry.otpIsHotp(): Boolean = getOtpField("type", "totp").lowercase() == "hotp"

/** 填充一次后推进 HOTP 计数器（模块值优先，旧版顶层字段兜底）。 */
fun Entry.withIncrementedOtpCounter(): Entry {
    return withIncrementedOtpCounter(moduleId = null)
}

/** 推进指定 OTP 模块；moduleId 为空时保持旧版“第一个模块/顶层字段”语义。 */
fun Entry.withIncrementedOtpCounter(moduleId: String?): Entry {
    val modules = entryModules()
    val index = modules.indexOfFirst {
        EntryModules.primitive(it["type"]) == ModuleType.OTP &&
            (moduleId == null || EntryModules.primitive(it["id"]) == moduleId)
    }
    if (index >= 0) {
        val value = (modules[index]["value"] as? JsonObject) ?: JsonObject(emptyMap())
        val counter = EntryModules.primitive(value["counter"]).toLongOrNull() ?: 0L
        val updated = modules.toMutableList()
        updated[index] = JsonObject(updated[index].toMutableMap().also { module ->
            module["value"] = JsonObject(value.toMutableMap().also { it["counter"] = JsonPrimitive(counter + 1) })
        })
        return withEntryModules(updated)
    }
    if (moduleId != null) return this
    val counter = getStringField("counter").toLongOrNull() ?: 0L
    return copy(fields = fields + ("counter" to JsonPrimitive(counter + 1)))
}

/** 独立动态码条目可额外配置的关联域名键（逗号分隔，用于 issuer 无法覆盖域名的场景）。 */
const val OTP_DOMAINS_KEY = "otp_domains"

/** 解析条目配置的关联域名列表（兼容动态码模块 value、顶层 JsonArray 与旧版逗号分隔字符串）。 */
fun Entry.otpDomains(): List<String> {
    val text = when (val raw = fields[OTP_DOMAINS_KEY]) {
        is JsonArray -> raw.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.joinToString(",")
        else -> getOtpField(OTP_DOMAINS_KEY)
    }
    return text.split(",", ";", "，", "；", "\n")
        .map { it.trim().removePrefix("https://").removePrefix("http://").trimEnd('/') }
        .filter { it.isNotEmpty() }
}

data class OtpDisplaySnapshot(
    val code: String,
    val issuer: String,
    val label: String,
    val algorithm: String,
    val digits: Int,
    val period: Int,
    val type: String,
    val counter: Long,
    val remaining: Int,
    val progress: Float,
)

/**
 * 从完整条目生成仅用于界面展示的动态码快照。
 * 返回值不包含动态码密钥，适合交给使用脱敏条目的列表界面。
 */
fun Entry.otpDisplaySnapshot(epochSeconds: Long = System.currentTimeMillis() / 1000): OtpDisplaySnapshot? {
    val secret = getOtpField("secret").ifEmpty { getStringField("otp_secret") }
    if (secret.isBlank()) return null

    val algorithm = getOtpField("algorithm", "SHA1").uppercase().let {
        if (it in setOf("SHA1", "SHA256", "SHA512")) it else "SHA1"
    }
    val digits = getOtpField("digits", "6").toIntOrNull()?.takeIf { it in 6..8 } ?: 6
    val period = getOtpField("period", "30").toIntOrNull()?.takeIf { it in 1..300 } ?: 30
    val type = getOtpField("type", "totp").lowercase().let { if (it == "hotp") "hotp" else "totp" }
    val counter = getOtpField("counter", "0").toLongOrNull()?.coerceAtLeast(0) ?: 0L
    val timeStep = if (type == "totp") epochSeconds / period else counter
    val hmacAlgorithm = when (algorithm) {
        "SHA256" -> "HmacSHA256"
        "SHA512" -> "HmacSHA512"
        else -> "HmacSHA1"
    }
    val elapsed = if (type == "totp") (epochSeconds % period).toInt() else 0
    return OtpDisplaySnapshot(
        code = OtpUtils.generateHOTP(secret, timeStep, digits, hmacAlgorithm),
        issuer = getOtpField("issuer"),
        label = getOtpField("label"),
        algorithm = algorithm,
        digits = digits,
        period = period,
        type = type,
        counter = counter,
        remaining = if (type == "totp") period - elapsed else 0,
        progress = if (type == "totp") (period - elapsed).toFloat() / period else 0f,
    )
}

// ── 泄露检测 — 对齐桌面端 spec §5/§6/§9/§11 ──────────────────────

/** 泄露缓存旧字段键名（从 fields 迁移到顶层前的旧 key）。 */
private val LEGACY_LEAK_KEYS = setOf(
    "leak_check_revision", "leak_pwned_count", "leak_common_weak", "leak_checked_at",
    "_leak_check_revision", "_leak_pwned_count", "_leak_common_weak", "_leak_checked_at",
    "_breach_count", "_leak_checked_at",
)

/** 从 fields 迁移泄露缓存到顶层（老数据兼容）。 */
fun Entry.migrateLeakFields(): Entry {
    var e = this
    var dirty = false
    for (oldKey in LEGACY_LEAK_KEYS) {
        val v = fields[oldKey]?.let { (it as? JsonPrimitive)?.contentOrNull }
        if (v.isNullOrEmpty()) continue
        when {
            oldKey.endsWith("leak_check_revision") || oldKey.endsWith("_leak_check_revision") -> {
                val d = v.toDoubleOrNull(); if (d != null && e.leakCheckRevision == null) { e = e.copy(leakCheckRevision = d); dirty = true }
            }
            oldKey.endsWith("leak_pwned_count") || oldKey.endsWith("_leak_pwned_count") || oldKey.endsWith("_breach_count") -> {
                val i = v.toIntOrNull(); if (i != null && e.leakPwnedCount == null) { e = e.copy(leakPwnedCount = i); dirty = true }
            }
            oldKey.endsWith("leak_common_weak") || oldKey.endsWith("_leak_common_weak") -> {
                val b = v.toBooleanStrictOrNull(); if (b != null && !e.leakCommonWeak) { e = e.copy(leakCommonWeak = b); dirty = true }
            }
            oldKey.endsWith("leak_checked_at") || oldKey.endsWith("_leak_checked_at") -> {
                val d = v.toDoubleOrNull(); if (d != null && e.leakCheckedAt == null) { e = e.copy(leakCheckedAt = d); dirty = true }
            }
        }
    }
    if (dirty) {
        // 清除旧的 fields 泄露键，避免冗余
        val remaining = fields - LEGACY_LEAK_KEYS
        e = e.copy(fields = remaining)
    }
    return e
}

/** 根据条目类型获取待检测的密码明文（无密码时返回空串）。 */
fun Entry.entrySecret(): String = when (secretType) {
    SecretType.LOGIN -> password
    SecretType.WIFI -> getStringField("wifi_password")
    SecretType.API_KEY -> getStringField("api_key")
    else -> ""
}

/** §6.1 缓存是否属于当前版本：revision 存在且等于 updatedAt，且 pwnedCount 已写入。 */
fun Entry.hasCurrentLeakCache(): Boolean {
    val r = leakCheckRevision ?: return false
    if (leakPwnedCount == null) return false
    return r == updatedAt
}

/** §9 泄露状态判定：优先走缓存，缓存不存在时退化为本地字典。 */
fun Entry.isEntryLeaked(context: android.content.Context): Boolean {
    if (hasCurrentLeakCache()) {
        return leakCommonWeak || (leakPwnedCount ?: 0) > 0
    }
    val secret = entrySecret()
    if (secret.isEmpty()) return false
    return com.vault.security.LeakedPasswordCheck.isLeaked(context, secret)
}

/** 是否需要执行泄露检测。force=true 用于手动检测或保存后的单条复查。 */
fun Entry.needsLeakCheck(recheckDays: Int, force: Boolean = false, now: Double = nowSeconds()): Boolean {
    val secret = entrySecret()
    if (secret.isEmpty()) return false
    if (force) return true
    val days = recheckDays.coerceIn(0, 30)
    if (days == 0) return false
    if (!hasCurrentLeakCache()) return true
    val checkedAt = leakCheckedAt ?: return true
    return now - checkedAt >= days * 86400.0
}

/** 兼容旧调用名。 */
fun Entry.needsOnlineCheck(recheckDays: Int): Boolean = needsLeakCheck(recheckDays)

/** §8 检测结果，写回前需校验 revision 匹配。 */
data class LeakCheckResult(
    val entryId: String,
    val revision: Double,
    val commonWeak: Boolean,
    val pwnedCount: Int,
    val checkedAt: Double,
)

fun Entry.applyLeakResult(result: LeakCheckResult): Entry =
    copy(
        leakCheckRevision = result.revision,
        leakPwnedCount = result.pwnedCount,
        leakCommonWeak = result.commonWeak,
        leakCheckedAt = result.checkedAt,
    )

fun Entry.withLeakCheckResult(
    commonWeak: Boolean,
    pwnedCount: Int,
    checkedAt: Double,
): Entry = applyLeakResult(
    LeakCheckResult(
        entryId = id,
        revision = updatedAt,
        commonWeak = commonWeak,
        pwnedCount = pwnedCount.coerceAtLeast(0),
        checkedAt = checkedAt,
    )
)

fun Entry.withCurrentLeakRevision(checkedAt: Double = nowSeconds()): Entry {
    if (leakPwnedCount == null && !leakCommonWeak) return withoutLeakCache()
    return copy(
        leakCheckRevision = updatedAt,
        leakPwnedCount = leakPwnedCount ?: 0,
        leakCheckedAt = leakCheckedAt ?: checkedAt,
    )
}

/** 清除所有泄露检测缓存（条目内容变化时触发重新检测）。 */
fun Entry.withoutLeakCache(): Entry =
    copy(leakCheckRevision = null, leakPwnedCount = null, leakCommonWeak = false, leakCheckedAt = null)

val Entry.displaySecret: String
    get() = displaySummary.ifEmpty { computedDisplaySecret }

private val Entry.computedDisplaySecret: String
    get() = when (secretType) {
        SecretType.LOGIN -> username
        SecretType.CARD_DOCUMENT -> {
            val last4 = getStringField("card_number_last4").ifEmpty {
                getStringField("card_number").filter(Char::isDigit).takeLast(4)
            }
            if (last4.isNotEmpty()) "**** $last4"
            else getStringField("cardholder").ifEmpty { getStringField("full_name") }.ifEmpty {
                getStringField("id_number").takeLast(4).takeIf { it.isNotEmpty() }?.let { "**** $it" }.orEmpty()
            }
        }
        SecretType.WIFI -> getStringField("ssid")
        SecretType.API_KEY -> getStringField("service").ifEmpty { username }
        SecretType.OTP -> getOtpField("label").ifEmpty { getOtpField("issuer") }.ifEmpty { username }
        SecretType.SECURE_NOTE -> ""
        SecretType.SERVER -> {
            val host = getStringField("server_host")
            val user = getStringField("server_user")
            if (host.isNotEmpty()) host
            else if (user.isNotEmpty()) user
            else entryModules()
                .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.SERVER_CONNECTION }
                ?.get("value")?.let { it as? kotlinx.serialization.json.JsonObject }
                ?.let { EntryModules.primitive(it["host"]).ifEmpty { EntryModules.primitive(it["username"]) } }
                .orEmpty()
        }
        SecretType.CUSTOM -> "${entryModules().size} 个模块"
        SecretType.PASSKEY -> username.ifEmpty { url }
        else -> username
    }

fun Entry.matches(query: String): Boolean {
    if (query.isEmpty()) return true
    val q = query.lowercase()
    val hs = searchHaystack
    return q in hs
}

/** 去重身份必须包含类型；同站点同账号的密码与 Passkey 是两种独立认证方式。 */
fun Entry.dedupKey(): Triple<String, String, String> = Triple(
    secretType,
    title.trim().lowercase(),
    username.trim().lowercase(),
)

fun Entry.sameContent(other: Entry): Boolean =
    secretType == other.secretType &&
        password == other.password &&
        url == other.url &&
        targetApp == other.targetApp &&
        notes == other.notes &&
        sortedTags == other.sortedTags &&
        fields == other.fields

fun Entry.contentEquals(other: Entry): Boolean =
    title == other.title && username == other.username && sameContent(other)

fun Entry.sameExceptPassword(other: Entry): Boolean =
    secretType == other.secretType && url == other.url && notes == other.notes && fields == other.fields

/** 加载时规范化：未知 secret_type → login；缺 id 补 uuid；迁移泄露缓存。 */
fun Entry.normalized(now: Double): Entry {
    // 旧版本把 Credential Manager 创建的 Passkey 错存成 login。即使模块已损坏也要
    // 归入只读 Passkey 类别，避免它重新暴露成可编辑的普通登录条目。
    val hasPasskey = entryModules().any {
        EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
    }
    val type = when {
        secretType == SecretType.LOGIN && hasPasskey -> SecretType.PASSKEY
        secretType in SecretType.ALL -> secretType
        else -> SecretType.LOGIN
    }
    // 标签对所有类型开放，包括 Passkey：条目本身仍不可编辑（密钥材料只由
    // Credential Manager 写），但标签是纯元数据，用户需要在混合类目里筛选与
    // 批量整理它们。此前在这里清空 tags，是沿用「非 login 一律清空」的旧规则，
    // 其余类型放开后 Passkey 成了唯一残留项。
    val idFixed = id.ifEmpty { UUID.randomUUID().toString().replace("-", "") }
    val ct = if (createdAt == 0.0) now else createdAt
    val ut = if (updatedAt == 0.0) now else updatedAt
    val base = copy(secretType = type, id = idFixed, createdAt = ct, updatedAt = ut)
    return base.migrateLeakFields()
}

fun Entry.touch(now: Double = nowSeconds()): Entry = copy(updatedAt = monotonicTimestamp(updatedAt, now))

/** Local writes must never move an imported LWW timestamp backwards when device clocks differ. */
fun monotonicTimestamp(previous: Double, now: Double = nowSeconds()): Double =
    maxOf(now, previous + 0.001)

fun nowSeconds(): Double = System.currentTimeMillis() / 1000.0

fun newEntry(secretType: String = SecretType.LOGIN): Entry {
    val t = nowSeconds()
    return Entry(
        id = UUID.randomUUID().toString(),
        createdAt = t,
        updatedAt = t,
        secretType = secretType,
    )
}

// --- Expiry ---
// 之前实现用 runCatching{ LocalDate.parse(...) } 当作格式探测，每条带到期的银行卡触发 5+ 次
// DateTimeParseException，真机上单条耗时 5-25ms。LazyColumn 在滚动时回收/复用 EntryCard 会重复
// 执行该计算，最终把列表帧率拖到 ~20fps。
//
// 新实现：用正则按形状分派，命中之后再做一次确定的解析；任何不匹配都立即返回 null，零异常路径。

// 顶层预编译：Regex 构造本身也不便宜，不要放在函数体内
private val ISO_DATE = Regex("^(\\d{4})[-/.](\\d{1,2})[-/.](\\d{1,2})$")
private val COMPACT_DATE = Regex("^(\\d{4})(\\d{2})(\\d{2})$")             // yyyyMMdd
private val ISO_YEAR_MONTH = Regex("^(\\d{4})[-/](\\d{1,2})$")             // yyyy-MM / yyyy/MM
private val MONTH_YEAR_LONG = Regex("^(\\d{1,2})/(\\d{4})$")               // MM/yyyy
private val MONTH_YEAR_SHORT = Regex("^(\\d{1,2})/(\\d{2})$")              // MM/YY 卡面格式
private val MONTH_YEAR_DIGITS = Regex("^(\\d{2})(\\d{2})$")                // MMYY 纯数字

fun Entry.getExpiryDate(): LocalDate? {
    val moduleExpiry = entryModules().asSequence().mapNotNull { module ->
        val type = EntryModules.primitive(module["type"])
        if (type != ModuleType.CARD_DOCUMENT) return@mapNotNull null
        val value = module["value"] as? JsonObject ?: return@mapNotNull null
        EntryModules.primitive(value["expiry_date"])
            .ifEmpty { EntryModules.primitive(value["expiry"]) }
            .takeIf(String::isNotBlank)
    }.firstOrNull().orEmpty()
    val s = expirySummary.ifEmpty {
        getStringField("expiry_date").ifEmpty { getStringField("expiry") }.ifEmpty { moduleExpiry }
    }.trim()
    if (s.isEmpty()) return null

    // 1) yyyy-?MM-?dd 形态
    ISO_DATE.matchEntire(s)?.let { m ->
        return safeDate(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt())
    }
    COMPACT_DATE.matchEntire(s)?.let { m ->
        return safeDate(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt())
    }

    // 2) yyyy-MM / yyyy/MM 形态 → 取月末
    ISO_YEAR_MONTH.matchEntire(s)?.let { m ->
        return safeEndOfMonth(m.groupValues[1].toInt(), m.groupValues[2].toInt())
    }

    // 3) MM/yyyy
    MONTH_YEAR_LONG.matchEntire(s)?.let { m ->
        return safeEndOfMonth(m.groupValues[2].toInt(), m.groupValues[1].toInt())
    }

    // 4) MM/YY 卡面格式：补齐世纪到"当前世纪附近"
    MONTH_YEAR_SHORT.matchEntire(s)?.let { m ->
        val month = m.groupValues[1].toInt()
        val yy = m.groupValues[2].toInt()
        if (month !in 1..12) return null
        val currentYear = LocalDate.now().year
        val century = (currentYear / 100) * 100
        return safeEndOfMonth(century + yy, month)
    }

    // 5) MMYY 纯数字（无斜杠），与 visualTransformation 配合的新格式
    MONTH_YEAR_DIGITS.matchEntire(s)?.let { m ->
        val month = m.groupValues[1].toInt()
        val yy = m.groupValues[2].toInt()
        if (month !in 1..12) return null
        val currentYear = LocalDate.now().year
        val century = (currentYear / 100) * 100
        return safeEndOfMonth(century + yy, month)
    }

    return null
}

private fun safeDate(y: Int, mo: Int, d: Int): LocalDate? {
    if (mo !in 1..12 || d !in 1..31 || y !in 1..9999) return null
    // YearMonth.lengthOfMonth() 不抛异常
    val maxDay = YearMonth.of(y, mo).lengthOfMonth()
    if (d > maxDay) return null
    return LocalDate.of(y, mo, d)
}

private fun safeEndOfMonth(y: Int, mo: Int): LocalDate? {
    if (mo !in 1..12 || y !in 1..9999) return null
    return YearMonth.of(y, mo).atEndOfMonth()
}

enum class ExpiryStatus { EXPIRED, EXPIRING_SOON }

/** 一次性返回 (status, dateStr) — 调用方需要两者时不必再算两遍。 */
data class ExpiryInfo(val status: ExpiryStatus?, val dateStr: String?)

/**
 * 卡证日期显示格式化：把各种存储形态（YYYYMMDD / YYYY-MM-DD / YYYY/MM / MM/YY / MMYY / MM/yyyy）
 * 归一为易读的 "YYYY-MM-DD" 或 "MM/YY"；「长期/永久」统一显示为「长期」；无法识别时原样返回。
 */
fun formatCardDate(raw: String): String {
    val s = raw.trim()
    if (s.isEmpty()) return s
    if (s.contains("长期") || s.contains("永久")) return "长期"
    ISO_DATE.matchEntire(s)?.let { m ->
        return "${m.groupValues[1]}-${m.groupValues[2].padStart(2, '0')}-${m.groupValues[3].padStart(2, '0')}"
    }
    COMPACT_DATE.matchEntire(s)?.let { m ->
        return "${m.groupValues[1]}-${m.groupValues[2]}-${m.groupValues[3]}"
    }
    ISO_YEAR_MONTH.matchEntire(s)?.let { m ->
        return "${m.groupValues[1]}-${m.groupValues[2].padStart(2, '0')}"
    }
    MONTH_YEAR_LONG.matchEntire(s)?.let { m ->
        return "${m.groupValues[2]}-${m.groupValues[1].padStart(2, '0')}"
    }
    MONTH_YEAR_SHORT.matchEntire(s)?.let { m ->
        return "${m.groupValues[1].padStart(2, '0')}/${m.groupValues[2].padStart(2, '0')}"
    }
    MONTH_YEAR_DIGITS.matchEntire(s)?.let { m ->
        if (m.groupValues[1].toInt() in 1..12) {
            return "${m.groupValues[1]}/${m.groupValues[2]}"
        }
    }
    return s
}

/**
 * 该条目是否有任意密码类字段应该被检查泄露。
 */
fun Entry.hasAnyPassword(): Boolean {
    if (password.isNotEmpty()) return true
    return when (secretType) {
        SecretType.API_KEY -> getStringField("api_key").isNotEmpty()
        SecretType.WIFI -> getStringField("wifi_password").isNotEmpty()
        else -> false
    }
}

fun Entry.expiryInfo(daysThreshold: Int = 30): ExpiryInfo {
    val d = getExpiryDate() ?: return ExpiryInfo(null, null)
    val today = LocalDate.now()
    val status = when {
        d.isBefore(today) -> ExpiryStatus.EXPIRED
        java.time.temporal.ChronoUnit.DAYS.between(today, d) <= daysThreshold -> ExpiryStatus.EXPIRING_SOON
        else -> null
    }
    return ExpiryInfo(status, d.toString())
}
