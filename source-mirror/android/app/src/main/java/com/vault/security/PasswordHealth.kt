package com.vault.security

import android.content.Context
import com.nulabinc.zxcvbn.Zxcvbn
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.entryModules
import com.vault.model.entrySecret
import com.vault.model.hasCurrentLeakCache
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.JsonObject

enum class PasswordFinding(
    val key: String,
    val label: String,
    val highRisk: Boolean,
    val description: String,
    val recommendation: String,
) {
    LEAKED(
        "leaked", "公开泄露", true,
        "该密码已出现在公开泄露数据中。",
        "立即更换，勿在其他账户复用。",
    ),
    DUPLICATE(
        "duplicate", "重复密码", true,
        "多个条目使用了相同密码。",
        "为每个账户设置不同的随机密码。",
    ),
    WEAK(
        "weak", "强度极低", true,
        "密码太短或字符种类过少。",
        "改用至少 12 位且难以猜测的随机密码。",
    ),
    COMMON_PATTERN(
        "pattern", "常见/初始密码", true,
        "密码过于常见或存在明显规律。",
        "更换为随机的强密码。",
    ),
    NEAR_DUPLICATE(
        "near_duplicate", "相似密码", false,
        "多个密码只是在细节上略有不同。",
        "改用互不相关的密码。",
    ),
    TOO_SHORT(
        "too_short", "长度不足 12 位", false,
        "密码长度少于建议的 12 位。",
        "换用更长的密码。",
    ),
    ACCOUNT_INFO(
        "account_info", "包含账户信息", false,
        "密码包含账号、名称或网址中的内容。",
        "移除与账户资料相关的内容。",
    ),
    LONG_UNCHANGED(
        "long_unchanged", "长期未修改", false,
        "该条目长期未修改。",
        "确认密码仍然有效且未泄露，必要时更换。",
    ),
    ;

    companion object {
        fun fromKey(key: String): PasswordFinding? = entries.firstOrNull { it.key == key }
    }
}

data class PasswordHealthReport(
    val total: Int,
    val findings: Map<PasswordFinding, List<Entry>>,
    val highRisk: List<Entry>,
    val improvement: List<Entry>,
    val healthy: List<Entry>,
    val duplicateGroupKeys: Map<String, String> = emptyMap(),
) {
    fun entriesFor(key: String): List<Entry> = when (key) {
        "high" -> highRisk
        "improvement" -> improvement
        "healthy" -> healthy
        "all" -> (highRisk + improvement).distinctBy(Entry::id)
        else -> PasswordFinding.fromKey(key)?.let { findings[it].orEmpty() }.orEmpty()
    }

    fun issuesFor(entryId: String): List<PasswordFinding> = PasswordFinding.entries.filter { finding ->
        findings[finding].orEmpty().any { it.id == entryId }
    }

    companion object {
        val EMPTY = PasswordHealthReport(
            total = 0,
            findings = PasswordFinding.entries.associateWith { emptyList() },
            highRisk = emptyList(),
            improvement = emptyList(),
            healthy = emptyList(),
            duplicateGroupKeys = emptyMap(),
        )
    }
}

object PasswordHealth {
    private const val LONG_UNCHANGED_DAYS = 180L
    private val sequencePatterns = listOf(
        "1234", "4321", "abcd", "qwerty", "password", "admin", "letmein", "welcome",
    )
    private val passwordFieldNames = setOf(
        "password", "wifi_password",
    )
    // zxcvbn 非线程安全，用 ThreadLocal 隔离各扫描线程的实例
    private val zxcvbn: ThreadLocal<Zxcvbn> = ThreadLocal.withInitial { Zxcvbn() }
    private val entryCache = ConcurrentHashMap<String, EntryAnalysis>()

    @Volatile
    private var cachedReportKey: String? = null

    @Volatile
    private var cachedReport: PasswordHealthReport? = null

    fun analyze(
        context: Context,
        entries: List<Entry>,
        logicalRevision: String = "",
        force: Boolean = false,
        onProgress: (checked: Int, total: Int) -> Unit = { _, _ -> },
    ): PasswordHealthReport = analyzeInternal(
        entries = entries,
        logicalRevision = logicalRevision,
        force = force,
        day = System.currentTimeMillis() / 86_400_000L,
        commonPasswordCheck = { LeakedPasswordCheck.isLeaked(context, it) },
        onProgress = onProgress,
    )

    internal fun analyzeForTest(
        entries: List<Entry>,
        day: Long,
        commonPasswordCheck: (String) -> Boolean = { false },
    ): PasswordHealthReport = analyzeInternal(
        entries = entries,
        logicalRevision = "",
        force = true,
        day = day,
        commonPasswordCheck = commonPasswordCheck,
    )

    private fun analyzeInternal(
        entries: List<Entry>,
        logicalRevision: String,
        force: Boolean,
        day: Long,
        commonPasswordCheck: (String) -> Boolean,
        onProgress: (checked: Int, total: Int) -> Unit = { _, _ -> },
    ): PasswordHealthReport {
        // 安全中心只检测「登录」与「Wi-Fi」两类条目的密码（银行卡/API Key/服务器等不参与）。
        val active = entries.filter {
            it.deletedAt == null &&
                (it.secretType == SecretType.LOGIN || it.secretType == SecretType.WIFI)
        }
        val reportKey = logicalRevision.takeIf(String::isNotBlank)?.let { "$it:$day" }
        if (!force && reportKey != null && cachedReportKey == reportKey) {
            cachedReport?.let { return rebind(it, active) }
        }

        if (force) entryCache.clear()
        val analyzed = ArrayList<EntryAnalysis>(active.size)
        active.forEachIndexed { index, entry ->
            val fingerprint = entryFingerprint(entry, day)
            val cached = entryCache[entry.id]
            val result = if (cached?.fingerprint == fingerprint) cached.copy(entry = entry) else {
                analyzeEntry(entry, fingerprint, day, commonPasswordCheck)
            }
            entryCache[entry.id] = result
            if (result.secretHashes.isNotEmpty()) analyzed += result
            onProgress(index + 1, active.size)
        }
        entryCache.keys.retainAll(active.mapTo(HashSet(), Entry::id))

        val exactEntryCounts = analyzed
            .flatMap { analysis -> analysis.secretHashes.map { it to analysis.entry.id } }
            .groupBy(Pair<String, String>::first)
            .mapValues { (_, values) -> values.map(Pair<String, String>::second).distinct().size }
        val nearEntryCounts = analyzed
            .flatMap { analysis -> analysis.nearHashes.map { it to analysis.entry.id } }
            .groupBy(Pair<String, String>::first)
            .mapValues { (_, values) -> values.map(Pair<String, String>::second).distinct().size }
        val findings = PasswordFinding.entries.associateWith { mutableListOf<Entry>() }

        analyzed.forEach { result ->
            val entry = result.entry
            if (result.leaked) findings.getValue(PasswordFinding.LEAKED) += entry
            if (result.secretHashes.any { (exactEntryCounts[it] ?: 0) > 1 }) {
                findings.getValue(PasswordFinding.DUPLICATE) += entry
            }
            if (result.weak) findings.getValue(PasswordFinding.WEAK) += entry
            if (result.commonPattern) findings.getValue(PasswordFinding.COMMON_PATTERN) += entry
            if (result.nearHashes.any { (nearEntryCounts[it] ?: 0) > 1 }) {
                findings.getValue(PasswordFinding.NEAR_DUPLICATE) += entry
            }
            if (result.tooShort) findings.getValue(PasswordFinding.TOO_SHORT) += entry
            if (result.accountInfo) findings.getValue(PasswordFinding.ACCOUNT_INFO) += entry
            if (result.longUnchanged) findings.getValue(PasswordFinding.LONG_UNCHANGED) += entry
        }

        val highIds = findingIds(findings, highRisk = true)
        val improvementIds = findingIds(findings, highRisk = false) - highIds
        val passwordEntries = analyzed.map(EntryAnalysis::entry)

        val duplicateGroupKeys = mutableMapOf<String, String>()
        analyzed.flatMap { a -> a.secretHashes.map { it to a.entry.id } }
            .groupBy({ it.first }, { it.second })
            .filter { (_, ids) -> ids.toSet().size > 1 }
            .forEach { (hash, ids) -> ids.forEach { duplicateGroupKeys[it] = hash } }
        analyzed.flatMap { a -> a.nearHashes.map { it to a.entry.id } }
            .groupBy({ it.first }, { it.second })
            .filter { (_, ids) -> ids.toSet().size > 1 }
            .forEach { (hash, ids) -> ids.forEach { id -> duplicateGroupKeys.putIfAbsent(id, hash) } }

        val report = PasswordHealthReport(
            total = passwordEntries.size,
            findings = findings.mapValues { it.value.toList() },
            highRisk = passwordEntries.filter { it.id in highIds },
            improvement = passwordEntries.filter { it.id in improvementIds },
            healthy = passwordEntries.filterNot { it.id in highIds || it.id in improvementIds },
            duplicateGroupKeys = duplicateGroupKeys,
        )
        if (reportKey != null) {
            cachedReport = report
            cachedReportKey = reportKey
        }
        return report
    }

    fun clearCache() {
        entryCache.clear()
        cachedReport = null
        cachedReportKey = null
    }

    fun latestReport(): PasswordHealthReport? = cachedReport

    private fun rebind(report: PasswordHealthReport, entries: List<Entry>): PasswordHealthReport {
        val current = entries.associateBy(Entry::id).mapValues { (_, entry) ->
            entry.copy(password = "", notes = "", fields = emptyMap())
        }
        fun List<Entry>.currentEntries() = mapNotNull { current[it.id] }
        return report.copy(
            findings = report.findings.mapValues { it.value.currentEntries() },
            highRisk = report.highRisk.currentEntries(),
            improvement = report.improvement.currentEntries(),
            healthy = report.healthy.currentEntries(),
        )
    }

    private fun analyzeEntry(
        entry: Entry,
        fingerprint: String,
        day: Long,
        commonPasswordCheck: (String) -> Boolean,
    ): EntryAnalysis {
        val secretHashes = LinkedHashSet<String>()
        val nearHashes = LinkedHashSet<String>()
        var weak = false
        var commonPattern = false
        var tooShort = false
        var accountInfo = false
        entrySecrets(entry).forEach { secret ->
            secretHashes += digest(secret)
            nearSignature(secret).takeIf(String::isNotEmpty)?.let { nearHashes += digest(it) }
            weak = weak || isZxcvbnWeak(secret)
            commonPattern = commonPattern || isCommonPattern(secret) || commonPasswordCheck(secret)
            tooShort = tooShort || secret.length < 12
            accountInfo = accountInfo || containsAccountInfo(entry, secret)
        }
        val hasOtp = entry.secretType == SecretType.OTP || entry.entryModules().any {
            EntryModules.primitive(it["type"]) == ModuleType.OTP
        }
        val longUnchanged = entry.updatedAt > 0.0 && day - (entry.updatedAt.toLong() / 86_400L) >= LONG_UNCHANGED_DAYS
        return EntryAnalysis(
            entry = entry.copy(password = "", notes = "", fields = emptyMap()),
            fingerprint = fingerprint,
            secretHashes = secretHashes,
            nearHashes = nearHashes,
            leaked = entry.hasCurrentLeakCache() && (entry.leakPwnedCount ?: 0) > 0,
            weak = weak,
            commonPattern = commonPattern || entry.leakCommonWeak,
            tooShort = tooShort,
            accountInfo = accountInfo,
            longUnchanged = longUnchanged,
        )
    }

    private fun entrySecrets(entry: Entry): Sequence<String> = sequence {
        entry.entrySecret().takeIf(String::isNotBlank)?.let { yield(it) }
        entry.entryModules().forEach { module ->
            val type = EntryModules.primitive(module["type"])
            val value = module["value"]
            if (type == ModuleType.PASSWORD) {
                EntryModules.primitive(value).takeIf(String::isNotBlank)?.let { yield(it) }
            } else if (value is JsonObject) {
                value.forEach { (key, raw) ->
                    if (key in passwordFieldNames) {
                        EntryModules.primitive(raw).takeIf(String::isNotBlank)?.let { yield(it) }
                    }
                }
            }
        }
    }.distinct()

    private fun entryFingerprint(entry: Entry, day: Long): String {
        val digest = MessageDigest.getInstance("SHA-256")
        fun add(value: String) {
            digest.update(value.encodeToByteArray())
            digest.update(0)
        }
        entrySecrets(entry).forEach(::add)
        add(entry.username)
        add(entry.title)
        add(entry.url)
        add(entry.updatedAt.toString())
        add(day.toString())
        entry.entryModules().forEach { module -> add(EntryModules.primitive(module["type"])) }
        return digest.digest().toHex()
    }

    private fun findingIds(
        findings: Map<PasswordFinding, List<Entry>>,
        highRisk: Boolean,
    ): Set<String> = PasswordFinding.entries.asSequence()
        .filter { it.highRisk == highRisk }
        .flatMap { findings.getValue(it).asSequence() }
        .map(Entry::id)
        .toSet()

    /** zxcvbn 评分 0/1 视为弱密码：可被自动化工具快速猜测。 */
    private fun isZxcvbnWeak(password: String): Boolean =
        zxcvbn.get()!!.measure(password).score <= 1

    private fun isCommonPattern(password: String): Boolean {
        val value = password.lowercase()
        if (sequencePatterns.any(value::contains)) return true
        if (value.length >= 4 && value.toSet().size <= 2) return true
        return (1..value.length / 2).any { size ->
            value.length % size == 0 && value.chunked(size).distinct().size == 1
        }
    }

    private fun nearSignature(password: String): String {
        val value = password.lowercase()
            .replace(Regex("\\d{2,}"), "#")
            .trim { !it.isLetterOrDigit() && it != '#' }
        return value.takeIf { it.length >= 5 } ?: ""
    }

    private fun containsAccountInfo(entry: Entry, password: String): Boolean {
        val value = password.lowercase()
        val candidates = buildList {
            add(entry.username.substringBefore('@'))
            add(entry.title)
            add(entry.url.substringAfter("://", entry.url).substringBefore('/').substringBefore('.'))
        }.map { it.trim().lowercase() }.filter { it.length >= 4 }
        return candidates.any(value::contains)
    }

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private data class EntryAnalysis(
        val entry: Entry,
        val fingerprint: String,
        val secretHashes: Set<String>,
        val nearHashes: Set<String>,
        val leaked: Boolean,
        val weak: Boolean,
        val commonPattern: Boolean,
        val tooShort: Boolean,
        val accountInfo: Boolean,
        val longUnchanged: Boolean,
    )
}
