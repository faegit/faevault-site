package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.net.IDN
import java.net.URI
import java.text.Normalizer
import java.util.Locale

object OriginMatcher {
    private val wordPattern = Regex("[\\p{L}\\p{N}]+")
    private val genericOriginWords = setOf("com", "org", "net", "www", "app", "apps", "android", "login", "auth")
    private val packagePattern = Regex("^[a-zA-Z][a-zA-Z0-9_]*(?:\\.[a-zA-Z0-9_]+)+$")
    private val deniedPackages = setOf(
        "com.android.settings",
        "com.android.systemui",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
    )
    private val supportedBrowsers = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.fenix",
        "com.microsoft.emmx",
        "com.microsoft.emmx.beta",
        "com.sec.android.app.sbrowser",
        "com.sec.android.app.sbrowser.beta",
        "com.brave.browser",
        "com.brave.browser_beta",
        "com.opera.browser",
        "com.vivaldi.browser",
    )

    fun originFrom(
        packageName: String?,
        webDomain: String?,
        ownPackage: String,
        signingCertificateSha256: Set<String> = emptySet(),
        trustedBrowserSigningCertificateSha256: Set<String> = emptySet(),
    ): TargetOrigin? {
        val pkg = packageName?.trim().orEmpty()
        if (!isSafePackage(pkg, ownPackage)) return null
        val certificates = signingCertificateSha256.mapTo(linkedSetOf()) { it.lowercase(Locale.ROOT) }
            .filterTo(linkedSetOf()) { it.matches(Regex("^[0-9a-f]{64}$")) }
        if (certificates.isEmpty()) return null
        val web = normalizeHost(webDomain)
        if (webDomain != null && web == null) return null
        return when {
            web != null && pkg in supportedBrowsers -> {
                val trustedCertificates = trustedBrowserSigningCertificateSha256
                    .mapTo(linkedSetOf()) { it.lowercase(Locale.ROOT) }
                    .filterTo(linkedSetOf()) { it.matches(Regex("^[0-9a-f]{64}$")) }
                if (certificates.intersect(trustedCertificates).isEmpty()) null
                else TargetOrigin.Web(web, pkg, certificates)
            }
            web != null -> null
            pkg in supportedBrowsers -> null
            else -> TargetOrigin.AndroidPackage(pkg, certificates)
        }
    }

    fun webHost(raw: String): String? {
        val cleaned = raw.trim()
        if (cleaned.isEmpty()) return null
        // 旧库条目常见 http:// 或无 scheme 的裸域名；这里仅对“存储的绑定值”宽容解析，
        // 目标来源仍由浏览器上报的域名驱动，不会因此放宽页面侧判断。
        val candidate = if (cleaned.contains("://")) cleaned else "https://$cleaned"
        val uri = runCatching { URI(candidate) }.getOrNull() ?: return null
        if (uri.scheme !in setOf("https", "http")) return null
        if (uri.rawUserInfo != null) return null
        val authority = uri.rawAuthority ?: return null
        val host = uri.host ?: authority.substringBeforeLast(':').takeIf { value ->
            value.isNotEmpty() && !value.contains('[') && !value.contains(']')
        }
        if (uri.port < -1 || uri.port > 65535) return null
        return normalizeHost(host)
    }

    fun matchLevel(target: TargetOrigin, binding: String): OriginMatchLevel = when (target) {
        is TargetOrigin.AndroidPackage -> {
            val bound = packageBinding(binding)
            if (bound == target.packageName) OriginMatchLevel.EXACT else OriginMatchLevel.NONE
        }
        is TargetOrigin.Web -> {
            val bound = webHost(binding) ?: return OriginMatchLevel.NONE
            when {
                target.host == bound -> OriginMatchLevel.EXACT
                isSafeParentDomain(target.host, bound) -> OriginMatchLevel.PARENT_DOMAIN
                else -> OriginMatchLevel.NONE
            }
        }
    }

    /** 对一条 Entry 同时检查 url 和 targetApp，任一匹配即算匹配。 */
    fun matchLevel(target: TargetOrigin, entry: Entry): OriginMatchLevel {
        // 旧库升级常见形态：网址/包名只存在于自定义模块（legacy url / target_app）而未落到
        // 顶层字段。这里把顶层字段与模块绑定一并收集，任一命中即视为匹配。
        val bindings = ArrayList<String>()
        entry.url.takeIf(String::isNotEmpty)?.let(bindings::add)
        moduleValues(entry, "url").mapNotNull(::webHost).forEach { bindings += "https://$it" }
        AutofillOriginMetadata.webHosts(entry).forEach { bindings += "https://$it" }
        entry.targetApp.takeIf(String::isNotEmpty)?.let(bindings::add)
        moduleValues(entry, "target_app").forEach(bindings::add)
        AutofillOriginMetadata.androidIdentities(entry).mapTo(bindings) { it.packageName }
        val bindingLevel = bindings.mapNotNull { binding ->
            matchLevel(target, binding).takeIf { it != OriginMatchLevel.NONE }
        }.maxByOrNull(::matchScore) ?: OriginMatchLevel.NONE
        if (bindingLevel == OriginMatchLevel.NONE) return OriginMatchLevel.NONE
        if (target !is TargetOrigin.AndroidPackage) return bindingLevel

        return if (AutofillOriginMetadata.androidIdentities(entry).any { stored ->
            stored.packageName == target.packageName &&
                stored.signingCertificateSha256.intersect(target.signingCertificateSha256).isNotEmpty()
        }) OriginMatchLevel.EXACT else OriginMatchLevel.NONE
    }

    private fun moduleValues(entry: Entry, wantedType: String): List<String> {
        val modules = entry.fields[EntryModules.FIELD_KEY] as? JsonArray ?: return emptyList()
        val values = ArrayList<String>()
        for (raw in modules) {
            val module = raw as? JsonObject ?: continue
            val type = (module["type"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
            if (type != wantedType) continue
            val value = (module["value"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
            value.takeIf(String::isNotEmpty)?.let(values::add)
        }
        return values
    }

    /** Suggestions for an explicit picker only; never proof that a credential belongs to an origin. */
    fun fillCandidateLevel(target: TargetOrigin, entry: Entry, appName: String? = null): OriginMatchLevel {
        val verified = matchLevel(target, entry)
        if (verified != OriginMatchLevel.NONE) return verified
        // Do not turn a known application's signer mismatch into a word suggestion.
        if (target is TargetOrigin.AndroidPackage && AutofillOriginMetadata.androidIdentities(entry).any {
                it.packageName == target.packageName &&
                    it.signingCertificateSha256.intersect(target.signingCertificateSha256).isEmpty()
            }) return OriginMatchLevel.NONE
        val targetWords = when (target) {
            is TargetOrigin.AndroidPackage -> words(target.packageName) + words(appName.orEmpty())
            is TargetOrigin.Web -> {
                val host = webHost(target.host) ?: return OriginMatchLevel.NONE
                val registrable = runCatching { "https://$host".toHttpUrl().topPrivateDomain() }.getOrNull()
                    ?: return OriginMatchLevel.NONE
                // Exclude the public/private suffix: sharing "com" or "co.uk" is not a service match.
                words(host.removeSuffix(".${registrable.substringAfter('.')}"))
            }
        }.filterNot { it in genericOriginWords }.toSet()
        if (targetWords.isEmpty()) return OriginMatchLevel.NONE
        val labels = buildList {
            add(entry.title)
            add(entry.url)
            add(entry.targetApp)
            addAll(moduleValues(entry, "url"))
            addAll(moduleValues(entry, "target_app"))
            addAll(AutofillOriginMetadata.webHosts(entry))
            addAll(AutofillOriginMetadata.androidIdentities(entry).map { it.packageName })
        }
        return if (labels.any { label -> words(label).any(targetWords::contains) }) {
            OriginMatchLevel.WORD_CANDIDATE
        } else OriginMatchLevel.NONE
    }

    private fun words(value: String): Set<String> = wordPattern.findAll(
        Normalizer.normalize(value, Normalizer.Form.NFKC).lowercase(Locale.ROOT),
    ).map { it.value }.toSet()

    fun rank(entries: List<Entry>, origin: TargetOrigin, limit: Int = 8): List<CredentialMatch> =
        entries.asSequence()
            .filter { it.deletedAt == null && it.secretType == SecretType.LOGIN && it.password.isNotEmpty() }
            .mapNotNull { entry ->
                val level = matchLevel(origin, entry)
                if (level == OriginMatchLevel.NONE) null
                else Ranked(
                    entry,
                    level,
                    matchScore(level),
                )
            }
            .sortedWith(
                compareByDescending<Ranked> { it.score }
                    .thenBy { it.entry.titleLower }
                    .thenBy { it.entry.id },
            )
            .take(limit.coerceIn(0, 8))
            .map { CredentialMatch(it.entry.id, it.level, it.score) }
            .toList()

    fun hasLegacyPackageBinding(entry: Entry, packageName: String): Boolean {
        val bindings = buildList {
            entry.url.takeIf(String::isNotEmpty)?.let(::add)
            entry.targetApp.takeIf(String::isNotEmpty)?.let(::add)
            addAll(moduleValues(entry, "target_app"))
        }
        return bindings.any { packageBinding(it) == packageName }
    }

    private fun packageBinding(raw: String): String? {
        val value = raw.trim()
        if (packagePattern.matches(value)) return value
        if (value.startsWith("androidapp://", ignoreCase = true)) {
            return runCatching { URI(value).host }.getOrNull()?.takeIf(packagePattern::matches)
        }
        return null
    }

    private fun isSafeParentDomain(targetHost: String, boundHost: String): Boolean {
        if (!targetHost.endsWith(".$boundHost")) return false
        val boundRegistrableDomain = runCatching {
            "https://$boundHost".toHttpUrl().topPrivateDomain()
        }.getOrNull() ?: return false
        val targetRegistrableDomain = runCatching {
            "https://$targetHost".toHttpUrl().topPrivateDomain()
        }.getOrNull() ?: return false
        return targetRegistrableDomain == boundRegistrableDomain
    }

    private fun isSafePackage(packageName: String, ownPackage: String): Boolean {
        if (!packagePattern.matches(packageName) || packageName == ownPackage) return false
        if (packageName in deniedPackages) return false
        return !packageName.startsWith("com.android.inputmethod") &&
            !packageName.contains("launcher", ignoreCase = true)
    }

    private fun matchScore(level: OriginMatchLevel): Int = when (level) {
        OriginMatchLevel.EXACT -> 200
        OriginMatchLevel.PARENT_DOMAIN -> 100
        OriginMatchLevel.LEGACY_PACKAGE -> 50
        OriginMatchLevel.WORD_CANDIDATE -> 25
        OriginMatchLevel.NONE -> 0
    }

    private fun normalizeHost(raw: String?): String? {
        val cleaned = raw?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT) ?: return null
        if (cleaned.isEmpty() || !cleaned.contains('.')) return null
        val ascii = runCatching { IDN.toASCII(cleaned, IDN.USE_STD3_ASCII_RULES) }.getOrNull() ?: return null
        if (ascii.length > 253 || ascii.split('.').any { it.isEmpty() || it.length > 63 }) return null
        if (ascii.matches(Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$"))) return null
        if (!ascii.contains('.')) return null
        if (!ascii.startsWith("www.")) return ascii
        val withoutWww = ascii.removePrefix("www.")
        val originalRegistrable = runCatching {
            "https://$ascii".toHttpUrl().topPrivateDomain()
        }.getOrNull()
        val strippedRegistrable = runCatching {
            "https://$withoutWww".toHttpUrl().topPrivateDomain()
        }.getOrNull()
        // Preserve the historical www.example.com == example.com behavior only when PSL
        // proves that stripping the label cannot collapse a private/public suffix boundary.
        return if (originalRegistrable != null && originalRegistrable == strippedRegistrable) {
            withoutWww
        } else {
            ascii
        }
    }

    private data class Ranked(val entry: Entry, val level: OriginMatchLevel, val score: Int)
}
