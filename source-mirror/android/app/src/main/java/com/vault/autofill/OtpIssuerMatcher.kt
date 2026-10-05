package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.getOtpField
import com.vault.model.otpDomains

/**
 * 独立 OTP 条目通常不记录 url，无法用 OriginMatcher 判域。
 * 按 otpauth URI 的 issuer（服务商全称）与目标域名做匹配（issuer 是 otpauth 的权威匹配键）。
 *
 * 匹配规则（全部在归一化后进行，归一化保留连字符以阻断 github-evil.com 类旁路）：
 *  1. issuer 与目标完全相等；
 *  2. 目标的某个点分 label 与 issuer 完全相等（排除通用 label）；
 *  3. 目标是 ".<issuer>" 结尾（覆盖 pages.github.io 这类多级发行方域名）。
 *
 * 刻意不采用别名映射与模糊匹配：issuer 与登录域名不一致的服务（如 Microsoft ↔ live.com）
 * 不自动命中，需在条目上显式配置 otp_domains 或手动填充；
 * 且 github-evil.com 含 github 会把真实动态码泄露给钓鱼页。
 */
object OtpIssuerMatcher {
    private val GENERIC_LABELS = setOf("www", "com", "net", "org", "io", "co", "cn", "me", "tv", "app")

    fun matches(entry: Entry, origin: TargetOrigin): Boolean {
        val target = when (origin) {
            is TargetOrigin.Web -> origin.host
            is TargetOrigin.AndroidPackage -> origin.packageName
        }
        if (target.isBlank()) return false
        val normalizedTarget = normalize(target)
        // 条目显式配置的关联域名优先（用户手动声明，覆盖 Microsoft ↔ live.com 类场景）
        if (origin is TargetOrigin.Web &&
            entry.otpDomains().any { domainMatches(normalize(it), normalizedTarget) }
        ) return true
        return issuerMatches(normalize(entry.getOtpField("issuer")), normalizedTarget)
    }

    private fun issuerMatches(issuer: String, target: String): Boolean {
        if (issuer.isEmpty() || target.isEmpty() || issuer in GENERIC_LABELS) return false
        if (issuer == target) return true
        val labels = target.split(".")
        if (labels.any { it == issuer }) return true
        return target.endsWith(".$issuer")
    }

    private fun domainMatches(domain: String, target: String): Boolean {
        if (domain.isEmpty() || target.isEmpty()) return false
        if (domain == target) return true
        // 仅允许带点域名做子域后缀匹配，裸 TLD（如 com）不得全量命中
        return domain.contains(".") && target.endsWith(".$domain")
    }

    private fun normalize(value: String): String =
        value.lowercase().replace(Regex("[^a-z0-9.-]"), "")
}
