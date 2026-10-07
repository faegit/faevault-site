package com.vault.autofill

import java.text.Normalizer
import java.util.Locale

/** Discovery only. Related labels never establish trust in a requesting origin. */
object AutofillMatchingPolicy {
    private val generic = setOf(
        "www", "com", "org", "net", "edu", "gov", "co", "app", "apps", "android", "auth", "login",
        "account", "accounts", "my", "git", "password", "mail", "email", "exe", "账号", "账户",
        "登录", "邮箱", "密码", "认证", "应用", "网页", "浏览器",
    )
    private val words = Regex("[\\p{L}\\p{N}]+")
    private val han = Regex("[\\p{IsHan}]{2,}")
    private val camel = Regex("(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
    private val scriptBoundary = Regex("(?<=[\\p{IsHan}])(?=[^\\p{IsHan}])|(?<=[^\\p{IsHan}])(?=[\\p{IsHan}])")

    private fun normalized(value: String) = Normalizer.normalize(value, Normalizer.Form.NFKC)
    private fun tokens(value: String): Set<String> {
        val normalized = normalized(value)
        val split = normalized.replace(camel, " ").replace(scriptBoundary, " ")
        return (words.findAll(normalized.replace(scriptBoundary, " ")) + words.findAll(split))
            .map { it.value.lowercase(Locale.ROOT) }
            .filter { it.length >= 2 && it !in generic }.toSet()
    }

    private fun compact(value: String): String = words.findAll(normalized(value).lowercase(Locale.ROOT))
        .joinToString("") { it.value }

    private fun joinedMeaningfulWords(value: String): String = words.findAll(
        normalized(value).replace(camel, " ").replace(scriptBoundary, " ").lowercase(Locale.ROOT),
    ).map { it.value }.filter { it.length >= 2 && (it !in generic || it == "git") }.joinToString("")

    fun relatedNames(left: String, right: String): Boolean {
        val leftTokens = tokens(left)
        val rightTokens = tokens(right)
        if (leftTokens.isEmpty() || rightTokens.isEmpty()) return false
        if (compact(left) == compact(right)) return true
        val joinedLeft = joinedMeaningfulWords(left)
        if (joinedLeft.isNotEmpty() && joinedLeft == joinedMeaningfulWords(right)) return true
        if (leftTokens.any(rightTokens::contains)) return true
        return leftTokens.any { a -> rightTokens.any { b ->
            han.matches(a) && han.matches(b) && (a.contains(b) || b.contains(a))
        } }
    }
}

enum class AutofillCandidateReason(val score: Int) {
    CONFIRMED_BINDING(400), EXACT_SOURCE(300), SAME_SITE(200), RELATED_NAME(100),
}
