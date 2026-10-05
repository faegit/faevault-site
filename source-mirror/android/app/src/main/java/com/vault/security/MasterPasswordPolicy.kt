package com.vault.security

import kotlin.math.log2
import kotlin.math.min

enum class MasterPasswordRisk { BLOCKED, WEAK, STRONG }

enum class MasterPasswordIssue { COMMON_PASSWORD, VERY_LOW_ENTROPY, BELOW_RECOMMENDATION, NONE }

data class MasterPasswordAssessment(
    val risk: MasterPasswordRisk,
    val estimatedEntropyBits: Double,
    val issue: MasterPasswordIssue,
) {
    fun permits(highSecurityMode: Boolean, weakPasswordConfirmed: Boolean): Boolean = when (risk) {
        MasterPasswordRisk.BLOCKED -> false
        MasterPasswordRisk.STRONG -> true
        MasterPasswordRisk.WEAK -> !highSecurityMode && weakPasswordConfirmed
    }
}

/**
 * Offline master-password admission policy shared by vault creation and password rotation.
 *
 * The estimate is deliberately conservative: it recognizes random character strings,
 * multi-word passphrases, repeated units and predictable suffixes. It is not presented as
 * exact Shannon entropy. Known/common passwords are always blocked and cannot be overridden.
 */
object MasterPasswordPolicy {
    const val MIN_USABLE_ENTROPY_BITS = 40.0
    const val RECOMMENDED_ENTROPY_BITS = 60.0

    private val trailingDecoration = Regex("[\\d\\p{Punct}\\s]+$")
    private val passphraseSeparator = Regex("[\\s_-]+")
    private val predictableSuffix = Regex("^([A-Za-z]{4,})(\\d{1,6})([^A-Za-z0-9]*)$")
    private val obviousPatterns = listOf("1234", "4321", "abcd", "qwerty", "password", "letmein")

    fun assess(
        password: String,
        isCommonPassword: (String) -> Boolean = { false },
    ): MasterPasswordAssessment {
        val common = commonCandidates(password).any(isCommonPassword)
        val bits = estimateEntropyBits(password)
        return when {
            common -> MasterPasswordAssessment(
                MasterPasswordRisk.BLOCKED,
                bits,
                MasterPasswordIssue.COMMON_PASSWORD,
            )
            bits < MIN_USABLE_ENTROPY_BITS -> MasterPasswordAssessment(
                MasterPasswordRisk.BLOCKED,
                bits,
                MasterPasswordIssue.VERY_LOW_ENTROPY,
            )
            bits < RECOMMENDED_ENTROPY_BITS -> MasterPasswordAssessment(
                MasterPasswordRisk.WEAK,
                bits,
                MasterPasswordIssue.BELOW_RECOMMENDATION,
            )
            else -> MasterPasswordAssessment(MasterPasswordRisk.STRONG, bits, MasterPasswordIssue.NONE)
        }
    }

    internal fun estimateEntropyBits(password: String): Double {
        if (password.isEmpty()) return 0.0
        val words = password.split(passphraseSeparator).filter { it.length >= 3 && it.any(Char::isLetter) }
        var bits = if (words.size >= 3) {
            words.size * 13.0
        } else {
            val pool = characterPool(password)
            password.length * log2(pool.toDouble())
        }
        if (words.size >= 3) {
            val distinctWords = words.map(String::lowercase).distinct().size
            val repeatedCharacterWords = words.count { word -> word.toSet().size <= 1 }
            if (distinctWords < 3 || repeatedCharacterWords * 2 >= words.size) {
                bits = min(bits, 35.0)
            }
        }

        if (password.all(Char::isLetter)) bits = min(bits, password.length * 2.5)
        predictableSuffix.matchEntire(password)?.let { match ->
            val letters = match.groupValues[1].length * 2.5
            val digits = match.groupValues[2].length * log2(10.0)
            val decoration = match.groupValues[3].length * 2.0
            bits = min(bits, letters + digits + decoration)
        }
        repeatedUnit(password)?.let { unit ->
            bits = min(bits, basicEntropy(unit) + log2((password.length / unit.length + 1).toDouble()))
        }
        val lower = password.lowercase()
        if (obviousPatterns.any(lower::contains)) bits = min(bits, 35.0)
        return bits
    }

    private fun commonCandidates(password: String): Set<String> {
        val lower = password.trim().lowercase()
        val deLeeted = lower.map { char ->
            when (char) {
                '@', '4' -> 'a'
                '3' -> 'e'
                '1', '!', '|' -> 'i'
                '0' -> 'o'
                '5', '$' -> 's'
                '7' -> 't'
                else -> char
            }
        }.joinToString("")
        return linkedSetOf(
            password,
            lower,
            deLeeted,
            lower.replace(trailingDecoration, ""),
            deLeeted.replace(trailingDecoration, ""),
        ).filterTo(linkedSetOf()) { it.isNotEmpty() }
    }

    private fun characterPool(password: String): Int {
        var pool = 0
        if (password.any(Char::isLowerCase)) pool += 26
        if (password.any(Char::isUpperCase)) pool += 26
        if (password.any(Char::isDigit)) pool += 10
        if (password.any { it == ' ' }) pool += 1
        if (password.any { it.code in 0x21..0x2f || it.code in 0x3a..0x40 || it.code in 0x5b..0x60 || it.code in 0x7b..0x7e }) pool += 32
        if (password.any { it.code > 0x7e }) pool += 100
        return pool.coerceAtLeast(1)
    }

    private fun basicEntropy(value: String): Double = value.length * log2(characterPool(value).toDouble())

    private fun repeatedUnit(value: String): String? = (1..value.length / 2).firstNotNullOfOrNull { size ->
        if (value.length % size == 0) {
            val unit = value.take(size)
            unit.takeIf { value == unit.repeat(value.length / size) }
        } else {
            null
        }
    }
}
