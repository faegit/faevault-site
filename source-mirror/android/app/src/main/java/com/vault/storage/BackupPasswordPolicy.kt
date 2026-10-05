package com.vault.storage

/** Minimum password policy for every newly exported encrypted backup. */
object BackupPasswordPolicy {
    fun isStrong(password: String): Boolean {
        if (password.length < 14) return false
        var lower = false
        var upper = false
        var digit = false
        var symbol = false
        password.forEach { char ->
            when {
                char.isLowerCase() -> lower = true
                char.isUpperCase() -> upper = true
                char.isDigit() -> digit = true
                else -> symbol = true
            }
        }
        return listOf(lower, upper, digit, symbol).count { it } >= 3
    }
}
