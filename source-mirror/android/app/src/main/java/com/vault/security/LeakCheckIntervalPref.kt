package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 泄露自动检测周期（天）。
 * 0 = 关闭解锁后的自动检测；
 * 默认 5 天重新检测一次。
 */
object LeakCheckIntervalPref {
    private const val PREF = "pmv_leak_check_interval"
    private const val KEY_DAYS = "days"

    const val MIN_DAYS = 0
    const val MAX_DAYS = 30
    const val DEFAULT_DAYS = 5

    val days: MutableState<Int> = mutableStateOf(DEFAULT_DAYS)

    fun init(context: Context) {
        val prefName = vaultPrefName(PREF, CurrentVaultKey.current())
        days.value = PreferencePersistence.getInt(context, prefName, KEY_DAYS, DEFAULT_DAYS).coerceIn(MIN_DAYS, MAX_DAYS)
    }

    fun setDays(context: Context, v: Int) {
        val clamped = v.coerceIn(MIN_DAYS, MAX_DAYS)
        if (days.value == clamped) return
        days.value = clamped
        PreferencePersistence.putInt(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_DAYS, clamped)
    }
}
