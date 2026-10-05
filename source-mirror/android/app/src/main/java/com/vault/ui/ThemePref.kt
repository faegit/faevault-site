package com.vault.ui

import com.vault.security.SecurePreferences
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/** 三种主题模式：跟随系统 / 浅色 / 深色。 */
enum class ThemeMode(val key: String) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark");

    companion object {
        fun fromKey(k: String?): ThemeMode = entries.firstOrNull { it.key == k } ?: SYSTEM
    }
}

/** 全局主题状态（跨 Activity 维持，依靠 SharedPreferences 持久化）。 */
object ThemePref {
    private const val PREF = "pmv_theme"
    private const val KEY = "mode"
    val mode: MutableState<ThemeMode> = mutableStateOf(ThemeMode.SYSTEM)

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
        mode.value = ThemeMode.fromKey(p.getString(KEY, null))
    }

    fun set(context: Context, m: ThemeMode) {
        mode.value = m
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().putString(KEY, m.key).apply()
    }
}
