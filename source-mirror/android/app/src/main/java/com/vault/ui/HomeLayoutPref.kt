package com.vault.ui

import com.vault.security.SecurePreferences
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

enum class HomeLayoutMode(val key: String) {
    ITEMS("items"),
    TWO_COLUMNS("two_columns");

    companion object {
        fun fromKey(key: String?): HomeLayoutMode = entries.firstOrNull { it.key == key } ?: ITEMS
    }
}

object HomeLayoutPref {
    private const val PREF = "pmv_home_layout"
    private const val KEY_MODE = "mode"

    val mode: MutableState<HomeLayoutMode> = mutableStateOf(HomeLayoutMode.ITEMS)

    fun init(context: Context) {
        val prefs = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
        mode.value = HomeLayoutMode.fromKey(prefs.getString(KEY_MODE, null))
    }

    fun set(context: Context, value: HomeLayoutMode) {
        mode.value = value
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().putString(KEY_MODE, value.key).apply()
    }
}
