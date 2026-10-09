package com.vault.ui

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
        val prefName = com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current())
        mode.value = HomeLayoutMode.fromKey(com.vault.security.PreferencePersistence.getString(context, prefName, KEY_MODE, null))
    }

    fun set(context: Context, value: HomeLayoutMode) {
        mode.value = value
        com.vault.security.PreferencePersistence.putString(context, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()), KEY_MODE, value.key)
    }
}
