package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

object BackgroundHidePref {
    private const val PREF = "pmv_background_hide"
    private const val KEY_HIDE = "hide_on_background"

    val enabled: MutableState<Boolean> = mutableStateOf(false)

    fun init(context: Context) {
        val prefName = vaultPrefName(PREF, CurrentVaultKey.current())
        enabled.value = PreferencePersistence.getBoolean(context, prefName, KEY_HIDE, false)
    }

    fun isEnabled(context: Context): Boolean = enabled.value

    fun setEnabled(context: Context, value: Boolean) {
        enabled.value = value
        PreferencePersistence.putBoolean(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_HIDE, value)
    }
}
