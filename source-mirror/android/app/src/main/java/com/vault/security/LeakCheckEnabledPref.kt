package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/** 泄露检测总开关。关闭后不检测、不置顶、不显示泄露标记。 */
object LeakCheckEnabledPref {
    private const val PREF = "pmv_leak_check_enabled"
    private const val KEY_ENABLED = "enabled"

    val enabled: MutableState<Boolean> = mutableStateOf(true)

    fun init(context: Context) {
        val prefName = vaultPrefName(PREF, CurrentVaultKey.current())
        enabled.value = PreferencePersistence.getBoolean(context, prefName, KEY_ENABLED, true)
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        PreferencePersistence.putBoolean(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_ENABLED, v)
    }
}
