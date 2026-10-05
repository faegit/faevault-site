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
        val p = SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
        enabled.value = p.getBoolean(KEY_ENABLED, true)
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit().putBoolean(KEY_ENABLED, v).apply()
    }
}
