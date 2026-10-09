package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 联网检测密码泄露（Pwned Passwords）开关。
 * 关闭后不发起在线查询，仅使用本地字典。
 */
object LeakOnlineCheckPref {
    private const val PREF = "pmv_leak_online"
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
