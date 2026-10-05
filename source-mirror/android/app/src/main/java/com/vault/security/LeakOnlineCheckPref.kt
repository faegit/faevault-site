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
        val p = SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
        enabled.value = p.getBoolean(KEY_ENABLED, true)
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit().putBoolean(KEY_ENABLED, v).apply()
    }
}
