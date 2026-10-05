package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 敏感信息守门开关：开启后，查看 / 复制 / 编辑 银行卡、证件、API 凭证 等条目里的
 * 敏感字段前需再次验证当前主密码（详情页内一次性缓存）。关闭后这类条目与登录条目
 * 一样直接可见，仅靠主入口的解锁保护。
 */
object SensitiveGuardPref {
    private const val PREF = "pmv_sensitive_guard"
    private const val KEY_ENABLED = "enabled"
    const val DEFAULT_ENABLED = false

    val enabled: MutableState<Boolean> = mutableStateOf(DEFAULT_ENABLED)

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
        enabled.value = p.getBoolean(KEY_ENABLED, DEFAULT_ENABLED)
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit().putBoolean(KEY_ENABLED, v).apply()
    }
}
