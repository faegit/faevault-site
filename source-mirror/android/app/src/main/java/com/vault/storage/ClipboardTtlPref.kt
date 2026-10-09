package com.vault.storage

import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 敏感内容复制到剪贴板后的自动清理超时（秒）。0 表示不自动清理。
 * 由 copySensitive 在写入剪贴板时读取。
 */
object ClipboardTtlPref {
    private const val PREF = "pmv_clipboard_ttl"
    private const val KEY_SECONDS = "seconds"

    const val MIN_SECONDS = 0   // 0 = 不清理
    const val MAX_SECONDS = 600
    const val DEFAULT_SECONDS = 60

    val seconds: MutableState<Int> = mutableStateOf(DEFAULT_SECONDS)

    fun init(context: Context) {
        val prefName = com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current())
        seconds.value = com.vault.security.PreferencePersistence.getInt(context, prefName, KEY_SECONDS, DEFAULT_SECONDS).coerceIn(MIN_SECONDS, MAX_SECONDS)
    }

    fun setSeconds(context: Context, v: Int) {
        val clamped = v.coerceIn(MIN_SECONDS, MAX_SECONDS)
        if (seconds.value == clamped) return
        seconds.value = clamped
        com.vault.security.PreferencePersistence.putInt(context, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()), KEY_SECONDS, clamped)
    }
}
