package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

object AutoHidePref {
    private const val PREF = "pmv_auto_hide"
    private const val KEY_SECONDS = "seconds"

    const val MIN_SECONDS = 2
    const val MAX_SECONDS = 120
    const val DEFAULT_SECONDS = 5

    val seconds: MutableState<Int> = mutableStateOf(DEFAULT_SECONDS)

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
        seconds.value = p.getInt(KEY_SECONDS, DEFAULT_SECONDS).coerceIn(MIN_SECONDS, MAX_SECONDS)
    }

    fun setSeconds(context: Context, v: Int) {
        val clamped = v.coerceIn(MIN_SECONDS, MAX_SECONDS)
        if (seconds.value == clamped) return
        seconds.value = clamped
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit().putInt(KEY_SECONDS, clamped).apply()
    }
}
