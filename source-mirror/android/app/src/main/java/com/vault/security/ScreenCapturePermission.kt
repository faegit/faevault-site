package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * Whether the main vault window may appear in screenshots and recordings.
 */
object ScreenCapturePermission {
    private const val PREF = "pmv_screen_capture"
    private const val KEY_ALLOWED = "allowed"
    private const val LEGACY_KEY_PROTECTED = "protected"
    const val DEFAULT_ALLOWED = false

    val allowed: MutableState<Boolean> = mutableStateOf(DEFAULT_ALLOWED)

    fun init(context: Context) {
        val prefs = SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
        allowed.value = if (prefs.contains(KEY_ALLOWED)) {
            prefs.getBoolean(KEY_ALLOWED, DEFAULT_ALLOWED)
        } else {
            !prefs.getBoolean(LEGACY_KEY_PROTECTED, true)
        }
    }

    fun setAllowed(context: Context, value: Boolean) {
        allowed.value = value
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit()
            .putBoolean(KEY_ALLOWED, value)
            .remove(LEGACY_KEY_PROTECTED)
            .apply()
    }
}
