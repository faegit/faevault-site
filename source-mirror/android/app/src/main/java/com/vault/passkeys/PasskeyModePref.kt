package com.vault.passkeys

import android.content.Context

enum class PasskeyCreationPreference(
    val wireValue: String,
    val fixedMode: PasskeyKeyMode?,
) {
    ASK_EVERY_TIME("ask_every_time", null),
    SYNCABLE(PasskeyKeyMode.SYNCABLE.wireValue, PasskeyKeyMode.SYNCABLE),
    DEVICE_BOUND(PasskeyKeyMode.DEVICE_BOUND.wireValue, PasskeyKeyMode.DEVICE_BOUND);

    companion object {
        fun parse(value: String): PasskeyCreationPreference? = entries.firstOrNull { it.wireValue == value }
    }
}

class PasskeyModePref(
    context: Context,
    vaultKey: String = com.vault.security.CurrentVaultKey.current(),
) {
    private val prefs = context.applicationContext.getSharedPreferences(
        com.vault.security.vaultPrefName(PREFS, vaultKey),
        Context.MODE_PRIVATE,
    )

    var creationPreference: PasskeyCreationPreference
        get() = parseOrDefault(prefs.getString(KEY, null))
        set(value) {
            prefs.edit().putString(KEY, value.wireValue).apply()
        }

    companion object {
        internal fun parseOrDefault(value: String?): PasskeyCreationPreference =
            value?.let(PasskeyCreationPreference::parse) ?: PasskeyCreationPreference.ASK_EVERY_TIME

        private const val PREFS = "passkey_mode_pref_v1"
        private const val KEY = "default_mode"
    }
}
