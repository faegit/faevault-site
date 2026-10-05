package com.vault.autofill

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

enum class AutofillSupportState { UNSUPPORTED, DISABLED, ENABLED }

object AutofillSetup {
    fun supportState(context: Context): AutofillSupportState {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return AutofillSupportState.UNSUPPORTED
        val expected = ComponentName(context, FAEVaultAutofillService::class.java)
        val selected = runCatching {
            Settings.Secure.getString(context.contentResolver, AUTOFILL_SERVICE_SETTING)
        }.getOrNull().orEmpty()
        val enabled = selected.split(':').any { raw ->
            ComponentName.unflattenFromString(raw)?.let { it == expected } == true
        }
        return if (enabled) AutofillSupportState.ENABLED else AutofillSupportState.DISABLED
    }

    fun credentialProviderState(context: Context): AutofillSupportState {
        if (Build.VERSION.SDK_INT < 34) return AutofillSupportState.UNSUPPORTED
        val expected = ComponentName(context, com.vault.passkeys.FAEVaultCredentialProviderService::class.java)
        val keys = listOf(CREDENTIAL_SERVICE_SETTING, CREDENTIAL_SERVICE_PRIMARY_SETTING, CREDENTIAL_SERVICE_DEFAULT_SETTING)
        val enabled = keys.any { key ->
            val raw = runCatching {
                Settings.Secure.getString(context.contentResolver, key)
            }.getOrNull().orEmpty()
            raw.split(':').any { ComponentName.unflattenFromString(it)?.let { c -> c == expected } == true }
        }
        return if (enabled) AutofillSupportState.ENABLED else AutofillSupportState.DISABLED
    }

    fun requestEnableIntent(context: Context): Intent =
        Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
            data = Uri.parse("package:${context.packageName}")
        }

    fun credentialProviderIntent(context: Context): Intent =
        Intent(ACTION_CREDENTIAL_PROVIDER).apply {
            data = Uri.parse("package:${context.packageName}")
        }

    private const val AUTOFILL_SERVICE_SETTING = "autofill_service"
    private const val CREDENTIAL_SERVICE_SETTING = "credential_service"
    private const val CREDENTIAL_SERVICE_PRIMARY_SETTING = "credential_service_primary"
    private const val CREDENTIAL_SERVICE_DEFAULT_SETTING = "credential_service_default"
    private const val ACTION_CREDENTIAL_PROVIDER = "android.settings.CREDENTIAL_PROVIDER"
}
