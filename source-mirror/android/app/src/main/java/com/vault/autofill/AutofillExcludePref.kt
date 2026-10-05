package com.vault.autofill

import com.vault.security.SecurePreferences
import android.content.Context

object AutofillExcludePref {
    private const val PREF = "pmv_autofill_exclude"
    private const val KEY_PACKAGES = "excluded_packages"
    private const val KEY_HOSTS = "excluded_hosts"

    private const val KEY_SCHEMA = "exclusions_v1"

    fun snapshot(context: Context, vaultKey: String = com.vault.security.CurrentVaultKey.current()): com.vault.model.AutofillExclusions {
        val prefs = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, vaultKey))
        val stored = prefs.getString(KEY_SCHEMA, null)?.let {
            runCatching { com.vault.storage.VaultCodec.json.decodeFromString(com.vault.model.AutofillExclusions.serializer(), it) }.getOrNull()
        }
        return (stored ?: com.vault.model.AutofillExclusions(
            packages = prefs.getStringSet(KEY_PACKAGES, emptySet()).orEmpty().toList(),
            hosts = prefs.getStringSet(KEY_HOSTS, emptySet()).orEmpty().toList(),
        )).normalized()
    }

    fun replace(context: Context, exclusions: com.vault.model.AutofillExclusions, vaultKey: String = com.vault.security.CurrentVaultKey.current()) {
        val normalized = exclusions.normalized()
        check(SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, vaultKey)).edit()
            .putString(KEY_SCHEMA, com.vault.storage.VaultCodec.json.encodeToString(com.vault.model.AutofillExclusions.serializer(), normalized))
            .remove(KEY_PACKAGES).remove(KEY_HOSTS).commit()) { com.vault.ui.localizeUiTextFor(context, "自动填充排除项缓存保存失败") }
    }

    fun excludedPackages(context: Context, vaultKey: String = com.vault.security.CurrentVaultKey.current()): Set<String> = snapshot(context, vaultKey).packages.toSet()
    fun excludedHosts(context: Context, vaultKey: String = com.vault.security.CurrentVaultKey.current()): Set<String> = snapshot(context, vaultKey).hosts.toSet()

    fun addPackage(context: Context, packageName: String) = edit(context, "packages", packageName, false)
    fun addHost(context: Context, host: String) = edit(context, "hosts", host, false)
    fun removePackage(context: Context, packageName: String) = edit(context, "packages", packageName, true)
    fun removeHost(context: Context, host: String) = edit(context, "hosts", host, true)

    @Synchronized
    private fun edit(context: Context, category: String, value: String, deleted: Boolean) {
        val vaultKey = com.vault.security.CurrentVaultKey.current()
        replace(context, snapshot(context, vaultKey).edit(category, value, deleted), vaultKey)
    }

    fun isExcluded(context: Context, origin: TargetOrigin, vaultKey: String = com.vault.security.CurrentVaultKey.current()): Boolean = when (origin) {
        is TargetOrigin.AndroidPackage -> origin.packageName.lowercase() in excludedPackages(context, vaultKey)
        is TargetOrigin.Web -> normalizeExcludedHost(origin.host) in excludedHosts(context, vaultKey)
    }
}
