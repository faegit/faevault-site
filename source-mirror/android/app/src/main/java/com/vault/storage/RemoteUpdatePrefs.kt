package com.vault.storage

import android.content.Context
import org.json.JSONArray

object RemoteUpdatePrefs {
    private fun prefs(context: Context) = com.vault.security.SecurePreferences.get(context, "remote_updates")
    private fun key(vault: String, target: String) = "${AutoCloudSyncPrefs.suffix(vault)}_$target"
    fun load(context: Context, vault: String, target: String): RemoteUpdateState {
        val p = prefs(context); val k = key(vault, target)
        val history = runCatching { JSONArray(p.getString("${k}_history", "[]")) }.getOrDefault(JSONArray())
        return RemoteUpdateState(p.getBoolean("${k}_enabled", false),
            p.getString("${k}_baseline", "").orEmpty(), p.getString("${k}_pending", "").orEmpty(),
            (0 until history.length()).mapNotNull { (history.opt(it) as? String)?.takeIf(String::isNotBlank) }.takeLast(32),
            p.getLong("${k}_detected", 0), p.getLong("${k}_checked", 0))
    }
    fun save(context: Context, vault: String, target: String, state: RemoteUpdateState) {
        val k = key(vault, target)
        prefs(context).edit().putBoolean("${k}_enabled", state.enabled)
            .putString("${k}_baseline", state.baseline).putString("${k}_pending", state.pending)
            .putString("${k}_history", JSONArray(state.notified).toString())
            .putLong("${k}_detected", state.detectedAt).putLong("${k}_checked", state.lastCheckedAt).apply()
    }
    fun associate(context: Context, vault: String, target: String, association: String) {
        val p = prefs(context); val k = "${key(vault, target)}_association"
        if (p.getString(k, "") == association) return
        val enabled = load(context, vault, target).enabled
        save(context, vault, target, RemoteUpdateState(enabled = enabled))
        p.edit().putString(k, association).apply()
    }
}
