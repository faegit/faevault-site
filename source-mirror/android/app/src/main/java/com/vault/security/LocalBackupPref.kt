package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import com.vault.storage.LocalBackupPolicy

/** 本地定期备份配置：目标目录（SAF tree URI）、卷标识、周期、上次备份时间。按保险库（账户）隔离。 */
object LocalBackupPref {
    private const val PREF = "pmv_local_backup"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_TREE_URI = "tree_uri"
    private const val KEY_VOLUME_ID = "volume_id"
    private const val KEY_SAF_ID = "saf_id"
    private const val KEY_DEVICE_UUID = "device_uuid"
    private const val KEY_INTERVAL = "interval_millis"
    private const val KEY_LAST = "last_backup_millis"
    private const val KEY_JOURNAL_SOURCE_SIZE = "journal_source_size"
    private const val KEY_JOURNAL_TARGET = "journal_target"
    private const val KEY_JOURNAL_PARTIAL = "journal_partial"
    private const val KEY_DEVICE_LABEL = "device_label"

    val enabled: MutableState<Boolean> = mutableStateOf(false)
    val intervalMillis: MutableState<Long> = mutableStateOf(LocalBackupPolicy.INTERVAL_DAILY)

    fun init(context: Context, vaultKey: String) {
        val prefs = prefs(context, vaultKey)
        enabled.value = prefs.getBoolean(KEY_ENABLED, false)
        intervalMillis.value = prefs.getLong(
            KEY_INTERVAL,
            LocalBackupPolicy.INTERVAL_DAILY,
        ).takeIf { it in LocalBackupPolicy.INTERVALS } ?: LocalBackupPolicy.INTERVAL_DAILY
    }

    /** Read persisted state so background workers also work after a cold process start. */
    fun isEnabled(context: Context, vaultKey: String): Boolean = prefs(context, vaultKey).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, vaultKey: String, value: Boolean) {
        if (enabled.value == value) return
        enabled.value = value
        prefs(context, vaultKey).edit().putBoolean(KEY_ENABLED, value).apply()
    }

    fun treeUri(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_TREE_URI, null)

    fun safId(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_SAF_ID, null)
        ?: prefs(context, vaultKey).getString(KEY_VOLUME_ID, null)

    /** 兼容旧调用；新代码应使用 [safId]。 */
    fun volumeId(context: Context, vaultKey: String): String? = safId(context, vaultKey)

    fun deviceUuid(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_DEVICE_UUID, null)

    fun setTarget(context: Context, vaultKey: String, treeUri: String, safId: String, deviceUuid: String) {
        prefs(context, vaultKey).edit()
            .putString(KEY_TREE_URI, treeUri)
            .putString(KEY_SAF_ID, safId)
            .putString(KEY_DEVICE_UUID, deviceUuid)
            .remove(KEY_VOLUME_ID)
            .apply()
    }

    /** Read persisted state rather than relying on Compose state initialized by MainActivity. */
    fun interval(context: Context, vaultKey: String): Long = prefs(context, vaultKey).getLong(
        KEY_INTERVAL,
        LocalBackupPolicy.INTERVAL_DAILY,
    ).takeIf { it in LocalBackupPolicy.INTERVALS } ?: LocalBackupPolicy.INTERVAL_DAILY

    fun setInterval(context: Context, vaultKey: String, value: Long) {
        if (intervalMillis.value == value) return
        intervalMillis.value = value
        prefs(context, vaultKey).edit().putLong(KEY_INTERVAL, value).apply()
    }

    fun lastBackupAt(context: Context, vaultKey: String): Long = prefs(context, vaultKey).getLong(KEY_LAST, 0L)

    fun setLastBackupAt(context: Context, vaultKey: String, value: Long) {
        prefs(context, vaultKey).edit().putLong(KEY_LAST, value).apply()
    }

    fun journalSourceSize(context: Context, vaultKey: String): Long = prefs(context, vaultKey).getLong(KEY_JOURNAL_SOURCE_SIZE, 0L)

    fun journalTarget(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_JOURNAL_TARGET, null)

    fun journalPartial(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_JOURNAL_PARTIAL, null)

    fun setJournal(context: Context, vaultKey: String, sourceSize: Long, target: String, partial: String) {
        prefs(context, vaultKey).edit()
            .putLong(KEY_JOURNAL_SOURCE_SIZE, sourceSize)
            .putString(KEY_JOURNAL_TARGET, target)
            .putString(KEY_JOURNAL_PARTIAL, partial)
            .apply()
    }

    fun clearJournal(context: Context, vaultKey: String) {
        prefs(context, vaultKey).edit()
            .remove(KEY_JOURNAL_SOURCE_SIZE)
            .remove(KEY_JOURNAL_TARGET)
            .remove(KEY_JOURNAL_PARTIAL)
            .apply()
    }

    fun deviceLabel(context: Context, vaultKey: String): String? = prefs(context, vaultKey).getString(KEY_DEVICE_LABEL, null)

    fun setDeviceLabel(context: Context, vaultKey: String, value: String?) {
        prefs(context, vaultKey).edit().putString(KEY_DEVICE_LABEL, value).apply()
    }

    private fun prefs(context: Context, vaultKey: String) =
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, vaultKey))
}
