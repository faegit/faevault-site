package com.vault.security
import android.content.Context

/**
 * PMVE 自动压缩进度记录：按保险库名保存最近一次压缩时的提交序号、文件字节数与时间，
 * 供解锁后的后台自动压缩判断是否需要再次压缩。
 */
object VaultMaintenancePref {
    private const val PREF = "pmv_maintenance"
    private const val KEY_PREFIX_REVISION = "compact_revision_"
    private const val KEY_PREFIX_SIZE = "compact_size_"
    private const val KEY_PREFIX_AT = "compact_at_"
    private const val KEY_PREFIX_IMPORTED_AT = "imported_at_"

    private fun revisionKey(vaultName: String) = KEY_PREFIX_REVISION + vaultName
    private fun sizeKey(vaultName: String) = KEY_PREFIX_SIZE + vaultName
    private fun atKey(vaultName: String) = KEY_PREFIX_AT + vaultName
    private fun importedAtKey(vaultName: String) = KEY_PREFIX_IMPORTED_AT + vaultName

    fun lastCompactRevision(context: Context, vaultName: String): Long =
        prefs(context).getLong(revisionKey(vaultName), 0L)

    fun lastCompactSize(context: Context, vaultName: String): Long =
        prefs(context).getLong(sizeKey(vaultName), 0L)

    fun lastCompactAt(context: Context, vaultName: String): Long =
        prefs(context).getLong(atKey(vaultName), 0L)

    fun recordCompact(context: Context, vaultName: String, revision: Long, sizeBytes: Long) {
        prefs(context).edit()
            .putLong(revisionKey(vaultName), revision)
            .putLong(sizeKey(vaultName), sizeBytes)
            .putLong(atKey(vaultName), System.currentTimeMillis())
            .apply()
    }

    fun recordImport(context: Context, vaultName: String) {
        prefs(context).edit().putLong(importedAtKey(vaultName), System.currentTimeMillis()).apply()
    }

    fun lastImportAt(context: Context, vaultName: String): Long =
        prefs(context).getLong(importedAtKey(vaultName), 0L)

    private fun prefs(context: Context) =
        SecurePreferences.get(context, vaultPrefName(PREF, CurrentVaultKey.current()))
}
