package com.vault.storage

import com.vault.security.SecurePreferences
import android.content.Context
import java.security.MessageDigest

data class AutoCloudSyncSettings(
    val enabled: Boolean,
    val target: String,
    val intervalMinutes: Int,
    val enabledAt: Long,
    val lastSuccess: Long,
    val failures: Int,
    val status: String,
)

data class CloudSyncStoredStatus(
    val lastSuccessAt: Long = 0L,
    val target: String = "",
    val error: String = "",
)

data class AutoCloudTargetStatus(val status: String, val failures: Int)

/** WebDAV 检测预览的远端版本缓存：ETag 未变化时复用本地缓存文件，避免重复整包下载。 */
data class WebDavPreviewCache(val etag: String = "", val size: Long = -1L)

object AutoCloudSyncPrefs {
    val intervals = listOf(15, 30, 60, 180, 360, 1_440, 10_080)
    val labels = listOf("15分钟", "30分钟", "1小时", "3小时", "6小时", "每天", "每周")

    private fun prefs(context: Context) = SecurePreferences.get(context, "cloud_sync")

    fun suffix(vaultId: String): String = MessageDigest.getInstance("SHA-256")
        .digest(vaultId.toByteArray()).take(12).joinToString("") { "%02x".format(it) }

    fun key(vaultId: String, name: String) = "${name}_${suffix(vaultId)}"

    fun isDue(settings: AutoCloudSyncSettings, now: Long): Boolean {
        val base = maxOf(settings.enabledAt, settings.lastSuccess)
        return settings.enabled && (base <= 0L || now >= base + settings.intervalMinutes * 60_000L)
    }

    /**
     * 读取单个同步目标（`drive` / `webdav`）的自动同步设置。
     *
     * 自动同步会同时观察两个目标，而 [load] 只返回当前选定的那一个；这里必须按目标
     * 显式读取，并保留与 [load] 相同的旧键回退，否则从单目标时代迁移来的用户会
     * 因缺少 `{target}_enabled` 而被误判为未启用。判定一律交给 [isDue]，避免调用方
     * 自行重算周期而产生第二份逻辑。
     */
    fun loadTarget(
        context: Context,
        vaultId: String,
        target: String,
    ): AutoCloudSyncSettings {
        val p = prefs(context)
        return buildTargetSettings(
            target = target,
            enabled = p.getBoolean(key(vaultId, "${target}_enabled"), p.getBoolean(key(vaultId, "auto_enabled"), false)),
            intervalMinutes = p.getInt(key(vaultId, "${target}_interval"), 60),
            enabledAt = p.getLong(key(vaultId, "${target}_enabled_at"), p.getLong(key(vaultId, "auto_enabled_at"), 0L)),
            lastSuccess = p.getLong(key(vaultId, "${target}_last_success"), 0L),
            failures = p.getInt(key(vaultId, "${target}_failures"), 0),
            status = p.getString(key(vaultId, "auto_status"), "尚未执行自动同步").orEmpty(),
        )
    }

    /** 归一化单目标设置：间隔必须落在可选档位内，非法值回落到 60 分钟。 */
    internal fun buildTargetSettings(
        target: String,
        enabled: Boolean,
        intervalMinutes: Int,
        enabledAt: Long,
        lastSuccess: Long,
        failures: Int,
        status: String,
    ): AutoCloudSyncSettings = AutoCloudSyncSettings(
        enabled = enabled,
        target = target,
        intervalMinutes = intervalMinutes.takeIf(intervals::contains) ?: 60,
        enabledAt = enabledAt,
        lastSuccess = lastSuccess,
        failures = failures,
        status = status,
    )

    fun load(context: Context, vaultId: String): AutoCloudSyncSettings {
        val p = prefs(context)
        val target = p.getString(key(vaultId, "auto_target"), "").orEmpty()
        return buildTargetSettings(
            target = target,
            enabled = p.getBoolean(key(vaultId, "${target}_enabled"), p.getBoolean(key(vaultId, "auto_enabled"), false)),
            intervalMinutes = p.getInt(key(vaultId, "${target}_interval"), 60),
            enabledAt = p.getLong(key(vaultId, "${target}_enabled_at"), p.getLong(key(vaultId, "auto_enabled_at"), 0L)),
            lastSuccess = p.getLong(key(vaultId, "${target}_last_success"), 0L),
            failures = p.getInt(key(vaultId, "${target}_failures"), 0),
            status = p.getString(key(vaultId, "auto_status"), "尚未执行自动同步").orEmpty(),
        )
    }

    fun loadSyncStatus(context: Context, vaultId: String): CloudSyncStoredStatus {
        val p = prefs(context)
        return CloudSyncStoredStatus(
            lastSuccessAt = p.getLong(key(vaultId, "sync_last_success"), 0L),
            target = p.getString(key(vaultId, "sync_last_target"), "").orEmpty(),
            error = p.getString(key(vaultId, "sync_last_error"), "").orEmpty(),
        )
    }

    fun save(context: Context, vaultId: String, enabled: Boolean, target: String, intervalMinutes: Int) {
        val p = prefs(context)
        val now = System.currentTimeMillis()
        val wasEnabled = p.getBoolean(key(vaultId, "${target}_enabled"), false)
        val edit = p.edit()
            .putBoolean(key(vaultId, "${target}_enabled"), enabled)
            .putString(key(vaultId, "auto_target"), target)
            .putInt(key(vaultId, "${target}_interval"), intervalMinutes.takeIf(intervals::contains) ?: 60)
        if (enabled && !wasEnabled) {
            edit.putLong(key(vaultId, "${target}_enabled_at"), now)
            edit.putLong(key(vaultId, "auto_enabled_at"), now)
        }
        // 兼容键：主开关 = 任一目标已开启，避免单个目标的开关互相覆盖。
        val otherTarget = if (target == "drive") "webdav" else "drive"
        val anyEnabled = enabled || p.getBoolean(key(vaultId, "${otherTarget}_enabled"), false)
        edit.putBoolean(key(vaultId, "auto_enabled"), anyEnabled)
        edit.apply()
    }

    fun success(context: Context, vaultId: String, status: String, target: String = "") {
        val t = target.ifBlank { load(context, vaultId).target }
        val now = System.currentTimeMillis()
        prefs(context).edit()
            .putLong(key(vaultId, "${t}_last_success"), now)
            .putInt(key(vaultId, "${t}_failures"), 0)
            .putString(key(vaultId, "auto_status"), status)
            .putString(key(vaultId, "${t}_auto_status"), status)
            .putLong(key(vaultId, "sync_last_success"), now)
            .putString(key(vaultId, "sync_last_target"), t)
            .remove(key(vaultId, "sync_last_error"))
            .apply()
    }

    fun recordFailure(context: Context, vaultId: String, target: String, message: String) {
        prefs(context).edit()
            .putString(key(vaultId, "sync_last_target"), target)
            .putString(key(vaultId, "sync_last_error"), message)
            .apply()
    }

    fun loadTargetStatus(context: Context, vaultId: String, target: String): AutoCloudTargetStatus {
        val p = prefs(context)
        return AutoCloudTargetStatus(
            status = p.getString(key(vaultId, "${target}_auto_status"),
                p.getString(key(vaultId, "auto_status"), "尚未执行自动同步")).orEmpty(),
            failures = p.getInt(key(vaultId, "${target}_failures"), 0),
        )
    }

    fun clearFailure(context: Context, vaultId: String) {
        prefs(context).edit().remove(key(vaultId, "sync_last_error")).apply()
    }

    fun skipped(context: Context, vaultId: String, status: String, target: String = "") {
        val edit = prefs(context).edit().putString(key(vaultId, "auto_status"), status)
        if (target.isNotBlank()) edit.putString(key(vaultId, "${target}_auto_status"), status)
        edit.apply()
    }

    fun saveWebDavPreviewCache(context: Context, vaultId: String, etag: String, size: Long) {
        prefs(context).edit()
            .putString(key(vaultId, "webdav_preview_etag"), etag)
            .putLong(key(vaultId, "webdav_preview_size"), size)
            .apply()
    }

    fun loadWebDavPreviewCache(context: Context, vaultId: String): WebDavPreviewCache {
        val p = prefs(context)
        return WebDavPreviewCache(
            etag = p.getString(key(vaultId, "webdav_preview_etag"), "").orEmpty(),
            size = p.getLong(key(vaultId, "webdav_preview_size"), -1L),
        )
    }

    fun failure(context: Context, vaultId: String, status: String, target: String = ""): Int {
        val t = target.ifBlank { load(context, vaultId).target }
        val p = prefs(context)
        val count = p.getInt(key(vaultId, "${t}_failures"), 0) + 1
        val edit = p.edit()
            .putInt(key(vaultId, "${t}_failures"), count)
            .putString(key(vaultId, "auto_status"), status)
            .putString(key(vaultId, "${t}_auto_status"), status)
        if (count >= 3) edit.putBoolean(key(vaultId, "${t}_enabled"), false)
        edit.apply()
        return count
    }
}
