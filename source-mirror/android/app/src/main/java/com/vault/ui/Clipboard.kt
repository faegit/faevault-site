package com.vault.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.widget.Toast
import com.vault.R
import com.vault.storage.ClipboardTtlPref
import java.util.UUID

/** 内部标签，用来在 TTL 到期时识别"还是我们之前写入的那份内容"。 */
private const val SENSITIVE_TAG = "pmv:sensitive"

/** 待清理元数据：进程被杀/返回桌面再回前台后，仍能按过期时刻补偿清理。 */
private const val CLEANUP_PREF = "pmv_clipboard_cleanup"
private const val KEY_TAG = "tag"
private const val KEY_EXPIRES_AT = "expires_at"

private val mainHandler = Handler(Looper.getMainLooper())

/** 主线程上挂起的定时清理，便于再次复制时取消旧任务。 */
private var pendingClear: Runnable? = null

/**
 * 复制敏感文本到剪贴板。
 *  - Android 13+ 标记 IS_SENSITIVE，让系统预览/历史里隐藏明文
 *  - 到期后若剪贴板还是同一份内容则自动清理（防止久留泄露）
 *  - 清理时刻持久化到本地：后台无法读取/清空剪贴板（API 29+），
 *    回前台时由 sweepClipboardOnForeground 补偿执行
 */
fun copySensitive(context: Context, label: String, value: String) {
    val localizedLabel = localizeUiTextFor(context, label)
    if (value.isEmpty()) {
        Toast.makeText(context, context.getString(R.string.clipboard_empty, localizedLabel), Toast.LENGTH_SHORT).show()
        return
    }
    writeSensitiveClip(context, ClipData.newPlainText(localizedLabel, value))
    val ttlSec = ClipboardTtlPref.seconds.value
    Toast.makeText(context, if (ttlSec <= 0)
        context.getString(R.string.clipboard_copied_no_ttl, localizedLabel)
    else context.getString(R.string.clipboard_copied_ttl, localizedLabel, ttlSec), Toast.LENGTH_SHORT).show()
}

/** Text and image copies share ownership tagging and expiration. */
internal fun writeSensitiveClip(context: Context, clip: ClipData) {
    val app = context.applicationContext
    val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    // 随机 tag 而不是哈希：识别"仍是本应用写入的内容"更可靠，也不泄露明文指纹
    val tag = UUID.randomUUID().toString()
    val extras = PersistableBundle().apply {
        putString(SENSITIVE_TAG, tag)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    clip.description.extras = extras
    cm.setPrimaryClip(clip)
    pendingClear?.let(mainHandler::removeCallbacks)
    pendingClear = null

    val ttlSec = ClipboardTtlPref.seconds.value
    if (ttlSec <= 0) {
        dropCleanup(app)
        return
    }
    val expiresAt = System.currentTimeMillis() + ttlSec * 1000L
    recordCleanup(app, tag, expiresAt)
    scheduleClear(app, tag, expiresAt)
}

/**
 * 回前台补偿：应用切到前台时调用。
 *  - 过期时刻未到：重新挂起定时清理（进程可能被系统回收，原任务已丢失）
 *  - 过期时刻已到且剪贴板仍是我们写的内容：立即清理并丢弃记录
 */
fun sweepClipboardOnForeground(context: Context) {
    val app = context.applicationContext
    val p = app.getSharedPreferences(CLEANUP_PREF, Context.MODE_PRIVATE)
    val tag = p.getString(KEY_TAG, null) ?: return
    val expiresAt = p.getLong(KEY_EXPIRES_AT, 0L)
    if (expiresAt <= 0L) return
    if (System.currentTimeMillis() < expiresAt) {
        scheduleClear(app, tag, expiresAt)
        return
    }
    val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    if (clearIfStillOurs(cm, tag)) dropCleanup(app)
}

private fun recordCleanup(app: Context, tag: String, expiresAt: Long) {
    app.getSharedPreferences(CLEANUP_PREF, Context.MODE_PRIVATE)
        .edit()
        .putString(KEY_TAG, tag)
        .putLong(KEY_EXPIRES_AT, expiresAt)
        .apply()
}

private fun dropCleanup(app: Context) {
    app.getSharedPreferences(CLEANUP_PREF, Context.MODE_PRIVATE)
        .edit()
        .remove(KEY_TAG)
        .remove(KEY_EXPIRES_AT)
        .apply()
}

private fun scheduleClear(app: Context, tag: String, expiresAt: Long) {
    pendingClear?.let { mainHandler.removeCallbacks(it) }
    val runnable = Runnable {
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        pendingClear = null
        val currentTag = app.getSharedPreferences(CLEANUP_PREF, Context.MODE_PRIVATE).getString(KEY_TAG, null)
        if (currentTag == tag && clearIfStillOurs(cm, tag)) dropCleanup(app)
    }
    pendingClear = runnable
    mainHandler.postDelayed(runnable, (expiresAt - System.currentTimeMillis()).coerceAtLeast(0L))
}

private fun clearIfStillOurs(cm: ClipboardManager, expectedTag: String): Boolean = cleanOwnedClipboard(
    expectedTag = expectedTag,
    readOwner = { cm.primaryClipDescription?.let { ClipboardOwner(it.extras?.getString(SENSITIVE_TAG)) } },
    clear = {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) cm.clearPrimaryClip()
        else cm.setPrimaryClip(ClipData.newPlainText("", ""))
    },
)
