package com.vault.ui

import android.content.Context
import java.security.MessageDigest

internal const val MAX_DETAIL_SCROLL_POSITION = 10_000_000

internal fun sanitizeDetailScrollPosition(position: Int): Int =
    position.coerceIn(0, MAX_DETAIL_SCROLL_POSITION)

internal fun detailScrollPreferenceKey(entryId: String): String {
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(entryId.toByteArray(Charsets.UTF_8))
        .joinToString("") { byte -> "%02x".format(byte) }
    return "entry_$digest"
}

internal object EntryDetailScrollPositionPref {
    // v2：语义从「verticalScroll 像素」迁移为「LazyColumn item 索引」，
    // 换键以隔离历史像素值（避免一次性错误跳转到列表尾部）
    private const val PREFS = "entry_detail_scroll_positions_v2"

    fun read(context: Context, entryId: String): Int = sanitizeDetailScrollPosition(
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(detailScrollPreferenceKey(entryId), 0),
    )

    fun write(context: Context, entryId: String, position: Int) {
        // 同步写盘：进程被杀/立即退出也不丢失最后位置
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(detailScrollPreferenceKey(entryId), sanitizeDetailScrollPosition(position))
            .commit()
    }
}
