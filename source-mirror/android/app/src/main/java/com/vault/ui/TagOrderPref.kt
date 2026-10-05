package com.vault.ui

import com.vault.security.SecurePreferences
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 登录标签排序配置。
 * 存储为逗号分隔的标签名列表，只记录用户调整过的顺序。
 * 未配置时保持字母序；新出现的标签自动按字母序追加到已有顺序之后。
 */
object TagOrderPref {
    private const val PREF = "pmv_tag_order"
    private const val KEY_ORDER = "order"

    val order: MutableState<List<String>> = mutableStateOf(emptyList())

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
        val raw = p.getString(KEY_ORDER, null)
        order.value = if (raw != null) normalize(raw.split(",").map { it.trim() }) else emptyList()
    }

    fun setOrder(context: Context, newOrder: List<String>) {
        val normalized = normalize(newOrder)
        order.value = normalized
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().putString(KEY_ORDER, normalized.joinToString(",")).apply()
    }

    fun normalize(candidate: List<String>): List<String> =
        candidate.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
}
