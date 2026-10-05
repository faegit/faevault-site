package com.vault.ui

import com.vault.security.SecurePreferences
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import com.vault.model.SecretType

/**
 * 主页分类排序配置。
 * 存储为逗号分隔的 type 字符串（如 "login,wifi,credit_card,id_card,api_key,otp"）。
 * 未配置时使用 [defaultOrder]。
 */
object NavOrderPref {
    private const val PREF = "pmv_nav_order"
    private const val KEY_ORDER = "order"

    const val PASSKEY_CATEGORY = SecretType.PASSKEY
    val defaultOrder: List<String> = SecretType.ALL

    val order: MutableState<List<String>> = mutableStateOf(defaultOrder)

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
        val raw = p.getString(KEY_ORDER, null)
        order.value = if (raw != null) normalize(raw.split(",").map { it.trim() }) else defaultOrder
    }

    fun setOrder(context: Context, newOrder: List<String>) {
        val normalized = normalize(newOrder)
        order.value = normalized
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().putString(KEY_ORDER, normalized.joinToString(",")).apply()
    }

    fun reset(context: Context) {
        order.value = defaultOrder
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().remove(KEY_ORDER).apply()
    }

    fun normalize(candidate: List<String>): List<String> {
        val knownTypes = SecretType.ALL
        val known = candidate.filter { it in knownTypes }.distinct()
        return known + knownTypes.filterNot(known::contains)
    }
}
