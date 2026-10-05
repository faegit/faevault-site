package com.vault.security
import android.content.Context

/**
 * "读取已安装应用列表"的同意标记。
 *
 * 注：原先持久化授权，被用户指出不符合"权限可关闭"的合规要求。现已改为每次询问，
 * 此类只保留是否曾经历史授权过的标记（仅用于清理旧 prefs，未来可删除）。
 */
object AppListConsentPref {
    private const val PREF = "pmv_app_list_consent"

    fun clearLegacy(context: Context) {
        SecurePreferences.get(context.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))
            .edit().clear().apply()
    }
}
