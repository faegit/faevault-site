package com.vault.autofill

import android.content.Context

/**
 * 把应用包名解析为用户可读的应用名称。
 *
 * 解析失败、应用未安装或名称为空/与包名相同（未配置 label 的兜底产物）时返回 null，
 * 由调用方统一回退为显示包名，保证标题在任何异常下都有可用值。
 */
object AppNameResolver {
    fun label(context: Context, packageName: String): String? = runCatching {
        val pm = context.packageManager
        pm.getApplicationInfo(packageName, 0).loadLabel(pm).toString()
            .takeIf { it.isNotBlank() && !it.equals(packageName, ignoreCase = true) }
    }.getOrNull()
}
