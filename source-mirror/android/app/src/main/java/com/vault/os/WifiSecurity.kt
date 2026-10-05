package com.vault.os

/**
 * Wi-Fi 加密类型跨端统一标准文本（与桌面端 core/modules.py 契约一致）。
 *
 * 落盘/展示/下拉框统一用 [OPTIONS]：每一项就是规范文本本身，不再有"聚合/简化"简写。
 * 外部来源（系统 netsh 的 WPA2-Personal、二维码 T 字段、CSV、旧数据）经 [normalizeSecurity]
 * 精确折叠到对应档位后写入，避免跨端枚举不一致导致下拉框找不到对应项。
 */
object WifiSecurity {
    val OPTIONS = listOf(
        "无加密",
        "WEP",
        "WPA-Personal",
        "WPA2-Personal",
        "WPA2/WPA3-Personal",
        "WPA3-Personal",
        "WPA-Enterprise",
        "WPA2-Enterprise",
        "WPA3-Enterprise",
    )

    private val NORMALIZE = mapOf(
        "" to "无加密",
        "NOPASS" to "无加密",
        "OPEN" to "无加密",
        "开放网络" to "无加密",
        "WEP" to "WEP",
        "WPA" to "WPA-Personal",
        "WPAPSK" to "WPA-Personal",
        "WPA-PERSONAL" to "WPA-Personal",
        "WPA-TKIP" to "WPA-Personal",
        "WPA/WPA2" to "WPA2-Personal",
        "WPA2" to "WPA2-Personal",
        "WPA2PSK" to "WPA2-Personal",
        "WPA2-PERSONAL" to "WPA2-Personal",
        "WPA2-PSK" to "WPA2-Personal",
        "WPA2-AES" to "WPA2-Personal",
        "WPA2/WPA3" to "WPA2/WPA3-Personal",
        "WPA-WPA3" to "WPA2/WPA3-Personal",
        "WPA3" to "WPA3-Personal",
        "SAE" to "WPA3-Personal",
        "WPA3-PERSONAL" to "WPA3-Personal",
        "WPA3-SAE" to "WPA3-Personal",
        "混合加密" to "WPA2/WPA3-Personal",
        "WPA-ENTERPRISE" to "WPA-Enterprise",
        "WPA-EAP" to "WPA-Enterprise",
        "WPA2-ENTERPRISE" to "WPA2-Enterprise",
        "WPA2-EAP" to "WPA2-Enterprise",
        "WPA3-ENTERPRISE" to "WPA3-Enterprise",
        "WPA3-EAP" to "WPA3-Enterprise",
    )

    /** 把任意来源的加密类型映射到统一标准文本；未知值原样返回。 */
    fun normalizeSecurity(value: String?): String {
        if (value.isNullOrBlank()) return "无加密"
        val key = value.trim().uppercase()
        if (key == "无加密") return "无加密"
        return NORMALIZE[key] ?: value.trim()
    }

    /** 分享 Wi-Fi 二维码的 T 字段：WPA 族统一聚合为 WPA（规范通配语义），WEP 精确保留。
     *  密码非空时拒绝 nopass（规范里 nopass 不应携带密码），兜底提升为 WPA。 */
    fun qrAuthToken(security: String?, hasPassword: Boolean): String {
        return when (normalizeSecurity(security)) {
            "WEP" -> "WEP"
            "无加密" -> if (hasPassword) "WPA" else "nopass"
            else -> "WPA"
        }
    }

    /** 保存时对密码/加密类型做一致性校正：有密码时不允许无加密，提升为 WPA2-Personal。 */
    fun coercedForSave(security: String?, password: String?): String {
        val norm = normalizeSecurity(security)
        return if (norm == "无加密" && !password.isNullOrEmpty()) "WPA2-Personal" else norm
    }
}