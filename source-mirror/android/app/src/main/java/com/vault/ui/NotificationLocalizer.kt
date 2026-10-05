package com.vault.ui

import java.util.Locale

/** Localizes transient ViewModel notifications, including messages with names or error details. */
internal fun localizeNotification(source: String, languageTag: String = Locale.getDefault().toLanguageTag()): String {
    val locale = when {
        languageTag.startsWith("en", true) -> "en"
        else -> return source
    }
    val fixed = NOTIFICATIONS[locale]?.get(source)
    if (fixed != null) return fixed
    val semantic = localizeUiText(source, languageTag)
    if (semantic != source) return semantic

    val detail = source.substringAfter('：', "").trim()
    if (detail.isNotEmpty() && (source.contains("失败") || source.startsWith("无法") || source.contains("错误"))) {
        val localizedDetail = localizeUiText(detail, languageTag)
        return if (localizedDetail.any { it in '\u3400'..'\u9fff' }) {
            "Couldn’t complete the operation"
        } else {
            "Couldn’t complete the operation: $localizedDetail"
        }
    }
    Regex("^已重命名为「(.+)」$").matchEntire(source)?.groupValues?.get(1)?.let { name ->
        return "Renamed to “$name”"
    }
    Regex("^已恢复「(.+)」$").matchEntire(source)?.groupValues?.get(1)?.let { name ->
        return "Restored “$name”"
    }
    Regex("^已导入到账户「(.+)」$").matchEntire(source)?.groupValues?.get(1)?.let { name ->
        return "Imported into “$name”"
    }
    return if (source.any { it in '\u3400'..'\u9fff' }) "FAEVault operation completed" else source
}

private val NOTIFICATIONS = mapOf(
    "en" to mapOf(
        "已启用生物识别解锁" to "Biometric unlock enabled",
        "主密码已重置，生物识别解锁已关闭" to "Master password reset. Biometric unlock was disabled.",
        "主密码已更新；恢复密钥仍然有效，生物识别解锁已关闭" to "Master password updated. Your recovery key remains valid; biometric unlock was disabled.",
        "保险库文件已导出" to "Vault file exported", "泄露检测已关闭" to "Breach checks are disabled",
        "没有需要检测的条目" to "No items need checking", "恢复密钥已重新生成，旧密钥已失效" to "A new recovery key is active; the previous key no longer works.",
        "已下载覆盖本地保险库并通过读回校验" to "Cloud vault downloaded and verified", "已从 WebDAV 下载覆盖本地保险库并通过读回校验" to "WebDAV vault downloaded and verified",
        "请先关联云端硬盘或 WebDAV" to "Connect cloud storage or WebDAV first", "请先连接 WebDAV" to "Connect WebDAV first",
        "导入文件中未识别到条目" to "No supported items were found in the import file", "账户不存在" to "Vault not found",
        "账户名不合法" to "Enter a valid vault name", "账户已存在" to "A vault with that name already exists",
        "生物识别已变更，原绑定已失效，请用主密码解锁后到「设置 → 启用生物识别解锁」重新绑定" to
            "Your biometric enrollment changed. Unlock with the master password, then enable biometric unlock again in Settings.",
        "生物识别解锁失败" to "Biometric unlock failed",
        "启用生物识别失败" to "Could not enable biometric unlock",
        "无法连接对方设备。请确认两台设备连接同一局域网，并保持对方传输站开启。" to
            "Could not connect to the other device. Make sure both devices are on the same local network and keep the transfer station open on the other device.",
    ),
)
