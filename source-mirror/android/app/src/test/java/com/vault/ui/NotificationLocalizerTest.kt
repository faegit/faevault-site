package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class NotificationLocalizerTest {
    @Test fun semanticEnglishNotificationsCoverFixedAndDynamicCopy() {
        assertEquals("Vault file exported", localizeNotification("保险库文件已导出", "en-US"))
        assertEquals("Renamed to “Work”", localizeNotification("已重命名为「Work」", "en-US"))
        assertEquals(
            "Couldn’t complete the operation: network unavailable",
            localizeNotification("云端同步失败：network unavailable", "en-US"),
        )
        assertEquals(
            "Could not connect to the other device. Make sure both devices are on the same local network and keep the transfer station open on the other device.",
            localizeNotification(
                "无法连接对方设备。请确认两台设备连接同一局域网，并保持对方传输站开启。",
                "en-US",
            ),
        )
    }

    @Test fun unsupportedLocalesKeepEstablishedChineseCopy() {
        assertEquals("保险库文件已导出", localizeNotification("保险库文件已导出", "fr-FR"))
    }

    @Test fun englishNotificationsNeverReturnChineseFallbackCopy() {
        val messages = listOf(
            "已删除「Work」，30 天后自动清除（可在账户列表页恢复）",
            "失败次数过多，已锁定 30 秒",
            "加密备份已导出（8 条）",
            "局域网同步已完成",
            "已采用远端密钥，请重新登录",
            "未知内部错误",
        )
        messages.forEach { source ->
            val english = localizeNotification(source, "en-US")
            assertFalse("$source -> $english", english.any { it in '\u3400'..'\u9fff' })
        }
    }
}
