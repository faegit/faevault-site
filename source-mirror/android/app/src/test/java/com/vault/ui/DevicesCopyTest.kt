package com.vault.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Test

class DevicesCopyTest {
    @Test fun systemDeviceNamesAndAuthenticatedRecordsAreAvailableInEnglish() {
        listOf(
            "设备记录", "查看设备记录", "当前设备", "已认证设备记录", "暂无有效授权设备记录", "未知设备",
            "查看保险库中记录的设备、最近活动与授权状态。",
            "设备名称自动读取系统设置；其他设备显示其最近同步的名称。",
            "签名授权有效", "签名授权已过期", "保险库记录中授权已撤销", "无已验证授权记录", "已验证的远端写入设备",
            "设备记录来自已认证的保险库。此处不提供服务器端设备撤销。",
        ).forEach { source ->
            assertFalse(source, localizeUiText(source, "en-US").any { it in '\u3400'..'\u9fff' })
            assertEquals(source, localizeUiText(source, "zh-CN"))
        }
    }
}
