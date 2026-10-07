package com.vault.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Test

class DevicesHistoryCopyTest {
    @Test fun authenticationAndRestoreConsequencesAreAvailableInEnglish() {
        listOf(
            "设备与历史版本", "当前设备", "已认证设备记录", "设备昵称已保存",
            "签名授权有效", "签名授权已过期", "保险库记录中授权已撤销", "无已验证授权记录", "已验证的远端写入设备",
            "历史版本预览需验证；若主密码已更改，请输入该版本使用的密码。",
            "历史主密码（可选）", "此版本没有可恢复条目", "确认恢复所选条目",
            "同ID条目将以历史内容恢复。会先保存恢复前版本，并保留当前其他条目。",
            "所选条目已恢复，恢复前版本已保存",
            "设备记录来自已认证的保险库。此处不提供服务器端设备撤销。",
        ).forEach { source ->
            assertFalse(source, localizeUiText(source, "en-US").any { it in '\u3400'..'\u9fff' })
            assertEquals(source, localizeUiText(source, "zh-CN"))
        }
    }
}
