package com.vault.ui

import com.vault.security.PasswordFinding
import com.vault.ui.screens.wrappedTimeWheelCandidates
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class UiTextTest {
    private fun assertNoChinese(label: String, value: String) {
        assertFalse("$label contains Chinese: $value", value.any { it in '\u3400'..'\u9fff' })
    }

    @Test fun supportedLocalesCoverDetailSettingsSecurityEditAndModules() {
        val copy = listOf(
            "用户名", "密码", "网址", "创建时间", "修改", "编辑", "删除", "复制",
            "账户设置", "安全", "备份与导出", "局域网同步", "密码健康", "高风险", "需改进", "未发现问题", "已泄露", "已过期", "即将到期",
            "条目名称", "标签", "备注", "附加内容", "添加模块", "删除模块",
            "选择动态码", "选择 Wi-Fi 网络", "强制敏感", "选择关联应用", "高级选项",
            "需要权限", "生成", "添加图片", "分享 Wi-Fi 二维码", "移入回收站",
        )
        copy.forEach { source -> assertNotEquals("en is missing $source", source, localizeUiText(source, "en")) }
    }

    @Test fun pendingCardAndPasskeyCopyIsLocalizedInEnglish() {
        val copy = mapOf(
            "自定义卡证名称" to "Custom card or document name",
            "拍照识别身份证" to "Scan ID card",
            "暂无同步型 Passkey" to "No syncable Passkeys yet",
        )

        copy.forEach { (source, expected) ->
            assertEquals("en translation for $source", expected, localizeUiText(source, "en-US"))
        }
    }

    @Test fun booleanAndDateTimeModulesAreFullyLocalizedInEnglish() {
        val copy = mapOf(
            "布尔值" to "Boolean",
            "日期时间" to "Date and time",
            "选择日期" to "Choose date",
        )

        copy.forEach { (source, expected) ->
            assertEquals("en translation for $source", expected, localizeUiText(source, "en-US"))
        }
    }

    @Test fun linkedAutofillDetailCopyIsLocalizedInEnglish() {
        val copy = mapOf(
            "关联自动填充内容" to "Linked autofill content",
            "来源不可用" to "Source unavailable",
            "查看详情" to "View details",
        )

        copy.forEach { (source, expected) ->
            assertEquals("en translation for $source", expected, localizeUiText(source, "en-US"))
        }
    }

    @Test fun dynamicCountsAndSecuritySummaryAreLocalized() {
        assertNotEquals("共 12 条", localizeUiText("共 12 条", "en"))
        assertNotEquals("高风险 3", localizeUiText("高风险 3", "en"))
        assertNotEquals("未发现问题 7", localizeUiText("未发现问题 7", "en"))
        assertNoChinese("healthy legend", "${localizeUiText("安全", "en")} 7")
        assertNotEquals("7 个未发现问题", localizeUiText("7 个未发现问题", "en"))
        assertNotEquals("共检测 10 个含密码条目", localizeUiText("共检测 10 个含密码条目", "en"))
        assertNotEquals("联系：test@example.com", localizeUiText("联系：test@example.com", "en"))
    }

    @Test fun everySecurityRingLabelIsLocalized() {
        PasswordFinding.entries.forEach { finding ->
            assertNotEquals(
                "en is missing ring label ${finding.label}",
                finding.label,
                localizeUiText(finding.label, "en"),
            )
        }
    }

    @Test fun wrappedTimeWheelCandidatesWrapAroundAtBothEnds() {
        assertEquals(listOf(21, 22, 23, 0, 1), wrappedTimeWheelCandidates(23, 24))
        assertEquals(listOf(22, 23, 0, 1, 2), wrappedTimeWheelCandidates(0, 24))
        assertEquals(listOf(57, 58, 59, 0, 1), wrappedTimeWheelCandidates(59, 60))
        assertEquals(listOf(58, 59, 0, 1, 2), wrappedTimeWheelCandidates(0, 60))
    }

    @Test fun englishSliderAndSyncLabelsDoNotRetainChineseUnits() {
        val interval = localizeUiText("每天", "en-US")
        val idleDuration = localizeUiText("5 分钟", "en-US")
        val retention = localizeUiText("2 个月", "en-US")
        val recheck = localizeUiText("每 3 周", "en-US")
        val rendered = listOf(
            localizeUiText("同步周期  ·  $interval", "en-US"),
            localizeUiText("空闲 $idleDuration 后锁定", "en-US"),
            localizeUiText("超过 $retention 的条目将被自动彻底删除", "en-US"),
            localizeUiText("超过 $recheck 后重新检测", "en-US"),
            localizeUiText("30 秒后清理", "en-US"),
            localizeUiText("2 分钟后隐藏", "en-US"),
            localizeUiText("下次预计：07-27 12:00", "en-US"),
        )

        rendered.forEachIndexed { index, value -> assertNoChinese("slider/sync label $index", value) }
    }

    @Test fun englishUiDoesNotLeakChineseAcrossMajorFlows() {
        val copy = listOf(
            "保险库维护",
            "回收站为空",
            "将彻底删除全部 12 条，此操作不可恢复。",
            "生成强密码",
            "保存恢复单",
            "使用恢复密钥",
            "连接 WebDAV",
            "云端已有保险库数据",
            "敏感内容二次保护",
            "选择要解锁的保险库",
            "主密码错误，还可尝试 3 次",
            "生物识别解锁失败",
            "选择登录账号",
            "未找到精确匹配，可手动选择",
            "已保存登录条目",
            "凭据未发生变化，无需保存",
            "正在验证 PIN 码…",
            "PIN 码错误，还可尝试 4 次",
            "PIN 码连续错误 5 次，连接已断开",
            "已检测到文档，按下方按钮拍摄",
            "框内有多个有效二维码，请只保留一个",
            "两端保险库的密钥版本号不一致：本端 v2，远端 v3，但密码一致。请选择同步策略：",
            "同步前本地 4 项 · 同步后 6 项 · 远端 12 KB",
            "上传远端：成功 · 读回校验：通过",
            "密钥已复制。第 1 组 PMRK1 是格式标识，不参与校验；以下序号按完整密钥从左到右计算，每组从 5 个候选中选择。",
            "恢复单已保存或分享。第 1 组 PMRK1 是格式标识，不参与校验；以下序号按完整密钥从左到右计算，每组从 5 个候选中选择。",
            "每天",
            "自动同步完成",
            "下次预计：07-27 12:00",
            "密码为空",
            "自动填充",
            "30 秒",
            "5 分钟",
            "2 个月",
            "3 周",
            "14 天",
            "每 2 个月",
            "每 3 周",
            "每 14 天",
            "正在下载更新…",
            "正在校验安装包…",
            "正在准备安装…",
            "下载更新失败",
            "安装包签名与当前版本不一致，已取消安装",
            "安装包信息无效",
            "更新包版本无效",
            "未找到可安装 APK 的应用",
            "需要允许安装未知应用后才能安装更新",
            "去开启",
            "重试",
            "已开始安装，完成后请重新打开保险库",
        )
        copy.forEach { source ->
            val english = localizeUiText(source, "en-US")
            assertNotEquals("en is missing $source", source, english)
            assertNoChinese(source, english)
        }
    }
}
