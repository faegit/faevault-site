package com.vault.ui.screens

import com.vault.ui.localizeUiText
import com.vault.R
import org.junit.Assert.assertEquals
import org.junit.Test

class PasswordCrackTimeEstimateTest {
    @Test fun veryLowEntropyIsReportedInUnderOneSecond() {
        assertEquals(CrackTime(R.string.entry_remaining_crack_under_second), estimateCrackTime(20.0))
    }

    @Test fun estimatesGrowWithEntropyIntoHumanScaleRanges() {
        assertEquals(CrackTime(R.string.entry_remaining_crack_seconds, "54"), estimateCrackTime(40.0))
        assertEquals(CrackTime(R.string.entry_remaining_crack_years, "1"), estimateCrackTime(60.0))
        assertEquals(CrackTime(R.string.entry_remaining_crack_thousand_years, "191.5"), estimateCrackTime(80.0))
        assertEquals(CrackTime(R.string.entry_remaining_crack_trillion_plus), estimateCrackTime(128.0))
    }

    @Test fun largeValuesUseNaturalChineseUnitsWithRoundedNumbers() {
        // 1.92e6 年 ≈ 191.5 万年（自然中文单位，且不再截断为 1 百万年）
        assertEquals(CrackTime(R.string.entry_remaining_crack_thousand_years, "191.5"), estimateCrackTime(80.0))
        // 1.96e9 年 ≈ 19.6 亿年（保留一位小数）
        assertEquals(CrackTime(R.string.entry_remaining_crack_million_years, "19.6"), estimateCrackTime(90.0))
    }

    @Test fun crackTimeAndClipboardCopyHaveEnglishUiCopy() {
        assertEquals(
            "Estimated crack time: about 12 minutes",
            localizeUiText("预计破解时长：约 12 分钟", "en-US"),
        )
        assertEquals(
            "Estimated crack time: about 191.5 ten-thousand years",
            localizeUiText("预计破解时长：约 191.5 万年", "en-US"),
        )
        assertEquals(
            "Copied “Generated password”; cleaned in 60 seconds",
            localizeUiText("已复制「Generated password」，60 秒后自动清理", "en-US"),
        )
    }
}
