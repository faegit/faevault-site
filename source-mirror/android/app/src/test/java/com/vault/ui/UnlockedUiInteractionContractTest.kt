package com.vault.ui

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class UnlockedUiInteractionContractTest {
    @Test
    fun `unlocked pager allows horizontal swipe navigation`() {
        val source = source("app/src/main/java/com/vault/ui/screens/UnlockedShell.kt")

        assertTrue(source.contains("userScrollEnabled = true"))
    }

    @Test
    fun `duplicate password groups use the active theme color`() {
        val source = source("app/src/main/java/com/vault/ui/screens/SecurityEntryListScreen.kt")

        assertTrue(source.contains("color = MaterialTheme.colorScheme.primary"))
    }

    @Test
    fun `lan transfer composer sets explicit text and cursor color`() {
        // BasicTextField 不读 LocalContentColor：textStyle.color 为 Unspecified 时
        // TextPainter 直接落回 Color.Black，深色模式下正文变黑；cursorBrush 默认值
        // 也硬编码 SolidColor(Color.Black)。两者都必须显式指定，否则深色模式不可读。
        val source = source("app/src/main/java/com/vault/ui/screens/SettingsScreen.kt")
        val composer = source.substringAfter("private fun LanTransferComposer(")
            .substringBefore("\nprivate fun ", "\n@Composable")

        assertTrue(composer.contains("color = MaterialTheme.colorScheme.onSurface"))
        assertTrue(composer.contains("cursorBrush = SolidColor(MaterialTheme.colorScheme.primary)"))
    }

    @Test
    fun `change password fields expose independent visibility controls`() {
        val source = source("app/src/main/java/com/vault/ui/screens/SettingsScreen.kt")
        val dialog = source.substringAfter("private fun ChangePasswordDialog(")
            .substringBefore("private fun ExportBackupDialog(")

        assertTrue(dialog.contains("var showPw by remember"))
        assertTrue(dialog.contains("var showPw2 by remember"))
        assertTrue(dialog.windowed("VaultVisibilityButton".length)
            .count { it == "VaultVisibilityButton" } >= 2)
    }

    private fun source(path: String): String {
        val candidates = listOf(File(path), File("..", path))
        return candidates.first(File::isFile).readText(Charsets.UTF_8)
    }
}
