package com.vault.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AppearanceLocalePopupTest {
    @Test
    fun appearanceDropdownStateIsRecreatedWhenLocaleChanges() {
        val source = sequenceOf(
            File("src/main/java/com/vault/ui/screens/SettingsScreen.kt"),
            File("app/src/main/java/com/vault/ui/screens/SettingsScreen.kt"),
        ).first(File::isFile).readText()

        assertTrue(source.contains("var expanded by remember(localeTag) { mutableStateOf(false) }"))
        assertTrue(source.contains("var languageExpanded by remember(localeTag) { mutableStateOf(false) }"))
    }
}
