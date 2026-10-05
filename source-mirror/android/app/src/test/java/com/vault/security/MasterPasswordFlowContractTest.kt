package com.vault.security

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MasterPasswordFlowContractTest {
    private fun source(path: String): String = String(Files.readAllBytes(Path.of(path)))

    @Test
    fun `view model protects create change and recovery reset boundaries`() {
        val viewModel = source("src/main/java/com/vault/ui/VaultViewModel.kt")

        assertEquals(4, Regex("acceptsNewMasterPassword\\(").findAll(viewModel).count())
        assertTrue(viewModel.contains("LeakedPasswordCheck.isLeaked"))
        assertTrue(viewModel.contains("weakPasswordConfirmed: Boolean = false"))
    }

    @Test
    fun `all three android entry surfaces require the shared risk confirmation`() {
        val sources = listOf(
            source("src/main/java/com/vault/ui/screens/WelcomeScreen.kt"),
            source("src/main/java/com/vault/ui/screens/SettingsScreen.kt"),
            source("src/main/java/com/vault/ui/AppRoot.kt"),
        )

        sources.forEach { assertTrue(it.contains("WeakMasterPasswordConfirmDialog")) }
    }
}
