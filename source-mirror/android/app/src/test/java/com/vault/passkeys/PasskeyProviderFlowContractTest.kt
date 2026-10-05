package com.vault.passkeys

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class PasskeyProviderFlowContractTest {
    @Test
    fun lockedProviderPublishesDirectEntryAndKeepsBiometricInsideVault() {
        val service = source("FAEVaultCredentialProviderService.kt")
        val activity = source("PasskeyCredentialActivity.kt")

        assertTrue(service.contains("builder.addCredentialEntry(directPasskeyEntry)"))
        assertTrue(service.contains("MODE_GET_DISCOVERABLE"))
        assertTrue(activity.contains("MODE_GET_DISCOVERABLE -> finishGetDiscoverable(session)"))
        assertFalse(activity.contains("setBiometricPromptData("))
        assertTrue(activity.contains("biometric.unlock(this@PasskeyCredentialActivity)"))
    }

    private fun source(name: String): String = sequenceOf(
        File("src/main/java/com/vault/passkeys/$name"),
        File("app/src/main/java/com/vault/passkeys/$name"),
    ).first(File::isFile).readText()
}
