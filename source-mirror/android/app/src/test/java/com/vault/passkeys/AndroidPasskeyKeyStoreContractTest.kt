package com.vault.passkeys

import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidPasskeyKeyStoreContractTest {
    private val source = String(
        Files.readAllBytes(Path.of("src/main/java/com/vault/passkeys/AndroidPasskeyKeyStore.kt")),
    )

    @Test
    fun `keystore authentication uses KeyProperties flags and declares API 30 boundary`() {
        assertTrue(source.contains("KeyProperties.AUTH_BIOMETRIC_STRONG"))
        assertTrue(source.contains("KeyProperties.AUTH_DEVICE_CREDENTIAL"))
        assertTrue(source.contains("@RequiresApi(Build.VERSION_CODES.R)"))
        assertFalse(source.contains("setUserAuthenticationParameters(0, AUTHENTICATORS)"))
    }
}
