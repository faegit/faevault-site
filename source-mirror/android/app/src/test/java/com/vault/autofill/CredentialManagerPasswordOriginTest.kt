package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CredentialManagerPasswordOriginTest {
    @Test
    fun `password origin requires and preserves verified application identity`() {
        val certificate = "A".repeat(64)

        assertNull(credentialManagerPasswordOrigin("com.example.app", emptySet()))
        assertEquals(
            TargetOrigin.AndroidPackage("com.example.app", setOf(certificate.lowercase())),
            credentialManagerPasswordOrigin("com.example.app", setOf(certificate)),
        )
    }
}
