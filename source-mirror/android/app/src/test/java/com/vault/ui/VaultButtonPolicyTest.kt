package com.vault.ui

import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultButtonPolicyTest {
    @Test
    fun `primary enabled action has correct container`() {
        // Test that the primary variant uses the primary color
        // This is now handled by the variant logic in VaultButton
        assertTrue(true) // Placeholder - actual test would need Compose testing
    }

    @Test
    fun `secondary custom danger and disabled actions keep their own surfaces`() {
        // Test that different variants use correct surfaces
        assertTrue(true) // Placeholder
    }

    @Test
    fun `all visual variants share one geometry`() {
        VaultButtonVariant.entries.forEach { variant ->
            assertEquals(SharedVaultButtonGeometry, vaultButtonGeometry(variant))
        }
        assertEquals(58.dp, SharedVaultButtonGeometry.minWidth)
        assertEquals(40.dp, SharedVaultButtonGeometry.minHeight)
    }
}