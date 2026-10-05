package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LanImportPolicyTest {
    @Test
    fun `utf8 account name survives export header round trip`() {
        val encoded = LanImportPolicy.encodeAccountName("默认")

        assertEquals("默认", LanImportPolicy.decodeAccountName(encoded, null))
    }

    @Test
    fun `android account name is not treated as a storage filename prefix`() {
        val encoded = LanImportPolicy.encodeAccountName("vault_默认")

        assertEquals("vault_默认", LanImportPolicy.decodeAccountName(encoded, null))
    }

    @Test
    fun `same vault collision requires confirmation instead of silent numbered import`() {
        val resolution = LanImportPolicy.resolveName(
            sourceName = "默认",
            existingNames = setOf("默认"),
            trashedNames = emptySet(),
            sameVaultExistingName = "默认",
        )

        assertEquals("默认2", resolution.targetName)
        assertEquals(LanImportConflictKind.SAME_VAULT, resolution.conflictKind)
        assertEquals("默认", resolution.conflictingName)
    }

    @Test
    fun `different vault with same account name requires confirmation`() {
        val resolution = LanImportPolicy.resolveName(
            sourceName = "默认",
            existingNames = setOf("默认"),
            trashedNames = emptySet(),
            sameVaultExistingName = null,
        )

        assertEquals("默认2", resolution.targetName)
        assertEquals(LanImportConflictKind.SAME_NAME_DIFFERENT_VAULT, resolution.conflictKind)
    }

    @Test
    fun `unused valid source name imports unchanged`() {
        val resolution = LanImportPolicy.resolveName(
            sourceName = "默认",
            existingNames = setOf("工作"),
            trashedNames = emptySet(),
            sameVaultExistingName = null,
        )

        assertEquals("默认", resolution.targetName)
        assertNull(resolution.conflictKind)
    }
}
