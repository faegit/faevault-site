package com.vault.storage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudTreeStorageTest {
    @Test
    fun `cloud filename uses account name and removes provider unsafe characters`() {
        val name = CloudTreeStorage.vaultFileName(" Alice/工作:*? ")
        assertTrue(name.startsWith("Alice_工作"))
        assertTrue(name.endsWith(".pmv"))
        assertFalse(name.any { it in "\\/:*?\"<>|" })
    }

    @Test
    fun `blank account name falls back to vault`() {
        assertTrue(CloudTreeStorage.vaultFileName(" . ") == "vault.pmv")
    }
}
