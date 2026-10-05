package com.vault

import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import org.junit.Assert.*
import org.junit.Test

class VaultOpsMultiTagTest {
    private fun entry(id: String) = Entry(id = id, title = id, createdAt = 1.0, updatedAt = 1.0, tags = listOf("old"))

    @Test fun addsAllSelectedTagsWithoutDuplicatesAndPreservesExcludedEntries() {
        val entries = listOf(entry("a"), entry("b"), entry("deleted").copy(deletedAt = 2.0),
            entry("passkey").copy(secretType = SecretType.PASSKEY), entry("unselected"))
        val payload = VaultPayload(entries = entries)
        val result = VaultOps.updateEntryTags(payload, setOf("a", "b", "deleted", "passkey"),
            listOf("one", " two ", "one", "old", ""), "add")
        result.entries.take(2).forEach {
            assertEquals(listOf("old", "one", "two"), it.tags)
            assertTrue(it.updatedAt > 1.0)
        }
        // 墓碑不可编辑；Passkey 现在允许打标签（纯元数据），因此不在保留名单里。
        assertEquals(entries[2], result.entries[2])
        assertEquals(listOf("old", "one", "two"), result.entries[3].tags)
        assertEquals(entries[4], result.entries[4])
        assertSame(result, VaultOps.updateEntryTags(result, setOf("a", "b"), listOf("one", "two"), "add"))
    }

    @Test fun blankSelectionDoesNotModifyPayloadAndSingleMoveStillReplacesTags() {
        val payload = VaultPayload(entries = listOf(entry("a")))
        assertSame(payload, VaultOps.updateEntryTags(payload, setOf("a"), listOf("", " "), "add"))
        assertEquals(listOf("new"), VaultOps.updateEntryTags(payload, setOf("a"), "new", "move").entries.single().tags)
    }
}
