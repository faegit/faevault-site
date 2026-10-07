package com.vault.storage

import com.vault.model.*
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class VaultHistoryRestoreTest {
    @Test fun previewModelsNeverExposeHistoricalSecrets() {
        val rows = VaultHistoryRestore.previewEntries(listOf(Entry(id = "a", title = "Account", username = "user", password = "secret", fields = mapOf("token" to JsonPrimitive("secret")), notes = "secret")))
        assertEquals("user", rows.single().username)
        assertEquals("", rows.single().password)
        assertTrue(rows.single().fields.isEmpty())
        assertEquals("", rows.single().notes)
    }
    @Test fun selectedRestoreKeepsNewEntriesAndCreatesNewerChanges() {
        val old = Entry(id = "a", title = "old", updatedAt = 1.0)
        val fresh = Entry(id = "b", title = "keep", updatedAt = 20.0)
        val current = VaultPayload(entries = listOf(old.copy(title = "new", updatedAt = 10.0), fresh))
        val restored = VaultHistoryRestore.plan(current, VaultPayload(entries = listOf(old)), setOf("a"), 5.0)
        assertEquals("old", restored.entries.first { it.id == "a" }.title)
        assertEquals(fresh, restored.entries.first { it.id == "b" })
        assertTrue(restored.entries.first { it.id == "a" }.updatedAt > 20.0)
        assertEquals(current.syncMeta, restored.syncMeta)
    }
    @Test fun selectiveRestoreImportsHistoricalMediaAfterCompaction() {
        val file = java.io.File.createTempFile("history-current-", ".pmv").also { it.delete() }
        val history = java.io.File.createTempFile("history-old-", ".pmv")
        val password = "history-test".encodeToByteArray()
        val root = PmvVaultStore.create(file, password, ByteArray(32),
            PmvEPayloadAdapter.toMetadata(VaultPayload(), java.util.UUID(0, 0)), emptyList()).use { it.copyRootKeyForDeviceUnlock() }
        val id = java.util.UUID.randomUUID()
        val imageId = java.util.UUID.randomUUID()
        val plain = "historical image bytes".repeat(5000).encodeToByteArray()
        try {
            PmvVaultStore.openRootKey(file, root).use { live ->
                live.applyMutation(live.identity().sequence, listOf(PmvVaultStore.ObjectImport(
                    java.io.ByteArrayInputStream(plain), plain.size.toLong(), imageId, 1, PmvAttachmentCodec.Kind.IMAGE))) { refs ->
                    val ref = refs.single().let { PmvMediaRef.Ref(it.objectId, it.generation, it.kind, it.size, it.sha256) }
                    PmvVaultStore.MutationContent(live.readMetadata(), listOf(Entry(id = id.toString(), title = "photo", fields = mapOf("images" to JsonArray(listOf(ref.toJson()))))))
                }
                file.copyTo(history, overwrite = true)
                live.saveFull(live.readMetadata(), listOf(Entry(id = id.toString(), title = "changed")), live.identity().sequence)
                live.compact()
                PmvVaultStore.openRootKey(history, root).use { source ->
                    val old = requireNotNull(source.readEntry(id))
                    val current = requireNotNull(live.readEntry(id))
                    val payload = VaultHistoryRestore.plan(VaultPayload(entries = listOf(current)), VaultPayload(entries = listOf(old)), setOf(id.toString()), 100.0)
                    live.saveMerged(source, live.readMetadata(), payload.entries, live.identity().sequence)
                }
                live.compact()
                val restored = java.io.ByteArrayOutputStream()
                live.openObject(imageId, 1, restored)
                assertArrayEquals(plain, restored.toByteArray())
            }
        } finally {
            root.fill(0); file.delete(); history.delete()
            java.io.File(file.parentFile, "${file.name}.writer.lock").delete()
        }
    }

    @Test fun retentionDoesNotDiscardTheSnapshotBeingRestored() {
        fun pin(id: Int, safety: Boolean = false) = buildJsonObject {
            put("id", id.toString()); put("created_at", id); put("protected_at", id); put("protected", safety)
        }
        val pins = (1..21).map { pin(it) } + (22..24).map { pin(it, true) }
        val kept = VaultHistoryRetention.keep(pins, "22")
        assertTrue(kept.any { it["id"]?.jsonPrimitive?.content == "22" })
        assertEquals(20, kept.count { it["protected"]?.jsonPrimitive?.boolean == false })
        assertEquals(2, VaultHistoryRetention.keep(pins).count { it["protected"]?.jsonPrimitive?.boolean == true })
    }
}
