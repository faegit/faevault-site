package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class PmvEPayloadAdapterTest {
    private val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
    private val activeFirst = entry("active-first", deletedAt = null)
    private val activeSecond = entry("active-second", deletedAt = null)
    private val trashed = entry("trashed", deletedAt = 123.5)

    @Test
    fun `metadata round trip preserves fields and collapses trash into entries`() {
        val payload = VaultPayload(
            version = 7,
            entries = listOf(activeSecond, activeFirst),
            trash = listOf(trashed),
            purgeTombstones = mapOf(entryId("purged").toString() to 456.75),
            syncMeta = SyncMeta(
                deviceId = UUID.fromString("20000000-0000-4000-8000-000000000002").toString(),
                keyRevision = 9,
            ),
            exportEpoch = 789.25,
        )

        val metadata = PmvEPayloadAdapter.toMetadata(payload, vaultId)
        val restored = PmvEPayloadAdapter.fromMetadata(metadata, listOf(activeFirst, trashed, activeSecond))

        // 应用内存模型：墓碑统一回到 entries，trash 置空
        assertEquals(
            payload.copy(entries = payload.entries + payload.trash, trash = emptyList()),
            restored,
        )
        assertEquals(
            listOf(activeSecond.id, activeFirst.id),
            (metadata.getValue("entry_order") as JsonArray).map { (it as JsonPrimitive).content },
        )
        assertEquals(
            listOf(trashed.id),
            (metadata.getValue("trash_order") as JsonArray).map { (it as JsonPrimitive).content },
        )
    }

    @Test
    fun `key created at is written to sync metadata and survives round trip`() {
        val payload = VaultPayload(
            entries = listOf(activeFirst),
            syncMeta = SyncMeta(
                deviceId = UUID.fromString("60000000-0000-4000-8000-000000000006").toString(),
                keyRevision = 1,
                keyCreatedAt = 1_752_000_000.5,
            ),
        )

        val metadata = PmvEPayloadAdapter.toMetadata(payload, vaultId)
        val sync = metadata.getValue("sync_meta") as JsonObject
        assertEquals(1_752_000_000.5, ((sync["key_created_at"] as JsonPrimitive).content).toDouble(), 0.0)
        assertEquals(
            payload,
            PmvEPayloadAdapter.fromMetadata(metadata, listOf(activeFirst)),
        )
    }

    @Test
    fun `tombstone kept in entries saves as trash order and loads back into entries`() {
        val appModel = VaultPayload(
            entries = listOf(activeFirst, trashed),
            trash = emptyList(),
            syncMeta = SyncMeta(
                deviceId = UUID.fromString("50000000-0000-4000-8000-000000000005").toString(),
                keyRevision = 3,
            ),
        )
        val metadata = PmvEPayloadAdapter.toMetadata(appModel, vaultId)
        assertEquals(
            listOf(activeFirst.id),
            (metadata.getValue("entry_order") as JsonArray).map { (it as JsonPrimitive).content },
        )
        assertEquals(
            listOf(trashed.id),
            (metadata.getValue("trash_order") as JsonArray).map { (it as JsonPrimitive).content },
        )
        val restored = PmvEPayloadAdapter.fromMetadata(metadata, listOf(activeFirst, trashed))
        assertEquals(appModel, restored)
    }

    @Test
    fun `saving known fields preserves unknown top level and sync metadata`() {
        val original = PmvEPayloadAdapter.toMetadata(
            VaultPayload(
                entries = listOf(activeFirst),
                syncMeta = SyncMeta(
                    deviceId = UUID.fromString("30000000-0000-4000-8000-000000000003").toString(),
                    keyRevision = 2,
                ),
            ),
            vaultId,
        ).let { metadata ->
            JsonObject(
                metadata.toMutableMap().apply {
                    put("future_metadata", JsonObject(mapOf("mode" to JsonPrimitive("keep"))))
                    put(
                        "sync_meta",
                        JsonObject(
                            (metadata.getValue("sync_meta") as JsonObject).toMutableMap().apply {
                                put("future_sync_cursor", JsonPrimitive("keep-too"))
                            },
                        ),
                    )
                },
            )
        }
        val changed = VaultPayload(
            entries = listOf(activeSecond),
            syncMeta = SyncMeta(
                deviceId = UUID.fromString("40000000-0000-4000-8000-000000000004").toString(),
                keyRevision = 11,
            ),
        )

        val updated = PmvEPayloadAdapter.toMetadata(changed, vaultId, original)

        assertEquals("keep", ((updated["future_metadata"] as JsonObject)["mode"] as JsonPrimitive).content)
        assertEquals(
            "keep-too",
            (((updated["sync_meta"] as JsonObject)["future_sync_cursor"]) as JsonPrimitive).content,
        )
        assertEquals(changed, PmvEPayloadAdapter.fromMetadata(updated, listOf(activeSecond)))
    }

    @Test
    fun `blank device id is normalized once to a canonical UUID`() {
        val normalized = PmvEPayloadAdapter.normalizePayload(VaultPayload())

        assertTrue(normalized.syncMeta.deviceId.isNotBlank())
        assertEquals(normalized.syncMeta.deviceId, UUID.fromString(normalized.syncMeta.deviceId).toString())
        assertEquals(normalized, PmvEPayloadAdapter.normalizePayload(normalized))
    }

    private fun entry(seed: String, deletedAt: Double?) = Entry(
        id = entryId(seed).toString(),
        title = seed,
        secretType = "login",
        deletedAt = deletedAt,
        updatedAt = 1.0,
    )

    private fun entryId(seed: String): UUID = UUID.nameUUIDFromBytes(seed.encodeToByteArray())
}
