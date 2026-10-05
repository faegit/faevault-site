package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Test

class VaultLogicalRevisionTest {
    @Test
    fun `revision ignores encryption epoch entry order and map order`() {
        val first = VaultPayload(
            entries = listOf(
                Entry(id = "b", title = "B", tags = listOf("two", "one"), fields = linkedMapOf(
                    "z" to JsonPrimitive("last"),
                    "a" to JsonObject(linkedMapOf("y" to JsonPrimitive(2), "x" to JsonPrimitive(1))),
                )),
                Entry(id = "a", title = "A"),
            ),
            purgeTombstones = linkedMapOf("z" to 2.0, "a" to 1.0),
            syncMeta = SyncMeta("vault"),
            exportEpoch = 100.0,
        )
        val second = first.copy(
            entries = first.entries.reversed().map { entry ->
                if (entry.id != "b") entry else entry.copy(
                    tags = entry.tags.reversed(),
                    fields = entry.fields.entries.reversed().associate { it.toPair() },
                )
            },
            purgeTombstones = first.purgeTombstones.entries.reversed().associate { it.toPair() },
            exportEpoch = 200.0,
        )

        assertEquals(VaultLogicalRevision.from(first), VaultLogicalRevision.from(second))
    }

    @Test
    fun `revision ignores format version and legacy trash storage`() {
        val deleted = Entry(id = "deleted", title = "Deleted", deletedAt = 20.0, updatedAt = 20.0)
        val current = VaultPayload(
            version = 2,
            entries = listOf(deleted),
            syncMeta = SyncMeta("vault"),
        )
        val legacy = current.copy(version = 1, entries = emptyList(), trash = listOf(deleted))

        assertEquals(VaultLogicalRevision.from(current), VaultLogicalRevision.from(legacy))
    }

    @Test
    fun `revision survives encrypted vault round trip`() {
        val payload = VaultPayload(
            entries = listOf(
                Entry(
                    id = "entry",
                    title = "Example",
                    username = "user",
                    password = "secret",
                    tags = listOf("two", "one"),
                    createdAt = 10.0,
                    updatedAt = 20.0,
                    fields = mapOf("nested" to JsonObject(mapOf("value" to JsonPrimitive("data")))),
                ),
            ),
            purgeTombstones = mapOf("removed" to 30.0),
            syncMeta = SyncMeta("vault"),
        )

        val encoded = VaultCodec.json.encodeToString(VaultPayload.serializer(), payload)
        val decoded = VaultCodec.json.decodeFromString<VaultPayload>(encoded)

        assertEquals(VaultLogicalRevision.from(payload), VaultLogicalRevision.from(decoded))
    }
}
