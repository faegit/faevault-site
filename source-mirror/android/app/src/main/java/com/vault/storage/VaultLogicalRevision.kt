package com.vault.storage

import com.vault.model.Entry
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.security.MessageDigest

/** Stable logical state hash that deliberately excludes per-save encryption randomness. */
object VaultLogicalRevision {
    fun from(payload: VaultPayload): String {
        val canonical = payload.copy(
            version = 0,
            entries = (payload.entries + payload.trash).sortedBy(Entry::id).map(::canonicalEntry),
            trash = emptyList(),
            purgeTombstones = payload.purgeTombstones.toSortedMap(),
            exportEpoch = null,
        )
        return MessageDigest.getInstance("SHA-256")
            .digest(VaultCodec.json.encodeToString(VaultPayload.serializer(), canonical).encodeToByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun canonicalEntry(entry: Entry): Entry = entry.copy(
        tags = entry.tags.sorted(),
        fields = entry.fields.toSortedMap().mapValues { canonicalJson(it.value) },
    )

    private fun canonicalJson(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(value.toSortedMap().mapValues { canonicalJson(it.value) })
        is JsonArray -> JsonArray(value.map(::canonicalJson))
        else -> value
    }
}
