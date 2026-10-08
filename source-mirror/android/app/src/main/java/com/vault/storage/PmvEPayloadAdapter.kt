package com.vault.storage

import com.vault.model.Entry
import com.vault.model.AutofillExclusions
import com.vault.model.SyncMeta
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.util.UUID

/**
 * Lossless adapter between the current application payload and PMVE metadata plus Entry blocks.
 * Unknown metadata fields are retained by merging known fields into [previousMetadata].
 */
internal object PmvEPayloadAdapter {
    private const val PAYLOAD_VERSION = "payload_version"
    private const val SYNC_KEY_REVISION = "key_revision"
    fun normalizePayload(payload: VaultPayload): VaultPayload {
        val deviceId = payload.syncMeta.deviceId.takeIf { raw ->
            runCatching { UUID.fromString(raw).toString() == raw }.getOrDefault(false)
        } ?: UUID.randomUUID().toString()
        return if (deviceId == payload.syncMeta.deviceId) payload else {
            payload.copy(syncMeta = payload.syncMeta.copy(deviceId = deviceId))
        }
    }

    fun toMetadata(
        payload: VaultPayload,
        vaultId: UUID,
        previousMetadata: JsonObject? = null,
    ): JsonObject {
        val normalized = normalizePayload(payload)
        // 应用内存模型统一以 entries 承载墓碑（deletedAt != null），
        // PMVE 存储按 entry_order/trash_order 分开：这里在边界处拆分，
        // 兼容“墓碑留在 entries”的调用方（VaultOps.delete 等）与显式 trash 列表。
        val alive = normalized.entries.filter { it.deletedAt == null }
        val aliveIds = alive.map(Entry::id).toSet()
        val trash = normalized.trash.filter { it.id !in aliveIds } +
            normalized.entries.filter { it.deletedAt != null }
        require(trash.none { it.deletedAt == null }) { "trash 只能包含已删除条目" }
        val all = alive + trash
        require(all.map(Entry::id).toSet().size == all.size) { "Entry ID 不得重复" }
        all.forEach { entry -> requireCanonicalUuid(entry.id, "Entry ID") }

        val previousSync = previousMetadata?.get("sync_meta") as? JsonObject
        val sync = JsonObject(
            (previousSync?.toMutableMap() ?: linkedMapOf()).apply {
                put("device_id", JsonPrimitive(normalized.syncMeta.deviceId))
                // Keep the logical sync revision inside sync_meta. PMVE's top-level key_revision
                // is also used by the cryptographic header lifecycle and may be normalized by Store.
                put(SYNC_KEY_REVISION, JsonPrimitive(normalized.syncMeta.keyRevision))
                if (normalized.syncMeta.keyUpdatedAt > 0.0) {
                    put("key_updated_at", JsonPrimitive(normalized.syncMeta.keyUpdatedAt))
                }
                if (normalized.syncMeta.keyCreatedAt > 0.0) {
                    put("key_created_at", JsonPrimitive(normalized.syncMeta.keyCreatedAt))
                }
            },
        )
        val result = JsonObject(
            (previousMetadata?.toMutableMap() ?: linkedMapOf()).apply {
                remove("passkey_keyset")
                put("schema", JsonPrimitive(PmvVaultMetadataCodec.SCHEMA))
                put("version", JsonPrimitive(PmvVaultMetadataCodec.VERSION))
                put("vault_id", JsonPrimitive(vaultId.toString()))
                put("entry_order", JsonArray(alive.map { JsonPrimitive(it.id) }))
                put("trash_order", JsonArray(trash.map { JsonPrimitive(it.id) }))
                put("sync_meta", sync)
                put("key_revision", JsonPrimitive(normalized.syncMeta.keyRevision))
                put("export_epoch", normalized.exportEpoch?.let { JsonPrimitive(it) } ?: JsonNull)
                put(
                    "purge_tombstones",
                    JsonObject(normalized.purgeTombstones.mapValues { JsonPrimitive(it.value) }),
                )
                put("deletion_baseline", VaultCodec.json.encodeToJsonElement(com.vault.model.DeletionBaseline.serializer(), normalized.deletionBaseline))
                put(PAYLOAD_VERSION, JsonPrimitive(normalized.version))
                put("autofill_exclusions", VaultCodec.json.encodeToJsonElement(
                    AutofillExclusions.serializer(), normalized.autofillExclusions.normalized(),
                ))
            },
        )
        PmvVaultMetadataCodec.encode(result).fill(0)
        return result
    }

    fun fromMetadata(metadata: JsonObject, storedEntries: List<Entry>): VaultPayload {
        PmvVaultMetadataCodec.encode(metadata).fill(0)
        require(storedEntries.map(Entry::id).toSet().size == storedEntries.size) { "Entry ID 不得重复" }
        val byId = storedEntries.associateBy(Entry::id)
        val entryOrder = orderedIds(metadata, "entry_order")
        val trashOrder = orderedIds(metadata, "trash_order")
        require((entryOrder + trashOrder).toSet() == byId.keys) {
            "Vault Metadata 顺序与 Entry 集合不一致"
        }
        val entries = entryOrder.map { id ->
            requireNotNull(byId[id]) { "entry_order 引用了不存在的 Entry" }.also {
                require(it.deletedAt == null) { "entry_order 不得引用已删除 Entry" }
            }
        }
        val trash = trashOrder.map { id ->
            requireNotNull(byId[id]) { "trash_order 引用了不存在的 Entry" }.also {
                require(it.deletedAt != null) { "trash_order 必须引用已删除 Entry" }
            }
        }
        val sync = metadata.getValue("sync_meta").jsonObject
        val deviceId = sync.getValue("device_id").jsonPrimitive.content.also { raw ->
            requireCanonicalUuid(raw, "sync_meta.device_id")
        }
        val keyRevision = readNonNegativeInt(
            sync[SYNC_KEY_REVISION] ?: metadata.getValue("key_revision"),
            "sync_meta.key_revision",
        )
        val keyUpdatedAt = sync["key_updated_at"]?.let { value ->
            value.jsonPrimitive.doubleOrNull?.also {
                require(it.isFinite() && it >= 0.0) { "sync_meta.key_updated_at 必须为非负有限数字" }
            } ?: 0.0
        } ?: 0.0
        val keyCreatedAt = sync["key_created_at"]?.let { value ->
            value.jsonPrimitive.doubleOrNull?.also {
                require(it.isFinite() && it >= 0.0) { "sync_meta.key_created_at 必须为非负有限数字" }
            } ?: 0.0
        } ?: 0.0
        val exportEpoch = metadata.getValue("export_epoch").let { value ->
            if (value is JsonNull) null else value.jsonPrimitive.doubleOrNull?.also {
                require(it.isFinite() && it >= 0.0) { "export_epoch 必须为非负有限数字" }
            } ?: throw IllegalArgumentException("export_epoch 必须为非负有限数字")
        }
        val purgeTombstones = metadata.getValue("purge_tombstones").jsonObject.mapValues { (id, value) ->
            requireCanonicalUuid(id, "purge_tombstones key")
            value.jsonPrimitive.doubleOrNull?.also {
                require(it.isFinite() && it >= 0.0) { "purge_tombstones[$id] 必须为非负有限数字" }
            } ?: throw IllegalArgumentException("purge_tombstones[$id] 必须为非负有限数字")
        }
        val version = metadata[PAYLOAD_VERSION]?.let {
            readNonNegativeInt(it, PAYLOAD_VERSION)
        } ?: 1
        val exclusions = metadata["autofill_exclusions"]?.let {
            VaultCodec.json.decodeFromJsonElement(AutofillExclusions.serializer(), it).normalized()
        } ?: AutofillExclusions()
        return VaultPayload(
            version = version,
            // 统一回落到应用内存模型：墓碑与活跃条目同放 entries，
            // trash 列表置空（VaultOps / 回收站 / 同步合并都按 entries 读取墓碑）。
            entries = entries + trash,
            trash = emptyList(),
            purgeTombstones = purgeTombstones,
            deletionBaseline = metadata["deletion_baseline"]?.let { VaultCodec.json.decodeFromJsonElement(com.vault.model.DeletionBaseline.serializer(), it) } ?: com.vault.model.DeletionBaseline(),
            syncMeta = SyncMeta(
                deviceId = deviceId,
                keyRevision = keyRevision,
                keyUpdatedAt = keyUpdatedAt,
                keyCreatedAt = keyCreatedAt,
            ),
            exportEpoch = exportEpoch,
            autofillExclusions = exclusions,
        )
    }

    private fun orderedIds(metadata: JsonObject, name: String): List<String> =
        (metadata.getValue(name) as JsonArray).map { value ->
            value.jsonPrimitive.content.also { requireCanonicalUuid(it, name) }
        }

    private fun readNonNegativeInt(value: kotlinx.serialization.json.JsonElement, name: String): Int {
        val primitive = value.jsonPrimitive
        val parsed = primitive.longOrNull
        require(!primitive.isString && parsed != null && parsed in 0..Int.MAX_VALUE.toLong()) {
            "$name 必须为非负 32 位整数"
        }
        return parsed.toInt()
    }

    private fun requireCanonicalUuid(raw: String, name: String) {
        require(runCatching { UUID.fromString(raw).toString() == raw }.getOrDefault(false)) {
            "$name 必须为规范小写 UUID"
        }
    }
}
