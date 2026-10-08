package com.vault.storage

import kotlinx.serialization.json.*
import java.util.UUID

/** Durable holder history, independent of device authorization revocation. */
internal object DeletionKnownMembers {
    const val KEY = "_deletion_known_members_v1"
    fun read(metadata: JsonObject): List<String> {
        val raw = metadata[KEY] ?: return emptyList()
        require(raw is JsonArray) { "删除记录设备历史无效" }
        val ids = raw.map { value ->
            val id = (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("删除记录设备历史无效")
            require(runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) { "删除记录设备历史无效" }
            id
        }
        require(ids == ids.distinct().sorted()) { "删除记录设备历史无效" }
        return ids
    }
    private fun rawActivityDeviceIds(metadata: JsonObject): List<String> {
        val raw = metadata[DeviceActivity.KEY] ?: return emptyList()
        require(raw is JsonObject) { "设备活动记录无效，无法安全清理" }
        val version = (raw["version"] as? JsonPrimitive)?.intOrNull
        require(version != null && version >= 1) { "不支持的设备活动记录，请更新应用" }
        if (version > 1) return emptyList() // Preserve the opaque activity object; cleanup rejects its schema.
        val profiles = raw["profiles"]
        require(profiles is JsonArray) { "设备活动记录无效，无法安全清理" }
        return profiles.map { profile ->
            val id = ((profile as? JsonObject)?.get("device_id") as? JsonPrimitive)?.takeIf { it.isString }?.content
            require(id != null && runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) { "设备活动记录无效，无法安全清理" }
            id
        }
    }
    fun retain(metadata: JsonObject, additional: List<String> = emptyList()): JsonObject {
        val ids = (read(metadata) + rawActivityDeviceIds(metadata) +
            PmvDeviceRegistry.decode(metadata).map { it.deviceId.toString() } + additional).distinct().sorted()
        return JsonObject(metadata.toMutableMap().apply { put(KEY, JsonArray(ids.map(::JsonPrimitive))) })
    }
    fun merge(left: JsonObject, right: JsonObject): JsonObject = retain(left, read(retain(right)))
}
