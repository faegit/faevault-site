package com.vault.storage

import kotlinx.serialization.json.*

data class DeviceActivityProfile(val deviceId: String, val name: String, val platform: String,
    val lastSeenAt: Long, val updatedAt: Long, val isCurrent: Boolean = false,
    val authorizationStatus: String? = null)

/** Informational activity only; this never grants or revokes device authorization. */
object DeviceActivity {
    const val KEY = "_device_activity_v1"
    fun authorizedProfiles(profiles: List<DeviceActivityProfile>): List<DeviceActivityProfile> =
        profiles.filter { it.authorizationStatus == "authorized" }
    fun profiles(metadata: JsonObject): List<DeviceActivityProfile> =
        ((metadata[KEY] as? JsonObject)?.get("profiles") as? JsonArray).orEmpty().mapNotNull { raw ->
            val obj = raw as? JsonObject ?: return@mapNotNull null
            val id = (obj["device_id"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
            if (runCatching { java.util.UUID.fromString(id) }.isFailure) return@mapNotNull null
            val name = (obj["name"] as? JsonPrimitive)?.contentOrNull ?: ""
            val platform = (obj["platform"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
            if (name.length > 64 || platform !in setOf("android", "pc")) return@mapNotNull null
            DeviceActivityProfile(id, name, platform,
                (obj["last_seen_at"] as? JsonPrimitive)?.longOrNull ?: 0,
                (obj["updated_at"] as? JsonPrimitive)?.longOrNull ?: 0)
        }

    fun merge(left: JsonObject, right: JsonObject): JsonObject {
        val leftVersion = ((left[KEY] as? JsonObject)?.get("version") as? JsonPrimitive)?.intOrNull ?: 1
        val rightVersion = ((right[KEY] as? JsonObject)?.get("version") as? JsonPrimitive)?.intOrNull ?: 1
        if (maxOf(leftVersion, rightVersion) > 1) return JsonObject(left.toMutableMap().apply {
            if (rightVersion > leftVersion) right[KEY]?.let { put(KEY, it) }
        })
        val activity = ((right[KEY] as? JsonObject).orEmpty() + (left[KEY] as? JsonObject).orEmpty()).toMutableMap()
        val profiles = (profiles(left) + profiles(right)).groupBy { it.deviceId }.values.map { group ->
            group.maxWith(compareBy<DeviceActivityProfile> { it.updatedAt }.thenBy { it.name }.thenBy { it.platform })
                .copy(lastSeenAt = group.maxOf { it.lastSeenAt })
        }.sortedBy { it.deviceId }
        activity["version"] = JsonPrimitive(1)
        val rawProfiles = listOf(left, right).flatMap { source ->
            ((source[KEY] as? JsonObject)?.get("profiles") as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
        }
        activity["profiles"] = JsonArray(profiles.map { profile ->
            val unknown = rawProfiles.filter { (it["device_id"] as? JsonPrimitive)?.contentOrNull == profile.deviceId }
                .sortedBy { it.toString() }.fold(emptyMap<String, JsonElement>()) { map, raw -> map + raw }
            JsonObject(unknown + encode(profile))
        })
        val writers = listOfNotNull((left[KEY] as? JsonObject)?.get("last_writer") as? JsonObject,
            (right[KEY] as? JsonObject)?.get("last_writer") as? JsonObject)
        writers.maxWithOrNull(compareBy<JsonObject> { (it["updated_at"] as? JsonPrimitive)?.longOrNull ?: 0 }
            .thenBy { (it["device_id"] as? JsonPrimitive)?.contentOrNull.orEmpty() }
            .thenBy { it.toString() })?.let { activity["last_writer"] = it }
        return JsonObject(left.toMutableMap().apply { put(KEY, JsonObject(activity)) })
    }

    fun touch(metadata: JsonObject, id: String, name: String? = null, now: Long = System.currentTimeMillis(), parentCommitId: String? = null): JsonObject {
        val version = ((metadata[KEY] as? JsonObject)?.get("version") as? JsonPrimitive)?.intOrNull ?: 1
        if (version > 1) {
            return metadata
        }
        require(name == null || name.trim().length in 1..64) { "设备名称须为 1–64 个字符" }
        val current = profiles(metadata).firstOrNull { it.deviceId == id }
        val previousTime = ((metadata[KEY] as? JsonObject)?.get("last_writer") as? JsonObject)
            ?.get("updated_at") as? JsonPrimitive
        val timestamp = maxOf(now, (previousTime?.longOrNull ?: -1L).let { if (it == Long.MAX_VALUE) error("设备活动时间无效") else it + 1 },
            if (name != null) (current?.updatedAt ?: -1L).let { if (it == Long.MAX_VALUE) error("设备名称时间无效") else it + 1 } else 0L)
        val profile = DeviceActivityProfile(id, name?.trim() ?: current?.name ?: "Android", "android", timestamp,
            if (name != null || current == null) timestamp else current.updatedAt)
        val update = buildJsonObject { put(KEY, buildJsonObject {
            put("version", 1); put("profiles", JsonArray(listOf(encode(profile))))
            put("last_writer", buildJsonObject { put("device_id", id); put("updated_at", timestamp)
                parentCommitId?.let { put("parent_commit_id", it) } })
        }) }
        return merge(metadata, update)
    }

    fun writer(metadata: JsonObject, parentCommitId: String?): DeviceActivityProfile? {
        if (((metadata[KEY] as? JsonObject)?.get("version") as? JsonPrimitive)?.intOrNull?.let { it != 1 } == true) return null
        val writer = (metadata[KEY] as? JsonObject)?.get("last_writer") as? JsonObject ?: return null
        if (parentCommitId == null || (writer["parent_commit_id"] as? JsonPrimitive)?.contentOrNull != parentCommitId) return null
        val id = (writer["device_id"] as? JsonPrimitive)?.contentOrNull
        return profiles(metadata).firstOrNull { it.deviceId == id }
    }
    private fun encode(p: DeviceActivityProfile) = buildJsonObject {
        put("device_id", p.deviceId); put("name", p.name); put("platform", p.platform)
        put("last_seen_at", p.lastSeenAt); put("updated_at", p.updatedAt)
    }
}
