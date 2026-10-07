package com.vault.autofill

import com.vault.model.autofill.AutofillRole
import kotlinx.serialization.json.*

/** Stored inside encrypted entry fields and carried by normal entry synchronization. */
object AutofillFieldMappingMetadata {
    const val FIELD_KEY = "_autofill_field_mappings"
    fun originKey(origin: TargetOrigin): String = when (origin) {
        is TargetOrigin.Web -> "https://${origin.host.lowercase(java.util.Locale.ROOT)}"
        is TargetOrigin.AndroidPackage -> "android:${origin.packageName}"
    }
    private fun timestamp(row: JsonObject): Double =
        (row["updated_at"] as? JsonPrimitive)?.doubleOrNull?.takeIf(Double::isFinite) ?: 0.0

    private val rowOrder = compareBy<JsonObject>(::timestamp)
        .thenBy { (it["deleted"] as? JsonPrimitive)?.booleanOrNull == true }
        .thenBy { (it["role"] as? JsonPrimitive)?.contentOrNull.orEmpty() }

    fun mappings(fields: Map<String, JsonElement>, origin: TargetOrigin): Map<String, String> =
        (fields[FIELD_KEY] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
            .filter { (it["origin"] as? JsonPrimitive)?.contentOrNull == originKey(origin) }
            .mapNotNull { row -> (row["field_key"] as? JsonPrimitive)?.contentOrNull
                ?.takeIf { it.length in 1..256 }?.let { it to row } }
            .groupBy({ it.first }, { it.second }).toSortedMap()
            .mapNotNull { (key, rows) ->
                val row = rows.maxWithOrNull(rowOrder) ?: return@mapNotNull null
                if ((row["deleted"] as? JsonPrimitive)?.booleanOrNull == true) return@mapNotNull null
                val role = (row["role"] as? JsonPrimitive)?.contentOrNull ?: return@mapNotNull null
                if (AutofillRole.fromWire(role) in listOf(null, AutofillRole.NONE)) null else key to role
            }.toMap()

    private fun nextTimestamp(rows: List<JsonElement>): Double =
        maxOf(System.currentTimeMillis().toDouble(), rows.mapNotNull { it as? JsonObject }.maxOfOrNull(::timestamp)
            ?.let { it + 1.0 } ?: 0.0)

    fun add(fields: Map<String, JsonElement>, origin: TargetOrigin, key: String, role: String): Map<String, JsonElement> {
        require(key.length in 1..256 && AutofillRole.fromWire(role) !in listOf(null, AutofillRole.NONE))
        val originKey = originKey(origin)
        val existingRows = (fields[FIELD_KEY] as? JsonArray).orEmpty()
        val updatedAt = nextTimestamp(existingRows)
        val rows = existingRows.filterNot { raw ->
            val row = raw as? JsonObject
            (row?.get("origin") as? JsonPrimitive)?.contentOrNull == originKey &&
                (row["field_key"] as? JsonPrimitive)?.contentOrNull == key
        }
        val row = buildJsonObject {
            put("origin", originKey); put("field_key", key); put("role", role)
            put("updated_at", updatedAt); put("deleted", false)
        }
        return fields + (FIELD_KEY to JsonArray(rows + row))
    }

    fun remove(fields: Map<String, JsonElement>, origin: TargetOrigin): Map<String, JsonElement> {
        val existingRows = (fields[FIELD_KEY] as? JsonArray).orEmpty()
        val updatedAt = nextTimestamp(existingRows)
        val rows = existingRows.map { raw ->
            val row = raw as? JsonObject
            if ((row?.get("origin") as? JsonPrimitive)?.contentOrNull == originKey(origin)) {
                JsonObject(row!! + mapOf("deleted" to JsonPrimitive(true), "updated_at" to JsonPrimitive(updatedAt)))
            } else raw
        }
        return fields + (FIELD_KEY to JsonArray(rows))
    }
}
