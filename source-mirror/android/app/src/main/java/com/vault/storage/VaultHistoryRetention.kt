package com.vault.storage

import kotlinx.serialization.json.*

internal object VaultHistoryRetention {
    fun keep(pins: List<JsonObject>, preserveId: String? = null): List<JsonObject> {
        val ordinary = pins.filter { it["protected"]?.jsonPrimitive?.booleanOrNull != true }.takeLast(20)
        val safety = pins.filter { it["protected"]?.jsonPrimitive?.booleanOrNull == true }
            .sortedBy { it["protected_at"]?.jsonPrimitive?.longOrNull ?: it["created_at"]?.jsonPrimitive?.longOrNull ?: 0 }.takeLast(2)
        val ids = (ordinary + safety).map { it.getValue("id").jsonPrimitive.content }.toSet() + listOfNotNull(preserveId)
        return pins.filter { it.getValue("id").jsonPrimitive.content in ids }
    }
}
