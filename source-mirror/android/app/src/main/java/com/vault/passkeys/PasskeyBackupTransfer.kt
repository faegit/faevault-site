package com.vault.passkeys

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/** Backup helpers for directly syncable Passkeys stored inside the encrypted vault. */
object PasskeyBackupTransfer {
    fun containsSyncable(entries: List<Entry>): Boolean = entries.any { entry ->
        entry.passkeyModules().any { (_, record) -> record.keyMode == PasskeyKeyMode.SYNCABLE }
    }

    fun markBackedUp(entries: List<Entry>): Pair<List<Entry>, Int> {
        var changedCount = 0
        val updated = entries.map { entry ->
            val modules = entry.fields[EntryModules.FIELD_KEY] as? JsonArray ?: return@map entry
            var changed = false
            val rewritten = modules.map { element ->
                val module = element as? JsonObject ?: return@map element
                if (EntryModules.primitive(module["type"]) != ModuleType.PASSKEY) return@map element
                val record = (module["value"] as? JsonObject)?.let(PasskeyRecord::parse) ?: return@map element
                if (record.keyMode != PasskeyKeyMode.SYNCABLE || record.backupState) return@map element
                val backedUp = record.copy(backupState = true)
                require(PasskeyRecord.parse(backedUp.toJson()) != null)
                changed = true
                changedCount++
                JsonObject(module.toMutableMap().also { it["value"] = backedUp.toJson() })
            }
            if (!changed) entry else entry.copy(
                fields = entry.fields + (EntryModules.FIELD_KEY to JsonArray(rewritten)),
            )
        }
        return updated to changedCount
    }

    private fun Entry.passkeyModules(): List<Pair<JsonObject, PasskeyRecord>> =
        ((fields[EntryModules.FIELD_KEY] as? JsonArray).orEmpty()).mapNotNull { element ->
            val module = element as? JsonObject ?: return@mapNotNull null
            if (EntryModules.primitive(module["type"]) != ModuleType.PASSKEY) return@mapNotNull null
            val record = (module["value"] as? JsonObject)?.let(PasskeyRecord::parse) ?: return@mapNotNull null
            module to record
        }
}
