package com.vault.passkeys

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import com.vault.model.VaultPayload
import com.vault.model.entryModules
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

data class StoredPasskey(
    val entry: Entry,
    val module: JsonObject,
    val record: PasskeyRecord,
) {
    val moduleId: String
        get() = EntryModules.primitive(module["id"])

    val hasUnresolvedKeyConflict: Boolean
        get() = EntryModules.primitive(
            (module["config"] as? JsonObject)?.get("passkeyConflictStatus"),
        ) == "key_mismatch"

    override fun toString(): String = "StoredPasskey(<redacted>)"
}

sealed interface PasskeyMutationResult {
    data class Success(val payload: VaultPayload, val entry: Entry) : PasskeyMutationResult
    data object Duplicate : PasskeyMutationResult
    data object Missing : PasskeyMutationResult
    data object Stale : PasskeyMutationResult
    data object Invalid : PasskeyMutationResult
}

object PasskeyRepository {
    fun find(
        payload: VaultPayload,
        request: GetPasskeyRequest,
        availability: (StoredPasskey) -> PasskeyAvailability = { PasskeyAvailability.AVAILABLE },
    ): List<StoredPasskey> =
        all(payload).filter { stored ->
            !stored.hasUnresolvedKeyConflict &&
                availability(stored) == PasskeyAvailability.AVAILABLE &&
                stored.record.rpId == request.rpId &&
                (
                    request.allowCredentialIds.isEmpty() ||
                        stored.record.credentialId in request.allowCredentialIds
                    )
        }

    fun hasExcludedCredential(
        payload: VaultPayload,
        request: CreatePasskeyRequest,
    ): Boolean = request.excludeCredentialIds.isNotEmpty() &&
        all(payload).any { stored ->
            stored.record.rpId == request.rpId &&
                stored.record.credentialId in request.excludeCredentialIds
        }

    fun all(payload: VaultPayload): List<StoredPasskey> = buildList {
        payload.entries.asSequence()
            .filter { it.deletedAt == null }
            .forEach { entry ->
                entry.entryModules().forEach { module ->
                    if (EntryModules.primitive(module["type"]) != ModuleType.PASSKEY) return@forEach
                    val value = module["value"] as? JsonObject ?: return@forEach
                    val record = PasskeyRecord.parse(value) ?: return@forEach
                    add(StoredPasskey(entry, module, record))
                }
            }
    }

    fun add(
        payload: VaultPayload,
        entry: Entry,
        record: PasskeyRecord,
        moduleId: String? = null,
    ): PasskeyMutationResult {
        if (PasskeyRecord.parse(record.toJson()) == null) return PasskeyMutationResult.Invalid
        if (all(payload).any {
                it.record.rpId == record.rpId &&
                    it.record.credentialId == record.credentialId
            }
        ) {
            return PasskeyMutationResult.Duplicate
        }
        val module = EntryModules.create(ModuleType.PASSKEY).let { raw ->
            JsonObject(raw.toMutableMap().also {
                it["value"] = record.toJson()
                moduleId?.let { id ->
                    require(id.isNotBlank() && id.length <= 128)
                    it["id"] = kotlinx.serialization.json.JsonPrimitive(id)
                }
            })
        }
        val existingModules = EntryModules.normalize(entry.fields[EntryModules.FIELD_KEY])
        val created = entry.copy(
            fields = entry.fields + (
                EntryModules.FIELD_KEY to JsonArray(existingModules + module)
                ),
        )
        return PasskeyMutationResult.Success(
            payload = payload.copy(entries = payload.entries + created),
            entry = created,
        )
    }

    fun update(
        payload: VaultPayload,
        entryId: String,
        moduleId: String,
        expectedCredentialId: String,
        updatedRecord: PasskeyRecord,
        updatedAt: Double,
    ): PasskeyMutationResult {
        if (PasskeyRecord.parse(updatedRecord.toJson()) == null) return PasskeyMutationResult.Invalid
        val existing = payload.entries.firstOrNull { it.id == entryId && it.deletedAt == null }
            ?: return PasskeyMutationResult.Missing
        val rawModules = existing.fields[EntryModules.FIELD_KEY] as? JsonArray
            ?: return PasskeyMutationResult.Missing
        var matched = false
        var invalid = false
        val modules = rawModules.map { element ->
            val module = element as? JsonObject ?: return@map element
            if (
                EntryModules.primitive(module["type"]) != ModuleType.PASSKEY ||
                EntryModules.primitive(module["id"]) != moduleId
            ) {
                return@map element
            }
            val current = (module["value"] as? JsonObject)?.let(PasskeyRecord::parse)
            if (current == null) {
                invalid = true
                return@map element
            }
            if (
                current.credentialId != expectedCredentialId ||
                updatedRecord.credentialId != expectedCredentialId ||
                updatedRecord.rpId != current.rpId ||
                updatedRecord.schemaVersion != current.schemaVersion ||
                updatedRecord.keyMode != current.keyMode ||
                updatedRecord.privateKey != current.privateKey ||
                updatedRecord.deviceBinding != current.deviceBinding ||
                updatedRecord.publicKey != current.publicKey ||
                updatedRecord.algorithm != current.algorithm ||
                updatedRecord.userId != current.userId
            ) {
                return PasskeyMutationResult.Stale
            }
            matched = true
            JsonObject(module.toMutableMap().also { it["value"] = updatedRecord.toJson() })
        }
        if (invalid) return PasskeyMutationResult.Invalid
        if (!matched) return PasskeyMutationResult.Missing
        val changed = existing.copy(
            updatedAt = updatedAt,
            fields = existing.fields + (EntryModules.FIELD_KEY to JsonArray(modules)),
        )
        return PasskeyMutationResult.Success(
            payload = payload.copy(
                entries = payload.entries.map { if (it.id == entryId) changed else it },
            ),
            entry = changed,
        )
    }
}
