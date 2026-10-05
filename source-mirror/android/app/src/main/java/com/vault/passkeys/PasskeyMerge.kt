package com.vault.passkeys

import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.Base64
import java.util.UUID

data class PasskeyMergeResult(
    val modules: List<JsonObject>,
    val hasKeyConflict: Boolean,
    val metadataConflicts: Set<String>,
)

object PasskeyMerge {
    private const val CONFLICT_GROUP = "passkeyConflictGroupId"
    private const val CONFLICT_STATUS = "passkeyConflictStatus"
    private val specialRecordFields = setOf(
        "rp_id",
        "user_id",
        "credential_id",
        "private_key",
        "key_mode",
        "device_binding",
        "public_key",
        "schema_version",
        "counter_mode",
        "sign_count",
        "created_at",
        "last_used_at",
        "discoverable",
        "backup_eligible",
        "backup_state",
    )

    fun merge(
        localModules: List<JsonObject>,
        remoteModules: List<JsonObject>,
    ): PasskeyMergeResult {
        val records = (localModules + remoteModules).map(::readModule)
        val grouped = records.groupBy { it.identity }
        val output = mutableListOf<JsonObject>()
        val metadataConflicts = sortedSetOf<String>()
        var hasKeyConflict = false

        grouped.toSortedMap(compareBy<CredentialIdentity>({ it.rpId }, { it.credentialId }))
            .forEach { (_, identityRecords) ->
                val variants = identityRecords.groupBy { it.keyIdentity }
                    .toSortedMap()
                    .values
                    .map { mergeSameKey(it, metadataConflicts) }
                if (variants.size > 1) {
                    hasKeyConflict = true
                    val groupId = UUID.randomUUID().toString().replace("-", "")
                    variants.forEach { variant ->
                        val config = (variant["config"] as JsonObject).toMutableMap()
                        config[CONFLICT_GROUP] = JsonPrimitive(groupId)
                        config[CONFLICT_STATUS] = JsonPrimitive("key_mismatch")
                        output += JsonObject(variant.toMutableMap().also {
                            it["config"] = JsonObject(config)
                        })
                    }
                } else {
                    output += variants
                }
            }

        return PasskeyMergeResult(
            modules = ensureDistinctModuleIds(output),
            hasKeyConflict = hasKeyConflict,
            metadataConflicts = metadataConflicts,
        )
    }

    private data class CredentialIdentity(
        val rpId: String,
        val credentialId: String,
    )

    private data class ModuleRecord(
        val module: JsonObject,
        val parsed: PasskeyRecord,
        val identity: CredentialIdentity,
        val keyIdentity: String,
    )

    private fun readModule(module: JsonObject): ModuleRecord {
        require(EntryModules.primitive(module["type"]) == ModuleType.PASSKEY)
        require(module["config"] is JsonObject)
        val value = module["value"] as? JsonObject ?: throw IllegalArgumentException("invalid passkey module set")
        val parsed = PasskeyRecord.parse(value) ?: throw IllegalArgumentException("invalid passkey module set")
        return ModuleRecord(
            module = module,
            parsed = parsed,
            identity = CredentialIdentity(
                parsed.rpId,
                canonicalBase64Url(parsed.credentialId),
            ),
            keyIdentity = keyIdentity(parsed),
        )
    }

    private fun keyIdentity(record: PasskeyRecord): String {
        val publicDigest = sha256Hex(decodeBase64Url(record.publicKey))
        val carrier = when {
            record.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION -> "legacy"
            record.keyMode == PasskeyKeyMode.SYNCABLE -> "syncable"
            else -> record.deviceBinding?.let {
                "device:${it.deviceId}:${it.bindingId}:${it.keyGeneration}"
            } ?: "device:missing"
        }
        return "$publicDigest:$carrier"
    }

    private fun mergeSameKey(
        records: List<ModuleRecord>,
        conflicts: MutableSet<String>,
    ): JsonObject {
        val preferred = records.maxWithOrNull(
            compareBy<ModuleRecord>(
                { timestamp(it.parsed.lastUsedAt) },
                { timestamp(it.parsed.createdAt) },
                { it.module.toString() },
            ),
        ) ?: throw IllegalArgumentException("invalid passkey module set")
        val result = preferred.module.toMutableMap()
        val config = (preferred.module["config"] as JsonObject).toMutableMap()
        val value = (preferred.module["value"] as JsonObject).toMutableMap()

        records.filter { it !== preferred }.forEach { record ->
            mergeMap(
                result,
                record.module,
                conflicts,
                prefix = "module.",
                skipped = setOf("id", "type", "value", "config"),
            )
            mergeMap(
                config,
                record.module["config"] as JsonObject,
                conflicts,
                prefix = "config.",
                skipped = setOf(CONFLICT_GROUP, CONFLICT_STATUS),
            )
            mergeMap(
                value,
                record.module["value"] as JsonObject,
                conflicts,
                prefix = "",
                skipped = specialRecordFields,
            )
        }

        value["counter_mode"] = JsonPrimitive(PasskeyRecord.COUNTER_MODE)
        value["sign_count"] = JsonPrimitive("0")
        value["created_at"] = JsonPrimitive(
            records.map { it.parsed.createdAt }.minBy(::timestamp),
        )
        value["last_used_at"] = JsonPrimitive(
            records.map { it.parsed.lastUsedAt }
                .filter(String::isNotEmpty)
                .maxByOrNull(::timestamp)
                .orEmpty(),
        )
        mergeBoolean(value, records, "discoverable") { it.discoverable }
        mergeBoolean(value, records, "backup_eligible") { it.backupEligible }
        mergeBoolean(value, records, "backup_state") { it.backupState }
        require(PasskeyRecord.parse(JsonObject(value)) != null)

        result["config"] = JsonObject(config)
        result["value"] = JsonObject(value)
        return JsonObject(result)
    }

    private fun mergeBoolean(
        value: MutableMap<String, JsonElement>,
        records: List<ModuleRecord>,
        key: String,
        selector: (PasskeyRecord) -> Boolean,
    ) {
        value[key] = JsonPrimitive(records.any { selector(it.parsed) }.toString())
    }

    private fun mergeMap(
        preferred: MutableMap<String, JsonElement>,
        other: JsonObject,
        conflicts: MutableSet<String>,
        prefix: String,
        skipped: Set<String>,
    ) {
        other.toSortedMap().forEach { (key, incoming) ->
            if (key in skipped) return@forEach
            val path = "$prefix$key"
            val current = preferred[key]
            if (current == null || isEmpty(current)) {
                preferred[key] = incoming
            } else if (!isEmpty(incoming) && current != incoming) {
                if (current is JsonObject && incoming is JsonObject) {
                    val nested = current.toMutableMap()
                    mergeMap(nested, incoming, conflicts, "$path.", emptySet())
                    preferred[key] = JsonObject(nested)
                } else {
                    conflicts += path
                }
            }
        }
    }

    private fun ensureDistinctModuleIds(modules: List<JsonObject>): List<JsonObject> {
        val seen = mutableSetOf<String>()
        return modules.mapIndexed { index, module ->
            val existing = EntryModules.primitive(module["id"])
            if (existing.isNotEmpty() && seen.add(existing)) {
                module
            } else {
                val value = module["value"] as JsonObject
                val parsed = PasskeyRecord.parse(value)
                    ?: throw IllegalArgumentException("invalid passkey module set")
                var nonce = 0
                var candidate: String
                do {
                    candidate = sha256Hex(
                        (
                            parsed.rpId + "\u0000" +
                                parsed.credentialId + "\u0000" +
                                parsed.publicKey + "\u0000" +
                                index + "\u0000" +
                                nonce
                            ).toByteArray(),
                    ).take(32)
                    nonce++
                } while (!seen.add(candidate))
                JsonObject(module.toMutableMap().also { it["id"] = JsonPrimitive(candidate) })
            }
        }
    }

    private fun isEmpty(value: JsonElement): Boolean = when (value) {
        is JsonPrimitive -> value.isString && value.content.isEmpty()
        is JsonArray -> value.isEmpty()
        is JsonObject -> value.isEmpty()
    }

    private fun timestamp(value: String): Long = if (value.isEmpty()) {
        Long.MIN_VALUE
    } else {
        OffsetDateTime.parse(value.replace('t', 'T').let {
            if (it.endsWith('z')) it.dropLast(1) + "Z" else it
        }).withOffsetSameInstant(ZoneOffset.UTC).toInstant().toEpochMilli()
    }

    private fun canonicalBase64Url(value: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(decodeBase64Url(value))

    private fun decodeBase64Url(value: String): ByteArray =
        Base64.getUrlDecoder().decode(value.padEnd((value.length + 3) / 4 * 4, '='))

    private fun sha256Hex(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
}
