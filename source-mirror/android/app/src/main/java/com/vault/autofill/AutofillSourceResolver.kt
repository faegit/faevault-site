package com.vault.autofill

import com.vault.model.AutofillFieldRef
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.autofill.AutofillFieldPolicy
import com.vault.model.autofill.AutofillPolicy
import com.vault.model.autofill.AutofillRole
import com.vault.model.autofillLinks
import com.vault.model.entryModules
import com.vault.model.getStringField
import com.vault.model.otpDisplaySnapshot
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

data class ResolvedAutofillValue(
    val role: AutofillRole,
    val value: String,
    val sourceEntryId: String,
    val moduleId: String?,
    val sourceKey: String,
    val requiresVerification: Boolean,
)

data class AutofillSnapshot(
    val values: Map<AutofillRole, ResolvedAutofillValue>,
    val unavailableRoles: Set<AutofillRole>,
) {
    fun valueFor(role: AutofillRole, verificationGranted: Boolean): String? = values[role]
        ?.takeIf { verificationGranted || !it.requiresVerification }
        ?.value

    fun requiresVerification(): Boolean = values.values.any(ResolvedAutofillValue::requiresVerification)
}

object AutofillSourceResolver {
    fun sourceValues(entry: Entry, nowEpochSeconds: Long = System.currentTimeMillis() / 1000): List<ResolvedAutofillValue> =
        entryValues(entry, nowEpochSeconds)

    fun resolve(entry: Entry, entries: List<Entry>, nowEpochSeconds: Long): AutofillSnapshot {
        val byId = entries.filter { it.deletedAt == null }.associateBy(Entry::id) + (entry.id to entry)
        val values = linkedMapOf<AutofillRole, ResolvedAutofillValue>()
        val unavailable = linkedSetOf<AutofillRole>()
        entryValues(entry, nowEpochSeconds).forEach { values.putIfAbsent(it.role, it) }

        entry.autofillLinks().forEach { link ->
            val source = byId[link.sourceEntryId]
            link.fields.forEach { ref ->
                val resolved = resolveRef(source, ref, nowEpochSeconds)
                if (resolved == null) {
                    values.remove(ref.role)
                    unavailable += ref.role
                } else {
                    values[ref.role] = resolved
                    unavailable -= ref.role
                }
            }
        }
        return AutofillSnapshot(values.toMap(), unavailable.toSet())
    }

    private fun entryValues(entry: Entry, now: Long): List<ResolvedAutofillValue> = buildList {
        listOf("username" to entry.username, "password" to entry.password).forEach { (key, value) ->
            AutofillFieldPolicy.forTopLevel(key)?.takeIf { value.isNotEmpty() }?.let {
                add(resolved(entry.id, null, key, value, it))
            }
        }
        entry.entryModules().forEach { addAll(moduleValues(entry.id, it, now)) }
        addAll(builtInFieldValues(entry, now))
    }

    /**
     * Built-in category editors still persist their dedicated fields at the entry top level.
     * Expose those values through the same policy table as modules so a whole card, Wi-Fi,
     * API, server, or OTP entry can be selected as an external autofill source.
     */
    private fun builtInFieldValues(entry: Entry, now: Long): List<ResolvedAutofillValue> = buildList {
        fun addField(moduleType: String, storedKey: String, policyKey: String = storedKey) {
            val value = entry.getStringField(storedKey)
            val policy = AutofillFieldPolicy.forField(moduleType, policyKey)
            if (value.isNotEmpty() && policy != null) {
                add(resolved(entry.id, null, storedKey, value, policy))
            }
        }

        when (entry.secretType) {
            SecretType.CARD_DOCUMENT -> listOf(
                "full_name",
                "id_number",
                "cardholder",
                "card_number",
                "expiry",
                "cvv",
            ).forEach { addField(ModuleType.CARD_DOCUMENT, it) }

            SecretType.WIFI -> listOf("ssid", "wifi_password", "admin_password")
                .forEach { addField(ModuleType.WIFI, it) }

            SecretType.API_KEY -> listOf("api_key", "api_secret")
                .forEach { addField(ModuleType.API_CREDENTIAL, it) }

            SecretType.SERVER -> listOf(
                Triple("server_host", "host", ModuleType.SERVER_CONNECTION),
                Triple("server_port", "port", ModuleType.SERVER_CONNECTION),
                Triple("server_user", "username", ModuleType.SERVER_CONNECTION),
                Triple("server_pass", "password", ModuleType.SERVER_CONNECTION),
            ).forEach { (storedKey, policyKey, moduleType) -> addField(moduleType, storedKey, policyKey) }

            SecretType.OTP -> {
                val code = entry.otpDisplaySnapshot(now)?.code.orEmpty()
                val policy = AutofillFieldPolicy.forField(ModuleType.OTP, "@computed/one_time_code")
                if (code.isNotEmpty() && policy != null) {
                    add(resolved(entry.id, null, "@computed/one_time_code", code, policy))
                }
            }
        }
    }

    private fun moduleValues(entryId: String, module: JsonObject, now: Long): List<ResolvedAutofillValue> {
        val type = EntryModules.primitive(module["type"])
        val moduleId = EntryModules.primitive(module["id"]).ifEmpty { null }
        val value = module["value"]
        val configured = EntryModules.configuredAutofillRole(module)
        if (type in setOf(ModuleType.TEXT, ModuleType.PASSWORD, ModuleType.DATETIME) && configured != null) {
            val text = (value as? JsonPrimitive)?.contentOrNull.orEmpty()
            if (text.isEmpty()) return emptyList()
            return listOf(
                resolved(
                    entryId,
                    moduleId,
                    "value",
                    text,
                    AutofillPolicy(configured, true, !configured.minimumRequiresVerification, configured.minimumRequiresVerification),
                ),
            )
        }
        if (type == ModuleType.OTP) {
            val temporary = Entry(id = entryId, fields = mapOf(EntryModules.FIELD_KEY to kotlinx.serialization.json.JsonArray(listOf(module))))
            val code = temporary.otpDisplaySnapshot(now)?.code.orEmpty()
            val policy = AutofillFieldPolicy.forField(type, "@computed/one_time_code")
            return if (code.isNotEmpty() && policy != null) {
                listOf(resolved(entryId, moduleId, "@computed/one_time_code", code, policy))
            } else emptyList()
        }
        val compound = value as? JsonObject ?: return emptyList()
        return compound.mapNotNull { (sourceKey, raw) ->
            val text = (raw as? JsonPrimitive)?.contentOrNull.orEmpty()
            val policy = AutofillFieldPolicy.forField(type, sourceKey)
            if (text.isNotEmpty() && policy != null) resolved(entryId, moduleId, sourceKey, text, policy) else null
        }
    }

    private fun resolveRef(source: Entry?, ref: AutofillFieldRef, now: Long): ResolvedAutofillValue? {
        if (source == null) return null
        val candidate = entryValues(source, now).firstOrNull {
            it.moduleId == ref.moduleId && it.sourceKey == ref.sourceKey && it.role == ref.role
        } ?: return null
        return candidate.copy(
            requiresVerification = ref.role.enforceRequiresVerification(ref.requiresVerification),
        )
    }

    private fun resolved(
        entryId: String,
        moduleId: String?,
        sourceKey: String,
        value: String,
        policy: AutofillPolicy,
    ) = ResolvedAutofillValue(
        policy.role,
        value,
        entryId,
        moduleId,
        sourceKey,
        policy.requiresVerification,
    )
}
