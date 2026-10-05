package com.vault.model

import com.vault.model.autofill.AutofillRole
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

data class AutofillFieldRef(
    val moduleId: String?,
    val sourceKey: String,
    val role: AutofillRole,
    val requiresVerification: Boolean,
)

data class AutofillLink(
    val id: String,
    val sourceEntryId: String,
    val fields: List<AutofillFieldRef>,
)

const val AUTOFILL_LINKS_KEY = "autofill_links"

object AutofillLinkCodec {
    fun decode(element: JsonElement?): List<AutofillLink> {
        val array = element as? JsonArray ?: return emptyList()
        val decoded = array.mapNotNull(::decodeOne)
        val originalIds = decoded.mapTo(mutableSetOf(), AutofillLink::id)
        val seenIds = mutableSetOf<String>()
        val occurrences = mutableMapOf<String, Int>()
        return decoded.mapIndexed { index, link ->
            val occurrence = occurrences.getOrDefault(link.id, 0)
            occurrences[link.id] = occurrence + 1
            if (occurrence == 0) {
                seenIds.add(link.id)
                link
            } else {
                link.copy(id = deterministicReplacementId(link, index, occurrence, originalIds, seenIds))
            }
        }
    }

    fun encode(links: List<AutofillLink>): JsonArray {
        val normalized = decode(JsonArray(links.map(::encodeRawLink)))
        return JsonArray(normalized.map(::encodeRawLink))
    }

    private fun encodeRawLink(link: AutofillLink): JsonObject = JsonObject(
        mapOf(
            "id" to JsonPrimitive(link.id),
            "source_entry_id" to JsonPrimitive(link.sourceEntryId),
            "fields" to JsonArray(link.fields.map(::encodeField)),
        ),
    )

    private fun decodeOne(element: JsonElement): AutofillLink? {
        val value = element as? JsonObject ?: return null
        val id = value.nonBlankString("id") ?: return null
        val sourceEntryId = value.nonBlankString("source_entry_id") ?: return null
        val fields = (value["fields"] as? JsonArray)
            ?.mapNotNull(::decodeField)
            .orEmpty()
        if (fields.isEmpty()) return null
        return AutofillLink(id, sourceEntryId, fields)
    }

    private fun decodeField(element: JsonElement): AutofillFieldRef? {
        val value = element as? JsonObject ?: return null
        val moduleId = when (val raw = value["module_id"]) {
            JsonNull -> null
            is JsonPrimitive -> raw.content.takeIf { raw.isString && it.isNotBlank() } ?: return null
            else -> return null
        }
        val sourceKey = value.nonBlankString("source_key") ?: return null
        val role = value.nonBlankString("role")?.let(AutofillRole::fromWire) ?: return null
        val requestedVerification = when (val raw = value["requires_verification"]) {
            is JsonPrimitive -> raw.booleanOrNull?.takeIf { !raw.isString } ?: return null
            else -> return null
        }
        return AutofillFieldRef(
            moduleId = moduleId,
            sourceKey = sourceKey,
            role = role,
            requiresVerification = role.enforceRequiresVerification(requestedVerification),
        )
    }

    private fun encodeField(field: AutofillFieldRef): JsonObject = JsonObject(
        mapOf(
            "module_id" to (field.moduleId?.let(::JsonPrimitive) ?: JsonNull),
            "source_key" to JsonPrimitive(field.sourceKey),
            "role" to JsonPrimitive(field.role.wire),
            "requires_verification" to JsonPrimitive(
                field.role.enforceRequiresVerification(field.requiresVerification),
            ),
        ),
    )

    private fun JsonObject.nonBlankString(key: String): String? {
        val primitive = this[key] as? JsonPrimitive ?: return null
        if (!primitive.isString) return null
        return primitive.content.takeIf(String::isNotBlank)
    }

    private fun deterministicReplacementId(
        link: AutofillLink,
        index: Int,
        occurrence: Int,
        originalIds: Set<String>,
        seenIds: MutableSet<String>,
    ): String {
        var salt = 0
        while (true) {
            val seed = buildString {
                append("faevault-autofill-link-id-repair-v1|")
                appendSeedPart(link.id)
                appendSeedPart(link.sourceEntryId)
                append(index).append('|').append(occurrence).append('|').append(salt).append('|')
                link.fields.forEach { field ->
                    appendSeedPart(field.moduleId)
                    appendSeedPart(field.sourceKey)
                    appendSeedPart(field.role.wire)
                    append(if (field.requiresVerification) '1' else '0').append('|')
                }
            }
            val candidate = UUID.nameUUIDFromBytes(seed.toByteArray(StandardCharsets.UTF_8)).toString()
            if (candidate !in originalIds && seenIds.add(candidate)) return candidate
            salt += 1
        }
    }

    private fun StringBuilder.appendSeedPart(value: String?) {
        if (value == null) {
            append("null|")
        } else {
            append(value.length).append(':').append(value).append('|')
        }
    }
}

fun Entry.autofillLinks(): List<AutofillLink> = AutofillLinkCodec.decode(fields[AUTOFILL_LINKS_KEY])

fun Entry.withAutofillLinks(links: List<AutofillLink>): Entry {
    val normalized = AutofillLinkCodec.decode(AutofillLinkCodec.encode(links))
    val preserved = fields - OTP_BINDING_KEY - AUTOFILL_LINKS_KEY
    return copy(
        fields = if (normalized.isEmpty()) {
            preserved
        } else {
            preserved + (AUTOFILL_LINKS_KEY to AutofillLinkCodec.encode(normalized))
        },
    )
}

fun Entry.migrateAutofillLinks(): Entry {
    val legacy = (fields[OTP_BINDING_KEY] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?.takeIf(String::isNotBlank)
        ?: return if (OTP_BINDING_KEY in fields) copy(fields = fields - OTP_BINDING_KEY) else this

    val current = autofillLinks()
    val alreadyLinked = current.any { link ->
        link.sourceEntryId == legacy && link.fields.any { field ->
            field.moduleId == null &&
                field.sourceKey == "@computed/one_time_code" &&
                field.role == AutofillRole.ONE_TIME_CODE
        }
    }
    if (alreadyLinked) return withAutofillLinks(current)

    return withAutofillLinks(
        current + AutofillLink(
            id = UUID.randomUUID().toString(),
            sourceEntryId = legacy,
            fields = listOf(
                AutofillFieldRef(
                    moduleId = null,
                    sourceKey = "@computed/one_time_code",
                    role = AutofillRole.ONE_TIME_CODE,
                    requiresVerification = false,
                ),
            ),
        ),
    )
}
