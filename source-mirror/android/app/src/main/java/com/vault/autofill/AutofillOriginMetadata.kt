package com.vault.autofill

import com.vault.model.Entry
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

object AutofillOriginMetadata {
    const val FIELD_KEY = "_autofill_origin"
    const val BINDINGS_FIELD_KEY = "_autofill_bindings"

    fun from(origin: TargetOrigin): JsonObject = when (origin) {
        is TargetOrigin.AndroidPackage -> JsonObject(
            mapOf(
                "kind" to JsonPrimitive("android"),
                "package" to JsonPrimitive(origin.packageName),
                "signing_cert_sha256" to JsonArray(
                    origin.signingCertificateSha256.sorted().map(::JsonPrimitive),
                ),
            ),
        )
        is TargetOrigin.Web -> JsonObject(
            mapOf(
                "kind" to JsonPrimitive("web"),
                "host" to JsonPrimitive(origin.host),
                "browser_package" to JsonPrimitive(origin.browserPackageName),
                "browser_signing_cert_sha256" to JsonArray(
                    origin.browserSigningCertificateSha256.sorted().map(::JsonPrimitive),
                ),
            ),
        )
    }

    fun androidIdentity(entry: Entry): AndroidIdentity? {
        return androidIdentities(entry).firstOrNull()
    }

    fun addBinding(fields: Map<String, JsonElement>, origin: TargetOrigin): Map<String, JsonElement> {
        val encoded = from(origin)
        val bindings = bindingObjects(fields).toMutableList()
        if (encoded !in bindings) bindings += encoded
        return fields + mapOf(
            FIELD_KEY to encoded,
            BINDINGS_FIELD_KEY to JsonArray(bindings),
        )
    }

    fun webHosts(entry: Entry): List<String> = bindingObjects(entry.fields).mapNotNull { raw ->
        if ((raw["kind"] as? JsonPrimitive)?.contentOrNull != "web") return@mapNotNull null
        (raw["host"] as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf(String::isNotEmpty)
    }.distinct()

    fun androidIdentities(entry: Entry): List<AndroidIdentity> = bindingObjects(entry.fields).mapNotNull(::androidIdentity)
        .distinct()

    private fun androidIdentity(raw: JsonObject): AndroidIdentity? {
        if ((raw["kind"] as? JsonPrimitive)?.contentOrNull != "android") return null
        val packageName = (raw["package"] as? JsonPrimitive)?.contentOrNull.orEmpty()
        val certificates = (raw["signing_cert_sha256"] as? JsonArray).orEmpty()
            .mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.lowercase() }
            .filterTo(linkedSetOf()) { it.matches(Regex("^[0-9a-f]{64}$")) }
        return packageName.takeIf(String::isNotEmpty)?.let { AndroidIdentity(it, certificates) }
    }

    private fun bindingObjects(fields: Map<String, JsonElement>): List<JsonObject> {
        val bindings = (fields[BINDINGS_FIELD_KEY] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
        val legacy = fields[FIELD_KEY] as? JsonObject
        return (bindings + listOfNotNull(legacy)).distinct()
    }

    data class AndroidIdentity(val packageName: String, val signingCertificateSha256: Set<String>)
}
