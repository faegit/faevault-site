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

    fun removeBinding(fields: Map<String, JsonElement>, origin: TargetOrigin): Map<String, JsonElement> {
        fun matches(raw: JsonObject): Boolean = when (origin) {
            is TargetOrigin.Web -> (raw["kind"] as? JsonPrimitive)?.contentOrNull == "web" &&
                OriginMatcher.webHost((raw["host"] as? JsonPrimitive)?.contentOrNull.orEmpty()) == origin.host &&
                ((raw["origin"] as? JsonPrimitive)?.contentOrNull?.let { value ->
                    runCatching { java.net.URI(value).port in setOf(-1, 443) }.getOrDefault(false)
                } ?: true)
            is TargetOrigin.AndroidPackage -> (raw["kind"] as? JsonPrimitive)?.contentOrNull == "android" &&
                (raw["package"] as? JsonPrimitive)?.contentOrNull == origin.packageName
        }
        val retained = bindingObjects(fields).filterNot(::matches)
        val result = fields.toMutableMap()
        result.remove(FIELD_KEY)
        result.remove(BINDINGS_FIELD_KEY)
        if (retained.isNotEmpty()) {
            result[BINDINGS_FIELD_KEY] = JsonArray(retained)
            result[FIELD_KEY] = retained.last()
        }
        return result
    }

    /** Android receives a host, not a verified page port; explicit nondefault-port origins cannot authorize it. */
    fun webHosts(entry: Entry): List<String> = bindingObjects(entry.fields).mapNotNull { raw ->
        if ((raw["kind"] as? JsonPrimitive)?.contentOrNull != "web" ||
            (raw["deleted"] as? JsonPrimitive)?.contentOrNull == "true") return@mapNotNull null
        val host = (raw["host"] as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf(String::isNotEmpty)
            ?: return@mapNotNull null
        val explicitOrigin = (raw["origin"] as? JsonPrimitive)?.contentOrNull
        val uri = runCatching { java.net.URI(explicitOrigin ?: "https://$host") }.getOrNull()
            ?: return@mapNotNull null
        if (uri.scheme != "https" || uri.port !in setOf(-1, 443) || uri.rawUserInfo != null ||
            OriginMatcher.webHost(uri.toString()) != OriginMatcher.webHost(host)) return@mapNotNull null
        host
    }.distinct()

    fun androidIdentities(entry: Entry): List<AndroidIdentity> = bindingObjects(entry.fields)
        .filterNot { (it["deleted"] as? JsonPrimitive)?.contentOrNull == "true" }.mapNotNull(::androidIdentity)
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
