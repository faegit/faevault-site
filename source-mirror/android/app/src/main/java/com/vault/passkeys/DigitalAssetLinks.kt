package com.vault.passkeys

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

object DigitalAssetLinksDocument {
    private const val RELATION = "delegate_permission/common.get_login_creds"
    private const val MAX_BYTES = 256 * 1024
    private const val MAX_STATEMENTS = 256
    private val packageName = Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$")
    private val json = Json {
        isLenient = false
        allowSpecialFloatingPointValues = false
    }

    fun authorizes(
        raw: String,
        expectedPackageName: String,
        expectedFingerprints: Set<String>,
    ): Boolean {
        require(raw.toByteArray(Charsets.UTF_8).size in 2..MAX_BYTES)
        require(packageName.matches(expectedPackageName))
        require(expectedFingerprints.isNotEmpty())
        val normalizedExpected = expectedFingerprints.map(::normalizeFingerprint).toSet()
        val statements = json.parseToJsonElement(raw) as? JsonArray
            ?: throw IllegalArgumentException("invalid asset links document")
        require(statements.size <= MAX_STATEMENTS)
        return statements.any { element ->
            val statement = element as? JsonObject ?: return@any false
            val relations = statement["relation"] as? JsonArray ?: return@any false
            val hasRelation = relations.any {
                (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content == RELATION
            }
            if (!hasRelation) return@any false
            val target = statement["target"] as? JsonObject ?: return@any false
            if (target.strictString("namespace") != "android_app") return@any false
            if (target.strictString("package_name") != expectedPackageName) return@any false
            val fingerprints = target["sha256_cert_fingerprints"] as? JsonArray ?: return@any false
            val normalizedTarget = fingerprints.mapNotNull {
                (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
            }.map(::normalizeFingerprint).toSet()
            normalizedExpected.all { it in normalizedTarget }
        }
    }

    private fun JsonObject.strictString(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content

    fun normalizeFingerprint(value: String): String {
        val compact = value.replace(":", "").uppercase()
        require(compact.length == 64 && compact.all { it in '0'..'9' || it in 'A'..'F' })
        return compact.chunked(2).joinToString(":")
    }
}

class DigitalAssetLinksVerifier(
    context: Context,
    private val client: OkHttpClient = secureClient(),
) {
    private val preferences = context.applicationContext
        .getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    suspend fun isAuthorized(
        rpId: String,
        packageName: String,
        fingerprints: Set<String>,
    ): Boolean = withContext(Dispatchers.IO) {
        val normalizedFingerprints = fingerprints.map(DigitalAssetLinksDocument::normalizeFingerprint).toSet()
        val cacheKey = cacheKey(rpId, packageName, normalizedFingerprints)
        val now = System.currentTimeMillis()
        val cachedAt = preferences.getLong("$cacheKey.time", 0L)
        val cachedResult = preferences.getString("$cacheKey.result", null)?.toBooleanStrictOrNull()
        val lifetime = if (cachedResult == true) POSITIVE_CACHE_MS else NEGATIVE_CACHE_MS
        if (cachedResult != null && now - cachedAt in 0 until lifetime) {
            return@withContext cachedResult
        }

        val url = HttpUrl.Builder()
            .scheme("https")
            .host(rpId)
            .addPathSegment(".well-known")
            .addPathSegment("assetlinks.json")
            .build()
        val authorized = try {
            client.newCall(
                Request.Builder()
                    .url(url)
                    .header("Accept", "application/json")
                    .build(),
            ).execute().use { response ->
                require(response.request.url == url)
                require(response.isSuccessful)
                val contentType = response.body?.contentType()
                require(contentType?.type == "application" && contentType.subtype == "json")
                val contentLength = response.body?.contentLength() ?: -1L
                require(contentLength < 0 || contentLength <= MAX_DOWNLOAD_BYTES)
                val raw = response.body?.byteStream()?.use(::readBounded)
                    ?: throw IllegalArgumentException("empty asset links document")
                DigitalAssetLinksDocument.authorizes(
                    raw.toString(Charsets.UTF_8),
                    packageName,
                    normalizedFingerprints,
                )
            }
        } catch (_: Exception) {
            false
        }
        preferences.edit()
            .putString("$cacheKey.result", authorized.toString())
            .putLong("$cacheKey.time", now)
            .apply()
        authorized
    }

    private fun readBounded(input: java.io.InputStream): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            require(total <= MAX_DOWNLOAD_BYTES)
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun cacheKey(
        rpId: String,
        packageName: String,
        fingerprints: Set<String>,
    ): String {
        val material = "$rpId\u0000$packageName\u0000${fingerprints.sorted().joinToString(",")}"
        return MessageDigest.getInstance("SHA-256")
            .digest(material.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val PREFERENCES = "passkey_asset_links"
        private const val MAX_DOWNLOAD_BYTES = 256 * 1024L
        private const val POSITIVE_CACHE_MS = 24 * 60 * 60 * 1000L
        private const val NEGATIVE_CACHE_MS = 5 * 60 * 1000L

        private fun secureClient(): OkHttpClient = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}
