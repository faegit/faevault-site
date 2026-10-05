package com.vault.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.security.MessageDigest
import java.util.Locale

object PackageIdentityResolver {
    fun signingCertificateSha256(context: Context, packageName: String): Set<String> = runCatching {
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        }
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return@runCatching emptySet()
            val current = signingInfo.apkContentsSigners.orEmpty().asList()
            val history = if (signingInfo.hasPastSigningCertificates()) {
                signingInfo.signingCertificateHistory.orEmpty().asList()
            } else emptyList()
            current + history
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures.orEmpty().asList()
        }
        signatures.mapTo(linkedSetOf()) { signature -> sha256(signature.toByteArray()) }
    }.getOrDefault(emptySet())

    internal fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

internal object BrowserTrustAllowlist {
    private val fingerprint = Regex("^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$")

    fun signingCertificateSha256(raw: String, packageName: String): Set<String> = runCatching {
        val root = Json.parseToJsonElement(raw) as? JsonObject ?: return@runCatching emptySet()
        val apps = root["apps"] as? JsonArray ?: return@runCatching emptySet()
        apps.asSequence()
            .mapNotNull { it as? JsonObject }
            .filter { (it["type"] as? JsonPrimitive)?.contentOrNull == "android" }
            .mapNotNull { it["info"] as? JsonObject }
            .filter { (it["package_name"] as? JsonPrimitive)?.contentOrNull == packageName }
            .flatMap { ((it["signatures"] as? JsonArray).orEmpty()).asSequence() }
            .mapNotNull { it as? JsonObject }
            .mapNotNull { (it["cert_fingerprint_sha256"] as? JsonPrimitive)?.contentOrNull }
            .filter(fingerprint::matches)
            .mapTo(linkedSetOf()) { it.replace(":", "").lowercase(Locale.ROOT) }
    }.getOrDefault(emptySet())
}
