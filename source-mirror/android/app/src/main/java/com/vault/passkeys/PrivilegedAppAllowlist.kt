package com.vault.passkeys

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

object PrivilegedAppAllowlistValidator {
    private const val MAX_BYTES = 256 * 1024
    private const val MAX_APPS = 256
    private const val MAX_SIGNATURES = 64
    private val packageName = Regex("^[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+$")
    private val fingerprint = Regex("^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$")
    private val json = Json {
        isLenient = false
        allowSpecialFloatingPointValues = false
    }

    fun requireValid(raw: String): String {
        val bytes = raw.toByteArray(Charsets.UTF_8)
        require(bytes.size in 2..MAX_BYTES)
        val root = json.parseToJsonElement(raw) as? JsonObject
            ?: throw IllegalArgumentException("invalid privileged app allowlist")
        val apps = root["apps"] as? JsonArray
            ?: throw IllegalArgumentException("invalid privileged app allowlist")
        require(apps.size in 1..MAX_APPS)
        val packages = mutableSetOf<String>()
        apps.forEach { element ->
            val app = element as? JsonObject
                ?: throw IllegalArgumentException("invalid privileged app allowlist")
            require(app.strictString("type") == "android")
            val info = app["info"] as? JsonObject
                ?: throw IllegalArgumentException("invalid privileged app allowlist")
            val name = info.strictString("package_name")
            require(name.length <= 255 && packageName.matches(name) && packages.add(name))
            val signatures = info["signatures"] as? JsonArray
                ?: throw IllegalArgumentException("invalid privileged app allowlist")
            require(signatures.size in 1..MAX_SIGNATURES)
            val seenFingerprints = mutableSetOf<String>()
            signatures.forEach { signatureElement ->
                val signature = signatureElement as? JsonObject
                    ?: throw IllegalArgumentException("invalid privileged app allowlist")
                val build = signature.strictString("build")
                require(build.isNotBlank() && build.length <= 64)
                val value = signature.strictString("cert_fingerprint_sha256")
                require(fingerprint.matches(value) && seenFingerprints.add(value))
            }
        }
        return raw
    }

    private fun JsonObject.strictString(key: String): String {
        val primitive = this[key] as? JsonPrimitive
            ?: throw IllegalArgumentException("invalid privileged app allowlist")
        require(primitive.isString)
        return primitive.content
    }
}

class PrivilegedAppAllowlistStore(
    context: Context,
    private val client: OkHttpClient = secureClient(),
) {
    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun current(): String {
        preferences.getString(KEY_ALLOWLIST, null)?.let { cached ->
            try {
                return PrivilegedAppAllowlistValidator.requireValid(cached)
            } catch (_: Exception) {
                // Fall back to the bundled last-known-good document.
            }
        }
        val bundled = appContext.assets.open(ASSET).bufferedReader(Charsets.UTF_8).use { it.readText() }
        return PrivilegedAppAllowlistValidator.requireValid(bundled)
    }

    suspend fun refresh(): Boolean = withContext(Dispatchers.IO) {
        val response = client.newCall(
            Request.Builder()
                .url(SOURCE_URL)
                .header("Accept", "application/json")
                .build(),
        ).execute()
        response.use {
            require(it.request.url.isHttps && it.request.url.toString() == SOURCE_URL)
            require(it.isSuccessful)
            val contentType = it.body?.contentType()
            require(contentType?.type == "application" && contentType.subtype == "json")
            val contentLength = it.body?.contentLength() ?: -1L
            require(contentLength < 0 || contentLength <= MAX_DOWNLOAD_BYTES)
            val raw = it.body?.byteStream()?.use(::readBounded)
                ?: throw IllegalArgumentException("empty privileged app allowlist")
            val validated = PrivilegedAppAllowlistValidator.requireValid(raw.toString(Charsets.UTF_8))
            preferences.edit()
                .putString(KEY_ALLOWLIST, validated)
                .putLong(KEY_UPDATED_AT, System.currentTimeMillis())
                .commit()
        }
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

    companion object {
        const val SOURCE_URL = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"
        private const val ASSET = "passkey_privileged_apps.json"
        private const val PREFERENCES = "passkey_privileged_apps"
        private const val KEY_ALLOWLIST = "last_known_good"
        private const val KEY_UPDATED_AT = "updated_at"
        private const val MAX_DOWNLOAD_BYTES = 256 * 1024L

        private fun secureClient(): OkHttpClient = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .callTimeout(20, TimeUnit.SECONDS)
            .build()
    }
}

class PrivilegedAppAllowlistWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = try {
        check(PrivilegedAppAllowlistStore(applicationContext).refresh())
        Result.success()
    } catch (_: Exception) {
        if (runAttemptCount < 3) Result.retry() else Result.failure()
    }
}

object PrivilegedAppAllowlistUpdates {
    private const val PERIODIC_WORK = "passkey-privileged-apps-periodic"
    private const val INITIAL_WORK = "passkey-privileged-apps-initial"

    fun schedule(context: Context) {
        val workManager = WorkManager.getInstance(context.applicationContext)
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        workManager.enqueueUniqueWork(
            INITIAL_WORK,
            ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<PrivilegedAppAllowlistWorker>()
                .setConstraints(constraints)
                .build(),
        )
        workManager.enqueueUniquePeriodicWork(
            PERIODIC_WORK,
            ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<PrivilegedAppAllowlistWorker>(24, TimeUnit.HOURS)
                .setConstraints(constraints)
                .build(),
        )
    }
}
