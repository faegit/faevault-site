package com.vault.ui.media

import android.content.Context
import android.net.Uri
import com.vault.R
import com.vault.security.SessionBytes
import com.vault.storage.PmvMediaContentRegistry
import com.vault.storage.PmvMediaRef
import com.vault.storage.VaultRegistry
import com.vault.storage.VaultRepository
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.OutputStream
import java.io.File

/**
 * Process-local bridge between Compose media widgets and the unlocked PMVE session.
 *
 * The bridge owns an obfuscated RootKey copy only while the vault is unlocked. Every operation
 * uses a temporary copy and clears it immediately. Locking, switching vaults and ViewModel
 * destruction call [clear], which also revokes every outstanding one-shot provider ticket.
 */
object PmvMediaUiSession {
    private data class Bound(
        val context: Context,
        val vaultName: String,
        val rootKey: SessionBytes,
    ) : AutoCloseable {
        override fun close() = rootKey.close()
    }

    private val lock = Any()
    private var bound: Bound? = null

    fun bind(context: Context, vaultName: String, rootKey: ByteArray) {
        require(vaultName.isNotBlank()) { context.getString(R.string.system_media_vault_name_empty) }
        require(rootKey.size == 32) { context.getString(R.string.system_media_root_key_invalid) }
        val replacement = Bound(context.applicationContext, vaultName, SessionBytes(rootKey))
        val switchedVault = synchronized(lock) {
            val switched = bound?.vaultName != vaultName
            bound?.close()
            bound = replacement
            switched
        }
        PmvMediaContentRegistry.clear()
        if (switchedVault) clearStaging(context.applicationContext)
    }

    fun clear() {
        val context = synchronized(lock) { bound?.context }
        synchronized(lock) {
            bound?.close()
            bound = null
        }
        PmvMediaContentRegistry.clear()
        context?.let(::clearStaging)
    }

    fun isBound(): Boolean = synchronized(lock) { bound != null }

    fun stagingDirectory(context: Context, kind: String): File {
        require(kind == "images" || kind == "attachments") { context.getString(R.string.system_media_staging_kind_invalid) }
        if (!isBound()) throw PmvMediaSessionLockedException()
        return File(context.cacheDir, "pmve_media_staging/$kind").also { directory ->
            check(directory.mkdirs() || directory.isDirectory) {
                context.getString(R.string.system_media_staging_directory_failed)
            }
        }
    }

    fun issue(
        value: String,
        displayName: String = "vault-media",
        mimeType: String = "application/octet-stream",
    ): Uri {
        val ref = PmvMediaRef.fromExternalString(value)
        val snapshot = revealSession()
        return try {
            PmvMediaContentRegistry.issue(
                snapshot.context,
                snapshot.vaultName,
                snapshot.rootKey,
                ref,
                displayName,
                mimeType,
            )
        } finally {
            snapshot.rootKey.fill(0)
        }
    }

    fun copyTo(value: String, output: OutputStream) {
        val ref = PmvMediaRef.fromExternalString(value)
        val snapshot = revealSession()
        try {
            repository(snapshot).openPmvEMedia(ref, snapshot.rootKey, output)
        } finally {
            snapshot.rootKey.fill(0)
        }
    }

    fun copyRangeTo(value: String, offset: Long, length: Long, output: OutputStream) {
        val ref = PmvMediaRef.fromExternalString(value)
        val snapshot = revealSession()
        try {
            repository(snapshot).openPmvEMediaRange(ref, snapshot.rootKey, offset, length, output)
        } finally {
            snapshot.rootKey.fill(0)
        }
    }

    private data class Snapshot(val context: Context, val vaultName: String, val rootKey: ByteArray)

    private fun revealSession(): Snapshot = synchronized(lock) {
        val current = bound ?: throw PmvMediaSessionLockedException()
        Snapshot(current.context, current.vaultName, current.rootKey.reveal())
    }

    private fun repository(snapshot: Snapshot): VaultRepository =
        VaultRepository(snapshot.context, VaultRegistry(snapshot.context), snapshot.vaultName)

    private fun clearStaging(context: Context) {
        File(context.cacheDir, "pmve_media_staging").deleteRecursively()
    }
}

/** Raised without a user-facing message; callers with a Context localize it at the UI boundary. */
internal class PmvMediaSessionLockedException : IllegalStateException()

fun isPmvEMediaRef(value: String): Boolean = value.startsWith("pmv4-object:v1:")

/** UI widgets keep using a compact String while the authoritative Entry retains canonical JSON. */
fun mediaValueString(value: JsonElement?): String = when (value) {
    is JsonObject -> runCatching { PmvMediaRef.fromJson(value).toExternalString() }.getOrDefault("")
    is JsonPrimitive -> value.content
    else -> ""
}

/**
 * 把媒体数组里的元素统一转成 UI 可用的紧凑字符串：
 * 兼容 PMVE 的 JsonObject 引用（[$pmv_media_ref]）、紧凑字符串引用与 base64。
 */
fun mediaListStrings(values: Iterable<JsonElement>?): List<String> =
    (values ?: emptyList()).mapNotNull(::mediaValueString).filter(String::isNotEmpty)
