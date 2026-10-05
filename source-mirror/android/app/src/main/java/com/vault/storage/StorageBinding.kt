package com.vault.storage

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import org.json.JSONObject
import java.util.UUID

/** 同步目标的双标识判定。只有 [KNOWN] 可以由后台自动写入。 */
enum class StorageBindingState {
    KNOWN,
    SUSPECTED_ORIGINAL,
    IDENTITY_ANOMALY,
    NEW_DEVICE,
}

object StorageBindingPolicy {
    fun blockedBackupToken(state: StorageBindingState): String? = when (state) {
        StorageBindingState.KNOWN -> null
        StorageBindingState.SUSPECTED_ORIGINAL -> null
        else -> "backup-device-abnormal"
    }

    fun evaluate(
        storedDeviceUuid: String?,
        storedAccessId: String?,
        observedDeviceUuid: String?,
        observedAccessId: String?,
    ): StorageBindingState {
        val uuidMatches = canonicalUuid(storedDeviceUuid) != null &&
            canonicalUuid(storedDeviceUuid) == canonicalUuid(observedDeviceUuid)
        val accessMatches = !storedAccessId.isNullOrBlank() &&
            storedAccessId.trim() == observedAccessId?.trim()
        return when {
            uuidMatches && accessMatches -> StorageBindingState.KNOWN
            uuidMatches -> StorageBindingState.SUSPECTED_ORIGINAL
            accessMatches -> StorageBindingState.IDENTITY_ANOMALY
            else -> StorageBindingState.NEW_DEVICE
        }
    }

    fun canonicalUuid(value: String?): String? = runCatching {
        value?.trim()?.takeIf { it.isNotEmpty() }?.let { UUID.fromString(it).toString() }
    }.getOrNull()
}

/** 存在 FAEVault 目录内、可跨 Android/PC 读取的非敏感设备 UUID 标记。 */
object SafDeviceMarker {
    const val FILE_NAME = "FAEVault.device.json"
    private const val MAX_BYTES = 4096

    sealed interface ReadResult {
        data object Missing : ReadResult
        data object Invalid : ReadResult
        data class Valid(val deviceUuid: String) : ReadResult
    }

    fun read(context: Context, treeUri: Uri): ReadResult = runCatching {
        val markerUri = findChild(context, treeUri, FILE_NAME) ?: return@runCatching ReadResult.Missing
        val bytes = context.contentResolver.openInputStream(markerUri)?.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (output.size() + count > MAX_BYTES) return@runCatching ReadResult.Invalid
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        } ?: return@runCatching ReadResult.Invalid
        val json = JSONObject(bytes.toString(Charsets.UTF_8))
        if (json.optInt("version", -1) != 1) return@runCatching ReadResult.Invalid
        val uuid = StorageBindingPolicy.canonicalUuid(json.optString("deviceUuid"))
            ?: return@runCatching ReadResult.Invalid
        ReadResult.Valid(uuid)
    }.getOrDefault(ReadResult.Invalid)

    /** 仅在用户明确授权新设备后调用；既有损坏标记绝不覆盖。 */
    fun create(context: Context, treeUri: Uri): ReadResult {
        when (val existing = read(context, treeUri)) {
            is ReadResult.Valid, ReadResult.Invalid -> return existing
            ReadResult.Missing -> Unit
        }
        return runCatching {
            val rootId = DocumentsContract.getTreeDocumentId(treeUri)
            val rootUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)
            val markerUri = DocumentsContract.createDocument(
                context.contentResolver,
                rootUri,
                "application/json",
                FILE_NAME,
            ) ?: return@runCatching ReadResult.Invalid
            val uuid = UUID.randomUUID().toString()
            val payload = JSONObject()
                .put("version", 1)
                .put("deviceUuid", uuid)
                .toString()
                .toByteArray(Charsets.UTF_8)
            context.contentResolver.openOutputStream(markerUri, "w")?.use { output ->
                output.write(payload)
                output.flush()
            } ?: return@runCatching ReadResult.Invalid
            read(context, treeUri).takeIf { it is ReadResult.Valid } ?: ReadResult.Invalid
        }.getOrDefault(ReadResult.Invalid)
    }

    private fun findChild(context: Context, treeUri: Uri, name: String): Uri? {
        val rootId = DocumentsContract.getTreeDocumentId(treeUri)
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId)
        context.contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            while (cursor.moveToNext()) {
                if (cursor.getString(1) == name) {
                    return DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0))
                }
            }
        }
        return null
    }
}
