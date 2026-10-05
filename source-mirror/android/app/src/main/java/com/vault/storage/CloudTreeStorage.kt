package com.vault.storage

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract

data class CloudDirectoryInspection(
    val exactMatches: List<CloudDocumentMetadata>,
    val pmvCount: Int,
)

data class CloudDocumentMetadata(val uri: Uri, val size: Long, val lastModified: Long)

enum class CloudFileState { PRESENT, MISSING, REPLACED, AMBIGUOUS }

data class CloudFileCheck(
    val state: CloudFileState,
    val metadata: CloudDocumentMetadata? = null,
    val logicalRevision: String? = null,
)

object CloudTreeStorage {
    private const val MAX_CHILDREN = 2_000

    fun vaultFileName(accountName: String): String {
        val safe = accountName.trim()
            .replace(Regex("[\\\\/:*?\"<>|]"), "_")
            .trim('.', ' ')
            .take(80)
            .ifEmpty { "vault" }
        // 命名统一：云端文件 = <账户名>.pmv，与本地/导出命名一致，不再加 vault_ 前缀。
        return "${safe}.pmv"
    }

    fun inspect(context: Context, treeUri: Uri, expectedName: String): CloudDirectoryInspection {
        val resolver = context.contentResolver
        val treeId = DocumentsContract.getTreeDocumentId(treeUri)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeId)
        val exact = mutableListOf<CloudDocumentMetadata>()
        var pmvCount = 0
        resolver.query(
            children,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            var scanned = 0
            while (cursor.moveToNext()) {
                check(++scanned <= MAX_CHILDREN) { "所选目录文件过多，请选择专用的保险库目录" }
                val name = cursor.getString(nameColumn).orEmpty()
                if (!name.endsWith(".pmv", ignoreCase = true)) continue
                pmvCount++
                if (name.equals(expectedName, ignoreCase = true)) {
                    exact += CloudDocumentMetadata(
                        uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(idColumn)),
                        size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L,
                        lastModified = if (modifiedColumn >= 0 && !cursor.isNull(modifiedColumn)) cursor.getLong(modifiedColumn) else 0L,
                    )
                }
            }
        } ?: error("云端文档提供程序无法列出所选目录")
        return CloudDirectoryInspection(exact, pmvCount)
    }

    fun create(context: Context, treeUri: Uri, displayName: String): Uri {
        val inspection = inspect(context, treeUri, displayName)
        if (inspection.exactMatches.size == 1) return inspection.exactMatches.single().uri
        check(inspection.pmvCount == 0) { "目录中已存在保险库文件，请选择已有文件" }
        val parent = DocumentsContract.buildDocumentUriUsingTree(
            treeUri,
            DocumentsContract.getTreeDocumentId(treeUri),
        )
        return DocumentsContract.createDocument(
            context.contentResolver,
            parent,
            "application/octet-stream",
            displayName,
        ) ?: error("云端文档提供程序未能创建保险库文件")
    }

    fun check(context: Context, treeUri: Uri, expectedName: String, currentFileUri: Uri): CloudFileCheck {
        findCurrentDocument(context, treeUri, currentFileUri)?.let {
            return CloudFileCheck(CloudFileState.PRESENT, it)
        }
        val exact = inspect(context, treeUri, expectedName).exactMatches
        return when (exact.size) {
            0 -> CloudFileCheck(CloudFileState.MISSING)
            1 -> CloudFileCheck(CloudFileState.REPLACED, exact.single())
            else -> CloudFileCheck(CloudFileState.AMBIGUOUS)
        }
    }

    fun metadata(context: Context, uri: Uri): CloudDocumentMetadata {
        context.contentResolver.query(
            uri,
            arrayOf(
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            check(cursor.moveToFirst()) { "云端文件不存在或无法读取" }
            val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            return CloudDocumentMetadata(
                uri = uri,
                size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L,
                lastModified = if (modifiedColumn >= 0 && !cursor.isNull(modifiedColumn)) cursor.getLong(modifiedColumn) else 0L,
            )
        } ?: error("云端文档提供程序无法读取文件信息")
    }

    private fun findCurrentDocument(context: Context, treeUri: Uri, currentFileUri: Uri): CloudDocumentMetadata? {
        val targetId = runCatching { DocumentsContract.getDocumentId(currentFileUri) }.getOrNull() ?: return null
        if (treeUri.authority != currentFileUri.authority) return null
        val treeId = DocumentsContract.getTreeDocumentId(treeUri)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeId)
        context.contentResolver.query(
            children,
            arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            ),
            null,
            null,
            null,
        )?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            var scanned = 0
            while (cursor.moveToNext()) {
                check(++scanned <= MAX_CHILDREN) { "所选目录文件过多，请选择专用的保险库目录" }
                val documentId = cursor.getString(idColumn)
                if (documentId != targetId) continue
                return CloudDocumentMetadata(
                    uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId),
                    size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L,
                    lastModified = if (modifiedColumn >= 0 && !cursor.isNull(modifiedColumn)) cursor.getLong(modifiedColumn) else 0L,
                )
            }
        } ?: error("云端文档提供程序无法列出所选目录")
        return null
    }
}
