package com.vault.storage

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.vault.security.LocalBackupPref
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/**
 * 设备级验证：本地自动备份**真的把保险库字节写到目标卷**，而不是只有 UI 报成功。
 *
 * 做法是直接调用生产函数 [ExternalRealtimeBackupCopier.copyCurrentVault]，
 * 用真实的 SAF 目录（应用私有 external files dir，经 DocumentsProvider 暴露）作为
 * 备份目标，然后逐项断言：
 *
 *  1. 目标卷上真的出现了 `{vault}.pmv`
 *  2. 其字节与源保险库**完全一致**（长度 + SHA-256）
 *  3. manifest 落盘
 *  4. lastBackupAt 被写入（决定下次触发）
 *  5. 再次调用不会把历史代次写坏
 *
 * 若生产逻辑只是更新 UI 状态而没有真正写文件，本测试会在第 1 项就失败。
 */
@RunWith(AndroidJUnit4::class)
class LocalBackupRealWriteTest {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun listNames(treeUri: Uri, rootId: String): List<String> {
        val cursor = requireNotNull(
            context.contentResolver.query(
                DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId),
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                ),
                null, null, null,
            ),
        )
        cursor.use {
            val out = mutableListOf<String>()
            while (it.moveToNext()) out.add(it.getString(1))
            return out
        }
    }

    private fun readChild(treeUri: Uri, rootId: String, name: String): ByteArray? {
        val cursor = requireNotNull(
            context.contentResolver.query(
                DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId),
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                ),
                null, null, null,
            ),
        )
        cursor.use {
            while (it.moveToNext()) {
                if (it.getString(1) == name) {
                    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, it.getString(0))
                    return context.contentResolver.openInputStream(docUri)!!.use { s -> s.readBytes() }
                }
            }
        }
        return null
    }

    @Test
    fun 本地备份真的把保险库写入目标卷() {
        val vaultName = "instrumentation-vault"
        val registry = VaultRegistry(context)
        val source = registry.fileFor(vaultName)

        // 1) 造一个可识别的保险库文件
        source.parentFile?.mkdirs()
        val payload = ByteArray(300 * 1024) { ((it * 17 + 11) % 251).toByte() }
        source.writeBytes(payload)

        // 2) 把外部存储 Documents 目录包装成可持久授权的 tree URI
        val rootTree = DocumentsContract.buildTreeDocumentUri(
            "com.android.externalstorage.documents",
            "primary:${android.os.Environment.DIRECTORY_DOCUMENTS}",
        )
        val takePersistable = try {
            context.contentResolver.takePersistableUriPermission(
                rootTree,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
            true
        } catch (t: Throwable) {
            false
        }
        assumeTrue("无法取得外部存储持久授权，跳过", takePersistable)

        val rootId = DocumentsContract.getTreeDocumentId(rootTree)

        // 3) 配置备份目标（setTarget 一次写入 treeUri / safId / deviceUuid）
        val volumeId = StorageVolumeResolver.resolve(context, rootTree)?.identityKey
        assumeTrue("无法解析目标卷身份，跳过", volumeId != null)
        val resolvedVolumeId = requireNotNull(volumeId)
        val deviceUuid = "instrumented-device-uuid"
        LocalBackupPref.setTarget(context, vaultName, rootTree.toString(), resolvedVolumeId, deviceUuid)
        LocalBackupPref.setEnabled(context, vaultName, true)
        LocalBackupPref.setInterval(context, vaultName, LocalBackupPolicy.INTERVAL_DAILY)
        LocalBackupPref.setLastBackupAt(context, vaultName, 0L)

        // 4) 预置设备标记，使绑定判定为 KNOWN
        val marker = SafDeviceMarker.create(context, rootTree)
        assumeTrue("无法写入设备标记：$marker", marker is SafDeviceMarker.ReadResult.Valid)

        // 5) 调生产函数执行备份
        val outcome = ExternalRealtimeBackupCopier.copyCurrentVault(context, vaultName, resolvedVolumeId)

        // 6) 关键断言：文件真的出现了，且字节一致
        val names = listNames(rootTree, rootId)
        val backupName = "$vaultName.pmv"
        assertTrue(
            "备份未落盘：目标卷上没有 $backupName，实际有 $names",
            names.contains(backupName),
        )
        val written = readChild(rootTree, rootId, backupName)
        assertTrue("备份文件读不出来", written != null)
        assertEquals("备份长度与源不一致", payload.size.toLong(), written!!.size.toLong())
        assertArrayEquals("备份字节与源不一致", payload, written)
        assertArrayEquals("备份摘要与源不一致", sha256(payload), sha256(written))

        // 7) manifest 落盘
        assertTrue("manifest 未生成", names.contains("$backupName.manifest.json"))

        // 8) 记录了备份时间（决定下次触发）
        assertTrue("lastBackupAt 未写入", LocalBackupPref.lastBackupAt(context, vaultName) > 0L)

        // 9) 没有残留 partial
        assertTrue(
            "残留未完成的 partial 文件：$names",
            names.none { it.contains("backup-partial") },
        )

        // 清理
        runCatching { LocalBackupPref.setEnabled(context, vaultName, false) }
        source.delete()
    }
}
