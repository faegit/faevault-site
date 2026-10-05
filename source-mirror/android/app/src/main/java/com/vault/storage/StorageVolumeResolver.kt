package com.vault.storage

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.StatFs
import android.os.storage.StorageManager
import android.provider.DocumentsContract
import java.security.MessageDigest

/**
 * 基于 Storage Access Framework（SAF）的稳定卷识别。
 *
 * 给定一个 SAF tree URI，产出稳定的卷指纹 [VolumeFingerprint]，用于在设备插拔、盘符变化后
 * 仍能可靠辨认同一块存储。
 *
 * 身份锚点**仅**取自 SAF tree URI 的根文档 ID（`doc:authority/rootDoc`）：
 * - 对可移除卷（SD/U 盘），AOSP 将其根文档 ID 设为卷 UUID，因此跨插拔、盘符变化、挂载初期都保持稳定，
 *   且不同介质根文档 ID 互异，足以可靠辨认。
 * - 主存储（primary 且不可移除）追加 `internal|` 前缀，便于外部连接流程排除它。
 *
 * `StorageManager.getStorageVolume(...)` 仅用于补充**展示信息**（卷标/容量），且全程容错：
 * 该调用在部分 ROM/模拟器/特定 tree URI 下会抛异常或返回 null，绝不能让它影响身份识别本身，
 * 否则会导致“所有设备都无法识别身份”的全局故障。身份比较见 [stableCore]，
 * 与设备 UUID 标记（`SafDeviceMarker`）共同构成双因子绑定。
 */
internal object StorageVolumeResolver {

    data class VolumeFingerprint(
        val identityKey: String,
        val displayName: String,
        val displayId: String,
        val capacityBytes: Long,
    )

    fun resolve(context: Context, treeUri: Uri): VolumeFingerprint? = runCatching {
        val authority = treeUri.authority.orEmpty()
        val rootDoc = DocumentsContract.getTreeDocumentId(treeUri)

        // 仅用于展示；查询失败（部分 ROM/模拟器会抛异常）绝不影响身份识别。
        val volume = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val sm = context.getSystemService(Context.STORAGE_SERVICE) as StorageManager
                sm.getStorageVolume(DocumentsContract.buildDocumentUriUsingTree(treeUri, rootDoc))
                    ?: sm.getStorageVolume(treeUri)
            } else {
                null
            }
        }.getOrNull()

        // 身份锚点：统一以 SAF 根文档 ID 为主。主存储（primary 且不可移除）加 internal 前缀
        // 以便外部连接流程排除；其余一律 doc: 前缀，跨重连稳定。
        val isInternal = volume != null && volume.isPrimary && !volume.isRemovable
        val key = if (isInternal) "internal|$authority|$rootDoc" else "doc:$authority/$rootDoc"

        val displayName = runCatching {
            if (!isInternal && volume != null) {
                volume.getDescription(context)?.takeIf { it.isNotBlank() }
            } else {
                null
            }
        }.getOrNull() ?: if (isInternal) "本机存储" else "备份设备"

        val capacity = runCatching { if (volume != null) capacityOf(volume) else 0L }.getOrNull() ?: 0L

        VolumeFingerprint(
            identityKey = key,
            displayName = displayName,
            displayId = "VOL-${shortId(key)}",
            capacityBytes = capacity,
        )
    }.getOrNull()

    private fun capacityOf(volume: android.os.storage.StorageVolume): Long {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return 0L
        val dir = runCatching { volume.directory }.getOrNull() ?: return 0L
        return runCatching { StatFs(dir.absolutePath).totalBytes }.getOrDefault(0L)
    }

    private fun shortId(seed: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(seed.toByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            .take(6)
            .uppercase()

    /**
     * 把任意时期生成的身份归一化为稳定比较核：仅取 `doc:` 根文档 ID 段。
     * 旧版身份含 `fs:/cap:/label:` 等易变分量，重连后难以对齐；统一以 `doc:` 段判定同一设备，
     * 保证历史保存的配置无需重新选择目录即可继续匹配。
     */
    fun stableCore(identity: String?): String? {
        if (identity.isNullOrBlank()) return null
        return identity.split("|").firstOrNull { it.startsWith("doc:") } ?: identity
    }
}
