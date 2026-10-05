package com.vault.ui.media

import android.content.Context
import com.vault.R

/** 旧格式（非 PMVE）图片上限：base64 需整体解码进内存，保留安全上限。 */
const val MAX_IMAGE_BYTES = 8L * 1024L * 1024L
/** PMVE 图片理论上限（1 TiB）：媒体流式写入容器 Object，仅受磁盘空间约束。 */
const val MAX_PMVE_IMAGE_BYTES = 1L * 1024L * 1024L * 1024L * 1024L
/** 图片数量理论上限：PMVE 支持大量图片同时添加，不再限制为 8 张。 */
const val MAX_IMAGES_PER_MODULE = 10_000
/** 附件数量理论上限：PMVE 支持大量附件同时添加，不再限制为 20 个。 */
const val MAX_ATTACHMENTS_PER_MODULE = 10_000
/** 旧格式（非 PMVE）附件模块字节上限。 */
const val MAX_ATTACHMENT_MODULE_BYTES = 32L * 1024L * 1024L
/** 旧格式（非 PMVE）应用媒体总容量上限。 */
const val MAX_APP_MEDIA_BYTES = 32L * 1024L * 1024L
/** PMVE 单附件理论上限（1 TiB）；格式层 Chunk 清单上限远高于此。 */
const val MAX_PMVE_ATTACHMENT_BYTES = 1L * 1024L * 1024L * 1024L * 1024L
/** PMVE 附件模块总容量仅受可用磁盘空间约束（理论上限）。 */
const val MAX_PMVE_ATTACHMENT_MODULE_BYTES = Long.MAX_VALUE

internal fun storedMediaBytes(context: Context): Long {
    val sizes = mutableMapOf<String, Long>()
    listOf("images", "attachments").forEach { kind ->
        listOf(
            context.filesDir.resolve(kind),
            context.cacheDir.resolve("vault_media/$kind"),
            context.cacheDir.resolve("pmve_media_staging/$kind"),
        ).forEach { directory ->
            directory.listFiles().orEmpty()
                .asSequence()
                .filter { it.isFile && !it.name.startsWith('.') }
                .forEach { file ->
                    val key = "$kind/${file.name}"
                    sizes[key] = maxOf(sizes[key] ?: 0L, file.length())
                }
        }
    }
    return sizes.values.sum()
}

internal fun requireMediaCapacity(context: Context, additionalBytes: Long) {
    require(additionalBytes >= 0L && storedMediaBytes(context) + additionalBytes <= MAX_APP_MEDIA_BYTES) {
        context.getString(R.string.system_media_total_capacity_exceeded)
    }
}
