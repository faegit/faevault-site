package com.vault.storage

import java.io.ByteArrayOutputStream
import java.io.InputStream

internal const val MAX_VAULT_BYTES: Long = 2L * 1024L * 1024L * 1024L
internal const val MAX_NETWORK_MESSAGE_BYTES: Long = 64L * 1024L

internal fun InputStream.readBytesLimited(limit: Long, label: String): ByteArray {
    require(limit > 0L) { "$label 大小限制必须为正数" }
    // 初始缓冲只按小值分配，避免 2 GiB 上限在 toInt 时溢出为负数
    val output = ByteArrayOutputStream(minOf(limit, 32 * 1024L).toInt())
    val buffer = ByteArray(32 * 1024)
    var total = 0L
    while (true) {
        val count = read(buffer)
        if (count < 0) break
        total += count
        if (total > limit) error("$label 超过安全大小限制")
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}
