package com.vault.storage

/**
 * PMVE 自动压缩决策。
 *
 * PMVE 为追加写容器，每次保存都会追加历史 Block，旧版本成为垃圾空间。
 * 为避免频繁重写大库，只有同时满足以下条件才在后台自动压缩一次：
 *  - 距上次压缩累计的提交数达到阈值；
 *  - 距上次压缩文件增长达到阈值（存在实际垃圾）；
 *  - 库文件达到最小规模；
 *  - 距上次压缩超过最短间隔（防止异常场景反复压缩）。
 */
object AutoCompactPolicy {
    /** 距上次压缩至少累计的提交数，避免频繁重写。 */
    const val MIN_COMMITS_SINCE_COMPACT = 200L

    /** 距上次压缩至少增长的文件字节数，小库/无实际垃圾时不重写。 */
    const val MIN_GROWTH_BYTES_SINCE_COMPACT = 1L * 1024 * 1024

    /** 库文件达到该大小时才考虑自动压缩。 */
    const val MIN_FILE_SIZE_BYTES = 512L * 1024

    /** 连续自动压缩之间的最短间隔（毫秒）。 */
    const val MIN_COMPACT_INTERVAL_MILLIS = 24L * 60 * 60 * 1000

    /** 导入后的冷却期：导入完成先正常使用，冷却期内不自动压缩，避免刚导入即重写。 */
    const val IMPORT_COOLDOWN_MILLIS = 24L * 60 * 60 * 1000

    fun shouldCompact(
        currentRevision: Long,
        lastCompactRevision: Long,
        fileSize: Long,
        lastCompactSize: Long,
        lastCompactAtMillis: Long = 0L,
        lastImportAtMillis: Long = 0L,
        nowMillis: Long = System.currentTimeMillis(),
        minCommits: Long = MIN_COMMITS_SINCE_COMPACT,
        minGrowth: Long = MIN_GROWTH_BYTES_SINCE_COMPACT,
        minFileSize: Long = MIN_FILE_SIZE_BYTES,
        minIntervalMillis: Long = MIN_COMPACT_INTERVAL_MILLIS,
        importCooldownMillis: Long = IMPORT_COOLDOWN_MILLIS,
    ): Boolean {
        if (fileSize < minFileSize) return false
        if (nowMillis - lastCompactAtMillis < minIntervalMillis) return false
        if (lastImportAtMillis > 0L && nowMillis - lastImportAtMillis < importCooldownMillis) return false
        val commitsSinceCompact = currentRevision - lastCompactRevision
        if (commitsSinceCompact < minCommits) return false
        return fileSize - lastCompactSize >= minGrowth
    }
}
