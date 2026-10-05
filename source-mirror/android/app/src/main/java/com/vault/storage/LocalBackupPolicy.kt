package com.vault.storage

/** 本地定期备份策略（纯 JVM，可单测）。 */
object LocalBackupPolicy {
    const val INTERVAL_REALTIME = 0L
    const val INTERVAL_HOURLY = 60L * 60L * 1000L
    const val INTERVAL_DAILY = 24L * 60L * 60L * 1000L
    const val INTERVAL_WEEKLY = 7L * 24L * 60L * 60L * 1000L
    const val INTERVAL_MONTHLY = 30L * 24L * 60L * 60L * 1000L

    /** 滑块档位（实时 → 每月）。 */
    val INTERVALS = listOf(
        INTERVAL_REALTIME,
        INTERVAL_HOURLY,
        INTERVAL_DAILY,
        INTERVAL_WEEKLY,
        INTERVAL_MONTHLY,
    )

    fun indexOf(intervalMillis: Long): Int =
        INTERVALS.indexOf(intervalMillis).coerceAtLeast(0)

    fun intervalAt(index: Int): Long =
        INTERVALS[index.coerceIn(0, INTERVALS.lastIndex)]

    fun label(intervalMillis: Long): String = when (intervalMillis) {
        INTERVAL_REALTIME -> "实时"
        INTERVAL_HOURLY -> "每小时"
        INTERVAL_DAILY -> "每天"
        INTERVAL_WEEKLY -> "每周"
        INTERVAL_MONTHLY -> "每月"
        else -> "每天"
    }

    /** 是否应执行本次备份：实时总是执行；其余按上次备份时间与周期判定。 */
    fun shouldRun(
        nowMillis: Long,
        lastBackupMillis: Long,
        intervalMillis: Long,
        force: Boolean = false,
    ): Boolean {
        require(intervalMillis in INTERVALS) { "无效的备份周期" }
        if (force) return true
        if (intervalMillis == INTERVAL_REALTIME) return true
        return nowMillis - lastBackupMillis >= intervalMillis
    }

    /** 外接设备连接时，任何有效周期都需要检查；是否复制由 [shouldRun] 决定。 */
    fun shouldTriggerExternalConnectionCheck(
        enabled: Boolean,
        intervalMillis: Long,
        expectedVolumeIdentity: String?,
    ): Boolean = enabled &&
        intervalMillis in INTERVALS &&
        !expectedVolumeIdentity.isNullOrBlank() &&
        !expectedVolumeIdentity.startsWith("internal|")

    /** 外接设备已经连接时，判断本次是否真正需要复制。 */
    fun shouldRunExternalConnectionBackup(
        enabled: Boolean,
        nowMillis: Long,
        lastBackupMillis: Long,
        intervalMillis: Long,
        expectedVolumeIdentity: String?,
    ): Boolean = shouldTriggerExternalConnectionCheck(
        enabled = enabled,
        intervalMillis = intervalMillis,
        expectedVolumeIdentity = expectedVolumeIdentity,
    ) && shouldRun(
        nowMillis = nowMillis,
        lastBackupMillis = lastBackupMillis,
        intervalMillis = intervalMillis,
    )
}
