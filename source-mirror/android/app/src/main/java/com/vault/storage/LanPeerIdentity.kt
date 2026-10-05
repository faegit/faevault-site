package com.vault.storage

/**
 * 一次认证留下的对方设备身份，供传输站界面显示「对方设备」。
 *
 * 单独抽出来是为了能在 JVM 单测里覆盖选取逻辑——这个 bug 恰恰是因为选取逻辑
 * 藏在 SyncServerHost 里、无法测试才漏出去的。
 */
internal data class LanPeerIdentity(
    val deviceId: String,
    val fingerprint: String,
    val address: String,
    val connectedAtMillis: Long,
)

/**
 * 从候选中挑出当前对方设备：只取已完成设备认证（deviceId 非空）里最近的一条。
 *
 * 回归点：原先拿「SPAKE2 配对时刻」去比对会话上的「设备挑战确认时刻」。这两个是
 * 两次独立的 System.currentTimeMillis()，几乎不可能相等，于是对方设备信息恒为空，
 * 安卓连安卓时传输站页面一直显示不出对方设备。
 */
internal fun pickLanPeerIdentity(candidates: List<LanPeerIdentity>): LanPeerIdentity? =
    candidates.filter { it.deviceId.isNotBlank() }.maxByOrNull { it.connectedAtMillis }
