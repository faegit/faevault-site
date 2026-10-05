package com.vault.ui

import com.vault.model.VaultOps
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Disconnect preserves the page and its role; only an explicit close discards the view.
 *
 * 记 [pairSeq] 是为了解决「点了关闭页面又自己回来」：重组/会话标志抖动会反复重跑
 * 那个启动 effect，只要 transferLive 仍为真就会再次 [sessionStarted]，把刚关掉的页面
 * 复活。绑定到配对序号后，同一场配对内 close 之后不会再被打开；只有对方重新配对
 * （pairSeq 变化）才允许开启新视图。
 */
internal data class LanTransferViewState(
    val open: Boolean = false,
    val host: Boolean = false,
    val pairSeq: Int = -1,
) {
    fun sessionStarted(host: Boolean, seq: Int = -1) =
        LanTransferViewState(open = true, host = host, pairSeq = seq)

    fun close() = copy(open = false)

    /** 同一场配对内已显式关闭过时，不再因会话标志抖动而复活。 */
    fun shouldStart(host: Boolean, seq: Int): Boolean {
        if (open) return host != this.host
        return seq != pairSeq
    }

    fun visible(sessionLive: Boolean) = sessionLive || open
}

/**
 * 同步挡在某一时刻该显示什么。
 *
 * 「已断开连接」只在既没有结果、且这一页确实开过时出现；有结果就必须显示完整统计。
 * 早先的判据把结果卡挂在 `!channelBusyElsewhere` 之下，而 `syncRunning` 归零与
 * `_syncResult` 写入之间存在一个重组窗口，两侧条件会同时不成立，于是总有一侧退化成
 * 「已关闭」——看起来就是一端有完整统计、另一端只说已关闭。这里改成互斥且只认
 * 结果本身，与另一侧的会话标志时序解耦。
 *
 * 同步进行中必须落到 [LanSyncViewMode.LIVE]，由会话面板与「断开连接」按钮表达状态；
 * 早先把它也归进 DISCONNECTED，结果扫码同步刚连上就满屏「已断开连接」。
 */
internal enum class LanSyncViewMode { LIVE, RESULT, DISCONNECTED, IDLE }

internal fun lanSyncViewMode(
    syncLive: Boolean,
    hasSyncResult: Boolean,
    viewOpen: Boolean,
): LanSyncViewMode = when {
    syncLive -> LanSyncViewMode.LIVE
    hasSyncResult -> LanSyncViewMode.RESULT
    viewOpen -> LanSyncViewMode.DISCONNECTED
    else -> LanSyncViewMode.IDLE
}

/** Decode the exact response produced after host validation/adoption, without losing statistics. */
internal fun hostSyncResultFromResponse(
    response: String,
    localCount: Int,
    mergedCount: Int,
    remoteBytes: Long,
): VaultViewModel.SyncResultState {
    val json = Json.parseToJsonElement(response).jsonObject
    fun count(key: String) = json[key]?.jsonPrimitive?.intOrNull ?: 0
    return VaultViewModel.SyncResultState(
        source = "LAN",
        stats = VaultOps.LwwMergeStats(
            added = count("added"), takeRemote = count("remote_wins"),
            takeLocal = count("local_wins"), identical = count("identical"),
            keptBoth = count("kept_both"), conflicts = count("conflicts"),
            passkeyConflicts = count("passkey_conflicts"), purged = count("purged"),
            purgeSkipped = count("purge_skipped"), coalesced = count("coalesced"),
        ),
        localCount = localCount, mergedCount = mergedCount, remoteBytes = remoteBytes,
        host = true, verified = true,
        lineage = json["lineage"]?.jsonPrimitive?.contentOrNull.orEmpty(),
    )
}
