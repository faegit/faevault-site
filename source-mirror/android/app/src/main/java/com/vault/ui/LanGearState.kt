package com.vault.ui

/**
 * 局域网三挡在某一时刻的显示决策。
 *
 * 这段判定原先内联在 SettingsScreen 的 composable 里，既难读也无法在 JVM 单测里
 * 逐格断言——而这里恰恰出过三次逻辑错误：面板无条件渲染、提示语无条件渲染、
 * 退出传输后回不到扫码页。抽成纯函数后，状态组合可以在测试里穷举，composable
 * 只负责按结果渲染。
 *
 * 术语：
 * - 「连接方」= 本机主动去连别人的传输站（对应 state.syncRunning / lanTransferActive）
 * - 「主机侧」= 本机开着传输站、被对端连上（对应 lanHostState）
 * 两套标志必须一起看：只看连接方那套会在主机侧漏判，反之亦然。
 */
internal data class LanGearState(
    /** 当前被占用的通道；null 表示没有任何同步/传输在进行。 */
    val busyChannel: String?,
    val syncLive: Boolean,
    val transferLive: Boolean,
    /** 别的挡位正在跑，本挡不可操作。 */
    val channelBusyElsewhere: Boolean,
    val hasSyncResult: Boolean,
) {
    /** 本挡是不是正在跑属于自己的会话。 */
    val ownsSession: Boolean get() = !channelBusyElsewhere && busyChannel != null

    /** 别的通道在跑时的那句说明。 */
    fun showBusyNotice(): Boolean = channelBusyElsewhere

    /** 同步会话面板：状态 / 进度 / 速率 / 时长 + 断开连接。 */
    fun showSyncPanel(): Boolean = ownsSession && syncLive

    /** 文件传输面板。 */
    fun showTransferPanel(): Boolean = ownsSession && transferLive

    /** 扫码 / 手动输入 / 连接：只在空闲、且没有待查看的同步结果时出现。 */
    fun showConnectorControls(): Boolean =
        !channelBusyElsewhere && !syncLive && !transferLive && !hasSyncResult

    /** 同步结束后的结果卡与「退出同步」。 */
    fun showSyncResult(): Boolean = !channelBusyElsewhere && hasSyncResult
}

internal object LanGearChannels {
    const val SYNC = "sync"
    const val TRANSFER = "transfer"
    const val HOST = "host"
    const val EXPORT = "export"
}

/**
 * 算出当前时刻三挡的显示决策。
 *
 * @param mode 当前所在挡位（HOST / SYNC / TRANSFER）。HOST 是独立一挡、不属于任何
 *   通道：它展示传输站本身（地址/二维码/对方设备）。不能用通道去推它「是否正忙」——
 *   否则传输站正在服务一个文件传输对端时，主机挡会误显示「当前正在进行「文件传输」，
 *   不可进行其他操作」，二维码和「关闭传输站」都够不着。
 * @param hostRunning 传输站是否开着
 * @param hostPaired 是否已有对端完成配对
 * @param hostOp 配对后的通道（sync / transfer / export）
 * @param transferViewExited 用户是否已从文件传输视图退出（退出后传输站仍在监听）
 */
internal fun resolveLanGearState(
    mode: String,
    hostRunning: Boolean,
    hostPaired: Boolean,
    hostOp: String,
    connectorSyncRunning: Boolean,
    connectorTransferActive: Boolean,
    connectorTransferConnecting: Boolean,
    transferViewExited: Boolean,
    hasSyncResult: Boolean,
    connectorTransferDisconnected: Boolean = false,
): LanGearState {
    val paired = hostRunning && hostPaired
    val hostSyncLive = paired && hostOp == LanGearChannels.SYNC
    // 用户退出传输视图后，主机仍在监听，但这一挡已经不再显示传输面板。
    val hostTransferLive = paired && hostOp == LanGearChannels.TRANSFER && !transferViewExited
    val syncLive = connectorSyncRunning || hostSyncLive
    val transferLive = connectorTransferSessionLive(
        connectorTransferActive, connectorTransferConnecting, connectorTransferDisconnected,
    ) || hostTransferLive
    // 导出（export）不占用同步/互传任一挡位。
    val busyChannel = when {
        transferLive -> LanGearChannels.TRANSFER
        syncLive -> LanGearChannels.SYNC
        else -> null
    }
    val currentChannel = when (mode) {
        LanGearChannels.TRANSFER -> LanGearChannels.TRANSFER
        LanGearChannels.SYNC -> LanGearChannels.SYNC
        else -> null // HOST 挡不属于任何通道
    }
    val channelBusyElsewhere =
        busyChannel != null && currentChannel != null && busyChannel != currentChannel
    return LanGearState(
        busyChannel = busyChannel,
        syncLive = syncLive,
        transferLive = transferLive,
        channelBusyElsewhere = channelBusyElsewhere,
        hasSyncResult = hasSyncResult,
    )
}

/** 对方断开优先于活跃标志，断开后的记录页不能继续发送或再次断开。 */
internal fun connectorTransferSessionLive(active: Boolean, connecting: Boolean, disconnected: Boolean): Boolean =
    !disconnected && (active || connecting)
