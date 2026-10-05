package com.vault.ui

import com.vault.ui.LanGearChannels.HOST
import com.vault.ui.LanGearChannels.SYNC
import com.vault.ui.LanGearChannels.TRANSFER
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 局域网三挡的显示决策。
 *
 * 这块出过三次逻辑错误（面板无条件渲染、提示语无条件渲染、退出传输后回不到扫码页），
 * 而当时编译与 930 项测试全绿——因为判定内联在 composable 里、根本没有覆盖。
 * 这里把状态组合穷举一遍，每格都断言「显示什么 / 不显示什么」。
 */
class LanGearStateTest {

    private fun state(
        mode: String,
        hostRunning: Boolean = false,
        hostPaired: Boolean = false,
        hostOp: String = "",
        connectorSync: Boolean = false,
        connectorTransfer: Boolean = false,
        connectorConnecting: Boolean = false,
        transferViewExited: Boolean = false,
        hasResult: Boolean = false,
    ) = resolveLanGearState(
        mode = mode,
        hostRunning = hostRunning,
        hostPaired = hostPaired,
        hostOp = hostOp,
        connectorSyncRunning = connectorSync,
        connectorTransferActive = connectorTransfer,
        connectorTransferConnecting = connectorConnecting,
        transferViewExited = transferViewExited,
        hasSyncResult = hasResult,
    )

    @Test
    fun `peer disconnect overrides stale active flags and preserves closable record page`() {
        val gear = resolveLanGearState(
            mode = TRANSFER, hostRunning = false, hostPaired = false, hostOp = "",
            connectorSyncRunning = false, connectorTransferActive = true,
            connectorTransferConnecting = true, transferViewExited = false,
            hasSyncResult = false, connectorTransferDisconnected = true,
        )
        assertFalse(gear.transferLive)
        assertNull(gear.busyChannel)
        val view = LanTransferViewState().sessionStarted(host = false, seq = 1)
        assertTrue(view.visible(gear.transferLive))
        assertFalse(view.close().visible(gear.transferLive))
        assertFalse(view.close().shouldStart(host = false, seq = 1))
    }

    @Test
    fun `connector live state distinguishes connecting active and disconnected`() {
        assertTrue(connectorTransferSessionLive(false, true, false))
        assertTrue(connectorTransferSessionLive(true, false, false))
        assertFalse(connectorTransferSessionLive(false, false, false))
        assertFalse(connectorTransferSessionLive(true, false, true))
        assertFalse(connectorTransferSessionLive(false, true, true))
    }

    // ---------- 空闲 ----------

    @Test
    fun `idle sync gear offers the connector controls and nothing else`() {
        val s = state(SYNC)

        assertNull(s.busyChannel)
        assertTrue("空闲时应给扫码入口", s.showConnectorControls())
        assertFalse("空闲时不该显示同步面板", s.showSyncPanel())
        assertFalse("空闲时不该显示传输面板", s.showTransferPanel())
        assertFalse("空闲时不该出现「正在进行」提示", s.showBusyNotice())
        assertFalse(s.showSyncResult())
    }

    @Test
    fun `idle transfer gear offers the connector controls`() {
        val s = state(TRANSFER)

        assertNull(s.busyChannel)
        assertTrue(s.showConnectorControls())
        assertFalse(s.showTransferPanel())
        assertFalse(s.showBusyNotice())
    }

    @Test
    fun `a pending sync result replaces the connector controls on the sync gear`() {
        val s = state(SYNC, hasResult = true)

        assertTrue("结果待看时应显示结果卡", s.showSyncResult())
        assertFalse("结果待看时不该同时给扫码入口", s.showConnectorControls())
        assertFalse(s.showSyncPanel())
    }

    // ---------- 本挡正在跑自己的会话 ----------

    @Test
    fun `connector sync on the sync gear shows the panel and hides the scan ui`() {
        val s = state(SYNC, connectorSync = true)

        assertEquals(SYNC, s.busyChannel)
        assertTrue(s.showSyncPanel())
        assertFalse("同步进行中不该出现扫码入口", s.showConnectorControls())
        assertFalse(s.showBusyNotice())
    }

    @Test
    fun `host side sync shows the panel too`() {
        // 回归点：连接方那套标志在主机侧为 false，只看它会把主机侧同步判成空闲。
        val s = state(SYNC, hostRunning = true, hostPaired = true, hostOp = SYNC)

        assertEquals(SYNC, s.busyChannel)
        assertTrue("主机侧同步也应显示面板", s.showSyncPanel())
        assertFalse(s.showConnectorControls())
    }

    @Test
    fun `host side transfer shows the transfer panel on the transfer gear`() {
        val s = state(TRANSFER, hostRunning = true, hostPaired = true, hostOp = TRANSFER)

        assertEquals(TRANSFER, s.busyChannel)
        assertTrue(s.showTransferPanel())
        assertFalse(s.showConnectorControls())
    }

    @Test
    fun `connector transfer connecting counts as live so the scan ui stays hidden`() {
        val s = state(TRANSFER, connectorConnecting = true)

        assertEquals(TRANSFER, s.busyChannel)
        assertTrue(s.showTransferPanel())
        assertFalse("连接中也不该出现扫码入口", s.showConnectorControls())
    }

    // ---------- 另一个通道在跑 ----------

    @Test
    fun `transfer running makes the sync gear show only the notice`() {
        val s = state(SYNC, connectorTransfer = true)

        assertEquals(TRANSFER, s.busyChannel)
        assertTrue(s.showBusyNotice())
        assertFalse("别的通道在跑时不该给扫码入口", s.showConnectorControls())
        assertFalse(s.showSyncPanel())
        assertFalse(s.showTransferPanel())
    }

    @Test
    fun `sync running makes the transfer gear show only the notice`() {
        val s = state(TRANSFER, hostRunning = true, hostPaired = true, hostOp = SYNC)

        assertEquals(SYNC, s.busyChannel)
        assertTrue(s.showBusyNotice())
        assertFalse(s.showConnectorControls())
        assertFalse(s.showTransferPanel())
    }

    @Test
    fun `a pending result is not surfaced while another channel is busy`() {
        val s = state(SYNC, connectorTransfer = true, hasResult = true)

        assertTrue(s.showBusyNotice())
        assertFalse("被占用时不该显示结果卡", s.showSyncResult())
    }

    // ---------- 退出传输 ----------

    @Test
    fun `leaving the transfer view returns the gear to the connector controls`() {
        // 回归点：判据若用 busyChannel == null，主机仍在监听就永远为 false，
        // 退出传输后回不到扫码页。
        val s = state(
            TRANSFER,
            hostRunning = true, hostPaired = true, hostOp = TRANSFER,
            transferViewExited = true,
        )

        assertNull("退出传输视图后不再算作进行中的传输", s.busyChannel)
        assertTrue("退出后应回到扫码页", s.showConnectorControls())
        assertFalse(s.showTransferPanel())
        assertFalse(s.showBusyNotice())
    }

    @Test
    fun `a new pairing after leaving the transfer view brings the panel back`() {
        // 传输站一直开着；新设备接入（pairSeq 变化 → 退出标志复位）后应重新进传输页。
        val s = state(
            TRANSFER,
            hostRunning = true, hostPaired = true, hostOp = TRANSFER,
            transferViewExited = false,
        )

        assertEquals(TRANSFER, s.busyChannel)
        assertTrue(s.showTransferPanel())
        assertFalse(s.showConnectorControls())
    }

    // ---------- 导出不占用任何挡位 ----------

    @Test
    fun `export session does not occupy the sync or transfer gear`() {
        val s = state(SYNC, hostRunning = true, hostPaired = true, hostOp = LanGearChannels.EXPORT)

        assertNull("导出不该占用同步挡", s.busyChannel)
        assertFalse(s.showBusyNotice())
        assertFalse(s.showSyncPanel())
        assertTrue("导出时同步挡仍应是扫码入口", s.showConnectorControls())
    }

    @Test
    fun `host gear is never covered by the cross-channel notice`() {
        // 回归点：currentChannel 曾把 HOST 也算成 SYNC，于是传输站正在服务一个
        // 文件传输对端时，主机挡会显示「当前正在进行「文件传输」，不可进行其他操作」——
        // 自己的二维码和「关闭传输站」都够不着。
        val s = state(HOST, hostRunning = true, hostPaired = true, hostOp = TRANSFER)

        assertEquals(TRANSFER, s.busyChannel)
        assertFalse("主机挡不该被跨通道说明覆盖", s.showBusyNotice())
    }

    @Test
    fun `host gear shows no notice while this device is the client instead`() {
        // 本机在当客户端连别人、自己的站开着但还没人连：主机挡照常显示传输站页。
        val s = state(HOST, hostRunning = true, hostPaired = false, connectorSync = true)

        assertEquals(SYNC, s.busyChannel)
        assertFalse(s.showBusyNotice())
    }

    @Test
    fun `transfer gear still shows the notice when this device hosts a sync`() {
        val s = state(TRANSFER, hostRunning = true, hostPaired = true, hostOp = SYNC)

        assertTrue(s.showBusyNotice())
        assertFalse(s.showConnectorControls())
    }

    @Test
    fun `transfer takes precedence over sync when both would be live`() {
        val s = state(TRANSFER, connectorSync = true, connectorTransfer = true)

        assertEquals(TRANSFER, s.busyChannel)
    }
}
