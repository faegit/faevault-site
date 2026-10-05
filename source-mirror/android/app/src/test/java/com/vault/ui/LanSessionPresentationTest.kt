package com.vault.ui

import org.junit.Assert.*
import org.junit.Test

class LanSessionPresentationTest {
    @Test fun `both transfer roles retain the page until closed and reopen for a new session`() {
        for (host in listOf(false, true)) {
            val idle = LanTransferViewState()
            assertFalse(idle.visible(false))
            val connected = idle.sessionStarted(host, seq = 1)
            assertTrue(connected.visible(true))
            assertTrue(connected.visible(false)) // peer or local disconnect
            assertEquals(host, connected.host)
            val closed = connected.close()
            assertFalse(closed.visible(false))
            assertFalse(closed.visible(false)) // repeated disconnected status does not reopen
            assertTrue(closed.sessionStarted(host, seq = 2).visible(true))
        }
    }

    @Test fun `a closed page is not revived by status churn within the same pairing`() {
        // 回归：close() 只清 open，而启动 effect 只要 transferLive 为真就再次
        // sessionStarted，pairSeq 变化触发重跑后页面自己回来——用户表现为「传输页面
        // 常驻、关不掉」。封存配对序号后，同一场配对内关闭即终态。
        val closed = LanTransferViewState().sessionStarted(host = true, seq = 7).close()
        assertFalse(closed.visible(false))
        repeat(5) {
            assertFalse(closed.shouldStart(host = true, seq = 7))
        }
        // 角色不同也算同一场配对，不应重新打开
        assertFalse(closed.shouldStart(host = false, seq = 7))
        // 对方重新配对 → 新会话，允许再开
        assertTrue(closed.shouldStart(host = true, seq = 8))
    }

    @Test fun `role change inside one pairing only updates an already open page`() {
        val opened = LanTransferViewState().sessionStarted(host = false, seq = 3)
        assertFalse(opened.shouldStart(host = false, seq = 3))
        assertTrue(opened.shouldStart(host = true, seq = 3))
        assertFalse(opened.close().shouldStart(host = true, seq = 3))
    }

    @Test fun `a restored saved page keeps working after process recreation`() {
        // rememberSaveable 会把 open/host/pairSeq 一起存盘：重建后不应因为
        // pairSeq 默认值对不上而丢掉已打开的视图。
        val saved = LanTransferViewState(open = true, host = true, pairSeq = 5)
        assertTrue(saved.visible(false))
        assertFalse(saved.shouldStart(host = true, seq = 5))
        assertTrue(saved.close().visible(false).not())
    }

    @Test fun `a sync result always wins over the disconnected notice on both roles`() {
        // 回归：结果卡原先还要求 !channelBusyElsewhere，而 syncRunning 归零与
        // _syncResult 写入之间存在重组窗口，两侧会同时不成立，总有一侧显示
        // 「已关闭」。有结果就必须出统计。
        for (viewOpen in listOf(false, true)) {
            assertEquals(
                LanSyncViewMode.RESULT,
                lanSyncViewMode(syncLive = false, hasSyncResult = true, viewOpen = viewOpen),
            )
        }
        // 没有结果但页面开过：只说已断开
        assertEquals(
            LanSyncViewMode.DISCONNECTED,
            lanSyncViewMode(syncLive = false, hasSyncResult = false, viewOpen = true),
        )
        // 两者都没有：回到扫码入口
        assertEquals(
            LanSyncViewMode.IDLE,
            lanSyncViewMode(syncLive = false, hasSyncResult = false, viewOpen = false),
        )
        // 进行中：必须是 LIVE。早先把它也归进 DISCONNECTED，于是扫码同步刚连上
        // 满屏「已断开连接」——明明正在同步。这正是本条要挡住的回归。
        assertEquals(
            LanSyncViewMode.LIVE,
            lanSyncViewMode(syncLive = true, hasSyncResult = false, viewOpen = true),
        )
        assertEquals(
            LanSyncViewMode.LIVE,
            lanSyncViewMode(syncLive = true, hasSyncResult = true, viewOpen = true),
        )
    }

    @Test fun `host summaries retain counts bytes role and every merge statistic`() {
        val report = hostSyncResultFromResponse(
            """{"lineage":"diverged","added":2,"remote_wins":3,"local_wins":4,
                "identical":5,"kept_both":6,"conflicts":7,"passkey_conflicts":8,
                "purged":9,"purge_skipped":10,"coalesced":11}""",
            localCount = 20, mergedCount = 25, remoteBytes = 8192,
        )
        assertEquals(20, report.localCount)
        assertEquals(25, report.mergedCount)
        assertEquals(8192L, report.remoteBytes)
        assertTrue(report.host)
        assertTrue(report.verified)
        assertEquals(listOf(2,3,4,5,6,7,8,9,10,11), with(report.stats) {
            listOf(added,takeRemote,takeLocal,identical,keptBoth,conflicts,passkeyConflicts,purged,purgeSkipped,coalesced)
        })
    }

    @Test fun `unchanged fast forward and local retained host results remain available`() {
        for ((key, lineage) in listOf("identical" to "same", "remote_wins" to "fast_forward", "local_wins" to "remote_stale")) {
            val report = hostSyncResultFromResponse(
                """{"$key":12,"lineage":"$lineage"}""", 12, 12, 1024,
            )
            assertEquals(12, report.stats.identical + report.stats.takeRemote + report.stats.takeLocal)
            assertEquals(lineage, report.lineage)
            assertTrue(report.verified)
        }
    }
}
