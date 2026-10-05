package com.vault.storage

import com.vault.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class BackgroundTaskNotifierTest {
    @Test
    fun `ongoing notification is shown for any active background work`() {
        assertFalse(BackgroundTaskPolicy.shouldShowOngoing(activeCount = 0))
        assertTrue(BackgroundTaskPolicy.shouldShowOngoing(activeCount = 1))
    }

    @Test
    fun `non cloud task stays visible while the app is in the foreground`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        // appVisible 默认 true：改前这里返回 HideOngoing，通知会随进入前台被撤销。
        val started = coordinator.begin(
            task(id = "backup-export", updatedAt = 20).copy(kind = BackgroundTaskKind.DATA_IMPORT_EXPORT),
        )
        assertTrue(started.ongoing is ShowFallback)
        assertTrue(coordinator.setAppVisible(true).ongoing is ShowFallback)
        assertTrue(coordinator.setAppVisible(false).ongoing is ShowForeground)
    }

    @Test
    fun `aggregation selects latest task and clamps its progress`() {
        val older = task(id = "backup-export", updatedAt = 20, current = 2, total = 10)
        val latest = task(id = "cloud-drive", updatedAt = 30, current = 12, total = 10)

        val aggregate = aggregateBackgroundTasks(listOf(older, latest))

        assertEquals(latest, aggregate.primary)
        assertEquals(listOf(latest, older), aggregate.tasks)
        assertEquals(100, aggregate.progressPercent)
        assertEquals(
            0,
            aggregateBackgroundTasks(
                listOf(task(id = "backup-import", updatedAt = 40, current = -1, total = 10)),
            ).progressPercent,
        )
        assertEquals(
            40,
            aggregateBackgroundTasks(
                listOf(task(id = "app-update", updatedAt = 50, current = 4, total = 10)),
            ).progressPercent,
        )
        assertEquals(
            29,
            aggregateBackgroundTasks(
                listOf(task(id = "cloud-webdav", updatedAt = 60, current = 29, total = 100)),
            ).progressPercent,
        )
    }

    @Test
    fun `aggregation accepts a non-list collection`() {
        val older = task(id = "backup-export", updatedAt = 20)
        val latest = task(id = "cloud-drive", updatedAt = 30)
        val activeTasks: Collection<BackgroundTaskSnapshot> = linkedSetOf(older, latest)

        val aggregate = aggregateBackgroundTasks(activeTasks)

        assertEquals(latest, aggregate.primary)
        assertEquals(listOf(latest, older), aggregate.tasks)
    }

    @Test
    fun `progress calculation remains exact at long boundaries`() {
        assertEquals(
            100,
            aggregateBackgroundTasks(
                listOf(
                    task(
                        id = "max-complete",
                        updatedAt = 20,
                        current = Long.MAX_VALUE,
                        total = Long.MAX_VALUE,
                    ),
                ),
            ).progressPercent,
        )
        assertEquals(
            50,
            aggregateBackgroundTasks(
                listOf(
                    task(
                        id = "max-half",
                        updatedAt = 20,
                        current = Long.MAX_VALUE / 2 + 1,
                        total = Long.MAX_VALUE,
                    ),
                ),
            ).progressPercent,
        )
        assertEquals(
            0,
            aggregateBackgroundTasks(
                listOf(
                    task(
                        id = "min-current",
                        updatedAt = 20,
                        current = Long.MIN_VALUE,
                        total = Long.MAX_VALUE,
                    ),
                ),
            ).progressPercent,
        )
    }

    @Test
    fun `unknown total produces indeterminate progress`() {
        val aggregate = aggregateBackgroundTasks(
            listOf(task(id = "backup-import", updatedAt = 20, current = 5, total = 0)),
        )

        assertNull(aggregate.progressPercent)
    }

    @Test
    fun `public notification copy does not expose private task detail`() {
        val privateDomain = "vault.private.example"

        val copy = publicNotificationCopy(
            task(id = "cloud-webdav", updatedAt = 20, detail = "正在同步 $privateDomain"),
        )

        assertEquals("FAEVault 正在执行后台任务", copy)
        assertFalse(copy.contains(privateDomain))
    }

    @Test
    fun `task snapshot records one creation time and initial progress`() {
        val snapshot = taskSnapshot(
            id = "cloud-drive",
            kind = BackgroundTaskKind.CLOUD_SYNC,
            title = "云同步",
            detail = "准备同步",
        )

        assertEquals("cloud-drive", snapshot.id)
        assertEquals(BackgroundTaskKind.CLOUD_SYNC, snapshot.kind)
        assertEquals("云同步", snapshot.title)
        assertEquals("准备同步", snapshot.detail)
        assertEquals(0, snapshot.current)
        assertEquals(0, snapshot.total)
        assertEquals(snapshot.startedAt, snapshot.updatedAt)
        assertTrue(snapshot.startedAt > 0)
    }

    @Test
    fun `terminal outcomes use distinct semantic icons`() {
        val icons = BackgroundTaskOutcome.entries.associateWith(::terminalSmallIcon)

        assertEquals(R.drawable.ic_notification_task_success, icons[BackgroundTaskOutcome.SUCCESS])
        assertEquals(R.drawable.ic_notification_task_failure, icons[BackgroundTaskOutcome.FAILURE])
        assertEquals(R.drawable.ic_notification_task_interrupted, icons[BackgroundTaskOutcome.INTERRUPTED])
        assertEquals(BackgroundTaskOutcome.entries.size, icons.values.toSet().size)
    }

    @Test
    fun `finishing one task removes only that task and keeps remaining work active`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val first = task(id = "cloud-drive", updatedAt = 20)
        val second = task(id = "backup-export", updatedAt = 30)
        coordinator.setAppVisible(false)
        coordinator.begin(first)
        coordinator.begin(second)

        val dispatch = coordinator.finish(
            id = second.id,
            outcome = BackgroundTaskOutcome.SUCCESS,
            detail = "导出完成",
        )

        assertEquals(second.id, dispatch?.terminalEffects?.single()?.task?.id)
        assertEquals(BackgroundTaskOutcome.SUCCESS, dispatch?.terminalEffects?.single()?.outcome)
        assertEquals(listOf(first), (dispatch?.ongoing as ShowForeground).aggregate.tasks)
        assertEquals(listOf(first), coordinator.aggregate()?.tasks)
    }

    @Test
    fun `begin replaces the same id and update preserves task identity`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val original = task(id = "shared", updatedAt = 20).copy(
            kind = BackgroundTaskKind.LAN_TRANSFER,
            title = "旧任务",
            startedAt = 10,
        )
        val replacement = task(id = "shared", updatedAt = 40).copy(
            kind = BackgroundTaskKind.APP_UPDATE,
            title = "应用更新",
            startedAt = 30,
        )
        coordinator.begin(original)
        coordinator.begin(replacement)

        coordinator.update("shared", "已下载一半", current = 5, total = 10)

        val active = coordinator.aggregate()!!.tasks.single()
        assertEquals(BackgroundTaskKind.APP_UPDATE, active.kind)
        assertEquals("应用更新", active.title)
        assertEquals(30, active.startedAt)
        assertEquals(100, active.updatedAt)
        assertEquals("已下载一半", active.detail)
        assertEquals(5, active.current)
        assertEquals(10, active.total)
    }

    @Test
    fun `finish while visible still posts a terminal notification and duplicate finish is a no-op`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        coordinator.begin(task(id = "cloud-drive", updatedAt = 20))

        val firstFinish = coordinator.finish(
            id = "cloud-drive",
            outcome = BackgroundTaskOutcome.FAILURE,
            detail = "同步失败",
        )

        assertEquals(1, firstFinish?.terminalEffects?.size)
        assertEquals("cloud-drive", firstFinish?.terminalEffects?.single()?.task?.id)
        assertEquals(BackgroundTaskOutcome.FAILURE, firstFinish?.terminalEffects?.single()?.outcome)
        assertEquals(HideOngoing, firstFinish?.ongoing)
        assertNull(coordinator.aggregate())
        assertNull(
            coordinator.finish(
                id = "cloud-drive",
                outcome = BackgroundTaskOutcome.FAILURE,
                detail = "重复回调",
            ),
        )
    }

    @Test
    fun `legacy status updates keep the session active until explicit stop`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val legacy = task(id = "legacy", updatedAt = 20).copy(title = "保险库传输中")

        val started = coordinator.beginLegacy(legacy)
        val backgrounded = coordinator.setAppVisible(false)
        val completed = coordinator.updateLegacy(
            id = legacy.id,
            title = "保险库传输完成",
            detail = "本批传输已完成",
            current = 100,
            total = 100,
        )

        assertTrue(started.ongoing is ShowFallback)
        assertTrue(backgrounded.ongoing is ShowForeground)
        assertTrue(completed?.ongoing is ShowForeground)
        assertEquals("保险库传输完成", coordinator.aggregate()?.primary?.title)
        assertEquals("本批传输已完成", coordinator.aggregate()?.primary?.detail)
        assertEquals(HideOngoing, coordinator.abandonLegacy(legacy.id).ongoing)
        assertNull(coordinator.aggregate())

        assertEquals(HideOngoing, coordinator.setAppVisible(true).ongoing)
    }

    @Test
    fun `timeout suppression uses fallback until a visible transition resets it`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        coordinator.setAppVisible(false)
        assertTrue(coordinator.begin(task(id = "cloud-drive", updatedAt = 20)).ongoing is ShowForeground)

        assertTrue(coordinator.suppressForeground().ongoing is ShowFallback)
        assertTrue(coordinator.isForegroundSuppressed())
        assertTrue(coordinator.update("cloud-drive", "仍在同步")?.ongoing is ShowFallback)
        assertTrue(coordinator.setAppVisible(false).ongoing is ShowFallback)

        assertTrue(coordinator.setAppVisible(true).ongoing is ShowFallback)
        assertFalse(coordinator.isForegroundSuppressed())
        assertTrue(coordinator.setAppVisible(false).ongoing is ShowForeground)
    }

    @Test
    fun `late stale fallback and foreground dispatches cannot overwrite hide`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val gate = BackgroundTaskRenderGate(coordinator)
        coordinator.setAppVisible(false)
        val foreground = coordinator.begin(task(id = "cloud-drive", updatedAt = 20))
        val fallback = coordinator.suppressForeground()
        val hide = coordinator.setAppVisible(true)
        val rendered = mutableListOf<BackgroundTaskOngoingDispatch>()

        assertTrue(gate.renderIfCurrent(hide) { rendered += it.ongoing })
        assertFalse(gate.renderIfCurrent(fallback) { rendered += it.ongoing })
        assertFalse(gate.renderIfCurrent(foreground) { rendered += it.ongoing })

        assertEquals(listOf(hide.ongoing), rendered)
        assertTrue(foreground.generation < fallback.generation)
        assertTrue(fallback.generation < hide.generation)
    }

    @Test
    fun `new dispatch waiting for renderer lock wins final state`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val gate = BackgroundTaskRenderGate(coordinator)
        coordinator.setAppVisible(false)
        val foreground = coordinator.begin(task(id = "cloud-drive", updatedAt = 20))
        val firstRendererEntered = CountDownLatch(1)
        val releaseFirstRenderer = CountDownLatch(1)
        val rendered = Collections.synchronizedList(mutableListOf<BackgroundTaskOngoingDispatch>())

        val firstThread = Thread {
            gate.renderIfCurrent(foreground) { current ->
                firstRendererEntered.countDown()
                releaseFirstRenderer.await(5, TimeUnit.SECONDS)
                rendered += current.ongoing
            }
        }.apply { start() }
        assertTrue(firstRendererEntered.await(5, TimeUnit.SECONDS))

        val hide = coordinator.setAppVisible(true)
        val latestThread = Thread {
            gate.renderIfCurrent(hide) { rendered += it.ongoing }
        }.apply { start() }
        releaseFirstRenderer.countDown()
        firstThread.join(5_000)
        latestThread.join(5_000)

        assertFalse(firstThread.isAlive)
        assertFalse(latestThread.isAlive)
        assertEquals(listOf(foreground.ongoing, hide.ongoing), rendered)
        assertTrue(rendered.last() is ShowFallback)
    }

    @Test
    fun `terminal effect survives newer generation and is acknowledged exactly once`() {
        val coordinator = BackgroundTaskCoordinator(now = { 100 })
        val gate = BackgroundTaskRenderGate(coordinator)
        coordinator.setAppVisible(false)
        coordinator.begin(task(id = "cloud-drive", updatedAt = 20))
        val finish = coordinator.finish(
            id = "cloud-drive",
            outcome = BackgroundTaskOutcome.SUCCESS,
            detail = "同步完成",
        )!!
        val newer = coordinator.begin(task(id = "backup-export", updatedAt = 30))
        val delivered = mutableListOf<Long>()

        assertFalse(gate.renderIfCurrent(finish) { error("stale generation rendered") })
        assertTrue(
            gate.renderIfCurrent(newer) { current ->
                current.terminalEffects.forEach { effect ->
                    delivered += effect.sequence
                    coordinator.acknowledgeTerminal(effect.sequence)
                }
            },
        )
        assertTrue(
            gate.renderIfCurrent(coordinator.currentDispatch()) { current ->
                current.terminalEffects.forEach { delivered += it.sequence }
            },
        )

        assertEquals(1, delivered.size)
        assertTrue(coordinator.currentDispatch().terminalEffects.isEmpty())
    }

    @Test
    fun `terminal notification ids are stable and do not collide for approved tasks`() {
        val taskIds = listOf(
            "lan-sync",
            "lan-transfer",
            "lan-host",
            "cloud-drive",
            "cloud-webdav",
            "backup-export",
            "backup-import",
            "password-manager-import",
            "vault-raw-export",
            "archive-export",
            "vault-account-import",
            "database-cleanup",
            "app-update",
            "breach-check",
        )
        val notificationIds = taskIds.map(::terminalNotificationId)

        taskIds.zip(notificationIds).forEach { (taskId, notificationId) ->
            assertEquals(notificationId, terminalNotificationId(taskId))
            assertTrue(notificationId in 3_000..102_999)
        }
        assertEquals(taskIds.size, notificationIds.toSet().size)
    }

    private fun task(
        id: String,
        updatedAt: Long,
        current: Long = 0,
        total: Long = 0,
        detail: String = "",
    ) = BackgroundTaskSnapshot(
        id = id,
        kind = BackgroundTaskKind.CLOUD_SYNC,
        title = "同步",
        detail = detail,
        current = current,
        total = total,
        startedAt = 10,
        updatedAt = updatedAt,
    )
}
