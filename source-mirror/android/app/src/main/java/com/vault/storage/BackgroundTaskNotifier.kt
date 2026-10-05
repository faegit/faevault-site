package com.vault.storage

import android.content.Context
import java.math.BigInteger

internal enum class BackgroundTaskKind {
    LAN_TRANSFER,
    CLOUD_SYNC,
    DATA_IMPORT_EXPORT,
    DATABASE_MAINTENANCE,
    BREACH_CHECK,
    APP_UPDATE,
}

internal enum class BackgroundTaskOutcome {
    SUCCESS,
    FAILURE,
    INTERRUPTED,
}

internal data class BackgroundTaskSnapshot(
    val id: String,
    val kind: BackgroundTaskKind,
    val title: String,
    val detail: String,
    val current: Long = 0,
    val total: Long = 0,
    val startedAt: Long,
    val updatedAt: Long,
)

internal data class BackgroundTaskAggregate(
    val primary: BackgroundTaskSnapshot,
    val tasks: List<BackgroundTaskSnapshot>,
    val progressPercent: Int?,
)

internal object BackgroundTaskPolicy {
    /** 只要有进行中的后台任务就保持通知可见，不再区分前后台。 */
    fun shouldShowOngoing(activeCount: Int): Boolean = activeCount > 0
}

internal sealed interface BackgroundTaskOngoingDispatch

internal data class ShowForeground(
    val aggregate: BackgroundTaskAggregate,
) : BackgroundTaskOngoingDispatch

internal data class ShowFallback(
    val aggregate: BackgroundTaskAggregate,
) : BackgroundTaskOngoingDispatch

internal data object HideOngoing : BackgroundTaskOngoingDispatch

internal data class BackgroundTaskTerminalEffect(
    val sequence: Long,
    val task: BackgroundTaskSnapshot,
    val outcome: BackgroundTaskOutcome,
)

internal data class BackgroundTaskDispatch(
    val generation: Long,
    val ongoing: BackgroundTaskOngoingDispatch,
    val terminalEffects: List<BackgroundTaskTerminalEffect> = emptyList(),
)

/**
 * Pure synchronized state machine. Every returned dispatch is immutable and safe to render later.
 *
 * The coordinator owns the *state lock*: generation increments on every effective transition and
 * unconfirmed terminal effects are retained for delivery. Rendering order is NOT governed here —
 * [BackgroundTaskRenderGate] owns that separate lock.
 */
internal class BackgroundTaskCoordinator(
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val active = linkedMapOf<String, BackgroundTaskSnapshot>()
    private var appVisible = true
    private var foregroundSuppressed = false
    private var generation = 0L
    private var nextTerminalSequence = 0L
    private val pendingTerminal = mutableListOf<BackgroundTaskTerminalEffect>()

    @Synchronized
    fun begin(snapshot: BackgroundTaskSnapshot): BackgroundTaskDispatch {
        active[snapshot.id] = snapshot
        return dispatchNext()
    }

    @Synchronized
    fun beginLegacy(snapshot: BackgroundTaskSnapshot): BackgroundTaskDispatch {
        active[snapshot.id] = snapshot
        return dispatchNext()
    }

    @Synchronized
    fun update(
        id: String,
        detail: String,
        current: Long = 0,
        total: Long = 0,
    ): BackgroundTaskDispatch? {
        val previous = active[id] ?: return null
        active[id] = previous.copy(
            detail = detail,
            current = current,
            total = total,
            updatedAt = now(),
        )
        return dispatchNext()
    }

    @Synchronized
    fun updateLegacy(
        id: String,
        title: String,
        detail: String,
        current: Long = 0,
        total: Long = 0,
    ): BackgroundTaskDispatch? {
        val previous = active[id] ?: return null
        active[id] = previous.copy(
            title = title,
            detail = detail,
            current = current,
            total = total,
            updatedAt = now(),
        )
        return dispatchNext()
    }

    @Synchronized
    fun finish(
        id: String,
        outcome: BackgroundTaskOutcome,
        detail: String,
    ): BackgroundTaskDispatch? {
        val previous = active.remove(id) ?: return null
        val finished = previous.copy(detail = detail, updatedAt = now())
        // 完成/失败通知一律入队：应用在前台时也照常提示，不再因为"可见"而丢弃。
        pendingTerminal += BackgroundTaskTerminalEffect(
            sequence = nextTerminalSequence++,
            task = finished,
            outcome = outcome,
        )
        return dispatchNext()
    }

    @Synchronized
    fun abandonLegacy(id: String): BackgroundTaskDispatch {
        active.remove(id)
        return dispatchNext()
    }

    @Synchronized
    fun setAppVisible(visible: Boolean): BackgroundTaskDispatch {
        appVisible = visible
        if (visible) foregroundSuppressed = false
        return dispatchNext()
    }

    @Synchronized
    fun suppressForeground(): BackgroundTaskDispatch {
        foregroundSuppressed = true
        return dispatchNext()
    }

    @Synchronized
    fun currentDispatch(): BackgroundTaskDispatch = snapshot()

    @Synchronized
    fun currentGeneration(): Long = generation

    @Synchronized
    fun aggregate(): BackgroundTaskAggregate? = aggregateLocked()

    @Synchronized
    fun isAppVisible(): Boolean = appVisible

    @Synchronized
    fun isForegroundSuppressed(): Boolean = foregroundSuppressed

    /** Confirms one terminal effect was handed to a serialized render; removes it from pending delivery. */
    @Synchronized
    fun acknowledgeTerminal(sequence: Long) {
        pendingTerminal.removeAll { it.sequence == sequence }
    }

    private fun dispatchNext(): BackgroundTaskDispatch {
        generation += 1
        return snapshot()
    }

    private fun snapshot(): BackgroundTaskDispatch {
        val aggregate = aggregateLocked()
        val ongoing = when {
            aggregate == null -> HideOngoing
            // 应用在前台也保留后台任务通知：切前后台不再反复撤销/重建通知，
            // 任务状态全程可见。前台走 fallback 通知，不起停前台服务
            // （前台服务只在真正后台时承担前台角色）。
            appVisible -> ShowFallback(aggregate)
            // 前台服务被系统超时降级：同样退回 fallback，直到下次可见性切换复位。
            foregroundSuppressed -> ShowFallback(aggregate)
            else -> ShowForeground(aggregate)
        }
        return BackgroundTaskDispatch(
            generation = generation,
            ongoing = ongoing,
            terminalEffects = pendingTerminal.toList(),
        )
    }

    private fun aggregateLocked(): BackgroundTaskAggregate? =
        active.values.takeIf { it.isNotEmpty() }?.let(::aggregateBackgroundTasks)
}

/**
 * Owns the *render ordering lock*, independent of the coordinator's state lock.
 *
 * Only the dispatch whose generation matches the coordinator's current generation may render;
 * a newer state waiting for the lock eventually overwrites the caller. Terminal effects ride on
 * whichever generation is current and are confirmed only after this gate lets them through.
 */
internal class BackgroundTaskRenderGate(
    private val coordinator: BackgroundTaskCoordinator,
) {
    private val renderLock = Any()

    fun renderIfCurrent(
        dispatch: BackgroundTaskDispatch,
        block: (BackgroundTaskDispatch) -> Unit,
    ): Boolean = synchronized(renderLock) {
        if (dispatch.generation != coordinator.currentGeneration()) {
            false
        } else {
            block(dispatch)
            true
        }
    }
}

/**
 * Process-local source of truth for user-visible background work.
 *
 * The registry deliberately stores no [Context]. Callers may pass an Activity, but every
 * rendering operation is handed its application context so task tracking cannot leak UI objects.
 */
internal object BackgroundTaskNotifier {
    private val coordinator = BackgroundTaskCoordinator()
    private val renderGate = BackgroundTaskRenderGate(coordinator)

    fun begin(context: Context, snapshot: BackgroundTaskSnapshot) {
        render(context.applicationContext, coordinator.begin(snapshot))
    }

    fun update(
        context: Context,
        id: String,
        detail: String,
        current: Long = 0,
        total: Long = 0,
    ) {
        val dispatch = coordinator.update(id, detail, current, total) ?: return
        render(context.applicationContext, dispatch)
    }

    fun finish(
        context: Context,
        id: String,
        outcome: BackgroundTaskOutcome,
        detail: String,
    ) {
        val dispatch = coordinator.finish(id, outcome, detail) ?: return
        render(context.applicationContext, dispatch)
    }

    fun setAppVisible(context: Context, visible: Boolean) {
        render(context.applicationContext, coordinator.setAppVisible(visible))
    }

    /** Stops tracking a task without posting a terminal notification (user-cancelled / teardown). */
    fun abandon(context: Context, id: String) {
        render(context.applicationContext, coordinator.abandonLegacy(id))
    }

    fun aggregate(): BackgroundTaskAggregate? = coordinator.aggregate()

    fun isAppVisible(): Boolean = coordinator.isAppVisible()

    fun success(context: Context, id: String, detail: String) {
        finish(context, id, BackgroundTaskOutcome.SUCCESS, detail)
    }

    fun fail(context: Context, id: String, detail: String) {
        finish(context, id, BackgroundTaskOutcome.FAILURE, detail)
    }

    fun interrupt(context: Context, id: String, detail: String) {
        finish(context, id, BackgroundTaskOutcome.INTERRUPTED, detail)
    }

    internal fun beginLegacy(context: Context, snapshot: BackgroundTaskSnapshot) {
        render(context.applicationContext, coordinator.beginLegacy(snapshot))
    }

    internal fun updateLegacy(
        context: Context,
        id: String,
        title: String,
        detail: String,
        current: Long = 0,
        total: Long = 0,
    ) {
        val dispatch = coordinator.updateLegacy(id, title, detail, current, total) ?: return
        render(context.applicationContext, dispatch)
    }

    internal fun abandonLegacy(context: Context, id: String) {
        render(context.applicationContext, coordinator.abandonLegacy(id))
    }

    /** Called by API 35 timeout before service cleanup so later updates stay on fallback mode. */
    internal fun suppressForegroundService(): BackgroundTaskDispatch =
        coordinator.suppressForeground()

    internal fun currentDispatch(): BackgroundTaskDispatch = coordinator.currentDispatch()

    private fun render(applicationContext: Context, dispatch: BackgroundTaskDispatch) {
        renderGate.renderIfCurrent(dispatch) { current ->
            current.terminalEffects.forEach { effect ->
                SyncForegroundService.postTerminal(
                    applicationContext,
                    effect.task,
                    effect.outcome,
                )
                coordinator.acknowledgeTerminal(effect.sequence)
            }
            when (val ongoing = current.ongoing) {
                is ShowForeground -> SyncForegroundService.showOrRefresh(
                    applicationContext,
                    ongoing.aggregate,
                )
                is ShowFallback -> SyncForegroundService.showFallback(
                    applicationContext,
                    ongoing.aggregate,
                )
                HideOngoing -> SyncForegroundService.hide(applicationContext)
            }
        }
    }
}

internal fun aggregateBackgroundTasks(tasks: Collection<BackgroundTaskSnapshot>): BackgroundTaskAggregate {
    require(tasks.isNotEmpty()) { "At least one background task is required" }
    val ordered = tasks.sortedByDescending { it.updatedAt }
    val primary = ordered.first()
    val progressPercent = if (primary.total > 0) {
        val current = primary.current.coerceIn(0, primary.total)
        BigInteger.valueOf(current)
            .multiply(BigInteger.valueOf(100))
            .divide(BigInteger.valueOf(primary.total))
            .toInt()
            .coerceIn(0, 100)
    } else {
        null
    }
    return BackgroundTaskAggregate(
        primary = primary,
        tasks = ordered,
        progressPercent = progressPercent,
    )
}

internal fun publicNotificationCopy(
    @Suppress("UNUSED_PARAMETER") task: BackgroundTaskSnapshot,
): String = "FAEVault 正在执行后台任务"

internal fun taskSnapshot(
    id: String,
    kind: BackgroundTaskKind,
    title: String,
    detail: String,
): BackgroundTaskSnapshot {
    val now = System.currentTimeMillis()
    return BackgroundTaskSnapshot(
        id = id,
        kind = kind,
        title = title,
        detail = detail,
        startedAt = now,
        updatedAt = now,
    )
}

internal fun terminalNotificationId(taskId: String): Int =
    3_000 + (taskId.hashCode() and Int.MAX_VALUE) % 100_000
