package com.vault.storage

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vault.MainActivity
import com.vault.R
import com.vault.ui.localizeUiTextFor

/** Hosts the legal foreground-service notification while registered work is backgrounded. */
class SyncForegroundService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null
    private var foregroundStarted = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val dispatch = BackgroundTaskNotifier.currentDispatch()
        val aggregate = when (val ongoing = dispatch.ongoing) {
            HideOngoing -> {
                stopForegroundAndSelf()
                return START_NOT_STICKY
            }
            is ShowFallback -> {
                clearForegroundState()
                showFallback(applicationContext, ongoing.aggregate)
                stopSelf(startId)
                return START_NOT_STICKY
            }
            is ShowForeground -> ongoing.aggregate
        }

        ensureChannels(applicationContext)
        return try {
            val notification = buildOngoingNotification(applicationContext, aggregate)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    ONGOING_NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                )
            } else {
                startForeground(ONGOING_NOTIFICATION_ID, notification)
            }
            foregroundStarted = true
            runCatching { acquireWakeLock() }
            START_STICKY
        } catch (_: SecurityException) {
            showFallback(applicationContext, aggregate)
            stopSelf(startId)
            START_NOT_STICKY
        } catch (_: RuntimeException) {
            showFallback(applicationContext, aggregate)
            stopSelf(startId)
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        releaseWakeLock()
        super.onDestroy()
    }

    @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
    override fun onTimeout(startId: Int, foregroundServiceType: Int) {
        val dispatch = BackgroundTaskNotifier.suppressForegroundService()
        clearForegroundState(forceStopForeground = true)
        (dispatch.ongoing as? ShowFallback)?.let { fallback ->
            showFallback(applicationContext, fallback.aggregate)
        }
        stopSelf(startId)
    }

    private fun stopForegroundAndSelf() {
        clearForegroundState()
        stopSelf()
    }

    private fun clearForegroundState(forceStopForeground: Boolean = false) {
        if (foregroundStarted || forceStopForeground) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
        foregroundStarted = false
        safeCancel(applicationContext, ONGOING_NOTIFICATION_ID)
        releaseWakeLock()
    }

    @SuppressLint("WakelockTimeout")
    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "vault:background-work",
        ).apply { acquire() }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { lock -> runCatching { if (lock.isHeld) lock.release() } }
        wakeLock = null
    }

    companion object {
        private const val ONGOING_CHANNEL_ID = "vault_background_work"
        private const val TERMINAL_CHANNEL_ID = "vault_background_results"
        internal const val ONGOING_NOTIFICATION_ID = 2001

        internal fun showOrRefresh(
            context: Context,
            aggregate: BackgroundTaskAggregate,
        ) {
            val applicationContext = context.applicationContext
            ensureChannels(applicationContext)
            val intent = Intent(applicationContext, SyncForegroundService::class.java)
            try {
                ContextCompat.startForegroundService(applicationContext, intent)
            } catch (_: SecurityException) {
                showFallback(applicationContext, aggregate)
            } catch (_: RuntimeException) {
                showFallback(applicationContext, aggregate)
            }
        }

        internal fun showFallback(
            context: Context,
            aggregate: BackgroundTaskAggregate,
        ) {
            val applicationContext = context.applicationContext
            ensureChannels(applicationContext)
            runCatching { buildOngoingNotification(applicationContext, aggregate) }
                .onSuccess { safeNotify(applicationContext, ONGOING_NOTIFICATION_ID, it) }
        }

        internal fun hide(context: Context) {
            val applicationContext = context.applicationContext
            runCatching {
                applicationContext.stopService(
                    Intent(applicationContext, SyncForegroundService::class.java),
                )
            }
            safeCancel(applicationContext, ONGOING_NOTIFICATION_ID)
        }

        internal fun postTerminal(
            context: Context,
            task: BackgroundTaskSnapshot,
            outcome: BackgroundTaskOutcome,
        ) {
            val applicationContext = context.applicationContext
            ensureChannels(applicationContext)
            val title = terminalTitle(applicationContext, task, outcome)
            val notificationId = terminalNotificationId(task.id)
            val smallIcon = terminalSmallIcon(outcome)
            runCatching {
                val contentIntent = launchPendingIntent(applicationContext, notificationId)
                val publicNotification = NotificationCompat.Builder(applicationContext, TERMINAL_CHANNEL_ID)
                    .setSmallIcon(smallIcon)
                    .setContentTitle("FAEVault 后台任务状态已更新")
                    .setContentText("打开应用查看详情")
                    .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                    .setAutoCancel(true)
                    .setContentIntent(contentIntent)
                    .build()
                NotificationCompat.Builder(applicationContext, TERMINAL_CHANNEL_ID)
                    .setSmallIcon(smallIcon)
                    .setContentTitle(title)
                    .setContentText(localizeUiTextFor(applicationContext, task.detail))
                    .setStyle(
                        NotificationCompat.BigTextStyle().bigText(
                            localizeUiTextFor(applicationContext, task.detail),
                        ),
                    )
                    .setContentIntent(contentIntent)
                    .setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                    .setPublicVersion(publicNotification)
                    .setOngoing(false)
                    .setAutoCancel(true)
                    .setWhen(task.updatedAt)
                    .build()
            }.onSuccess { notification ->
                safeNotify(applicationContext, notificationId, notification)
            }
        }

        internal fun terminalTitle(
            context: Context,
            task: BackgroundTaskSnapshot,
            outcome: BackgroundTaskOutcome,
        ): String {
            val base = task.title.ifBlank { backgroundTaskKindName(context, task.kind) }
            val suffix = when (outcome) {
                BackgroundTaskOutcome.SUCCESS -> "已完成"
                BackgroundTaskOutcome.FAILURE -> "失败"
                BackgroundTaskOutcome.INTERRUPTED -> "已中断"
            }
            return "${localizeUiTextFor(context, base)}${localizeUiTextFor(context, suffix)}"
        }

        internal fun backgroundTaskKindName(context: Context, kind: BackgroundTaskKind): String =
            localizeUiTextFor(
                context,
                when (kind) {
                    BackgroundTaskKind.LAN_TRANSFER -> "传输"
                    BackgroundTaskKind.CLOUD_SYNC -> "云同步"
                    BackgroundTaskKind.DATA_IMPORT_EXPORT -> "导入导出"
                    BackgroundTaskKind.DATABASE_MAINTENANCE -> "数据库维护"
                    BackgroundTaskKind.BREACH_CHECK -> "泄露检测"
                    BackgroundTaskKind.APP_UPDATE -> "应用更新"
                },
            )

        internal fun ensureChannels(context: Context) {
            runCatching {
                val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                if (manager.getNotificationChannel(ONGOING_CHANNEL_ID) == null) {
                    manager.createNotificationChannel(
                        NotificationChannel(
                            ONGOING_CHANNEL_ID,
                            "后台任务",
                            NotificationManager.IMPORTANCE_LOW,
                        ).apply { description = "FAEVault 后台任务的进行状态" },
                    )
                }
                if (manager.getNotificationChannel(TERMINAL_CHANNEL_ID) == null) {
                    manager.createNotificationChannel(
                        NotificationChannel(
                            TERMINAL_CHANNEL_ID,
                            "后台任务结果",
                            NotificationManager.IMPORTANCE_DEFAULT,
                        ).apply { description = "FAEVault 后台任务的完成、失败与中断结果" },
                    )
                }
            }
        }

        internal fun buildOngoingNotification(
            context: Context,
            aggregate: BackgroundTaskAggregate,
        ): Notification {
            val primary = aggregate.primary
            val title = if (aggregate.tasks.size == 1) {
                localizeUiTextFor(context, primary.title).ifBlank { backgroundTaskKindName(context, primary.kind) }
            } else {
                localizeUiTextFor(context, "正在执行 ${aggregate.tasks.size} 项后台任务")
            }
            val publicNotification = NotificationCompat.Builder(context, ONGOING_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_brand_lock)
                .setContentTitle(publicNotificationCopy(primary))
                .setContentText(localizeUiTextFor(context, "打开应用查看详情"))
                .setCategory(NotificationCompat.CATEGORY_PROGRESS)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(launchPendingIntent(context, ONGOING_NOTIFICATION_ID))
                .build()
            val style = NotificationCompat.InboxStyle()
            aggregate.tasks.take(5).forEach { task ->
                val taskLabel = localizeUiTextFor(context, task.title).ifBlank {
                    backgroundTaskKindName(context, task.kind)
                }
                val taskDetail = localizeUiTextFor(context, task.detail)
                val line = if (task.total > 0) {
                    val percent = (task.current.coerceIn(0, task.total) * 100L / task.total).toInt()
                    "$taskLabel · $taskDetail $percent%"
                } else {
                    "$taskLabel · $taskDetail"
                }
                style.addLine(line)
            }
            val extraCount = aggregate.tasks.size - minOf(aggregate.tasks.size, 5)
            if (extraCount > 0) {
                style.setSummaryText(localizeUiTextFor(context, "另有 $extraCount 项任务进行中"))
            }
            val builder = NotificationCompat.Builder(context, ONGOING_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_brand_lock)
                .setContentTitle(title)
                .setContentText(localizeUiTextFor(context, primary.detail))
                .setStyle(style)
                .setContentIntent(launchPendingIntent(context, ONGOING_NOTIFICATION_ID))
                .setCategory(NotificationCompat.CATEGORY_PROGRESS)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(publicNotification)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setAutoCancel(false)
                .setWhen(primary.startedAt)
                .setShowWhen(true)
                .setUsesChronometer(true)
            aggregate.progressPercent?.let { percent ->
                builder.setProgress(100, percent, false)
            } ?: builder.setProgress(0, 0, true)
            return builder.build()
        }

        private fun launchPendingIntent(context: Context, requestCode: Int): PendingIntent =
            PendingIntent.getActivity(
                context,
                requestCode,
                Intent(context, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                },
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

        @SuppressLint("MissingPermission")
        private fun safeNotify(context: Context, id: Int, notification: Notification) {
            try {
                NotificationManagerCompat.from(context).notify(id, notification)
            } catch (_: SecurityException) {
                // Notification permission can be denied without affecting the underlying task.
            } catch (_: RuntimeException) {
                // OEM notification services may reject a request; background work must continue.
            }
        }

        private fun safeCancel(context: Context, id: Int) {
            runCatching { NotificationManagerCompat.from(context).cancel(id) }
        }

        // ── Typed API（各后台任务场景统一入口） ─────────────────────────────

        internal fun beginTask(
            context: Context,
            id: String,
            kind: BackgroundTaskKind,
            title: String,
            detail: String,
        ) {
            BackgroundTaskNotifier.begin(context, taskSnapshot(id, kind, title, detail))
        }

        internal fun updateTask(
            context: Context,
            id: String,
            detail: String,
            current: Long = 0,
            total: Long = 0,
        ) {
            BackgroundTaskNotifier.update(context, id, detail, current, total)
        }

        internal fun finishTask(
            context: Context,
            id: String,
            outcome: BackgroundTaskOutcome,
            detail: String,
        ) {
            BackgroundTaskNotifier.finish(context, id, outcome, detail)
        }

        internal fun succeedTask(context: Context, id: String, detail: String) {
            BackgroundTaskNotifier.success(context, id, detail)
        }

        internal fun failTask(context: Context, id: String, detail: String) {
            BackgroundTaskNotifier.fail(context, id, detail)
        }

        internal fun interruptTask(context: Context, id: String, detail: String) {
            BackgroundTaskNotifier.interrupt(context, id, detail)
        }

        internal fun abandonTask(context: Context, id: String) {
            BackgroundTaskNotifier.abandon(context, id)
        }
    }
}

internal fun terminalSmallIcon(outcome: BackgroundTaskOutcome): Int = when (outcome) {
    BackgroundTaskOutcome.SUCCESS -> R.drawable.ic_notification_task_success
    BackgroundTaskOutcome.FAILURE -> R.drawable.ic_notification_task_failure
    BackgroundTaskOutcome.INTERRUPTED -> R.drawable.ic_notification_task_interrupted
}
