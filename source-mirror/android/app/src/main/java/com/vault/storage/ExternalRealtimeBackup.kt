package com.vault.storage

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.storage.StorageManager
import android.os.storage.StorageVolume
import android.provider.DocumentsContract
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vault.R
import com.vault.security.LocalBackupPref
import java.io.File
import java.io.FileNotFoundException
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Prevents duplicate mount broadcasts from copying the same vault concurrently in one process. */
internal object LocalBackupRunGuard {
    private val running = AtomicBoolean(false)

    fun tryAcquire(): Boolean = running.compareAndSet(false, true)
    fun release() = running.set(false)
}

/** 进程不在时仍可由系统挂载事件唤醒，并立即交给持久后台任务。 */
class ExternalBackupMountReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_MEDIA_MOUNTED && isExternalVolumeMount(context, intent)) {
            ExternalRealtimeBackupScheduler.enqueueIfEligible(context, notifyConnection = true)
        }
    }

    private fun isExternalVolumeMount(context: Context, intent: Intent): Boolean = runCatching {
        val path = intent.data?.path ?: return@runCatching true
        val volume = (context.getSystemService(Context.STORAGE_SERVICE) as StorageManager)
            .getStorageVolume(File(path)) ?: return@runCatching true
        volume.isRemovable || !volume.isPrimary
    }.getOrDefault(true)
}

object ExternalRealtimeBackupScheduler {
    private const val UNIQUE_WORK = "external-realtime-local-backup"
    internal const val INPUT_NOTIFY_CONNECTION = "notify_connection"

    fun enqueueIfEligible(context: Context, notifyConnection: Boolean = false): Boolean {
        val appContext = context.applicationContext
        val registry = VaultRegistry(appContext)
        var eligible = false
        for (vaultName in registry.list()) {
            if (LocalBackupPref.deviceUuid(appContext, vaultName).isNullOrBlank()) continue
            if (LocalBackupPolicy.shouldTriggerExternalConnectionCheck(
                    enabled = LocalBackupPref.isEnabled(appContext, vaultName),
                    intervalMillis = LocalBackupPref.interval(appContext, vaultName),
                    expectedVolumeIdentity = LocalBackupPref.volumeId(appContext, vaultName),
                )
            ) {
                eligible = true
                break
            }
        }
        if (!eligible) return false

        val work = OneTimeWorkRequestBuilder<ExternalRealtimeBackupWorker>()
            .setInputData(androidx.work.workDataOf(INPUT_NOTIFY_CONNECTION to notifyConnection))
            .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            .setBackoffCriteria(
                androidx.work.BackoffPolicy.LINEAR,
                10,
                TimeUnit.SECONDS,
            )
            .build()
        WorkManager.getInstance(appContext).enqueueUniqueWork(
            UNIQUE_WORK,
            ExistingWorkPolicy.KEEP,
            work,
        )
        return true
    }
}

/**
 * 进程存活时使用 StorageVolumeCallback 补充系统广播；Activity 恢复时还会主动补检一次，
 * 覆盖应用被强停、升级或广播到达前进程尚未启动等场景。
 */
object ExternalStorageMonitor {
    private val callbackRegistered = AtomicBoolean(false)

    fun start(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && callbackRegistered.compareAndSet(false, true)) {
            if (!Api30ExternalStorageMonitor.register(context.applicationContext)) {
                callbackRegistered.set(false)
            }
        }
    }

    fun checkNow(context: Context) {
        val appContext = context.applicationContext
        val registry = VaultRegistry(appContext)
        var shouldEnqueue = false
        for (vaultName in registry.list()) {
            if (LocalBackupPref.deviceUuid(appContext, vaultName).isNullOrBlank()) continue
            if (LocalBackupPolicy.shouldRunExternalConnectionBackup(
                    enabled = LocalBackupPref.isEnabled(appContext, vaultName),
                    nowMillis = System.currentTimeMillis(),
                    lastBackupMillis = LocalBackupPref.lastBackupAt(appContext, vaultName),
                    intervalMillis = LocalBackupPref.interval(appContext, vaultName),
                    expectedVolumeIdentity = LocalBackupPref.volumeId(appContext, vaultName),
                )
            ) {
                shouldEnqueue = true
                break
            }
        }
        if (shouldEnqueue) {
            ExternalRealtimeBackupScheduler.enqueueIfEligible(appContext)
        }
    }
}

@RequiresApi(Build.VERSION_CODES.R)
private object Api30ExternalStorageMonitor {
    private val callbackExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "vault-storage-monitor").apply { isDaemon = true }
    }
    @Volatile private var appContext: Context? = null
    private val callback = object : StorageManager.StorageVolumeCallback() {
        override fun onStateChanged(volume: StorageVolume) {
            if (volume.state == Environment.MEDIA_MOUNTED && (volume.isRemovable || !volume.isPrimary)) {
                appContext?.let { context ->
                    ExternalRealtimeBackupScheduler.enqueueIfEligible(context, notifyConnection = true)
                }
            }
        }
    }

    fun register(context: Context): Boolean {
        appContext = context
        val storageManager = context.getSystemService(Context.STORAGE_SERVICE) as StorageManager
        return runCatching {
            storageManager.registerStorageVolumeCallback(callbackExecutor, callback)
        }.isSuccess
    }
}

class ExternalRealtimeBackupWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val notifyConnection = inputData.getBoolean(ExternalRealtimeBackupScheduler.INPUT_NOTIFY_CONNECTION, false)
        val registry = VaultRegistry(applicationContext)
        val due = mutableListOf<String>()
        for (vaultName in registry.list()) {
            val deviceUuid = LocalBackupPref.deviceUuid(applicationContext, vaultName)
            if (deviceUuid.isNullOrBlank()) continue
            val expectedIdentity = LocalBackupPref.volumeId(applicationContext, vaultName) ?: continue
            if (!LocalBackupPolicy.shouldTriggerExternalConnectionCheck(
                    enabled = LocalBackupPref.isEnabled(applicationContext, vaultName),
                    intervalMillis = LocalBackupPref.interval(applicationContext, vaultName),
                    expectedVolumeIdentity = expectedIdentity,
                )
            ) continue
            when (ExternalRealtimeBackupCopier.configuredTargetStatus(applicationContext, vaultName, expectedIdentity)) {
                ExternalRealtimeBackupCopier.TargetStatus.SUSPECTED_ORIGINAL -> {
                    if (notifyConnection) showStatusNotification(R.string.viewmodel_backup_suspected_original)
                    continue
                }
                ExternalRealtimeBackupCopier.TargetStatus.IDENTITY_ANOMALY -> {
                    if (notifyConnection) showStatusNotification(R.string.viewmodel_backup_identity_anomaly)
                    continue
                }
                ExternalRealtimeBackupCopier.TargetStatus.NEW_DEVICE -> {
                    if (notifyConnection) showStatusNotification(R.string.viewmodel_backup_new_device)
                    continue
                }
                ExternalRealtimeBackupCopier.TargetStatus.NOT_READY -> {
                    // 设备未连接：不重试、不通知（静默），与"已连接并备份"区分开。
                    continue
                }
                ExternalRealtimeBackupCopier.TargetStatus.AVAILABLE -> Unit
            }
            if (!LocalBackupPolicy.shouldRun(
                    nowMillis = System.currentTimeMillis(),
                    lastBackupMillis = LocalBackupPref.lastBackupAt(applicationContext, vaultName),
                    intervalMillis = LocalBackupPref.interval(applicationContext, vaultName),
                )
            ) {
                // 设备已连接但周期未到：本轮不触发备份，不通知。
                continue
            }
            due.add(vaultName)
        }
        if (due.isEmpty()) return Result.success()
        if (!LocalBackupRunGuard.tryAcquire()) return Result.success()
        return try {
            setForeground(createForegroundInfo())
            for (vaultName in due) {
                val expectedIdentity = LocalBackupPref.volumeId(applicationContext, vaultName) ?: continue
                when (ExternalRealtimeBackupCopier.copyCurrentVault(applicationContext, vaultName, expectedIdentity)) {
                    ExternalRealtimeBackupCopier.Outcome.COPIED -> showCompletedNotification()
                    ExternalRealtimeBackupCopier.Outcome.DEVICE_NOT_READY ->
                        // 设备中途断开：静默，不重试也不通知
                        continue
                    ExternalRealtimeBackupCopier.Outcome.SUSPECTED_ORIGINAL ->
                        showStatusNotification(R.string.viewmodel_backup_suspected_original)
                    ExternalRealtimeBackupCopier.Outcome.IDENTITY_ANOMALY ->
                        showStatusNotification(R.string.viewmodel_backup_identity_anomaly)
                    ExternalRealtimeBackupCopier.Outcome.NEW_DEVICE ->
                        showStatusNotification(R.string.viewmodel_backup_new_device)
                    ExternalRealtimeBackupCopier.Outcome.NO_CURRENT_VAULT ->
                        showStatusNotification(R.string.viewmodel_backup_connected_no_vault)
                    ExternalRealtimeBackupCopier.Outcome.NOT_ENOUGH_SPACE ->
                        showStatusNotification(R.string.viewmodel_backup_space_skipped)
                    ExternalRealtimeBackupCopier.Outcome.FAILED ->
                        showStatusNotification(R.string.viewmodel_backup_connected_failed)
                }
            }
            Result.success()
        } finally {
            LocalBackupRunGuard.release()
        }
    }

    private fun createForegroundInfo(): ForegroundInfo {
        ensureNotificationChannel()
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_task_success)
            .setContentTitle(applicationContext.getString(R.string.app_name))
            .setContentText(applicationContext.getString(R.string.viewmodel_backup_connected_in_progress))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(appLaunchPendingIntent())
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            ForegroundInfo(NOTIFICATION_ID, notification)
        }
    }

    private fun showCompletedNotification() {
        showStatusNotification(R.string.viewmodel_backup_background_completed)
    }

    private fun showStatusNotification(textRes: Int) {
        ensureNotificationChannel()
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_task_success)
            .setContentTitle(applicationContext.getString(R.string.app_name))
            .setContentText(applicationContext.getString(textRes))
            .setAutoCancel(true)
            .setContentIntent(appLaunchPendingIntent())
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        (applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(COMPLETED_NOTIFICATION_ID, notification)
    }

    private fun appLaunchPendingIntent(): PendingIntent {
        val intent = applicationContext.packageManager.getLaunchIntentForPackage(applicationContext.packageName)
            ?: Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
                setPackage(applicationContext.packageName)
            }
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        return PendingIntent.getActivity(
            applicationContext,
            CONTENT_INTENT_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun ensureNotificationChannel() {        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    applicationContext.getString(R.string.viewmodel_backup_notification_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }

    private companion object {
        const val CHANNEL_ID = "local_backup"
        const val NOTIFICATION_ID = 24041
        const val COMPLETED_NOTIFICATION_ID = 24042
        const val CONTENT_INTENT_REQUEST_CODE = 24043
    }
}

internal object ExternalRealtimeBackupCopier {
    enum class TargetStatus {
        AVAILABLE,
        NOT_READY,
        SUSPECTED_ORIGINAL,
        IDENTITY_ANOMALY,
        NEW_DEVICE,
    }

    enum class Outcome {
        COPIED,
        DEVICE_NOT_READY,
        SUSPECTED_ORIGINAL,
        IDENTITY_ANOMALY,
        NEW_DEVICE,
        NO_CURRENT_VAULT,
        NOT_ENOUGH_SPACE,
        FAILED,
    }

    internal fun blockedTargetStatus(bindingState: StorageBindingState): TargetStatus? = when (bindingState) {
        StorageBindingState.KNOWN -> null
        StorageBindingState.SUSPECTED_ORIGINAL -> TargetStatus.SUSPECTED_ORIGINAL
        StorageBindingState.IDENTITY_ANOMALY -> TargetStatus.IDENTITY_ANOMALY
        StorageBindingState.NEW_DEVICE -> TargetStatus.NEW_DEVICE
    }

    internal fun blockedOutcome(bindingState: StorageBindingState): Outcome? = when (bindingState) {
        StorageBindingState.KNOWN -> null
        StorageBindingState.SUSPECTED_ORIGINAL -> Outcome.SUSPECTED_ORIGINAL
        StorageBindingState.IDENTITY_ANOMALY -> Outcome.IDENTITY_ANOMALY
        StorageBindingState.NEW_DEVICE -> Outcome.NEW_DEVICE
    }

    /** 轻量预检，避免目标未连接时启动前台复制通知，并区分错盘提示。 */
    fun configuredTargetStatus(context: Context, vaultKey: String, expectedIdentity: String): TargetStatus = runCatching {
        val rawUri = LocalBackupPref.treeUri(context, vaultKey) ?: return@runCatching TargetStatus.NOT_READY
        val treeUri = Uri.parse(rawUri)
        val currentIdentity = StorageVolumeResolver.resolve(context, treeUri)?.identityKey
            ?: return@runCatching TargetStatus.NOT_READY
        val observedUuid = when (val marker = SafDeviceMarker.read(context, treeUri)) {
            is SafDeviceMarker.ReadResult.Valid -> marker.deviceUuid
            else -> null
        }
        val bindingState = StorageBindingPolicy.evaluate(
            LocalBackupPref.deviceUuid(context, vaultKey),
            StorageVolumeResolver.stableCore(expectedIdentity),
            observedUuid,
            StorageVolumeResolver.stableCore(currentIdentity),
        )
        blockedTargetStatus(bindingState)?.let { return@runCatching it }
        val rootId = DocumentsContract.getTreeDocumentId(treeUri)
        val rootUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)
        val available = context.contentResolver.query(
            rootUri,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID),
            null,
            null,
            null,
        )?.use { cursor -> cursor.moveToFirst() } == true
        if (available) TargetStatus.AVAILABLE else TargetStatus.NOT_READY
    }.getOrDefault(TargetStatus.NOT_READY)

    fun copyCurrentVault(context: Context, vaultName: String, expectedIdentity: String): Outcome {
        return try {
        val rawUri = LocalBackupPref.treeUri(context, vaultName) ?: return Outcome.DEVICE_NOT_READY
        val treeUri = Uri.parse(rawUri)
        val currentIdentity = StorageVolumeResolver.resolve(context, treeUri)?.identityKey
            ?: return Outcome.DEVICE_NOT_READY
        val observedUuid = when (val marker = SafDeviceMarker.read(context, treeUri)) {
            is SafDeviceMarker.ReadResult.Valid -> marker.deviceUuid
            else -> null
        }
        val bindingState = StorageBindingPolicy.evaluate(
            LocalBackupPref.deviceUuid(context, vaultName),
            StorageVolumeResolver.stableCore(expectedIdentity),
            observedUuid,
            StorageVolumeResolver.stableCore(currentIdentity),
        )
        blockedOutcome(bindingState)?.let { return it }

        val rootId = DocumentsContract.getTreeDocumentId(treeUri)
        val source = VaultRegistry(context).fileFor(vaultName)
        if (!source.isFile) return Outcome.NO_CURRENT_VAULT
        val resolver = context.contentResolver
        val rootUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)
        val targetName = "$vaultName.pmv"
        val partialName = "$targetName.backup-partial"

        val volumeDir = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching {
                (context.getSystemService(Context.STORAGE_SERVICE) as StorageManager)
                    .getStorageVolume(treeUri)?.directory
            }.getOrNull()
        } else {
            null
        }
        if (volumeDir != null && source.length() > StatFs(volumeDir.absolutePath).availableBytes) {
            return Outcome.NOT_ENOUGH_SPACE
        }

        fun findChild(name: String): Uri? {
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, rootId)
            resolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                ),
                null,
                null,
                null,
            )?.use { cursor ->
                while (cursor.moveToNext()) {
                    if (cursor.getString(1) == name) {
                        return DocumentsContract.buildDocumentUriUsingTree(treeUri, cursor.getString(0))
                    }
                }
            }
            return null
        }

        val digest = MessageDigest.getInstance("SHA-256")
        var partialUri = findChild(partialName)
        if (partialUri != null) {
            // A size-only checkpoint cannot prove that the source prefix is unchanged.
            // Restart from byte zero rather than concatenate bytes from two source versions.
            runCatching { DocumentsContract.deleteDocument(resolver, partialUri) }
            partialUri = null
        }
        LocalBackupPref.setJournal(context, vaultName, source.length(), targetName, partialName)
        if (partialUri == null) {
            partialUri = DocumentsContract.createDocument(
                resolver,
                rootUri,
                "application/octet-stream",
                partialName,
            ) ?: return Outcome.FAILED
        }

        resolver.openOutputStream(partialUri, "w")?.use { output ->
            source.inputStream().buffered().use { input ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    output.write(buffer, 0, count)
                    digest.update(buffer, 0, count)
                }
            }
            output.flush()
            (output as? java.io.FileOutputStream)?.fd?.sync()
        } ?: return Outcome.FAILED
        val sourceHash = digest.digest()

        val verifyDigest = MessageDigest.getInstance("SHA-256")
        val verifiedSize = resolver.openInputStream(partialUri)?.use { input ->
            var total = 0L
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                verifyDigest.update(buffer, 0, count)
                total += count
            }
            total
        } ?: return Outcome.FAILED
        if (verifiedSize != source.length() ||
            !MessageDigest.isEqual(verifyDigest.digest(), sourceHash)
        ) {
            return Outcome.FAILED
        }

        if (findChild(targetName) != null) {
            val oldestName = "$targetName.history.4"
            findChild(oldestName)?.let {
                check(DocumentsContract.deleteDocument(resolver, it)) { "无法清理最旧备份" }
            }
            for (generation in 3 downTo 1) {
                val olderName = "$targetName.history.$generation"
                findChild(olderName)?.let {
                    check(DocumentsContract.renameDocument(resolver, it,
                        "$targetName.history.${generation + 1}") != null) { "无法轮转备份历史" }
                }
            }
            findChild(targetName)?.let {
                check(DocumentsContract.renameDocument(resolver, it,
                    "$targetName.history.1") != null) { "无法保留上一份备份" }
            }
        }
        DocumentsContract.renameDocument(resolver, partialUri, targetName) ?: return Outcome.FAILED

        val manifestName = "$targetName.manifest.json"
        findChild(manifestName)?.let { DocumentsContract.deleteDocument(resolver, it) }
        DocumentsContract.createDocument(resolver, rootUri, "application/json", manifestName)?.let { manifestUri ->
            resolver.openOutputStream(manifestUri, "w")?.use { output ->
                output.write(
                    org.json.JSONObject()
                        .put("file", targetName)
                        .put("size", source.length())
                        .put("sha256", sourceHash.joinToString("") { "%02x".format(it.toInt() and 0xff) })
                        .put("created_at", System.currentTimeMillis() / 1000.0)
                        .put("resumed", false)
                        .toString()
                        .toByteArray(),
                )
            }
        }
        LocalBackupPref.clearJournal(context, vaultName)
        LocalBackupPref.setLastBackupAt(context, vaultName, System.currentTimeMillis())
            Outcome.COPIED
        } catch (error: Exception) {
            val missing = error is FileNotFoundException ||
                (error is IllegalArgumentException && error.message.orEmpty().contains("No root", ignoreCase = true))
            if (missing) Outcome.DEVICE_NOT_READY else Outcome.FAILED
        }
    }

    private const val BUFFER_SIZE = 1024 * 1024
}
