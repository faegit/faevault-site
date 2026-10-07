package com.vault.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.vault.MainActivity

internal object RemoteUpdateNotifications {
    private const val CHANNEL = "remote_updates"
    private fun tag(vault: String, target: String) = "remote-update:$vault:$target"
    private fun id(vault: String, target: String) = "remote:$vault:$target".hashCode()
    fun cancel(context: Context, vault: String, target: String) {
        context.getSystemService(NotificationManager::class.java).cancel(tag(vault, target), id(vault, target))
    }
    fun show(context: Context, vault: String, target: String, detectedAt: Long) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL,
            localizeUiTextFor(context, "远端更新"), NotificationManager.IMPORTANCE_DEFAULT))
        val intent = Intent(context, MainActivity::class.java)
            .setData(android.net.Uri.Builder().scheme("faevault").authority("remote-update").appendPath(vault).appendPath(target).build())
            .putExtra("remote_update_vault", vault).putExtra("remote_update_target", target)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pending = PendingIntent.getActivity(context, id(vault, target), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val label = localizeUiTextFor(context, if (target == "drive") "云端硬盘" else "WebDAV")
        // Permission denial must never affect the persistent in-app indication.
        runCatching { manager.notify(tag(vault, target), id(vault, target), NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_notify_sync).setContentTitle(localizeUiTextFor(context, "远端有更新"))
            .setContentText(label).setWhen(detectedAt).setShowWhen(true).setContentIntent(pending)
            .setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build()) }
    }
}
