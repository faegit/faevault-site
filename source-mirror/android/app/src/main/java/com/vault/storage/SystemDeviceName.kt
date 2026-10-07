package com.vault.storage

import android.content.Context
import android.os.Build
import android.provider.Settings

/** Same setting used by Android's About phone > Device name page; no Bluetooth permission. */
internal object SystemDeviceName {
    fun read(context: Context): String = resolve(
        runCatching { Settings.Global.getString(context.contentResolver, "device_name") }.getOrNull(),
        Build.MODEL,
    )

    fun resolve(systemName: String?, model: String?): String =
        sequenceOf(systemName, model, "Android").mapNotNull { it?.trim()?.takeIf(String::isNotEmpty) }
            .first().take(64)
}
