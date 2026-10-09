package com.vault.security

import android.content.Context
import android.util.Log
import com.vault.storage.PreferenceWriteQueue
import com.vault.storage.PendingPreferenceValues
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/** Application-owned persistence for ordinary settings, never credential or permission grants. */
internal object PreferencePersistence {
    private val pending = PendingPreferenceValues()
    private val queue = PreferenceWriteQueue(CoroutineScope(SupervisorJob() + Dispatchers.IO)) {
        Log.e("PreferencePersistence", "Unable to persist setting", it)
    }

    fun putBoolean(context: Context, prefName: String, key: String, value: Boolean) {
        val app = context.applicationContext
        val token = pending.stage(prefName, key, value)
        queue.submit {
            SecurePreferences.get(app, prefName).edit().putBoolean(key, value).apply()
            pending.persisted(token)
        }
    }

    fun putInt(context: Context, prefName: String, key: String, value: Int) {
        val app = context.applicationContext
        val token = pending.stage(prefName, key, value)
        queue.submit {
            SecurePreferences.get(app, prefName).edit().putInt(key, value).apply()
            pending.persisted(token)
        }
    }

    fun putString(context: Context, prefName: String, key: String, value: String) {
        val app = context.applicationContext
        val token = pending.stage(prefName, key, value)
        queue.submit {
            SecurePreferences.get(app, prefName).edit().putString(key, value).apply()
            pending.persisted(token)
        }
    }

    fun getBoolean(context: Context, prefName: String, key: String, fallback: Boolean): Boolean =
        pending.value(prefName, key) as? Boolean
            ?: SecurePreferences.get(context.applicationContext, prefName).getBoolean(key, fallback)

    fun getInt(context: Context, prefName: String, key: String, fallback: Int): Int =
        pending.value(prefName, key) as? Int
            ?: SecurePreferences.get(context.applicationContext, prefName).getInt(key, fallback)

    fun getString(context: Context, prefName: String, key: String, fallback: String?): String? =
        pending.value(prefName, key) as? String
            ?: SecurePreferences.get(context.applicationContext, prefName).getString(key, fallback)
}
