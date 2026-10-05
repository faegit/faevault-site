package com.vault.storage

import com.vault.security.SecurePreferences
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 回收站自动清理保留天数；0 表示永不自动删除。
 * 在解锁时由 VaultViewModel 读取并据此清理 trash。
 */
object TrashRetentionPref {
    private const val PREF = "pmv_trash_retention"
    private const val KEY_DAYS = "days"

    const val MIN_DAYS = 1
    const val MAX_DAYS = 365
    const val DEFAULT_DAYS = 30

    /** 滑条固定档位：一天 / 一周 / 一个月 / 三个月 / 一年。 */
    val PRESET_DAYS = intArrayOf(1, 7, 30, 90, 365)

    /** 把任意天数吸附到最近的档位值。 */
    fun snapDays(value: Int): Int {
        return PRESET_DAYS.minByOrNull { kotlin.math.abs(it - value) } ?: DEFAULT_DAYS
    }

    /** 天数对应的滑条档位下标（用于驱动 VaultSlider 的离散取值）。 */
    fun indexForDays(value: Int): Int {
        val snapped = snapDays(value)
        return PRESET_DAYS.indexOf(snapped).coerceAtLeast(0)
    }

    /** 档位下标对应的天数。 */
    fun daysForIndex(index: Int): Int =
        PRESET_DAYS.getOrElse(index.coerceIn(0, PRESET_DAYS.lastIndex)) { DEFAULT_DAYS }

    val days: MutableState<Int> = mutableStateOf(DEFAULT_DAYS)

    fun init(context: Context) {
        val p = SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
        days.value = snapDays(p.getInt(KEY_DAYS, DEFAULT_DAYS).coerceIn(MIN_DAYS, MAX_DAYS))
    }

    fun setDays(context: Context, v: Int) {
        val clamped = snapDays(v.coerceIn(MIN_DAYS, MAX_DAYS))
        if (days.value == clamped) return
        days.value = clamped
        SecurePreferences.get(context.applicationContext, com.vault.security.vaultPrefName(PREF, com.vault.security.CurrentVaultKey.current()))
            .edit().putInt(KEY_DAYS, clamped).apply()
    }
}
