package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 应用进入解锁状态后的"无操作自动锁定"配置。
 *
 * 单一档位模型：索引 0 表示关闭，其余为固定预设秒数（15s / 30s / 1min / 2min / 5min / 10min）。
 * 兼容旧字段：[enabled] 由档位派生（索引 0 → false），[seconds] 保存当前档位对应的秒数。
 */
object IdleLockPref {
    private const val PREF = "pmv_idlelock"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_SECONDS = "seconds"

    /** 滑动条档位：索引 0 = 关闭，其余为对应秒数。 */
    val PRESET_SECONDS = intArrayOf(0, 15, 30, 60, 120, 300, 600)
    const val DEFAULT_SECONDS = 60

    val enabled: MutableState<Boolean> = mutableStateOf(false)
    val seconds: MutableState<Int> = mutableStateOf(DEFAULT_SECONDS)

    fun init(context: Context) {
        val prefName = vaultPrefName(PREF, CurrentVaultKey.current())
        enabled.value = PreferencePersistence.getBoolean(context, prefName, KEY_ENABLED, false)
        seconds.value = snapSeconds(PreferencePersistence.getInt(context, prefName, KEY_SECONDS, DEFAULT_SECONDS))
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        PreferencePersistence.putBoolean(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_ENABLED, v)
    }

    fun setSeconds(context: Context, v: Int) {
        val snapped = snapSeconds(v)
        seconds.value = snapped
        PreferencePersistence.putInt(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_SECONDS, snapped)
    }

    /** 秒数对齐到最接近的启用档位（不含"关闭"档）。 */
    private fun snapSeconds(value: Int): Int =
        PRESET_SECONDS.drop(1).minByOrNull { kotlin.math.abs(it - value) } ?: DEFAULT_SECONDS

    /** 秒数 → 档位索引（0 为关闭）。 */
    fun indexForSeconds(value: Int): Int =
        PRESET_SECONDS.indexOf(snapSeconds(value)).coerceAtLeast(0)

    /** 档位索引 → 秒数（0 为关闭）。 */
    fun secondsForIndex(index: Int): Int =
        PRESET_SECONDS.getOrElse(index.coerceIn(0, PRESET_SECONDS.lastIndex)) { DEFAULT_SECONDS }

    /** 当前配置下的超时毫秒数。 */
    fun timeoutMs(): Long = seconds.value * 1000L
}
