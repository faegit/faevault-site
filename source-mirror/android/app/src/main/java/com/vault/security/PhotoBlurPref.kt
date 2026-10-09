package com.vault.security
import android.content.Context
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf

/**
 * 开启后详情页缩略图始终模糊，查看器在通过所需验证后显示原图。
 * 与二次保护独立：关闭此开关不能解除敏感照片的验证要求。
 */
object PhotoBlurPref {
    private const val PREF = "pmv_photo_blur"
    private const val KEY_ENABLED = "enabled"
    const val DEFAULT_ENABLED = true

    val enabled: MutableState<Boolean> = mutableStateOf(DEFAULT_ENABLED)

    fun init(context: Context) {
        val prefName = vaultPrefName(PREF, CurrentVaultKey.current())
        enabled.value = PreferencePersistence.getBoolean(context, prefName, KEY_ENABLED, DEFAULT_ENABLED)
    }

    fun setEnabled(context: Context, v: Boolean) {
        enabled.value = v
        PreferencePersistence.putBoolean(context, vaultPrefName(PREF, CurrentVaultKey.current()), KEY_ENABLED, v)
    }
}
