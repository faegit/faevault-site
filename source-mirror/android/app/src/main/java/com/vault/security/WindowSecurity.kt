package com.vault.security

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.view.WindowManager

/**
 * 两个独立功能的统一出口（不要混淆）：
 *
 * 1. 允许截屏（ScreenCapturePermission）：关闭时窗口使用 FLAG_SECURE，
 *    避免截图、录屏和投屏捕获。
 * 2. 后台界面隐藏（BackgroundHidePref）：开关开启期间将本应用任务从最近任务列表排除
 *    （AppTask.setExcludeFromRecents），切到后台后任务栏不出现本应用卡片；
 *    与 FLAG_SECURE 完全独立，不影响前台截图。
 */
object WindowSecurity {
    fun captureAllowed(): Boolean = ScreenCapturePermission.allowed.value

    /** 应用允许截屏设置，并同步后台隐藏的最近任务排除状态。 */
    fun applyTo(activity: Activity?) {
        val window = activity?.window ?: return
        if (captureAllowed()) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        applyRecentsExclusion(activity)
    }

    /**
     * 后台界面隐藏：把本应用任务根 Intent 标记为 EXCLUDE_FROM_RECENTS。
     * 开启后任务不出现在最近任务列表；关闭后恢复，下次进入后台时重新出现。
     * 尽力而为：个别 OEM 可能不立即生效，失败不影响允许截屏设置。
     */
    fun applyRecentsExclusion(activity: Activity?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return
        val context = activity ?: return
        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return
            am.appTasks.firstOrNull()?.setExcludeFromRecents(BackgroundHidePref.enabled.value)
        } catch (_: Exception) {
            // 忽略：后台隐藏失败时最坏情况是任务栏可见，不影响其余功能
        }
    }
}
