package com.vault

import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue

import android.app.ActivityManager
import android.content.Intent
import android.content.pm.PackageManager
import android.Manifest
import android.os.Build
import android.os.Bundle
import android.view.Display
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.app.PictureInPictureParams
import android.content.res.Configuration
import android.util.Rational
import android.widget.FrameLayout
import android.widget.ImageView
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.vault.security.IdleLockPref
import com.vault.security.WindowSecurity
import com.vault.storage.CacheCleaner
import com.vault.storage.TrashRetentionPref
import com.vault.ui.AppRoot
import com.vault.ui.IdleTracker
import com.vault.ui.ThemePref
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * 单 Activity 入口。继承 FragmentActivity 以满足 BiometricPrompt 要求。
 * 全部界面均为 Compose，状态在 VaultViewModel 内集中维护。
 *
 * dispatchTouchEvent 捕获用户所有触摸事件，通过 IdleTracker.touch()
 * 重置「最后活动时间」，供超时锁定计时使用。
 */
class MainActivity : FragmentActivity() {
    private var remoteUpdateOpenRequest by androidx.compose.runtime.mutableStateOf<com.vault.ui.RemoteUpdateOpenRequest?>(null)

    private fun captureRemoteUpdateIntent(source: android.content.Intent?) {
        val vault = source?.getStringExtra("remote_update_vault") ?: return
        val target = source.getStringExtra("remote_update_target") ?: return
        if (vault.isNotBlank() && vault.length <= 200 && target in setOf("drive", "webdav")) {
            remoteUpdateOpenRequest = com.vault.ui.RemoteUpdateOpenRequest(vault, target, System.nanoTime())
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        captureRemoteUpdateIntent(intent)
    }

    /** 后台品牌封面：切后台时显示品牌深色底 + 应用 Logo，代替敏感内容。 */
    private var backgroundCover: View? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        com.vault.security.CurrentVaultKey.install(
            com.vault.storage.VaultRegistry(this).current()
                ?: com.vault.security.CurrentVaultKey.DEFAULT,
        )
        // Mermaid SVG 磁盘持久缓存：详情页图表跨会话按需复用
        com.vault.ui.markdown.installMermaidSvgCache(this)
        // PiP（右上角小窗口）比例：密码管理器用 1:1，避免横向空间浪费
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            setPictureInPictureParams(
                PictureInPictureParams.Builder()
                    .setAspectRatio(Rational(1, 1))
                    .build(),
            )
        }
        // 后台界面隐藏（最近任务排除）统一由 WindowSecurity 管理。
        WindowSecurity.applyTo(this)
        // 很多设备 / OEM ROM 在低功耗下把合成路径锁到 60Hz（甚至省电模式下 30Hz），
        // 导致 120Hz 屏幕上动画 / 滚动看起来掉帧。
        // 这里显式向 SurfaceFlinger 申请显示器支持的最高刷新率模式，覆盖默认行为。
        requestMaxRefreshRate()
        // 最近任务卡片的标题 + 强调色：避免系统默认的白底任务预览过于突兀
        val brandPrimary = ContextCompat.getColor(this, R.color.brand_primary)
        val brandBg = ContextCompat.getColor(this, R.color.brand_bg_top)
        val taskLabel = getString(R.string.app_name)
        val taskDesc = if (Build.VERSION.SDK_INT >= 33) {
            ActivityManager.TaskDescription.Builder()
                .setLabel(taskLabel)
                .setPrimaryColor(brandBg)
                .setBackgroundColor(brandBg)
                .build()
        } else {
            @Suppress("DEPRECATION")
            ActivityManager.TaskDescription(taskLabel, null, brandPrimary)
        }
        setTaskDescription(taskDesc)
        ThemePref.init(this)
        IdleLockPref.init(this)
        TrashRetentionPref.init(this)
        com.vault.storage.ClipboardTtlPref.init(this)
        com.vault.security.SensitiveGuardPref.init(this)
        com.vault.security.PhotoBlurPref.init(this)
        com.vault.ui.NavOrderPref.init(this)
        com.vault.ui.TagOrderPref.init(this)
        com.vault.ui.HomeLayoutPref.init(this)
        com.vault.security.AutoHidePref.init(this)
        com.vault.security.BackgroundHidePref.init(this)
        com.vault.security.ScreenCapturePermission.init(this)
        com.vault.security.LocalBackupPref.init(this, com.vault.security.CurrentVaultKey.current())
        com.vault.storage.ExternalStorageMonitor.start(this)
        com.vault.security.LeakCheckEnabledPref.init(this)
        com.vault.security.LeakCheckIntervalPref.init(this)
        com.vault.security.LeakOnlineCheckPref.init(this)
        captureRemoteUpdateIntent(intent)
        setContent {
            AppRoot(remoteUpdateRequest = remoteUpdateOpenRequest, onRemoteUpdateRequestHandled = {
                remoteUpdateOpenRequest = null
                intent.removeExtra("remote_update_vault")
                intent.removeExtra("remote_update_target")
            })
        }
        // 权限弹窗至少等首屏进入消息队列，避免首次启动只看到系统弹窗而看不到应用内容。
        window.decorView.post { requestNotificationPermission() }
        // 首屏提交后再做非关键维护，避免目录扫描、WorkManager 初始化和旧设置迁移
        // 与 Compose 首次绘制争抢主线程。生命周期结束时任务会自动取消。
        lifecycleScope.launch(Dispatchers.IO) {
            com.vault.passkeys.PrivilegedAppAllowlistUpdates.schedule(this@MainActivity)
            CacheCleaner.clean(this@MainActivity)
            // 崩溃残留暂存回收：仅清理超过 24h 的孤儿文件，不误删最近暂存/恢复草稿引用的媒体
            CacheCleaner.cleanStaleMediaStaging(this@MainActivity)
            com.vault.security.AppListConsentPref.clearLegacy(this@MainActivity)
        }
    }

    /** Android 13+ 请求通知权限（前台服务通知/传输进度展示需要）。 */
    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            REQUEST_POST_NOTIFICATIONS,
        )
    }

    override fun onResume() {
        super.onResume()
        IdleTracker.touch()
        com.vault.storage.ExternalStorageMonitor.checkNow(this)
        // 剪贴板敏感内容到期后若进程已回收，回前台时补偿清理
        com.vault.ui.sweepClipboardOnForeground(this)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) com.vault.ui.sweepClipboardOnForeground(this)
    }

override fun onStart() {
        super.onStart()
        // 回前台：移除品牌封面，重新断言最近任务排除
        removeBackgroundCover()
        WindowSecurity.applyTo(this)
        // 通知全程保留，只切换形态：前台用 fallback 通知，切后台（onStop）后换成
        // 前台服务通知。可见性不再随前后台变化。
        com.vault.storage.BackgroundTaskNotifier.setAppVisible(this, true)
    }

    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) return
        // 真正进入后台（Home/最近任务）时允许显示后台任务通知；
        // 对话框、生物识别等仅失焦/暂停的操作不会误触发。
        com.vault.storage.BackgroundTaskNotifier.setAppVisible(this, false)
        // 允许截屏/录屏后，OS 最近任务与过渡画面可能记录当前内容；
        // 退后台时始终盖上品牌模板，避免敏感内容留在最近任务预览中。
        showBackgroundCover()
    }

    override fun onPictureInPictureModeChanged(
        isInPictureInPictureMode: Boolean,
        newConfig: Configuration,
    ) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        if (!isInPictureInPictureMode) return
        // 进入右上角小窗口：立即锁定，小窗口只显示安全占位（解锁页），不暴露敏感数据
        runCatching {
            val vm = ViewModelProvider(this)[com.vault.ui.VaultViewModel::class.java]
            if (vm.state.value.phase == com.vault.ui.Phase.UNLOCKED) vm.lock()
        }
    }

    /** 品牌封面：品牌深色背景 + 居中 Logo；最近任务快照被捕获到该帧时即为品牌模板。 */
    private fun showBackgroundCover() {
        if (backgroundCover != null) return
        val logoSize = (88 * resources.displayMetrics.density).toInt()
        val cover = FrameLayout(this).apply {
            setBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.brand_bg_top))
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }
        val logo = ImageView(this).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = FrameLayout.LayoutParams(logoSize, logoSize, Gravity.CENTER)
        }
        cover.addView(logo)
        (window.decorView as? ViewGroup)?.addView(cover)
        backgroundCover = cover
    }

    private fun removeBackgroundCover() {
        backgroundCover?.let { cover ->
            (window.decorView as? ViewGroup)?.removeView(cover)
            backgroundCover = null
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_RUNNING_LOW) {
            com.vault.security.LeakedPasswordCheck.clearMemoryCache()
        }
        if (level >= TRIM_MEMORY_BACKGROUND) {
            lifecycleScope.launch(Dispatchers.IO) { CacheCleaner.clean(this@MainActivity) }
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        com.vault.security.LeakedPasswordCheck.clearMemoryCache()
        lifecycleScope.launch(Dispatchers.IO) { CacheCleaner.clean(this@MainActivity) }
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        IdleTracker.touch()
        return super.dispatchTouchEvent(ev)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        IdleTracker.touch()
    }

    override fun dispatchGenericMotionEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_SCROLL) IdleTracker.touch()
        return super.dispatchGenericMotionEvent(event)
    }

    /**
     * 选用屏幕支持的最高刷新率模式（120Hz / 90Hz 等）。
     *  - API 30+ 用 Activity#getDisplay
     *  - API 26-29 用 WindowManager#defaultDisplay（已弃用但仍可用）
     * 同分辨率下挑 refreshRate 最大的 mode，避免某些设备把"最大模式"判成更低分辨率。
     */
    private fun requestMaxRefreshRate() {
        val d: Display? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) display
            else @Suppress("DEPRECATION") windowManager.defaultDisplay
        val current = d?.mode ?: return
        val best = d.supportedModes
            .filter { it.physicalWidth == current.physicalWidth && it.physicalHeight == current.physicalHeight }
            .maxByOrNull { it.refreshRate }
            ?: return
        if (best.modeId == current.modeId) return
        window.attributes = window.attributes.apply { preferredDisplayModeId = best.modeId }
    }

    companion object {
        private const val REQUEST_POST_NOTIFICATIONS = 901
    }
}
