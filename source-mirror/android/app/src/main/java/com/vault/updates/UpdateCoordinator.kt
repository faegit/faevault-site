package com.vault.updates

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.vault.storage.BackgroundTaskKind
import com.vault.storage.SyncForegroundService
import com.vault.ui.localizeUiTextFor

/**
 * 应用内更新的进程级协调器。
 *
 * 为什么不留在「关于」这一节里：那里的 `rememberCoroutineScope` 随组合销毁而取消，
 * 而组合会被折叠手风琴、LazyColumn 滚出视口、切换底部导航页、旋转屏幕四条路径销毁，
 * 下载会半途而废、已经发现的更新也会无声消失。状态与作业都挂在这里，UI 离开页面、
 * 切后台、甚至重建 Activity 都继续下载；回到页面重新读 [state] 就能接上进度。
 *
 * 后台执行由既有的 [SyncForegroundService] 前台通知兜底（[beginTask] 会真正拉起前台服务），
 * 所以进程存活期间下载不会因为进入后台被系统掐掉。
 *
 * 所有入口都自带闸门：[check] 与 [startUpdate] 在同一事件处理里被串行调用，
 * 第二次点击必然读到已置位的标志并直接返回。
 */
object UpdateCoordinator {

    /** 失败原因用枚举而非文案：文案要在 Compose 侧按当前语言解析。 */
    enum class Failure { CHECK, DOWNLOAD, SIGNATURE_MISMATCH, INVALID_PACKAGE, INVALID_VERSION, NO_INSTALLER, INSTALL_BLOCKED }

    data class State(
        val checking: Boolean = false,
        val info: UpdateInfo? = null,
        val downloading: Boolean = false,
        val received: Long = 0L,
        val total: Long = 0L,
        val verifying: Boolean = false,
        val installing: Boolean = false,
        val needsInstallPermission: Boolean = false,
        val launchingPermissionSettings: Boolean = false,
        val failure: Failure? = null,
        /** 动态部分（HTTP 状态码、异常消息），由 UI 与 [Failure] 拼成完整文案。 */
        val failureDetail: String = "",
        val upToDate: Boolean = false,
    ) {
        val busy: Boolean get() = downloading || verifying || installing
    }

    private const val TASK_ID = "app-update"

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    /** 进程级作用域：Activity 销毁与切后台都不取消，只有进程结束才停。 */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private var checkJob: Job? = null
    private var updateJob: Job? = null

    fun check(context: Context, currentVersion: String) {
        // 直接读 _state.value，不读任何组合期派生值：派生 val 是上一帧的快照，挡不住连点。
        if (_state.value.checking) return
        val appContext = context.applicationContext
        _state.value = _state.value.copy(
            checking = true,
            failure = null,
            failureDetail = "",
            upToDate = false,
        )
        checkJob = scope.launch {
            val result = try {
                Result.success(withContext(Dispatchers.IO) { checkLatest(preferredAsset()) })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Result.failure(e)
            }
            val current = _state.value
            if (!current.checking) return@launch // 已被新一轮检查接管
            _state.value = current.copy(
                checking = false,
                failure = if (result.isFailure) Failure.CHECK else null,
                failureDetail = result.exceptionOrNull()?.message.orEmpty(),
                info = result.getOrNull()?.takeIf { isNewer(it.version, currentVersion) }
                    ?: current.info.takeIf { result.isSuccess },
                upToDate = result.isSuccess && !isNewer(result.getOrNull()?.version.orEmpty(), currentVersion),
            )
        }
    }

    fun startUpdate(context: Context) {
        val current = _state.value
        val info = current.info ?: return
        // 闸门读的是状态对象本身；downloading/verifying/installing 任一为真都直接返回。
        if (current.busy || current.launchingPermissionSettings) return
        val appContext = context.applicationContext
        if (!AppUpdater.canRequestPackageInstalls(appContext)) {
            _state.value = current.copy(needsInstallPermission = true, failure = null, failureDetail = "")
            return
        }
        // 在协程之外同步置位：launch 是 post 到消息队列的，放进协程体会留下
        // 「一次消息分发 + 一帧」的窗口让第二次点击挤进来。
        _state.value = current.copy(
            downloading = true,
            received = 0L,
            total = 0L,
            failure = null,
            failureDetail = "",
            needsInstallPermission = false,
        )
        updateJob = scope.launch {
            val taskTitle = localizeUiTextFor(appContext, "应用更新")
            val downloadingDetail = localizeUiTextFor(appContext, "正在下载更新包…")
            SyncForegroundService.beginTask(
                appContext, TASK_ID, BackgroundTaskKind.APP_UPDATE, taskTitle, downloadingDetail,
            )
            try {
                val apk = withContext(Dispatchers.IO) {
                    AppUpdater.downloadApk(
                        appContext,
                        info,
                        onProgress = { received, total ->
                            _state.value = _state.value.copy(received = received, total = total)
                            SyncForegroundService.updateTask(
                                appContext, TASK_ID, downloadingDetail,
                                current = received, total = if (total > 0) total else -1L,
                            )
                        },
                    )
                }
                _state.value = _state.value.copy(downloading = false, verifying = true)
                val result = withContext(Dispatchers.IO) { AppUpdater.verify(appContext, apk) }
                if (result != AppUpdater.VerifyResult.OK) {
                    val failure = when (result) {
                        AppUpdater.VerifyResult.SIGNATURE_MISMATCH -> Failure.SIGNATURE_MISMATCH
                        AppUpdater.VerifyResult.INVALID_VERSION -> Failure.INVALID_VERSION
                        AppUpdater.VerifyResult.INVALID_INFO -> Failure.INVALID_PACKAGE
                        AppUpdater.VerifyResult.OK -> Failure.DOWNLOAD
                    }
                    _state.value = _state.value.copy(verifying = false, failure = failure, failureDetail = "")
                    SyncForegroundService.failTask(appContext, TASK_ID, downloadingDetail)
                    return@launch
                }
                _state.value = _state.value.copy(verifying = false, installing = true)
                val installed = try {
                    appContext.startActivity(AppUpdater.buildInstallIntent(appContext, apk))
                    true
                } catch (e: android.content.ActivityNotFoundException) {
                    _state.value = _state.value.copy(installing = false, failure = Failure.NO_INSTALLER, failureDetail = "")
                    SyncForegroundService.failTask(appContext, TASK_ID, localizeUiTextFor(appContext, "未找到可安装 APK 的应用"))
                    return@launch
                } catch (e: Exception) {
                    // 后台启动安装器可能被系统拦下：保留已下好的包与弹窗，用户回到前台可重试。
                    _state.value = _state.value.copy(installing = false, failure = Failure.INSTALL_BLOCKED, failureDetail = e.message.orEmpty())
                    SyncForegroundService.failTask(appContext, TASK_ID, localizeUiTextFor(appContext, "无法启动安装器，请回到应用后重试"))
                    return@launch
                }
                if (installed) {
                    _state.value = _state.value.copy(installing = false, info = null, received = 0L, total = 0L)
                    SyncForegroundService.succeedTask(appContext, TASK_ID, localizeUiTextFor(appContext, "更新包已下载并开始安装"))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val detail = e.message.orEmpty()
                _state.value = _state.value.copy(
                    downloading = false,
                    verifying = false,
                    installing = false,
                    failure = Failure.DOWNLOAD,
                    failureDetail = detail,
                )
                SyncForegroundService.failTask(appContext, TASK_ID, localizeUiTextFor(appContext, "下载更新失败：$detail"))
            } finally {
                val s = _state.value
                _state.value = s.copy(downloading = false, verifying = false, installing = false)
            }
        }
    }

    fun retryUpdate(context: Context) = startUpdate(context)

    /** 「去开启」按钮：闸门保证只拉起一个系统设置页。 */
    fun markLaunchingPermissionSettings() {
        val current = _state.value
        if (current.launchingPermissionSettings) return
        _state.value = current.copy(launchingPermissionSettings = true)
    }

    /**
     * 从系统设置页回来。先无条件放下 [launchingPermissionSettings] 闸——回调只来一次，
     * 但闸必须每条路径都落，否则上一次留下的 true 会把下一次「去开启」永久禁掉。
     */
    fun onInstallPermissionResult(context: Context, granted: Boolean) {
        val current = _state.value
        _state.value = current.copy(launchingPermissionSettings = false)
        if (granted) {
            startUpdate(context)
        } else {
            _state.value = _state.value.copy(needsInstallPermission = false)
        }
    }

    /** 用户关闭「发现新版本」弹窗：丢弃结论，但不动正在跑的下载。 */
    fun dismiss() {
        val current = _state.value
        if (current.busy) return
        _state.value = current.copy(
            info = null,
            failure = null,
            failureDetail = "",
            needsInstallPermission = false,
            upToDate = false,
            received = 0L,
            total = 0L,
        )
    }

    private fun preferredAsset(): String {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        return when {
            abi.startsWith("arm64") -> "faevault-arm64-v8a.apk"
            abi.startsWith("armeabi") -> "faevault-armeabi-v7a.apk"
            abi == "x86_64" -> "faevault-x86_64.apk"
            abi == "x86" -> "faevault-x86.apk"
            else -> "faevault-universal.apk"
        }
    }

    /** 仅供测试与进程收尾使用。 */
    internal fun resetForTest() {
        checkJob?.cancel()
        updateJob?.cancel()
        checkJob = null
        updateJob = null
        _state.value = State()
    }
}