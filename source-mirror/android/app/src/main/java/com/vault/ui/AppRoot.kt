package com.vault.ui

import android.app.Activity
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.BlurredEdgeTreatment
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.core.spring
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.material.icons.Icons
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import com.vault.ui.BreathingRing
import com.vault.ui.InputFilters
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupProperties
import androidx.compose.runtime.snapshotFlow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.dropWhile
import kotlinx.coroutines.flow.first
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vault.R
import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.touch
import com.vault.model.withOtpBinding
import com.vault.security.IdleLockPref
import com.vault.security.LockoutPref
import com.vault.security.BackgroundHidePref
import com.vault.security.WindowSecurity
import com.vault.security.PasswordFinding
import com.vault.security.PasswordHealth
import com.vault.security.PasswordHealthReport
import com.vault.security.MasterPasswordRisk
import com.vault.storage.VaultLogicalRevision
import com.vault.ui.screens.EntryDetailScreen
import com.vault.ui.screens.EntryEditScreen
import com.vault.ui.screens.HomeScreen
import com.vault.ui.screens.RootPage
import com.vault.ui.screens.MaintenanceDedupScreen
import com.vault.ui.screens.MaintenanceOverviewScreen
import com.vault.ui.screens.MaintenanceSameServiceScreen
import com.vault.ui.screens.SettingsScreen
import com.vault.ui.screens.SettingsContentMode
import com.vault.ui.screens.SecurityCenterScreen
import com.vault.ui.screens.SecurityEntryListScreen
import com.vault.ui.screens.TrashScreen
import com.vault.ui.screens.UnlockedShell
import com.vault.ui.screens.UnlockScreen
import com.vault.ui.screens.RecoveryKeyConfirmDialog
import com.vault.ui.screens.VaultActionButton
import com.vault.ui.screens.VaultActionStyle
import com.vault.ui.screens.VaultDialog
import com.vault.ui.screens.VaultListScreen
import com.vault.ui.screens.WelcomeScreen
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** 路由（仅在 Unlocked 阶段使用）。 */
sealed class Route {
    object Root : Route()
    data class Category(val type: String) : Route()
    data class SecurityResults(val filter: String) : Route()
    data class Detail(
        val id: String,
        val category: String,
        val returnDetailId: String? = null,
    ) : Route()
    data class MaintenanceSection(val section: String) : Route()
    data class Edit(
        val id: String?,
        val type: String,
        val fromDetail: Boolean = false,
        val returnCategory: String = "",
        val returnDetailId: String? = null,
    ) : Route()
}

private const val SECURITY_ORIGIN_PREFIX = "security:"
private const val MAINTENANCE_ORIGIN_PREFIX = "maintenance:"

// 弹窗遮罩变暗层：叠在 vaultBackdrop 模糊之上，对话框 / 回收站 / 同步结果共用。
// 想更浅或更深直接改这个值。
private const val MODAL_DIM_ALPHA = 0.3f
private const val DIM_FADE_IN_MS = 180
private const val DIM_FADE_OUT_MS = 140

private fun securityOrigin(filter: String): String = "$SECURITY_ORIGIN_PREFIX$filter"
private fun maintenanceOrigin(section: String): String = "$MAINTENANCE_ORIGIN_PREFIX$section"

private fun routeForOrigin(origin: String): Route = when {
    origin.startsWith(SECURITY_ORIGIN_PREFIX) ->
        Route.SecurityResults(origin.removePrefix(SECURITY_ORIGIN_PREFIX))
    origin.startsWith(MAINTENANCE_ORIGIN_PREFIX) ->
        Route.MaintenanceSection(origin.removePrefix(MAINTENANCE_ORIGIN_PREFIX))
    else -> Route.Category(origin)
}

internal fun autofillSourceEntries(
    entries: List<Entry>,
    currentEntryId: String?,
    revealEntry: (String) -> Entry?,
): List<Entry> = entries.asSequence()
    .filter { it.id != currentEntryId && it.deletedAt == null }
    .map { revealEntry(it.id) ?: it }
    .toList()

@Composable
fun AppRoot() {
    FAEVaultTheme {
        Surface(modifier = Modifier.fillMaxSize(), color = androidx.compose.material3.MaterialTheme.colorScheme.background) {
            val vm: VaultViewModel = viewModel()
            val state by vm.state.collectAsStateWithLifecycle()
            val event by vm.events.collectAsStateWithLifecycle()
            val currentVault by vm.currentVault.collectAsStateWithLifecycle()
            val snackbar = remember { SnackbarHostState() }
            // UiEvent.Error 与 Info 的字段结构一致，只能靠这里把"错误"这一位传给
            // 自定义通知条，让错误提示真的走红色，而不是靠文案区分。
            var snackbarIsError by remember { mutableStateOf(false) }
            // 冷却常驻通知：锁定原因由 UiEvent.Error 发出，但"还要等多久"必须逐秒刷新。
            // SnackbarData.visuals.message 在 showSnackbar 时就固定了，改不了，
            // 所以剩余秒数独立存在这里，由下方通知条拼进文案渲染。
            var stickyLockNotice by remember { mutableStateOf(false) }
            var cooldownSecondsLeft by remember { mutableIntStateOf(0) }
            val snackbarPopupWidth = with(LocalConfiguration.current) {
                (screenWidthDp.dp - 32.dp).coerceAtMost(560.dp)
            }
            val context = androidx.compose.ui.platform.LocalContext.current
            // 冷却期指纹全程可用（解锁页会自动弹 BiometricPrompt），所以设了指纹就要在
            // 通知里换行说清楚，避免用户以为只能干等。判定与 UnlockScreen 的 bioAvailable 一致。
            var biometricAvailable by remember(currentVault) { mutableStateOf(false) }
            LaunchedEffect(currentVault) {
                biometricAvailable = withContext(Dispatchers.IO) {
                    val appContext = context.applicationContext
                    currentVault?.let { vm.biometricFor(it) }
                        ?.let { it.isEnrolled() && it.canAuthenticate(appContext) } == true
                }
            }
            val activity = androidx.activity.compose.LocalActivity.current
            // 让每个 Route 拥有独立的 SaveableState 容器，
            // 离开后再回到该 Route 时其 rememberSaveable 状态（包括 LazyListState 的滚动位置）会被还原
            val saveableHolder = rememberSaveableStateHolder()
            var route by rememberSaveable(stateSaver = RouteSaver) {
                mutableStateOf<Route>(Route.Root)
            }
            var selectedRootPage by rememberSaveable { mutableStateOf(RootPage.HOME.ordinal) }
            var homeTopSignal by remember { mutableIntStateOf(0) }
            var trashTopSignal by remember { mutableIntStateOf(0) }
            var securityTopSignal by remember { mutableIntStateOf(0) }
            var securityAnimationSignal by remember { mutableIntStateOf(0) }
            var syncTopSignal by remember { mutableIntStateOf(0) }
            var maintenanceTopSignal by remember { mutableIntStateOf(0) }
            var settingsTopSignal by remember { mutableIntStateOf(0) }
            var showTrashDialog by rememberSaveable { mutableStateOf(false) }
            var editDraft by remember { mutableStateOf<Pair<String, com.vault.model.Entry>?>(null) }
            var isInBackground by remember { mutableStateOf(false) }
            val backgroundHideEnabled by BackgroundHidePref.enabled
            LaunchedEffect(activity, backgroundHideEnabled) {
                WindowSecurity.applyTo(activity)
            }
            LaunchedEffect(currentVault) { editDraft = null }

            LaunchedEffect(event) {
                val e = event ?: return@LaunchedEffect
                val locales = context.resources.configuration.locales
                // 冷却由持久化截止时间驱动，其他事件不能覆盖常驻倒计时。
                val cooling = state.phase == Phase.LOCKED &&
                    withContext(Dispatchers.IO) {
                        LockoutPref.lockoutUntilMs(context.applicationContext) > System.currentTimeMillis()
                    }
                if (!cooling) {
                    when (e) {
                        is UiEvent.Error -> {
                            snackbarIsError = true
                            snackbar.showSnackbar(localizeUiText(e.message, locales[0].toLanguageTag()))
                        }
                        is UiEvent.Info -> {
                            snackbarIsError = false
                            snackbar.showSnackbar(localizeUiText(e.message, locales[0].toLanguageTag()))
                        }
                    }
                }
                vm.consumeEvent()
            }

            // 持续观察截止时间：首次输错、重启、切库、指纹成功和后台恢复都走同一状态。
            LaunchedEffect(currentVault, state.phase) {
                val appContext = context.applicationContext
                if (state.phase != Phase.LOCKED) {
                    cooldownSecondsLeft = 0
                    stickyLockNotice = false
                    return@LaunchedEffect
                }
                while (true) {
                    // AndroidKeyStore 解密会调用系统服务，不能占用动画所在的主线程。
                    val remaining = withContext(Dispatchers.IO) {
                        (LockoutPref.lockoutUntilMs(appContext) - System.currentTimeMillis()).coerceAtLeast(0L)
                    }
                    cooldownSecondsLeft = LockoutPref.remainingSeconds(remaining)
                    stickyLockNotice = remaining > 0L
                    delay(200L)
                }
            }
            LaunchedEffect(stickyLockNotice, currentVault) {
                snackbar.currentSnackbarData?.dismiss()
                if (stickyLockNotice) {
                    snackbarIsError = true
                    snackbar.showSnackbar(
                        context.getString(R.string.viewmodel_too_many_attempts, cooldownSecondsLeft),
                        duration = SnackbarDuration.Indefinite,
                    )
                }
            }

            // 设备配对成功（局域网传输站被扫码连接）时自动进入传输页，
            // 由传输页决定是否确认导出等操作。
            LaunchedEffect(Unit) {
                vm.lanHostConnectSignal.collect { if (it > 0 && state.phase == Phase.UNLOCKED) selectedRootPage = RootPage.SYNC.ordinal }
            }

            // 库被删除/切换到无库状态时才清除二级路由；普通锁定后解锁应回到锁定前页面。
            LaunchedEffect(state.phase) {
                if (state.phase == Phase.NO_VAULT) {
                    route = Route.Root
                    selectedRootPage = RootPage.HOME.ordinal
                }
            }

            // 敏感内容二次保护：进入主页（Route.Root）时清除已验证会话，再次查看敏感内容需重新验证；
            // 详情/编辑及其上级列表页之间往返保持会话，不因退出编辑页而立即锁定。
            LaunchedEffect(route) {
                if (route == Route.Root) vm.clearSecuritySession()
            }

            // 空闲超时锁定：解锁状态下定期检查最后活动时间，超时则 vm.lock()
            LaunchedEffect(state.phase) {
                if (state.phase != Phase.UNLOCKED) return@LaunchedEffect
                while (true) {
                    delay(5000L)
                    if (!IdleLockPref.enabled.value) continue
                    if (vm.state.value.isExternalActionInProgress) continue
                    // 云端同步/下载进行中不因无操作而锁库，避免“保险库会话已失效”
                    if (vm.state.value.cloudSyncRunning) continue
                    val idle = System.currentTimeMillis() - IdleTracker.lastActivityMs.value
                    val timeout = IdleLockPref.seconds.value * 1000L
                    if (idle >= timeout) {
                        vm.autoLock()
                        break
                    }
                }
            }

            // 系统返回键：二级页面逐级返回；列表页第一次提示，2 秒内再次按返回放行退到桌面。
            BackHandler(enabled = state.phase == Phase.UNLOCKED && route != Route.Root) {
                if (route is Route.Edit) editDraft = null
                route = when (val r = route) {
                    is Route.Category -> Route.Root
                    is Route.SecurityResults -> Route.Root
                    is Route.MaintenanceSection -> Route.Root
                    is Route.Detail -> r.returnDetailId
                        ?.let { Route.Detail(it, r.category) }
                        ?: routeForOrigin(r.category)
                    is Route.Edit -> {
                        val origin = r.returnCategory.ifBlank { r.type }
                        if (r.fromDetail && r.id != null) {
                            Route.Detail(r.id, origin, r.returnDetailId)
                        } else {
                            routeForOrigin(origin)
                        }
                    }
                    Route.Root -> Route.Root
                }
            }
            var lastBackMs by remember { mutableStateOf(0L) }
            val ctxForToast = androidx.compose.ui.platform.LocalContext.current
            BackHandler(enabled = state.phase == Phase.UNLOCKED && route == Route.Root) {
                val now = System.currentTimeMillis()
                if (now - lastBackMs < 2000L) {
                    (ctxForToast as? android.app.Activity)?.moveTaskToBack(true)
                } else {
                    lastBackMs = now
                    val locales = ctxForToast.resources.configuration.locales
                    android.widget.Toast.makeText(
                        ctxForToast,
                        localizeUiText("再按一次返回桌面", locales[0].toLanguageTag()),
                        android.widget.Toast.LENGTH_SHORT,
                    ).show()
                }
            }

            // 应用进入后台立即锁库，并按需从最近任务中隐藏。
            // 特例：如果正在进行外部系统操作（如扫码、OCR 扫描），或发生屏幕旋转等配置变更，则忽略状态变化。
            val lifecycleOwner = LocalLifecycleOwner.current
            // LocalActivity 内部按 ContextWrapper 逐层解包再取 Activity：直接对 LocalContext 做
            // as? Activity 在被包装的宿主里会拿到 null，旋转时会把配置变更误判成进后台而自动锁库。
            // lint 的 ContextCastToActivity 也要求走这个 API（不能强转 LocalContext）。
            val currentActivity = androidx.activity.compose.LocalActivity.current
            DisposableEffect(lifecycleOwner, currentActivity) {
                val observer = LifecycleEventObserver { _, event ->
                    when (event) {
                        Lifecycle.Event.ON_RESUME -> {
                            isInBackground = false
                            // ON_STOP 的 pauseBackgroundWork 会取消自动同步轮询，
                            // 回前台必须重新拉起，否则自动同步在本次解锁期间再也不会到点执行。
                            vm.refreshAutoCloudSyncSchedule()
                        }
                        Lifecycle.Event.ON_STOP -> {
                            if (currentActivity?.isChangingConfigurations == true) return@LifecycleEventObserver
                            isInBackground = true
                            vm.pauseBackgroundWork()
                            if (shouldLockOnStop(vm.state.value)) {
                                vm.autoLock()
                            }
                        }
                        else -> {}
                    }
                }
                lifecycleOwner.lifecycle.addObserver(observer)
                onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
            }

            val trashBackground = remember { dev.chrisbanes.haze.HazeState() }
            val trashVisibility = remember { androidx.compose.animation.core.MutableTransitionState(false) }
            trashVisibility.targetState = showTrashDialog && state.phase == Phase.UNLOCKED
            CompositionLocalProvider(LocalVaultModalSource provides trashBackground) {
            Box(modifier = Modifier.fillMaxSize()) {
                Box(Modifier.fillMaxSize().vaultBackdropSource(trashBackground)) {
                when (state.phase) {
                    Phase.NO_VAULT -> Box(Modifier.fillMaxSize()) {
                        WelcomeScreen(vm)
                    }
                    Phase.LOCKED -> UnlockScreen(vm)
                    Phase.UNLOCKED -> {
                        val payload = state.payload
                        if (payload == null) {
                            // 理论上不会出现
                        } else {
                            val trashedEntries = remember(payload) {
                                com.vault.model.VaultOps.trashed(payload)
                            }
                            AnimatedContent(
                                targetState = route,
                                contentKey = { it },
                                transitionSpec = {
                                    // 用栈深度判定方向：Root=0，Category=1，Detail=2，Edit=2/3
                                    // 深度变大 → 前进（新页从右滑入，旧页向左轻移）
                                    // 深度变小 → 回退（新页从左轻移入，旧页向右滑出）
                                    val from = routeDepth(initialState)
                                    val to = routeDepth(targetState)
                                    // 详情↔详情 同深度时深度失效，改用 returnDetailId 链接关系：
                                    // 目标的返回ID指向当前页 → 正在进入关联来源（前进）；
                                    // 当前的返回ID指向目标页 → 正在沿链返回（回退）。
                                    val forward = if (from == to &&
                                        initialState is Route.Detail && targetState is Route.Detail
                                    ) {
                                        val src = initialState as Route.Detail
                                        val dst = targetState as Route.Detail
                                        dst.returnDetailId == src.id || src.returnDetailId != dst.id
                                    } else {
                                        to >= from
                                    }
                                    // Root ↔ Category：纯淡化，避免列表页大量卡片首次组合挤压动画帧
                                    if (initialState is Route.MaintenanceSection || targetState is Route.MaintenanceSection) {
                                        slideInHorizontally(tween(220)) { if (forward) it else -it } togetherWith
                                            slideOutHorizontally(tween(220)) { if (forward) -it else it }
                                    } else if (from <= 1 && to <= 1) {
                                        (fadeIn(tween(180)) + scaleIn(tween(180), initialScale = 0.97f)) togetherWith
                                            fadeOut(tween(120))
                                    } else if (forward) {
                                        (slideInHorizontally(tween(220, easing = FastOutSlowInEasing)) { it } + fadeIn(tween(150))) togetherWith
                                            (slideOutHorizontally(tween(220, easing = FastOutSlowInEasing)) { -it } + fadeOut(tween(120)))
                                    } else {
                                        (slideInHorizontally(tween(220, easing = FastOutSlowInEasing)) { -it } + fadeIn(tween(150))) togetherWith
                                            (slideOutHorizontally(tween(220, easing = FastOutSlowInEasing)) { it } + fadeOut(tween(120)))
                                    }
                                },
                                label = "routeTransition",
                            ) { currentRoute ->
                                key(currentRoute) {
                                    val pageBackdrop = remember { dev.chrisbanes.haze.HazeState() }
                                    VaultBackdropHost(state = pageBackdrop) {
                                    when (currentRoute) {
                                    Route.Root -> saveableHolder.SaveableStateProvider("root") {
                                        UnlockedShell(
                                            selectedPage = selectedRootPage,
                                            trashCount = trashedEntries.size,
                                            onSelectedPageChanged = {
                                                selectedRootPage = it
                                                if (it == RootPage.SECURITY.ordinal) vm.scanPasswordHealth()
                                            },
                                            onNavigationClick = { page ->
                                                if (page == RootPage.SECURITY) securityAnimationSignal++
                                            },
                                            onReselect = { page ->
                                                when (page) {
                                                    RootPage.HOME -> homeTopSignal++
                                                    RootPage.MAINTENANCE -> maintenanceTopSignal++
                                                    RootPage.SECURITY -> {
                                                        securityTopSignal++
                                                    }
                                                    RootPage.SYNC -> syncTopSignal++
                                                    RootPage.SETTINGS -> settingsTopSignal++
                                                }
                                            },
                                            onTrashClick = {
                                                trashTopSignal++
                                                showTrashDialog = true
                                            },
                                            onLock = vm::lock,
                                            home = {
                                                HomeScreen(
                                                    entries = payload.entries,
                                                    onOpenCategory = { type ->
                                                        vm.clearListFilters()
                                                        route = Route.Category(type)
                                                    },
                                                    onOrderChanged = { NavOrderPref.setOrder(context, it) },
                                                    onAdd = { type -> route = Route.Edit(null, type, fromDetail = false) },
                                                    scrollToTopSignal = homeTopSignal,
                                                    // 主页下拉（标准 pull-to-refresh 手势）打开回收站，
                                                    // 与顶栏回收站图标同一动作。
                                                    onPullToTrash = {
                                                        trashTopSignal++
                                                        showTrashDialog = true
                                                    },
                                                )
                                            },
                                            maintenance = {
                                                MaintenanceOverviewScreen(
                                                    vm = vm,
                                                    onOpenSection = { section -> route = Route.MaintenanceSection(section) },
                                                    scrollToTopSignal = maintenanceTopSignal,
                                                )
                                            },
                                            security = {
                                                SecurityCenterScreen(
                                                    vm = vm,
                                                    onOpenFilter = { filter -> route = Route.SecurityResults(filter) },
                                                    scrollToTopSignal = securityTopSignal,
                                                    animationSignal = securityAnimationSignal,
                                                )
                                            },
                                            sync = {
                                                SettingsScreen(
                                                    vm = vm,
                                                    isActive = selectedRootPage == RootPage.SYNC.ordinal,
                                                    contentMode = SettingsContentMode.TRANSFER,
                                                    scrollToTopSignal = syncTopSignal,
                                                )
                                            },
                                            settings = {
                                                SettingsScreen(
                                                    vm = vm,
                                                    isActive = selectedRootPage == RootPage.SETTINGS.ordinal,
                                                    onOpenEntry = { entry -> route = Route.Detail(entry.id, entry.secretType) },
                                                    scrollToTopSignal = settingsTopSignal,
                                                )
                                            },
                                        )
                                    }
                                    is Route.Category -> saveableHolder.SaveableStateProvider("category:${currentRoute.type}") {
                                        VaultListScreen(
                                            state = state,
                                            category = currentRoute.type,
                                            onSearch = vm::setQuery,
                                            onTagFilter = vm::setTagFilter,
                                            onBack = { route = Route.Root },
                                            onOpen = { route = Route.Detail(it.id, currentRoute.type) },
                                            onEdit = {
                                                route = if (it.secretType == com.vault.model.SecretType.PASSKEY) {
                                                    Route.Detail(it.id, currentRoute.type)
                                                } else {
                                                    Route.Edit(it.id, it.secretType, fromDetail = false)
                                                }
                                            },
                                            onDelete = { vm.deleteEntry(it.id) },
                                            onAdd = { route = Route.Edit(null, it, fromDetail = false) },
                                            onRenameTag = vm::renameTag,
                                            onReorderTag = vm::reorderTag,
                                            onBatchDelete = vm::deleteEntries,
                                            onBatchTag = { mode, tag, ids -> vm.updateEntryTags(ids, tag, mode) },
                                            otpSnapshotProvider = vm::otpDisplaySnapshot,
                                        )
                                    }
                                    is Route.SecurityResults -> saveableHolder.SaveableStateProvider("security:${currentRoute.filter}") {
                                        val securityReport by vm.securityReport.collectAsStateWithLifecycle()
                                        LaunchedEffect(currentRoute.filter) {
                                            vm.scanPasswordHealth()
                                        }
                                        val securityEntryIds = remember(securityReport, currentRoute.filter) {
                                            securityReport.entriesFor(currentRoute.filter).map { it.id }.toSet()
                                        }
                                        val activeEntries = remember(payload, securityEntryIds) {
                                            payload.entries.filter { it.deletedAt == null && it.id in securityEntryIds }
                                        }
                                        val resultEntries = activeEntries
                                        val issuesByEntryId = remember(securityReport, resultEntries) {
                                            resultEntries.associate { entry ->
                                                entry.id to securityReport.issuesFor(entry.id).map(PasswordFinding::label)
                                            }
                                        }
                                        val finding = PasswordFinding.fromKey(currentRoute.filter)
                                        val label = when (currentRoute.filter) {
                                            "high" -> uiText("高风险")
                                            "improvement" -> uiText("需改进")
                                            "healthy" -> uiText("安全")
                                            "all" -> uiText("全部风险")
                                            else -> PasswordFinding.fromKey(currentRoute.filter)?.label?.let { uiText(it) } ?: uiText("检测结果")
                                        }
                                        val description = finding?.description?.let { uiText(it) } ?: when (currentRoute.filter) {
                                            "high" -> uiText("包含高风险问题的条目，请优先处理。")
                                            "improvement" -> uiText("无高风险问题，但仍有可改进之处。")
                                            "healthy" -> uiText("未发现本地问题；不代表密码从未泄露。")
                                            else -> ""
                                        }
                                        SecurityEntryListScreen(
                                            label = label,
                                            description = description,
                                            recommendation = finding?.recommendation,
                                            entries = resultEntries,
                                            issuesFor = { entry -> issuesByEntryId[entry.id].orEmpty() },
                                            onBack = { route = Route.Root },
                                            onOpen = {
                                                route = Route.Detail(it.id, securityOrigin(currentRoute.filter))
                                            },
                                            onEdit = {
                                                route = Route.Edit(
                                                    id = it.id,
                                                    type = it.secretType,
                                                    returnCategory = securityOrigin(currentRoute.filter),
                                                )
                                            },
                                            onDelete = { vm.deleteEntry(it.id) },
                                            enableBatch = false,
                                            duplicateGroupKeys = securityReport.duplicateGroupKeys,
                                        )
                                    }
                                    is Route.MaintenanceSection -> saveableHolder.SaveableStateProvider("maintenance:${currentRoute.section}") {
                                        when (currentRoute.section) {
                                            "dedup" -> MaintenanceDedupScreen(
                                                vm = vm,
                                                onBack = { route = Route.Root },
                                            )
                                            "same_service" -> MaintenanceSameServiceScreen(
                                                vm = vm,
                                                onBack = { route = Route.Root },
                                                onEdit = {
                                                    route = Route.Detail(
                                                        id = it.id,
                                                        category = maintenanceOrigin("same_service"),
                                                    )
                                                },
                                            )
                                            else -> MaintenanceSameServiceScreen(
                                                vm = vm,
                                                onBack = { route = Route.Root },
                                                onEdit = {
                                                    route = Route.Detail(
                                                        id = it.id,
                                                        category = maintenanceOrigin("same_service"),
                                                    )
                                                },
                                            )
                                        }
                                    }
                                    is Route.Detail -> saveableHolder.SaveableStateProvider("detail:${currentRoute.id}") {
                                        // 先同步用内存中的会话条目库填充（编辑返回/切库重进时立即可见），
                                        // 避免异步重载期间闪现加载环导致页面闪烁；异步仅用于兜底刷新与媒体 reveal。
                                        var entry by remember(currentRoute.id, payload) {
                                            mutableStateOf(vm.revealEntry(currentRoute.id)?.takeIf { it.deletedAt == null })
                                        }
                                        var entryLoaded by remember(currentRoute.id, payload) { mutableStateOf(entry != null) }
                                        LaunchedEffect(currentRoute.id, payload) {
                                            vm.loadEntry(currentRoute.id) { loaded ->
                                                entry = loaded?.takeIf { it.deletedAt == null }
                                                entryLoaded = true
                                            }
                                        }
                                        val loadedEntry = entry
                                        if (loadedEntry == null && !entryLoaded) {
                                            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                                BreathingRing()
                                            }
                                        } else if (loadedEntry == null) {
                                            route = currentRoute.returnDetailId
                                                ?.let { Route.Detail(it, currentRoute.category) }
                                                ?: routeForOrigin(currentRoute.category)
                                        } else EntryDetailScreen(
                                            entry = loadedEntry,
                                            verifyMasterPassword = vm::verifySessionPassword,
                                            hasSecuritySession = vm::hasSecuritySession,
                                            elevateSecuritySession = vm::elevateSecuritySession,
                                            onBack = {
                                                route = currentRoute.returnDetailId
                                                    ?.let { Route.Detail(it, currentRoute.category) }
                                                    ?: routeForOrigin(currentRoute.category)
                                            },
                                            onEdit = {
                                                route = Route.Edit(
                                                    loadedEntry.id,
                                                    loadedEntry.secretType,
                                                    fromDetail = true,
                                                    returnCategory = currentRoute.category,
                                                    returnDetailId = currentRoute.returnDetailId,
                                                )
                                            },
                                            onDelete = {
                                                vm.deleteEntry(loadedEntry.id)
                                                route = currentRoute.returnDetailId
                                                    ?.let { Route.Detail(it, currentRoute.category) }
                                                    ?: routeForOrigin(currentRoute.category)
                                            },
                                            setExternalActionInProgress = vm::setExternalActionInProgress,
                                            autofillSourceOptions = remember(payload, loadedEntry.id) {
                                                autofillSourceEntries(
                                                    payload.entries,
                                                    loadedEntry.id,
                                                    vm::revealEntry,
                                                )
                                            },
                                            onOpenAutofillSource = { source ->
                                                route = Route.Detail(
                                                    id = source.id,
                                                    category = currentRoute.category,
                                                    returnDetailId = loadedEntry.id,
                                                )
                                            },
                                        )
                                    }
                                    is Route.Edit -> {
                                        var existing by remember(currentRoute.id, payload) { mutableStateOf<com.vault.model.Entry?>(null) }
                                        var entryLoaded by remember(currentRoute.id, payload) {
                                            mutableStateOf(currentRoute.id == null)
                                        }
                                        LaunchedEffect(currentRoute.id, payload) {
                                            val id = currentRoute.id
                                            if (id == null) {
                                                existing = null
                                                entryLoaded = true
                                            } else {
                                                entryLoaded = false
                                                vm.loadEntry(id) { loaded ->
                                                    existing = loaded
                                                    entryLoaded = true
                                                }
                                            }
                                        }
                                        val draftKey = currentRoute.id ?: "new:${currentRoute.type}"
                                        val returnOrigin = currentRoute.returnCategory.ifBlank { currentRoute.type }
                                        val existingEntry = existing
                                        if (!entryLoaded) {
                                            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                                BreathingRing()
                                            }
                                        } else saveableHolder.SaveableStateProvider("edit:${draftKey}") {
                                            EntryEditScreen(
                                                initial = existingEntry,
                                                draft = editDraft?.takeIf { it.first == draftKey }?.second,
                                                initialType = currentRoute.type,
                                                onCancel = {
                                                    editDraft = null
                                                    route = if (currentRoute.fromDetail && existingEntry != null) {
                                                        Route.Detail(existingEntry.id, returnOrigin, currentRoute.returnDetailId)
                                                    } else {
                                                        routeForOrigin(returnOrigin)
                                                    }
                                                },
                                                onSave = { saved ->
                                                    editDraft = null
                                                    if (existingEntry == null) {
                                                        vm.addEntry(saved)
                                                    } else {
                                                        vm.updateEntry(saved)
                                                    }
                                                    route = if (currentRoute.fromDetail && existingEntry != null) {
                                                        Route.Detail(saved.id, returnOrigin, currentRoute.returnDetailId)
                                                    } else {
                                                        routeForOrigin(returnOrigin)
                                                    }
                                                },
                                                onDraftChanged = { draft -> editDraft = draftKey to draft },
                                                setExternalActionInProgress = vm::setExternalActionInProgress,
                                                // 标签按类别隔离：编辑页只提供与当前条目同类型的已有标签，
                                                // 避免登录等类别的标签串到其他类别的编辑页。
                                                existingTags = payload.entries
                                                    .filter { it.deletedAt == null && it.secretType == currentRoute.type }
                                                    .flatMap { it.tags }.distinct().sorted(),
                                                autofillSourceOptions = remember(payload, currentRoute.id) {
                                                    autofillSourceEntries(
                                                        payload.entries,
                                                        currentRoute.id,
                                                        vm::revealEntry,
                                                    )
                                                },
                                            )
                                        }
                                    }
                                }
                                }
                                }
                            }
                        }
                    }
                }
                if (snackbar.currentSnackbarData != null) {
                    Popup(
                        alignment = Alignment.TopCenter,
                        offset = IntOffset(0, with(LocalDensity.current) { (48.dp).roundToPx() }),
                        properties = PopupProperties(
                            // 通知条窗口不抢焦点、不响应返回/外部点击，避免干扰页面交互；
                            // 关闭只由超时、点击或上滑手势触发。
                            focusable = false,
                            dismissOnBackPress = false,
                            dismissOnClickOutside = false,
                            clippingEnabled = false,
                        ),
                        onDismissRequest = {},
                    ) {
                        // 顶部通知条置于独立窗口：始终悬浮于页面内容之上，
                        // 不被应用内弹窗、卡片或底部内容覆盖。
                        Box(
                            Modifier
                                .width(snackbarPopupWidth)
                                .fillMaxWidth(),
                            contentAlignment = Alignment.TopCenter,
                        ) {
                            SnackbarHost(snackbar) { data ->
                                val isError = snackbarIsError
                                var dragOffsetDp by remember(data) { mutableFloatStateOf(0f) }
                                var dismissing by remember(data) { mutableStateOf(false) }
                                val density = LocalDensity.current
                                val dismissAlpha by animateFloatAsState(
                                    targetValue = if (dismissing) 0f else 1f,
                                    animationSpec = tween(240),
                                    label = "snackbarDismissAlpha",
                                )
                                LaunchedEffect(dismissing) {
                                    if (dismissing) {
                                        snapshotFlow { dismissAlpha }
                                            .first { it < 0.001f }
                                        data.dismiss()
                                    }
                                }
                                Box(
                                    modifier = Modifier
                                        .graphicsLayer {
                                            alpha = dismissAlpha
                                        }
                                        .clickable(
                                            interactionSource = remember { MutableInteractionSource() },
                                            indication = LocalIndication.current,
                                        ) {
                                            // 点击通知条即触发原有淡出消失动画
                                            if (!stickyLockNotice) dismissing = true
                                        }
                                        .pointerInput(data) {
                                            detectVerticalDragGestures(
                                                onDragEnd = {
                                                    // 上滑不再移动通知条：直接触发现有的淡出消失动画。
                                                    if (dragOffsetDp < -10f && !stickyLockNotice) {
                                                        dismissing = true
                                                    } else {
                                                        dragOffsetDp = 0f
                                                    }
                                                },
                                                onDragCancel = { dragOffsetDp = 0f },
                                                onVerticalDrag = { change, dragAmount ->
                                                    change.consume()
                                                    dragOffsetDp += with(density) { dragAmount.toDp().value }
                                                    dragOffsetDp = dragOffsetDp.coerceAtMost(0f)
                                                },
                                            )
                                        },
                                ) {
                                    Surface(
                                        color = if (isError) {
                                            MaterialTheme.colorScheme.errorContainer
                                        } else {
                                            MaterialTheme.colorScheme.inverseSurface
                                        },
                                        contentColor = if (isError) {
                                            MaterialTheme.colorScheme.onErrorContainer
                                        } else {
                                            MaterialTheme.colorScheme.inverseOnSurface
                                        },
                                        shape = VaultShape,
                                        tonalElevation = 0.dp,
                                        shadowElevation = 0.dp,
                                        modifier = Modifier
                                            .padding(PaddingValues(horizontal = 16.dp))
                                            .fillMaxWidth()
                                            .widthIn(max = 560.dp),
                                    ) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                        ) {
                                            Spacer(Modifier.size(32.dp))
                                            Text(
                                                // 常驻锁定通知的剩余秒数逐秒重算；其余通知用原始文案。
                                                if (stickyLockNotice && cooldownSecondsLeft > 0) {
                                                    val seconds = stringResource(
                                                        R.string.cooling_notice_seconds,
                                                        cooldownSecondsLeft,
                                                    )
                                                    if (biometricAvailable) {
                                                        seconds + "\n" +
                                                            stringResource(R.string.cooling_notice_biometric_hint)
                                                    } else {
                                                        seconds
                                                    }
                                                } else {
                                                    data.visuals.message
                                                },
                                                modifier = Modifier.weight(1f).padding(horizontal = 8.dp),
                                                textAlign = TextAlign.Center,
                                                style = MaterialTheme.typography.bodyMedium,
                                            )
                                            // 胶囊样式：不提供叉按钮，上滑或自动消失即可关闭。
                                            Spacer(Modifier.size(32.dp))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                }
                // 对话框遮罩：模糊 + 变暗层一起淡入淡出。用 AnimatedVisibility 而不是 if，
                // 关闭时遮罩才会逐步变亮，而不是瞬间消失。
                AnimatedVisibility(
                    visible = VaultModalBackdrops.owners.isNotEmpty() || trashVisibility.targetState,
                    enter = fadeIn(tween(DIM_FADE_IN_MS)),
                    exit = fadeOut(tween(DIM_FADE_OUT_MS)),
                    label = "modalBackdropTransition",
                ) {
                    Box(Modifier.fillMaxSize()
                        .vaultBackdrop(shape = androidx.compose.ui.graphics.RectangleShape, state = trashBackground)
                        .background(MaterialTheme.colorScheme.scrim.copy(alpha = MODAL_DIM_ALPHA)))
                }
                AnimatedVisibility(
                    visibleState = trashVisibility,
                    // Keep the full-window blur static; animate only the card layer.
                    enter = androidx.compose.animation.EnterTransition.None,
                    exit = androidx.compose.animation.ExitTransition.None,
                    label = "trashDialogTransition",
                ) {
                    val payload = state.payload
                    val trashedEntries = if (payload != null) remember(payload) {
                        com.vault.model.VaultOps.trashed(payload)
                    } else emptyList()
                    val trashBackdrop = remember { dev.chrisbanes.haze.HazeState() }
                    BackHandler(enabled = true) { showTrashDialog = false }
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                            ) { showTrashDialog = false },
                        contentAlignment = Alignment.Center,
                    ) {
                        Surface(
                            shape = VaultShape,
                            color = Color.Transparent,
                            tonalElevation = 0.dp,
                            modifier = Modifier
                                .animateEnterExit(
                                    enter = fadeIn(tween(180)) + scaleIn(
                                        animationSpec = tween(180),
                                        initialScale = 0.97f,
                                    ),
                                    exit = fadeOut(tween(120)) + scaleOut(tween(120), targetScale = 0.98f),
                                )
                                .padding(horizontal = 24.dp, vertical = 24.dp)
                                .widthIn(max = 560.dp)
                                .fillMaxWidth()
                                .heightIn(max = 620.dp)
                                .vaultPopupCardSurface()
                                .pointerInput(Unit) { detectTapGestures(onTap = {}) },
                        ) {
                            VaultBackdropHost(state = trashBackdrop, backgroundColor = Color.Transparent) {
                                TrashScreen(
                                    trash = trashedEntries,
                                    onRestore = vm::restoreEntry,
                                    onRestoreMany = vm::restoreEntries,
                                    onPurge = vm::purgeEntry,
                                    onPurgeMany = vm::purgeEntries,
                                    onPurgeAll = vm::purgeAllTrash,
                                    scrollToTopSignal = trashTopSignal,
                                )
                            }
                        }
                    }
                }
                // 同步结果原先是盖在全局的暗化弹窗上；现在由局域网「同步」挡位内的
                // 页面卡片承载（见 SettingsScreen），避免用户被拦在任何页面之前。
                // 同步后密钥/主密码自动收敛：红色警示弹窗，只能确认、不可取消。
                val keyConvergedNotice by vm.keyConvergedNotice.collectAsStateWithLifecycle()
                keyConvergedNotice?.let { notice ->
                    VaultDialog(
                        onDismissRequest = {},
                        title = {
                            Text(
                                if (notice.kind == VaultViewModel.KeyConvergenceKind.PASSWORD) {
                                    uiText("主密码/密钥版本已更新")
                                } else {
                                    uiText("恢复密钥版本已更新")
                                },
                                color = MaterialTheme.colorScheme.error,
                            )
                        },
                        text = { Text(uiText(notice.message)) },
                        confirmButton = {
                            VaultActionButton(
                                onClick = vm::confirmKeyConvergedNotice,
                                style = VaultActionStyle.DANGER,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(
                                    if (notice.kind == VaultViewModel.KeyConvergenceKind.PASSWORD) {
                                        uiText("确认并锁定")
                                    } else {
                                        uiText("确认")
                                    },
                                )
                            }
                        },
                    )
                }
                // 恢复密钥解锁后的强制流程：重发恢复密钥 → 设置新主密码（均不可关闭）
                val recoveryStep by vm.recoveryFlow.collectAsStateWithLifecycle()
                // 强制流程进行期间暂停无操作自动锁定，避免流程被锁定打断。
                LaunchedEffect(recoveryStep) {
                    vm.setExternalActionInProgress(recoveryStep != RecoveryFlowStep.NONE)
                }
                var recoveryNewPassword by remember { mutableStateOf("") }
                var recoveryNewPasswordConfirm by remember { mutableStateOf("") }
                var recoveryHighSecurityMode by remember { mutableStateOf(true) }
                var showRecoveryWeakConfirmation by remember { mutableStateOf(false) }
                val recoveryPasswordAssessment = rememberMasterPasswordAssessment(recoveryNewPassword)
                when (recoveryStep) {
                    RecoveryFlowStep.RESET_PASSWORD -> VaultDialog(
                        onDismissRequest = {},
                        title = { Text(uiText("设置新的主密码")) },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text(
                                    uiText("请先设置新的主密码，恢复密钥仍然有效；完成后下一步重新保存恢复密钥。此流程不可取消。"),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                OutlinedTextField(
                                    value = recoveryNewPassword,
                                    onValueChange = {
                                        recoveryNewPassword = InputFilters.capLength(
                                            InputFilters.asciiPrintable(it),
                                            128,
                                        )
                                        showRecoveryWeakConfirmation = false
                                    },
                                    label = { Text(uiText("新主密码")) },
                                    visualTransformation = PasswordVisualTransformation(),
                                    singleLine = true,
                                    shape = VaultShape,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                OutlinedTextField(
                                    value = recoveryNewPasswordConfirm,
                                    onValueChange = {
                                        recoveryNewPasswordConfirm = InputFilters.capLength(
                                            InputFilters.asciiPrintable(it),
                                            128,
                                        )
                                    },
                                    label = { Text(uiText("再次输入")) },
                                    visualTransformation = PasswordVisualTransformation(),
                                    singleLine = true,
                                    isError = recoveryNewPasswordConfirm.isNotEmpty() &&
                                        recoveryNewPasswordConfirm != recoveryNewPassword,
                                    shape = VaultShape,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                MasterPasswordPolicyControls(
                                    assessment = recoveryPasswordAssessment,
                                    highSecurityMode = recoveryHighSecurityMode,
                                    onHighSecurityModeChange = {
                                        recoveryHighSecurityMode = it
                                        showRecoveryWeakConfirmation = false
                                    },
                                )
                            }
                        },
                        confirmButton = {
                            VaultActionButton(
                                onClick = {
                                    if (recoveryPasswordAssessment.risk == MasterPasswordRisk.WEAK) {
                                        showRecoveryWeakConfirmation = true
                                    } else {
                                        vm.resetPasswordAfterRecovery(recoveryNewPassword)
                                        recoveryNewPassword = ""
                                        recoveryNewPasswordConfirm = ""
                                    }
                                },
                                enabled = recoveryNewPassword == recoveryNewPasswordConfirm &&
                                    recoveryPasswordAssessment.risk != MasterPasswordRisk.BLOCKED &&
                                    (!recoveryHighSecurityMode ||
                                        recoveryPasswordAssessment.risk == MasterPasswordRisk.STRONG),
                                style = VaultActionStyle.PRIMARY,
                            ) { Text(uiText("完成并进入保险库")) }
                        },
                        dismissButton = {},
                    )
                    RecoveryFlowStep.REISSUE -> RecoveryKeyConfirmDialog(
                        title = uiText("重新保存恢复密钥"),
                        message = uiText("主密码已重置。请重新保存一份新恢复密钥；确认前旧恢复密钥仍然有效，确认后旧密钥立即失效。此流程不可取消。"),
                        keyVersion = (state.payload?.syncMeta?.keyRevision ?: 0) + 1,
                        accountName = currentVault.orEmpty(),
                        onCancel = {},
                        onConfirmed = vm::confirmRecoveryReissue,
                    )
                    RecoveryFlowStep.NONE -> Unit
                }
                if (showRecoveryWeakConfirmation) {
                    WeakMasterPasswordConfirmDialog(
                        onCancel = { showRecoveryWeakConfirmation = false },
                        onConfirm = {
                            showRecoveryWeakConfirmation = false
                            vm.resetPasswordAfterRecovery(
                                recoveryNewPassword,
                                weakPasswordConfirmed = true,
                            )
                            recoveryNewPassword = ""
                            recoveryNewPasswordConfirm = ""
                        },
                    )
                }
                // 深浅色切换的圆形扩散覆盖层：置于最顶层（各屏幕、通知条之上）
                ThemeSwitch.Overlay()
            }
            }
        }
    }
}

internal fun shouldLockOnStop(state: UiState): Boolean =
    !state.isExternalActionInProgress &&
        state.phase != Phase.NO_VAULT &&
        (state.phase == Phase.UNLOCKED || state.busy || state.unlockSuccess)

@Composable
internal fun LanSyncResultStatus(
    result: VaultViewModel.SyncResultState,
    modifier: Modifier = Modifier,
) {
    val stats = result.stats
    // 页面内状态不能读取包含自身的弹窗背景源，否则会在绘制时形成循环。
    Column(modifier = modifier.fillMaxWidth().padding(vertical = 12.dp)) {
        Text(uiText("同步完成"), style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(10.dp))
        val changed = stats.added + stats.takeRemote + stats.takeLocal + stats.keptBoth + stats.purged + stats.coalesced
        // 每个分支各自 uiText 包一层：不能靠外层 uiText(when { ... })，守卫按行判断
        // 包装上下文，when 的分支换行后就看不到上面的 uiText( 了。
        val headline = when {
            changed == 0 && stats.conflicts == 0 -> uiText("双方内容一致，未发现需要合并的修改。")
            result.host -> uiText("已发送本地数据，并完成对方回传数据的校验与合并。")
            result.uploaded -> uiText("已完成拉取、合并和回传。")
            else -> uiText("已完成拉取和合并；远端已包含合并结果，无需重复上传。")
        }
        Text(headline, style = MaterialTheme.typography.bodyMedium)
        Text(
            if (result.host) uiText("本机角色：传输站") else uiText("本机角色：连接方"),
            style = MaterialTheme.typography.bodySmall,
        )
        val lineageLabel = when (result.lineage) {
            "same" -> uiText("数据关系：双方一致")
            "fast_forward" -> uiText("数据关系：已采用对方的新版本")
            "remote_stale" -> uiText("数据关系：保留本地较新版本")
            "diverged" -> uiText("数据关系：双方修改已合并")
            else -> ""
        }
        if (lineageLabel.isNotEmpty()) Text(lineageLabel, style = MaterialTheme.typography.bodySmall)
        Text(
            uiText(
                "同步前本地 ${result.localCount} 项 · 同步后 ${result.mergedCount} 项" +
                    if (result.remoteBytes > 0) " · 远端 ${result.remoteBytes / 1024} KB" else "",
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        HorizontalDivider()
        Spacer(Modifier.height(10.dp))
        SyncResultStatRow("新增", stats.added, color = MaterialTheme.colorScheme.primary)
        SyncResultStatRow("取远端", stats.takeRemote, color = MaterialTheme.colorScheme.primary)
        SyncResultStatRow("留本地", stats.takeLocal, color = MaterialTheme.colorScheme.tertiary)
        if (stats.keptBoth > 0)
            SyncResultStatRow("保留双份", stats.keptBoth, color = MaterialTheme.colorScheme.error)
        if (stats.conflicts > 0)
            SyncResultStatRow("冲突", stats.conflicts, color = MaterialTheme.colorScheme.error)
        if (stats.passkeyConflicts > 0)
            SyncResultStatRow("通行密钥冲突", stats.passkeyConflicts, color = MaterialTheme.colorScheme.error)
        if (stats.identical > 0)
            SyncResultStatRow("无变化", stats.identical, color = MaterialTheme.colorScheme.outline)
        if (stats.purged > 0)
            SyncResultStatRow("已清理", stats.purged, color = MaterialTheme.colorScheme.outline)
        if (stats.purgeSkipped > 0)
            SyncResultStatRow("忽略过期删除日志", stats.purgeSkipped, color = MaterialTheme.colorScheme.outline)
        if (stats.coalesced > 0)
            SyncResultStatRow("合并重复条目", stats.coalesced, color = MaterialTheme.colorScheme.outline)
        // 同样是逐分支包装：整句模板跨行后守卫读不到 uiText(，会当成新增硬编码。
        val uploadLabel = when {
            result.host -> uiText("本地数据已发送 · 对方回传已接收 · 数据校验：通过")
            result.uploaded && result.verified -> uiText("上传远端：成功 · 数据校验：通过")
            result.uploaded -> uiText("上传远端：成功 · 数据校验：未执行")
            result.verified -> uiText("上传远端：未执行，内容一致 · 数据校验：通过")
            else -> uiText("上传远端：未执行，内容一致 · 数据校验：未执行")
        }
        Text(
            uploadLabel,
            style = MaterialTheme.typography.bodySmall,
            color = if (result.verified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun SyncResultStatRow(label: String, count: Int, color: androidx.compose.ui.graphics.Color) {
    if (count <= 0) return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(color, VaultShape),
            )
            Spacer(Modifier.width(8.dp))
            Text(uiText(label), style = MaterialTheme.typography.bodyMedium)
        }
        Text(
            "$count",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun routeDepth(r: Route): Int = when (r) {
    Route.Root -> 0
    is Route.Category -> 1
    is Route.SecurityResults -> 1
    is Route.MaintenanceSection -> 1
    is Route.Detail -> 2
    is Route.Edit -> if (r.fromDetail) 3 else 2
}

private val RouteSaver = androidx.compose.runtime.saveable.Saver<Route, List<String>>(
    save = { r ->
        when (r) {
            Route.Root -> listOf("root")
            is Route.Category -> listOf("category", r.type)
            is Route.SecurityResults -> listOf("security", r.filter)
            is Route.MaintenanceSection -> listOf("maintenance", r.section)
            is Route.Detail -> listOf("detail", r.id, r.category, r.returnDetailId.orEmpty())
            is Route.Edit -> listOf(
                "edit",
                r.id ?: "",
                r.type,
                if (r.fromDetail) "detail" else "category",
                r.returnCategory,
                r.returnDetailId.orEmpty(),
            )
        }
    },
    restore = { l ->
        when (l[0]) {
            "root" -> Route.Root
            "category" -> Route.Category(l[1])
            "security" -> Route.SecurityResults(l[1])
            "maintenance" -> Route.MaintenanceSection(l[1])
            "detail" -> Route.Detail(l[1], l[2], l.getOrNull(3)?.ifEmpty { null })
            "edit" -> Route.Edit(
                l[1].ifEmpty { null },
                l[2],
                l.getOrNull(3) == "detail",
                l.getOrNull(4).orEmpty(),
                l.getOrNull(5)?.ifEmpty { null },
            )
            else -> Route.Root
        }
    },
)
