package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource
import com.vault.ui.vaultBackdrop
import com.vault.ui.vaultBottomActionWidth
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.unit.IntSize
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.tween
import kotlinx.coroutines.launch

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import com.vault.ui.VaultLazyVerticalGrid as LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import com.vault.ui.VaultDropdownMenu as DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.pulltorefresh.pullToRefresh
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.ViewConfiguration
import androidx.compose.ui.platform.LocalViewConfiguration
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.zIndex
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp
import com.vault.R
import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.ui.NavOrderPref
import com.vault.ui.VaultFloatingBar
import com.vault.ui.VaultIconResources
import com.vault.ui.HomeLayoutMode
import com.vault.ui.HomeLayoutPref
import com.vault.ui.uiText
import kotlin.math.abs
import com.vault.ui.vaultShadow
import com.vault.ui.VaultShape

/** 下拉多远算“松手即进入回收站”。 */
private val PULL_TO_TRASH_THRESHOLD = 96.dp

/**
 * 主页卡片接管指针的长按时长。
 *
 * 平台默认是 500ms，而卡片的“按下”反馈更早出现——两者之间的空窗里横向位移会被
 * 外层 HorizontalPager 拿走，表现为“长按后横滑变成翻页”。这里把两者对齐到同一个值，
 * 空窗消失；只覆盖 HomeScreen 子树，翻页器自身的 touch slop 不受影响。
 */
private const val HOME_LONG_PRESS_MS = 200L

/** 下拉提示文案跟随位移的比例：1.0 = 与卡片同步，这里只跟一小部分以形成跟随感。 */
private const val PULL_HINT_FOLLOW = 0.35f

@OptIn(ExperimentalFoundationApi::class, androidx.compose.material3.ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    entries: List<Entry>,
    onOpenCategory: (String) -> Unit,
    onOrderChanged: (List<String>) -> Unit,
    onAdd: (String) -> Unit,
    scrollToTopSignal: Int = 0,
    modifier: Modifier = Modifier,
    // 卡片长按进入拖拽换位时上报 true：外层用它临时关闭“下拉打开回收站”手势，
    // 避免拖拽换位途中的位移被误判成下拉。
    onDragActiveChanged: (Boolean) -> Unit = {},
    // 顶部继续下拉（标准 pull-to-refresh 手势）时打开回收站。
    onPullToTrash: () -> Unit = {},
) {
    val listState = rememberLazyGridState()
    // PullToRefresh 负责累计下拉距离、阈值和松手触发；页面视觉位移由 distanceFraction 单独驱动。
    // material3 1.3.0 的状态对象不持有 Dp 阈值，实际阈值在 pullToRefresh modifier 上指定。
    val pullState = rememberPullToRefreshState()
    // Only stationary cards feed this state; the dragged card must not sample itself.
    val dragBackdrop = remember { dev.chrisbanes.haze.HazeState() }
    val preferredOrder = NavOrderPref.order.value
    val layoutMode = HomeLayoutPref.mode.value
    var pressedCategory by remember { mutableStateOf<String?>(null) }
    val localOrderState = remember { mutableStateOf(preferredOrder) }
    val localOrder by localOrderState
    val latestOnOrderChanged by rememberUpdatedState(onOrderChanged)
    val latestOnDragActiveChanged by rememberUpdatedState(onDragActiveChanged)
    var draggingType by remember { mutableStateOf<String?>(null) }
    var dragOffsetX by remember { mutableFloatStateOf(0f) }
    var dragOffset by remember { mutableFloatStateOf(0f) }
    val dragScope = rememberCoroutineScope()
    var dragSize by remember { mutableStateOf(IntSize.Zero) }
    var settlingDrag by remember { mutableStateOf(false) }
    var reorderPending by remember { mutableStateOf(false) }
    var dragStartOrder by remember { mutableStateOf<List<String>?>(null) }
    var suppressNextIdleSync by remember { mutableStateOf(false) }
    var showAddSelector by remember { mutableStateOf(false) }
    val activeCountsByType = remember(entries) {
        entries.asSequence().filter { it.deletedAt == null }.groupingBy { it.secretType }.eachCount()
    }
    val activeEntryCount = remember(entries) { entries.count { it.deletedAt == null } }

    fun updateDragTarget() {
        val type = draggingType ?: return
        if (reorderPending || settlingDrag) return
        val layout = listState.layoutInfo
        val cx = dragOffsetX + dragSize.width / 2f
        // Grid item offsets exclude the leading content padding; the overlay uses viewport coordinates.
        val cy = dragOffset + dragSize.height / 2f - layout.beforeContentPadding
        fun contains(item: androidx.compose.foundation.lazy.grid.LazyGridItemInfo) =
            cx >= item.offset.x && cx <= item.offset.x + item.size.width &&
                cy >= item.offset.y && cy <= item.offset.y + item.size.height
        if (layout.visibleItemsInfo.firstOrNull { it.key == type }?.let(::contains) == true) return
        val targetKey = layout.visibleItemsInfo.firstOrNull {
            it.key != type && it.key in localOrderState.value && contains(it)
        }?.key ?: return
        val order = localOrderState.value
        val from = order.indexOf(type)
        val to = order.indexOf(targetKey)
        if (from < 0 || to < 0 || from == to) return
        reorderPending = true
        localOrderState.value = order.toMutableList().also { it.add(to, it.removeAt(from)) }
    }
    LaunchedEffect(localOrder) {
        withFrameNanos { }
        withFrameNanos { }
        reorderPending = false
    }
    LaunchedEffect(draggingType) {
        if (draggingType == null) return@LaunchedEffect
        var lastFrame = withFrameNanos { it }
        while (draggingType != null) {
            val frame = withFrameNanos { it }
            val seconds = ((frame - lastFrame) / 1_000_000_000f).coerceAtMost(0.05f)
            lastFrame = frame
            if (settlingDrag) continue
            val edge = dragSize.height * 0.65f
            val viewport = listState.layoutInfo.viewportSize.height
            val speed = when {
                dragOffset < edge -> -500f * (1f - dragOffset / edge.coerceAtLeast(1f))
                dragOffset + dragSize.height > viewport - edge ->
                    500f * ((dragOffset + dragSize.height - viewport + edge) / edge.coerceAtLeast(1f))
                else -> 0f
            }
            if (speed != 0f) listState.scrollBy(speed * seconds)
            updateDragTarget()
        }
    }

    // 记录上一次已消费的置顶信号：页面重建（从二级页返回）时旧信号不应再次触发置顶，
    // 否则主页滚动位置会被“回到顶部”覆盖。
    var lastScrollSignal by remember { mutableIntStateOf(scrollToTopSignal) }
    LaunchedEffect(scrollToTopSignal) {
        if (scrollToTopSignal > lastScrollSignal) {
            lastScrollSignal = scrollToTopSignal
            listState.animateScrollToItem(0)
        }
    }

    LaunchedEffect(preferredOrder, draggingType) {
        if (draggingType == null) {
            if (suppressNextIdleSync) {
                suppressNextIdleSync = false
            } else {
                localOrderState.value = preferredOrder
            }
        }
    }

    // 下拉进度：节点在每次拖动事件里 snapTo，按住期间单调跟手（不回弹），
    // 松手后由节点的 onRelease 自己 animateToThreshold/animateToHidden。
    // 切勿在这里手动调 state.animateToHidden：它会取消 onRelease 里等待中的
    // animateToThreshold，使 onRefresh() 与 distancePulled = 0f 都被跳过
    // （表现为回收站不弹 + 之后滚动被持续吃掉）。
    val pullFraction = pullState.distanceFraction.coerceAtLeast(0f)
    val pullThresholdPx = with(LocalDensity.current) { PULL_TO_TRASH_THRESHOLD.toPx() }
    val pullVisualOffsetPx = pullThresholdPx * pullFraction.coerceAtMost(1.35f)
    val pullVisualFraction = pullFraction

    // 触发是一次性动作（开回收站），不是刷新：不要停在阈值处，直接回弹。
    // 注意时机——onRelease 是「animateToThreshold() 跑完 → onRefresh()」，所以在
    // onRefresh 里启动隐藏动画不会取消它，且其后的 distancePulled = 0f 仍会执行。
    val pullScope = rememberCoroutineScope()

    val baseViewConfiguration = LocalViewConfiguration.current
    val homeViewConfiguration = remember(baseViewConfiguration) {
        object : ViewConfiguration by baseViewConfiguration {
            override val longPressTimeoutMillis: Long = HOME_LONG_PRESS_MS
        }
    }

    CompositionLocalProvider(LocalViewConfiguration provides homeViewConfiguration) {
    Box(modifier = modifier.fillMaxSize()) {
        // 图标位于网格后方；网格下移时露出，松手后跟随页面一起淡出回弹。
        // 下拉提示用「回收站」文案（与顶栏图标的 contentDescription 同一词条）。
        // 只按位移的一小部分跟随下移，于是它比卡片"慢半拍"，像被拉住一点。
        Text(
            stringResource(com.vault.R.string.nav_trash),
            style = MaterialTheme.typography.labelLarge,
            color = if (pullVisualFraction >= 1f) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
            modifier = Modifier
                .align(Alignment.TopCenter)
                .padding(top = 12.dp)
                .graphicsLayer {
                    translationY = pullVisualOffsetPx * PULL_HINT_FOLLOW
                    alpha = pullVisualFraction.coerceIn(0f, 1f)
                },
        )
        LazyVerticalGrid(
            columns = GridCells.Fixed(if (layoutMode == HomeLayoutMode.TWO_COLUMNS) 2 else 1),
            state = listState,
            modifier = Modifier
                .vaultBackdropSource()
                .fillMaxSize()
                // 拖动时实时跟手；松手后由框架的释放动画自动回到顶部。
                .graphicsLayer {
                    translationY = pullVisualOffsetPx
                }
                .background(MaterialTheme.colorScheme.background)
                .pullToRefresh(
                    isRefreshing = false,
                    state = pullState,
                    enabled = draggingType == null,
                    threshold = PULL_TO_TRASH_THRESHOLD,
                    onRefresh = {
                        pullScope.launch { pullState.animateToHidden() }
                        onPullToTrash()
                    },
                )
                .then(if (draggingType != null) Modifier.vaultBackdropSource(dragBackdrop) else Modifier),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = 16.dp, end = 16.dp, top = 8.dp, bottom = 80.dp
            ),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            // 顶部继续下拉交给 PullToRefreshBox，底部保留边缘回弹。
            allowTopPull = true,
        ) {
            item(key = "hint", span = { GridItemSpan(maxLineSpan) }) {
                Text(
                    uiText("共 $activeEntryCount 条"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 2.dp, vertical = 0.dp),
                )
            }
            items(localOrder, key = { it }) { type ->
                val isDragging = draggingType == type
                val isPressed = pressedCategory == type && !isDragging && !listState.isScrollInProgress
                val drawLayer = if (isDragging) {
                    1f
                } else {
                    ((localOrder.size - localOrder.indexOf(type)).coerceAtLeast(0)) / 100f
                }
                val cardScale by animateFloatAsState(
                    targetValue = if (isPressed) 0.95f else 1f,
                    animationSpec = if (listState.isScrollInProgress) androidx.compose.animation.core.snap() else spring(stiffness = 600f),
                )
                val count = activeCountsByType[type] ?: 0
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 76.dp)
                        .zIndex(drawLayer)
                        // 拖拽换位时其余卡片以柔和动画平滑滑入新位置（而非瞬跳），收敛弹性避免过度活泼；
                        // 手指正按住的这张卡片跳过该动画，只交给下面的 graphicsLayer 跟手位移，
                        // 否则会和 animateItem 的位移动画叠加，看起来像“被顶开”。
                        .then(
                            if (isDragging || listState.isScrollInProgress ||
                                (draggingType == null && !settlingDrag && !reorderPending)) Modifier
                            else Modifier.animateItem(
                                fadeInSpec = null,
                                placementSpec = spring(
                                    dampingRatio = Spring.DampingRatioNoBouncy,
                                    stiffness = Spring.StiffnessMediumLow,
                                ),
                                fadeOutSpec = null,
                            )
                        )
                        .graphicsLayer {
                            scaleX = cardScale
                            scaleY = cardScale
                            alpha = if (isDragging) 0f else 1f
                        }
                        .pointerInput(type) {
                            detectDragGesturesAfterLongPress(
                                onDragStart = {
                                    dragStartOrder = localOrderState.value
                                    draggingType = type
                                    val item = listState.layoutInfo.visibleItemsInfo.firstOrNull { it.key == type }
                                    // Lazy 网格的悬浮层位于外层 Box，单列时也必须保留网格的左右安全内边距。
                                    dragOffsetX = maxOf(16.dp.toPx(), item?.offset?.x?.toFloat() ?: 16.dp.toPx())
                                    dragOffset = (item?.offset?.y ?: 0).toFloat() + listState.layoutInfo.beforeContentPadding
                                    dragSize = item?.size ?: IntSize.Zero
                                    settlingDrag = false
                                    latestOnDragActiveChanged(true)
                                },
                                onDragCancel = {
                                    dragStartOrder?.let { localOrderState.value = it }
                                    dragStartOrder = null
                                    draggingType = null
                                    dragOffsetX = 0f
                                    dragOffset = 0f
                                    latestOnDragActiveChanged(false)
                                },
                                onDragEnd = {
                                    settlingDrag = true
                                    dragScope.launch {
                                        val target = listState.layoutInfo.visibleItemsInfo.firstOrNull { it.key == type }
                                        val startX = dragOffsetX
                                        val startY = dragOffset
                                        val safeX = 16.dp.toPx()
                                        val endX = (target?.offset?.x?.toFloat() ?: startX).coerceIn(
                                            safeX, (listState.layoutInfo.viewportSize.width - dragSize.width - safeX).coerceAtLeast(safeX))
                                        val endY = target?.let { it.offset.y.toFloat() + listState.layoutInfo.beforeContentPadding } ?: startY
                                        animate(0f, 1f, animationSpec = tween(140)) { progress, _ ->
                                            dragOffsetX = startX + (endX - startX) * progress
                                            dragOffset = startY + (endY - startY) * progress
                                        }
                                        dragStartOrder = null
                                        suppressNextIdleSync = true
                                        draggingType = null
                                        settlingDrag = false
                                        latestOnDragActiveChanged(false)
                                        latestOnOrderChanged(localOrderState.value)
                                    }
                                },
                                onDrag = { change, amount ->
                                    change.consume()
                                    val viewport = listState.layoutInfo.viewportSize
                                    if (layoutMode == HomeLayoutMode.TWO_COLUMNS) {
                                        dragOffsetX = (dragOffsetX + amount.x).coerceIn(
                                            16.dp.toPx(), (viewport.width - dragSize.width - 16.dp.toPx()).coerceAtLeast(16.dp.toPx())
                                        )
                                    }
                                    dragOffset = (dragOffset + amount.y).coerceIn(
                                        0f, (viewport.height - dragSize.height).coerceAtLeast(0).toFloat()
                                    )
                                    updateDragTarget()
                                },
                            )
                        }
                        .pointerInput(type) {
                            detectTapGestures(
                                onPress = {
                                    if (!isDragging) {
                                        pressedCategory = type
                                        try { tryAwaitRelease() }
                                        finally {
                                            if (pressedCategory == type) pressedCategory = null
                                        }
                                    }
                                },
                                onTap = {
                                    if (!isDragging) onOpenCategory(type)
                                },
                            )
                        },
                    shape = VaultShape,
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                    ),
                    elevation = CardDefaults.cardElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp,
                        focusedElevation = 0.dp,
                        hoveredElevation = 0.dp,
                        draggedElevation = 0.dp,
                        disabledElevation = 0.dp,
                    ),
                ) {
                    HomeCategoryContent(type, count)
                }
            }
        }

        draggingType?.let { type ->
            val density = LocalDensity.current
            Card(
                modifier = Modifier
                    .width(with(density) { dragSize.width.toDp() })
                    .height(with(density) { dragSize.height.toDp() })
                    .graphicsLayer { translationX = dragOffsetX; translationY = dragOffset }
                    .vaultShadow(14.dp)
                    .vaultBackdrop(state = dragBackdrop)
                    .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.5f), VaultShape),
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = Color.Transparent),
                elevation = CardDefaults.cardElevation(0.dp),
            ) {
                HomeCategoryContent(type, activeCountsByType[type] ?: 0)
            }
        }

        BoxWithConstraints(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .wrapContentWidth()
                .padding(24.dp),
        ) {
            VaultFloatingBar(
                onClick = { showAddSelector = true },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                elevation = 8.dp,
                contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
                backdropEnabled = false,
                containerAlpha = 1f,
            ) {
                Spacer(Modifier.width(8.dp))
                Icon(Icons.Default.Add, null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.add), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.width(8.dp))
            }
            // 选择器高度随窗口自适应（小窗下不挤压/覆盖新增按钮）：DropdownMenu 内容区
            // Material3 内部已自带纵向滚动 Column，这里只需用 heightIn 限高触发它；
            // 若再叠加一层 Modifier.verticalScroll 会形成同轴嵌套可滚动容器，
            // 测量时抛出 "measured with an infinity maximum height constraints" 崩溃。
            val menuMaxHeight = (maxHeight - 96.dp).coerceAtLeast(120.dp)
            DropdownMenu(
                expanded = showAddSelector,
                onDismissRequest = { showAddSelector = false },
                alignRight = true,
                modifier = Modifier
                    .heightIn(max = menuMaxHeight),
                containerColor = popupMenuSurface(),
            ) {
                localOrder.filterNot { it == NavOrderPref.PASSKEY_CATEGORY }.forEach { type ->
                    DropdownMenuItem(
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier.size(28.dp).clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainerHighest),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Icon(
                                        painter = painterResource(categoryIconRes(type)),
                                        contentDescription = null,
                                        tint = androidx.compose.ui.graphics.Color.Unspecified,
                                        modifier = Modifier.size(20.dp),
                                    )
                                }
                                Spacer(Modifier.width(10.dp))
                                Text(categoryLabel(type))
                            }
                        },
                        onClick = { showAddSelector = false; onAdd(type) },
                    )
                }
            }
        }
    }
    }
}

@Composable
internal fun categoryLabel(type: String): String = stringResource(when (type) {
    SecretType.LOGIN -> R.string.category_login
    SecretType.WIFI -> R.string.category_wifi
    SecretType.CARD_DOCUMENT -> R.string.category_card_document
    SecretType.API_KEY -> R.string.category_key
    SecretType.OTP -> R.string.category_otp
    SecretType.SECURE_NOTE -> R.string.category_secure_note
    SecretType.SERVER -> R.string.category_server
    SecretType.CUSTOM -> R.string.category_custom
    NavOrderPref.PASSKEY_CATEGORY -> R.string.category_passkey
    else -> R.string.category_custom
})

internal fun categoryIconRes(type: String): Int = VaultIconResources.category(type)

// 分类图标背景色统一走 Theme.kt 的 TypeColors 单一来源，避免与详情页色板漂移。
internal fun categoryIconBackground(type: String) = com.vault.ui.TypeColors.of(type)

@Composable
private fun HomeCategoryContent(type: String, count: Int) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            painter = painterResource(categoryIconRes(type)),
                            contentDescription = null,
                            tint = androidx.compose.ui.graphics.Color.Unspecified,
                            modifier = Modifier.size(36.dp),
                        )
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(
                                categoryLabel(type),
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                stringResource(R.string.item_count, count),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
}
