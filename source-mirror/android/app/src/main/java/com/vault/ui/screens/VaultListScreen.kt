package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource
import com.vault.ui.vaultBackdrop
import com.vault.ui.vaultHorizontalFeather
import com.vault.ui.vaultBottomActionWidth

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.core.Spring
import androidx.activity.compose.BackHandler
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.WindowInsetsSides
import com.vault.ui.VaultLazyColumn as LazyColumn
import com.vault.ui.VaultLazyRow as LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Tag
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import com.vault.model.Entry
import com.vault.model.ExpiryInfo
import com.vault.model.ExpiryStatus
import com.vault.model.SecretType
import com.vault.model.VaultOps
import com.vault.model.OtpDisplaySnapshot
import com.vault.model.displaySecret
import com.vault.model.expiryInfo
import com.vault.R
import com.vault.ui.uiText
import com.vault.ui.copySensitive
import com.vault.ui.TypeColors
import com.vault.ui.UiState
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.VaultFloatingBar
import com.vault.ui.VaultHazePopup
import androidx.compose.foundation.layout.heightIn
import com.vault.ui.VaultDropdownMenu
import com.vault.ui.vaultFrostedSurface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.abs
import kotlin.math.roundToInt
import com.vault.ui.VaultShape
import com.vault.ui.vaultShadow

@OptIn(ExperimentalMaterial3Api::class, kotlinx.coroutines.FlowPreview::class)
@Composable
fun VaultListScreen(
    state: UiState,
    category: String,
    onSearch: (String) -> Unit,
    onTagFilter: (String?) -> Unit,
    onBack: () -> Unit,
    onOpen: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onDelete: (Entry) -> Unit,
    onAdd: (String) -> Unit,
    onRenameTag: (String, String) -> Unit,
    onReorderTag: (String, Int) -> Unit = { _, _ -> },
    onBatchDelete: (Set<String>) -> Unit = {},
    onBatchTag: (String, List<String>, Set<String>) -> Unit = { _, _, _ -> },
    otpSnapshotProvider: (String, Long) -> OtpDisplaySnapshot? = { _, _ -> null },
) {
    val payload = state.payload ?: return
    var deleteTarget by remember { mutableStateOf<Entry?>(null) }
    var renamingTag by remember { mutableStateOf<String?>(null) }
    var showRenameTagMenu by remember { mutableStateOf(false) }
    var moreActionsMode by remember { mutableStateOf(false) }
    var selectedIds by remember { mutableStateOf(setOf<String>()) }
    var showMoreActionsTagDialog by remember { mutableStateOf(false) }
    var moreActionsTagMode by remember { mutableStateOf("") } // "move" or "add"
    var batchBarHeightDp by remember { mutableStateOf(0.dp) } // 底部批量操作条高度（A-Z 条底部让位用）
    var batchDeleteIds by remember { mutableStateOf<Set<String>?>(null) }
    val tagFilter = state.tagFilter
    val typeFilter = category
    val currentListState = rememberLazyListState()
    val currentOnTagFilter by rememberUpdatedState(onTagFilter)

    val showFab by remember(currentListState) {
        derivedStateOf {
            currentListState.firstVisibleItemIndex == 0 || !currentListState.isScrollInProgress
        }
    }

    // 输入框走本地 state 即时回显；80ms 去抖后异步推到 ViewModel，避免连击键时主线程反复重组+过滤
    val searchInput = remember(category) { com.vault.ui.SearchInputState(state.query) }
    val searchFocus = remember { androidx.compose.ui.focus.FocusRequester() }
    val currentOnSearch by rememberUpdatedState(onSearch)
    LaunchedEffect(searchInput) {
        snapshotFlow { searchInput.value.text }
            .debounce(80)
            .distinctUntilChanged()
            .conflate()
            .collectLatest { q ->
                // Publish on the UI thread so old asynchronous callbacks cannot race newer edits.
                if (q == searchInput.value.text) currentOnSearch(searchInput.publish())
            }
    }
    // 外部清空（如点击当前类别图标）时同步回本地
    LaunchedEffect(state.query) {
        searchInput.acceptExternal(state.query)
    }

    val currentOnOpen by rememberUpdatedState(onOpen)
    val listIndex = state.listIndex
    val categoryEntries = remember(listIndex, category) {
        listIndex.entriesByType[category].orEmpty()
    }
    val byQuery = remember(categoryEntries, state.query) {
        VaultOps.filterSorted(categoryEntries, state.query)
    }
    val filtered = remember(byQuery, tagFilter, category) {
        when (tagFilter) {
            null -> byQuery
            UNTAGGED_KEY -> byQuery.filter { it.tags.isEmpty() }
            else -> byQuery.filter { tagFilter in it.tags }
        }
    }
    val leakedIds = remember(filtered, listIndex, category) {
        val categoryLeakedIds = listIndex.leakedIdsByType[category].orEmpty()
        if (categoryLeakedIds.isEmpty()) emptySet()
        else filtered.asSequence()
            .map { it.id }
            .filterTo(linkedSetOf()) { it in categoryLeakedIds }
    }
    val currentBatchIds = remember(filtered) {
        filtered.map { it.id }.toSet()
    }
    val allCurrentSelected = currentBatchIds.isNotEmpty() && currentBatchIds.all { it in selectedIds }
    // 标签是纯元数据，Passkey 条目也允许打标签与批量整理；条目本身仍不可编辑。
    val canManageTags = true
    val tags: List<String> = listIndex.tagsByType[typeFilter].orEmpty()
    val hasUntagged: Boolean = typeFilter in listIndex.hasUntaggedByType

    LaunchedEffect(tags, hasUntagged, tagFilter) {
        when {
            !hasUntagged && tagFilter == UNTAGGED_KEY -> onTagFilter(null)
            tagFilter != null && tagFilter != UNTAGGED_KEY && tagFilter !in tags -> onTagFilter(null)
        }
    }
    val swipeTagFilters = remember(tags, hasUntagged) {
        buildList<String?> {
            add(null)
            if (hasUntagged) add(UNTAGGED_KEY)
            addAll(tags)
        }
    }
    val tagSwipeModifier =
        if (swipeTagFilters.size > 1 && !moreActionsMode) {
            Modifier.pointerInput(swipeTagFilters, tagFilter) {
                var dragOffset = 0f
                detectHorizontalDragGestures(
                    onDragStart = { dragOffset = 0f },
                    onHorizontalDrag = { change, dragAmount ->
                        change.consume()
                        dragOffset += dragAmount
                    },
                    onDragEnd = {
                        val threshold = 72.dp.toPx()
                        if (abs(dragOffset) >= threshold) {
                            val current = swipeTagFilters.indexOf(tagFilter).takeIf { it >= 0 } ?: 0
                            val next = when {
                                dragOffset < 0f -> (current + 1).coerceAtMost(swipeTagFilters.lastIndex)
                                else -> (current - 1).coerceAtLeast(0)
                            }
                            if (next != current) currentOnTagFilter(swipeTagFilters[next])
                        }
                        dragOffset = 0f
                    },
                    onDragCancel = { dragOffset = 0f },
                )
            }
        } else {
            Modifier
        }

    BackHandler(enabled = moreActionsMode) {
        moreActionsMode = false
        selectedIds = emptySet()
    }

    Scaffold(
        topBar = {
            Box(modifier = Modifier.fillMaxWidth()) {
                VaultSubpageTopBar(
                    title = if (moreActionsMode) "" else categoryLabel(category),
                    subtitle = if (moreActionsMode) null else uiText("${listIndex.activeCountsByType[category] ?: 0} 条"),
                    titleColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    onBack = if (moreActionsMode) null else onBack,
                    backContentDescription = stringResource(R.string.general_remaining_back),
                )
                if (moreActionsMode) {
                    // 批量模式：标题栏整体居中的 “✕ + 已选 N 条” 胶囊。
                    // 避开标题栏系统保留区，与返回箭头中心齐平；胶囊高度 32dp，
                    // 左右留白与原胶囊一致，不额外撑宽。
                    Row(
                        modifier = Modifier
                            .align(Alignment.Center)
                            .windowInsetsPadding(TopAppBarDefaults.windowInsets)
                            .height(32.dp)
                            .clip(RoundedCornerShape(percent = 50))
                            .background(
                                color = MaterialTheme.colorScheme.surfaceContainerHighest.copy(alpha = 0.9f),
                                shape = RoundedCornerShape(percent = 50),
                            )
                            .clickable {
                                moreActionsMode = false
                                selectedIds = emptySet()
                            }
                            .padding(horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        Icon(
                            Icons.Default.Close,
                            stringResource(R.string.general_remaining_cancel_selection),
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            uiText("已选 ${selectedIds.size} 条"),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        )
                    }
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad ->
        Box(modifier = Modifier.fillMaxSize().padding(pad)) {
            Box(Modifier.align(Alignment.BottomCenter).zIndex(3f)) {
            // Standalone bottom action, centered in the page overlay.
            AnimatedVisibility(
                visible = !moreActionsMode && showFab && category != com.vault.ui.NavOrderPref.PASSKEY_CATEGORY,
                enter = androidx.compose.animation.EnterTransition.None,
                exit = androidx.compose.animation.ExitTransition.None,
            ) {
                // Half-window width leaves equal safe margins.
                Box(
                    modifier = Modifier.padding(bottom = 28.dp),
                    contentAlignment = Alignment.CenterEnd,
                ) {
                    VaultFloatingBar(
                        modifier = Modifier.vaultBottomActionWidth().height(48.dp),
                        onClick = { onAdd(category) },
                        contentColor = MaterialTheme.colorScheme.primary,
                        elevation = 8.dp,
                        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 0.dp),
                    ) {
                        Spacer(Modifier.width(8.dp))
                        Icon(Icons.Default.Add, null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(uiText("新增条目"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.width(8.dp))
                    }
                }
            }
            }
            var tagBarHeight by remember { mutableStateOf(0.dp) }
            var searchBarHeightDp by remember { mutableStateOf(0.dp) }
            // 批量底部条：内容层覆盖（整屏宽居中，不占 FAB 槽）
            if (moreActionsMode) {
                val barDensity = LocalDensity.current
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .zIndex(10f)
                        .padding(start = 16.dp, end = 16.dp, bottom = 28.dp)
                        .onSizeChanged { px -> batchBarHeightDp = with(barDensity) { px.height.toDp() } },
                ) {
                    MoreActionsBar(
                        selectedCount = selectedIds.size,
                        allSelected = allCurrentSelected,
                        canManageTags = canManageTags,
                        onDelete = {
                            val ids = selectedIds.toSet()
                            if (ids.isNotEmpty()) batchDeleteIds = ids
                        },
                        onToggleAll = {
                            selectedIds = if (allCurrentSelected) {
                                selectedIds - currentBatchIds
                            } else {
                                selectedIds + currentBatchIds
                            }
                        },
                        onTagMove = {
                            if (canManageTags && selectedIds.isNotEmpty()) {
                                moreActionsTagMode = "move"
                                showMoreActionsTagDialog = true
                            }
                        },
                        onTagAdd = {
                            if (canManageTags && selectedIds.isNotEmpty()) {
                                moreActionsTagMode = "add"
                                showMoreActionsTagDialog = true
                            }
                        },
                    )
                }
            }
            Column(modifier = Modifier.fillMaxSize()) {
            // 搜索条始终显示；批量模式下标签悬浮条照常避开搜索框并悬浮于列表之上
            run {
            // 紧凑搜索条：M3 TextField 内部最小高度约 80dp，改用 BasicTextField 自绘压到 44dp
            // 外层 Box 测量搜索条实际高度，标签悬浮条据此避开搜索框、只悬浮于列表之上。
            val searchBarDensity = LocalDensity.current
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .onSizeChanged { px -> searchBarHeightDp = with(searchBarDensity) { px.height.toDp() } },
            ) {
            BasicTextField(
                value = searchInput.value,
                onValueChange = searchInput::edit,
                modifier = Modifier.focusRequester(searchFocus),
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(color = MaterialTheme.colorScheme.onSurface),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                decorationBox = { innerTextField ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 6.dp)
                            .vaultShadow(2.dp)
                            .background(color = MaterialTheme.colorScheme.surface, shape = VaultShape)
                            .height(44.dp)
                            .padding(horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Default.Search,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.width(8.dp))
                        Box(Modifier.weight(1f)) {
                            if (searchInput.value.text.isEmpty()) {
                                Text(
                                    uiText("搜索条目"),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                )
                            }
                            innerTextField()
                        }
                        // Reserve a stable trailing slot so clearing does not resize the editor.
                        Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                            if (searchInput.value.text.isNotEmpty()) {
                                IconButton(onClick = {
                                    currentOnSearch(searchInput.clear())
                                    searchFocus.requestFocus()
                                }) {
                                    Icon(Icons.Default.Close,
                                        contentDescription = stringResource(R.string.clear_search_query),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(20.dp))
                                }
                            }
                        }
                    }
                },
            )
            }
            }
            run {
                val pageEntries = filtered
                data class PageSort(val entries: List<Entry>, val leakedCount: Int, val hasLeaked: Boolean)
                val pageData = remember(pageEntries, leakedIds) {
                    val hasLeaked = leakedIds.isNotEmpty()
                    val sorted = if (hasLeaked) {
                        pageEntries.sortedWith(
                            compareBy<Entry> { it.id !in leakedIds }
                                .thenBy { it.titleSortKey }
                        )
                    } else {
                        pageEntries
                    }
                    // leakedCount 必须是 sorted 中实际位于顶部的置顶（泄露）条目数；
                    // 直接用 leakedIds.size 在按分类/标签过滤后会偏大，导致字母索引跳转错位。
                    val leakedCount = sorted.takeWhile { it.id in leakedIds }.size
                    PageSort(sorted, leakedCount, hasLeaked)
                }
                Box(modifier = tagSwipeModifier.fillMaxSize().clipToBounds()) {
                    VaultListPageContent(
                        page = VaultListPage(
                            category,
                            pageData.entries,
                            pageData.leakedCount,
                            listIndex.activeCountsByType.values.sum(),
                            hasLeaked = pageData.hasLeaked,
                            leakedIds = leakedIds,
                        ),
                        listState = currentListState,
                        showAlphabetSidebar = true,
                        moreActionsMode = moreActionsMode,
                        selectedIds = selectedIds,
                        // 列表和字母索引顶部均为悬浮标签保留原有高度
                        contentTopPadding = if ((tags.isNotEmpty() || hasUntagged) || moreActionsMode) tagBarHeight + 8.dp else 8.dp,
                        onOpen = currentOnOpen,
                        onEdit = onEdit,
                        onDeleteRequest = { deleteTarget = it },
                        onToggleSelect = { id ->
                            selectedIds = if (id in selectedIds) selectedIds - id else selectedIds + id
                        },
                        onMoreActionsEnter = { id ->
                            moreActionsMode = true
                            selectedIds = setOf(id)
                        },
                        otpSnapshotProvider = otpSnapshotProvider,
                    )
                }
            }
        }
        // 标签筛选条：整条内容直接悬浮（无背景容器），位于搜索框正下方、只覆盖列表顶部，
        // 列表内容可滚动从 chips 之间/下方穿过。
        // offset 负责把它放到搜索框下方（不参与高度测量），tagBarHeight 统计整个悬浮头部（标签行+数量胶囊）高度。
        if ((tags.isNotEmpty() || hasUntagged) || moreActionsMode) {
            val tagListState = rememberLazyListState()
            val selectedTagIndex = when (tagFilter) {
                null -> 0
                UNTAGGED_KEY -> if (hasUntagged) 1 else 0
                else -> {
                    val tagIndex = tags.indexOf(tagFilter)
                    if (tagIndex < 0) 0 else tagIndex + 1 + if (hasUntagged) 1 else 0
                }
            }
            LaunchedEffect(selectedTagIndex, tags, hasUntagged) {
                tagListState.animateScrollToItem(selectedTagIndex)
            }
            val density = LocalDensity.current
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    // 搜索条常驻，标签悬浮条始终错开其高度
                    .offset(y = searchBarHeightDp)
                    .padding(start = 16.dp, end = 28.dp),
            ) {
                // 悬浮头部（常驻）：条目从下方穿过时，用自上而下的羽化渐变蒙版避免透字杂乱
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Brush.verticalGradient(
                                0f to MaterialTheme.colorScheme.background.copy(alpha = 0.97f),
                                0.6f to MaterialTheme.colorScheme.background.copy(alpha = 0.8f),
                                1f to Color.Transparent,
                            )
                        )
                        .onSizeChanged { px -> tagBarHeight = with(density) { px.height.toDp() } },
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (tags.isNotEmpty()) {
                            Box {
                                Box(
                                    modifier = Modifier
                                        .size(32.dp)
                                        .clip(CircleShape)
                                        .clickable { showRenameTagMenu = true },
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Icon(Icons.Default.Edit, stringResource(R.string.general_remaining_rename_tag), modifier = Modifier.size(18.dp))
                                }
                                if (showRenameTagMenu) {
                                    VaultDropdownMenu(
                                        expanded = showRenameTagMenu,
                                        onDismissRequest = { showRenameTagMenu = false },
                                        modifier = Modifier.heightIn(max = 320.dp),
                                    ) {
                                    // 点选 → 重命名；长按 → 直接拖动到目标位排序（支持多位置跳转）
                                    val rowHeightPx = with(LocalDensity.current) { 36.dp.toPx() }
                                    var draggingTag by remember { mutableStateOf<String?>(null) }
                                    var dragFromIndex by remember { mutableIntStateOf(0) }
                                    var dragTargetIndex by remember { mutableIntStateOf(0) }
                                    for (t in tags) {
                                        val index = tags.indexOf(t)
                                        val accent = MaterialTheme.colorScheme.primary
                                        val isDragging = draggingTag == t
                                        val isDropTarget = draggingTag != null && !isDragging &&
                                            index == dragTargetIndex && dragTargetIndex != dragFromIndex
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .clip(VaultShape)
                                                .clickable { showRenameTagMenu = false; renamingTag = t }
                                                .background(
                                                    color = if (isDragging) accent.copy(alpha = 0.08f) else Color.Transparent,
                                                    shape = RoundedCornerShape(8.dp),
                                                )
                                                .drawBehind {
                                                    if (isDropTarget) {
                                                        val strokeWidth = 3f
                                                        val halfStroke = strokeWidth / 2f
                                                        val y = if (dragTargetIndex > dragFromIndex) {
                                                            size.height - halfStroke
                                                        } else {
                                                            halfStroke
                                                        }
                                                        drawLine(
                                                            color = accent,
                                                            start = Offset(0f, y),
                                                            end = Offset(size.width, y),
                                                            strokeWidth = strokeWidth,
                                                        )
                                                    }
                                                }
                                                .pointerInput(t) {
                                                    // onDrag 的 amount 是单帧位移，须累计成总位移再换算目标位
                                                    var accY = 0f
                                                    detectDragGesturesAfterLongPress(
                                                        onDragStart = {
                                                            accY = 0f
                                                            draggingTag = t
                                                            dragFromIndex = index
                                                            dragTargetIndex = index
                                                        },
                                                        onDrag = { change, amount ->
                                                            change.consume()
                                                            accY += amount.y
                                                            dragTargetIndex = (dragFromIndex + (accY / rowHeightPx).roundToInt())
                                                                .coerceIn(0, tags.lastIndex)
                                                        },
                                                        onDragEnd = {
                                                            val from = dragFromIndex
                                                            val to = dragTargetIndex
                                                            if (draggingTag != null && from != to) {
                                                                onReorderTag(draggingTag!!, to)
                                                            }
                                                            draggingTag = null
                                                        },
                                                        onDragCancel = { draggingTag = null },
                                                    )
                                                }
                                                .padding(horizontal = 12.dp, vertical = 6.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                        ) {
                                            Text(
                                                t,
                                                style = MaterialTheme.typography.bodyMedium,
                                                maxLines = 1,
                                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                                                modifier = Modifier.weight(1f),
                                            )
                                        }
                                    }
                                    }
                                }
                            }
                            Spacer(Modifier.width(4.dp))
                        }
                        LazyRow(
                            state = tagListState,
                            modifier = Modifier.weight(1f)
                                .vaultHorizontalFeather({ tagListState.canScrollBackward }, { tagListState.canScrollForward }),
                            contentPadding = PaddingValues(end = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            item {
                                TagFilterChip(
                                    selected = tagFilter == null,
                                    onClick = { onTagFilter(null) },
                                    label = uiText("全部标签"),
                                )
                            }
                            if (hasUntagged) {
                                item {
                                    TagFilterChip(
                                        selected = tagFilter == UNTAGGED_KEY,
                                        onClick = { onTagFilter(if (tagFilter == UNTAGGED_KEY) null else UNTAGGED_KEY) },
                                        label = uiText("无标签"),
                                    )
                                }
                            }
                            items(tags) { t ->
                                TagFilterChip(
                                    selected = tagFilter == t,
                                    onClick = { onTagFilter(if (tagFilter == t) null else t) },
                                    label = t,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    }

    renamingTag?.let { old ->
        var newName by remember { mutableStateOf(old) }
        VaultDialog(
            containerColor = MaterialTheme.colorScheme.background,
            onDismissRequest = { renamingTag = null },
            title = { Text(uiText("重命名标签")) },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = com.vault.ui.InputFilters.capLength(it.trim(), 30) },
                    label = { Text(uiText("新标签名")) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        val trimmed = newName.trim()
                        if (trimmed.isNotEmpty() && trimmed != old) {
                            onRenameTag(old, trimmed)
                            if (tagFilter == old) onTagFilter(trimmed)
                        }
                        renamingTag = null
                    },
                    enabled = newName.trim().isNotEmpty() && newName.trim() != old,
                ) { Text(uiText("确认")) }
            },
            dismissButton = {
                VaultButton(
                    onClick = { renamingTag = null },
                    variant = VaultButtonVariant.OUTLINED,
                ) { Text(uiText("取消")) }
            },
        )
    }

    if (showMoreActionsTagDialog) {
        val allTags = remember(payload.entries) {
            payload.entries.asSequence()
                .filter { it.deletedAt == null && it.secretType == category }
                .flatMap { it.tags.asSequence() }
                .distinct()
                .sorted()
                .toList()
        }
        var tagInput by remember { mutableStateOf("") }
        val currentTags = remember(tagInput) { com.vault.ui.splitTagText(tagInput) }
        // 与编辑页标签框一致：单一数据源为输入文本，点击已有标签自动填入/切换移除，手动输入确认时统一解析格式化。
        val toggleTagText: (String) -> Unit = { t ->
            val cleaned = t.trim()
            if (cleaned.isNotEmpty()) {
                val cur = com.vault.ui.splitTagText(tagInput)
                tagInput = if (cleaned in cur) {
                    (cur - cleaned).joinToString(", ")
                } else {
                    (cur + cleaned).joinToString(", ")
                }
            }
        }
        val tagsToApply = if (moreActionsTagMode == "add") {
            currentTags
        } else listOf(tagInput.trim()).filter(String::isNotEmpty)
        VaultDialog(
            containerColor = MaterialTheme.colorScheme.background,
            onDismissRequest = { showMoreActionsTagDialog = false },
            shape = VaultShape,
            title = { Text(stringResource(if (moreActionsTagMode == "move") R.string.general_remaining_move_to_tag else R.string.general_remaining_add_tag)) },
            text = {
                Column {
                    Text(
                        stringResource(if (moreActionsTagMode == "move") R.string.general_remaining_replace_tags_for_selected else R.string.general_remaining_add_tag_for_selected, selectedIds.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(10.dp))
                    OutlinedTextField(
                        value = tagInput,
                        onValueChange = { tagInput = com.vault.ui.InputFilters.capLength(it, 300) },
                        label = { Text(uiText("标签名称")) },
                        singleLine = true,
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (allTags.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            uiText("已有标签"),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(4.dp))
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(allTags) { t ->
                                FilterChip(
                                    selected = if (moreActionsTagMode == "add") t in currentTags else tagInput == t,
                                    onClick = {
                                        if (moreActionsTagMode == "add") toggleTagText(t) else tagInput = t
                                    },
                                    label = { Text(t) },
                                    shape = VaultShape,
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        if (tagsToApply.isNotEmpty()) {
                            onBatchTag(moreActionsTagMode, tagsToApply, selectedIds.toSet())
                            moreActionsMode = false
                            selectedIds = emptySet()
                        }
                        showMoreActionsTagDialog = false
                    },
                    enabled = tagsToApply.isNotEmpty(),
                    style = VaultActionStyle.PRIMARY,
                    disabledContainerColor = Color.Transparent,
                ) { Text(uiText("确认")) }
            },
            dismissButton = {
                VaultActionButton(onClick = { showMoreActionsTagDialog = false }) { Text(uiText("取消")) }
            },
        )
    }

    deleteTarget?.let { entry ->
        VaultDialog(
            containerColor = MaterialTheme.colorScheme.background,
            onDismissRequest = { deleteTarget = null },
            shape = VaultShape,
            title = { Text(uiText("删除条目")) },
            text = { Text(uiText("确定删除「${entry.title.ifEmpty { "无标题" }}」？删除后可在回收站中恢复。")) },
            confirmButton = {
                VaultActionButton(
                    onClick = { onDelete(entry); deleteTarget = null },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("删除")) }
            },
            dismissButton = {
                VaultActionButton(onClick = { deleteTarget = null }) { Text(uiText("取消")) }
            },
        )
    }

    batchDeleteIds?.let { ids ->
        VaultDialog(
            containerColor = MaterialTheme.colorScheme.background,
            onDismissRequest = { batchDeleteIds = null },
            shape = VaultShape,
            title = { Text(uiText("批量删除")) },
            text = { Text(uiText("确定删除已选择的 ${ids.size} 条条目？删除后可在回收站中恢复。")) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        onBatchDelete(ids)
                        batchDeleteIds = null
                        moreActionsMode = false
                        selectedIds = emptySet()
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("删除")) }
            },
            dismissButton = {
                VaultActionButton(onClick = { batchDeleteIds = null }) { Text(uiText("取消")) }
            },
        )
    }
}

private data class VaultListPage(
    val typeFilter: String?,
    val entries: List<Entry>,
    val leakedCount: Int,
    val totalEntries: Int,
    val hasLeaked: Boolean = false,
    val leakedIds: Set<String> = emptySet(),
)

private fun categoryIndex(type: String?, types: List<String>): Int =
    types.indexOf(type).takeIf { it >= 0 } ?: 0

/** 标签筛选 chip：胶囊自身半透明 + 背景模糊（自绘，避免 FilterChip 的模糊层盖到 48dp 触控区）。 */
@Composable
private fun TagFilterChip(
    selected: Boolean,
    onClick: () -> Unit,
    label: String,
) {
    val container = if (selected) MaterialTheme.colorScheme.primary else popupMenuSurface()
    val contentColor = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
    Box(
        modifier = Modifier
            .clip(VaultShape)
            .vaultBackdrop(baseColor = container)
            .background(container.copy(alpha = if (selected) 1f else 0.5f), VaultShape)
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = contentColor, maxLines = 1)
    }
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
private fun VaultListPageContent(
    page: VaultListPage,
    listState: androidx.compose.foundation.lazy.LazyListState,
    showAlphabetSidebar: Boolean,
    moreActionsMode: Boolean = false,
    selectedIds: Set<String> = emptySet(),
    onOpen: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onDeleteRequest: (Entry) -> Unit,
    onToggleSelect: (String) -> Unit = {},
    onMoreActionsEnter: (String) -> Unit = {},
    otpSnapshotProvider: (String, Long) -> OtpDisplaySnapshot? = { _, _ -> null },
    contentTopPadding: Dp = 8.dp,
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val compactWindow = remember(context, configuration) {
        var hostContext = context
        while (hostContext is android.content.ContextWrapper && hostContext !is android.app.Activity) {
            hostContext = hostContext.baseContext
        }
        (hostContext as? android.app.Activity)?.isInMultiWindowMode == true
    }
    Box(modifier = Modifier.fillMaxSize()) {
        if (page.entries.isEmpty()) {
            EmptyState(typeFilter = page.typeFilter, totalEntries = page.totalEntries)
        } else {
            var activeLetter by remember(page.typeFilter) { mutableStateOf<Char?>(null) }
            Row(modifier = Modifier.fillMaxSize()) {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.vaultBackdropSource().weight(1f).fillMaxSize(),
                    contentPadding = PaddingValues(start = 16.dp, end = 8.dp, top = contentTopPadding, bottom = 92.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(
                        items = page.entries,
                        key = { it.id },
                        contentType = { it.secretType },
                    ) { entry ->
                        val leaked = !moreActionsMode && entry.id in page.leakedIds
                        val onClick = remember(entry.id) { { onOpen(entry) } }
                        val onEditCard = remember(entry.id) { { onEdit(entry) } }
                        val onDeleteCard = remember(entry.id) { { onDeleteRequest(entry) } }
                        EntryCard(
                            // 字母导航 scrollToItem 瞬时跳转时，卡片淡入淡出会造成满屏闪烁；
                            // 取消 fade，仅保留干脆的位置过渡，内容替换更安静。
                            modifier = Modifier.animateItem(
                                fadeInSpec = tween(0),
                                placementSpec = spring(stiffness = Spring.StiffnessHigh),
                                fadeOutSpec = tween(0),
                            ),
                            entry = entry,
                            onClick = onClick,
                            onEdit = onEditCard,
                            onDelete = onDeleteCard,
                            isKnownLeaked = leaked,
                            moreActionsMode = moreActionsMode,
                            isSelected = entry.id in selectedIds,
                            onToggleSelect = { onToggleSelect(entry.id) },
                            onMoreActionsEnter = { onMoreActionsEnter(entry.id) },
                            otpSnapshotProvider = otpSnapshotProvider,
                        )
                    }
                    item { Spacer(Modifier.size(80.dp)) }
                }
                Box(modifier = Modifier.fillMaxHeight().width(24.dp).padding(top = contentTopPadding, end = 4.dp)) {
                    androidx.compose.animation.AnimatedVisibility(
                        visible = showAlphabetSidebar,
                        enter = fadeIn(tween(80)),
                        exit = fadeOut(tween(60)),
                    ) {
                        AlphabetSidebar(
                            entries = page.entries,
                            leakedIds = page.leakedIds,
                            listState = listState,
                            activeLetter = activeLetter,
                            onActiveChange = { activeLetter = it },
                            // 正常窗口保留原有上下留白；小窗减少底部空白并缩小字号。
                            compactWindow = compactWindow,
                            modifier = Modifier.fillMaxSize().padding(bottom = if (compactWindow) 8.dp else 56.dp),
                        )
                    }
                }
            }
            activeLetter?.let { ch ->
                Box(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(76.dp)
                        .clip(VaultShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.7f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        ch.toString(),
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                }
            }
        }
    }
}

/** 右侧 A-Z-# 索引条：点击或拖动跳转到对应首字母的第一条（排除已泄露条目）。 */
@Composable
private fun AlphabetSidebar(
    entries: List<Entry>,
    leakedIds: Set<String> = emptySet(),
    listState: androidx.compose.foundation.lazy.LazyListState,
    activeLetter: Char?,
    onActiveChange: (Char?) -> Unit,
    compactWindow: Boolean = false,
    modifier: Modifier = Modifier,
) {
    val letters = remember { listOf('#') + ('A'..'Z').toList() }
    val firstIndexFor = remember(entries, leakedIds) {
        alphabetFirstIndices(entries, leakedIds)
    }
    val maxIndex = entries.size - 1
    val scope = rememberCoroutineScope()

    var heightPx by remember { mutableIntStateOf(0) }
    val sidebarDensity = LocalDensity.current
    val compactLetterSize = with(sidebarDensity) {
        androidx.compose.ui.unit.TextUnit(
            (heightPx / letters.size.toFloat() / density / fontScale).coerceIn(7f, 10f),
            androidx.compose.ui.unit.TextUnitType.Sp,
        )
    }
    fun letterAt(y: Float): Char? {
        if (heightPx == 0) return null
        val perItem = heightPx.toFloat() / letters.size
        val idx = (y / perItem).toInt().coerceIn(0, letters.size - 1)
        return letters[idx]
    }

    Column(
        modifier = modifier
            .onSizeChanged { heightPx = it.height }
            .pointerInput(firstIndexFor, listState, maxIndex) {
                detectTapGestures(
                    onPress = { offset ->
                        letterAt(offset.y)?.let { ch ->
                            onActiveChange(ch)
                            firstIndexFor[ch]?.let { idx ->
                                scope.launch { listState.scrollToItem(idx.coerceIn(0, maxIndex.coerceAtLeast(0))) }
                            }
                        }
                        tryAwaitRelease()
                        onActiveChange(null)
                    },
                )
            }
            .pointerInput(firstIndexFor, listState, maxIndex) {
                detectDragGestures(
                    onDragEnd = { onActiveChange(null) },
                    onDragCancel = { onActiveChange(null) },
                    onDrag = { change, _ ->
                        change.consume()
                        letterAt(change.position.y)?.let { ch ->
                            onActiveChange(ch)
                            firstIndexFor[ch]?.let { idx ->
                                scope.launch { listState.scrollToItem(idx.coerceIn(0, maxIndex.coerceAtLeast(0))) }
                            }
                        }
                    },
                )
            },
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        for (i in letters.indices) {
            val c = letters[i]
            val isActive = activeLetter == c
            val hasItems = c in firstIndexFor.keys
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    c.toString(),
                    fontSize = if (compactWindow) compactLetterSize else androidx.compose.ui.unit.TextUnit.Unspecified,
                    lineHeight = if (compactWindow) compactLetterSize else androidx.compose.ui.unit.TextUnit.Unspecified,
                    maxLines = 1,
                    softWrap = false,
                    style = if (isActive) MaterialTheme.typography.labelMedium else MaterialTheme.typography.labelSmall,
                    fontWeight = if (isActive) FontWeight.ExtraBold else FontWeight.Normal,
                    color = when {
                        isActive -> MaterialTheme.colorScheme.tertiary
                        hasItems -> MaterialTheme.colorScheme.primary.copy(alpha = 0.85f)
                        else -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.30f)
                    },
                )
            }
        }
    }
}

/**
 * 建立字母到 LazyColumn 实际位置的映射。
 *
 * 泄露条目可能因分类、标签或搜索过滤而不再连续，不能用“泄露数量”整体平移索引。
 * 这里保留原列表的真实下标，同时明确排除置顶的泄露项，保证每个字母都落到对应
 * 的普通条目上；若某字母只有泄露条目，则该字母显示为不可跳转。
 */
internal fun alphabetFirstIndices(
    entries: List<Entry>,
    leakedIds: Set<String>,
    letterOf: (Entry) -> Char = { it.firstLetter },
): Map<Char, Int> {
    val result = linkedMapOf<Char, Int>()
    // 已泄露条目归入 “#” 分组（置顶在列表最前），点击 # 定位到泄露区。
    if (entries.any { it.id in leakedIds }) result['#'] = 0
    entries.forEachIndexed { index, entry ->
        if (entry.id !in leakedIds) result.putIfAbsent(letterOf(entry), index)
    }
    return result
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun EntryCard(
    modifier: Modifier = Modifier,
    entry: Entry,
    onClick: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    isKnownLeaked: Boolean = false,
    moreActionsMode: Boolean = false,
    isSelected: Boolean = false,
    onToggleSelect: () -> Unit = {},
    onMoreActionsEnter: () -> Unit = {},
    showMoreActionsOption: Boolean = true,
    otpSnapshotProvider: (String, Long) -> OtpDisplaySnapshot? = { _, _ -> null },
) {
    val context = LocalContext.current
    val tint = TypeColors.of(entry.secretType)
    val expiryInfo = remember(entry, moreActionsMode) {
        if (moreActionsMode) ExpiryInfo(null, null) else entry.expiryInfo()
    }
    val expiry = expiryInfo.status
    val expiryStr = expiryInfo.dateStr
    val secret = remember(entry, moreActionsMode) {
        if (moreActionsMode) "" else entry.displaySecret
    }
    val otpSnapshot = remember(entry.id, entry.updatedAt) { mutableStateOf<OtpDisplaySnapshot?>(null) }
    LaunchedEffect(entry.id, entry.updatedAt, entry.secretType, moreActionsMode, otpSnapshotProvider) {
        if (entry.secretType != SecretType.OTP || moreActionsMode) {
            otpSnapshot.value = null
            return@LaunchedEffect
        }
        while (true) {
            val now = System.currentTimeMillis()
            otpSnapshot.value = otpSnapshotProvider(entry.id, now / 1000)
            delay(1000 - now % 1000)
        }
    }
    var isPressed by remember { mutableStateOf(false) }
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.97f else 1f,
        animationSpec = spring(dampingRatio = 0.7f),
        label = "cardScale",
    )
    var showMenu by remember { mutableStateOf(false) }
    var menuOffset by remember { mutableStateOf(IntOffset.Zero) }
    val cardContainerColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)
    } else {
        MaterialTheme.colorScheme.surface
    }
    val cardModifier = modifier
        .graphicsLayer { scaleX = scale; scaleY = scale }
        .fillMaxWidth()
        .then(
            if (moreActionsMode) {
                Modifier.vaultFrostedSurface(containerColor = cardContainerColor)
            } else {
                Modifier
            },
        )
    Card(
        shape = VaultShape,
        colors = CardDefaults.cardColors(
            containerColor = if (moreActionsMode) Color.Transparent else cardContainerColor,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = cardModifier,
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .pointerInput(moreActionsMode) {
                        detectTapGestures(
                            onPress = {
                                isPressed = true
                                tryAwaitRelease()
                                isPressed = false
                            },
                            onLongPress = { offset ->
                                isPressed = false
                                if (moreActionsMode) {
                                    onToggleSelect()
                                } else if (entry.secretType == SecretType.OTP) {
                                    otpSnapshot.value?.code?.takeIf(String::isNotBlank)?.let { code ->
                                        copySensitive(context, "动态码", code)
                                    }
                                } else {
                                    menuOffset = IntOffset(offset.x.toInt(), offset.y.toInt())
                                    showMenu = true
                                }
                            },
                            onTap = {
                                if (moreActionsMode) onToggleSelect()
                                else onClick()
                            },
                        )
                    }
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (moreActionsMode) {
                    Checkbox(
                        checked = isSelected,
                        onCheckedChange = { onToggleSelect() },
                        modifier = Modifier.padding(end = 8.dp),
                    )
                }
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(CircleShape)
                        .background(categoryIconBackground(entry.secretType).copy(alpha = 0.16f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(categoryIconRes(entry.secretType)),
                        contentDescription = null,
                        tint = Color.Unspecified,
                        modifier = Modifier.size(24.dp),
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            if (entry.title.isEmpty()) stringResource(R.string.general_remaining_untitled_entry) else entry.title,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        if (isKnownLeaked) {
                            Spacer(Modifier.width(6.dp))
                            LeakedBadge()
                        }
                        if (expiry != null) {
                            Spacer(Modifier.width(6.dp))
                            ExpiryBadge(expiry)
                        }
                    }
                    if (!moreActionsMode && entry.secretType == SecretType.OTP) {
                        OtpCardCode(otpSnapshot, tint, secret)
                    } else {
                        val secondary = listOfNotNull(
                            secret.takeIf { it.isNotEmpty() },
                            expiryStr?.let { stringResource(R.string.general_remaining_expiry_date, it) },
                        ).joinToString(" · ")
                        if (secondary.isNotEmpty()) {
                            Text(
                                secondary,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    if (!moreActionsMode && entry.tags.isNotEmpty()) {
                        Spacer(Modifier.size(2.dp))
                        Text(
                            entry.tags.joinToString("  "),
                            style = MaterialTheme.typography.labelSmall,
                            color = tint,
                        )
                    }
                }
            }
            if (!moreActionsMode && entry.secretType == SecretType.OTP) {
                OtpCardProgress(otpSnapshot)
            }
        }
        if (showMenu) {
            VaultHazePopup(
                onDismissRequest = { showMenu = false },
                offset = menuOffset,
                containerColor = popupMenuSurface(),
                minWidth = 64.dp,
            ) {
                if (entry.secretType != SecretType.PASSKEY) {
                    ContextMenuText(uiText("编辑")) {
                        showMenu = false
                        onEdit()
                    }
                }
                ContextMenuText(uiText("删除"), color = MaterialTheme.colorScheme.error) {
                    showMenu = false
                    onDelete()
                }
                if (showMoreActionsOption) {
                    ContextMenuText(uiText("更多操作")) {
                        showMenu = false
                        onMoreActionsEnter()
                    }
                }
            }
        }
    }
}

@Composable
private fun ContextMenuText(
    text: String,
    color: Color = MaterialTheme.colorScheme.onSurface,
    onClick: () -> Unit,
) {
    // 整行可点：行填满菜单宽度，后方空位也能触发
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(VaultShape)
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 10.dp),
    ) {
        Text(
            text,
            color = color,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

/** OTP 卡片内动态码展示：6 位数字，每秒刷新，monospace 字体 */
@Composable
private fun OtpCardCode(snapshot: androidx.compose.runtime.State<OtpDisplaySnapshot?>, tint: Color, fallbackSummary: String) {
    val current = snapshot.value
    if (current == null) {
        if (fallbackSummary.isNotEmpty()) {
            Spacer(Modifier.size(2.dp))
            Text(
                fallbackSummary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            )
        }
        return
    }
    val subtitle = listOfNotNull(
        current.issuer.takeIf { it.isNotEmpty() },
        current.label.takeIf { it.isNotEmpty() },
    ).joinToString(" · ")

    Spacer(Modifier.size(2.dp))
    Text(
        current.code,
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
        color = tint,
        maxLines = 1,
    )
    if (subtitle.isNotEmpty()) {
        Text(
            subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
        )
    }
}

/** OTP 卡片底部倒计时进度条 */
@Composable
private fun OtpCardProgress(snapshot: androidx.compose.runtime.State<OtpDisplaySnapshot?>) {
    val current = snapshot.value ?: return
    if (current.type != "totp") return

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 14.dp, end = 14.dp, bottom = 8.dp)
            .height(3.dp)
            .clip(RoundedCornerShape(2.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(current.progress)
                .fillMaxHeight()
                .clip(RoundedCornerShape(2.dp))
                .background(MaterialTheme.colorScheme.primary),
        )
    }
}

@Composable
private fun LeakedBadge() {
    Box(
        modifier = Modifier
            .clip(VaultShape)
            .background(MaterialTheme.colorScheme.error.copy(alpha = 0.16f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(uiText("已泄露"), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun ExpiryBadge(status: ExpiryStatus) {
    val (text, color) = when (status) {
        ExpiryStatus.EXPIRED -> "已过期" to MaterialTheme.colorScheme.error
        ExpiryStatus.EXPIRING_SOON -> "即将到期" to MaterialTheme.colorScheme.tertiary
    }
    Box(
        modifier = Modifier
            .clip(VaultShape)
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(uiText(text), color = color, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun EmptyState(typeFilter: String?, totalEntries: Int) {
    Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .clip(CircleShape)
                    .background(categoryIconBackground(typeFilter ?: SecretType.LOGIN).copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    painter = painterResource(categoryIconRes(typeFilter ?: SecretType.LOGIN)),
                    contentDescription = null,
                    tint = Color.Unspecified,
                    modifier = Modifier.size(36.dp),
                )
            }
            Spacer(Modifier.size(12.dp))
            val msg = when {
                totalEntries == 0 -> stringResource(R.string.general_remaining_empty_add_hint)
                typeFilter != null -> stringResource(R.string.general_remaining_empty_category)
                else -> stringResource(R.string.general_remaining_empty_search)
            }
            Text(msg, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

internal const val UNTAGGED_KEY = "__untagged__"

internal fun typeIcon(type: String): ImageVector = when (type) {
    SecretType.LOGIN -> Icons.Default.Key
    SecretType.CARD_DOCUMENT -> Icons.Default.CreditCard
    SecretType.WIFI -> Icons.Default.Wifi
    SecretType.API_KEY -> Icons.Default.Password
    SecretType.OTP -> OtpKeyIcon
    SecretType.SECURE_NOTE -> Icons.Default.Description
    SecretType.SERVER -> Icons.Default.Dns
    SecretType.CUSTOM -> Icons.Default.Widgets
    else -> Icons.Default.Key
}

private var _otpKeyIcon: ImageVector? = null

internal val OtpKeyIcon: ImageVector
    get() {
        _otpKeyIcon?.let { return it }
        return ImageVector.Builder(
            name = "OtpAuth",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).apply {
            path(fill = SolidColor(Color.Black)) {
                moveTo(3f, 3.5f)
                horizontalLineTo(21f)
                verticalLineTo(5.5f)
                horizontalLineTo(3f)
                close()
                moveTo(3f, 18.5f)
                horizontalLineTo(21f)
                verticalLineTo(20.5f)
                horizontalLineTo(3f)
                close()
                moveTo(6.5f, 10.5f)
                horizontalLineTo(10.5f)
                verticalLineTo(13.5f)
                horizontalLineTo(6.5f)
                close()
                moveTo(7.5f, 8.5f)
                horizontalLineTo(9.5f)
                verticalLineTo(15.5f)
                horizontalLineTo(7.5f)
                close()
                moveTo(13.5f, 10.5f)
                horizontalLineTo(17.5f)
                verticalLineTo(13.5f)
                horizontalLineTo(13.5f)
                close()
                moveTo(14.5f, 8.5f)
                horizontalLineTo(16.5f)
                verticalLineTo(15.5f)
                horizontalLineTo(14.5f)
                close()
            }
        }.build().also { _otpKeyIcon = it }
    }

@Composable
private fun MoreActionsBar(
    selectedCount: Int,
    allSelected: Boolean,
    canManageTags: Boolean,
    onDelete: () -> Unit,
    onToggleAll: () -> Unit,
    onTagMove: () -> Unit,
    onTagAdd: () -> Unit,
) {
    // 底部批量：全选|标签处理|删除 单容器；点“标签处理”后在其上方弹出 移入/添加标签 合并悬浮
    var tagMenuExpanded by remember { mutableStateOf(false) }
    LaunchedEffect(selectedCount, canManageTags) {
        if (selectedCount == 0 || !canManageTags) tagMenuExpanded = false
    }
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        AnimatedVisibility(
            visible = tagMenuExpanded,
            enter = fadeIn(tween(80)) + slideInVertically(tween(80)) { it / 2 },
            exit = fadeOut(tween(80)) + slideOutVertically(tween(80)) { it / 2 },
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                VaultFloatingBar(
                    // 标签操作菜单按文字内容自适应，避免套用底部操作条的屏幕比例宽度。
                    modifier = Modifier.wrapContentWidth(),
                    shape = VaultShape,
                    elevation = 8.dp,
                ) {
                    VaultButton(
                        onClick = {
                            tagMenuExpanded = false
                            onTagMove()
                        },
                        variant = VaultButtonVariant.TEXT,
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                    ) {
                        Text(uiText("移入标签"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                    }
                    MoreActionsDivider()
                    VaultButton(
                        onClick = {
                            tagMenuExpanded = false
                            onTagAdd()
                        },
                        variant = VaultButtonVariant.TEXT,
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                    ) {
                        Text(uiText("添加标签"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                    }
                }
                Spacer(Modifier.height(8.dp))
            }
        }
        // 全选 | 标签处理 | 删除 合并进同一悬浮容器，水平居中
        VaultFloatingBar(
            modifier = Modifier.vaultBottomActionWidth(),
            shape = VaultShape,
            elevation = 8.dp,
        ) {
            VaultButton(
                onClick = {
                    tagMenuExpanded = false
                    onToggleAll()
                },
                variant = VaultButtonVariant.TEXT,
                contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
            ) {
                Text(stringResource(if (allSelected) R.string.general_remaining_deselect_all else R.string.general_remaining_select_all), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            }
            MoreActionsDivider()
VaultButton(
                            onClick = { tagMenuExpanded = !tagMenuExpanded },
                            enabled = canManageTags && selectedCount > 0,
                            variant = VaultButtonVariant.TEXT,
                            disabledContainerColor = Color.Transparent,
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                        ) {
                Text(uiText("标签处理"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            }
            MoreActionsDivider()
VaultButton(
                        onClick = {
                            tagMenuExpanded = false
                            onDelete()
                        },
                        enabled = selectedCount > 0,
                        variant = VaultButtonVariant.TEXT,
                        contentColor = MaterialTheme.colorScheme.error,
                        disabledContainerColor = Color.Transparent,
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp),
                        minimalPress = false,
                    ) {
                Text(uiText("删除"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

/** 批量悬浮容器内的细分隔线。 */
@Composable
private fun MoreActionsDivider() {
    Box(
        Modifier
            .padding(vertical = 12.dp)
            .width(1.dp)
            .height(16.dp)
            .background(MaterialTheme.colorScheme.outlineVariant)
    )
}

@Composable
internal fun typeLabel(type: String): String = categoryLabel(type)
