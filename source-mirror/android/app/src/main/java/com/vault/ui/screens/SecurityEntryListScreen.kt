package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import com.vault.ui.vaultHorizontalScroll as horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsetsSides
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.ui.draw.clip
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.vault.R
import com.vault.ui.uiText
import com.vault.model.Entry
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.VaultFloatingBar
import com.vault.ui.VaultShape
import com.vault.ui.vaultShadow
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityEntryListScreen(
    label: String,
    description: String,
    recommendation: String? = null,
    entries: List<Entry>,
    issuesFor: (Entry) -> List<String>,
    onBack: () -> Unit,
    onOpen: (Entry) -> Unit,
    onEdit: (Entry) -> Unit,
    onDelete: (Entry) -> Unit,
    enableBatch: Boolean = true,
    duplicateGroupKeys: Map<String, String> = emptyMap(),
) {
    var deleteTarget by remember { mutableStateOf<Entry?>(null) }
    var deleteSelectedTarget by remember { mutableStateOf<Set<String>?>(null) }
    var selectedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var selectionActive by remember { mutableStateOf(false) }

    val batchEnabled = enableBatch

    fun toggleSelected(id: String) {
        if (!batchEnabled) return
        if (id !in selectedIds && !selectionActive) selectionActive = true
        selectedIds = if (id in selectedIds) selectedIds - id else selectedIds + id
    }

    var searchQuery by remember { mutableStateOf("") }
    val filteredEntries = remember(entries, searchQuery) {
        if (searchQuery.isBlank()) entries else entries.filter { entry ->
            entry.title?.contains(searchQuery, ignoreCase = true) == true
                || entry.url?.contains(searchQuery, ignoreCase = true) == true
                || entry.username?.contains(searchQuery, ignoreCase = true) == true
        }
    }

    fun exitSelection() {
        selectionActive = false
        selectedIds = emptySet()
    }

    BackHandler(enabled = selectionActive && batchEnabled) { exitSelection() }

    Scaffold(
        topBar = {
            VaultSubpageTopBar(
                title = label,
                onBack = onBack,
                // 与主页二级页（分类列表）同排版：数量换行显示，标题与数量同色
                subtitle = uiText("${entries.size} 条"),
                titleColor = MaterialTheme.colorScheme.onSurfaceVariant,
                actions = {
                    if (description.isNotBlank()) SecurityHelpIcon(description, recommendation)
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            BasicTextField(
                value = searchQuery,
                onValueChange = { searchQuery = com.vault.ui.InputFilters.capLength(it, 100) },
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
                            if (searchQuery.isEmpty()) {
                                Text(
                                    uiText("搜索条目"),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                )
                            }
                            innerTextField()
                        }
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Default.Close, contentDescription = uiText("清除"))
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            // 搜索框与列表之间预留安全留白，避免输入框贴住卡片列表。
            Spacer(Modifier.height(10.dp))
            val displayRows = remember(filteredEntries, duplicateGroupKeys) {
                val groups = linkedMapOf<String, MutableList<Entry>>()
                for (entry in filteredEntries) {
                    val key = duplicateGroupKeys[entry.id] ?: entry.id
                    groups.getOrPut(key) { mutableListOf() }.add(entry)
                }
                buildList {
                    groups.entries.forEachIndexed { gi, (_, groupEntries) ->
                        groupEntries.forEach { add(it) }
                        if (gi < groups.size - 1) {
                            add(Entry(id = "__divider__", secretType = ""))
                        }
                    }
                }
            }

            LazyColumn(
                modifier = Modifier.vaultBackdropSource().fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 92.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (entries.isEmpty()) {
                    item(contentType = "empty") {
                        Box(
                            modifier = Modifier.fillParentMaxSize().padding(32.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                uiText("没有符合\u201c$label\u201d的条目"),
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = TextAlign.Center,
                            )
                        }
                    }
                } else {
                    items(
                        displayRows,
                        key = {
                            if (it.id == "__divider__") "div:${System.identityHashCode(it)}" else it.id
                        },
                    ) { entry ->
                        if (entry.id == "__divider__") {
                            HorizontalDivider(
                                modifier = Modifier.padding(vertical = 4.dp),
                                color = MaterialTheme.colorScheme.primary,
                            )
                        } else {
                            val realEntry = entry
                            Column {
                                EntryCard(
                                    entry = realEntry,
                                    onClick = { onOpen(realEntry) },
                                    onEdit = { onEdit(realEntry) },
                                    onDelete = { deleteTarget = realEntry },
                                    isKnownLeaked = false,
                                    moreActionsMode = selectionActive && batchEnabled,
                                    isSelected = realEntry.id in selectedIds && batchEnabled,
                                    onToggleSelect = { if (batchEnabled) toggleSelected(realEntry.id) },
                                    onMoreActionsEnter = {
                                        if (batchEnabled) {
                                            selectionActive = true
                                            selectedIds = setOf(realEntry.id)
                                        }
                                    },
                                    showMoreActionsOption = false,
                                )
                                val issues = issuesFor(realEntry)
                                if (issues.isNotEmpty() && !selectionActive) {
                                    Spacer(Modifier.height(4.dp))
                                    Row(
                                        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                                    ) {
                                        issues.forEach { issue ->
                                            Text(
                                                uiText(issue),
                                                style = MaterialTheme.typography.labelSmall,
                                                color = MaterialTheme.colorScheme.error,
                                                modifier = Modifier
                                                    .background(MaterialTheme.colorScheme.error.copy(alpha = 0.09f), VaultShape)
                                                    .padding(horizontal = 5.dp, vertical = 2.dp),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (entries.isNotEmpty() && searchQuery.isNotBlank() && filteredEntries.isEmpty()) {
                    item(contentType = "search-empty") {
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 32.dp),
                            horizontalArrangement = Arrangement.Center,
                        ) {
                            Text(uiText("没有匹配的条目"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }

    deleteTarget?.let { entry ->
        VaultDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(uiText("移入回收站")) },
            text = { Text(stringResource(R.string.general_remaining_move_to_trash_confirm, if (entry.title.isBlank()) stringResource(R.string.general_remaining_untitled_entry) else entry.title)) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                    deleteTarget = null
                    onDelete(entry)
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("删除")) }
            },
            dismissButton = {
                VaultActionButton(onClick = { deleteTarget = null }) { Text(uiText("取消")) }
            },
        )
    }

    deleteSelectedTarget?.let { ids ->
        VaultDialog(
            onDismissRequest = { deleteSelectedTarget = null },
            title = { Text(uiText("批量移入回收站")) },
            text = { Text(uiText("确定将所选 ${ids.size} 条移入回收站吗？")) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                    deleteSelectedTarget = null
                    selectedIds = emptySet()
                    ids.forEach { id -> entries.find { it.id == id }?.let(onDelete) }
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("删除")) }
            },
            dismissButton = {
                VaultActionButton(onClick = { deleteSelectedTarget = null }) { Text(uiText("取消")) }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SecurityHelpIcon(description: String, recommendation: String?) {
    val helpText = if (recommendation.isNullOrBlank()) {
        uiText(description)
    } else {
        "${uiText("建议改进")}：${uiText(recommendation)}\n${uiText(description)}"
    }
    val tooltipState = rememberTooltipState(isPersistent = true)
    val scope = rememberCoroutineScope()
    TooltipBox(
        positionProvider = TooltipDefaults.rememberPlainTooltipPositionProvider(),
        tooltip = {
            PlainTooltip(
                modifier = Modifier.semantics {
                    liveRegion = LiveRegionMode.Assertive
                    paneTitle = helpText
                },
            ) {
                Text(helpText)
            }
        },
        state = tooltipState,
    ) {
        // 顶栏 actions 里必须用 IconButton：48dp 触达区自带右侧安全边距，
        // 裸 16dp Icon 会贴着屏幕右边缘，点击热区也远小于 48dp。
        IconButton(onClick = { scope.launch { tooltipState.show() } }) {
            Icon(
                Icons.AutoMirrored.Outlined.HelpOutline,
                contentDescription = uiText("帮助"),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}
