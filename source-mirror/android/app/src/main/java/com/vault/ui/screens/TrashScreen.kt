package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vault.model.Entry
import com.vault.R
import com.vault.model.displaySecret
import com.vault.storage.TrashRetentionPref
import com.vault.ui.uiText
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.VaultFloatingBar
import com.vault.ui.vaultBottomActionWidth
import com.vault.ui.VaultShape

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(
    trash: List<Entry>,
    onRestore: (String) -> Unit,
    onRestoreMany: (Set<String>) -> Unit,
    onPurge: (String) -> Unit,
    onPurgeMany: (Set<String>) -> Unit,
    onPurgeAll: () -> Unit,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(0.dp),
    scrollToTopSignal: Int = 0,
) {
    val listState = rememberLazyListState()
    var confirmAll by remember { mutableStateOf(false) }
    var confirmAll2 by remember { mutableStateOf(false) }
    var confirmPurge by remember { mutableStateOf<Entry?>(null) }
    var confirmSelectedPurge by remember { mutableStateOf<Set<String>?>(null) }
    var selectedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var selectionActive by remember { mutableStateOf(false) }
    val selectionMode = selectedIds.isNotEmpty()
    val selectAllText = stringResource(R.string.settings_remaining_select_all)
    val deselectAllText = stringResource(R.string.settings_remaining_deselect_all)
    val untitledText = stringResource(R.string.settings_remaining_untitled)
    val restoreText = stringResource(R.string.settings_remaining_restore)
    val purgeText = stringResource(R.string.settings_remaining_purge)
    val cancelSelectionInteraction = remember { MutableInteractionSource() }

    fun toggleSelected(id: String) {
        if (id !in selectedIds && !selectionActive) selectionActive = true
        selectedIds = if (id in selectedIds) selectedIds - id else selectedIds + id
    }

    fun exitSelection() {
        selectionActive = false
        selectedIds = emptySet()
    }

    LaunchedEffect(trash) {
        if (trash.isEmpty()) {
            exitSelection()
        } else {
            val trashIds = trash.map { it.id }.toSet()
            selectedIds = selectedIds.filter { it in trashIds }.toSet()
        }
    }
    LaunchedEffect(scrollToTopSignal) {
        if (scrollToTopSignal > 0) listState.animateScrollToItem(0)
    }

    BackHandler(enabled = selectionActive) {
        exitSelection()
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            if (selectionMode || trash.isNotEmpty()) {
                if (selectionActive) {
                    // 顶部不用胶囊：直接 “✕ + 已选 N 条” 文本，与下方“共 N 条”同行高、同字号
                    // （固定 28.dp，✕ 用紧凑圆钮，不撑高顶栏）。
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(28.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(24.dp)
                                .clip(CircleShape)
                                .clickable(
                                    interactionSource = cancelSelectionInteraction,
                                    indication = null,
                                    onClick = { exitSelection() },
                                ),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(Icons.Default.Close, uiText("取消选择"), modifier = Modifier.size(14.dp))
                        }
                        Text(
                            uiText("已选 ${selectedIds.size} 条"),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(28.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            uiText("共 ${trash.size} 条"),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.surface
    ) { padding ->
        // 根内容：列表 + 底部悬浮覆盖层（不占 FAB 槽；居中基准=整屏宽，真·水平居中）
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            val retention by TrashRetentionPref.days
            if (trash.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(uiText("回收站为空"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.vaultBackdropSource().fillMaxSize(),
                    contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 140.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val retentionDays = retention
                    items(trash, key = { it.id }) { e ->
                        TrashEntryCard(
                            entry = e,
                            retentionDays = retentionDays,
                            selected = e.id in selectedIds,
                            selectionActive = selectionActive,
                            onToggleSelected = { toggleSelected(e.id) },
                            onRestore = { onRestore(e.id) },
                            onPurge = { confirmPurge = e },
                        )
                    }
                }
            }
            // 底部悬浮覆盖层：整屏宽内水平居中
            if (selectionActive) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, bottom = 28.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    // 全选/恢复/删除 合并进同一个悬浮容器，水平居中；高度与“清空回收站”对齐
                    VaultFloatingBar(
                        modifier = Modifier.vaultBottomActionWidth().heightIn(min = 48.dp),
                        rippleEnabled = true,
                        containerAlpha = 0.5f,
                    ) {
                        VaultButton(
                            onClick = {
                                selectedIds = if (selectedIds.size < trash.size) trash.map { it.id }.toSet() else emptySet()
                            },
                            variant = VaultButtonVariant.TEXT,
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
                            minimalPress = false,
                        ) {
                            Text(if (selectedIds.size < trash.size) selectAllText else deselectAllText, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                        }
                        MoreActionsDivider()
                        VaultButton(
                            onClick = {
                                val ids = selectedIds
                                selectedIds = emptySet()
                                exitSelection()
                                onRestoreMany(ids)
                            },
                            enabled = selectedIds.isNotEmpty(),
                            variant = VaultButtonVariant.TEXT,
                            disabledContainerColor = Color.Transparent,
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
                            minimalPress = false,
                        ) {
                            Text(uiText("恢复"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                        }
                        MoreActionsDivider()
                        VaultButton(
                            onClick = { confirmSelectedPurge = selectedIds },
                            enabled = selectedIds.isNotEmpty(),
                            variant = VaultButtonVariant.TEXT,
                            contentColor = MaterialTheme.colorScheme.error,
                            disabledContainerColor = Color.Transparent,
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
                            minimalPress = false,
                        ) {
                            Text(uiText("删除"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
            // 非批量时：清空回收站独立悬浮于列表顶层
            if (!selectionActive && trash.isNotEmpty()) {
                Box(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, bottom = 28.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    VaultFloatingBar(
                        onClick = { confirmAll = true },
                        modifier = Modifier.vaultBottomActionWidth(),
                        containerColor = popupMenuSurface(),
                        contentColor = MaterialTheme.colorScheme.error,
                        elevation = 8.dp,
                        rippleEnabled = true,
                        containerAlpha = 0.5f,
                    ) {
                        Icon(Icons.Filled.DeleteForever, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(uiText("清空回收站"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }

    if (confirmAll) VaultDialog(
        onDismissRequest = { confirmAll = false },
        title = { Text(uiText("清空回收站")) },
        text = { Text(uiText("将彻底删除全部 ${trash.size} 条，此操作不可恢复。")) },
        confirmButton = { VaultActionButton(onClick = { confirmAll = false; confirmAll2 = true }) { Text(uiText("下一步")) } },
        dismissButton = { VaultActionButton(onClick = { confirmAll = false }) { Text(uiText("取消")) } },
    )
    if (confirmAll2) VaultDialog(
        onDismissRequest = { confirmAll2 = false },
        title = { Text(uiText("再次确认清空")) },
        text = { Text(uiText("最后确认：这 ${trash.size} 条将无法找回。")) },
        confirmButton = {
            VaultActionButton(
                onClick = { confirmAll2 = false; onPurgeAll() },
                style = VaultActionStyle.DANGER,
            ) { Text(uiText("彻底清空")) }
        },
        dismissButton = { VaultActionButton(onClick = { confirmAll2 = false }) { Text(uiText("取消")) } },
    )

    confirmPurge?.let { e ->
        VaultDialog(
            onDismissRequest = { confirmPurge = null },
            title = { Text(uiText("彻底删除条目")) },
            text = { Text(stringResource(R.string.settings_remaining_purge_entry, e.title.ifEmpty { untitledText })) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        val id = e.id
                        confirmPurge = null
                        onPurge(id)
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("彻底删除")) }
            },
            dismissButton = { VaultActionButton(onClick = { confirmPurge = null }) { Text(uiText("取消")) } },
        )
    }

    confirmSelectedPurge?.let { ids ->
        VaultDialog(
            onDismissRequest = { confirmSelectedPurge = null },
            title = { Text(uiText("彻底删除所选条目")) },
            text = { Text(uiText("将彻底删除所选 ${ids.size} 条，此操作不可恢复。")) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        confirmSelectedPurge = null
                        selectedIds = emptySet()
                        onPurgeMany(ids)
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("彻底删除")) }
            },
            dismissButton = { VaultActionButton(onClick = { confirmSelectedPurge = null }) { Text(uiText("取消")) } },
        )
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun TrashEntryCard(
    entry: Entry,
    retentionDays: Int,
    selected: Boolean,
    selectionActive: Boolean,
    onToggleSelected: () -> Unit,
    onRestore: () -> Unit,
    onPurge: () -> Unit,
) {
    val untitledText = stringResource(R.string.settings_remaining_untitled)
    val restoreText = stringResource(R.string.settings_remaining_restore)
    val purgeText = stringResource(R.string.settings_remaining_purge)
    val tint = categoryIconBackground(entry.secretType)
    val cardInteraction = remember { MutableInteractionSource() }
    val isLight = MaterialTheme.colorScheme.background.luminance() > 0.5f
    Card(
        shape = VaultShape,
        colors = CardDefaults.cardColors(
            containerColor = when {
                selected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f)
                isLight -> Color(0xFFF3F3F3)
                else -> MaterialTheme.colorScheme.surfaceContainerHighest
            },
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                interactionSource = cardInteraction,
                indication = null,
                onClick = {
                    if (selectionActive) onToggleSelected()
                },
                onLongClick = {
                    if (!selectionActive) onToggleSelected()
                }
            )
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (selectionActive) {
                Checkbox(
                    checked = selected,
                    onCheckedChange = { onToggleSelected() },
                    modifier = Modifier.padding(end = 8.dp),
                )
            }
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(tint.copy(alpha = 0.14f)),
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
                Text(
                    entry.title.ifEmpty { untitledText },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
                entry.displaySecret.takeIf { it.isNotEmpty() }?.let { summary ->
                    Text(
                        summary,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    )
                }
                if (retentionDays > 0 && entry.deletedAt != null) {
                    val now = System.currentTimeMillis() / 1000.0
                    val remainSec = (entry.deletedAt + retentionDays * 86400.0 - now).toInt()
                    val remainText = when {
                        remainSec <= 0 -> stringResource(R.string.settings_remaining_auto_delete_soon)
                        remainSec < 86400 -> stringResource(R.string.settings_remaining_auto_delete_hours, remainSec / 3600)
                        else -> stringResource(R.string.settings_remaining_auto_delete_days, remainSec / 86400)
                    }
                    Text(
                        remainText,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        maxLines = 1,
                    )
                }
            }
            if (!selectionActive) {
                IconButton(onClick = onRestore) { Icon(Icons.Default.Restore, restoreText, tint = MaterialTheme.colorScheme.primary) }
                IconButton(onClick = onPurge) { Icon(Icons.Default.DeleteForever, purgeText, tint = MaterialTheme.colorScheme.error) }
            }
        }
    }
}

@Composable
private fun TrashTypeIcon(entry: Entry) {
    val tint = categoryIconBackground(entry.secretType)
    androidx.compose.foundation.layout.Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(tint.copy(alpha = 0.14f)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painter = painterResource(categoryIconRes(entry.secretType)),
            contentDescription = null,
            tint = Color.Unspecified,
            modifier = Modifier.size(24.dp),
        )
    }
}
