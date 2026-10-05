package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.WindowInsetsSides
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.ui.res.stringResource
import com.vault.R
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.HelpOutline
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.Card
import com.vault.ui.VaultDropdownMenu as DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vault.model.Entry
import com.vault.model.VaultOps
import com.vault.storage.AutoCompactPolicy
import com.vault.storage.TrashRetentionPref
import com.vault.ui.VaultViewModel
import com.vault.ui.uiText
import com.vault.ui.VaultFloatingBar
import com.vault.ui.vaultBottomActionWidth
import com.vault.ui.VaultShape
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

// ── 维护总览 ───────────────────────────────────────────────────
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MaintenanceOverviewScreen(
    vm: VaultViewModel,
    onOpenSection: (String) -> Unit,
    scrollToTopSignal: Int = 0,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val ctx = LocalContext.current
    val listState = rememberLazyListState()
    var expandedSection by remember { mutableStateOf<String?>(null) }
    var lastScrollSignal by remember { mutableIntStateOf(scrollToTopSignal) }
    LaunchedEffect(scrollToTopSignal) {
        if (scrollToTopSignal > lastScrollSignal) {
            expandedSection = null
            listState.animateScrollToItem(0)
        }
        lastScrollSignal = scrollToTopSignal
    }

    LazyColumn(
        state = listState,
        modifier = Modifier.vaultBackdropSource().fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 0.dp, bottom = 8.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Spacer(Modifier.height(8.dp)) }
        item {
            PageHeaderCard(
                title = stringResource(R.string.maintenance_title),
                subtitle = stringResource(R.string.maintenance_subtitle),
                icon = Icons.Default.Build,
            )
        }

        // 全部维护项合并为一张悬浮大卡，内部按功能区划分
        item(key = "maintenance") {
            Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.fillMaxWidth()) {
                    val dedupTitle = stringResource(R.string.dedup_title)
                    val sameServiceTitle = stringResource(R.string.same_service_title)
                    val retentionTitle = stringResource(R.string.trash_retention_title)
                    fun toggleSection(title: String) {
                        expandedSection = if (expandedSection == title) null else title
                    }
                    // 去重 / 同服务合并：右箭头导航，点击直接进入二级页操作，不做就地展开。
                    // 与下方手风琴同属单开：任一分区展开时导航行一并收起，只留当前展开分区。
                    AnimatedVisibility(
                        visible = expandedSection == null,
                        enter = fadeIn() + expandVertically(expandFrom = Alignment.Top),
                        exit = fadeOut() + shrinkVertically(shrinkTowards = Alignment.Top),
                    ) {
                        Column(Modifier.fillMaxWidth()) {
                            MaintenanceNavRow(
                                title = dedupTitle,
                                onClick = { onOpenSection("dedup") },
                            )
                            MaintenanceNavRow(
                                title = sameServiceTitle,
                                onClick = { onOpenSection("same_service") },
                            )
                        }
                    }

                    SettingsAccordion(
                        title = retentionTitle,
                        expanded = expandedSection == retentionTitle,
                        activeTitle = expandedSection,
                        onToggle = { toggleSection(retentionTitle) },
                    ) {
                        TrashRetentionContent(ctx = ctx)
                    }
                }
            }
        }
    }
}

/** 大卡内的导航行：整行点击进入二级页，右侧显示右键头。 */
@Composable
private fun MaintenanceNavRow(title: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(VaultShape)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.weight(1f),
        )
        Icon(
            Icons.Default.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
    }
}

// ── 回收站自动清理内容（内联） ────────────────────────────────

@Composable
private fun TrashRetentionContent(ctx: android.content.Context) {
    val days by TrashRetentionPref.days
    val label = when {
        days >= 365 -> stringResource(R.string.retention_year, days / 365)
        days >= 30 && days % 30 == 0 -> stringResource(R.string.retention_months, days / 30)
        days in 7..29 && days % 7 == 0 -> stringResource(R.string.retention_weeks, days / 7)
        else -> stringResource(R.string.retention_days, days)
    }
    Text(
        stringResource(R.string.retention_summary, label),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    VaultSlider(
        value = TrashRetentionPref.indexForDays(days).toFloat(),
        onValueChange = {
            TrashRetentionPref.setDays(ctx, TrashRetentionPref.daysForIndex(it.roundToInt()))
        },
        valueRange = 0f..(TrashRetentionPref.PRESET_DAYS.size - 1).toFloat(),
        steps = TrashRetentionPref.PRESET_DAYS.size - 2,
        modifier = Modifier.fillMaxWidth(),
    )
}

// ── 重复条目合并 ────────────────────────────────────────────────

private data class GroupedDupes(
    val samePw: List<List<Entry>>,
    val pwConflict: List<List<Entry>>,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MaintenanceDedupScreen(
    vm: VaultViewModel,
    onBack: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val groups = remember(state.payload) { vm.duplicateGroupsForMaintenance() }
    val grouped = remember(groups) {
        val samePw = mutableListOf<List<Entry>>()
        val conflict = mutableListOf<List<Entry>>()
        for (g in groups) {
            if (g.map { it.password }.toSet().size <= 1) samePw.add(g)
            else conflict.add(g)
        }
        GroupedDupes(samePw, conflict)
    }

    MaintenanceSubpageScaffold(
        title = stringResource(R.string.dedup_title),
        description = stringResource(R.string.dedup_sub_desc),
        onBack = onBack,
        bottomAction = {
            if (groups.isNotEmpty()) {
                VaultFloatingBar(
                    modifier = Modifier.vaultBottomActionWidth(),
                    onClick = {
                        vm.dedup { dupes -> dupes.maxByOrNull { it.updatedAt } }
                        onBack()
                    },
                    containerColor = popupMenuSurface(),
                    contentColor = MaterialTheme.colorScheme.primary,
                    contentPadding = PaddingValues(horizontal = 22.dp, vertical = 12.dp),
                ) {
                    Icon(Icons.Filled.Sync, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.merge_confirm),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
        },
    ) {
        LazyColumn(
            modifier = Modifier.vaultBackdropSource().fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 92.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (groups.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier.fillParentMaxSize().padding(32.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            stringResource(R.string.no_mergeable_dupes),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        )
                    }
                }
            } else {
                // 分区段：密码冲突在前（高优先级），完全一致在后
                if (grouped.pwConflict.isNotEmpty()) {
                    item(key = "header-conflict") {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                stringResource(R.string.pw_conflict),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.error,
                            )
                            Spacer(Modifier.width(8.dp))
                            Surface(
                                shape = VaultShape,
                                color = MaterialTheme.colorScheme.error.copy(alpha = 0.12f),
                            ) {
                                Text(
                                    stringResource(R.string.group_count, grouped.pwConflict.size),
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                    }
                    items(grouped.pwConflict, key = { "c-" + it.joinToString(":") { e -> e.id } }) { group ->
                        val winner = group.first()
                        Surface(
                            color = MaterialTheme.colorScheme.surface,
                            shape = VaultShape,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(winner.title.ifBlank { stringResource(R.string.unnamed_entry) }, fontWeight = FontWeight.SemiBold)
                                Text(
                                    stringResource(R.string.group_records_note, group.size),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                                group.forEachIndexed { index, entry ->
                                    Text(
                                        "${if (index == 0) stringResource(R.string.keep) else stringResource(R.string.merge)} · ${entry.username.ifBlank { stringResource(R.string.no_account) }} · ${formatEpoch(entry.updatedAt)}",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    val pkg = entry.targetApp.ifBlank { stringResource(R.string.no_target_app) }
                                    Text(
                                        stringResource(
                                            R.string.pkg_password_note,
                                            pkg,
                                            if (entry.password.isBlank()) {
                                                stringResource(R.string.pw_blank_short)
                                            } else {
                                                stringResource(R.string.password_set)
                                            },
                                        ),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                }
                if (grouped.samePw.isNotEmpty()) {
                    item(key = "header-same") {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                stringResource(R.string.identical),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.primary,
                            )
                            Spacer(Modifier.width(8.dp))
                            Surface(
                                shape = VaultShape,
                                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                            ) {
                                Text(
                                    stringResource(R.string.group_count, grouped.samePw.size),
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                        }
                    }
                    items(grouped.samePw, key = { "s-" + it.joinToString(":") { e -> e.id } }) { group ->
                        val winner = group.first()
                        Surface(
                            color = MaterialTheme.colorScheme.surface,
                            shape = VaultShape,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(winner.title.ifBlank { stringResource(R.string.unnamed_entry) }, fontWeight = FontWeight.SemiBold)
                                Text(
                                    stringResource(R.string.group_records_note, group.size),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                                group.forEachIndexed { index, entry ->
                                    Text(
                                        "${if (index == 0) stringResource(R.string.keep) else stringResource(R.string.merge)} · ${entry.username.ifBlank { stringResource(R.string.no_account) }} · ${formatEpoch(entry.updatedAt)}",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    val pkg = entry.targetApp.ifBlank { stringResource(R.string.no_target_app) }
                                    Text(
                                        stringResource(
                                            R.string.pkg_password_note,
                                            pkg,
                                            if (entry.password.isBlank()) {
                                                stringResource(R.string.pw_blank_short)
                                            } else {
                                                stringResource(R.string.password_set)
                                            },
                                        ),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
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

// ── 相同服务处理 ──────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MaintenanceSameServiceScreen(
    vm: VaultViewModel,
    onBack: () -> Unit,
    onEdit: (Entry) -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    var sameServiceSelectedIds by rememberSaveable { mutableStateOf<Set<String>>(emptySet()) }
    // 系统返回键：先清空选中，再退出，避免 rememberSaveable 在下次进入时恢复旧选中状态
    BackHandler {
        sameServiceSelectedIds = emptySet()
        onBack()
    }
    var showSameServiceMergeConfirm by remember { mutableStateOf(false) }
    var mergeResolveTitle by remember { mutableStateOf("") }
    var mergeResolvePassword by remember { mutableStateOf("") }
    var mergeResolveUsername by remember { mutableStateOf("") }
    var mergeTitleOptions by remember { mutableStateOf<List<String>>(emptyList()) }
    var mergePasswordOptions by remember { mutableStateOf<List<String>>(emptyList()) }
    var mergeUsernameOptions by remember { mutableStateOf<List<String>>(emptyList()) }

    val groups = remember(state.payload) { state.payload?.let { VaultOps.scanSameService(it) }.orEmpty() }
    val passwordBlankById = remember(groups, state.payload) {
        groups.asSequence()
            .flatMap { it.entries.asSequence() }
            .associate { entry -> entry.id to (vm.revealEntry(entry.id)?.password.isNullOrBlank()) }
    }

    fun mergeSelected() {
        val toMerge = groups.flatMap { it.entries }
            .filter { it.id in sameServiceSelectedIds }
            .mapNotNull { vm.revealEntry(it.id) }
        val titles = toMerge.map { it.title }.filter { it.isNotBlank() }.distinct()
        val passwords = toMerge.map { it.password }.filter { it.isNotBlank() }.distinct()
        val usernames = toMerge.map { it.username }.filter { it.isNotBlank() }.distinct()
        if (titles.size <= 1 && passwords.size <= 1 && usernames.size <= 1) {
            vm.mergeServiceEntries(
                sameServiceSelectedIds,
                titles.firstOrNull().orEmpty(),
                passwords.firstOrNull().orEmpty(),
                usernames.firstOrNull().orEmpty(),
            )
            sameServiceSelectedIds = emptySet()
        } else {
            mergeTitleOptions = titles
            mergePasswordOptions = passwords
            mergeUsernameOptions = usernames
            mergeResolveTitle = titles.firstOrNull().orEmpty()
            mergeResolvePassword = passwords.firstOrNull().orEmpty()
            mergeResolveUsername = usernames.firstOrNull().orEmpty()
            showSameServiceMergeConfirm = true
        }
    }

    MaintenanceSubpageScaffold(
        title = stringResource(R.string.same_service_title),
        description = stringResource(R.string.same_service_sub_desc),
        onBack = {
            sameServiceSelectedIds = emptySet()
            onBack()
        },
        bottomAction = {
                VaultFloatingBar(
                    modifier = Modifier.vaultBottomActionWidth(),
                    onClick = ::mergeSelected,
                    enabled = sameServiceSelectedIds.size >= 2,
                    containerColor = popupMenuSurface(),
                    contentColor = MaterialTheme.colorScheme.primary,
                    contentPadding = PaddingValues(horizontal = 22.dp, vertical = 12.dp),
                ) {
                    Icon(Icons.Filled.Sync, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.merge_selected_count, sameServiceSelectedIds.size),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
        },
    ) {
        LazyColumn(
            modifier = Modifier.vaultBackdropSource().fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 92.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (groups.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier.fillParentMaxSize().padding(32.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            stringResource(R.string.no_same_service),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        )
                    }
                }
            } else {
                groups.forEach { group ->
                    item(key = group.serviceKey) {
                    val groupIds = group.entries.mapTo(linkedSetOf()) { it.id }
                    val entireGroupSelected = groupIds.isNotEmpty() && groupIds.all { it in sameServiceSelectedIds }
                    Text(
                        group.serviceKey,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(VaultShape)
                            .clickable {
                                sameServiceSelectedIds = if (entireGroupSelected) emptySet() else groupIds
                            }
                            .padding(horizontal = 4.dp, vertical = 10.dp),
                    )
                    group.entries.forEach { entry ->
                        val isSelected = entry.id in sameServiceSelectedIds
                        Surface(
                            onClick = { vm.revealEntry(entry.id)?.let(onEdit) },
                            color = MaterialTheme.colorScheme.surface,
                            shape = VaultShape,
                            modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
                        ) {
                            Row(
                                Modifier.padding(start = 12.dp, end = 12.dp, top = 10.dp, bottom = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = { checked ->
                                        sameServiceSelectedIds = if (checked)
                                            sameServiceSelectedIds + entry.id
                                        else
                                            sameServiceSelectedIds - entry.id
                                    },
                                )
                                Spacer(Modifier.width(8.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(
                                        entry.title.ifBlank { stringResource(R.string.unnamed_entry) },
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Row {
                                        if (entry.username.isNotBlank()) {
                                            Text(
                                                entry.username,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                        if (passwordBlankById[entry.id] == true) {
                                            if (entry.username.isNotBlank()) {
                                                Text(
                                                    " · ${stringResource(R.string.password_empty)}",
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.error,
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
        }
    }
    }

    // 合并冲突确认弹窗
    if (showSameServiceMergeConfirm) {
        VaultDialog(
            onDismissRequest = { showSameServiceMergeConfirm = false },
            title = { Text(stringResource(R.string.merge_conflict_confirm)) },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        stringResource(R.string.merge_conflict_desc),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    DropdownField(
                        value = mergeResolveTitle,
                        options = mergeTitleOptions,
                        label = stringResource(R.string.merge_title_label),
                        onPick = { mergeResolveTitle = it },
                    )
                    DropdownField(
                        value = mergeResolveUsername,
                        options = mergeUsernameOptions,
                        label = stringResource(R.string.merge_username_label),
                        onPick = { mergeResolveUsername = it },
                    )
                    DropdownField(
                        value = mergeResolvePassword,
                        options = mergePasswordOptions,
                        label = stringResource(R.string.merge_password_label),
                        onPick = { mergeResolvePassword = it },
                    )
                }
            },
            confirmButton = {
                VaultActionButton(onClick = {
                    vm.mergeServiceEntries(sameServiceSelectedIds, mergeResolveTitle, mergeResolvePassword, mergeResolveUsername)
                    sameServiceSelectedIds = emptySet()
                    showSameServiceMergeConfirm = false
                }, style = VaultActionStyle.PRIMARY) { Text(stringResource(R.string.merge_confirm)) }
            },
            dismissButton = {
                VaultActionButton(onClick = { showSameServiceMergeConfirm = false }) { Text(stringResource(R.string.back_to_edit)) }
            },
        )
    }
}

/** 下拉选择器：只读 OutlinedTextField + 透明点击层 + DropdownMenu。 */
@Composable
private fun DropdownField(
    value: String,
    options: List<String>,
    label: String,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (options.size > 1) {
        var expanded by remember { mutableStateOf(false) }
        Box(modifier = modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = value,
                onValueChange = {},
                readOnly = true,
                label = { Text(label) },
                singleLine = true,
                trailingIcon = {
                    Icon(
                        if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = null,
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .clip(VaultShape)
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = LocalIndication.current,
                    ) { expanded = true },
            )
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                containerColor = popupMenuSurface(),
            ) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            onPick(option)
                            expanded = false
                        },
                        trailingIcon = if (option == value) {
                            { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                        } else null,
                    )
                }
            }
        }
    } else {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            singleLine = true,
            modifier = modifier.fillMaxWidth(),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MaintenanceSubpageScaffold(
    title: String,
    description: String,
    onBack: () -> Unit,
    bottomAction: @Composable BoxScope.() -> Unit = {},
    content: @Composable () -> Unit,
) {
    Scaffold(
        topBar = {
            VaultSubpageTopBar(
                title = title,
                onBack = onBack,
                backContentDescription = stringResource(R.string.back),
                actions = { MaintenanceHelpIcon(description) },
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        // 内容层 Box：滚动内容 + 底部动作悬浮覆盖（不占 FAB 槽，整屏居中）
        Box(Modifier.fillMaxSize().padding(padding)) {
            Column(Modifier.fillMaxSize()) {
                content()
            }
            Box(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = 28.dp),
                contentAlignment = Alignment.Center,
            ) {
                bottomAction()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MaintenanceHelpIcon(help: String, modifier: Modifier = Modifier) {
    val tooltipState = rememberTooltipState(isPersistent = true)
    val scope = rememberCoroutineScope()
    TooltipBox(
        positionProvider = TooltipDefaults.rememberPlainTooltipPositionProvider(),
        tooltip = {
            PlainTooltip(
                modifier = Modifier.semantics {
                    liveRegion = LiveRegionMode.Assertive
                    paneTitle = help
                },
            ) {
                Text(help)
            }
        },
        state = tooltipState,
        modifier = modifier,
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

// ── 工具函数 ───────────────────────────────────────────────────

private fun formatEpoch(epoch: Double): String = java.text.SimpleDateFormat(
    "yyyy-MM-dd HH:mm",
    java.util.Locale.getDefault(),
).format(java.util.Date((epoch * 1000).toLong()))

