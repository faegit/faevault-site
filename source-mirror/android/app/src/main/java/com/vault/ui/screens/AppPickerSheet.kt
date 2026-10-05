package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import com.vault.ui.uiText
import com.vault.R

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.drawable.Drawable
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.width
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.vault.ui.VaultShape
import com.vault.ui.VaultTopShape

data class AppInfo(
    val label: String,
    val packageName: String,
    val icon: Drawable?,
)

data class VaultPickerRow(
    val id: String,
    val title: String,
    val subtitle: String = "",
    val selected: Boolean = false,
    val categoryType: String? = null,
)

/** 与关联程序选择器共用同一底部选择页视觉和列表交互。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultPickerSheet(
    title: String,
    rows: List<VaultPickerRow>,
    onDismiss: () -> Unit,
    onSelect: (VaultPickerRow) -> Unit,
    onBack: (() -> Unit)? = null,
    searchPlaceholder: String = uiText("搜索"),
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var query by remember(title) { mutableStateOf("") }
    val filtered = remember(query, rows) {
        if (query.isBlank()) rows else rows.filter {
            it.title.contains(query, ignoreCase = true) ||
                it.subtitle.contains(query, ignoreCase = true)
        }
    }
    com.vault.ui.VaultModalBackdrop()
    // 卡片底色必须由 containerColor 提供：ModalBottomSheet 的 modifier 挂在
    // draggableAnchors 上，该节点尺寸是卡片尺寸但位于屏幕顶部，而内容被 place 到偏移处，
    // 于是在 modifier 上画 background/clip 会画到屏幕顶部的另一块矩形（顶部白块、底部缺失）。
    ModalBottomSheet(
        scrimColor = androidx.compose.ui.graphics.Color.Transparent,
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = VaultTopShape,
        containerColor = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp).padding(bottom = 16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (onBack != null) {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, uiText("返回"))
                    }
                    Spacer(Modifier.width(4.dp))
                }
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text(searchPlaceholder) },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                singleLine = true,
                shape = VaultShape,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            if (filtered.isEmpty()) {
                EmptyState(text = uiText("没有匹配内容"))
            } else {
                Surface(
                    shape = VaultShape,
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                    modifier = Modifier.fillMaxWidth().height(520.dp),
                ) {
                    LazyColumn(Modifier.fillMaxSize()) {
                        items(filtered, key = VaultPickerRow::id) { row ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable { onSelect(row) }
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                            ) {
                                Box(
                                    modifier = Modifier.size(44.dp).clip(VaultShape)
                                        .background(MaterialTheme.colorScheme.surface),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    if (row.categoryType != null) {
                                        Icon(
                                            painter = painterResource(categoryIconRes(row.categoryType)),
                                            contentDescription = null,
                                            tint = Color.Unspecified,
                                            modifier = Modifier.size(40.dp),
                                        )
                                    } else {
                                        Icon(Icons.Default.Link, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                }
                                Spacer(Modifier.width(14.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(row.title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    if (row.subtitle.isNotBlank()) {
                                        Spacer(Modifier.height(2.dp))
                                        Text(row.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    }
                                }
                                Spacer(Modifier.width(8.dp))
                                if (row.selected) {
                                    Box(Modifier.size(10.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
                                } else {
                                    Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f), modifier = Modifier.size(20.dp))
                                }
                            }
                            HorizontalDivider(
                                modifier = Modifier.padding(start = 72.dp, end = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun loadApps(pm: PackageManager): List<AppInfo> {
    // 调用 getInstalledApplications 会触发国产 ROM 的"获取应用列表"运行时弹窗。
    // 用户拒绝时返回的只是自身 + 系统白名单（很少几个），不会抛异常。
    val raw = try {
        @Suppress("DEPRECATION")
        pm.getInstalledApplications(PackageManager.GET_META_DATA)
    } catch (_: Exception) {
        emptyList()
    }
    return raw.mapNotNull { ai: ApplicationInfo ->
        val launchable = pm.getLaunchIntentForPackage(ai.packageName) != null
        val isUserApp = (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0
        if (!launchable && !isUserApp) return@mapNotNull null
        val label = pm.getApplicationLabel(ai).toString()
        if (label.isBlank() || ai.packageName.isBlank()) null
        else AppInfo(
            label = label,
            packageName = ai.packageName,
            icon = try { pm.getApplicationIcon(ai) } catch (_: Exception) { null },
        )
    }
        .distinctBy { it.packageName }
        .sortedBy { it.label }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPickerSheet(
    onDismiss: () -> Unit,
    onAppSelected: (label: String, packageName: String) -> Unit,
) {
    val ctx = LocalContext.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()

    var apps by remember { mutableStateOf<List<AppInfo>?>(null) }

    // 国产 ROM 的"读取应用列表"确认是异步的：调用立即返回精简列表，用户随后才点允许。
    // 策略：
    //  1) ON_RESUME 时拉一次（覆盖大多数情况：弹窗作为独立窗口、从设置返回）；
    //  2) 若结果像被拒，再延迟轮询数次（兜底部分 ROM 用 overlay 弹窗不触发生命周期）。
    fun applyIfBetter(fresh: List<AppInfo>) {
        val prev = apps
        if (prev == null || fresh.size > prev.size) apps = fresh
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                scope.launch {
                    val fresh = withContext(Dispatchers.IO) { loadApps(ctx.packageManager) }
                    applyIfBetter(fresh)
                }
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // 看起来被拒（结果过少）时短延迟轮询，等用户在 ROM 弹窗里点"允许"
    LaunchedEffect(apps) {
        val current = apps ?: return@LaunchedEffect
        if (current.size > 5) return@LaunchedEffect
        repeat(10) {                                        // 最多 ~10 秒
            delay(1000L)
            val fresh = withContext(Dispatchers.IO) { loadApps(ctx.packageManager) }
            if (fresh.size > (apps?.size ?: 0)) {
                apps = fresh
                return@LaunchedEffect
            }
        }
    }

    var query by remember { mutableStateOf("") }
    val filtered = remember(query, apps) {
        val list = apps ?: emptyList()
        if (query.isBlank()) list
        else list.filter {
            it.label.contains(query, ignoreCase = true) ||
                it.packageName.contains(query, ignoreCase = true)
        }
    }
    // 经验阈值：被国产 ROM 拒绝后通常只剩 1~3 项
    val likelyDenied = apps != null && apps!!.size <= 5

    com.vault.ui.VaultModalBackdrop()

    ModalBottomSheet(
        scrimColor = androidx.compose.ui.graphics.Color.Transparent,
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = VaultTopShape,
        containerColor = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 16.dp),
        ) {
            Text(
                text = stringResource(R.string.media_select_app),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.padding(bottom = 12.dp),
            )

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text(uiText("搜索应用名或包名")) },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                singleLine = true,
                shape = VaultShape,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(12.dp))

            when {
                apps == null -> {
                    LoadingState()
                }
                likelyDenied -> {
                    PermissionDeniedState(onOpenSettings = {
                        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                            .setData(Uri.fromParts("package", ctx.packageName, null))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        try { ctx.startActivity(intent) } catch (_: Exception) {}
                    })
                }
                filtered.isEmpty() -> {
                    EmptyState(text = stringResource(R.string.media_no_match))
                }
                else -> {
                    Surface(
                        shape = VaultShape,
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(520.dp),
                    ) {
                        LazyColumn(modifier = Modifier.vaultBackdropSource().fillMaxSize()) {
                            items(filtered, key = { it.packageName }) { app ->
                                AppRow(app = app, onClick = {
                                    onAppSelected(app.label, app.packageName)
                                })
                                HorizontalDivider(
                                    modifier = Modifier.padding(start = 72.dp, end = 16.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppRow(app: AppInfo, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clip(VaultShape)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        AppIcon(app.icon)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = app.label,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = app.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Spacer(Modifier.width(8.dp))
        Icon(
            Icons.AutoMirrored.Filled.KeyboardArrowRight,
            null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
            modifier = Modifier.size(20.dp),
        )
    }
}

@Composable
private fun AppIcon(drawable: Drawable?) {
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(VaultShape)
            .background(MaterialTheme.colorScheme.surface),
        contentAlignment = Alignment.Center,
    ) {
        if (drawable != null) {
            val bitmap = remember(drawable) {
                val w = drawable.intrinsicWidth.coerceIn(1, 128)
                val h = drawable.intrinsicHeight.coerceIn(1, 128)
                Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { output ->
                    val canvas = android.graphics.Canvas(output)
                    drawable.setBounds(0, 0, w, h)
                    drawable.draw(canvas)
                }
            }
            Icon(
                painter = BitmapPainter(bitmap.asImageBitmap()),
                contentDescription = null,
                tint = androidx.compose.ui.graphics.Color.Unspecified,
                modifier = Modifier.size(40.dp),
            )
        } else {
            Icon(Icons.Default.Apps, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun LoadingState() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(360.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            uiText("加载中…"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun EmptyState(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(360.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun PermissionDeniedState(onOpenSettings: () -> Unit) {
    Surface(
        shape = VaultShape,
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 320.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(64.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.errorContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Default.Apps,
                    null,
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.size(32.dp),
                )
            }
            Spacer(Modifier.height(16.dp))
            Text(
                uiText("未获取到应用列表"),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                uiText("可能系统拒绝了 \"读取应用列表\" 权限。\n请到应用权限设置中开启。"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
            Spacer(Modifier.height(20.dp))
            VaultActionButton(
                onClick = onOpenSettings,
                shape = VaultShape,
                style = VaultActionStyle.PRIMARY,
            ) {
                Icon(Icons.Default.Settings, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(uiText("去设置开启"))
            }
        }
    }
}
