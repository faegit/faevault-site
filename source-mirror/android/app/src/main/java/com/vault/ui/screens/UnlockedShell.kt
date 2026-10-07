package com.vault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.layout.offset
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.TopAppBarDefaults
import com.vault.ui.vaultBackdropSource
import com.vault.ui.vaultEdgeBounce
import com.vault.ui.vaultBackdrop
import com.vault.ui.vaultShadow
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.math.abs
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import com.vault.R
import kotlinx.coroutines.flow.distinctUntilChanged

enum class RootPage(val labelRes: Int) {
    HOME(R.string.nav_home), MAINTENANCE(R.string.nav_maintenance), SECURITY(R.string.nav_security),
    SYNC(R.string.nav_sync), SETTINGS(R.string.nav_settings),
}

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun UnlockedShell(
    selectedPage: Int,
    trashCount: Int,
    onSelectedPageChanged: (Int) -> Unit,
    onNavigationClick: (RootPage) -> Unit,
    onReselect: (RootPage) -> Unit,
    onTrashClick: () -> Unit,
    onLock: () -> Unit,
    home: @Composable () -> Unit,
    maintenance: @Composable () -> Unit,
    security: @Composable () -> Unit,
    sync: @Composable () -> Unit,
    settings: @Composable () -> Unit,
) {
    val pages = RootPage.entries
    val pagerState = rememberPagerState(initialPage = selectedPage.coerceIn(pages.indices), pageCount = { pages.size })
    val context = LocalContext.current
    // 键盘弹出时隐藏底部导航栏，避免在键盘上方露出白色色块
    val imeVisible = WindowInsets.isImeVisible

    LaunchedEffect(selectedPage) {
        val target = selectedPage.coerceIn(pages.indices)
        // 点击底部导航直接跳到目标页（瞬时 snap），不经过中间页动画：
        // 快速连点/跨页切换时不再依次组合中间页面，避免整页重排导致掉帧。
        if (pagerState.currentPage != target) pagerState.scrollToPage(target)
    }
    LaunchedEffect(pagerState) {
        snapshotFlow { pagerState.settledPage }
            .distinctUntilChanged()
            .collect(onSelectedPageChanged)
    }

    Scaffold(
        topBar = {
            androidx.compose.material3.CenterAlignedTopAppBar(
                title = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            stringResource(pages[pagerState.currentPage].labelRes),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                },
                navigationIcon = {
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .clickable(
                                interactionSource = remember { MutableInteractionSource() },
                                indication = null,
                                onClick = onTrashClick,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        BadgedBox(
                            badge = {
                                if (trashCount > 0) {
                                    Badge(modifier = Modifier.offset(x = 5.dp, y = (-4).dp).widthIn(min = 16.dp)) {
                                        Text(
                                            if (trashCount > 99) "99+" else trashCount.toString(),
                                            style = MaterialTheme.typography.labelSmall,
                                        )
                                    }
                                }
                            },
                        ) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = stringResource(R.string.nav_trash),
                                modifier = Modifier.size(20.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = onLock) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = stringResource(R.string.lock),
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                )
            )
        },
        bottomBar = {
            if (!imeVisible) {
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    tonalElevation = 0.dp,
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            // safeDrawing 同时覆盖手势导航、小白条和自由窗口的系统保留区。
                            // inset 放在固定内容高度之外，导航项本身始终保持 56dp，不会压进系统区域。
                            .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Bottom))
                            .height(56.dp),
                    ) {
                    pages.forEach { page ->
                        val index = page.ordinal
                        val selected = pagerState.currentPage == index
                        val interactionSource = remember { MutableInteractionSource() }
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxSize()
                                .padding(bottom = 8.dp)
                                .selectable(
                                    selected = selected,
                                    interactionSource = interactionSource,
                                    indication = null,
                                    role = Role.Tab,
                                    onClick = {
                                        onNavigationClick(page)
                                        if (pagerState.currentPage == index) onReselect(page)
                                        else onSelectedPageChanged(index)
                                    },
                                ),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Bottom,
                        ) {
                            val icon: ImageVector = when (page) {
                                RootPage.HOME -> Icons.Default.Home
                                RootPage.MAINTENANCE -> Icons.Default.FolderOpen
                                RootPage.SECURITY -> Icons.Default.Security
                                RootPage.SYNC -> Icons.Default.Sync
                                RootPage.SETTINGS -> Icons.Default.Settings
                            }
                            // 导航仅通过图标和文字选中色反馈，不绘制涟漪。
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(percent = 50))
                                    .padding(horizontal = 22.dp, vertical = 4.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    icon,
                                    contentDescription = stringResource(page.labelRes),
                                    modifier = Modifier.size(20.dp),
                                    tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            Spacer(Modifier.height(2.dp))
                            Text(
                                stringResource(page.labelRes),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                    }
                }
            }
        },
    ) { padding ->
    Box(Modifier.fillMaxSize()) {
        HorizontalPager(
            state = pagerState,
            modifier = Modifier
                .fillMaxSize()
                // 首/末页继续横向拖动时给边缘回弹，而不是硬停。
                // 用项目自建的 vaultEdgeBounce：只做视觉位移、不消费事件，
                // 因此不影响正常翻页；也没有启用平台 stretch（Theme 里全局关掉了它，
                // 因为平台版本会吃掉下一次拖动）。
                .vaultEdgeBounce(horizontal = true),
            contentPadding = padding,
            // 允许左右滑动切换页面，配合底部导航
            userScrollEnabled = true,
        ) { page ->
            when (pages[page]) {
                RootPage.HOME -> home()
                RootPage.MAINTENANCE -> maintenance()
                RootPage.SECURITY -> security()
                RootPage.SYNC -> sync()
                RootPage.SETTINGS -> settings()
            }
        }
    }
    }
}
