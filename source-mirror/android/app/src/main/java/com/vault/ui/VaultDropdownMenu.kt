package com.vault.ui

import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp

/** 保留原生菜单定位；在模糊之后绘制填充，避免底色被模糊层覆盖。 */
@Composable
internal fun VaultDropdownMenu(
    expanded: Boolean,
    alignRight: Boolean = false,
    onDismissRequest: () -> Unit,
    modifier: Modifier = Modifier,
    offset: DpOffset = DpOffset.Zero,
    scrollState: ScrollState = rememberScrollState(),
    containerColor: Color = MaterialTheme.colorScheme.surface,
    backdropEnabled: Boolean = true,
    containerAlpha: Float = 0.50f,
    content: @Composable ColumnScope.() -> Unit,
) {
    val sourceView = LocalView.current
    val gapPx = with(androidx.compose.ui.platform.LocalDensity.current) { 8.dp.roundToPx() }
    if (alignRight) {
        if (expanded) {
            androidx.compose.ui.window.Popup(
                popupPositionProvider = object : androidx.compose.ui.window.PopupPositionProvider {
                    override fun calculatePosition(
                        anchorBounds: androidx.compose.ui.unit.IntRect,
                        windowSize: androidx.compose.ui.unit.IntSize,
                        layoutDirection: androidx.compose.ui.unit.LayoutDirection,
                        popupContentSize: androidx.compose.ui.unit.IntSize,
                    ): androidx.compose.ui.unit.IntOffset = androidx.compose.ui.unit.IntOffset(
                        (anchorBounds.right - popupContentSize.width).coerceIn(0, (windowSize.width - popupContentSize.width).coerceAtLeast(0)),
                        // Keep a small breathing gap from the anchor control.
                        (anchorBounds.top - popupContentSize.height - gapPx).coerceIn(0, (windowSize.height - popupContentSize.height).coerceAtLeast(0)),
                    )
                },
                onDismissRequest = onDismissRequest,
                properties = androidx.compose.ui.window.PopupProperties(focusable = true),
            ) {
                androidx.compose.foundation.layout.Column(
                    modifier = Modifier.widthIn(max = 360.dp).then(modifier)
                        .width(androidx.compose.foundation.layout.IntrinsicSize.Max)
                        .widthIn(max = 360.dp)
                        .heightIn(max = 320.dp)
                        .vaultShadow(6.dp)
                        .vaultPopupBackdrop(sourceView)
                        .background(vaultFloatingSurfaceColor().copy(alpha = 0.50f), VaultShape)
                        .clip(VaultShape)
                        .vaultScrollHints({ scrollState.canScrollBackward }, { scrollState.canScrollForward })
                        // Match the regular dropdown's arrow breathing room at both ends.
                        .padding(vertical = 12.dp)
                        .verticalScroll(scrollState),
                    content = content,
                )
            }
        }
        return
    }
    DropdownMenu(
        expanded = expanded,
        onDismissRequest = onDismissRequest,
        modifier = Modifier.widthIn(max = 360.dp).then(modifier)
            .heightIn(max = 320.dp)
            .widthIn(max = 360.dp)
            .padding(8.dp)
            .vaultShadow(6.dp)
            .vaultPopupBackdrop(sourceView)
            .background(vaultFloatingSurfaceColor().copy(alpha = 0.50f), VaultShape)
            .clip(VaultShape)
            .vaultScrollHints({ scrollState.canScrollBackward }, { scrollState.canScrollForward }),
        offset = offset,
        scrollState = scrollState,
        shape = VaultShape,
        containerColor = Color.Transparent,
        tonalElevation = 0.dp,
        shadowElevation = 0.dp,
        content = content,
    )
}
