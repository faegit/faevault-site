package com.vault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.vault.R
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.uiText
import com.vault.ui.vaultShadow
import com.vault.ui.VaultShape

/**
 * 二级页统一标题栏：返回箭头 + 居中标题。
 * [subtitle] 非空时换行显示在标题下方（如列表页的「N 条」），与标题各自居中；
 * [titleColor] 留空沿用标题栏默认内容色，列表页传 onSurfaceVariant 与副标题同色。
 * 帮助气泡等尾随图标请放 [actions]：与标题同排会让标题文字偏离中轴，无法与副标题对齐。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun VaultSubpageTopBar(
    title: String,
    onBack: (() -> Unit)?,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    titleColor: Color = Color.Unspecified,
    backContentDescription: String = uiText("返回"),
    actions: @Composable RowScope.() -> Unit = {},
) {
    CenterAlignedTopAppBar(
        modifier = modifier,
        title = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = titleColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (subtitle != null) {
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        },
        navigationIcon = {
            if (onBack != null) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = backContentDescription)
                }
            }
        },
        actions = actions,
        // 顶栏用 background，滚动态用 surface，与主页/安全页二级页保持一致
        colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
            containerColor = MaterialTheme.colorScheme.background,
            scrolledContainerColor = MaterialTheme.colorScheme.surface,
        ),
    )
}

enum class VaultActionStyle {
    NEUTRAL,
    PRIMARY,
    DANGER,
}

/** 下拉菜单与批量悬浮操作条共用中性填充色；透明度由 VaultDropdownMenu 固定为 72%。 */
@Composable
internal fun popupMenuSurface(): Color =
    if (MaterialTheme.colorScheme.background.luminance() < 0.5f) {
        MaterialTheme.colorScheme.surfaceContainerHighest
    } else {
        Color(0xFFE5E5E5)
    }

@Composable
internal fun VaultVisibilityButton(
    visible: Boolean,
    onClick: () -> Unit,
    enabled: Boolean = true,
) {
    IconButton(onClick = onClick, enabled = enabled, modifier = Modifier.size(40.dp)) {
        Icon(
            painter = painterResource(
                if (visible) R.drawable.ic_action_eye_off_custom
                else R.drawable.ic_action_eye_custom,
            ),
            contentDescription = stringResource(if (visible) R.string.general_remaining_hide else R.string.general_remaining_show),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp),
        )
    }
}

@Composable
internal fun VaultActionButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    style: VaultActionStyle = VaultActionStyle.NEUTRAL,
    shape: Shape = VaultShape,
    contentPadding: PaddingValues = ButtonDefaults.ContentPadding,
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    disabledContainerColor: Color? = null,
    content: @Composable RowScope.() -> Unit,
) {
    VaultButton(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        variant = when (style) {
            VaultActionStyle.NEUTRAL -> VaultButtonVariant.NEUTRAL
            VaultActionStyle.PRIMARY -> VaultButtonVariant.PRIMARY
            VaultActionStyle.DANGER -> VaultButtonVariant.DANGER
        },
        shape = shape,
        contentPadding = contentPadding,
        interactionSource = interactionSource,
        disabledContainerColor = disabledContainerColor,
        content = content,
    )
}

@Composable
internal fun PageHeaderCard(
    title: String,
    subtitle: String,
    icon: ImageVector,
    accent: Color = MaterialTheme.colorScheme.primary,
    containerColor: Color = MaterialTheme.colorScheme.primaryContainer,
    contentColor: Color = MaterialTheme.colorScheme.onPrimaryContainer,
) {
    Surface(
        color = containerColor,
        contentColor = contentColor,
        shape = VaultShape,
        shadowElevation = 0.dp,
        modifier = Modifier.fillMaxWidth().vaultShadow(8.dp),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Surface(
                color = accent,
                contentColor = Color.White,
                shape = VaultShape,
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    modifier = Modifier.padding(10.dp).size(24.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(uiText(title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    uiText(subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = contentColor.copy(alpha = 0.78f),
                )
            }
        }
    }
}

@Composable
internal fun VaultEditorField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    enabled: Boolean = true,
    readOnly: Boolean = false,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    trailingIcon: (@Composable () -> Unit)? = null,
    keepContainerColorOnFocus: Boolean = false,
    containerColorOverride: Color? = null,
) {
    val lightTheme = MaterialTheme.colorScheme.background.luminance() > 0.5f
    val unfocusedContainerColor = containerColorOverride ?:
        if (lightTheme) MaterialTheme.colorScheme.surface
        else MaterialTheme.colorScheme.surfaceContainerHigh
    TextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        enabled = enabled,
        readOnly = readOnly,
        label = { Text(uiText(label), style = MaterialTheme.typography.labelMedium) },
        placeholder = placeholder?.let { text ->
            { Text(uiText(text), color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.58f)) }
        },
        singleLine = singleLine,
        minLines = minLines,
        visualTransformation = visualTransformation,
        keyboardOptions = keyboardOptions,
        trailingIcon = trailingIcon,
        shape = VaultShape,
        colors = TextFieldDefaults.colors(
            focusedContainerColor = containerColorOverride ?:
                if (keepContainerColorOnFocus) unfocusedContainerColor
                else if (lightTheme) MaterialTheme.colorScheme.surface
                else MaterialTheme.colorScheme.surfaceContainerHighest,
            unfocusedContainerColor = unfocusedContainerColor,
            disabledContainerColor = unfocusedContainerColor,
            focusedIndicatorColor = Color.Transparent,
            unfocusedIndicatorColor = Color.Transparent,
            disabledIndicatorColor = Color.Transparent,
            errorIndicatorColor = MaterialTheme.colorScheme.error,
            disabledTextColor = MaterialTheme.colorScheme.onSurface,
            disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
        ),
    )
}

@Composable
internal fun VaultEditorField(
    value: TextFieldValue,
    onValueChange: (TextFieldValue) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    enabled: Boolean = true,
    readOnly: Boolean = false,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    trailingIcon: (@Composable () -> Unit)? = null,
    keepContainerColorOnFocus: Boolean = false,
    containerColorOverride: Color? = null,
) {
    val lightTheme = MaterialTheme.colorScheme.background.luminance() > 0.5f
    val unfocusedContainerColor = containerColorOverride ?:
        if (lightTheme) MaterialTheme.colorScheme.surface
        else MaterialTheme.colorScheme.surfaceContainerHigh
    TextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        enabled = enabled,
        readOnly = readOnly,
        label = { Text(uiText(label), style = MaterialTheme.typography.labelMedium) },
        placeholder = placeholder?.let { text ->
            { Text(uiText(text), color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.58f)) }
        },
        singleLine = singleLine,
        minLines = minLines,
        visualTransformation = visualTransformation,
        keyboardOptions = keyboardOptions,
        trailingIcon = trailingIcon,
        shape = VaultShape,
        colors = TextFieldDefaults.colors(
            focusedContainerColor = containerColorOverride ?:
                if (keepContainerColorOnFocus) unfocusedContainerColor
                else if (lightTheme) MaterialTheme.colorScheme.surface
                else MaterialTheme.colorScheme.surfaceContainerHighest,
            unfocusedContainerColor = unfocusedContainerColor,
            disabledContainerColor = unfocusedContainerColor,
            focusedIndicatorColor = Color.Transparent,
            unfocusedIndicatorColor = Color.Transparent,
            disabledIndicatorColor = Color.Transparent,
            errorIndicatorColor = MaterialTheme.colorScheme.error,
            disabledTextColor = MaterialTheme.colorScheme.onSurface,
            disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
        ),
    )
}

@Composable
internal fun EditorSectionHeading(
    title: String,
    subtitle: String? = null,
    accent: Color = MaterialTheme.colorScheme.primary,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(width = 4.dp, height = 28.dp)
                .background(accent, RoundedCornerShape(2.dp)),
        )
        Spacer(Modifier.width(10.dp))
        Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
            Text(uiText(title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            if (!subtitle.isNullOrBlank()) {
                Text(
                    uiText(subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
internal fun EditorIdentityHeader(
    title: String,
    subtitle: String,
    painter: Painter,
    accent: Color,
) {
    Surface(
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surface,
        shadowElevation = 0.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(accent.copy(alpha = 0.13f), VaultShape),
                contentAlignment = Alignment.Center,
            ) {
                Icon(painter, contentDescription = null, tint = Color.Unspecified, modifier = Modifier.size(30.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(uiText(title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(uiText(subtitle), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
