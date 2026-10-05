package com.vault.ui

import androidx.compose.foundation.shape.CornerBasedShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** 全局唯一矩形圆角半径：所有 rectilinear 表面统一 16dp（胶囊/圆形/细进度条保持全圆）。 */
val VaultCornerRadius: Dp = 16.dp

/** 四角 16dp：卡片 / 按钮 / 输入框 / 对话框等绝大多数矩形表面。 */
val VaultShape: CornerBasedShape = RoundedCornerShape(VaultCornerRadius)

/** 仅顶部两角 16dp（ModalBottomSheet、Markdown 组首块）。 */
val VaultTopShape: CornerBasedShape =
    RoundedCornerShape(topStart = VaultCornerRadius, topEnd = VaultCornerRadius)

/** 仅底部两角 16dp（Markdown 组末块）。 */
val VaultBottomShape: CornerBasedShape =
    RoundedCornerShape(bottomStart = VaultCornerRadius, bottomEnd = VaultCornerRadius)
