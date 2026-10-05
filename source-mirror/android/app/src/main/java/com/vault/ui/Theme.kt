package com.vault.ui

import android.app.Activity
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.ClipOp
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.addOutline
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.clipPath
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.drawOutline
import androidx.compose.ui.unit.dp
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.Dp
import androidx.core.view.WindowCompat

/** 品牌主色唯一来源：Compose 模板与未接入 MaterialTheme 的独立界面（扫码/相机）共用。 */
val BrandPrimary = Color(0xFF1A7DC4)

private val VaultLight = lightColorScheme(
    primary = BrandPrimary,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFC5E0F5),
    onPrimaryContainer = Color(0xFF0A2B47),
    secondary = Color(0xFF4A9BA8),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD1E9ED),
    onSecondaryContainer = Color(0xFF1A363B),
    tertiary = Color(0xFFD48A2E),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFBE9CA),
    onTertiaryContainer = Color(0xFF4A2B05),
    error = Color(0xFFD32F2F),
    onError = Color.White,
    errorContainer = Color(0xFFFCE4E3),
    onErrorContainer = Color(0xFF5C0A0A),
    background = Color(0xFFF3F3F3),
    onBackground = Color(0xFF111111),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111111),
    surfaceVariant = Color(0xFFF8F8F8),
    onSurfaceVariant = Color(0xFF555555),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF8F8F8),
    surfaceContainer = Color(0xFFE8E8E8),
    surfaceContainerHigh = Color(0xFFE0E0E0),
    surfaceContainerHighest = Color(0xFFE5E5E5),
    outline = Color(0xFFE0E0E0),
    outlineVariant = Color(0xFFE5E5E5),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFF2A2E33),
    inverseOnSurface = Color(0xFFF1F2F4),
    inversePrimary = Color(0xFF80B6DC),
)

private val VaultDark = darkColorScheme(
    primary = Color(0xFF80B6DC),
    onPrimary = Color(0xFF082234),
    primaryContainer = Color(0xFF234E70),
    onPrimaryContainer = Color(0xFFD5E7F4),
    secondary = Color(0xFF94B8BF),
    onSecondary = Color(0xFF15333A),
    secondaryContainer = Color(0xFF345A60),
    onSecondaryContainer = Color(0xFFD4E5E8),
    tertiary = Color(0xFFE5B370),
    onTertiary = Color(0xFF3F2706),
    tertiaryContainer = Color(0xFF74511A),
    onTertiaryContainer = Color(0xFFF7E0BA),
    error = Color(0xFFF08585),
    onError = Color(0xFF3E0808),
    errorContainer = Color(0xFF6E1F1F),
    onErrorContainer = Color(0xFFFBDDDD),
    background = Color(0xFF000000),
    onBackground = Color(0xFFF2F2F2),
    surface = Color(0xFF242424),
    onSurface = Color(0xFFF2F2F2),
    surfaceVariant = Color(0xFF2C2C2C),
    onSurfaceVariant = Color(0xFFB5B5B5),
    surfaceContainerLowest = Color(0xFF000000),
    surfaceContainerLow = Color(0xFF242424),
    surfaceContainer = Color(0xFF313131),
    surfaceContainerHigh = Color(0xFF303030),
    surfaceContainerHighest = Color(0xFF333333),
    outline = Color(0xFF333333),
    outlineVariant = Color(0xFF303030),
    scrim = Color(0xFF000000),
    inverseSurface = Color(0xFFE6E2D9),
    inverseOnSurface = Color(0xFF23262B),
    inversePrimary = Color(0xFF1E6FA8),
)

@Composable
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
fun FAEVaultTheme(content: @Composable () -> Unit) {
    val systemDark = isSystemInDarkTheme()
    val dark = isSystemInDarkTheme() || ThemePref.mode.value == ThemeMode.DARK
    // 浅色/深色使用 Vault Sapphire 配色
    val scheme = if (ThemePref.mode.value == ThemeMode.LIGHT || (!dark && ThemePref.mode.value == ThemeMode.SYSTEM)) {
        VaultLight
    } else {
        VaultDark
    }
    // 上报当前生效深色：供主题扩散动画在过渡期间保持旧图标深浅
    ThemeSwitch.reportDark(dark)
    // 同步系统状态栏 / 导航栏图标的明暗模式：
    // 圆形扩散动画期间图标沿用切换前配色，动画结束（revealActive 复位）后再翻到新配色，
    // 避免图标先变、色板未到的低对比闪烁。
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window ?: return@SideEffect
            val controller = WindowCompat.getInsetsController(window, view)
            val iconsDark = if (ThemeSwitch.revealActive) ThemeSwitch.oldDark else dark
            controller.isAppearanceLightStatusBars = !iconsDark
            controller.isAppearanceLightNavigationBars = !iconsDark
        }
    }
    // 有意压平 Material3 的 shape 层级：所有矩形容器统一 16dp（VaultShape）。
    // 圆形/胶囊（CircleShape / CornerFull）不受 Shapes 影响，保持全圆。
    MaterialTheme(
        colorScheme = scheme,
        shapes = Shapes(
            extraSmall = VaultShape,
            small = VaultShape,
            medium = VaultShape,
            large = VaultShape,
            extraLarge = VaultShape,
        ),
        content = {
            val backdrop = androidx.compose.runtime.remember { dev.chrisbanes.haze.HazeState() }
            CompositionLocalProvider(
                LocalVaultBackdrop provides backdrop,
                LocalIndication provides ripple(),
                // VaultEdgeScroll supplies a visual-only spring; platform stretch must not consume the next drag.
                androidx.compose.foundation.LocalOverscrollConfiguration provides null,
                content = { VaultBackdropHost(state = backdrop, content = content) },
            )
        },
    )
}

/** 浅色保留系统投影；深色使用向下偏移的柔和光晕，重点落在底部，跟随控件轮廓。 */
@Composable
fun Modifier.vaultShadow(elevation: Dp, shape: Shape = VaultShape): Modifier {
    if (elevation <= 0.dp) return this
    if (MaterialTheme.colorScheme.background.luminance() > 0.5f) {
        return shadow(elevation, shape, clip = false)
    }
    val glow = Color.White
    return drawWithCache {
        val outline = shape.createOutline(size, layoutDirection, this)
        val radius = elevation.toPx().coerceAtMost(4.dp.toPx())
        val offsetY = radius * 0.35f
        val shapePath = Path().apply { addOutline(outline) }
        onDrawBehind {
            // 光晕只画在轮廓外侧：整体下移后裁掉形状内部，避免白色贴边渗入造成羽化。
            clipPath(shapePath, ClipOp.Difference) {
                translate(top = offsetY) {
                    for (step in 10 downTo 1) {
                        drawOutline(
                            outline = outline,
                            color = glow.copy(alpha = 0.01f),
                            style = Stroke(width = radius * 2f * step / 10f),
                        )
                    }
                }
            }
        }
    }
}

/**
 * 自动填充 / 通行密钥弹窗内部的次级容器灰。
 * 比 surfaceContainerHighest 更深一档，与卡片本体的近白色拉开对比，
 * 避免列表 / 徽标等灰色分区被误认为卡片底色。深色模式沿用主题 surfaceContainerHighest。
 */
@Composable
internal fun vaultDialogInsetColor(): Color =
    if (MaterialTheme.colorScheme.background.luminance() > 0.5f) {
        Color(0xFFD0D0D0)
    } else {
        MaterialTheme.colorScheme.surfaceContainerHighest
    }

/**
 * 5 种 secret_type 的强调色：使用多彩且鲜艳的高饱和配色，避免单一蓝系。
 */
object TypeColors {
    val Login = Color(0xFF1E88E5)        // 蓝
    val Wifi = Color(0xFF06B6D4)         // 蓝绿（匹配 Wi-Fi 图标色调）
    val CreditCard = Color(0xFF3F51B5)   // 靛蓝（避开红/橙警示色系）
    val IdCard = Color(0xFFFB8C00)       // 橙
    val ApiKey = Color(0xFF43A047)       // 绿
    val Otp = Color(0xFF00BFA5)          // 青绿
    val SecureNote = Color(0xFF546E7A)   // 蓝灰
    val Server = Color(0xFF00897B)       // 深青
    val Custom = Color(0xFF6D4C41)       // 棕
    val Passkey = Color(0xFF7C3AED)      // 紫罗兰

    fun of(type: String): Color = when (type) {
        com.vault.model.SecretType.LOGIN -> Login
        com.vault.model.SecretType.CARD_DOCUMENT -> CreditCard
        com.vault.model.SecretType.WIFI -> Wifi
        com.vault.model.SecretType.API_KEY -> ApiKey
        com.vault.model.SecretType.OTP -> Otp
        com.vault.model.SecretType.SECURE_NOTE -> SecureNote
        com.vault.model.SecretType.SERVER -> Server
        com.vault.model.SecretType.CUSTOM -> Custom
        com.vault.model.SecretType.PASSKEY -> Passkey
        else -> Login
    }
}

/**
 * 语义成功色（安全检查/健康状态）：集中管理明暗变体，替代散落的硬编码绿。
 * 不属于 M3 标准槽位，故与 TypeColors 同层单独提供。
 */
object SuccessColors {
    /** 页头卡片强调色（随明暗切换）。 */
    fun headerAccent(dark: Boolean): Color = if (dark) Color(0xFF69C59B) else Color(0xFF16845A)

    /** 页头卡片容器底色（随明暗切换）。 */
    fun headerContainer(dark: Boolean): Color = if (dark) Color(0xFF183B2D) else Color(0xFFC8E8CC)

    /** 页头卡片内容色（随明暗切换）。 */
    fun headerContent(dark: Boolean): Color = if (dark) Color(0xFFD8F3E5) else Color(0xFF123D2C)

    /** 状态指示绿：圆点/图例/环形图，明暗通用。 */
    val Indicator = Color(0xFF22A06B)

    /** 行内标签文字绿。 */
    val Label = Color(0xFF16845A)

    /** 轻量成功提示（如同步状态圆点）。 */
    val ToastDot = Color(0xFF2E9B57)
}
