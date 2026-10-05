package com.vault.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import com.vault.ui.vaultHorizontalScroll as horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import com.vault.ui.VaultSwitch
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.vault.R
import com.vault.security.PasswordGenerator
import com.vault.ui.copySensitive
import com.vault.ui.uiText
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.round
import java.util.Locale
import com.vault.ui.VaultShape

/**
 * 密码生成器对话框。生成结果通过 [onAccept] 交给调用方填入密码字段。
 */
@Composable
fun PasswordGeneratorDialog(
    initialLength: Int = 16,
    onCancel: () -> Unit,
    onAccept: (String) -> Unit,
) {
    var length by remember { mutableIntStateOf(initialLength.coerceIn(4, 64)) }
    var lower by remember { mutableStateOf(true) }
    var upper by remember { mutableStateOf(true) }
    var digit by remember { mutableStateOf(true) }
    var symbol by remember { mutableStateOf(true) }
    var avoidAmbiguous by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf("") }

    val configuration = LocalConfiguration.current
    val compact = configuration.screenHeightDp < 640 || configuration.screenWidthDp < 360
    val contentMaxHeight = (
        configuration.screenHeightDp - if (compact) 180 else 220
    ).coerceIn(140, 520).dp
    val enabledCount = listOf(lower, upper, digit, symbol).count { it }
    val poolSize = (if (lower) 26 else 0) +
        (if (upper) 26 else 0) +
        (if (digit) 10 else 0) +
        (if (symbol) 29 else 0)
    val strength = passwordStrength(length, poolSize)

    fun roll() {
        preview = PasswordGenerator.generate(
            PasswordGenerator.Options(
                length = length,
                lower = lower,
                upper = upper,
                digit = digit,
                symbol = symbol,
                avoidAmbiguous = avoidAmbiguous,
            ),
        )
    }

    fun setCharset(current: Boolean, update: (Boolean) -> Unit) {
        if (current && enabledCount == 1) return
        update(!current)
    }

    LaunchedEffect(length, lower, upper, digit, symbol, avoidAmbiguous) { roll() }

    VaultDialog(
        onDismissRequest = onCancel,
        shape = VaultShape,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .background(
                            MaterialTheme.colorScheme.primary.copy(alpha = 0.13f),
                            VaultShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Default.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp),
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                    Text(uiText("生成强密码"), style = MaterialTheme.typography.titleLarge)
                    if (!compact) {
                        Text(
                            uiText("按当前规则实时生成"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = contentMaxHeight)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(if (compact) 10.dp else 14.dp),
            ) {
                PasswordPreview(preview = preview, strength = strength, compact = compact, onRefresh = ::roll)

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(uiText("密码长度"), style = MaterialTheme.typography.titleSmall)
                            if (!compact) {
                                Text(
                                    uiText("建议至少 16 位"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        LengthStepper(
                            length = length,
                            onDecrease = { length = (length - 1).coerceAtLeast(4) },
                            onIncrease = { length = (length + 1).coerceAtMost(64) },
                        )
                    }
                    VaultSlider(
                        value = length.toFloat(),
                        onValueChange = { length = it.toInt().coerceIn(4, 64) },
                        valueRange = 4f..64f,
                        steps = 59,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(uiText("包含字符"), style = MaterialTheme.typography.titleSmall)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CharsetOption(if (compact) stringResource(R.string.entry_remaining_lowercase_short) else stringResource(R.string.entry_remaining_lowercase), "a-z", lower, compact, Modifier.weight(1f)) {
                            setCharset(lower) { lower = it }
                        }
                        CharsetOption(if (compact) stringResource(R.string.entry_remaining_uppercase_short) else stringResource(R.string.entry_remaining_uppercase), "A-Z", upper, compact, Modifier.weight(1f)) {
                            setCharset(upper) { upper = it }
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CharsetOption(stringResource(R.string.entry_remaining_digits), "0-9", digit, compact, Modifier.weight(1f)) {
                            setCharset(digit) { digit = it }
                        }
                        CharsetOption(if (compact) stringResource(R.string.entry_remaining_symbols_short) else stringResource(R.string.entry_remaining_symbols), "!@#", symbol, compact, Modifier.weight(1f)) {
                            setCharset(symbol) { symbol = it }
                        }
                    }
                    if (!compact) {
                        Text(
                            uiText("至少保留一种字符；启用的每一类都会出现至少一次。"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(VaultShape)
                        .clickable(role = Role.Switch) { avoidAmbiguous = !avoidAmbiguous },
                    color = MaterialTheme.colorScheme.surfaceContainer,
                    shape = VaultShape,
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(uiText("避开形近字符"), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                            if (!compact) {
                                Text(
                                    uiText("排除 0/O、1/l/I 等易混淆字符"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        VaultSwitch(
                            checked = avoidAmbiguous,
                            onCheckedChange = { avoidAmbiguous = it },
                        )
                    }
                }
            }
        },
        confirmButton = {
            VaultActionButton(
                onClick = { onAccept(preview) },
                enabled = preview.isNotEmpty(),
                style = VaultActionStyle.PRIMARY,
            ) { Text(uiText("使用此密码")) }
        },
        dismissButton = {
            VaultActionButton(onClick = onCancel) { Text(uiText("取消")) }
        },
    )
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
private fun PasswordPreview(
    preview: String,
    strength: PasswordStrength,
    compact: Boolean,
    onRefresh: () -> Unit,
) {
    val context = LocalContext.current
    val generatedPasswordLabel = uiText("生成的密码")
    // 数字以当前主题主色高亮，其余字符保持原样
    val digitColor = MaterialTheme.colorScheme.primary
    val previewAnnotated = remember(preview, digitColor) {
        buildAnnotatedString {
            preview.forEach { char ->
                withStyle(if (char.isDigit()) SpanStyle(color = digitColor) else SpanStyle()) {
                    append(char)
                }
            }
        }
    }
    Surface(
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(
                start = 14.dp,
                top = if (compact) 8.dp else 12.dp,
                end = 6.dp,
                bottom = if (compact) 8.dp else 12.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(if (compact) 6.dp else 10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    previewAnnotated,
                    modifier = Modifier
                        .weight(1f)
                        .combinedClickable(
                            onClick = {},
                            onLongClick = {
                                copySensitive(context, generatedPasswordLabel, preview)
                            },
                        )
                        .horizontalScroll(rememberScrollState()),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    softWrap = false,
                )
                IconButton(onClick = onRefresh) {
                    Icon(Icons.Default.Refresh, stringResource(R.string.entry_remaining_regenerate), tint = MaterialTheme.colorScheme.primary)
                }
            }
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        stringResource(strength.labelRes),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = strength.color,
                    )
                    Spacer(Modifier.weight(1f))
                    Text(
                        "${stringResource(R.string.entry_remaining_crack_estimate)} · ${strength.crackTime.format()}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    repeat(4) { index ->
                        Box(
                            Modifier
                                .weight(1f)
                                .height(4.dp)
                                .background(
                                    if (index < strength.level) strength.color else MaterialTheme.colorScheme.outlineVariant,
                                    RoundedCornerShape(2.dp),
                                ),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun LengthStepper(length: Int, onDecrease: () -> Unit, onIncrease: () -> Unit) {
    Surface(
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onDecrease, enabled = length > 4, modifier = Modifier.size(36.dp)) {
                Icon(Icons.Default.Remove, stringResource(R.string.entry_remaining_shorten), modifier = Modifier.size(18.dp))
            }
            Text(
                length.toString(),
                modifier = Modifier.width(34.dp),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            IconButton(onClick = onIncrease, enabled = length < 64, modifier = Modifier.size(36.dp)) {
                Icon(Icons.Default.Add, stringResource(R.string.entry_remaining_lengthen), modifier = Modifier.size(18.dp))
            }
        }
    }
}

@Composable
private fun CharsetOption(
    title: String,
    sample: String,
    checked: Boolean,
    compact: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val background = if (checked) {
        MaterialTheme.colorScheme.surfaceContainerHigh
    } else {
        MaterialTheme.colorScheme.surfaceContainer
    }
    Surface(
        modifier = modifier.clip(VaultShape).clickable(role = Role.Checkbox, onClick = onClick),
        shape = VaultShape,
        color = background,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = if (compact) 7.dp else 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(22.dp)
                    .background(
                        if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceContainerHighest,
                        VaultShape,
                    ),
                contentAlignment = Alignment.Center,
            ) {
                if (checked) {
                    Icon(
                        Icons.Default.Check,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.size(15.dp),
                    )
                }
            }
            Spacer(Modifier.width(9.dp))
            Column {
                Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                Text(
                    sample,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private data class PasswordStrength(
    val level: Int,
    @androidx.annotation.StringRes val labelRes: Int,
    val color: Color,
    val crackTime: CrackTime,
)

internal data class CrackTime(
    @androidx.annotation.StringRes val resId: Int,
    val amount: String? = null,
) {
    @Composable
    fun format(): String = amount?.let { stringResource(resId, it) } ?: stringResource(resId)
}

private fun passwordStrength(length: Int, poolSize: Int): PasswordStrength {
    val entropy = if (poolSize > 1) length * (ln(poolSize.toDouble()) / ln(2.0)) else 0.0
    return when {
        entropy < 45 -> PasswordStrength(1, R.string.entry_remaining_password_weak, Color(0xFFD14949), estimateCrackTime(entropy))
        entropy < 65 -> PasswordStrength(2, R.string.entry_remaining_password_average, Color(0xFFD48722), estimateCrackTime(entropy))
        entropy < 90 -> PasswordStrength(3, R.string.entry_remaining_password_strong, Color(0xFF2E8B68), estimateCrackTime(entropy))
        else -> PasswordStrength(4, R.string.entry_remaining_password_very_strong, Color(0xFF16856A), estimateCrackTime(entropy))
    }
}

/**
 * 以人类可读的方式估算离线穷举破解的平均耗时。
 *
 * 假设每秒 100 亿次猜测，并取穷举一半组合的平均值。该估算只反映密码熵本身；
 * 实际攻击还会受站点限流与密码哈希方式影响，可能远比此值更慢。
 *
 * 数值取整采用四舍五入并保留一位小数（如 3.5 万年），大数按中文习惯用万/亿/万亿
 * 分组（万年、亿年、万亿年），避免「百万年/十亿年」这类拗口的直译。
 */
internal fun estimateCrackTime(entropyBits: Double): CrackTime {
    if (entropyBits <= 0.0) return CrackTime(R.string.entry_remaining_crack_under_second)
    val seconds = 2.0.pow(entropyBits - 1.0) / OFFLINE_GUESSES_PER_SECOND
    val years = seconds / SECONDS_PER_YEAR
    return when {
        seconds < 1.0 -> CrackTime(R.string.entry_remaining_crack_under_second)
        seconds < 60.0 -> CrackTime(R.string.entry_remaining_crack_seconds, seconds.toLong().coerceAtLeast(1).toString())
        seconds < 3_600.0 -> CrackTime(R.string.entry_remaining_crack_minutes, (seconds / 60.0).toLong().toString())
        seconds < 86_400.0 -> CrackTime(R.string.entry_remaining_crack_hours, (seconds / 3_600.0).toLong().toString())
        seconds < SECONDS_PER_YEAR -> CrackTime(R.string.entry_remaining_crack_days, (seconds / 86_400.0).toLong().toString())
        years < 10_000.0 -> CrackTime(R.string.entry_remaining_crack_years, years.toLong().toString())
        years < 100_000_000.0 -> CrackTime(R.string.entry_remaining_crack_thousand_years, formatChineseNumber(years / 10_000.0))
        years < 1_000_000_000_000.0 -> CrackTime(R.string.entry_remaining_crack_million_years, formatChineseNumber(years / 100_000_000.0))
        else -> CrackTime(R.string.entry_remaining_crack_trillion_plus)
    }
}

/** 四舍五入并压缩尾零：整数输出整数，非整数保留一位小数。 */
private fun formatChineseNumber(value: Double): String {
    val rounded = round(value * 10.0) / 10.0
    return if (rounded == rounded.toLong().toDouble()) {
        rounded.toLong().toString()
    } else {
        String.format(Locale.ROOT, "%.1f", rounded)
    }
}

private const val OFFLINE_GUESSES_PER_SECOND = 10_000_000_000.0
private const val SECONDS_PER_YEAR = 31_557_600.0
