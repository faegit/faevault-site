package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.PaddingValues
import com.vault.ui.VaultLazyColumn as LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import com.vault.ui.VaultLazyRow as LazyRow
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.setValue
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vault.R
import com.vault.model.Entry
import com.vault.security.AutoHidePref
import com.vault.security.LockoutPref
import com.vault.model.EntryModules
import com.vault.model.ExpiryStatus
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import com.vault.passkeys.PasskeyKeyMode
import com.vault.model.otpDisplaySnapshot
import com.vault.model.SecretType
import com.vault.model.entryModules
import com.vault.model.withEntryModules
import com.vault.model.detailModules
import com.vault.model.associatedAppPackage
import com.vault.model.hasSensitiveModules
import com.vault.model.expiryInfo
import com.vault.model.formatCardDate
import com.vault.model.getStringField
import com.vault.model.getOtpField
import com.vault.model.hasOtp
import com.vault.model.otpBindingId
import com.vault.model.autofillLinks
import com.vault.model.autofill.AutofillRole
import com.vault.model.isEntryLeaked
import com.vault.ui.TypeColors
import com.vault.ui.EntryDetailScrollPositionPref
import com.vault.ui.MarkdownRenderResult
import com.vault.ui.MarkdownAnchorRegistry
import com.vault.ui.MarkdownBlockSpec
import com.vault.ui.MarkdownJumpController
import com.vault.ui.SharedMarkdownDocumentCache
import com.vault.ui.buildMarkdownBlockSpecs
import com.vault.ui.markdownBlockItems
import com.vault.ui.copySensitive
import com.vault.ui.uiText
import com.vault.ui.media.Base64Image
import com.vault.ui.media.ImageViewerDialog
import com.vault.ui.media.QrImage
import com.vault.ui.media.copyImageToClipboard
import com.vault.ui.media.parseImageList
import com.vault.ui.media.mediaValueString
import com.vault.ui.media.saveImageToUri
import com.vault.ui.media.imageExportInfo
import com.vault.ui.media.wifiQrPayload
import com.vault.ui.media.exportAttachmentToUri
import com.vault.ui.media.PmvMediaSessionLockedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import androidx.compose.runtime.mutableStateMapOf
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import com.vault.ui.VaultFloatingBar
import com.vault.ui.vaultBottomActionWidth
import com.vault.ui.VaultShape
import com.vault.ui.VaultTopShape
import com.vault.ui.VaultBottomShape

/** 与桌面端一致：登录、Wi-Fi 以外的条目，其敏感字段与原图查看需要二次验证主密码。 */
private val UNGUARDED_TYPES = setOf(SecretType.LOGIN, SecretType.WIFI)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryDetailScreen(
    entry: Entry,
    verifyMasterPassword: (String) -> Boolean,
    hasSecuritySession: () -> Boolean = { false },
    elevateSecuritySession: () -> Unit = {},
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    setExternalActionInProgress: (Boolean) -> Unit = {},
    autofillSourceOptions: List<Entry> = emptyList(),
    onOpenAutofillSource: (Entry) -> Unit = {},
) {
    var confirmDelete by remember { mutableStateOf(false) }
    var showWifiQr by remember { mutableStateOf(false) }
    // 当前条目会话内是否已验证过主密码；首次验证后同一详情页内不再反复要求
    var masterVerified by remember(entry.id) { mutableStateOf(hasSecuritySession()) }
    LaunchedEffect(entry.id) {
        while (true) {
            masterVerified = hasSecuritySession()
            delay(1_000L)
        }
    }
    // 主密码对话框的回调：验证成功时执行
    var pendingAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    val detailContext = LocalContext.current
    val savedDetailScrollPosition = remember(entry.id) {
        EntryDetailScrollPositionPref.read(detailContext, entry.id)
    }
    val detailScrollState = rememberLazyListState()
    var detailScrollRestored by remember(entry.id) { mutableStateOf(false) }
    val markdownModuleTokens = remember(entry) {
        entry.detailModules()
            .filter { module ->
                EntryModules.primitive(module["type"]) == ModuleType.MULTILINE &&
                    EntryModules.primitive(module["value"]).isNotBlank()
            }
            .mapTo(linkedSetOf(), ::markdownModuleToken)
    }
    // ── MULTILINE 备注页面级平铺状态 ──
    val markdownRegistry = remember(entry.id) { MarkdownAnchorRegistry() }
    val detailComposeScope = rememberCoroutineScope()
    val jumpController = remember(entry.id) { MarkdownJumpController(detailComposeScope) }
    val multilineParsedSpecs = remember(entry.id, entry.updatedAt) {
        mutableStateMapOf<String, Pair<MarkdownRenderResult, List<MarkdownBlockSpec>>>()
    }
    val multilineNotes = remember(entry.id, entry.updatedAt) {
        entry.detailModules().mapNotNull { module ->
            if (EntryModules.primitive(module["type"]) != ModuleType.MULTILINE) return@mapNotNull null
            val raw = EntryModules.primitive(module["value"])
            if (raw.isBlank()) return@mapNotNull null
            module to raw
        }
    }
    val hasFieldsCard = remember(entry, autofillSourceOptions) {
        hasVisibleFieldsCard(entry, autofillSourceOptions)
    }
    var renderedMarkdownTokens by remember(entry.id, entry.updatedAt) { mutableStateOf(emptySet<String>()) }
    val markdownContentReady = markdownModuleTokens.all(renderedMarkdownTokens::contains)
    // 后台逐个解析 MULTILINE 备注：AST + BlockSpecs 就绪后平铺 items 才出现
    LaunchedEffect(entry.id, entry.updatedAt, multilineNotes) {
        for ((module, raw) in multilineNotes) {
            val token = markdownModuleToken(module)
            if (multilineParsedSpecs.containsKey(token)) continue
            val result = withContext(Dispatchers.Default) { SharedMarkdownDocumentCache.compute(raw) }
            multilineParsedSpecs[token] = result to buildMarkdownBlockSpecs(result)
            renderedMarkdownTokens = renderedMarkdownTokens + token
        }
    }
    LaunchedEffect(entry.id, savedDetailScrollPosition, markdownContentReady) {
        if (!markdownContentReady) return@LaunchedEffect
        // 等待 Lazy 首次测量产出 item 总数（上限 120 帧兜底），再钳位定位，
        // 避免 scrollToItem 越界异常被吞掉后表现为"回到顶部"
        var frames = 0
        while (detailScrollState.layoutInfo.totalItemsCount == 0 && frames < 120) {
            withFrameNanos { }
            frames++
        }
        val total = detailScrollState.layoutInfo.totalItemsCount
        if (total == 0) {
            detailScrollRestored = true
            return@LaunchedEffect
        }
        runCatching {
            detailScrollState.scrollToItem(savedDetailScrollPosition.coerceIn(0, total - 1))
        }
        detailScrollRestored = true
    }
    LaunchedEffect(entry.id, detailScrollRestored) {
        if (!detailScrollRestored) return@LaunchedEffect
        snapshotFlow { detailScrollState.firstVisibleItemIndex }
            .distinctUntilChanged()
            .collectLatest { position ->
                delay(250L)
                EntryDetailScrollPositionPref.write(detailContext, entry.id, position)
            }
    }
    DisposableEffect(entry.id, detailScrollRestored) {
        onDispose {
            if (detailScrollRestored) {
                EntryDetailScrollPositionPref.write(detailContext, entry.id, detailScrollState.firstVisibleItemIndex)
            }
        }
    }
    val guardEnabled by com.vault.security.SensitiveGuardPref.enabled
    val guarded = guardEnabled && (entry.secretType !in UNGUARDED_TYPES || entry.hasSensitiveModules())
    val photoBlurEnabled by com.vault.security.PhotoBlurPref.enabled
    val tint = TypeColors.of(entry.secretType)
    val ctxForBadge = LocalContext.current
    val leakCheckEnabled by com.vault.security.LeakCheckEnabledPref.enabled
    val isLeaked = remember(entry, ctxForBadge, leakCheckEnabled) {
        leakCheckEnabled && entry.isEntryLeaked(ctxForBadge)
    }
    // 逐字段泄露检查（用于标签标红）
    val isFieldLeaked = remember(entry, ctxForBadge, leakCheckEnabled) {
        { v: String -> leakCheckEnabled && v.isNotEmpty() && com.vault.security.LeakedPasswordCheck.isLeaked(ctxForBadge, v) }
    }
    val expiryInfo = remember(entry) { entry.expiryInfo() }

    // 守卫函数：guarded 类型需要主密码（一次验证后缓存）
    val gate: ((() -> Unit) -> Unit) = { action ->
        val sessionActive = hasSecuritySession()
        masterVerified = sessionActive
        if (!guarded || sessionActive) {
            action()
        } else pendingAction = action
    }

    Scaffold(
        topBar = {
            VaultSubpageTopBar(
                title = if (entry.secretType == SecretType.PASSKEY) stringResource(R.string.category_passkey)
                else typeLabel(entry.secretType),
                onBack = onBack,
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad ->
        // 内容层 Box：滚动内容 + 底部操作悬浮覆盖（整屏居中，不占 FAB 槽）
        Box(modifier = Modifier.fillMaxSize()) {
        val markdownSurfaceColor = MaterialTheme.colorScheme.surface

        // P0：详情页统一单一 LazyColumn——Markdown/字段/图片均为 item，
        // 屏幕外区块不参与组合，滚动期间页面高度恒定
        LazyColumn(
            state = detailScrollState,
            modifier = Modifier.vaultBackdropSource()
                .fillMaxSize()
                .padding(pad)
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(bottom = 84.dp),
        ) {
            // Hero
            item(key = "hero", contentType = "card") {
            Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(
                    containerColor = categoryIconBackground(entry.secretType).copy(alpha = 0.10f),
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(modifier = Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier.size(56.dp).clip(CircleShape).background(categoryIconBackground(entry.secretType).copy(alpha = 0.18f)),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            painter = painterResource(categoryIconRes(entry.secretType)),
                            contentDescription = null,
                            tint = androidx.compose.ui.graphics.Color.Unspecified,
                            modifier = Modifier.size(34.dp),
                        )
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            entry.title.ifEmpty { stringResource(R.string.entry_remaining_no_title) },
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 2,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                        )
                        if (entry.tags.isNotEmpty()) {
                            Text(
                                entry.tags.joinToString("  "),
                                style = MaterialTheme.typography.labelSmall,
                                color = tint,
                            )
                        }
                        val hasBadge = isLeaked || expiryInfo.status != null
                        if (hasBadge) {
                            Spacer(Modifier.height(6.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                if (isLeaked) {
                                    val leakCount = entry.leakPwnedCount?.takeIf { it > 0 }
                                    BadgeChip(
                                        if (leakCount != null) "已泄露 ${formatLeakCount(leakCount)} 次" else uiText("已泄露"),
                                        MaterialTheme.colorScheme.error,
                                    )
                                }
                                expiryInfo.status?.let { status ->
                                    val (text, color) = when (status) {
                                        ExpiryStatus.EXPIRED -> "已过期" to MaterialTheme.colorScheme.error
                                        ExpiryStatus.EXPIRING_SOON -> "即将到期" to MaterialTheme.colorScheme.tertiary
                                    }
                                    BadgeChip(uiText(text), color)
                                }
                            }
                        }
                    }
                    if (guarded) {
                        Icon(
                            Icons.Default.Lock,
                            stringResource(R.string.entry_remaining_sensitive_unlocked),
                            tint = tint.copy(alpha = 0.6f),
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
            }
            } // hero item
            // 字段卡片不存在时同步移除其前置占位，避免 Markdown-only 条目留下额外空白高度。
            if (hasFieldsCard) {
                item(key = "heroGap") { Spacer(Modifier.height(12.dp)) }
                item(key = "fields", contentType = "card") {
                Card(
                shape = VaultShape,
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    when (entry.secretType) {
                        SecretType.LOGIN -> {
                            FieldRow("用户名", entry.username, copy = true)
                            PasswordRow(entry.password, label = "密码", leaked = isLeaked || isFieldLeaked(entry.password), gate = gate)
                            FieldRow("网址", entry.url, copy = true)
                            FieldRow("关联程序包名", entry.associatedAppPackage(), copy = true)
                            val linkedGroups = linkedAutofillDetailGroups(entry, autofillSourceOptions)
                            val otpSource = detailOtpSource(entry, autofillSourceOptions)
                            if (linkedGroups.isNotEmpty()) {
                                LinkedAutofillDetails(
                                    groups = linkedGroups,
                                    gate = gate,
                                    onOpenSource = onOpenAutofillSource,
                                )
                                // 内置动态码不属于外部来源卡片，即使还关联了其他条目也要继续显示。
                                otpSource?.takeIf { it.id == entry.id }
                                    ?.let { OTPCodeDisplay(entry = it, gate = gate) }
                            } else {
                                // 未迁移的内嵌/旧版动态码仍按原详情语义展示。
                                otpSource?.let { resolvedOtp ->
                                    OTPCodeDisplay(entry = resolvedOtp, gate = gate)
                                }
                            }
                        }
                        SecretType.CARD_DOCUMENT -> {
                            val cardType = entry.getStringField("card_type").ifBlank { EntryModules.CARD_BANK }
                            FieldRow(stringResource(R.string.entry_remaining_card_type), cardTypeDisplayLabel(EntryModules.cardTypeLabels[cardType] ?: cardType))
                            when (cardType) {
                                EntryModules.CARD_BANK -> {
                                    FieldRow("持卡人", entry.getStringField("cardholder"))
                                    PasswordRow(entry.getStringField("card_number"), label = "完整卡号", gate = gate)
                                    FieldRow("开户行", entry.getStringField("bank"))
                                    FieldRow("分行/支行", entry.getStringField("bank_branch"))
                                    FieldRow("有效期", formatCardDate(entry.getStringField("expiry")))
                                    PasswordRow(entry.getStringField("cvv"), label = "CVV", copyable = false, gate = gate)
                                    PasswordRow(entry.getStringField("withdrawal_password"), label = stringResource(R.string.entry_remaining_withdrawal_password), copyable = false, gate = gate)
                                }
                                EntryModules.CARD_ID_CARD -> {
                                    FieldRow("姓名", entry.getStringField("full_name"))
                                    PasswordRow(entry.getStringField("id_number"), label = uiText("证件号"), gate = gate)
                                    FieldRow("签发日期", formatCardDate(entry.getStringField("issue_date")))
                                    FieldRow("到期日期", formatCardDate(entry.getStringField("expiry_date")))
                                    FieldRow("签发机关", entry.getStringField("issuing_authority"))
                                }
                                else -> {
                                    FieldRow(uiText("自定义卡证名称"), entry.getStringField("card_name"))
                                    PasswordRow(entry.getStringField("card_number"), label = "卡号", gate = gate)
                                    FieldRow("有效期", formatCardDate(entry.getStringField("expiry")))
                                }
                            }
                        }
                        SecretType.WIFI -> {
                            FieldRow("SSID", entry.getStringField("ssid"), copy = true)
                            val wifiPw = entry.getStringField("wifi_password").ifEmpty { entry.getStringField("password") }
                            PasswordRow(wifiPw, label = stringResource(R.string.entry_remaining_wifi_password), leaked = isLeaked || isFieldLeaked(wifiPw), gate = gate)
                            FieldRow(stringResource(R.string.entry_remaining_security_type), entry.getStringField("security_type"))
                            FieldRow(stringResource(R.string.entry_remaining_router_admin_url), entry.getStringField("router_admin_url"), copy = true)
                            val adminPw = entry.getStringField("admin_password")
                            if (adminPw.isNotEmpty()) PasswordRow(adminPw, label = stringResource(R.string.entry_remaining_admin_password), leaked = isLeaked || isFieldLeaked(adminPw), gate = gate)
                            val ssid = entry.getStringField("ssid")
                            if (ssid.isNotEmpty()) {
                                val qrInteractionSource = remember { MutableInteractionSource() }
                                val qrPressed by qrInteractionSource.collectIsPressedAsState()
                                val qrScale by animateFloatAsState(
                                    targetValue = if (qrPressed) 0.97f else 1f,
                                    animationSpec = spring(dampingRatio = 0.7f),
                                    label = "qrScale",
                                )
                                VaultActionButton(
                                    onClick = { showWifiQr = true },
                                    modifier = Modifier.scale(qrScale).fillMaxWidth().padding(vertical = 8.dp),
                                    interactionSource = qrInteractionSource,
                                ) {
                                    Icon(Icons.Default.QrCode2, null)
                                    Spacer(Modifier.width(8.dp))
                                    Text(uiText("分享WiFi"))
                                }
                                if (showWifiQr) VaultDialog(
                                    onDismissRequest = { showWifiQr = false },
                                    onClose = { showWifiQr = false },
                                    title = { Text(uiText("Wi-Fi 二维码")) },
        text = {
                                        Column(
                                            horizontalAlignment = Alignment.CenterHorizontally,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) {
                                            QrImage(content = wifiQrPayload(ssid, wifiPw, entry.getStringField("security_type")), sizeDp = 240)
                                            Spacer(Modifier.height(8.dp))
                                            Text(ssid, style = MaterialTheme.typography.titleMedium)
                                            Text(
                                                uiText("用手机相机扫码即可连接"),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            )
                                        }
                                    },
                                )
                            }
                        }
                        SecretType.API_KEY -> {
                            FieldRow(stringResource(R.string.entry_remaining_service), entry.getStringField("service"))
                            FieldRow(stringResource(R.string.entry_remaining_username_appid), entry.username, copy = true)
                            val apiKeyVal = entry.getStringField("api_key").ifEmpty { entry.password }
                            PasswordRow(
                                apiKeyVal,
                                label = "API Key",
                                leaked = isLeaked || isFieldLeaked(apiKeyVal),
                                gate = gate,
                            )
                            val apiSecretVal = entry.getStringField("api_secret")
                            PasswordRow(apiSecretVal, label = "API Secret", leaked = isFieldLeaked(apiSecretVal), gate = gate)
                            FieldRow("Base URL", entry.getStringField("base_url"), copy = true)
                            FieldRow("Scopes", entry.getStringField("scopes"))
                        }
                        SecretType.OTP -> {
                            OTPCodeDisplay(
                                entry = entry,
                                gate = gate,
                            )
                        }
                        SecretType.SECURE_NOTE -> {
                            val noteText = entry.getStringField("note").ifEmpty {
                                entry.entryModules()
                                    .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.MULTILINE }
                                    ?.let { (it["value"] as? JsonPrimitive)?.contentOrNull }
                                    .orEmpty()
                            }
                            if (noteText.isNotEmpty()) {
                                PasswordRow(noteText, label = stringResource(R.string.entry_remaining_secure_note_content), gate = gate)
                            }
                        }
                        SecretType.SERVER -> {
                            val srvModule = entry.entryModules()
                                .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.SERVER_CONNECTION }
                            val srvValue = srvModule?.get("value") as? JsonObject
                            val host = entry.getStringField("server_host").ifEmpty {
                                srvValue?.let { v -> EntryModules.primitive(v["host"]) }.orEmpty()
                            }
                            val port = entry.getStringField("server_port").ifEmpty {
                                srvValue?.let { v -> EntryModules.primitive(v["port"]) }.orEmpty()
                            }
                            val srvUsername = entry.getStringField("server_user").ifEmpty {
                                srvValue?.let { v -> EntryModules.primitive(v["username"]) }.orEmpty()
                            }
                            val srvPassword = entry.getStringField("server_pass").ifEmpty {
                                srvValue?.let { v -> EntryModules.primitive(v["password"]) }.orEmpty()
                            }
                            if (host.isNotEmpty()) FieldRow(stringResource(R.string.entry_remaining_host), host, copy = true)
                            if (port.isNotEmpty()) FieldRow(stringResource(R.string.entry_remaining_port), port, copy = true)
                            if (srvUsername.isNotEmpty()) FieldRow(stringResource(R.string.entry_remaining_username), srvUsername, copy = true)
                            if (srvPassword.isNotEmpty()) PasswordRow(srvPassword, label = stringResource(R.string.entry_remaining_password), gate = gate)
                        }
                    }
                    ModuleRows(
                        entry = entry,
                        gate = gate,
                        masterVerified = masterVerified,
                        photoBlurEnabled = photoBlurEnabled,
                        protectionRequired = guarded,
                        setExternalActionInProgress = setExternalActionInProgress,
                        skipMultilineTokens = markdownModuleTokens,
                    )
                    if (entry.notes.isNotEmpty()) FieldRow(stringResource(R.string.entry_remaining_notes), entry.notes)
                }
            }
                } // fields item
            }

            // ── MULTILINE 备注平铺：标题行 + 逐块 items ──
            fun mdBlockBase(targetToken: String): Int? {
                var count = 1 + if (hasFieldsCard) 2 else 0 // hero + 可选 gap + fields
                for ((module, _) in multilineNotes) {
                    val token = markdownModuleToken(module)
                    count += 1 // header item
                    if (token == targetToken) return count
                    multilineParsedSpecs[token]?.let { count += it.second.size }
                }
                return null
            }
            for ((module, _) in multilineNotes) {
                val token = markdownModuleToken(module)
                item(key = "mdh:$token", contentType = "mdHeader") {
                    val type = EntryModules.primitive(module["type"])
                    val spec = EntryModules.catalog[type]
                    val storedTitle = EntryModules.primitive(module["title"]).ifEmpty { "模块" }
                    val titleText = if (storedTitle == spec?.title || storedTitle == "模块") uiText(storedTitle) else storedTitle
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp)
                            .background(
                                color = MaterialTheme.colorScheme.surface,
                                shape = VaultTopShape,
                            )
                            .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 4.dp),
                    ) {
                        Text(
                            titleText,
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.weight(1f),
                        )
                        DetailActionIconButton(
                            iconRes = R.drawable.ic_action_copy_custom,
                            contentDescription = uiText("复制 $titleText"),
                            onClick = { copySensitive(ctxForBadge, titleText, EntryModules.primitive(module["value"])) },
                        )
                    }
                }
                val parsed = multilineParsedSpecs[token]
                if (parsed == null) {
                    item(key = "mdl:$token", contentType = "mdLoading") {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 96.dp)
                                .background(
                                    color = MaterialTheme.colorScheme.surface,
                                    shape = VaultBottomShape,
                                )
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        }
                    }
                } else {
                    val (_, specs) = parsed
                    if (specs.isEmpty()) {
                        item(key = "mde:$token", contentType = "mdEmpty") {
                            Spacer(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(8.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.surface,
                                        shape = VaultBottomShape,
                                    ),
                            )
                        }
                    } else {
                        markdownBlockItems(
                            specs = specs,
                            keyPrefix = "md$token",
                            registry = markdownRegistry,
                            controller = jumpController,
                            listState = detailScrollState,
                            basePosForPrefix = { target -> mdBlockBase(target.removePrefix("md")) },
                            surfaceColor = markdownSurfaceColor,
                            attachToPrevious = true,
                        )
                    }
                }
            }

            // 图片：卡证（正反面影像）
            val imageKey: String? = when (entry.secretType) {
                SecretType.CARD_DOCUMENT -> "card_images_b64"
                else -> null
            }
            if (imageKey != null) {
                val imgs = parseImageList(entry.fields[imageKey])
                if (imgs.isNotEmpty()) {
                    item(key = "images", contentType = "images") {
                        Column {
                            Spacer(Modifier.height(12.dp))
                            Text(
                                uiText("证件照片"),
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                            )
                            Spacer(Modifier.height(6.dp))
                            LazyRow(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                itemsIndexed(imgs) { imageIndex, b64 ->
                                    GuardedImageCard(
                                        b64 = b64,
                                        images = imgs,
                                        index = imageIndex,
                                        masterVerified = masterVerified,
                                        blurEnabled = photoBlurEnabled,
                                        protectionRequired = guarded,
                                        onRequestVerify = { gate(it) },
                                        setExternalActionInProgress = setExternalActionInProgress,
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item(key = "meta") {
                Column {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "${stringResource(R.string.entry_remaining_created)} ${formatTs(entry.createdAt)}   ·   ${uiText("修改")} ${formatTs(entry.updatedAt)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    )
                    Spacer(Modifier.height(24.dp))
                }
            }
        }
            // 底部操作悬浮：内容层覆盖（整屏居中，不占 FAB 槽）；
            // 避让小横条用与列表一致的 Scaffold insets（pad）而非 navigationBarsPadding，
            // 避免手势条区域被按钮遮挡。
            Box(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .padding(start = 16.dp, end = 16.dp, bottom = pad.calculateBottomPadding() + 28.dp),
                contentAlignment = Alignment.Center,
            ) {
                Row(
                    modifier = Modifier.vaultBottomActionWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (entry.secretType != SecretType.PASSKEY) {
                        VaultFloatingBar(
                            modifier = Modifier.weight(1f),
                            onClick = { gate { onEdit() } },
                            containerColor = popupMenuSurface(),
                            contentColor = MaterialTheme.colorScheme.primary,
                            // 左右各加宽 18
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp),
                        ) {
                            Icon(Icons.Default.Edit, null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(uiText("编辑"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    VaultFloatingBar(
                        modifier = Modifier.weight(1f),
                        onClick = { gate { confirmDelete = true } },
                        containerColor = popupMenuSurface(),
                        contentColor = MaterialTheme.colorScheme.error,
                        // 左右各加宽：与编辑同排时每侧 +18；独立删除(Passkey)每侧 +28
                        contentPadding = PaddingValues(
                            horizontal = 8.dp,
                            vertical = 10.dp,
                        ),
                    ) {
                        Icon(Icons.Default.Delete, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(uiText("删除"), style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }

    // 主密码二次验证
    if (pendingAction != null) MasterPasswordDialog(
        reason = stringResource(R.string.entry_remaining_sensitive_verification_reason, typeLabel(entry.secretType)),
        verify = verifyMasterPassword,
        coolingRemainingMs = { LockoutPref.coolingRemainingMs(detailContext) },
        onCancel = { pendingAction = null },
        onSuccess = {
            elevateSecuritySession()
            masterVerified = true
            val action = pendingAction
            pendingAction = null
            action?.invoke()
        },
    )

    if (confirmDelete) VaultDialog(
        onDismissRequest = { confirmDelete = false },
        title = { Text(uiText("移入回收站")) },
        text = { Text("${entry.title} — ${uiText("将移入回收站，可在 30 天内恢复。")}") },
        confirmButton = {
            VaultActionButton(
                onClick = { confirmDelete = false; onDelete() },
                style = VaultActionStyle.DANGER,
            ) { Text(uiText("确认")) }
        },
        dismissButton = {
            VaultActionButton(onClick = { confirmDelete = false }) { Text(uiText("取消")) }
        },
    )
}

//---详情字段可见性---

/**
 * 判断非 Markdown 模块是否会在 ModuleRows 中产生可见内容。
 *
 * @param module 条目模块。
 * @return true 表示该模块会产生至少一个可见组件。
 */
private fun hasRenderableModuleContent(module: JsonObject): Boolean {
    val type = EntryModules.primitive(module["type"])
    if (type == ModuleType.MULTILINE) return false
    if (EntryModules.catalog[type] == null || type == ModuleType.PASSKEY) return true

    return when (val value = module["value"]) {
        is JsonObject -> true
        is JsonArray -> {
            if (type == ModuleType.ATTACHMENTS) {
                value.any { it is JsonObject }
            } else {
                value.any { mediaValueString(it)?.isNotEmpty() == true }
            }
        }
        is JsonPrimitive -> type == ModuleType.BOOLEAN || value.contentOrNull?.isNotEmpty() == true
        else -> false
    }
}

/**
 * 判断详情页字段卡片中是否存在真实可见内容。
 *
 * @param entry 当前条目。
 * @param autofillSourceOptions 自动填充关联候选。
 * @return true 表示需要创建字段卡片。
 */
private fun hasVisibleFieldsCard(entry: Entry, autofillSourceOptions: List<Entry>): Boolean {
    if (entry.notes.isNotEmpty()) return true
    if (entry.detailModules().any(::hasRenderableModuleContent)) return true

    return when (entry.secretType) {
        SecretType.LOGIN -> {
            entry.username.isNotEmpty() ||
                entry.password.isNotEmpty() ||
                entry.url.isNotEmpty() ||
                entry.associatedAppPackage().isNotEmpty() ||
                linkedAutofillDetailGroups(entry, autofillSourceOptions).isNotEmpty() ||
                detailOtpSource(entry, autofillSourceOptions) != null
        }
        SecretType.CARD_DOCUMENT -> true
        SecretType.WIFI -> {
            entry.getStringField("ssid").isNotEmpty() ||
                entry.getStringField("wifi_password").isNotEmpty() ||
                entry.getStringField("password").isNotEmpty() ||
                entry.getStringField("security_type").isNotEmpty() ||
                entry.getStringField("router_admin_url").isNotEmpty() ||
                entry.getStringField("admin_password").isNotEmpty()
        }
        SecretType.API_KEY -> {
            entry.getStringField("service").isNotEmpty() ||
                entry.username.isNotEmpty() ||
                entry.getStringField("api_key").isNotEmpty() ||
                entry.password.isNotEmpty() ||
                entry.getStringField("api_secret").isNotEmpty() ||
                entry.getStringField("base_url").isNotEmpty() ||
                entry.getStringField("scopes").isNotEmpty()
        }
        SecretType.OTP -> entry.otpDisplaySnapshot() != null
        SecretType.SECURE_NOTE -> {
            entry.getStringField("note").isNotEmpty() ||
                entry.entryModules().any { module ->
                    EntryModules.primitive(module["type"]) == ModuleType.MULTILINE &&
                        EntryModules.primitive(module["value"]).isNotEmpty()
                }
        }
        SecretType.SERVER -> {
            val serverModule = entry.entryModules()
                .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.SERVER_CONNECTION }
            val serverValue = serverModule?.get("value") as? JsonObject
            entry.getStringField("server_host").isNotEmpty() ||
                entry.getStringField("server_port").isNotEmpty() ||
                entry.getStringField("server_user").isNotEmpty() ||
                entry.getStringField("server_pass").isNotEmpty() ||
                serverValue?.let { value ->
                    EntryModules.primitive(value["host"]).isNotEmpty() ||
                        EntryModules.primitive(value["port"]).isNotEmpty() ||
                        EntryModules.primitive(value["username"]).isNotEmpty() ||
                        EntryModules.primitive(value["password"]).isNotEmpty()
                } == true
        }
        else -> false
    }
}

@Composable
private fun cardTypeDisplayLabel(value: String): String = when (value) {
    "银行卡" -> stringResource(R.string.entry_remaining_card_type_bank)
    "身份证" -> stringResource(R.string.entry_remaining_id_type_identity)
    "其他卡证", "自定义" -> stringResource(R.string.entry_remaining_card_type_custom)
    "会员卡" -> stringResource(R.string.entry_remaining_card_type_membership)
    "社保卡" -> stringResource(R.string.entry_remaining_card_type_social_security)
    else -> value
}

@Composable
private fun ModuleRows(
    entry: Entry,
    gate: ((() -> Unit) -> Unit),
    masterVerified: Boolean,
    photoBlurEnabled: Boolean,
    protectionRequired: Boolean,
    setExternalActionInProgress: (Boolean) -> Unit,
    skipMultilineTokens: Set<String>,
) {
    val ctx = LocalContext.current
    val labels = mapOf(
        "username" to "用户名", "password" to "密码", "api_key" to "API Key", "api_secret" to "API Secret",
        "ssid" to "SSID", "wifi_password" to "Wi-Fi 密码", "admin_password" to "管理密码", "host" to "主机 / IP", "port" to "端口",
        "security_type" to "加密类型", "router_admin_url" to "路由器管理地址", "engine" to "数据库引擎",
        "private_key" to "私钥", "fingerprint" to "指纹", "database" to "数据库名", "secret" to "密钥", "issuer" to "发行方",
        "label" to "账户名", "card_number" to "卡号", "cvv" to "CVV", "id_number" to "证件号码",
        "algorithm" to "算法", "digits" to "位数", "period" to "周期", "type" to "类型", "counter" to "计数器",
        "cardholder" to "持卡人", "withdrawal_password" to "取款密码", "bank" to "银行", "bank_branch" to "分行/支行",
        "card_type" to "卡片类型", "card_name" to uiText("自定义卡证名称"), "notes" to "备注",
        "full_name" to "姓名", "issue_date" to "签发日期", "issuing_authority" to "签发机关",
        "country" to "国家 / 地区", "region" to "省 / 州", "city" to "城市", "address" to "详细地址", "postal_code" to "邮政编码",
        "question" to "安全问题", "answer" to "答案", "expiry" to "有效期", "expiry_date" to "到期日期",
    )
    entry.detailModules().forEach { module ->
        val type = EntryModules.primitive(module["type"])
        // MULTILINE 模块由页面级平铺区（markdownBlockItems）格式化渲染，这里跳过避免重复的裸文本行
        if (type == ModuleType.MULTILINE && markdownModuleToken(module) in skipMultilineTokens) return@forEach
        val spec = EntryModules.catalog[type]
        val storedTitle = EntryModules.primitive(module["title"]).ifEmpty { "模块" }
        val title = if (storedTitle == spec?.title || storedTitle == "模块") uiText(storedTitle) else storedTitle
        if (spec == null) {
            Text(
                uiText("$title：当前版本暂不支持，数据已保留"),
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(vertical = 8.dp),
            )
            return@forEach
        }
        if (type == ModuleType.PASSKEY) {
            val record = PasskeyRecord.parse(module["value"] as? JsonObject ?: JsonObject(emptyMap()))
            val conflict = EntryModules.primitive(
                (module["config"] as? JsonObject)?.get("passkeyConflictStatus"),
            ) == "key_mismatch"
            Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 10.dp))
            if (conflict) {
                Text(uiText("通行密钥存在密钥冲突，已停止使用"), color = MaterialTheme.colorScheme.error)
            } else if (record == null) {
                Text(uiText("通行密钥数据无效，已停止使用"), color = MaterialTheme.colorScheme.error)
            }
            if (record != null) {
                FieldRow(uiText("依赖方域名"), record.rpId, copy = true)
                FieldRow(uiText("账户"), record.userDisplayName.ifEmpty { record.userName })
                val storageMode = when {
                    record.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION -> uiText("待安全升级（旧版软件私钥）")
                    record.keyMode == PasskeyKeyMode.SYNCABLE -> uiText("PMV 同步型")
                    else -> uiText("本设备高安全性")
                }
                FieldRow(uiText("存储模式"), storageMode)
                when (record.keyMode) {
                    PasskeyKeyMode.SYNCABLE -> FieldRow(
                        uiText("备份状态"),
                        if (record.backupState) uiText("已确认同步或备份") else uiText("尚未确认同步或备份"),
                    )
                    PasskeyKeyMode.DEVICE_BOUND -> FieldRow(
                        uiText("可用范围"),
                        record.deviceBinding?.deviceId?.toString()?.take(8)?.let { uiText("仅可在绑定设备 $it 使用") }
                            ?: uiText("设备密钥已丢失"),
                    )
                }
                FieldRow("创建时间", formatPasskeyTimestamp(record.createdAt))
                FieldRow("最后使用", formatPasskeyTimestamp(record.lastUsedAt))
                FieldRow("签名计数", record.signCount.toString())
            }
            return@forEach
        }
        val sensitiveAll = (module["sensitive"] as? JsonPrimitive)?.booleanOrNull == true
        val guardEnabled by com.vault.security.SensitiveGuardPref.enabled
        when (val value = module["value"]) {
            is JsonObject -> {
                Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 10.dp))
                val config = module["config"] as? JsonObject
                val extras = (config?.get("sensitiveFields") as? JsonArray).orEmpty().mapNotNull {
                    (it as? JsonPrimitive)?.contentOrNull
                }.toSet()
                val hidden = spec.mandatorySensitiveFields + extras
                val ordered = EntryModules.orderedValue(module)
                val cardFields = if (type == ModuleType.CARD_DOCUMENT) {
                    EntryModules.cardFieldKeys(EntryModules.primitive(value["card_type"]).ifBlank { EntryModules.CARD_BANK }) - "notes"
                } else emptySet()
                ordered.forEach { (key, raw) ->
                    if (type == ModuleType.CARD_DOCUMENT && key !in cardFields && key != "images") return@forEach
                    if (key == "images" && raw is JsonArray) {
                        val images = raw.mapNotNull(::mediaValueString).filter(String::isNotEmpty)
                        if (images.isNotEmpty()) {
                            Text(uiText("图片"), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                itemsIndexed(images) { imageIndex, b64 ->
                                    GuardedImageCard(
                                        b64 = b64,
                                        images = images,
                                        index = imageIndex,
                                        masterVerified = masterVerified,
                                        blurEnabled = photoBlurEnabled,
                                        protectionRequired = protectionRequired,
                                        onRequestVerify = { gate(it) },
                                        setExternalActionInProgress = setExternalActionInProgress,
                                    )
                                }
                            }
                        }
                    } else {
                        val rawText = (raw as? JsonPrimitive)?.contentOrNull ?: raw.toString().takeUnless { it == "null" }.orEmpty()
                        val text = when {
                            key == "card_type" -> cardTypeDisplayLabel(EntryModules.cardTypeLabels[rawText] ?: rawText)
                            key == "issue_date" || key == "expiry_date" || key == "expiry" -> formatCardDate(rawText)
                            else -> rawText
                        }
                        if (sensitiveAll || key in hidden) PasswordRow(text, labels[key] ?: key, gate = gate)
                        else FieldRow(labels[key] ?: key, text, copy = true)
                    }
                }
            }
            is JsonArray -> {
                if (type == ModuleType.ATTACHMENTS) {
                    val attachments = value.mapNotNull { it as? JsonObject }
                    if (attachments.isNotEmpty()) {
                        val totalBytes = attachments.sumOf { EntryModules.primitive(it["size"]).toLongOrNull() ?: 0L }
                        Text(
                            "$title · ${attachments.size} · ${formatAttachmentSize(totalBytes)}",
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 10.dp),
                        )
                        AttachmentRows(attachments, gate, setExternalActionInProgress)
                    }
                    return@forEach
                }
                val images = value.mapNotNull(::mediaValueString)
                if (images.isNotEmpty()) {
                    Text(title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 10.dp))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        itemsIndexed(images) { imageIndex, b64 ->
                            GuardedImageCard(
                                b64 = b64,
                                images = images,
                                index = imageIndex,
                                masterVerified = masterVerified,
                                blurEnabled = photoBlurEnabled,
                                protectionRequired = protectionRequired,
                                onRequestVerify = { gate(it) },
                                setExternalActionInProgress = setExternalActionInProgress,
                            )
                        }
                    }
                }
            }
            else -> {
                val rawText = (value as? JsonPrimitive)?.contentOrNull.orEmpty()
                val text = if (type == ModuleType.BOOLEAN) uiText(if (rawText == "true") "是" else "否") else rawText
                // 日期时间模块的线缆格式为 yyyy-MM-ddTHH:mm，详情展示改用空格以免暴露 ISO 分隔符
                val displayValue = if (type == ModuleType.DATETIME && rawText.contains('T')) rawText.replace('T', ' ') else text
                if (sensitiveAll) {
                    PasswordRow(displayValue, title, gate = gate)
                } else {
                    FieldRow(title, displayValue, copy = true)
                }
            }
        }
    }
}

internal fun detailOtpSource(entry: Entry, sourceOptions: List<Entry>): Entry? {
    val linked = entry.autofillLinks().asSequence().flatMap { link ->
        link.fields.asSequence().map { field -> link.sourceEntryId to field }
    }.firstOrNull { (_, field) -> field.role == AutofillRole.ONE_TIME_CODE }
    if (linked != null) {
        val (sourceId, field) = linked
        val source = sourceOptions.firstOrNull { it.id == sourceId && it.deletedAt == null } ?: return null
        val moduleId = field.moduleId ?: return source.takeIf(Entry::hasOtp)
        val module = source.entryModules().firstOrNull {
            EntryModules.primitive(it["id"]) == moduleId &&
                EntryModules.primitive(it["type"]) == ModuleType.OTP
        } ?: return null
        return source.withEntryModules(listOf(module))
    }
    return entry.takeIf(Entry::hasOtp)
        ?: entry.otpBindingId()?.let { boundId -> sourceOptions.firstOrNull { it.id == boundId && it.hasOtp() } }
}

internal data class LinkedAutofillDetailGroup(
    val sourceEntryId: String,
    val source: Entry?,
    val roles: List<AutofillRole>,
)

internal fun linkedAutofillDetailGroups(
    entry: Entry,
    sourceOptions: List<Entry>,
): List<LinkedAutofillDetailGroup> {
    val sourcesById = sourceOptions.filter { it.deletedAt == null }.associateBy(Entry::id)
    return entry.autofillLinks()
        .groupBy { it.sourceEntryId }
        .map { (sourceEntryId, links) ->
            LinkedAutofillDetailGroup(
                sourceEntryId = sourceEntryId,
                source = sourcesById[sourceEntryId],
                roles = links.flatMap { it.fields }.map { it.role }.distinct(),
            )
        }
}

@Composable
private fun LinkedAutofillDetails(
    groups: List<LinkedAutofillDetailGroup>,
    gate: ((() -> Unit) -> Unit),
    onOpenSource: (Entry) -> Unit,
) {
    Spacer(Modifier.height(12.dp))
    Text(
        uiText("关联自动填充内容"),
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
    )
    Spacer(Modifier.height(8.dp))
    groups.forEachIndexed { index, group ->
        val source = group.source
        val roleLabels = group.roles.map { role -> autofillLinkRoleLabel(role) }.joinToString("、")
        val sourceCategory = source?.let { categoryLabel(it.secretType) }
        Surface(
            shape = VaultShape,
            color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f),
            modifier = Modifier
                .fillMaxWidth()
                .clip(VaultShape)
                .clickable(enabled = source != null) { source?.let(onOpenSource) },
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(
                            source?.let { categoryIconBackground(it.secretType).copy(alpha = 0.16f) }
                                ?: MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    if (source != null) {
                        Icon(
                            painterResource(categoryIconRes(source.secretType)),
                            contentDescription = null,
                            tint = Color.Unspecified,
                            modifier = Modifier.size(20.dp),
                        )
                    } else {
                        Icon(
                            Icons.Default.Link,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp),
                        )
                    }
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        source?.title?.ifBlank { uiText("未命名条目") } ?: uiText("来源不可用"),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                    Text(
                        buildString {
                            if (sourceCategory != null) append(sourceCategory).append(" · ")
                            append(roleLabels)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (source != null) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = uiText("查看详情"),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
        if (index != groups.lastIndex) Spacer(Modifier.height(8.dp))
    }
}

private fun markdownModuleToken(module: JsonObject): String =
    EntryModules.primitive(module["id"]).ifBlank {
        "${EntryModules.primitive(module["type"])}:${module.hashCode()}"
    }

@Composable
private fun AttachmentRows(
    attachments: List<JsonObject>,
    gate: ((() -> Unit) -> Unit),
    setExternalActionInProgress: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    var pending by remember { mutableStateOf<JsonObject?>(null) }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        setExternalActionInProgress(false)
        val item = pending
        pending = null
        if (uri != null && item != null) runCatching {
            exportAttachmentToUri(
                context = context,
                dataRefOrBase64 = mediaValueString(item["data"]),
                target = uri,
            )
        }.onSuccess {
            Toast.makeText(context, context.getString(R.string.entry_remaining_attachment_exported), Toast.LENGTH_SHORT).show()
        }.onFailure {
            val message = when (it) {
                is PmvMediaSessionLockedException -> context.getString(R.string.system_media_session_locked)
                else -> context.getString(R.string.entry_remaining_export_failed, it.message ?: "")
            }
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }
    }
    attachments.forEach { item ->
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Column(Modifier.weight(1f)) {
                val name = EntryModules.primitive(item["name"]).ifBlank { "attachment.bin" }
                val size = EntryModules.primitive(item["size"]).toLongOrNull() ?: 0L
                val mime = EntryModules.primitive(item["mime"]).ifBlank { "application/octet-stream" }
                Text(name, style = MaterialTheme.typography.bodyLarge)
                Text(
                    "${formatAttachmentSize(size)} · $mime",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            DetailActionIconButton(
                iconRes = R.drawable.ic_action_download_custom,
                contentDescription = uiText("下载附件"),
                onClick = {
                    gate {
                        pending = item
                        setExternalActionInProgress(true)
                        exporter.launch(EntryModules.primitive(item["name"]).ifBlank { "attachment.bin" })
                    }
                },
            )
        }
    }
}

private fun formatAttachmentSize(bytes: Long): String = when {
    bytes >= 1024L * 1024L -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    bytes >= 1024L -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FieldRow(label: String, value: String, copy: Boolean = false, leaked: Boolean = false) {
    if (value.isEmpty()) return
    val ctx = LocalContext.current
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {},
                onLongClick = { copySensitive(ctx, label, value) },
            )
            .padding(vertical = 10.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                uiText(label),
                style = MaterialTheme.typography.labelMedium,
                color = if (leaked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
        if (copy) DetailActionIconButton(
            iconRes = R.drawable.ic_action_copy_custom,
            contentDescription = uiText("复制 $label"),
            onClick = { copySensitive(ctx, label, value) },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun PasswordRow(
    value: String,
    label: String = "密码",
    copyable: Boolean = true,
    leaked: Boolean = false,
    gate: ((() -> Unit) -> Unit) = { it() },
) {
    if (value.isEmpty()) return
    val ctx = LocalContext.current
    var revealed by remember { mutableStateOf(false) }
    LaunchedEffect(revealed) {
        if (revealed) {
            val sec = AutoHidePref.seconds.value
            if (sec > 0) {
                delay(sec * 1000L)
                revealed = false
            }
        }
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = {},
                onLongClick = { gate { copySensitive(ctx, label, value) } },
            )
            .padding(vertical = 10.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                uiText(label),
                style = MaterialTheme.typography.labelMedium,
                color = if (leaked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                if (revealed) value else "••••••",
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.combinedClickable(
                    onClick = {
                        if (revealed) revealed = false
                        else gate { revealed = true }
                    },
                    onLongClick = { gate { copySensitive(ctx, label, value) } },
                ),
            )
        }
        DetailActionIconButton(
            iconRes = if (revealed) R.drawable.ic_action_eye_off_custom else R.drawable.ic_action_eye_custom,
            contentDescription = uiText("显隐"),
            onClick = {
                if (revealed) revealed = false
                else gate { revealed = true }
            },
        )
        // CVV / 取款密码 等短码不提供复制（用户体验上手动输入更快、也避免误粘到表单）
        if (copyable) {
            DetailActionIconButton(
                iconRes = R.drawable.ic_action_copy_custom,
                contentDescription = uiText("复制"),
                onClick = { gate { copySensitive(ctx, label, value) } },
            )
        }
    }
}

@Composable
private fun DetailActionIconButton(
    iconRes: Int,
    contentDescription: String,
    onClick: () -> Unit,
) {
    IconButton(
        onClick = onClick,
        modifier = Modifier.size(40.dp),
    ) {
        Icon(
            painter = painterResource(iconRes),
            contentDescription = contentDescription,
            tint = Color.Unspecified,
            modifier = Modifier.size(21.dp),
        )
    }
}

/** OTP 动态码显示组件：每秒刷新一次，带倒计时进度条 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun OTPCodeDisplay(entry: Entry, gate: ((() -> Unit) -> Unit)) {
    var snapshot by remember(entry.id, entry.updatedAt) { mutableStateOf(entry.otpDisplaySnapshot()) }
    // 密钥缺失或条目遮蔽时静默隐藏，不展示「密钥」行。
    if (snapshot == null) return

    LaunchedEffect(entry.id, entry.updatedAt) {
        while (true) {
            val now = System.currentTimeMillis()
            snapshot = entry.otpDisplaySnapshot(now / 1000)
            delay(1000 - now % 1000)
        }
    }

    val current = snapshot ?: return
    val ctx = LocalContext.current

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
        Text(
            uiText("动态码"),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        if (current.issuer.isNotEmpty() || current.label.isNotEmpty()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (current.issuer.isNotEmpty()) {
                    Text(current.issuer, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (current.label.isNotEmpty()) Text(" · ", style = MaterialTheme.typography.labelMedium)
                }
                if (current.label.isNotEmpty()) {
                    Text(current.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                current.code,
                style = MaterialTheme.typography.displaySmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .weight(1f)
                    .combinedClickable(
                        onClick = {},
                        onLongClick = { gate { copySensitive(ctx, "动态码", current.code) } },
                    ),
            )
            DetailActionIconButton(
                iconRes = R.drawable.ic_action_copy_custom,
                contentDescription = uiText("复制动态码"),
                onClick = { gate { copySensitive(ctx, "动态码", current.code) } },
            )
        }

        val algorithmLabel = current.algorithm.replace("SHA", "SHA-")
        val detail = if (current.type == "totp") {
            stringResource(R.string.entry_remaining_totp_summary, algorithmLabel, current.digits, current.period)
        } else {
            stringResource(R.string.entry_remaining_hotp_summary, algorithmLabel, current.digits, current.counter)
        }
        Text(
            detail,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (current.type == "totp") {
            Spacer(Modifier.height(8.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(current.progress)
                        .fillMaxHeight()
                        .clip(RoundedCornerShape(2.dp))
                        .background(MaterialTheme.colorScheme.primary),
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                uiText("${current.remaining}秒"),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * 二次保护独立控制验证权限；图像模糊开关只控制详情页缩略图。
 * 通过验证后可打开原图查看器，缩略图仍遵循始终模糊设置。
 */
@Composable
private fun GuardedImageCard(
    b64: String,
    images: List<String>,
    index: Int,
    masterVerified: Boolean,
    blurEnabled: Boolean,
    protectionRequired: Boolean,
    onRequestVerify: (() -> Unit) -> Unit,
    setExternalActionInProgress: (Boolean) -> Unit = {},
) {
    val ctx = LocalContext.current
    val presentation = photoPresentation(protectionRequired, masterVerified, blurEnabled)
    val locked = presentation.locked
    var showViewer by remember { mutableStateOf(false) }
    val exportInfo = remember(b64) { imageExportInfo(ctx, b64) }
    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(exportInfo.mime)
    ) { uri ->
        setExternalActionInProgress(false)
        if (uri != null) saveImageToUri(ctx, b64, uri)
    }

    val imgInteractionSource = remember { MutableInteractionSource() }
    val imgPressed by imgInteractionSource.collectIsPressedAsState()
    val imgScale by animateFloatAsState(
        targetValue = if (imgPressed) 0.97f else 1f,
        animationSpec = spring(dampingRatio = 0.7f),
        label = "imgScale",
    )
    Box(
        modifier = Modifier
            .scale(imgScale)
            .size(220.dp, 160.dp)
            .clip(VaultShape)
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(
                interactionSource = imgInteractionSource,
                indication = LocalIndication.current,
            ) {
                if (locked) onRequestVerify { showViewer = true }
                else showViewer = true
            },
    ) {
        if (showViewer) ImageViewerDialog(images = images, initialIndex = index, onClose = { showViewer = false })
        Base64Image(
            b64 = b64,
            maxDecodePx = 512,
            modifier = Modifier
                .fillMaxSize()
                .then(if (presentation.blurred) Modifier.blur(18.dp) else Modifier),
        )
        if (locked) {
            Box(
                modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.45f)),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.Lock, null, tint = MaterialTheme.colorScheme.inverseOnSurface, modifier = Modifier.size(28.dp))
                    Spacer(Modifier.height(4.dp))
                    Text(
                        uiText("点击验证主密码查看"),
                        color = MaterialTheme.colorScheme.inverseOnSurface,
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
            }
        } else {
            if (presentation.blurred) {
                Box(
                    modifier = Modifier
                        .align(Alignment.Center)
                        .size(40.dp)
                        .clip(androidx.compose.foundation.shape.CircleShape)
                        .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_action_eye_custom),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(22.dp),
                    )
                }
            }
            // 右下操作栏：复制 / 保存 — 深底 + 高亮自定义图标；已调小整体尺寸
            Row(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(6.dp)
                    .clip(VaultShape)
                    .background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.85f))
                    .padding(horizontal = 4.dp, vertical = 3.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = { copyImageToClipboard(ctx, b64) }, modifier = Modifier.size(28.dp)) {
                    Icon(
                        painterResource(R.drawable.ic_action_copy_custom), stringResource(R.string.entry_remaining_copy_image),
                        tint = androidx.compose.ui.graphics.Color.White,
                        modifier = Modifier.size(16.dp),
                    )
                }
                IconButton(
                    onClick = {
                        setExternalActionInProgress(true)
                        saveLauncher.launch("image_${System.currentTimeMillis()}.${exportInfo.extension}")
                    },
                    modifier = Modifier.size(28.dp),
                ) {
                    Icon(
                        painterResource(R.drawable.ic_action_download_custom), stringResource(R.string.entry_remaining_save_image),
                        tint = androidx.compose.ui.graphics.Color.White,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}

/** 带圆角背景和按压缩放动效的图标按钮。 */

@Composable
private fun BadgeChip(text: String, color: androidx.compose.ui.graphics.Color) {
    Box(
        modifier = Modifier
            .clip(VaultShape)
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(text, color = color, style = MaterialTheme.typography.labelSmall)
    }
}

private fun formatTs(ts: Double): String {
    if (ts <= 0.0) return "—"
    val dt = Instant.ofEpochMilli((ts * 1000).toLong()).atZone(ZoneId.systemDefault())
    return dt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"))
}

internal fun formatPasskeyTimestamp(value: String, zoneId: ZoneId = ZoneId.systemDefault()): String {
    if (value.isEmpty()) return value
    val normalized = value.replace('t', 'T').let {
        if (it.endsWith('z')) it.dropLast(1) + "Z" else it
    }
    return runCatching {
        OffsetDateTime.parse(normalized, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            .atZoneSameInstant(zoneId)
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
    }.getOrDefault(value)
}

private fun formatLeakCount(count: Int): String =
    if (count > 9_999_999) "9999999+" else count.coerceAtLeast(0).toString()
