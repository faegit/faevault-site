package com.vault.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.vault.R
import com.vault.model.Entry
import com.vault.model.autofill.AutofillRole
import com.vault.model.OtpDisplaySnapshot
import com.vault.model.SecretType
import com.vault.model.otpBindingId
import com.vault.model.otpDisplaySnapshot
import com.vault.model.otpIsHotp
import com.vault.security.BiometricVault
import com.vault.ui.FAEVaultTheme
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.TypeColors
import com.vault.ui.VaultChooserList
import com.vault.ui.VaultUnlockCard
import com.vault.ui.VaultUnlockLoading
import com.vault.ui.VaultUnlockPanel
import com.vault.ui.uiText
import com.vault.ui.vaultDialogInsetColor
import com.vault.ui.screens.PasswordGeneratorDialog
import com.vault.ui.screens.VaultActionStyle
import com.vault.ui.screens.VaultDialog
import java.util.UUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import com.vault.ui.VaultShape
import com.vault.ui.VaultCornerRadius

class AutofillAuthActivity : FragmentActivity() {
    private lateinit var gateway: AutofillVaultGateway
    private var activeSession: AutofillVaultSession? = null
    private var activeOrigin: TargetOrigin? = null
    private var requestToken: String? = null
    private var removeTaskOnFinish = false
    private var requestFinished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 冷启动补齐「当前保险库」命名空间：进程被系统回收后由自动填充框架直接唤起时，
        // CurrentVaultKey 尚未安装，会回退 DEFAULT 导致排除列表 / 锁定时长 / Passkey 模式
        // 等按账户隔离的偏好解析到错误账户。
        com.vault.security.CurrentVaultKey.install(
            com.vault.storage.VaultRegistry(this).current()
                ?: com.vault.security.CurrentVaultKey.DEFAULT,
        )
        setFinishOnTouchOutside(false)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        gateway = AutofillVaultGateway(
            AndroidAutofillVaultDataSource(this),
            AndroidAutofillAttemptPolicy(this),
            excludeFilter = { origin -> AutofillExcludePref.isExcluded(this, origin) },
            appNameResolver = { AppNameResolver.label(this, it) },
            exclusionRulesResolver = { vaultName -> AutofillExcludePref.snapshot(this, vaultName) },
        )
        val token = intent.getStringExtra(EXTRA_REQUEST_TOKEN)
        requestToken = token
        val request = SaveRequestIntentTransport.read(intent)
            ?: token?.let(AutofillRequestStore::peek)
        removeTaskOnFinish = request is PendingAutofillRequest.Save
        if (request == null) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        activeOrigin = request.form.origin
        if (gateway.isOriginExcluded(request.form.origin)) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        setContent {
            FAEVaultTheme {
                AutofillAuthContent(request)
            }
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) com.vault.ui.sweepClipboardOnForeground(this)
    }

    @Composable
    private fun AutofillAuthContent(request: PendingAutofillRequest) {
        val vaults = remember { gateway.listVaults() }
        var selectedVault by remember { mutableStateOf(vaults.singleOrNull()) }
        var session by remember { mutableStateOf<AutofillVaultSession?>(null) }
        var password by remember { mutableStateOf("") }
        var message by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        var retrySeconds by remember { mutableIntStateOf(0) }
        var biometricAttemptedFor by remember { mutableStateOf<String?>(null) }
        var unlockSuccess by remember { mutableStateOf(false) }
        var otpWaiting by remember { mutableStateOf(false) }
        var dismissConfirmationVisible by remember { mutableStateOf(false) }
        val scope = rememberCoroutineScope()

        // 用户在多账户选择器中切换到某个账户后，让排除列表 / 锁定计数等偏好跟随所选账户。
        LaunchedEffect(selectedVault) {
            selectedVault?.let { com.vault.security.CurrentVaultKey.install(it) }
        }

        fun requestDismiss() {
            dismissConfirmationVisible = true
        }

        fun acceptAuth(result: VaultAuthResult) {
            busy = false
            when (result) {
                is VaultAuthResult.Success -> {
                    if (gateway.isOriginExcluded(request.form.origin, result.session)) {
                        result.session.clear()
                        finishRequest(AutofillSaveCompletion.DISMISSED)
                        return
                    }
                    activeSession?.clear()
                    activeSession = result.session
                    password = ""
                    message = ""
                    unlockSuccess = true
                    scope.launch {
                        delay(800)
                        session = result.session
                        unlockSuccess = false
                    }
                }
                is VaultAuthResult.CoolingDown -> {
                    retrySeconds = ((result.remainingMs + 999) / 1000).toInt()
                    message = getString(R.string.system_auth_attempts_cooldown)
                }
                is VaultAuthResult.WrongPassword -> {
                    retrySeconds = ((result.failure.retryDelayMs + 999) / 1000).toInt()
                    message = if (result.failure.cooldownMs > 0) getString(R.string.system_auth_attempts_cooling)
                    else getString(R.string.system_auth_wrong_password_remaining, result.failure.remainingAttempts)
                }
                VaultAuthResult.MissingVault -> message = getString(R.string.system_auth_vault_missing_deleted)
                is VaultAuthResult.Failure -> message = getString(result.code.messageRes())
            }
        }

        fun authenticateWithPassword() {
            val vault = selectedVault ?: return
            if (password.isEmpty() || retrySeconds > 0) return
            busy = true
            val chars = password.toCharArray()
            lifecycleScope.launch(Dispatchers.IO) {
                acceptAuth(gateway.authenticate(vault, chars))
            }
        }

        fun authenticateWithBiometric(vault: String) {
            val bio = BiometricVault(this, vault)
            if (!bio.isEnrolled() || !bio.canAuthenticate(this)) return
            busy = true
            lifecycleScope.launch {
                runCatching { bio.unlock(this@AutofillAuthActivity) }
                    .onSuccess { material ->
                        try {
                            material.withSecret(material.binding) { deviceKey ->
                                acceptAuth(gateway.authenticateWithDeviceKey(vault, deviceKey, material.binding))
                            }
                        } finally {
                            material.close()
                        }
                    }
                    .onFailure { error ->
                        busy = false
                        if (error is BiometricVault.BiometricKeyInvalidated) {
                            message = getString(R.string.system_auth_biometric_invalidated)
                        } else if (error !is BiometricVault.BiometricCancelled) {
                            message = getString(R.string.system_auth_biometric_unavailable)
                        }
                    }
            }
        }

        LaunchedEffect(retrySeconds) {
            if (retrySeconds > 0) {
                delay(1_000)
                retrySeconds--
            }
        }
        LaunchedEffect(selectedVault, session) {
            val vault = selectedVault
            if (session == null && vault != null && biometricAttemptedFor != vault
                && (request is PendingAutofillRequest.Save || request is PendingAutofillRequest.Fill)
            ) {
                biometricAttemptedFor = vault
                authenticateWithBiometric(vault)
            }
        }

        // Auto-fill on single match — before UI renders
        val exactFill = remember(session, request) {
            val s = session
            if (s != null && request is PendingAutofillRequest.Fill) {
                val r = request as PendingAutofillRequest.Fill
                val mm = gateway.findMatches(s, r.form.origin)
                val singleId = mm.map { it.entryId }.distinct().singleOrNull()
                singleId?.let { id -> gateway.entry(s, id) }
                    ?.let { entry -> r to entry }
            } else null
        }
        LaunchedEffect(exactFill) {
            exactFill?.let { (r, entry) ->
                val hasOtpField = r.form.fields.any { it.kind == FieldKind.OTP }
                val otpSource = gateway.otpSourceRef(session!!, entry)
                if (hasOtpField && otpSource != null) {
                    val computationEntry = otpSource.computationEntry()
                    val code = OtpAutofill.computeFillCode(computationEntry) { delay(it) }
                    if (code != null && computationEntry.otpIsHotp()) {
                        gateway.advanceOtpCounter(session!!, otpSource)
                    }
                    finishFill(r, session!!, entry, code)
                } else {
                    finishFill(r, session!!, entry, null)
                }
            }
        }
        if (exactFill != null) return

        fun pickEntry(request: PendingAutofillRequest.Fill, session: AutofillVaultSession, entry: Entry) {
            if (gateway.isOriginExcluded(request.form.origin, session)) {
                finishRequest(AutofillSaveCompletion.DISMISSED)
                return
            }
            (request.form.origin as? TargetOrigin.AndroidPackage)?.let { origin ->
                gateway.upgradeLegacyAndroidBinding(session, entry.id, origin)
            }
            val hasOtpField = request.form.fields.any { it.kind == FieldKind.OTP }
            val otpSource = gateway.otpSourceRef(session, entry)
            if (!hasOtpField || otpSource == null) {
                finishFill(request, session, entry, null)
                return
            }
            otpWaiting = true
            scope.launch {
                val computationEntry = otpSource.computationEntry()
                val code = OtpAutofill.computeFillCode(computationEntry) { delay(it) }
                if (code != null && computationEntry.otpIsHotp()) {
                    gateway.advanceOtpCounter(session, otpSource)
                }
                otpWaiting = false
                finishFill(request, session, entry, code)
            }
        }

        BackHandler { requestDismiss() }
        VaultUnlockCard(
            title = if (request is PendingAutofillRequest.Fill) uiText("从保险库填充") else uiText("保存到保险库"),
            originText = request.form.origin.displayName(),
            onClose = ::requestDismiss,
        ) {
            when {
                vaults.isEmpty() -> Text(
                    uiText("尚未创建保险库，请先打开保险库应用完成设置。"),
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                selectedVault == null -> VaultChooserList(vaults) { selectedVault = it }
                unlockSuccess -> VaultUnlockLoading(isComplete = true)
                session == null -> {
                    val vault = selectedVault!!
                    if (busy) {
                        VaultUnlockLoading(isComplete = false)
                    } else {
                        VaultUnlockPanel(
                            vaultName = vault,
                            password = password,
                            onPasswordChange = { password = it },
                            message = message,
                            busy = busy,
                            retrySeconds = retrySeconds,
                            hasBiometric = runCatching {
                                val bio = BiometricVault(this@AutofillAuthActivity, vault)
                                bio.isEnrolled() && bio.canAuthenticate(this@AutofillAuthActivity)
                            }.getOrDefault(false),
                            onUnlock = ::authenticateWithPassword,
                            onBiometric = { authenticateWithBiometric(vault) },
                            onSwitch = { selectedVault = null },
                        )
                    }
                }
                request is PendingAutofillRequest.Fill -> {
                    if (otpWaiting) {
                        Text(
                            uiText("正在获取动态码…"),
                            modifier = Modifier.fillMaxWidth(),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center,
                        )
                    } else {
                        FillFlow(
                            request, session!!,
                            onPick = { entry -> pickEntry(request, session!!, entry) },
                        )
                    }
                }
                request is PendingAutofillRequest.Save -> SaveChooser(request, session!!)
            }
        }
        if (dismissConfirmationVisible) {
            VaultDialog(
                onDismissRequest = { dismissConfirmationVisible = false },
                title = uiText("确认关闭"),
                text = uiText("关闭后可能暂时无法再次唤起自动填充窗口。"),
                confirmText = uiText("确认关闭"),
                onConfirm = { finishRequest(AutofillSaveCompletion.DISMISSED) },
                confirmStyle = VaultActionStyle.DANGER,
                dismissText = uiText("继续自动填充"),
                onDismiss = { dismissConfirmationVisible = false },
            )
        }
    }


@Composable
    private fun FillFlow(
        request: PendingAutofillRequest.Fill,
        session: AutofillVaultSession,
        onPick: (Entry) -> Unit,
    ) {
        FillChooser(request, session, onPick)
    }

    @Composable
    private fun FillChooser(
        request: PendingAutofillRequest.Fill,
        session: AutofillVaultSession,
        onPick: (Entry) -> Unit,
    ) {
        var query by remember { mutableStateOf("") }
        var showPasswordGenerator by remember { mutableStateOf(false) }
        val eligible = remember(session, request) {
            gateway.findFillCandidates(session, request.form.origin)
        }
        val hasOtpField = request.form.fields.any { it.kind == FieldKind.OTP }
        val candidates = remember(session, request, hasOtpField, eligible) {
            if (hasOtpField) {
                OtpAutofill.mergeCandidates(eligible, gateway.findOtpEntries(session, request.form.origin))
            } else eligible
        }
        val matchedIds = remember(eligible, request) {
            eligible.filter {
                OriginMatcher.matchLevel(request.form.origin, it) != OriginMatchLevel.NONE
            }.mapTo(linkedSetOf()) { it.id }
        }
        // 其他动态码：未被主候选覆盖的独立 OTP（无 url / issuer 未命中 / 绑定给未匹配登录条目）
        val otherOtp = remember(session, request, hasOtpField, candidates) {
            if (!hasOtpField) return@remember emptyList()
            val excludeIds = candidates.mapTo(HashSet()) { it.id }
            candidates.mapNotNullTo(excludeIds) { it.otpBindingId() }
            gateway.findOtherOtpEntries(session, excludeIds)
        }
        // 全库登录条目：仅当用户开始搜索时物化，供「其他登录条目」分组检索
        var allLogins by remember(session) { mutableStateOf<List<Entry>?>(null) }
        LaunchedEffect(query) {
            if (query.isNotBlank() && allLogins == null) allLogins = gateway.findAllLoginEntries(session)
        }
        val candidateIds = remember(candidates) { candidates.mapTo(HashSet()) { it.id } }
        val shown = if (query.isBlank()) {
            candidates.sortedWith(
                compareByDescending<Entry> {
                    OriginMatcher.matchLevel(request.form.origin, it) == OriginMatchLevel.EXACT
                }.thenByDescending { it.id in matchedIds }.thenBy { it.titleLower }.thenBy { it.id },
            ).take(40)
        } else {
            AutofillEntrySearch.search(candidates, query)
        }
        val otherOtpShown = otherOtp.filter { entry ->
            query.isBlank() || entry.title.contains(query, ignoreCase = true) ||
                entry.username.contains(query, ignoreCase = true) || entry.url.contains(query, ignoreCase = true)
        }.sortedBy { it.titleLower }.take(40)
        val searchLogins = if (query.isBlank()) emptyList() else {
            AutofillEntrySearch.search(allLogins ?: emptyList(), query, excludeIds = candidateIds)
        }
        val allShownRows = shown + otherOtpShown + searchLogins
        val hasOtpRow = remember(allShownRows) { allShownRows.any { gateway.otpSourceRef(session, it) != null } }
        var tick by remember { mutableIntStateOf(0) }
        LaunchedEffect(hasOtpRow) {
            if (hasOtpRow) while (true) {
                delay(1_000)
                tick++
            }
        }
        val otpSnapshots = remember(tick, allShownRows) {
            buildMap {
                allShownRows.forEach { entry ->
                    val source = gateway.otpSourceRef(session, entry) ?: return@forEach
                    val snap = source.computationEntry().otpDisplaySnapshot() ?: return@forEach
                    put(entry.id, snap)
                }
            }
        }

Text(uiText("选择登录账号"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = query,
            onValueChange = { query = it.take(80) },
            placeholder = { Text(uiText("搜索名称、用户名…")) },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(20.dp)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = VaultShape,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.outline,
            ),
        )
Spacer(Modifier.height(8.dp))
        if (allShownRows.isEmpty()) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    if (query.isBlank()) uiText("没有可用的登录条目") else uiText("没有找到匹配的条目"),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                VaultButton(onClick = { showPasswordGenerator = true }) {
                    Text(uiText("生成密码并填充"))
                }
            }
        } else {
            BoxWithConstraints(Modifier.fillMaxWidth()) {
                val listHeight = (maxHeight * 0.6f).coerceAtLeast(200.dp)
                Card(
                    shape = VaultShape,
                    colors = CardDefaults.cardColors(containerColor = vaultDialogInsetColor()),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(listHeight)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        if (shown.isNotEmpty()) {
                            EntryRows(shown, matchedIds, otpSnapshots, onPick)
                        }
                        if (otherOtpShown.isNotEmpty()) {
                            GroupDivider()
                            GroupHeader(uiText("其他动态码"))
                            EntryRows(otherOtpShown, matchedIds, otpSnapshots, onPick)
                        }
                        if (searchLogins.isNotEmpty()) {
                            GroupDivider()
                            GroupHeader(uiText("其他登录条目"))
                            EntryRows(searchLogins, matchedIds, otpSnapshots, onPick)
                        }
                    }
                }
            }
        }
        if (showPasswordGenerator) {
            PasswordGeneratorDialog(
                onCancel = { showPasswordGenerator = false },
                onAccept = { password ->
                    showPasswordGenerator = false
                    finishFillGenerated(request, session, password)
                },
            )
        }
    }

    @Composable
    private fun EntryRows(
        entries: List<Entry>,
        matchedIds: Set<String>,
        otpSnapshots: Map<String, OtpDisplaySnapshot>,
        onPick: (Entry) -> Unit,
    ) {
        entries.forEachIndexed { i, entry ->
            val snap = otpSnapshots[entry.id]
            EntryRow(
                title = entry.title.ifBlank { entry.url },
                subtitle = entry.username.ifBlank {
                    snap?.issuer?.ifBlank { snap.label } ?: entry.username
                },
                isMatched = entry.id in matchedIds,
                otp = snap,
                onClick = { onPick(entry) },
            )
            if (i < entries.lastIndex) {
                GroupDivider()
            }
        }
    }

    @Composable
    private fun GroupHeader(text: String) {
        Text(
            text,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    @Composable
    private fun GroupDivider() {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(0.5.dp)
                .padding(horizontal = 12.dp)
                .background(MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)),
        )
    }

    @Composable
    private fun EntryRow(
        title: String,
        subtitle: String,
        isMatched: Boolean,
        otp: OtpDisplaySnapshot?,
        onClick: () -> Unit,
    ) {
        val bg = if (isMatched) Modifier.background(MaterialTheme.colorScheme.primaryContainer) else Modifier
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .then(bg)
                .clickable(onClick = onClick)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(VaultShape)
                    .background(TypeColors.Login),
            )
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (isMatched) FontWeight.SemiBold else FontWeight.Normal,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (subtitle.isNotBlank()) {
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                otp?.let { snap ->
                    val suffix = when (snap.type) {
                        "totp" -> " · ${snap.remaining}s"
                        "hotp" -> " · #${snap.counter}"
                        else -> ""
                    }
                    Text(
                        "${snap.code}$suffix",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
            if (isMatched) {
                Surface(
                    shape = VaultShape,
                    color = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f),
                ) {
                    Text(
                        uiText("匹配"),
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }

    @Composable
    private fun SaveChooser(request: PendingAutofillRequest.Save, session: AutofillVaultSession) {
        val matches = remember(session, request) { gateway.findMatches(session, request.form.origin) }
        var pendingLegacyUpdate by remember { mutableStateOf<Triple<Entry, String, String>?>(null) }
        val updateMatches = matches.filter {
            it.level == OriginMatchLevel.EXACT || it.level == OriginMatchLevel.LEGACY_PACKAGE
        }
        val existing = updateMatches.firstOrNull()?.entryId
            ?.let { id -> gateway.entry(session, id) }
        val decision = SavePolicy.decide(
            request.candidate,
            request.form.origin,
            updateMatches.map { it.entryId },
            existing?.let { ExistingCredential(it.username, it.password) },
        )
        val singleUpdate = remember(session, decision) {
            (decision as? SaveDecision.UpdateChoice)
                ?.matchingEntryIds
                ?.singleOrNull()
                ?.takeIf { id -> matches.any { it.entryId == id && mayAutoApplySavedCredentialUpdate(it.level) } }
                ?.let { id -> gateway.entry(session, id) }
                ?.let { entry -> Triple(entry, decision.username, decision.password) }
        }
        LaunchedEffect(singleUpdate) {
            singleUpdate?.let { (entry, username, password) ->
                finishUpdate(session, entry, username, password)
            }
        }
        if (singleUpdate != null) {
            VaultUnlockLoading(isComplete = false)
            return
        }
        LaunchedEffect(decision) {
            if (decision is SaveDecision.Unchanged) {
                Toast.makeText(
                    this@AutofillAuthActivity,
                    getString(R.string.system_auth_unchanged),
                    Toast.LENGTH_SHORT,
                ).show()
                finishRequest(AutofillSaveCompletion.HANDLED)
            }
        }
        if (decision is SaveDecision.Unchanged) {
            VaultUnlockLoading(isComplete = false)
            return
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            when (decision) {
                SaveDecision.Unchanged -> Unit
                is SaveDecision.Reject -> {
                    Surface(
                        shape = VaultShape,
                        color = MaterialTheme.colorScheme.errorContainer,
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Outlined.Warning,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp),
                                tint = MaterialTheme.colorScheme.onErrorContainer,
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                getString(savePolicyReasonRes(decision.reason)),
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
                is SaveDecision.Create -> {
                    Card(
                        shape = VaultShape,
                        colors = CardDefaults.cardColors(containerColor = vaultDialogInsetColor()),
                        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                    ) {
                        Row(Modifier.fillMaxWidth()) {
                            Box(Modifier.width(6.dp).fillMaxWidth().height(60.dp).background(TypeColors.Login, RoundedCornerShape(topStart = VaultCornerRadius, bottomStart = VaultCornerRadius)))
                            Column(Modifier.padding(start = 14.dp, end = 16.dp, top = 14.dp, bottom = 14.dp).weight(1f)) {
                                Text(uiText("新建登录条目"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Spacer(Modifier.height(4.dp))
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(if (decision.username.isBlank()) uiText("未填写用户名") else decision.username, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
                                    Spacer(Modifier.width(8.dp))
                                    Surface(shape = VaultShape, color = MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)) {
                                        Row(Modifier.padding(horizontal = 6.dp, vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                                            Icon(Icons.Filled.CheckCircle, null, modifier = Modifier.size(12.dp), tint = MaterialTheme.colorScheme.primary)
                                            Spacer(Modifier.width(3.dp))
                                            Text(uiText("密码已填写"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    VaultButton(
                        onClick = { finishCreate(session, request.form.origin, decision.username, decision.password) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = VaultShape,
                    ) {
                        Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(uiText("保存到保险库"))
                    }
                }
                is SaveDecision.UpdateChoice -> {
                    val entries = decision.matchingEntryIds.mapNotNull { id -> gateway.entry(session, id) }
                    Text(uiText("选择要更新的条目，或新建一条"), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium)
                    entries.forEach { entry ->
                        Card(
                        modifier = Modifier.fillMaxWidth().clickable {
                                if (matches.any { it.entryId == entry.id && it.level == OriginMatchLevel.LEGACY_PACKAGE }) {
                                    pendingLegacyUpdate = Triple(entry, decision.username, decision.password)
                                } else {
                                    finishUpdate(session, entry, decision.username, decision.password)
                                }
                            },
                            shape = VaultShape,
                            colors = CardDefaults.cardColors(containerColor = vaultDialogInsetColor()),
                            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                        ) {
                            Row(Modifier.fillMaxWidth()) {
                                Box(Modifier.width(6.dp).fillMaxWidth().height(IntrinsicSize.Min).background(TypeColors.Login, RoundedCornerShape(topStart = VaultCornerRadius, bottomStart = VaultCornerRadius)))
                                Row(
                                    Modifier.padding(start = 12.dp, end = 14.dp, top = 14.dp, bottom = 14.dp).weight(1f),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(entry.title.ifBlank { entry.url }, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        if (entry.username.isNotBlank()) {
                                            Spacer(Modifier.height(2.dp))
                                            Text(entry.username, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        }
                                    }
                                    Spacer(Modifier.width(8.dp))
                                    Icon(
                                        Icons.Default.KeyboardArrowRight,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                                        modifier = Modifier.size(20.dp),
                                    )
                                }
                            }
                        }
                        Spacer(Modifier.height(6.dp))
                    }
                    VaultButton(
                        onClick = { finishCreate(session, request.form.origin, decision.username, decision.password) },
                        modifier = Modifier.fillMaxWidth(),
                        shape = VaultShape,
                        variant = VaultButtonVariant.OUTLINED,
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(uiText("新建条目"))
                    }
                }
            }
        }
        pendingLegacyUpdate?.let { (entry, username, password) ->
            AlertDialog(
                onDismissRequest = { pendingLegacyUpdate = null },
                title = { Text(uiText("确认更新旧版应用绑定")) },
                text = { Text(uiText("此条目没有经过当前应用签名校验。确认后会将其绑定到当前应用，并更新保存的凭据。")) },
                confirmButton = {
                    TextButton(onClick = {
                        pendingLegacyUpdate = null
                        finishUpdate(session, entry, username, password)
                    }) { Text(uiText("确认并更新")) }
                },
                dismissButton = {
                    TextButton(onClick = { pendingLegacyUpdate = null }) { Text(uiText("取消")) }
                },
            )
        }
    }

    private fun finishFill(
        request: PendingAutofillRequest.Fill,
        session: AutofillVaultSession,
        selected: Entry,
        otpCode: String? = null,
    ) {
        if (gateway.isOriginExcluded(request.form.origin, session)) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        val snapshot = gateway.resolveAutofillValues(session, selected)
        val resolvedOtpCode = otpCode
            ?: snapshot.values[AutofillRole.ONE_TIME_CODE]?.value
        val dataset = AutofillResponseFactory.authenticatedDataset(
            this,
            request.form,
            selected,
            request.inlineSpec,
            resolvedOtpCode,
            snapshot,
            verificationGranted = true,
        )
            ?: return finishRequest(AutofillSaveCompletion.DISMISSED)
        val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
        setResult(Activity.RESULT_OK, result)
        requestToken?.let { AutofillRequestStore.remove(it) }
        activeSession?.clear()
        activeSession = null
        finish()
    }

    /** 无匹配时：用户先在生成页选定密码，再填充目标字段并写入登录条目供 autofill 保存/更新机制持续维护。 */
    private fun finishFillGenerated(
        request: PendingAutofillRequest.Fill,
        session: AutofillVaultSession,
        password: String,
    ) {
        if (gateway.isOriginExcluded(request.form.origin, session)) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        // 暂存：把生成的密码写入保险库（用户名留空），后续保存/更新机制会保持该密码正确可用。
        gateway.createLogin(session, request.form.origin, "", password)
        val generated = Entry(
            id = UUID.randomUUID().toString(),
            title = request.form.origin.displayName(),
            username = "",
            password = password,
            url = when (val origin = request.form.origin) {
                is TargetOrigin.AndroidPackage -> origin.packageName
                is TargetOrigin.Web -> origin.host
            },
            secretType = SecretType.LOGIN,
        )
        val dataset = AutofillResponseFactory.authenticatedDataset(
            this,
            request.form,
            generated,
            request.inlineSpec,
            verificationGranted = true,
        )
            ?: return finishRequest(AutofillSaveCompletion.DISMISSED)
        val result = Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
        setResult(Activity.RESULT_OK, result)
        requestToken?.let { AutofillRequestStore.remove(it) }
        activeSession?.clear()
        activeSession = null
        finish()
    }

    private fun finishCreate(session: AutofillVaultSession, origin: TargetOrigin, username: String, password: String) {
        if (gateway.isOriginExcluded(origin, session)) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        when (gateway.createLogin(session, origin, username, password)) {
            is VaultWriteResult.Success -> {
                Toast.makeText(this, getString(R.string.system_auth_save_success), Toast.LENGTH_SHORT).show()
                finishRequest(AutofillSaveCompletion.HANDLED)
            }
            is VaultWriteResult.Failure -> Toast.makeText(this, getString(R.string.system_auth_save_retry), Toast.LENGTH_SHORT).show()
            else -> Toast.makeText(this, getString(R.string.system_auth_credential_changed_retry), Toast.LENGTH_SHORT).show()
        }
    }

    private fun savePolicyReasonRes(reason: String): Int = when (reason) {
        SavePolicy.ORIGIN_UNKNOWN -> R.string.system_auth_save_policy_origin_unknown
        SavePolicy.PASSWORD_MISMATCH -> R.string.system_auth_save_policy_password_mismatch
        SavePolicy.PASSWORD_EMPTY -> R.string.system_auth_save_policy_password_empty
        else -> R.string.system_auth_generic_error
    }

    private fun AutofillErrorCode.messageRes(): Int = when (this) {
        AutofillErrorCode.VAULT_OPEN_FAILED -> R.string.system_auth_vault_open_failed
        AutofillErrorCode.DEVICE_BINDING_MISMATCH -> R.string.system_auth_device_binding_mismatch
        AutofillErrorCode.MUTATION_BASELINE_MISSING -> R.string.system_auth_mutation_baseline_missing
        AutofillErrorCode.SESSION_KEY_INVALID -> R.string.system_auth_session_key_invalid
        AutofillErrorCode.PASSKEY_INVALID -> R.string.system_auth_passkey_invalid
        AutofillErrorCode.SAVE_FAILED, AutofillErrorCode.UNKNOWN -> R.string.system_auth_generic_error
    }

    private fun finishUpdate(session: AutofillVaultSession, entry: Entry, username: String, password: String) {
        if (activeOrigin?.let { gateway.isOriginExcluded(it, session) } == true) {
            finishRequest(AutofillSaveCompletion.DISMISSED)
            return
        }
        when (gateway.updateLogin(session, entry.id, entry.updatedAt, username, password, activeOrigin)) {
            is VaultWriteResult.Success -> {
                Toast.makeText(this, getString(R.string.system_auth_update_success), Toast.LENGTH_SHORT).show()
                finishRequest(AutofillSaveCompletion.HANDLED)
            }
            is VaultWriteResult.Failure -> Toast.makeText(this, getString(R.string.system_auth_update_retry), Toast.LENGTH_SHORT).show()
            else -> Toast.makeText(this, getString(R.string.system_auth_entry_changed), Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * 只有真正保存/更新或确认无需变化才把 SaveCallback 标记为完成。
     * 中途关闭必须返回取消，让登录字段消失或页面完成时的第二层触发仍能再次提示。
     */
    private fun finishRequest(completion: AutofillSaveCompletion) {
        if (requestFinished) return
        requestFinished = true
        requestToken?.let { AutofillRequestStore.remove(it) }
        requestToken = null
        intent.removeExtra(EXTRA_REQUEST_TOKEN)
        SaveRequestIntentTransport.clear(intent)
        activeSession?.clear()
        activeSession = null
        activeOrigin = null
        setResult(
            if (AutofillSaveLifecycle.shouldReportSuccess(removeTaskOnFinish, completion)) {
                Activity.RESULT_OK
            } else {
                Activity.RESULT_CANCELED
            },
        )
        finishAuthActivity()
    }

    /**
     * 保存认证页始终使用独立 task。即使系统将新页面放进了已有的自动填充 task，
     * 也要移除整个 task，避免未解锁退出后留下空页面并拦截下一次保存请求。
     */
    private fun finishAuthActivity() {
        if (removeTaskOnFinish) finishAndRemoveTask() else finish()
    }

    override fun onDestroy() {
        activeSession?.clear()
        activeSession = null
        activeOrigin = null
        super.onDestroy()
    }

    private fun TargetOrigin.displayName(): String = when (this) {
        // 优先显示应用名称，解析不到（未安装/异常）时回退为包名。
        is TargetOrigin.AndroidPackage -> AppNameResolver.label(this@AutofillAuthActivity, packageName) ?: packageName
        is TargetOrigin.Web -> host
    }

    companion object {
        const val EXTRA_REQUEST_TOKEN = "com.vault.autofill.REQUEST_TOKEN"
    }
}
