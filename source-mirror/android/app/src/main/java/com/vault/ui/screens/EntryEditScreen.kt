package com.vault.ui.screens

import com.vault.ui.vaultBackdropSource

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.gestures.BringIntoViewSpec
import androidx.compose.foundation.gestures.LocalBringIntoViewSpec
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import com.vault.ui.VaultLazyRow as LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import com.vault.R
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.vault.model.Entry
import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.AutofillLinkCodec
import com.vault.model.AUTOFILL_LINKS_KEY
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.entryModules
import com.vault.model.withEntryModules
import com.vault.model.associatedAppPackage
import com.vault.model.getStringField
import com.vault.model.newEntry
import com.vault.model.autofillLinks
import com.vault.model.migrateAutofillLinks
import com.vault.model.autofill.AutofillRole
import com.vault.model.withoutLeakCache
import com.vault.model.getOtpField
import com.vault.autofill.AutofillSourceResolver
import com.vault.autofill.ResolvedAutofillValue
import com.vault.ocr.CardParser
import kotlin.math.roundToInt
import kotlin.math.abs
import com.vault.ocr.DocCrop
import com.vault.ocr.Ocr
import com.vault.os.WifiQr
import com.vault.ui.BreathingRing
import com.vault.ui.IdleTracker
import com.vault.ui.InputFilters
import com.vault.ui.uiText
import com.vault.ui.localizeUiTextFor
import com.vault.ui.TypeColors
import com.vault.ui.NavOrderPref
import com.vault.ui.media.Base64Image
import com.vault.ui.scan.CameraScanActivity
import com.vault.ui.scan.QrLiveScanActivity
import com.vault.ui.media.ImageViewerDialog
import com.vault.ui.media.MediaImportProgressDialog
import com.vault.ui.media.MAX_IMAGES_PER_MODULE
import com.vault.ui.media.encodeImageFromUri
import com.vault.ui.media.PmvMediaSessionLockedException
import com.vault.ui.media.expandImageBase64
import com.vault.ui.media.parseImageList
import com.vault.ui.media.toJsonField
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.io.File
import java.util.UUID
import com.vault.ui.VaultShape

/** 实时扫码用途 */
private enum class QrType { NONE, WIFI, OTP }

internal fun replaceAutofillRole(
    links: List<AutofillLink>,
    source: Entry,
    value: ResolvedAutofillValue,
): List<AutofillLink> {
    val remaining = links.mapNotNull { link ->
        val fields = link.fields.filterNot { it.role == value.role }
        link.copy(fields = fields).takeIf { fields.isNotEmpty() }
    }
    return remaining + AutofillLink(
        id = UUID.randomUUID().toString(),
        sourceEntryId = source.id,
        fields = listOf(
            AutofillFieldRef(
                moduleId = value.moduleId,
                sourceKey = value.sourceKey,
                role = value.role,
                requiresVerification = value.requiresVerification,
            ),
        ),
    )
}

internal fun removeAutofillRole(links: List<AutofillLink>, role: AutofillRole): List<AutofillLink> =
    links.mapNotNull { link ->
        val fields = link.fields.filterNot { it.role == role }
        link.copy(fields = fields).takeIf { fields.isNotEmpty() }
    }

internal fun replaceAutofillEntry(
    links: List<AutofillLink>,
    source: Entry,
    values: List<ResolvedAutofillValue>,
): List<AutofillLink> {
    val selectedValues = values
        .asSequence()
        .filter { it.sourceEntryId == source.id && it.value.isNotEmpty() }
        .distinctBy(ResolvedAutofillValue::role)
        .toList()
    if (selectedValues.isEmpty()) return links
    val selectedRoles = selectedValues.mapTo(hashSetOf(), ResolvedAutofillValue::role)
    val remaining = links.mapNotNull { link ->
        val fields = link.fields.filterNot { it.role in selectedRoles }
        link.copy(fields = fields).takeIf { fields.isNotEmpty() }
    }
    return remaining + AutofillLink(
        id = UUID.randomUUID().toString(),
        sourceEntryId = source.id,
        fields = selectedValues.map { value ->
            AutofillFieldRef(
                moduleId = value.moduleId,
                sourceKey = value.sourceKey,
                role = value.role,
                requiresVerification = value.requiresVerification,
            )
        },
    )
}

internal fun autofillLinkCategoryTypes(order: List<String>): List<String> =
    order.filter {
        it in SecretType.ALL && it !in setOf(SecretType.LOGIN, SecretType.PASSKEY)
    }.distinct()

@Composable
internal fun autofillLinkRoleLabel(role: AutofillRole): String = when (role) {
    AutofillRole.USERNAME -> uiText("用户名")
    AutofillRole.EMAIL -> uiText("邮箱")
    AutofillRole.PASSWORD -> uiText("密码")
    AutofillRole.ONE_TIME_CODE -> uiText("动态码")
    AutofillRole.FULL_NAME -> uiText("姓名")
    AutofillRole.PHONE -> uiText("电话")
    AutofillRole.COUNTRY -> uiText("国家 / 地区")
    AutofillRole.REGION -> uiText("省 / 州")
    AutofillRole.CITY -> uiText("城市")
    AutofillRole.STREET_ADDRESS -> uiText("街道地址")
    AutofillRole.POSTAL_CODE -> uiText("邮编")
    AutofillRole.CARDHOLDER -> uiText("持卡人")
    AutofillRole.CARD_NUMBER -> uiText("卡号")
    AutofillRole.CARD_EXPIRY -> uiText("有效期")
    AutofillRole.CARD_CVV -> "CVV"
    AutofillRole.ID_NUMBER -> uiText("证件号码")
    AutofillRole.API_KEY -> "API Key"
    AutofillRole.API_SECRET -> "API Secret"
    AutofillRole.HOST -> uiText("主机")
    AutofillRole.PORT -> uiText("端口")
    AutofillRole.DATABASE -> uiText("数据库")
    AutofillRole.SSID -> "SSID"
    AutofillRole.WIFI_PASSWORD -> uiText("Wi-Fi 密码")
    AutofillRole.RECOVERY_ANSWER -> uiText("恢复答案")
    AutofillRole.CUSTOM_TEXT -> uiText("自定义文本")
    AutofillRole.CUSTOM_SECRET -> uiText("自定义敏感文本")
    AutofillRole.NONE -> uiText("不自动填充")
}

/** 卡证条目 OCR 分流：身份证走证件解析，其他类型走卡面解析。 */
private fun parseCardDocumentText(cardType: String, text: String): Map<String, String> =
    if (cardType == EntryModules.CARD_ID_CARD) CardParser.parseIdCard(text).filterKeys {
        it in setOf("full_name", "id_number", "issue_date", "expiry_date", "issuing_authority")
    }
    else CardParser.parseCreditCard(text)

private fun typeEditorSubtitle(type: String): String = when (type) {
    SecretType.LOGIN -> "账号、密码与目标应用"
    SecretType.CARD_DOCUMENT -> "卡片/证件信息与正反面影像"
    SecretType.WIFI -> "网络凭据与路由器信息"
    SecretType.API_KEY -> "接口身份与访问密钥"
    SecretType.OTP -> "动态口令参数"
    SecretType.SECURE_NOTE -> "受保护的自由文本"
    SecretType.SERVER -> "主机连接与认证信息"
    SecretType.CUSTOM -> "自由组合所需内容模块"
    else -> "安全保存此条目"
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun EntryEditScreen(
    initial: Entry?,
    draft: Entry? = null,
    initialType: String,
    onCancel: () -> Unit,
    onSave: (Entry) -> Unit,
    onDraftChanged: (Entry) -> Unit = {},
    setExternalActionInProgress: (Boolean) -> Unit = {},
    existingTags: List<String> = emptyList(),
    autofillSourceOptions: List<Entry> = emptyList(),
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val editorScrollState = rememberScrollState()
    var suppressMarkdownBringIntoView by remember { mutableStateOf(false) }
    val editorBringIntoViewSpec = remember {
        object : BringIntoViewSpec {
            override fun calculateScrollDistance(offset: Float, size: Float, containerSize: Float): Float {
                if (suppressMarkdownBringIntoView) return 0f
                val trailingEdge = offset + size
                return when {
                    offset >= 0f && trailingEdge <= containerSize -> 0f
                    offset < 0f && trailingEdge > containerSize -> 0f
                    abs(offset) < abs(trailingEdge - containerSize) -> offset
                    else -> trailingEdge - containerSize
                }
            }
        }
    }
    LaunchedEffect(suppressMarkdownBringIntoView) {
        if (suppressMarkdownBringIntoView) {
            delay(500)
            suppressMarkdownBringIntoView = false
        }
    }
    var editorViewportTopPx by remember { mutableStateOf(0) }
    val editSessionKey = initial?.let { "existing:${it.id}:${it.updatedAt}" } ?: "new:$initialType"
    var seed by remember(editSessionKey) { mutableStateOf(draft ?: initial ?: newEntry(initialType)) }
    var title by remember(editSessionKey) { mutableStateOf(seed.title) }
    var username by remember(editSessionKey) { mutableStateOf(seed.username) }
    var password by remember(editSessionKey) { mutableStateOf(seed.password) }
    var url by remember(editSessionKey) { mutableStateOf(seed.url) }
    var targetApp by remember(editSessionKey) { mutableStateOf(seed.associatedAppPackage()) }
    var autofillLinks by remember(editSessionKey) { mutableStateOf(seed.migrateAutofillLinks().autofillLinks()) }
    var notes by remember(editSessionKey) { mutableStateOf(seed.notes) }
    var tagsText by remember(editSessionKey) { mutableStateOf(seed.tags.joinToString(", ")) }
    var modules by remember(editSessionKey) {
        mutableStateOf(
            seed.entryModules().ifEmpty {
                if (initial == null) EntryModules.preset(seed.secretType) else emptyList()
            }
        )
    }
    val extras = remember(editSessionKey) {
        mutableStateMapOf<String, String>().apply {
            for (k in extraKeysFor(seed.secretType)) put(k, seed.getStringField(k))
            if (seed.secretType == SecretType.CARD_DOCUMENT && this["card_type"].isNullOrEmpty()) {
                this["card_type"] = EntryModules.CARD_BANK
            }
        }
    }
    val imageKey = imageKeyFor(seed.secretType)
    val images = remember(editSessionKey) {
        mutableStateListOf<String>().apply {
            if (imageKey != null) addAll(parseImageList(seed.fields[imageKey]))
        }
    }
    // 线上泄露检测结果（编辑时由 PasswordFieldWithTools 异步查询并上报）
    var breachCount by remember(editSessionKey) { mutableStateOf(seed.leakPwnedCount ?: -1) }
    var editDetectedLeak by remember(editSessionKey) { mutableStateOf(seed.leakCommonWeak) }
    var isDirty by remember(editSessionKey) { mutableStateOf(false) }
    var cleanDraft by remember(editSessionKey) { mutableStateOf<Entry?>(null) }
    var showDiscardDialog by remember(editSessionKey) { mutableStateOf(false) }

    // 相册权限字符串（API 33+ 用细粒度 READ_MEDIA_IMAGES，旧版用 READ_EXTERNAL_STORAGE）
    val galleryPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        Manifest.permission.READ_MEDIA_IMAGES
    else
        Manifest.permission.READ_EXTERNAL_STORAGE

    // OCR：调用 Document Scanner → 拿到自动裁剪的页面 → 识别文字 → 解析字段填表
    var ocrBusy by remember { mutableStateOf(false) }
    // 批量图片导入进度（已处理 / 总数）；非空时显示实时进度弹窗
    var importProgress by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    var wifiQrBusy by remember { mutableStateOf(false) }
    var currentWifiBusy by remember { mutableStateOf(false) }
    var pendingQrType by remember { mutableStateOf(QrType.NONE) }
    var qrChoices by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }

    fun applyWifiQrPayload(raw: String?, emptyMessage: String): Boolean {
        if (raw.isNullOrBlank()) {
            Toast.makeText(ctx, emptyMessage, Toast.LENGTH_SHORT).show()
            return false
        }
        val parsed = WifiQr.parse(raw)
        if (parsed == null) {
            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_invalid_wifi_qr), Toast.LENGTH_LONG).show()
            return false
        }
        extras["ssid"] = parsed.ssid
        extras["wifi_password"] = parsed.password
        extras["security_type"] = parsed.security
        Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_wifi_imported, parsed.ssid), Toast.LENGTH_SHORT).show()
        return true
    }

    fun applyOtpQrPayload(raw: String): Boolean {
        val parsed = com.vault.model.OtpUtils.parseOtpAuthUri(raw) ?: return false
        val (type, secret, params) = parsed
        if (secret.isNullOrEmpty()) return false
        extras["secret"] = secret
        type?.let { extras["type"] = it }
        listOf("algorithm", "digits", "period", "issuer", "label", "counter").forEach { key ->
            params[key]?.let { extras[key] = it }
        }
        Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_otp_imported), Toast.LENGTH_SHORT).show()
        return true
    }

    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        setExternalActionInProgress(false)
        if (uris.isNotEmpty()) scope.launch {
            ocrBusy = true
            try {
                val maxImages = if (seed.secretType == SecretType.CARD_DOCUMENT) {
                    2
                } else {
                    MAX_IMAGES_PER_MODULE
                }
                val remaining = (maxImages - images.size).coerceAtLeast(0)
                if (remaining == 0) Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_image_limit), Toast.LENGTH_SHORT).show()
                val targets = uris.take(remaining)
                importProgress = 0 to targets.size
                for ((index, uri) in targets.withIndex()) {
                    importProgress = index to targets.size
                    val b64 = withContext(Dispatchers.IO) { encodeImageFromUri(ctx, uri) }
                    images.add(b64)
                    importProgress = (index + 1) to targets.size
                    // 仅前 2 张图片自动 OCR 填表（证件照和银行卡适用）
                    if (index >= 2) continue
                    val text = withContext(Dispatchers.IO) { Ocr.recognize(ctx, uri) }
                    if (text.isNotBlank()) {
                        val parsed: Map<String, String> = if (seed.secretType == SecretType.CARD_DOCUMENT) {
                            parseCardDocumentText(extras["card_type"].orEmpty(), text)
                        } else emptyMap()
                        var count = 0
                        for ((k, v) in parsed) if (v.isNotBlank() && extras[k].isNullOrEmpty()) {
                            extras[k] = v
                            count++
                        }
                        if (count > 0) Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_auto_filled, count), Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (t: PmvMediaSessionLockedException) {
                Toast.makeText(ctx, ctx.getString(R.string.system_media_session_locked), Toast.LENGTH_LONG).show()
            } catch (_: Throwable) {
                // OCR / 图片编码失败静默，避免栈轨迹写入 logcat 泄露条目片段
            } finally {
                ocrBusy = false
                importProgress = null
            }
        }
    }

    // ── 辅助方法（供权限回调等使用，需在 launcher 之前声明） ──────────

    // 拍照后：URI 已经是用户在复核屏确认过的裁剪结果，直接编码进图片字段 + OCR
    suspend fun handleCapturedDoc(uri: Uri) {
        data class Prepared(val b64: String, val ocrBytes: ByteArray)
        val prepared: Prepared = withContext(Dispatchers.IO) {
            val bytes = ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error(ctx.getString(R.string.entry_remaining_unreadable_camera_image))
            // 复核屏确认出来的是已经是最终 JPEG（方向已烘焙、无 EXIF 旋转）。
            // 方向正常且体积未超限时直接沿用原始字节：再解码-重压一次只会白丢一代画质
            // （实测这条路原来是把扫描件按 JPEG 85 又压了一遍）。仅方向异常或过大时才重编码。
            val uprightJpeg = bytes.size >= 3 &&
                bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() && bytes[2] == 0xFF.toByte() &&
                bytes.size <= com.vault.ui.media.MAX_IMAGE_BYTES &&
                DocCrop.exifRotationDegrees(bytes) == 0
            val jpeg = if (uprightJpeg) {
                bytes
            } else {
                val oriented = DocCrop.decodeOriented(bytes)
                    ?: error(ctx.getString(R.string.entry_remaining_image_decode_failed))
                val baos = java.io.ByteArrayOutputStream()
                oriented.compress(android.graphics.Bitmap.CompressFormat.JPEG, 92, baos)
                oriented.recycle()
                baos.toByteArray()
            }
            val b64 = android.util.Base64.encodeToString(jpeg, android.util.Base64.NO_WRAP)
            Prepared(b64, jpeg)
        }
        images.add(prepared.b64)

        // 仅前 2 张图片自动 OCR 填表
        if (images.size > 2) return
        val text = runCatching { Ocr.recognize(prepared.ocrBytes) }.getOrElse {
            if (it is PmvMediaSessionLockedException) throw it
            ""
        }
        if (text.isNotBlank()) {
            val parsed = if (seed.secretType == SecretType.CARD_DOCUMENT) {
                parseCardDocumentText(extras["card_type"].orEmpty(), text)
            } else emptyMap()
            var count = 0
            for ((k, v) in parsed) if (v.isNotBlank() && extras[k].isNullOrEmpty()) {
                extras[k] = v
                count++
            }
            if (count > 0) Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_auto_filled, count), Toast.LENGTH_SHORT).show()
        }
    }

    // 本地 CameraX 文档扫描：实时框选、拍照后四角复核。
    val docCameraLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        setExternalActionInProgress(false)
        val uri = res.data?.data
        if (res.resultCode != Activity.RESULT_OK || uri == null) {
            ocrBusy = false
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            try { handleCapturedDoc(uri) }
            catch (_: PmvMediaSessionLockedException) {
                Toast.makeText(ctx, ctx.getString(R.string.system_media_session_locked), Toast.LENGTH_LONG).show()
            }
            catch (t: Throwable) {
                val msg = t.message?.takeIf { it.isNotBlank() } ?: ctx.getString(R.string.entry_remaining_processing)
                Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_processing_failed, msg), Toast.LENGTH_LONG).show()
            }
            finally { ocrBusy = false }
        }
    }

    // 实时扫码：Wi-Fi / OTP 共用 CameraX + ZXing 实时解码
    val qrliveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        setExternalActionInProgress(false)
        wifiQrBusy = false
        if (res.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        IdleTracker.touch()
        val raw = res.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT) ?: return@rememberLauncherForActivityResult
        if (pendingQrType == QrType.OTP) {
            if (!applyOtpQrPayload(raw)) {
                Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_invalid_otp_qr), Toast.LENGTH_LONG).show()
            }
        } else {
                applyWifiQrPayload(raw, ctx.getString(R.string.entry_remaining_unrecognized_qr))
        }
    }

    fun startWifiQrScanInternal() {
        if (wifiQrBusy) return
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_camera_permission), Toast.LENGTH_SHORT).show()
            return
        }
        pendingQrType = QrType.WIFI
        wifiQrBusy = true
        setExternalActionInProgress(true)
        qrliveLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_WIFI))
    }

    fun startScanInternal() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_camera_permission), Toast.LENGTH_SHORT).show()
            return
        }
        if (ocrBusy) return
        ocrBusy = true
        setExternalActionInProgress(true)
        docCameraLauncher.launch(android.content.Intent(ctx, CameraScanActivity::class.java))
    }

    // ── 运行时权限申请（合规） ──────────────────────────────────────

    /** 待相机权限授予后执行的回调 */
    var pendingCameraAction by remember { mutableStateOf<(() -> Unit)?>(null) }

    // 权限说明弹窗：当用户之前拒绝过权限时，显示解释后再发起请求
    var rationalePermission by remember { mutableStateOf<String?>(null) }
    // 国产 ROM 永久拒绝后引导前往系统设置
    var showPermissionSettings by remember { mutableStateOf<String?>(null) }

    val requestCameraPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            pendingCameraAction?.invoke()
        } else {
            if (!ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, Manifest.permission.CAMERA)) {
                showPermissionSettings = Manifest.permission.CAMERA
            } else {
                Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_camera_permission), Toast.LENGTH_SHORT).show()
            }
        }
        pendingCameraAction = null
    }

    /** 待相册权限授予后要使用的目标 + MIME（通过 lambda 变量避免前向引用） */
    var pendingGalleryLauncher by remember { mutableStateOf<((String) -> Unit)?>(null) }
    var pendingGalleryMime by remember { mutableStateOf<String?>(null) }

    val requestGalleryPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted && pendingGalleryMime != null && pendingGalleryLauncher != null) {
            setExternalActionInProgress(true)
            pendingGalleryLauncher!!(pendingGalleryMime!!)
        } else {
            setExternalActionInProgress(false)
            wifiQrBusy = false
            if (!granted) {
                val perm = pendingGalleryMime ?: return@rememberLauncherForActivityResult
                if (!ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, perm)) {
                    showPermissionSettings = perm
                } else {
                    Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_gallery_permission), Toast.LENGTH_SHORT).show()
                }
            }
        }
        pendingGalleryLauncher = null
        pendingGalleryMime = null
    }

    // 读取当前连接的 Wi-Fi：Android 12+ 需附近设备权限，Android 11 及以下需要定位权限
    val wifiReadPermissions = remember {
        buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.ACCESS_FINE_LOCATION)
            }
        }
    }

    // 从当前网络读取 SSID；未连接 Wi-Fi 或权限不足时返回 null
    fun currentWifiSsid(): String? {
        val context = ctx.applicationContext
        val connectivityManager = context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
        val network = connectivityManager?.activeNetwork ?: return null
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return null
        if (!capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)) return null
        // Android 10+ 从 transportInfo 取当前连接；更早版本改走 WifiManager（需定位权限）
        val wifiInfo: android.net.wifi.WifiInfo? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            capabilities.transportInfo as? android.net.wifi.WifiInfo
        } else {
            @Suppress("DEPRECATION")
            (context.getSystemService(android.content.Context.WIFI_SERVICE) as? android.net.wifi.WifiManager)?.connectionInfo
        }
        val ssid = wifiInfo?.ssid?.trim('"').orEmpty()
        return ssid.takeIf { it.isNotBlank() && !it.equals("<unknown ssid>", ignoreCase = true) }
    }

    fun importCurrentWifiInternal() {
        currentWifiBusy = true
        scope.launch {
            val ssid = withContext(Dispatchers.IO) { currentWifiSsid() }
            currentWifiBusy = false
            if (ssid == null) {
                Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_no_wifi_connection), Toast.LENGTH_LONG).show()
                return@launch
            }
            extras["ssid"] = ssid
            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_wifi_imported, ssid), Toast.LENGTH_SHORT).show()
        }
    }

    /** 待定位/附近 WiFi 权限授予后读取当前 Wi-Fi 的记号 */
    var pendingCurrentWifiAction by remember { mutableStateOf<(() -> Unit)?>(null) }

    val requestWifiLocationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (pendingCurrentWifiAction != null && grants.values.all { it }) {
            pendingCurrentWifiAction?.invoke()
        } else {
            currentWifiBusy = false
            if (!grants.values.all { it }) {
                val denied = grants.keys.firstOrNull { grant -> grants[grant] == false } ?: return@rememberLauncherForActivityResult
                if (!ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, denied)) {
                    showPermissionSettings = denied
                } else {
                    Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_permission_wifi_location), Toast.LENGTH_SHORT).show()
                }
            }
        }
        pendingCurrentWifiAction = null
    }

    fun importCurrentWifi() {
        if (currentWifiBusy) return
        val missing = wifiReadPermissions.filter {
            ContextCompat.checkSelfPermission(ctx, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            pendingCurrentWifiAction = { importCurrentWifiInternal() }
            val rationaleVisible = missing.any {
                ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, it)
            }
            if (rationaleVisible) {
                rationalePermission = missing.first()
            } else {
                requestWifiLocationPermission.launch(missing.toTypedArray())
            }
            return
        }
        importCurrentWifiInternal()
    }

    // ── 公共方法 ────────────────────────────────────────────────────

    fun splitTags(v: String): List<String> = com.vault.ui.splitTagText(v)

    // 标签操作：把一个 tag 追加到 tagsText（去重 + 逗号分隔）
    fun addTag(t: String) {
        val cleaned = t.trim()
        if (cleaned.isEmpty()) return
        val current = splitTags(tagsText)
        if (cleaned in current) return
        tagsText = (current + cleaned).joinToString(", ")
    }

    // 标签操作：多选切换——已有则移除，没有则追加
    fun toggleTag(t: String) {
        val cleaned = t.trim()
        if (cleaned.isEmpty()) return
        val current = splitTags(tagsText)
        tagsText = if (cleaned in current) {
            (current - cleaned).joinToString(", ")
        } else {
            (current + cleaned).joinToString(", ")
        }
    }

    // App 选取（仅 LOGIN）：自绘 ModalBottomSheet（精致列表）
    var showAppPicker by remember { mutableStateOf(false) }

    // 扫描 Wi-Fi QR 码
    fun startWifiQrScan() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingCameraAction = { startWifiQrScanInternal() }
            if (ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, Manifest.permission.CAMERA)) {
                rationalePermission = Manifest.permission.CAMERA
            } else {
                requestCameraPermission.launch(Manifest.permission.CAMERA)
            }
            return
        }
        startWifiQrScanInternal()
    }

    // 扫描 OTP (TOTP/HOTP) 二维码
    fun startOtpQrScanInternal() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_camera_permission), Toast.LENGTH_SHORT).show()
            return
        }
        pendingQrType = QrType.OTP
        wifiQrBusy = true
        setExternalActionInProgress(true)
        qrliveLauncher.launch(QrLiveScanActivity.intent(ctx, QrLiveScanActivity.PURPOSE_OTP))
    }

    fun startOtpQrScan() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingCameraAction = { startOtpQrScanInternal() }
            if (ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, Manifest.permission.CAMERA)) {
                rationalePermission = Manifest.permission.CAMERA
            } else {
                requestCameraPermission.launch(Manifest.permission.CAMERA)
            }
            return
        }
        startOtpQrScanInternal()
    }

    // 文档扫描
    fun startScan() {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingCameraAction = { startScanInternal() }
            if (ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, Manifest.permission.CAMERA)) {
                rationalePermission = Manifest.permission.CAMERA
            } else {
                requestCameraPermission.launch(Manifest.permission.CAMERA)
            }
            return
        }
        startScanInternal()
    }

    fun buildDraft(): Entry {
        // 标签对所有可编辑条目类型开放（passkey 不在此编辑页），统一解析保存。
        val finalTags = com.vault.ui.splitTagText(tagsText)
        val managedKeys = extraKeysFor(seed.secretType).toMutableSet().also {
            if (imageKey != null) it.add(imageKey)
            it.add(EntryModules.FIELD_KEY)
            if (seed.secretType == SecretType.LOGIN) {
                it.add("bound_otp_id")
                it.add(AUTOFILL_LINKS_KEY)
            }
        }
        val normalizedModules = EntryModules.normalize(JsonArray(modules))
        val finalTargetApp = targetApp.ifBlank {
            normalizedModules
                .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.TARGET_APP }
                ?.let { EntryModules.primitive(it["value"]) }
                .orEmpty().trim()
        }
        val finalFields = buildMap<String, kotlinx.serialization.json.JsonElement> {
            for (key in extraKeysFor(seed.secretType)) {
                val value = if (key == "security_type" && seed.secretType == SecretType.WIFI) {
                    com.vault.os.WifiSecurity.coercedForSave(extras[key], extras["wifi_password"])
                } else {
                    extras[key].orEmpty()
                }
                if (value.isNotEmpty()) put(key, JsonPrimitive(value))
            }
            if (imageKey != null && images.isNotEmpty()) put(imageKey, images.toList().toJsonField())
            if (normalizedModules.isNotEmpty() || seed.fields.containsKey(EntryModules.FIELD_KEY)) {
                put(EntryModules.FIELD_KEY, JsonArray(normalizedModules))
            }
            if (seed.secretType == SecretType.LOGIN && autofillLinks.isNotEmpty()) {
                put(AUTOFILL_LINKS_KEY, AutofillLinkCodec.encode(autofillLinks))
            }
            for ((key, value) in seed.fields) if (key !in managedKeys) put(key, value)
        }
        val leakPwnedCount = if (breachCount >= 0) breachCount else null
        val outBase = seed.copy(
            title = title,
            username = username,
            password = password,
            url = url,
            targetApp = finalTargetApp,
            notes = notes,
            tags = finalTags,
            fields = finalFields,
        )
        val passwordChanged = password != seed.password
        return if (leakPwnedCount != null || editDetectedLeak) {
            outBase.copy(
                leakCheckRevision = if (passwordChanged) null else outBase.leakCheckRevision,
                leakPwnedCount = leakPwnedCount?.coerceAtLeast(0),
                leakCommonWeak = editDetectedLeak,
                leakCheckedAt = if (passwordChanged) null else outBase.leakCheckedAt,
            )
        } else if (passwordChanged) outBase.withoutLeakCache() else outBase
    }

    // Presets and legacy field normalization are editor initialization, not user edits.
    LaunchedEffect(editSessionKey) {
        if (seed.secretType == SecretType.SECURE_NOTE && extras["note"].isNullOrEmpty()) {
            val module = modules.firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.MULTILINE }
            if (module != null) {
                extras["note"] = (module["value"] as? JsonPrimitive)?.contentOrNull.orEmpty()
                modules = modules.filter { EntryModules.primitive(it["type"]) != ModuleType.MULTILINE }
            }
        } else if (seed.secretType == SecretType.SERVER) {
            val needsMigrate = listOf("server_host", "server_port", "server_user", "server_pass")
                .any { extras[it].isNullOrEmpty() }
            if (needsMigrate) {
                val module = modules.firstOrNull {
                    EntryModules.primitive(it["type"]) == ModuleType.SERVER_CONNECTION
                }
                val value = module?.get("value") as? JsonObject
                if (value != null) {
                    if (extras["server_host"].isNullOrEmpty()) extras["server_host"] = EntryModules.primitive(value["host"])
                    if (extras["server_port"].isNullOrEmpty()) extras["server_port"] = EntryModules.primitive(value["port"])
                    if (extras["server_user"].isNullOrEmpty()) extras["server_user"] = EntryModules.primitive(value["username"])
                    if (extras["server_pass"].isNullOrEmpty()) extras["server_pass"] = EntryModules.primitive(value["password"])
                }
                if (module != null) {
                    modules = modules.filter { EntryModules.primitive(it["type"]) != ModuleType.SERVER_CONNECTION }
                }
            }
        }
        cleanDraft = buildDraft()
        isDirty = false
    }

    val draftExtras = extras.toMap()
    val draftImages = images.toList()
    LaunchedEffect(title, username, password, url, targetApp, notes, tagsText, modules, draftExtras, draftImages, breachCount, editDetectedLeak) {
        onDraftChanged(buildDraft())
    }

    LaunchedEffect(editSessionKey) {
        snapshotFlow { buildDraft() }.collect { draft ->
            cleanDraft?.let { baseline -> isDirty = hasMeaningfulEditorChanges(baseline, draft) }
        }
    }

    Scaffold(
        topBar = {
            VaultSubpageTopBar(
                title = categoryLabel(seed.secretType),
                onBack = { if (isDirty) showDiscardDialog = true else onCancel() },
                actions = {
                    IconButton(onClick = {
                        val trimmedTitle = title.trim()
                        if (trimmedTitle.isEmpty()) {
                            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_enter_title), Toast.LENGTH_SHORT).show()
                            return@IconButton
                        }
                        val cardValues = buildList<Map<String, String>> {
                            if (seed.secretType == SecretType.CARD_DOCUMENT) add(extras)
                            modules.filter { EntryModules.primitive(it["type"]) == ModuleType.CARD_DOCUMENT }
                                .forEach { module ->
                                    (module["value"] as? JsonObject)?.let { fields ->
                                        add(fields.mapValues { EntryModules.primitive(it.value) })
                                    }
                                }
                        }
                        if (cardValues.any { fields ->
                            val keys = EntryModules.cardFieldKeys(fields["card_type"].orEmpty())
                            keys.filter { it == "issue_date" || it == "expiry_date" ||
                                (it == "expiry" && fields["card_type"] != EntryModules.CARD_BANK)
                            }.any { !InputFilters.isValidDate(fields[it].orEmpty(), allowLongTerm = it != "issue_date") }
                        }) {
                            Toast.makeText(ctx, com.vault.ui.localizeUiTextFor(ctx, "请输入有效日期（YYYY-MM-DD）。"), Toast.LENGTH_LONG).show()
                            return@IconButton
                        }
                        // 标签对所有可编辑条目类型开放（passkey 不在此编辑页），统一解析保存。
                        // 统一复用 buildDraft()（含关联自动填充项写入），避免内联逻辑漂移。
                        onSave(buildDraft())
                        isDirty = false
                    }) { Icon(Icons.Default.Check, uiText("保存")) }
                },
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad ->
        CompositionLocalProvider(LocalBringIntoViewSpec provides editorBringIntoViewSpec) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(pad)
                    .imePadding()
                    .padding(horizontal = 16.dp)
                    .vaultBackdropSource()
                    .verticalScroll(editorScrollState)
                    .onGloballyPositioned { editorViewportTopPx = it.positionInWindow().y.roundToInt() },
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
            val accent = TypeColors.of(seed.secretType)
            EditorIdentityHeader(
                title = typeLabel(seed.secretType),
                subtitle = typeEditorSubtitle(seed.secretType),
                painter = painterResource(categoryIconRes(seed.secretType)),
                accent = accent,
            )
            EditorSectionHeading("基本信息", "用于识别和查找此条目", accent)
            VaultEditorField(
                value = title,
                onValueChange = { title = InputFilters.capLength(it, 100) }, label = stringResource(R.string.entry_remaining_title),
                modifier = Modifier.fillMaxWidth(),
            )
            when (seed.secretType) {
                SecretType.LOGIN -> {
                    Field(value = username, onChange = { username = it }, label = stringResource(R.string.entry_remaining_username), maxLen = 200)
                    PasswordFieldWithTools(
                        value = password,
                        onChange = { password = it; breachCount = -1; editDetectedLeak = false },
                        leakCheckEnabled = com.vault.security.LeakCheckEnabledPref.enabled.value,
                        onlineLeakCheckEnabled = com.vault.security.LeakOnlineCheckPref.enabled.value,
                        onBreachDetected = { breachCount = it },
                        onLocalLeakDetected = { editDetectedLeak = true },
                    )
                    Field(value = url, onChange = { url = it }, label = stringResource(R.string.entry_remaining_website), maxLen = 500, noWhitespace = true, placeholder = "https://")
                }
                SecretType.CARD_DOCUMENT -> {
                    CardTypeField(extras)
                    val cardType = extras["card_type"].orEmpty().ifBlank { EntryModules.CARD_BANK }
                    run {
                        ScanButton(
                            ocrBusy = ocrBusy,
                            label = if (cardType == EntryModules.CARD_ID_CARD) {
                                uiText("拍照识别身份证")
                            } else if (cardType == EntryModules.CARD_BANK) {
                                uiText("拍照识别银行卡")
                            } else {
                                uiText("拍照获取图像")
                            },
                            onClick = { startScan() },
                        )
                    }
                    ImagesField(images, {
                        if (ContextCompat.checkSelfPermission(ctx, galleryPermission) == PackageManager.PERMISSION_GRANTED) {
                            setExternalActionInProgress(true)
                            pickImage.launch(it)
                        } else {
                            pendingGalleryLauncher = { pickImage.launch(it) }
                            pendingGalleryMime = it
                            if (ActivityCompat.shouldShowRequestPermissionRationale(ctx as Activity, galleryPermission)) {
                                rationalePermission = galleryPermission
                            } else {
                                requestGalleryPermission.launch(galleryPermission)
                            }
                        }
                    }, label = stringResource(R.string.entry_remaining_card_photo), maxImages = 2)
                    when (cardType) {
                        EntryModules.CARD_BANK -> {
                            ExtraField(extras, "cardholder", "持卡人", maxLen = 100)
                            ExtraField(extras, "card_number", "完整卡号", password = true, maxLen = 19, digitsOnly = true, keyboard = KeyboardType.Number, placeholder = "1234 5678 9012 3456", visualTransformation = InputFilters.CardNumberSpacing)
                            ExtraField(extras, "bank", "开户行", maxLen = 80)
                            ExtraField(extras, "bank_branch", "分行/支行", maxLen = 120)
                            ExtraField(extras, "expiry", "有效期 MM/YY", maxLen = 5, formatter = InputFilters::formatExpiryMMYY, keyboard = KeyboardType.Number, placeholder = "MM/YY", cursorToEnd = true)
                            ExtraField(extras, "cvv", "CVV", password = true, maxLen = 4, digitsOnly = true)
                            ExtraField(extras, "withdrawal_password", stringResource(R.string.entry_remaining_withdrawal_password), password = true, maxLen = 6, digitsOnly = true)
                        }
                        EntryModules.CARD_ID_CARD -> {
                            ExtraField(extras, "full_name", "姓名", maxLen = 100)
                            ExtraField(extras, "id_number", "证件号", password = true, maxLen = 60)
                            ExtraField(extras, "issue_date", "签发日期", maxLen = 10, formatter = { InputFilters.formatDate(it) }, keyboard = KeyboardType.Number, placeholder = "YYYY-MM-DD", cursorToEnd = true)
                            ExtraField(extras, "expiry_date", "到期日期", maxLen = 10, formatter = { InputFilters.formatDate(it) }, keyboard = KeyboardType.Number, placeholder = "YYYY-MM-DD", cursorToEnd = true)
                            ExtraField(extras, "issuing_authority", "签发机关", maxLen = 100)
                        }
                        else -> {
                            ExtraField(extras, "card_name", uiText("自定义卡证名称"), maxLen = 100)
                            ExtraField(extras, "card_number", "卡号", password = true, maxLen = 100)
                            ExtraField(extras, "expiry", "有效期", maxLen = 10, formatter = { InputFilters.formatDate(it) }, keyboard = KeyboardType.Number, placeholder = "YYYY-MM-DD", cursorToEnd = true)
                        }
                    }
                    LaunchedEffect(extras["card_number"]) {
                        val full = extras["card_number"].orEmpty().filter { it.isDigit() }
                        if (full.length >= 4) extras["card_number_last4"] = full.takeLast(4)
                    }
                }
                SecretType.WIFI -> {
                    VaultActionButton(
                        onClick = { importCurrentWifi() },
                        enabled = !currentWifiBusy,
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.Wifi, null)
                        Spacer(Modifier.size(8.dp))
                        Text(uiText(if (currentWifiBusy) "正在读取当前 Wi-Fi…" else "导入当前 Wi-Fi"))
                    }
                    VaultActionButton(
                        onClick = { startWifiQrScan() },
                        enabled = !wifiQrBusy,
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.QrCodeScanner, null)
                        Spacer(Modifier.size(8.dp))
                        Text(uiText(if (wifiQrBusy) "正在导入 Wi-Fi…" else "扫码导入 Wi-Fi"))
                    }
                    ExtraField(extras, "ssid", "SSID", maxLen = 32)
                    ExtraField(extras, "wifi_password", stringResource(R.string.entry_remaining_wifi_password), password = true, maxLen = 256)
                    WifiSecurityDropdown(
                        value = extras["security_type"].orEmpty(),
                        onChange = { extras["security_type"] = it },
                    )
                    ExtraField(extras, "router_admin_url", stringResource(R.string.entry_remaining_router_admin_url), maxLen = 200, noWhitespace = true, placeholder = "http://192.168.1.1")
                    ExtraField(extras, "admin_password", stringResource(R.string.entry_remaining_admin_password), password = true, maxLen = 256)
                }
                SecretType.API_KEY -> {
                    ExtraField(extras, "service", stringResource(R.string.entry_remaining_service), maxLen = 100)
                    Field(value = username, onChange = { username = it }, label = stringResource(R.string.entry_remaining_username_appid), maxLen = 200)
                    ExtraField(extras, "api_key", "API Key", password = true, maxLen = 512)
                    ExtraField(extras, "api_secret", "API Secret", password = true, maxLen = 512)
                    ExtraField(extras, "base_url", "Base URL", maxLen = 300, noWhitespace = true, placeholder = "https://api.example.com")
                    ExtraField(extras, "scopes", "Scopes", maxLen = 300, placeholder = "read write admin")
                }
                SecretType.OTP -> {
                    VaultActionButton(
                        onClick = { startOtpQrScan() },
                        shape = VaultShape,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.QrCodeScanner, null)
                        Spacer(Modifier.size(8.dp))
                        Text(uiText("扫码导入"))
                    }
                    // Base32 Secret (required)
                    ExtraField(extras, "secret", stringResource(R.string.entry_remaining_secret), password = true, maxLen = 512, placeholder = stringResource(R.string.entry_remaining_base32_hint))
                    // Issuer
                    ExtraField(extras, "issuer", stringResource(R.string.entry_remaining_issuer), maxLen = 100, placeholder = stringResource(R.string.entry_remaining_issuer_hint))
                    // Label
                    ExtraField(extras, "label", stringResource(R.string.entry_remaining_account_name), maxLen = 100, placeholder = "user@example.com")
                    // 关联域名（用于 issuer 无法覆盖域名的服务，如 Microsoft ↔ live.com）
                    ExtraField(
                        extras, "otp_domains", uiText("关联域名"), maxLen = 500,
                        placeholder = "example.com, example.org",
                    )

                    // 高级选项（折叠）
                    var otpAdvanced by remember { mutableStateOf(false) }
                    VaultActionButton(
                        onClick = { otpAdvanced = !otpAdvanced },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(
                            if (otpAdvanced) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                        )
                        Spacer(Modifier.size(4.dp))
                        Text(uiText("高级选项"))
                    }
                    if (otpAdvanced) {
                        // Algorithm dropdown
                        AlgorithmDropdown(
                            value = extras["algorithm"].orEmpty(),
                            onChange = { extras["algorithm"] = it },
                        )
                        // Digits dropdown
                        DigitsDropdown(
                            value = extras["digits"].orEmpty(),
                            onChange = { extras["digits"] = it },
                        )
                        // Period field
                        ExtraField(extras, "period", stringResource(R.string.entry_remaining_period), maxLen = 5, digitsOnly = true, placeholder = "30")
                        // Type dropdown (TOTP/HOTP)
                        OtpTypeDropdown(
                            value = extras["type"].orEmpty(),
                            onChange = { extras["type"] = it },
                        )
                        // Counter (for HOTP)
                        ExtraField(extras, "counter", stringResource(R.string.entry_remaining_counter), maxLen = 20, digitsOnly = true, placeholder = "0")
                    }
                }
                SecretType.SECURE_NOTE -> {
                    VaultEditorField(
                        value = extras["note"].orEmpty(),
                        onValueChange = { extras["note"] = it },
                        label = stringResource(R.string.entry_remaining_content),
                        singleLine = false,
                        minLines = 10,
                        modifier = Modifier.fillMaxWidth().height(300.dp),
                    )
                }
                SecretType.SERVER -> {
                    ExtraField(extras, "server_host", stringResource(R.string.entry_remaining_host), maxLen = 200, noWhitespace = true, placeholder = "192.168.1.1")
                    ExtraField(extras, "server_port", stringResource(R.string.entry_remaining_port), maxLen = 10, digitsOnly = true, placeholder = "22")
                    ExtraField(extras, "server_user", stringResource(R.string.entry_remaining_username), maxLen = 200)
                    ExtraField(extras, "server_pass", stringResource(R.string.entry_remaining_password), password = true, maxLen = 256)
                }
            }
            // 标签对所有条目类型开放：用于分类和筛选（与登录条目一致的编辑/快捷添加体验）。
            Field(value = tagsText, onChange = { tagsText = it }, label = stringResource(R.string.entry_remaining_tags), maxLen = 300)
            if (existingTags.isNotEmpty()) {
                Text(
                    uiText("已有标签"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val currentTags = remember(tagsText) { splitTags(tagsText) }
                LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(existingTags) { t ->
                        androidx.compose.material3.FilterChip(
                            selected = t in currentTags,
                            onClick = { toggleTag(t) },
                            label = { Text(t) },
                            shape = VaultShape,
                        )
                    }
                }
            }
            if (seed.secretType == SecretType.LOGIN) {
                var showAutofillPicker by remember { mutableStateOf(false) }
                var selectedAutofillCategory by remember { mutableStateOf<String?>(null) }
                var pendingAutofillSelection by remember {
                    mutableStateOf<Triple<Entry, List<ResolvedAutofillValue>, Set<AutofillRole>>?>(null)
                }
                val sourceChoices = remember(autofillSourceOptions) {
                    autofillSourceOptions.associateWith { AutofillSourceResolver.sourceValues(it) }
                }
                val validSourceChoices = remember(sourceChoices) { sourceChoices.filterValues(List<ResolvedAutofillValue>::isNotEmpty) }
                val categoryTypes = autofillLinkCategoryTypes(NavOrderPref.order.value)
                val linkableSourceChoices = remember(validSourceChoices, categoryTypes) {
                    validSourceChoices.filterKeys { it.secretType in categoryTypes }
                }
                val internalRoles = remember(username, password, modules) {
                    AutofillSourceResolver.sourceValues(
                        seed.copy(username = username, password = password).withEntryModules(modules),
                    ).mapTo(linkedSetOf(), ResolvedAutofillValue::role)
                }
                VaultActionButton(
                    onClick = {
                        if (linkableSourceChoices.isEmpty()) {
                            Toast.makeText(ctx, localizeUiTextFor(ctx, "没有可关联的填充内容"), Toast.LENGTH_SHORT).show()
                        } else {
                            selectedAutofillCategory = null
                            showAutofillPicker = true
                        }
                    },
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(painterResource(R.drawable.ic_action_otp_link_custom), null)
                    Spacer(Modifier.size(8.dp))
                    Text(uiText("关联填充内容"))
                }
                autofillLinks.forEach { link ->
                    val source = autofillSourceOptions.firstOrNull { it.id == link.sourceEntryId }
                    val roles = link.fields.map { autofillLinkRoleLabel(it.role) }.distinct().joinToString("、")
                    Surface(
                        shape = VaultShape,
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        modifier = Modifier.align(Alignment.Start),
                    ) {
                        Row(Modifier.padding(horizontal = 10.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            if (source != null) {
                                Icon(
                                    painterResource(categoryIconRes(source.secretType)),
                                    null,
                                    tint = androidx.compose.ui.graphics.Color.Unspecified,
                                    modifier = Modifier.size(18.dp),
                                )
                                Spacer(Modifier.size(6.dp))
                            }
                            Text(
                                "${source?.title ?: uiText("来源不可用")} · $roles",
                                style = MaterialTheme.typography.bodySmall,
                            )
                            IconButton(onClick = { autofillLinks = autofillLinks.filterNot { it.id == link.id } }, modifier = Modifier.size(20.dp)) {
                                Icon(Icons.Default.Close, uiText("清除"), modifier = Modifier.size(14.dp))
                            }
                        }
                    }
                }
                if (showAutofillPicker) {
                    val category = selectedAutofillCategory
                    val pickerRows = if (category == null) {
                        categoryTypes.map { candidateCategory ->
                            val count = linkableSourceChoices.keys.count { it.secretType == candidateCategory }
                            VaultPickerRow(
                                id = candidateCategory,
                                title = categoryLabel(candidateCategory),
                                subtitle = uiText("$count 条"),
                                categoryType = candidateCategory,
                            )
                        }
                    } else {
                        linkableSourceChoices.filterKeys { it.secretType == category }.map { (source, values) ->
                            VaultPickerRow(
                                id = source.id,
                                title = source.title.ifBlank { uiText("未命名条目") },
                                subtitle = values.map { autofillLinkRoleLabel(it.role) }.distinct().joinToString("、"),
                                selected = autofillLinks.any { it.sourceEntryId == source.id },
                                categoryType = source.secretType,
                            )
                        }
                    }
                    VaultPickerSheet(
                        title = if (category == null) uiText("选择分类") else categoryLabel(category),
                        rows = pickerRows,
                        searchPlaceholder = if (category == null) uiText("搜索分类") else uiText("搜索条目"),
                        onDismiss = { showAutofillPicker = false },
                        onBack = if (category == null) null else { { selectedAutofillCategory = null } },
                        onSelect = { row ->
                            if (category == null) {
                                selectedAutofillCategory = row.id
                            } else {
                                val source = linkableSourceChoices.keys.first { it.id == row.id }
                                val values = linkableSourceChoices.getValue(source)
                                    .distinctBy(ResolvedAutofillValue::role)
                                val occupiedExternalRoles = autofillLinks
                                    .filterNot { it.sourceEntryId == source.id }
                                    .flatMapTo(linkedSetOf()) { link -> link.fields.map(AutofillFieldRef::role) }
                                val conflicts = values.mapTo(linkedSetOf(), ResolvedAutofillValue::role)
                                    .intersect(internalRoles + occupiedExternalRoles)
                                if (conflicts.isEmpty()) {
                                    autofillLinks = replaceAutofillEntry(autofillLinks, source, values)
                                } else {
                                    pendingAutofillSelection = Triple(source, values, conflicts)
                                }
                                showAutofillPicker = false
                            }
                        },
                    )
                }
                pendingAutofillSelection?.let { (source, values, conflicts) ->
                    val conflictLabels = mutableListOf<String>()
                    for (conflict in conflicts) conflictLabels += autofillLinkRoleLabel(conflict)
                    VaultDialog(
                        onDismissRequest = { pendingAutofillSelection = null },
                        onClose = { pendingAutofillSelection = null },
                        title = { Text(uiText("自动填充来源冲突")) },
                        text = {
                            Text(
                                "${uiText("以下内容已有来源，请选择保留当前内容或改用新条目：")}\n" +
                                    conflictLabels.joinToString("、"),
                            )
                        },
                        confirmButton = {
                            VaultActionButton(onClick = {
                                autofillLinks = replaceAutofillEntry(autofillLinks, source, values)
                                pendingAutofillSelection = null
                            }) { Text("${uiText("改用")}“${source.title}”") }
                        },
                        dismissButton = {
                            VaultActionButton(onClick = { pendingAutofillSelection = null }) { Text(uiText("保留当前内容")) }
                        },
                    )
                }
                VaultActionButton(
                    onClick = { showAppPicker = true },
                    shape = VaultShape,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Default.Apps, null)
                    Spacer(Modifier.size(8.dp))
                    Text(uiText("选择关联应用"))
                }
                if (targetApp.isNotEmpty()) {
                    Surface(
                        shape = VaultShape,
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        modifier = Modifier.align(Alignment.Start),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                targetApp,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                            )
                            Spacer(Modifier.size(6.dp))
                            IconButton(
                                onClick = { targetApp = "" },
                                modifier = Modifier.size(16.dp),
                            ) {
                                Icon(
                                    Icons.Default.Close,
                                    contentDescription = uiText("清除"),
                                    modifier = Modifier.size(14.dp),
                                    tint = MaterialTheme.colorScheme.onSecondaryContainer.copy(alpha = 0.7f),
                                )
                            }
                        }
                    }
                }
            }
            EditorSectionHeading("附加内容", "按需组合模块，长按模块可调整顺序", accent)
            EntryModuleEditor(
                modules = modules,
                onChange = { modules = it },
                onMarkdownFocusChanged = { focused ->
                    suppressMarkdownBringIntoView = focused
                },
                setExternalActionInProgress = setExternalActionInProgress,
                hasBoundOtp = seed.secretType == SecretType.LOGIN && autofillLinks.any { link ->
                    link.fields.any { it.role == AutofillRole.ONE_TIME_CODE }
                },
                onOtpModuleOverride = {
                    autofillLinks = removeAutofillRole(autofillLinks, AutofillRole.ONE_TIME_CODE)
                },
            )
            EditorSectionHeading("补充额外说明", "不属于字段的附加说明", accent)
            VaultEditorField(
                value = notes,
                onValueChange = { notes = InputFilters.capLength(it, 2000) },
                label = stringResource(R.string.entry_remaining_note_extra),
                singleLine = false,
                minLines = 4,
                modifier = Modifier.fillMaxWidth().height(120.dp),
            )
            Spacer(Modifier.height(72.dp))
            }
        }
    }

    BackHandler(enabled = isDirty) { showDiscardDialog = true }

    // ── 弹窗（放在 Scaffold 之后、函数结束之前，满足 Compose 作用域规则） ──

    if (showDiscardDialog) {
        VaultDialog(
            onDismissRequest ={ showDiscardDialog = false },
            shape = VaultShape,
            title = { Text(uiText("放弃编辑？")) },
            text = { Text(uiText("当前编辑尚未保存，确定放弃吗？")) },
            confirmButton = {
                VaultActionButton(onClick = { showDiscardDialog = false }) { Text(uiText("继续编辑")) }
            },
            dismissButton = {
                VaultActionButton(
                    onClick = {
                        showDiscardDialog = false
                        isDirty = false
                        onCancel()
                    },
                    style = VaultActionStyle.DANGER,
                ) { Text(uiText("放弃")) }
            },
        )
    }

    if (qrChoices.isNotEmpty()) {
        val closeQrChoices = {
            qrChoices = emptyList()
            pendingQrType = QrType.NONE
        }
        VaultDialog(
            onDismissRequest = closeQrChoices,
            shape = VaultShape,
            onClose = closeQrChoices,
            title = { Text(uiText("选择要导入的二维码")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    qrChoices.forEachIndexed { index, (label, raw) ->
                        Surface(
                            modifier = Modifier.fillMaxWidth().clip(VaultShape).clickable {
                                val type = pendingQrType
                                qrChoices = emptyList()
                                pendingQrType = QrType.NONE
                                if (type == QrType.OTP) applyOtpQrPayload(raw) else applyWifiQrPayload(raw, ctx.getString(R.string.entry_remaining_unrecognized_qr))
                            },
                            shape = VaultShape,
                            color = MaterialTheme.colorScheme.surfaceContainer,
                        ) {
                            Text(
                                "${index + 1}. ${label.ifBlank { ctx.getString(R.string.entry_remaining_unnamed_qr) }}",
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 14.dp),
                            )
                        }
                    }
                }
            },
        )
    }

    // 权限说明弹窗：当 shouldShowRequestPermissionRationale 返回 true 时显示
    rationalePermission?.let { perm ->
        val message = when (perm) {
            Manifest.permission.CAMERA -> ctx.getString(R.string.entry_remaining_permission_camera_rationale)
            Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_EXTERNAL_STORAGE ->
                ctx.getString(R.string.entry_remaining_permission_gallery_rationale)
            Manifest.permission.NEARBY_WIFI_DEVICES, Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION ->
                ctx.getString(R.string.entry_remaining_permission_wifi_location)
            else -> ctx.getString(R.string.entry_remaining_permission_other_rationale)
        }
        VaultDialog(
            onDismissRequest ={ rationalePermission = null; wifiQrBusy = false },
            shape = VaultShape,
            title = { Text(stringResource(R.string.entry_remaining_permission_required)) },
            text = { Text(message) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        rationalePermission = null
                        when (perm) {
                            Manifest.permission.CAMERA -> requestCameraPermission.launch(perm)
                            Manifest.permission.NEARBY_WIFI_DEVICES, Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION ->
                                requestWifiLocationPermission.launch(wifiReadPermissions.toTypedArray())
                            else -> requestGalleryPermission.launch(perm)
                        }
                    },
                    style = VaultActionStyle.PRIMARY,
                    shape = VaultShape,
                ) { Text(stringResource(R.string.entry_remaining_allow)) }
            },
            dismissButton = {
                VaultActionButton(onClick = { rationalePermission = null; wifiQrBusy = false }) {
                    Text(uiText("取消"))
                }
            },
        )
    }

    // 国产 ROM 永久拒绝引导弹窗：跳转系统设置页手动授权
    showPermissionSettings?.let { perm ->
        val message = when (perm) {
            Manifest.permission.CAMERA -> ctx.getString(R.string.entry_remaining_permission_camera_denied)
            Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_EXTERNAL_STORAGE ->
                ctx.getString(R.string.entry_remaining_permission_gallery_denied)
            else -> ctx.getString(R.string.entry_remaining_permission_other_denied)
        }
        VaultDialog(
            onDismissRequest ={ showPermissionSettings = null },
            shape = VaultShape,
            title = { Text(stringResource(R.string.entry_remaining_permission_required)) },
            text = { Text(message) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        showPermissionSettings = null
                        try {
                            val intent = android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = android.net.Uri.fromParts("package", ctx.packageName, null)
                            }
                            ctx.startActivity(intent)
                        } catch (_: Exception) {
                            Toast.makeText(ctx, ctx.getString(R.string.entry_remaining_settings_failed), Toast.LENGTH_LONG).show()
                        }
                    },
                    style = VaultActionStyle.PRIMARY,
                    shape = VaultShape,
                ) { Text(stringResource(R.string.entry_remaining_go_settings)) }
            },
            dismissButton = {
                VaultActionButton(onClick = { showPermissionSettings = null }) {
                    Text(uiText("取消"))
                }
            },
        )
    }

    // 批量图片导入实时进度
    importProgress?.let { (done, total) ->
        MediaImportProgressDialog(done = done, total = total, label = ctx.getString(R.string.entry_remaining_importing_images))
    }

    if (showAppPicker) {
        AppPickerSheet(
            onDismiss = { showAppPicker = false },
            onAppSelected = { label, pkg ->
                // 与自动填充保存一致的标题兜底：能查到应用名称用名称，查不到回退包名。
                val resolved = com.vault.autofill.AppNameResolver.label(ctx, pkg) ?: pkg
                if (seed.secretType == SecretType.OTP) {
                    title = resolved
                    extras["issuer"] = resolved
                } else {
                    title = resolved
                    targetApp = pkg
                }
                showAppPicker = false
            },
        )
    }
}

@Composable
private fun ScanButton(
    ocrBusy: Boolean,
    label: String,
    onClick: () -> Unit,
    busyLabel: String = "识别中…",
    icon: ImageVector = Icons.Default.CameraAlt,
    busyClickable: Boolean = false,
) {
    VaultActionButton(
        onClick = onClick,
        enabled = !ocrBusy || busyClickable,
        shape = VaultShape,
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (ocrBusy) {
            BreathingRing(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
            )
            Spacer(Modifier.size(8.dp))
            Text(uiText(busyLabel))
        } else {
            Icon(icon, null)
            Spacer(Modifier.size(8.dp))
            Text(uiText(label))
        }
    }
}

internal fun hasMeaningfulEditorChanges(baseline: Entry, current: Entry): Boolean =
    baseline.title != current.title ||
        baseline.username != current.username ||
        baseline.password != current.password ||
        baseline.url != current.url ||
        baseline.targetApp != current.targetApp ||
        baseline.notes != current.notes ||
        baseline.tags != current.tags ||
        baseline.secretType != current.secretType ||
        baseline.editorComparableFields() != current.editorComparableFields()

private fun Entry.editorComparableFields(): Map<String, kotlinx.serialization.json.JsonElement> = fields

/** Wi-Fi 加密类型下拉框：选项来自跨端统一枚举 [com.vault.os.WifiSecurity.OPTIONS]，
 *  与其他下拉控件一致占满整行，避免右侧出现留白。 */
@Composable
private fun WifiSecurityDropdown(value: String, onChange: (String) -> Unit) {
    val options = com.vault.os.WifiSecurity.OPTIONS
    var expanded by remember { mutableStateOf(false) }
    val displayValue = value.ifEmpty { options.first() }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = uiText(displayValue),
            onValueChange = {},
            label = { Text(uiText("加密类型")) },
            readOnly = true,
            enabled = false,
            trailingIcon = {
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    null,
                )
            },
            shape = VaultShape,
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                disabledTextColor = MaterialTheme.colorScheme.onSurface,
                disabledBorderColor = MaterialTheme.colorScheme.outline,
                disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .clip(VaultShape)
                .clickable { expanded = true },
        )
        com.vault.ui.VaultDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            for (opt in options) {
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text(uiText(opt), fontWeight = if (opt == displayValue) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal) },
                    onClick = { onChange(opt); expanded = false },
                    trailingIcon = selectedDropdownDot(opt == displayValue),
                )
            }
        }
    }
}

/**
 * 登录条目的密码字段：标准 Field + 右侧"生成"按钮 + 泄露警告。
 *  - 生成：弹密码生成器对话框
 *  - 已泄露：本地字典 + Pwned Passwords API 双重检测
 */
@Composable
private fun PasswordFieldWithTools(
    value: String,
    onChange: (String) -> Unit,
    leakCheckEnabled: Boolean = true,
    onlineLeakCheckEnabled: Boolean = true,
    onBreachDetected: (Int) -> Unit = {},
    onLocalLeakDetected: () -> Unit = {},
) {
    val ctx = LocalContext.current
    var showGen by remember { mutableStateOf(false) }
    val leakedLocal = remember(value, leakCheckEnabled) {
        val r = leakCheckEnabled && value.isNotEmpty() && com.vault.security.LeakedPasswordCheck.isLeaked(ctx, value)
        if (r) onLocalLeakDetected()
        r
    }
    var onlineBreaches by remember { mutableStateOf<Int?>(null) }

    LaunchedEffect(value, leakCheckEnabled, onlineLeakCheckEnabled) {
        onlineBreaches = null
        if (!leakCheckEnabled) return@LaunchedEffect
        if (!onlineLeakCheckEnabled) return@LaunchedEffect
        if (value.length < 4) return@LaunchedEffect
        delay(600L)
        // LaunchedEffect 在 key 变化时会自动取消前一个协程，因此此处 value 与启动时一致
        val count = withContext(Dispatchers.IO) {
            com.vault.security.PwnedPasswordsCheck.breachCount(value)
        }
        onlineBreaches = count
        if (count > 0) onBreachDetected(count)
    }

    Column {
        androidx.compose.foundation.layout.Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Box(modifier = Modifier.weight(1f)) {
                Field(value = value, onChange = onChange, label = stringResource(R.string.entry_remaining_password), password = true, maxLen = 256)
            }
            Spacer(Modifier.size(8.dp))
            VaultActionButton(
                onClick = { showGen = true },
                shape = VaultShape,
                contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp),
                modifier = Modifier.height(56.dp),
            ) {
                Icon(Icons.Default.AutoAwesome, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.size(4.dp))
                Text(uiText("生成"))
            }
        }
        if (leakedLocal || (onlineBreaches != null && onlineBreaches!! > 0)) {
            Spacer(Modifier.size(4.dp))
            androidx.compose.foundation.layout.Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(start = 4.dp),
            ) {
                Icon(
                    Icons.Default.Warning,
                    null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(Modifier.size(4.dp))
                val msg = when {
                    leakedLocal && onlineBreaches != null && onlineBreaches!! > 0 ->
                        ctx.getString(R.string.entry_remaining_password_leak_local, onlineBreaches ?: 0)
                    leakedLocal ->
                        ctx.getString(R.string.entry_remaining_password_leak_dictionary)
                    onlineBreaches != null && onlineBreaches!! > 0 ->
                        ctx.getString(R.string.entry_remaining_password_leak_online, onlineBreaches ?: 0)
                    else -> ""
                }
                Text(
                    msg,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
    if (showGen) PasswordGeneratorDialog(
        onCancel = { showGen = false },
        onAccept = { generated ->
            onChange(generated)
            showGen = false
        },
    )
}

/** OTP 算法下拉框 */
@Composable
private fun AlgorithmDropdown(value: String, onChange: (String) -> Unit) {
    val options = listOf("SHA1", "SHA256", "SHA512")
    var expanded by remember { mutableStateOf(false) }
    val displayValue = value.ifEmpty { "SHA1" }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = displayValue,
            onValueChange = {},
            label = { Text(uiText("算法")) },
            readOnly = true,
            enabled = false,
            trailingIcon = {
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    null,
                )
            },
            shape = VaultShape,
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                disabledTextColor = MaterialTheme.colorScheme.onSurface,
                disabledBorderColor = MaterialTheme.colorScheme.outline,
                disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .clip(VaultShape)
                .clickable { expanded = true },
        )
        com.vault.ui.VaultDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            for (opt in options) {
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text(opt, fontWeight = if (opt == displayValue) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal) },
                    onClick = { onChange(opt); expanded = false },
                    trailingIcon = selectedDropdownDot(opt == displayValue),
                )
            }
        }
    }
}

/** OTP 位数下拉框 */
@Composable
private fun DigitsDropdown(value: String, onChange: (String) -> Unit) {
    val options = listOf("6", "7", "8")
    var expanded by remember { mutableStateOf(false) }
    val displayValue = value.ifEmpty { "6" }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = displayValue,
            onValueChange = {},
            label = { Text(uiText("位数")) },
            readOnly = true,
            enabled = false,
            trailingIcon = {
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    null,
                )
            },
            shape = VaultShape,
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                disabledTextColor = MaterialTheme.colorScheme.onSurface,
                disabledBorderColor = MaterialTheme.colorScheme.outline,
                disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .clip(VaultShape)
                .clickable { expanded = true },
        )
        com.vault.ui.VaultDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            for (opt in options) {
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text(opt, fontWeight = if (opt == displayValue) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal) },
                    onClick = { onChange(opt); expanded = false },
                    trailingIcon = selectedDropdownDot(opt == displayValue),
                )
            }
        }
    }
}

/** OTP 类型下拉框 (TOTP/HOTP) */
@Composable
private fun OtpTypeDropdown(value: String, onChange: (String) -> Unit) {
    val options = listOf("totp", "hotp")
    var expanded by remember { mutableStateOf(false) }
    val displayValue = value.ifEmpty { "totp" }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = displayValue,
            onValueChange = {},
            label = { Text(uiText("类型")) },
            readOnly = true,
            enabled = false,
            trailingIcon = {
                Icon(
                    if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    null,
                )
            },
            shape = VaultShape,
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                disabledTextColor = MaterialTheme.colorScheme.onSurface,
                disabledBorderColor = MaterialTheme.colorScheme.outline,
                disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .clip(VaultShape)
                .clickable { expanded = true },
        )
        com.vault.ui.VaultDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            for (opt in options) {
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text(opt.uppercase(), fontWeight = if (opt == displayValue) androidx.compose.ui.text.font.FontWeight.Bold else androidx.compose.ui.text.font.FontWeight.Normal) },
                    onClick = { onChange(opt); expanded = false },
                    trailingIcon = selectedDropdownDot(opt == displayValue),
                )
            }
        }
    }
}

/**
 * 通用单行字段：支持长度上限 / 只数字 / 禁空白 / 自定义格式化 / 自定义键盘类型 / 占位符 / 密文。
 * 文本变换顺序：formatter → digitsOnly → noWhitespace → capLength。
 */
@Composable
private fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    password: Boolean = false,
    maxLen: Int = 256,
    digitsOnly: Boolean = false,
    noWhitespace: Boolean = false,
    formatter: ((String) -> String)? = null,
    keyboard: KeyboardType = KeyboardType.Text,
    placeholder: String? = null,
    visualTransformation: androidx.compose.ui.text.input.VisualTransformation = androidx.compose.ui.text.input.VisualTransformation.None,
    cursorToEnd: Boolean = false,
) {
    var masked by remember { mutableStateOf(false) }
    var focused by remember { mutableStateOf(false) }
    val sanitize: (String) -> String = { raw ->
        var t = formatter?.invoke(raw) ?: raw
        if (digitsOnly) t = InputFilters.digitsOnly(t)
        if (noWhitespace) t = InputFilters.noWhitespace(t)
        InputFilters.capLength(t, maxLen)
    }
    val effectiveTransform = if (password && masked) PasswordVisualTransformation() else visualTransformation
    val visibilityIcon: (@Composable () -> Unit)? = if (password) {
        { VaultVisibilityButton(visible = !masked, onClick = { masked = !masked }) }
    } else null
    if (cursorToEnd) {
        // 有效期/证件日期等短字段：始终把光标放在末尾，避免格式化（MM/YY、补横线）后光标跳到中间。
        var editorValue by remember { mutableStateOf(TextFieldValue(value, TextRange(value.length))) }
        LaunchedEffect(value) {
            if (value != editorValue.text) editorValue = TextFieldValue(value, TextRange(value.length))
        }
        VaultEditorField(
            value = editorValue,
            onValueChange = { next ->
                val t = sanitize(next.text)
                editorValue = TextFieldValue(t, TextRange(t.length))
                if (t != value) onChange(t)
            },
            label = label,
            placeholder = placeholder,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = if (digitsOnly) KeyboardType.Number else keyboard),
            visualTransformation = effectiveTransform,
            trailingIcon = visibilityIcon,
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { state ->
                    if (state.isFocused) {
                        editorValue = TextFieldValue(editorValue.text, TextRange(editorValue.text.length))
                    } else if (focused && formatter != null) {
                        val formatted = formatter(value)
                        if (formatted != value) onChange(formatted)
                    }
                    focused = state.isFocused
                },
        )
    } else {
        VaultEditorField(
            value = value,
            onValueChange = { raw -> onChange(sanitize(raw)) },
            label = label,
            placeholder = placeholder,
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = if (digitsOnly) KeyboardType.Number else keyboard),
            visualTransformation = effectiveTransform,
            trailingIcon = visibilityIcon,
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { state ->
                    if (focused && !state.isFocused && formatter != null) {
                        val formatted = formatter(value)
                        if (formatted != value) onChange(formatted)
                    }
                    focused = state.isFocused
                },
        )
    }
}

@Composable
private fun ExtraField(
    extras: androidx.compose.runtime.snapshots.SnapshotStateMap<String, String>,
    key: String,
    label: String,
    password: Boolean = false,
    maxLen: Int = 256,
    digitsOnly: Boolean = false,
    noWhitespace: Boolean = false,
    formatter: ((String) -> String)? = null,
    keyboard: KeyboardType = KeyboardType.Text,
    placeholder: String? = null,
    visualTransformation: androidx.compose.ui.text.input.VisualTransformation = androidx.compose.ui.text.input.VisualTransformation.None,
    cursorToEnd: Boolean = false,
) {
    Field(
        value = extras[key].orEmpty(),
        onChange = { extras[key] = it },
        label = label,
        password = password,
        maxLen = maxLen,
        digitsOnly = digitsOnly,
        noWhitespace = noWhitespace,
        formatter = formatter,
        keyboard = keyboard,
        placeholder = placeholder,
        visualTransformation = visualTransformation,
        cursorToEnd = cursorToEnd,
    )
}

@Composable
private fun ReadOnlyField(value: String, label: String) {
    VaultEditorField(
        value = value,
        onValueChange = {},
        label = label,
        readOnly = true,
        enabled = false,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun cardTypeLabel(value: String): String = when (value) {
    "银行卡" -> stringResource(R.string.entry_remaining_card_type_bank)
    "身份证" -> stringResource(R.string.entry_remaining_id_type_identity)
    "其他卡证", "自定义" -> stringResource(R.string.entry_remaining_card_type_custom)
    "会员卡" -> stringResource(R.string.entry_remaining_card_type_membership)
    "社保卡" -> stringResource(R.string.entry_remaining_card_type_social_security)
    else -> value
}


@Composable
private fun CardTypeField(extras: androidx.compose.runtime.snapshots.SnapshotStateMap<String, String>) {
    var expanded by remember { mutableStateOf(false) }
    val current = extras["card_type"].orEmpty().takeIf(EntryModules.cardTypeLabels::containsKey)
        ?: EntryModules.CARD_BANK
    Box(Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = cardTypeLabel(EntryModules.cardTypeLabels.getValue(current)),
            onValueChange = {},
            readOnly = true,
            enabled = false,
            label = { Text(stringResource(R.string.entry_remaining_card_type)) },
            trailingIcon = { Icon(if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown, null) },
            shape = VaultShape,
            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                disabledTextColor = MaterialTheme.colorScheme.onSurface,
                disabledBorderColor = MaterialTheme.colorScheme.outline,
                disabledLabelColor = MaterialTheme.colorScheme.onSurfaceVariant,
                disabledTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
        Box(Modifier.matchParentSize().clip(VaultShape).clickable { expanded = true })
        com.vault.ui.VaultDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            EntryModules.cardTypeLabels.forEach { (stored, label) ->
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text(cardTypeLabel(label)) },
                    onClick = { extras["card_type"] = stored; expanded = false },
                    trailingIcon = selectedDropdownDot(stored == current),
                )
            }
        }
    }
}

private fun selectedDropdownDot(selected: Boolean): (@Composable () -> Unit)? = if (selected) {
    { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
} else {
    null
}


@Composable
private fun ImagesField(
    images: androidx.compose.runtime.snapshots.SnapshotStateList<String>,
    onPick: (String) -> Unit,
    label: String,
    maxImages: Int = MAX_IMAGES_PER_MODULE,
) {
    val deleteText = stringResource(R.string.entry_remaining_delete)
    Column {
        Text(label, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(6.dp))
        // 卡片需要 padding 给删除按钮的悬浮位置留出空间，避免被外层裁剪
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(top = 8.dp, end = 4.dp),
        ) {
            itemsIndexed(images) { idx, b64 ->
                var showViewer by remember(b64) { mutableStateOf(false) }
                if (showViewer) ImageViewerDialog(images = images, initialIndex = idx, onClose = { showViewer = false })
                Box(modifier = Modifier.size(128.dp)) {
                    // 图片本体在内层（圆角裁剪）；点击放大查看
                    Box(
                        modifier = Modifier
                            .padding(top = 6.dp, end = 6.dp)
                            .size(122.dp)
                            .clip(VaultShape)
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .clickable { showViewer = true },
                    ) {
                        Base64Image(b64 = b64, maxDecodePx = 512, modifier = Modifier.fillMaxSize())
                    }
                    // 删除按钮：浮在右上角外侧，独立 32dp 圆形，主色 + 阴影
                    androidx.compose.material3.FilledIconButton(
                        onClick = { images.removeAt(idx) },
                        shape = CircleShape,
                        colors = androidx.compose.material3.IconButtonDefaults.filledIconButtonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ),
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .size(32.dp),
                    ) { Icon(Icons.Default.Close, deleteText, modifier = Modifier.size(18.dp)) }
                }
            }
            if (images.size < maxImages) {
                item {
                    Box(
                        modifier = Modifier
                            .size(120.dp)
                            .clip(VaultShape)
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .clickable { onPick("image/*") },
                        contentAlignment = Alignment.Center,
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.AddPhotoAlternate, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.height(4.dp))
                            Text(uiText("添加图片"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }
}

private fun extraKeysFor(type: String): List<String> = when (type) {
    SecretType.CARD_DOCUMENT -> listOf(
        "card_type", "cardholder", "bank", "bank_branch",
        "card_number", "card_number_last4", "expiry", "cvv", "withdrawal_password",
        "full_name", "id_number", "issuing_authority", "issue_date", "expiry_date",
        "card_name", "notes",
    )
    SecretType.WIFI -> listOf("ssid", "wifi_password", "security_type", "router_admin_url", "admin_password")
    SecretType.API_KEY -> listOf("service", "api_key", "api_secret", "base_url", "scopes")
    SecretType.OTP -> listOf("secret", "algorithm", "digits", "period", "issuer", "label", "type", "counter", "otp_domains")
    SecretType.SECURE_NOTE -> listOf("note")
    SecretType.SERVER -> listOf("server_host", "server_port", "server_user", "server_pass")
    else -> emptyList()
}

private fun imageKeyFor(type: String): String? = when (type) {
    SecretType.CARD_DOCUMENT -> "card_images_b64"
    else -> null
}
