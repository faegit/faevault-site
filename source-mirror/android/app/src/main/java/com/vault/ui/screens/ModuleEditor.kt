package com.vault.ui.screens

import com.vault.ui.vaultPopupCardSurface

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.location.Geocoder
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.provider.OpenableColumns
import android.text.format.DateFormat
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import com.vault.ui.VaultLazyRow as LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.BasicTextField
import com.vault.ui.vaultVerticalScroll as verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.DragHandle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDefaults
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import com.vault.ui.VaultDropdownMenu as DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.vault.R
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.OtpUtils
import com.vault.model.autofill.AutofillRole
import com.vault.ocr.CardParser
import com.vault.ocr.Ocr
import com.vault.os.WifiQr
import com.vault.ui.CapsuleOption
import com.vault.ui.CapsuleSegmentedControl
import com.vault.ui.uiText
import com.vault.ui.VaultIconResources
import com.vault.ui.VaultSwitch
import com.vault.ui.localizeUiTextFor
import com.vault.ui.media.Base64Image
import com.vault.ui.media.ImageViewerDialog
import com.vault.ui.media.MAX_ATTACHMENT_MODULE_BYTES
import com.vault.ui.media.MAX_IMAGES_PER_MODULE
import com.vault.ui.media.PmvMediaUiSession
import com.vault.ui.media.PmvMediaSessionLockedException
import com.vault.ui.media.encodeImageFromUri
import com.vault.ui.media.attachmentFileFromRef
import com.vault.ui.media.storeAttachmentFromUri
import com.vault.ui.media.mediaListStrings
import com.vault.ui.media.MediaImportProgressDialog
import com.vault.ui.scan.CameraScanActivity
import com.vault.ui.scan.QrLiveScanActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.coroutines.launch
import java.time.DayOfWeek
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.YearMonth
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.TextStyle
import java.time.temporal.WeekFields
import java.util.Locale
import com.vault.ui.VaultShape

internal data class CalendarWeekLayout(
    val weekdays: List<DayOfWeek>,
    val firstDayOffset: Int,
)

internal fun calendarWeekLayout(locale: Locale, month: YearMonth): CalendarWeekLayout {
    val firstDayOfWeek = if (locale.language == "zh" && locale.country == "CN") {
        DayOfWeek.MONDAY
    } else {
        WeekFields.of(locale).firstDayOfWeek
    }
    return CalendarWeekLayout(
        weekdays = List(7) { firstDayOfWeek.plus(it.toLong()) },
        firstDayOffset = (month.atDay(1).dayOfWeek.value - firstDayOfWeek.value + 7) % 7,
    )
}

@Composable
private fun moduleFieldLabel(key: String): String = when (key) {
    "username" -> stringResource(R.string.entry_remaining_username)
    "password" -> stringResource(R.string.entry_remaining_password)
    "api_key" -> stringResource(R.string.entry_remaining_api_key)
    "api_secret" -> stringResource(R.string.entry_remaining_api_secret)
    "ssid" -> "SSID"
    "wifi_password" -> uiText("Wi-Fi 密码")
    "security_type" -> uiText("加密类型")
    "router_admin_url" -> uiText("管理地址")
    "admin_password" -> uiText("管理密码")
    "host" -> uiText("主机 / IP")
    "port" -> uiText("端口")
    "private_key" -> uiText("私钥")
    "fingerprint" -> uiText("指纹")
    "engine" -> uiText("数据库类型")
    "database" -> uiText("数据库名")
    "secret" -> uiText("密钥")
    "issuer" -> uiText("发行方")
    "label" -> uiText("账户名")
    "algorithm" -> uiText("算法")
    "digits" -> uiText("位数")
    "period" -> uiText("周期")
"type" -> uiText("类型")
    "counter" -> uiText("计数器")
    "otp_domains" -> uiText("关联域名")
    "cardholder" -> uiText("持卡人")
    "card_number" -> uiText("卡号")
    "cvv" -> "CVV"
    "withdrawal_password" -> uiText("取款密码")
    "expiry" -> uiText("有效期")
    "bank" -> uiText("银行")
    "bank_branch" -> uiText("分行/支行")
    "card_type" -> uiText("卡片类型")
    "card_name" -> uiText("自定义卡证名称")
    "notes" -> uiText("备注")
    "full_name" -> uiText("姓名")
    "id_number" -> uiText("证件号码")
    "issue_date" -> uiText("签发日期")
    "expiry_date" -> uiText("到期日期")
    "issuing_authority" -> uiText("签发机关")
    "country" -> uiText("国家 / 地区")
    "region" -> uiText("省 / 州")
    "city" -> uiText("城市")
    "address" -> uiText("详细地址")
    "postal_code" -> uiText("邮编")
    "question" -> uiText("安全问题")
    "answer" -> uiText("答案")
    else -> key
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryModuleEditor(
    modules: List<JsonObject>,
    onChange: (List<JsonObject>) -> Unit,
    onMarkdownFocusChanged: (Boolean) -> Unit = {},
    setExternalActionInProgress: (Boolean) -> Unit = {},
    hasBoundOtp: Boolean = false,
    onOtpModuleOverride: (() -> Unit)? = null,
) {
    var showPicker by remember { mutableStateOf(false) }
    var pendingOtpOverride by remember { mutableStateOf<String?>(null) }
    var deleteIndex by remember { mutableStateOf<Int?>(null) }
    var dragIndex by remember { mutableStateOf<Int?>(null) }
    var dragOffset by remember { mutableFloatStateOf(0f) }
    var dragSwapCompleted by remember { mutableStateOf(false) }
    val reorderThreshold = with(LocalDensity.current) { 48.dp.toPx() }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val latestModules by rememberUpdatedState(modules)
    var pendingModuleId by remember { mutableStateOf<String?>(null) }
    var pendingAction by remember { mutableStateOf<String?>(null) }
    // 正在获取当前位置的模块 id：定位结束前按钮保持禁用并显示进行中提示
    var locatingModuleId by remember { mutableStateOf<String?>(null) }
    // 定位权限被拒后再次请求前的说明弹窗；国产 ROM 永久拒绝后引导前往系统设置
    var locationRationale by remember { mutableStateOf(false) }
    var locationSettings by remember { mutableStateOf(false) }
    var otpChoices by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var wifiChoices by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }

    fun updateModule(id: String, transform: (JsonObject) -> JsonObject) {
        val current = latestModules
        val index = current.indexOfFirst { EntryModules.primitive(it["id"]) == id }
        if (index < 0) return
        onChange(current.toMutableList().also { it[index] = transform(it[index]) })
    }

    fun fillCompound(id: String, values: Map<String, String>, overwrite: Boolean = false) {
        updateModule(id) { module ->
            val current = module["value"] as? JsonObject ?: JsonObject(emptyMap())
            val merged = current.toMutableMap()
            values.forEach { (key, value) ->
                if (value.isNotBlank() && (overwrite || EntryModules.primitive(merged[key]).isBlank())) {
                    merged[key] = JsonPrimitive(value)
                }
            }
            module.with("value", JsonObject(merged))
        }
    }

    fun appendDocumentImage(id: String, encoded: String): Boolean {
        var added = false
        updateModule(id) { module ->
            val current = module["value"] as? JsonObject ?: JsonObject(emptyMap())
            val imagesRaw = (current["images"] as? JsonArray).orEmpty()
            val images = mediaListStrings(imagesRaw)
            val moduleType = EntryModules.primitive(module["type"])
            val maxImages = if (moduleType == ModuleType.CARD_DOCUMENT) {
                2
            } else {
                MAX_IMAGES_PER_MODULE
            }
            when {
                images.size >= maxImages -> Toast.makeText(
                    context,
                    if (maxImages <= 2) context.getString(R.string.entry_remaining_image_limit_two) else context.getString(R.string.entry_remaining_image_limit),
                    Toast.LENGTH_SHORT,
                ).show()
                encoded in images -> Toast.makeText(context, context.getString(R.string.entry_remaining_image_exists), Toast.LENGTH_SHORT).show()
                else -> {
                    added = true
                    return@updateModule module.with(
                        "value",
                        // 保留既有元素（含 PMVE JsonObject 引用），只追加新图
                        current.with("images", JsonArray(imagesRaw.toList() + JsonPrimitive(encoded))),
                    )
                }
            }
            module
        }
        return added
    }

    fun applyOtp(id: String, raw: String): Boolean {
        val parsed = OtpUtils.parseOtpAuthUri(raw) ?: return false
        val (type, secret, params) = parsed
        if (type == null || secret.isNullOrBlank()) return false
        fillCompound(id, buildMap {
            put("type", type); put("secret", secret)
            listOf("issuer", "label", "algorithm", "digits", "period", "counter").forEach { key ->
                params[key]?.let { put(key, it) }
            }
        }, overwrite = true)
        return true
    }

    fun applyWifi(id: String, raw: String): Boolean {
        val parsed = WifiQr.parse(raw) ?: return false
        updateModule(id) { module ->
            val current = (module["value"] as? JsonObject ?: JsonObject(emptyMap())).toMutableMap()
            current["ssid"] = JsonPrimitive(parsed.ssid)
            current["wifi_password"] = JsonPrimitive(parsed.password)
            current["security_type"] = JsonPrimitive(parsed.security)
            module.with("value", JsonObject(current))
        }
        return true
    }

    suspend fun applyOcr(id: String, uri: android.net.Uri) {
        val sourceModule = latestModules.firstOrNull { EntryModules.primitive(it["id"]) == id } ?: return
        val type = EntryModules.primitive(sourceModule["type"])
        val cardType = (sourceModule["value"] as? JsonObject)?.let { EntryModules.primitive(it["card_type"]) }
            .orEmpty().ifBlank { EntryModules.CARD_BANK }
        val encoded = withContext(Dispatchers.IO) { encodeImageFromUri(context, uri) }
        if (!appendDocumentImage(id, encoded)) return
        // 身份证不走银行卡卡面 OCR。
        if (type == ModuleType.CARD_DOCUMENT && cardType == EntryModules.CARD_ID_CARD) return
        // 仅前 2 张图片自动 OCR 填表
        val module = latestModules.firstOrNull { EntryModules.primitive(it["id"]) == id }
            ?: return
        val images = (module["value"] as? JsonObject)?.let { it["images"] as? JsonArray }.orEmpty()
        if (images.size > 2) return
        val text = Ocr.recognize(context, uri)
        val parsed = when (type) {
            ModuleType.CARD_DOCUMENT -> CardParser.parseCreditCard(text)
            else -> emptyMap()
        }
        if (parsed.isEmpty()) Toast.makeText(context, context.getString(R.string.entry_remaining_unrecognized_fields_count), Toast.LENGTH_SHORT).show()
        else {
            fillCompound(id, parsed)
            Toast.makeText(context, context.getString(R.string.entry_remaining_recognized_fields, parsed.size), Toast.LENGTH_SHORT).show()
        }
    }

    val mediaLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        setExternalActionInProgress(false)
        val id = pendingModuleId
        val action = pendingAction
        pendingModuleId = null; pendingAction = null
        if (uri == null || id == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                when (action) {
                    "ocr_gallery" -> applyOcr(id, uri)
                }
            }.onFailure {
                Toast.makeText(
                    context,
                    if (it is PmvMediaSessionLockedException) context.getString(R.string.system_media_session_locked)
                    else context.getString(R.string.entry_remaining_processing_failed, it.message ?: context.getString(R.string.entry_remaining_unable_read)),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    val cameraLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        setExternalActionInProgress(false)
        val id = pendingModuleId
        pendingModuleId = null; pendingAction = null
        val uri = result.data?.data
        if (result.resultCode == Activity.RESULT_OK && id != null && uri != null) {
            scope.launch { runCatching { applyOcr(id, uri) }.onFailure {
                Toast.makeText(
                    context,
                    if (it is PmvMediaSessionLockedException) context.getString(R.string.system_media_session_locked)
                    else context.getString(R.string.entry_remaining_ocr_failed, it.message ?: context.getString(R.string.entry_remaining_processing)),
                    Toast.LENGTH_LONG,
                ).show()
            } }
        }
    }

    val otpCameraLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        setExternalActionInProgress(false)
        val id = pendingModuleId
        pendingModuleId = null; pendingAction = null
        val raw = result.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT)
        if (result.resultCode == Activity.RESULT_OK && id != null && raw != null && !applyOtp(id, raw)) {
            Toast.makeText(context, localizeUiTextFor(context, "不是有效的 TOTP/HOTP 二维码"), Toast.LENGTH_LONG).show()
        }
    }

    val wifiCameraLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        setExternalActionInProgress(false)
        val id = pendingModuleId
        pendingModuleId = null; pendingAction = null
        val raw = result.data?.getStringExtra(QrLiveScanActivity.EXTRA_RESULT)
        if (result.resultCode == Activity.RESULT_OK && id != null && raw != null && !applyWifi(id, raw)) {
            Toast.makeText(context, localizeUiTextFor(context, "不是有效的 Wi-Fi 二维码"), Toast.LENGTH_LONG).show()
        }
    }

fun useCurrentLocation(id: String) {
        scope.launch {
            locatingModuleId = id
            runCatching {
                val values = withContext(Dispatchers.IO) {
                    val manager = context.getSystemService(android.content.Context.LOCATION_SERVICE) as LocationManager
                    val location = currentOrLastLocation(context, manager)
                    val address = if (Build.VERSION.SDK_INT >= 33) {
                        withTimeoutOrNull(10_000) {
                            kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
                                Geocoder(context, Locale.getDefault()).getFromLocation(location.latitude, location.longitude, 1) { result ->
                                    if (continuation.isActive) continuation.resume(result.firstOrNull()) { _, _, _ -> }
                                }
                            }
                        }
                    } else {
                        @Suppress("DEPRECATION") Geocoder(context, Locale.getDefault())
                            .getFromLocation(location.latitude, location.longitude, 1)?.firstOrNull()
                    }
                    buildMap {
                        address?.countryName?.let { put("country", it) }
                        address?.adminArea?.let { put("region", it) }
                        (address?.locality ?: address?.subAdminArea)?.let { put("city", it) }
                        address?.getAddressLine(0)?.let { put("address", it) }
                        address?.postalCode?.let { put("postal_code", it) }
                        if (address == null) put("address", "${location.latitude}, ${location.longitude}")
                    }
                }
                if (values.isEmpty()) error(localizeUiTextFor(context, "无法解析当前位置"))
                fillCompound(id, values)
                Toast.makeText(context, localizeUiTextFor(context, "已填入当前位置"), Toast.LENGTH_SHORT).show()
            }.onFailure { Toast.makeText(context, it.message ?: localizeUiTextFor(context, "定位失败"), Toast.LENGTH_LONG).show() }
            locatingModuleId = null
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val id = pendingModuleId ?: return@rememberLauncherForActivityResult
        val action = pendingAction
        if (!granted) {
            setExternalActionInProgress(false)
            pendingModuleId = null; pendingAction = null
            Toast.makeText(context, localizeUiTextFor(context, "未授予所需权限"), Toast.LENGTH_SHORT).show()
        } else when (action) {
            "otp_camera" -> {
                setExternalActionInProgress(true)
                otpCameraLauncher.launch(QrLiveScanActivity.intent(context, QrLiveScanActivity.PURPOSE_OTP))
            }
            "wifi_camera" -> {
                setExternalActionInProgress(true)
                wifiCameraLauncher.launch(QrLiveScanActivity.intent(context, QrLiveScanActivity.PURPOSE_WIFI))
            }
            "ocr_camera" -> {
                setExternalActionInProgress(true)
                cameraLauncher.launch(android.content.Intent(context, CameraScanActivity::class.java))
            }
            "location" -> { pendingModuleId = null; pendingAction = null; useCurrentLocation(id) }
        }
    }

val locationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        val id = pendingModuleId
        val granted = result[Manifest.permission.ACCESS_COARSE_LOCATION] == true ||
            result[Manifest.permission.ACCESS_FINE_LOCATION] == true
        pendingModuleId = null; pendingAction = null
        if (granted && id != null) useCurrentLocation(id)
        else {
            val deniedForever = !ActivityCompat.shouldShowRequestPermissionRationale(
                context as Activity, Manifest.permission.ACCESS_COARSE_LOCATION,
            ) && !ActivityCompat.shouldShowRequestPermissionRationale(
                context as Activity, Manifest.permission.ACCESS_FINE_LOCATION,
            )
            if (deniedForever) locationSettings = true
            else Toast.makeText(context, localizeUiTextFor(context, "未授予位置权限"), Toast.LENGTH_SHORT).show()
        }
    }

    fun launchProtected(id: String, action: String, permission: String, launch: () -> Unit) {
        pendingModuleId = id; pendingAction = action
        if (ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED) {
            setExternalActionInProgress(true)
            launch()
        }
        else permissionLauncher.launch(permission)
    }

    modules.forEachIndexed { index, module ->
        val isDragging = dragIndex == index
        val moduleId = EntryModules.primitive(module["id"])
        androidx.compose.runtime.key(moduleId.ifEmpty { "module-$index" }) { ModuleCard(
            module = module,
            isDragging = isDragging,
            dragTranslation = if (isDragging) dragOffset else 0f,
            onChange = { changed -> onChange(modules.toMutableList().also { it[index] = changed }) },
            onMarkdownFocusChanged = onMarkdownFocusChanged,
            onDelete = {
                if (moduleHasContent(module)) deleteIndex = index
                else onChange(modules.toMutableList().also { it.removeAt(index) })
            },
            onStartDrag = {
                dragSwapCompleted = false
                dragIndex = index
                dragOffset = 0f
            },
            onDrag = { change, amount ->
                change.consume()
                if (dragSwapCompleted) return@ModuleCard
                val draggingOutOfBounds =
                    (index == 0 && amount.y < 0f) ||
                    (index == modules.lastIndex && amount.y > 0f)
                if (draggingOutOfBounds) {
                    dragOffset = 0f
                    return@ModuleCard
                }
                val newOffset = dragOffset + amount.y
                if (kotlin.math.abs(newOffset) >= reorderThreshold) {
                    val target = index + if (newOffset > 0) 1 else -1
                    if (target in modules.indices) {
                        val reordered = modules.toMutableList()
                        val item = reordered.removeAt(index)
                        reordered.add(target, item)
                        dragSwapCompleted = true
                        dragIndex = null
                        dragOffset = 0f
                        onChange(reordered)
                    }
                    if (!dragSwapCompleted) dragOffset = 0f
                } else {
                    dragOffset = newOffset
                }
            },
            onDragEnd = {
                dragSwapCompleted = false
                dragIndex = null
                dragOffset = 0f
            },
            onOtpCamera = {
                launchProtected(moduleId, "otp_camera", Manifest.permission.CAMERA) {
                    otpCameraLauncher.launch(QrLiveScanActivity.intent(context, QrLiveScanActivity.PURPOSE_OTP))
                }
            },
            onWifiCamera = {
                launchProtected(moduleId, "wifi_camera", Manifest.permission.CAMERA) {
                    wifiCameraLauncher.launch(QrLiveScanActivity.intent(context, QrLiveScanActivity.PURPOSE_WIFI))
                }
            },
            onOcrCamera = {
                launchProtected(moduleId, "ocr_camera", Manifest.permission.CAMERA) {
                    cameraLauncher.launch(android.content.Intent(context, CameraScanActivity::class.java))
                }
            },
            onOcrGallery = {
                pendingModuleId = moduleId; pendingAction = "ocr_gallery"
                setExternalActionInProgress(true)
                mediaLauncher.launch("image/*")
            },
onLocation = {
                if (locatingModuleId == moduleId) return@ModuleCard
                Toast.makeText(context, localizeUiTextFor(context, "正在获取当前位置…"), Toast.LENGTH_SHORT).show()
                pendingModuleId = moduleId; pendingAction = "location"
                val locationGranted = ContextCompat.checkSelfPermission(
                    context, Manifest.permission.ACCESS_COARSE_LOCATION,
                ) == PackageManager.PERMISSION_GRANTED || ContextCompat.checkSelfPermission(
                    context, Manifest.permission.ACCESS_FINE_LOCATION,
                ) == PackageManager.PERMISSION_GRANTED
                if (locationGranted) {
                    pendingModuleId = null; pendingAction = null
                    useCurrentLocation(moduleId)
                } else if (
                    ActivityCompat.shouldShowRequestPermissionRationale(
                        context as Activity, Manifest.permission.ACCESS_COARSE_LOCATION,
                    ) || ActivityCompat.shouldShowRequestPermissionRationale(
                        context as Activity, Manifest.permission.ACCESS_FINE_LOCATION,
                    )
                ) {
                    locationRationale = true
                } else {
                    locationPermissionLauncher.launch(arrayOf(
                        Manifest.permission.ACCESS_COARSE_LOCATION,
                        Manifest.permission.ACCESS_FINE_LOCATION,
                    ))
                }
            },
            setExternalActionInProgress = setExternalActionInProgress,
            locatingModuleId = locatingModuleId,
        ) }
    }

    // ── 定位权限说明弹窗 ──────────────────────────────────────────
    if (locationRationale) {
        VaultDialog(
            onDismissRequest = { locationRationale = false },
            shape = VaultShape,
            title = { Text(stringResource(R.string.entry_remaining_permission_required)) },
            text = { Text(stringResource(R.string.entry_remaining_location_rationale)) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        locationRationale = false
                        locationPermissionLauncher.launch(arrayOf(
                            Manifest.permission.ACCESS_COARSE_LOCATION,
                            Manifest.permission.ACCESS_FINE_LOCATION,
                        ))
                    },
                    style = VaultActionStyle.PRIMARY,
                    shape = VaultShape,
                ) { Text(stringResource(R.string.entry_remaining_allow)) }
            },
            dismissButton = {
                VaultActionButton(onClick = { locationRationale = false }) { Text(uiText("取消")) }
            },
        )
    }

    // 国产 ROM 永久拒绝定位权限：跳转系统设置页手动授权
    if (locationSettings) {
        VaultDialog(
            onDismissRequest = { locationSettings = false },
            shape = VaultShape,
            title = { Text(stringResource(R.string.entry_remaining_permission_required)) },
            text = { Text(stringResource(R.string.entry_remaining_location_denied)) },
            confirmButton = {
                VaultActionButton(
                    onClick = {
                        locationSettings = false
                        try {
                            val intent = android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = android.net.Uri.fromParts("package", context.packageName, null)
                            }
                            context.startActivity(intent)
                        } catch (_: Exception) {
                            Toast.makeText(
                                context,
                                context.getString(R.string.entry_remaining_settings_failed),
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                    },
                    style = VaultActionStyle.PRIMARY,
                    shape = VaultShape,
                ) { Text(stringResource(R.string.entry_remaining_go_settings)) }
            },
            dismissButton = {
                VaultActionButton(onClick = { locationSettings = false }) { Text(uiText("取消")) }
            },
        )
    }

    Surface(
        onClick = { showPicker = true },
        shape = VaultShape,
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Default.Add, contentDescription = null)
            Spacer(Modifier.size(8.dp))
            Text(if (modules.isEmpty()) uiText("添加第一个模块") else uiText("继续添加模块"), fontWeight = FontWeight.SemiBold)
        }
    }

    if (showPicker) {
        com.vault.ui.VaultModalBackdrop()
        ModalBottomSheet(
            shape = com.vault.ui.VaultTopShape,
            scrimColor = androidx.compose.ui.graphics.Color.Transparent,
            onDismissRequest = { showPicker = false },
            containerColor = MaterialTheme.colorScheme.surface,
            tonalElevation = 0.dp,
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(uiText("选择模块"), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(bottom = 8.dp))
                EntryModules.groups.forEach { group ->
                    Text(
                        group,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 8.dp, bottom = 4.dp),
                    )
                    EntryModules.catalog
                        .filter { (type, spec) -> spec.group == group && type != ModuleType.PASSKEY }
                        .forEach { (type, spec) ->
                        Surface(
                            onClick = {
                                if (type == ModuleType.OTP && hasBoundOtp && onOtpModuleOverride != null) {
                                    pendingOtpOverride = type
                                    showPicker = false
                                } else {
                                    onChange(modules + EntryModules.create(type))
                                    showPicker = false
                                }
                            },
                            shape = VaultShape,
                            // 浅色下取 surfaceContainerHighest(#E5E5E5)
                            color = MaterialTheme.colorScheme.surfaceContainerHighest,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    painter = androidx.compose.ui.res.painterResource(VaultIconResources.module(type)),
                                    contentDescription = null,
                                    tint = androidx.compose.ui.graphics.Color.Unspecified,
                                    modifier = Modifier.size(22.dp),
                                )
                                Spacer(Modifier.size(12.dp))
                                Text(uiText(spec.title), style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                    }
                }
                Spacer(Modifier.height(32.dp))
            }
        }
    }

    if (otpChoices.isNotEmpty()) {
        val closeOtpChoices = {
            otpChoices = emptyList()
            pendingModuleId = null
        }
        VaultDialog(
            onDismissRequest = closeOtpChoices,
            onClose = closeOtpChoices,
            title = { Text(uiText("选择动态码")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    otpChoices.forEach { (label, raw) ->
                        Surface(
                            onClick = {
                                pendingModuleId?.let { applyOtp(it, raw) }
                                otpChoices = emptyList(); pendingModuleId = null
                            },
                            shape = VaultShape,
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(uiText(label), modifier = Modifier.padding(12.dp)) }
                    }
                }
            },
        )
    }

    if (wifiChoices.isNotEmpty()) {
        val closeWifiChoices = {
            wifiChoices = emptyList()
            pendingModuleId = null
        }
        VaultDialog(
            onDismissRequest = closeWifiChoices,
            onClose = closeWifiChoices,
            title = { Text(uiText("选择 Wi-Fi 网络")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    wifiChoices.forEach { (ssid, raw) ->
                        Surface(
                            onClick = {
                                pendingModuleId?.let { applyWifi(it, raw) }
                                wifiChoices = emptyList(); pendingModuleId = null
                            },
                            shape = VaultShape,
                            color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(ssid, modifier = Modifier.padding(12.dp)) }
                    }
                }
            },
        )
    }

    deleteIndex?.let { index ->
        VaultDialog(
            onDismissRequest = { deleteIndex = null },
            title = { Text(uiText("删除模块")) },
            text = { Text(uiText("此模块已有内容，确定删除吗？")) },
            confirmButton = {
                VaultActionButton(onClick = {
                    onChange(modules.toMutableList().also { it.removeAt(index) })
                    deleteIndex = null
                }, style = VaultActionStyle.DANGER) { Text(uiText("删除")) }
            },
            dismissButton = { VaultActionButton(onClick = { deleteIndex = null }) { Text(uiText("取消")) } },
        )
    }

    pendingOtpOverride?.let { type ->
        VaultDialog(
            onDismissRequest = { pendingOtpOverride = null },
            title = { Text(uiText("替换外部动态码")) },
            text = { Text(uiText("此登录条目已关联独立的动态码条目。添加动态码模块后将改用模块中的密钥，并自动解除外部关联。")) },
            confirmButton = {
                VaultActionButton(onClick = {
                    onChange(modules + EntryModules.create(type))
                    onOtpModuleOverride?.invoke()
                    pendingOtpOverride = null
                }, style = VaultActionStyle.PRIMARY) { Text(uiText("覆盖并解除关联")) }
            },
            dismissButton = { VaultActionButton(onClick = { pendingOtpOverride = null }) { Text(uiText("取消")) } },
        )
    }
}

@Composable
private fun ModuleCard(
    module: JsonObject,
    isDragging: Boolean = false,
    dragTranslation: Float = 0f,
    onChange: (JsonObject) -> Unit,
    onMarkdownFocusChanged: (Boolean) -> Unit = {},
    onDelete: () -> Unit,
    onStartDrag: () -> Unit = {},
    onDrag: (change: androidx.compose.ui.input.pointer.PointerInputChange, amount: androidx.compose.ui.geometry.Offset) -> Unit = { _, _ -> },
    onDragEnd: () -> Unit = {},
    onOtpCamera: () -> Unit = {},
    onWifiCamera: () -> Unit = {},
    onOcrCamera: () -> Unit = {},
onOcrGallery: () -> Unit = {},
    onLocation: () -> Unit = {},
    setExternalActionInProgress: (Boolean) -> Unit = {},
    locatingModuleId: String? = null,
) {
    val context = LocalContext.current
    val maxDragTranslation = with(LocalDensity.current) { 18.dp.toPx() }
    val scope = rememberCoroutineScope()
    val latestOnStartDrag by rememberUpdatedState(onStartDrag)
    val latestOnDrag by rememberUpdatedState(onDrag)
    val latestOnDragEnd by rememberUpdatedState(onDragEnd)
    val dragReorderModifier = Modifier.pointerInput(Unit) {
        detectDragGesturesAfterLongPress(
            onDragStart = { latestOnStartDrag() },
            onDrag = { change, amount -> latestOnDrag(change, amount) },
            onDragEnd = { latestOnDragEnd() },
            onDragCancel = { latestOnDragEnd() },
        )
    }
    val type = EntryModules.primitive(module["type"])
    var showAppPicker by remember { mutableStateOf(false) }
    // 批量导入进度（图片 / 附件共用）
    var importProgress by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    val spec = EntryModules.catalog[type]
    val required = (module["required"] as? JsonPrimitive)?.booleanOrNull ?: false
    val sensitive = (module["sensitive"] as? JsonPrimitive)?.booleanOrNull == true
    val lockedSensitive = spec?.lockedSensitive == true
    val moduleHeaderColor = if (MaterialTheme.colorScheme.background.luminance() > 0.5f) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        setExternalActionInProgress(false)
        if (uris.isNotEmpty()) scope.launch {
            runCatching {
                val current = (module["value"] as? JsonArray).orEmpty()
                val existing = mediaListStrings(current).toSet()
                val added = mutableListOf<String>()
                val targets = uris
                importProgress = 0 to targets.size
                for ((index, uri) in targets.withIndex()) {
                    importProgress = index to targets.size
                    if (existing.size + added.size >= MAX_IMAGES_PER_MODULE) break
                    val encoded = encodeImageFromUri(context, uri)
                    if (encoded !in existing && encoded !in added) added.add(encoded)
                    importProgress = (index + 1) to targets.size
                }
                if (added.isNotEmpty()) {
                    onChange(module.with("value", JsonArray(current.toMutableList().also { it.addAll(added.map(::JsonPrimitive)) })))
                }
            }.onFailure {
                Toast.makeText(
                    context,
                    if (it is PmvMediaSessionLockedException) context.getString(R.string.system_media_session_locked)
                    else context.getString(R.string.entry_remaining_image_processing_failed, it.message ?: context.getString(R.string.entry_remaining_unable_read)),
                    Toast.LENGTH_LONG,
                ).show()
            }
                .also { importProgress = null }
        }
    }
    val attachmentPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        setExternalActionInProgress(false)
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val existing = (module["value"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }.toMutableList()
                    val hashes = existing.map { EntryModules.primitive(it["sha256"]) }.toMutableSet()
                    var total = existing.sumOf { EntryModules.primitive(it["size"]).toLongOrNull() ?: 0L }
                    val pmve = PmvMediaUiSession.isBound()
                    val perFileLimit = if (pmve) 1L * 1024L * 1024L * 1024L * 1024L else 16L * 1024 * 1024
                    val moduleLimit = if (pmve) Long.MAX_VALUE else MAX_ATTACHMENT_MODULE_BYTES
                    if (pmve) {
                        val usable = context.cacheDir.usableSpace
                        require(usable > 256L * 1024 * 1024) {
                            context.getString(R.string.entry_remaining_storage_insufficient, usable / 1024 / 1024)
                        }
                    }
                    importProgress = 0 to uris.size
                    for ((index, uri) in uris.withIndex()) {
                        importProgress = index to uris.size
                        require(existing.size < 10_000) { context.getString(R.string.entry_remaining_attachment_count_limit) }
                        var name = context.getString(R.string.entry_remaining_attachment_default_name)
                        var declaredSize = -1L
                        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                            if (cursor.moveToFirst()) {
                                name = cursor.getString(0)?.substringAfterLast('/')?.substringAfterLast('\\')?.take(255) ?: name
                                declaredSize = if (cursor.isNull(1)) -1 else cursor.getLong(1)
                            }
                        }
                        require(declaredSize <= perFileLimit || declaredSize < 0) {
                            context.getString(R.string.entry_remaining_attachment_too_large, name, if (pmve) "1 TB" else "16 MB")
                        }
                        val remaining = moduleLimit - total
                        require(remaining > 0) {
                            if (pmve) context.getString(R.string.entry_remaining_attachment_module_limit_pmve)
                            else context.getString(R.string.entry_remaining_attachment_module_limit)
                        }
                        val stored = storeAttachmentFromUri(context, uri, minOf(perFileLimit, remaining))
                        if (!hashes.add(stored.sha256)) {
                            attachmentFileFromRef(context, stored.ref)?.delete()
                            continue
                        }
                        existing += JsonObject(mapOf(
                            "name" to JsonPrimitive(name), "mime" to JsonPrimitive(context.contentResolver.getType(uri) ?: "application/octet-stream"),
                            "size" to JsonPrimitive(stored.size), "sha256" to JsonPrimitive(stored.sha256),
                            "data" to JsonPrimitive(stored.ref),
                        ))
                        total += stored.size
                        importProgress = (index + 1) to uris.size
                    }
                    existing
                }
            }.onSuccess { onChange(module.with("value", JsonArray(it))) }
                .onFailure {
                    Toast.makeText(
                        context,
                        if (it is PmvMediaSessionLockedException) context.getString(R.string.system_media_session_locked)
                        else context.getString(R.string.entry_remaining_attachment_processing_failed, it.message ?: context.getString(R.string.entry_remaining_unable_read)),
                        Toast.LENGTH_LONG,
                    ).show()
                }
                .also { importProgress = null }
        }
    }
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .graphicsLayer {
                translationY = dragTranslation.coerceIn(-maxDragTranslation, maxDragTranslation)
                clip = true
                shape = VaultShape
            },
        shape = VaultShape,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
        border = BorderStroke(
            if (isDragging) 2.dp else 1.dp,
            if (isDragging) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
        ),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(moduleHeaderColor)
                    .padding(start = 12.dp, end = 6.dp, top = 10.dp, bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(VaultShape)
                        .background(MaterialTheme.colorScheme.surface),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(VaultIconResources.module(type)),
                        contentDescription = null,
                        tint = Color.Unspecified,
                        modifier = Modifier.size(28.dp),
                    )
                }
                Spacer(Modifier.width(10.dp))
                Column(
                    Modifier
                        .weight(1f)
                        .then(dragReorderModifier),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    val storedTitle = EntryModules.primitive(module["title"])
                    val displayedTitle = if (storedTitle == spec?.title) uiText(storedTitle) else storedTitle
                    BasicTextField(
                        value = displayedTitle,
                        onValueChange = { title -> onChange(module.with("title", JsonPrimitive(title.take(60)))) },
                        enabled = type != ModuleType.PASSKEY,
                        singleLine = true,
                        textStyle = MaterialTheme.typography.titleSmall.copy(
                            color = MaterialTheme.colorScheme.onSurface,
                            fontWeight = FontWeight.SemiBold,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (lockedSensitive) {
                            Icon(Icons.Default.Lock, null, Modifier.size(13.dp), tint = MaterialTheme.colorScheme.primary)
                            Spacer(Modifier.width(4.dp))
                            Text(uiText("强制敏感"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                        } else {
                            Text(
                                uiText(if (sensitive) "敏感模块" else "普通模块"),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.width(6.dp))
                            VaultSwitch(
                                checked = sensitive,
                                onCheckedChange = { checked -> onChange(module.with("sensitive", JsonPrimitive(checked))) },
                            )
                        }
                    }
                }
            Icon(
                Icons.Default.DragHandle,
                uiText("长按拖动"),
                modifier = dragReorderModifier,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
                if (!required) {
                    IconButton(
                        onClick = onDelete,
                        modifier = Modifier.size(36.dp),
                        colors = IconButtonDefaults.iconButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Icon(Icons.Default.Close, uiText("删除模块"), modifier = Modifier.size(19.dp)) }
                }
            }
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                val availableRoles = EntryModules.autofillRoleOptions(type, sensitive)
                if (availableRoles.isNotEmpty()) {
                    AutofillRoleEditor(
                        module = module,
                        roles = availableRoles,
                        onChange = onChange,
                    )
                }
                when {
                    spec == null -> Text(uiText("当前版本暂不支持此模块；数据将原样保留。"), color = MaterialTheme.colorScheme.error)
                    type == ModuleType.PASSKEY -> {
                        val value = module["value"] as? JsonObject
                        val rpId = EntryModules.primitive(value?.get("rp_id"))
                        val account = EntryModules.primitive(value?.get("user_display_name"))
                            .ifBlank { EntryModules.primitive(value?.get("user_name")) }
                        Text("${uiText("依赖方")}：${rpId.ifBlank { uiText("未知") }}", style = MaterialTheme.typography.bodyMedium)
                        if (account.isNotBlank()) Text("${uiText("账户")}：$account", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            uiText("由 Android 通行密钥提供程序创建和使用，密钥材料不可手动编辑。"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    type == ModuleType.IMAGES -> {
                        val images = (module["value"] as? JsonArray).orEmpty()
                        val strings = mediaListStrings(images)
                        ModuleImageStrip(
                            images = strings,
                            maxImages = MAX_IMAGES_PER_MODULE,
                            onDelete = { index ->
                                onChange(module.with("value", JsonArray(images.filterIndexed { i, _ -> i != index })))
                            },
                            onAdd = {
                                setExternalActionInProgress(true)
                                imagePicker.launch("image/*")
                            },
                        )
                    }
                    type == ModuleType.ATTACHMENTS -> {
                        val attachments = (module["value"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
                        attachments.forEachIndexed { index, item ->
                            Surface(
                                shape = VaultShape,
                                color = MaterialTheme.colorScheme.surfaceContainer,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.padding(start = 10.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
                                ) {
                                    Icon(Icons.Default.AttachFile, null, tint = MaterialTheme.colorScheme.primary)
                                    Spacer(Modifier.width(8.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text(EntryModules.primitive(item["name"]), maxLines = 2, style = MaterialTheme.typography.bodyMedium)
                                        val bytes = EntryModules.primitive(item["size"]).toLongOrNull() ?: 0L
                                        Text(
                                            if (bytes >= 1024 * 1024) "%.1f MB".format(bytes / 1024f / 1024f) else "${bytes / 1024} KB",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    IconButton(onClick = {
                                        onChange(module.with("value", JsonArray(attachments.filterIndexed { i, _ -> i != index })))
        }) { Icon(Icons.Default.Close, uiText("删除附件"), tint = MaterialTheme.colorScheme.error) }
                                }
                            }
                        }
                        VaultActionButton(onClick = {
                            setExternalActionInProgress(true)
                            attachmentPicker.launch(arrayOf("*/*"))
                        }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.AttachFile, null); Spacer(Modifier.width(8.dp)); Text(uiText("添加附件"))
                        }
                    }
                    type == ModuleType.TARGET_APP -> {
                        VaultEditorField(
                            value = EntryModules.primitive(module["value"]),
                            onValueChange = { onChange(module.with("value", JsonPrimitive(it.take(255).trim()))) },
            label = uiText("应用包名"),
            trailingIcon = { IconButton(onClick = { showAppPicker = true }) { Icon(Icons.Default.Apps, uiText("选择程序")) } },
                            keepContainerColorOnFocus = true,
                            containerColorOverride = MaterialTheme.colorScheme.background,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        VaultActionButton(onClick = { showAppPicker = true }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Default.Apps, null); Spacer(Modifier.width(8.dp)); Text(uiText("选择已安装程序"))
                        }
                    }
                    type == ModuleType.BOOLEAN -> {
                        val checked = (module["value"] as? JsonPrimitive)?.booleanOrNull ?: false
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(if (checked) uiText("是") else uiText("否"), style = MaterialTheme.typography.bodyLarge)
                            VaultSwitch(
                                checked = checked,
                                onCheckedChange = { onChange(module.with("value", JsonPrimitive(it))) },
                            )
                        }
                    }
                    type == ModuleType.DATETIME -> DateTimeModuleEditor(module = module, onChange = onChange)
                    module["value"] is JsonObject -> CompoundFields(
                        module = module,
                        onChange = onChange,
                        onOtpCamera = onOtpCamera,
                        onWifiCamera = onWifiCamera,
                        onOcrCamera = onOcrCamera,
                        onOcrGallery = onOcrGallery,
                        onLocation = onLocation,
                        locatingModuleId = locatingModuleId,
                    )
                    else -> {
                        val value = EntryModules.primitive(module["value"])
                        val isMarkdown = type == ModuleType.MULTILINE
                        if (isMarkdown) {
                            var preview by remember { mutableStateOf(false) }
                            val moduleId = EntryModules.primitive(module["id"])
                            var editorValue by remember(moduleId) { mutableStateOf(TextFieldValue(value)) }
                            LaunchedEffect(value) {
                                if (value != editorValue.text) {
                                    editorValue = TextFieldValue(value, selection = TextRange(value.length))
                                }
                            }
                            CapsuleSegmentedControl(
                                options = listOf(CapsuleOption(uiText("编辑")), CapsuleOption(uiText("查看"))),
                                selectedIndex = if (preview) 1 else 0,
                                onSelected = { index -> preview = index == 1 },
                                height = 44.dp,
                            )
                            Spacer(Modifier.height(6.dp))
                            if (preview) {
                                MarkdownView(
                                    markdown = value.ifBlank { uiText("*空*") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            } else {
                                VaultEditorField(
                                    value = editorValue,
                                    onValueChange = { next ->
                                        val textChanged = next.text != editorValue.text
                                        editorValue = next
                                        if (textChanged) {
                                            onChange(module.with("value", JsonPrimitive(next.text)))
                                        }
                                    },
                                    label = "Markdown",
                                    singleLine = false,
                                    minLines = 6,
                                    keepContainerColorOnFocus = true,
                                    containerColorOverride = MaterialTheme.colorScheme.background,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .onFocusChanged { onMarkdownFocusChanged(it.isFocused) },
                                )
                            }
                        } else {
                            var pwVisible by remember { mutableStateOf(false) }
                            VaultEditorField(
                                value = value,
                                onValueChange = { onChange(module.with("value", JsonPrimitive(it.take(4000)))) },
                                label = EntryModules.primitive(module["title"]).ifEmpty { spec.title }.let {
                                    if (it == spec.title) uiText(it) else it
                                },
                                singleLine = type == ModuleType.PASSWORD || sensitive,
                                minLines = if (type == ModuleType.TEXT) 3 else 1,
                                visualTransformation = if ((type == ModuleType.PASSWORD || sensitive) && !pwVisible) PasswordVisualTransformation() else VisualTransformation.None,
                                trailingIcon = if (type == ModuleType.PASSWORD || sensitive) {
                                    {
                                        VaultVisibilityButton(visible = pwVisible, onClick = { pwVisible = !pwVisible })
                                    }
                                } else null,
                                keepContainerColorOnFocus = true,
                                containerColorOverride = MaterialTheme.colorScheme.background,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }
            }
        }
    }

    if (showAppPicker) {
        AppPickerSheet(
            onDismiss = { showAppPicker = false },
            onAppSelected = { _, packageName ->
                onChange(module.with("value", JsonPrimitive(packageName)))
                showAppPicker = false
            },
        )
    }

    importProgress?.let { (done, total) ->
        MediaImportProgressDialog(
            done = done,
            total = total,
            label = if (type == ModuleType.ATTACHMENTS) context.getString(R.string.entry_remaining_importing_attachments) else context.getString(R.string.entry_remaining_importing_images),
        )
    }
}

@Composable
private fun AutofillRoleEditor(
    module: JsonObject,
    roles: List<AutofillRole>,
    onChange: (JsonObject) -> Unit,
) {
    val type = EntryModules.primitive(module["type"])
    val config = module["config"] as? JsonObject ?: JsonObject(emptyMap())
    val rawRole = EntryModules.primitive(config["autofill_role"])
    val blankLabel = if (type == ModuleType.TEXT) uiText("按名称精确匹配") else uiText("不自动填充")
    val options = buildList {
        if (type == ModuleType.TEXT) {
            // 文本模块首个选项为「不自动填充」，与密码模块对齐：可选中后内容不参与自动填充
            add(AutofillRole.NONE.wire to uiText("不自动填充"))
        }
        add("" to blankLabel)
        addAll(roles.filter { it != AutofillRole.NONE }.map { it.wire to autofillRoleLabel(it) })
        if (rawRole.isNotEmpty() && roles.none { it.wire == rawRole } && rawRole != AutofillRole.NONE.wire) {
            add(rawRole to uiText("不可用") + ": $rawRole")
        }
    }
    ModuleSelectField(
        label = uiText("自动填充类型"),
        value = rawRole,
        options = options,
        exactMatch = true,
        onSelected = { selected ->
            val parsed = AutofillRole.fromWire(selected)
            if (parsed != null || selected.isEmpty()) {
                onChange(EntryModules.withAutofillRole(module, parsed))
            }
        },
    )
}

@Composable
private fun autofillRoleLabel(role: AutofillRole): String = when (role) {
    AutofillRole.USERNAME -> uiText("用户名")
    AutofillRole.EMAIL -> uiText("邮箱")
    AutofillRole.PASSWORD -> uiText("密码")
    AutofillRole.ONE_TIME_CODE -> uiText("一次性验证码")
    AutofillRole.FULL_NAME -> uiText("姓名")
    AutofillRole.PHONE -> uiText("电话")
    AutofillRole.COUNTRY -> uiText("国家 / 地区")
    AutofillRole.REGION -> uiText("省 / 州")
    AutofillRole.CITY -> uiText("城市")
    AutofillRole.STREET_ADDRESS -> uiText("详细地址")
    AutofillRole.POSTAL_CODE -> uiText("邮编")
    AutofillRole.CARDHOLDER -> uiText("持卡人")
    AutofillRole.CARD_NUMBER -> uiText("卡号")
    AutofillRole.CARD_EXPIRY -> uiText("有效期")
    AutofillRole.CARD_CVV -> uiText("安全码")
    AutofillRole.ID_NUMBER -> uiText("证件号码")
    AutofillRole.API_KEY -> uiText("API 凭证")
    AutofillRole.API_SECRET -> uiText("API 密文")
    AutofillRole.NONE -> uiText("不自动填充")
    AutofillRole.HOST -> uiText("主机")
    AutofillRole.PORT -> uiText("端口")
    AutofillRole.DATABASE -> uiText("数据库")
    AutofillRole.SSID -> uiText("Wi-Fi 名称")
    AutofillRole.WIFI_PASSWORD -> uiText("Wi-Fi 密码")
    AutofillRole.RECOVERY_ANSWER -> uiText("恢复答案")
    AutofillRole.CUSTOM_TEXT -> uiText("自定义文本")
    AutofillRole.CUSTOM_SECRET -> uiText("自定义密文")
}

@Composable
private fun CompoundFields(
    module: JsonObject,
    onChange: (JsonObject) -> Unit,
    onOtpCamera: () -> Unit,
    onWifiCamera: () -> Unit,
    onOcrCamera: () -> Unit,
    onOcrGallery: () -> Unit,
    onLocation: () -> Unit,
    locatingModuleId: String? = null,
) {
    val type = EntryModules.primitive(module["type"])
    val moduleId = EntryModules.primitive(module["id"])
    val mandatory = EntryModules.catalog[type]?.mandatorySensitiveFields.orEmpty()
    val value = module["value"] as JsonObject
    val selectOptions = when (type) {
        ModuleType.OTP -> mapOf(
            "type" to listOf("totp" to "TOTP", "hotp" to "HOTP"),
            "algorithm" to listOf("SHA1" to "SHA-1", "SHA256" to "SHA-256", "SHA512" to "SHA-512"),
            "digits" to listOf("6" to stringResource(R.string.entry_remaining_digits_6), "7" to stringResource(R.string.entry_remaining_digits_7), "8" to stringResource(R.string.entry_remaining_digits_8)),
            "period" to listOf("30" to stringResource(R.string.entry_remaining_seconds_30), "60" to stringResource(R.string.entry_remaining_seconds_60)),
        )
        ModuleType.WIFI -> mapOf(
            "security_type" to com.vault.os.WifiSecurity.OPTIONS.map { it to it },
        )
        ModuleType.DATABASE -> mapOf("engine" to listOf(
            "MySQL" to "MySQL", "PostgreSQL" to "PostgreSQL", "SQL Server" to "SQL Server",
            "Oracle" to "Oracle", "SQLite" to "SQLite", "MongoDB" to "MongoDB", "Redis" to "Redis",
        ))
        ModuleType.CARD_DOCUMENT -> mapOf("card_type" to EntryModules.cardTypeLabels.map { it.key to uiText(it.value) })
        else -> emptyMap()
    }

    if (type == ModuleType.CARD_DOCUMENT) {
        val imagesRaw = (value["images"] as? JsonArray).orEmpty()
        val images = mediaListStrings(imagesRaw)
        ModuleImageStrip(
            images = images,
            maxImages = 2,
            onDelete = { index ->
                onChange(module.with(
                    "value",
                    value.with("images", JsonArray(imagesRaw.filterIndexed { i, _ -> i != index })),
                ))
            },
            onAdd = onOcrGallery,
        )
    }

    when (type) {
        ModuleType.OTP -> VaultActionButton(onClick = onOtpCamera, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Default.QrCodeScanner, null); Spacer(Modifier.width(6.dp)); Text(uiText("扫码"))
        }
        ModuleType.WIFI -> VaultActionButton(onClick = onWifiCamera, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Default.QrCodeScanner, null); Spacer(Modifier.width(6.dp)); Text(uiText("扫码"))
        }
        ModuleType.CARD_DOCUMENT -> Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            VaultActionButton(onClick = onOcrCamera, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.CameraAlt, null); Spacer(Modifier.width(6.dp)); Text(uiText("扫描"))
            }
        }
        ModuleType.ADDRESS -> {
            val locating = locatingModuleId == moduleId
            VaultActionButton(
                onClick = onLocation,
                enabled = !locating,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (locating) uiText("正在获取当前位置…") else uiText("使用当前位置"))
            }
        }
    }

    val isOtp = type == ModuleType.OTP
    val otpAdvancedKeys = setOf("algorithm", "digits", "period", "type", "counter")
    var otpAdvancedExpanded by remember(moduleId) { mutableStateOf(false) }

    val orderedEntries = EntryModules.orderedValue(module).entries.toList()
    val activeCardFields = if (type == ModuleType.CARD_DOCUMENT) {
        EntryModules.cardFieldKeys(EntryModules.primitive(value["card_type"]).ifBlank { EntryModules.CARD_BANK }) - "notes"
    } else emptySet()
    orderedEntries.forEach { (key, raw) ->
        if (key == "images") return@forEach
        if (isOtp && key in otpAdvancedKeys) return@forEach
        if (type == ModuleType.CARD_DOCUMENT && key !in activeCardFields) return@forEach
        val hidden = key in mandatory
        val options = selectOptions[key]
        if (options != null) {
            ModuleSelectField(
                label = moduleFieldLabel(key),
                value = EntryModules.primitive(raw),
                options = options,
                onSelected = { selected ->
                    val next = if (type == ModuleType.CARD_DOCUMENT && key == "card_type") {
                        EntryModules.cardValueForType(value, selected)
                    } else {
                        value.with(key, JsonPrimitive(selected))
                    }
                    onChange(module.with("value", next))
                },
            )
            return@forEach
        }
        var visible by remember(EntryModules.primitive(module["id"]), key) { mutableStateOf(false) }
        val cardDate = type == ModuleType.CARD_DOCUMENT &&
            (key in setOf("issue_date", "expiry_date") ||
                (key == "expiry" && EntryModules.primitive(value["card_type"]) != EntryModules.CARD_BANK))
        val bankExpiry = type == ModuleType.CARD_DOCUMENT && key == "expiry" && !cardDate
        val digitsOnly = key in setOf("port", "digits", "period", "counter", "card_number", "cvv", "postal_code")
        VaultEditorField(
            value = EntryModules.primitive(raw),
            onValueChange = { text ->
                val filtered = when {
                    cardDate -> com.vault.ui.InputFilters.formatDate(text)
                    bankExpiry -> com.vault.ui.InputFilters.formatExpiryMMYY(text)
                    digitsOnly -> text.filter(Char::isDigit)
                    else -> text
                }
                onChange(module.with("value", value.with(key, JsonPrimitive(filtered.take(4000)))))
            },
            label = moduleFieldLabel(key),
            placeholder = if (cardDate) "YYYY-MM-DD" else if (bankExpiry) "MM/YY" else null,
            visualTransformation = if (hidden && !visible) PasswordVisualTransformation() else VisualTransformation.None,
            trailingIcon = if (hidden) {{
                VaultVisibilityButton(visible = visible, onClick = { visible = !visible })
            }} else null,
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = if (digitsOnly || cardDate || bankExpiry) androidx.compose.ui.text.input.KeyboardType.Number else androidx.compose.ui.text.input.KeyboardType.Text,
            ),
            singleLine = key != "private_key",
            minLines = if (key == "private_key") 3 else 1,
            keepContainerColorOnFocus = true,
            containerColorOverride = MaterialTheme.colorScheme.background,
            modifier = Modifier.fillMaxWidth(),
        )
    }

    if (isOtp) {
        val hasAdvancedContent = otpAdvancedKeys.any { key ->
            val raw = EntryModules.orderedValue(module)[key]
            raw != null && EntryModules.primitive(raw).isNotEmpty()
        }
        VaultActionButton(
            onClick = { otpAdvancedExpanded = !otpAdvancedExpanded },
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        ) {
            Icon(
                if (otpAdvancedExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                contentDescription = null,
            )
            Spacer(Modifier.size(4.dp))
            Text(uiText("高级选项"))
            Spacer(Modifier.weight(1f))
            if (hasAdvancedContent) {
                Text(
                    uiText("已设置"),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        if (otpAdvancedExpanded) {
            EntryModules.orderedValue(module).forEach { (key, raw) ->
                if (key == "images" || key !in otpAdvancedKeys) return@forEach
                val options = selectOptions[key]
                if (options != null) {
                    ModuleSelectField(
                        label = moduleFieldLabel(key),
                        value = EntryModules.primitive(raw),
                        options = options,
                        onSelected = { selected -> onChange(module.with("value", value.with(key, JsonPrimitive(selected)))) },
                    )
                    return@forEach
                }
                val digitsOnly = key in setOf("port", "digits", "period", "counter", "card_number", "cvv", "postal_code")
                VaultEditorField(
                    value = EntryModules.primitive(raw),
                    onValueChange = { text ->
                        val filtered = if (digitsOnly) text.filter(Char::isDigit) else text
                        onChange(module.with("value", value.with(key, JsonPrimitive(filtered.take(4000)))))
                    },
                    label = moduleFieldLabel(key),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = if (digitsOnly) androidx.compose.ui.text.input.KeyboardType.Number else androidx.compose.ui.text.input.KeyboardType.Text,
                    ),
                    singleLine = true,
                    keepContainerColorOnFocus = true,
                    containerColorOverride = MaterialTheme.colorScheme.background,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun DateTimeModuleEditor(
    module: JsonObject,
    onChange: (JsonObject) -> Unit,
) {
    val config = module["config"] as? JsonObject ?: JsonObject(emptyMap())
    val mode = EntryModules.primitive(config["mode"]).takeIf { it in setOf("date", "time", "datetime") } ?: "datetime"
    val storedValue = EntryModules.primitive(module["value"])
    val now = LocalDateTime.now()
    val latestModule by rememberUpdatedState(module)
    val latestOnChange by rememberUpdatedState(onChange)
    val value = storedValue.ifBlank { EntryModules.dateTimeValueForMode("", mode, now) }

    LaunchedEffect(EntryModules.primitive(module["id"]), mode, storedValue) {
        if (storedValue.isBlank()) {
            latestOnChange(module.with("value", JsonPrimitive(value)))
        }
    }

    fun updateValue(next: String) = latestOnChange(latestModule.with("value", JsonPrimitive(next)))
    fun changeMode(nextMode: String) {
        val current = latestModule
        val currentConfig = current["config"] as? JsonObject ?: JsonObject(emptyMap())
        latestOnChange(
            current
                .with("config", JsonObject(currentConfig.toMutableMap().also { it["mode"] = JsonPrimitive(nextMode) }))
                .with("value", JsonPrimitive(EntryModules.dateTimeValueForMode(EntryModules.primitive(current["value"]), nextMode, now))),
        )
    }

    ModuleSelectField(
        label = uiText("日期时间类型"),
        value = mode,
        options = listOf("date" to uiText("仅日期"), "time" to uiText("仅时间"), "datetime" to uiText("日期和时间")),
        onSelected = ::changeMode,
    )
    val displayValue = if (mode == "datetime") value.replace("T", " · ") else value
    VaultEditorField(
        value = displayValue,
        onValueChange = {
            val normalized = it.replace(" · ", "T").replace(" ", "T")
            updateValue(if (mode == "date") com.vault.ui.InputFilters.formatDate(normalized) else normalized.filter { c -> c in "0123456789-:T" }.take(16))
        },
        label = when (mode) {
            "date" -> "YYYY-MM-DD"
            "time" -> "HH:mm"
            else -> "YYYY-MM-DD · HH:mm"
        },
        singleLine = true,
        keepContainerColorOnFocus = true,
        containerColorOverride = MaterialTheme.colorScheme.background,
        modifier = Modifier.fillMaxWidth(),
    )
    if (value.isNotEmpty() && !EntryModules.isValidDateTimeValue(mode, value)) {
        Text(uiText("格式无效"), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
    }

    if (mode != "time") {
        var showDatePicker by remember { mutableStateOf(false) }
        VaultActionButton(
            onClick = { showDatePicker = true },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(uiText("日历选择")) }
        if (showDatePicker) {
            VaultDatePickerDialog(
                mode = mode,
                value = value,
                now = now,
                onDismiss = { showDatePicker = false },
                onConfirm = { date ->
                    updateValue(if (mode == "date") date else "${date}T${timePart(latestModule.let { EntryModules.primitive(it["value"]) }, now)}")
                    showDatePicker = false
                },
            )
        }
    }

    if (mode != "date") {
        val time = runCatching { LocalTime.parse(timePart(value, now)) }.getOrDefault(now.toLocalTime())
        ModernTimePicker(
            hour = time.hour,
            minute = time.minute,
            onHourChange = { hour ->
                val current = latestModule
                updateValue(EntryModules.withDateTimePart(EntryModules.primitive(current["value"]), mode, hour, time.minute, now))
            },
            onMinuteChange = { minute ->
                val current = latestModule
                updateValue(EntryModules.withDateTimePart(EntryModules.primitive(current["value"]), mode, time.hour, minute, now))
            },
        )
    }
}

/** 紧凑时间选择器：双列步进，随时可见当前值，避免滚轮误触。 */
@Composable
private fun ModernTimePicker(hour: Int, minute: Int, onHourChange: (Int) -> Unit, onMinuteChange: (Int) -> Unit) {
    Surface(modifier = Modifier.fillMaxWidth(), shape = VaultShape, color = MaterialTheme.colorScheme.surfaceContainerHigh) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TimeStepper(uiText("小时"), hour, 24, onHourChange, Modifier.weight(1f))
            Text(":", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
            TimeStepper(uiText("分钟"), minute, 60, onMinuteChange, Modifier.weight(1f))
        }
    }
}

/** 单个时间列：固定尺寸候选项，横向浏览并在首尾互相环绕。 */
internal fun wrappedTimeWheelCandidates(value: Int, itemCount: Int, visibleCount: Int = 5): List<Int> {
    require(itemCount > 0) { "itemCount must be positive" }
    require(visibleCount > 0) { "visibleCount must be positive" }
    val span = minOf(visibleCount, itemCount)
    val offset = (span - 1) / 2
    return (0 until span).map { index ->
        val raw = value + index - offset
        val wrapped = ((raw % itemCount) + itemCount) % itemCount
        wrapped
    }
}

@Composable
private fun TimeStepper(
    label: String,
    value: Int,
    itemCount: Int,
    onChange: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 2.dp),
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            RepeatStepButton("−") { onChange((value + itemCount - 1) % itemCount) }
            Surface(shape = VaultShape, color = MaterialTheme.colorScheme.primaryContainer) {
                Text(
                    "%02d".format(value),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                )
            }
            RepeatStepButton("+") { onChange((value + 1) % itemCount) }
        }
    }
}

/** 轻触变更一次；持续按住后以固定节奏重复，松手立即停止。 */
@Composable
private fun RepeatStepButton(symbol: String, onStep: () -> Unit) {
    val latestOnStep by rememberUpdatedState(onStep)
    Surface(
        modifier = Modifier
            .size(36.dp)
            .pointerInput(Unit) {
                detectTapGestures(
                    onPress = {
                        coroutineScope {
                            latestOnStep()
                            val repeatJob = launch {
                                delay(350)
                                while (isActive) {
                                    latestOnStep()
                                    delay(90)
                                }
                            }
                            tryAwaitRelease()
                            repeatJob.cancel()
                        }
                    },
                )
            },
        shape = CircleShape,
        color = MaterialTheme.colorScheme.surfaceVariant,
        contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(symbol, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        }
    }
}

/** 小型月历：仅呈现月份、日期与操作，颜色完全来自当前 Material 主题。 */
@Composable
private fun VaultDatePickerDialog(
    mode: String,
    value: String,
    now: LocalDateTime,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    val initial = runCatching {
        LocalDate.parse(if (mode == "datetime") value.substringBefore('T') else value)
    }.getOrDefault(now.toLocalDate())
    var selectedDate by remember(value, mode) { mutableStateOf(initial) }
    var visibleMonth by remember(value, mode) { mutableStateOf(YearMonth.from(initial)) }
    val today = LocalDate.now()
    val locale = LocalConfiguration.current.locales[0]
    val monthFormatter = remember(locale) {
        DateTimeFormatter.ofPattern(DateFormat.getBestDateTimePattern(locale, "yMMMM"), locale)
    }
    val weekLayout = remember(locale, visibleMonth) { calendarWeekLayout(locale, visibleMonth) }
    com.vault.ui.VaultModalBackdrop()
    Dialog(onDismissRequest = onDismiss) {
        VaultDialogWindow()
        Surface(
            modifier = Modifier.width(336.dp).vaultPopupCardSurface(),
            color = Color.Transparent,
            contentColor = MaterialTheme.colorScheme.onSurface,
            shape = VaultShape,
            tonalElevation = 0.dp,
        ) {
            Column(Modifier.padding(16.dp)) {
                Text(uiText("选择日期"), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                Text(selectedDate.toString(), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 2.dp, bottom = 8.dp))
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = { visibleMonth = visibleMonth.minusYears(1) }) { Text("«") }
                    TextButton(onClick = { visibleMonth = visibleMonth.minusMonths(1) }) { Text("‹") }
                    Text(visibleMonth.format(monthFormatter), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                        textAlign = TextAlign.Center, modifier = Modifier.weight(1f))
                    TextButton(onClick = { visibleMonth = visibleMonth.plusMonths(1) }) { Text("›") }
                    TextButton(onClick = { visibleMonth = visibleMonth.plusYears(1) }) { Text("»") }
                }
                Row(Modifier.fillMaxWidth()) {
                    weekLayout.weekdays.forEach { weekday ->
                        val label = weekday.getDisplayName(TextStyle.NARROW_STANDALONE, locale)
                        Text(label, textAlign = TextAlign.Center, style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f).padding(vertical = 4.dp))
                    }
                }
                val firstOffset = weekLayout.firstDayOffset
                val length = visibleMonth.lengthOfMonth()
                repeat(6) { week ->
                    Row(Modifier.fillMaxWidth()) {
                        repeat(7) { weekday ->
                            val day = week * 7 + weekday - firstOffset + 1
                            val date = if (day in 1..length) visibleMonth.atDay(day) else null
                            Box(contentAlignment = Alignment.Center, modifier = Modifier.weight(1f).height(38.dp)) {
                                if (date != null) {
                                    val selected = date == selectedDate
                                    val isToday = date == today
                                    Surface(
                                        shape = CircleShape,
                                        color = when { selected -> MaterialTheme.colorScheme.primary; isToday -> MaterialTheme.colorScheme.secondaryContainer; else -> Color.Transparent },
                                        modifier = Modifier.size(32.dp).clip(CircleShape).clickable { selectedDate = date },
                                    ) {
                                        Box(contentAlignment = Alignment.Center) {
                                            Text(date.dayOfMonth.toString(), style = MaterialTheme.typography.bodyMedium,
                                                fontWeight = if (selected || isToday) FontWeight.SemiBold else FontWeight.Normal,
                                                color = when { selected -> MaterialTheme.colorScheme.onPrimary; isToday -> MaterialTheme.colorScheme.onSecondaryContainer; else -> MaterialTheme.colorScheme.onSurface })
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { selectedDate = today; visibleMonth = YearMonth.from(today) }) { Text(uiText("今天")) }
                    TextButton(onClick = onDismiss) { Text(uiText("取消")) }
                    TextButton(onClick = { onConfirm(selectedDate.toString()) }) { Text(uiText("确定")) }
                }
            }
        }
    }
}

private fun timePart(value: String, fallback: LocalDateTime): String =
    value.substringAfter('T', value).takeIf { EntryModules.isValidDateTimeValue("time", it) }
        ?: "%02d:%02d".format(fallback.hour, fallback.minute)

@Composable
private fun ModuleImageStrip(
    images: List<String>,
    maxImages: Int,
    onDelete: (Int) -> Unit,
    onAdd: () -> Unit,
) {
    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        itemsIndexed(images, key = { index, b64 -> "$index:${b64.hashCode()}" }) { index, b64 ->
            var showViewer by remember(b64) { mutableStateOf(false) }
            if (showViewer) ImageViewerDialog(images = images, initialIndex = index, onClose = { showViewer = false })
            Box(Modifier.size(104.dp)) {
                Box(
                    Modifier.padding(top = 6.dp, end = 6.dp).size(98.dp)
                        .clip(VaultShape)
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .clickable { showViewer = true },
                ) { Base64Image(b64, Modifier.fillMaxWidth().height(98.dp), maxDecodePx = 512) }
                androidx.compose.material3.FilledIconButton(
                    onClick = { onDelete(index) },
                    modifier = Modifier.align(Alignment.TopEnd).size(28.dp),
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    ),
        ) { Icon(Icons.Default.Close, uiText("删除图片"), Modifier.size(16.dp)) }
            }
        }
        item {
            Box(
                Modifier.size(98.dp).clip(VaultShape)
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .clickable(enabled = images.size < maxImages, onClick = onAdd),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.AddPhotoAlternate, null)
            Text(if (images.size < maxImages) uiText("添加图片") else uiText("已达上限"), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

@Composable
private fun ModuleSelectField(
    label: String,
    value: String,
    options: List<Pair<String, String>>,
    exactMatch: Boolean = false,
    onSelected: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabelRaw = moduleSelectDisplayLabel(value, options, exactMatch)
    val selectedLabel = uiText(selectedLabelRaw)
    Box(Modifier.fillMaxWidth()) {
        VaultEditorField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            enabled = false,
            label = uiText(label),
            trailingIcon = {
                Icon(
                    Icons.Default.ArrowDropDown,
                    null,
                    modifier = Modifier.graphicsLayer { rotationZ = if (expanded) 180f else 0f },
                )
            },
            keepContainerColorOnFocus = true,
            containerColorOverride = MaterialTheme.colorScheme.background,
            modifier = Modifier.fillMaxWidth(),
        )
        Box(Modifier.matchParentSize().clip(VaultShape).clickable { expanded = true })
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            containerColor = popupMenuSurface(),
        ) {
            options.forEach { (stored, shown) ->
                DropdownMenuItem(
                    text = { Text(uiText(shown)) },
                    onClick = { onSelected(stored); expanded = false },
                    trailingIcon = if (moduleSelectValueMatches(stored, value, exactMatch)) {
                        { Box(Modifier.size(8.dp).background(MaterialTheme.colorScheme.primary, CircleShape)) }
                    } else null,
                )
            }
        }
    }
}

internal fun moduleSelectValueMatches(stored: String, value: String, exactMatch: Boolean): Boolean =
    if (exactMatch) stored == value else stored.equals(value, ignoreCase = true)

internal fun moduleSelectDisplayLabel(
    value: String,
    options: List<Pair<String, String>>,
    exactMatch: Boolean,
): String = options.firstOrNull { moduleSelectValueMatches(it.first, value, exactMatch) }?.second
    ?: value.ifBlank { options.firstOrNull()?.second.orEmpty() }

private fun JsonObject.with(key: String, value: kotlinx.serialization.json.JsonElement): JsonObject =
    JsonObject(toMutableMap().also { it[key] = value })

@Suppress("MissingPermission")
private suspend fun currentOrLastLocation(context: android.content.Context, manager: LocationManager): Location {
    val providers = listOf(LocationManager.NETWORK_PROVIDER, LocationManager.GPS_PROVIDER)
        .filter { runCatching { manager.isProviderEnabled(it) }.getOrDefault(false) }
    if (providers.isEmpty()) error(localizeUiTextFor(context, "系统定位未开启"))

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        for (provider in providers) {
            val location = withTimeoutOrNull(6_000) {
                kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
                    val cancellation = android.os.CancellationSignal()
                    continuation.invokeOnCancellation { cancellation.cancel() }
                    manager.getCurrentLocation(
                        provider,
                        cancellation,
                        ContextCompat.getMainExecutor(context),
                    ) { result ->
                        if (continuation.isActive) continuation.resume(result) { _, _, _ -> }
                    }
                }
            }
            if (location != null) return location
        }
    }

    return providers.mapNotNull { provider ->
        runCatching { manager.getLastKnownLocation(provider) }.getOrNull()
    }.maxByOrNull { it.time } ?: error(localizeUiTextFor(context, "暂时无法取得位置，请稍后重试"))
}

private fun moduleHasContent(module: JsonObject): Boolean = jsonHasContent(module["value"])

private fun jsonHasContent(value: kotlinx.serialization.json.JsonElement?): Boolean = when (value) {
    is JsonObject -> value.values.any(::jsonHasContent)
    is JsonArray -> value.any(::jsonHasContent)
    is JsonPrimitive -> value.contentOrNull?.isNotBlank() == true
    else -> false
}

