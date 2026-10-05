package com.vault.model

import com.vault.model.autofill.AutofillRole
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.util.UUID

object ModuleType {
    const val TEXT = "text"
    const val PASSWORD = "password"
    const val MULTILINE = "multiline"
    const val URL = "url"
    const val DATE = "date"
    const val BOOLEAN = "boolean"
    const val DATETIME = "datetime"
    const val IMAGES = "images"
    const val ATTACHMENTS = "attachments"
    const val LOGIN_ACCOUNT = "login_account"
    const val TARGET_APP = "target_app"
    const val API_CREDENTIAL = "api_credential"
    const val WIFI = "wifi"
    const val SERVER_CONNECTION = "server_connection"
    const val SSH = "ssh"
    const val DATABASE = "database"
    const val OTP = "otp"
    const val CARD_DOCUMENT = "card_document"
    const val ADDRESS = "address"
    const val RECOVERY = "recovery"
    const val PASSKEY = "passkey"
}

data class ModuleSpec(
    val title: String,
    val group: String,
    val defaultValue: JsonElement = JsonPrimitive(""),
    val sensitive: Boolean = false,
    val lockedSensitive: Boolean = false,
    val mandatorySensitiveFields: Set<String> = emptySet(),
    val fieldOrder: List<String> = emptyList(),
    val autofillRole: AutofillRole? = null,
)

object EntryModules {
    const val FIELD_KEY = "modules"
    // Stored card-date sentinel, independent of the display language.
    const val CARD_LONG_TERM = "长期"
    const val CARD_BANK = "bank_card"
    const val CARD_ID_CARD = "id_card"
    const val CARD_CUSTOM = "custom"

    val cardTypeLabels = linkedMapOf(
        CARD_BANK to "银行卡",
        CARD_ID_CARD to "身份证",
        CARD_CUSTOM to "其他卡证",
    )

    private val documentFields = listOf("card_type", "full_name", "id_number", "issue_date", "expiry_date", "issuing_authority")

    private val cardFields = mapOf(
        CARD_BANK to listOf("card_type", "cardholder", "card_number", "bank", "bank_branch", "expiry", "cvv", "withdrawal_password"),
        CARD_ID_CARD to documentFields,
        CARD_CUSTOM to listOf("card_type", "card_name", "card_number", "expiry", "notes"),
    )

    val groups = listOf("通用", "账号与网络", "身份与金融")

    val catalog = linkedMapOf(
        ModuleType.TEXT to ModuleSpec("文本", "通用"),
        ModuleType.PASSWORD to ModuleSpec("密码", "通用", sensitive = true, lockedSensitive = true),
        ModuleType.MULTILINE to ModuleSpec("Markdown", "通用"),
        ModuleType.BOOLEAN to ModuleSpec("布尔值", "通用", JsonPrimitive(false)),
        ModuleType.DATETIME to ModuleSpec("日期时间", "通用"),
        ModuleType.IMAGES to ModuleSpec("图片", "通用", JsonArray(emptyList())),
        ModuleType.ATTACHMENTS to ModuleSpec("附件", "通用", JsonArray(emptyList()), sensitive = true),
        ModuleType.LOGIN_ACCOUNT to compound("登录", "账号与网络", "username", "password", sensitive = setOf("password")),
        ModuleType.TARGET_APP to ModuleSpec("关联程序", "账号与网络"),
        ModuleType.API_CREDENTIAL to compound("API 凭证", "账号与网络", "api_key", "api_secret", sensitive = setOf("api_key", "api_secret")),
        ModuleType.WIFI to compound(
            "Wi-Fi", "账号与网络", "ssid", "wifi_password", "security_type", "router_admin_url", "admin_password",
            sensitive = setOf("wifi_password", "admin_password"),
            defaults = mapOf("security_type" to "无加密"),
        ),
        ModuleType.SERVER_CONNECTION to compound("服务器", "账号与网络", "host", "port", "username", "password", sensitive = setOf("password")),
        ModuleType.SSH to compound("SSH", "账号与网络", "host", "port", "username", "password", "private_key", "fingerprint", sensitive = setOf("password", "private_key")),
        ModuleType.DATABASE to compound(
            "数据库连接", "账号与网络", "engine", "host", "port", "database", "username", "password",
            sensitive = setOf("password"),
            defaults = mapOf("engine" to "MySQL"),
        ),
        ModuleType.OTP to compound(
            "动态码", "账号与网络", "secret", "issuer", "label", "algorithm", "digits", "period", "type", "counter", "otp_domains",
            sensitive = setOf("secret"),
            defaults = mapOf("type" to "totp", "algorithm" to "SHA1", "digits" to "6", "period" to "30"),
        ),
        ModuleType.CARD_DOCUMENT to ModuleSpec(
            "卡证", "身份与金融", cardValueForType(JsonObject(emptyMap()), CARD_BANK),
            mandatorySensitiveFields = setOf("card_number", "cvv", "withdrawal_password", "id_number"),
            fieldOrder = cardFields.getValue(CARD_BANK) + "images",
        ),
        ModuleType.ADDRESS to compound("地址", "身份与金融", "country", "region", "city", "address", "postal_code"),
        ModuleType.RECOVERY to compound("恢复信息", "身份与金融", "question", "answer", sensitive = setOf("answer")),
        ModuleType.PASSKEY to compound(
            "通行密钥", "账号与网络",
            "schema_version", "rp_id", "rp_name", "user_id", "user_name", "user_display_name",
            "credential_id", "private_key", "public_key", "algorithm", "transports", "aaguid",
            "discoverable", "backup_eligible", "backup_state", "counter_mode", "sign_count",
            "created_at", "last_used_at",
            sensitive = setOf("user_id", "credential_id", "private_key"),
            lockedSensitive = true,
            defaults = mapOf(
                "schema_version" to "2",
                "algorithm" to "-7",
                "transports" to "internal",
                "discoverable" to "true",
                "backup_eligible" to "true",
                "backup_state" to "true",
                "counter_mode" to "synced_zero",
                "sign_count" to "0",
            ),
        ),
    )

    private val legacyTypes = mapOf(
        ModuleType.URL to ModuleType.TEXT,
        ModuleType.DATE to ModuleType.TEXT,
    )

    private fun resolveType(type: String): String = legacyTypes[type] ?: type

    fun defaultAutofillRole(type: String): AutofillRole? = catalog[resolveType(type)]?.autofillRole

    fun autofillRoleOptions(type: String, sensitive: Boolean = false): List<AutofillRole> = when (resolveType(type)) {
        ModuleType.TEXT -> AutofillRole.entries.filter { sensitive || !it.minimumRequiresVerification }
        ModuleType.PASSWORD -> listOf(
            AutofillRole.PASSWORD,
            AutofillRole.CARD_CVV,
            AutofillRole.ID_NUMBER,
            AutofillRole.API_KEY,
            AutofillRole.API_SECRET,
            AutofillRole.WIFI_PASSWORD,
            AutofillRole.RECOVERY_ANSWER,
            AutofillRole.CUSTOM_SECRET,
        )
        ModuleType.DATETIME -> listOf(AutofillRole.CARD_EXPIRY, AutofillRole.CUSTOM_TEXT)
        else -> emptyList()
    }

    fun configuredAutofillRole(module: JsonObject): AutofillRole? {
        val config = module["config"] as? JsonObject ?: return null
        return AutofillRole.fromWire(primitive(config["autofill_role"]))
    }

    fun withAutofillRole(module: JsonObject, role: AutofillRole?): JsonObject {
        val config = (module["config"] as? JsonObject ?: JsonObject(emptyMap())).toMutableMap()
        if (role == null) config.remove("autofill_role") else config["autofill_role"] = JsonPrimitive(role.wire)
        return JsonObject(module.toMutableMap().also { it["config"] = JsonObject(config) })
    }

    fun cardValueForType(value: JsonObject, requestedType: String): JsonObject {
        val cardType = requestedType.takeIf(cardTypeLabels::containsKey) ?: CARD_CUSTOM
        val out = linkedMapOf<String, JsonElement>()
        cardFields.getValue(cardType).forEach { out[it] = JsonPrimitive("") }
        out["card_type"] = JsonPrimitive(cardType)
        out["images"] = JsonArray(emptyList())
        value.filterKeys { it in cardFields.getValue(cardType) || it == "images" }
            .forEach { (key, item) -> out[key] = item }
        out["card_type"] = JsonPrimitive(cardType)
        if (out["images"] !is JsonArray) out["images"] = JsonArray(emptyList())
        return JsonObject(out)
    }

    fun cardFieldKeys(cardType: String): Set<String> =
        (cardFields[cardType] ?: cardFields.getValue(CARD_CUSTOM)).toSet() + "images"

    fun isValidDateTimeValue(mode: String, value: String): Boolean {
        if (value.isEmpty()) return true
        val matchesWireFormat = when (mode) {
            "date" -> Regex("""\d{4}-\d{2}-\d{2}""").matches(value)
            "time" -> Regex("""\d{2}:\d{2}""").matches(value)
            "datetime" -> Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}""").matches(value)
            else -> false
        }
        if (!matchesWireFormat) return false
        return runCatching {
            when (mode) {
                "date" -> LocalDate.parse(value)
                "time" -> LocalTime.parse(value)
                "datetime" -> LocalDateTime.parse(value)
                else -> return false
            }
        }.isSuccess
    }

    fun dateTimeValueForMode(
        value: String,
        nextMode: String,
        fallback: LocalDateTime = LocalDateTime.now(),
    ): String = when (nextMode) {
        "date" -> value.substringBefore('T').takeIf { isValidDateTimeValue("date", it) }
            ?: fallback.toLocalDate().toString()
        "time" -> value.substringAfter('T', value).takeIf { isValidDateTimeValue("time", it) }
            ?: "%02d:%02d".format(fallback.hour, fallback.minute)
        else -> when {
            isValidDateTimeValue("datetime", value) -> value
            isValidDateTimeValue("date", value) -> "${value}T00:00"
            isValidDateTimeValue("time", value) -> "${fallback.toLocalDate()}T$value"
            else -> "%sT%02d:%02d".format(fallback.toLocalDate(), fallback.hour, fallback.minute)
        }
    }

    fun withDateTimePart(
        value: String,
        mode: String,
        hour: Int,
        minute: Int,
        fallback: LocalDateTime = LocalDateTime.now(),
    ): String {
        val time = "%02d:%02d".format(hour, minute)
        if (mode == "time") return time
        val date = value.substringBefore('T').takeIf { isValidDateTimeValue("date", it) }
            ?: fallback.toLocalDate().toString()
        return "${date}T$time"
    }

    private fun compound(
        title: String,
        group: String,
        vararg keys: String,
        sensitive: Set<String> = emptySet(),
        lockedSensitive: Boolean = false,
        images: Boolean = false,
        defaults: Map<String, String> = emptyMap(),
    ): ModuleSpec =
        ModuleSpec(
            title,
            group,
            JsonObject(buildMap {
                keys.forEach { put(it, JsonPrimitive(defaults[it].orEmpty())) }
                if (images) put("images", JsonArray(emptyList()))
            }),
            sensitive = lockedSensitive,
            lockedSensitive = lockedSensitive,
            mandatorySensitiveFields = sensitive,
            fieldOrder = keys.toList() + if (images) listOf("images") else emptyList(),
        )

    fun create(type: String, required: Boolean = false): JsonObject {
        val resolved = resolveType(type)
        val spec = catalog[resolved]
        return JsonObject(
            mapOf(
                "id" to JsonPrimitive(newId()),
                "type" to JsonPrimitive(type),
                "title" to JsonPrimitive(spec?.title ?: "未知模块"),
                "sensitive" to JsonPrimitive(spec?.sensitive ?: false),
                "required" to JsonPrimitive(required),
                "config" to if (resolved == ModuleType.DATETIME) {
                    JsonObject(mapOf("mode" to JsonPrimitive("datetime")))
                } else {
                    JsonObject(emptyMap())
                },
                "value" to (spec?.defaultValue ?: JsonPrimitive("")),
            )
        )
    }

    fun normalize(value: JsonElement?): List<JsonObject> {
        val array = value as? JsonArray ?: return emptyList()
        val seen = mutableSetOf<String>()
        return array.mapNotNull { it as? JsonObject }.map { raw ->
            val result = raw.toMutableMap()
            val type = resolveType(primitive(raw["type"]).ifEmpty { "unknown" })
            val spec = catalog[type]
            var id = primitive(raw["id"])
            if (id.isEmpty() || !seen.add(id)) {
                id = newId()
                seen.add(id)
            }
            result["id"] = JsonPrimitive(id)
            result["type"] = JsonPrimitive(type)
            result["title"] = JsonPrimitive(primitive(raw["title"]).ifEmpty { spec?.title ?: "未知模块" })
            result["required"] = JsonPrimitive((raw["required"] as? JsonPrimitive)?.booleanOrNull ?: false)
            val config = (raw["config"] as? JsonObject ?: JsonObject(emptyMap())).toMutableMap()
            if (type == ModuleType.DATETIME && primitive(config["mode"]) !in setOf("date", "time", "datetime")) {
                config["mode"] = JsonPrimitive("datetime")
            }
            result["config"] = JsonObject(config)
            val requestedSensitive = (raw["sensitive"] as? JsonPrimitive)?.booleanOrNull ?: spec?.sensitive ?: false
            result["sensitive"] = JsonPrimitive(if (spec?.lockedSensitive == true) true else requestedSensitive)
            if ("value" !in result) result["value"] = spec?.defaultValue ?: JsonPrimitive("")
            if (type == ModuleType.BOOLEAN) {
                val primitive = result["value"] as? JsonPrimitive
                val boolean = primitive?.booleanOrNull ?: primitive?.contentOrNull?.lowercase()?.let {
                    when (it) { "true" -> true; "false" -> false; else -> null }
                } ?: false
                result["value"] = JsonPrimitive(boolean)
            } else if (type == ModuleType.CARD_DOCUMENT) {
                val value = result["value"] as? JsonObject ?: JsonObject(emptyMap())
                val requested = primitive(value["card_type"]).ifEmpty { CARD_BANK }
                result["value"] = cardValueForType(value, requested)
            }
            JsonObject(result)
        }
    }

    fun preset(secretType: String): List<JsonObject> = when (secretType) {
        SecretType.SECURE_NOTE -> listOf(create(ModuleType.MULTILINE, required = true))
        SecretType.SERVER -> listOf(create(ModuleType.SERVER_CONNECTION, required = true))
        else -> emptyList()
    }

    fun searchableValues(module: JsonObject): List<String> {
        val type = primitive(module["type"])
        if ((module["sensitive"] as? JsonPrimitive)?.booleanOrNull == true || type in setOf(ModuleType.IMAGES, ModuleType.ATTACHMENTS)) return emptyList()
        val value = module["value"]
        if (value !is JsonObject) return plainStrings(value)
        val config = module["config"] as? JsonObject
        val extra = (config?.get("sensitiveFields") as? JsonArray).orEmpty().mapNotNull {
            (it as? JsonPrimitive)?.contentOrNull
        }
        val hidden = catalog[type]?.mandatorySensitiveFields.orEmpty() + extra
        return plainStrings(JsonObject(value.filterKeys { it !in hidden && it !in setOf("images", "card_type") }))
    }

    private fun plainStrings(value: JsonElement?): List<String> {
        val output = ArrayList<String>()
        val stack = ArrayDeque<Pair<JsonElement?, Int>>()
        stack.addLast(value to 0)
        var nodes = 0
        var textChars = 0
        while (stack.isNotEmpty()) {
            val (current, depth) = stack.removeLast()
            nodes++
            if (nodes > 10_000 || depth > 64) continue
            when (current) {
                is JsonPrimitive -> if (current.isString) {
                    val text = current.content
                    if (text.isNotEmpty() && text.length <= 100_000 - textChars) {
                        output += text
                        textChars += text.length
                    }
                }
                is JsonObject -> if (current.size <= 1_000) {
                    current.values.toList().asReversed().forEach { stack.addLast(it to depth + 1) }
                }
                is JsonArray -> if (current.size <= 1_000) {
                    current.asReversed().forEach { stack.addLast(it to depth + 1) }
                }
                else -> Unit
            }
        }
        return output
    }

    fun primitive(value: JsonElement?): String = (value as? JsonPrimitive)?.contentOrNull.orEmpty()
    private fun newId(): String = UUID.randomUUID().toString().replace("-", "")

    /** 按模块定义顺序重排 value 字段，未知键保持原相对顺序附加到尾部。 */
    fun orderedValue(module: JsonObject): JsonObject {
        val value = module["value"] as? JsonObject ?: return JsonObject(emptyMap())
        val type = resolveType(primitive(module["type"]))
        val order = if (type == ModuleType.CARD_DOCUMENT) {
            val cardType = primitive(value["card_type"]).takeIf(cardTypeLabels::containsKey) ?: CARD_BANK
            cardFields.getValue(cardType) + "images"
        } else {
            catalog[type]?.fieldOrder.orEmpty()
        }
        if (order.isEmpty()) return value
        val byKey = value.toMap()
        val out = linkedMapOf<String, JsonElement>()
        for (key in order) byKey[key]?.let { out[key] = it }
        for ((key, element) in value) if (key !in out) out[key] = element
        return JsonObject(out)
    }
}

fun Entry.entryModules(): List<JsonObject> =
    _entryModules ?: EntryModules.normalize(fields[EntryModules.FIELD_KEY]).also { _entryModules = it }

/**
 * 详情页应展示的附加模块。条目自身的专用区域已消费的模块将被跳过（每类最多跳过一个），
 * 同类型的其他自定义模块仍然保留展示。
 * LOGIN 额外跳过 OTP 模块：动态码由详情页专用区域渲染（只显示码值与倒计时，不暴露密钥）。
 */
fun Entry.detailModules(): List<JsonObject> {
    val all = entryModules()
    val consumedTypes = when (secretType) {
        SecretType.LOGIN -> setOf(ModuleType.TARGET_APP, ModuleType.OTP)
        SecretType.OTP -> setOf(ModuleType.OTP)
        SecretType.SECURE_NOTE -> setOf(ModuleType.MULTILINE)
        SecretType.SERVER -> setOf(ModuleType.SERVER_CONNECTION)
        else -> emptySet()
    }
    if (consumedTypes.isEmpty()) return all
    val consumed = consumedTypes.toMutableSet()
    return all.filter { module ->
        val isPrimary = EntryModules.primitive(module["type"]) in consumedTypes
        if (isPrimary && consumed.remove(EntryModules.primitive(module["type"]))) {
            false
        } else {
            true
        }
    }
}

fun Entry.associatedAppPackage(): String = targetApp.ifBlank {
    entryModules()
        .firstOrNull { EntryModules.primitive(it["type"]) == ModuleType.TARGET_APP }
        ?.let { EntryModules.primitive(it["value"]) }
        .orEmpty()
        .trim()
}

fun Entry.withEntryModules(modules: List<JsonObject>): Entry =
    copy(fields = fields + (EntryModules.FIELD_KEY to JsonArray(EntryModules.normalize(JsonArray(modules)))))

fun Entry.hasSensitiveModules(): Boolean = entryModules().any { module ->
    val type = EntryModules.primitive(module["type"])
    (module["sensitive"] as? JsonPrimitive)?.booleanOrNull == true ||
        EntryModules.catalog[type]?.mandatorySensitiveFields?.isNotEmpty() == true ||
        ((module["config"] as? JsonObject)?.get("sensitiveFields") as? JsonArray)?.isNotEmpty() == true
}
