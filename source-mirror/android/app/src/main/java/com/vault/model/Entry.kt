package com.vault.model

import androidx.compose.runtime.Immutable
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * 密码条目——字段名与桌面端 core/models.py 的 dataclass 严格一致。
 * fields 用 Map<String, JsonElement> 宽松承载各类型扩展字段，未知键原样保留以保证往返不丢数据。
 */
@Immutable
@Serializable
data class Entry(
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    @SerialName("target_app") val targetApp: String = "",
    val notes: String = "",
    val tags: List<String> = emptyList(),
    val id: String = "",
    @SerialName("created_at") val createdAt: Double = 0.0,
    @SerialName("updated_at") val updatedAt: Double = 0.0,
    @SerialName("secret_type") val secretType: String = SecretType.LOGIN,
    val fields: Map<String, JsonElement> = emptyMap(),
    @SerialName("deleted_at") val deletedAt: Double? = null,
    // ── 泄露检测缓存（桌面端 core/models.py 顶层字段对齐）──
    @SerialName("leak_check_revision") val leakCheckRevision: Double? = null,
    @SerialName("leak_pwned_count") val leakPwnedCount: Int? = null,
    @SerialName("leak_common_weak") val leakCommonWeak: Boolean = false,
    @SerialName("leak_checked_at") val leakCheckedAt: Double? = null,
    @kotlinx.serialization.Transient val containsPasskey: Boolean = false,
    @kotlinx.serialization.Transient val displaySummary: String = "",
    @kotlinx.serialization.Transient val expirySummary: String = "",
) {
    @kotlinx.serialization.Transient
    private var _searchHaystack: String? = null

    @kotlinx.serialization.Transient
    private var _titleLower: String? = null

    @kotlinx.serialization.Transient
    private var _titleSortKey: String? = null

    @kotlinx.serialization.Transient
    private var _firstLetter: Char? = null

    @kotlinx.serialization.Transient
    internal var _entryModules: List<JsonObject>? = null

    @kotlinx.serialization.Transient
    private var _sortedTags: List<String>? = null

    @kotlinx.serialization.Transient
    private var _fieldsWithoutTargetApp: Map<String, JsonElement>? = null

    val searchHaystack: String
        get() {
            val cached = _searchHaystack
            if (cached != null) return cached
            val legacyExtra = fields.entries
                .filter { it.key != "card_images_b64" && it.key != "id_images_b64" && it.key != EntryModules.FIELD_KEY }
                .joinToString(" ") { it.value.toString() }
            val moduleExtra = entryModules().flatMap(EntryModules::searchableValues).joinToString(" ")
            val extra = "$legacyExtra $moduleExtra"
            return listOf(title, username, url, targetApp, notes, tags.joinToString(" "), extra)
                .joinToString(" ").lowercase()
                .also { _searchHaystack = it }
        }

    val titleLower: String
        get() = _titleLower ?: title.lowercase().also { _titleLower = it }

    /** 排序键：把中文转拼音、英文小写后做混排比较，让 "苹果" 和 "apple" 落到正确的字母段。 */
    val titleSortKey: String
        get() = _titleSortKey ?: Pinyin.sortKey(title).also { _titleSortKey = it }

    /** 首字母（侧边索引用）：从已缓存的 titleSortKey 推导，避免重复 JNI 调用。 */
    val firstLetter: Char
        get() {
            val cached = _firstLetter
            if (cached != null) return cached
            // 基于条目的第一个字符：数字/符号开头归入 '#'，中文取拼音首字母。
            val ch = Pinyin.firstLetter(title)
            return ch.also { _firstLetter = it }
        }

    /** 排序后的标签，供内容比较 / 去重热路径复用，避免每次对列表重复 sort。 */
    val sortedTags: List<String>
        get() = _sortedTags ?: tags.sorted().also { _sortedTags = it }

    /** 剔除 TARGET_APP 模块后的 fields 视图，供合并去重复用（一次计算，多次比较）。 */
    val fieldsWithoutTargetApp: Map<String, JsonElement>
        get() {
            val cached = _fieldsWithoutTargetApp
            if (cached != null) return cached
            val modules = entryModules().filter {
                EntryModules.primitive(it["type"]) != ModuleType.TARGET_APP
            }
            val result = if (modules.isEmpty()) {
                fields - EntryModules.FIELD_KEY
            } else {
                fields + (EntryModules.FIELD_KEY to JsonArray(modules))
            }
            return result.also { _fieldsWithoutTargetApp = it }
        }
}

object SecretType {
    const val LOGIN = "login"
    /** 卡证合并类型：银行卡 / 会员卡 / 社保卡 / 证件等统一入口，子类型由 fields.card_type 区分。 */
    const val CARD_DOCUMENT = "card_document"
    // 旧 wire 类型：读取时映射到 CARD_DOCUMENT（见 EntryExt.normalized）。
    const val CREDIT_CARD = "credit_card"
    const val ID_CARD = "id_card"
    const val WIFI = "wifi"
    const val API_KEY = "api_key"
    const val OTP = "otp"
    const val SECURE_NOTE = "secure_note"
    const val SERVER = "server"
    const val CUSTOM = "custom"
    const val PASSKEY = "passkey"
    /** 所有可持久化类型。Passkey 只能由 Credential Manager 创建，不允许手动新增。 */
    val ALL = listOf(LOGIN, WIFI, CARD_DOCUMENT, API_KEY, OTP, SECURE_NOTE, SERVER, CUSTOM, PASSKEY)
    val CREATABLE = ALL.filterNot { it == PASSKEY }
}

@Immutable
@Serializable
data class VaultPayload(
    val version: Int = 1,
    val entries: List<Entry> = emptyList(),
    val trash: List<Entry> = emptyList(),
    @SerialName("purge_tombstones") val purgeTombstones: Map<String, Double> = emptyMap(),
    @SerialName("sync_meta") val syncMeta: SyncMeta = SyncMeta(),
    // 写入时刻（秒，UTC）。仅作为导出元数据和旧格式兼容字段；
    // 同步直接比较条目的原始 updatedAt，不使用该字段改写条目时间。
    @SerialName("export_epoch") val exportEpoch: Double? = null,
    @SerialName("autofill_exclusions") val autofillExclusions: AutofillExclusions = AutofillExclusions(),
)

@Immutable
@Serializable
data class AutofillExclusions(
    val packages: List<String> = emptyList(),
    val hosts: List<String> = emptyList(),
    val processes: List<String> = emptyList(),
    val states: Map<String, AutofillExclusionState> = emptyMap(),
) {
    fun normalized(): AutofillExclusions = merge(AutofillExclusions())

    fun merge(other: AutofillExclusions): AutofillExclusions {
        val merged = sortedMapOf<String, AutofillExclusionState>()
        fun accept(key: String, state: AutofillExclusionState) {
            val category = key.substringBefore(':')
            val value = normalizeValue(category, key.substringAfter(':', "")) ?: return
            val canonical = "$category:$value"
            val current = merged[canonical]
            if (current == null || state.updatedAt > current.updatedAt ||
                (state.updatedAt == current.updatedAt && state.deleted && !current.deleted)) {
                merged[canonical] = state.copy(updatedAt = state.updatedAt.coerceAtLeast(0))
            }
        }
        for (source in listOf(this, other)) {
            for ((category, values) in listOf("packages" to source.packages, "hosts" to source.hosts, "processes" to source.processes)) {
                values.forEach { accept("$category:$it", AutofillExclusionState()) }
            }
            source.states.forEach { (key, state) -> accept(key, state) }
        }
        fun active(category: String) = merged.filter { (key, state) -> key.startsWith("$category:") && !state.deleted }
            .keys.map { it.substringAfter(':') }
        return AutofillExclusions(active("packages"), active("hosts"), active("processes"), merged)
    }

    fun edit(category: String, value: String, deleted: Boolean, nowMillis: Long = System.currentTimeMillis()): AutofillExclusions {
        val canonical = normalizeValue(category, value) ?: return this
        val current = normalized()
        val newest = current.states.values.maxOfOrNull { it.updatedAt } ?: 0L
        check(newest < Long.MAX_VALUE) { "排除项时间戳已超出范围" }
        val timestamp = maxOf(nowMillis, newest + 1)
        return current.copy(states = current.states + ("$category:$canonical" to AutofillExclusionState(timestamp, deleted))).normalized()
    }

    companion object {
        fun normalizeValue(category: String, value: String): String? = when (category) {
            "packages" -> value.trim().lowercase(java.util.Locale.ROOT).takeIf { it.isNotEmpty() }
            "processes" -> value.trim().replace('\\', '/').substringAfterLast('/').lowercase(java.util.Locale.ROOT).takeIf { it.isNotEmpty() }
            "hosts" -> runCatching {
                val input = value.trim()
                require(input.isNotEmpty() && input.none(Char::isWhitespace))
                val uri = java.net.URI(if (input.contains("://")) input else "https://$input")
                require(uri.scheme.lowercase(java.util.Locale.ROOT) in setOf("http", "https") && uri.rawUserInfo == null)
                val host = uri.host ?: uri.rawAuthority?.substringBefore(':') ?: return null
                java.net.IDN.toASCII(host.trimEnd('.')).lowercase(java.util.Locale.ROOT).takeIf { it.isNotEmpty() }
            }.getOrNull()
            else -> null
        }
    }
}

@Immutable
@Serializable
data class AutofillExclusionState(
    @SerialName("updated_at") val updatedAt: Long = 0,
    val deleted: Boolean = false,
)

/**
 * 多端同步元数据（spec/SYNC_V2.md）。当前只承载 deviceId；
 * v1 老库首次解码时 [com.vault.storage.VaultCodec.decode] 会注入 UUID。
 *
 * deviceId 与"库"绑定，不是与"设备"绑定：A 端导出的库被 B 端导入时仍沿用 A 的 deviceId。
 * 用途是合并时识别"此 incoming 来自哪个端"，便于将来实现 lastSyncWith 同步基线。
 */
@Immutable
@Serializable
data class SyncMeta(
    @SerialName("device_id") val deviceId: String = "",
    @SerialName("key_revision") val keyRevision: Int = 0,
    // 主密码/恢复密钥最近一次变更时刻（UTC 秒）。两端分叉时据此自动收敛：
    // 只保留更新时间最新的密钥/密码版本，旧端自动替换。
    @SerialName("key_updated_at") val keyUpdatedAt: Double = 0.0,
    // 存储密钥首次创建时刻（UTC 秒）。老库可能为 0，表示未知。
    @SerialName("key_created_at") val keyCreatedAt: Double = 0.0,
)
