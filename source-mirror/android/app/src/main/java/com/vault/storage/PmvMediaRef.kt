package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.io.InputStream
import java.util.UUID

/** Canonical PMVE ObjectStore references embedded in Entry.fields. */
object PmvMediaRef {
    const val TYPE_KEY = "\$pmv_media_ref"
    const val TYPE_VALUE = "pmv4-object-v1"
    private const val STRING_PREFIX = "pmv4-object:v1:"
    private val IMAGE_KEYS = setOf("images", "card_images_b64", "id_images_b64")
    private val ATTACHMENT_KEYS = setOf("attachments")
    private val HEX = Regex("[0-9a-f]{64}")
    private val UNSIGNED_DECIMAL = Regex("0|[1-9][0-9]*")
    private val BASE64 = Regex("[A-Za-z0-9+/]+={0,2}")
    private val WINDOWS_PATH = Regex("[A-Za-z]:[\\\\/].+")

    data class Ref(
        val objectId: UUID,
        val generation: Long,
        val kind: PmvAttachmentCodec.Kind,
        val size: Long,
        val sha256: ByteArray,
    ) {
        init {
            require(generation >= 0) { "media generation 必须为非负 signed Long" }
            require(size >= 0) { "media size 必须为非负 signed Long" }
            require(sha256.size == 32) { "media sha256 必须为 32 字节" }
        }

        fun toJson(): JsonObject = JsonObject(linkedMapOf(
            TYPE_KEY to JsonPrimitive(TYPE_VALUE),
            "object_id" to JsonPrimitive(objectId.toString()),
            "generation" to JsonPrimitive(generation),
            "kind" to JsonPrimitive(kindName(kind)),
            "size" to JsonPrimitive(size),
            "sha256" to JsonPrimitive(sha256.toHex()),
        ))

        fun toExternalString(): String = buildString {
            append(STRING_PREFIX)
            append(objectId)
            append(':').append(generation)
            append(':').append(kindName(kind))
            append(':').append(size)
            append(':').append(sha256.toHex())
        }

        fun copySha256(): Ref = copy(sha256 = sha256.copyOf())

        override fun equals(other: Any?): Boolean = other is Ref && objectId == other.objectId &&
            generation == other.generation && kind == other.kind && size == other.size &&
            sha256.contentEquals(other.sha256)

        override fun hashCode(): Int {
            var result = objectId.hashCode()
            result = 31 * result + generation.hashCode()
            result = 31 * result + kind.hashCode()
            result = 31 * result + size.hashCode()
            return 31 * result + sha256.contentHashCode()
        }
    }

    enum class Classification { OBJECT, LEGACY_EXTERNAL, INLINE, UNKNOWN }

    data class Occurrence(
        val path: String,
        val classification: Classification,
        val kind: PmvAttachmentCodec.Kind?,
        val raw: JsonElement,
        val ref: Ref? = null,
    )

    data class LegacyStream(
        val path: String,
        val input: InputStream,
        val expectedSize: Long,
        val objectId: UUID,
        val generation: Long,
        val kind: PmvAttachmentCodec.Kind,
    )

    class TransformPlan internal constructor(
        private val original: Entry,
        val objectImports: List<PmvVaultStore.ObjectImport>,
        private val paths: List<String>,
        private val pathImportIndexes: List<Int>,
    ) {
        /** Uses applyMutation's refs, in import order, to produce the Entry for that same commit. */
        fun transform(objectRefs: List<PmvVaultStore.ObjectRef>): Entry {
            require(objectRefs.size == objectImports.size) { "ObjectRef 数量与媒体导入计划不一致" }
            val replacements = paths.indices.associate { index ->
                val path = paths[index]
                val importIndex = pathImportIndexes[index]
                val value = objectRefs[importIndex]
                val request = objectImports[importIndex]
                require(value.objectId == request.objectId && value.generation == request.generation &&
                    value.kind == request.kind && value.size == request.expectedSize) {
                    "ObjectRef 与媒体导入计划不一致"
                }
                path to fromStoreRef(value).toJson()
            }
            val fields = original.fields.mapValues { (key, value) ->
                replace(value, "/fields/${escape(key)}", replacements)
            }
            return original.copy(fields = fields)
        }

        /** Convenience bridge used directly from applyMutation's prepare callback. */
        fun prepare(
            objectRefs: List<PmvVaultStore.ObjectRef>,
            metadata: JsonObject,
            otherEntries: List<Entry> = emptyList(),
        ): PmvVaultStore.MutationContent =
            PmvVaultStore.MutationContent(metadata, otherEntries + transform(objectRefs))
    }

    fun fromJson(value: JsonElement): Ref {
        val raw = value as? JsonObject ?: throw IllegalArgumentException("media ref JSON 必须为对象")
        require(raw.keys == setOf(TYPE_KEY, "object_id", "generation", "kind", "size", "sha256")) {
            "media ref JSON 字段不规范"
        }
        require(raw[TYPE_KEY]?.jsonPrimitive?.contentOrNull == TYPE_VALUE) { "media ref 类型无效" }
        val objectText = raw["object_id"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val objectId = UUID.fromString(objectText).also { require(it.toString() == objectText) {
            "object_id 必须为小写 canonical UUID"
        } }
        val generation = strictLong(raw["generation"], "generation")
        val size = strictLong(raw["size"], "size")
        val kind = parseKind(raw["kind"]?.jsonPrimitive?.contentOrNull.orEmpty())
        val digest = raw["sha256"]?.jsonPrimitive?.contentOrNull.orEmpty()
        require(HEX.matches(digest)) { "sha256 必须为小写 hex" }
        return Ref(objectId, generation, kind, size, digest.hexToBytes())
    }

    fun fromExternalString(value: String): Ref {
        require(value.startsWith(STRING_PREFIX)) { "media ref 字符串前缀无效" }
        val parts = value.removePrefix(STRING_PREFIX).split(':')
        require(parts.size == 5) { "media ref 字符串字段数量无效" }
        val objectId = UUID.fromString(parts[0]).also { require(it.toString() == parts[0]) {
            "object_id 必须为小写 canonical UUID"
        } }
        require(UNSIGNED_DECIMAL.matches(parts[1])) { "generation 必须为 canonical integer" }
        val generation = parts[1].toLongOrNull() ?: throw IllegalArgumentException("generation 无效")
        val kind = parseKind(parts[2])
        require(UNSIGNED_DECIMAL.matches(parts[3])) { "size 必须为 canonical integer" }
        val size = parts[3].toLongOrNull() ?: throw IllegalArgumentException("size 无效")
        require(HEX.matches(parts[4])) { "sha256 必须为小写 hex" }
        return Ref(objectId, generation, kind, size, parts[4].hexToBytes())
    }

    fun scan(entry: Entry): List<Occurrence> = buildList {
        entry.fields.forEach { (key, value) -> scan(value, "/fields/${escape(key)}", kindForKey(key), this) }
    }

    /** Scans canonical refs anywhere in metadata; non-ref values are ignored unless media-shaped. */
    fun scanJson(value: JsonElement, basePath: String = "/metadata"): List<Occurrence> = buildList {
        scan(value, basePath, null, this)
    }

    /**
     * 把条目字段中 path 命中的媒体引用替换为导出文件引用（通用压缩包导出用，不落库）。
     * 仅替换 key 精确匹配的对象；替换值由调用方提供（如 {"type":"file","path":...}）。
     */
    fun replaceEntryRefs(entry: Entry, replacements: Map<String, JsonObject>): Entry {
        if (replacements.isEmpty()) return entry
        val rewritten = replace(JsonObject(entry.fields), "/fields", replacements) as JsonObject
        return entry.copy(fields = rewritten.mapValues { it.value })
    }

    fun plan(entry: Entry, streams: List<LegacyStream>): TransformPlan {
        require(streams.map { it.path }.toSet().size == streams.size) { "媒体导入 path 不得重复" }
        val occurrences = scan(entry).associateBy(Occurrence::path)
        streams.forEach { source ->
            val occurrence = requireNotNull(occurrences[source.path]) { "媒体导入 path 不存在: ${source.path}" }
            require(occurrence.classification in setOf(Classification.LEGACY_EXTERNAL, Classification.INLINE)) {
                "媒体导入只接受 legacy 或 inline 引用: ${source.path}"
            }
            require(occurrence.kind == source.kind) { "媒体导入 kind 与字段位置不一致: ${source.path}" }
            require(source.expectedSize >= 0 && source.generation >= 0) { "媒体导入大小或 generation 无效" }
        }
        val imports = mutableListOf<PmvVaultStore.ObjectImport>()
        val byKey = linkedMapOf<Pair<UUID, Long>, Int>()
        val indexes = streams.map { source ->
            byKey.getOrPut(source.objectId to source.generation) {
                imports += PmvVaultStore.ObjectImport(
                    source.input, source.expectedSize, source.objectId, source.generation, source.kind,
                )
                imports.lastIndex
            }
        }
        return TransformPlan(entry, imports, streams.map(LegacyStream::path), indexes)
    }

    fun fromStoreRef(value: PmvVaultStore.ObjectRef): Ref =
        Ref(value.objectId, value.generation, value.kind, value.size, value.sha256.copyOf())

    private fun scan(value: JsonElement, path: String, inheritedKind: PmvAttachmentCodec.Kind?, out: MutableList<Occurrence>) {
        runCatching { fromJson(value) }.getOrNull()?.let {
            out += Occurrence(path, Classification.OBJECT, it.kind, value, it.copySha256())
            return
        }
        when (value) {
            is JsonObject -> {
                if (TYPE_KEY in value) {
                    out += Occurrence(path, Classification.UNKNOWN, inheritedKind, value)
                    return
                }
                if (inheritedKind != null && value.keys.any { it in setOf("name", "mime", "size", "sha256") } &&
                    "data" !in value
                ) {
                    out += Occurrence(path, Classification.UNKNOWN, inheritedKind, value)
                    return
                }
                val moduleKind = value["type"]?.let { (it as? JsonPrimitive)?.contentOrNull }?.let(::kindForKey)
                value.forEach { (key, child) ->
                    val childKind = kindForKey(key) ?: when (key) {
                        "value" -> moduleKind
                        "data" -> inheritedKind
                        else -> null
                    }
                    scan(child, "$path/${escape(key)}", childKind, out)
                }
            }
            is JsonArray -> value.forEachIndexed { index, child -> scan(child, "$path/$index", inheritedKind, out) }
            is JsonPrimitive -> {
                val text = value.contentOrNull
                if (text != null) {
                    runCatching { fromExternalString(text) }.getOrNull()?.let {
                        out += Occurrence(path, Classification.OBJECT, it.kind, value, it.copySha256())
                        return
                    }
                    if (text.startsWith(STRING_PREFIX)) {
                        out += Occurrence(path, Classification.UNKNOWN, inheritedKind, value)
                        return
                    }
                    if (text.startsWith("img:") || text.startsWith("att:") || text.startsWith("blb:")) {
                        val kind = when {
                            text.startsWith("img:") || text.startsWith("blb:image:") -> PmvAttachmentCodec.Kind.IMAGE
                            text.startsWith("att:") || text.startsWith("blb:attachment:") -> PmvAttachmentCodec.Kind.ATTACHMENT
                            else -> inheritedKind
                        }
                        out += Occurrence(path, Classification.LEGACY_EXTERNAL, kind, value)
                        return
                    }
                }
                if (inheritedKind != null) {
                    val classification = when {
                        text == null -> Classification.UNKNOWN
                        isLegacy(text) -> Classification.LEGACY_EXTERNAL
                        isInline(text) -> Classification.INLINE
                        else -> Classification.UNKNOWN
                    }
                    val kind = when {
                        text?.startsWith("img:") == true -> PmvAttachmentCodec.Kind.IMAGE
                        text?.startsWith("att:") == true -> PmvAttachmentCodec.Kind.ATTACHMENT
                        else -> inheritedKind
                    }
                    out += Occurrence(path, classification, kind, value)
                }
            }
        }
    }

    private fun replace(value: JsonElement, path: String, replacements: Map<String, JsonObject>): JsonElement {
        replacements[path]?.let { return it }
        return when (value) {
            is JsonObject -> JsonObject(value.mapValues { (key, child) ->
                replace(child, "$path/${escape(key)}", replacements)
            })
            is JsonArray -> JsonArray(value.mapIndexed { index, child -> replace(child, "$path/$index", replacements) })
            else -> value
        }
    }

    private fun kindForKey(key: String): PmvAttachmentCodec.Kind? = when (key) {
        in IMAGE_KEYS, "image", "photo" -> PmvAttachmentCodec.Kind.IMAGE
        in ATTACHMENT_KEYS, "attachment" -> PmvAttachmentCodec.Kind.ATTACHMENT
        else -> null
    }

    private fun isLegacy(value: String): Boolean = value.startsWith("img:") || value.startsWith("att:") ||
        value.startsWith("blb:") ||
        value.startsWith("file://") || value.startsWith('/') || WINDOWS_PATH.matches(value)

    private fun isInline(value: String): Boolean {
        if (value.startsWith("data:") && ";base64," in value) return true
        val compact = value.filterNot(Char::isWhitespace)
        return compact.length >= 16 && compact.length % 4 == 0 && BASE64.matches(compact)
    }

    private fun strictLong(value: JsonElement?, name: String): Long {
        val primitive = value as? JsonPrimitive ?: throw IllegalArgumentException("$name 必须为 JSON integer")
        require(!primitive.isString && !primitive.content.contains('.') && !primitive.content.contains('e', true)) {
            "$name 必须为 JSON integer"
        }
        return primitive.content.toLongOrNull() ?: throw IllegalArgumentException("$name 超出 signed Long")
    }

    private fun kindName(kind: PmvAttachmentCodec.Kind) = kind.name.lowercase()
    private fun parseKind(value: String) = when (value) {
        "image" -> PmvAttachmentCodec.Kind.IMAGE
        "attachment" -> PmvAttachmentCodec.Kind.ATTACHMENT
        else -> throw IllegalArgumentException("media kind 无效")
    }
    private fun escape(value: String) = value.replace("~", "~0").replace("/", "~1")
    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun String.hexToBytes() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
