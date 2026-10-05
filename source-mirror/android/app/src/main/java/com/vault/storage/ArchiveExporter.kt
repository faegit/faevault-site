package com.vault.storage

import android.content.Context
import android.net.Uri
import com.vault.BuildConfig
import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import net.lingala.zip4j.io.outputstream.ZipOutputStream
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.AesKeyStrength
import net.lingala.zip4j.model.enums.CompressionLevel
import net.lingala.zip4j.model.enums.CompressionMethod
import net.lingala.zip4j.model.enums.EncryptionMethod
import java.io.FileNotFoundException
import java.io.OutputStream
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.util.UUID

/**
 * 单账户通用压缩包导出：
 *   Vault_<账户名>_<yyyyMMdd>.zip（WinZip AES-256 加密，口令为导出口令）
 *   ├── manifest.json     导出元信息与媒体文件清单
 *   ├── logins.csv        登录条目（复用 [CsvExporter] 列格式，明文）
 *   ├── data.json         非登录条目完整 JSON；PMVE 媒体引用重写为相对路径
 *   ├── images/           图片媒体明文流式写入
 *   └── attachments/      附件媒体明文流式写入
 *
 * 全程流式：媒体从 PMVE 对象直接写入压缩条目，不落明文临时文件；
 * 压缩包内为解密后的明文，加密与保护由 AES-256 口令承担，仅主密码守门后允许触发。
 */
object ArchiveExporter {

    const val FORMAT_VERSION = 1

    data class Stats(val loginCount: Int, val otherCount: Int, val mediaCount: Int)

    /** PMVE 媒体顺序读取接入：实现方负责按块流式解码（见 VaultRepository.openPmvEMediaRange）。 */
    interface MediaSource {
        /** 读取对象前 [length] 字节用于嗅探扩展名；对象更短时返回实际字节。 */
        fun readPrefix(ref: PmvMediaRef.Ref, length: Int): ByteArray

        /** 将对象全部明文顺序写入 [output]。 */
        fun readAll(ref: PmvMediaRef.Ref, output: OutputStream)
    }

    fun suggestedFileName(vaultName: String, date: LocalDate = LocalDate.now()): String =
        "Vault_${sanitizeSegment(vaultName)}_${date.format(DateTimeFormatter.BASIC_ISO_DATE)}.zip"

    fun write(
        context: Context,
        uri: Uri,
        vaultName: String,
        password: String,
        entries: List<Entry>,
        media: MediaSource,
    ): Stats {
        val output = context.contentResolver.openOutputStream(uri, "w")
            ?: throw FileNotFoundException("无法写入压缩包目标")
        return output.use { raw -> writeToZip(raw, vaultName, password, entries, media) }
    }

    /** 面向纯 JVM 的入口：直接写 [raw]（单元测试与桌面端复用），不依赖 Android 环境。 */
    fun writeToZip(
        raw: OutputStream,
        vaultName: String,
        password: String,
        entries: List<Entry>,
        media: MediaSource,
    ): Stats = ZipOutputStream(raw, password.toCharArray()).use { zip ->
        writeZip(zip, vaultName, entries, media)
    }

    private fun writeZip(
        zip: ZipOutputStream,
        vaultName: String,
        entries: List<Entry>,
        media: MediaSource,
    ): Stats {
        val logins = entries.filter { it.secretType == SecretType.LOGIN }
        val others = entries.filter { it.secretType != SecretType.LOGIN }

        // 附件媒体对象在条目里带原始文件名/MIME 兄弟字段（data 引用 + name/mime），
        // 先全量收集用于还原原始文件名与扩展名。
        val attachmentMeta = LinkedHashMap<Pair<UUID, Long>, MediaMeta>()
        entries.forEach { walkMediaMeta(JsonObject(it.fields), attachmentMeta) }

        // 收集全部 PMVE 媒体出现点，按对象去重并分配导出路径。
        val objectByKey = LinkedHashMap<Pair<UUID, Long>, MediaEntry>()
        val usedNames = HashMap<String, Int>()
        for (e in entries) {
            var index = 0
            for (occ in PmvMediaRef.scan(e)) {
                val ref = occ.ref ?: continue
                if (occ.classification != PmvMediaRef.Classification.OBJECT) continue
                val key = ref.objectId to ref.generation
                objectByKey.getOrPut(key) {
                    val kind = occ.kind ?: ref.kind
                    val dir = if (kind == PmvAttachmentCodec.Kind.IMAGE) "images" else "attachments"
                    if (kind == PmvAttachmentCodec.Kind.IMAGE) {
                        val ext = sniffExtension(ref, kind, media)
                        MediaEntry(ref, kind, "$dir/${sanitizeSegment(e.id)}_${index++}$ext", e.id, null, null)
                    } else {
                        val meta = attachmentMeta[key]
                        val ext = sniffExtension(ref, kind, media)
                        val name = resolveAttachmentName(meta?.name, meta?.mime, ext)
                        MediaEntry(
                            ref, kind, "$dir/${uniqueName(usedNames, name)}", e.id, meta?.name, meta?.mime,
                        )
                    }
                }
            }
        }

        // 1) manifest.json
        val manifest = buildJsonObject {
            put("format", JsonPrimitive("faevault-export"))
            put("formatVersion", JsonPrimitive(FORMAT_VERSION))
            put("exportedAt", JsonPrimitive(DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(OffsetDateTime.now())))
            put("appVersion", JsonPrimitive(BuildConfig.VERSION_NAME))
            put("vaultName", JsonPrimitive(vaultName))
            put("entryCount", JsonPrimitive(entries.size))
            put("loginCount", JsonPrimitive(logins.size))
            put("otherCount", JsonPrimitive(others.size))
            put("mediaCount", JsonPrimitive(objectByKey.size))
            put("files", JsonArray(objectByKey.values.map { me ->
                buildJsonObject {
                    put("path", JsonPrimitive(me.path))
                    put("kind", JsonPrimitive(if (me.kind == PmvAttachmentCodec.Kind.IMAGE) "image" else "attachment"))
                    put("entryId", JsonPrimitive(me.entryId))
                    me.originalName?.let { put("originalName", JsonPrimitive(it)) }
                    me.mime?.let { put("mime", JsonPrimitive(it)) }
                    put("sha256", JsonPrimitive(me.ref.sha256.joinToString("") { "%02x".format(it) }))
                    put("size", JsonPrimitive(me.ref.size))
                }
            }))
        }
        writeEntry(zip, "manifest.json") { it.write(manifest.toString().toByteArray(Charsets.UTF_8)) }

        // 2) logins.csv
        // 刻意不加公式注入防护（guardFormulas = false）：这份 CSV 在加密归档内部，由本应用
        // 与 PC 端解析，不是拿去用 Excel 打开的；加前导单引号会污染跨端往返的字段值。
        writeEntry(zip, "logins.csv") { CsvExporter.writeTo(it, logins, guardFormulas = false) }

        // 3) data.json：非登录条目完整 JSON，媒体引用重写为相对路径
        val dataEntries = JsonArray(others.map { e ->
            val replacements = PmvMediaRef.scan(e)
                .filter { it.ref != null && it.classification == PmvMediaRef.Classification.OBJECT }
                .associate { occ ->
                    val me = objectByKey.getValue(occ.ref!!.objectId to occ.ref!!.generation)
                    occ.path to buildJsonObject {
                        put("type", JsonPrimitive("file"))
                        put("path", JsonPrimitive(me.path))
                        me.originalName?.let { put("originalName", JsonPrimitive(it)) }
                        me.mime?.let { put("mime", JsonPrimitive(it)) }
                        put("sha256", JsonPrimitive(me.ref.sha256.joinToString("") { "%02x".format(it) }))
                        put("size", JsonPrimitive(me.ref.size))
                    }
                }
            VaultCodec.json.encodeToJsonElement(Entry.serializer(), PmvMediaRef.replaceEntryRefs(e, replacements))
        })
        val dataJson = buildJsonObject {
            put("format", JsonPrimitive("faevault-export"))
            put("formatVersion", JsonPrimitive(FORMAT_VERSION))
            put("entries", dataEntries)
        }
        writeEntry(zip, "data.json") { it.write(dataJson.toString().toByteArray(Charsets.UTF_8)) }

        // 4) 媒体：images/ attachments/ 明文流式写入
        for (me in objectByKey.values) {
            writeEntry(zip, me.path) { media.readAll(me.ref, it) }
        }

        return Stats(logins.size, others.size, objectByKey.size)
    }

    private fun writeEntry(zip: ZipOutputStream, name: String, block: (OutputStream) -> Unit) {
        zip.putNextEntry(entryParams(name))
        block(zip)
        zip.closeEntry()
    }

    private fun entryParams(name: String): ZipParameters = ZipParameters().apply {
        compressionMethod = CompressionMethod.DEFLATE
        compressionLevel = CompressionLevel.NORMAL
        isEncryptFiles = true
        encryptionMethod = EncryptionMethod.AES
        aesKeyStrength = AesKeyStrength.KEY_STRENGTH_256
        fileNameInZip = name
    }

    private fun sniffExtension(
        ref: PmvMediaRef.Ref,
        kind: PmvAttachmentCodec.Kind,
        media: MediaSource,
    ): String {
        val prefix = if (ref.size <= 0) ByteArray(0) else media.readPrefix(ref, 32)
        return try {
            when {
                prefix.size >= 3 && prefix[0] == 'G'.code.toByte() && prefix[1] == 'I'.code.toByte() &&
                    prefix[2] == 'F'.code.toByte() -> ".gif"
                prefix.size >= 4 && prefix[0] == 0x89.toByte() && prefix[1] == 'P'.code.toByte() &&
                    prefix[2] == 'N'.code.toByte() && prefix[3] == 'G'.code.toByte() -> ".png"
                prefix.size >= 12 && String(prefix, 0, 4, Charsets.US_ASCII) == "RIFF" &&
                    String(prefix, 8, 4, Charsets.US_ASCII) == "WEBP" -> ".webp"
                prefix.size >= 12 && String(prefix, 4, 8, Charsets.US_ASCII).startsWith("ftyphei") -> ".heic"
                prefix.size >= 2 && prefix[0] == 0xFF.toByte() && prefix[1] == 0xD8.toByte() -> ".jpg"
                prefix.size >= 5 && String(prefix, 0, 5, Charsets.US_ASCII) == "%PDF-" -> ".pdf"
                prefix.size >= 2 && prefix[0] == 'P'.code.toByte() && prefix[1] == 'K'.code.toByte() -> ".zip"
                else -> if (kind == PmvAttachmentCodec.Kind.IMAGE) ".jpg" else ".bin"
            }
        } finally {
            prefix.fill(0)
        }
    }

    private fun sanitizeSegment(name: String): String {
        val cleaned = name.map { c -> if (c.isLetterOrDigit() || c == '_' || c == '-') c else '_' }.joinToString("")
        return cleaned.ifBlank { "item" }
    }

    /** 递归收集附件对象（data 引用 + name/mime 兄弟字段）的原始文件名与 MIME。 */
    private fun walkMediaMeta(element: JsonElement, out: MutableMap<Pair<UUID, Long>, MediaMeta>) {
        when (element) {
            is JsonObject -> {
                val data = element["data"]
                if (data != null) {
                    val ref = parseMediaRef(data)
                    if (ref != null) {
                        val name = (element["name"] as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank)
                        val mime = (element["mime"] as? JsonPrimitive)?.contentOrNull?.takeIf(String::isNotBlank)
                        if (name != null || mime != null) out.putIfAbsent(ref.objectId to ref.generation, MediaMeta(name, mime))
                    }
                }
                element.forEach { (_, child) -> walkMediaMeta(child, out) }
            }
            is JsonArray -> element.forEach { walkMediaMeta(it, out) }
            else -> {}
        }
    }

    private fun parseMediaRef(value: JsonElement): PmvMediaRef.Ref? = when (value) {
        is JsonObject -> runCatching { PmvMediaRef.fromJson(value) }.getOrNull()
        is JsonPrimitive -> value.contentOrNull?.let { runCatching { PmvMediaRef.fromExternalString(it) }.getOrNull() }
        else -> null
    }

    /** 附件文件名解析：优先还原入库的原始名；无扩展名或无名时依次用 MIME、魔数嗅探兜底。 */
    private fun resolveAttachmentName(originalName: String?, mime: String?, sniffedExt: String): String {
        val base = originalName?.let(::sanitizeFileName)
        if (!base.isNullOrBlank()) {
            val dot = base.lastIndexOf('.')
            val nameExt = if (dot > 0) base.substring(dot + 1) else ""
            if (nameExt.isNotEmpty() && nameExt.length <= 8 && nameExt.all { it.isLetterOrDigit() }) return base
            return base + (mimeToExt(mime) ?: sniffedExt)
        }
        return "attachment" + (mimeToExt(mime) ?: sniffedExt)
    }

    /** 清洗用户文件名：去掉路径段、非法字符替换为下划线，防目录穿越。 */
    private fun sanitizeFileName(name: String): String {
        val base = name.substringAfterLast('/').substringAfterLast('\\').trim()
            .map { c -> if (c.isLetterOrDigit() || c in "._- ") c else '_' }
            .joinToString("")
            .trimStart('.')
        return base.take(120)
    }

    /** 同一目录下重名时追加 _2/_3 后缀（保留扩展名）。 */
    private fun uniqueName(used: MutableMap<String, Int>, name: String): String {
        val count = used.merge(name, 1, Int::plus)!! - 1
        if (count == 0) return name
        val dot = name.lastIndexOf('.')
        return if (dot > 0) name.substring(0, dot) + "_${count + 1}" + name.substring(dot) else name + "_${count + 1}"
    }

    private fun mimeToExt(mime: String?): String? =
        mime?.substringBefore(';')?.trim()?.lowercase()?.let(MIME_TO_EXT::get)

    private val MIME_TO_EXT: Map<String, String> = mapOf(
        "application/pdf" to ".pdf",
        "application/zip" to ".zip",
        "application/x-7z-compressed" to ".7z",
        "application/x-rar-compressed" to ".rar",
        "application/x-tar" to ".tar",
        "application/gzip" to ".gz",
        "application/x-bzip2" to ".bz2",
        "application/json" to ".json",
        "application/xml" to ".xml",
        "application/javascript" to ".js",
        "application/msword" to ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" to ".docx",
        "application/vnd.ms-excel" to ".xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" to ".xlsx",
        "application/vnd.ms-powerpoint" to ".ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" to ".pptx",
        "application/vnd.android.package-archive" to ".apk",
        "application/x-httpd-php" to ".php",
        "text/plain" to ".txt",
        "text/csv" to ".csv",
        "text/html" to ".html",
        "text/xml" to ".xml",
        "text/markdown" to ".md",
        "image/jpeg" to ".jpg",
        "image/png" to ".png",
        "image/gif" to ".gif",
        "image/webp" to ".webp",
        "image/heic" to ".heic",
        "image/bmp" to ".bmp",
        "image/tiff" to ".tiff",
        "image/svg+xml" to ".svg",
        "font/otf" to ".otf",
        "font/ttf" to ".ttf",
    )

    private data class MediaMeta(val name: String?, val mime: String?)

    private data class MediaEntry(
        val ref: PmvMediaRef.Ref,
        val kind: PmvAttachmentCodec.Kind,
        val path: String,
        val entryId: String,
        val originalName: String?,
        val mime: String?,
    )
}
