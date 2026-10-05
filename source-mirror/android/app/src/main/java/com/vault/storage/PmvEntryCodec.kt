package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.encodeToJsonElement
import java.util.UUID

/** 单条 Entry 的规范 JSON 负载；只处理内存编解码，落盘前必须交给 [PmvBlockCrypto]。 */
object PmvEntryCodec {
    private const val MAX_ENTRY_PLAIN_SIZE =
        PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE - PmvContainerFormat.GCM_TAG_SIZE

    fun encode(entry: Entry): ByteArray {
        requireCanonicalId(entry.id)
        val element = VaultCodec.json.encodeToJsonElement(Entry.serializer(), entry)
        val encoded = canonicalJson(element).encodeToByteArray()
        require(encoded.size <= MAX_ENTRY_PLAIN_SIZE) { "Entry 负载超过单 Block 上限" }
        return encoded
    }

    fun decode(raw: ByteArray, expectedEntryId: UUID? = null): Entry {
        require(raw.size <= MAX_ENTRY_PLAIN_SIZE) { "Entry 负载超过单 Block 上限" }
        val decoded = VaultCodec.json.decodeFromString<Entry>(raw.decodeToString(throwOnInvalidSequence = true))
        val decodedId = requireCanonicalId(decoded.id)
        require(expectedEntryId == null || decodedId == expectedEntryId) { "Entry 负载 ID 与 Block object_id 不一致" }
        return decoded
    }

    /**
     * PMV next 的跨端规范 JSON：对象键按无符号 UTF-8 字节序排列，数组保序，数字使用
     * 去除尾零且禁止指数的十进制表示。它不改变旧格式 [VaultCodec] 的 JSON 行为。
     */
    internal fun canonicalJson(value: JsonElement): String = when (value) {
        JsonNull -> "null"
        is JsonArray -> value.joinToString(prefix = "[", postfix = "]", separator = ",") { canonicalJson(it) }
        is JsonObject -> value.entries
            .sortedWith { left, right -> compareUtf8(left.key, right.key) }
            .joinToString(prefix = "{", postfix = "}", separator = ",") { (key, child) ->
                "${JsonPrimitive(key)}:${canonicalJson(child)}"
            }
        is JsonPrimitive -> when {
            value.isString -> value.toString()
            value.booleanOrNull != null -> value.content
            else -> canonicalNumber(value.content)
        }
    }

    private fun canonicalNumber(raw: String): String {
        val number = try {
            raw.toBigDecimal()
        } catch (error: NumberFormatException) {
            throw IllegalArgumentException("Entry JSON 包含非有限数字", error)
        }
        return if (number.compareTo(java.math.BigDecimal.ZERO) == 0) "0"
        else number.stripTrailingZeros().toPlainString()
    }

    private fun compareUtf8(left: String, right: String): Int {
        val leftBytes = left.encodeToByteArray()
        val rightBytes = right.encodeToByteArray()
        val common = minOf(leftBytes.size, rightBytes.size)
        for (index in 0 until common) {
            val comparison = (leftBytes[index].toInt() and 0xff).compareTo(rightBytes[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return leftBytes.size.compareTo(rightBytes.size)
    }

    private fun requireCanonicalId(value: String): UUID {
        val parsed = try {
            UUID.fromString(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Entry ID 必须为 UUID", error)
        }
        require(parsed.toString() == value.lowercase()) { "Entry ID 必须使用规范 UUID 表示" }
        return parsed
    }
}
