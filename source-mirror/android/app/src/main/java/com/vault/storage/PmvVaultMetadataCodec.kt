package com.vault.storage

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.util.UUID

/**
 * PMV next 顶层保险库元数据。条目、回收站条目和媒体明文必须存放在各自的对象 Block 中。
 *
 * Codec 使用中立 [JsonObject]，避免当前两端模型尚未认识的扩展字段在读写时丢失。返回值可直接
 * 作为 [PmvContainerFormat.BlockType.OBJECT_METADATA] 的明文交给 [PmvBlockCrypto]。
 */
object PmvVaultMetadataCodec {
    const val SCHEMA = "pmv-vault-metadata"
    const val VERSION = 1
    const val MAX_PLAIN_SIZE =
        PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE - PmvContainerFormat.GCM_TAG_SIZE
    val BLOCK_TYPE: PmvContainerFormat.BlockType = PmvContainerFormat.BlockType.OBJECT_METADATA

    private val DIGEST_DOMAIN = "PMV Vault Metadata Logical Digest v1\u0000".encodeToByteArray()
    private val REQUIRED_FIELDS = setOf(
        "schema", "version", "vault_id", "entry_order", "trash_order", "sync_meta",
        "key_revision", "export_epoch", "purge_tombstones",
    )
    private val FORBIDDEN_TOP_LEVEL = setOf("entries", "trash", "media", "attachments", "images")
    private val FORBIDDEN_SECRET_FIELDS = setOf(
        "password", "secret", "private_key", "private_key_pkcs8", "media_plaintext", "content_bytes",
    )

    fun encode(metadata: JsonObject): ByteArray {
        validate(metadata)
        val encoded = PmvEntryCodec.canonicalJson(metadata).encodeToByteArray()
        require(encoded.size <= MAX_PLAIN_SIZE) { "Vault Metadata 超过单 Block 上限" }
        return encoded
    }

    fun decode(raw: ByteArray, expectedVaultId: UUID? = null): JsonObject {
        require(raw.size <= MAX_PLAIN_SIZE) { "Vault Metadata 超过单 Block 上限" }
        val value = try {
            Json.parseToJsonElement(raw.decodeToString(throwOnInvalidSequence = true))
        } catch (error: Exception) {
            throw IllegalArgumentException("Vault Metadata 不是有效的 UTF-8 JSON", error)
        }
        require(value is JsonObject) { "Vault Metadata 必须为 JSON 对象" }
        validate(value)
        val vaultId = canonicalUuid(value.getValue("vault_id").jsonPrimitive.content, "vault_id")
        require(expectedVaultId == null || vaultId == expectedVaultId) {
            "Vault Metadata vault_id 与 Block object_id 不一致"
        }
        return value
    }

    /** 只覆盖逻辑内容，不包含 Block 位置、nonce 或密文等物理属性。 */
    fun logicalDigest(metadata: JsonObject): ByteArray {
        val canonical = encode(metadata)
        return MessageDigest.getInstance("SHA-256").apply {
            update(DIGEST_DOMAIN)
            update(canonical)
        }.digest()
    }

    private fun validate(metadata: JsonObject) {
        require(metadata.keys.containsAll(REQUIRED_FIELDS)) { "Vault Metadata 缺少必需字段" }
        require(metadata["schema"]?.jsonPrimitive?.content == SCHEMA) { "Vault Metadata schema 无效" }
        val version = metadata["version"]?.jsonPrimitive
        require(version != null && !version.isString && version.longOrNull == VERSION.toLong()) {
            "Vault Metadata version 无效"
        }
        canonicalUuid(metadata.getValue("vault_id").jsonPrimitive.content, "vault_id")

        val entryIds = validateUuidArray(metadata.getValue("entry_order"), "entry_order")
        val trashIds = validateUuidArray(metadata.getValue("trash_order"), "trash_order")
        require(entryIds.intersect(trashIds).isEmpty()) { "entry_order 与 trash_order 不得重复" }

        val syncMeta = metadata.getValue("sync_meta").jsonObject
        val deviceId = syncMeta["device_id"]?.jsonPrimitive?.content
            ?: throw IllegalArgumentException("sync_meta.device_id 缺失")
        canonicalUuid(deviceId, "sync_meta.device_id")

        requireNonNegativeLong(metadata.getValue("key_revision"), "key_revision")
        metadata.getValue("export_epoch").let { value ->
            if (value !is JsonNull) requireNonNegativeNumber(value, "export_epoch")
        }
        metadata.getValue("purge_tombstones").jsonObject.forEach { (id, timestamp) ->
            canonicalUuid(id, "purge_tombstones key")
            requireNonNegativeNumber(timestamp, "purge_tombstones[$id]")
        }

        require(metadata.keys.none(FORBIDDEN_TOP_LEVEL::contains)) { "Vault Metadata 不得包含条目或媒体内容" }
        rejectSecretFields(metadata)
    }

    private fun validateUuidArray(value: JsonElement, name: String): Set<UUID> {
        val ids = value.jsonArray.mapIndexed { index, item ->
            canonicalUuid(item.jsonPrimitive.content, "$name[$index]")
        }
        require(ids.size == ids.toSet().size) { "$name 不得包含重复 UUID" }
        return ids.toSet()
    }

    private fun requireNonNegativeLong(value: JsonElement, name: String) {
        val primitive = value.jsonPrimitive
        val parsed = primitive.longOrNull
        require(!primitive.isString && parsed != null && parsed >= 0) { "$name 必须为 0..2^63-1 的整数" }
    }

    private fun requireNonNegativeNumber(value: JsonElement, name: String) {
        val primitive = value as? JsonPrimitive
            ?: throw IllegalArgumentException("$name 必须为有限数字")
        require(!primitive.isString) { "$name 必须为有限数字" }
        val number = runCatching { primitive.content.toBigDecimal() }.getOrNull()
        require(number != null && number.signum() >= 0) { "$name 必须为非负有限数字" }
    }

    private fun rejectSecretFields(value: JsonElement) {
        when (value) {
            is JsonObject -> value.forEach { (key, child) ->
                require(key !in FORBIDDEN_SECRET_FIELDS) { "Vault Metadata 不得包含秘密或媒体明文字段: $key" }
                rejectSecretFields(child)
            }
            is JsonArray -> value.forEach(::rejectSecretFields)
            else -> Unit
        }
    }

    private fun canonicalUuid(value: String, name: String): UUID {
        val parsed = try {
            UUID.fromString(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$name 必须为 UUID", error)
        }
        require(parsed.toString() == value) { "$name 必须使用规范小写 UUID 表示" }
        return parsed
    }
}
