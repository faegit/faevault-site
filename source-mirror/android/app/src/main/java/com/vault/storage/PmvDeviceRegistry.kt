package com.vault.storage

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64
import java.util.UUID

/**
 * PMVE 元数据内的设备授权清单。
 *
 * 清单保存在保险库签名提交的元数据中（字段 `device_authorizations`），每条记录是
 * [PmvSyncAuthorization.encodeAuthorization] 的 256 字节 canonical 编码（base64）。
 * 任何能解锁保险库的设备都能用 Vault 签名密钥签发/撤销授权；同步对端只信任
 * Vault 公钥验证过的记录，并强制“认证先于数据”。
 */
object PmvDeviceRegistry {
    const val METADATA_FIELD = "device_authorizations"

    fun encode(records: List<PmvSyncAuthorization.DeviceAuthorization>): JsonArray = JsonArray(
        records.sortedWith(compareBy({ it.deviceId.toString() }, { it.epoch })).map { record ->
            JsonPrimitive(
                Base64.getEncoder().encodeToString(PmvSyncAuthorization.encodeAuthorization(record)),
            )
        },
    )

    fun decode(metadata: JsonObject): List<PmvSyncAuthorization.DeviceAuthorization> {
        val raw = metadata[METADATA_FIELD] ?: return emptyList()
        val values = raw as? JsonArray ?: throw IllegalArgumentException(
            "device_authorizations 必须为数组",
        )
        val records = values.mapIndexed { index, value ->
            val encoded = (value as? JsonPrimitive)?.content
                ?: throw IllegalArgumentException("device_authorizations[$index] 不是字符串")
            val bytes = try {
                Base64.getDecoder().decode(encoded)
            } catch (error: IllegalArgumentException) {
                throw IllegalArgumentException("device_authorizations[$index] base64 无效", error)
            }
            PmvSyncAuthorization.decodeAuthorization(bytes)
        }
        val byDevice = linkedMapOf<UUID, PmvSyncAuthorization.DeviceAuthorization>()
        var previousDevice: UUID? = null
        var previousEpoch = -1L
        records.forEach { record ->
            val device = record.deviceId
            if (previousDevice != null) {
                require(previousDevice == device || previousDevice.toString() < device.toString()) {
                    "device_authorizations 顺序非 canonical"
                }
                require(previousDevice != device || record.epoch > previousEpoch) {
                    "device_authorizations 中设备 epoch 未单调递增"
                }
            }
            previousDevice = device
            previousEpoch = record.epoch
            val current = byDevice[device]
            require(current == null || record.epoch > current.epoch) {
                "device_authorizations 中设备 epoch 未单调递增"
            }
            byDevice[device] = record
        }
        return byDevice.values.toList()
    }

    /** 校验清单每条都由受信 Vault 公钥签名；返回可直接供 [PmvSyncAuthorization.AuthorizationRegistry] 安装的记录。 */
    fun verifyAll(records: List<PmvSyncAuthorization.DeviceAuthorization>, vaultPublicKey: ByteArray): List<PmvSyncAuthorization.DeviceAuthorization> {
        records.forEach { record ->
            require(PmvSyncAuthorization.verifyAuthorization(record, vaultPublicKey)) {
                "Device authorization 不是由受信 Vault 签名: ${record.deviceId}"
            }
        }
        return records
    }

    fun withRegistry(metadata: JsonObject, records: List<PmvSyncAuthorization.DeviceAuthorization>): JsonObject {
        val updated = metadata.toMutableMap()
        if (records.isEmpty()) {
            updated.remove(METADATA_FIELD)
        } else {
            updated[METADATA_FIELD] = encode(records)
        }
        return JsonObject(updated)
    }

    fun latest(records: List<PmvSyncAuthorization.DeviceAuthorization>, deviceId: UUID): PmvSyncAuthorization.DeviceAuthorization? =
        records.filter { it.deviceId == deviceId }.maxByOrNull { it.epoch }
}
