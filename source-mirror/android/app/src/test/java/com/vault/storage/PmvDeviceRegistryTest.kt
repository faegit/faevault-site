package com.vault.storage

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/** PMVE 元数据设备授权清单：签名校验、epoch 单调、round-trip。 */
class PmvDeviceRegistryTest {
    private val vaultSeed = ByteArray(32) { (it * 3 + 1).toByte() }
    private val vaultPublicKey = Ed25519PrivateKeyParameters(vaultSeed, 0).generatePublicKey().encoded

    private fun record(
        deviceId: UUID,
        epoch: Long,
        revokedAt: Long = 0L,
        permissions: Int = PmvSyncAuthorization.PERMISSION_READ or
            PmvSyncAuthorization.PERMISSION_WRITE or PmvSyncAuthorization.PERMISSION_AUTHORIZE,
    ) = PmvSyncAuthorization.signAuthorization(
        PmvSyncAuthorization.DeviceAuthorization(
            vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
            deviceId = deviceId,
            devicePublicKey = ByteArray(32) { (it * 7 + deviceId.hashCode()).toByte() },
            permissions = permissions,
            issuedAtEpochMillis = 1000L,
            expiresAtEpochMillis = 0L,
            revokedAtEpochMillis = revokedAt,
            epoch = epoch,
        ),
        vaultSeed,
    )

    @Test
    fun `registry round-trips through metadata and preserves unknown fields`() {
        val metadata = buildJsonObject {
            put("schema", JsonPrimitive("pmv-vault-metadata"))
            put("future_field", JsonPrimitive("kept"))
        }
        val records = listOf(record(UUID.randomUUID(), 1), record(UUID.randomUUID(), 2))
        val updated = PmvDeviceRegistry.withRegistry(metadata, records)
        assertEquals("kept", updated["future_field"]?.let { (it as JsonPrimitive).content })
        assertEquals(records.size, updated[PmvDeviceRegistry.METADATA_FIELD]?.let {
            (it as kotlinx.serialization.json.JsonArray).size
        })
        val decoded = PmvDeviceRegistry.decode(updated)
        assertEquals(records.size, decoded.size)
        PmvDeviceRegistry.verifyAll(decoded, vaultPublicKey)
    }

    @Test
    fun `signature verification rejects records not signed by the vault`() {
        val forged = record(UUID.randomUUID(), 1).copy(signature = ByteArray(64))
        assertThrows(IllegalArgumentException::class.java) {
            PmvDeviceRegistry.verifyAll(listOf(forged), vaultPublicKey)
        }
    }

    @Test
    fun `epoch must be monotonic per device and latest wins`() {
        val device = UUID.randomUUID()
        val old = record(device, 1)
        val newer = record(device, 2, revokedAt = 5000L)
        val metadata = PmvDeviceRegistry.withRegistry(JsonObject(emptyMap()), listOf(old, newer))
        val decoded = PmvDeviceRegistry.decode(metadata)
        assertEquals(1, decoded.size)
        assertEquals(2L, decoded.single().epoch)
        assertTrue(decoded.single().revokedAtEpochMillis == 5000L)
        // 规范化编码会重排记录；手工构造乱序元数据时解码必须失败关闭。
        assertThrows(IllegalArgumentException::class.java) {
            PmvDeviceRegistry.decode(
                buildJsonObject {
                    put(
                        PmvDeviceRegistry.METADATA_FIELD,
                        kotlinx.serialization.json.JsonArray(
                            listOf(
                                JsonPrimitive(java.util.Base64.getEncoder().encodeToString(
                                    PmvSyncAuthorization.encodeAuthorization(newer),
                                )),
                                JsonPrimitive(java.util.Base64.getEncoder().encodeToString(
                                    PmvSyncAuthorization.encodeAuthorization(old),
                                )),
                            ),
                        ),
                    )
                },
            )
        }
    }

    @Test
    fun `invalid base64 and unknown field types fail closed`() {
        assertThrows(IllegalArgumentException::class.java) {
            PmvDeviceRegistry.decode(
                buildJsonObject { put(PmvDeviceRegistry.METADATA_FIELD, JsonPrimitive("not-array")) },
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvDeviceRegistry.decode(
                buildJsonObject {
                    put(PmvDeviceRegistry.METADATA_FIELD, kotlinx.serialization.json.JsonArray(listOf(JsonPrimitive("!!!"))))
                },
            )
        }
        assertTrue(PmvDeviceRegistry.decode(JsonObject(emptyMap())).isEmpty())
    }
}
