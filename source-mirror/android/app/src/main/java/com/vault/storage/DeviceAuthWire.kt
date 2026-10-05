package com.vault.storage

import com.vault.security.VaultDeviceIdentity
import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/**
 * 局域网同步/导出通道的设备授权握手（SPAKE2 配对之后、任何敏感数据之前）。
 *
 * 线格式（Android 与 PC 共享）：
 *   POST /api/auth/challenge
 *     {"v":1,"clientNonce":"<b64 32B>","deviceId":"<uuid>","vaultId":"<uuid>",
 *      "op":"read|write|authorize","requestedCommitId":"<uuid|null>","requestDigest":"<b64|null>"}
 *     → 200 {"v":1,"challenge":"<b64 256B>"}
 *   POST /api/auth/challenge/confirm
 *     {"v":1,"challenge":"<b64 256B>","signature":"<b64 64B>"}
 *     → 200 {"v":1}
 */
object DeviceAuthWire {
    const val PROTOCOL_VERSION = 1
    private val ZERO_UUID = UUID(0L, 0L)

    data class ChallengeRequest(
        val clientNonce: ByteArray,
        val deviceId: UUID,
        val devicePublicKey: ByteArray,
        val vaultId: UUID,
        val operation: PmvSyncAuthorization.Operation,
        val requestedCommitId: UUID?,
        val requestDigest: ByteArray,
    )

    data class ConfirmRequest(
        val challenge: ByteArray,
        val signature: ByteArray,
    )

    fun parseChallengeRequest(body: String): ChallengeRequest {
        val json = JSONObject(body)
        require(json.optInt("v", -1) == PROTOCOL_VERSION) { "设备认证协议版本无效" }
        val clientNonce = decodeB64(json.getString("clientNonce"), 32, "clientNonce")
        val deviceId = parseUuid(json.getString("deviceId"), "deviceId")
        val devicePublicKey = decodeB64(json.getString("devicePublicKey"), 32, "devicePublicKey")
        val vaultId = parseUuid(json.getString("vaultId"), "vaultId")
        val operation = parseOperation(json.getString("op"))
        val requestedCommit = json.optString("requestedCommitId").takeIf { it.isNotBlank() && it != "null" }
            ?.let { parseUuid(it, "requestedCommitId") }
        val digestText = json.optString("requestDigest")
        val requestDigest = if (digestText.isBlank() || digestText == "null") ByteArray(32) else {
            decodeB64(digestText, 32, "requestDigest")
        }
        return ChallengeRequest(clientNonce, deviceId, devicePublicKey, vaultId, operation, requestedCommit, requestDigest)
    }

    fun challengeResponse(challenge: ByteArray): String = JSONObject()
        .put("v", PROTOCOL_VERSION)
        .put("challenge", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge))
        .toString()

    fun parseConfirmRequest(body: String): ConfirmRequest {
        val json = JSONObject(body)
        require(json.optInt("v", -1) == PROTOCOL_VERSION) { "设备认证协议版本无效" }
        return ConfirmRequest(
            challenge = decodeB64(json.getString("challenge"), PmvSyncAuthorization.CHALLENGE_SIZE, "challenge"),
            signature = decodeB64(json.getString("signature"), 64, "signature"),
        )
    }

    fun confirmResponse(): String = JSONObject().put("v", PROTOCOL_VERSION).toString()

    /** 客户端：用设备私钥对服务器 challenge 签名。 */
    fun signChallenge(challenge: ByteArray, identity: VaultDeviceIdentity): ByteArray {
        val decoded = PmvSyncAuthorization.decodeChallenge(challenge)
        require(decoded.deviceId == identity.deviceId) { "Challenge 绑定了其他设备" }
        return identity.withPrivateSeed { seed -> PmvSyncAuthorization.signChallenge(decoded, seed) }
    }

    /** 服务端：每个连接一个门，challenge 一次性、过期、绑定操作/库/设备。 */
    class ServerGate(private val registry: PmvSyncAuthorization.AuthorizationRegistry) {
        @Volatile
        var authorizedDeviceId: UUID? = null
            private set

        @Synchronized
        fun issue(
            request: ChallengeRequest,
            nowMillis: Long = System.currentTimeMillis(),
        ): ByteArray {
            // 导出通道客户端在首次拉库前不知道 vault_id，允许以零 UUID 占位，
            // 服务端用真实 vault_id 签发 challenge（客户端只签名服务端返回的 challenge）。
            val vaultId = if (request.vaultId == ZERO_UUID) registry.vaultId else request.vaultId
            require(vaultId == registry.vaultId) { "Challenge 不属于本保险库" }
            val challenge = registry.issue(
                deviceId = request.deviceId,
                operation = request.operation,
                clientNonce = request.clientNonce,
                requestedCommitId = request.requestedCommitId,
                requestDigest = request.requestDigest,
                nowMillis = nowMillis,
            )
            return PmvSyncAuthorization.encodeChallenge(challenge)
        }

        @Synchronized
        fun confirm(
            encoded: ByteArray,
            signature: ByteArray,
            nowMillis: Long = System.currentTimeMillis(),
        ) {
            val challenge = PmvSyncAuthorization.decodeChallenge(encoded)
            registry.consume(challenge, signature, nowMillis)
            authorizedDeviceId = challenge.deviceId
        }

        fun requireAuthorized(): UUID =
            authorizedDeviceId ?: throw IllegalStateException("设备尚未完成授权认证")
    }

    private fun decodeB64(raw: String, size: Int, name: String): ByteArray {
        val padded = raw + "=".repeat((4 - raw.length % 4) % 4)
        val decoded = try {
            Base64.getUrlDecoder().decode(padded)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$name base64 无效", error)
        }
        require(decoded.size == size) { "$name 长度必须为 $size 字节" }
        return decoded
    }

    private fun parseUuid(raw: String, name: String): UUID {
        val value = try {
            UUID.fromString(raw)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("$name 无效", error)
        }
        require(value.toString() == raw) { "$name 必须为 canonical UUID" }
        return value
    }

    private fun parseOperation(raw: String): PmvSyncAuthorization.Operation = when (raw) {
        "read" -> PmvSyncAuthorization.Operation.READ
        "write" -> PmvSyncAuthorization.Operation.WRITE
        "authorize" -> PmvSyncAuthorization.Operation.AUTHORIZE
        else -> throw IllegalArgumentException("设备认证操作无效")
    }
}
