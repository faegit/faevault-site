package com.vault.storage

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/** Vault-signed device authorization plus replay-safe operation-bound challenges. */
object PmvSyncAuthorization {
    const val AUTH_SIZE = 256
    const val CHALLENGE_SIZE = 256
    const val PERMISSION_READ = 1
    const val PERMISSION_WRITE = 2
    const val PERMISSION_AUTHORIZE = 4

    /** Only these bits map to a real operation; anything else is inert. */
    const val DEFINED_PERMISSION_MASK = PERMISSION_READ or PERMISSION_WRITE or PERMISSION_AUTHORIZE
    private val AUTH_DOMAIN = "pmv/v1/device-authorization\u0000".encodeToByteArray()
    private val CHALLENGE_DOMAIN = "pmv/v1/device-challenge\u0000".encodeToByteArray()
    private val ZERO_UUID = UUID(0, 0)

    enum class Operation(val id: Int, val permission: Int) {
        READ(1, PERMISSION_READ), WRITE(2, PERMISSION_WRITE), AUTHORIZE(3, PERMISSION_AUTHORIZE);
        companion object {
            fun fromId(value: Int) = entries.firstOrNull { it.id == value }
                ?: throw IllegalArgumentException("Device challenge operation 无效")
        }
    }

    data class DeviceAuthorization(
        val vaultId: UUID,
        val deviceId: UUID,
        val devicePublicKey: ByteArray,
        val permissions: Int,
        val issuedAtEpochMillis: Long,
        val expiresAtEpochMillis: Long,
        val revokedAtEpochMillis: Long,
        val epoch: Long,
        val signature: ByteArray = ByteArray(64),
    ) {
        init {
            require(devicePublicKey.size == 32) { "Device public key 必须为 32 字节" }
            require(permissions > 0) { "Device permissions 无效" }
            require(grantedPermissions != 0) { "Device authorization 未授予任何已定义权限" }
            require(listOf(issuedAtEpochMillis, expiresAtEpochMillis, revokedAtEpochMillis, epoch).all { it >= 0 })
            require(expiresAtEpochMillis == 0L || expiresAtEpochMillis >= issuedAtEpochMillis)
            require(revokedAtEpochMillis == 0L || revokedAtEpochMillis >= issuedAtEpochMillis)
            require(signature.size == 64) { "Device authorization signature 必须为 64 字节" }
        }

        fun activeAt(nowMillis: Long): Boolean {
            require(nowMillis >= 0)
            return revokedAtEpochMillis == 0L && (expiresAtEpochMillis == 0L || nowMillis <= expiresAtEpochMillis)
        }

        /**
         * Only the permission bits that map to a real operation.
         *
         * [permissions] keeps the exact value found on the wire so that encoding a decoded
         * record reproduces the original bytes and its signature keeps verifying. Records
         * written by codecs that accepted undefined bits therefore stay readable forever:
         * the bits survive the round-trip and remain covered by the signature, but they can
         * never grant an operation, because every authorization decision reads this
         * projection instead.
         */
        val grantedPermissions: Int get() = permissions and DEFINED_PERMISSION_MASK

        fun allows(operation: Operation): Boolean = grantedPermissions and operation.permission != 0

        override fun equals(other: Any?): Boolean = other is DeviceAuthorization &&
            vaultId == other.vaultId && deviceId == other.deviceId &&
            devicePublicKey.contentEquals(other.devicePublicKey) && permissions == other.permissions &&
            issuedAtEpochMillis == other.issuedAtEpochMillis && expiresAtEpochMillis == other.expiresAtEpochMillis &&
            revokedAtEpochMillis == other.revokedAtEpochMillis && epoch == other.epoch &&
            signature.contentEquals(other.signature)

        override fun hashCode(): Int = deviceId.hashCode() * 31 + epoch.hashCode()
    }

    fun authorizationSigningBytes(value: DeviceAuthorization): ByteArray =
        AUTH_DOMAIN + authorizationPrefix(value)

    fun signAuthorization(value: DeviceAuthorization, vaultPrivateSeed: ByteArray): DeviceAuthorization {
        require(vaultPrivateSeed.size == 32) { "Vault private seed 必须为 32 字节" }
        val signer = Ed25519Signer().apply { init(true, Ed25519PrivateKeyParameters(vaultPrivateSeed, 0)) }
        val bytes = authorizationSigningBytes(value)
        return try {
            signer.update(bytes, 0, bytes.size)
            value.copy(signature = signer.generateSignature())
        } finally {
            bytes.fill(0)
        }
    }

    fun verifyAuthorization(value: DeviceAuthorization, trustedVaultPublicKey: ByteArray): Boolean {
        if (trustedVaultPublicKey.size != 32) return false
        val bytes = authorizationSigningBytes(value)
        return try {
            Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(trustedVaultPublicKey, 0))
                update(bytes, 0, bytes.size)
                verifySignature(value.signature)
            }
        } catch (_: Exception) {
            false
        } finally {
            bytes.fill(0)
        }
    }

    fun encodeAuthorization(value: DeviceAuthorization): ByteArray = ByteBuffer.allocate(AUTH_SIZE)
        .order(ByteOrder.BIG_ENDIAN).apply {
            put(authorizationPrefix(value))
            put(value.signature)
        }.array()

    fun decodeAuthorization(raw: ByteArray): DeviceAuthorization {
        require(raw.size == AUTH_SIZE) { "Device authorization 大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals("PMDA".encodeToByteArray()))
        require(input.int == 1 && input.int == AUTH_SIZE)
        val value = DeviceAuthorization(
            input.uuid(), input.uuid(), ByteArray(32).also(input::get), input.int,
            input.long, input.long, input.long, input.long, ByteArray(64).also(input::get),
        )
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "Device authorization 保留字段非零" }
        return value
    }

    data class Challenge(
        val vaultId: UUID,
        val deviceId: UUID,
        val serverNonce: ByteArray,
        val clientNonce: ByteArray,
        val operation: Operation,
        val requestedCommitId: UUID?,
        val requestDigest: ByteArray,
        val sessionId: UUID,
        val expiresAtEpochMillis: Long,
    ) {
        init {
            require(serverNonce.size == 32 && clientNonce.size == 32)
            require(requestDigest.size == 32)
            require(expiresAtEpochMillis >= 0)
        }

        override fun equals(other: Any?): Boolean = other is Challenge &&
            vaultId == other.vaultId && deviceId == other.deviceId &&
            serverNonce.contentEquals(other.serverNonce) && clientNonce.contentEquals(other.clientNonce) &&
            operation == other.operation && requestedCommitId == other.requestedCommitId &&
            requestDigest.contentEquals(other.requestDigest) && sessionId == other.sessionId &&
            expiresAtEpochMillis == other.expiresAtEpochMillis

        override fun hashCode(): Int = sessionId.hashCode()
    }

    fun encodeChallenge(value: Challenge): ByteArray = ByteBuffer.allocate(CHALLENGE_SIZE)
        .order(ByteOrder.BIG_ENDIAN).apply {
            put("PMCH".encodeToByteArray()); putInt(1); putInt(CHALLENGE_SIZE)
            putUuid(value.vaultId); putUuid(value.deviceId)
            put(value.serverNonce); put(value.clientNonce); put(value.operation.id.toByte()); put(ByteArray(7))
            putUuid(value.requestedCommitId ?: ZERO_UUID); put(value.requestDigest); putUuid(value.sessionId)
            putLong(value.expiresAtEpochMillis)
        }.array()

    fun decodeChallenge(raw: ByteArray): Challenge {
        require(raw.size == CHALLENGE_SIZE) { "Device challenge 大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals("PMCH".encodeToByteArray()))
        require(input.int == 1 && input.int == CHALLENGE_SIZE)
        val vaultId = input.uuid(); val deviceId = input.uuid()
        val serverNonce = ByteArray(32).also(input::get); val clientNonce = ByteArray(32).also(input::get)
        val operation = Operation.fromId(input.get().toInt() and 0xff)
        repeat(7) { require(input.get() == 0.toByte()) }
        val commit = input.uuid()
        val result = Challenge(
            vaultId, deviceId, serverNonce, clientNonce, operation,
            commit.takeUnless { it == ZERO_UUID }, ByteArray(32).also(input::get), input.uuid(), input.long,
        )
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "Device challenge 保留字段非零" }
        return result
    }

    fun challengeSigningBytes(value: Challenge): ByteArray = CHALLENGE_DOMAIN + encodeChallenge(value)

    fun signChallenge(value: Challenge, devicePrivateSeed: ByteArray): ByteArray {
        require(devicePrivateSeed.size == 32)
        val bytes = challengeSigningBytes(value)
        return try {
            Ed25519Signer().run {
                init(true, Ed25519PrivateKeyParameters(devicePrivateSeed, 0))
                update(bytes, 0, bytes.size)
                generateSignature()
            }
        } finally {
            bytes.fill(0)
        }
    }

    fun verifyChallenge(value: Challenge, signature: ByteArray, devicePublicKey: ByteArray): Boolean {
        if (signature.size != 64 || devicePublicKey.size != 32) return false
        val bytes = challengeSigningBytes(value)
        return try {
            Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(devicePublicKey, 0))
                update(bytes, 0, bytes.size)
                verifySignature(signature)
            }
        } catch (_: Exception) {
            false
        } finally {
            bytes.fill(0)
        }
    }

    class AuthorizationRegistry(
        val vaultId: UUID,
        trustedVaultPublicKey: ByteArray,
        private val random: SecureRandom = SecureRandom(),
    ) {
        private val trustedKey = trustedVaultPublicKey.copyOf().also { require(it.size == 32) }
        private val authorizations = HashMap<UUID, DeviceAuthorization>()
        private val transientGrants = HashMap<UUID, DeviceAuthorization>()
        private val pending = HashMap<UUID, Challenge>()

        /**
         * Installs a vault-signed authorization record.
         *
         * Persistent and transient grants keep **separate epoch namespaces**. A transient
         * grant is minted with `epoch = nowMillis` so that it looks recent, but that value
         * is ~10^12 while persistent epochs are a small counter; sharing one sequence
         * would make every transient grant permanently outrank — and therefore block —
         * each later persistent grant for the same device. Ordering is therefore only
         * enforced among persistent records, and a transient record's epoch carries no
         * ordering meaning at all.
         *
         * Both namespaces are still verified against the vault key individually, and a
         * device is authorized when *either* namespace grants the operation, so separating
         * them can never authorize more than the vault itself signed.
         */
        @Synchronized
        fun install(value: DeviceAuthorization, transient: Boolean = false) {
            require(value.vaultId == vaultId && verifyAuthorization(value, trustedKey)) {
                "Device authorization 不是由受信 Vault 签名"
            }
            if (transient) {
                transientGrants[value.deviceId] = value.snapshot()
                return
            }
            val current = authorizations[value.deviceId]
            require(current == null || value.epoch > current.epoch) { "Device authorization epoch 已过期" }
            authorizations[value.deviceId] = value.snapshot()
        }

        /**
         * The record that authorizes [operation] right now, or `null`.
         *
         * Transient grants are checked first: they are the narrower, session-scoped intent
         * behind an export/transfer approval. Callers must verify a device signature against
         * the returned record's own public key.
         */
        /**
         * 该设备当前生效的授权记录，没有则为 null。
         *
         * 供传输站界面取公钥来显示可核对的指纹。必须是**签名记录里**那把公钥，不能用
         * 客户端在挑战请求里自报的那把——否则对端可以显示任意内容冒充身份。
         * 与 granting 一样，瞬时记录优先：它才是导出/互传批准背后的会话级意图。
         */
        @Synchronized
        fun activeAuthorization(
            deviceId: UUID,
            nowMillis: Long = System.currentTimeMillis(),
        ): DeviceAuthorization? {
            pruneTransient(nowMillis)
            transientGrants[deviceId]?.let { if (it.activeAt(nowMillis)) return it.snapshot() }
            authorizations[deviceId]?.let { if (it.activeAt(nowMillis)) return it.snapshot() }
            return null
        }

        private fun granting(deviceId: UUID, operation: Operation, nowMillis: Long): DeviceAuthorization? {
            transientGrants[deviceId]?.let {
                if (it.activeAt(nowMillis) && it.allows(operation)) return it
            }
            authorizations[deviceId]?.let {
                if (it.activeAt(nowMillis) && it.allows(operation)) return it
            }
            return null
        }

        private fun pruneTransient(nowMillis: Long) {
            transientGrants.entries.removeAll { !it.value.activeAt(nowMillis) }
        }

        @Synchronized
        fun issue(
            deviceId: UUID,
            operation: Operation,
            clientNonce: ByteArray,
            requestedCommitId: UUID? = null,
            requestDigest: ByteArray = ByteArray(32),
            nowMillis: Long = System.currentTimeMillis(),
            ttlMillis: Long = 30_000,
        ): Challenge {
            require(nowMillis >= 0 && ttlMillis in 1..300_000)
            require(clientNonce.size == NONCE_SIZE) { "Client nonce 必须为 32 字节" }
            require(requestDigest.size == DIGEST_SIZE) { "Request digest 必须为 32 字节" }
            pruneTransient(nowMillis)
            requireNotNull(granting(deviceId, operation, nowMillis)) { "Device 未授权或权限不足" }
            pending.entries.removeAll { it.value.expiresAtEpochMillis < nowMillis }
            require(pending.size < MAX_PENDING_CHALLENGES) { "待确认的设备请求过多，请稍后重试" }
            val challenge = Challenge(
                vaultId, deviceId, ByteArray(NONCE_SIZE).also(random::nextBytes), clientNonce.copyOf(), operation,
                requestedCommitId, requestDigest.copyOf(), UUID.randomUUID(), Math.addExact(nowMillis, ttlMillis),
            )
            pending[challenge.sessionId] = challenge.snapshot()
            return challenge.snapshot()
        }

        @Synchronized
        fun consume(value: Challenge, signature: ByteArray, nowMillis: Long = System.currentTimeMillis()) {
            require(nowMillis >= 0) { "当前时间无效" }
            val expected = pending.remove(value.sessionId)
            require(expected == value) { "Device challenge 未知或已经使用" }
            require(nowMillis <= value.expiresAtEpochMillis) { "Device challenge 已过期" }
            val authorization = requireNotNull(granting(value.deviceId, value.operation, nowMillis)) {
                "Device 已撤销或权限不足"
            }
            require(verifyChallenge(value, signature, authorization.devicePublicKey)) { "Device challenge 签名无效" }
        }

        private companion object {
            const val NONCE_SIZE = 32
            const val DIGEST_SIZE = 32
            const val MAX_PENDING_CHALLENGES = 1_024
        }

        private fun DeviceAuthorization.snapshot(): DeviceAuthorization = copy(
            devicePublicKey = devicePublicKey.copyOf(),
            signature = signature.copyOf(),
        )

        private fun Challenge.snapshot(): Challenge = copy(
            serverNonce = serverNonce.copyOf(),
            clientNonce = clientNonce.copyOf(),
            requestDigest = requestDigest.copyOf(),
        )

        /** 连接级鉴权查询：设备已授权、未撤销且具备操作权限。 */
        @Synchronized
        fun isAuthorized(
            deviceId: UUID,
            operation: Operation,
            nowMillis: Long = System.currentTimeMillis(),
        ): Boolean = granting(deviceId, operation, nowMillis) != null
    }

    private fun authorizationPrefix(value: DeviceAuthorization): ByteArray = ByteBuffer.allocate(112)
        .order(ByteOrder.BIG_ENDIAN).apply {
            put("PMDA".encodeToByteArray()); putInt(1); putInt(AUTH_SIZE)
            putUuid(value.vaultId); putUuid(value.deviceId); put(value.devicePublicKey); putInt(value.permissions)
            putLong(value.issuedAtEpochMillis); putLong(value.expiresAtEpochMillis)
            putLong(value.revokedAtEpochMillis); putLong(value.epoch)
        }.array()

    private fun ByteBuffer.putUuid(value: UUID) { putLong(value.mostSignificantBits); putLong(value.leastSignificantBits) }
    private fun ByteBuffer.uuid(): UUID = UUID(long, long)
}
