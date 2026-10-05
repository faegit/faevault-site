package com.vault.passkeys

import com.vault.model.PasskeyRecord
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayOutputStream
import java.net.IDN
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Security
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.Base64
import java.util.UUID

object PasskeyAuthenticator {
    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_BE = 0x08
    private const val FLAG_BS = 0x10
    private const val FLAG_AT = 0x40

    private const val ES256 = -7
    private const val RS256 = -257
    private const val EDDSA = -8

    private val AAGUID = "fbfa2e4a-f3b0-4fa7-9e5d-a4b75819ef3f"
    private val AAGUID_BYTES: ByteArray by lazy {
        val uuid = UUID.fromString(AAGUID)
        ByteBuffer.allocate(16).apply { putLong(uuid.mostSignificantBits); putLong(uuid.leastSignificantBits) }.array()
    }

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    data class Created(val record: PasskeyRecord, val responseJson: String)
    data class Asserted(val record: PasskeyRecord, val responseJson: String)
    data class CreationRecord(
        val rpId: String,
        val rpName: String,
        val userId: String,
        val userName: String,
        val userDisplayName: String,
        val credentialId: String,
        val publicKey: String,
        val algorithm: Int,
        val createdAt: String,
        val aaguid: String,
    )

    fun create(
        requestJson: String,
        origin: String,
        userVerified: Boolean,
        clientDataHash: ByteArray? = null,
    ): Created {
        val algorithm = PasskeyRequests.parseCreate(requestJson).algorithm
        return SoftwarePasskeySigningKey.generate(algorithm).use { signingKey ->
            create(
                requestJson = requestJson,
                origin = origin,
                userVerified = userVerified,
                signingKey = signingKey,
                recordFactory = { seed ->
                    val privateKey = signingKey.exportPrivateKey()
                    val encodedPrivateKey = try {
                        encode(privateKey)
                    } finally {
                        privateKey.fill(0)
                    }
                    PasskeyRecord(
                        rpId = seed.rpId,
                        rpName = seed.rpName,
                        userId = seed.userId,
                        userName = seed.userName,
                        userDisplayName = seed.userDisplayName,
                        credentialId = seed.credentialId,
                        privateKey = encodedPrivateKey,
                        publicKey = seed.publicKey,
                        signCount = 0,
                        createdAt = seed.createdAt,
                        lastUsedAt = "",
                        transports = "internal",
                        algorithm = seed.algorithm,
                        schemaVersion = PasskeyRecord.LEGACY_SCHEMA_VERSION,
                        aaguid = seed.aaguid,
                        discoverable = true,
                        backupEligible = true,
                        backupState = true,
                    )
                },
                clientDataHash = clientDataHash,
            )
        }
    }

    fun create(
        requestJson: String,
        origin: String,
        userVerified: Boolean,
        signingKey: PasskeySigningKey,
        recordFactory: (CreationRecord) -> PasskeyRecord,
        clientDataHash: ByteArray? = null,
    ): Created {
        require(userVerified)
        require(clientDataHash == null || clientDataHash.size == 32)
        val request = PasskeyRequests.parseCreate(requestJson)
        val safeOrigin = validateOrigin(origin, request.rpId)
        // 特权浏览器（Chrome 等）只下发 clientDataHash：
        // 1. 签名必须覆盖该哈希（developer.android.com Credential Provider 指南明确要求）；
        // 2. 响应中的 clientDataJSON 只需结构完整（type/challenge/origin/crossOrigin），
        //    不要求与浏览器哈希一致——Chrome 会随机插入 GREASE 成员（见
        //    chromium client_data_json.md），第三方无法逐字节复现，最终交给 RP 的
        //    是 Chrome 自己保留的那份 JSON，其哈希恰为我们所签，两端自洽。
        //    注意不可退化为空占位符："{}" 会被 Chrome 解析拒绝导致注册被静默丢弃。
        val clientData = clientData("webauthn.create", encode(request.challenge), safeOrigin)

        val algorithm = request.algorithm
        require(signingKey.algorithm == algorithm)
        val cose = signingKey.publicKeyCose
        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val aaguidBytes = AAGUID_BYTES

        val now = Instant.now().toString()
        val record = recordFactory(
            CreationRecord(
                rpId = request.rpId,
                rpName = request.rpName,
                userId = encode(request.userId),
                userName = request.userName,
                userDisplayName = request.userDisplayName,
                credentialId = encode(credentialId),
                publicKey = encode(cose),
                algorithm = algorithm,
                createdAt = now,
                aaguid = AAGUID,
            ),
        )
        require(record.rpId == request.rpId && record.credentialId == encode(credentialId))
        require(record.publicKey == encode(cose) && record.algorithm == algorithm)
        if (record.schemaVersion == PasskeyRecord.CURRENT_SCHEMA_VERSION) {
            require(PasskeyRecord.parse(record.toJson()) != null) { "Passkey record factory returned an invalid record" }
        } else {
            require(record.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION)
        }

        val uvFlag = if (userVerified) FLAG_UV else 0
        val backupFlags = if (record.backupEligible) {
            FLAG_BE or if (record.backupState) FLAG_BS else 0
        } else {
            require(!record.backupState)
            0
        }
        val flags = FLAG_UP or uvFlag or backupFlags or FLAG_AT
        val authData = sha256(request.rpId.toByteArray()) + byteArrayOf(flags.toByte()) + uint32(0) +
            aaguidBytes + uint16(credentialId.size) + credentialId + cose
        // ── 两条互斥路径（勿合并回单一逻辑）──
        // Normal Flow：无系统哈希 → 签名覆盖 SHA256(自建 clientData)，返回的 JSON 必须与参与
        //   哈希的字节完全一致；
        // Privileged Browser Flow：系统已下发 clientDataHash → 直接签名该哈希，绝不重算；
        //   返回的 clientDataJSON 仅为结构完整的规范 JSON（Chrome 自留含 GREASE 的原始 JSON
        //   交给 RP，两者不必一致，也不可强校验一致）。
        val attestation = if (request.attestation == null || request.attestation == "none") {
            cborMap(linkedMapOf(
                "fmt" to "none",
                "attStmt" to emptyMap<String, Any>(),
                "authData" to authData,
            ))
        } else {
            val attestationToSign = authData + (clientDataHash ?: sha256(clientData))
            val attStmt = buildPackedSelfAttStmt(algorithm, signingKey, attestationToSign)
            requireDerSignature(algorithm, attStmt["sig"] as ByteArray)
            cborMap(linkedMapOf(
                "fmt" to "packed",
                "attStmt" to attStmt,
                "authData" to authData,
            ))
        }
        val response = buildJsonObject {
            put("id", record.credentialId); put("rawId", record.credentialId); put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", buildJsonObject {
                put("clientDataJSON", encode(clientData)); put("attestationObject", encode(attestation))
                put("authenticatorData", encode(authData))
                put("publicKey", encode(cosePublicKeyToSubjectPublicKeyInfo(algorithm, cose)))
                put("publicKeyAlgorithm", algorithm)
                put("transports", JsonArray(listOf(JsonPrimitive("internal"))))
            })
            put(
                "clientExtensionResults",
                if (request.credentialPropertiesRequested) {
                    buildJsonObject {
                        put("credProps", buildJsonObject { put("rk", true) })
                    }
                } else {
                    JsonObject(emptyMap())
                },
            )
        }
        return Created(record, response.toString())
    }

    fun get(
        requestJson: String,
        origin: String,
        source: PasskeyRecord,
        userVerified: Boolean,
        clientDataHash: ByteArray? = null,
    ): Asserted {
        require(source.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION)
        val privateKey = decode(source.privateKey)
        val publicCose = decode(source.publicKey)
        return try {
            SoftwarePasskeySigningKey.open(source.algorithm, privateKey, publicCose).use { signingKey ->
                get(requestJson, origin, source, userVerified, signingKey, clientDataHash)
            }
        } finally {
            privateKey.fill(0)
            publicCose.fill(0)
        }
    }

    fun get(
        requestJson: String,
        origin: String,
        source: PasskeyRecord,
        userVerified: Boolean,
        signingKey: PasskeySigningKey,
        clientDataHash: ByteArray? = null,
        localCounterStore: PasskeyLocalCounterStore = PasskeyLocalCounterStore.NoOp,
    ): Asserted {
        require(userVerified)
        require(clientDataHash == null || clientDataHash.size == 32)
        val request = PasskeyRequests.parseGet(requestJson)
        require(request.rpId == source.rpId)
        require(request.allowCredentialIds.isEmpty() || source.credentialId in request.allowCredentialIds)
        val safeOrigin = validateOrigin(origin, request.rpId)
        require(source.schemaVersion in PasskeyRecord.SUPPORTED_SCHEMA_VERSIONS)
        val clientData = clientData("webauthn.get", encode(request.challenge), safeOrigin)
        require(signingKey.algorithm == source.algorithm)
        require(MessageDigest.isEqual(signingKey.publicKeyCose, decode(source.publicKey)))

        // 设备绑定（DEVICE_BOUND）Passkey 的私钥不可导出、凭证不随保险库同步，因此使用设备本地的
        // 单调计数器（按 bindingId 持久化）。同步型（SYNCABLE）继续使用常量 0（synced_zero）。
        // 该计数值只进入 authenticatorData，绝不回写保险库的 signCount（解析强制要求为 0）。
        val authCount = if (source.keyMode == PasskeyKeyMode.DEVICE_BOUND) {
            val identity = requireNotNull(source.deviceBinding?.bindingId) {
                "DEVICE_BOUND passkey is missing deviceBinding"
            }
            localCounterStore.increment(identity)
        } else {
            0L
        }
        val backupFlags = if (source.backupEligible) {
            FLAG_BE or if (source.backupState) FLAG_BS else 0
        } else {
            require(!source.backupState)
            0
        }
        val uvFlag = if (userVerified) FLAG_UV else 0
        val flags = FLAG_UP or uvFlag or backupFlags
        val authData = sha256(request.rpId.toByteArray()) + byteArrayOf(flags.toByte()) + uint32(authCount)
        // 同 create()：Normal 用自建 JSON 的哈希；Privileged 直接签名系统下发的哈希
        val signedHash = clientDataHash ?: sha256(clientData)
        val signature = signingKey.sign(authData + signedHash)
        requireDerSignature(source.algorithm, signature)
        // 保险库内的 signCount 始终为 0（synced_zero，解析强制要求），本地真实计数仅体现在 authData 中。
        val updated = source.copy(signCount = 0L, lastUsedAt = Instant.now().toString())
        val response = buildJsonObject {
            put("id", source.credentialId); put("rawId", source.credentialId); put("type", "public-key")
            put("response", buildJsonObject {
                put("clientDataJSON", encode(clientData)); put("authenticatorData", encode(authData))
                put("signature", encode(signature)); put("userHandle", source.userId)
            })
            put("clientExtensionResults", JsonObject(emptyMap()))
        }
        return Asserted(updated, response.toString())
    }

    internal fun buildCosePublicKey(algorithm: Int, publicKey: java.security.PublicKey): ByteArray = when (algorithm) {
        ES256 -> {
            val ecKey = publicKey as ECPublicKey
            val x = unsigned32(ecKey.w.affineX.toByteArray())
            val y = unsigned32(ecKey.w.affineY.toByteArray())
            cborMap(linkedMapOf(1 to 2, 3 to -7, -1 to 1, -2 to x, -3 to y))
        }
        RS256 -> {
            val rsaKey = publicKey as java.security.interfaces.RSAPublicKey
            val modulus = unsignedBytes(rsaKey.modulus.toByteArray())
            val exponent = unsignedBytes(rsaKey.publicExponent.toByteArray())
            // RFC 8230：-1=n、-2=e 均为最短无符号大端字节串
            // （2048-bit n 通常 256B；e=65537 必须是 3 字节 01 00 01，不得定长填充）
            cborMap(linkedMapOf(1 to 3, 3 to -257, -1 to modulus, -2 to exponent))
        }
        EDDSA -> {
            val spki = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(publicKey.encoded)
            val x = spki.publicKeyData.octets
            cborMap(linkedMapOf(1 to 1, 3 to -8, -1 to 6, -2 to x))
        }
        else -> error("Unsupported algorithm: $algorithm")
    }

    private fun buildPackedSelfAttStmt(
        algorithm: Int,
        signingKey: PasskeySigningKey,
        data: ByteArray,
    ): Map<*, *> = linkedMapOf("alg" to algorithm, "sig" to signingKey.sign(data))

    /**
     * ES256 签名格式自检：WebAuthn 要求 ASN.1 DER——首字节必须是 SEQUENCE 标签 0x30，
     * 长度在 64..72 区间（r/s 的 INTEGER 编码长度可变，不能写死 70）。
     * 若看到固定 64 字节即说明被错误转换为 P1363(r||s)，RP 验签必败。
     */
    private fun requireDerSignature(algorithm: Int, signature: ByteArray) {
        if (algorithm != ES256) return
        require(signature.size in 64..72 && signature.first() == 0x30.toByte()) {
            "ES256 signature is not ASN.1 DER (len=${signature.size}, head=${signature.first()})"
        }
    }

    private fun validateOrigin(origin: String, rpId: String): String {
        if (ANDROID_ORIGIN.matches(origin)) return origin
        val uri = URI(origin)
        require(
            uri.scheme == "https" &&
                uri.userInfo == null &&
                uri.query == null &&
                uri.fragment == null &&
                (uri.path.isNullOrEmpty() || uri.path == "/"),
        )
        val host = uri.host?.let {
            IDN.toASCII(it.lowercase().trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
        } ?: error("missing origin host")
        require(host == rpId || host.endsWith(".$rpId"))
        return "https://$host" + if (uri.port > 0 && uri.port != 443) ":${uri.port}" else ""
    }

    private fun clientData(type: String, challenge: String, origin: String): ByteArray = buildJsonObject {
        put("type", type); put("challenge", challenge); put("origin", origin); put("crossOrigin", false)
    }.toString().toByteArray()

    private fun encode(value: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value.padEnd((value.length + 3) / 4 * 4, '='))
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun unsigned32(value: ByteArray): ByteArray = value.takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
    /** 最短无符号大端表示：仅去除 BigInteger 符号位补的 0x00，不做定长填充（零 → 单字节 0x00）。 */
    private fun unsignedBytes(value: ByteArray): ByteArray {
        val stripped = value.dropWhile { it == 0.toByte() }.toByteArray()
        return if (stripped.isEmpty()) byteArrayOf(0) else stripped
    }
    private fun uint16(value: Int) = byteArrayOf((value ushr 8).toByte(), value.toByte())
    private fun uint32(value: Long) = byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

    private fun cborMap(value: Map<*, *>): ByteArray = ByteArrayOutputStream().also { out ->
        head(out, 5, value.size.toLong()); value.forEach { (k, v) -> cbor(out, k); cbor(out, v) }
    }.toByteArray()

    private fun cbor(out: ByteArrayOutputStream, value: Any?) { when (value) {
        is Int -> if (value >= 0) head(out, 0, value.toLong()) else head(out, 1, (-1L - value))
        is Long -> if (value >= 0) head(out, 0, value) else head(out, 1, (-1L - value))
        is String -> value.toByteArray().also { head(out, 3, it.size.toLong()); out.write(it) }
        is ByteArray -> { head(out, 2, value.size.toLong()); out.write(value) }
        is Map<*, *> -> { head(out, 5, value.size.toLong()); value.forEach { (k, v) -> cbor(out, k); cbor(out, v) } }
        else -> error("unsupported CBOR value")
    } }

    private fun head(out: ByteArrayOutputStream, major: Int, size: Long) { when {
        size < 24 -> out.write((major shl 5) or size.toInt())
        size <= 0xff -> { out.write((major shl 5) or 24); out.write(size.toInt()) }
        size <= 0xffff -> { out.write((major shl 5) or 25); out.write(uint16(size.toInt())) }
        else -> { out.write((major shl 5) or 26); out.write(uint32(size)) }
    } }

    private val ANDROID_ORIGIN = Regex("^android:apk-key-hash:[A-Za-z0-9_-]{43}$")
}
