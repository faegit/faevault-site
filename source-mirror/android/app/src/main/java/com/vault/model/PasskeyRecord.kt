package com.vault.model

import com.vault.passkeys.PasskeyDeviceBinding
import com.vault.passkeys.PasskeyKeyMode
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.net.IDN
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.UUID

data class PasskeyRecord(
    val rpId: String,
    val rpName: String,
    val userId: String,
    val userName: String,
    val userDisplayName: String,
    val credentialId: String,
    val privateKey: String,
    val publicKey: String,
    val signCount: Long,
    val createdAt: String,
    val lastUsedAt: String,
    val transports: String,
    val algorithm: Int,
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,
    val aaguid: String,
    val discoverable: Boolean,
    val backupEligible: Boolean,
    val backupState: Boolean,
    val keyMode: PasskeyKeyMode = PasskeyKeyMode.SYNCABLE,
    val deviceBinding: PasskeyDeviceBinding? = null,
    val unknownFields: JsonObject = JsonObject(emptyMap()),
) {
    fun toJson(): JsonObject {
        val values = unknownFields.toMutableMap()
        values["rp_id"] = JsonPrimitive(rpId)
        values["rp_name"] = JsonPrimitive(rpName)
        values["user_id"] = JsonPrimitive(userId)
        values["user_name"] = JsonPrimitive(userName)
        values["user_display_name"] = JsonPrimitive(userDisplayName)
        values["credential_id"] = JsonPrimitive(credentialId)
        values["public_key"] = JsonPrimitive(publicKey)
        values["sign_count"] = JsonPrimitive(signCount.toString())
        values["created_at"] = JsonPrimitive(createdAt)
        values["last_used_at"] = JsonPrimitive(lastUsedAt)
        values["transports"] = JsonPrimitive(transports)
        values["algorithm"] = JsonPrimitive(algorithm.toString())
        values["schema_version"] = JsonPrimitive(schemaVersion.toString())
        values["aaguid"] = JsonPrimitive(aaguid)
        values["discoverable"] = JsonPrimitive(discoverable.toString())
        values["backup_eligible"] = JsonPrimitive(backupEligible.toString())
        values["backup_state"] = JsonPrimitive(backupState.toString())
        values["counter_mode"] = JsonPrimitive(COUNTER_MODE)
        if (schemaVersion == LEGACY_SCHEMA_VERSION) {
            values["private_key"] = JsonPrimitive(privateKey)
            values.remove("key_mode")
            values.remove("private_key_envelope")
            values.remove("device_binding")
        } else {
            values["key_mode"] = JsonPrimitive(keyMode.wireValue)
            values.remove("private_key_envelope")
            values.remove("device_binding")
            when (keyMode) {
                PasskeyKeyMode.SYNCABLE -> values["private_key"] = JsonPrimitive(privateKey)
                PasskeyKeyMode.DEVICE_BOUND -> {
                    values.remove("private_key")
                    deviceBinding?.let { values["device_binding"] = it.toJson() }
                }
            }
        }
        return JsonObject(values)
    }

    override fun toString(): String = "PasskeyRecord(<redacted>)"

    companion object {
        const val LEGACY_SCHEMA_VERSION = 2
        const val CURRENT_SCHEMA_VERSION = 3
        val SUPPORTED_SCHEMA_VERSIONS = setOf(LEGACY_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION)
        const val COUNTER_MODE = "synced_zero"
        private const val MAX_USER_ID_BYTES = 1024
        private const val MAX_CREDENTIAL_ID_BYTES = 1024
        private const val MAX_PRIVATE_KEY_BYTES = 16384
        private const val MAX_PUBLIC_KEY_BYTES = 4096
        private const val MAX_TEXT_CHARS = 4096
        private const val MAX_TIMESTAMP_CHARS = 64
        private val BASE64URL = Regex("^[A-Za-z0-9_-]+={0,2}$")
        private val RFC3339 = Regex(
            "^\\d{4}-\\d{2}-\\d{2}[Tt]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:[Zz]|[+-]\\d{2}:\\d{2})$"
        )
        private val AAGUID = Regex(
            "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
        )
        private val KNOWN_FIELDS = setOf(
            "schema_version",
            "rp_id",
            "rp_name",
            "user_id",
            "user_name",
            "user_display_name",
            "credential_id",
            "private_key",
            "key_mode",
            "private_key_envelope",
            "device_binding",
            "public_key",
            "algorithm",
            "transports",
            "aaguid",
            "discoverable",
            "backup_eligible",
            "backup_state",
            "counter_mode",
            "sign_count",
            "created_at",
            "last_used_at",
        )

        fun parse(value: JsonObject): PasskeyRecord? = try {
            parseStrict(value)
        } catch (_: Exception) {
            null
        }

        private fun parseStrict(value: JsonObject): PasskeyRecord {
            val schemaVersion = string(value, "schema_version", required = true).toInt()
            require(schemaVersion in SUPPORTED_SCHEMA_VERSIONS)

            val rpId = normalizeRpId(string(value, "rp_id", required = true, maximum = 253))
            val rpName = string(value, "rp_name", required = true, allowEmpty = true, maximum = MAX_TEXT_CHARS)
            val userName = string(value, "user_name", required = true, allowEmpty = true, maximum = MAX_TEXT_CHARS)
            val userDisplayName = string(
                value,
                "user_display_name",
                required = true,
                allowEmpty = true,
                maximum = MAX_TEXT_CHARS,
            )
            val userId = string(value, "user_id", required = true)
            decodeBase64Url(userId, MAX_USER_ID_BYTES)
            val credentialId = string(value, "credential_id", required = true)
            require(decodeBase64Url(credentialId, MAX_CREDENTIAL_ID_BYTES).size in 16..MAX_CREDENTIAL_ID_BYTES)
            val publicKey = string(value, "public_key", required = true)
            val publicKeyBytes = decodeBase64Url(publicKey, MAX_PUBLIC_KEY_BYTES)
            val algorithm = parseAlgorithm(value)
            val keyMode: PasskeyKeyMode
            val privateKey: String
            val deviceBinding: PasskeyDeviceBinding?
            if (schemaVersion == LEGACY_SCHEMA_VERSION) {
                keyMode = PasskeyKeyMode.SYNCABLE
                privateKey = string(value, "private_key", required = true)
                deviceBinding = null
                require("key_mode" !in value && "private_key_envelope" !in value && "device_binding" !in value)
                val privateKeyBytes = decodeBase64Url(privateKey, MAX_PRIVATE_KEY_BYTES)
                try {
                    validateKeyPair(privateKeyBytes, publicKeyBytes, algorithm)
                } finally {
                    privateKeyBytes.fill(0)
                }
            } else {
                keyMode = PasskeyKeyMode.parse(string(value, "key_mode", required = true))
                    ?: throw IllegalArgumentException("Unsupported Passkey key mode")
                val envelopeValue = value["private_key_envelope"]
                val bindingValue = value["device_binding"]
                deviceBinding = (bindingValue as? JsonObject)?.let(PasskeyDeviceBinding::parse)
                require(envelopeValue == null || envelopeValue is JsonNull) {
                    "Passkey private-key envelope is no longer supported"
                }
                when (keyMode) {
                    PasskeyKeyMode.SYNCABLE -> {
                        privateKey = string(value, "private_key", required = true)
                        val privateKeyBytes = decodeBase64Url(privateKey, MAX_PRIVATE_KEY_BYTES)
                        try {
                            validateKeyPair(privateKeyBytes, publicKeyBytes, algorithm)
                        } finally {
                            privateKeyBytes.fill(0)
                        }
                        require(deviceBinding == null)
                        require(bindingValue == null || bindingValue is JsonNull)
                    }
                    PasskeyKeyMode.DEVICE_BOUND -> {
                        privateKey = ""
                        require("private_key" !in value)
                        require(deviceBinding != null)
                    }
                }
                validatePublicKey(publicKeyBytes, algorithm)
            }

            val transports = parseTransports(value)
            val signCount = parseSignCount(value["sign_count"])
            require(string(value, "counter_mode", required = true) == COUNTER_MODE)
            require(signCount == 0L)

            val createdAt = string(value, "created_at", required = true, maximum = MAX_TIMESTAMP_CHARS)
            val lastUsedAt = string(
                value,
                "last_used_at",
                required = true,
                allowEmpty = true,
                maximum = MAX_TIMESTAMP_CHARS,
            )
            validateTimestamp(createdAt, allowEmpty = false)
            validateTimestamp(lastUsedAt, allowEmpty = true)

            val aaguid = string(value, "aaguid", required = true, maximum = 36)
            require(AAGUID.matches(aaguid))
            UUID.fromString(aaguid)
            val discoverable = booleanString(value, "discoverable")
            val backupEligible = booleanString(value, "backup_eligible")
            val backupState = booleanString(value, "backup_state")
            require(!backupState || backupEligible)
            if (schemaVersion == CURRENT_SCHEMA_VERSION) {
                when (keyMode) {
                    PasskeyKeyMode.SYNCABLE -> require(backupEligible)
                    PasskeyKeyMode.DEVICE_BOUND -> require(!backupEligible && !backupState)
                }
            }

            return PasskeyRecord(
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = userDisplayName,
                credentialId = credentialId,
                privateKey = privateKey,
                publicKey = publicKey,
                signCount = signCount,
                createdAt = createdAt,
                lastUsedAt = lastUsedAt,
                transports = transports,
                algorithm = algorithm,
                schemaVersion = schemaVersion,
                aaguid = aaguid,
                discoverable = discoverable,
                backupEligible = backupEligible,
                backupState = backupState,
                keyMode = keyMode,
                deviceBinding = deviceBinding,
                unknownFields = JsonObject(value.filterKeys { it !in KNOWN_FIELDS }),
            )
        }

        private fun string(
            value: JsonObject,
            key: String,
            required: Boolean = false,
            allowEmpty: Boolean = !required,
            maximum: Int = MAX_TEXT_CHARS,
        ): String {
            val element = value[key]
            if (element == null) {
                require(!required)
                return ""
            }
            val primitive = element as? JsonPrimitive ?: throw IllegalArgumentException()
            require(primitive.isString)
            return primitive.content.also {
                require(it.length <= maximum)
                if (!allowEmpty) require(it.isNotEmpty())
            }
        }

        private fun booleanString(value: JsonObject, key: String): Boolean {
            val primitive = value[key] as? JsonPrimitive ?: throw IllegalArgumentException()
            require(primitive.isString)
            return when (primitive.content) {
                "true" -> true
                "false" -> false
                else -> throw IllegalArgumentException()
            }
        }

        private fun parseAlgorithm(value: JsonObject): Int {
            val primitive = value["algorithm"] as? JsonPrimitive ?: throw IllegalArgumentException()
            require(primitive.isString && primitive.booleanOrNull == null)
            val text = primitive.content
            require(text in setOf("-7", "-257", "-8")) { "Unsupported algorithm: $text" }
            return text.toInt()
        }

        private fun parseTransports(value: JsonObject): String {
            val primitive = value["transports"] as? JsonPrimitive ?: throw IllegalArgumentException()
            require(primitive.isString)
            val text = primitive.content
            require(text == "internal")
            return text
        }

        private fun parseSignCount(value: kotlinx.serialization.json.JsonElement?): Long {
            val primitive = value as? JsonPrimitive ?: throw IllegalArgumentException()
            require(primitive.isString && primitive.booleanOrNull == null)
            val text = primitive.content
            require(text.isNotEmpty() && text.length <= 10 && text.all { it in '0'..'9' })
            if (text.length == 10) require(text <= "4294967295")
            return text.toLong().also { require(it in 0..0xffff_ffffL) }
        }

        private fun normalizeRpId(value: String): String {
            require(value.isNotEmpty() && value.length <= 253 && value == value.trim())
            val domain = value.removeSuffix(".")
            require('.' in domain && !domain.startsWith('.') && !domain.endsWith('.'))
            val labels = domain.split('.')
            require(labels.all { label ->
                label.isNotEmpty() && label.codePoints().toArray().all { cp ->
                    cp == '-'.code || when (Character.getType(cp)) {
                        Character.UPPERCASE_LETTER.toInt(), Character.LOWERCASE_LETTER.toInt(),
                        Character.TITLECASE_LETTER.toInt(), Character.MODIFIER_LETTER.toInt(),
                        Character.OTHER_LETTER.toInt(), Character.NON_SPACING_MARK.toInt(),
                        Character.COMBINING_SPACING_MARK.toInt(), Character.ENCLOSING_MARK.toInt(),
                        Character.DECIMAL_DIGIT_NUMBER.toInt(), Character.LETTER_NUMBER.toInt(),
                        Character.OTHER_NUMBER.toInt() -> true
                        else -> false
                    }
                }
            })
            val ascii = IDN.toASCII(domain.lowercase(), IDN.USE_STD3_ASCII_RULES)
            require(ascii.length <= 253 && ascii.contains('.') && !ascii.startsWith('.') && !ascii.endsWith('.'))
            val asciiLabels = ascii.split('.')
            require(asciiLabels.all { it.isNotEmpty() && it.length <= 63 })
            require(!asciiLabels.last().all(Char::isDigit))
            return ascii
        }

        private fun validateTimestamp(value: String, allowEmpty: Boolean) {
            if (value.isEmpty()) {
                require(allowEmpty)
                return
            }
            require(RFC3339.matches(value))
            val normalized = value.replace('t', 'T').let {
                if (it.endsWith('z')) it.dropLast(1) + "Z" else it
            }
            OffsetDateTime.parse(normalized, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        }

        private fun decodeBase64Url(value: String, maximumBytes: Int): ByteArray {
            require(value.isNotEmpty() && value.length <= ((maximumBytes + 2) / 3) * 4)
            require(BASE64URL.matches(value))
            val padding = value.length - value.trimEnd('=').length
            require((padding == 0 && value.length % 4 != 1) || (padding > 0 && value.length % 4 == 0))
            val decoded = Base64.getUrlDecoder().decode(value.padEnd((value.length + 3) / 4 * 4, '='))
            require(decoded.size <= maximumBytes)
            val canonical = Base64.getUrlEncoder().let { encoder ->
                if (padding == 0) encoder.withoutPadding().encodeToString(decoded) else encoder.encodeToString(decoded)
            }
            require(MessageDigest.isEqual(canonical.toByteArray(Charsets.US_ASCII), value.toByteArray(Charsets.US_ASCII)))
            return decoded
        }

        private fun validateKeyPair(privateBytes: ByteArray, publicBytes: ByteArray, algorithm: Int = -7) {
            when (algorithm) {
                -7 -> validateEcKeyPair(privateBytes, publicBytes)
                -257 -> validateRsaKeyPair(privateBytes, publicBytes)
                -8 -> validateEd25519KeyPair(privateBytes, publicBytes)
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }

        private fun validatePublicKey(publicBytes: ByteArray, algorithm: Int) {
            when (algorithm) {
                -7 -> {
                    val coordinates = CborReader(publicBytes).readCoseP256Key()
                    val parameters = ECNamedCurveTable.getParameterSpec("secp256r1")
                    parameters.curve.validatePoint(
                        BigInteger(1, coordinates.first),
                        BigInteger(1, coordinates.second),
                    )
                }
                -257 -> {
                    val (modulus, exponent) = CborReader(publicBytes).readCoseRsaKey()
                    require(BigInteger(1, modulus).bitLength() >= 2048)
                    require(BigInteger(1, exponent).signum() > 0)
                }
                -8 -> require(CborReader(publicBytes).readCoseEd25519Key().size == 32)
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }

        private fun validateEcKeyPair(privateBytes: ByteArray, publicBytes: ByteArray) {
            val info = PrivateKeyInfo.getInstance(privateBytes)
            require(info.privateKeyAlgorithm.algorithm == X9ObjectIdentifiers.id_ecPublicKey)
            require((info.privateKeyAlgorithm.parameters as? ASN1ObjectIdentifier) == SECObjectIdentifiers.secp256r1)
            val privateKey = KeyFactory.getInstance("EC")
                .generatePrivate(PKCS8EncodedKeySpec(privateBytes)) as? ECPrivateKey
                ?: throw IllegalArgumentException()
            val parameters = ECNamedCurveTable.getParameterSpec("secp256r1")
            require(privateKey.params != null)
            require(privateKey.params.order == parameters.n)
            require(privateKey.s.signum() > 0 && privateKey.s < parameters.n)

            val coordinates = CborReader(publicBytes).readCoseP256Key()
            val publicPoint = parameters.curve.validatePoint(
                BigInteger(1, coordinates.first),
                BigInteger(1, coordinates.second),
            ).normalize()
            val derivedPoint = parameters.g.multiply(privateKey.s).normalize()
            require(MessageDigest.isEqual(unsigned32(publicPoint.affineXCoord.encoded), unsigned32(derivedPoint.affineXCoord.encoded)))
            require(MessageDigest.isEqual(unsigned32(publicPoint.affineYCoord.encoded), unsigned32(derivedPoint.affineYCoord.encoded)))
        }

        private fun validateRsaKeyPair(privateBytes: ByteArray, publicBytes: ByteArray) {
            val privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(privateBytes)) as? RSAPrivateKey
                ?: throw IllegalArgumentException()
            require(privateKey.modulus.bitLength() >= 2048) { "RSA key must be at least 2048 bits" }
            require(privateKey.privateExponent.signum() > 0) { "RSA private exponent must be positive" }

            val rsaPublicKeyInfo = CborReader(publicBytes).readCoseRsaKey()
            require(MessageDigest.isEqual(privateKey.modulus.toByteArray().stripLeadingZero(), rsaPublicKeyInfo.first)) { "RSA modulus mismatch" }
        }

        private fun validateEd25519KeyPair(privateBytes: ByteArray, publicBytes: ByteArray) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
            val info = PrivateKeyInfo.getInstance(privateBytes)
            val seed = (info.parsePrivateKey() as org.bouncycastle.asn1.ASN1OctetString).octets
            require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }

            val bcPrivate = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
            val bcPublic = bcPrivate.generatePublicKey()
            val expectedPublicBytes = CborReader(publicBytes).readCoseEd25519Key()
            val rawPub = ByteArray(32)
            bcPublic.encode(rawPub, 0)
            require(MessageDigest.isEqual(rawPub, expectedPublicBytes)) { "Ed25519 public key mismatch" }
        }

        private fun ByteArray.stripLeadingZero(): ByteArray {
            val idx = indexOfFirst { it != 0.toByte() }
            return if (idx >= 0) copyOfRange(idx, size) else byteArrayOf(0)
        }

        private fun unsigned32(value: ByteArray): ByteArray {
            require(value.size <= 32)
            return ByteArray(32 - value.size) + value
        }
    }
}

private class CborReader(private val value: ByteArray) {
    private var offset = 0

    fun readCoseP256Key(): Pair<ByteArray, ByteArray> {
        val size = head().also { require(it.first == 5) }.second
        require(size <= 16)
        val result = mutableMapOf<Int, Any>()
        var previousOrder: Pair<Int, ByteArray>? = null
        repeat(size.toInt()) {
            val keyStart = offset
            val key = readItem() as? Int ?: throw IllegalArgumentException()
            val keyBytes = value.copyOfRange(keyStart, offset)
            val order = keyBytes.size to keyBytes
            previousOrder?.let {
                require(order.first > it.first || (order.first == it.first && compare(order.second, it.second) > 0))
            }
            previousOrder = order
            require(key !in result)
            result[key] = readItem()
        }
        require(offset == value.size)
        require(result[1] == 2)
        require(result[3] == -7)
        require(result[-1] == 1)
        val x = result[-2] as? ByteArray ?: throw IllegalArgumentException()
        val y = result[-3] as? ByteArray ?: throw IllegalArgumentException()
        require(x.size == 32 && y.size == 32)
        return x to y
    }

    fun readCoseRsaKey(): Pair<ByteArray, ByteArray> {
        val size = head().also { require(it.first == 5) }.second
        require(size <= 16)
        val result = mutableMapOf<Int, Any>()
        var previousOrder: Pair<Int, ByteArray>? = null
        repeat(size.toInt()) {
            val keyStart = offset
            val key = readItem() as? Int ?: throw IllegalArgumentException()
            val keyBytes = value.copyOfRange(keyStart, offset)
            val order = keyBytes.size to keyBytes
            previousOrder?.let {
                require(order.first > it.first || (order.first == it.first && compare(order.second, it.second) > 0))
            }
            previousOrder = order
            require(key !in result)
            result[key] = readItem()
        }
        require(offset == value.size)
        require(result[1] == 3)
        require(result[3] == -257)
        val modulus = result[-1] as? ByteArray ?: throw IllegalArgumentException()
        val exponent = result[-2] as? ByteArray ?: throw IllegalArgumentException()
        return modulus to exponent
    }

    fun readCoseEd25519Key(): ByteArray {
        val size = head().also { require(it.first == 5) }.second
        require(size <= 16)
        val result = mutableMapOf<Int, Any>()
        var previousOrder: Pair<Int, ByteArray>? = null
        repeat(size.toInt()) {
            val keyStart = offset
            val key = readItem() as? Int ?: throw IllegalArgumentException()
            val keyBytes = value.copyOfRange(keyStart, offset)
            val order = keyBytes.size to keyBytes
            previousOrder?.let {
                require(order.first > it.first || (order.first == it.first && compare(order.second, it.second) > 0))
            }
            previousOrder = order
            require(key !in result)
            result[key] = readItem()
        }
        require(offset == value.size)
        require(result[1] == 1)
        require(result[3] == -8)
        val x = result[-2] as? ByteArray ?: throw IllegalArgumentException()
        require(x.size == 32)
        return x
    }

    private fun readItem(): Any {
        val (major, argument) = head()
        return when (major) {
            0 -> argument.toInt().also { require(argument <= Int.MAX_VALUE) }
            1 -> (-1L - argument).toInt().also { require(argument <= Int.MAX_VALUE.toLong()) }
            2 -> {
                require(argument <= Int.MAX_VALUE && offset + argument.toInt() <= value.size)
                value.copyOfRange(offset, offset + argument.toInt()).also { offset += argument.toInt() }
            }
            else -> throw IllegalArgumentException()
        }
    }

    private fun head(): Pair<Int, Long> {
        require(offset < value.size)
        val initial = value[offset++].toInt() and 0xff
        val major = initial ushr 5
        val additional = initial and 0x1f
        if (additional < 24) return major to additional.toLong()
        val count = when (additional) {
            24 -> 1
            25 -> 2
            26 -> 4
            27 -> 8
            else -> throw IllegalArgumentException()
        }
        require(offset + count <= value.size)
        var argument = 0L
        repeat(count) { argument = (argument shl 8) or (value[offset++].toLong() and 0xff) }
        val minimum = when (count) {
            1 -> 24L
            2 -> 0x100L
            4 -> 0x1_0000L
            else -> 0x1_0000_0000L
        }
        require(argument >= minimum)
        return major to argument
    }

    private fun compare(left: ByteArray, right: ByteArray): Int {
        for (index in left.indices) {
            val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
            if (difference != 0) return difference
        }
        return 0
    }
}
