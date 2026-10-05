package com.vault.passkeys

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.net.IDN
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.Locale

enum class UserVerificationRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED,
}

class CreatePasskeyRequest internal constructor(
    val rpId: String,
    val rpName: String,
    userId: ByteArray,
    val userName: String,
    val userDisplayName: String,
    challenge: ByteArray,
    val algorithm: Int,
    excludeCredentialIds: Set<String>,
    val residentKeyRequired: Boolean,
    val userVerification: UserVerificationRequirement,
    val credentialPropertiesRequested: Boolean,
    val attestation: String?,
) {
    private val storedUserId = userId.copyOf()
    private val storedChallenge = challenge.copyOf()
    private val storedExcludeCredentialIds =
        Collections.unmodifiableSet(LinkedHashSet(excludeCredentialIds))

    val userId: ByteArray
        get() = storedUserId.copyOf()

    val challenge: ByteArray
        get() = storedChallenge.copyOf()

    val excludeCredentialIds: Set<String>
        get() = storedExcludeCredentialIds

    override fun equals(other: Any?): Boolean =
        this === other ||
            other is CreatePasskeyRequest &&
            rpId == other.rpId &&
            rpName == other.rpName &&
            MessageDigest.isEqual(storedUserId, other.storedUserId) &&
            userName == other.userName &&
            userDisplayName == other.userDisplayName &&
            MessageDigest.isEqual(storedChallenge, other.storedChallenge) &&
            algorithm == other.algorithm &&
            storedExcludeCredentialIds == other.storedExcludeCredentialIds &&
            residentKeyRequired == other.residentKeyRequired &&
            userVerification == other.userVerification &&
            credentialPropertiesRequested == other.credentialPropertiesRequested &&
            attestation == other.attestation

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + rpName.hashCode()
        result = 31 * result + storedUserId.contentHashCode()
        result = 31 * result + userName.hashCode()
        result = 31 * result + userDisplayName.hashCode()
        result = 31 * result + storedChallenge.contentHashCode()
        result = 31 * result + algorithm
        result = 31 * result + storedExcludeCredentialIds.hashCode()
        result = 31 * result + residentKeyRequired.hashCode()
        result = 31 * result + userVerification.hashCode()
        result = 31 * result + credentialPropertiesRequested.hashCode()
        result = 31 * result + (attestation?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String = "CreatePasskeyRequest(<redacted>)"
}

class GetPasskeyRequest internal constructor(
    val rpId: String,
    challenge: ByteArray,
    allowCredentialIds: Set<String>,
    val userVerification: UserVerificationRequirement,
) {
    private val storedChallenge = challenge.copyOf()
    private val storedAllowCredentialIds =
        Collections.unmodifiableSet(LinkedHashSet(allowCredentialIds))

    val challenge: ByteArray
        get() = storedChallenge.copyOf()

    val allowCredentialIds: Set<String>
        get() = storedAllowCredentialIds

    override fun equals(other: Any?): Boolean =
        this === other ||
            other is GetPasskeyRequest &&
            rpId == other.rpId &&
            MessageDigest.isEqual(storedChallenge, other.storedChallenge) &&
            storedAllowCredentialIds == other.storedAllowCredentialIds &&
            userVerification == other.userVerification

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + storedChallenge.contentHashCode()
        result = 31 * result + storedAllowCredentialIds.hashCode()
        result = 31 * result + userVerification.hashCode()
        return result
    }

    override fun toString(): String = "GetPasskeyRequest(<redacted>)"
}

object PasskeyRequests {
    private const val MAX_REQUEST_BYTES = 131_072
    private const val MAX_NAME_BYTES = 64
    private const val MAX_USER_HANDLE_BYTES = 64
    private const val MAX_CHALLENGE_BYTES = 1_024
    private const val MAX_CREDENTIAL_ID_BYTES = 1_023
    private const val MAX_CREDENTIALS = 64
    private const val MAX_ALGORITHMS = 32
    private const val ES256 = -7
    private const val RS256 = -257
    private const val EDDSA = -8
    private val SUPPORTED_ALGORITHMS = setOf(ES256, RS256, EDDSA)

    private val json = Json {
        isLenient = false
        allowSpecialFloatingPointValues = false
    }

    fun parseCreate(requestJson: String): CreatePasskeyRequest = safely {
        val request = rootObject(requestJson)
        val credentialPropertiesRequested = validateExtensions(request)
        val rp = request.requiredObject("rp")
        val user = request.requiredObject("user")
        val algorithms = request.requiredArray("pubKeyCredParams")
        checkSafe(algorithms.size in 1..MAX_ALGORITHMS, "algorithms")
        algorithms.forEach { parameter ->
            val value = parameter as? JsonObject ?: invalid("algorithms")
            checkSafe(value.requiredString("type") == "public-key", "algorithm type")
            value.requiredInteger("alg")
        }
        checkSafe(
            algorithms.any { (it as JsonObject).requiredInteger("alg") in SUPPORTED_ALGORITHMS },
            "unsupported algorithm",
        )

        val selection = request.optionalObject("authenticatorSelection")
        val residentKey = selection?.optionalString("residentKey")?.also {
            checkSafe(it in RESIDENT_KEY_VALUES, "resident key")
        }
        val requireResidentKey = selection?.optionalBoolean("requireResidentKey")
        if (residentKey != null && requireResidentKey != null) {
            checkSafe((residentKey == "required") == requireResidentKey, "resident key")
        }
        selection?.optionalString("authenticatorAttachment")?.let {
            checkSafe(it == "platform", "authenticator attachment")
        }

        val selectedAlgorithm = selectBestAlgorithm(algorithms)

        val attestation = request.optionalString("attestation")?.also {
            checkSafe(it in ATTESTATION_VALUES, "attestation")
        }

        CreatePasskeyRequest(
            rpId = normalizeRpId(rp.requiredString("id")),
            rpName = rp.requiredName("name"),
            userId = decodeBase64Url(
                user.requiredString("id"),
                maximumBytes = MAX_USER_HANDLE_BYTES,
                field = "user handle",
            ),
            userName = user.requiredName("name"),
            userDisplayName = user.requiredName("displayName"),
            challenge = decodeBase64Url(
                request.requiredString("challenge"),
                maximumBytes = MAX_CHALLENGE_BYTES,
                field = "challenge",
            ),
            algorithm = selectedAlgorithm,
            excludeCredentialIds = parseCredentialIds(request, "excludeCredentials"),
            residentKeyRequired = residentKey == "required" ||
                (residentKey == null && requireResidentKey == true),
            userVerification = parseUserVerification(
                selection?.optionalString("userVerification"),
            ),
            credentialPropertiesRequested = credentialPropertiesRequested,
            attestation = attestation,
        )
    }

    fun parseGet(requestJson: String): GetPasskeyRequest = safely {
        val request = rootObject(requestJson)
        validateExtensions(request)
        GetPasskeyRequest(
            rpId = normalizeRpId(request.requiredString("rpId")),
            challenge = decodeBase64Url(
                request.requiredString("challenge"),
                maximumBytes = MAX_CHALLENGE_BYTES,
                field = "challenge",
            ),
            allowCredentialIds = parseCredentialIds(request, "allowCredentials"),
            userVerification = parseUserVerification(request.optionalString("userVerification")),
        )
    }

    private fun selectBestAlgorithm(algorithms: JsonArray): Int {
        val requested = algorithms
            .mapNotNull { (it as? JsonObject)?.requiredInteger("alg") }
            .filter { it in SUPPORTED_ALGORITHMS }
        require(requested.isNotEmpty()) { "No supported algorithm in request" }
        return when {
            ES256 in requested -> ES256
            RS256 in requested -> RS256
            EDDSA in requested -> EDDSA
            else -> requested.first()
        }
    }

    private fun rootObject(requestJson: String): JsonObject {
        val size = requestJson.toByteArray(Charsets.UTF_8).size
        checkSafe(size in 2..MAX_REQUEST_BYTES, "request size")
        return json.parseToJsonElement(requestJson) as? JsonObject ?: invalid("request")
    }

    private fun parseCredentialIds(request: JsonObject, key: String): Set<String> {
        val credentials = request[key] ?: return emptySet()
        val array = credentials as? JsonArray ?: invalid(key)
        checkSafe(array.size <= MAX_CREDENTIALS, key)
        val ids = LinkedHashSet<String>(array.size)
        array.forEach { descriptor ->
            val value = descriptor as? JsonObject ?: invalid(key)
            checkSafe(value.requiredString("type") == "public-key", "credential type")
            val id = value.requiredString("id")
            val decodedId = decodeBase64Url(id, MAX_CREDENTIAL_ID_BYTES, "credential id")
            val canonicalId = Base64.getUrlEncoder().withoutPadding().encodeToString(decodedId)
            checkSafe(ids.add(canonicalId), "duplicate credential id")
            value["transports"]?.let(::validateTransports)
        }
        return ids
    }

    private fun validateTransports(element: JsonElement) {
        val transports = element as? JsonArray ?: invalid("transports")
        checkSafe(transports.size <= 8, "transports")
        val seen = HashSet<String>()
        transports.forEach {
            val transport = (it as? JsonPrimitive)
                ?.takeIf(JsonPrimitive::isString)
                ?.content
                ?: invalid("transports")
            checkSafe(transport in TRANSPORTS && seen.add(transport), "transports")
        }
    }

    private fun parseUserVerification(value: String?): UserVerificationRequirement = when (value) {
        null, "preferred" -> UserVerificationRequirement.PREFERRED
        "required" -> UserVerificationRequirement.REQUIRED
        "discouraged" -> UserVerificationRequirement.DISCOURAGED
        else -> invalid("user verification")
    }

    private fun normalizeRpId(raw: String): String {
        checkSafe(raw.isNotEmpty() && raw == raw.trim(), "RP ID")
        checkSafe(raw.length <= 1_024, "RP ID")
        checkSafe(
            raw.none { it == '/' || it == '\\' || it == '@' || it == ':' || it == '?' || it == '#' },
            "RP ID",
        )
        val withoutFinalDot = if (raw.endsWith('.')) raw.dropLast(1) else raw
        checkSafe(withoutFinalDot.isNotEmpty() && !withoutFinalDot.endsWith('.'), "RP ID")
        val ascii = try {
            IDN.toASCII(
                withoutFinalDot.lowercase(Locale.ROOT),
                IDN.USE_STD3_ASCII_RULES,
            ).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            invalid("RP ID")
        }
        checkSafe(ascii.length in 1..253, "RP ID")
        val labels = ascii.split('.')
        checkSafe(labels.size >= 2, "RP ID")
        checkSafe(
            labels.all { label ->
                label.isNotEmpty() &&
                    label.length <= 63 &&
                    !label.startsWith('-') &&
                    !label.endsWith('-')
            },
            "RP ID",
        )
        checkSafe(ascii != "localhost" && !ascii.endsWith(".localhost"), "RP ID")
        val url = try {
            "https://$ascii/".toHttpUrl()
        } catch (_: IllegalArgumentException) {
            invalid("RP ID")
        }
        checkSafe(url.host == ascii && url.topPrivateDomain() != null, "RP ID")
        return ascii
    }

    private fun decodeBase64Url(
        value: String,
        maximumBytes: Int,
        field: String,
    ): ByteArray {
        val unpadded = value.trimEnd('=')
        val paddingLength = value.length - unpadded.length
        checkSafe(unpadded.isNotEmpty(), field)
        checkSafe(
            paddingLength in 0..2 && value.drop(unpadded.length).all { it == '=' },
            field,
        )
        checkSafe(unpadded.length <= encodedLengthWithoutPadding(maximumBytes), field)
        checkSafe(BASE64_URL.matches(unpadded) && unpadded.length % 4 != 1, field)
        val decoded = try {
            Base64.getUrlDecoder().decode(unpadded.padEnd((unpadded.length + 3) / 4 * 4, '='))
        } catch (_: IllegalArgumentException) {
            invalid(field)
        }
        checkSafe(decoded.isNotEmpty() && decoded.size <= maximumBytes, field)
        val canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)
        checkSafe(
            MessageDigest.isEqual(
                canonical.toByteArray(Charsets.US_ASCII),
                unpadded.toByteArray(Charsets.US_ASCII),
            ),
            field,
        )
        return decoded
    }

    private fun encodedLengthWithoutPadding(bytes: Int): Int = (bytes * 4 + 2) / 3

    private fun validateExtensions(request: JsonObject): Boolean {
        val extensions = request["extensions"] ?: return false
        val values = extensions as? JsonObject ?: invalid("extensions")
        val credProps = values["credProps"]?.strictBooleanOrNull()
        if ("credProps" in values) checkSafe(credProps != null, "extensions")
        values.forEach { (name, value) ->
            checkSafe(name.toByteArray(Charsets.UTF_8).size in 1..64, "extensions")
            checkSafe(!requiresUnsupportedExtension(name, value, depth = 0), "unsupported extension")
        }
        return credProps == true
    }

    private fun requiresUnsupportedExtension(
        name: String,
        value: JsonElement,
        depth: Int,
    ): Boolean {
        if (depth > 8) invalid("extensions")
        if (value is JsonPrimitive && value.isString && value.content == "required") return true
        if (value !is JsonObject) return false
        if (value["required"].strictBooleanOrNull() == true) return true
        if (name == "largeBlob" && value["support"].strictStringOrNull() == "required") return true
        if (
            name == "credProtect" &&
            value["enforceCredentialProtectionPolicy"].strictBooleanOrNull() == true
        ) {
            return true
        }
        return value.values.any { requiresUnsupportedExtension(name, it, depth + 1) }
    }

    private fun JsonObject.requiredObject(key: String): JsonObject =
        this[key] as? JsonObject ?: invalid(key)

    private fun JsonObject.optionalObject(key: String): JsonObject? {
        val value = this[key] ?: return null
        return value as? JsonObject ?: invalid(key)
    }

    private fun JsonObject.requiredArray(key: String): JsonArray =
        this[key] as? JsonArray ?: invalid(key)

    private fun JsonObject.requiredString(key: String): String =
        optionalString(key)?.takeIf(String::isNotEmpty) ?: invalid(key)

    private fun JsonObject.optionalString(key: String): String? {
        val value = this[key] ?: return null
        return value.strictStringOrNull() ?: invalid(key)
    }

    private fun JsonObject.requiredName(key: String): String =
        requiredString(key).also {
            checkSafe(it.toByteArray(Charsets.UTF_8).size <= MAX_NAME_BYTES, key)
            checkSafe(it.any { character -> !character.isWhitespace() && !character.isISOControl() }, key)
            checkSafe(it.none(Char::isISOControl), key)
        }

    private fun JsonObject.optionalBoolean(key: String): Boolean? {
        val value = this[key] ?: return null
        return value.strictBooleanOrNull() ?: invalid(key)
    }

    private fun JsonObject.requiredInteger(key: String): Int {
        val value = this[key] as? JsonPrimitive ?: invalid(key)
        checkSafe(!value.isString && value.booleanOrNull == null, key)
        return value.intOrNull ?: invalid(key)
    }

    private fun JsonElement?.strictStringOrNull(): String? =
        (this as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content

    private fun JsonElement?.strictBooleanOrNull(): Boolean? {
        val primitive = this as? JsonPrimitive ?: return null
        if (primitive.isString) return null
        return primitive.booleanOrNull
    }

    private inline fun <T> safely(block: () -> T): T = try {
        block()
    } catch (error: SafeRequestException) {
        throw IllegalArgumentException(error.message)
    } catch (_: Exception) {
        throw IllegalArgumentException("Invalid passkey request")
    }

    private fun checkSafe(condition: Boolean, field: String) {
        if (!condition) invalid(field)
    }

    private fun invalid(field: String): Nothing =
        throw SafeRequestException("Invalid passkey request: $field")

    private class SafeRequestException(message: String) : IllegalArgumentException(message)

    private val BASE64_URL = Regex("^[A-Za-z0-9_-]+$")
    private val RESIDENT_KEY_VALUES = setOf("required", "preferred", "discouraged")
    private val ATTESTATION_VALUES = setOf("none", "indirect", "direct", "enterprise")
    private val TRANSPORTS = setOf("usb", "nfc", "ble", "hybrid", "internal")
}
