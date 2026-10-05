package com.vault.passkeys

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.Base64
import java.util.UUID

enum class PasskeyKeyMode(val wireValue: String) {
    SYNCABLE("syncable"),
    DEVICE_BOUND("device_bound");

    companion object {
        fun parse(value: String): PasskeyKeyMode? = entries.firstOrNull { it.wireValue == value }
    }
}

/** Software keys need an activity-level user-verification gate; device keys bind it to Keystore signing. */
fun PasskeyKeyMode.requiresActivityUserVerification(): Boolean = this == PasskeyKeyMode.SYNCABLE

enum class PasskeyAvailability {
    AVAILABLE,
    OTHER_DEVICE,
    KEY_MISSING,
}

data class PasskeyDeviceBinding(
    val provider: String,
    val deviceId: UUID,
    val bindingId: String,
    val keyGeneration: Long,
    val unknownFields: JsonObject = JsonObject(emptyMap()),
) {
    fun toJson(): JsonObject = JsonObject(unknownFields.toMutableMap().also { values ->
        values["provider"] = JsonPrimitive(provider)
        values["device_id"] = JsonPrimitive(deviceId.toString())
        values["binding_id"] = JsonPrimitive(bindingId)
        values["key_generation"] = JsonPrimitive(keyGeneration.toString())
    })

    companion object {
        private val knownFields = setOf("provider", "device_id", "binding_id", "key_generation")
        private val base64Url = Regex("^[A-Za-z0-9_-]+$")

        fun parse(value: JsonObject): PasskeyDeviceBinding? = runCatching {
            val provider = value.strictString("provider")
            require(provider == "android_keystore")
            val deviceIdText = value.strictString("device_id")
            val deviceId = UUID.fromString(deviceIdText)
            require(deviceId.toString() == deviceIdText.lowercase())
            val bindingId = value.strictString("binding_id")
            require(base64Url.matches(bindingId))
            require(Base64.getUrlDecoder().decode(bindingId.padBase64()).size in 16..64)
            val generationText = value.strictString("key_generation")
            require(generationText.isNotEmpty() && generationText.all(Char::isDigit))
            val generation = generationText.toLong()
            require(generation > 0)
            PasskeyDeviceBinding(
                provider,
                deviceId,
                bindingId,
                generation,
                JsonObject(value.filterKeys { it !in knownFields }),
            )
        }.getOrNull()
    }
}

internal fun JsonObject.strictString(key: String): String {
    val primitive = this[key] as? JsonPrimitive ?: throw IllegalArgumentException("$key must be a string")
    require(primitive.isString)
    return primitive.content
}

internal fun String.padBase64(): String = padEnd((length + 3) / 4 * 4, '=')
