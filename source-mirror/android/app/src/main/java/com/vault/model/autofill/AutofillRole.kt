package com.vault.model.autofill

enum class AutofillRole(
    val wire: String,
    val minimumRequiresVerification: Boolean = false,
) {
    USERNAME("username"),
    EMAIL("email"),
    PASSWORD("password", minimumRequiresVerification = true),
    ONE_TIME_CODE("one_time_code"),
    FULL_NAME("full_name"),
    PHONE("phone"),
    COUNTRY("country"),
    REGION("region"),
    CITY("city"),
    STREET_ADDRESS("street_address"),
    POSTAL_CODE("postal_code"),
    CARDHOLDER("cardholder"),
    CARD_NUMBER("card_number"),
    CARD_EXPIRY("card_expiry"),
    CARD_CVV("card_cvv", minimumRequiresVerification = true),
    ID_NUMBER("id_number", minimumRequiresVerification = true),
    API_KEY("api_key", minimumRequiresVerification = true),
    API_SECRET("api_secret", minimumRequiresVerification = true),
    HOST("host"),
    PORT("port"),
    DATABASE("database"),
    SSID("ssid"),
    WIFI_PASSWORD("wifi_password", minimumRequiresVerification = true),
    RECOVERY_ANSWER("recovery_answer", minimumRequiresVerification = true),
    CUSTOM_TEXT("custom_text"),
    CUSTOM_SECRET("custom_secret", minimumRequiresVerification = true),
    NONE("none"),
    ;

    companion object {
        private val byWire = entries.associateBy(AutofillRole::wire)

        fun fromWire(value: String): AutofillRole? = byWire[value]
    }

    fun enforceRequiresVerification(requested: Boolean): Boolean =
        requested || minimumRequiresVerification
}
