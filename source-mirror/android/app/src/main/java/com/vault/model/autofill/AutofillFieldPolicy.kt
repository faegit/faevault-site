package com.vault.model.autofill

import com.vault.model.ModuleType

data class AutofillPolicy(
    val role: AutofillRole,
    val internalDefault: Boolean,
    val externalDefault: Boolean,
    val requiresVerification: Boolean,
)

object AutofillFieldPolicy {
    private fun policy(role: AutofillRole) = AutofillPolicy(
        role = role,
        internalDefault = true,
        externalDefault = !role.minimumRequiresVerification,
        requiresVerification = role.minimumRequiresVerification,
    )

    private val topLevelPolicies = mapOf(
        "username" to policy(AutofillRole.USERNAME),
        "password" to policy(AutofillRole.PASSWORD),
    )

    private val modulePolicies = mapOf(
        (ModuleType.LOGIN_ACCOUNT to "username") to policy(AutofillRole.USERNAME),
        (ModuleType.LOGIN_ACCOUNT to "password") to policy(AutofillRole.PASSWORD),


        (ModuleType.ADDRESS to "country") to policy(AutofillRole.COUNTRY),
        (ModuleType.ADDRESS to "region") to policy(AutofillRole.REGION),
        (ModuleType.ADDRESS to "city") to policy(AutofillRole.CITY),
        (ModuleType.ADDRESS to "address") to policy(AutofillRole.STREET_ADDRESS),
        (ModuleType.ADDRESS to "postal_code") to policy(AutofillRole.POSTAL_CODE),

        (ModuleType.CARD_DOCUMENT to "full_name") to policy(AutofillRole.FULL_NAME),
        (ModuleType.CARD_DOCUMENT to "id_number") to policy(AutofillRole.ID_NUMBER),
        (ModuleType.CARD_DOCUMENT to "cardholder") to policy(AutofillRole.CARDHOLDER),
        (ModuleType.CARD_DOCUMENT to "card_number") to policy(AutofillRole.CARD_NUMBER),
        (ModuleType.CARD_DOCUMENT to "expiry") to policy(AutofillRole.CARD_EXPIRY),
        (ModuleType.CARD_DOCUMENT to "cvv") to policy(AutofillRole.CARD_CVV),

        (ModuleType.API_CREDENTIAL to "api_key") to policy(AutofillRole.API_KEY),
        (ModuleType.API_CREDENTIAL to "api_secret") to policy(AutofillRole.API_SECRET),

        (ModuleType.WIFI to "ssid") to policy(AutofillRole.SSID),
        (ModuleType.WIFI to "wifi_password") to policy(AutofillRole.WIFI_PASSWORD),
        (ModuleType.WIFI to "admin_password") to policy(AutofillRole.WIFI_PASSWORD),

        (ModuleType.SERVER_CONNECTION to "host") to policy(AutofillRole.HOST),
        (ModuleType.SERVER_CONNECTION to "port") to policy(AutofillRole.PORT),
        (ModuleType.SERVER_CONNECTION to "username") to policy(AutofillRole.USERNAME),
        (ModuleType.SERVER_CONNECTION to "password") to policy(AutofillRole.PASSWORD),

        (ModuleType.SSH to "host") to policy(AutofillRole.HOST),
        (ModuleType.SSH to "port") to policy(AutofillRole.PORT),
        (ModuleType.SSH to "username") to policy(AutofillRole.USERNAME),
        (ModuleType.SSH to "password") to policy(AutofillRole.PASSWORD),

        (ModuleType.DATABASE to "host") to policy(AutofillRole.HOST),
        (ModuleType.DATABASE to "port") to policy(AutofillRole.PORT),
        (ModuleType.DATABASE to "database") to policy(AutofillRole.DATABASE),
        (ModuleType.DATABASE to "username") to policy(AutofillRole.USERNAME),
        (ModuleType.DATABASE to "password") to policy(AutofillRole.PASSWORD),

        (ModuleType.RECOVERY to "answer") to policy(AutofillRole.RECOVERY_ANSWER),
        (ModuleType.OTP to "@computed/one_time_code") to policy(AutofillRole.ONE_TIME_CODE),

        (ModuleType.TEXT to "value") to policy(AutofillRole.CUSTOM_TEXT),
        (ModuleType.PASSWORD to "value") to policy(AutofillRole.CUSTOM_SECRET),
    )

    fun forTopLevel(sourceKey: String): AutofillPolicy? = topLevelPolicies[sourceKey]

    fun forField(moduleType: String, sourceKey: String): AutofillPolicy? =
        modulePolicies[moduleType to sourceKey]
}
