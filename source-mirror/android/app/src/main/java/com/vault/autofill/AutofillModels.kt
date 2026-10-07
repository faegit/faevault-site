package com.vault.autofill

enum class FieldKind {
    USERNAME, EMAIL, PASSWORD, NEW_PASSWORD, OTP,
    FULL_NAME, PHONE, COUNTRY, REGION, CITY, STREET_ADDRESS, POSTAL_CODE,
    CARDHOLDER, CARD_NUMBER, CARD_EXPIRY, CARD_CVV,
    ID_NUMBER, API_KEY, API_SECRET, HOST, PORT, DATABASE, SSID, WIFI_PASSWORD,
    RECOVERY_ANSWER, CUSTOM_TEXT, CUSTOM_SECRET,
    UNKNOWN,
}

data class FieldEvidence(
    val autofillHints: Set<String> = emptySet(),
    val htmlAttributes: Map<String, String> = emptyMap(),
    val resourceId: String? = null,
    val className: String? = null,
    val inputType: Int = 0,
    val label: String? = null,
    val focused: Boolean = false,
    val visible: Boolean = true,
    val enabled: Boolean = true,
    val currentText: String? = null,
    val fieldKey: String? = null,
)

data class FieldCandidate<T>(val id: T, val evidence: FieldEvidence)

data class FieldClassification(val kind: FieldKind, val score: Int)

data class ClassifiedField<T>(
    val id: T,
    val kind: FieldKind,
    val score: Int,
    val focused: Boolean,
    val currentText: String? = null,
    val fieldKey: String? = null,
    val label: String? = null,
)

sealed interface TargetOrigin {
    data class AndroidPackage(
        val packageName: String,
        val signingCertificateSha256: Set<String> = emptySet(),
    ) : TargetOrigin
    data class Web(
        val host: String,
        val browserPackageName: String = "",
        val browserSigningCertificateSha256: Set<String> = emptySet(),
    ) : TargetOrigin
}

data class ParsedForm<T>(
    val origin: TargetOrigin,
    val fields: List<ClassifiedField<T>>,
    val packageName: String,
)

enum class OriginMatchLevel { EXACT, PARENT_DOMAIN, LEGACY_PACKAGE, WORD_CANDIDATE, NONE }

internal fun mayAutoApplySavedCredentialUpdate(level: OriginMatchLevel): Boolean =
    level == OriginMatchLevel.EXACT

data class CredentialMatch(
    val entryId: String,
    val level: OriginMatchLevel,
    val score: Int,
)

data class SaveCandidate(
    val username: String?,
    val password: String?,
    val newPassword: String? = null,
    val confirmationPassword: String? = null,
)

data class ExistingCredential(val username: String, val password: String)

sealed interface SaveDecision {
    data object Unchanged : SaveDecision
    data class Reject(val reason: String) : SaveDecision
    data class Create(val username: String, val password: String) : SaveDecision
    data class UpdateChoice(
        val username: String,
        val password: String,
        val matchingEntryIds: List<String>,
    ) : SaveDecision
}
