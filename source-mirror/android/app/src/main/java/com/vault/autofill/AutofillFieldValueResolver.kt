package com.vault.autofill

import com.vault.model.autofill.AutofillRole

/** Username and email inputs both accept the explicitly resolved account identifier. */
object AutofillFieldValueResolver {
    fun value(kind: FieldKind, snapshot: AutofillSnapshot?, verificationGranted: Boolean): String? {
        val roles = when (kind) {
            FieldKind.USERNAME -> listOf(AutofillRole.USERNAME, AutofillRole.EMAIL)
            FieldKind.EMAIL -> listOf(AutofillRole.EMAIL, AutofillRole.USERNAME)
            FieldKind.UNKNOWN, FieldKind.NEW_PASSWORD -> emptyList()
            FieldKind.OTP -> listOf(AutofillRole.ONE_TIME_CODE)
            else -> listOfNotNull(AutofillRole.fromWire(kind.name.lowercase(java.util.Locale.ROOT)))
        }
        return roles.firstNotNullOfOrNull { snapshot?.valueFor(it, verificationGranted)?.takeIf(String::isNotBlank) }
    }
}
