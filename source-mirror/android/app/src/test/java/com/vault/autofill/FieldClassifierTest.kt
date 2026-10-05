package com.vault.autofill

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Test

class FieldClassifierTest {
    @Test
    fun explicitHintsWinOverHeuristics() {
        val evidence = FieldEvidence(
            autofillHints = setOf("username"),
            resourceId = "confirm_password",
            inputType = InputType.TYPE_CLASS_TEXT,
        )

        assertEquals(FieldKind.USERNAME, FieldClassifier.classify(evidence).kind)
    }

    @Test
    fun classifiesPasswordInputWithoutHints() {
        val evidence = FieldEvidence(
            resourceId = "field_42",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
        )

        assertEquals(FieldKind.PASSWORD, FieldClassifier.classify(evidence).kind)
    }

    @Test
    fun classifiesNewPasswordAndChineseUsernameLabels() {
        assertEquals(
            FieldKind.NEW_PASSWORD,
            FieldClassifier.classify(
                FieldEvidence(htmlAttributes = mapOf("autocomplete" to "new-password")),
            ).kind,
        )
        assertEquals(
            FieldKind.USERNAME,
            FieldClassifier.classify(FieldEvidence(label = "账号")).kind,
        )
    }

    @Test
    fun classifies2faAndEmailOtpHints() {
        assertEquals(
            FieldKind.OTP,
            FieldClassifier.classify(FieldEvidence(autofillHints = setOf("2faAppOTPCode"))).kind,
        )
        assertEquals(
            FieldKind.OTP,
            FieldClassifier.classify(FieldEvidence(autofillHints = setOf("emailOTPCode"))).kind,
        )
        assertEquals(
            FieldKind.OTP,
            FieldClassifier.classify(FieldEvidence(autofillHints = setOf("smsOTPCode"))).kind,
        )
        assertEquals(
            FieldKind.OTP,
            FieldClassifier.classify(FieldEvidence(htmlAttributes = mapOf("name" to "totp_secret"))).kind,
        )
    }

    @Test
    fun classifiesBrowserHtmlAttributesWithoutAndroidHints() {
        assertEquals(
            FieldKind.USERNAME,
            FieldClassifier.classify(FieldEvidence(htmlAttributes = mapOf("name" to "login_account"))).kind,
        )
        assertEquals(
            FieldKind.PASSWORD,
            FieldClassifier.classify(FieldEvidence(htmlAttributes = mapOf("type" to "password"))).kind,
        )
        assertEquals(
            FieldKind.EMAIL,
            FieldClassifier.classify(FieldEvidence(htmlAttributes = mapOf("aria-label" to "Email address"))).kind,
        )
    }

    @Test
    fun ignoresHiddenAndDisabledFields() {
        assertEquals(
            FieldKind.UNKNOWN,
            FieldClassifier.classify(FieldEvidence(autofillHints = setOf("password"), visible = false)).kind,
        )
        assertEquals(
            FieldKind.UNKNOWN,
            FieldClassifier.classify(FieldEvidence(autofillHints = setOf("username"), enabled = false)).kind,
        )
    }

    @Test
    fun conflictingTopLevelHintsAreUnknown() {
        val result = FieldClassifier.classify(
            FieldEvidence(autofillHints = setOf("username", "password")),
        )

        assertEquals(FieldKind.UNKNOWN, result.kind)
    }

    @Test
    fun passwordFlagsNeverBecomeUsername() {
        val result = FieldClassifier.classify(
            FieldEvidence(
                resourceId = "username",
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
            ),
        )

        assertEquals(FieldKind.PASSWORD, result.kind)
    }

    @Test
    fun selectsFocusedManualUnknownButCapsFields() {
        val fields = (0 until 12).map { index ->
            FieldCandidate(
                id = index,
                evidence = FieldEvidence(
                    resourceId = if (index == 0) "mystery" else "username_$index",
                    focused = index == 0,
                ),
            )
        }

        val selected = FieldClassifier.selectFields(fields, manualRequest = true)

        assertEquals(8, selected.size)
        assertEquals(0, selected.first().id)
        assertEquals(FieldKind.CUSTOM_TEXT, selected.first().kind)
    }

    @Test
    fun classifiesEveryExtendedAutofillRole() {
        val cases = mapOf(
            "identity_number" to FieldKind.ID_NUMBER,
            "api_key" to FieldKind.API_KEY,
            "api_secret" to FieldKind.API_SECRET,
            "server_host" to FieldKind.HOST,
            "server_port" to FieldKind.PORT,
            "database_name" to FieldKind.DATABASE,
            "wifi_ssid" to FieldKind.SSID,
            "wifi_password" to FieldKind.WIFI_PASSWORD,
            "recovery_answer" to FieldKind.RECOVERY_ANSWER,
            "custom_text" to FieldKind.CUSTOM_TEXT,
            "custom_secret" to FieldKind.CUSTOM_SECRET,
        )
        cases.forEach { (name, expected) ->
            assertEquals(expected, FieldClassifier.classify(FieldEvidence(htmlAttributes = mapOf("name" to name))).kind)
        }
    }
}
