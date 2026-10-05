package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.OtpUtils
import com.vault.model.SecretType
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OtpAutofillTest {
    private fun otpEntry(
        secret: String = "JBSWY3DPEHPK3PXP",
        extra: Map<String, JsonPrimitive> = emptyMap(),
    ) = Entry(
        id = "otp",
        title = "GitHub",
        username = "alice",
        secretType = SecretType.OTP,
        fields = mapOf("otp_secret" to JsonPrimitive(secret)) + extra,
    )

    @Test
    fun `totp with enough remaining fills immediately without waiting`() = runBlocking {
        var fakeNow = 10L
        var slept = 0L
        val code = OtpAutofill.computeFillCode(
            otpEntry(),
            now = { fakeNow },
            sleep = { ms -> slept = ms },
        )
        assertEquals(OtpUtils.generateTOTP("JBSWY3DPEHPK3PXP", 0), code)
        assertEquals(0L, slept)
    }

    @Test
    fun `totp with less than threshold waits for the next window`() = runBlocking {
        var fakeNow = 28L
        var slept = 0L
        val code = OtpAutofill.computeFillCode(
            otpEntry(),
            now = { fakeNow },
            sleep = { ms -> slept = ms; fakeNow += ms / 1000 },
        )
        assertEquals(3_000L, slept)
        assertEquals(OtpUtils.generateTOTP("JBSWY3DPEHPK3PXP", 31 / 30), code)
    }

    @Test
    fun `totp with too short period is never filled`() = runBlocking {
        var slept = 0L
        val code = OtpAutofill.computeFillCode(
            otpEntry(extra = mapOf("period" to JsonPrimitive("3"))),
            now = { 0L },
            sleep = { ms -> slept = ms },
        )
        assertNull(code)
        assertEquals(0L, slept)
    }

    @Test
    fun `hotp fills immediately regardless of window`() = runBlocking {
        var slept = 0L
        val code = OtpAutofill.computeFillCode(
            otpEntry(extra = mapOf("type" to JsonPrimitive("hotp"), "counter" to JsonPrimitive("5"))),
            now = { 0L },
            sleep = { ms -> slept = ms },
        )
        assertEquals(OtpUtils.generateHOTP("JBSWY3DPEHPK3PXP", 5), code)
        assertEquals(0L, slept)
    }

    @Test
    fun `merge candidates dedups bound otp entries`() {
        val loginA = Entry(id = "a", title = "A", username = "u", password = "p", secretType = SecretType.LOGIN)
        val loginB = loginA.copy(id = "b", fields = mapOf("bound_otp_id" to JsonPrimitive("x")))
        val otpX = Entry(id = "x", title = "X", secretType = SecretType.OTP)
        val otpY = Entry(id = "y", title = "Y", secretType = SecretType.OTP)
        val loginBEmbedded = loginA.copy(id = "c", fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")))

        assertEquals(
            listOf("a", "b", "c", "y"),
            OtpAutofill.mergeCandidates(
                listOf(loginA, loginB, loginBEmbedded),
                listOf(otpX, otpY),
            ).map { it.id },
        )
    }

    @Test
    fun `otp fill values segment by digit count`() {
        assertEquals(listOf("123456"), OtpAutofill.otpFillValues("123456", 1))
        assertEquals(listOf("1", "2", "3", "4", "5", "6"), OtpAutofill.otpFillValues("123456", 6))
        assertEquals(listOf("12", "34", "56"), OtpAutofill.otpFillValues("123456", 3))
        assertEquals(listOf("12", "34", "56", "78"), OtpAutofill.otpFillValues("12345678", 4))
        assertEquals(listOf("123456", "", "", ""), OtpAutofill.otpFillValues("123456", 4))
        assertEquals(listOf("", "", "", "", "", ""), OtpAutofill.otpFillValues(null, 6))
        assertEquals(listOf("", ""), OtpAutofill.otpFillValues("", 2))
    }

    @Test
    fun `entry without otp module returns null`() = runBlocking {
        val code = OtpAutofill.computeFillCode(
            Entry(id = "plain", title = "plain", secretType = SecretType.LOGIN, username = "a", password = "b"),
            now = { 0L },
            sleep = { _ -> },
        )
        assertNull(code)
    }
}