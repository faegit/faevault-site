package com.vault

import com.vault.model.OtpUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OtpUtilsTest {
    @Test
    fun parseOtpAuthUriAcceptsTotpAndHotpOnly() {
        val totp = OtpUtils.parseOtpAuthUri(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        val hotp = OtpUtils.parseOtpAuthUri(
            "otpauth://hotp/Token?secret=JBSWY3DPEHPK3PXP&counter=7",
        )

        assertEquals("totp", totp?.first)
        assertEquals("hotp", hotp?.first)
    }

    @Test
    fun parseOtpAuthUriRejectsUnsupportedTypesAndMissingSecret() {
        assertNull(OtpUtils.parseOtpAuthUri("otpauth://steam/Steam:alice?secret=JBSWY3DPEHPK3PXP"))
        assertNull(OtpUtils.parseOtpAuthUri("otpauth://totp/GitHub:alice?issuer=GitHub"))
    }

    @Test
    fun parseOtpAuthUriRejectsInvalidParameters() {
        val base = "otpauth://totp/Account?secret=JBSWY3DPEHPK3PXP"

        assertNull(OtpUtils.parseOtpAuthUri("otpauth://totp/Account?secret=INVALID01"))
        assertNull(OtpUtils.parseOtpAuthUri("$base&algorithm=MD5"))
        assertNull(OtpUtils.parseOtpAuthUri("$base&digits=9"))
        assertNull(OtpUtils.parseOtpAuthUri("$base&period=0"))
        assertNull(OtpUtils.parseOtpAuthUri("otpauth://hotp/Account?secret=JBSWY3DPEHPK3PXP"))
        assertNull(OtpUtils.parseOtpAuthUri("otpauth://hotp/Account?secret=JBSWY3DPEHPK3PXP&counter=-1"))
    }

    @Test
    fun parseOtpAuthUriNormalizesDefaultsAndPadding() {
        val parsed = OtpUtils.parseOtpAuthUri(
            "otpauth://totp/Account?secret=jbswy3dpehpk3pxp%3D&algorithm=sha256",
        )

        assertEquals("JBSWY3DPEHPK3PXP", parsed?.second)
        assertEquals("SHA256", parsed?.third?.get("algorithm"))
        assertEquals("6", parsed?.third?.get("digits"))
        assertEquals("30", parsed?.third?.get("period"))
    }
}
