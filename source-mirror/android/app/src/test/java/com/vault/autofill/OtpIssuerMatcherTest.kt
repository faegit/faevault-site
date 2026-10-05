package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OtpIssuerMatcherTest {

    private fun otp(issuer: String? = null, label: String? = null): Entry = Entry(
        id = "11111111-1111-4111-8111-111111111111",
        title = "OTP",
        secretType = SecretType.OTP,
        fields = buildMap {
            put("otp_secret", JsonPrimitive("JBSWY3DPEHPK3PXP"))
            if (issuer != null) put("issuer", JsonPrimitive(issuer))
            if (label != null) put("label", JsonPrimitive(label))
        },
    )

    @Test
    fun `matches when host label equals issuer`() {
        assertTrue(OtpIssuerMatcher.matches(otp(issuer = "example"), TargetOrigin.Web("example.com")))
        assertTrue(OtpIssuerMatcher.matches(otp(issuer = "github"), TargetOrigin.Web("login.github.com")))
    }

    @Test
    fun `matches dotted issuer as host suffix`() {
        assertTrue(OtpIssuerMatcher.matches(otp(issuer = "github.io"), TargetOrigin.Web("pages.github.io")))
    }

    @Test
    fun `matches android package label`() {
        assertTrue(OtpIssuerMatcher.matches(otp(issuer = "github"), TargetOrigin.AndroidPackage("com.github.android")))
    }

    @Test
    fun `rejects label as match key`() {
        assertFalse(OtpIssuerMatcher.matches(otp(label = "example"), TargetOrigin.Web("example.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "someco", label = "Outlook"), TargetOrigin.Web("outlook.com")))
    }

    @Test
    fun `rejects short issuer substring false positive`() {
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "go"), TargetOrigin.Web("google.com")))
    }

    @Test
    fun `rejects hyphenated phishing domain`() {
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "github"), TargetOrigin.Web("github-evil.com")))
    }

    @Test
    fun `rejects prefix squatting domain without delimiter`() {
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "github"), TargetOrigin.Web("githubevil.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "github"), TargetOrigin.AndroidPackage("com.evil.githubclone")))
    }

    @Test
    fun `rejects generic label as issuer`() {
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "com"), TargetOrigin.Web("example.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "io"), TargetOrigin.Web("example.io")))
    }

    @Test
    fun `rejects blank issuer and label`() {
        assertFalse(OtpIssuerMatcher.matches(otp(), TargetOrigin.Web("example.com")))
    }

    @Test
    fun `is case insensitive`() {
        assertTrue(OtpIssuerMatcher.matches(otp(issuer = "GitHub"), TargetOrigin.Web("GITHUB.COM")))
    }

    @Test
    fun `matches configured otp domains before issuer`() {
        val withDomains = otp(issuer = "elsewhere").copy(
            fields = otp(issuer = "elsewhere").fields + ("otp_domains" to JsonPrimitive("example.com,github.io")),
        )
        assertTrue(OtpIssuerMatcher.matches(withDomains, TargetOrigin.Web("example.com")))
        assertTrue(OtpIssuerMatcher.matches(withDomains, TargetOrigin.Web("login.example.com")))
        assertTrue(OtpIssuerMatcher.matches(withDomains, TargetOrigin.Web("pages.github.io")))
        assertFalse(OtpIssuerMatcher.matches(withDomains, TargetOrigin.Web("evil.org")))
        assertFalse(OtpIssuerMatcher.matches(withDomains, TargetOrigin.AndroidPackage("com.example.app")))
    }

    @Test
    fun `bare tld domain does not match every site`() {
        val withCom = otp(issuer = "elsewhere").copy(
            fields = otp(issuer = "elsewhere").fields + ("otp_domains" to JsonPrimitive("com")),
        )
        assertFalse(OtpIssuerMatcher.matches(withCom, TargetOrigin.Web("example.com")))
    }

    @Test
    fun `rejects issuer without matching domain label`() {
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "Microsoft"), TargetOrigin.Web("login.live.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "Apple"), TargetOrigin.Web("id.icloud.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "amazon"), TargetOrigin.Web("a.co")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "microsoft"), TargetOrigin.Web("evil-live.com")))
        assertFalse(OtpIssuerMatcher.matches(otp(issuer = "apple"), TargetOrigin.Web("evilcloud.com")))
    }
}