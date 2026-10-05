package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class PackageIdentityResolverTest {
    @Test
    fun computesStableLowercaseSha256() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            PackageIdentityResolver.sha256("abc".encodeToByteArray()),
        )
    }

    @Test
    fun extractsTrustedSignerForExactBrowserPackage() {
        val chromeCertificate = (0 until 32).joinToString(":") { "AA" }
        val firefoxCertificate = (0 until 32).joinToString(":") { "BB" }
        val allowlist = """{
            "apps": [
                {"type":"android","info":{"package_name":"com.android.chrome","signatures":[
                    {"build":"release","cert_fingerprint_sha256":"$chromeCertificate"}
                ]}},
                {"type":"android","info":{"package_name":"org.mozilla.firefox","signatures":[
                    {"build":"release","cert_fingerprint_sha256":"$firefoxCertificate"}
                ]}}
            ]
        }"""

        assertEquals(
            setOf("aa".repeat(32)),
            BrowserTrustAllowlist.signingCertificateSha256(allowlist, "com.android.chrome"),
        )
        assertEquals(
            emptySet<String>(),
            BrowserTrustAllowlist.signingCertificateSha256(allowlist, "com.chrome.beta"),
        )
    }
}
