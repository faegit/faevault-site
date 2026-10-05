package com.vault

import com.vault.passkeys.PrivilegedAppAllowlistValidator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

class PrivilegedAppAllowlistTest {
    @Test
    fun bundledOfficialAllowlistIsValidAndContainsMajorBrowsers() {
        val file = File("src/main/assets/passkey_privileged_apps.json")
        val raw = file.readText()

        assertEquals(raw, PrivilegedAppAllowlistValidator.requireValid(raw))
        listOf(
            "com.android.chrome",
            "com.microsoft.emmx",
            "org.mozilla.firefox",
            "com.brave.browser",
            "com.opera.browser",
        ).forEach { assert(raw.contains("\"package_name\": \"$it\"")) }
    }

    @Test
    fun validatorRejectsDuplicatePackagesAndMalformedFingerprints() {
        val app =
            """{"type":"android","info":{"package_name":"com.example.browser","signatures":[{"build":"release","cert_fingerprint_sha256":"${fingerprint("AA")}"}]}}"""
        assertThrows(IllegalArgumentException::class.java) {
            PrivilegedAppAllowlistValidator.requireValid("""{"apps":[$app,$app]}""")
        }
        assertThrows(IllegalArgumentException::class.java) {
            PrivilegedAppAllowlistValidator.requireValid(
                """{"apps":[{"type":"android","info":{"package_name":"com.example.browser","signatures":[{"build":"release","cert_fingerprint_sha256":"not-a-fingerprint"}]}}]}""",
            )
        }
    }

    @Test
    fun validatorRejectsNonAndroidEntriesAndOversizedDocuments() {
        assertThrows(IllegalArgumentException::class.java) {
            PrivilegedAppAllowlistValidator.requireValid(
                """{"apps":[{"type":"web","info":{"package_name":"com.example.browser","signatures":[{"build":"release","cert_fingerprint_sha256":"${fingerprint("AA")}"}]}}]}""",
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            PrivilegedAppAllowlistValidator.requireValid(
                """{"apps":[],"padding":"${"x".repeat(300_000)}"}""",
            )
        }
    }

    private fun fingerprint(byte: String): String = List(32) { byte }.joinToString(":")
}
