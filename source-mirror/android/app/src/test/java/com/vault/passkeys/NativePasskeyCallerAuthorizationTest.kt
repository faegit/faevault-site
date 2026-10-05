package com.vault.passkeys

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class NativePasskeyCallerAuthorizationTest {
    @Test
    fun `native passkey caller must be linked to the relying party`() = runBlocking {
        val certificate = "native-app-certificate".toByteArray()
        var checkedRpId = ""
        var checkedPackage = ""
        var checkedFingerprints = emptySet<String>()

        assertThrows(SecurityException::class.java) {
            runBlocking {
                authorizeNativePasskeyCaller(
                    rpId = "example.com",
                    packageName = "com.example.app",
                    signerCertificates = listOf(certificate),
                ) { rpId, packageName, fingerprints ->
                    checkedRpId = rpId
                    checkedPackage = packageName
                    checkedFingerprints = fingerprints
                    false
                }
            }
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(certificate)
        assertEquals("example.com", checkedRpId)
        assertEquals("com.example.app", checkedPackage)
        assertEquals(setOf(digest.toFingerprint()), checkedFingerprints)
    }

    @Test
    fun `authorized native caller uses its APK certificate origin`() = runBlocking {
        val certificate = "authorized-certificate".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate)

        val caller = authorizeNativePasskeyCaller(
            rpId = "example.com",
            packageName = "com.example.app",
            signerCertificates = listOf(certificate),
        ) { _, _, fingerprints -> fingerprints == setOf(digest.toFingerprint()) }

        assertEquals(
            "android:apk-key-hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest),
            caller.origin,
        )
        assertTrue(!caller.privilegedBrowser)
    }

    @Test
    fun `password caller does not require a web relying-party association`() = runBlocking {
        var assetLinkChecks = 0

        authorizeNativePasskeyCaller(
            rpId = "",
            packageName = "com.example.app",
            signerCertificates = listOf("certificate".toByteArray()),
        ) { _, _, _ ->
            assetLinkChecks++
            false
        }

        assertEquals(0, assetLinkChecks)
    }

    private fun ByteArray.toFingerprint(): String =
        joinToString(":") { "%02X".format(it.toInt() and 0xff) }
}
