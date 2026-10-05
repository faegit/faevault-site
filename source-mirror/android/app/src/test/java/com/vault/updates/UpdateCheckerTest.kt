package com.vault.updates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {
    private fun release(url: String = "https://github.com/faegit/faevault-site/releases/download/android/v3.7.0/faevault-arm64-v8a.apk") = """
        {"tag_name":"android/v3.7.0","draft":false,"prerelease":false,
         "html_url":"https://github.com/faegit/faevault-site/releases/tag/android/v3.7.0","body":"changes",
         "assets":[{"name":"faevault-arm64-v8a.apk","browser_download_url":"$url"},
                   {"name":"faevault-universal.apk","browser_download_url":"https://github.com/faegit/faevault-site/releases/download/android/v3.7.0/faevault-universal.apk"}]}
    """.trimIndent()

    @Test fun `digest matches downloaded bytes and rejects corruption`() {
        val bytes = "apk bytes".encodeToByteArray()
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
        val expected = hash.joinToString("") { "%02x".format(it) }
        assertEquals(expected, parseAssetDigest("sha256:$expected"))
        verifyAssetDigest(hash, expected)
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            verifyAssetDigest(ByteArray(32), expected)
        }
    }

    @Test fun `redirect policy rejects downgrade and lookalike domains`() {
        requireTrustedDownloadUrl(java.net.URL("https://release-assets.githubusercontent.com/asset"))
        listOf("http://github.com/asset", "https://github.com.evil.test/asset", "https://user@github.com/asset",
            "https://github.com:444/asset").forEach { url ->
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { requireTrustedDownloadUrl(java.net.URL(url)) }
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `malformed asset digest is rejected`() {
        parseRelease(release().replace("\"name\":\"faevault-arm64-v8a.apk\"", "\"digest\":\"sha256:invalid\",\"name\":\"faevault-arm64-v8a.apk\""), "faevault-arm64-v8a.apk")
    }

    @Test fun `numeric versions compare correctly`() {
        assertTrue(isNewer("3.10.0", "3.9.9"))
        assertFalse(isNewer("3.6.2", "3.6.2"))
    }

    @Test fun `preferred ABI asset is selected`() {
        assertEquals("faevault-arm64-v8a.apk", parseRelease(release(), "faevault-arm64-v8a.apk").downloadUrl.substringAfterLast('/'))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `untrusted APK URL is rejected`() {
        parseRelease(release("https://example.com/app.apk"), "faevault-arm64-v8a.apk")
    }

    @Test fun `only android-prefixed releases are considered`() {
        val list = """
            [{"tag_name":"pc/v9.9.9","draft":false,"prerelease":false,"assets":[]},
             {"tag_name":"android/v4.6.1","draft":false,"prerelease":false,"assets":[]},
             {"tag_name":"android/v4.6.2","draft":false,"prerelease":false,"assets":[]},
             {"tag_name":"android/v5.0.0-rc1","draft":false,"prerelease":true,"assets":[]}]
        """.trimIndent()
        val picked = selectAndroidRelease(list) ?: error("expected a release")
        assertTrue(picked.contains("\"tag_name\":\"android/v4.6.2\""))
    }

    @Test fun `missing android release yields null`() {
        val onlyPc = """[{"tag_name":"pc/v4.1.0","draft":false,"prerelease":false,"assets":[]}]"""
        assertNull(selectAndroidRelease(onlyPc))
    }
}
