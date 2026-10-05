package com.vault

import com.vault.storage.MediaCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File

class MediaCryptoTest {

    private val dek = ByteArray(32) { it.toByte() }

    @Test
    fun `mediaKey matches PC side derivation vector`() {
        MediaCrypto.setContext("vault-x", dek)
        // 与 PC core/media_files.py 的 HKDF-SHA256(DEK, info=vault-media-v1) 一致
        val expected = "dc5e093265b9c26187f012018646f186fdc5def3c35d2c4f830afef3c959b5cc"
        assertEquals(expected, MediaCrypto.mediaKey().joinToString("") { "%02x".format(it) })
        MediaCrypto.clear()
    }

    @Test
    fun `encrypt then decrypt roundtrips`() {
        MediaCrypto.setContext("vault-x", dek)
        val plain = "sensitive-image".encodeToByteArray()
        val ct = MediaCrypto.encrypt(plain)
        assertTrue(MediaCrypto.isEncrypted(ct))
        assertFalse(plain.contentEquals(ct))
        assertArrayEquals(plain, MediaCrypto.decrypt(ct))
        MediaCrypto.clear()
    }

    @Test
    fun `stream encryption roundtrips data larger than the copy buffer`() {
        MediaCrypto.setContext("vault-x", dek)
        val plain = ByteArray(3 * 1024 * 1024 + 17) { (it * 31).toByte() }
        val encrypted = ByteArrayOutputStream()

        MediaCrypto.encryptStream(ByteArrayInputStream(plain), encrypted)

        assertTrue(MediaCrypto.isEncrypted(encrypted.toByteArray()))
        val restored = MediaCrypto.decryptStream(ByteArrayInputStream(encrypted.toByteArray())).use { it.readBytes() }
        assertArrayEquals(plain, restored)
        MediaCrypto.clear()
    }

    @Test
    fun `decryptable returns false for foreign key or plaintext`() {
        MediaCrypto.setContext("vault-x", dek)
        val ct = MediaCrypto.encrypt("data".encodeToByteArray())
        assertTrue(MediaCrypto.decryptable(ct))
        assertFalse(MediaCrypto.decryptable("plaintext".encodeToByteArray()))
        MediaCrypto.clear()
        MediaCrypto.setContext("vault-y", ByteArray(32) { (it + 1).toByte() })
        assertFalse(MediaCrypto.decryptable(ct)) // 不同库密钥 → 不可解
        MediaCrypto.clear()
    }

    @Test
    fun `file decryptability check streams and rejects tampering`() {
        MediaCrypto.setContext("vault-x", dek)
        val file = File.createTempFile("media-crypto-", ".vmed")
        try {
            file.outputStream().use { output ->
                MediaCrypto.encryptStream(ByteArrayInputStream(ByteArray(2 * 1024 * 1024) { it.toByte() }), output)
            }
            assertTrue(MediaCrypto.decryptable(file))

            file.writeBytes(file.readBytes().also { it[it.lastIndex] = (it.last() + 1).toByte() })
            assertFalse(MediaCrypto.decryptable(file))
        } finally {
            file.delete()
            MediaCrypto.clear()
        }
    }

    @Test
    fun `legacy plaintext passes through decrypt unchanged`() {
        MediaCrypto.setContext("vault-x", dek)
        val legacy = "not-encrypted".encodeToByteArray()
        assertFalse(MediaCrypto.isEncrypted(legacy))
        assertArrayEquals(legacy, MediaCrypto.decrypt(legacy))
        MediaCrypto.clear()
    }

    @Test
    fun `requires context`() {
        MediaCrypto.clear()
        runCatching { MediaCrypto.mediaKey() }.exceptionOrNull()?.let {
            assertTrue(it.message?.contains("媒体未解锁") == true)
        }
    }
}
