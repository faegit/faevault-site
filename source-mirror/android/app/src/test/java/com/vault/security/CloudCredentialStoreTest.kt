package com.vault.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

class CloudCredentialStoreTest {
    private val vaultId = "00112233-4455-6677-8899-aabbccddeeff"
    private val key = ByteArray(32) { it.toByte() }
    private val nonce = ByteArray(12) { (0x40 + it).toByte() }

    @Test
    fun `field encryption round-trips with fixed nonce`() {
        val plain = "用户:秘密".encodeToByteArray()
        val sealed = CloudCredentialCrypto.sealField(key, vaultId, "webdav", "password", 1, plain, nonce)
        assertArrayEquals(
            plain,
            CloudCredentialCrypto.openField(key, vaultId, "webdav", "password", 1, sealed),
        )
    }

    @Test
    fun `wrong vault provider field version and tampering fail closed`() {
        val sealed = CloudCredentialCrypto.sealField(
            key, vaultId, "webdav", "bearer_token", 1, "token".encodeToByteArray(), nonce,
        )
        val otherVault = "10112233-4455-6677-8899-aabbccddeeff"
        val attempts = listOf<() -> Unit>(
            { CloudCredentialCrypto.openField(key, otherVault, "webdav", "bearer_token", 1, sealed) },
            { CloudCredentialCrypto.openField(key, vaultId, "drive", "bearer_token", 1, sealed) },
            { CloudCredentialCrypto.openField(key, vaultId, "webdav", "cookie", 1, sealed) },
            { CloudCredentialCrypto.openField(key, vaultId, "webdav", "bearer_token", 2, sealed) },
            {
                val changed = sealed.copyOf()
                changed[changed.lastIndex] = (changed.last().toInt() xor 1).toByte()
                CloudCredentialCrypto.openField(key, vaultId, "webdav", "bearer_token", 1, changed)
            },
        )
        attempts.forEach { assertThrows(Exception::class.java) { it() } }
    }

    @Test
    fun `metadata source excludes sensitive fields`() {
        val source = listOf(
            File("app/src/main/java/com/vault/security/CloudCredentialStore.kt"),
            File("src/main/java/com/vault/security/CloudCredentialStore.kt"),
        ).first { it.isFile }.readText()
        val metadataBody = source.substringAfter("private data class Metadata(").substringBefore("\n    )")
        listOf("username", "password", "bearerToken", "cookie", "clientCertificate", "domain")
            .forEach { assertFalse("Metadata must not contain $it", metadataBody.contains(it)) }
    }
}
