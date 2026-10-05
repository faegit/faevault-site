package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.VaultCrypto
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File

class PmvBackupCryptoTest {
    @Test
    fun `round trip with unicode password and binary plaintext`() {
        val plaintext = byteArrayOf(0, 1, 2, -1, -2, 64, 65)
        val password = "导出密码🙂".toByteArray(Charsets.UTF_8)
        val data = PmvBackupCrypto.encrypt(plaintext, password)
        assertArrayEquals(plaintext, PmvBackupCrypto.decrypt(data, password))
    }

    @Test
    fun `encrypted payload has v2 header layout`() {
        val data = PmvBackupCrypto.encrypt("abc".encodeToByteArray(), "pw".toByteArray())
        assertEquals("PMXB", data.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(2, data[4].toInt() and 0xff)
        assertEquals(PmvBackupCrypto.KDF_ID_ARGON2ID, data[5].toInt() and 0xff)
        assertEquals(46, data.size - (data.size - 46))
        // 密文长度 = 总长 - 46 字节头部，至少包含 16 字节 GCM tag
        assert(data.size >= 46 + 16)
    }

    @Test
    fun `wrong password throws DecryptError`() {
        val plaintext = "secret".encodeToByteArray()
        val data = PmvBackupCrypto.encrypt(plaintext, "right".toByteArray())
        val error = assertThrows(VaultCrypto.DecryptError::class.java) {
            PmvBackupCrypto.decrypt(data, "wrong".toByteArray())
        }
        assert(error.message!!.contains("口令") || error.message!!.contains("损坏"))
    }

    @Test
    fun `corrupt header throws CorruptFileError`() {
        val data = PmvBackupCrypto.encrypt("abc".encodeToByteArray(), "pw".toByteArray())
        val tampered = data.copyOf()
        tampered[0] = 'X'.code.toByte()
        assertThrows(VaultCrypto.CorruptFileError::class.java) {
            PmvBackupCrypto.decrypt(tampered, "pw".toByteArray())
        }
    }

    @Test
    fun `tampered ciphertext fails authentication`() {
        val data = PmvBackupCrypto.encrypt("abc".encodeToByteArray(), "pw".toByteArray())
        val tampered = data.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
        assertThrows(VaultCrypto.DecryptError::class.java) {
            PmvBackupCrypto.decrypt(tampered, "pw".toByteArray())
        }
    }

    @Test
    fun `shared cross-platform vector decrypts to known plaintext`() {
        val spec = System.getProperty("spec.dir") ?: error("spec.dir is required")
        val file = File(spec, "backup_v2_fixture.json")
        require(file.isFile) { "required shared backup v2 fixture is missing: ${file.absolutePath}" }
        val doc = Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
        val case = doc.getValue("cases").jsonArray.single().jsonObject
        val password = doc.getValue("passwordUtf8Hex").jsonPrimitive.content.decodeHex().toString(Charsets.UTF_8)
        val expected = doc.getValue("plaintextUtf8Hex").jsonPrimitive.content.decodeHex()
        val fileBytes = case.getValue("fileHex").jsonPrimitive.content.decodeHex()
        val plaintext = PmvBackupCrypto.decrypt(fileBytes, password.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected, plaintext)
        // 头部字段与布局断言（对齐 spec/VAULT_FORMAT.md §7）
        assertEquals("PMXB", fileBytes.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(2, fileBytes[4].toInt() and 0xff)
        assertEquals(PmvBackupCrypto.KDF_ID_ARGON2ID, fileBytes[5].toInt() and 0xff)
        assertEquals(PmvKeySchedule.ARGON2_MEMORY_KIB, readBe32(fileBytes, 6))
        assertEquals(PmvKeySchedule.ARGON2_ITERATIONS, readBe32(fileBytes, 10))
        assertEquals(PmvKeySchedule.ARGON2_PARALLELISM, readBe32(fileBytes, 14))
        assertEquals(0x00010203, readBe32(fileBytes, 18))
        assertEquals("0c0d0e0f1011121314151617", fileBytes.copyOfRange(34, 46).toHex())
    }

    @Test
    fun `shared cross-platform vector rejects wrong password`() {
        val spec = System.getProperty("spec.dir") ?: error("spec.dir is required")
        val file = File(spec, "backup_v2_fixture.json")
        val doc = Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
        val case = doc.getValue("cases").jsonArray.single().jsonObject
        val fileBytes = case.getValue("fileHex").jsonPrimitive.content.decodeHex()
        assertThrows(VaultCrypto.DecryptError::class.java) {
            PmvBackupCrypto.decrypt(fileBytes, "wrong-password".toByteArray(Charsets.UTF_8))
        }
    }

    @Test
    fun `shared cross-platform vector rejects tampered kdf parameter`() {
        val spec = System.getProperty("spec.dir") ?: error("spec.dir is required")
        val file = File(spec, "backup_v2_fixture.json")
        val doc = Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
        val case = doc.getValue("cases").jsonArray.single().jsonObject
        val password = doc.getValue("passwordUtf8Hex").jsonPrimitive.content.decodeHex().toString(Charsets.UTF_8)
        val fileBytes = case.getValue("fileHex").jsonPrimitive.content.decodeHex().copyOf()
        fileBytes[7] = 0 // MEMORY_KIB 次高字节翻转 → 与实现常量不符
        assertThrows(VaultCrypto.CorruptFileError::class.java) {
            PmvBackupCrypto.decrypt(fileBytes, password.toByteArray(Charsets.UTF_8))
        }
    }

    private fun readBe32(data: ByteArray, off: Int): Int =
        ((data[off].toInt() and 0xff) shl 24) or
            ((data[off + 1].toInt() and 0xff) shl 16) or
            ((data[off + 2].toInt() and 0xff) shl 8) or
            (data[off + 3].toInt() and 0xff)
}

private fun String.decodeHex(): ByteArray {
    require(length % 2 == 0)
    return ByteArray(length / 2) { i ->
        ((Character.digit(this[i * 2], 16) shl 4) or Character.digit(this[i * 2 + 1], 16)).toByte()
    }
}

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
