package com.vault.storage

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID

class PmvCompressionTest {
    private val vector by lazy {
        val file = File(requireNotNull(System.getProperty("spec.dir")), "interop/pmv_next/v1/compression.json")
        Json.parseToJsonElement(file.readText()).jsonObject["cases"]!!.jsonArray.single().jsonObject
    }

    @Test
    fun `shared zstd frame is byte exact and round trips`() {
        val input = vector["inputs"]!!.jsonObject
        val expected = vector["expected"]!!.jsonObject
        val unit = input["unitUtf8"]!!.jsonPrimitive.content.encodeToByteArray()
        val repeat = input["repeat"]!!.jsonPrimitive.content.toInt()
        val plain = ByteArray(unit.size * repeat) { unit[it % unit.size] }
        val compressed = PmvCompression.compressZstdFrame(plain)
        assertEquals(expected["plainSize"]!!.jsonPrimitive.content.toLong(), plain.size.toLong())
        assertEquals(expected["compressedHex"]!!.jsonPrimitive.content, compressed.toHex())
        assertEquals(plain.size.toLong(), PmvCompression.validateSingleZstdFrame(compressed))
        assertArrayEquals(plain, PmvCompression.decode(1, compressed, plain.size.toLong()))
    }

    @Test
    fun `adaptive policy and strict frame rejection`() {
        val compressible = ByteArray(8192) { 'A'.code.toByte() }
        val digest = MessageDigest.getInstance("SHA-256")
        val incompressible = ByteArray(4096)
        repeat(128) { index ->
            val block = digest.digest(byteArrayOf(
                (index ushr 24).toByte(), (index ushr 16).toByte(),
                (index ushr 8).toByte(), index.toByte(),
            ))
            block.copyInto(incompressible, index * block.size)
        }
        assertEquals(PmvCompression.CODEC_ZSTD_FRAME_V1, PmvCompression.chooseCodec(compressible))
        assertEquals(PmvCompression.CODEC_NONE, PmvCompression.chooseCodec(incompressible))
        val encoded = PmvCompression.compressZstdFrame(compressible)
        listOf(encoded.copyOf(encoded.size - 1), encoded + byteArrayOf(0), encoded + encoded).forEach {
            expectIllegalArgument { PmvCompression.decode(1, it, compressible.size.toLong()) }
        }
        expectIllegalArgument { PmvCompression.decode(1, encoded, compressible.size - 1L) }
        expectIllegalArgument { PmvCompression.decode(9, encoded, compressible.size.toLong()) }
    }

    @Test
    fun `block AEAD binds codec and uncompressed size`() {
        val vaultId = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val objectId = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        val key = ByteArray(32) { it.toByte() }
        val unit = "compress me".encodeToByteArray()
        val plain = ByteArray(unit.size * 4096) { unit[it % unit.size] }
        val block = PmvBlockCrypto.seal(
            vaultId, key, PmvContainerFormat.BlockType.ATTACHMENT_CHUNK,
            objectId, 3, plain, chunkIndex = 0,
            codecId = PmvCompression.CODEC_ZSTD_FRAME_V1,
        )
        assertEquals(plain.size.toLong(), block.header.plainSize)
        assertTrue(block.header.cipherSize < plain.size)
        assertArrayEquals(plain, PmvBlockCrypto.open(vaultId, key, block))
        val tampered = block.copy(header = block.header.copy(codecId = PmvCompression.CODEC_NONE))
        expectFailure { PmvBlockCrypto.open(vaultId, key, tampered) }
    }

    private fun expectIllegalArgument(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected failure")
        } catch (_: Exception) {
            // expected
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
