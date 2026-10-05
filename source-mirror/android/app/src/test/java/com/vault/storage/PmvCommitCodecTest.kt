package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

class PmvCommitCodecTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val commitId = UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f")
    private val parentId = UUID.fromString("ffeeddcc-bbaa-9988-7766-554433221100")
    private val seed = ByteArray(32) { it.toByte() }
    private val digest = ByteArray(32) { (0xa0 + it).toByte() }

    @Test
    fun `round trips fixed layout and verifies trusted identity`() {
        val commit = signed(parentId)
        val raw = PmvCommitCodec.encode(commit)

        assertEquals(224, raw.size)
        assertArrayEquals("PMVC".encodeToByteArray(), raw.copyOfRange(0, 4))
        assertEquals(1, ByteBuffer.wrap(raw, 4, 4).order(ByteOrder.BIG_ENDIAN).int)
        assertEquals(224, ByteBuffer.wrap(raw, 8, 4).order(ByteOrder.BIG_ENDIAN).int)
        assertEquals(1, raw[48].toInt())
        assertEquals(7, ByteBuffer.wrap(raw, 72, 8).order(ByteOrder.BIG_ENDIAN).long)
        assertEquals(16_384L, ByteBuffer.wrap(raw, 80, 8).order(ByteOrder.BIG_ENDIAN).long)
        assertEquals(16_512L, ByteBuffer.wrap(raw, 88, 8).order(ByteOrder.BIG_ENDIAN).long)

        val decoded = PmvCommitCodec.decodeAndVerify(raw, vaultId, digest, commit.signingPublicKey)
        assertEquals(commit, decoded)
        assertEquals(parentId, decoded.parentCommitId)
        assertTrue(PmvCommitCodec.verifySignature(decoded))
    }

    @Test
    fun `canonical signing bytes have frozen cross-platform order`() {
        val canonical = PmvCommitCodec.canonicalSigningBytes(vaultId, commitId, null, 7, digest)
        val domain = "pmv/v1/commit\u0000".encodeToByteArray()

        assertArrayEquals(domain, canonical.copyOfRange(0, domain.size))
        assertArrayEquals(uuidBytes(vaultId), canonical.copyOfRange(domain.size, domain.size + 16))
        assertArrayEquals(uuidBytes(commitId), canonical.copyOfRange(domain.size + 16, domain.size + 32))
        assertEquals(0, canonical[domain.size + 32].toInt())
        assertArrayEquals(ByteArray(16), canonical.copyOfRange(domain.size + 33, domain.size + 49))
        assertEquals(7, ByteBuffer.wrap(canonical, domain.size + 49, 8).order(ByteOrder.BIG_ENDIAN).long)
        assertArrayEquals(digest, canonical.copyOfRange(domain.size + 57, canonical.size))
    }

    @Test
    fun `parent absent is encoded canonically`() {
        val raw = PmvCommitCodec.encode(signed(null))

        assertEquals(0, raw[48].toInt())
        assertArrayEquals(ByteArray(7), raw.copyOfRange(49, 56))
        assertArrayEquals(ByteArray(16), raw.copyOfRange(56, 72))
        assertNull(PmvCommitCodec.decode(raw).parentCommitId)
    }

    @Test
    fun `rejects signature root identity and reserved field tampering`() {
        val commit = signed(parentId)
        val raw = PmvCommitCodec.encode(commit)

        val signatureTampered = raw.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) { PmvCommitCodec.decode(signatureTampered) }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.decodeAndVerify(raw, vaultId, ByteArray(32), commit.signingPublicKey)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.decodeAndVerify(raw, UUID.randomUUID(), digest, commit.signingPublicKey)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.decodeAndVerify(raw, vaultId, digest, ByteArray(32))
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.decode(raw.copyOf().also { it[49] = 1 })
        }
    }

    @Test
    fun `rejects noncanonical parent and invalid index bounds`() {
        val raw = PmvCommitCodec.encode(signed(null))
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.decode(raw.copyOf().also { it[56] = 1 })
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.sign(vaultId, commitId, null, 7, 1, 16_512, digest, seed)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvCommitCodec.sign(vaultId, commitId, null, 7, 16_384, 1, digest, seed)
        }
    }

    @Test
    fun `root digest hashes canonical root representation`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            PmvCommitCodec.rootDigest("abc".encodeToByteArray()).toHex(),
        )
    }

    private fun signed(parent: UUID?) = PmvCommitCodec.sign(
        vaultId = vaultId,
        commitId = commitId,
        parentCommitId = parent,
        revision = 7,
        indexRootOffset = 16_384,
        indexRootLength = 16_512,
        rootDigest = digest,
        privateSeed = seed,
    )

    private fun uuidBytes(value: UUID): ByteArray = ByteBuffer.allocate(16)
        .order(ByteOrder.BIG_ENDIAN)
        .putLong(value.mostSignificantBits)
        .putLong(value.leastSignificantBits)
        .array()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
