package com.vault.storage

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/** Fixed-width PMV v1 Commit plaintext and Ed25519 authentication. */
object PmvCommitCodec {
    const val PLAIN_SIZE = 224
    const val ROOT_DIGEST_SIZE = 32
    const val PUBLIC_KEY_SIZE = 32
    const val PRIVATE_SEED_SIZE = 32
    const val SIGNATURE_SIZE = 64

    private const val VERSION = 1
    private const val HEADER_FLAGS = 0
    private const val PARENT_RESERVED_SIZE = 7
    private val MAGIC = "PMVC".encodeToByteArray()
    private val SIGNING_DOMAIN = "pmv/v1/commit\u0000".encodeToByteArray()
    private val ZERO_UUID = UUID(0, 0)
    private val DATA_START = PmvContainerFormat.DATA_START
    private val MIN_INDEX_ROOT_LENGTH =
        (PmvContainerFormat.BLOCK_HEADER_SIZE + PmvContainerFormat.GCM_TAG_SIZE).toLong()
    private val MAX_INDEX_ROOT_LENGTH =
        (PmvContainerFormat.BLOCK_HEADER_SIZE + PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE).toLong()

    data class Commit(
        val vaultId: UUID,
        val commitId: UUID,
        val parentCommitId: UUID?,
        val revision: Long,
        val indexRootOffset: Long,
        val indexRootLength: Long,
        val rootDigest: ByteArray,
        val signingPublicKey: ByteArray,
        val signature: ByteArray,
    ) {
        init {
            require(vaultId != ZERO_UUID) { "Commit vault UUID 不能为零" }
            require(commitId != ZERO_UUID) { "Commit UUID 不能为零" }
            require(parentCommitId == null || parentCommitId != ZERO_UUID) { "父 Commit UUID 不能为零" }
            require(parentCommitId != commitId) { "父 Commit UUID 不能等于当前 Commit" }
            require(revision >= 0) { "Commit revision 不能为负数" }
            require(indexRootOffset >= DATA_START) { "Commit Index Root 偏移无效" }
            require(indexRootLength in MIN_INDEX_ROOT_LENGTH..MAX_INDEX_ROOT_LENGTH) {
                "Commit Index Root 长度无效"
            }
            require(indexRootOffset <= Long.MAX_VALUE - indexRootLength) { "Commit Index Root 范围溢出" }
            require(rootDigest.size == ROOT_DIGEST_SIZE) { "Commit root digest 必须为 32 字节" }
            require(signingPublicKey.size == PUBLIC_KEY_SIZE) { "Ed25519 公钥必须为 32 字节" }
            require(signature.size == SIGNATURE_SIZE) { "Ed25519 签名必须为 64 字节" }
        }

        override fun equals(other: Any?): Boolean = other is Commit &&
            vaultId == other.vaultId && commitId == other.commitId &&
            parentCommitId == other.parentCommitId && revision == other.revision &&
            indexRootOffset == other.indexRootOffset && indexRootLength == other.indexRootLength &&
            rootDigest.contentEquals(other.rootDigest) &&
            signingPublicKey.contentEquals(other.signingPublicKey) && signature.contentEquals(other.signature)

        override fun hashCode(): Int {
            var result = vaultId.hashCode()
            result = 31 * result + commitId.hashCode()
            result = 31 * result + (parentCommitId?.hashCode() ?: 0)
            result = 31 * result + revision.hashCode()
            result = 31 * result + indexRootOffset.hashCode()
            result = 31 * result + indexRootLength.hashCode()
            result = 31 * result + rootDigest.contentHashCode()
            result = 31 * result + signingPublicKey.contentHashCode()
            return 31 * result + signature.contentHashCode()
        }
    }

    /** Creates a Commit and signs the frozen cross-platform canonical representation. */
    fun sign(
        vaultId: UUID,
        commitId: UUID,
        parentCommitId: UUID?,
        revision: Long,
        indexRootOffset: Long,
        indexRootLength: Long,
        rootDigest: ByteArray,
        privateSeed: ByteArray,
    ): Commit {
        require(privateSeed.size == PRIVATE_SEED_SIZE) { "Ed25519 私钥种子必须为 32 字节" }
        require(rootDigest.size == ROOT_DIGEST_SIZE) { "Commit root digest 必须为 32 字节" }
        val privateKey = Ed25519PrivateKeyParameters(privateSeed, 0)
        val publicKey = privateKey.generatePublicKey().encoded
        val canonical = canonicalSigningBytes(
            vaultId,
            commitId,
            parentCommitId,
            revision,
            rootDigest,
        )
        val signature = Ed25519Signer().run {
            init(true, privateKey)
            update(canonical, 0, canonical.size)
            generateSignature()
        }
        canonical.fill(0)
        return Commit(
            vaultId = vaultId,
            commitId = commitId,
            parentCommitId = parentCommitId,
            revision = revision,
            indexRootOffset = indexRootOffset,
            indexRootLength = indexRootLength,
            rootDigest = rootDigest.copyOf(),
            signingPublicKey = publicKey,
            signature = signature,
        )
    }

    /** Encodes only a structurally valid Commit carrying a valid self-signature. */
    fun encode(commit: Commit): ByteArray {
        require(verifySignature(commit)) { "Commit Ed25519 签名无效" }
        return ByteBuffer.allocate(PLAIN_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(VERSION)
            putInt(PLAIN_SIZE)
            putInt(HEADER_FLAGS)
            putUuid(commit.vaultId)
            putUuid(commit.commitId)
            put((if (commit.parentCommitId == null) 0 else 1).toByte())
            put(ByteArray(PARENT_RESERVED_SIZE))
            putUuid(commit.parentCommitId ?: ZERO_UUID)
            putLong(commit.revision)
            putLong(commit.indexRootOffset)
            putLong(commit.indexRootLength)
            put(commit.rootDigest)
            put(commit.signingPublicKey)
            put(commit.signature)
        }.array()
    }

    /** Strictly parses the fixed 224-byte plaintext and verifies its embedded signature. */
    fun decode(raw: ByteArray): Commit {
        require(raw.size == PLAIN_SIZE) { "Commit 明文长度无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size).also(input::get)
        require(magic.contentEquals(MAGIC)) { "Commit magic 无效" }
        require(input.int == VERSION) { "Commit 版本无效" }
        require(input.int == PLAIN_SIZE) { "Commit 声明长度无效" }
        require(input.int == HEADER_FLAGS) { "Commit Header 保留字段非零" }
        val vaultId = input.getUuid()
        val commitId = input.getUuid()
        val parentPresent = input.get().toInt()
        require(parentPresent == 0 || parentPresent == 1) { "Commit parent_present 无效" }
        repeat(PARENT_RESERVED_SIZE) {
            require(input.get() == 0.toByte()) { "Commit parent 保留字段非零" }
        }
        val encodedParentId = input.getUuid()
        val parentId = if (parentPresent == 1) {
            require(encodedParentId != ZERO_UUID) { "Commit 声明父提交但 UUID 为零" }
            encodedParentId
        } else {
            require(encodedParentId == ZERO_UUID) { "Commit 未声明父提交但 UUID 非零" }
            null
        }
        val commit = Commit(
            vaultId = vaultId,
            commitId = commitId,
            parentCommitId = parentId,
            revision = input.long,
            indexRootOffset = input.long,
            indexRootLength = input.long,
            rootDigest = ByteArray(ROOT_DIGEST_SIZE).also(input::get),
            signingPublicKey = ByteArray(PUBLIC_KEY_SIZE).also(input::get),
            signature = ByteArray(SIGNATURE_SIZE).also(input::get),
        )
        check(!input.hasRemaining()) { "Commit 解码未消费完整明文" }
        require(verifySignature(commit)) { "Commit Ed25519 签名无效" }
        return commit
    }

    /**
     * Verifies the Commit against the reader's trusted Vault identity and its independently
     * calculated root digest. This prevents accepting an attacker-supplied replacement public key.
     */
    fun decodeAndVerify(
        raw: ByteArray,
        expectedVaultId: UUID,
        expectedRootDigest: ByteArray,
        trustedSigningPublicKey: ByteArray,
    ): Commit {
        require(expectedVaultId != ZERO_UUID) { "预期 Vault UUID 不能为零" }
        require(expectedRootDigest.size == ROOT_DIGEST_SIZE) { "预期 root digest 必须为 32 字节" }
        require(trustedSigningPublicKey.size == PUBLIC_KEY_SIZE) { "受信 Ed25519 公钥必须为 32 字节" }
        val commit = decode(raw)
        require(commit.vaultId == expectedVaultId) { "Commit 属于其他 Vault" }
        require(MessageDigest.isEqual(commit.rootDigest, expectedRootDigest)) { "Commit root digest 不匹配" }
        require(MessageDigest.isEqual(commit.signingPublicKey, trustedSigningPublicKey)) {
            "Commit 签名公钥与 Vault Identity 不匹配"
        }
        return commit
    }

    fun verifySignature(commit: Commit): Boolean {
        val canonical = canonicalSigningBytes(
            commit.vaultId,
            commit.commitId,
            commit.parentCommitId,
            commit.revision,
            commit.rootDigest,
        )
        return try {
            Ed25519Signer().run {
                init(false, Ed25519PublicKeyParameters(commit.signingPublicKey, 0))
                update(canonical, 0, canonical.size)
                verifySignature(commit.signature)
            }
        } catch (_: RuntimeException) {
            false
        } finally {
            canonical.fill(0)
        }
    }

    /** SHA-256 over the agreed canonical root representation. */
    fun rootDigest(canonicalRootRepresentation: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(canonicalRootRepresentation)

    /**
     * ASCII `pmv/v1/commit\0` || vault UUID || commit UUID || parent flag || parent UUID/zero ||
     * revision u64be || root digest.
     */
    fun canonicalSigningBytes(
        vaultId: UUID,
        commitId: UUID,
        parentCommitId: UUID?,
        revision: Long,
        rootDigest: ByteArray,
    ): ByteArray {
        require(vaultId != ZERO_UUID) { "Commit vault UUID 不能为零" }
        require(commitId != ZERO_UUID) { "Commit UUID 不能为零" }
        require(parentCommitId == null || parentCommitId != ZERO_UUID) { "父 Commit UUID 不能为零" }
        require(parentCommitId != commitId) { "父 Commit UUID 不能等于当前 Commit" }
        require(revision >= 0) { "Commit revision 不能为负数" }
        require(rootDigest.size == ROOT_DIGEST_SIZE) { "Commit root digest 必须为 32 字节" }
        return ByteBuffer.allocate(SIGNING_DOMAIN.size + 16 + 16 + 1 + 16 + 8 + ROOT_DIGEST_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .apply {
                put(SIGNING_DOMAIN)
                putUuid(vaultId)
                putUuid(commitId)
                put((if (parentCommitId == null) 0 else 1).toByte())
                putUuid(parentCommitId ?: ZERO_UUID)
                putLong(revision)
                put(rootDigest)
            }.array()
    }

    private fun ByteBuffer.putUuid(value: UUID) {
        putLong(value.mostSignificantBits)
        putLong(value.leastSignificantBits)
    }

    private fun ByteBuffer.getUuid(): UUID = UUID(long, long)
}
