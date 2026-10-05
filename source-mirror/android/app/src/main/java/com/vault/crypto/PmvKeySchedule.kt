package com.vault.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import java.util.UUID

/** PMV v1 crypto-suite 1 key derivation. */
object PmvKeySchedule {
    const val KEY_SIZE = 32
    const val KDF_SALT_SIZE = 16
    const val ARGON2_MEMORY_KIB = 65_536
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 1

    private val INFO_METADATA = ascii("pmv/v1/metadata")
    private val INFO_ENTRY_ROOT = ascii("pmv/v1/entry-root")
    private val INFO_ATTACHMENT_ROOT = ascii("pmv/v1/attachment-root")
    private val INFO_INDEX = ascii("pmv/v1/index")
    private val INFO_SEARCH_INDEX = ascii("pmv/v1/search-index")
    private val INFO_INTEGRITY = ascii("pmv/v1/integrity")
    private val INFO_SYNC_AUTH = ascii("pmv/v1/sync-auth")
    private val INFO_KEY_WRAP = ascii("pmv/v1/key-wrap")
    private val INFO_CLOUD_CREDENTIALS = ascii("pmv/v1/cloud-credentials")
    private val INFO_ENTRY_GENERATION_PREFIX = ascii("pmv/v1/entry-generation\u0000")
    private val INFO_ATTACHMENT_GENERATION_PREFIX = ascii("pmv/v1/attachment-generation\u0000")
    private val INFO_CHUNK_PREFIX = ascii("pmv/v1/chunk\u0000")
    private val INFO_COMMIT_BLOCK_PREFIX = ascii("pmv/v1/commit-block-key\u0000")
    private val INFO_METADATA_BLOCK_PREFIX = ascii("pmv/v1/metadata-block-key\u0000")
    private val INFO_INDEX_PAGE_PREFIX = ascii("pmv/v1/index-page-key\u0000")

    /** Logical page type is part of the KDF domain even though all pages use INDEX_PAGE on disk. */
    enum class IndexPageType(val domain: String) {
        ENTRY_INDEX("entry-index"),
        VAULT_ROOT("vault-root"),
        LOGIN_INDEX("login-index"),
        OBJECT_INDEX("object-index"),
        CHUNK_INDEX("chunk-index"),
    }

    /**
     * Eight independent suite-1 root keys, including the keyed lookup-only search index.
     *
     * This instance owns these arrays. Callers must not mutate them and must call [close] as soon as
     * the keys are no longer needed. [deepCopy] is the safe way to retain an independent copy;
     * the data-class generated `copy()` is shallow and therefore shares the underlying arrays.
    */
    data class RootKeys(
        val metadataKey: ByteArray,
        val entryRootKey: ByteArray,
        val attachmentRootKey: ByteArray,
        val indexKey: ByteArray,
        val searchIndexKey: ByteArray,
        val integrityKey: ByteArray,
        val syncAuthKey: ByteArray,
        val keyWrapKey: ByteArray,
    ) : AutoCloseable {
        init {
            require(metadataKey.size == KEY_SIZE) { "metadata key must be 32 bytes" }
            require(entryRootKey.size == KEY_SIZE) { "entry-root key must be 32 bytes" }
            require(attachmentRootKey.size == KEY_SIZE) { "attachment-root key must be 32 bytes" }
            require(indexKey.size == KEY_SIZE) { "index key must be 32 bytes" }
            require(searchIndexKey.size == KEY_SIZE) { "search-index key must be 32 bytes" }
            require(integrityKey.size == KEY_SIZE) { "integrity key must be 32 bytes" }
            require(syncAuthKey.size == KEY_SIZE) { "sync-auth key must be 32 bytes" }
            require(keyWrapKey.size == KEY_SIZE) { "key-wrap key must be 32 bytes" }
        }

        fun deepCopy(): RootKeys = RootKeys(
            metadataKey = metadataKey.copyOf(),
            entryRootKey = entryRootKey.copyOf(),
            attachmentRootKey = attachmentRootKey.copyOf(),
            indexKey = indexKey.copyOf(),
            searchIndexKey = searchIndexKey.copyOf(),
            integrityKey = integrityKey.copyOf(),
            syncAuthKey = syncAuthKey.copyOf(),
            keyWrapKey = keyWrapKey.copyOf(),
        )

        override fun close() {
            metadataKey.fill(0)
            entryRootKey.fill(0)
            attachmentRootKey.fill(0)
            indexKey.fill(0)
            searchIndexKey.fill(0)
            integrityKey.fill(0)
            syncAuthKey.fill(0)
            keyWrapKey.fill(0)
        }
    }

    /**
     * Argon2id v1.3 password KDF. [passwordUtf8] is already UTF-8 encoded and is never modified.
     * The returned 32-byte root key is owned by the caller and should be wiped after use.
     */
    fun derivePasswordKek(
        passwordUtf8: ByteArray,
        salt: ByteArray,
        parameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
    ): ByteArray {
        require(salt.size == KDF_SALT_SIZE) { "Argon2 salt must be exactly 16 bytes" }
        PmvKdfPolicy.validate(parameters)
        val argon2Parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(parameters.memoryKiB)
            .withIterations(parameters.iterations)
            .withParallelism(parameters.parallelism)
            .withSalt(salt)
            .build()
        return ByteArray(KEY_SIZE).also { output ->
            Argon2BytesGenerator().apply { init(argon2Parameters) }.generateBytes(passwordUtf8, output)
        }
    }

    /** Derives all purpose-separated root keys using the vault UUID's canonical raw 16 bytes as salt. */
    fun deriveRootKeys(vaultRootKey: ByteArray, vaultId: UUID): RootKeys {
        requireKey(vaultRootKey, "vault root key")
        val salt = uuidBytes(vaultId)
        val derived = ArrayList<ByteArray>(8)
        try {
            derived += hkdf(vaultRootKey, salt, INFO_METADATA)
            derived += hkdf(vaultRootKey, salt, INFO_ENTRY_ROOT)
            derived += hkdf(vaultRootKey, salt, INFO_ATTACHMENT_ROOT)
            derived += hkdf(vaultRootKey, salt, INFO_INDEX)
            derived += hkdf(vaultRootKey, salt, INFO_SEARCH_INDEX)
            derived += hkdf(vaultRootKey, salt, INFO_INTEGRITY)
            derived += hkdf(vaultRootKey, salt, INFO_SYNC_AUTH)
            derived += hkdf(vaultRootKey, salt, INFO_KEY_WRAP)
            return RootKeys(
                metadataKey = derived[0],
                entryRootKey = derived[1],
                attachmentRootKey = derived[2],
                indexKey = derived[3],
                searchIndexKey = derived[4],
                integrityKey = derived[5],
                syncAuthKey = derived[6],
                keyWrapKey = derived[7],
            )
        } catch (error: Throwable) {
            derived.forEach { it.fill(0) }
            throw error
        } finally {
            salt.fill(0)
        }
    }

    /** Derives the vault-bound key used only for encrypted cloud credential fields. */
    fun deriveCloudCredentialKey(keyWrapKey: ByteArray): ByteArray {
        requireKey(keyWrapKey, "key-wrap key")
        val salt = ByteArray(KEY_SIZE)
        return try {
            hkdf(keyWrapKey, salt, INFO_CLOUD_CREDENTIALS)
        } finally {
            salt.fill(0)
        }
    }

    fun deriveEntryKey(entryRootKey: ByteArray, entryId: UUID, generation: Long): ByteArray {
        requireKey(entryRootKey, "entry-root key")
        requireUnsignedLong(generation, "entry generation")
        return deriveGenerationKey(entryRootKey, uuidBytes(entryId), INFO_ENTRY_GENERATION_PREFIX, generation)
    }

    fun deriveAttachmentObjectKey(
        attachmentRootKey: ByteArray,
        attachmentId: UUID,
        generation: Long,
    ): ByteArray {
        requireKey(attachmentRootKey, "attachment-root key")
        requireUnsignedLong(generation, "attachment generation")
        return deriveGenerationKey(
            attachmentRootKey,
            uuidBytes(attachmentId),
            INFO_ATTACHMENT_GENERATION_PREFIX,
            generation,
        )
    }

    fun deriveChunkKey(attachmentObjectKey: ByteArray, chunkIndex: Long): ByteArray {
        requireKey(attachmentObjectKey, "attachment object key")
        requireUnsignedLong(chunkIndex, "chunk index")
        val salt = ByteArray(KEY_SIZE)
        val info = generationInfo(INFO_CHUNK_PREFIX, chunkIndex)
        return try {
            hkdf(attachmentObjectKey, salt, info)
        } finally {
            salt.fill(0)
            info.fill(0)
        }
    }

    /**
     * Derives the AEAD key for one immutable commit block.
     *
     * Frozen Suite-1 layout: salt = commitId raw16; info =
     * ASCII("pmv/v1/commit-block-key\\0") || u64be(revision).
     */
    fun deriveCommitBlockKey(integrityKey: ByteArray, commitId: UUID, revision: Long): ByteArray {
        requireKey(integrityKey, "integrity key")
        requireUnsignedLong(revision, "commit revision")
        return deriveGenerationKey(integrityKey, uuidBytes(commitId), INFO_COMMIT_BLOCK_PREFIX, revision)
    }

    /** Unique AEAD key for one immutable Vault Metadata generation. */
    fun deriveMetadataBlockKey(metadataKey: ByteArray, objectId: UUID, generation: Long): ByteArray {
        requireKey(metadataKey, "metadata key")
        requireUnsignedLong(generation, "metadata generation")
        return deriveGenerationKey(metadataKey, uuidBytes(objectId), INFO_METADATA_BLOCK_PREFIX, generation)
    }

    /**
     * Derives the AEAD key for one immutable logical index page.
     *
     * Frozen Suite-1 layout: salt = objectId raw16; info =
     * ASCII("pmv/v1/index-page-key\\0") || ASCII(pageType.domain) || NUL || u64be(generation).
     */
    fun deriveIndexPageKey(
        parentKey: ByteArray,
        objectId: UUID,
        generation: Long,
        pageType: IndexPageType,
    ): ByteArray {
        requireKey(parentKey, "index page parent key")
        requireUnsignedLong(generation, "index page generation")
        val domain = ascii(pageType.domain)
        val infoPrefix = ByteArray(INFO_INDEX_PAGE_PREFIX.size + domain.size + 1)
        INFO_INDEX_PAGE_PREFIX.copyInto(infoPrefix)
        domain.copyInto(infoPrefix, INFO_INDEX_PAGE_PREFIX.size)
        return try {
            deriveGenerationKey(parentKey, uuidBytes(objectId), infoPrefix, generation)
        } finally {
            domain.fill(0)
            infoPrefix.fill(0)
        }
    }

    private fun deriveGenerationKey(
        parentKey: ByteArray,
        salt: ByteArray,
        infoPrefix: ByteArray,
        generation: Long,
    ): ByteArray {
        val info = generationInfo(infoPrefix, generation)
        return try {
            hkdf(parentKey, salt, info)
        } finally {
            salt.fill(0)
            info.fill(0)
        }
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        requireKey(ikm, "HKDF input key")
        return ByteArray(KEY_SIZE).also { output ->
            val generator = HKDFBytesGenerator(SHA256Digest())
            generator.init(HKDFParameters(ikm, salt, info))
            val written = generator.generateBytes(output, 0, output.size)
            check(written == output.size) { "HKDF produced an unexpected output length" }
        }
    }

    private fun generationInfo(prefix: ByteArray, value: Long): ByteArray =
        ByteArray(prefix.size + U64_SIZE).also { output ->
            prefix.copyInto(output)
            writeU64BigEndian(value, output, prefix.size)
        }

    private fun uuidBytes(uuid: UUID): ByteArray = ByteArray(UUID_SIZE).also { output ->
        writeU64BigEndian(uuid.mostSignificantBits, output, 0)
        writeU64BigEndian(uuid.leastSignificantBits, output, U64_SIZE)
    }

    private fun writeU64BigEndian(value: Long, output: ByteArray, offset: Int) {
        for (index in 0 until U64_SIZE) {
            output[offset + index] = (value ushr (56 - index * 8)).toByte()
        }
    }

    private fun requireUnsignedLong(value: Long, label: String) {
        // The public API uses signed Long, so its representable non-negative u64 subset is 0..2^63-1.
        require(value >= 0) { "$label must be a non-negative u64 value representable by Long" }
    }

    private fun requireKey(key: ByteArray, label: String) {
        require(key.size == KEY_SIZE) { "$label must be exactly 32 bytes" }
    }

    private fun ascii(value: String): ByteArray = value.toByteArray(Charsets.US_ASCII)

    private const val U64_SIZE = 8
    private const val UUID_SIZE = 16
}
