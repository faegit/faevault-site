package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import com.vault.model.Entry
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

class PmvCompositeRootIntegrationTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val entryId = UUID.fromString("10000000-0000-0000-0000-000000000001")
    private val superblockKey = ByteArray(32) { (it + 1).toByte() }
    private val entryRootKey = ByteArray(32) { (it * 3 + 1).toByte() }
    private val indexRootKey = ByteArray(32) { (it * 5 + 1).toByte() }
    private val integrityKey = ByteArray(32) { (it * 7 + 1).toByte() }
    private val signingSeed = ByteArray(32) { (it * 11 + 1).toByte() }
    private val signingPublicKey = Ed25519PrivateKeyParameters(signingSeed, 0).generatePublicKey().encoded

    @Test
    fun `derived composite root reads entry and permits absent optional roots`() = withContainer { container, _ ->
        assertEquals(16_384L, PmvContainerFormat.DATA_START)
        val built = buildCommit(container.state().superblock.committedFileEnd, 1, null, "value")
        append(container, built, 0)

        reader(container).use { assertEquals("value", it.find(entryId)?.title) }
    }

    @Test
    fun `wrong vault-root derivation domain is rejected before append`() = withContainer { container, _ ->
        val built = buildCommit(
            container.state().superblock.committedFileEnd,
            1,
            null,
            "value",
            vaultRootDomain = PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )
        assertThrows(IllegalArgumentException::class.java) { append(container, built, 0) }
    }

    @Test
    fun `reader falls back when newest PMVR is corrupted`() = assertLayerFallback(Layer.VAULT_ROOT)

    @Test
    fun `reader falls back when newest Entry root is corrupted`() = assertLayerFallback(Layer.ENTRY_ROOT)

    @Test
    fun `reader falls back when newest Entry leaf is corrupted`() = assertLayerFallback(Layer.ENTRY_LEAF)

    private fun assertLayerFallback(layer: Layer) = withContainer { container, file ->
        val first = buildCommit(container.state().superblock.committedFileEnd, 1, null, "old")
        append(container, first, 0)
        val second = buildCommit(container.state().superblock.committedFileEnd, 2, first.commit.commitId, "new")
        append(container, second, 1)

        val offset = when (layer) {
            Layer.VAULT_ROOT -> second.vaultRootOffset
            Layer.ENTRY_ROOT -> second.entryRootOffset
            Layer.ENTRY_LEAF -> second.entryLeafOffset
        }
        RandomAccessFile(file, "rw").use { output ->
            output.seek(offset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            val old = output.read()
            require(old >= 0)
            output.seek(offset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            output.write(old xor 1)
            output.fd.sync()
        }

        reader(container).use { assertEquals("old", it.find(entryId)?.title) }
    }

    private fun reader(container: PmvAppendOnlyFile) = PmvEntryReader(
        container,
        vaultId,
        entryRootKey,
        indexRootKey,
        integrityKey,
        signingPublicKey,
    )

    private fun append(container: PmvAppendOnlyFile, built: BuiltCommit, base: Long) {
        container.commitAuthenticated(
            dataBlocks = listOf(built.entryBlock),
            indexBlocks = listOf(built.vaultRootBlock, built.entryRootBlock, built.entryLeafBlock),
            commitBlock = built.commitBlock,
            commit = built.commit,
            expectedBaseSequence = base,
            indexRootKey = indexRootKey,
            integrityKey = integrityKey,
        )
    }

    private fun buildCommit(
        start: Long,
        revision: Long,
        parentCommitId: UUID?,
        title: String,
        vaultRootDomain: PmvKeySchedule.IndexPageType = PmvKeySchedule.IndexPageType.VAULT_ROOT,
    ): BuiltCommit {
        val entryPlaintext = PmvEntryCodec.encode(
            Entry(id = entryId.toString(), title = title, secretType = "login", updatedAt = revision.toDouble()),
        )
        val entryBlock = sealEntry(entryPlaintext, revision)
        entryPlaintext.fill(0)
        val vaultRootOffset = start + storedLength(entryBlock)
        val entryRootOffset = vaultRootOffset + indexStoredLength(PmvVaultRootCodec.PAGE_SIZE)
        val entryLeafOffset = entryRootOffset + indexStoredLength(PmvEntryIndexRootCodec.PAGE_SIZE)

        val leaf = PmvEntryIndexCodec.Page(
            listOf(
                PmvEntryIndexCodec.Record(
                    entryId = entryId,
                    entryType = "login",
                    revision = revision,
                    offset = start,
                    length = storedLength(entryBlock),
                    state = PmvEntryIndexCodec.State.ACTIVE,
                    displayTitle = title,
                    modifiedAtEpochMillis = revision,
                    contentDigest = PmvIntegrity.encryptedBlockDigest(entryBlock),
                ),
            ),
            0,
        )
        val leafBlock = sealIndex(PmvEntryIndexCodec.encode(leaf), revision, PmvKeySchedule.IndexPageType.ENTRY_INDEX)
        val entryRoot = PmvEntryIndexRootCodec.Root(
            listOf(
                PmvEntryIndexRootCodec.Record(
                    entryId,
                    entryId,
                    entryLeafOffset,
                    PmvIntegrity.entryPageDigest(leaf),
                ),
            ),
        )
        val entryRootBlock = sealIndex(
            PmvEntryIndexRootCodec.encode(entryRoot),
            revision,
            PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )
        val vaultRoot = PmvVaultRootCodec.Root(
            entry = PmvVaultRootCodec.Reference(
                PmvVaultRootCodec.RootType.ENTRY,
                entryRootOffset,
                storedLength(entryRootBlock),
                PmvIntegrity.entryRootDigest(entryRoot),
            ),
        )
        val vaultRootBlock = sealIndex(PmvVaultRootCodec.encode(vaultRoot), revision, vaultRootDomain)
        val commit = PmvCommitCodec.sign(
            vaultId = vaultId,
            commitId = UUID.randomUUID(),
            parentCommitId = parentCommitId,
            revision = revision,
            indexRootOffset = vaultRootOffset,
            indexRootLength = storedLength(vaultRootBlock),
            rootDigest = PmvVaultRootCodec.logicalDigest(vaultRoot),
            privateSeed = signingSeed,
        )
        val commitKey = PmvKeySchedule.deriveCommitBlockKey(integrityKey, commit.commitId, revision)
        val commitPlaintext = PmvCommitCodec.encode(commit)
        val commitBlock = try {
            PmvBlockCrypto.seal(
                vaultId,
                commitKey,
                PmvContainerFormat.BlockType.COMMIT,
                commit.commitId,
                revision,
                commitPlaintext,
            )
        } finally {
            commitKey.fill(0)
            commitPlaintext.fill(0)
        }
        return BuiltCommit(
            entryBlock,
            vaultRootBlock,
            entryRootBlock,
            leafBlock,
            commit,
            commitBlock,
            vaultRootOffset,
            entryRootOffset,
            entryLeafOffset,
        )
    }

    private fun sealEntry(plaintext: ByteArray, revision: Long): PmvContainerFormat.EncodedBlock {
        val key = PmvKeySchedule.deriveEntryKey(entryRootKey, entryId, revision)
        return try {
            PmvBlockCrypto.seal(
                vaultId,
                key,
                PmvContainerFormat.BlockType.ENTRY,
                entryId,
                revision,
                plaintext,
            )
        } finally {
            key.fill(0)
        }
    }

    private fun sealIndex(
        plaintext: ByteArray,
        revision: Long,
        domain: PmvKeySchedule.IndexPageType,
    ): PmvContainerFormat.EncodedBlock {
        val objectId = UUID.randomUUID()
        val key = PmvKeySchedule.deriveIndexPageKey(indexRootKey, objectId, revision, domain)
        return try {
            PmvBlockCrypto.seal(
                vaultId,
                key,
                PmvContainerFormat.BlockType.INDEX_PAGE,
                objectId,
                revision,
                plaintext,
            )
        } finally {
            key.fill(0)
            plaintext.fill(0)
        }
    }

    private fun withContainer(block: (PmvAppendOnlyFile, File) -> Unit) {
        val file = File.createTempFile("pmv-composite-root-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { block(it, file) }
        } finally {
            file.delete()
        }
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + block.header.cipherSize

    private fun indexStoredLength(plaintextSize: Int): Long =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + plaintextSize + PmvContainerFormat.GCM_TAG_SIZE

    private enum class Layer { VAULT_ROOT, ENTRY_ROOT, ENTRY_LEAF }

    private data class BuiltCommit(
        val entryBlock: PmvContainerFormat.EncodedBlock,
        val vaultRootBlock: PmvContainerFormat.EncodedBlock,
        val entryRootBlock: PmvContainerFormat.EncodedBlock,
        val entryLeafBlock: PmvContainerFormat.EncodedBlock,
        val commit: PmvCommitCodec.Commit,
        val commitBlock: PmvContainerFormat.EncodedBlock,
        val vaultRootOffset: Long,
        val entryRootOffset: Long,
        val entryLeafOffset: Long,
    )
}
