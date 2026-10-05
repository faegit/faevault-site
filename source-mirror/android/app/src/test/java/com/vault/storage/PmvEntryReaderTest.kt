package com.vault.storage

import com.vault.model.Entry
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID

class PmvEntryReaderTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val superblockKey = ByteArray(32) { (it * 3).toByte() }
    private val entryKey = ByteArray(32) { (it * 5).toByte() }
    private val indexKey = ByteArray(32) { (it * 7).toByte() }
    private val commitKey = ByteArray(32) { (it * 11).toByte() }
    private val signingSeed = ByteArray(32) { (it * 13 + 1).toByte() }
    private val trustedSigningPublicKey = Ed25519PrivateKeyParameters(signingSeed, 0).generatePublicKey().encoded

    @Test
    fun `lookup follows encrypted index pages and decrypts only the matched entry`() {
        val file = File.createTempFile("pmv-entry-reader-", ".bin")
        val firstId = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val targetId = UUID.fromString("00000000-0000-0000-0000-000000000002")
        try {
            val firstEntry = entryBlock(firstId, "unrelated")
            val targetEntry = entryBlock(targetId, "target")
            val firstOffset = PmvContainerFormat.DATA_START
            val targetOffset = firstOffset + storedLength(firstEntry)
            val rootOffset = targetOffset + storedLength(targetEntry)
            val firstIndexOffset = rootOffset + INDEX_BLOCK_LENGTH
            val secondIndexOffset = firstIndexOffset + INDEX_BLOCK_LENGTH
            val firstPage = indexBlock(
                listOf(indexRecord(firstId, firstOffset, firstEntry, "Unrelated display", favorite = true)),
                nextPageOffset = 0,
            )
            val secondPage = indexBlock(
                listOf(indexRecord(targetId, targetOffset, targetEntry, "Target display", favorite = false)),
                nextPageOffset = 0,
            )
            val root = rootBlock(
                listOf(
                    rootRecord(firstId, firstId, firstIndexOffset, firstPage),
                    rootRecord(targetId, targetId, secondIndexOffset, secondPage),
                ),
            )

            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(
                    dataBlocks = listOf(firstEntry, targetEntry),
                    indexBlocks = listOf(root, firstPage, secondPage),
                    commitBlock = commitBlock(root, rootOffset, 1),
                )
                RandomAccessFile(file, "rw").use { output ->
                    output.seek(firstOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
                    output.write(0x7f)
                    output.fd.sync()
                }

                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    val listPage = reader.listPage()
                    assertEquals(listOf("Unrelated display"), listPage.items.map { it.displayTitle })
                    assertEquals(listOf(true), listPage.items.map { it.favorite })
                    RandomAccessFile(file, "rw").use { output ->
                        output.seek(firstIndexOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
                        output.write(0x6e)
                        output.fd.sync()
                    }
                    assertEquals("target", reader.find(targetId)?.title)

                    val nextCommitStart = container.state().superblock.committedFileEnd
                    val newLeafOffset = nextCommitStart + INDEX_BLOCK_LENGTH
                    val newLeaf = indexBlock(
                        listOf(indexRecord(targetId, targetOffset, targetEntry, "Target display", false)),
                        0,
                    )
                    val newRoot = rootBlock(
                        listOf(rootRecord(targetId, targetId, newLeafOffset, newLeaf)),
                    )
                    container.commit(emptyList(), listOf(newRoot, newLeaf), commitBlock(newRoot, nextCommitStart, 2))
                    val continued = reader.listPage(requireNotNull(listPage.nextCursor))
                    assertEquals(listOf("Target display"), continued.items.map { it.displayTitle })
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `lookup rejects a root range that does not match its leaf page`() {
        val file = File.createTempFile("pmv-entry-range-", ".bin")
        try {
            val indexedId = UUID.fromString("00000000-0000-0000-0000-000000000001")
            val differentId = UUID.fromString("00000000-0000-0000-0000-000000000002")
            val rootOffset = PmvContainerFormat.DATA_START
            val leafOffset = rootOffset + INDEX_BLOCK_LENGTH
            val leaf = indexBlock(
                listOf(
                    PmvEntryIndexCodec.Record(
                        entryId = differentId,
                        entryType = "login",
                        revision = 1,
                        offset = PmvContainerFormat.DATA_START,
                        length = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + PmvContainerFormat.GCM_TAG_SIZE,
                        state = PmvEntryIndexCodec.State.TOMBSTONE,
                    ),
                ),
                nextPageOffset = 0,
            )
            val root = rootBlock(listOf(rootRecord(indexedId, indexedId, leafOffset, leaf)))
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(emptyList(), listOf(root, leaf), commitBlock(root, rootOffset, 1))
                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertNull(reader.find(indexedId))
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `lookup rejects index metadata that does not match the entry block`() {
        val file = File.createTempFile("pmv-entry-metadata-", ".bin")
        val entryId = UUID.fromString("00000000-0000-0000-0000-000000000003")
        try {
            val entryBlock = entryBlock(entryId, "mismatch")
            val badRecord = indexRecord(entryId, PmvContainerFormat.DATA_START, entryBlock, "Mismatch", false).copy(revision = 99)
            val rootOffset = PmvContainerFormat.DATA_START + storedLength(entryBlock)
            val leafOffset = rootOffset + INDEX_BLOCK_LENGTH
            val page = indexBlock(listOf(badRecord), 0)
            val root = rootBlock(listOf(rootRecord(entryId, entryId, leafOffset, page)))
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(listOf(entryBlock), listOf(root, page), commitBlock(root, rootOffset, 1))
                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertNull(reader.find(entryId))
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `reader falls back when commit revision differs from superblock sequence`() {
        val file = File.createTempFile("pmv-entry-commit-revision-", ".bin")
        try {
            val root = rootBlock(emptyList())
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(emptyList(), listOf(root), commitBlock(root, PmvContainerFormat.DATA_START, revision = 2))
                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertEquals(emptyList<Any>(), reader.listPage().items)
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `reader rejects zero digest for active entry`() {
        val file = File.createTempFile("pmv-entry-zero-content-digest-", ".bin")
        val entryId = UUID.fromString("00000000-0000-0000-0000-000000000006")
        try {
            val entry = entryBlock(entryId, "zero digest")
            val rootOffset = PmvContainerFormat.DATA_START + storedLength(entry)
            val leafOffset = rootOffset + INDEX_BLOCK_LENGTH
            val leaf = indexBlock(
                listOf(indexRecord(entryId, PmvContainerFormat.DATA_START, entry, "Zero", false).copy(contentDigest = ByteArray(32))),
                0,
            )
            val root = rootBlock(listOf(rootRecord(entryId, entryId, leafOffset, leaf)))
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(listOf(entry), listOf(root, leaf), commitBlock(root, rootOffset, 1))
                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertNull(reader.find(entryId))
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `reader rejects zero leaf page digest`() {
        val file = File.createTempFile("pmv-entry-zero-page-digest-", ".bin")
        val entryId = UUID.fromString("00000000-0000-0000-0000-000000000007")
        try {
            val rootOffset = PmvContainerFormat.DATA_START
            val leafOffset = rootOffset + INDEX_BLOCK_LENGTH
            val tombstone = PmvEntryIndexCodec.Record(
                entryId = entryId,
                entryType = "login",
                revision = 1,
                offset = PmvContainerFormat.DATA_START,
                length = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + PmvContainerFormat.GCM_TAG_SIZE,
                state = PmvEntryIndexCodec.State.TOMBSTONE,
            )
            val leaf = indexBlock(listOf(tombstone), 0)
            val root = rootBlock(listOf(PmvEntryIndexRootCodec.Record(entryId, entryId, leafOffset)))
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                container.commit(emptyList(), listOf(root, leaf), commitBlock(root, rootOffset, 1))
                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertTrue(reader.listPage().items.isEmpty())
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `reader falls back when the newest encrypted index root is corrupted`() {
        val file = File.createTempFile("pmv-entry-root-fallback-", ".bin")
        val entryId = UUID.fromString("00000000-0000-0000-0000-000000000004")
        try {
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                val oldEntry = entryBlock(entryId, "old committed value")
                val oldEntryOffset = PmvContainerFormat.DATA_START
                val oldRootOffset = oldEntryOffset + storedLength(oldEntry)
                val oldLeafOffset = oldRootOffset + INDEX_BLOCK_LENGTH
                val oldLeaf = indexBlock(
                    listOf(indexRecord(entryId, oldEntryOffset, oldEntry, "Old", false)),
                    0,
                )
                val oldRoot = rootBlock(listOf(rootRecord(entryId, entryId, oldLeafOffset, oldLeaf)))
                container.commit(
                    listOf(oldEntry),
                    listOf(oldRoot, oldLeaf),
                    commitBlock(oldRoot, oldRootOffset, 1),
                )

                val newEntry = entryBlock(entryId, "new committed value")
                val newEntryOffset = container.state().superblock.committedFileEnd
                val newRootOffset = newEntryOffset + storedLength(newEntry)
                val newLeafOffset = newRootOffset + INDEX_BLOCK_LENGTH
                val newLeaf = indexBlock(
                    listOf(indexRecord(entryId, newEntryOffset, newEntry, "New", false)),
                    0,
                )
                val newRoot = rootBlock(listOf(rootRecord(entryId, entryId, newLeafOffset, newLeaf)))
                val newest = container.commit(
                    listOf(newEntry),
                    listOf(newRoot, newLeaf),
                    commitBlock(newRoot, newRootOffset, 2),
                )
                RandomAccessFile(file, "rw").use { output ->
                    flipByte(output, newest.superblock.latestIndexOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
                    output.fd.sync()
                }

                PmvEntryReader(container, vaultId, entryKey, indexKey, commitKey, trustedSigningPublicKey, allowLegacyStaticKeys = true).use { reader ->
                    assertEquals("old committed value", reader.find(entryId)?.title)
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `fallback snapshot cursor continues across entry index pages`() {
        val file = File.createTempFile("pmv-entry-cursor-fallback-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                // A login record occupies 113 bytes, so 145 records cannot fit in one 16 KiB page.
                val entryIds = (1..145).map { UUID(0L, it.toLong()) }
                val entries = entryIds.map { entryBlock(it, "entry-$it") }
                var entryOffset = PmvContainerFormat.DATA_START
                val records = entryIds.zip(entries).map { (entryId, block) ->
                    indexRecord(entryId, entryOffset, block, "", false).also {
                        entryOffset += storedLength(block)
                    }
                }
                val oldPages = listOf(records.take(144), records.drop(144))
                val oldRootOffset = entryOffset
                val oldFirstLeafOffset = oldRootOffset + INDEX_BLOCK_LENGTH
                val oldLeafBlocks = oldPages.map { indexBlock(it, 0) }
                val oldRoot = rootBlock(
                    oldPages.mapIndexed { index, page ->
                        rootRecord(
                            page.first().entryId,
                            page.last().entryId,
                            oldFirstLeafOffset + index * INDEX_BLOCK_LENGTH,
                            oldLeafBlocks[index],
                        )
                    },
                )
                container.commit(
                    entries,
                    listOf(oldRoot) + oldLeafBlocks,
                    commitBlock(oldRoot, oldRootOffset, 1),
                )

                val newRootOffset = container.state().superblock.committedFileEnd
                val newFirstLeafOffset = newRootOffset + INDEX_BLOCK_LENGTH
                val newLeafBlocks = oldPages.map { indexBlock(it, 0) }
                val newRoot = rootBlock(
                    oldPages.mapIndexed { index, page ->
                        rootRecord(
                            page.first().entryId,
                            page.last().entryId,
                            newFirstLeafOffset + index * INDEX_BLOCK_LENGTH,
                            newLeafBlocks[index],
                        )
                    },
                )
                container.commit(
                    emptyList(),
                    listOf(newRoot) + newLeafBlocks,
                    commitBlock(newRoot, newRootOffset, 2),
                )
                RandomAccessFile(file, "rw").use { output ->
                    flipByte(output, newFirstLeafOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
                    output.fd.sync()
                }

                PmvEntryReader(
                    container,
                    vaultId,
                    entryKey,
                    indexKey,
                    commitKey,
                    trustedSigningPublicKey,
                    allowLegacyStaticKeys = true,
                ).use { reader ->
                    val firstPage = reader.listPage()
                    assertEquals(144, firstPage.items.size)
                    val oldSnapshotCursor = requireNotNull(firstPage.nextCursor)
                    assertEquals(1L, oldSnapshotCursor.sequence)

                    val secondPage = reader.listPage(oldSnapshotCursor)
                    assertEquals(listOf(entryIds.last()), secondPage.items.map { it.entryId })
                    assertNull(secondPage.nextCursor)
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `reader falls back when newest commit authentication tag is corrupted`() {
        assertNewestCommitRejected(CommitDamage.AUTHENTICATION_TAG)
    }

    @Test
    fun `reader falls back when newest commit root digest is wrong`() {
        assertNewestCommitRejected(CommitDamage.ROOT_DIGEST)
    }

    @Test
    fun `reader falls back when newest commit uses an untrusted signing key`() {
        assertNewestCommitRejected(CommitDamage.SIGNING_KEY)
    }

    @Test
    fun `reader falls back when newest commit signature is corrupted`() {
        assertNewestCommitRejected(CommitDamage.SIGNATURE)
    }

    private fun assertNewestCommitRejected(damage: CommitDamage) {
        val file = File.createTempFile("pmv-entry-commit-fallback-", ".bin")
        val entryId = UUID.fromString("00000000-0000-0000-0000-000000000005")
        try {
            PmvAppendOnlyFile.create(file, vaultId, superblockKey).use { container ->
                val oldEntry = entryBlock(entryId, "trusted old value")
                val oldEntryOffset = PmvContainerFormat.DATA_START
                val oldRootOffset = oldEntryOffset + storedLength(oldEntry)
                val oldLeafOffset = oldRootOffset + INDEX_BLOCK_LENGTH
                val oldLeaf = indexBlock(listOf(indexRecord(entryId, oldEntryOffset, oldEntry, "Old", false)), 0)
                val oldRoot = rootBlock(listOf(rootRecord(entryId, entryId, oldLeafOffset, oldLeaf)))
                container.commit(
                    listOf(oldEntry),
                    listOf(oldRoot, oldLeaf),
                    commitBlock(oldRoot, oldRootOffset, 1),
                )

                val newEntry = entryBlock(entryId, "untrusted new value")
                val newEntryOffset = container.state().superblock.committedFileEnd
                val newRootOffset = newEntryOffset + storedLength(newEntry)
                val newLeafOffset = newRootOffset + INDEX_BLOCK_LENGTH
                val newLeaf = indexBlock(listOf(indexRecord(entryId, newEntryOffset, newEntry, "New", false)), 0)
                val newRoot = rootBlock(listOf(rootRecord(entryId, entryId, newLeafOffset, newLeaf)))
                val newCommit = when (damage) {
                    CommitDamage.AUTHENTICATION_TAG -> commitBlock(newRoot, newRootOffset, 2)
                    CommitDamage.ROOT_DIGEST -> commitBlock(
                        newRoot,
                        newRootOffset,
                        2,
                        rootDigest = ByteArray(PmvCommitCodec.ROOT_DIGEST_SIZE) { 0x5a },
                    )
                    CommitDamage.SIGNING_KEY -> commitBlock(
                        newRoot,
                        newRootOffset,
                        2,
                        seed = ByteArray(PmvCommitCodec.PRIVATE_SEED_SIZE) { (it * 19 + 3).toByte() },
                    )
                    CommitDamage.SIGNATURE -> commitBlock(newRoot, newRootOffset, 2) { plaintext ->
                        plaintext[plaintext.lastIndex] = (plaintext.last().toInt() xor 1).toByte()
                    }
                }
                val newest = container.commit(
                    listOf(newEntry),
                    listOf(newRoot, newLeaf),
                    newCommit,
                )
                if (damage == CommitDamage.AUTHENTICATION_TAG) {
                    RandomAccessFile(file, "rw").use { output ->
                        flipByte(output, newest.superblock.latestCommitOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
                        output.fd.sync()
                    }
                }

                PmvEntryReader(
                    container,
                    vaultId,
                    entryKey,
                    indexKey,
                    commitKey,
                    trustedSigningPublicKey,
                    allowLegacyStaticKeys = true,
                ).use { reader ->
                    assertEquals("trusted old value", reader.find(entryId)?.title)
                }
            }
        } finally {
            file.delete()
        }
    }

    private fun entryBlock(id: UUID, title: String): PmvContainerFormat.EncodedBlock =
        PmvBlockCrypto.seal(
            vaultId = vaultId,
            key = com.vault.crypto.PmvKeySchedule.deriveEntryKey(entryKey, id, 1),
            blockType = PmvContainerFormat.BlockType.ENTRY,
            objectId = id,
            objectRevision = 1,
            plaintext = PmvEntryCodec.encode(
                Entry(id = id.toString(), title = title, secretType = "login", updatedAt = 1.0),
            ),
        )

    private fun indexRecord(
        id: UUID,
        offset: Long,
        block: PmvContainerFormat.EncodedBlock,
        displayTitle: String,
        favorite: Boolean,
    ) = PmvEntryIndexCodec.Record(
        entryId = id,
        entryType = "login",
        revision = block.header.objectRevision,
        offset = offset,
        length = storedLength(block),
        state = PmvEntryIndexCodec.State.ACTIVE,
        displayTitle = displayTitle,
        favorite = favorite,
        modifiedAtEpochMillis = 1_700_000_000_000,
        contentDigest = PmvIntegrity.encryptedBlockDigest(block),
    )

    private fun rootRecord(
        minEntryId: UUID,
        maxEntryId: UUID,
        pageOffset: Long,
        pageBlock: PmvContainerFormat.EncodedBlock,
    ): PmvEntryIndexRootCodec.Record {
        val plaintext = PmvBlockCrypto.open(vaultId, indexKey, pageBlock)
        return try {
            PmvEntryIndexRootCodec.Record(
                minEntryId,
                maxEntryId,
                pageOffset,
                PmvIntegrity.entryPageDigest(PmvEntryIndexCodec.decode(plaintext)),
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun indexBlock(
        records: List<PmvEntryIndexCodec.Record>,
        nextPageOffset: Long,
    ): PmvContainerFormat.EncodedBlock = PmvBlockCrypto.seal(
        vaultId = vaultId,
        key = indexKey,
        blockType = PmvContainerFormat.BlockType.INDEX_PAGE,
        objectId = UUID.randomUUID(),
        objectRevision = 1,
        plaintext = PmvEntryIndexCodec.encode(PmvEntryIndexCodec.Page(records, nextPageOffset)),
    )

    private fun rootBlock(
        records: List<PmvEntryIndexRootCodec.Record>,
    ): PmvContainerFormat.EncodedBlock = PmvBlockCrypto.seal(
        vaultId = vaultId,
        key = indexKey,
        blockType = PmvContainerFormat.BlockType.INDEX_PAGE,
        objectId = UUID.randomUUID(),
        objectRevision = 1,
        plaintext = PmvEntryIndexRootCodec.encode(PmvEntryIndexRootCodec.Root(records)),
    )

    private fun commitBlock(
        rootBlock: PmvContainerFormat.EncodedBlock,
        rootOffset: Long,
        revision: Long,
        seed: ByteArray = signingSeed,
        rootDigest: ByteArray? = null,
        mutatePlaintext: (ByteArray) -> Unit = {},
    ): PmvContainerFormat.EncodedBlock {
        val rootPlaintext = PmvBlockCrypto.open(vaultId, indexKey, rootBlock)
        val root = try {
            PmvEntryIndexRootCodec.decode(rootPlaintext)
        } finally {
            rootPlaintext.fill(0)
        }
        val commit = PmvCommitCodec.sign(
            vaultId = vaultId,
            commitId = UUID.randomUUID(),
            parentCommitId = null,
            revision = revision,
            indexRootOffset = rootOffset,
            indexRootLength = storedLength(rootBlock),
            rootDigest = rootDigest ?: PmvIntegrity.entryRootDigest(root),
            privateSeed = seed,
        )
        val plaintext = PmvCommitCodec.encode(commit).also(mutatePlaintext)
        return try {
            PmvBlockCrypto.seal(
                vaultId = vaultId,
                key = commitKey,
                blockType = PmvContainerFormat.BlockType.COMMIT,
                objectId = commit.commitId,
                objectRevision = commit.revision,
                plaintext = plaintext,
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        PmvContainerFormat.BLOCK_HEADER_SIZE + block.ciphertext.size.toLong()

    private fun flipByte(file: RandomAccessFile, offset: Long) {
        file.seek(offset)
        val original = file.read()
        require(original >= 0) { "测试损坏偏移超出文件" }
        file.seek(offset)
        file.write(original xor 1)
    }

    companion object {
        private enum class CommitDamage { AUTHENTICATION_TAG, ROOT_DIGEST, SIGNING_KEY, SIGNATURE }

        private val INDEX_BLOCK_LENGTH =
            PmvContainerFormat.BLOCK_HEADER_SIZE + PmvEntryIndexCodec.PAGE_SIZE + PmvContainerFormat.GCM_TAG_SIZE.toLong()
    }
}
