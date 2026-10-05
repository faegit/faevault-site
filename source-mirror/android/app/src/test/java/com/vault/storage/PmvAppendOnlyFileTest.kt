package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PmvAppendOnlyFileTest {

    private val authKey = ByteArray(32) { (it * 13).toByte() }
    private val commitKey = ByteArray(32) { (it * 11 + 1).toByte() }
    private val vaultId = UUID.fromString("12345678-1234-5678-9abc-def012345678")

    @Test
    fun `commit appends data index and commit before advancing alternate superblock`() {
        val file = File.createTempFile("pmv-append-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val initial = container.state()
                val committed = container.commit(
                    dataBlocks = listOf(block(PmvContainerFormat.BlockType.ENTRY, 96)),
                    indexBlock = block(PmvContainerFormat.BlockType.INDEX_PAGE, 80),
                    commitBlock = block(PmvContainerFormat.BlockType.COMMIT, 112),
                )

                assertEquals(0, initial.activeSlot)
                assertEquals(0, initial.superblock.sequence)
                assertEquals(1, committed.activeSlot)
                assertEquals(1, committed.superblock.sequence)
                assertTrue(committed.superblock.latestIndexOffset >= PmvContainerFormat.DATA_START)
                assertTrue(committed.superblock.latestCommitOffset > committed.superblock.latestIndexOffset)
                assertEquals(committed.superblock.committedFileEnd, file.length())
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `uncommitted tail is ignored and removed before the next commit`() {
        val file = File.createTempFile("pmv-tail-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val first = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 64)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 64),
                    block(PmvContainerFormat.BlockType.COMMIT, 64),
                )
                RandomAccessFile(file, "rw").use { raf ->
                    raf.seek(raf.length())
                    raf.write(ByteArray(4096) { 0x5a })
                    raf.fd.sync()
                }
                assertTrue(file.length() > first.superblock.committedFileEnd)
                assertEquals(first.superblock, container.state().superblock)

                val second = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 48),
                    block(PmvContainerFormat.BlockType.COMMIT, 48),
                )

                assertEquals(2, second.superblock.sequence)
                assertEquals(second.superblock.committedFileEnd, file.length())
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `corrupt newest superblock falls back to the previous committed snapshot`() {
        val file = File.createTempFile("pmv-superblock-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                    block(PmvContainerFormat.BlockType.COMMIT, 32),
                )
                val second = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                    block(PmvContainerFormat.BlockType.COMMIT, 32),
                )
                assertEquals(0, second.activeSlot)
            }
            RandomAccessFile(file, "rw").use { raf ->
                raf.seek(80)
                raf.write(0x7f)
                raf.fd.sync()
            }

            PmvAppendOnlyFile.open(file, authKey).use { reopened ->
                assertEquals(1, reopened.state().superblock.sequence)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `truncated newest commit falls back to the previous file boundary`() {
        val file = File.createTempFile("pmv-truncate-", ".bin")
        try {
            var previousEnd = 0L
            var newestEnd = 0L
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                previousEnd = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                    block(PmvContainerFormat.BlockType.COMMIT, 32),
                ).superblock.committedFileEnd
                newestEnd = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 64)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 64),
                    block(PmvContainerFormat.BlockType.COMMIT, 64),
                ).superblock.committedFileEnd
            }
            RandomAccessFile(file, "rw").use { raf ->
                raf.setLength(newestEnd - 8)
                raf.fd.sync()
            }

            PmvAppendOnlyFile.open(file, authKey).use { reopened ->
                assertEquals(1, reopened.state().superblock.sequence)
                assertEquals(previousEnd, reopened.state().superblock.committedFileEnd)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `commit rejects blocks assigned to the wrong role`() {
        val file = File.createTempFile("pmv-role-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                assertThrows(IllegalArgumentException::class.java) {
                    container.commit(
                        emptyList(),
                        block(PmvContainerFormat.BlockType.ENTRY, 32),
                        block(PmvContainerFormat.BlockType.COMMIT, 32),
                    )
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `readBlock performs positional read inside the committed snapshot`() {
        val file = File.createTempFile("pmv-read-", ".bin")
        try {
            val expected = block(PmvContainerFormat.BlockType.INDEX_PAGE, 80)
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val committed = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 96)),
                    expected,
                    block(PmvContainerFormat.BlockType.COMMIT, 112),
                )

                val actual = container.readBlock(
                    committed.superblock.latestIndexOffset,
                    PmvContainerFormat.BlockType.INDEX_PAGE,
                )

                assertEquals(expected.header, actual.header)
                assertArrayEquals(expected.ciphertext, actual.ciphertext)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `readBlock rejects uncommitted tail even when it contains a valid block`() {
        val file = File.createTempFile("pmv-read-tail-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val committed = container.commit(
                    emptyList(),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                    block(PmvContainerFormat.BlockType.COMMIT, 32),
                )
                val tail = block(PmvContainerFormat.BlockType.ENTRY, 32)
                RandomAccessFile(file, "rw").use { output ->
                    output.seek(output.length())
                    output.write(PmvContainerFormat.encodeBlockHeader(tail.header))
                    output.write(tail.ciphertext)
                    output.fd.sync()
                }

                assertThrows(IllegalArgumentException::class.java) {
                    container.readBlock(committed.superblock.committedFileEnd)
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `readBlock rejects a corrupt header and an unexpected role`() {
        val file = File.createTempFile("pmv-read-corrupt-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val committed = container.commit(
                    listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                    block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                    block(PmvContainerFormat.BlockType.COMMIT, 32),
                )
                assertThrows(IllegalArgumentException::class.java) {
                    container.readBlock(
                        PmvContainerFormat.DATA_START,
                        PmvContainerFormat.BlockType.COMMIT,
                    )
                }

                RandomAccessFile(file, "rw").use { output ->
                    output.seek(PmvContainerFormat.DATA_START + 127)
                    output.write(1)
                    output.fd.sync()
                }
                assertThrows(IllegalArgumentException::class.java) {
                    container.readBlock(PmvContainerFormat.DATA_START)
                }
                assertEquals(1, committed.superblock.sequence)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `create refuses to truncate an existing nonempty file`() {
        val file = File.createTempFile("pmv-existing-", ".bin")
        try {
            file.writeBytes("existing vault bytes".encodeToByteArray())

            assertThrows(IllegalArgumentException::class.java) {
                PmvAppendOnlyFile.create(file, vaultId, authKey)
            }
            assertEquals("existing vault bytes", file.readText())
        } finally {
            file.delete()
        }
    }

    @Test
    fun `two open writer instances serialize commits to the same file`() {
        val file = File.createTempFile("pmv-two-writers-", ".bin")
        val executor = Executors.newFixedThreadPool(2)
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).close()
            PmvAppendOnlyFile.open(file, authKey).use { first ->
                PmvAppendOnlyFile.open(file, authKey).use { second ->
                    val start = CountDownLatch(1)
                    val futures = listOf(first, second).map { writer ->
                        executor.submit<Long> {
                            start.await(5, TimeUnit.SECONDS)
                            writer.commit(
                                listOf(block(PmvContainerFormat.BlockType.ENTRY, 32)),
                                block(PmvContainerFormat.BlockType.INDEX_PAGE, 32),
                                block(PmvContainerFormat.BlockType.COMMIT, 32),
                            ).superblock.sequence
                        }
                    }
                    start.countDown()

                    assertEquals(setOf(1L, 2L), futures.map { it.get(10, TimeUnit.SECONDS) }.toSet())
                    assertEquals(2, first.state().superblock.sequence)
                }
            }
        } finally {
            executor.shutdownNow()
            file.delete()
        }
    }

    @Test
    fun `authenticated commit binds commit identity and index root layout before superblock advances`() {
        val file = File.createTempFile("pmv-authenticated-commit-", ".bin")
        try {
            val rootBlock = block(PmvContainerFormat.BlockType.INDEX_PAGE, 64)
            val commitId = UUID.randomUUID()
            val commit = PmvCommitCodec.sign(
                vaultId = vaultId,
                commitId = commitId,
                parentCommitId = null,
                revision = 1,
                indexRootOffset = PmvContainerFormat.DATA_START,
                indexRootLength = storedLength(rootBlock),
                rootDigest = ByteArray(PmvCommitCodec.ROOT_DIGEST_SIZE) { it.toByte() },
                privateSeed = ByteArray(PmvCommitCodec.PRIVATE_SEED_SIZE) { (it * 7 + 1).toByte() },
            )
            val matchingBlock = PmvBlockCrypto.seal(
                vaultId = vaultId,
                key = commitKey,
                blockType = PmvContainerFormat.BlockType.COMMIT,
                objectId = commitId,
                objectRevision = commit.revision,
                plaintext = PmvCommitCodec.encode(commit),
            )
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                assertThrows(IllegalArgumentException::class.java) {
                    container.commitAuthenticated(
                        emptyList(),
                        listOf(rootBlock),
                        matchingBlock,
                        commit.copy(indexRootOffset = commit.indexRootOffset + 1),
                        0,
                        commitKey,
                    )
                }
                assertEquals(0, container.state().superblock.sequence)

                val committed = container.commitAuthenticated(
                    emptyList(),
                    listOf(rootBlock),
                    matchingBlock,
                    commit,
                    0,
                    commitKey,
                )
                assertEquals(1, committed.superblock.sequence)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `authenticated commit rejects stale base broken parent and skipped revision`() {
        val file = File.createTempFile("pmv-authenticated-chain-", ".bin")
        try {
            PmvAppendOnlyFile.create(file, vaultId, authKey).use { container ->
                val firstRoot = block(PmvContainerFormat.BlockType.INDEX_PAGE, 64)
                val (firstCommit, firstBlock) = authenticatedCommitBlock(
                    rootBlock = firstRoot,
                    rootOffset = container.state().superblock.committedFileEnd,
                    revision = 1,
                    parentCommitId = null,
                )
                val (invalidFirst, invalidFirstBlock) = authenticatedCommitBlock(
                    rootBlock = firstRoot,
                    rootOffset = container.state().superblock.committedFileEnd,
                    revision = 1,
                    parentCommitId = UUID.randomUUID(),
                )
                assertThrows(IllegalArgumentException::class.java) {
                    container.commitAuthenticated(
                        emptyList(), listOf(firstRoot), invalidFirstBlock, invalidFirst, 0, commitKey,
                    )
                }
                container.commitAuthenticated(
                    emptyList(),
                    listOf(firstRoot),
                    firstBlock,
                    firstCommit,
                    0,
                    commitKey,
                )

                val secondRoot = block(PmvContainerFormat.BlockType.INDEX_PAGE, 64)
                val secondRootOffset = container.state().superblock.committedFileEnd
                val (validSecond, validSecondBlock) = authenticatedCommitBlock(
                    rootBlock = secondRoot,
                    rootOffset = secondRootOffset,
                    revision = 2,
                    parentCommitId = firstCommit.commitId,
                )
                assertThrows(IllegalArgumentException::class.java) {
                    container.commitAuthenticated(
                        emptyList(), listOf(secondRoot), validSecondBlock, validSecond, 0, commitKey,
                    )
                }

                val (wrongParent, wrongParentBlock) = authenticatedCommitBlock(
                    rootBlock = secondRoot,
                    rootOffset = secondRootOffset,
                    revision = 2,
                    parentCommitId = UUID.randomUUID(),
                )
                assertThrows(IllegalArgumentException::class.java) {
                    container.commitAuthenticated(
                        emptyList(), listOf(secondRoot), wrongParentBlock, wrongParent, 1, commitKey,
                    )
                }

                val (skippedRevision, skippedRevisionBlock) = authenticatedCommitBlock(
                    rootBlock = secondRoot,
                    rootOffset = secondRootOffset,
                    revision = 3,
                    parentCommitId = firstCommit.commitId,
                )
                assertThrows(IllegalArgumentException::class.java) {
                    container.commitAuthenticated(
                        emptyList(), listOf(secondRoot), skippedRevisionBlock, skippedRevision, 1, commitKey,
                    )
                }
                assertEquals(1, container.state().superblock.sequence)

                assertEquals(
                    2,
                    container.commitAuthenticated(
                        emptyList(), listOf(secondRoot), validSecondBlock, validSecond, 1, commitKey,
                    ).superblock.sequence,
                )
            }
        } finally {
            file.delete()
        }
    }

    private fun authenticatedCommitBlock(
        rootBlock: PmvContainerFormat.EncodedBlock,
        rootOffset: Long,
        revision: Long,
        parentCommitId: UUID?,
    ): Pair<PmvCommitCodec.Commit, PmvContainerFormat.EncodedBlock> {
        val commit = PmvCommitCodec.sign(
            vaultId = vaultId,
            commitId = UUID.randomUUID(),
            parentCommitId = parentCommitId,
            revision = revision,
            indexRootOffset = rootOffset,
            indexRootLength = storedLength(rootBlock),
            rootDigest = ByteArray(PmvCommitCodec.ROOT_DIGEST_SIZE) { (it + 1).toByte() },
            privateSeed = ByteArray(PmvCommitCodec.PRIVATE_SEED_SIZE) { (it * 7 + 1).toByte() },
        )
        return commit to PmvBlockCrypto.seal(
            vaultId = vaultId,
            key = commitKey,
            blockType = PmvContainerFormat.BlockType.COMMIT,
            objectId = commit.commitId,
            objectRevision = commit.revision,
            plaintext = PmvCommitCodec.encode(commit),
        )
    }

    private fun block(
        type: PmvContainerFormat.BlockType,
        cipherSize: Int,
        objectId: UUID = UUID.randomUUID(),
        revision: Long = 1,
    ): PmvContainerFormat.EncodedBlock {
        val header = PmvContainerFormat.BlockHeader(
            blockId = UUID.randomUUID(),
            blockType = type,
            objectId = objectId,
            objectRevision = revision,
            chunkIndex = if (type == PmvContainerFormat.BlockType.ATTACHMENT_CHUNK) 0 else -1,
            flags = 0,
            cryptoSuiteId = 1,
            codecId = 0,
            plainSize = (cipherSize - PmvContainerFormat.GCM_TAG_SIZE).toLong(),
            cipherSize = cipherSize.toLong(),
            nonce = ByteArray(PmvContainerFormat.GCM_NONCE_SIZE) { it.toByte() },
        )
        return PmvContainerFormat.EncodedBlock(header, ByteArray(cipherSize) { (it * 17).toByte() })
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + block.header.cipherSize
}
