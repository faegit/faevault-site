package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PmvStreamingTransactionTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val auth = ByteArray(32) { it.toByte() }
    private val index = ByteArray(32) { (it + 32).toByte() }
    private val integrity = ByteArray(32) { (it + 64).toByte() }
    private val seed = ByteArray(32) { (it + 1).toByte() }

    @Test fun `append failure commit failure and superblock failure auto abort`() {
        PmvAppendOnlyFile.WriteStage.entries.forEach { failedStage ->
            val file = File.createTempFile("pmv-stream-fault-", ".bin").also { it.delete() }
            try {
                PmvAppendOnlyFile.create(file, vaultId, auth).use { container ->
                    val oldEnd = container.state().superblock.committedFileEnd
                    val transaction = container.beginWriteInternal(0) { stage ->
                        if (stage == failedStage) throw ExpectedFailure()
                    }
                    assertThrows(ExpectedFailure::class.java) {
                        if (failedStage == PmvAppendOnlyFile.WriteStage.AFTER_APPEND) {
                            transaction.appendBlock(block(PmvContainerFormat.BlockType.ENTRY, UUID.randomUUID(), 1, "x".encodeToByteArray()))
                        } else publish(transaction)
                    }
                    assertEquals(oldEnd, file.length())
                    assertEquals(0, PmvAppendOnlyFile.open(file, auth).use { it.state().superblock.sequence })
                }
            } finally { file.delete() }
        }
    }

    @Test fun `second writer blocks and becomes stale after first publishes`() {
        val file = File.createTempFile("pmv-stream-writers-", ".bin").also { it.delete() }
        val executor = Executors.newSingleThreadExecutor()
        try {
            PmvAppendOnlyFile.create(file, vaultId, auth).use { first ->
                val transaction = first.beginWrite(0)
                val started = CountDownLatch(1)
                val future = executor.submit<PmvAppendOnlyFile.Transaction> {
                    started.countDown(); PmvAppendOnlyFile.open(file, auth).use { it.beginWrite(0) }
                }
                assertTrue(started.await(1, TimeUnit.SECONDS))
                Thread.sleep(50)
                if (future.isDone) {
                    try {
                        future.get()
                        fail("第二个写事务未等待首个事务释放锁")
                    } catch (failure: Exception) {
                        throw AssertionError("第二个写事务在等待锁前异常退出", failure)
                    }
                }
                publish(transaction)
                assertThrows(Exception::class.java) { future.get(5, TimeUnit.SECONDS) }
            }
        } finally { executor.shutdownNow(); file.delete() }
    }

    @Test fun `one thousand chunks stream directly and close truncates unpublished tail`() {
        val file = File.createTempFile("pmv-stream-large-", ".bin").also { it.delete() }
        try {
            PmvAppendOnlyFile.create(file, vaultId, auth).use { container ->
                val transaction = container.beginWrite(0)
                repeat(1_000) { chunk ->
                    transaction.appendBlock(block(PmvContainerFormat.BlockType.ATTACHMENT_CHUNK, UUID(0, 1), 1,
                        byteArrayOf(chunk.toByte()), chunk))
                }
                assertEquals(0, transaction.retainedCiphertextBytesForTest())
                assertEquals(1, publish(transaction).superblock.sequence)
                val committedEnd = file.length()
                val aborted = container.beginWrite(1)
                aborted.appendBlock(block(PmvContainerFormat.BlockType.ENTRY, UUID.randomUUID(), 2, ByteArray(256)))
                assertTrue(file.length() > committedEnd)
                aborted.close()
                assertEquals(committedEnd, file.length())
            }
        } finally { file.delete() }
    }

    private fun publish(transaction: PmvAppendOnlyFile.Transaction): PmvAppendOnlyFile.State {
        val entryRoot = block(PmvContainerFormat.BlockType.INDEX_PAGE, UUID.randomUUID(), transaction.nextRevision, "entry-root".encodeToByteArray())
        val entryRef = transaction.appendBlock(entryRoot)
        val root = PmvVaultRootCodec.Root(PmvVaultRootCodec.Reference(
            PmvVaultRootCodec.RootType.ENTRY, entryRef.offset, entryRef.length, ByteArray(32) { it.toByte() }))
        val rootId = UUID.randomUUID()
        val rootKey = PmvKeySchedule.deriveIndexPageKey(index, rootId, transaction.nextRevision, PmvKeySchedule.IndexPageType.VAULT_ROOT)
        val rootBlock = try { PmvBlockCrypto.seal(transaction.vaultId, rootKey, PmvContainerFormat.BlockType.INDEX_PAGE,
            rootId, transaction.nextRevision, PmvVaultRootCodec.encode(root)) } finally { rootKey.fill(0) }
        val rootRef = transaction.appendBlock(rootBlock)
        val commit = PmvCommitCodec.sign(transaction.vaultId, UUID.randomUUID(), transaction.parentCommitId,
            transaction.nextRevision, rootRef.offset, rootRef.length, PmvVaultRootCodec.logicalDigest(root), seed)
        val commitKey = PmvKeySchedule.deriveCommitBlockKey(integrity, commit.commitId, commit.revision)
        val encryptedCommit = try { PmvBlockCrypto.seal(transaction.vaultId, commitKey, PmvContainerFormat.BlockType.COMMIT,
            commit.commitId, commit.revision, PmvCommitCodec.encode(commit)) } finally { commitKey.fill(0) }
        return transaction.publish(rootRef, encryptedCommit, commit, index, integrity, commit.signingPublicKey)
    }

    private fun block(type: PmvContainerFormat.BlockType, id: UUID, revision: Long, plain: ByteArray, chunkIndex: Int = -1) =
        PmvBlockCrypto.seal(vaultId, ByteArray(32), type, id, revision, plain, chunkIndex = chunkIndex)

    private class ExpectedFailure : RuntimeException()
}
