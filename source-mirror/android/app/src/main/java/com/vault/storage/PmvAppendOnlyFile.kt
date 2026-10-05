package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * 最终 PMV 格式的追加写与双 Superblock 恢复原型。
 *
 * 该类服务于 PMVE 追加写容器。调用方负责在传入前完成块加密；这里仅保证提交顺序、落盘边界、
 * 角色约束，以及进程内同路径串行化与跨进程文件锁。
 */
class PmvAppendOnlyFile private constructor(
    private val file: File,
    authenticationKey: ByteArray,
) : Closeable {
    private val authenticationKey = authenticationKey.copyOf()
    private var closed = false

    data class State(
        val activeSlot: Int,
        val superblock: PmvContainerFormat.Superblock,
    )

    data class BlockRef(
        val offset: Long,
        val length: Long,
        val blockType: PmvContainerFormat.BlockType,
        val objectId: UUID,
        val revision: Long,
        val chunkIndex: Int,
    )

    internal enum class WriteStage { AFTER_APPEND, BEFORE_COMMIT, BEFORE_SUPERBLOCK }

    /**
     * Single-writer streaming transaction. Only compact [BlockRef] metadata is retained; ciphertext is
     * written immediately and never accumulated by the transaction.
     */
    inner class Transaction internal constructor(
        private val output: RandomAccessFile,
        private val processLock: ReentrantLock,
        private val lockFile: RandomAccessFile,
        private val osLock: FileLock,
        val baseSnapshot: State,
        private val faultInjector: ((WriteStage) -> Unit)?,
    ) : Closeable {
        val vaultId: UUID get() = baseSnapshot.superblock.vaultId
        val baseSequence: Long get() = baseSnapshot.superblock.sequence
        val nextRevision: Long get() = Math.addExact(baseSequence, 1L)
        val parentCommitId: UUID? = if (baseSequence == 0L) null else run {
            readBlock(output, baseSnapshot, baseSnapshot.superblock.latestCommitOffset).header.objectId
        }

        private var lastAppended: BlockRef? = null
        private var appendTail: Long = baseSnapshot.superblock.committedFileEnd
        private var finished = false

        @Synchronized
        fun appendBlock(block: PmvContainerFormat.EncodedBlock): BlockRef {
            checkActive()
            try {
                require(block.header.blockType != PmvContainerFormat.BlockType.COMMIT) {
                    "Commit Block 只能由 publish 写入"
                }
                val offset = output.filePointer
                output.writeBlock(block)
                val reference = BlockRef(
                    offset, storedLength(block), block.header.blockType, block.header.objectId,
                    block.header.objectRevision, block.header.chunkIndex,
                )
                lastAppended = reference
                appendTail = Math.addExact(reference.offset, reference.length)
                faultInjector?.invoke(WriteStage.AFTER_APPEND)
                return reference
            } catch (failure: Throwable) {
                abortQuietly(failure)
                throw failure
            }
        }

        /** Authenticate and atomically publish the already-streamed snapshot. */
        @Synchronized
        fun publish(
            indexRootRef: BlockRef,
            encryptedCommit: PmvContainerFormat.EncodedBlock,
            commit: PmvCommitCodec.Commit,
            indexRootKey: ByteArray,
            integrityKey: ByteArray,
            trustedSigningPublicKey: ByteArray = commit.signingPublicKey,
        ): State {
            checkActive()
            try {
                val newest = readState(output)
                require(newest.superblock.sequence == baseSequence) { "写事务基线已过期" }
                require(newest.superblock.vaultId == vaultId && commit.vaultId == vaultId) { "Commit vault_id 与容器不一致" }
                require(commit.revision == nextRevision) { "Commit revision 必须紧随事务基线" }
                require(commit.parentCommitId == parentCommitId) { "Commit parent_commit_id 未指向事务基线" }
                require(PmvCommitCodec.verifySignature(commit)) { "Commit Ed25519 签名无效" }
                require(trustedSigningPublicKey.size == PmvCommitCodec.PUBLIC_KEY_SIZE &&
                    MessageDigest.isEqual(trustedSigningPublicKey, commit.signingPublicKey)) {
                    "Commit 签名身份不是 Vault 信任身份"
                }
                require(encryptedCommit.header.blockType == PmvContainerFormat.BlockType.COMMIT &&
                    encryptedCommit.header.objectId == commit.commitId &&
                    encryptedCommit.header.objectRevision == commit.revision &&
                    encryptedCommit.header.chunkIndex == -1 && encryptedCommit.header.flags == 0) {
                    "Commit Block 与 typed Commit 不一致"
                }
                require(lastAppended == indexRootRef &&
                    indexRootRef.blockType == PmvContainerFormat.BlockType.INDEX_PAGE) { "Index Root 不属于当前事务" }
                require(commit.indexRootOffset == indexRootRef.offset && commit.indexRootLength == indexRootRef.length) {
                    "Commit 未绑定实际 Index Root"
                }
                validatePreviousCommitIdentity(commit, integrityKey)
                validateStreamedVaultRoot(indexRootRef, commit, indexRootKey)

                val commitKey = PmvKeySchedule.deriveCommitBlockKey(integrityKey, commit.commitId, commit.revision)
                try {
                    val plaintext = PmvBlockCrypto.open(vaultId, commitKey, encryptedCommit)
                    try { require(PmvCommitCodec.decode(plaintext) == commit) { "加密 Commit 与 typed Commit 不一致" } }
                    finally { plaintext.fill(0) }
                } finally { commitKey.fill(0) }

                output.fd.sync()
                faultInjector?.invoke(WriteStage.BEFORE_COMMIT)
                val commitOffset = output.filePointer
                output.writeBlock(encryptedCommit)
                val committedEnd = output.filePointer
                output.fd.sync()
                faultInjector?.invoke(WriteStage.BEFORE_SUPERBLOCK)

                val updated = baseSnapshot.superblock.copy(
                    sequence = nextRevision,
                    latestCommitOffset = commitOffset,
                    latestIndexOffset = indexRootRef.offset,
                    committedFileEnd = committedEnd,
                )
                val targetSlot = 1 - baseSnapshot.activeSlot
                output.seek(targetSlot * PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
                output.write(PmvContainerFormat.encodeSuperblock(updated, authenticationKey))
                output.fd.sync()
                finished = true
                releaseResources()
                return State(targetSlot, updated)
            } catch (failure: Throwable) {
                abortQuietly(failure)
                throw failure
            }
        }

        @Synchronized
        fun abort() {
            if (finished) return
            try {
                output.setLength(baseSnapshot.superblock.committedFileEnd)
                output.fd.sync()
            } finally {
                finished = true
                releaseResources()
            }
        }

        @Synchronized override fun close() = abort()

        internal fun retainedCiphertextBytesForTest(): Long = 0L

        private fun validatePreviousCommitIdentity(commit: PmvCommitCodec.Commit, integrityKey: ByteArray) {
            if (baseSequence == 0L) return
            val previousBlock = readBlock(output, baseSnapshot, baseSnapshot.superblock.latestCommitOffset)
            val key = PmvKeySchedule.deriveCommitBlockKey(integrityKey, previousBlock.header.objectId, previousBlock.header.objectRevision)
            val plaintext = try { PmvBlockCrypto.open(vaultId, key, previousBlock) } finally { key.fill(0) }
            val previous = try { PmvCommitCodec.decode(plaintext) } finally { plaintext.fill(0) }
            require(previous.commitId == parentCommitId && previous.revision == baseSequence &&
                previous.vaultId == vaultId && PmvCommitCodec.verifySignature(previous)) { "事务基线 Commit 无效" }
            require(MessageDigest.isEqual(previous.signingPublicKey, commit.signingPublicKey)) { "Commit 签名身份发生变化" }
        }

        private fun validateStreamedVaultRoot(reference: BlockRef, commit: PmvCommitCodec.Commit, indexRootKey: ByteArray) {
            val block = readStreamedBlock(reference)
            require(block.header.objectRevision == nextRevision && block.header.chunkIndex == -1 &&
                block.header.flags == 0 && block.header.codecId == 0) { "VaultRoot Block Header 角色无效" }
            val key = PmvKeySchedule.deriveIndexPageKey(
                indexRootKey, block.header.objectId, block.header.objectRevision,
                PmvKeySchedule.IndexPageType.VAULT_ROOT,
            )
            val plaintext = try { PmvBlockCrypto.open(vaultId, key, block) } finally { key.fill(0) }
            val root = try { PmvVaultRootCodec.decode(plaintext) } finally { plaintext.fill(0) }
            require(MessageDigest.isEqual(PmvVaultRootCodec.logicalDigest(root), commit.rootDigest)) {
                "Commit root_digest 与流式 VaultRoot 不一致"
            }
        }

        private fun readStreamedBlock(reference: BlockRef): PmvContainerFormat.EncodedBlock {
            output.seek(reference.offset)
            val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE).also(output::readFully)
            val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
            require(Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), header.cipherSize) == reference.length)
            require(header.blockType == reference.blockType && header.objectId == reference.objectId &&
                header.objectRevision == reference.revision && header.chunkIndex == reference.chunkIndex) {
                "流式 Block Header 与 BlockRef 不一致"
            }
            val ciphertext = ByteArray(header.cipherSize.toInt()).also(output::readFully)
            output.seek(appendTail)
            return PmvContainerFormat.EncodedBlock(header, ciphertext)
        }

        private fun abortQuietly(primary: Throwable) {
            try { abort() } catch (rollback: Throwable) { primary.addSuppressed(rollback) }
        }
        private fun checkActive() { check(!finished) { "写事务已结束" }; checkOpen() }
        private fun releaseResources() {
            try { osLock.release() } finally {
                try { lockFile.close() } finally {
                    try { output.close() } finally { processLock.unlock() }
                }
            }
        }
    }

    @Synchronized
    fun beginWrite(expectedBaseSequence: Long): Transaction =
        beginWriteInternal(expectedBaseSequence, null)

    internal fun beginWriteInternal(
        expectedBaseSequence: Long,
        faultInjector: ((WriteStage) -> Unit)?,
    ): Transaction {
        checkOpen()
        require(expectedBaseSequence >= 0) { "事务基线 sequence 无效" }
        val processLock = processWriteLocks.computeIfAbsent(file.canonicalFile.path) { ReentrantLock() }
        processLock.lock()
        var output: RandomAccessFile? = null
        var lockFile: RandomAccessFile? = null
        var osLock: FileLock? = null
        try {
            lockFile = RandomAccessFile(writerLockFile(file), "rw")
            osLock = lockFile.channel.lock()
            output = RandomAccessFile(file, "rw")
            val current = readState(output)
            require(newestPublishedSequence(output) == current.superblock.sequence) {
                "最新发布的 PMV Superblock 结构损坏，写入前必须显式恢复"
            }
            require(current.superblock.sequence == expectedBaseSequence) { "写事务基线已过期" }
            output.setLength(current.superblock.committedFileEnd)
            output.seek(current.superblock.committedFileEnd)
            return Transaction(
                requireNotNull(output),
                processLock,
                requireNotNull(lockFile),
                requireNotNull(osLock),
                current,
                faultInjector,
            )
        } catch (failure: Throwable) {
            try { osLock?.release() } catch (_: Throwable) {}
            try { lockFile?.close() } catch (_: Throwable) {}
            try { output?.close() } catch (_: Throwable) {}
            processLock.unlock()
            throw failure
        }
    }

    private fun newestPublishedSequence(input: RandomAccessFile): Long {
        val candidates = (0..1).mapNotNull { slot ->
            try {
                input.seek(slot * PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
                val raw = ByteArray(PmvContainerFormat.SUPERBLOCK_SIZE).also(input::readFully)
                PmvContainerFormat.decodeSuperblock(raw, authenticationKey).sequence
            } catch (_: Exception) { null }
        }
        require(candidates.isNotEmpty()) { "没有认证的 PMV Superblock" }
        return candidates.max()
    }

    @Synchronized
    fun state(): State {
        checkOpen()
        return readState()
    }

    /** 从当前已提交快照中按偏移读取一个 Block，不扫描前置内容。 */
    @Synchronized
    fun readBlock(
        offset: Long,
        expectedType: PmvContainerFormat.BlockType? = null,
    ): PmvContainerFormat.EncodedBlock {
        checkOpen()
        return readBlock(readState(), offset, expectedType)
    }

    @Synchronized
    internal fun candidateStates(): List<State> {
        checkOpen()
        return RandomAccessFile(file, "r").use(::readStateCandidates)
    }

    internal fun readBlock(
        snapshot: State,
        offset: Long,
        expectedType: PmvContainerFormat.BlockType? = null,
    ): PmvContainerFormat.EncodedBlock {
        checkOpen()
        val committedFileEnd = snapshot.superblock.committedFileEnd
        require(offset >= PmvContainerFormat.DATA_START && offset <= committedFileEnd - PmvContainerFormat.BLOCK_HEADER_SIZE) {
            "Block Header 超出当前提交边界"
        }
        return RandomAccessFile(file, "r").use { input ->
            input.seek(offset)
            val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
            input.readFully(rawHeader)
            val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
            if (expectedType != null) {
                require(header.blockType == expectedType) { "Block 类型与索引角色不一致" }
            }
            val blockEnd = Math.addExact(
                Math.addExact(offset, PmvContainerFormat.BLOCK_HEADER_SIZE.toLong()),
                header.cipherSize,
            )
            require(blockEnd <= committedFileEnd) { "Block 密文超出当前提交边界" }
            val ciphertext = ByteArray(header.cipherSize.toInt())
            input.readFully(ciphertext)
            PmvContainerFormat.EncodedBlock(header, ciphertext)
        }
    }

    /**
     * 提交顺序：回收未提交尾部，追加数据并 fsync，再追加索引和 Commit 并 fsync，最后切换备用
     * Superblock 并再次 fsync。因此任一步骤中断后，重开文件都只会看到旧提交或完整的新提交。
     */
    @Synchronized
    @Deprecated("仅供未接入 Commit Codec 的原型测试；生产写入请使用 commitAuthenticated")
    fun commit(
        dataBlocks: List<PmvContainerFormat.EncodedBlock>,
        indexBlock: PmvContainerFormat.EncodedBlock,
        commitBlock: PmvContainerFormat.EncodedBlock,
    ): State = commit(dataBlocks, listOf(indexBlock), commitBlock)

    @Synchronized
    @Deprecated("仅供未接入 Commit Codec 的原型测试；生产写入请使用 commitAuthenticated")
    fun commit(
        dataBlocks: List<PmvContainerFormat.EncodedBlock>,
        indexBlocks: List<PmvContainerFormat.EncodedBlock>,
        commitBlock: PmvContainerFormat.EncodedBlock,
    ): State = commitInternal(dataBlocks, indexBlocks, commitBlock, null)

    /**
     * 生产写入入口。除追加顺序外，还将明文 Commit 的身份及 Index Root 引用与实际布局绑定，
     * 避免 Superblock 被推进到一个结构上不匹配的 Commit。
    */
    @Synchronized
    @Deprecated("原型静态 Commit Key；生产写入必须传 indexRootKey 与 integrityKey 使用分层派生")
    fun commitAuthenticated(
        dataBlocks: List<PmvContainerFormat.EncodedBlock>,
        indexBlocks: List<PmvContainerFormat.EncodedBlock>,
        commitBlock: PmvContainerFormat.EncodedBlock,
        commit: PmvCommitCodec.Commit,
        expectedBaseSequence: Long,
        commitKey: ByteArray,
    ): State {
        val plaintext = PmvBlockCrypto.open(commit.vaultId, commitKey, commitBlock)
        try {
            require(PmvCommitCodec.decode(plaintext) == commit) {
                "加密 Commit Block 与 typed Commit 不一致"
            }
        } finally {
            plaintext.fill(0)
        }
        return commitInternal(dataBlocks, indexBlocks, commitBlock, commit, expectedBaseSequence, commitKey)
    }

    /**
     * Suite-1 authenticated append. The commit and every index page use immutable, purpose-separated
     * block keys. [indexBlocks] must start with PMVR, followed by the referenced Entry root/page set.
     */
    @Synchronized
    fun commitAuthenticated(
        dataBlocks: List<PmvContainerFormat.EncodedBlock>,
        indexBlocks: List<PmvContainerFormat.EncodedBlock>,
        commitBlock: PmvContainerFormat.EncodedBlock,
        commit: PmvCommitCodec.Commit,
        expectedBaseSequence: Long,
        indexRootKey: ByteArray,
        integrityKey: ByteArray,
    ): State {
        val commitKey = PmvKeySchedule.deriveCommitBlockKey(integrityKey, commit.commitId, commit.revision)
        try {
            val plaintext = PmvBlockCrypto.open(commit.vaultId, commitKey, commitBlock)
            try {
                require(PmvCommitCodec.decode(plaintext) == commit) {
                    "加密 Commit Block 与 typed Commit 不一致"
                }
            } finally {
                plaintext.fill(0)
            }
            validateCompositeRoot(commit.vaultId, indexBlocks, commit, indexRootKey)
            return commitInternal(
                dataBlocks,
                indexBlocks,
                commitBlock,
                commit,
                expectedBaseSequence,
                integrityKey,
                derivedCommitKeys = true,
            )
        } finally {
            commitKey.fill(0)
        }
    }

    private fun commitInternal(
        dataBlocks: List<PmvContainerFormat.EncodedBlock>,
        indexBlocks: List<PmvContainerFormat.EncodedBlock>,
        commitBlock: PmvContainerFormat.EncodedBlock,
        authenticatedCommit: PmvCommitCodec.Commit?,
        expectedBaseSequence: Long? = null,
        commitKey: ByteArray? = null,
        derivedCommitKeys: Boolean = false,
    ): State {
        checkOpen()
        require(indexBlocks.isNotEmpty()) { "每次提交至少需要一个索引页" }
        require(indexBlocks.all { it.header.blockType == PmvContainerFormat.BlockType.INDEX_PAGE }) {
            "所有索引块必须使用 INDEX_PAGE 类型"
        }
        require(commitBlock.header.blockType == PmvContainerFormat.BlockType.COMMIT) {
            "提交块必须使用 COMMIT 类型"
        }
        require(dataBlocks.none {
            it.header.blockType == PmvContainerFormat.BlockType.INDEX_PAGE ||
                it.header.blockType == PmvContainerFormat.BlockType.COMMIT
        }) { "数据块不能冒充 INDEX_PAGE 或 COMMIT" }

        return withExclusiveWrite(file) { output ->
            val current = readState(output)
            val expectedIndexOffset = dataBlocks.fold(current.superblock.committedFileEnd) { offset, block ->
                Math.addExact(offset, storedLength(block))
            }
            if (authenticatedCommit != null) {
                require(current.superblock.sequence == expectedBaseSequence) {
                    "提交基线已过期"
                }
                require(authenticatedCommit.revision == Math.addExact(current.superblock.sequence, 1L)) {
                    "Commit revision 必须紧随当前 Superblock sequence"
                }
                require(PmvCommitCodec.verifySignature(authenticatedCommit)) { "Commit Ed25519 签名无效" }
                require(authenticatedCommit.vaultId == current.superblock.vaultId) {
                    "Commit vault_id 与容器不一致"
                }
                require(commitBlock.header.objectId == authenticatedCommit.commitId) {
                    "Commit Block object_id 与 Commit UUID 不一致"
                }
                require(commitBlock.header.objectRevision == authenticatedCommit.revision) {
                    "Commit Block revision 与 Commit 明文不一致"
                }
                require(authenticatedCommit.indexRootOffset == expectedIndexOffset) {
                    "Commit Index Root 偏移与实际布局不一致"
                }
                require(authenticatedCommit.indexRootLength == storedLength(indexBlocks.first())) {
                    "Commit Index Root 长度与实际 Block 不一致"
                }
                if (current.superblock.sequence == 0L) {
                    require(authenticatedCommit.parentCommitId == null) { "首个 Commit 不得包含父提交" }
                } else {
                    requireNotNull(commitKey) { "认证追加必须提供 Commit Key" }
                    val previousBlock = readBlock(output, current, current.superblock.latestCommitOffset)
                    val previousKey = if (derivedCommitKeys) {
                        PmvKeySchedule.deriveCommitBlockKey(
                            commitKey,
                            previousBlock.header.objectId,
                            previousBlock.header.objectRevision,
                        )
                    } else {
                        commitKey
                    }
                    val previousPlaintext = try {
                        PmvBlockCrypto.open(current.superblock.vaultId, previousKey, previousBlock)
                    } finally {
                        if (derivedCommitKeys) previousKey.fill(0)
                    }
                    val previousCommit = try {
                        PmvCommitCodec.decode(previousPlaintext)
                    } finally {
                        previousPlaintext.fill(0)
                    }
                    require(previousBlock.header.blockType == PmvContainerFormat.BlockType.COMMIT) {
                        "当前 Superblock 未引用 Commit Block"
                    }
                    require(previousBlock.header.objectId == previousCommit.commitId) {
                        "当前 Commit Block object_id 与 Commit UUID 不一致"
                    }
                    require(previousBlock.header.objectRevision == previousCommit.revision) {
                        "当前 Commit Block revision 与 Commit 明文不一致"
                    }
                    require(previousCommit.vaultId == current.superblock.vaultId) { "当前 Commit 属于其他 Vault" }
                    require(previousCommit.revision == current.superblock.sequence) {
                        "当前 Commit revision 与 Superblock sequence 不一致"
                    }
                    require(PmvCommitCodec.verifySignature(previousCommit)) { "当前 Commit Ed25519 签名无效" }
                    require(MessageDigest.isEqual(previousCommit.signingPublicKey, authenticatedCommit.signingPublicKey)) {
                        "Commit 签名身份发生变化"
                    }
                    require(authenticatedCommit.parentCommitId == previousCommit.commitId) {
                        "Commit parent_commit_id 未指向当前提交"
                    }
                }
            }
            output.setLength(current.superblock.committedFileEnd)
            output.seek(current.superblock.committedFileEnd)

            dataBlocks.forEach { output.writeBlock(it) }
            output.fd.sync()

            val indexOffset = output.filePointer
            indexBlocks.forEach { output.writeBlock(it) }
            val commitOffset = output.filePointer
            check(indexOffset == expectedIndexOffset) { "Index Root 实际偏移与预计算布局不一致" }
            output.writeBlock(commitBlock)
            val committedFileEnd = output.filePointer
            output.fd.sync()

            val updated = current.superblock.copy(
                sequence = Math.addExact(current.superblock.sequence, 1L),
                latestCommitOffset = commitOffset,
                latestIndexOffset = indexOffset,
                committedFileEnd = committedFileEnd,
            )
            val targetSlot = 1 - current.activeSlot
            output.seek(targetSlot * PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
            output.write(PmvContainerFormat.encodeSuperblock(updated, authenticationKey))
            output.fd.sync()
            State(targetSlot, updated)
        }
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            authenticationKey.fill(0)
        }
    }

    private fun readState(): State {
        return RandomAccessFile(file, "r").use(::readState)
    }

    private fun readState(input: RandomAccessFile): State = readStateCandidates(input).first()

    private fun readStateCandidates(input: RandomAccessFile): List<State> {
        val fileLength = input.length()
        require(fileLength >= PmvContainerFormat.DATA_START) { "PMV 文件小于容器元数据区域" }
        val candidates = (0..1).mapNotNull { slot ->
            try {
                val raw = ByteArray(PmvContainerFormat.SUPERBLOCK_SIZE)
                input.seek(slot * PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
                input.readFully(raw)
                val superblock = PmvContainerFormat.decodeSuperblock(raw, authenticationKey)
                validateCommittedSnapshot(input, superblock, fileLength)
                State(slot, superblock)
            } catch (_: Exception) {
                null
            }
        }
        require(candidates.isNotEmpty()) { "没有可恢复的 PMV Superblock" }
        val vaultIds = candidates.map { it.superblock.vaultId }.distinct()
        require(vaultIds.size == 1) { "双 Superblock 的 vault_id 不一致" }
        return candidates.sortedByDescending { it.superblock.sequence }
    }

    private fun validateCommittedSnapshot(
        input: RandomAccessFile,
        superblock: PmvContainerFormat.Superblock,
        fileLength: Long,
    ) {
        require(superblock.committedFileEnd <= fileLength) { "提交边界超过实际文件长度" }
        if (superblock.sequence == 0L) {
            require(superblock.latestIndexOffset == 0L && superblock.latestCommitOffset == 0L) {
                "初始 Superblock 不应引用提交块"
            }
            return
        }
        validateReferencedBlock(
            input,
            superblock.latestIndexOffset,
            superblock.committedFileEnd,
            PmvContainerFormat.BlockType.INDEX_PAGE,
        )
        validateReferencedBlock(
            input,
            superblock.latestCommitOffset,
            superblock.committedFileEnd,
            PmvContainerFormat.BlockType.COMMIT,
        )
        require(superblock.latestIndexOffset < superblock.latestCommitOffset) { "索引必须位于 Commit 之前" }
    }

    private fun validateReferencedBlock(
        input: RandomAccessFile,
        offset: Long,
        committedFileEnd: Long,
        expectedType: PmvContainerFormat.BlockType,
    ) {
        require(offset >= PmvContainerFormat.DATA_START && offset <= committedFileEnd - PmvContainerFormat.BLOCK_HEADER_SIZE) {
            "提交引用的 Block Header 超出边界"
        }
        val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
        input.seek(offset)
        input.readFully(rawHeader)
        val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
        require(header.blockType == expectedType) { "提交引用的 Block 类型无效" }
        val blockEnd = Math.addExact(
            Math.addExact(offset, PmvContainerFormat.BLOCK_HEADER_SIZE.toLong()),
            header.cipherSize,
        )
        require(blockEnd <= committedFileEnd) { "提交引用的 Block 密文超出边界" }
    }

    private fun checkOpen() {
        check(!closed) { "PMV 文件已关闭" }
    }

    private fun RandomAccessFile.writeBlock(block: PmvContainerFormat.EncodedBlock) {
        write(PmvContainerFormat.encodeBlockHeader(block.header))
        write(block.ciphertext)
    }

    private fun readBlock(
        input: RandomAccessFile,
        snapshot: State,
        offset: Long,
    ): PmvContainerFormat.EncodedBlock {
        require(offset >= PmvContainerFormat.DATA_START && offset <= snapshot.superblock.committedFileEnd - PmvContainerFormat.BLOCK_HEADER_SIZE) {
            "Block Header 超出当前提交边界"
        }
        input.seek(offset)
        val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
        input.readFully(rawHeader)
        val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
        val blockEnd = Math.addExact(
            Math.addExact(offset, PmvContainerFormat.BLOCK_HEADER_SIZE.toLong()),
            header.cipherSize,
        )
        require(blockEnd <= snapshot.superblock.committedFileEnd) { "Block 密文超出当前提交边界" }
        return PmvContainerFormat.EncodedBlock(
            header,
            ByteArray(header.cipherSize.toInt()).also(input::readFully),
        )
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), block.header.cipherSize)

    private fun validateCompositeRoot(
        vaultId: UUID,
        indexBlocks: List<PmvContainerFormat.EncodedBlock>,
        commit: PmvCommitCodec.Commit,
        indexRootKey: ByteArray,
    ) {
        require(indexBlocks.isNotEmpty()) { "提交缺少 VaultRoot" }
        val offsets = ArrayList<Long>(indexBlocks.size)
        var offset = commit.indexRootOffset
        indexBlocks.forEach { block ->
            offsets += offset
            offset = Math.addExact(offset, storedLength(block))
        }
        val vaultRootBlock = indexBlocks.first()
        val vaultRootKey = PmvKeySchedule.deriveIndexPageKey(
            indexRootKey,
            vaultRootBlock.header.objectId,
            vaultRootBlock.header.objectRevision,
            PmvKeySchedule.IndexPageType.VAULT_ROOT,
        )
        val vaultRootPlaintext = try {
            try {
                PmvBlockCrypto.open(vaultId, vaultRootKey, vaultRootBlock)
            } catch (error: GeneralSecurityException) {
                throw IllegalArgumentException("VaultRoot 无法使用派生页面密钥认证", error)
            }
        } finally {
            vaultRootKey.fill(0)
        }
        val vaultRoot = try {
            PmvVaultRootCodec.decode(vaultRootPlaintext)
        } finally {
            vaultRootPlaintext.fill(0)
        }
        require(MessageDigest.isEqual(commit.rootDigest, PmvVaultRootCodec.logicalDigest(vaultRoot))) {
            "Commit root_digest 与 VaultRoot 不一致"
        }
        val entryIndex = offsets.indexOf(vaultRoot.entry.offset)
        require(entryIndex > 0) { "VaultRoot Entry 子根未包含在本次索引块中" }
        val entryBlock = indexBlocks[entryIndex]
        require(vaultRoot.entry.length == storedLength(entryBlock)) { "VaultRoot Entry 子根长度不一致" }
        val entryKey = PmvKeySchedule.deriveIndexPageKey(
            indexRootKey,
            entryBlock.header.objectId,
            entryBlock.header.objectRevision,
            PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )
        val entryPlaintext = try {
            PmvBlockCrypto.open(vaultId, entryKey, entryBlock)
        } finally {
            entryKey.fill(0)
        }
        val entryRoot = try {
            PmvEntryIndexRootCodec.decode(entryPlaintext)
        } finally {
            entryPlaintext.fill(0)
        }
        require(MessageDigest.isEqual(vaultRoot.entry.digest, PmvIntegrity.entryRootDigest(entryRoot))) {
            "VaultRoot Entry 子根摘要不一致"
        }
    }

    companion object {
        private val processWriteLocks = ConcurrentHashMap<String, ReentrantLock>()

        fun create(
            file: File,
            vaultId: UUID,
            authenticationKey: ByteArray,
            kdfParametersOffset: Long = 0,
            featureFlags: Long = 0,
        ): PmvAppendOnlyFile {
            require(authenticationKey.size >= 32) { "Superblock 认证密钥至少为 256 bit" }
            require(!file.isDirectory) { "PMV 路径不能是目录" }
            val initial = PmvContainerFormat.Superblock(
                vaultId = vaultId,
                sequence = 0,
                latestCommitOffset = 0,
                latestIndexOffset = 0,
                committedFileEnd = PmvContainerFormat.DATA_START,
                kdfParametersOffset = kdfParametersOffset,
                featureFlags = featureFlags,
            )
            withExclusiveWrite(file) { output ->
                require(output.length() == 0L) { "拒绝覆盖非空 PMV 文件" }
                output.setLength(PmvContainerFormat.DATA_START)
                output.seek(0)
                output.write(PmvContainerFormat.encodeSuperblock(initial, authenticationKey))
                output.write(ByteArray(PmvContainerFormat.SUPERBLOCK_SIZE))
                output.fd.sync()
            }
            return PmvAppendOnlyFile(file, authenticationKey)
        }

        fun open(file: File, authenticationKey: ByteArray): PmvAppendOnlyFile {
            require(authenticationKey.size >= 32) { "Superblock 认证密钥至少为 256 bit" }
            require(file.isFile) { "PMV 文件不存在" }
            return PmvAppendOnlyFile(file, authenticationKey).also { it.state() }
        }

        internal fun <T> withExclusiveWriterLock(file: File, action: () -> T): T {
            val path = file.canonicalFile.path
            val processLock = processWriteLocks.computeIfAbsent(path) { ReentrantLock() }
            return processLock.withLock {
                if (file.name.endsWith(".tmp")) return@withLock action()
                RandomAccessFile(writerLockFile(file), "rw").use { lockFile ->
                    lockFile.channel.lock().use {
                        action()
                    }
                }
            }
        }

        private fun <T> withExclusiveWrite(file: File, action: (RandomAccessFile) -> T): T =
            withExclusiveWriterLock(file) { RandomAccessFile(file, "rw").use(action) }

        private fun writerLockFile(file: File): File = File(file.parentFile, "${file.name}.writer.lock")
    }
}
