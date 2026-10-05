package com.vault.storage

import com.vault.model.Entry
import com.vault.crypto.PmvKeySchedule
import java.io.Closeable
import java.security.MessageDigest
import java.util.UUID

/** 基于稳定 Commit 头索引按需读取单条 Entry；不会遍历或解密无关 Entry Block。 */
class PmvEntryReader(
    private val container: PmvAppendOnlyFile,
    private val vaultId: UUID,
    entryRootKey: ByteArray,
    indexRootKey: ByteArray,
    integrityKey: ByteArray,
    trustedVaultSigningPublicKey: ByteArray,
    private val allowLegacyStaticKeys: Boolean = false,
) : Closeable {
    private val entryRootKey = copyKey(entryRootKey, "Entry Root")
    private val indexRootKey = copyKey(indexRootKey, "Index Root")
    private val integrityKey = copyKey(integrityKey, "Integrity")
    private val trustedVaultSigningPublicKey = trustedVaultSigningPublicKey.copyOf().also {
        require(it.size == PmvCommitCodec.PUBLIC_KEY_SIZE) { "Vault Signing Public Key 必须为 32 字节" }
    }
    private var closed = false

    data class Summary(
        val entryId: UUID,
        val entryType: String,
        val displayTitle: String,
        val favorite: Boolean,
        val iconObjectId: UUID?,
        val modifiedAtEpochMillis: Long,
        val revision: Long,
    )

    class Cursor internal constructor(
        val sequence: Long,
        val pageIndex: Int,
    )

    data class ListPage(
        val items: List<Summary>,
        val nextCursor: Cursor?,
    )

    private data class Snapshot(
        val state: PmvAppendOnlyFile.State,
        val root: PmvEntryIndexRootCodec.Root,
    )

    init {
        try {
            require(container.state().superblock.vaultId == vaultId) { "Reader vault_id 与容器不一致" }
        } catch (error: Exception) {
            this.entryRootKey.fill(0)
            this.indexRootKey.fill(0)
            this.integrityKey.fill(0)
            this.trustedVaultSigningPublicKey.fill(0)
            throw error
        }
    }

    @Synchronized
    fun listPage(cursor: Cursor? = null): ListPage {
        check(!closed) { "Entry Reader 已关闭" }
        val candidates = resolveSnapshots()
        if (cursor != null) {
            val snapshot = candidates.firstOrNull { it.state.superblock.sequence == cursor.sequence }
                ?: throw IllegalArgumentException("EntryIndex 游标不属于可认证的提交快照")
            return listPage(snapshot, cursor.pageIndex)
        }
        var lastError: Exception? = null
        candidates.forEach { snapshot ->
            try {
                return listPage(snapshot, 0)
            } catch (error: Exception) {
                lastError = error
            }
        }
        throw IllegalArgumentException("没有可读取的 EntryIndex 页", lastError)
    }

    @Synchronized
    fun find(entryId: UUID): Entry? {
        check(!closed) { "Entry Reader 已关闭" }
        var lastError: Exception? = null
        resolveSnapshots().forEach { snapshot ->
            if (snapshot.state.superblock.latestIndexOffset == 0L) return null
            val directoryRecord = snapshot.root.findPage(entryId) ?: return null
            val record = try {
                readLeafPage(snapshot.state, directoryRecord).find(entryId) ?: return null
            } catch (error: Exception) {
                lastError = error
                return@forEach
            }
            if (record.state == PmvEntryIndexCodec.State.TOMBSTONE) {
                try {
                    readTombstone(snapshot.state, record)
                } catch (error: Exception) {
                    throw IllegalArgumentException("最新提交的 Tombstone 无法认证", error)
                }
                return null
            }
            try {
                return readEntry(snapshot.state, record)
            } catch (error: Exception) {
                lastError = error
            }
        }
        throw IllegalArgumentException("没有可读取的 Entry 快照", lastError)
    }

    /** Returns the newest authenticated index record without decrypting an ACTIVE Entry payload. */
    @Synchronized
    fun findRecord(entryId: UUID): PmvEntryIndexCodec.Record? {
        check(!closed) { "Entry Reader 已关闭" }
        val snapshot = resolveSnapshots().first()
        val directory = snapshot.root.findPage(entryId) ?: return null
        return readLeafPage(snapshot.state, directory).find(entryId)?.let { record ->
            record.copy(contentDigest = record.contentDigest.copyOf())
        }
    }

    @Synchronized
    fun allRecords(): List<PmvEntryIndexCodec.Record> {
        check(!closed) { "Entry Reader 已关闭" }
        val snapshot = resolveSnapshots().first()
        return snapshot.root.records.flatMap { directory ->
            readLeafPage(snapshot.state, directory).records.map { record ->
                record.copy(contentDigest = record.contentDigest.copyOf())
            }
        }
    }

    @Synchronized
    fun allPages(): List<PmvEntryIndexCodec.Page> {
        check(!closed) { "Entry Reader 已关闭" }
        val snapshot = resolveSnapshots().first()
        return snapshot.root.records.map { directory -> readLeafPage(snapshot.state, directory) }
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            entryRootKey.fill(0)
            indexRootKey.fill(0)
            integrityKey.fill(0)
            trustedVaultSigningPublicKey.fill(0)
        }
    }

    private fun readEntry(snapshot: PmvAppendOnlyFile.State, record: PmvEntryIndexCodec.Record): Entry {
        val indexedEnd = Math.addExact(record.offset, record.length)
        require(indexedEnd <= snapshot.superblock.committedFileEnd) { "EntryIndex 引用超出提交边界" }
        val encryptedEntry = container.readBlock(snapshot, record.offset, PmvContainerFormat.BlockType.ENTRY)
        val actualLength = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + encryptedEntry.header.cipherSize
        require(actualLength == record.length) { "EntryIndex 长度与 Entry Block 不一致" }
        require(encryptedEntry.header.objectId == record.entryId) { "EntryIndex ID 与 Entry Block 不一致" }
        require(encryptedEntry.header.objectRevision == record.revision) { "EntryIndex 修订与 Entry Block 不一致" }
        require(record.contentDigest.any { it != 0.toByte() }) { "ACTIVE Entry 必须包含非零内容摘要" }
        require(PmvIntegrity.encryptedBlockDigest(encryptedEntry).contentEquals(record.contentDigest)) {
            "Entry Block 摘要与索引不一致"
        }
        val entryKey = PmvKeySchedule.deriveEntryKey(entryRootKey, record.entryId, record.revision)
        val plaintext = try {
            PmvBlockCrypto.open(vaultId, entryKey, encryptedEntry)
        } finally {
            entryKey.fill(0)
        }
        return try {
            PmvEntryCodec.decode(plaintext, record.entryId).also { entry ->
                require(entry.secretType == record.entryType) { "EntryIndex 类型与 Entry 负载不一致" }
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun readTombstone(snapshot: PmvAppendOnlyFile.State, record: PmvEntryIndexCodec.Record) {
        val encrypted = container.readBlock(snapshot, record.offset, PmvContainerFormat.BlockType.TOMBSTONE)
        require(storedLength(encrypted) == record.length) { "Tombstone Block 长度与索引不一致" }
        require(encrypted.header.objectId == record.entryId && encrypted.header.objectRevision == record.revision) {
            "Tombstone Block 身份与索引不一致"
        }
        require(record.contentDigest.any { it != 0.toByte() } &&
            PmvIntegrity.encryptedBlockDigest(encrypted).contentEquals(record.contentDigest)) {
            "Tombstone Block 摘要与索引不一致"
        }
        val key = PmvKeySchedule.deriveEntryKey(entryRootKey, record.entryId, record.revision)
        val plaintext = try { PmvBlockCrypto.open(vaultId, key, encrypted) } finally { key.fill(0) }
        try {
            val tombstone = PmvTombstoneCodec.decode(plaintext)
            require(tombstone.entryId == record.entryId && tombstone.revision == record.revision) {
                "Tombstone 明文与索引不一致"
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), block.header.cipherSize)

    private fun listPage(snapshot: Snapshot, pageIndex: Int): ListPage {
        val superblock = snapshot.state.superblock
        if (superblock.latestIndexOffset == 0L || snapshot.root.records.isEmpty()) {
            return ListPage(emptyList(), null)
        }
        require(pageIndex in snapshot.root.records.indices) { "EntryIndex 游标页号无效" }
        val page = readLeafPage(snapshot.state, snapshot.root.records[pageIndex])
        return ListPage(
            items = page.records.asSequence()
                .filter { it.state == PmvEntryIndexCodec.State.ACTIVE }
                .map { record ->
                    Summary(
                        entryId = record.entryId,
                        entryType = record.entryType,
                        displayTitle = record.displayTitle,
                        favorite = record.favorite,
                        iconObjectId = record.iconObjectId,
                        modifiedAtEpochMillis = record.modifiedAtEpochMillis,
                        revision = record.revision,
                    )
                }.toList(),
            nextCursor = (pageIndex + 1).takeIf { it < snapshot.root.records.size }
                ?.let { Cursor(superblock.sequence, it) },
        )
    }

    private fun readIndexPage(snapshot: PmvAppendOnlyFile.State, pageOffset: Long): PmvEntryIndexCodec.Page {
        val encryptedPage = container.readBlock(snapshot, pageOffset, PmvContainerFormat.BlockType.INDEX_PAGE)
        val pagePlaintext = openIndexBlock(encryptedPage, PmvKeySchedule.IndexPageType.ENTRY_INDEX)
        return try {
            PmvEntryIndexCodec.decode(pagePlaintext)
        } finally {
            pagePlaintext.fill(0)
        }
    }

    private fun readLeafPage(
        snapshot: PmvAppendOnlyFile.State,
        directoryRecord: PmvEntryIndexRootCodec.Record,
    ): PmvEntryIndexCodec.Page {
        val page = readIndexPage(snapshot, directoryRecord.pageOffset)
        require(page.nextPageOffset == 0L) { "根目录模式下叶页不能包含链式下一页" }
        require(page.records.isNotEmpty()) { "EntryIndex 根目录不能引用空叶页" }
        require(page.records.first().entryId == directoryRecord.minEntryId) { "EntryIndex 叶页最小键与根目录不一致" }
        require(page.records.last().entryId == directoryRecord.maxEntryId) { "EntryIndex 叶页最大键与根目录不一致" }
        require(directoryRecord.pageDigest.any { it != 0.toByte() }) { "EntryIndex 根目录必须包含非零页摘要" }
        require(PmvIntegrity.entryPageDigest(page).contentEquals(directoryRecord.pageDigest)) {
            "EntryIndex 叶页逻辑摘要与根目录不一致"
        }
        return page
    }

    private fun resolveSnapshots(): List<Snapshot> {
        val snapshots = mutableListOf<Snapshot>()
        for (candidate in container.candidateStates()) {
            if (candidate.superblock.vaultId != vaultId) continue
            if (candidate.superblock.sequence == 0L) {
                snapshots += Snapshot(candidate, PmvEntryIndexRootCodec.Root(emptyList()))
                continue
            }
            try {
                val encryptedCommit = container.readBlock(
                    candidate,
                    candidate.superblock.latestCommitOffset,
                    PmvContainerFormat.BlockType.COMMIT,
                )
                val commitEnd = Math.addExact(
                    candidate.superblock.latestCommitOffset,
                    PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + encryptedCommit.header.cipherSize,
                )
                require(commitEnd == candidate.superblock.committedFileEnd) {
                    "Commit Block 不是当前提交边界的最后一个 Block"
                }
                val commitPlaintext = openCommitBlock(encryptedCommit)
                try {
                    val commit = PmvCommitCodec.decode(commitPlaintext)
                    require(encryptedCommit.header.objectId == commit.commitId) {
                        "Commit Block object_id 与 Commit UUID 不一致"
                    }
                    require(encryptedCommit.header.objectRevision == commit.revision) {
                        "Commit Block revision 与 Commit 明文不一致"
                    }
                    require(commit.vaultId == vaultId) { "Commit 属于其他 Vault" }
                    require(commit.revision == candidate.superblock.sequence) {
                        "Commit revision 与 Superblock sequence 不一致"
                    }
                    require(MessageDigest.isEqual(commit.signingPublicKey, trustedVaultSigningPublicKey)) {
                        "Commit 签名公钥与 Vault Identity 不匹配"
                    }
                    require(commit.indexRootOffset == candidate.superblock.latestIndexOffset) {
                        "Superblock Index Root 偏移与 Commit 不一致"
                    }
                    val rootBlock = container.readBlock(
                        candidate,
                        commit.indexRootOffset,
                        PmvContainerFormat.BlockType.INDEX_PAGE,
                    )
                    val actualRootLength = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + rootBlock.header.cipherSize
                    require(commit.indexRootLength == actualRootLength) {
                        "Commit Index Root 长度与 Block 不一致"
                    }
                    val roots = decodeCompositeRoot(candidate, rootBlock)
                    val root = roots.second
                    PmvCommitCodec.decodeAndVerify(
                        commitPlaintext,
                        vaultId,
                        roots.first,
                        trustedVaultSigningPublicKey,
                    )
                    snapshots += Snapshot(candidate, root)
                } finally {
                    commitPlaintext.fill(0)
                }
            } catch (_: Exception) {
                // 继续尝试上一个已认证 Superblock；不吞掉 VM Error。
            }
        }
        require(snapshots.isNotEmpty()) { "没有可认证的 EntryIndex 提交快照" }
        return snapshots
    }

    private fun decodeCompositeRoot(
        snapshot: PmvAppendOnlyFile.State,
        encryptedVaultRoot: PmvContainerFormat.EncodedBlock,
    ): Pair<ByteArray, PmvEntryIndexRootCodec.Root> {
        val plaintext = openIndexBlock(encryptedVaultRoot, PmvKeySchedule.IndexPageType.VAULT_ROOT)
        try {
            val vaultRoot = try {
                PmvVaultRootCodec.decode(plaintext)
            } catch (_: IllegalArgumentException) {
                require(allowLegacyStaticKeys) { "不允许读取原型 PMER 根" }
                // Transitional prototype compatibility: older tests/fixtures placed PMER directly
                // at latestIndexOffset. New writes must use PMVR.
                val legacyRoot = PmvEntryIndexRootCodec.decode(plaintext)
                return PmvIntegrity.entryRootDigest(legacyRoot) to legacyRoot
            }
            val entryReference = vaultRoot.entry
            val entryEnd = Math.addExact(entryReference.offset, entryReference.length)
            require(entryEnd <= snapshot.superblock.committedFileEnd) { "VaultRoot Entry 子根超出提交边界" }
            val encryptedEntryRoot = container.readBlock(
                snapshot,
                entryReference.offset,
                PmvContainerFormat.BlockType.INDEX_PAGE,
            )
            val actualLength = PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + encryptedEntryRoot.header.cipherSize
            require(actualLength == entryReference.length) { "VaultRoot Entry 子根长度不一致" }
            val entryPlaintext = openIndexBlock(encryptedEntryRoot, PmvKeySchedule.IndexPageType.ENTRY_INDEX)
            val entryRoot = try {
                PmvEntryIndexRootCodec.decode(entryPlaintext)
            } finally {
                entryPlaintext.fill(0)
            }
            require(MessageDigest.isEqual(entryReference.digest, PmvIntegrity.entryRootDigest(entryRoot))) {
                "VaultRoot Entry 子根摘要不一致"
            }
            return PmvVaultRootCodec.logicalDigest(vaultRoot) to entryRoot
        } finally {
            plaintext.fill(0)
        }
    }

    private fun openCommitBlock(block: PmvContainerFormat.EncodedBlock): ByteArray {
        val key = PmvKeySchedule.deriveCommitBlockKey(
            integrityKey,
            block.header.objectId,
            block.header.objectRevision,
        )
        return try {
            try {
                PmvBlockCrypto.open(vaultId, key, block)
            } catch (error: Exception) {
                if (!allowLegacyStaticKeys) throw error
                // Read-only compatibility for the pre-derived prototype fixture format.
                PmvBlockCrypto.open(vaultId, integrityKey, block)
            }
        } finally {
            key.fill(0)
        }
    }

    private fun openIndexBlock(
        block: PmvContainerFormat.EncodedBlock,
        pageType: PmvKeySchedule.IndexPageType,
    ): ByteArray {
        val key = PmvKeySchedule.deriveIndexPageKey(
            indexRootKey,
            block.header.objectId,
            block.header.objectRevision,
            pageType,
        )
        return try {
            try {
                PmvBlockCrypto.open(vaultId, key, block)
            } catch (error: Exception) {
                if (!allowLegacyStaticKeys) throw error
                // Read-only compatibility for the pre-derived prototype fixture format.
                PmvBlockCrypto.open(vaultId, indexRootKey, block)
            }
        } finally {
            key.fill(0)
        }
    }

    companion object {
        private fun copyKey(value: ByteArray, label: String): ByteArray {
            require(value.size == 32) { "$label Key 必须为 256 bit" }
            return value.copyOf()
        }
    }
}
