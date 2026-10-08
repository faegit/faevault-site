package com.vault.storage

import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.PmvKdfParameters
import com.vault.crypto.PmvKdfProfile
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.PasskeyRecord
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.net.URI
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/**
 * Production-facing PMV v1 store over the append-only primitives.
 *
 * [Session.saveFull] deliberately rebuilds the Entry index tree for each commit. Blocks remain
 * append-only and authenticated; page-level copy-on-write can replace this implementation later
 * without changing the public optimistic-concurrency contract.
 */
object PmvVaultStore {
    data class ObjectImport(
        val input: InputStream,
        val expectedSize: Long,
        val objectId: UUID,
        val generation: Long,
        val kind: PmvAttachmentCodec.Kind,
    )

    data class ObjectRef(
        val objectId: UUID,
        val generation: Long,
        val kind: PmvAttachmentCodec.Kind,
        val size: Long,
        val sha256: ByteArray,
    )

    data class MutationContent(val metadata: JsonObject, val entries: List<Entry>)

    data class MutationResult(val identity: Identity, val objectRefs: List<ObjectRef>)

    data class Identity(
        val vaultId: UUID,
        val sequence: Long,
        val latestCommitId: UUID,
        val parentCommitId: UUID?,
        val keyRevision: Long,
        val headerRevision: Long,
        val signingPublicKey: ByteArray,
        val rootDigest: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is Identity &&
            vaultId == other.vaultId && sequence == other.sequence &&
            latestCommitId == other.latestCommitId && parentCommitId == other.parentCommitId &&
            keyRevision == other.keyRevision &&
            headerRevision == other.headerRevision && signingPublicKey.contentEquals(other.signingPublicKey) &&
            rootDigest.contentEquals(other.rootDigest)

        override fun hashCode(): Int {
            var result = vaultId.hashCode()
            result = 31 * result + sequence.hashCode()
            result = 31 * result + latestCommitId.hashCode()
            result = 31 * result + (parentCommitId?.hashCode() ?: 0)
            result = 31 * result + keyRevision.hashCode()
            result = 31 * result + headerRevision.hashCode()
            result = 31 * result + signingPublicKey.contentHashCode()
            return 31 * result + rootDigest.contentHashCode()
        }
    }

    fun create(
        file: File,
        passwordUtf8: ByteArray,
        recoverySecret: ByteArray,
        initialMetadata: JsonObject,
        initialEntries: List<Entry>,
        random: SecureRandom = SecureRandom(),
        vaultId: UUID = randomUuid(random),
        keyRevision: Long = 1,
        headerRevision: Long = 1,
        kdfParameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
    ): Session {
        require(passwordUtf8.isNotEmpty()) { "主密码不能为空" }
        require(recoverySecret.size == PmvKeySchedule.KEY_SIZE) { "恢复密钥必须为 32 字节" }
        require(file.parentFile?.isDirectory != false) { "PMV 父目录不存在" }
        require(!file.exists() || file.length() == 0L) { "拒绝覆盖非空 PMV 文件" }
        val targetExisted = file.exists()
        val vaultRootKey = randomBytes(PmvKeySchedule.KEY_SIZE, random)
        val signingSeed = randomBytes(PmvCommitCodec.PRIVATE_SEED_SIZE, random)
        val salt = randomBytes(PmvKeySchedule.KDF_SALT_SIZE, random)
        val headerRaw = PmvVaultHeaderCodec.create(
            vaultId = vaultId,
            keyRevision = keyRevision,
            headerRevision = headerRevision,
            passwordUtf8 = passwordUtf8,
            recoverySecret = recoverySecret,
            vaultRootKey = vaultRootKey,
            signingPrivateSeed = signingSeed,
            salt = salt,
            kdfParameters = kdfParameters,
        )
        val rootKeys = PmvKeySchedule.deriveRootKeys(vaultRootKey, vaultId)
        var container: PmvAppendOnlyFile? = null
        var session: Session? = null
        try {
            container = PmvAppendOnlyFile.create(file, vaultId, rootKeys.integrityKey)
            val initialState = container.state().superblock
            RandomAccessFile(file, "rw").use { output ->
                output.seek(PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
                output.write(PmvContainerFormat.encodeSuperblock(initialState, rootKeys.integrityKey))
                output.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
                output.write(headerRaw)
                output.seek(PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET)
                output.write(headerRaw)
                output.fd.sync()
            }
            syncDirectory(file)
            val header = PmvVaultHeaderCodec.decode(headerRaw)
            session = Session(file, container, header, vaultRootKey, signingSeed)
            session.saveFull(initialMetadata, initialEntries, expectedSequence = 0)
            return session
        } catch (error: Throwable) {
            session?.close() ?: container?.close()
            runCatching {
                if (targetExisted) RandomAccessFile(file, "rw").use { it.setLength(0) }
                else if (file.isFile) file.delete()
            }
            throw error
        } finally {
            headerRaw.fill(0)
            salt.fill(0)
            signingSeed.fill(0)
            vaultRootKey.fill(0)
            rootKeys.close()
        }
    }

    fun openPassword(file: File, passwordUtf8: ByteArray): Session =
        open(file) { first, second ->
            PmvVaultHeaderCodec.unlockCandidatesWithPassword(first, second, passwordUtf8)
        }

    fun openRecovery(file: File, recoverySecret: ByteArray): Session =
        open(file) { first, second ->
            PmvVaultHeaderCodec.unlockCandidatesWithRecovery(first, second, recoverySecret)
        }

    fun openRootKey(file: File, vaultRootKey: ByteArray): Session =
        open(file) { first, second ->
            PmvVaultHeaderCodec.unlockCandidatesWithRootKey(first, second, vaultRootKey)
        }

    private fun open(
        file: File,
        unlock: (ByteArray, ByteArray) -> List<PmvVaultHeaderCodec.UnlockedHeader>,
    ): Session {
        require(file.isFile && file.length() >= PmvContainerFormat.DATA_START) { "PMV 文件不存在或已截断" }
        val (first, second) = readHeaderSlots(file)
        val candidates = try {
            unlock(first, second)
        } finally {
            first.fill(0)
            second.fill(0)
        }
        require(candidates.isNotEmpty()) { "没有可由所给凭据认证的 PMV Header" }
        var lastError: Throwable? = null
        try {
            candidates.forEach { unlocked ->
                var container: PmvAppendOnlyFile? = null
                var session: Session? = null
                try {
                    container = PmvAppendOnlyFile.open(file, unlocked.superblockAuthenticationKey)
                    require(container.state().superblock.vaultId == unlocked.header.vaultId) {
                        "PMV Header 与 Superblock vault_id 不一致"
                    }
                    val opened = Session(file, container, unlocked.header, unlocked.vaultRootKey, unlocked.signingPrivateSeed)
                    session = opened
                    opened.identity()
                    return opened
                } catch (error: Throwable) {
                    lastError = error
                    session?.close() ?: container?.close()
                }
            }
        } finally {
            candidates.forEach(PmvVaultHeaderCodec.UnlockedHeader::close)
        }
        throw IllegalArgumentException("没有与当前提交数据匹配的认证 PMV Header", lastError)
    }

    class Session internal constructor(
        private val file: File,
        private val container: PmvAppendOnlyFile,
        header: PmvVaultHeaderCodec.Header,
        vaultRootKey: ByteArray,
        signingPrivateSeed: ByteArray,
    ) : AutoCloseable {
        private val vaultId = header.vaultId
        private val signingPublicKey = header.signingPublicKey.copyOf()
        private val signingPrivateSeed = signingPrivateSeed.copyOf()
        private val vaultRootKey = vaultRootKey.copyOf()
        private val rootKeys = PmvKeySchedule.deriveRootKeys(this.vaultRootKey, vaultId)
        private var keyRevision = header.keyRevision
        private var headerRevision = header.headerRevision
        private var kdfParameters = header.kdfParameters
        private var closed = false

        @Synchronized
        fun kdfParameters(): PmvKdfParameters {
            checkOpen()
            return kdfParameters
        }

        @Synchronized
        fun identity(): Identity {
            checkOpen()
            val commit = resolveLatestAuthenticatedSnapshot().commit
            return Identity(
                vaultId = vaultId,
                sequence = commit.revision,
                latestCommitId = commit.commitId,
                parentCommitId = commit.parentCommitId,
                keyRevision = keyRevision,
                headerRevision = headerRevision,
                signingPublicKey = signingPublicKey.copyOf(),
                rootDigest = commit.rootDigest.copyOf(),
            )
        }

        /** Returns an independent RootKey copy; the caller must clear it immediately after enrollment. */
        @Synchronized
        fun copyRootKeyForDeviceUnlock(): ByteArray {
            checkOpen()
            return vaultRootKey.copyOf()
        }

        /** Returns an independent copy of the currently selected authenticated header raw bytes. */
        @Synchronized
        fun copyHeaderRaw(): ByteArray {
            checkOpen()
            val (first, second) = readHeaderSlots(file)
            try {
                val best = listOf(first, second)
                    .map { raw -> raw to PmvVaultHeaderCodec.decode(raw) }
                    .maxWithOrNull(
                        compareBy<Pair<ByteArray, PmvVaultHeaderCodec.Header>> { it.second.headerRevision }
                            .thenBy { it.second.keyRevision },
                    ) ?: error("PMV Header 缺失")
                return best.first.copyOf()
            } finally {
                first.fill(0)
                second.fill(0)
            }
        }

        /** Supplies a temporary RootKey copy and clears it when [block] returns or throws. */
        @Synchronized
        fun <T> withRootKeyForDeviceUnlock(block: (ByteArray) -> T): T {
            checkOpen()
            val copy = vaultRootKey.copyOf()
            return try { block(copy) } finally { copy.fill(0) }
        }

        @Synchronized
        fun listSummaries(): List<PmvEntryReader.Summary> {
            checkOpen()
            val summaries = reader().use { reader ->
                val result = ArrayList<PmvEntryReader.Summary>()
                var cursor: PmvEntryReader.Cursor? = null
                do {
                    val page = reader.listPage(cursor)
                    result += page.items
                    cursor = page.nextCursor
                } while (cursor != null)
                result
            }
            val byId = summaries.associateBy(PmvEntryReader.Summary::entryId)
            val ordered = ArrayList<PmvEntryReader.Summary>(summaries.size)
            val metadata = readMetadata()
            val metadataOrder = listOf("entry_order", "trash_order").flatMap { key ->
                (metadata[key] as? JsonArray).orEmpty()
            }
            val orderedIds = metadataOrder.map { value ->
                UUID.fromString(value.jsonPrimitive.content)
            }
            require(orderedIds.size == orderedIds.toSet().size && orderedIds.toSet() == byId.keys) {
                "Vault Metadata 顺序与 EntryIndex 集合不一致"
            }
            orderedIds.forEach { ordered += requireNotNull(byId[it]) }
            return ordered
        }

        @Synchronized
        fun readEntry(entryId: UUID): Entry? {
            checkOpen()
            return reader().use { it.find(entryId) }
        }

        @Synchronized
        fun queryDomain(domain: String): List<UUID> = queryLoginIndex { root, loadPage ->
            PmvLoginFastIndex.queryDomain(root, rootKeys.searchIndexKey, domain, loadPage)
        }

        @Synchronized
        fun queryPackage(packageName: String): List<UUID> = queryLoginIndex { root, loadPage ->
            PmvLoginFastIndex.queryPackage(root, rootKeys.searchIndexKey, packageName, loadPage)
        }

        @Synchronized
        fun queryRpId(rpId: String): List<UUID> = queryLoginIndex { root, loadPage ->
            PmvLoginFastIndex.queryRpId(root, rootKeys.searchIndexKey, rpId, loadPage)
        }

        @Synchronized
        fun readMetadata(): JsonObject {
            checkOpen()
            var lastError: Exception? = null
            resolveAuthenticatedSnapshots().forEach { snapshot ->
                try {
                    return readMetadata(snapshot)
                } catch (error: Exception) {
                    lastError = error
                }
            }
            throw IllegalArgumentException("没有可认证的 Vault Metadata 提交快照", lastError)
        }

        /**
         * 记录“密钥/密码最近变更时刻”到 sync_meta.key_updated_at，供分叉同步自动收敛
         * （只保留更新时间最新的密钥版本）。不改动条目与密钥材料，仅追加一次元数据提交。
         */
        @Synchronized
        fun touchKeyUpdatedAt(epochSeconds: Double): Identity {
            checkOpen()
            require(epochSeconds >= 0.0 && epochSeconds.isFinite()) { "key_updated_at 必须为非负有限数字" }
            val metadata = readMetadata().toMutableMap()
            val sync = ((metadata["sync_meta"] as? JsonObject)?.toMutableMap() ?: linkedMapOf())
            sync["key_updated_at"] = JsonPrimitive(epochSeconds)
            metadata["sync_meta"] = JsonObject(sync)
            val entries = listSummaries().mapNotNull { readEntry(it.entryId) }
            return saveFull(JsonObject(metadata), entries, identity().sequence)
        }

        /**
         * 主密码/恢复密钥变更后把逻辑密钥版本 +1 并记录变更时刻，一并持久化到
         * sync_meta.key_revision / key_updated_at。只追加一次元数据提交，不改动
         * 条目与密钥材料。两端都读这个字段，避免重启或同步后版本回退/不刷新。
         */
        @Synchronized
        fun touchKeyRevision(epochSeconds: Double): Identity {
            checkOpen()
            require(epochSeconds >= 0.0 && epochSeconds.isFinite()) { "key_updated_at 必须为非负有限数字" }
            val metadata = readMetadata().toMutableMap()
            val sync = ((metadata["sync_meta"] as? JsonObject)?.toMutableMap() ?: linkedMapOf())
            val previous = (sync["key_revision"] as? JsonPrimitive)?.content?.toLongOrNull()
                ?: (metadata["key_revision"] as? JsonPrimitive)?.content?.toLongOrNull()
                ?: 0L
            sync["key_revision"] = JsonPrimitive(previous + 1)
            sync["key_updated_at"] = JsonPrimitive(epochSeconds)
            metadata["sync_meta"] = JsonObject(sync)
            val entries = listSummaries().mapNotNull { readEntry(it.entryId) }
            return saveFull(JsonObject(metadata), entries, identity().sequence)
        }

        /**
         * 若最新提交缺少登录快速索引（迁移/导入的库可能没有），则重建索引并提交。
         * 返回 true 表示本次补充了索引。自动填充依赖该索引做精确查询。
         */
        @Synchronized
        fun ensureLoginIndex(): Boolean {
            checkOpen()
            val snapshot = resolveLatestAuthenticatedSnapshot()
            if (snapshot.root.login != null) return false
            val metadata = readMetadata()
            val entries = listSummaries().mapNotNull { readEntry(it.entryId) }
            saveFull(metadata, entries, identity().sequence)
            return true
        }

        /** Streams one immutable object generation and publishes its two lookup roots atomically. */
        @Synchronized
        fun importObject(
            input: InputStream,
            expectedSize: Long,
            objectId: UUID,
            generation: Long,
            kind: PmvAttachmentCodec.Kind,
            expectedSequence: Long,
        ): Identity {
            checkOpen()
            require(expectedSize >= 0) { "对象大小不能为负数" }
            require(generation >= 0) { "Object generation 无效" }
            require(expectedSequence > 0) { "对象导入要求已提交的事务基线" }
            val snapshot = resolveAuthenticatedSnapshots().first()
            require(snapshot.commit.revision == expectedSequence) { "提交基线已过期" }
            val objects = loadObjectIndex(snapshot)
            val chunks = loadChunkIndex(snapshot)
            val objectKey = PmvObjectIndexCodec.ObjectKey(objectId, generation)
            require(objects.records.none { it.key == objectKey }) { "Object generation 已存在" }
            require(chunks.records.none { it.key.objectId == objectId && it.key.generation == generation }) {
                "Object generation 的 ChunkIndex 已存在"
            }

            container.beginWrite(expectedSequence).use { transaction ->
                requireSameSnapshot(transaction, snapshot)
                val imported = PmvObjectStore.importFrom(
                    input = input,
                    expectedSize = expectedSize,
                    vaultId = vaultId,
                    objectId = objectId,
                    generation = generation,
                    kind = kind,
                    attachmentRootKey = rootKeys.attachmentRootKey,
                    append = { block ->
                        val reference = transaction.appendBlock(block)
                        PmvObjectStore.StoredBlock(reference.offset, reference.length)
                    },
                )
                writeObjectCommit(
                    transaction,
                    snapshot.root,
                    objects,
                    chunks,
                    (objects.records + imported.objectRecord).sortedBy { it.key },
                    (chunks.records + imported.chunkRecords).sortedBy { it.key },
                )
            }
            syncDirectory(file)
            return identity()
        }

        /** Streams the authenticated object generation to caller-owned [output]. */
        @Synchronized
        fun openObject(objectId: UUID, generation: Long, output: OutputStream) {
            checkOpen()
            val snapshot = resolveAuthenticatedSnapshots().first()
            val lookup = objectLookup(snapshot, objectId, generation)
            PmvObjectStore.openTo(
                lookup.objectRecord,
                vaultId,
                rootKeys.attachmentRootKey,
                lookup::readBlock,
                lookup::findChunk,
                output,
            )
        }

        /** Streams only the requested authenticated byte range without loading unrelated chunks. */
        @Synchronized
        fun openObjectRange(
            objectId: UUID,
            generation: Long,
            offset: Long,
            length: Long,
            output: OutputStream,
        ) {
            checkOpen()
            val snapshot = resolveAuthenticatedSnapshots().first()
            val lookup = objectLookup(snapshot, objectId, generation)
            PmvObjectStore.openRangeTo(
                lookup.objectRecord,
                offset,
                length,
                vaultId,
                rootKeys.attachmentRootKey,
                lookup::readBlock,
                lookup::findChunk,
                output,
            )
        }

        /** Full-tree rewrite today; optimistic sequence and parent binding make concurrent writers safe. */
        @Synchronized
        fun saveMerged(source: Session, metadata: JsonObject, entries: List<Entry>, expectedSequence: Long): Identity {
            checkOpen()
            source.checkOpen()
            require(source.vaultId == vaultId && source.file.canonicalFile != file.canonicalFile) {
                "合并对象来源必须是同一保险库的另一份文件"
            }
            val snapshot = resolveLatestAuthenticatedSnapshot()
            require(snapshot.commit.revision == expectedSequence) { "提交基线已过期" }
            val sourceSnapshot = source.resolveLatestAuthenticatedSnapshot()
            val available = loadObjectIndex(snapshot).records.map { it.key }.toSet()
            val refs = linkedMapOf<PmvObjectIndexCodec.ObjectKey, PmvMediaRef.Ref>()
            (entries.flatMap(PmvMediaRef::scan) + PmvMediaRef.scanJson(metadata)).forEach { occurrence ->
                occurrence.ref?.let { ref ->
                    val key = PmvObjectIndexCodec.ObjectKey(ref.objectId, ref.generation)
                    val prior = refs.put(key, ref)
                    require(prior == null || prior == ref) { "合并中的同一附件引用内容不一致" }
                }
            }
            val imports = ArrayList<ObjectImport>()
            refs.forEach { (key, ref) ->
                val owner = if (key in available) this else source
                val ownerSnapshot = if (key in available) snapshot else sourceSnapshot
                val lookup = owner.objectLookup(ownerSnapshot, ref.objectId, ref.generation)
                val manifest = PmvObjectStore.readManifest(
                    lookup.objectRecord, vaultId, owner.rootKeys.attachmentRootKey, lookup::readBlock,
                )
                require(manifest.kind == ref.kind && manifest.totalSize == ref.size &&
                    MessageDigest.isEqual(manifest.sha256, ref.sha256)) { "合并附件与引用的大小或摘要不一致" }
                if (key !in available) {
                    // Read from the fixed authenticated source snapshot directly into the importer's
                    // chunk buffer. No plaintext temporary file or whole-object allocation.
                    val input = object : InputStream() {
                        var position = 0L
                        override fun read(): Int {
                            val one = ByteArray(1)
                            return try { if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 255 }
                            finally { one.fill(0) }
                        }
                        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                            require(offset >= 0 && length >= 0 && offset <= buffer.size - length)
                            if (length == 0) return 0
                            if (position == ref.size) return -1
                            val count = minOf(length.toLong(), ref.size - position,
                                PmvAttachmentCodec.CHUNK_SIZE.toLong()).toInt()
                            var written = 0
                            val output = object : OutputStream() {
                                override fun write(value: Int) { buffer[offset + written++] = value.toByte() }
                                override fun write(bytes: ByteArray, start: Int, size: Int) {
                                    bytes.copyInto(buffer, offset + written, start, start + size)
                                    written += size
                                }
                            }
                            PmvObjectStore.openRangeTo(lookup.objectRecord, position, count.toLong(), vaultId,
                                source.rootKeys.attachmentRootKey, lookup::readBlock, lookup::findChunk, output)
                            check(written == count)
                            position += count
                            return count
                        }
                    }
                    imports += ObjectImport(input, ref.size, ref.objectId, ref.generation, ref.kind)
                }
            }
            return applyMutation(expectedSequence, imports) { imported ->
                imported.forEach { actual ->
                    val expected = refs.getValue(PmvObjectIndexCodec.ObjectKey(actual.objectId, actual.generation))
                    require(actual.size == expected.size && actual.kind == expected.kind &&
                        MessageDigest.isEqual(actual.sha256, expected.sha256)) { "合并附件传输校验失败" }
                }
                require(source.identity().latestCommitId == sourceSnapshot.commit.commitId) { "合并期间本地保险库已变化" }
                MutationContent(metadata, entries)
            }.identity
        }

        @Synchronized
        fun saveFull(metadata: JsonObject, entries: List<Entry>, expectedSequence: Long): Identity {
            checkOpen()
            require(expectedSequence >= 0) { "expectedSequence 不能为负数" }
            require(entries.map(Entry::id).toSet().size == entries.size) { "Entry ID 不得重复" }
            val state = container.state().superblock
            require(state.sequence == expectedSequence) { "提交基线已过期" }
            val snapshot = if (expectedSequence == 0L) null else resolveAuthenticatedSnapshots().first().also {
                require(it.commit.revision == expectedSequence) { "提交基线已过期" }
            }
            val normalizedMetadata = normalizeMetadata(metadata, entries)
            val previousObjects = snapshot?.let(::loadObjectIndex)
            val previousChunks = snapshot?.let(::loadChunkIndex)
            container.beginWrite(expectedSequence).use { transaction ->
                if (snapshot != null) requireSameSnapshot(transaction, snapshot)
                val objectRoots = if (snapshot == null) {
                    null to null
                } else {
                    requireNotNull(previousObjects)
                    requireNotNull(previousChunks)
                    reachableObjectRoots(transaction, snapshot, previousObjects, previousChunks, normalizedMetadata, entries)
                }
                writeFull(transaction, normalizedMetadata, entries, snapshot?.root, objectRoots)
            }
            syncDirectory(file)
            return identity()
        }

        /** Rewrites only blocks reachable from the latest Commit without creating a logical Commit. */
        @Synchronized
        fun compact(): Identity = compactInternal { }

        @Synchronized
        internal fun compactForTest(fault: (String) -> Unit): Identity = compactInternal(fault)

        private fun compactInternal(fault: (String) -> Unit): Identity {
            checkOpen()
            val oldIdentity = identity()
            val temporary = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.compact.tmp")
            return PmvAppendOnlyFile.withExclusiveWriterLock(file) {
                try {
                    val snapshot = resolveLatestAuthenticatedSnapshot()
                    val commit = snapshot.commit
                    val entryPages = reader().use(PmvEntryReader::allPages)
                    RandomAccessFile(temporary, "rw").use { output ->
                        output.setLength(PmvContainerFormat.DATA_START)
                        RandomAccessFile(file, "r").use { input ->
                            for (offset in listOf(
                                PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET,
                                PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET,
                            )) {
                                val raw = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
                                input.seek(offset)
                                input.readFully(raw)
                                output.seek(offset)
                                output.write(raw)
                                raw.fill(0)
                            }
                        }
                        val writer = CompactWriter(output)

                        // 压缩只回收历史数据块；提交链必须完整保留。祖先 COMMIT 块
                        // 按原样复制（谱系标记），否则 readPmvEAncestorCommitIds 会因
                        // 父提交块缺失报“缺少父提交”，导致同步/设备认证无法工作。
                        var lineageOffset = PmvContainerFormat.DATA_START
                        while (lineageOffset < snapshot.state.superblock.committedFileEnd) {
                            val block = container.readBlock(lineageOffset)
                            if (block.header.blockType == PmvContainerFormat.BlockType.COMMIT &&
                                block.header.objectId != commit.commitId
                            ) {
                                writer.append(block)
                            }
                            lineageOffset = Math.addExact(
                                lineageOffset,
                                Math.addExact(
                                    PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(),
                                    block.header.cipherSize,
                                ),
                            )
                        }

                        val entryRanges = entryPages.map { page ->
                            val movedRecords = page.records.map { record ->
                                reader().use { it.find(record.entryId) }
                                val expectedType = if (record.state == PmvEntryIndexCodec.State.ACTIVE) {
                                    PmvContainerFormat.BlockType.ENTRY
                                } else {
                                    PmvContainerFormat.BlockType.TOMBSTONE
                                }
                                val copied = writer.append(container.readBlock(snapshot.state, record.offset, expectedType))
                                record.copy(offset = copied.offset, length = copied.length,
                                    contentDigest = record.contentDigest.copyOf())
                            }
                            val movedPage = PmvEntryIndexCodec.Page(movedRecords, 0)
                            val digest = PmvIntegrity.entryPageDigest(movedPage)
                            val pageRef = writer.append(sealIndex(
                                PmvEntryIndexCodec.encode(movedPage), commit.revision,
                                PmvKeySchedule.IndexPageType.ENTRY_INDEX,
                            ))
                            PmvEntryIndexRootCodec.Record(
                                movedRecords.first().entryId, movedRecords.last().entryId, pageRef.offset, digest,
                            )
                        }
                        val entryRoot = PmvEntryIndexRootCodec.Root(entryRanges)
                        val entryRootRef = writer.append(sealIndex(
                            PmvEntryIndexRootCodec.encode(entryRoot), commit.revision,
                            PmvKeySchedule.IndexPageType.ENTRY_INDEX,
                        ))
                        val entryReference = PmvVaultRootCodec.Reference(
                            PmvVaultRootCodec.RootType.ENTRY, entryRootRef.offset, entryRootRef.length,
                            PmvIntegrity.entryRootDigest(entryRoot),
                        )
                        requireSameLogicalReference(entryReference, snapshot.root.entry, "EntryIndex")

                        val oldLogin = snapshot.root.login
                        val loginReference = oldLogin?.let { reference ->
                            val loginRoot = readLoginRoot(snapshot, reference)
                            val movedRanges = loginRoot.ranges.map { range ->
                                val page = readLoginPage(snapshot, range)
                                require(MessageDigest.isEqual(PmvLoginFastIndex.logicalDigest(page), range.pageLogicalDigest))
                                val leaf = writer.append(container.readBlock(
                                    snapshot.state, range.pageOffset, PmvContainerFormat.BlockType.LOGIN_INDEX,
                                ))
                                PmvLoginFastIndex.PageRange(
                                    range.minKind, range.minToken, range.maxKind, range.maxToken,
                                    leaf.offset, leaf.length, range.pageLogicalDigest,
                                )
                            }
                            val movedRoot = PmvLoginFastIndex.Root(movedRanges)
                            val rootRef = writer.append(sealIndex(
                                PmvLoginFastIndex.encodeRoot(movedRoot), commit.revision,
                                PmvKeySchedule.IndexPageType.LOGIN_INDEX,
                                PmvContainerFormat.BlockType.LOGIN_INDEX,
                            ))
                            PmvVaultRootCodec.Reference(
                                PmvVaultRootCodec.RootType.LOGIN, rootRef.offset, rootRef.length,
                                PmvLoginFastIndex.logicalDigest(movedRoot),
                            ).also { requireSameLogicalReference(it, reference, "LoginFastIndex") }
                        }

                        val objects = loadObjectIndex(snapshot)
                        val chunks = loadChunkIndex(snapshot)
                        val chunksByObject = chunks.records.groupBy { it.key.objectId to it.key.generation }
                        val movedObjects = ArrayList<PmvObjectIndexCodec.ObjectRecord>()
                        val movedChunks = ArrayList<PmvObjectIndexCodec.ChunkRecord>()
                        objects.records.forEach { record ->
                            openObject(record.key.objectId, record.key.generation, NullOutputStream)
                            val manifest = writer.append(container.readBlock(
                                snapshot.state, record.manifestOffset, PmvContainerFormat.BlockType.OBJECT_METADATA,
                            ))
                            movedObjects += record.copy(manifestOffset = manifest.offset, manifestLength = manifest.length,
                                plainDigest = record.plainDigest.copyOf(), cipherDigest = record.cipherDigest.copyOf())
                            chunksByObject[record.key.objectId to record.key.generation].orEmpty().forEach { chunk ->
                                val chunkBlock = container.readBlock(snapshot.state, chunk.blockOffset)
                                require(chunkBlock.header.blockType in setOf(
                                    PmvContainerFormat.BlockType.IMAGE_CHUNK,
                                    PmvContainerFormat.BlockType.ATTACHMENT_CHUNK,
                                )) { "ChunkIndex 引用了非媒体 Chunk Block" }
                                val copied = writer.append(chunkBlock)
                                movedChunks += chunk.copy(blockOffset = copied.offset, blockLength = copied.length,
                                    plainDigest = chunk.plainDigest.copyOf(), cipherDigest = chunk.cipherDigest.copyOf())
                            }
                        }
                        val objectRoots = if (movedObjects.isEmpty()) {
                            null to null
                        } else {
                            writeCompactObjectIndexes(writer, commit.revision, movedObjects.sortedBy { it.key },
                                movedChunks.sortedBy { it.key })
                        }
                        requireSameLogicalReference(objectRoots.first, snapshot.root.objectIndex, "ObjectIndex")
                        requireSameLogicalReference(objectRoots.second, snapshot.root.chunkIndex, "ChunkIndex")

                        readMetadata(snapshot)
                        val oldMetadata = requireNotNull(snapshot.root.metadata)
                        val metadataBlock = writer.append(container.readBlock(
                            snapshot.state, oldMetadata.offset, PmvContainerFormat.BlockType.OBJECT_METADATA,
                        ))
                        val metadataReference = PmvVaultRootCodec.Reference(
                            PmvVaultRootCodec.RootType.METADATA, metadataBlock.offset, metadataBlock.length,
                            oldMetadata.digest.copyOf(),
                        )
                        requireSameLogicalReference(metadataReference, oldMetadata, "Metadata")

                        val movedRoot = PmvVaultRootCodec.Root(
                            entryReference, loginReference, objectRoots.first, objectRoots.second, metadataReference,
                        )
                        require(MessageDigest.isEqual(PmvVaultRootCodec.logicalDigest(movedRoot), commit.rootDigest)) {
                            "Compact 改变了 VaultRoot 逻辑摘要"
                        }
                        val vaultRootRef = writer.append(sealIndex(
                            PmvVaultRootCodec.encode(movedRoot), commit.revision,
                            PmvKeySchedule.IndexPageType.VAULT_ROOT,
                        ))
                        val movedCommit = commit.copy(
                            indexRootOffset = vaultRootRef.offset,
                            indexRootLength = vaultRootRef.length,
                            rootDigest = commit.rootDigest.copyOf(),
                            signingPublicKey = commit.signingPublicKey.copyOf(),
                            signature = commit.signature.copyOf(),
                        )
                        val commitPlaintext = PmvCommitCodec.encode(movedCommit)
                        val commitKey = PmvKeySchedule.deriveCommitBlockKey(
                            rootKeys.integrityKey, movedCommit.commitId, movedCommit.revision,
                        )
                        val commitBlock = try {
                            PmvBlockCrypto.seal(
                                vaultId, commitKey, PmvContainerFormat.BlockType.COMMIT,
                                movedCommit.commitId, movedCommit.revision, commitPlaintext,
                            )
                        } finally {
                            commitKey.fill(0)
                            commitPlaintext.fill(0)
                        }
                        val commitRef = writer.append(commitBlock)
                        output.fd.sync()
                        val superblock = PmvContainerFormat.Superblock(
                            vaultId, commit.revision, commitRef.offset, vaultRootRef.offset, writer.tail,
                            snapshot.state.superblock.kdfParametersOffset, snapshot.state.superblock.featureFlags,
                        )
                        val encoded = PmvContainerFormat.encodeSuperblock(superblock, rootKeys.integrityKey)
                        output.seek(0L)
                        output.write(encoded)
                        output.seek(PmvContainerFormat.SUPERBLOCK_SIZE.toLong())
                        output.write(encoded)
                        output.setLength(writer.tail)
                        output.fd.sync()
                        encoded.fill(0)
                    }

                    val candidateRootKey = vaultRootKey.copyOf()
                    try {
                        openRootKey(temporary, candidateRootKey).use { candidate ->
                            require(candidate.identity() == oldIdentity) { "Compact 改变了 Commit Identity" }
                            candidate.readMetadata()
                            candidate.listSummaries().forEach { summary ->
                                requireNotNull(candidate.readEntry(summary.entryId)) { "Compact 丢失 Entry" }
                            }
                            val candidateSnapshot = candidate.resolveLatestAuthenticatedSnapshot()
                            candidate.loadObjectIndex(candidateSnapshot).records.forEach { record ->
                                candidate.openObject(record.key.objectId, record.key.generation, NullOutputStream)
                            }
                        }
                    } finally {
                        candidateRootKey.fill(0)
                    }
                    fault("beforeReplace")
                    Files.move(
                        temporary.toPath(), file.toPath(),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING,
                    )
                    syncDirectory(file)
                    require(identity() == oldIdentity) { "安装后的 Compact Identity 发生变化" }
                    oldIdentity
                } finally {
                    temporary.delete()
                }
            }
        }

        /**
         * Atomically publishes a complete logical Entry/metadata replacement and zero or more
         * streamed objects. [prepare] runs after every stream has reached its declared EOF, but
         * before any PMVR/Commit is published, so it can embed the returned object IDs and
         * generations in the Entries without a second commit. Throwing (including cancellation)
         * leaves the old snapshot authoritative and truncates every block appended by this call.
         * The Store never closes caller-owned input streams; retrying after any failure requires
         * newly opened streams because prior streams may already have been partially consumed.
         */
        @Synchronized
        fun applyMutation(
            expectedSequence: Long,
            objectImports: List<ObjectImport> = emptyList(),
            prepare: (List<ObjectRef>) -> MutationContent,
        ): MutationResult {
            checkOpen()
            require(expectedSequence > 0) { "VaultMutation 要求已提交的事务基线" }
            val keys = objectImports.map { PmvObjectIndexCodec.ObjectKey(it.objectId, it.generation) }
            require(keys.toSet().size == keys.size) { "VaultMutation Object generation 不得重复" }
            objectImports.forEach {
                require(it.expectedSize >= 0) { "对象大小不能为负数" }
                require(it.generation >= 0) { "Object generation 无效" }
            }
            val snapshot = resolveLatestAuthenticatedSnapshot()
            require(snapshot.commit.revision == expectedSequence) { "提交基线已过期" }
            val previousObjects = loadObjectIndex(snapshot)
            val previousChunks = loadChunkIndex(snapshot)
            require(keys.none { key -> previousObjects.records.any { it.key == key } }) {
                "Object generation 已存在"
            }

            val refs = ArrayList<ObjectRef>(objectImports.size)
            container.beginWrite(expectedSequence).use { transaction ->
                requireSameSnapshot(transaction, snapshot)
                var objectRecords = previousObjects.records
                var chunkRecords = previousChunks.records
                objectImports.forEach { request ->
                    val imported = PmvObjectStore.importFrom(
                        input = request.input,
                        expectedSize = request.expectedSize,
                        vaultId = vaultId,
                        objectId = request.objectId,
                        generation = request.generation,
                        kind = request.kind,
                        attachmentRootKey = rootKeys.attachmentRootKey,
                        append = { block ->
                            transaction.appendBlock(block).let { PmvObjectStore.StoredBlock(it.offset, it.length) }
                        },
                    )
                    objectRecords = (objectRecords + imported.objectRecord).sortedBy { it.key }
                    chunkRecords = (chunkRecords + imported.chunkRecords).sortedBy { it.key }
                    refs += ObjectRef(
                        request.objectId,
                        request.generation,
                        request.kind,
                        imported.manifest.totalSize,
                        imported.manifest.sha256.copyOf(),
                    )
                }
                val content = prepare(refs.map { it.copy(sha256 = it.sha256.copyOf()) })
                require(content.entries.map(Entry::id).toSet().size == content.entries.size) { "Entry ID 不得重复" }
                val normalizedMetadata = normalizeMetadata(content.metadata, content.entries)
                val mediaOccurrences = content.entries.flatMap(PmvMediaRef::scan) +
                    PmvMediaRef.scanJson(normalizedMetadata)
                require(mediaOccurrences.none { it.classification in setOf(
                    PmvMediaRef.Classification.LEGACY_EXTERNAL,
                    PmvMediaRef.Classification.INLINE,
                ) }) { "最终 Entry/metadata 不得以外置路径或 inline 数据作为媒体权威引用" }
                val referencedKeys = mediaOccurrences.mapNotNull { occurrence -> occurrence.ref?.let {
                        PmvObjectIndexCodec.ObjectKey(it.objectId, it.generation)
                    } }.toSet()
                val availableKeys = previousObjects.records.map { it.key }.toSet() + keys
                require(referencedKeys.all { it in availableKeys }) { "最终 Entry/metadata 含悬挂 PMV ObjectRef" }
                require(keys.all { it in referencedKeys }) { "VaultMutation 导入了未被最终状态引用的孤立 Object" }
                objectRecords = objectRecords.filter { it.key in referencedKeys }
                chunkRecords = chunkRecords.filter {
                    PmvObjectIndexCodec.ObjectKey(it.key.objectId, it.key.generation) in referencedKeys
                }
                val rootsChanged = objectRecords.size != previousObjects.records.size || objectImports.isNotEmpty()
                val objectRoots = when {
                    objectRecords.isEmpty() -> null to null
                    rootsChanged -> writeObjectIndexes(transaction, previousObjects, previousChunks, objectRecords, chunkRecords)
                    else -> snapshot.root.objectIndex to snapshot.root.chunkIndex
                }
                writeFull(transaction, normalizedMetadata, content.entries, snapshot.root, objectRoots)
            }
            syncDirectory(file)
            return MutationResult(identity(), refs.map { it.copy(sha256 = it.sha256.copyOf()) })
        }

        /** Revoke historical headers by replacing every encrypted object and the signing identity.
         * The source remains authoritative until a verified encrypted candidate is atomically installed.
         * This session must be closed after success; callers reopen with the new credential.
         */
        @Synchronized
        fun rotatePassword(
            newPasswordUtf8: ByteArray,
            newRecoverySecret: ByteArray,
            beforeReplace: () -> Unit = {},
        ) {
            checkOpen()
            val temporary = File(file.parentFile, ".${file.name}.${UUID.randomUUID()}.rekey.tmp")
            PmvAppendOnlyFile.withExclusiveWriterLock(file) {
                try {
                    val original = identity()
                    val entries = listSummaries().map { requireNotNull(readEntry(it.entryId)) }
                    val metadata = JsonObject(readMetadata().toMutableMap().apply {
                        // Authorizations signed by the revoked signing key cannot survive rotation.
                        remove(PmvDeviceRegistry.METADATA_FIELD)
                    })
                    val bootstrap = JsonObject(metadata.filterKeys { it in setOf(
                        "schema", "version", "vault_id", "entry_order", "trash_order", "sync_meta",
                        "key_revision", "export_epoch", "purge_tombstones",
                    ) })
                    create(temporary, newPasswordUtf8, newRecoverySecret, bootstrap, emptyList(),
                        vaultId = vaultId,
                        keyRevision = Math.addExact(original.keyRevision, 1),
                        headerRevision = Math.addExact(original.headerRevision, 1),
                        kdfParameters = kdfParameters(),
                    ).use { target ->
                        target.saveMerged(this, metadata, entries, target.identity().sequence)
                        target.touchKeyRevision(com.vault.model.nowSeconds())
                    }
                    openPassword(temporary, newPasswordUtf8).use { verified ->
                        check(verified.listSummaries().map { verified.readEntry(it.entryId) } == entries)
                        (entries.flatMap(PmvMediaRef::scan) + PmvMediaRef.scanJson(metadata))
                            .mapNotNull { it.ref }.distinct().forEach {
                                verified.openObject(it.objectId, it.generation, NullOutputStream)
                            }
                    }
                    openRecovery(temporary, newRecoverySecret).use { it.readMetadata() }
                    check(identity() == original) { "Vault changed during key rotation" }
                    beforeReplace()
                    Files.move(temporary.toPath(), file.toPath(),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                    syncDirectory(file)
                } finally { temporary.delete() }
            }
        }

        @Synchronized
        fun rewrapPassword(oldPasswordUtf8: ByteArray, newPasswordUtf8: ByteArray) {
            checkOpen()
            require(oldPasswordUtf8.isNotEmpty() && newPasswordUtf8.isNotEmpty()) { "主密码不能为空" }
            val selectedRaw = selectCompatibleHeaderRaw { raw ->
                PmvVaultHeaderCodec.unlockWithPassword(raw, oldPasswordUtf8)
            }
            val newSalt = randomBytes(PmvKeySchedule.KDF_SALT_SIZE, SecureRandom())
            val updated = try {
                val selected = PmvVaultHeaderCodec.decode(selectedRaw)
                PmvVaultHeaderCodec.rewrapPassword(
                    raw = selectedRaw,
                    oldPasswordUtf8 = oldPasswordUtf8,
                    newPasswordUtf8 = newPasswordUtf8,
                    newSalt = newSalt,
                    newHeaderRevision = Math.addExact(selected.headerRevision, 1L),
                )
            } finally {
                newSalt.fill(0)
                selectedRaw.fill(0)
            }
            publishHeader(updated)
        }

        @Synchronized
        fun rewrapPasswordProfile(passwordUtf8: ByteArray, targetProfile: PmvKdfProfile) {
            checkOpen()
            require(passwordUtf8.isNotEmpty()) { "主密码不能为空" }
            val selectedRaw = selectCompatibleHeaderRaw { raw ->
                PmvVaultHeaderCodec.unlockWithPassword(raw, passwordUtf8)
            }
            val newSalt = randomBytes(PmvKeySchedule.KDF_SALT_SIZE, SecureRandom())
            val updated = try {
                val selected = PmvVaultHeaderCodec.decode(selectedRaw)
                PmvVaultHeaderCodec.rewrapPassword(
                    raw = selectedRaw,
                    oldPasswordUtf8 = passwordUtf8,
                    newPasswordUtf8 = passwordUtf8,
                    newSalt = newSalt,
                    newHeaderRevision = Math.addExact(selected.headerRevision, 1L),
                    targetParameters = targetProfile.parameters,
                )
            } finally {
                newSalt.fill(0)
                selectedRaw.fill(0)
            }
            publishHeader(updated)
        }

        @Synchronized
        fun rotateRecovery(oldRecoverySecret: ByteArray, newRecoverySecret: ByteArray) {
            checkOpen()
            require(oldRecoverySecret.size == PmvKeySchedule.KEY_SIZE &&
                newRecoverySecret.size == PmvKeySchedule.KEY_SIZE) { "恢复密钥必须为 32 字节" }
            val selectedRaw = selectCompatibleHeaderRaw { raw ->
                PmvVaultHeaderCodec.unlockWithRecovery(raw, oldRecoverySecret)
            }
            val updated = try {
                val selected = PmvVaultHeaderCodec.decode(selectedRaw)
                PmvVaultHeaderCodec.rewrapRecovery(
                    selectedRaw,
                    oldRecoverySecret,
                    newRecoverySecret,
                    Math.addExact(selected.headerRevision, 1L),
                )
            } finally {
                selectedRaw.fill(0)
            }
            publishHeader(updated)
        }

        /** Regenerates the recovery slot from the password credential; the old recovery secret is not required. */
        @Synchronized
        fun regenerateRecoveryKey(passwordUtf8: ByteArray, newRecoverySecret: ByteArray) {
            checkOpen()
            require(passwordUtf8.isNotEmpty()) { "主密码不能为空" }
            require(newRecoverySecret.size == PmvKeySchedule.KEY_SIZE) { "恢复密钥必须为 32 字节" }
            val selectedRaw = selectCompatibleHeaderRaw { raw ->
                PmvVaultHeaderCodec.unlockWithPassword(raw, passwordUtf8)
            }
            val updated = try {
                val selected = PmvVaultHeaderCodec.decode(selectedRaw)
                PmvVaultHeaderCodec.rewrapRecoveryWithPassword(
                    selectedRaw,
                    passwordUtf8,
                    newRecoverySecret,
                    Math.addExact(selected.headerRevision, 1L),
                )
            } finally {
                selectedRaw.fill(0)
            }
            publishHeader(updated)
        }

        /** 用 Vault 签名密钥签发设备授权记录（授权/撤销均由保险库持有者执行）。 */
        @Synchronized
        fun signDeviceAuthorization(
            value: PmvSyncAuthorization.DeviceAuthorization,
        ): PmvSyncAuthorization.DeviceAuthorization {
            checkOpen()
            require(value.vaultId == vaultId) { "Device authorization 不属于本保险库" }
            val seed = signingPrivateSeed.copyOf()
            return try {
                PmvSyncAuthorization.signAuthorization(value, seed)
            } finally {
                seed.fill(0)
            }
        }

        @Synchronized
        fun resetPasswordWithRecovery(recoverySecret: ByteArray, newPasswordUtf8: ByteArray) {
            checkOpen()
            require(recoverySecret.size == PmvKeySchedule.KEY_SIZE) { "恢复密钥必须为 32 字节" }
            require(newPasswordUtf8.isNotEmpty()) { "主密码不能为空" }
            val selectedRaw = selectCompatibleHeaderRaw { raw ->
                PmvVaultHeaderCodec.unlockWithRecovery(raw, recoverySecret)
            }
            val newSalt = randomBytes(PmvKeySchedule.KDF_SALT_SIZE, SecureRandom())
            val updated = try {
                val selected = PmvVaultHeaderCodec.decode(selectedRaw)
                PmvVaultHeaderCodec.rewrapPasswordWithRecovery(
                    selectedRaw,
                    recoverySecret,
                    newPasswordUtf8,
                    newSalt,
                    Math.addExact(selected.headerRevision, 1L),
                )
            } finally {
                selectedRaw.fill(0)
                newSalt.fill(0)
            }
            publishHeader(updated)
        }

        /**
         * 将本保险库另一份认证 Header（同一 vault_id、同一签名身份、同一根密钥）写入
         * 两个头部槽位。用于分叉同步合并：当采用“本端（更新）密钥版本”时，合并文件
         * 的密码/恢复密钥槽必须替换为本端槽，否则合并后本端新主密码会失效。
         */
        @Synchronized
        fun adoptHeader(raw: ByteArray) {
            checkOpen()
            val source = raw.copyOf()
            try {
                PmvVaultHeaderCodec.unlockWithRootKey(source, vaultRootKey).use { unlocked ->
                    require(unlocked.header.vaultId == vaultId) { "采纳的 PMV Header vault_id 与当前保险库不一致" }
                    require(MessageDigest.isEqual(unlocked.header.signingPublicKey, signingPublicKey)) {
                        "采纳的 PMV Header 签名身份与当前保险库不一致"
                    }
                    require(MessageDigest.isEqual(unlocked.vaultRootKey, vaultRootKey)) {
                        "采纳的 PMV Header 根密钥与当前保险库不一致"
                    }
                    val container = PmvAppendOnlyFile.open(file, unlocked.superblockAuthenticationKey)
                    try {
                        require(container.state().superblock.vaultId == unlocked.header.vaultId) {
                            "采纳的 PMV Header 无法认证当前提交链"
                        }
                    } finally {
                        container.close()
                    }
                }
                publishHeader(source)
            } finally {
                source.fill(0)
            }
        }

        @Synchronized
        override fun close() {
            if (!closed) {
                closed = true
                signingPrivateSeed.fill(0)
                signingPublicKey.fill(0)
                vaultRootKey.fill(0)
                rootKeys.close()
                container.close()
                keyRevision = -1
                headerRevision = -1
            }
        }

        private fun writeFull(
            transaction: PmvAppendOnlyFile.Transaction,
            metadata: JsonObject,
            entries: List<Entry>,
            previousRoot: PmvVaultRootCodec.Root?,
            objectRoots: Pair<PmvVaultRootCodec.Reference?, PmvVaultRootCodec.Reference?> =
                previousRoot?.let { it.objectIndex to it.chunkIndex } ?: (null to null),
        ) {
            val revision = transaction.nextRevision
            val sortedEntries = entries.sortedBy { UUID.fromString(it.id).toString() }
            val purges = metadata.getValue("purge_tombstones").jsonObject
            val activeIds = sortedEntries.map { UUID.fromString(it.id) }.toSet()
            val purgeIds = purges.keys.map(UUID::fromString)
            require(activeIds.intersect(purgeIds.toSet()).isEmpty()) { "Entry 与 purge_tombstones 不得重叠" }
            val previousRecords = if (previousRoot == null) emptyMap() else reader().use { entryReader ->
                entryReader.allRecords().associateBy(PmvEntryIndexCodec.Record::entryId)
            }
            val records = ArrayList<PmvEntryIndexCodec.Record>(sortedEntries.size + purges.size)
            sortedEntries.forEach { entry ->
                val entryId = UUID.fromString(entry.id).also { require(it.toString() == entry.id.lowercase()) }
                val plaintext = PmvEntryCodec.encode(entry)
                val key = PmvKeySchedule.deriveEntryKey(rootKeys.entryRootKey, entryId, revision)
                val block = try {
                    PmvBlockCrypto.seal(
                        vaultId, key, PmvContainerFormat.BlockType.ENTRY, entryId, revision, plaintext,
                        codecId = PmvCompression.chooseCodec(plaintext),
                    )
                } finally {
                    key.fill(0)
                    plaintext.fill(0)
                }
                val blockRef = transaction.appendBlock(block)
                records += PmvEntryIndexCodec.Record(
                    entryId = entryId,
                    entryType = entry.secretType,
                    revision = revision,
                    offset = blockRef.offset,
                    length = blockRef.length,
                    // Recycle-bin entries remain readable objects. PMEI TOMBSTONE is reserved for
                    // purge tombstones that intentionally have no readable Entry payload.
                    state = PmvEntryIndexCodec.State.ACTIVE,
                    displayTitle = entry.title,
                    favorite = entry.fields["favorite"]?.jsonPrimitive?.booleanOrNull == true,
                    iconObjectId = entry.fields["icon_object_id"]?.jsonPrimitive?.content
                        ?.let { value -> runCatching { UUID.fromString(value) }.getOrNull() },
                    modifiedAtEpochMillis = epochMillis(entry.updatedAt),
                    contentDigest = PmvIntegrity.encryptedBlockDigest(block),
                )
            }
            purges.forEach { (idText, timestamp) ->
                val entryId = UUID.fromString(idText)
                val previous = previousRecords[entryId]
                val purgedAt = epochMillis(timestamp.jsonPrimitive.content.toDouble())
                val tombstonePlaintext = PmvTombstoneCodec.encode(
                    PmvTombstoneCodec.Tombstone(
                        entryId,
                        revision,
                        purgedAt,
                        previous?.contentDigest?.copyOf() ?: ByteArray(32),
                    ),
                )
                val key = PmvKeySchedule.deriveEntryKey(rootKeys.entryRootKey, entryId, revision)
                val block = try {
                    PmvBlockCrypto.seal(
                        vaultId, key, PmvContainerFormat.BlockType.TOMBSTONE, entryId, revision, tombstonePlaintext,
                    )
                } finally {
                    key.fill(0)
                    tombstonePlaintext.fill(0)
                }
                val blockRef = transaction.appendBlock(block)
                records += PmvEntryIndexCodec.Record(
                    entryId = entryId,
                    entryType = previous?.entryType ?: "tombstone",
                    revision = revision,
                    offset = blockRef.offset,
                    length = blockRef.length,
                    state = PmvEntryIndexCodec.State.TOMBSTONE,
                    modifiedAtEpochMillis = purgedAt,
                    contentDigest = PmvIntegrity.encryptedBlockDigest(block),
                )
            }
            records.sortBy { it.entryId.toString() }

            val metadataPlaintext = PmvVaultMetadataCodec.encode(metadata)
            val metadataKey = PmvKeySchedule.deriveMetadataBlockKey(rootKeys.metadataKey, vaultId, revision)
            val metadataBlock = try {
                PmvBlockCrypto.seal(
                    vaultId,
                    metadataKey,
                    PmvContainerFormat.BlockType.OBJECT_METADATA,
                    vaultId,
                    revision,
                    metadataPlaintext,
                    codecId = PmvCompression.chooseCodec(metadataPlaintext),
                )
            } finally {
                metadataKey.fill(0)
                metadataPlaintext.fill(0)
            }
            val metadataRef = transaction.appendBlock(metadataBlock)

            // Frozen physical order shared with the desktop writer: data, metadata, Login leaves/root,
            // Entry leaves/root, VaultRoot, Commit.
            val loginRecords = buildLoginRecords(sortedEntries)
            val loginPages = PmvLoginFastIndex.buildPages(loginRecords)
            val loginLocations = loginPages.map { page ->
                val pageBlock = sealIndex(
                    PmvLoginFastIndex.encode(page),
                    revision,
                    PmvKeySchedule.IndexPageType.LOGIN_INDEX,
                    PmvContainerFormat.BlockType.LOGIN_INDEX,
                )
                transaction.appendBlock(pageBlock).let { PmvLoginFastIndex.PageLocation(it.offset, it.length) }
            }
            val loginRoot = loginPages.takeIf { it.isNotEmpty() }
                ?.let { PmvLoginFastIndex.buildRoot(it, loginLocations) }
            val loginRootRef = loginRoot?.let { root ->
                transaction.appendBlock(
                    sealIndex(
                        PmvLoginFastIndex.encodeRoot(root),
                        revision,
                        PmvKeySchedule.IndexPageType.LOGIN_INDEX,
                        PmvContainerFormat.BlockType.LOGIN_INDEX,
                    ),
                )
            }

            val pages = paginate(records)
            val entryRootRecords = pages.map { page ->
                val leafBlock = sealIndex(
                    PmvEntryIndexCodec.encode(page),
                    revision,
                    PmvKeySchedule.IndexPageType.ENTRY_INDEX,
                )
                val leafRef = transaction.appendBlock(leafBlock)
                PmvEntryIndexRootCodec.Record(
                    minEntryId = page.records.first().entryId,
                    maxEntryId = page.records.last().entryId,
                    pageOffset = leafRef.offset,
                    pageDigest = PmvIntegrity.entryPageDigest(page),
                )
            }
            val entryRoot = PmvEntryIndexRootCodec.Root(entryRootRecords)
            val entryRootBlock = sealIndex(
                PmvEntryIndexRootCodec.encode(entryRoot),
                revision,
                PmvKeySchedule.IndexPageType.ENTRY_INDEX,
            )
            val entryRootRef = transaction.appendBlock(entryRootBlock)

            val vaultRoot = PmvVaultRootCodec.Root(
                entry = PmvVaultRootCodec.Reference(
                    PmvVaultRootCodec.RootType.ENTRY,
                    entryRootRef.offset,
                    entryRootRef.length,
                    PmvIntegrity.entryRootDigest(entryRoot),
                ),
                login = loginRootRef?.let { reference ->
                    PmvVaultRootCodec.Reference(
                        PmvVaultRootCodec.RootType.LOGIN,
                        reference.offset,
                        reference.length,
                        PmvLoginFastIndex.logicalDigest(requireNotNull(loginRoot)),
                    )
                },
                objectIndex = objectRoots.first,
                chunkIndex = objectRoots.second,
                metadata = PmvVaultRootCodec.Reference(
                    PmvVaultRootCodec.RootType.METADATA,
                    metadataRef.offset,
                    metadataRef.length,
                    PmvVaultMetadataCodec.logicalDigest(metadata),
                ),
            )
            val vaultRootBlock = sealIndex(
                PmvVaultRootCodec.encode(vaultRoot),
                revision,
                PmvKeySchedule.IndexPageType.VAULT_ROOT,
            )
            val vaultRootRef = transaction.appendBlock(vaultRootBlock)
            val commitId = UUID.randomUUID()
            val commit = PmvCommitCodec.sign(
                vaultId = vaultId,
                commitId = commitId,
                parentCommitId = transaction.parentCommitId,
                revision = revision,
                indexRootOffset = vaultRootRef.offset,
                indexRootLength = vaultRootRef.length,
                rootDigest = PmvVaultRootCodec.logicalDigest(vaultRoot),
                privateSeed = signingPrivateSeed,
            )
            val commitPlaintext = PmvCommitCodec.encode(commit)
            val commitKey = PmvKeySchedule.deriveCommitBlockKey(rootKeys.integrityKey, commitId, revision)
            val commitBlock = try {
                PmvBlockCrypto.seal(
                    vaultId,
                    commitKey,
                    PmvContainerFormat.BlockType.COMMIT,
                    commitId,
                    revision,
                    commitPlaintext,
                )
            } finally {
                commitKey.fill(0)
                commitPlaintext.fill(0)
            }
            transaction.publish(
                indexRootRef = vaultRootRef,
                encryptedCommit = commitBlock,
                commit = commit,
                indexRootKey = rootKeys.indexKey,
                integrityKey = rootKeys.integrityKey,
                trustedSigningPublicKey = signingPublicKey,
            )
        }

        private fun resolveAuthenticatedSnapshots(): List<AuthenticatedSnapshot> {
            val result = ArrayList<AuthenticatedSnapshot>()
            container.candidateStates().forEach { candidate ->
                if (candidate.superblock.sequence == 0L) return@forEach
                try {
                    result += resolveAuthenticatedSnapshot(candidate)
                } catch (_: Exception) {
                    // Try the other independently authenticated Superblock snapshot.
                }
            }
            require(result.isNotEmpty()) { "没有可认证的 PMV 提交快照" }
            return result
        }

        private fun resolveLatestAuthenticatedSnapshot(): AuthenticatedSnapshot =
            resolveAuthenticatedSnapshots().first()

        private fun resolveAuthenticatedSnapshot(candidate: PmvAppendOnlyFile.State): AuthenticatedSnapshot {
            val superblock = candidate.superblock
            require(superblock.vaultId == vaultId && superblock.sequence > 0)
            val commitBlock = container.readBlock(candidate, superblock.latestCommitOffset, PmvContainerFormat.BlockType.COMMIT)
            require(Math.addExact(superblock.latestCommitOffset, storedLength(commitBlock)) == superblock.committedFileEnd) {
                "Commit Block 必须位于提交边界末尾"
            }
            val commitKey = PmvKeySchedule.deriveCommitBlockKey(rootKeys.integrityKey, commitBlock.header.objectId,
                commitBlock.header.objectRevision)
            val commitPlaintext = try { PmvBlockCrypto.open(vaultId, commitKey, commitBlock) } finally { commitKey.fill(0) }
            val commit = try { PmvCommitCodec.decode(commitPlaintext) } finally { commitPlaintext.fill(0) }
            require(commit.vaultId == vaultId && commit.revision == superblock.sequence)
            require(commit.commitId == commitBlock.header.objectId && commit.revision == commitBlock.header.objectRevision)
            require(PmvCommitCodec.verifySignature(commit))
            require(MessageDigest.isEqual(commit.signingPublicKey, signingPublicKey))
            require(commit.indexRootOffset == superblock.latestIndexOffset)

            val rootBlock = container.readBlock(candidate, commit.indexRootOffset, PmvContainerFormat.BlockType.INDEX_PAGE)
            require(storedLength(rootBlock) == commit.indexRootLength)
            val rootKey = PmvKeySchedule.deriveIndexPageKey(rootKeys.indexKey, rootBlock.header.objectId,
                rootBlock.header.objectRevision, PmvKeySchedule.IndexPageType.VAULT_ROOT)
            val rootPlaintext = try { PmvBlockCrypto.open(vaultId, rootKey, rootBlock) } finally { rootKey.fill(0) }
            val vaultRoot = try { PmvVaultRootCodec.decode(rootPlaintext) } finally { rootPlaintext.fill(0) }
            require(MessageDigest.isEqual(commit.rootDigest, PmvVaultRootCodec.logicalDigest(vaultRoot)))
            return AuthenticatedSnapshot(candidate, commit, vaultRoot)
        }

        private fun queryLoginIndex(
            query: (PmvLoginFastIndex.Root, (PmvLoginFastIndex.PageRange) -> PmvLoginFastIndex.Page) -> List<UUID>,
        ): List<UUID> {
            checkOpen()
            val snapshot = resolveLatestAuthenticatedSnapshot()
            val reference = snapshot.root.login ?: return emptyList()
            return try {
                val loginRoot = readLoginRoot(snapshot, reference)
                query(loginRoot) { range -> readLoginPage(snapshot, range) }
            } catch (error: Exception) {
                throw IllegalArgumentException("最新提交的 LoginFastIndex 无法认证", error)
            }
        }

        private fun readLoginRoot(
            snapshot: AuthenticatedSnapshot,
            reference: PmvVaultRootCodec.Reference,
        ): PmvLoginFastIndex.Root {
            val rootBlock = container.readBlock(
                snapshot.state,
                reference.offset,
                PmvContainerFormat.BlockType.LOGIN_INDEX,
            )
            require(storedLength(rootBlock) == reference.length)
            require(rootBlock.header.objectRevision == snapshot.commit.revision && rootBlock.header.chunkIndex == -1 &&
                rootBlock.header.flags == 0) { "LoginFastIndex 根 Block Header 无效" }
            val rootKey = PmvKeySchedule.deriveIndexPageKey(rootKeys.indexKey, rootBlock.header.objectId,
                rootBlock.header.objectRevision, PmvKeySchedule.IndexPageType.LOGIN_INDEX)
            val rootPlaintext = try { PmvBlockCrypto.open(vaultId, rootKey, rootBlock) } finally { rootKey.fill(0) }
            return try {
                PmvLoginFastIndex.decodeRoot(rootPlaintext).also { root ->
                    require(MessageDigest.isEqual(reference.digest, PmvLoginFastIndex.logicalDigest(root))) {
                        "VaultRoot Login 子根摘要不一致"
                    }
                }
            } finally {
                rootPlaintext.fill(0)
            }
        }

        private fun readLoginPage(
            snapshot: AuthenticatedSnapshot,
            range: PmvLoginFastIndex.PageRange,
        ): PmvLoginFastIndex.Page {
            val pageBlock = container.readBlock(
                snapshot.state,
                range.pageOffset,
                PmvContainerFormat.BlockType.LOGIN_INDEX,
            )
            require(storedLength(pageBlock) == range.pageLength)
            require(pageBlock.header.objectRevision == snapshot.commit.revision && pageBlock.header.chunkIndex == -1 &&
                pageBlock.header.flags == 0) { "LoginFastIndex 叶页 Block Header 无效" }
            val pageKey = PmvKeySchedule.deriveIndexPageKey(rootKeys.indexKey, pageBlock.header.objectId,
                pageBlock.header.objectRevision, PmvKeySchedule.IndexPageType.LOGIN_INDEX)
            val pagePlaintext = try { PmvBlockCrypto.open(vaultId, pageKey, pageBlock) } finally { pageKey.fill(0) }
            return try { PmvLoginFastIndex.decode(pagePlaintext) } finally { pagePlaintext.fill(0) }
        }

        private fun readMetadata(snapshot: AuthenticatedSnapshot): JsonObject {
            val reference = requireNotNull(snapshot.root.metadata) { "VaultRoot 缺少 Metadata 引用" }
            val metadataBlock = container.readBlock(
                snapshot.state,
                reference.offset,
                PmvContainerFormat.BlockType.OBJECT_METADATA,
            )
            require(storedLength(metadataBlock) == reference.length)
            require(metadataBlock.header.objectId == vaultId)
            val metadataKey = PmvKeySchedule.deriveMetadataBlockKey(
                rootKeys.metadataKey,
                metadataBlock.header.objectId,
                metadataBlock.header.objectRevision,
            )
            val metadataPlaintext = try {
                PmvBlockCrypto.open(vaultId, metadataKey, metadataBlock)
            } finally {
                metadataKey.fill(0)
            }
            return try {
                PmvVaultMetadataCodec.decode(metadataPlaintext, vaultId).also { metadata ->
                    require(MessageDigest.isEqual(reference.digest, PmvVaultMetadataCodec.logicalDigest(metadata)))
                }
            } finally {
                metadataPlaintext.fill(0)
            }
        }

        private fun writeObjectCommit(
            transaction: PmvAppendOnlyFile.Transaction,
            previousRoot: PmvVaultRootCodec.Root,
            previousObjects: LoadedObjectIndex,
            previousChunks: LoadedChunkIndex,
            objectRecords: List<PmvObjectIndexCodec.ObjectRecord>,
            chunkRecords: List<PmvObjectIndexCodec.ChunkRecord>,
        ) {
            val revision = transaction.nextRevision
            val objectPlans = PmvObjectIndexCodec.planObjectPages(
                objectRecords,
                previousObjects.root.records.map { record ->
                    PmvObjectIndexCodec.ExistingPage(
                        record.minKey,
                        record.maxKey,
                        record.pageOffset,
                        record.pageDigest,
                    )
                },
            )
            val objectRanges = objectPlans.map { plan ->
                val offset = plan.reusedOffset ?: transaction.appendBlock(
                    sealIndex(
                        PmvObjectIndexCodec.encodeObjectPage(plan.page),
                        revision,
                        PmvKeySchedule.IndexPageType.OBJECT_INDEX,
                    ),
                ).offset
                PmvObjectIndexCodec.RangeRecord(
                    plan.page.records.first().key,
                    plan.page.records.last().key,
                    offset,
                    plan.digest,
                )
            }
            val objectRoot = PmvObjectIndexCodec.RangeRoot(objectRanges)
            val objectRootRef = transaction.appendBlock(
                sealIndex(
                    PmvObjectIndexCodec.encodeObjectRoot(objectRoot),
                    revision,
                    PmvKeySchedule.IndexPageType.OBJECT_INDEX,
                ),
            )

            val chunkPlans = PmvObjectIndexCodec.planChunkPages(
                chunkRecords,
                previousChunks.root.records.map { record ->
                    PmvObjectIndexCodec.ExistingPage(
                        record.minKey,
                        record.maxKey,
                        record.pageOffset,
                        record.pageDigest,
                    )
                },
            )
            val chunkRanges = chunkPlans.map { plan ->
                val offset = plan.reusedOffset ?: transaction.appendBlock(
                    sealIndex(
                        PmvObjectIndexCodec.encodeChunkPage(plan.page),
                        revision,
                        PmvKeySchedule.IndexPageType.CHUNK_INDEX,
                    ),
                ).offset
                PmvObjectIndexCodec.RangeRecord(
                    plan.page.records.first().key,
                    plan.page.records.last().key,
                    offset,
                    plan.digest,
                )
            }
            val chunkRoot = PmvObjectIndexCodec.RangeRoot(chunkRanges)
            val chunkRootRef = transaction.appendBlock(
                sealIndex(
                    PmvObjectIndexCodec.encodeChunkRoot(chunkRoot),
                    revision,
                    PmvKeySchedule.IndexPageType.CHUNK_INDEX,
                ),
            )

            val vaultRoot = previousRoot.copy(
                objectIndex = PmvVaultRootCodec.Reference(
                    PmvVaultRootCodec.RootType.OBJECT,
                    objectRootRef.offset,
                    objectRootRef.length,
                    PmvObjectIndexCodec.objectRootDigest(objectRoot),
                ),
                chunkIndex = PmvVaultRootCodec.Reference(
                    PmvVaultRootCodec.RootType.CHUNK,
                    chunkRootRef.offset,
                    chunkRootRef.length,
                    PmvObjectIndexCodec.chunkRootDigest(chunkRoot),
                ),
            )
            val vaultRootRef = transaction.appendBlock(
                sealIndex(
                    PmvVaultRootCodec.encode(vaultRoot),
                    revision,
                    PmvKeySchedule.IndexPageType.VAULT_ROOT,
                ),
            )
            val commitId = UUID.randomUUID()
            val commit = PmvCommitCodec.sign(
                vaultId = vaultId,
                commitId = commitId,
                parentCommitId = transaction.parentCommitId,
                revision = revision,
                indexRootOffset = vaultRootRef.offset,
                indexRootLength = vaultRootRef.length,
                rootDigest = PmvVaultRootCodec.logicalDigest(vaultRoot),
                privateSeed = signingPrivateSeed,
            )
            val commitPlaintext = PmvCommitCodec.encode(commit)
            val commitKey = PmvKeySchedule.deriveCommitBlockKey(rootKeys.integrityKey, commitId, revision)
            val commitBlock = try {
                PmvBlockCrypto.seal(
                    vaultId,
                    commitKey,
                    PmvContainerFormat.BlockType.COMMIT,
                    commitId,
                    revision,
                    commitPlaintext,
                )
            } finally {
                commitKey.fill(0)
                commitPlaintext.fill(0)
            }
            transaction.publish(
                indexRootRef = vaultRootRef,
                encryptedCommit = commitBlock,
                commit = commit,
                indexRootKey = rootKeys.indexKey,
                integrityKey = rootKeys.integrityKey,
                trustedSigningPublicKey = signingPublicKey,
            )
        }

        private fun writeObjectIndexes(
            transaction: PmvAppendOnlyFile.Transaction,
            previousObjects: LoadedObjectIndex,
            previousChunks: LoadedChunkIndex,
            objectRecords: List<PmvObjectIndexCodec.ObjectRecord>,
            chunkRecords: List<PmvObjectIndexCodec.ChunkRecord>,
        ): Pair<PmvVaultRootCodec.Reference, PmvVaultRootCodec.Reference> {
            val revision = transaction.nextRevision
            val objectRanges = PmvObjectIndexCodec.planObjectPages(
                objectRecords,
                previousObjects.root.records.map { record ->
                    PmvObjectIndexCodec.ExistingPage(record.minKey, record.maxKey, record.pageOffset, record.pageDigest)
                },
            ).map { plan ->
                val offset = plan.reusedOffset ?: transaction.appendBlock(
                    sealIndex(
                        PmvObjectIndexCodec.encodeObjectPage(plan.page),
                        revision,
                        PmvKeySchedule.IndexPageType.OBJECT_INDEX,
                    ),
                ).offset
                PmvObjectIndexCodec.RangeRecord(
                    plan.page.records.first().key,
                    plan.page.records.last().key,
                    offset,
                    plan.digest,
                )
            }
            val objectRoot = PmvObjectIndexCodec.RangeRoot(objectRanges)
            val objectRootRef = transaction.appendBlock(
                sealIndex(
                    PmvObjectIndexCodec.encodeObjectRoot(objectRoot),
                    revision,
                    PmvKeySchedule.IndexPageType.OBJECT_INDEX,
                ),
            )

            val chunkRanges = PmvObjectIndexCodec.planChunkPages(
                chunkRecords,
                previousChunks.root.records.map { record ->
                    PmvObjectIndexCodec.ExistingPage(record.minKey, record.maxKey, record.pageOffset, record.pageDigest)
                },
            ).map { plan ->
                val offset = plan.reusedOffset ?: transaction.appendBlock(
                    sealIndex(
                        PmvObjectIndexCodec.encodeChunkPage(plan.page),
                        revision,
                        PmvKeySchedule.IndexPageType.CHUNK_INDEX,
                    ),
                ).offset
                PmvObjectIndexCodec.RangeRecord(
                    plan.page.records.first().key,
                    plan.page.records.last().key,
                    offset,
                    plan.digest,
                )
            }
            val chunkRoot = PmvObjectIndexCodec.RangeRoot(chunkRanges)
            val chunkRootRef = transaction.appendBlock(
                sealIndex(
                    PmvObjectIndexCodec.encodeChunkRoot(chunkRoot),
                    revision,
                    PmvKeySchedule.IndexPageType.CHUNK_INDEX,
                ),
            )
            return PmvVaultRootCodec.Reference(
                PmvVaultRootCodec.RootType.OBJECT,
                objectRootRef.offset,
                objectRootRef.length,
                PmvObjectIndexCodec.objectRootDigest(objectRoot),
            ) to PmvVaultRootCodec.Reference(
                PmvVaultRootCodec.RootType.CHUNK,
                chunkRootRef.offset,
                chunkRootRef.length,
                PmvObjectIndexCodec.chunkRootDigest(chunkRoot),
            )
        }

        private data class CompactRef(val offset: Long, val length: Long)

        private class CompactWriter(private val output: RandomAccessFile) {
            var tail: Long = PmvContainerFormat.DATA_START
                private set

            fun append(block: PmvContainerFormat.EncodedBlock): CompactRef {
                output.seek(tail)
                output.write(PmvContainerFormat.encodeBlockHeader(block.header))
                output.write(block.ciphertext)
                val result = CompactRef(
                    tail,
                    Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), block.header.cipherSize),
                )
                tail = Math.addExact(tail, result.length)
                return result
            }
        }

        private object NullOutputStream : OutputStream() {
            override fun write(value: Int) = Unit
            override fun write(value: ByteArray, offset: Int, length: Int) = Unit
        }

        private fun writeCompactObjectIndexes(
            writer: CompactWriter,
            revision: Long,
            objects: List<PmvObjectIndexCodec.ObjectRecord>,
            chunks: List<PmvObjectIndexCodec.ChunkRecord>,
        ): Pair<PmvVaultRootCodec.Reference, PmvVaultRootCodec.Reference> {
            val objectRanges = PmvObjectIndexCodec.planObjectPages(objects).map { plan ->
                val page = plan.page
                val ref = writer.append(sealIndex(
                    PmvObjectIndexCodec.encodeObjectPage(page), revision,
                    PmvKeySchedule.IndexPageType.OBJECT_INDEX,
                ))
                PmvObjectIndexCodec.RangeRecord(
                    page.records.first().key, page.records.last().key, ref.offset, plan.digest,
                )
            }
            val objectRoot = PmvObjectIndexCodec.RangeRoot(objectRanges)
            val objectRootRef = writer.append(sealIndex(
                PmvObjectIndexCodec.encodeObjectRoot(objectRoot), revision,
                PmvKeySchedule.IndexPageType.OBJECT_INDEX,
            ))

            val chunkRanges = PmvObjectIndexCodec.planChunkPages(chunks).map { plan ->
                val page = plan.page
                val ref = writer.append(sealIndex(
                    PmvObjectIndexCodec.encodeChunkPage(page), revision,
                    PmvKeySchedule.IndexPageType.CHUNK_INDEX,
                ))
                PmvObjectIndexCodec.RangeRecord(
                    page.records.first().key, page.records.last().key, ref.offset, plan.digest,
                )
            }
            val chunkRoot = PmvObjectIndexCodec.RangeRoot(chunkRanges)
            val chunkRootRef = writer.append(sealIndex(
                PmvObjectIndexCodec.encodeChunkRoot(chunkRoot), revision,
                PmvKeySchedule.IndexPageType.CHUNK_INDEX,
            ))
            return PmvVaultRootCodec.Reference(
                PmvVaultRootCodec.RootType.OBJECT, objectRootRef.offset, objectRootRef.length,
                PmvObjectIndexCodec.objectRootDigest(objectRoot),
            ) to PmvVaultRootCodec.Reference(
                PmvVaultRootCodec.RootType.CHUNK, chunkRootRef.offset, chunkRootRef.length,
                PmvObjectIndexCodec.chunkRootDigest(chunkRoot),
            )
        }

        private fun requireSameLogicalReference(
            current: PmvVaultRootCodec.Reference?,
            previous: PmvVaultRootCodec.Reference?,
            label: String,
        ) {
            require((current == null) == (previous == null)) { "Compact 改变了 $label 存在状态" }
            if (current != null && previous != null) {
                require(current.type == previous.type && current.length == previous.length &&
                    MessageDigest.isEqual(current.digest, previous.digest)) {
                    "Compact 改变了 $label 逻辑引用"
                }
            }
        }

        private fun reachableObjectRoots(
            transaction: PmvAppendOnlyFile.Transaction,
            snapshot: AuthenticatedSnapshot,
            previousObjects: LoadedObjectIndex,
            previousChunks: LoadedChunkIndex,
            metadata: JsonObject,
            entries: List<Entry>,
        ): Pair<PmvVaultRootCodec.Reference?, PmvVaultRootCodec.Reference?> {
            val occurrences = entries.flatMap(PmvMediaRef::scan) + PmvMediaRef.scanJson(metadata)
            require(occurrences.none { it.classification in setOf(
                PmvMediaRef.Classification.LEGACY_EXTERNAL,
                PmvMediaRef.Classification.INLINE,
            ) }) { "最终 Entry/metadata 不得以外置路径或 inline 数据作为媒体权威引用" }
            val referenced = occurrences.mapNotNull { occurrence -> occurrence.ref?.let { ref ->
                PmvObjectIndexCodec.ObjectKey(ref.objectId, ref.generation)
            } }.toSet()
            val available = previousObjects.records.map { it.key }.toSet()
            require(referenced.all { it in available }) { "最终 Entry/metadata 含悬挂 PMV ObjectRef" }
            if (referenced == available) return snapshot.root.objectIndex to snapshot.root.chunkIndex
            if (referenced.isEmpty()) return null to null
            val objects = previousObjects.records.filter { it.key in referenced }
            val chunks = previousChunks.records.filter {
                PmvObjectIndexCodec.ObjectKey(it.key.objectId, it.key.generation) in referenced
            }
            return writeObjectIndexes(transaction, previousObjects, previousChunks, objects, chunks)
        }

        private fun loadObjectIndex(snapshot: AuthenticatedSnapshot): LoadedObjectIndex {
            val objectReference = snapshot.root.objectIndex
            val chunkReference = snapshot.root.chunkIndex
            require((objectReference == null) == (chunkReference == null)) {
                "VaultRoot 必须同时包含 ObjectIndex 与 ChunkIndex"
            }
            if (objectReference == null) {
                return LoadedObjectIndex(PmvObjectIndexCodec.RangeRoot(emptyList()), emptyList())
            }
            val root = readObjectRoot(snapshot, objectReference)
            val records = root.records.flatMap { range -> readObjectPage(snapshot, range).records }
            return LoadedObjectIndex(root, records)
        }

        private fun loadChunkIndex(snapshot: AuthenticatedSnapshot): LoadedChunkIndex {
            val objectReference = snapshot.root.objectIndex
            val chunkReference = snapshot.root.chunkIndex
            require((objectReference == null) == (chunkReference == null)) {
                "VaultRoot 必须同时包含 ObjectIndex 与 ChunkIndex"
            }
            if (chunkReference == null) {
                return LoadedChunkIndex(PmvObjectIndexCodec.RangeRoot(emptyList()), emptyList())
            }
            val root = readChunkRoot(snapshot, chunkReference)
            val records = root.records.flatMap { range -> readChunkPage(snapshot, range).records }
            return LoadedChunkIndex(root, records)
        }

        private fun objectLookup(snapshot: AuthenticatedSnapshot, objectId: UUID, generation: Long): ObjectLookup {
            require(generation >= 0) { "Object generation 无效" }
            val objectReference = requireNotNull(snapshot.root.objectIndex) { "提交快照不包含 ObjectIndex" }
            val chunkReference = requireNotNull(snapshot.root.chunkIndex) { "提交快照不包含 ChunkIndex" }
            val objectRoot = readObjectRoot(snapshot, objectReference)
            val key = PmvObjectIndexCodec.ObjectKey(objectId, generation)
            val range = requireNotNull(objectRoot.findPage(key)) { "Object generation 不存在" }
            val objectRecord = requireNotNull(readObjectPage(snapshot, range).find(key)) { "Object generation 不存在" }
            return ObjectLookup(snapshot, objectRecord, readChunkRoot(snapshot, chunkReference))
        }

        private fun readObjectRoot(
            snapshot: AuthenticatedSnapshot,
            reference: PmvVaultRootCodec.Reference,
        ): PmvObjectIndexCodec.RangeRoot<PmvObjectIndexCodec.ObjectKey> {
            val block = readObjectIndexBlock(snapshot, reference.offset, PmvKeySchedule.IndexPageType.OBJECT_INDEX)
            require(storedLength(block) == reference.length) { "ObjectIndex 根长度不一致" }
            val plaintext = openIndexBlock(block, PmvKeySchedule.IndexPageType.OBJECT_INDEX)
            return try {
                PmvObjectIndexCodec.decodeObjectRoot(plaintext).also { root ->
                    require(MessageDigest.isEqual(reference.digest, PmvObjectIndexCodec.objectRootDigest(root))) {
                        "VaultRoot ObjectIndex 子根摘要不一致"
                    }
                }
            } finally {
                plaintext.fill(0)
            }
        }

        private fun readChunkRoot(
            snapshot: AuthenticatedSnapshot,
            reference: PmvVaultRootCodec.Reference,
        ): PmvObjectIndexCodec.RangeRoot<PmvObjectIndexCodec.ChunkKey> {
            val block = readObjectIndexBlock(snapshot, reference.offset, PmvKeySchedule.IndexPageType.CHUNK_INDEX)
            require(storedLength(block) == reference.length) { "ChunkIndex 根长度不一致" }
            val plaintext = openIndexBlock(block, PmvKeySchedule.IndexPageType.CHUNK_INDEX)
            return try {
                PmvObjectIndexCodec.decodeChunkRoot(plaintext).also { root ->
                    require(MessageDigest.isEqual(reference.digest, PmvObjectIndexCodec.chunkRootDigest(root))) {
                        "VaultRoot ChunkIndex 子根摘要不一致"
                    }
                }
            } finally {
                plaintext.fill(0)
            }
        }

        private fun readObjectPage(
            snapshot: AuthenticatedSnapshot,
            range: PmvObjectIndexCodec.RangeRecord<PmvObjectIndexCodec.ObjectKey>,
        ): PmvObjectIndexCodec.ObjectPage {
            val block = readObjectIndexBlock(snapshot, range.pageOffset, PmvKeySchedule.IndexPageType.OBJECT_INDEX)
            val plaintext = openIndexBlock(block, PmvKeySchedule.IndexPageType.OBJECT_INDEX)
            return try {
                PmvObjectIndexCodec.decodeObjectPage(plaintext).also { page ->
                    require(page.records.isNotEmpty() && page.records.first().key == range.minKey &&
                        page.records.last().key == range.maxKey &&
                        MessageDigest.isEqual(range.pageDigest, PmvObjectIndexCodec.objectPageDigest(page))) {
                        "ObjectIndex 叶页与范围根不一致"
                    }
                }
            } finally {
                plaintext.fill(0)
            }
        }

        private fun readChunkPage(
            snapshot: AuthenticatedSnapshot,
            range: PmvObjectIndexCodec.RangeRecord<PmvObjectIndexCodec.ChunkKey>,
        ): PmvObjectIndexCodec.ChunkPage {
            val block = readObjectIndexBlock(snapshot, range.pageOffset, PmvKeySchedule.IndexPageType.CHUNK_INDEX)
            val plaintext = openIndexBlock(block, PmvKeySchedule.IndexPageType.CHUNK_INDEX)
            return try {
                PmvObjectIndexCodec.decodeChunkPage(plaintext).also { page ->
                    require(page.records.isNotEmpty() && page.records.first().key == range.minKey &&
                        page.records.last().key == range.maxKey &&
                        MessageDigest.isEqual(range.pageDigest, PmvObjectIndexCodec.chunkPageDigest(page))) {
                        "ChunkIndex 叶页与范围根不一致"
                    }
                }
            } finally {
                plaintext.fill(0)
            }
        }

        private fun readObjectIndexBlock(
            snapshot: AuthenticatedSnapshot,
            offset: Long,
            pageType: PmvKeySchedule.IndexPageType,
        ): PmvContainerFormat.EncodedBlock = container.readBlock(
            snapshot.state,
            offset,
            PmvContainerFormat.BlockType.INDEX_PAGE,
        ).also { block ->
            require(block.header.objectRevision in 1..snapshot.commit.revision && block.header.chunkIndex == -1 &&
                block.header.flags == 0 && block.header.codecId == 0) {
                "${pageType.domain} Block Header 角色无效"
            }
        }

        private fun openIndexBlock(
            block: PmvContainerFormat.EncodedBlock,
            pageType: PmvKeySchedule.IndexPageType,
        ): ByteArray {
            val key = PmvKeySchedule.deriveIndexPageKey(
                rootKeys.indexKey,
                block.header.objectId,
                block.header.objectRevision,
                pageType,
            )
            return try {
                PmvBlockCrypto.open(vaultId, key, block)
            } finally {
                key.fill(0)
            }
        }

        private fun requireSameSnapshot(
            transaction: PmvAppendOnlyFile.Transaction,
            snapshot: AuthenticatedSnapshot,
        ) {
            val base = transaction.baseSnapshot.superblock
            val selected = snapshot.state.superblock
            require(base.sequence == selected.sequence && base.vaultId == selected.vaultId &&
                base.latestCommitOffset == selected.latestCommitOffset &&
                base.latestIndexOffset == selected.latestIndexOffset &&
                base.committedFileEnd == selected.committedFileEnd) {
                "写事务基线与已认证快照不一致"
            }
        }

        private fun selectCompatibleHeaderRaw(
            unlock: (ByteArray) -> PmvVaultHeaderCodec.UnlockedHeader,
        ): ByteArray {
            val (first, second) = readHeaderSlots(file)
            val candidates = listOf(first, second).mapIndexedNotNull { index, raw ->
                runCatching { unlock(raw) }.getOrNull()?.let { index to it }
            }.sortedWith(
                compareByDescending<Pair<Int, PmvVaultHeaderCodec.UnlockedHeader>> { it.second.header.headerRevision }
                    .thenByDescending { it.second.header.keyRevision },
            )
            try {
                candidates.forEach { (index, unlocked) ->
                    if (unlocked.header.vaultId == vaultId &&
                        MessageDigest.isEqual(unlocked.header.signingPublicKey, signingPublicKey) &&
                        MessageDigest.isEqual(unlocked.vaultRootKey, vaultRootKey)
                    ) {
                        return (if (index == 0) first else second).copyOf()
                    }
                }
                throw IllegalArgumentException("凭据未认证当前会话的 PMV Header")
            } finally {
                candidates.forEach { it.second.close() }
                first.fill(0)
                second.fill(0)
            }
        }

        private fun publishHeader(updated: ByteArray) {
            try {
                // Secondary then primary, each independently durable, preserves one usable slot on interruption.
                RandomAccessFile(file, "rw").use { output ->
                    output.seek(PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET)
                    output.write(updated)
                    output.fd.sync()
                    output.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
                    output.write(updated)
                    output.fd.sync()
                }
                val decoded = PmvVaultHeaderCodec.decode(updated)
                headerRevision = decoded.headerRevision
                kdfParameters = decoded.kdfParameters
                syncDirectory(file)
            } finally {
                updated.fill(0)
            }
        }

        private data class LoadedObjectIndex(
            val root: PmvObjectIndexCodec.RangeRoot<PmvObjectIndexCodec.ObjectKey>,
            val records: List<PmvObjectIndexCodec.ObjectRecord>,
        )

        private data class LoadedChunkIndex(
            val root: PmvObjectIndexCodec.RangeRoot<PmvObjectIndexCodec.ChunkKey>,
            val records: List<PmvObjectIndexCodec.ChunkRecord>,
        )

        private inner class ObjectLookup(
            private val snapshot: AuthenticatedSnapshot,
            val objectRecord: PmvObjectIndexCodec.ObjectRecord,
            private val chunkRoot: PmvObjectIndexCodec.RangeRoot<PmvObjectIndexCodec.ChunkKey>,
        ) {
            fun readBlock(offset: Long, length: Long): PmvContainerFormat.EncodedBlock =
                container.readBlock(snapshot.state, offset).also { block ->
                    require(storedLength(block) == length) { "Object Block 长度与索引不一致" }
                }

            fun findChunk(key: PmvObjectIndexCodec.ChunkKey): PmvObjectIndexCodec.ChunkRecord? {
                val range = chunkRoot.findPage(key) ?: return null
                return readChunkPage(snapshot, range).find(key)
            }
        }

        private data class AuthenticatedSnapshot(
            val state: PmvAppendOnlyFile.State,
            val commit: PmvCommitCodec.Commit,
            val root: PmvVaultRootCodec.Root,
        )

        private fun reader() = PmvEntryReader(
            container = container,
            vaultId = vaultId,
            entryRootKey = rootKeys.entryRootKey,
            indexRootKey = rootKeys.indexKey,
            integrityKey = rootKeys.integrityKey,
            trustedVaultSigningPublicKey = signingPublicKey,
        )

        private fun sealIndex(
            plaintext: ByteArray,
            revision: Long,
            pageType: PmvKeySchedule.IndexPageType,
            blockType: PmvContainerFormat.BlockType = PmvContainerFormat.BlockType.INDEX_PAGE,
        ): PmvContainerFormat.EncodedBlock {
            val objectId = UUID.randomUUID()
            val key = PmvKeySchedule.deriveIndexPageKey(rootKeys.indexKey, objectId, revision, pageType)
            return try {
                PmvBlockCrypto.seal(vaultId, key, blockType, objectId, revision, plaintext)
            } finally {
                key.fill(0)
                plaintext.fill(0)
            }
        }

        private fun buildLoginRecords(entries: List<Entry>): List<PmvLoginFastIndex.Record> {
            val records = ArrayList<PmvLoginFastIndex.Record>()
            val seenRpTokens = ArrayList<Pair<UUID, ByteArray>>()
            try {
                entries.forEach { entry ->
                if (entry.deletedAt != null) return@forEach
                val entryId = UUID.fromString(entry.id)
                if (entry.secretType == SecretType.LOGIN) {
                    // 旧库升级常见形态：网址只存在 legacy url 模块、包名只存在 target_app 模块。
                    // 顶层字段与模块值一并建立索引，避免升级后登录条目完全查不到。
                    val webBindings = sequenceOf(entry.url) +
                        moduleStringValues(entry, "url") +
                        autofillOriginValues(entry, "web", "host")
                    webBindings.mapNotNull(::domainFromUrl).distinct().forEach { domain ->
                        runCatching { PmvLoginFastIndex.domainToken(rootKeys.searchIndexKey, domain) }.getOrNull()
                            ?.let { token ->
                                records += PmvLoginFastIndex.Record(
                                    entryId,
                                    PmvLoginFastIndex.EntryType.LOGIN,
                                    PmvLoginFastIndex.State.ACTIVE,
                                    PmvLoginFastIndex.LookupKind.DOMAIN,
                                    token,
                                )
                                token.fill(0)
                            }
                    }
                    // 与旧版索引保持一致：target_app 与 url 都可能保存 Android 包名，
                    // 按规范化结果去重后建立 PACKAGE 索引，避免升级库中仅 url 存包名时无法命中。
                    val packageCandidates = linkedSetOf<String>()
                    (sequenceOf(entry.targetApp, entry.url) + moduleStringValues(entry, "target_app") +
                        autofillOriginValues(entry, "android", "package")).forEach { raw ->
                        runCatching { PmvLoginFastIndex.normalizePackage(raw) }.getOrNull()?.let(packageCandidates::add)
                    }
                    packageCandidates.forEach { packageName ->
                        runCatching { PmvLoginFastIndex.packageToken(rootKeys.searchIndexKey, packageName) }.getOrNull()
                            ?.let { token ->
                                records += PmvLoginFastIndex.Record(
                                    entryId,
                                    PmvLoginFastIndex.EntryType.LOGIN,
                                    PmvLoginFastIndex.State.ACTIVE,
                                    PmvLoginFastIndex.LookupKind.PACKAGE,
                                    token,
                                )
                                token.fill(0)
                            }
                    }
                }
                passkeyRpIds(entry).forEach { rpId ->
                        runCatching { PmvLoginFastIndex.rpIdToken(rootKeys.searchIndexKey, rpId) }.getOrNull()
                            ?.let { token ->
                            if (seenRpTokens.none { (seenEntryId, seenToken) ->
                                seenEntryId == entryId && MessageDigest.isEqual(seenToken, token)
                            }) {
                                seenRpTokens += entryId to token.copyOf()
                                records += PmvLoginFastIndex.Record(
                                        entryId,
                                        PmvLoginFastIndex.EntryType.PASSKEY,
                                        PmvLoginFastIndex.State.ACTIVE,
                                        PmvLoginFastIndex.LookupKind.RP_ID,
                                        token,
                                    )
                                }
                                token.fill(0)
                            }
                }
                }
            } finally {
                seenRpTokens.forEach { (_, token) -> token.fill(0) }
            }
            return records
        }

        private fun autofillOriginValues(entry: Entry, kind: String, key: String): Sequence<String> {
            val origins = ArrayList<JsonObject>()
            (entry.fields["_autofill_bindings"] as? JsonArray).orEmpty()
                .mapNotNullTo(origins) { it as? JsonObject }
            (entry.fields["_autofill_origin"] as? JsonObject)?.let(origins::add)
            return origins.asSequence().mapNotNull { origin ->
                val actualKind = origin["kind"] as? JsonPrimitive
                if (actualKind?.isString != true || actualKind.content != kind) return@mapNotNull null
                val value = origin[key] as? JsonPrimitive
                value?.takeIf(JsonPrimitive::isString)?.content?.trim()?.takeIf(String::isNotEmpty)
            }.distinct()
        }

        private fun passkeyRpIds(entry: Entry): List<String> {
            val result = ArrayList<String>()
            fun addString(value: kotlinx.serialization.json.JsonElement?) {
                val primitive = value as? JsonPrimitive ?: return
                if (!primitive.isString) return
                primitive.content.trim().takeIf(String::isNotEmpty)?.let(result::add)
            }
            if (entry.secretType == SecretType.PASSKEY) addString(entry.fields["rp_id"])
            (entry.fields["modules"] as? JsonArray).orEmpty().forEach { raw ->
                val module = raw as? JsonObject ?: return@forEach
                val type = module["type"] as? JsonPrimitive ?: return@forEach
                if (!type.isString || type.content != "passkey") return@forEach
                val value = module["value"] as? JsonObject ?: return@forEach
                PasskeyRecord.parse(value)?.rpId?.let(result::add)
            }
            return result.distinct()
        }

        private fun moduleStringValues(entry: Entry, type: String): List<String> {
            val modules = entry.fields[EntryModules.FIELD_KEY] as? JsonArray ?: return emptyList()
            val result = ArrayList<String>()
            for (raw in modules) {
                val module = raw as? JsonObject ?: continue
                val moduleType = (module["type"] as? JsonPrimitive)?.contentOrNull?.trim().orEmpty()
                if (moduleType != type) continue
                (module["value"] as? JsonPrimitive)?.contentOrNull?.trim()
                    ?.takeIf(String::isNotEmpty)?.let(result::add)
            }
            return result.distinct()
        }

        private fun domainFromUrl(raw: String): String? {
            val value = raw.trim()
            if (value.isEmpty()) return null
            return runCatching { URI(value).host }.getOrNull()?.takeIf { it.isNotBlank() }
                ?: runCatching { URI("https://$value").host }.getOrNull()?.takeIf { it.isNotBlank() }
        }

        private fun normalizeMetadata(metadata: JsonObject, entries: List<Entry>): JsonObject {
            val updated = metadata.toMutableMap().apply {
                remove("deletion_baseline")
                remove("_deletion_known_members_v1")
            }
            updated["vault_id"] = JsonPrimitive(vaultId.toString())
            updated["key_revision"] = JsonPrimitive(keyRevision)
            updated["entry_order"] = JsonArray(entries.filter { it.deletedAt == null }.map { JsonPrimitive(it.id) })
            updated["trash_order"] = JsonArray(entries.filter { it.deletedAt != null }.map { JsonPrimitive(it.id) })
            return JsonObject(updated).also { value ->
                val encoded = PmvVaultMetadataCodec.encode(value)
                encoded.fill(0)
            }
        }

        private fun checkOpen() = check(!closed) { "PMV Store Session 已关闭" }
    }

    private fun paginate(records: List<PmvEntryIndexCodec.Record>): List<PmvEntryIndexCodec.Page> {
        if (records.isEmpty()) return emptyList()
        val result = ArrayList<PmvEntryIndexCodec.Page>()
        var current = ArrayList<PmvEntryIndexCodec.Record>()
        records.forEach { record ->
            val candidate = current + record
            if (runCatching { PmvEntryIndexCodec.encode(PmvEntryIndexCodec.Page(candidate, 0)) }.isSuccess) {
                current.add(record)
            } else {
                require(current.isNotEmpty()) { "单条 EntryIndex 记录超过页容量" }
                result += PmvEntryIndexCodec.Page(current, 0)
                current = arrayListOf(record)
                PmvEntryIndexCodec.encode(PmvEntryIndexCodec.Page(current, 0)).fill(0)
            }
        }
        if (current.isNotEmpty()) result += PmvEntryIndexCodec.Page(current, 0)
        return result
    }

    private fun readHeaderSlots(file: File): Pair<ByteArray, ByteArray> = RandomAccessFile(file, "r").use { input ->
        val first = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
        val second = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
        input.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
        input.readFully(first)
        input.seek(PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET)
        input.readFully(second)
        first to second
    }

    private fun randomBytes(size: Int, random: SecureRandom): ByteArray = ByteArray(size).also(random::nextBytes)

    private fun randomUuid(random: SecureRandom): UUID {
        val bytes = randomBytes(16, random)
        bytes[6] = ((bytes[6].toInt() and 0x0f) or 0x40).toByte()
        bytes[8] = ((bytes[8].toInt() and 0x3f) or 0x80).toByte()
        return java.nio.ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }.also { bytes.fill(0) }
    }

    private fun storedLength(block: PmvContainerFormat.EncodedBlock): Long =
        Math.addExact(PmvContainerFormat.BLOCK_HEADER_SIZE.toLong(), block.header.cipherSize)

    private fun epochMillis(seconds: Double): Long = when {
        !seconds.isFinite() || seconds <= 0.0 -> 0L
        seconds >= Long.MAX_VALUE / 1000.0 -> Long.MAX_VALUE
        else -> (seconds * 1000.0).toLong()
    }

    private fun syncDirectory(file: File) {
        val parent = file.canonicalFile.parentFile ?: return
        runCatching {
            FileChannel.open(parent.toPath(), StandardOpenOption.READ).use { it.force(true) }
        }
    }
}
