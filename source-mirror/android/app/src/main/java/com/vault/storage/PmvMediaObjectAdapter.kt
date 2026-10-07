package com.vault.storage

import com.vault.model.Entry
import com.vault.model.VaultPayload
import java.io.FilterOutputStream
import java.io.OutputStream
import java.security.MessageDigest

/** Streaming PMVE media facade. It never materializes an object or writes plaintext cache files. */
internal class PmvMediaObjectAdapter(private val file: java.io.File) {
    data class SaveResult(
        val identity: PmvVaultStore.Identity,
        val entry: Entry,
        val entryRevision: Long,
        val refs: List<PmvMediaRef.Ref>,
    )

    fun open(ref: PmvMediaRef.Ref, rootKey: ByteArray, output: OutputStream) {
        val verified = DigestingOutputStream(output)
        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            session.openObject(ref.objectId, ref.generation, verified)
        }
        require(verified.count == ref.size && MessageDigest.isEqual(verified.digest(), ref.sha256)) {
            "PMVE Object 内容与 Entry ObjectRef 不一致"
        }
    }

    fun openRange(
        ref: PmvMediaRef.Ref,
        rootKey: ByteArray,
        offset: Long,
        length: Long,
        output: OutputStream,
    ) {
        require(offset >= 0 && length >= 0 && offset <= ref.size && length <= ref.size - offset) {
            "PMVE Object range 超出引用大小"
        }
        val counted = CountingOutputStream(output)
        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            session.openObjectRange(ref.objectId, ref.generation, offset, length, counted)
        }
        require(counted.count == length) { "PMVE Object range 输出长度不一致" }
    }

    fun saveEntryWithMedia(
        rootKey: ByteArray,
        expectedSequence: Long,
        entry: Entry,
        expectedEntryRevision: Long?,
        streams: List<PmvMediaRef.LegacyStream>,
        transformMetadata: (PmvVaultStore.Session, kotlinx.serialization.json.JsonObject) -> kotlinx.serialization.json.JsonObject = { _, metadata -> metadata },
    ): SaveResult = PmvVaultStore.openRootKey(file, rootKey).use { session ->
        if (session.identity().sequence != expectedSequence) {
            throw VaultStaleMutationException("PMVE 媒体提交基线已过期")
        }
        // Fail fast before consuming caller-owned streams. The same check is repeated inside
        // applyMutation.prepare, where the Store writer lock makes it authoritative.
        requireExpectedEntryRevision(session.listSummaries(), entry, expectedEntryRevision)
        val plan = PmvMediaRef.plan(entry, streams)
        var committedEntry: Entry? = null
        val result = try {
            session.applyMutation(expectedSequence, plan.objectImports) { objectRefs ->
                val metadata = session.readMetadata()
                val summaries = session.listSummaries()
                requireExpectedEntryRevision(summaries, entry, expectedEntryRevision)
                val currentEntries = summaries.map { summary ->
                    requireNotNull(session.readEntry(summary.entryId)) {
                        "PMVE EntryIndex 引用了不存在的 Entry"
                    }
                }
                val currentPayload = PmvEPayloadAdapter.fromMetadata(metadata, currentEntries)
                val transformed = plan.transform(objectRefs)
                committedEntry = transformed
                val updatedPayload = replaceEntry(currentPayload, transformed)
                val updatedMetadata = PmvEPayloadAdapter.toMetadata(
                    updatedPayload,
                    session.identity().vaultId,
                    metadata,
                )
                PmvVaultStore.MutationContent(
                    transformMetadata(session, updatedMetadata),
                    updatedPayload.entries + updatedPayload.trash,
                )
            }
        } catch (error: IllegalArgumentException) {
            if (error.message?.contains("基线已过期") == true) {
                throw VaultStaleMutationException("PMVE 媒体提交基线已过期", error)
            }
            throw error
        }
        SaveResult(
            result.identity,
            requireNotNull(committedEntry) { "PMVE 媒体事务未生成 Entry" },
            result.identity.sequence,
            result.objectRefs.map(PmvMediaRef::fromStoreRef),
        )
    }

    private fun requireExpectedEntryRevision(
        summaries: List<PmvEntryReader.Summary>,
        entry: Entry,
        expectedEntryRevision: Long?,
    ) {
        val existing = summaries.firstOrNull { it.entryId.toString() == entry.id }
        if (existing == null) {
            if (expectedEntryRevision != null) {
                throw VaultStaleMutationException("待更新的 PMVE Entry 不存在")
            }
        } else if (expectedEntryRevision == null || existing.revision != expectedEntryRevision) {
            throw VaultStaleMutationException("PMVE Entry revision 已变化")
        }
    }

    private fun replaceEntry(payload: VaultPayload, entry: Entry): VaultPayload {
        val existingActive = payload.entries.indexOfFirst { it.id == entry.id }
        val existingTrash = payload.trash.indexOfFirst { it.id == entry.id }
        require(existingActive < 0 || existingTrash < 0) { "Entry 同时存在于 active 与 trash" }
        val active = payload.entries.toMutableList().apply {
            if (existingActive >= 0) removeAt(existingActive)
        }
        val trash = payload.trash.toMutableList().apply {
            if (existingTrash >= 0) removeAt(existingTrash)
        }
        if (entry.deletedAt == null) {
            active.add(if (existingActive >= 0) existingActive else active.size, entry)
        } else {
            trash.add(if (existingTrash >= 0) existingTrash else trash.size, entry)
        }
        return payload.copy(entries = active, trash = trash)
    }

    private open class CountingOutputStream(output: OutputStream) : FilterOutputStream(output) {
        var count: Long = 0
            private set

        override fun write(value: Int) {
            out.write(value)
            count = Math.addExact(count, 1L)
        }

        override fun write(buffer: ByteArray, offset: Int, length: Int) {
            out.write(buffer, offset, length)
            count = Math.addExact(count, length.toLong())
        }
    }

    private class DigestingOutputStream(output: OutputStream) : CountingOutputStream(output) {
        private val messageDigest = MessageDigest.getInstance("SHA-256")

        override fun write(value: Int) {
            super.write(value)
            messageDigest.update(value.toByte())
        }

        override fun write(buffer: ByteArray, offset: Int, length: Int) {
            super.write(buffer, offset, length)
            messageDigest.update(buffer, offset, length)
        }

        fun digest(): ByteArray = messageDigest.digest()
    }
}
