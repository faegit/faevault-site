package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.CancellationException

class PmvMediaObjectAdapterTest {
    private val password = "media-adapter-password".encodeToByteArray()
    private val recovery = ByteArray(32) { (it * 11).toByte() }

    @Test
    fun `zero byte media is imported with entry and opened without a plaintext file`() = withVault { file, rootKey ->
        val entry = legacyEntry("zero")
        val objectId = UUID.nameUUIDFromBytes("zero-object".encodeToByteArray())
        val adapter = PmvMediaObjectAdapter(file)

        val saved = adapter.saveEntryWithMedia(
            rootKey,
            expectedSequence = 1,
            entry = entry,
            expectedEntryRevision = null,
            streams = listOf(stream(ByteArray(0), objectId)),
        )
        val output = ByteArrayOutputStream()
        adapter.open(saved.refs.single(), rootKey, output)

        assertEquals(2L, saved.identity.sequence)
        assertEquals(2L, saved.entryRevision)
        assertEquals(0L, saved.refs.single().size)
        assertEquals(0, output.size())
        assertEquals(PmvMediaRef.Classification.OBJECT, PmvMediaRef.scan(saved.entry).single().classification)
        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            assertEquals(saved.entry, session.readEntry(UUID.fromString(entry.id)))
            assertEquals(
                listOf(entry.id),
                session.readMetadata().getValue("entry_order").jsonArray.map { it.jsonPrimitive.content },
            )
        }
    }

    @Test
    fun `cross chunk object and authenticated range stream exact bytes`() = withVault { file, rootKey ->
        val entry = legacyEntry("cross-chunk")
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 37) { (it * 29).toByte() }
        val adapter = PmvMediaObjectAdapter(file)
        val saved = adapter.saveEntryWithMedia(
            rootKey,
            1,
            entry,
            null,
            listOf(stream(plain, UUID.nameUUIDFromBytes("cross-object".encodeToByteArray()))),
        )

        val whole = ByteArrayOutputStream()
        adapter.open(saved.refs.single(), rootKey, whole)
        val start = PmvAttachmentCodec.CHUNK_SIZE.toLong() - 5
        val range = ByteArrayOutputStream()
        adapter.openRange(saved.refs.single(), rootKey, start, 19, range)

        assertArrayEquals(plain, whole.toByteArray())
        assertArrayEquals(plain.copyOfRange(start.toInt(), start.toInt() + 19), range.toByteArray())
    }

    @Test
    fun `cancelled import leaves entry object and sequence unpublished`() = withVault { file, rootKey ->
        val entry = legacyEntry("cancel")
        val objectId = UUID.nameUUIDFromBytes("cancel-object".encodeToByteArray())
        val cancelled = object : InputStream() {
            override fun read(): Int = throw CancellationException("cancelled")
        }
        val adapter = PmvMediaObjectAdapter(file)

        assertThrows(CancellationException::class.java) {
            adapter.saveEntryWithMedia(
                rootKey,
                1,
                entry,
                null,
                listOf(PmvMediaRef.LegacyStream(
                    "/fields/images/0",
                    cancelled,
                    1,
                    objectId,
                    1,
                    PmvAttachmentCodec.Kind.IMAGE,
                )),
            )
        }

        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            assertEquals(1L, session.identity().sequence)
            assertEquals(null, session.readEntry(UUID.fromString(entry.id)))
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(objectId, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `stale sequence rejects before consuming media stream`() = withVault { file, rootKey ->
        val entry = legacyEntry("stale")
        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            session.applyMutation(1) {
                PmvVaultStore.MutationContent(session.readMetadata(), emptyList())
            }
        }
        var reads = 0
        val source = object : InputStream() {
            override fun read(): Int {
                reads++
                return -1
            }
        }

        assertThrows(VaultStaleMutationException::class.java) {
            PmvMediaObjectAdapter(file).saveEntryWithMedia(
                rootKey,
                expectedSequence = 1,
                entry = entry,
                expectedEntryRevision = null,
                streams = listOf(PmvMediaRef.LegacyStream(
                    "/fields/images/0",
                    source,
                    0,
                    UUID.nameUUIDFromBytes("stale-object".encodeToByteArray()),
                    1,
                    PmvAttachmentCodec.Kind.IMAGE,
                )),
            )
        }

        assertEquals(0, reads)
        PmvVaultStore.openRootKey(file, rootKey).use { assertEquals(2L, it.identity().sequence) }
    }

    @Test
    fun `existing entry media replacement requires expected revision and preserves order`() = withVault { file, rootKey ->
        val adapter = PmvMediaObjectAdapter(file)
        val firstEntry = legacyEntry("existing")
        val first = adapter.saveEntryWithMedia(
            rootKey,
            1,
            firstEntry,
            null,
            listOf(stream("old".encodeToByteArray(), UUID.nameUUIDFromBytes("old-object".encodeToByteArray()))),
        )
        var reads = 0
        val rejectedSource = object : InputStream() {
            override fun read(): Int {
                reads++
                return -1
            }
        }
        val pending = first.entry.copy(
            updatedAt = 3.0,
            fields = mapOf("images" to JsonArray(listOf(JsonPrimitive("img:new.enc")))),
        )

        assertThrows(VaultStaleMutationException::class.java) {
            adapter.saveEntryWithMedia(
                rootKey,
                2,
                pending,
                expectedEntryRevision = 999,
                streams = listOf(PmvMediaRef.LegacyStream(
                    "/fields/images/0",
                    rejectedSource,
                    0,
                    UUID.nameUUIDFromBytes("rejected-object".encodeToByteArray()),
                    1,
                    PmvAttachmentCodec.Kind.IMAGE,
                )),
            )
        }
        assertEquals(0, reads)

        val replacementBytes = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 3) { (it * 7).toByte() }
        val replacement = adapter.saveEntryWithMedia(
            rootKey,
            2,
            pending,
            expectedEntryRevision = first.entryRevision,
            streams = listOf(stream(
                replacementBytes,
                UUID.nameUUIDFromBytes("replacement-object".encodeToByteArray()),
            )),
        )

        PmvVaultStore.openRootKey(file, rootKey).use { session ->
            val summaries = session.listSummaries()
            assertEquals(listOf(UUID.fromString(firstEntry.id)), summaries.map { it.entryId })
            assertEquals(replacement.entryRevision, summaries.single().revision)
        }
        val output = ByteArrayOutputStream()
        adapter.open(replacement.refs.single(), rootKey, output)
        assertArrayEquals(replacementBytes, output.toByteArray())
    }

    private fun stream(bytes: ByteArray, objectId: UUID) = PmvMediaRef.LegacyStream(
        path = "/fields/images/0",
        input = ByteArrayInputStream(bytes),
        expectedSize = bytes.size.toLong(),
        objectId = objectId,
        generation = 1,
        kind = PmvAttachmentCodec.Kind.IMAGE,
    )

    private fun legacyEntry(seed: String) = Entry(
        id = UUID.nameUUIDFromBytes(seed.encodeToByteArray()).toString(),
        title = seed,
        fields = mapOf("images" to JsonArray(listOf(JsonPrimitive("img:$seed.enc")))),
        createdAt = 1.0,
        updatedAt = 2.0,
    )

    private inline fun withVault(block: (File, ByteArray) -> Unit) {
        val file = File.createTempFile("pmv-media-adapter-", ".pmv").also { it.delete() }
        val payload = VaultPayload(
            syncMeta = SyncMeta(UUID.nameUUIDFromBytes("device".encodeToByteArray()).toString(), 1),
        )
        val rootKey = PmvVaultStore.create(
            file,
            password,
            recovery,
            PmvEPayloadAdapter.toMetadata(payload, UUID(0L, 0L)),
            emptyList(),
        ).use(PmvVaultStore.Session::copyRootKeyForDeviceUnlock)
        try {
            block(file, rootKey)
        } finally {
            rootKey.fill(0)
            file.delete()
            File(file.parentFile, "${file.name}.writer.lock").delete()
        }
    }
}
