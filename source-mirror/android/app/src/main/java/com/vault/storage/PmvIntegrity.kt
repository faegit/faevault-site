package com.vault.storage

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.UUID

/** Canonical SHA-256 digests for the logical Entry index tree. Physical offsets are excluded. */
object PmvIntegrity {
    private val RECORD_DOMAIN = "pmv/v1/entry-index-record\u0000".encodeToByteArray()
    private val PAGE_DOMAIN = "pmv/v1/entry-index-page\u0000".encodeToByteArray()
    private val ROOT_DOMAIN = "pmv/v1/entry-index-root\u0000".encodeToByteArray()

    fun encryptedBlockDigest(block: PmvContainerFormat.EncodedBlock): ByteArray =
        sha256(PmvContainerFormat.encodeBlockHeader(block.header), block.ciphertext)

    fun entryRecordDigest(record: PmvEntryIndexCodec.Record): ByteArray {
        val type = record.entryType.encodeToByteArray()
        val title = record.displayTitle.encodeToByteArray()
        return canonicalDigest(RECORD_DOMAIN) {
            writeUuid(record.entryId)
            writeUnsignedShort(type.size)
            write(type)
            writeLong(record.revision)
            writeByte(record.state.id)
            writeUnsignedShort(title.size)
            write(title)
            writeByte(if (record.favorite) 1 else 0)
            writeByte(if (record.iconObjectId != null) 1 else 0)
            writeUuid(record.iconObjectId ?: ZERO_UUID)
            writeLong(record.modifiedAtEpochMillis)
            write(record.contentDigest)
        }
    }

    fun entryPageDigest(page: PmvEntryIndexCodec.Page): ByteArray = canonicalDigest(PAGE_DOMAIN) {
        writeInt(page.records.size)
        page.records.forEach { write(entryRecordDigest(it)) }
    }

    fun entryRootDigest(root: PmvEntryIndexRootCodec.Root): ByteArray = canonicalDigest(ROOT_DOMAIN) {
        writeInt(root.records.size)
        root.records.forEach { record ->
            writeUuid(record.minEntryId)
            writeUuid(record.maxEntryId)
            write(record.pageDigest)
        }
    }

    private inline fun canonicalDigest(domain: ByteArray, block: DataOutputStream.() -> Unit): ByteArray {
        val bytes = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { output ->
                output.write(domain)
                output.block()
            }
            buffer.toByteArray()
        }
        return try {
            sha256(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun DataOutputStream.writeUnsignedShort(value: Int) {
        require(value in 0..0xffff) { "canonical field exceeds u16" }
        writeShort(value)
    }

    private fun DataOutputStream.writeUuid(value: UUID) {
        writeLong(value.mostSignificantBits)
        writeLong(value.leastSignificantBits)
    }

    private fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
        parts.forEach(::update)
        digest()
    }

    private val ZERO_UUID = UUID(0, 0)
}
