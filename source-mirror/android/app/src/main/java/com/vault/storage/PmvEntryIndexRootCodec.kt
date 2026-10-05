package com.vault.storage

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** 固定 16 KiB 的 EntryIndex 叶页根目录明文格式。 */
object PmvEntryIndexRootCodec {
    const val PAGE_SIZE = 16 * 1024

    private const val VERSION = 1
    private const val HEADER_SIZE = 32
    private const val RECORD_SIZE = 72
    private const val MAX_RECORDS = (PAGE_SIZE - HEADER_SIZE) / RECORD_SIZE
    private val MAGIC = "PMER".encodeToByteArray()
    private val DATA_START = PmvContainerFormat.DATA_START

    data class Record(
        val minEntryId: UUID,
        val maxEntryId: UUID,
        val pageOffset: Long,
        val pageDigest: ByteArray = ByteArray(32),
    ) {
        init {
            require(compareIds(minEntryId, maxEntryId) <= 0) { "EntryIndex 根目录范围无效" }
            require(pageOffset >= DATA_START) { "EntryIndex 叶页偏移无效" }
            require(pageDigest.size == 32) { "EntryIndex 叶页摘要必须为 SHA-256" }
        }

        override fun equals(other: Any?): Boolean = other is Record &&
            minEntryId == other.minEntryId && maxEntryId == other.maxEntryId &&
            pageOffset == other.pageOffset && pageDigest.contentEquals(other.pageDigest)

        override fun hashCode(): Int {
            var result = minEntryId.hashCode()
            result = 31 * result + maxEntryId.hashCode()
            result = 31 * result + pageOffset.hashCode()
            return 31 * result + pageDigest.contentHashCode()
        }
    }

    data class Root(val records: List<Record>) {
        init {
            require(records.size <= MAX_RECORDS) { "EntryIndex 根目录记录数超过上限" }
            require(records.map(Record::pageOffset).toSet().size == records.size) {
                "EntryIndex 根目录叶页偏移不能重复"
            }
            require(records.zipWithNext().all { (left, right) ->
                compareIds(left.maxEntryId, right.minEntryId) < 0
            }) {
                "EntryIndex 根目录范围必须严格递增且不能重叠"
            }
        }

        fun findPage(entryId: UUID): Record? {
            var low = 0
            var high = records.lastIndex
            while (low <= high) {
                val middle = (low + high).ushr(1)
                val candidate = records[middle]
                when {
                    compareIds(entryId, candidate.minEntryId) < 0 -> high = middle - 1
                    compareIds(entryId, candidate.maxEntryId) > 0 -> low = middle + 1
                    else -> return candidate
                }
            }
            return null
        }
    }

    fun encode(root: Root): ByteArray =
        ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(VERSION)
            putInt(PAGE_SIZE)
            putInt(root.records.size)
            putLong(0)
            putLong(0)
            root.records.forEach { record ->
                putUuid(record.minEntryId)
                putUuid(record.maxEntryId)
                putLong(record.pageOffset)
                put(record.pageDigest)
            }
        }.array()

    fun decode(raw: ByteArray): Root {
        require(raw.size == PAGE_SIZE) { "EntryIndex 根目录页大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size).also(input::get)
        require(magic.contentEquals(MAGIC)) { "EntryIndex 根目录 magic 无效" }
        require(input.int == VERSION) { "EntryIndex 根目录版本无效" }
        require(input.int == PAGE_SIZE) { "EntryIndex 根目录声明页大小无效" }
        val count = input.int
        require(count in 0..MAX_RECORDS) { "EntryIndex 根目录记录数无效" }
        require(input.long == 0L && input.long == 0L) { "EntryIndex 根目录 Header 保留字段非零" }

        val records = ArrayList<Record>(count)
        repeat(count) {
            require(input.remaining() >= RECORD_SIZE) { "EntryIndex 根目录记录被截断" }
            records += Record(
                minEntryId = input.getUuid(),
                maxEntryId = input.getUuid(),
                pageOffset = input.long,
                pageDigest = ByteArray(32).also(input::get),
            )
        }
        while (input.hasRemaining()) {
            require(input.get() == 0.toByte()) { "EntryIndex 根目录页尾保留字段非零" }
        }
        return Root(records)
    }

    private fun compareIds(left: UUID, right: UUID): Int = left.toString().compareTo(right.toString())

    private fun ByteBuffer.putUuid(value: UUID) {
        putLong(value.mostSignificantBits)
        putLong(value.leastSignificantBits)
    }

    private fun ByteBuffer.getUuid(): UUID = UUID(long, long)
}
