package com.vault.storage

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.util.UUID

/** 固定大小、可独立加密的分页 EntryIndex 明文格式。 */
object PmvEntryIndexCodec {
    const val PAGE_SIZE = 16 * 1024
    private const val VERSION = 1
    private const val HEADER_SIZE = 32
    private const val RECORD_FIXED_SIZE = 108
    private const val MAX_TYPE_BYTES = 64
    private const val MAX_TITLE_BYTES = 1024
    private val MAGIC = "PMEI".encodeToByteArray()

    enum class State(val id: Int) {
        ACTIVE(1),
        TOMBSTONE(2),
        ;

        companion object {
            fun fromId(id: Int): State = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("未知 EntryIndex 状态")
        }
    }

    data class Record(
        val entryId: UUID,
        val entryType: String,
        val revision: Long,
        val offset: Long,
        val length: Long,
        val state: State,
        val displayTitle: String = "",
        val favorite: Boolean = false,
        val iconObjectId: UUID? = null,
        val modifiedAtEpochMillis: Long = 0,
        val contentDigest: ByteArray = ByteArray(32),
    ) {
        init {
            val typeBytes = entryType.encodeToByteArray()
            val titleBytes = displayTitle.encodeToByteArray()
            require(typeBytes.isNotEmpty() && typeBytes.size <= MAX_TYPE_BYTES) { "Entry 类型长度无效" }
            require(titleBytes.size <= MAX_TITLE_BYTES) { "Entry 列表标题长度无效" }
            require(revision >= 0) { "Entry 修订号不能为负数" }
            require(modifiedAtEpochMillis >= 0) { "Entry 修改时间不能为负数" }
            require(offset >= DATA_START) { "Entry Block 偏移无效" }
            require(length in MIN_BLOCK_LENGTH..MAX_BLOCK_LENGTH) { "Entry Block 长度无效" }
            require(contentDigest.size == 32) { "Entry 内容摘要必须为 SHA-256" }
        }

        override fun equals(other: Any?): Boolean = other is Record &&
            entryId == other.entryId && entryType == other.entryType && revision == other.revision &&
            offset == other.offset && length == other.length && state == other.state &&
            displayTitle == other.displayTitle && favorite == other.favorite &&
            iconObjectId == other.iconObjectId && modifiedAtEpochMillis == other.modifiedAtEpochMillis &&
            contentDigest.contentEquals(other.contentDigest)

        override fun hashCode(): Int {
            var result = entryId.hashCode()
            result = 31 * result + entryType.hashCode()
            result = 31 * result + revision.hashCode()
            result = 31 * result + offset.hashCode()
            result = 31 * result + length.hashCode()
            result = 31 * result + state.hashCode()
            result = 31 * result + displayTitle.hashCode()
            result = 31 * result + favorite.hashCode()
            result = 31 * result + (iconObjectId?.hashCode() ?: 0)
            result = 31 * result + modifiedAtEpochMillis.hashCode()
            return 31 * result + contentDigest.contentHashCode()
        }
    }

    data class Page(
        val records: List<Record>,
        val nextPageOffset: Long,
    ) {
        init {
            require(records.size <= MAX_RECORDS_PER_PAGE) { "EntryIndex 页记录数超过上限" }
            require(nextPageOffset == 0L || nextPageOffset >= DATA_START) { "下一索引页偏移无效" }
            require(records.zipWithNext().all { (left, right) -> compareIds(left.entryId, right.entryId) < 0 }) {
                "EntryIndex 记录必须按 UUID 严格排序且不能重复"
            }
        }

        fun find(entryId: UUID): Record? {
            var low = 0
            var high = records.lastIndex
            while (low <= high) {
                val middle = (low + high).ushr(1)
                val comparison = compareIds(records[middle].entryId, entryId)
                when {
                    comparison < 0 -> low = middle + 1
                    comparison > 0 -> high = middle - 1
                    else -> return records[middle]
                }
            }
            return null
        }
    }

    fun encode(page: Page): ByteArray {
        var requiredSize = HEADER_SIZE
        page.records.forEach { record ->
            requiredSize = Math.addExact(
                requiredSize,
                RECORD_FIXED_SIZE + record.entryType.encodeToByteArray().size + record.displayTitle.encodeToByteArray().size,
            )
            require(requiredSize <= PAGE_SIZE) { "EntryIndex 页容量不足" }
        }
        return ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(VERSION)
            putInt(PAGE_SIZE)
            putInt(page.records.size)
            putLong(page.nextPageOffset)
            putLong(0)
            page.records.forEach { record ->
                val typeBytes = record.entryType.encodeToByteArray()
                val titleBytes = record.displayTitle.encodeToByteArray()
                putUuid(record.entryId)
                putShort(typeBytes.size.toShort())
                put(typeBytes)
                putShort(titleBytes.size.toShort())
                put(titleBytes)
                putLong(record.revision)
                putLong(record.offset)
                putLong(record.length)
                put(record.state.id.toByte())
                put(if (record.favorite) 1 else 0)
                put(if (record.iconObjectId != null) 1 else 0)
                put(ByteArray(5))
                putUuid(record.iconObjectId ?: ZERO_UUID)
                putLong(record.modifiedAtEpochMillis)
                put(record.contentDigest)
            }
        }.array()
    }

    fun decode(raw: ByteArray): Page {
        require(raw.size == PAGE_SIZE) { "EntryIndex 页大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size).also(input::get)
        require(magic.contentEquals(MAGIC)) { "EntryIndex magic 无效" }
        require(input.int == VERSION) { "EntryIndex 版本无效" }
        require(input.int == PAGE_SIZE) { "EntryIndex 声明页大小无效" }
        val count = input.int
        require(count in 0..((PAGE_SIZE - HEADER_SIZE) / RECORD_FIXED_SIZE)) { "EntryIndex 记录数无效" }
        val nextPageOffset = input.long
        require(input.long == 0L) { "EntryIndex Header 保留字段非零" }
        val records = ArrayList<Record>(count)
        repeat(count) {
            require(input.remaining() >= 18) { "EntryIndex 记录被截断" }
            val entryId = input.getUuid()
            val typeLength = input.short.toInt() and 0xffff
            require(typeLength in 1..MAX_TYPE_BYTES) { "Entry 类型长度无效" }
            require(input.remaining() >= typeLength + 2) { "EntryIndex 记录被截断" }
            val typeBytes = ByteArray(typeLength).also(input::get)
            val entryType = decodeUtf8(typeBytes)
            val titleLength = input.short.toInt() and 0xffff
            require(titleLength in 0..MAX_TITLE_BYTES) { "Entry 列表标题长度无效" }
            require(input.remaining() >= titleLength + RECORD_FIXED_SIZE - 20) { "EntryIndex 记录被截断" }
            val displayTitle = decodeUtf8(ByteArray(titleLength).also(input::get))
            val revision = input.long
            val offset = input.long
            val length = input.long
            val state = State.fromId(input.get().toInt() and 0xff)
            val favorite = decodeBoolean(input.get(), "favorite")
            val hasIcon = decodeBoolean(input.get(), "icon flag")
            repeat(5) { require(input.get() == 0.toByte()) { "EntryIndex Record 保留字段非零" } }
            val encodedIcon = input.getUuid()
            require(hasIcon || encodedIcon == ZERO_UUID) { "无图标记录包含非零 icon_object_id" }
            val modifiedAtEpochMillis = input.long
            val contentDigest = ByteArray(32).also(input::get)
            records += Record(
                entryId = entryId,
                entryType = entryType,
                revision = revision,
                offset = offset,
                length = length,
                state = state,
                displayTitle = displayTitle,
                favorite = favorite,
                iconObjectId = encodedIcon.takeIf { hasIcon },
                modifiedAtEpochMillis = modifiedAtEpochMillis,
                contentDigest = contentDigest,
            )
        }
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "EntryIndex 页尾保留字段非零" }
        return Page(records, nextPageOffset)
    }

    private fun compareIds(left: UUID, right: UUID): Int = left.toString().compareTo(right.toString())

    private fun decodeUtf8(value: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(value))
        .toString()

    private fun decodeBoolean(value: Byte, label: String): Boolean = when (value.toInt()) {
        0 -> false
        1 -> true
        else -> throw IllegalArgumentException("EntryIndex $label 无效")
    }

    private fun ByteBuffer.putUuid(value: UUID) {
        putLong(value.mostSignificantBits)
        putLong(value.leastSignificantBits)
    }

    private fun ByteBuffer.getUuid(): UUID = UUID(long, long)

    private val DATA_START = PmvContainerFormat.DATA_START
    private val ZERO_UUID = UUID(0, 0)
    private const val MAX_RECORDS_PER_PAGE = (PAGE_SIZE - HEADER_SIZE) / RECORD_FIXED_SIZE
    private val MIN_BLOCK_LENGTH =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + PmvContainerFormat.GCM_TAG_SIZE
    private val MAX_BLOCK_LENGTH =
        PmvContainerFormat.BLOCK_HEADER_SIZE.toLong() + PmvContainerFormat.MAX_BLOCK_CIPHER_SIZE
}
