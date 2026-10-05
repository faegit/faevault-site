package com.vault.storage

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/** Canonical plaintext carried by an authenticated TOMBSTONE block. */
object PmvTombstoneCodec {
    const val SIZE = 128
    const val FLAG_PURGED = 1
    private const val VERSION = 1
    private val MAGIC = "PMVT".encodeToByteArray()

    data class Tombstone(
        val entryId: UUID,
        val revision: Long,
        val purgedAtEpochMillis: Long,
        val previousContentDigest: ByteArray,
        val flags: Int = FLAG_PURGED,
    ) {
        init {
            require(revision >= 0) { "Tombstone revision 不能为负数" }
            require(purgedAtEpochMillis >= 0) { "Tombstone 清除时间不能为负数" }
            require(previousContentDigest.size == 32) { "Tombstone 前序摘要必须为 SHA-256" }
            require(flags == FLAG_PURGED) { "Tombstone flags 无效" }
        }

        override fun equals(other: Any?): Boolean = other is Tombstone &&
            entryId == other.entryId && revision == other.revision &&
            purgedAtEpochMillis == other.purgedAtEpochMillis && flags == other.flags &&
            previousContentDigest.contentEquals(other.previousContentDigest)

        override fun hashCode(): Int = (((entryId.hashCode() * 31 + revision.hashCode()) * 31 +
            purgedAtEpochMillis.hashCode()) * 31 + previousContentDigest.contentHashCode()) * 31 + flags
    }

    fun encode(value: Tombstone): ByteArray = ByteBuffer.allocate(SIZE).order(ByteOrder.BIG_ENDIAN).apply {
        put(MAGIC)
        putInt(VERSION)
        putInt(SIZE)
        putLong(value.entryId.mostSignificantBits)
        putLong(value.entryId.leastSignificantBits)
        putLong(value.revision)
        putLong(value.purgedAtEpochMillis)
        put(value.previousContentDigest)
        putInt(value.flags)
        put(ByteArray(48))
    }.array()

    fun decode(raw: ByteArray): Tombstone {
        require(raw.size == SIZE) { "Tombstone 大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals(MAGIC)) { "Tombstone magic 无效" }
        require(input.int == VERSION) { "Tombstone 版本无效" }
        require(input.int == SIZE) { "Tombstone 声明大小无效" }
        val value = Tombstone(
            entryId = UUID(input.long, input.long),
            revision = input.long,
            purgedAtEpochMillis = input.long,
            previousContentDigest = ByteArray(32).also(input::get),
            flags = input.int,
        )
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "Tombstone 保留字段非零" }
        return value
    }
}
