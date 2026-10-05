package com.vault.storage

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Fixed 16 KiB composite root. Its logical digest deliberately excludes physical offsets. */
object PmvVaultRootCodec {
    const val PAGE_SIZE = 16 * 1024
    private const val VERSION = 1
    private const val HEADER_SIZE = 32
    private const val RECORD_SIZE = 64
    private val MAGIC = "PMVR".encodeToByteArray()
    private val DIGEST_DOMAIN = "pmv/v1/vault-root\u0000".encodeToByteArray()
    private val DATA_START = PmvContainerFormat.DATA_START

    enum class RootType(val id: Int) {
        ENTRY(1), LOGIN(2), OBJECT(3), CHUNK(4), METADATA(5);
        companion object { fun fromId(id: Int) = entries.firstOrNull { it.id == id }
            ?: throw IllegalArgumentException("未知 VaultRoot 子根类型") }
    }

    data class Reference(val type: RootType, val offset: Long, val length: Long, val digest: ByteArray) {
        init {
            require(offset >= DATA_START) { "VaultRoot 子根偏移无效" }
            require(length > 0) { "VaultRoot 子根长度无效" }
            require(digest.size == 32) { "VaultRoot 子根摘要必须为 SHA-256" }
        }
        override fun equals(other: Any?) = other is Reference && type == other.type && offset == other.offset &&
            length == other.length && digest.contentEquals(other.digest)
        override fun hashCode() = (((type.hashCode() * 31 + offset.hashCode()) * 31 + length.hashCode()) * 31) + digest.contentHashCode()
    }

    data class Root(
        val entry: Reference,
        val login: Reference? = null,
        val objectIndex: Reference? = null,
        val chunkIndex: Reference? = null,
        val metadata: Reference? = null,
    ) {
        init {
            require(entry.type == RootType.ENTRY) { "entry 子根类型不匹配" }
            listOf(login to RootType.LOGIN, objectIndex to RootType.OBJECT, chunkIndex to RootType.CHUNK,
                metadata to RootType.METADATA).forEach { (ref, type) ->
                require(ref == null || ref.type == type) { "VaultRoot 子根类型不匹配" }
            }
        }
        fun references(): List<Reference?> = listOf(entry, login, objectIndex, chunkIndex, metadata)
    }

    fun encode(root: Root): ByteArray = ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
        put(MAGIC); putInt(VERSION); putInt(PAGE_SIZE); putInt(5); putLong(0); putLong(0)
        root.references().forEachIndexed { index, reference ->
            val expected = RootType.entries[index]
            put(if (reference != null) 1 else 0); put(expected.id.toByte()); repeat(6) { put(0) }
            putLong(reference?.offset ?: 0); putLong(reference?.length ?: 0)
            put(reference?.digest ?: ByteArray(32)); putLong(0)
        }
    }.array()

    fun decode(raw: ByteArray): Root {
        require(raw.size == PAGE_SIZE) { "VaultRoot 页大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals(MAGIC)) { "VaultRoot magic 无效" }
        require(input.int == VERSION && input.int == PAGE_SIZE && input.int == 5) { "VaultRoot Header 无效" }
        require(input.long == 0L && input.long == 0L) { "VaultRoot Header 保留字段非零" }
        val refs = RootType.entries.map { expected ->
            val present = input.get().toInt() and 0xff
            require(present in 0..1) { "VaultRoot present 标志无效" }
            require(RootType.fromId(input.get().toInt() and 0xff) == expected) { "VaultRoot 子根顺序无效" }
            repeat(6) { require(input.get() == 0.toByte()) { "VaultRoot 子根保留字段非零" } }
            val offset = input.long; val length = input.long; val digest = ByteArray(32).also(input::get)
            require(input.long == 0L) { "VaultRoot 子根保留字段非零" }
            if (present == 0) {
                require(offset == 0L && length == 0L && digest.all { it == 0.toByte() }) { "缺失子根必须规范化为零" }
                null
            } else Reference(expected, offset, length, digest)
        }
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "VaultRoot 页尾保留字段非零" }
        requireNotNull(refs[0]) { "VaultRoot 必须包含 Entry 根" }
        return Root(refs[0]!!, refs[1], refs[2], refs[3], refs[4])
    }

    fun logicalDigest(root: Root): ByteArray {
        val canonical = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { out ->
                out.write(DIGEST_DOMAIN)
                root.references().forEachIndexed { index, reference ->
                    out.writeByte(index + 1); out.writeByte(if (reference != null) 1 else 0)
                    out.writeLong(reference?.length ?: 0); out.write(reference?.digest ?: ByteArray(32))
                }
            }; buffer.toByteArray()
        }
        return try { MessageDigest.getInstance("SHA-256").digest(canonical) } finally { canonical.fill(0) }
    }
}
