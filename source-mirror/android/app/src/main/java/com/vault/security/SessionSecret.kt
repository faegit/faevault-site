package com.vault.security

import java.security.SecureRandom

/** Avoids retaining the master password as a plain String for an unlocked session. */
class SessionSecret private constructor(value: ByteArray) : AutoCloseable {
    private var closed = false
    private var key = ByteArray(value.size).also(SecureRandom()::nextBytes)
    private var data = value.copyOf().also { raw ->
        for (index in raw.indices) raw[index] = (raw[index].toInt() xor key[index].toInt()).toByte()
    }

    fun <T> useBytes(block: (ByteArray) -> T): T {
        val raw = copyBytes()
        return try { block(raw) } finally { raw.fill(0) }
    }

    suspend fun <T> useBytesSuspend(block: suspend (ByteArray) -> T): T {
        val raw = copyBytes()
        return try { block(raw) } finally { raw.fill(0) }
    }

    fun matches(candidate: ByteArray): Boolean = useBytes { expected ->
        var difference = expected.size xor candidate.size
        for (index in 0 until maxOf(expected.size, candidate.size)) {
            difference = difference or (
                expected.getOrElse(index) { 0 }.toInt() xor candidate.getOrElse(index) { 0 }.toInt()
            )
        }
        difference == 0
    }

    @Synchronized
    override fun close() {
        data.fill(0)
        key.fill(0)
        data = ByteArray(0)
        key = ByteArray(0)
        closed = true
    }

    private fun copyBytes(): ByteArray = synchronized(this) {
        check(!closed) { "会话凭据已清除" }
        ByteArray(data.size) { index -> (data[index].toInt() xor key[index].toInt()).toByte() }
    }

    companion object {
        fun fromUtf8(value: ByteArray): SessionSecret = SessionSecret(value)
    }
}

/** 与 [SessionSecret] 相同的内存遮蔽，用于生物识别解锁后的 PMVE RootKey。 */
class SessionBytes(value: ByteArray) : AutoCloseable {
    private var closed = false
    private var mask = ByteArray(value.size).also(SecureRandom()::nextBytes)
    private var data = value.copyOf().also { raw ->
        for (index in raw.indices) raw[index] = (raw[index].toInt() xor mask[index].toInt()).toByte()
    }

    @Synchronized
    fun reveal(): ByteArray {
        check(!closed) { "会话密钥已清除" }
        return ByteArray(data.size) { index -> (data[index].toInt() xor mask[index].toInt()).toByte() }
    }

    @Synchronized
    override fun close() {
        data.fill(0)
        mask.fill(0)
        data = ByteArray(0)
        mask = ByteArray(0)
        closed = true
    }
}
