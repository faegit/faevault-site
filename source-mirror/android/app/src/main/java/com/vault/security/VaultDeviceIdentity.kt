package com.vault.security

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.UUID

/**
 * 每库独立的设备身份：device_id + Ed25519 私钥种子。
 *
 * 该对象只持有明文种子的最短生命周期；Android 上持久化时必须由 Android Keystore
 * 包裹（见 [VaultDeviceIdentityStore]），纯 JVM 编解码用于跨端一致性与测试。
 */
class VaultDeviceIdentity private constructor(
    val deviceId: UUID,
    private val privateSeed: ByteArray,
) : AutoCloseable {
    val publicKey: ByteArray = derivePublicKey(privateSeed)
    var isCleared: Boolean = false
        private set

    fun <T> withPrivateSeed(block: (ByteArray) -> T): T {
        check(!isCleared) { "设备身份已清除" }
        val copy = privateSeed.copyOf()
        return try {
            block(copy)
        } finally {
            copy.fill(0)
        }
    }

    override fun close() {
        if (isCleared) return
        privateSeed.fill(0)
        isCleared = true
    }

    companion object {
        const val SEED_SIZE = 32
        private const val MAGIC = "PMDI"
        private const val VERSION = 1
        private const val HEADER_SIZE = 4 + 4 + 4
        private const val RESERVED = 32
        val ENCODED_SIZE: Int = HEADER_SIZE + 16 + 32 + SEED_SIZE + RESERVED

        fun generate(random: SecureRandom = SecureRandom()): VaultDeviceIdentity {
            val seed = ByteArray(SEED_SIZE).also(random::nextBytes)
            return VaultDeviceIdentity(UUID(random.nextLong(), random.nextLong()), seed)
        }

        fun fromSeed(deviceId: UUID, privateSeed: ByteArray): VaultDeviceIdentity {
            require(privateSeed.size == SEED_SIZE) { "设备私钥种子必须为 32 字节" }
            return VaultDeviceIdentity(deviceId, privateSeed.copyOf())
        }

        fun encode(value: VaultDeviceIdentity): ByteArray {
            val seed = value.copySeedForEncoding()
            return try {
                ByteBuffer.allocate(ENCODED_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
                    put(MAGIC.encodeToByteArray())
                    putInt(VERSION)
                    putInt(ENCODED_SIZE)
                    putLong(value.deviceId.mostSignificantBits)
                    putLong(value.deviceId.leastSignificantBits)
                    put(value.publicKey)
                    put(seed)
                    put(ByteArray(RESERVED))
                }.array()
            } finally {
                seed.fill(0)
            }
        }

        fun decode(raw: ByteArray): VaultDeviceIdentity {
            require(raw.size == ENCODED_SIZE) { "设备身份编码长度无效" }
            val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
            require(ByteArray(4).also(input::get).contentEquals(MAGIC.encodeToByteArray())) {
                "设备身份 magic 无效"
            }
            require(input.int == VERSION && input.int == ENCODED_SIZE) { "设备身份版本无效" }
            val deviceId = UUID(input.long, input.long)
            val publicKey = ByteArray(32).also(input::get)
            val seed = ByteArray(SEED_SIZE).also(input::get)
            try {
                repeat(RESERVED) { require(input.get() == 0.toByte()) { "设备身份保留字段非零" } }
                // 构造函数直接持有传入数组：必须拷贝后再交给身份对象，
                // 否则 finally 中清空 seed 会把身份对象的私钥一并清零。
                val identity = VaultDeviceIdentity(deviceId, seed.copyOf())
                if (!identity.publicKey.contentEquals(publicKey)) {
                    identity.close()
                    throw IllegalArgumentException("设备公钥与种子不匹配")
                }
                return identity
            } finally {
                publicKey.fill(0)
                seed.fill(0)
            }
        }

        private fun derivePublicKey(seed: ByteArray): ByteArray =
            Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    private fun copySeedForEncoding(): ByteArray {
        check(!isCleared) { "设备身份已清除" }
        return privateSeed.copyOf()
    }
}
