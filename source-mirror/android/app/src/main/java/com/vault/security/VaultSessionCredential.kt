package com.vault.security

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/**
 * In-memory credential for an unlocked vault session。
 * PMVE 统一使用 RootKey 会话，密钥副本使用后即清零。
 */
sealed class VaultSessionCredential : AutoCloseable {
    abstract val isCleared: Boolean

    class Password(value: ByteArray) : VaultSessionCredential() {
        private val value = SessionSecret.fromUtf8(value)
        override var isCleared: Boolean = false
            private set

        fun <T> useBytes(block: (ByteArray) -> T): T = value.useBytes(block)
        suspend fun <T> useBytesSuspend(block: suspend (ByteArray) -> T): T = value.useBytesSuspend(block)
        fun matches(candidate: ByteArray): Boolean = value.matches(candidate)

        override fun close() {
            value.close()
            isCleared = true
        }
    }

    class RootKey(value: ByteArray, val identity: VaultKeyIdentity) : VaultSessionCredential() {
        private val value = SessionBytes(value)
        override var isCleared: Boolean = false
            private set

        fun <T> withRootKey(expectedIdentity: VaultKeyIdentity, block: (ByteArray) -> T): T {
            check(!isCleared) { "会话密钥已清除" }
            if (!identity.matches(expectedIdentity)) throw SecurityException("设备解锁身份与当前保险库不匹配")
            val copy = value.reveal()
            return try { block(copy) } finally { copy.fill(0) }
        }

        fun copyRootKey(expectedIdentity: VaultKeyIdentity): ByteArray {
            check(!isCleared) { "会话密钥已清除" }
            if (!identity.matches(expectedIdentity)) throw SecurityException("设备解锁身份与当前保险库不匹配")
            return value.reveal()
        }

        override fun close() {
            value.close()
            isCleared = true
        }
    }

    /** Password unlock may retain both the password and the PMVE RootKey session. */
    class Compound(
        val password: Password,
        val key: VaultSessionCredential,
    ) : VaultSessionCredential() {
        init {
            require(key is RootKey) { "复合会话的密钥类型无效" }
        }

        override val isCleared: Boolean get() = password.isCleared && key.isCleared

        override fun close() {
            password.close()
            key.close()
        }
    }
}

/** Immutable PMVE identity bound into the device-unlock envelope. */
class VaultKeyIdentity(
    val vaultId: UUID,
    val keyRevision: Long,
    signingPublicKey: ByteArray,
) {
    private val signingPublicKey = signingPublicKey.copyOf()

    init {
        require(keyRevision >= 0) { "keyRevision must be non-negative" }
        require(signingPublicKey.size == SIGNING_PUBLIC_KEY_SIZE) { "signingPublicKey must be 32 bytes" }
    }

    fun copySigningPublicKey(): ByteArray = signingPublicKey.copyOf()

    fun matches(other: VaultKeyIdentity): Boolean =
        vaultId == other.vaultId &&
            keyRevision == other.keyRevision &&
            MessageDigest.isEqual(signingPublicKey, other.signingPublicKey)

    override fun equals(other: Any?): Boolean = other is VaultKeyIdentity && matches(other)

    override fun hashCode(): Int {
        var result = vaultId.hashCode()
        result = 31 * result + keyRevision.hashCode()
        return 31 * result + signingPublicKey.contentHashCode()
    }

    companion object {
        const val SIGNING_PUBLIC_KEY_SIZE = 32
    }
}

enum class DeviceUnlockKeyKind(internal val id: Byte) {
    PMVE_ROOT_KEY(2);

    companion object {
        internal fun fromId(id: Byte): DeviceUnlockKeyKind = entries.firstOrNull { it.id == id }
            ?: throw IllegalArgumentException("未知的设备解锁密钥类型")
    }
}

/** Decrypted device-unlock material. Owns and clears its secret bytes. */
class DeviceUnlockMaterial private constructor(
    val kind: DeviceUnlockKeyKind,
    val binding: VaultKeyIdentity?,
    secret: ByteArray,
) : AutoCloseable {
    private val secret = SessionBytes(secret)
    var isCleared: Boolean = false
        private set

    init {
        require(secret.size == KEY_SIZE) { "设备解锁密钥必须为 32 字节" }
        require(kind != DeviceUnlockKeyKind.PMVE_ROOT_KEY || binding != null) {
            "PMVE RootKey 必须绑定保险库身份"
        }
    }

    fun <T> withSecret(expectedBinding: VaultKeyIdentity? = null, block: (ByteArray) -> T): T {
        check(!isCleared) { "设备解锁密钥已清除" }
        if (kind == DeviceUnlockKeyKind.PMVE_ROOT_KEY) {
            val expected = expectedBinding ?: throw SecurityException("PMVE RootKey 缺少预期保险库身份")
            if (binding?.matches(expected) != true) throw SecurityException("设备解锁身份与当前保险库不匹配")
        }
        val copy = secret.reveal()
        return try { block(copy) } finally { copy.fill(0) }
    }

    suspend fun <T> withSecretSuspend(
        expectedBinding: VaultKeyIdentity? = null,
        block: suspend (ByteArray) -> T,
    ): T {
        check(!isCleared) { "设备解锁密钥已清除" }
        if (kind == DeviceUnlockKeyKind.PMVE_ROOT_KEY) {
            val expected = expectedBinding ?: throw SecurityException("PMVE RootKey 缺少预期保险库身份")
            if (binding?.matches(expected) != true) throw SecurityException("设备解锁身份与当前保险库不匹配")
        }
        val copy = secret.reveal()
        return try { block(copy) } finally { copy.fill(0) }
    }

    internal fun copySecretForEncoding(): ByteArray {
        check(!isCleared) { "设备解锁密钥已清除" }
        return secret.reveal()
    }

    /** Compatibility with existing UI cleanup sites. */
    fun fill(@Suppress("UNUSED_PARAMETER") value: Byte) = close()

    override fun close() {
        if (isCleared) return
        secret.close()
        isCleared = true
    }

    companion object {
        const val KEY_SIZE = 32

        fun pmveRootKey(rootKey: ByteArray, identity: VaultKeyIdentity): DeviceUnlockMaterial =
            DeviceUnlockMaterial(DeviceUnlockKeyKind.PMVE_ROOT_KEY, identity, rootKey)
    }
}

/** Pure JVM codec for the plaintext protected by Android Keystore AES-GCM. */
object DeviceUnlockEnvelopeCodec {
    private val MAGIC = byteArrayOf('D'.code.toByte(), 'U'.code.toByte(), 'E'.code.toByte(), 1)
    private const val PMVE_SIZE = 4 + 1 + 16 + 8 + VaultKeyIdentity.SIGNING_PUBLIC_KEY_SIZE + DeviceUnlockMaterial.KEY_SIZE

    fun encode(material: DeviceUnlockMaterial): ByteArray {
        val secret = material.copySecretForEncoding()
        return try {
            val binding = requireNotNull(material.binding) { "PMVE RootKey 必须绑定保险库身份" }
            ByteBuffer.allocate(PMVE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
                put(MAGIC)
                put(material.kind.id)
                putLong(binding.vaultId.mostSignificantBits)
                putLong(binding.vaultId.leastSignificantBits)
                putLong(binding.keyRevision)
                val publicKey = binding.copySigningPublicKey()
                try { put(publicKey) } finally { publicKey.fill(0) }
                put(secret)
            }.array()
        } finally {
            secret.fill(0)
        }
    }

    fun decode(encoded: ByteArray): DeviceUnlockMaterial {
        require(encoded.size == PMVE_SIZE) { "设备解锁信封长度无效" }
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size).also { input.get(it) }
        require(magic.contentEquals(MAGIC)) { "设备解锁信封版本无效" }
        val kind = DeviceUnlockKeyKind.fromId(input.get())
        require(kind == DeviceUnlockKeyKind.PMVE_ROOT_KEY) { "仅支持 PMVE RootKey 设备解锁信封" }
        val vaultId = UUID(input.long, input.long)
        val keyRevision = input.long
        val publicKey = ByteArray(VaultKeyIdentity.SIGNING_PUBLIC_KEY_SIZE).also { input.get(it) }
        val binding = try { VaultKeyIdentity(vaultId, keyRevision, publicKey) } finally { publicKey.fill(0) }
        val secret = ByteArray(DeviceUnlockMaterial.KEY_SIZE).also { input.get(it) }
        return try { DeviceUnlockMaterial.pmveRootKey(secret, binding) } finally { secret.fill(0) }
    }
}
