package com.vault.passkeys

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.vault.security.SecurePreferences
import com.vault.ui.localizeUiTextFor
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class GeneratedDevicePasskey(
    val binding: PasskeyDeviceBinding,
    val publicKeyCose: ByteArray,
)

/** Android Keystore-backed, non-exportable Passkey signing keys. */
@RequiresApi(Build.VERSION_CODES.R)
class AndroidPasskeyKeyStore(context: Context, private val deviceId: UUID) : PasskeyLocalCounterStore {
    private val appContext = context.applicationContext
    private val prefs = SecurePreferences.get(appContext, PREFS)

    fun generate(algorithm: Int): GeneratedDevicePasskey {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        require(algorithm == ES256 || algorithm == RS256) {
            localizeUiTextFor(appContext, "本设备高安全性模式仅支持 ES256 或 RS256")
        }
        val bindingId = ByteArray(BINDING_SIZE).also(SecureRandom()::nextBytes).let(::encode)
        val alias = "$ALIAS_PREFIX${UUID.randomUUID()}"
        val generator = when (algorithm) {
            ES256 -> KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
                initialize(
                    baseSpec(alias, algorithm)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build(),
                )
            }
            else -> KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).apply {
                initialize(
                    baseSpec(alias, algorithm)
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .build(),
                )
            }
        }
        val pair = generator.generateKeyPair()
        check(pair.private.encoded == null) { "Android Keystore unexpectedly exported a private key" }
        val publicCose = PasskeyAuthenticator.buildCosePublicKey(algorithm, pair.public)
        val generation = 1L
        val binding = PasskeyDeviceBinding(
            provider = "android_keystore",
            deviceId = deviceId,
            bindingId = bindingId,
            keyGeneration = generation,
        )
        val stored = listOf(alias, algorithm.toString(), generation.toString(), digest(publicCose)).joinToString("|")
        try {
            check(prefs.edit().putString(field(bindingId), stored).commit()) {
                localizeUiTextFor(appContext, "设备 Passkey 绑定保存失败")
            }
        } catch (error: Throwable) {
            keyStore().deleteEntry(alias)
            throw error
        }
        return GeneratedDevicePasskey(binding, publicCose)
    }

    fun availability(binding: PasskeyDeviceBinding): PasskeyAvailability {
        if (binding.deviceId != deviceId) return PasskeyAvailability.OTHER_DEVICE
        val stored = read(binding.bindingId) ?: return PasskeyAvailability.KEY_MISSING
        if (stored.generation != binding.keyGeneration) return PasskeyAvailability.KEY_MISSING
        return if (runCatching { keyStore().containsAlias(stored.alias) }.getOrDefault(false)) {
            PasskeyAvailability.AVAILABLE
        } else {
            PasskeyAvailability.KEY_MISSING
        }
    }

    suspend fun openForSigning(
        activity: FragmentActivity,
        binding: PasskeyDeviceBinding,
        algorithm: Int,
        publicKeyCose: ByteArray,
    ): PasskeySigningKey {
        require(availability(binding) == PasskeyAvailability.AVAILABLE) {
            localizeUiTextFor(appContext, "设备绑定 Passkey 在本机不可用")
        }
        val stored = requireNotNull(read(binding.bindingId))
        require(stored.algorithm == algorithm && stored.publicKeyDigest == digest(publicKeyCose)) {
            localizeUiTextFor(appContext, "设备绑定 Passkey 元数据不匹配")
        }
        val privateKey = keyStore().getKey(stored.alias, null) as? PrivateKey
            ?: throw IllegalStateException(localizeUiTextFor(appContext, "设备绑定 Passkey 私钥已丢失"))
        check(privateKey.encoded == null) { "Android Keystore unexpectedly exported a private key" }
        val signature = Signature.getInstance(signatureAlgorithm(algorithm)).apply { initSign(privateKey) }
        val authenticated = authenticate(activity, signature)
        return AuthenticatedAndroidSigningKey(algorithm, publicKeyCose, authenticated)
    }

    fun delete(binding: PasskeyDeviceBinding) {
        if (binding.deviceId != deviceId) return
        val stored = read(binding.bindingId)
        prefs.edit().remove(field(binding.bindingId)).commit()
        clearCounter(binding.bindingId)
        stored?.let { runCatching { keyStore().deleteEntry(it.alias) } }
    }

    /** 返回该设备绑定凭证下一次（自增后）的签名计数，持久化在设备本地（不进 PMV）。 */
    override fun increment(identity: String): Long {
        val key = counterField(identity)
        val next = prefs.getLong(key, 0L) + 1
        check(prefs.edit().putLong(key, next).commit()) {
            localizeUiTextFor(appContext, "设备 Passkey 计数器写入失败")
        }
        return next
    }

    override fun peek(identity: String): Long = prefs.getLong(counterField(identity), 0L)

    /** 删除该凭证的本地计数器（凭证移除时调用）。 */
    fun clearCounter(identity: String) {
        prefs.edit().remove(counterField(identity)).apply()
    }

    private fun counterField(identity: String): String = "counter_${digest(identity.encodeToByteArray())}"

    private fun baseSpec(alias: String, algorithm: Int): KeyGenParameterSpec.Builder =
        // 目标仅是"不可导出 + 用户验证后才能签名"，不申请硬件 Attestation——
        // setAttestationChallenge 在部分设备会触发 ERROR_ATTESTATION_KEYS_UNAVAILABLE
        // 等兼容故障，且生成的证书链当前无人解析验证，纯属负担。
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KEYSTORE_AUTHENTICATORS)

    private suspend fun authenticate(activity: FragmentActivity, signature: Signature): Signature =
        suspendCancellableCoroutine { continuation ->
            val settled = AtomicBoolean()
            lateinit var prompt: BiometricPrompt
            fun finish(result: Result<Signature>) {
                if (!settled.compareAndSet(false, true) || !continuation.isActive) return
                result.fold(continuation::resume, continuation::resumeWithException)
            }
            prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authenticated = result.cryptoObject?.signature
                        if (authenticated == null) finish(
                            Result.failure(
                                IllegalStateException(localizeUiTextFor(appContext, "系统未返回认证后的签名操作")),
                            ),
                        )
                        else finish(Result.success(authenticated))
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        finish(Result.failure(DeviceKeyCancelled(errString.toString())))
                    }
                },
            )
            continuation.invokeOnCancellation {
                if (settled.compareAndSet(false, true)) prompt.cancelAuthentication()
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(localizeUiTextFor(appContext, "使用本设备高安全性 Passkey"))
                .setSubtitle(localizeUiTextFor(appContext, "验证锁屏后由 Android Keystore 完成签名"))
                .setAllowedAuthenticators(PROMPT_AUTHENTICATORS)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
        }

    private fun read(bindingId: String): StoredBinding? {
        val parts = prefs.getString(field(bindingId), null)?.split('|') ?: return null
        if (parts.size != 4 || !parts[0].startsWith(ALIAS_PREFIX)) return null
        val algorithm = parts[1].toIntOrNull() ?: return null
        val generation = parts[2].toLongOrNull()?.takeIf { it > 0 } ?: return null
        return StoredBinding(parts[0], algorithm, generation, parts[3])
    }

    private fun field(bindingId: String): String = "binding_${digest(bindingId.encodeToByteArray())}"
    private fun digest(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private fun encode(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    private fun signatureAlgorithm(algorithm: Int): String = when (algorithm) {
        ES256 -> "SHA256withECDSA"
        RS256 -> "SHA256withRSA"
        else -> throw IllegalArgumentException("Unsupported device Passkey algorithm: $algorithm")
    }

    private data class StoredBinding(
        val alias: String,
        val algorithm: Int,
        val generation: Long,
        val publicKeyDigest: String,
    )

    private class AuthenticatedAndroidSigningKey(
        override val algorithm: Int,
        publicKeyCose: ByteArray,
        private var signature: Signature?,
    ) : PasskeySigningKey {
        private val cose = publicKeyCose.copyOf()
        override val publicKeyCose: ByteArray get() = cose.copyOf()

        override fun sign(data: ByteArray): ByteArray {
            val signer = signature ?: error("Authenticated signing operation already consumed")
            signature = null
            signer.update(data)
            // WebAuthn 要求 ES256 签名为 ASN.1 DER，Keystore 的 SHA256withECDSA 输出即是，
            // 直接返回；不做 DER→P1363 转换
            return signer.sign()
        }

        override fun close() {
            signature = null
            cose.fill(0)
        }
    }

    class DeviceKeyCancelled(message: String) : Exception(message)

    companion object {
        private const val ES256 = -7
        private const val RS256 = -257
        private const val BINDING_SIZE = 32
        private const val PREFS = "passkey_device_bindings_v1"
        private const val ALIAS_PREFIX = "faevault_device_passkey_"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_AUTHENTICATORS =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        private const val PROMPT_AUTHENTICATORS =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
    }
}
