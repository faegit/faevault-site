package com.vault.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.vault.R
import java.security.InvalidKeyException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

/**
 * 生物识别解锁：用 AndroidKeyStore 的 AES/GCM 密钥包裹版本化设备解锁信封，
 * 不在生物凭据中保存主密码。PMVE 保存 RootKey 副本及其
 * vaultId、签名公钥、keyRevision 绑定，两者不会共用无类型的 32 字节入口。
 *
 * - 密钥要求用户认证（setUserAuthenticationRequired(true)）
 * - 仅接受 BIOMETRIC_STRONG：支持强生物识别传感器和系统认定为高安全级别的 3D 人脸，不接受弱 2D 人脸
 * - setInvalidatedByBiometricEnrollment(true)：用户新增/删除生物识别模板后旧密文自动失效
 * - 包裹后的 IV+密文以 Base64 存于 SharedPreferences
 */
class BiometricVault(context: Context, vaultName: String) {

    private val appContext = context.applicationContext
    private val scopeName = VaultNameScope.resolve(appContext, vaultName)
    private val prefs = appContext
        .getSharedPreferences(PREF_PREFIX + scopeName, Context.MODE_PRIVATE)

    private val keyAlias = "${KEY_ALIAS_PREFIX}_${scopeName}"

    fun isEnrolled(): Boolean = prefs.contains(KEY_CT)

    /** 设备是否具备可用的生物识别。 */
    fun canAuthenticate(context: Context): Boolean {
        val bm = BiometricManager.from(context)
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    fun clear() {
        prefs.edit().clear().apply()
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.deleteEntry(keyAlias)
        }
    }

    /** 弹出生物提示，校验通过后用 Keystore 密钥加密主密码并落盘。
     *  如旧密钥已被生物识别模板变更失效，自动重建密钥后再走一次完整流程。 */
    suspend fun enroll(activity: FragmentActivity, material: DeviceUnlockMaterial) {
        val plaintext = DeviceUnlockEnvelopeCodec.encode(material)
        val cipher = initEncryptCipherWithRecovery()
        try {
            val authed = authenticate(
                activity,
                cipher,
                title = appContext.getString(R.string.biometric_enable_title),
                subtitle = appContext.getString(R.string.biometric_enable_subtitle),
            )
            val ct = authed.doFinal(plaintext)
            val iv = authed.iv
            prefs.edit()
                .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString(KEY_CT, Base64.encodeToString(ct, Base64.NO_WRAP))
                .apply()
            ct.fill(0)
        } finally {
            plaintext.fill(0)
        }
    }

    /** 弹出生物提示，校验通过后解包返回主密码。
     *  生物识别模板变更后旧密钥失效 → 抛 [BiometricKeyInvalidated]，并清理本地残留，让 UI 引导用户回落到主密码。 */
    suspend fun unlock(activity: FragmentActivity): DeviceUnlockMaterial {
        val ivB64 = prefs.getString(KEY_IV, null)
            ?: throw BiometricKeyInvalidated(appContext.getString(R.string.biometric_not_enabled))
        val ctB64 = prefs.getString(KEY_CT, null)
            ?: throw BiometricKeyInvalidated(appContext.getString(R.string.biometric_not_enabled))
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val ct = Base64.decode(ctB64, Base64.NO_WRAP)
        val cipher = try {
            Cipher.getInstance(TRANSFORM).apply {
                init(Cipher.DECRYPT_MODE, loadKey(), GCMParameterSpec(128, iv))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            clear()                                                          // 失效密钥 + 旧密文一起清掉
            throw BiometricKeyInvalidated(appContext.getString(R.string.biometric_binding_changed))
        } catch (e: InvalidKeyException) {
            // 部分厂商 ROM 在 API <30 / 锁屏凭据被移除时也走这条路径
            clear()
            throw BiometricKeyInvalidated(appContext.getString(R.string.biometric_key_unavailable))
        }
        val authed = authenticate(
            activity,
            cipher,
            title = appContext.getString(R.string.biometric_unlock_title),
            subtitle = appContext.getString(R.string.biometric_unlock_subtitle),
        )
        val pt = authed.doFinal(ct)
        return try {
            DeviceUnlockEnvelopeCodec.decode(pt)
        } catch (error: IllegalArgumentException) {
            clear()
            throw BiometricKeyInvalidated(appContext.getString(R.string.biometric_legacy_binding_invalid))
        } finally {
            pt.fill(0)
            ct.fill(0)
            iv.fill(0)
        }
    }

    /** 初始化加密 Cipher：如旧密钥已被失效，删掉重新生成再试一次（仅 enroll 路径走）。 */
    private fun initEncryptCipherWithRecovery(): Cipher {
        ensureKey()
        return try {
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, loadKey()) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // 走 clear + 重新生成密钥；旧的密文也是过期的，可以一并清
            clear()
            ensureKey()
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, loadKey()) }
        }
    }

    private fun ensureKey() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(keyAlias)) return
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private fun loadKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (ks.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private suspend fun authenticate(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
    ): Cipher = suspendCoroutine { cont ->
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                        ?: return cont.resumeWithException(
                            IllegalStateException(appContext.getString(R.string.biometric_cipher_missing)),
                        )
                    cont.resume(c)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    cont.resumeWithException(BiometricCancelled(errString.toString()))
                }
                override fun onAuthenticationFailed() { /* 用户重试中，忽略 */ }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(appContext.getString(R.string.biometric_cancel))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    class BiometricCancelled(msg: String) : Exception(msg)

    /** 生物密钥已失效（用户增删生物识别模板 / 移除锁屏凭据）。UI 应清理状态并提示回落到主密码。 */
    class BiometricKeyInvalidated(msg: String) : Exception(msg)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "pmv_master_pw"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val PREF_PREFIX = "pmv_bio_"
        private const val KEY_IV = "iv"
        private const val KEY_CT = "ct"
    }
}
