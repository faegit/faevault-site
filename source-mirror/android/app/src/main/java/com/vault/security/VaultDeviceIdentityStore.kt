package com.vault.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/**
 * 每库设备身份持久化：Android Keystore AES-GCM 包裹 [VaultDeviceIdentity.encode] 的明文，
 * IV+密文存 SharedPreferences。Keystore 密钥不可导出，设备私钥种子永不落盘明文。
 */
class VaultDeviceIdentityStore(context: Context, vaultName: String) {
    private val prefs = context.getSharedPreferences(PREF_PREFIX + vaultName, Context.MODE_PRIVATE)
    private val keyAlias = KEY_ALIAS_PREFIX + vaultName

    fun load(): VaultDeviceIdentity? {
        val ivText = prefs.getString(KEY_IV, null) ?: return null
        val ct = prefs.getString(KEY_CT, null) ?: return null
        return runCatching {
            val iv = Base64.getDecoder().decode(ivText)
            val ciphertext = Base64.getDecoder().decode(ct)
            val plaintext = try {
                val cipher = Cipher.getInstance(TRANSFORM).apply {
                    init(Cipher.DECRYPT_MODE, loadKey(), GCMParameterSpec(128, iv))
                }
                cipher.doFinal(ciphertext)
            } finally {
                iv.fill(0)
                ciphertext.fill(0)
            }
            try { VaultDeviceIdentity.decode(plaintext) } finally { plaintext.fill(0) }
        }.getOrNull()
    }

    fun loadOrCreate(): VaultDeviceIdentity = load() ?: VaultDeviceIdentity.generate().also(::save)

    fun save(identity: VaultDeviceIdentity) {
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.ENCRYPT_MODE, loadOrCreateKey())
        }
        val plaintext = VaultDeviceIdentity.encode(identity)
        val ct = try { cipher.doFinal(plaintext) } finally { plaintext.fill(0) }
        try {
            prefs.edit()
                .putString(KEY_IV, Base64.getEncoder().encodeToString(cipher.iv))
                .putString(KEY_CT, Base64.getEncoder().encodeToString(ct))
                .apply()
        } finally {
            ct.fill(0)
        }
    }

    fun delete() {
        prefs.edit().clear().apply()
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        }
    }

    private fun loadOrCreateKey(): javax.crypto.SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun loadKey(): javax.crypto.SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (keyStore.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val PREF_PREFIX = "vault_device_identity_"
        private const val KEY_ALIAS_PREFIX = "faevault_device_"
        private const val KEY_IV = "iv"
        private const val KEY_CT = "ct"
    }
}
