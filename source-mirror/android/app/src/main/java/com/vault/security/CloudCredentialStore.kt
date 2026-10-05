package com.vault.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.vault.crypto.PmvKeySchedule
import com.vault.storage.WebDavConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Pure per-field crypto; its AAD layout is shared with the desktop client. */
object CloudCredentialCrypto {
    private val AAD_DOMAIN = "pmv/cloud-credential\u0000".toByteArray(Charsets.US_ASCII)
    private const val FORMAT_VERSION = 1
    private const val NONCE_SIZE = 12

    fun sealField(
        key: ByteArray,
        vaultId: String,
        provider: String,
        field: String,
        fieldVersion: Int,
        plaintextUtf8: ByteArray,
        nonce: ByteArray = ByteArray(NONCE_SIZE).also(SecureRandom()::nextBytes),
    ): ByteArray {
        val uuid = UUID.fromString(vaultId)
        require(key.size == PmvKeySchedule.KEY_SIZE) { "云凭据密钥必须为 32 字节" }
        require(nonce.size == NONCE_SIZE) { "云凭据 nonce 必须为 12 字节" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(uuid, provider, field, fieldVersion))
        return nonce + cipher.doFinal(plaintextUtf8)
    }

    fun openField(
        key: ByteArray,
        vaultId: String,
        provider: String,
        field: String,
        fieldVersion: Int,
        packed: ByteArray,
    ): ByteArray {
        val uuid = UUID.fromString(vaultId)
        require(key.size == PmvKeySchedule.KEY_SIZE) { "云凭据密钥必须为 32 字节" }
        require(packed.size >= NONCE_SIZE + 16) { "云凭据字段长度无效" }
        val nonce = packed.copyOfRange(0, NONCE_SIZE)
        val ciphertext = packed.copyOfRange(NONCE_SIZE, packed.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad(uuid, provider, field, fieldVersion))
            cipher.doFinal(ciphertext)
        } finally {
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun aad(vaultId: UUID, provider: String, field: String, fieldVersion: Int): ByteArray {
        require(fieldVersion > 0) { "云凭据字段版本无效" }
        require(provider.isNotEmpty() && field.isNotEmpty() && '\u0000' !in provider && '\u0000' !in field) {
            "云凭据操作域无效"
        }
        val providerBytes = provider.toByteArray(Charsets.UTF_8)
        val fieldBytes = field.toByteArray(Charsets.UTF_8)
        return try {
            ByteBuffer.allocate(AAD_DOMAIN.size + 4 + 16 + providerBytes.size + 1 + fieldBytes.size + 1 + 4)
                .order(ByteOrder.BIG_ENDIAN).apply {
                    put(AAD_DOMAIN)
                    putInt(FORMAT_VERSION)
                    putLong(vaultId.mostSignificantBits)
                    putLong(vaultId.leastSignificantBits)
                    put(providerBytes)
                    put(0)
                    put(fieldBytes)
                    put(0)
                    putInt(fieldVersion)
                }.array()
        } finally {
            providerBytes.fill(0)
            fieldBytes.fill(0)
        }
    }
}

/** Vault-bound WebDAV persistence. Sensitive fields never enter a JSON object. */
object CloudCredentialStore {
    private const val PREFS = "cloud_credentials"
    private const val PROVIDER = "webdav"
    private const val FIELD_VERSION = 1
    private const val LEGACY_KEY_ALIAS = "vault_cloud_credentials"
    private const val LEGACY_VALUE = "webdav_"
    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private data class Metadata(
        val formatVersion: Int = 2,
        val label: String,
        val fileUrl: String,
        val authMode: String,
        val certificateSha256: String,
        val createDirectories: Boolean,
    )

    @Serializable
    private data class LegacyConfig(
        val label: String,
        val fileUrl: String,
        val username: String,
        val password: String,
        val authMode: String = "basic",
        val bearerToken: String = "",
        val certificateSha256: String = "",
        val createDirectories: Boolean = false,
        val cookie: String = "",
        val clientCertificate: String = "",
        val clientCertificatePassword: String = "",
        val domain: String = "",
    )

    private val sensitiveFields = listOf(
        "username", "password", "bearer_token", "cookie", "client_certificate",
        "client_certificate_password", "domain",
    )

    fun hasCloudConfig(context: Context, vaultId: String, legacyId: String? = null): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.contains(metaKey(vaultId)) ||
            (legacyId != null && prefs.contains(legacyKeyFor(legacyId)))
    }

    fun save(context: Context, vaultId: String, config: WebDavConfig, rootKey: ByteArray) {
        val cloudKey = deriveCloudKey(rootKey, vaultId)
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        try {
            editor.putString(
                metaKey(vaultId),
                json.encodeToString(
                    Metadata(
                        label = config.label,
                        fileUrl = config.fileUrl,
                        authMode = config.authMode,
                        certificateSha256 = config.certificateSha256,
                        createDirectories = config.createDirectories,
                    ),
                ),
            )
            val values = listOf(
                config.username, config.password, config.bearerToken, config.cookie,
                config.clientCertificate, config.clientCertificatePassword, config.domain,
            )
            sensitiveFields.zip(values).forEach { (field, value) ->
                val plaintext = value.toByteArray(Charsets.UTF_8)
                try {
                    val encrypted = CloudCredentialCrypto.sealField(
                        cloudKey, vaultId, PROVIDER, field, FIELD_VERSION, plaintext,
                    )
                    try {
                        editor.putString(fieldKey(vaultId, field), Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    } finally {
                        encrypted.fill(0)
                    }
                } finally {
                    plaintext.fill(0)
                }
            }
            editor.apply()
        } finally {
            cloudKey.fill(0)
        }
    }

    /** Migrates the original device-Keystore blob only while the vault RootKey is available. */
    fun load(
        context: Context,
        vaultId: String,
        rootKey: ByteArray,
        legacyId: String? = null,
    ): WebDavConfig? {
        loadV2(context, vaultId, rootKey)?.let { return it }
        val legacy = legacyId?.let { loadLegacy(context, it) } ?: return null
        save(context, vaultId, legacy, rootKey)
        val verified = loadV2(context, vaultId, rootKey) ?: return null
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().remove(legacyKeyFor(legacyId)).apply()
        deleteLegacyKeyWhenUnused(prefs)
        return verified
    }

    private fun loadV2(context: Context, vaultId: String, rootKey: ByteArray): WebDavConfig? = runCatching {
        val uuid = UUID.fromString(vaultId)
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val metadata = json.decodeFromString<Metadata>(prefs.getString(metaKey(vaultId), null) ?: return null)
        require(metadata.formatVersion == 2) { "云凭据格式版本无效" }
        val cloudKey = deriveCloudKey(rootKey, vaultId)
        try {
            val values = sensitiveFields.associateWith { field ->
                val packed = Base64.decode(requireNotNull(prefs.getString(fieldKey(vaultId, field), null)), Base64.NO_WRAP)
                val plaintext = try {
                    CloudCredentialCrypto.openField(cloudKey, vaultId, PROVIDER, field, FIELD_VERSION, packed)
                } finally {
                    packed.fill(0)
                }
                try { plaintext.toString(Charsets.UTF_8) } finally { plaintext.fill(0) }
            }
            WebDavConfig(
                metadata.label, metadata.fileUrl, values.getValue("username"), values.getValue("password"),
                metadata.authMode, values.getValue("bearer_token"), metadata.certificateSha256,
                metadata.createDirectories, values.getValue("cookie"), values.getValue("client_certificate"),
                values.getValue("client_certificate_password"), values.getValue("domain"),
            )
        } finally {
            cloudKey.fill(0)
        }
    }.getOrNull()

    fun clear(context: Context, vaultId: String, legacyId: String? = null) {
        val editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(metaKey(vaultId))
        sensitiveFields.forEach { editor.remove(fieldKey(vaultId, it)) }
        legacyId?.let { editor.remove(legacyKeyFor(it)) }
        editor.apply()
        deleteLegacyKeyWhenUnused(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE))
    }

    private fun deriveCloudKey(rootKey: ByteArray, vaultId: String): ByteArray {
        val uuid = UUID.fromString(vaultId)
        require(rootKey.size == PmvKeySchedule.KEY_SIZE) { "保险库根密钥必须为 32 字节" }
        return PmvKeySchedule.deriveRootKeys(rootKey, uuid).use { rootKeys ->
            PmvKeySchedule.deriveCloudCredentialKey(rootKeys.keyWrapKey)
        }
    }

    private fun loadLegacy(context: Context, legacyId: String): WebDavConfig? = runCatching {
        val encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(legacyKeyFor(legacyId), null) ?: return null
        val packed = Base64.decode(encoded, Base64.NO_WRAP)
        require(packed.size > 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, legacyKey(), GCMParameterSpec(128, packed.copyOfRange(0, 12)))
        val plaintext = cipher.doFinal(packed.copyOfRange(12, packed.size))
        try {
            val stored = json.decodeFromString<LegacyConfig>(plaintext.toString(Charsets.UTF_8))
            WebDavConfig(
                stored.label, stored.fileUrl, stored.username, stored.password, stored.authMode,
                stored.bearerToken, stored.certificateSha256, stored.createDirectories, stored.cookie,
                stored.clientCertificate, stored.clientCertificatePassword, stored.domain,
            )
        } finally {
            plaintext.fill(0)
            packed.fill(0)
        }
    }.getOrNull()

    private fun legacyKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(LEGACY_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    LEGACY_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
    }

    private fun deleteLegacyKeyWhenUnused(prefs: android.content.SharedPreferences) {
        if (prefs.all.keys.any { it.startsWith(LEGACY_VALUE) }) return
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(LEGACY_KEY_ALIAS)
        }
    }

    private fun suffix(vaultId: String): String {
        val uuid = UUID.fromString(vaultId)
        return MessageDigest.getInstance("SHA-256")
            .digest(ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array())
            .take(12).joinToString("") { "%02x".format(it) }
    }

    private fun metaKey(vaultId: String) = "v2_${suffix(vaultId)}_meta"
    private fun fieldKey(vaultId: String, field: String) = "v2_${suffix(vaultId)}_$field"
    private fun legacyKeyFor(legacyId: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(legacyId.toByteArray())
        return LEGACY_VALUE + digest.take(12).joinToString("") { "%02x".format(it) }
    }
}
