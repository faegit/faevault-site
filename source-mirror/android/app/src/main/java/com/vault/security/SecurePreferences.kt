package com.vault.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keystore-backed preferences with per-value AES-256-GCM authentication.
 *
 * Existing plaintext values are migrated on first successful read. Preference name and key are
 * authenticated as AAD, so ciphertext cannot be copied between settings. Values required before
 * vault unlock remain available because the key is device-bound rather than session-bound.
 */
object SecurePreferences {
    private const val ALIAS = "faevault_preferences_v1"
    private const val PREFIX = "FAEP1:"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val MIGRATION_MARKER = "__faep_migration_complete_v1"
    private val preferences = ConcurrentHashMap<String, SharedPreferences>()
    @Volatile private var cachedKey: SecretKey? = null
    @Volatile private var cachedKeyStore: KeyStore? = null

    internal enum class MigrationDecision { MIGRATE_PLAINTEXT, MARK_ENCRYPTED, ALREADY_COMPLETE, REJECT }

    internal fun migrationDecision(hasKey: Boolean, values: Map<String, *>): MigrationDecision {
        val marker = values[MIGRATION_MARKER]
        if (hasKey) {
            return if (marker is String && marker.startsWith(PREFIX)) {
                MigrationDecision.ALREADY_COMPLETE
            } else {
                MigrationDecision.REJECT
            }
        }
        if (marker != null) return MigrationDecision.REJECT
        return if (values.isNotEmpty() && values.values.all { it is String && it.startsWith(PREFIX) }) {
            MigrationDecision.MARK_ENCRYPTED
        } else {
            MigrationDecision.MIGRATE_PLAINTEXT
        }
    }

    fun get(context: Context, name: String): SharedPreferences {
        preferences[name]?.let { return it }
        return synchronized(preferences) {
            preferences[name] ?: EncryptedPreferences(
                context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE),
                name,
            ).also { preferences[name] = it }
        }
    }

    private fun keyStore(): KeyStore {
        cachedKeyStore?.let { return it }
        return synchronized(this) {
            cachedKeyStore ?: KeyStore.getInstance("AndroidKeyStore")
                .apply { load(null) }
                .also { cachedKeyStore = it }
        }
    }

    private fun key(): SecretKey {
        cachedKey?.let { return it }
        return synchronized(this) {
            cachedKey ?: run {
                val resolved = (keyStore().getKey(ALIAS, null) as? SecretKey)
                    ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                        init(
                            KeyGenParameterSpec.Builder(
                                ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                            )
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setKeySize(256)
                                .build(),
                        )
                        generateKey()
                    }
                cachedKey = resolved
                resolved
            }
        }
    }

    private fun migrationAlias(name: String): String = ALIAS + "_migrated_" +
        MessageDigest.getInstance("SHA-256").digest(name.toByteArray()).take(8).joinToString("") { "%02x".format(it) }

    private fun migrationMarkerExists(name: String): Boolean =
        synchronized(this) { keyStore().containsAlias(migrationAlias(name)) }

    private fun markMigrationComplete(name: String) {
        if (migrationMarkerExists(name)) return
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(migrationAlias(name), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            generateKey()
        }
    }

    private fun aad(name: String, field: String) = "FAEVault/preferences/v1\u0000$name\u0000$field".toByteArray()

    private fun seal(name: String, field: String, plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.ENCRYPT_MODE, key())
            updateAAD(aad(name, field))
        }
        return PREFIX + Base64.encodeToString(cipher.iv + cipher.doFinal(plain), Base64.NO_WRAP)
    }

    private fun open(name: String, field: String, value: String): ByteArray {
        require(value.startsWith(PREFIX)) { "Not an encrypted preference" }
        val packed = Base64.decode(value.removePrefix(PREFIX), Base64.NO_WRAP)
        require(packed.size > 28) { "Encrypted preference is truncated" }
        return try {
            Cipher.getInstance(TRANSFORM).run {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, packed.copyOfRange(0, 12)))
                updateAAD(aad(name, field))
                doFinal(packed.copyOfRange(12, packed.size))
            }
        } catch (error: AEADBadTagException) {
            throw SecurityException("Encrypted preference authentication failed", error)
        }
    }

    private class EncryptedPreferences(
        private val delegate: SharedPreferences,
        private val name: String,
    ) : SharedPreferences {
        init {
            when (migrationDecision(migrationMarkerExists(name), delegate.all)) {
                MigrationDecision.MIGRATE_PLAINTEXT -> {
                    val values = delegate.all.toMap()
                    val editor = Editor(delegate.edit().clear(), name, allowMarker = true)
                    values.forEach { (field, value) -> editor.putAny(field, value) }
                    check(editor.putBoolean(MIGRATION_MARKER, true).commit()) { "Preference migration failed" }
                    markMigrationComplete(name)
                }
                MigrationDecision.MARK_ENCRYPTED -> check(
                    Editor(delegate.edit(), name, allowMarker = true)
                        .putBoolean(MIGRATION_MARKER, true)
                        .commit(),
                ) { "Preference migration marker could not be stored" }.also { markMigrationComplete(name) }
                MigrationDecision.ALREADY_COMPLETE -> {
                    val marker = decodedValue(MIGRATION_MARKER)
                    if (marker != true) throw SecurityException("Encrypted preference migration marker is invalid")
                    if (delegate.all.any { (field, value) ->
                            field != MIGRATION_MARKER && (value !is String || !value.startsWith(PREFIX))
                        }) {
                        throw SecurityException("Plaintext preference found after encrypted migration")
                    }
                }
                MigrationDecision.REJECT -> throw SecurityException("Preference encryption state is invalid")
            }
        }

        private fun decodedValue(key: String): Any? {
            val raw = delegate.all[key] ?: return null
            if (raw !is String || !raw.startsWith(PREFIX)) {
                throw SecurityException("Plaintext preference found after encrypted migration")
            }
            val bytes = open(name, key, raw)
            require(bytes.isNotEmpty()) { "Encrypted preference is empty" }
            return when (bytes[0].toInt()) {
                1 -> bytes.copyOfRange(1, bytes.size).decodeToString()
                2 -> ByteBuffer.wrap(bytes, 1, 4).int
                3 -> ByteBuffer.wrap(bytes, 1, 8).long
                4 -> bytes[1].toInt() != 0
                5 -> ByteBuffer.wrap(bytes, 1, 4).float
                6 -> bytes.copyOfRange(1, bytes.size).decodeToString().split('\u0000').filter { it.isNotEmpty() }.toSet()
                else -> throw SecurityException("Encrypted preference type is invalid")
            }
        }

        private fun decoded(key: String): Any? {
            if (!delegate.contains(key)) return null
            return decodedValue(key)
        }

        override fun getAll(): Map<String, *> = delegate.all.keys.filter { it != MIGRATION_MARKER }.associateWith(::decoded)
        override fun getString(key: String, defValue: String?): String? = decoded(key) as? String ?: defValue
        override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
            @Suppress("UNCHECKED_CAST") ((decoded(key) as? Set<String>) ?: defValues)
        override fun getInt(key: String, defValue: Int): Int = decoded(key) as? Int ?: defValue
        override fun getLong(key: String, defValue: Long): Long = decoded(key) as? Long ?: defValue
        override fun getFloat(key: String, defValue: Float): Float = decoded(key) as? Float ?: defValue
        override fun getBoolean(key: String, defValue: Boolean): Boolean = decoded(key) as? Boolean ?: defValue
        override fun contains(key: String): Boolean = key != MIGRATION_MARKER && delegate.contains(key)
        override fun edit(): SharedPreferences.Editor = Editor(delegate.edit(), name)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) =
            delegate.registerOnSharedPreferenceChangeListener(listener)
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) =
            delegate.unregisterOnSharedPreferenceChangeListener(listener)
    }

    private class Editor(
        private val delegate: SharedPreferences.Editor,
        private val name: String,
        private val allowMarker: Boolean = false,
    ) : SharedPreferences.Editor {
        fun putAny(key: String, value: Any?): Editor = when (value) {
            null -> remove(key)
            is String -> putString(key, value)
            is Int -> putInt(key, value)
            is Long -> putLong(key, value)
            is Boolean -> putBoolean(key, value)
            is Float -> putFloat(key, value)
            is Set<*> -> putStringSet(key, value.filterIsInstance<String>().toSet())
            else -> throw IllegalArgumentException("Unsupported preference type")
        }

        private fun store(key: String, type: Byte, payload: ByteArray): Editor {
            if (key == MIGRATION_MARKER && !allowMarker) throw SecurityException("Reserved preference key")
            delegate.putString(key, seal(name, key, byteArrayOf(type) + payload))
            return this
        }

        override fun putString(key: String, value: String?): Editor = if (value == null) remove(key) else store(key, 1, value.toByteArray())
        override fun putStringSet(key: String, values: Set<String>?): Editor =
            if (values == null) remove(key) else store(key, 6, values.sorted().joinToString("\u0000").toByteArray())
        override fun putInt(key: String, value: Int): Editor = store(key, 2, ByteBuffer.allocate(4).putInt(value).array())
        override fun putLong(key: String, value: Long): Editor = store(key, 3, ByteBuffer.allocate(8).putLong(value).array())
        override fun putFloat(key: String, value: Float): Editor = store(key, 5, ByteBuffer.allocate(4).putFloat(value).array())
        override fun putBoolean(key: String, value: Boolean): Editor = store(key, 4, byteArrayOf(if (value) 1 else 0))
        override fun remove(key: String): Editor {
            if (key == MIGRATION_MARKER) throw SecurityException("Reserved preference key")
            delegate.remove(key)
            return this
        }
        override fun clear(): Editor {
            delegate.clear()
            delegate.putString(MIGRATION_MARKER, seal(name, MIGRATION_MARKER, byteArrayOf(4, 1)))
            return this
        }
        override fun commit(): Boolean = delegate.commit()
        override fun apply() = delegate.apply()
    }
}
