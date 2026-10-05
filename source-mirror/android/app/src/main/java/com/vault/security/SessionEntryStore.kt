package com.vault.security

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.VaultPayload
import com.vault.model.displaySecret
import com.vault.model.entryModules
import com.vault.model.getExpiryDate
import com.vault.storage.V2EntryPayload
import com.vault.storage.VaultCodec
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Keeps entry secrets encrypted while the unlocked UI only retains list metadata.
 * This is process-memory hardening, not a boundary against code already executing in-process.
 */
class SessionEntryStore : AutoCloseable {
    private data class SealedEntry(val nonce: ByteArray, val ciphertext: ByteArray)

    private val random = SecureRandom()
    private var key = SessionBytes(ByteArray(KEY_SIZE).also(random::nextBytes))
    private val sealed = LinkedHashMap<String, SealedEntry>()
    private var closed = false

    @Synchronized
    fun seal(payload: VaultPayload): VaultPayload {
        check(!closed) { "会话条目密封区已清除" }
        sealed.values.forEach(::wipe)
        sealed.clear()
        val sessionKey = key.reveal()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val redacted = try {
            payload.entries.map { entry ->
                sealed[entry.id] = encrypt(entry, sessionKey, cipher)
                entry.redacted()
            }
        } finally {
            sessionKey.fill(0)
        }
        return payload.copy(entries = redacted, trash = emptyList())
    }

    @Synchronized
    fun replace(entry: Entry) {
        check(!closed) { "会话条目密封区已清除" }
        sealed.remove(entry.id)?.let(::wipe)
        val sessionKey = key.reveal()
        try {
            sealed[entry.id] = encrypt(entry, sessionKey, Cipher.getInstance(TRANSFORMATION))
        } finally {
            sessionKey.fill(0)
        }
    }

    private fun encrypt(entry: Entry, sessionKey: ByteArray, cipher: Cipher): SealedEntry {
        val plain = VaultCodec.json.encodeToString(
            V2EntryPayload.serializer(),
            V2EntryPayload.fromEntry(entry),
        ).encodeToByteArray()
        try {
            val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
            val ciphertext = cipher.run {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(TAG_BITS, nonce))
                updateAAD(entry.id.encodeToByteArray())
                doFinal(plain)
            }
            return SealedEntry(nonce, ciphertext)
        } finally {
            plain.fill(0)
        }
    }

    @Synchronized
    fun reveal(metadata: Entry): Entry {
        check(!closed) { "会话条目密封区已清除" }
        val item = sealed[metadata.id] ?: return metadata
        val sessionKey = key.reveal()
        val plain = try {
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(TAG_BITS, item.nonce))
                updateAAD(metadata.id.encodeToByteArray())
                doFinal(item.ciphertext)
            }
        } finally {
            sessionKey.fill(0)
        }
        return try {
            val payload = VaultCodec.json.decodeFromString(V2EntryPayload.serializer(), plain.decodeToString())
            metadata.copy(
                password = payload.password,
                notes = payload.notes,
                fields = payload.fields,
                displaySummary = "",
                expirySummary = "",
            )
        } finally {
            plain.fill(0)
        }
    }

    @Synchronized
    fun materialize(payload: VaultPayload): VaultPayload {
        check(!closed) { "会话条目密封区已清除" }
        return payload.copy(entries = payload.entries.map(::reveal))
    }

    @Synchronized
    override fun close() {
        if (closed) return
        sealed.values.forEach(::wipe)
        sealed.clear()
        key.close()
        closed = true
    }

    private fun wipe(item: SealedEntry) {
        item.nonce.fill(0)
        item.ciphertext.fill(0)
    }

    private fun Entry.redacted(): Entry = copy(
        password = "",
        notes = "",
        fields = emptyMap(),
        displaySummary = displaySecret,
        expirySummary = getExpiryDate()?.toString().orEmpty(),
        containsPasskey = containsPasskey || entryModules().any {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        },
    )

    private companion object {
        const val KEY_SIZE = 32
        const val NONCE_SIZE = 12
        const val TAG_BITS = 128
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
