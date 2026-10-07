package com.vault.storage

import android.content.Context
import com.vault.security.SecurePreferences
import com.vault.model.Entry
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID
import kotlinx.serialization.json.*

data class VaultHistoryRecord(val id: String, val createdAt: Long, val sequence: Long)
data class VaultHistoryPreview(val record: VaultHistoryRecord, val entries: List<Entry>, val expectedCommit: String,
    internal val expectedSequence: Long, internal val snapshotCommit: String)

/** Immutable complete encrypted PMVE files; pins are Keystore protected, never trusted from filenames. */
class VaultHistoryStore(context: Context, private val vaultId: UUID) {
    private val archiveRoot = File(context.filesDir, "history")
    private val directory = File(context.filesDir, "history/$vaultId")
    private val prefs = SecurePreferences.get(context, "vault_history_$vaultId")
    private fun pins(): JsonArray = prefs.getString("pins", null)?.let {
        Json.parseToJsonElement(it) as? JsonArray
    } ?: JsonArray(emptyList())
    private fun record(pin: JsonObject) = VaultHistoryRecord(pin.getValue("id").jsonPrimitive.content,
        pin.getValue("created_at").jsonPrimitive.long, pin.getValue("sequence").jsonPrimitive.long)
    fun list(): List<VaultHistoryRecord> = pins().map { record(it.jsonObject) }.sortedByDescending { it.createdAt }
    fun create(source: File, identity: VaultIdentity, protected: Boolean = false, preserveId: String? = null, verifySnapshot: ((File) -> VaultIdentity)? = null): VaultHistoryRecord = synchronized(lock) {
        requireSafeDirectory()
        require(identity.vaultId == vaultId)
        val previous = pins().map { it.jsonObject }
        val commit = identity.commitId.toString()
        val signer = identity.signingPublicKey.joinToString("") { "%02x".format(it) }
        previous.firstOrNull { it["commit"]?.jsonPrimitive?.content == commit && it["signer"]?.jsonPrimitive?.content == signer }?.let { existing ->
            file(record(existing).id) // verify an existing immutable copy before reporting success
            if (protected && existing["protected"]?.jsonPrimitive?.booleanOrNull != true) {
                val upgraded = JsonObject(existing + mapOf("protected" to JsonPrimitive(true), "protected_at" to JsonPrimitive(System.currentTimeMillis())))
                check(prefs.edit().putString("pins", JsonArray(previous.map { if (it == existing) upgraded else it }).toString()).commit())
            }
            return@synchronized record(existing)
        }
        check(directory.isDirectory || directory.mkdirs()) { "无法创建历史快照目录" }
        val id = UUID.randomUUID().toString()
        val target = File(directory, "$id.pmv")
        try {
            FileOutputStream(target).use { output -> source.inputStream().use { it.copyTo(output) }; output.fd.sync() }
            verifySnapshot?.invoke(target)?.let { actual ->
                require(actual.vaultId == identity.vaultId && actual.commitId == identity.commitId && actual.sequence == identity.sequence) { "快照源已变化，请重新创建" }
            }
            check(target.setReadOnly()) { "无法保护历史快照" }
            val pin = buildJsonObject {
                put("id", id); put("created_at", System.currentTimeMillis()); put("sequence", identity.sequence)
                put("commit", commit); put("signer", signer); put("sha256", digest(target)); put("vault_id", vaultId.toString())
                put("protected", protected); if (protected) put("protected_at", System.currentTimeMillis())
            }
            val keep = VaultHistoryRetention.keep(previous + pin, preserveId)
            check(prefs.edit().putString("pins", JsonArray(keep).toString()).commit()) { "无法保存快照验证信息" }
            previous.filter { old -> keep.none { it["id"] == old["id"] } }.forEach { old ->
                File(directory, "${old.getValue("id").jsonPrimitive.content}.pmv").delete()
            }
            record(pin)
        } catch (error: Throwable) { target.delete(); throw error }
    }
    fun prune() = synchronized(lock) {
        requireSafeDirectory()
        val previous = pins().map { it.jsonObject }
        val keep = VaultHistoryRetention.keep(previous)
        check(prefs.edit().putString("pins", JsonArray(keep).toString()).commit())
        previous.filter { pin -> keep.none { it["id"] == pin["id"] } }.forEach { pin ->
            val id = pin.getValue("id").jsonPrimitive.content
            if (runCatching { UUID.fromString(id) }.isSuccess) File(directory, "$id.pmv").delete()
        }
    }
    fun file(id: String): File = synchronized(lock) {
        requireSafeDirectory()
        require(runCatching { UUID.fromString(id) }.isSuccess) { "无效历史快照" }
        val pin = pins().map { it.jsonObject }.firstOrNull { it["id"]?.jsonPrimitive?.content == id }
            ?: error("历史快照已失效")
        val file = File(directory, "$id.pmv")
        check(!java.nio.file.Files.isSymbolicLink(file.toPath()) && file.canonicalFile.parentFile == directory.canonicalFile &&
            file.isFile && digest(file) == pin.getValue("sha256").jsonPrimitive.content) { "历史快照校验失败" }
        file
    }
    fun verifyIdentity(id: String, identity: PmvVaultStore.Identity) {
        val pin = pins().map { it.jsonObject }.firstOrNull { it["id"]?.jsonPrimitive?.content == id }
            ?: error("历史快照已失效")
        require(identity.vaultId == vaultId && identity.sequence == pin.getValue("sequence").jsonPrimitive.long &&
            identity.latestCommitId.toString() == pin.getValue("commit").jsonPrimitive.content) { "历史快照身份校验失败" }
    }
    private fun requireSafeDirectory() {
        require(!java.nio.file.Files.isSymbolicLink(archiveRoot.toPath()) && !java.nio.file.Files.isSymbolicLink(directory.toPath()) &&
            directory.canonicalFile.parentFile == archiveRoot.canonicalFile) { "历史快照目录无效" }
    }
    companion object {
        private val lock = Any()
        private fun digest(file: File): String {
            val md = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input -> val buffer = ByteArray(65536); while (true) {
                val n = input.read(buffer); if (n < 0) break; md.update(buffer, 0, n)
            } }
            return md.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
