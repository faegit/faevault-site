package com.vault.storage

import android.content.Context
import android.net.Uri
import com.vault.crypto.VaultCrypto
import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.nowSeconds
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.FileNotFoundException

/**
 * .pmbak 加密备份编解码，对齐桌面端 core/backup.py。
 * 明文 JSON 含 entries + syncMeta + exportEpoch，使用独立的导出口令加密。
 *
 * 加密格式：
 * - 导出使用 [PmvBackupCrypto]（Argon2id + AES-256-GCM + AAD，V2 布局）。
 *
 * v2 起 BackupPayload 携带库谱系信息（syncMeta.deviceId），合并方据此判断
 * "是同一份库的不同版本"还是"两个不同账户的库"，避免跨账户误合并。
 * Passkey 同步型私钥作为 Entry 内容随整个备份加密，不再携带额外密钥包。
 */
object BackupCodec {
    @Serializable
    data class BackupPayload(
        val version: Int = 3,
        val entries: List<Entry> = emptyList(),
        @SerialName("purge_tombstones") val purgeTombstones: Map<String, Double> = emptyMap(),
        @SerialName("deletion_baseline") val deletionBaseline: com.vault.model.DeletionBaseline = com.vault.model.DeletionBaseline(),
        @SerialName("sync_meta") val syncMeta: SyncMeta = SyncMeta(),
        @SerialName("export_epoch") val exportEpoch: Double? = null,
        @SerialName("autofill_exclusions") val autofillExclusions: com.vault.model.AutofillExclusions = com.vault.model.AutofillExclusions(),

    )

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = true
    }

    /** 导出加密备份。entries 应包含活跃 + 墓碑全集；syncMeta 与导出时刻由调用方提供。 */
    fun exportTo(
        context: Context,
        uri: Uri,
        entries: List<Entry>,
        password: String,
        syncMeta: SyncMeta = SyncMeta(),
        purgeTombstones: Map<String, Double> = emptyMap(),
        autofillExclusions: com.vault.model.AutofillExclusions = com.vault.model.AutofillExclusions(),
        deletionBaseline: com.vault.model.DeletionBaseline = com.vault.model.DeletionBaseline(),
    ) {
        val data = encodeEncrypted(
            BackupPayload(
                entries = entries,
                purgeTombstones = purgeTombstones,
                deletionBaseline = deletionBaseline,
                syncMeta = syncMeta,
                exportEpoch = nowSeconds(),
                autofillExclusions = autofillExclusions.normalized(),
            ),
            password,
        )
        try {
            context.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                output.write(data)
                output.flush()
            } ?: throw FileNotFoundException("无法写入备份目标")
        } finally {
            data.fill(0)
        }
    }

    fun importFrom(context: Context, uri: Uri, password: String): BackupPayload {
        val raw = context.contentResolver.openInputStream(uri)?.use {
            it.readBytesLimited(MAX_VAULT_BYTES, "备份文件")
        }
            ?: throw FileNotFoundException("无法读取备份文件")
        return try {
            decodeEncrypted(raw, password)
        } finally {
            raw.fill(0)
        }
    }

    internal fun encodeEncrypted(payload: BackupPayload, password: String): ByteArray {
        require(payload.version in 2..3) { "不支持的备份版本" }
        require(BackupPasswordPolicy.isStrong(password)) {
            "导出口令至少 14 位并包含大小写字母、数字、符号中的三类"
        }
        val plaintext = json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray()
        val passwordBytes = password.encodeToByteArray()
        return try {
            PmvBackupCrypto.encrypt(plaintext, passwordBytes)
        } finally {
            plaintext.fill(0)
            passwordBytes.fill(0)
        }
    }

    internal fun decodeEncrypted(raw: ByteArray, password: String): BackupPayload {
        val plaintext = decryptBackup(raw, password)
        return try {
            json.decodeFromString(BackupPayload.serializer(), plaintext.decodeToString()).also { payload ->
                require(payload.version in 2..3) { "不支持的备份版本" }
            }
        } finally {
            plaintext.fill(0)
        }
    }

    /** 解密 V2 备份。结构损坏（CorruptFileError）统一归为"不是有效的加密备份文件"。 */
    private fun decryptBackup(raw: ByteArray, password: String): ByteArray {
        val utf8 = password.toByteArray(Charsets.UTF_8)
        return try {
            PmvBackupCrypto.decrypt(raw, utf8)
        } catch (e: VaultCrypto.DecryptError) {
            throw e
        } catch (_: VaultCrypto.CorruptFileError) {
            throw VaultCrypto.DecryptError("不是有效的加密备份文件")
        } finally {
            utf8.fill(0)
        }
    }
}
