package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * 编解码公共件（PMVE 复用）。
 * 旧格式（PMV1/2/3）编解码已全部移除，视为历史遗留。
 */
object VaultCodec {
    val json = Json {
        ignoreUnknownKeys = true   // 桌面端新增字段不致崩溃
        encodeDefaults = true      // 与 Python 全字段输出对齐
        explicitNulls = true       // deleted_at: null 显式保留
    }
}

/** V2 payload（仅 password/notes/fields），会话条目存储仍在复用。 */
@Serializable
internal data class V2EntryPayload(
    val password: String = "",
    val notes: String = "",
    val fields: Map<String, JsonElement> = emptyMap(),
    @SerialName("blob_refs") val blobRefs: Map<Int, String> = emptyMap(),
) {
    companion object {
        fun fromEntry(e: Entry): V2EntryPayload = V2EntryPayload(
            password = e.password,
            notes = e.notes,
            fields = e.fields,
        )
    }
}
