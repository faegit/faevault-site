package com.vault.storage

import com.vault.model.*

/** Restore selected active entries as new changes; the current payload owns all security state. */
internal object VaultHistoryRestore {
    fun previewEntries(entries: List<Entry>): List<Entry> = entries.filter { it.deletedAt == null }.map {
        Entry(id = it.id, title = it.title, username = it.username, secretType = it.secretType, createdAt = it.createdAt, updatedAt = it.updatedAt)
    }

    fun plan(current: VaultPayload, historical: VaultPayload, ids: Set<String>, nowSeconds: Double): VaultPayload {
        require(ids.isNotEmpty()) { "请选择需要恢复的条目" }
        val selected = historical.entries.filter { it.deletedAt == null && it.id in ids }
        require(selected.size == ids.size) { "只能恢复历史快照中的有效条目" }
        require(selected.none { it.id in current.purgeTombstones }) { "已永久删除的条目不能从历史恢复" }
        require(selected.none { entry -> entry.secretType == SecretType.PASSKEY || entry.entryModules().any {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        } }) { "通行密钥条目暂不支持历史恢复" }
        val newest = (current.entries + current.trash + historical.entries + historical.trash).maxOfOrNull { it.updatedAt } ?: 0.0
        val timestamp = maxOf(nowSeconds, Math.nextUp(newest))
        require(timestamp.isFinite() && timestamp > newest) { "条目时间戳无效，无法安全恢复" }
        return current.copy(entries = current.entries.filterNot { it.id in ids } + selected.map { it.copy(updatedAt = timestamp, deletedAt = null) },
            trash = current.trash.filterNot { it.id in ids })
    }
}
