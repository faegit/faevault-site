package com.vault.model

import com.vault.passkeys.PasskeyMerge
import kotlinx.serialization.json.JsonArray

/** 库内业务操作（纯函数，输入旧 payload，输出新 payload），与桌面端 storage.py 对齐。 */
object VaultOps {
    /**
     * 密钥/密码版本自动收敛决策：返回 true 表示远端密钥版本更新、应采用远端。
     *
     * 优先按“密钥更新时间”（key_updated_at）比较；时间缺失/相等时退回
     * key_revision 计数；仍相等则保留本端（确定性行为，不弹人工选择）。
     */
    fun remoteKeyVersionNewer(
        localRevision: Int,
        localUpdatedAt: Double,
        remoteRevision: Int,
        remoteUpdatedAt: Double,
    ): Boolean {
        if (localUpdatedAt > 0.0 && remoteUpdatedAt > 0.0 && localUpdatedAt != remoteUpdatedAt) {
            return remoteUpdatedAt > localUpdatedAt
        }
        if (localUpdatedAt <= 0.0 && remoteUpdatedAt > 0.0) return true
        if (remoteUpdatedAt <= 0.0 && localUpdatedAt > 0.0) return false
        if (remoteRevision != localRevision) return remoteRevision > localRevision
        return false
    }

    /** 分叉合并时选择两端中“密钥/密码版本更新”的一端的 syncMeta（时间优先，其次 revision）。 */
    fun newerKeySyncMeta(local: VaultPayload, remote: VaultPayload): SyncMeta =        if (remoteKeyVersionNewer(
                local.syncMeta.keyRevision,
                local.syncMeta.keyUpdatedAt,
                remote.syncMeta.keyRevision,
                remote.syncMeta.keyUpdatedAt,
            )
        ) {
            remote.syncMeta
        } else {
            local.syncMeta
        }

    fun add(payload: VaultPayload, entry: Entry): VaultPayload {
        val now = nowSeconds()
        val normalized = entry.normalized(now).withCurrentLeakRevision(now)
        return payload.copy(entries = payload.entries + normalized)
    }

    fun update(payload: VaultPayload, updated: Entry): VaultPayload {
        val now = nowSeconds()
        var changed = false
        val new = payload.entries.map { e ->
            if (e.id != updated.id) {
                e
            } else if (updated.contentEquals(e)) {
                val leakCacheChanged = updated.leakCheckRevision != e.leakCheckRevision ||
                    updated.leakPwnedCount != e.leakPwnedCount ||
                    updated.leakCommonWeak != e.leakCommonWeak ||
                    updated.leakCheckedAt != e.leakCheckedAt
                if (!leakCacheChanged) {
                    e
                } else {
                    changed = true
                    updated.copy(updatedAt = e.updatedAt).withCurrentLeakRevision(now)
                }
            } else {
                changed = true
                val touched = updated.touch(now)
                val sameSecret = e.entrySecret() == updated.entrySecret()
                val hasFreshLeakResult = updated.leakCheckRevision == null &&
                    (updated.leakPwnedCount != null || updated.leakCommonWeak)
                if (sameSecret || hasFreshLeakResult) {
                    touched.withCurrentLeakRevision(now)
                } else {
                    touched.withoutLeakCache()
                }
            }
        }
        return if (changed) payload.copy(entries = new) else payload
    }

    /** 软删除：设置 deletedAt 并刷新 updatedAt，确保删除状态能通过 LWW 传播。 */
    fun delete(payload: VaultPayload, entryId: String): VaultPayload {
        val now = nowSeconds()
        val updated = payload.entries.map { e ->
            if (e.id == entryId && e.deletedAt == null) {
                val changedAt = monotonicTimestamp(e.updatedAt, now)
                e.copy(deletedAt = changedAt, updatedAt = changedAt)
            } else e
        }
        return payload.copy(entries = updated)
    }

    /** 批量软删除：一次遍历、一次 deletedAt 时间戳，避免逐条删除反复落盘。 */
    fun deleteMany(payload: VaultPayload, entryIds: Set<String>): VaultPayload {
        if (entryIds.isEmpty()) return payload
        val now = nowSeconds()
        var changed = false
        val updated = payload.entries.map { e ->
            if (e.id in entryIds && e.deletedAt == null) {
                changed = true
                val changedAt = monotonicTimestamp(e.updatedAt, now)
                e.copy(deletedAt = changedAt, updatedAt = changedAt)
            } else {
                e
            }
        }
        return if (changed) payload.copy(entries = updated) else payload
    }

/** 批量调整条目标签。mode=move 表示替换标签，否则表示追加标签。 */
    fun updateEntryTags(payload: VaultPayload, entryIds: Set<String>, tag: String, mode: String): VaultPayload {
        return updateEntryTags(payload, entryIds, listOf(tag), mode)
    }

    fun updateEntryTags(payload: VaultPayload, entryIds: Set<String>, tags: List<String>, mode: String): VaultPayload {
        val cleanTags = tags.map(String::trim).filter(String::isNotEmpty).distinct()
        if (entryIds.isEmpty() || cleanTags.isEmpty()) return payload
        var changed = false
        val updated = payload.entries.map { e ->
            // 墓碑不可编辑；Passkey 现在也允许改标签（纯元数据，密钥材料仍只由
            // Credential Manager 写），此前在这里一并拦掉。
            if (e.id !in entryIds || e.deletedAt != null) return@map e
            val newTags = when (mode) {
                "move" -> cleanTags
                else -> e.tags + cleanTags.filterNot { it in e.tags }
            }
            if (newTags == e.tags) e else {
                changed = true
                e.copy(tags = newTags).touch()
            }
        }
        return if (changed) payload.copy(entries = updated) else payload
    }

    /** 从回收站恢复：清除墓碑并刷新 updatedAt，确保恢复状态能通过 LWW 传播。 */
    fun restore(payload: VaultPayload, entryId: String): VaultPayload {
        val now = nowSeconds()
        val updated = payload.entries.map { e ->
            if (e.id == entryId && e.deletedAt != null) {
                e.copy(deletedAt = null, updatedAt = monotonicTimestamp(e.updatedAt, now))
            } else e
        }
        return payload.copy(entries = updated)
    }

    /** 批量恢复回收站条目，不改写条目编辑时间 updatedAt。 */
    fun restoreMany(payload: VaultPayload, entryIds: Set<String>): VaultPayload {
        if (entryIds.isEmpty()) return payload
        val now = nowSeconds()
        val updated = payload.entries.map { e ->
            if (e.id in entryIds && e.deletedAt != null) {
                e.copy(deletedAt = null, updatedAt = monotonicTimestamp(e.updatedAt, now))
            } else e
        }
        return payload.copy(entries = updated)
    }

    /** 物理彻底删除单条墓碑条目。 */
    fun purge(payload: VaultPayload, entryId: String): VaultPayload {
        val target = payload.entries.firstOrNull { it.id == entryId && it.deletedAt != null } ?: return payload
        val purgedAt = monotonicTimestamp(target.updatedAt)
        return payload.copy(
            entries = payload.entries.filterNot { it.id == entryId && it.deletedAt != null },
            purgeTombstones = recordPurge(payload.purgeTombstones, target.id, purgedAt),
        )
    }

    /** 物理彻底删除多条墓碑条目。 */
    fun purgeMany(payload: VaultPayload, entryIds: Set<String>): VaultPayload {
        if (entryIds.isEmpty()) return payload
        val purged = payload.entries.filter { it.id in entryIds && it.deletedAt != null }
        if (purged.isEmpty()) return payload
        val purgedAt = monotonicTimestamp(purged.maxOf { it.updatedAt })
        return payload.copy(
            entries = payload.entries.filterNot { it.id in entryIds && it.deletedAt != null },
            purgeTombstones = recordPurges(payload.purgeTombstones, purged.map { it.id }, purgedAt),
        )
    }

    /** 物理彻底删除全部墓碑条目（清空回收站）。 */
    fun purgeAll(payload: VaultPayload): VaultPayload {
        val purged = payload.entries.filter { it.deletedAt != null }
        if (purged.isEmpty()) return payload
        val purgedAt = monotonicTimestamp(purged.maxOf { it.updatedAt })
        return payload.copy(
            entries = payload.entries.filterNot { it.deletedAt != null },
            purgeTombstones = recordPurges(payload.purgeTombstones, purged.map { it.id }, purgedAt),
        )
    }

    /** 打开时清理超期回收站条目，删除记录持续保留直到所有设备确认。 */
    fun purgeExpired(payload: VaultPayload, retentionDays: Int): VaultPayload {
        val cutoff = nowSeconds() - retentionDays * 86400.0
        val remain = payload.entries.filterNot { e ->
            val d = e.deletedAt ?: return@filterNot false
            d < cutoff
        }
        if (remain.size == payload.entries.size) return payload
        val purged = payload.entries.filter { it.deletedAt != null && it.deletedAt < cutoff }
        val purgedAt = monotonicTimestamp(purged.maxOf { it.updatedAt })
        val cleanedTombstones = payload.purgeTombstones
        return payload.copy(
            entries = remain,
            purgeTombstones = recordPurges(cleanedTombstones, purged.map { it.id }, purgedAt),
        )
    }

    /** 活跃条目（未墓碑）—— UI 列表 / 搜索 / 排序 默认输入。 */
    fun alive(payload: VaultPayload): List<Entry> =
        payload.entries.filter { it.deletedAt == null }

    /** 墓碑条目（回收站）—— TrashScreen 数据源。 */
    fun trashed(payload: VaultPayload): List<Entry> =
        payload.entries.filter { it.deletedAt != null }

    /**
     * 自动清理悬空动态码绑定：登录条目指向的独立动态码条目已删除 / 已进回收站 /
     * 不再携带动态码时，解除该绑定。不改 updatedAt，避免本地修复在同步层伪装成用户编辑。
     */
    fun repairOtpBindings(payload: VaultPayload): VaultPayload {
        val liveOtpIds = payload.entries.asSequence()
            .filter { it.deletedAt == null && it.secretType == SecretType.OTP && it.hasOtp() }
            .mapTo(HashSet()) { it.id }
        var changed = false
        val repaired = payload.entries.map { e ->
            val boundId = e.otpBindingId()
            if (boundId != null && boundId !in liveOtpIds) {
                changed = true
                e.withoutOtpBinding()
            } else e
        }
        return if (changed) payload.copy(entries = repaired) else payload
    }

    /** 预排序：用缓存的拼音 sortKey 让中文按拼音序排，"苹果" 与 "apple" 落到 P / A 各自字母段。 */
    fun sortedByTitle(entries: List<Entry>): List<Entry> =
        entries.sortedBy { it.titleSortKey }

    /** 在已排序列表上做 filter；保留输入顺序，无需重新排序。 */
    fun filterSorted(sortedEntries: List<Entry>, query: String): List<Entry> =
        if (query.isEmpty()) sortedEntries
        else sortedEntries.filter { it.matches(query) }

    fun renameTag(payload: VaultPayload, oldTag: String, newTag: String): Pair<VaultPayload, Int> {
        var affected = 0
        val updated = payload.entries.map { e ->
            // 墓碑条目不改 tags：它们已不可编辑，且改了反而会被同步层视为"复活后修改"
            if (e.deletedAt != null || oldTag !in e.tags) e else {
                val renamed = mutableListOf<String>()
                for (t in e.tags) {
                    val v = if (t == oldTag) newTag else t
                    if (v !in renamed) renamed.add(v)
                }
                affected++
                e.copy(tags = renamed).touch()
            }
        }
        return payload.copy(entries = updated) to affected
    }

    // --- 合并 ---

    enum class MergeAction { OVERWRITE, KEEP_BOTH, SKIP, CANCEL }

    data class MergeStats(
        var added: Int = 0,
        var overwritten: Int = 0,
        var keptBoth: Int = 0,
        var skipped: Int = 0,
        var identical: Int = 0,
        var passkeyConflicts: Int = 0,
        var cancelled: Boolean = false,
    )

    /**
     * 与桌面端 Vault.merge 对齐：同 dedupKey 内容不同 → 由 resolver 决定。
     *
     * 当前阶段（Step 3）：墓碑参与逻辑非常有限——本地墓碑保持原样，incoming 中的墓碑被忽略
     * （由对端的 dedupKey 与本地活跃条目误碰可能引发覆盖事故）。Step 5 将整体重写为
     * 按 id 的 LWW 合并，墓碑会真正参与跨端删除传播。
     */
    fun merge(
        payload: VaultPayload,
        incoming: List<Entry>,
        resolver: (existing: Entry, incoming: Entry) -> MergeAction,
    ): Pair<VaultPayload, MergeStats> {
        val stats = MergeStats()
        val (aliveLocal, tombstonesLocal) = payload.entries.partition { it.deletedAt == null }
        val byKey: MutableMap<Triple<String, String, String>, Entry> =
            aliveLocal.associateBy { it.dedupKey() }.toMutableMap()
        val list = aliveLocal.toMutableList()
        val idToIndex = HashMap<String, Int>(list.size * 2)
        list.forEachIndexed { i, e -> idToIndex[e.id] = i }
        for (incRaw in incoming) {
            if (incRaw.deletedAt != null) { stats.skipped++; continue }
            var inc = incRaw.normalized(nowSeconds())
            val key = inc.dedupKey()
            var cur = byKey[key]
            if (cur == null) {
                list.add(inc); idToIndex[inc.id] = list.lastIndex; byKey[key] = inc; stats.added++; continue
            }
            val passkeys = mergeEntryPasskeys(cur, inc)
            cur = passkeys.local
            inc = passkeys.remote
            if (passkeys.hasKeyConflict) stats.passkeyConflicts++
            val currentIndex = idToIndex[cur.id] ?: -1
            if (currentIndex >= 0) list[currentIndex] = cur
            byKey[key] = cur
            if (cur.sameContent(inc)) {
                val mergedLeakCache = cur.withImportedLeakCache(inc)
                if (mergedLeakCache == cur) {
                    stats.identical++
                } else {
                    val idx = idToIndex[cur.id] ?: -1
                    if (idx >= 0) list[idx] = mergedLeakCache
                    byKey[key] = mergedLeakCache
                    stats.overwritten++
                }
                continue
            }
            when (resolver(cur, inc)) {
                MergeAction.CANCEL -> { stats.cancelled = true; break }
                MergeAction.OVERWRITE -> {
                    val replaced = inc.copy(id = cur.id, createdAt = cur.createdAt).touch()
                    val idx = idToIndex[cur.id] ?: -1
                    if (idx >= 0) list[idx] = replaced
                    byKey[key] = replaced
                    stats.overwritten++
                }
                MergeAction.KEEP_BOTH -> { list.add(inc); idToIndex[inc.id] = list.lastIndex; stats.keptBoth++ }
                MergeAction.SKIP -> stats.skipped++
            }
        }
        return payload.copy(entries = list + tombstonesLocal) to stats
    }

    // --- LWW 合并（Sync v2，spec/SYNC_V2.md §5）---

    enum class ConflictChoice { KEEP_LOCAL, KEEP_REMOTE, KEEP_BOTH }

    data class LwwMergeStats(
        var added: Int = 0,
        var takeRemote: Int = 0,
        var takeLocal: Int = 0,
        var keptBoth: Int = 0,
        var identical: Int = 0,
        var conflicts: Int = 0,
        var purged: Int = 0,
        var purgeSkipped: Int = 0,
        var coalesced: Int = 0,
        var passkeyConflicts: Int = 0,
    )

    /**
     * Last-Writer-Wins 合并（spec/SYNC_V2.md）：按 id 匹配，按 updatedAt 比较；
     * 同秒不同内容 → onConflict 决定。墓碑参与同步（删除可传播 / 复活）。
     *
     * @param incomingExportEpoch 远端文件的 exportEpoch（VaultPayload.exportEpoch）。
     *   仅作为格式兼容参数保留；合并只比较每条 Entry 自己的 updatedAt，不用文件导出时间
     *   改写条目时间。
     */
    fun mergeLww(
        local: VaultPayload,
        incoming: List<Entry>,
        incomingExportEpoch: Double? = null,
        localNow: Double = nowSeconds(),
        incomingPurgeTombstones: Map<String, Double> = emptyMap(),
        incomingExclusions: AutofillExclusions = AutofillExclusions(),
        incomingDeletionBaseline: DeletionBaseline = DeletionBaseline(),
        onConflict: (Entry, Entry) -> ConflictChoice = { _, _ -> ConflictChoice.KEEP_BOTH },
    ): Pair<VaultPayload, LwwMergeStats> {
        DeletionBaseline.requireCompatible(local.deletionBaseline, incomingDeletionBaseline)
        val mergedBaseline = DeletionBaseline.merge(local.deletionBaseline, incomingDeletionBaseline)
        val stats = LwwMergeStats()
        @Suppress("UNUSED_VARIABLE")
        val ignoredExportEpoch = incomingExportEpoch
        @Suppress("UNUSED_VARIABLE")
        val ignoredLocalNow = localNow

        val mergedPurges = local.purgeTombstones.toMutableMap()
        for ((id, purgedAt) in incomingPurgeTombstones) {
            if (purgedAt > (mergedPurges[id] ?: 0.0)) mergedPurges[id] = purgedAt
        }
        val byId = local.entries.associateBy { it.id }.toMutableMap()

        for ((id, purgedAt) in mergedPurges.toMap()) {
            val cur = byId[id]
            if (cur != null) {
                if (purgedAt > cur.updatedAt) {
                    byId.remove(id)
                    stats.purged++
                } else {
                    mergedPurges.remove(id)
                    stats.purgeSkipped++
                }
            }
        }

        for (incRaw in incoming) {
            var inc = incRaw
            val purgeAt = mergedPurges[inc.id]
            if (purgeAt != null && purgeAt > inc.updatedAt) {
                stats.purgeSkipped++
                continue
            }
            if (purgeAt != null) mergedPurges.remove(inc.id)
            var cur = byId[inc.id]
            if (cur == null) {
                val duplicate = byId.values.firstOrNull { packageOnlyDuplicate(it, inc) }
                if (duplicate != null) {
                    val packageName = duplicate.associatedAppPackage().ifBlank { inc.associatedAppPackage() }
                    byId[duplicate.id] = duplicate.copy(targetApp = packageName)
                    val purgedAt = maxOf(nowSeconds(), duplicate.updatedAt, inc.updatedAt) + 0.001
                    mergedPurges[inc.id] = maxOf(mergedPurges[inc.id] ?: 0.0, purgedAt)
                    stats.coalesced++
                    continue
                }
                byId[inc.id] = inc
                stats.added++
                continue
            }
            val passkeys = mergeEntryPasskeys(cur, inc)
            cur = passkeys.local
            inc = passkeys.remote
            if (passkeys.hasKeyConflict) stats.passkeyConflicts++
            when {
                inc.updatedAt > cur.updatedAt -> {
                    byId[inc.id] = inc
                    stats.takeRemote++
                }
                inc.updatedAt < cur.updatedAt -> {
                    byId[cur.id] = cur
                    stats.takeLocal++
                }
                else -> {
                    // updatedAt 完全相等
                    if (entriesEffectivelyEqual(cur, inc)) {
                        val mergedLeakCache = cur.withImportedLeakCache(inc)
                        if (mergedLeakCache == cur) {
                            stats.identical++
                        } else {
                            byId[cur.id] = mergedLeakCache
                            stats.takeRemote++
                        }
                        continue
                    }
                    stats.conflicts++
                    when (onConflict(cur, inc)) {
                        ConflictChoice.KEEP_LOCAL -> {
                            byId[cur.id] = cur
                            stats.takeLocal++
                        }
                        ConflictChoice.KEEP_REMOTE -> {
                            byId[inc.id] = inc
                            stats.takeRemote++
                        }
                        ConflictChoice.KEEP_BOTH -> {
                            val dup = inc.copy(id = java.util.UUID.randomUUID().toString())
                            byId[dup.id] = dup
                            stats.keptBoth++
                        }
                    }
                }
            }
        }

        return local.copy(entries = byId.values.toList(), purgeTombstones = mergedPurges, deletionBaseline = mergedBaseline,
            autofillExclusions = local.autofillExclusions.merge(incomingExclusions)) to stats
    }

    // --- 局域网导入（内容身份匹配，spec/局域网导入与安全传输方案.md §14/§15）---

    enum class ImportChoice { KEEP_LOCAL, KEEP_IMPORTED, KEEP_BOTH }

    /** 冲突条目：imported 为导入版本，local 为本地版本；choice 由用户逐条决定。 */
    data class ImportConflict(
        val imported: Entry,
        val local: Entry,
        var choice: ImportChoice = ImportChoice.KEEP_LOCAL,
    )

    data class ImportPlan(
        val newEntries: List<Entry>,
        val conflicts: List<ImportConflict>,
        val skippedIdentical: Int,
        val unsupported: List<String>,   // 不支持导入的条目标题（如 passkey）
    )

    data class ImportStats(
        var addedNew: Int = 0,
        var takeImported: Int = 0,
        var keepLocal: Int = 0,
        var keepBoth: Int = 0,
    )

    private data class ImportIdentity(val secretType: String, val title: String, val username: String, val url: String)

    private fun Entry.importIdentityKey(): ImportIdentity = ImportIdentity(
        secretType = secretType,
        title = title.trim().lowercase(),
        username = username.trim().lowercase(),
        url = url.trim().lowercase(),
    )

    /**
     * 导入规划：按内容身份匹配，绝不静默覆盖高敏感字段。
     *  - 身份键 = 类型 + 标题 + 用户名 + 网站；标题相同但账号/网站不同 → 视为新条目；
     *  - 同身份且内容完全相同 → 自动跳过（不产生重复）；
     *  - 同身份但内容不同 → 冲突，由用户在预览界面逐条决定；
     *  - 本地墓碑条目不参与匹配（导入条目只落活跃区）；
     *  - Passkey 无法重建（设备绑定），记入 unsupported 跳过。
     */
    fun planImport(local: VaultPayload, incoming: List<Entry>, now: Double = nowSeconds()): ImportPlan {
        val aliveLocal = local.entries.filter { it.deletedAt == null }
        val byIdentity = HashMap<ImportIdentity, MutableList<Entry>>()
        for (e in aliveLocal) byIdentity.getOrPut(e.importIdentityKey()) { mutableListOf() }.add(e)

        val newEntries = mutableListOf<Entry>()
        val conflicts = mutableListOf<ImportConflict>()
        val unsupported = mutableListOf<String>()
        var skippedIdentical = 0

        for (raw in incoming) {
            if (raw.secretType == SecretType.PASSKEY) {
                unsupported.add(raw.title.ifBlank { "Passkey" })
                continue
            }
            val inc = raw.normalized(now)
            val matches = byIdentity[inc.importIdentityKey()].orEmpty()
            if (matches.any { it.contentEquals(inc) }) {
                skippedIdentical++
                continue
            }
            val conflict = matches.firstOrNull()
            if (conflict != null) conflicts.add(ImportConflict(imported = inc, local = conflict))
            else newEntries.add(inc)
        }
        return ImportPlan(newEntries, conflicts, skippedIdentical, unsupported)
    }

    /** 应用导入决定，返回新 payload 与统计。不改变任何墓碑。 */
    fun applyImportPlan(local: VaultPayload, plan: ImportPlan, now: Double = nowSeconds()): Pair<VaultPayload, ImportStats> {
        if (plan.newEntries.isEmpty() && plan.conflicts.isEmpty()) return local to ImportStats()
        val stats = ImportStats()
        val alive = local.entries.filter { it.deletedAt == null }
        val tombstones = local.entries.filter { it.deletedAt != null }
        val list = alive.toMutableList()

        for (entry in plan.newEntries) {
            list.add(entry)
            stats.addedNew++
        }
        for (conflict in plan.conflicts) {
            val imported = conflict.imported
            when (conflict.choice) {
                ImportChoice.KEEP_LOCAL -> stats.keepLocal++
                ImportChoice.KEEP_IMPORTED -> {
                    // 保留本地 id 与创建时间，仅以导入版本覆盖内容
                    val replaced = imported.copy(id = conflict.local.id, createdAt = conflict.local.createdAt).touch(now)
                    val idx = list.indexOfFirst { it.id == conflict.local.id }
                    if (idx >= 0) list[idx] = replaced else list.add(replaced)
                    stats.takeImported++
                }
                ImportChoice.KEEP_BOTH -> {
                    list.add(imported)
                    stats.keepBoth++
                }
            }
        }
        return local.copy(entries = list + tombstones) to stats
    }

    private data class PasskeyEnrichedEntries(
        val local: Entry,
        val remote: Entry,
        val hasKeyConflict: Boolean,
    )

    private fun mergeEntryPasskeys(local: Entry, remote: Entry): PasskeyEnrichedEntries {
        val localModules = local.entryModules()
        val remoteModules = remote.entryModules()
        val localPasskeys = localModules.filter {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        }
        val remotePasskeys = remoteModules.filter {
            EntryModules.primitive(it["type"]) == ModuleType.PASSKEY
        }
        if (localPasskeys.isEmpty() && remotePasskeys.isEmpty()) {
            return PasskeyEnrichedEntries(local, remote, false)
        }
        val merged = PasskeyMerge.merge(localPasskeys, remotePasskeys)
        fun enriched(entry: Entry, modules: List<kotlinx.serialization.json.JsonObject>): Entry {
            val ordinary = modules.filter {
                EntryModules.primitive(it["type"]) != ModuleType.PASSKEY
            }
            return entry.copy(
                fields = entry.fields + (
                    EntryModules.FIELD_KEY to JsonArray(ordinary + merged.modules)
                    ),
            )
        }
        return PasskeyEnrichedEntries(
            local = enriched(local, localModules),
            remote = enriched(remote, remoteModules),
            hasKeyConflict = merged.hasKeyConflict,
        )
    }

    private fun packageOnlyDuplicate(a: Entry, b: Entry): Boolean {
        val aPackage = a.associatedAppPackage()
        val bPackage = b.associatedAppPackage()
        if (a.id == b.id || a.deletedAt != null || b.deletedAt != null) return false
        if (a.secretType != SecretType.LOGIN || b.secretType != SecretType.LOGIN) return false
        if (aPackage.isNotBlank() == bPackage.isNotBlank()) return false
        return a.title == b.title &&
            a.username == b.username &&
            a.password == b.password &&
            a.url == b.url &&
            a.notes == b.notes &&
            a.sortedTags == b.sortedTags &&
            a.fieldsWithoutTargetApp == b.fieldsWithoutTargetApp
    }

    private fun Entry.withImportedLeakCache(incoming: Entry): Entry {
        val incomingHasCache = incoming.leakPwnedCount != null || incoming.leakCommonWeak
        if (!incomingHasCache) return this
        val sameCache = leakPwnedCount == incoming.leakPwnedCount &&
            leakCommonWeak == incoming.leakCommonWeak &&
            leakCheckedAt == incoming.leakCheckedAt
        if (sameCache && hasCurrentLeakCache()) return this
        return copy(
            leakPwnedCount = incoming.leakPwnedCount,
            leakCommonWeak = incoming.leakCommonWeak,
            leakCheckedAt = incoming.leakCheckedAt,
        ).withCurrentLeakRevision()
    }

    /** 同秒且内容（含标题/账号/墓碑状态）一致 = 无实际冲突，可安全跳过。 */
    private fun entriesEffectivelyEqual(a: Entry, b: Entry): Boolean {
        val aDeleted = a.deletedAt != null
        val bDeleted = b.deletedAt != null
        if (aDeleted != bDeleted) return false
        return a.contentEquals(b)
    }

    // --- 库内去重 ---

    data class DedupStats(var exactMerged: Int = 0, var pwResolved: Int = 0, var pwSkipped: Int = 0)

    data class DedupScan(val exact: Int, val pwConflict: Int)

    fun scanDuplicates(payload: VaultPayload): DedupScan {
        // 去重仅看活跃条目；墓碑条目可能与活跃条目同名同用户名，但它们不应参与
        val groups = payload.entries
            .filter { it.deletedAt == null && it.secretType == SecretType.LOGIN }
            .groupBy { it.dedupKey() }
        var exact = 0; var conflict = 0
        for (dupes in groups.values) {
            if (dupes.size <= 1) continue
            val first = dupes[0]
            val sameExceptPw = dupes.drop(1).all { first.sameExceptPassword(it) }
            if (sameExceptPw) {
                if (dupes.map { it.password }.toSet().size == 1) exact++
                else conflict++
            } else exact++
        }
        return DedupScan(exact, conflict)
    }

    fun duplicateGroups(payload: VaultPayload): List<List<Entry>> =
        payload.entries
            .filter { it.deletedAt == null && it.secretType == SecretType.LOGIN }
            .groupBy { it.dedupKey() }
            .values
            .filter { it.size > 1 }
            .map { it.sortedByDescending(Entry::updatedAt) }
            .sortedByDescending { it.size }

    /**
     * @param pwResolver 接收一组密码冲突的重复条目，返回选中条目（其密码生效），返回 null 跳过。
     */
    fun dedupEntries(
        payload: VaultPayload,
        pwResolver: ((List<Entry>) -> Entry?)? = null,
    ): Pair<VaultPayload, DedupStats> {
        // 只处理活跃条目；墓碑条目原样保留
        val (alive, tombstones) = payload.entries.partition { it.deletedAt == null }
        val groups = alive
            .filter { it.secretType == SecretType.LOGIN }
            .groupBy { it.dedupKey() }
        val dupGroups = groups.filter { it.value.size > 1 }
        if (dupGroups.isEmpty()) return payload to DedupStats()

        val stats = DedupStats()
        val toRemoveKeys = mutableSetOf<Triple<String, String, String>>()
        val replacements = mutableListOf<Entry>()

        for ((key, dupes) in dupGroups) {
            val first = dupes[0]
            val sameFields = dupes.drop(1).all { first.sameExceptPassword(it) }
            val passwords = dupes.map { it.password }.toSet()
            if (!sameFields || passwords.size == 1) {
                replacements.add(mergeGroup(dupes, password = null))
                toRemoveKeys.add(key)
                stats.exactMerged++
            } else {
                if (pwResolver == null) { stats.pwSkipped++; continue }
                val chosen = pwResolver(dupes)
                if (chosen == null) { stats.pwSkipped++; continue }
                replacements.add(mergeGroup(dupes, password = chosen.password))
                toRemoveKeys.add(key)
                stats.pwResolved++
            }
        }
        val kept = alive.filterNot {
            it.secretType == SecretType.LOGIN && it.dedupKey() in toRemoveKeys
        }
        return payload.copy(entries = kept + replacements + tombstones) to stats
    }

    private fun mergeGroup(dupes: List<Entry>, password: String?): Entry {
        val sorted = dupes.sortedByDescending { it.updatedAt }
        val winner = sorted.first()
        val seen = LinkedHashSet<String>()
        for (e in sorted) for (t in e.tags) if (t.isNotEmpty()) seen.add(t)
        val mergedFields = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        for (e in sorted.reversed()) mergedFields.putAll(e.fields)
        return winner.copy(
            tags = seen.toList(),
            fields = mergedFields,
            createdAt = dupes.minOf { it.createdAt },
            updatedAt = dupes.maxOf { it.updatedAt },
            id = dupes.minByOrNull { it.createdAt }?.id ?: winner.id,
            password = password ?: winner.password,
        )
    }

    // --- 同服务条目检测 ---

    data class SameServiceGroup(
        val serviceKey: String,
        val entries: List<Entry>,
    )

    private fun Entry.serviceDomain(): String {
        val domain = url.trim().removePrefix("https://").removePrefix("http://")
            .removePrefix("www.").split("/").first().split("?")[0].trim().lowercase()
        if (domain.isNotBlank()) return domain
        if (targetApp.isNotBlank()) return targetApp.trim().lowercase()
        return title.trim().lowercase()
    }

    fun scanSameService(payload: VaultPayload): List<SameServiceGroup> {
        val alive = payload.entries.filter {
            it.deletedAt == null &&
                it.secretType == SecretType.LOGIN &&
                it.serviceDomain().isNotBlank()
        }
        val groups = alive.groupBy { it.serviceDomain() }
            .filter { it.value.size > 1 }
            .map { (key, entries) -> SameServiceGroup(key, entries.sortedByDescending(Entry::updatedAt)) }
            .sortedByDescending { it.entries.size }
        return groups
    }

    fun mergeEntries(entries: List<Entry>, resolvedTitle: String, resolvedPassword: String, resolvedUsername: String = ""): Entry {
        val sorted = entries.sortedByDescending { it.updatedAt }
        val winner = sorted.first()
        val seen = LinkedHashSet<String>()
        for (e in sorted) for (t in e.tags) if (t.isNotEmpty()) seen.add(t)
        val mergedFields = linkedMapOf<String, kotlinx.serialization.json.JsonElement>()
        for (e in sorted.reversed()) mergedFields.putAll(e.fields)
        return winner.copy(
            title = resolvedTitle.ifBlank { winner.title },
            username = if (resolvedUsername.isNotBlank()) resolvedUsername
                       else entries.map { it.username }.firstOrNull { it.isNotBlank() } ?: winner.username,
            url = entries.map { it.url }.firstOrNull { it.isNotBlank() } ?: winner.url,
            targetApp = entries.map { it.targetApp }.firstOrNull { it.isNotBlank() } ?: winner.targetApp,
            password = resolvedPassword,
            tags = seen.toList(),
            fields = mergedFields,
            createdAt = entries.minOf { it.createdAt },
            updatedAt = nowSeconds(),
            id = entries.minByOrNull { it.createdAt }?.id ?: winner.id,
        )
    }

    private fun recordPurge(source: Map<String, Double>, entryId: String, purgedAt: Double = nowSeconds()): Map<String, Double> {
        val current = source[entryId] ?: 0.0
        return source + (entryId to maxOf(current, purgedAt))
    }

    private fun recordPurges(source: Map<String, Double>, entryIds: Collection<String>, purgedAt: Double = nowSeconds()): Map<String, Double> {
        if (entryIds.isEmpty()) return source
        val out = source.toMutableMap()
        for (id in entryIds) {
            out[id] = maxOf(out[id] ?: 0.0, purgedAt)
        }
        return out
    }

    /**
     * 谱系分叉时的合并结果：条目按 LWW 合并，密钥版本取两端较新的一端。
     *
     * [mergeLww] 返回本地副本，其 [SyncMeta] 恒为本地值。分叉合并必须单独把密钥版本
     * 收敛到较新的一端，否则本端刚轮换的主密码会被远端的旧版本覆盖。
     * 主机与客户端两条 DIVERGED 路径共用本函数，避免再次出现一侧漏收敛。
     */
    fun mergeDiverged(
        local: VaultPayload,
        remote: VaultPayload,
        onConflict: (Entry, Entry) -> ConflictChoice = { _, _ -> ConflictChoice.KEEP_BOTH },
    ): Pair<VaultPayload, LwwMergeStats> {
        val (merged, stats) = mergeLww(
            local = local,
            incoming = remote.entries,
            incomingExportEpoch = remote.exportEpoch,
            incomingPurgeTombstones = remote.purgeTombstones,
            incomingExclusions = remote.autofillExclusions,
            incomingDeletionBaseline = remote.deletionBaseline,
            onConflict = onConflict,
        )
        return merged.copy(syncMeta = newerKeySyncMeta(local, remote)) to stats
    }
}
