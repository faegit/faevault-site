package com.vault.storage

import com.vault.security.SecurePreferences
import android.content.Context
import com.vault.security.BiometricVault
import com.vault.security.VaultNameScope
import java.io.File

/**
 * 多账户注册表：管理 filesDir/vaults/ 下的多个 .pmv 账户，并记住当前选中的账户名。
 *
 * - 账户名即文件名（去扩展名），合法字符：中英文 / 数字 / _ -，长度 1..40
 *
 * 删除流程（2.3.3+）改为软删除：
 *  - [markForDeletion] 仅在 SharedPreferences 中登记 deletedAt 时间戳，物理文件保留
 *  - 标记后 [list] / [current] 不再展示该账户，但 [listTrashed] 仍可见
 *  - [restoreFromDeletion] 清掉标记，账户回到正常列表
 *  - [purgeExpired] 在解锁/进入设置等时机扫描，对超过 retentionDays 的账户做真正物理删除
 */
class VaultRegistry(private val context: Context) {

    data class Snapshot(
        val vaults: List<String>,
        val trashedVaults: Map<String, Long>,
        val currentVault: String?,
    )

    private val prefs = SecurePreferences.get(context, PREF)
    init { VaultNameScope.load(context) }
    private val vaultsDir: File get() = File(context.filesDir, "vaults").apply { mkdirs() }

    /** 列出全部可见账户名（按字母序，排除已标记软删除的）。 */
    fun list(): List<String> {
        val trashed = trashedMap().keys
        return vaultsDir
            .listFiles { f -> f.isFile && f.name.endsWith(".pmv") }
            ?.map { it.nameWithoutExtension }
            ?.filter { it !in trashed }
            ?.sorted()
            ?: emptyList()
    }

    /**
     * 启动状态的一致性快照：账户目录与加密偏好各读取一次，避免 ViewModel 初始化时
     * 为列表、回收站、当前账户和 phase 重复扫描目录、重复解密同一字段。
     */
    fun snapshot(): Snapshot {
        val trashed = trashedMap()
        val files = vaultsDir
            .listFiles { file -> file.isFile && file.name.endsWith(".pmv") }
            .orEmpty()
        val existingNames = files.asSequence().map { it.nameWithoutExtension }.toSet()
        val visible = existingNames.asSequence()
            .filterNot(trashed::containsKey)
            .sorted()
            .toList()
        val visibleTrash = trashed.filterKeys(existingNames::contains)
        val pinned = prefs.getString(KEY_CURRENT, null)
        val current = pinned?.takeIf { it in visible } ?: visible.firstOrNull()
        return Snapshot(visible, visibleTrash, current)
    }

    /** 当前选中账户；若无则返回首个账户或 null。软删除账户不算 current。 */
    fun current(): String? {
        val trashed = trashedMap().keys
        val pinned = prefs.getString(KEY_CURRENT, null)
        if (pinned != null && pinned !in trashed && fileFor(pinned).exists()) return pinned
        return list().firstOrNull()
    }

    fun setCurrent(name: String) {
        require(fileFor(name).exists()) { "账户 $name 不存在" }
        require(name !in trashedMap().keys) { "账户 $name 已在回收站" }
        prefs.edit().putString(KEY_CURRENT, name).apply()
    }

    fun fileFor(name: String): File = File(vaultsDir, "$name.pmv")
    fun tmpFor(name: String): File = File(vaultsDir, "$name.pmv.tmp")
    fun bakFor(name: String): File = File(vaultsDir, "$name.pmv.bak")

    fun exists(name: String): Boolean = fileFor(name).exists() && name !in trashedMap().keys

    /** 校验账户名是否合法（不检查重复）。 */
    fun isValidName(name: String): Boolean {
        if (name.isEmpty() || name.length > 40) return false
        return name.all { it.isLetterOrDigit() || it == '_' || it == '-' || it in '一'..'鿿' }
    }

    /** 重命名账户文件（含 .bak）。会修改 currentVault 指针。 */
    fun rename(old: String, new: String) {
        require(isValidName(new)) { "账户名不合法" }
        require(!fileFor(new).exists()) { "账户 $new 已存在" }
        val oldFile = fileFor(old)
        require(oldFile.exists()) { "账户 $old 不存在" }
        require(old !in trashedMap().keys) { "回收站账户请先恢复再重命名" }
        require(VaultNameScope.prepareRename(context, old, new)) { "无法保存账户设置身份" }
        if (!oldFile.renameTo(fileFor(new))) {
            VaultNameScope.releaseName(context, new)
            error("无法重命名账户文件")
        }
        if (!VaultNameScope.releaseName(context, old)) {
            check(fileFor(new).renameTo(oldFile)) { "账户身份保存失败且文件回滚失败" }
            VaultNameScope.releaseName(context, new)
            error("无法释放旧账户名")
        }
        if (bakFor(old).exists()) bakFor(old).renameTo(bakFor(new))
        if (prefs.getString(KEY_CURRENT, null) == old) {
            prefs.edit().putString(KEY_CURRENT, new).apply()
        }
    }

    // ============ 软删除 / 回收站 ============

    /** 软删除：仅登记 deletedAt 时间戳，物理文件保留；若是当前账户则清空指针。 */
    fun markForDeletion(name: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        if (!fileFor(name).exists()) return false
        val map = trashedMap().toMutableMap()
        map[name] = nowMs
        writeTrashed(map)
        if (prefs.getString(KEY_CURRENT, null) == name) {
            prefs.edit().remove(KEY_CURRENT).apply()
        }
        return true
    }

    /** 从回收站恢复账户：清除时间戳即可。 */
    fun restoreFromDeletion(name: String): Boolean {
        val map = trashedMap().toMutableMap()
        val removed = map.remove(name) != null
        if (removed) writeTrashed(map)
        return removed
    }

    /** 当前所有已软删除的账户：name -> deletedAt(epoch ms)。 */
    fun listTrashed(): Map<String, Long> = trashedMap().filter { fileFor(it.key).exists() }

    /** 立即彻底删除（无论是否在回收站）：删文件 + 清生物密钥 + 清标记。 */
    fun purgeNow(name: String): Boolean {
        BiometricVault(context, name).clear()
        val removed = fileFor(name).delete()
        bakFor(name).delete()
        tmpFor(name).delete()
        val map = trashedMap().toMutableMap()
        if (map.remove(name) != null) writeTrashed(map)
        if (prefs.getString(KEY_CURRENT, null) == name) {
            prefs.edit().remove(KEY_CURRENT).apply()
        }
        if (removed) VaultNameScope.releaseName(context, name)
        return removed
    }

    /** 扫描回收站，对超过 [retentionDays] 的账户调用 [purgeNow]。返回被清掉的账户名列表。 */
    fun purgeExpired(retentionDays: Int = DEFAULT_RETENTION_DAYS, nowMs: Long = System.currentTimeMillis()): List<String> {
        val cutoff = nowMs - retentionDays.toLong() * 24L * 3600L * 1000L
        val expired = trashedMap().filterValues { it <= cutoff }.keys.toList()
        expired.forEach { purgeNow(it) }
        return expired
    }

    /** 给新账户分配一个不冲突的建议名（同时避开回收站名）。 */
    fun suggestName(base: String = "账户"): String {
        val taken = list().toSet() + trashedMap().keys
        if (base !in taken) return base
        var i = 2
        while ("$base$i" in taken) i++
        return "$base$i"
    }

    // ---------- 内部存储：JSON map "name|ts" 以 ';' 拼接，转义 ';' '|' ----------

    private fun trashedMap(): Map<String, Long> {
        val raw = prefs.getString(KEY_TRASHED, null) ?: return emptyMap()
        if (raw.isEmpty()) return emptyMap()
        val out = mutableMapOf<String, Long>()
        for (token in raw.split(';')) {
            if (token.isEmpty()) continue
            val idx = token.lastIndexOf('|')
            if (idx <= 0) continue
            val name = token.substring(0, idx).replace("\\s", ";").replace("\\b", "|").replace("\\\\", "\\")
            val ts = token.substring(idx + 1).toLongOrNull() ?: continue
            out[name] = ts
        }
        return out
    }

    private fun writeTrashed(map: Map<String, Long>) {
        val encoded = map.entries.joinToString(";") { (n, t) ->
            val safe = n.replace("\\", "\\\\").replace("|", "\\b").replace(";", "\\s")
            "$safe|$t"
        }
        prefs.edit().putString(KEY_TRASHED, encoded).apply()
    }

    companion object {
        private const val PREF = "pmv_registry"
        private const val KEY_CURRENT = "current"
        private const val KEY_TRASHED = "trashed"
        const val DEFAULT_RETENTION_DAYS = 30
    }
}
