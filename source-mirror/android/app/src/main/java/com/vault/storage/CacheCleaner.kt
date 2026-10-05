package com.vault.storage

import android.content.Context
import java.io.File

// 启动时清理可能泄露内容的临时缓存：
//  - cacheDir/img_share/        复制图片到剪贴板时写的中转 JPEG
//  - cacheDir/img_capture/      拍照流程的临时 JPEG
//  - cacheDir/sync_snapshots/   同步时创建的库文件快照（createSyncSnapshot）
//  - filesDir/vaults/X.pmv.tmp  上一次写入未完成的库临时文件
// 这些目录里的内容理论上短命，但崩溃/异常终止会留下残留。开机时做一次扫雷。
object CacheCleaner {

    data class CleanupReport(val removedFiles: Int, val freedBytes: Long)

    fun clean(context: Context) {
        runCatching {
            val app = context.applicationContext
            wipeDir(File(app.cacheDir, "img_share"))
            wipeDir(File(app.cacheDir, "img_capture"))
            // 同步快照正常由调用方在 finally 里删除（VaultViewModel 的 remoteFile /
            // pending.source / outgoingSnapshot），这里只兜住同步途中进程被杀留下的孤儿。
            // 启动清理发生在解锁之前，此时不会有进行中的同步快照。
            wipeDir(File(app.cacheDir, "sync_snapshots"))
            File(app.filesDir, "vaults").listFiles { f -> f.isFile && f.name.endsWith(".pmv.tmp") }
                ?.forEach { it.delete() }
        }
    }

    /**
     * 崩溃残留回收：清理导入/导出过程中被杀进程遗留的暂存文件。
     *
     * 只删除超过 [maxAgeMillis]（默认 24 小时）的文件：
     * 最近暂存的图片/附件可能仍被“恢复的编辑草稿”引用，启动时不能误删；
     * 超过时限的则必然是无法恢复的孤儿，安全回收磁盘空间。
     */
    fun cleanStaleMediaStaging(context: Context, maxAgeMillis: Long = 24L * 60 * 60 * 1000) {
        runCatching {
            val app = context.applicationContext
            val now = System.currentTimeMillis()
            val roots = listOf(
                File(app.cacheDir, "pmve_media_staging"),
                File(app.cacheDir, "vault_media"),
            )
            for (root in roots) {
                if (!root.isDirectory) continue
                root.walkTopDown()
                    .filter { it.isFile && now - it.lastModified() > maxAgeMillis }
                    .forEach { runCatching { it.delete() } }
                // 回收被清空后的空目录
                root.walkBottomUp()
                    .filter { it.isDirectory && it != root }
                    .sortedByDescending { it.absolutePath.length }
                    .forEach { if (it.listFiles()?.isEmpty() == true) runCatching { it.delete() } }
            }
            // 图片编码的临时文件（encodeImageFromUri 崩溃残留）
            app.cacheDir.listFiles { f -> f.isFile && f.name.startsWith("img_") }?.forEach { file ->
                if (now - file.lastModified() > maxAgeMillis) runCatching { file.delete() }
            }
        }
    }

    /**
     * 手动“数据库清理”使用的计数版：清理临时残留（img_share/img_capture/未完成库
     * 临时文件/Mermaid SVG 磁盘缓存）与超过 [staleMaxAgeMillis] 的暂存媒体孤儿，返回释放统计。
     * 注意：mermaid_svg 内容为 VMED 加密密文，启动清理（clean）不触碰它以保留跨会话复用，
     * 仅在用户手动深度清理时一并回收。
     */
    fun cleanForReport(
        context: Context,
        staleMaxAgeMillis: Long = 24L * 60 * 60 * 1000,
    ): CleanupReport {
        var removed = 0
        var freed = 0L
        val app = context.applicationContext

        fun countDelete(file: File) {
            freed += file.length()
            if (file.delete()) removed++
        }

        fun wipeDir(dir: File) {
            if (!dir.isDirectory) return
            dir.listFiles()?.forEach { countDelete(it) }
        }

        wipeDir(File(app.cacheDir, "img_share"))
        wipeDir(File(app.cacheDir, "img_capture"))
        wipeDir(File(app.cacheDir, "mermaid_svg"))
        File(app.filesDir, "vaults").listFiles { f -> f.isFile && f.name.endsWith(".pmv.tmp") }
            ?.forEach { countDelete(it) }

        val now = System.currentTimeMillis()
        val roots = listOf(
            File(app.cacheDir, "pmve_media_staging"),
            File(app.cacheDir, "vault_media"),
        )
        for (root in roots) {
            if (!root.isDirectory) continue
            root.walkTopDown()
                .filter { it.isFile && now - it.lastModified() > staleMaxAgeMillis }
                .forEach { countDelete(it) }
            root.walkBottomUp()
                .filter { it.isDirectory && it != root }
                .sortedByDescending { it.absolutePath.length }
                .forEach { if (it.listFiles()?.isEmpty() == true) runCatching { it.delete() } }
        }
        app.cacheDir.listFiles { f -> f.isFile && f.name.startsWith("img_") }?.forEach { file ->
            if (now - file.lastModified() > staleMaxAgeMillis) countDelete(file)
        }
        return CleanupReport(removed, freed)
    }

    private fun wipeDir(dir: File) {
        if (!dir.exists() || !dir.isDirectory) return
        dir.listFiles()?.forEach { runCatching { it.delete() } }
    }
}
