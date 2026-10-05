package com.vault.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class LanPeerCopyTest {
    private val projectRoot: File
        get() = System.getProperty("spec.dir")
            ?.let(::File)
            ?.parentFile
            ?: File(System.getProperty("user.dir").orEmpty())

    @Test
    fun `production LAN copy does not describe the peer as a computer`() {
        val sourceRoot = File(projectRoot, "app/src/main/java")
        val forbidden = listOf("电脑端", "手机和电脑", "无法连接电脑", "PC 端不支持")
        val hits = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file ->
                file.readLines().asSequence().mapIndexedNotNull { index, line ->
                    forbidden.firstOrNull(line::contains)?.let { "${file.name}:${index + 1}:$it" }
                }
            }
            .toList()

        assertTrue("Found peer-specific LAN copy: $hits", hits.isEmpty())
    }

    @Test
    fun `LAN failures preserve actionable vault identity detail`() {
        val source = File(projectRoot, "app/src/main/java/com/vault/ui/VaultViewModel.kt").readText()
        val strings = File(projectRoot, "app/src/main/res/values/strings_viewmodel.xml").readText()
        assertTrue(strings.contains("保险库 ID 不一致"))
        assertTrue(strings.contains("未保存任何内容"))
        assertFalse(source.contains("同步没有完成，请稍后重试"))
    }

    @Test
    fun `LAN sync serializes vault changes and uploads a disposable snapshot`() {
        val source = File(projectRoot, "app/src/main/java/com/vault/ui/VaultViewModel.kt").readText()
        val host = File(projectRoot, "app/src/main/java/com/vault/storage/SyncServerHost.kt").readText()

        assertTrue(source.contains("val outgoingSnapshot = repository.createSyncSnapshot()"))
        assertTrue(source.contains("pushLanSyncVault(serverUrl, pin, outgoingSnapshot)"))
        assertTrue(source.contains("outgoingSnapshot.delete()"))
        assertFalse(source.contains("pushLanSyncVault(serverUrl, pin, repository.syncFile())"))
        assertTrue(host.contains("PmvAppendOnlyFile.withExclusiveWriterLock(file)"))
    }
}
