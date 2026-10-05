package com.vault.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 局域网同步错误分支的判定顺序。
 *
 * 传输站对旧二维码、旧 PIN、错配 ticket 一律回 403（PIN_ROTATE_INTERVAL_MS = 120s，
 * 且配对成功即轮换），这类失败必须归到「重新建立传输站 + 重新扫码」；若被更靠前的
 * 403/未授权档接走，用户会被指引去主机点「允许本次同步」，方向完全相反。
 */
class LanSyncErrorBranchOrderTest {
    private val projectRoot: File
        get() = System.getProperty("spec.dir")
            ?.let(::File)
            ?.parentFile
            ?: File(System.getProperty("user.dir").orEmpty())

    private val mapper: String
        get() = File(projectRoot, "app/src/main/java/com/vault/ui/VaultViewModel.kt")
            .readText()
            .substringAfter("private fun lanSyncErrorMessage(")
            .substringBefore("private fun Throwable.isLanReachabilityFailure")

    @Test
    fun `pairing branch is evaluated before the 403 and unauthorized branches`() {
        val pairing = mapper.indexOf("R.string.viewmodel_sync_error_pairing")
        val unauthorized = mapper.indexOf("R.string.viewmodel_sync_error_unauthorized")

        assertTrue("pairing branch missing", pairing >= 0)
        assertTrue("unauthorized branch missing", unauthorized >= 0)
        assertTrue(
            "配对失效必须先于未授权判定，否则旧二维码 403 会被误报成「对方尚未授权本设备」",
            pairing < unauthorized,
        )
    }

    @Test
    fun `no branch classifies a bare 403 as missing device authorization`() {
        val body = mapper.substringBefore("R.string.viewmodel_sync_error_pairing")

        assertTrue(
            "不能用裸 http 403 判定未授权：配对/会话失效同样回 403",
            !body.contains("\"http 403\""),
        )
    }

    @Test
    fun `a locked vault is reported as locked, not as awaiting confirmation`() {
        val locked = mapper.indexOf("R.string.viewmodel_sync_error_locked")
        val pending = mapper.indexOf("R.string.viewmodel_sync_error_pending")

        assertTrue("缺少锁定分支（主机侧确实会以 423 上报锁定态）", locked >= 0)
        assertTrue("缺少等待确认分支", pending >= 0)
        assertTrue(
            "锁定态同样用 423 上报，锁定分支必须排在等待确认之前，否则「解锁」会被说成「点允许」",
            locked < pending,
        )
        assertTrue(
            "锁定分支必须按「已锁定」匹配报文",
            mapper.substring(0, locked).contains("\"已锁定\" in raw"),
        )
    }

    @Test
    fun `locked and pending confirmation copy stay distinct`() {
        val zh = File(projectRoot, "app/src/main/res/values/strings_viewmodel.xml").readText()
        val en = File(projectRoot, "app/src/main/res/values-en/strings_viewmodel.xml").readText()

        val zhLocked = zh.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_locked\"") }
        val zhPending = zh.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_pending\"") }
        val enLocked = en.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_locked\"") }
        val enPending = en.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_pending\"") }

        assertTrue("中文锁定文案缺失", zhLocked != null)
        assertTrue("中文等待确认文案缺失", zhPending != null)
        assertTrue("英文锁定文案缺失", enLocked != null)
        assertTrue("英文等待确认文案缺失", enPending != null)
        assertTrue("锁定文案应指引解锁", zhLocked!!.contains("解锁"))
        assertTrue("锁定文案应指引解锁", enLocked!!.contains("Unlock"))
        assertTrue("等待确认文案应指引重新建立传输站", zhPending!!.contains("重新建立传输站"))
        assertTrue("等待确认文案应指引重新建立传输站", enPending!!.contains("transfer station again"))
        assertTrue(
            "锁定文案不得与等待确认文案相同，否则两档不可区分",
            zhLocked != zhPending && enLocked != enPending,
        )
    }

    @Test
    fun `pending branch can actually match the 423 message the client raises`() {
        val client = File(projectRoot, "app/src/main/java/com/vault/storage/SyncClient.kt").readText()
        val thrown = Regex("""throw SyncException\("([^"]*等待主机确认[^"]*)"""")
            .find(client)
            ?.groupValues
            ?.get(1)

        assertTrue("未找到客户端 423 等待超时的抛出文案", thrown != null)
        val pendingKeyword = Regex(""""([^"]*等待主机确认[^"]*)" in raw""")
            .find(mapper)
            ?.groupValues
            ?.get(1)
        assertTrue("等待确认分支未按「等待主机确认」匹配", pendingKeyword != null)
        assertTrue(
            "映射关键词必须能在客户端文案里命中，否则该分支不可达：'$thrown' vs '$pendingKeyword'",
            thrown!!.contains(pendingKeyword!!),
        )
    }

    @Test
    fun `423 wait timeout names the actual channel instead of always saying export`() {
        val client = File(projectRoot, "app/src/main/java/com/vault/storage/SyncClient.kt").readText()

        assertTrue(
            "423 等待超时的文案必须按 sessionOp 生成，不能写死成「导出」",
            client.contains("等待主机确认\${sessionOpLabel(sessionOp)}超时"),
        )
        for (label in listOf("同步", "文件传输", "导出")) {
            assertTrue("通道名缺少 $label", client.contains("\"$label\""))
        }
        // 导出通道的文案必须与既有词条/导入映射器保持一致
        assertTrue(
            "导入映射器与英文词表依赖「等待主机确认导出超时」原文",
            client.contains("EXPORT_OP -> \"导出\""),
        )
    }

    @Test
    fun `every 409 the servers can raise is caught by a specific branch`() {
        val keywords = Regex(""""([^"]+)" in (?:raw|lower)""")
            .findAll(mapper)
            .map { it.groupValues[1] }
            .toSet()

        val bodies = listOf(
            File(projectRoot, "app/src/main/java/com/vault/storage/SyncServerHost.kt"),
            File(projectRoot, "app/src/main/java/com/vault/ui/VaultViewModel.kt"),
        )
            .flatMap { file ->
                Regex("""409,\s*"([^"]+)"""")
                    .findAll(file.readText())
                    .map { it.groupValues[1] }
                    .toList()
            }
            .distinct()

        assertTrue("未解析到任何 409 文案，测试本身失效", bodies.isNotEmpty())
        assertTrue(
            "映射器不应再有 409 兜底档：真实 409 都应被具体档按正文接住",
            !mapper.contains("\"409\" in raw"),
        )
        for (body in bodies) {
            assertTrue(
                "409 文案没有任何具体分支能接住：$body",
                keywords.any { body.contains(it) },
            )
        }
    }

    @Test
    fun `device authorization stays ahead of the bare authentication failure branch`() {
        val unauthorized = mapper.indexOf("R.string.viewmodel_sync_error_unauthorized")
        val auth = mapper.indexOf("R.string.viewmodel_sync_error_auth")

        assertTrue(unauthorized >= 0 && auth >= 0)
        assertTrue(
            "设备未授权（403 报文含「设备未授权或已撤销」）必须先于裸「认证失败」判定",
            unauthorized < auth,
        )
    }

    @Test
    fun `pending confirmation copy tells the user to re-establish the station`() {
        val zh = File(projectRoot, "app/src/main/res/values/strings_viewmodel.xml").readText()
        val en = File(projectRoot, "app/src/main/res/values-en/strings_viewmodel.xml").readText()

        val zhLine = zh.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_pending") }
        val enLine = en.lineSequence().firstOrNull { it.contains("viewmodel_sync_error_pending") }
        assertTrue("中文文案缺失", zhLine != null)
        assertTrue("英文文案缺失", enLine != null)
        assertTrue("应提示重新建立传输站", zhLine!!.contains("重新建立传输站"))
        assertTrue("应提示重新建立传输站", enLine!!.contains("establish the transfer station again"))
    }
}
