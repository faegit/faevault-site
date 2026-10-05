package com.vault.storage

import com.vault.security.VaultDeviceIdentity
import java.io.File
import java.security.MessageDigest
import java.net.URI
import java.util.UUID
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 真实内容端到端互操作（可选运行，需要 live PC 传输站）。
 *
 * 启动：`PYTHONPATH=<vault_pc> uv run python tools/lan_sync_e2e_server.py --out params.json`
 * 环境变量：LAN_E2E_URL / LAN_E2E_PIN / LAN_E2E_VAULT_ID / LAN_E2E_DEVICE_ID /
 *   LAN_E2E_SEED_HEX / LAN_E2E_PASSWORD / LAN_E2E_SAMPLE_ID / LAN_E2E_SAMPLE_SHA256 / LAN_E2E_VAULT_SHA256
 * 未配置环境变量时测试直接通过。
 *
 * 覆盖：数据导入（export 整库下载）、同步（pull + push）、文件传输（上传 + 下载真实字节）。
 */
class LanRealTransferInteropTest {
    /** 从 LAN_E2E_PARAMS 读取指定角色的独立传输站参数；未配置时返回 null（测试直接通过）。 */
    private fun role(name: String): Map<String, String>? {
        val path = System.getenv("LAN_E2E_PARAMS") ?: return null
        val file = File(path)
        if (!file.isFile) return null
        val root = kotlinx.serialization.json.Json.parseToJsonElement(file.readText()).jsonObject
        val role = root["roles"]?.jsonObject?.get(name)?.jsonObject ?: return null
        return role.mapValues { (_, value) -> value.jsonPrimitive.content }
    }

    /** 回环地址：测试环境本机防火墙对局域网 IP 拦截，服务端实际监听 0.0.0.0。 */
    private fun loopback(p: Map<String, String>): String {
        val uri = URI(p.getValue("url"))
        val query = uri.rawQuery.orEmpty()
        return "https://127.0.0.1:${uri.port}${uri.path}?$query"
    }

    private fun sha256(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    @Test
    fun `import channel downloads whole vault that unlocks with password`() = runBlocking {
        val p = role("import") ?: return@runBlocking
        val url = loopback(p)
        val pin = p.getValue("pin")
        val vaultId = p.getValue("vaultId").let(UUID::fromString)
        val password = p.getValue("password")
        val target = File.createTempFile("lan-export-", ".pmv")
        try {
            SyncClient.downloadVaultExport(url, pin, target)
            assertEquals(VaultFileFormat.PMVE, VaultFileFormat.detect(target))
            PmvVaultStore.openPassword(target, password.encodeToByteArray()).use { session ->
                assertEquals(vaultId, session.identity().vaultId)
                assertTrue("导出库应包含跨端同步条目", session.listSummaries().any { it.displayTitle == "跨端同步条目" })
            }
        } finally {
            target.delete()
        }
    }

    @Test
    fun `sync channel pulls real vault and pushes it back`() {
        val p = role("sync") ?: return
        val url = loopback(p)
        val pin = p.getValue("pin")
        val vaultId = p.getValue("vaultId").let(UUID::fromString)
        val deviceId = p.getValue("deviceId").let(UUID::fromString)
        val seedHex = p.getValue("seedHex")
        val password = p.getValue("password")
        val seed = seedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val identity = VaultDeviceIdentity.fromSeed(deviceId, seed)
        try {
            SyncClient.authenticateDevice(url, pin, vaultId, identity, "read")
            SyncClient.authenticateDevice(url, pin, vaultId, identity, "write")
            val bytes = SyncClient.pull(url, pin)
            val file = File.createTempFile("lan-sync-", ".pmv")
            try {
                file.writeBytes(bytes)
                PmvVaultStore.openPassword(file, password.encodeToByteArray()).use { session ->
                    assertEquals(vaultId, session.identity().vaultId)
                    assertTrue("同步库应包含跨端同步条目", session.listSummaries().any { it.displayTitle == "跨端同步条目" })
                }
                val response = SyncClient.pushFromFile(url, pin, file)
                assertTrue("push 响应不能为空", response.isNotBlank())
            } finally {
                file.delete()
            }
        } finally { identity.close() }
    }

    @Test
    fun `transfer channel uploads real content and downloads queued sample`() {
        val p = role("transfer") ?: return
        val url = loopback(p)
        val pin = p.getValue("pin")
        val sampleId = p.getValue("sampleId")
        val sampleSha = p.getValue("sampleSha256")

        // 上传真实字节并校验服务端返回的 sha256
        val upload = ByteArray(32 * 1024) { (it * 7 + 3).toByte() }
        val offer = SyncClient.uploadTransferFileWithRetry(
            baseUrl = url,
            pin = pin,
            inputFactory = { upload.inputStream() },
            size = upload.size.toLong(),
            name = "e2e-upload.bin",
            mime = "application/octet-stream",
            kind = "file",
        )
        assertEquals(sha256(upload), offer.sha256)

        // 下载服务端预置样本并校验真实内容
        val sample = SyncClient.listTransferOffers(url, pin).first { it.id == sampleId }
        val target = File.createTempFile("lan-download-", ".bin")
        try {
            SyncClient.downloadTransferOffer(url, pin, sample, target)
            val received = target.readBytes()
            assertEquals(sampleSha, sha256(received))
            assertEquals(List(16 * 1024) { (it % 256).toByte() }, received.toList())
        } finally {
            target.delete()
        }
        SyncClient.acknowledgeTransferOffer(url, pin, sampleId)
    }
}
