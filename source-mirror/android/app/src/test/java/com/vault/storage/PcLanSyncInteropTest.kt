package com.vault.storage

import com.vault.security.VaultDeviceIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.URI
import java.util.UUID
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Android↔PC 端到端协议互操作（可选运行）。
 *
 * 需要先启动 `vault_pc/tools/lan_sync_e2e_server.py --out params.json`，
 * 并把参数文件路径以环境变量传入：`LAN_E2E_PARAMS`（roles.interop 为本次测试的独立传输站）。
 *
 * 验证：SPAKE2 配对 → 设备认证（read+write）→ 拉取 PMVE → 打开验证条目与设备清单。
 * 未配置环境变量时测试直接通过（作为可选互操作测试）。
 */
class PcLanSyncInteropTest {
    @Test
    fun `authenticate and pull pmve vault from live pc server`() {
        val paramsPath = System.getenv("LAN_E2E_PARAMS") ?: return
        val paramsFile = File(paramsPath)
        if (!paramsFile.isFile) return
        val root = kotlinx.serialization.json.Json.parseToJsonElement(paramsFile.readText()).jsonObject
        val role = root["roles"]?.jsonObject?.get("interop")?.jsonObject ?: return
        val p = role.mapValues { (_, value) -> value.jsonPrimitive.content }
        val uri = URI(p.getValue("url"))
        val url = "https://127.0.0.1:${uri.port}${uri.path}?${uri.rawQuery.orEmpty()}"
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
            val file = File.createTempFile("lan-e2e-", ".pmv")
            try {
                file.writeBytes(bytes)
                PmvVaultStore.openPassword(file, password.encodeToByteArray()).use { session ->
                    assertEquals(vaultId, session.identity().vaultId)
                    assertEquals("跨端同步条目", session.listSummaries().single().displayTitle)
                    val records = PmvDeviceRegistry.decode(session.readMetadata())
                    assertTrue(records.any { it.deviceId == deviceId })
                }
            } finally {
                file.delete()
            }
        } finally {
            identity.close()
        }
    }
}
