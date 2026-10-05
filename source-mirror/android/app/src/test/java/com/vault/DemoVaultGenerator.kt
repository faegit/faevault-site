package com.vault

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.PasskeyRecord
import com.vault.model.SecretType
import com.vault.model.entryModules
import com.vault.model.withEntryModules
import com.vault.passkeys.PasskeyKeyMode
import com.vault.passkeys.PasskeySigningKey
import com.vault.passkeys.SoftwarePasskeySigningKey
import com.vault.storage.PmvVaultStore
import com.vault.storage.PmvVaultMetadataCodec
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.UUID

/**
 * 生成用于软件宣传/截图的演示保险库（全部为虚构数据）。
 * 直接复用 App 自身的 PMVE 加密/编解码代码，确保产出的 .pmv 可被 App 正常打开。
 *
 * 运行：.\gradlew.bat testDebugUnitTest --tests com.vault.DemoVaultGenerator
 */
class DemoVaultGenerator {

    private val desktop = File(System.getProperty("user.home"), "Desktop")
    private val password = "test_faevault001".encodeToByteArray()
    private val recovery = ByteArray(32) { (it * 31 + 7).toByte() }
    private val now = OffsetDateTime.now(ZoneOffset.UTC)
    private val nowSec = now.toEpochSecond().toDouble()
    private val ts = now.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
    private val png1x1 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

    private fun mod(type: String, value: JsonElement): JsonObject =
        EntryModules.create(type).toMutableMap().also { it["value"] = value }.let { JsonObject(it) }

    private fun obj(vararg pairs: Pair<String, String>): JsonObject =
        JsonObject(pairs.toMap().mapValues { JsonPrimitive(it.value) })

    private fun arr(vararg items: String): JsonArray = JsonArray(items.map { JsonPrimitive(it) })

    private fun card(cardType: String, vararg pairs: Pair<String, String>): JsonObject =
        EntryModules.cardValueForType(obj(*pairs), cardType)

    private fun e(
        title: String,
        secretType: String,
        username: String = "",
        password: String = "",
        url: String = "",
        targetApp: String = "",
        notes: String = "",
        tags: List<String> = emptyList(),
        modules: List<JsonObject> = emptyList(),
    ): Entry = Entry(
        id = UUID.randomUUID().toString(),
        title = title,
        username = username,
        password = password,
        url = url,
        targetApp = targetApp,
        notes = notes,
        tags = tags,
        secretType = secretType,
        createdAt = nowSec,
        updatedAt = nowSec,
    ).withEntryModules(modules)

    private fun buildPasskeyModule(rpId: String, rpName: String): JsonObject {
        val key = SoftwarePasskeySigningKey.generate(-7)
        val privateKeyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(key.exportPrivateKey())
        val publicKeyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(key.publicKeyCose)
        val userId = Base64.getUrlEncoder().withoutPadding().encodeToString("demo-user-$rpId".toByteArray())
        val credId = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { it.toByte() })
        val record = PasskeyRecord(
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = "test",
            userDisplayName = "演示用户 Test",
            credentialId = credId,
            privateKey = privateKeyB64,
            publicKey = publicKeyB64,
            signCount = 0,
            createdAt = ts,
            lastUsedAt = ts,
            transports = "internal",
            algorithm = -7,
            schemaVersion = 3,
            aaguid = "00000000-0000-0000-0000-000000000000",
            discoverable = true,
            backupEligible = true,
            backupState = true,
            keyMode = PasskeyKeyMode.SYNCABLE,
            deviceBinding = null,
        )
        return mod(ModuleType.PASSKEY, record.toJson())
    }

    private fun buildEntries(): List<Entry> = listOf(
        // ── 登录 ──
        e(
            "个人邮箱", SecretType.LOGIN,
            username = "test@example.com", password = "Mail-Demo!2024",
            url = "https://mail.example.com", targetApp = "com.android.email",
            notes = "演示用虚构邮箱账户，请勿用于真实登录。",
            tags = listOf("邮箱", "常用"),
            modules = listOf(
                mod(ModuleType.TARGET_APP, JsonPrimitive("com.android.email")),
                mod(ModuleType.OTP, obj(
                    "secret" to "JBSWY3DPEHPK3PXP", "issuer" to "Example Mail",
                    "label" to "test@example.com", "algorithm" to "SHA1",
                    "digits" to "6", "period" to "30", "type" to "totp",
                )),
                mod(ModuleType.ATTACHMENTS, arr(png1x1)),
            ),
        ),
        e(
            "社交媒体账号", SecretType.LOGIN,
            username = "test_demo", password = "Social#Demo2024",
            url = "https://weibo.example.com", targetApp = "com.example.weibo",
            tags = listOf("社交"),
            modules = listOf(mod(ModuleType.TARGET_APP, JsonPrimitive("com.example.weibo"))),
        ),
        e(
            "网上银行登录", SecretType.LOGIN,
            username = "6225888888888888", password = "Bank-Demo-Pwd!1",
            url = "https://bank.example.com", targetApp = "com.example.bank",
            notes = "演示网银，卡号与密码均为虚构。",
            tags = listOf("金融", "重要"),
            modules = listOf(
                mod(ModuleType.TARGET_APP, JsonPrimitive("com.example.bank")),
                mod(ModuleType.OTP, obj(
                    "secret" to "KRSXG5CTMVRXEZLU", "issuer" to "Demo Bank",
                    "label" to "网银动态码", "algorithm" to "SHA1",
                    "digits" to "6", "period" to "30", "type" to "totp",
                )),
            ),
        ),
        e(
            "公司 VPN", SecretType.LOGIN,
            username = "test.vpn", password = "Vpn-Demo-Passw0rd",
            url = "https://vpn.company.example", notes = "演示企业 VPN 账户。",
            tags = listOf("工作"),
        ),
        e(
            "游戏平台账号", SecretType.LOGIN,
            username = "demo_gamer", password = "Game-Demo#8848",
            url = "https://store.example.com", targetApp = "com.example.store",
            tags = listOf("游戏"),
            modules = listOf(mod(ModuleType.TARGET_APP, JsonPrimitive("com.example.store"))),
        ),
        e(
            "购物网站", SecretType.LOGIN,
            username = "test_shopper", password = "Shop-Demo-2024!",
            url = "https://shop.example.com", tags = listOf("购物"),
        ),

        // ── Wi-Fi ──
        e(
            "家庭 Wi-Fi", SecretType.WIFI,
            username = "HomeWiFi-Demo", notes = "演示家庭无线网络。",
            tags = listOf("网络", "家庭"),
            modules = listOf(mod(ModuleType.WIFI, obj(
                "ssid" to "HomeWiFi-Demo", "wifi_password" to "wifi-demo-2024",
                "security_type" to "WPA2/WPA3", "router_admin_url" to "http://192.168.1.1",
                "admin_password" to "admin-demo-123",
            ))),
        ),
        e(
            "公司办公 Wi-Fi", SecretType.WIFI,
            notes = "演示办公网络。", tags = listOf("网络", "工作"),
            modules = listOf(mod(ModuleType.WIFI, obj(
                "ssid" to "Office-Guest-Demo", "wifi_password" to "office-wifi-demo",
                "security_type" to "WPA2", "router_admin_url" to "http://10.0.0.1",
                "admin_password" to "office-admin-demo",
            ))),
        ),
        e(
            "咖啡厅公共网络", SecretType.WIFI,
            tags = listOf("网络", "公共"),
            modules = listOf(mod(ModuleType.WIFI, obj(
                "ssid" to "Cafe-Free-Demo", "wifi_password" to "",
                "security_type" to "无加密", "router_admin_url" to "",
                "admin_password" to "",
            ))),
        ),

        // ── 卡证 ──
        e(
            "招商银行储蓄卡", SecretType.CARD_DOCUMENT,
            notes = "演示银行卡（虚构卡号）。",
            tags = listOf("金融", "银行卡"),
            modules = listOf(mod(ModuleType.CARD_DOCUMENT, card(EntryModules.CARD_BANK,
                "cardholder" to "演示用户", "card_number" to "6225888812345678",
                "bank" to "招商银行", "bank_branch" to "演示分行",
                "expiry" to "12/28", "cvv" to "123", "withdrawal_password" to "123456",
            ))),
        ),
        e(
            "信用卡 Visa", SecretType.CARD_DOCUMENT,
            notes = "演示信用卡。", tags = listOf("金融", "信用卡"),
            modules = listOf(mod(ModuleType.CARD_DOCUMENT, card(EntryModules.CARD_BANK,
                "cardholder" to "DEMO USER", "card_number" to "4111111145551111",
                "bank" to "Visa", "bank_branch" to "", "expiry" to "08/27",
                "cvv" to "321", "withdrawal_password" to "",
            ))),
        ),
        e(
            "居民身份证", SecretType.CARD_DOCUMENT,
            notes = "演示身份证（虚构号码）。", tags = listOf("证件", "身份"),
            modules = listOf(mod(ModuleType.CARD_DOCUMENT, card(EntryModules.CARD_ID_CARD,
                "full_name" to "演示用户", "id_number" to "110101199003071234",
                "issue_date" to "2019-05-20", "expiry_date" to "2039-05-20",
                "issuing_authority" to "演示市公安局",
            ).let { v ->
                val m = v.toMutableMap(); m["images"] = JsonArray(listOf(JsonPrimitive(png1x1))); JsonObject(m)
            })),
        ),
        e(
            "健身房会员卡", SecretType.CARD_DOCUMENT,
            tags = listOf("会员卡"),
            modules = listOf(mod(ModuleType.CARD_DOCUMENT, card(EntryModules.CARD_CUSTOM,
                "card_name" to "演示健身房会员", "card_number" to "GYM2024000123",
                "expiry" to "2025-12-31", "notes" to "演示会员卡。",
            ))),
        ),

        // ── API 密钥 ──
        e(
            "云服务 API", SecretType.API_KEY,
            notes = "演示云厂商密钥。",
            tags = listOf("开发", "密钥"),
            modules = listOf(mod(ModuleType.API_CREDENTIAL, obj(
                "api_key" to "AKID-DEMO-0000000000000000",
                "api_secret" to "secret-demo-a1b2c3d4e5f6",
            ))),
        ),
        e(
            "代码托管 Token", SecretType.API_KEY,
            notes = "演示代码平台 Token。", tags = listOf("开发", "密钥"),
            modules = listOf(mod(ModuleType.API_CREDENTIAL, obj(
                "api_key" to "ghp_DEMOtoken00000000000000000000",
                "api_secret" to "",
            ))),
        ),
        e(
            "AI 平台密钥", SecretType.API_KEY,
            notes = "演示 AI 服务密钥。", tags = listOf("开发", "AI"),
            modules = listOf(mod(ModuleType.API_CREDENTIAL, obj(
                "api_key" to "sk-DEMO0000000000000000000000000000",
                "api_secret" to "",
            ))),
        ),

        // ── 动态码 ──
        e(
            "独立动态码（GitHub）", SecretType.OTP,
            notes = "演示独立 TOTP。", tags = listOf("动态码"),
            modules = listOf(mod(ModuleType.OTP, obj(
                "secret" to "JBSWY3DPEHPK3PXP", "issuer" to "GitHub",
                "label" to "test@example.com", "algorithm" to "SHA1",
                "digits" to "6", "period" to "30", "type" to "totp",
                "otp_domains" to "github.com",
            ))),
        ),
        e(
            "动态码（云盘）", SecretType.OTP,
            tags = listOf("动态码"),
            modules = listOf(mod(ModuleType.OTP, obj(
                "secret" to "KRSXG5CTMVRXEZLU", "issuer" to "DemoDrive",
                "label" to "云盘", "algorithm" to "SHA1",
                "digits" to "6", "period" to "30", "type" to "totp",
            ))),
        ),

        // ── 安全笔记 ──
        e(
            "私密笔记：恢复短语", SecretType.SECURE_NOTE,
            notes = "演示 Markdown 笔记。",
            tags = listOf("笔记"),
            modules = listOf(mod(ModuleType.MULTILINE, JsonPrimitive(
                "# 恢复短语（演示）\n\n- 苹果 椅子 河流 星辰 海洋 山岭 书本 火焰\n- 请妥善保管，切勿泄露\n\n> 本条目所有内容均为虚构演示数据。",
            ))),
        ),
        e(
            "保险箱提示", SecretType.SECURE_NOTE,
            tags = listOf("笔记"),
            modules = listOf(mod(ModuleType.MULTILINE, JsonPrimitive(
                "保险箱密码提示：演示用，答案与童年宠物有关。",
            ))),
        ),

        // ── 服务器 ──
        e(
            "生产服务器", SecretType.SERVER,
            notes = "演示生产主机。",
            tags = listOf("运维", "服务器"),
            modules = listOf(mod(ModuleType.SERVER_CONNECTION, obj(
                "host" to "prod.demo.example", "port" to "22",
                "username" to "deploy", "password" to "Prod-Demo-Ssh!9",
            ))),
        ),
        e(
            "数据库服务器", SecretType.SERVER,
            notes = "演示数据库主机。",
            tags = listOf("运维", "数据库"),
            modules = listOf(
                mod(ModuleType.SERVER_CONNECTION, obj(
                    "host" to "db.demo.example", "port" to "22",
                    "username" to "dba", "password" to "Db-Demo-Pwd!2",
                )),
                mod(ModuleType.DATABASE, obj(
                    "engine" to "MySQL", "host" to "db.demo.example", "port" to "3306",
                    "database" to "demo_app", "username" to "app", "password" to "App-Demo-Db!3",
                )),
            ),
        ),
        e(
            "SSH 跳板机", SecretType.SERVER,
            notes = "演示 SSH 密钥登录。",
            tags = listOf("运维", "SSH"),
            modules = listOf(mod(ModuleType.SSH, obj(
                "host" to "bastion.demo.example", "port" to "22",
                "username" to "jump", "password" to "Jump-Demo!4",
                "private_key" to "-----BEGIN OPENSSH PRIVATE KEY-----\nDEMO-KEY-MATERIAL\n-----END OPENSSH PRIVATE KEY-----",
                "fingerprint" to "SHA256:demofingerprint000000000000000000000",
            ))),
        ),

        // ── 自定义 ──
        e(
            "软件许可证", SecretType.CUSTOM,
            notes = "演示许可证密钥。",
            tags = listOf("授权"),
            modules = listOf(
                mod(ModuleType.TEXT, JsonPrimitive("Adobe 全家桶（演示）")),
                mod(ModuleType.PASSWORD, JsonPrimitive("XXXX-XXXX-XXXX-DEMO-0001")),
            ),
        ),
        e(
            "产品序列号", SecretType.CUSTOM,
            tags = listOf("授权"),
            modules = listOf(mod(ModuleType.TEXT, JsonPrimitive("SN-DEMO-0000000000"))),
        ),

        // ── 综合：地址 / 恢复 / 布尔 / 日期 ──
        e(
            "个人身份档案", SecretType.LOGIN,
            username = "test", password = "Profile-Demo!1",
            notes = "演示多模块聚合条目。",
            tags = listOf("身份", "综合"),
            modules = listOf(
                mod(ModuleType.ADDRESS, obj(
                    "country" to "中国", "region" to "北京市", "city" to "北京",
                    "address" to "演示区演示路 1 号", "postal_code" to "100000",
                )),
                mod(ModuleType.RECOVERY, obj(
                    "question" to "你的童年宠物叫什么？", "answer" to "演示答案",
                )),
                mod(ModuleType.BOOLEAN, JsonPrimitive(true)),
                mod(ModuleType.DATETIME, JsonPrimitive("2025-01-01T09:30")),
                mod(ModuleType.IMAGES, JsonArray(listOf(JsonPrimitive(png1x1)))),
            ),
        ),
        e(
            "证件照片备份", SecretType.LOGIN,
            username = "test", notes = "演示图片模块。",
            tags = listOf("图片"),
            modules = listOf(mod(ModuleType.IMAGES, JsonArray(listOf(JsonPrimitive(png1x1))))),
        ),
        e(
            "联系方式", SecretType.CUSTOM,
            tags = listOf("联系"),
            modules = listOf(
                mod(ModuleType.TEXT, JsonPrimitive("test@example.com")),
                mod(ModuleType.TEXT, JsonPrimitive("+86 138 0000 0000")),
            ),
        ),

        // ── 通行密钥 ──
        e(
            "网站通行密钥", SecretType.PASSKEY,
            username = "test", notes = "演示 Passkey（软件 EC P-256 密钥对）。",
            tags = listOf("通行密钥"),
            modules = listOf(buildPasskeyModule("example.com", "Example")),
        ),
    )

    private fun metadata(): JsonObject = JsonObject(
        mapOf(
            "schema" to JsonPrimitive(PmvVaultMetadataCodec.SCHEMA),
            "version" to JsonPrimitive(PmvVaultMetadataCodec.VERSION),
            "vault_id" to JsonPrimitive(UUID(0, 1).toString()),
            "entry_order" to JsonArray(emptyList()),
            "trash_order" to JsonArray(emptyList()),
            "sync_meta" to JsonObject(
                mapOf(
                    "device_id" to JsonPrimitive(UUID.randomUUID().toString()),
                    "key_revision" to JsonPrimitive(0),
                ),
            ),
            "key_revision" to JsonPrimitive(0),
            "export_epoch" to JsonNull,
            "purge_tombstones" to JsonObject(emptyMap()),
            "account" to JsonPrimitive("test"),
        ),
    )

    @Test
    fun generateDemoVault() {
        assumeTrue("Desktop is required to generate the demo vault", desktop.isDirectory)
        val entries = buildEntries()
        val file = File(desktop, "FAEVault-Demo.pmv")
        if (file.exists()) file.delete()
        PmvVaultStore.create(file, password, recovery, metadata(), entries).close()

        // 重新打开校验，确保 App 可正常加载
        PmvVaultStore.openPassword(file, password).use { session ->
            var ok = 0
            var passkeyOk = false
            for (entry in entries) {
                val restored = session.readEntry(UUID.fromString(entry.id))
                if (restored != null) {
                    ok++
                    if (entry.secretType == SecretType.PASSKEY) {
                        val value = restored.fields[EntryModules.FIELD_KEY] as? JsonArray
                        val pk = value?.firstOrNull() as? JsonObject
                        val pkValue = pk?.get("value") as? JsonObject
                        passkeyOk = pkValue != null && PasskeyRecord.parse(pkValue) != null
                    }
                }
            }
            assertEquals("所有条目应可被重新读取", entries.size, ok)
            assertTrue("Passkey 模块应可被解析", passkeyOk)
        }

        val md = buildMarkdown(entries)
        val mdFile = File(desktop, "FAEVault-Demo-测试数据.md")
        mdFile.writeText(md)

        println("演示保险库已生成: ${file.absolutePath} (${file.length()} 字节, ${entries.size} 条)")
        println("测试数据文档已生成: ${mdFile.absolutePath}")
    }

    private fun buildMarkdown(entries: List<Entry>): String {
        val sb = StringBuilder()
        sb.appendLine("# FAEVault 演示保险库 · 测试数据清单")
        sb.appendLine()
        sb.appendLine("> ⚠️ 本文件及对应 `.pmv` 中的全部数据均为**虚构演示数据**，仅用于软件宣传与界面截图，不含任何真实凭据。")
        sb.appendLine()
        sb.appendLine("## 打开方式")
        sb.appendLine()
        sb.appendLine("- 保险库文件：`FAEVault-Demo.pmv`（位于桌面）")
        sb.appendLine("- 主密码（数据库密码）：`test_faevault001`")
        sb.appendLine("- 账户（account）：`test`")
        sb.appendLine("- 条目总数：${entries.size}")
        sb.appendLine()
        sb.appendLine("## 分类统计")
        sb.appendLine()
        sb.appendLine("| 类型 | 数量 |")
        sb.appendLine("| --- | --- |")
        entries.groupBy { it.secretType }.forEach { (type, list) ->
            sb.appendLine("| $type | ${list.size} |")
        }
        sb.appendLine()
        sb.appendLine("## 条目明细")
        sb.appendLine()
        entries.forEachIndexed { index, entry ->
            sb.appendLine("### ${index + 1}. ${entry.title}")
            sb.appendLine()
            sb.appendLine("- 类型：`${entry.secretType}`")
            if (entry.username.isNotBlank()) sb.appendLine("- 用户名：`${entry.username}`")
            if (entry.password.isNotBlank()) sb.appendLine("- 密码：`${entry.password}`")
            if (entry.url.isNotBlank()) sb.appendLine("- 网址：`${entry.url}`")
            if (entry.targetApp.isNotBlank()) sb.appendLine("- 关联程序：`${entry.targetApp}`")
            if (entry.tags.isNotEmpty()) sb.appendLine("- 标签：${entry.tags.joinToString(", ") { "`$it`" }}")
            if (entry.notes.isNotBlank()) sb.appendLine("- 备注：${entry.notes}")
            val modules = entry.entryModules()
            if (modules.isNotEmpty()) {
                sb.appendLine("- 附加模块：")
                modules.forEach { module ->
                    val type = EntryModules.primitive(module["type"])
                    val title = EntryModules.primitive(module["title"])
                    val sensitive = (module["sensitive"] as? JsonPrimitive)?.content == "true"
                    sb.appendLine("  - **$title** (`$type`)" + if (sensitive) " 🔒" else "")
                    renderValue(sb, module["value"], "    ", sensitive)
                }
            }
            sb.appendLine()
        }
        return sb.toString()
    }

    private fun renderValue(sb: StringBuilder, value: JsonElement?, indent: String, sensitive: Boolean) {
        when (value) {
            null -> {}
            is JsonPrimitive -> {
                val text = value.content
                val shown = if (sensitive && text.length > 12) "${text.take(4)}••••••${text.takeLast(4)}" else text
                sb.appendLine("${indent}值：`$shown`")
            }
            is JsonObject -> {
                value.entries.forEach { (k, v) ->
                    if (v is JsonPrimitive) {
                        val text = v.content
                        val long = text.length > 40
                        val shown = if (long) "${text.take(16)}…(已截断 ${text.length} 字节)" else text
                        sb.appendLine("$indent- $k：'$shown'")
                    } else if (v is JsonArray) {
                        sb.appendLine("${indent}- $k：数组(${v.size} 项)")
                    } else {
                        sb.appendLine("$indent- $k：$v")
                    }
                }
            }
            is JsonArray -> sb.appendLine("${indent}数组(${value.size} 项)")
            else -> sb.appendLine("$indent$value")
        }
    }
}
