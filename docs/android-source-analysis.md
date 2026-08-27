# FAEVault Android 源码分析报告

> 本文基于对 `vault_android` 仓库（Kotlin Multiplatform / 单 Activity Compose 应用）的源码分析，
> 梳理其加密设计、平台安全机制、同步与数据模型，并作为官网文案的事实依据。
> 所有结论均给出 `文件:行号` 级别的源码证据；未找到源码依据的断言一律标注「无证据/需修正」。

## 1. 项目身份信息

| 项 | 值 | 证据 |
|---|---|---|
| 应用显示名 | 保险库 | `app/src/main/res/values/strings.xml:3`（`app_name`） |
| 英文品牌 | FAEVault | `AndroidManifest.xml`（主题 `Theme.FAEVault`、服务类名 `FAEVaultAutofillService` / `FAEVaultCredentialProviderService`） |
| 命名空间 | `com.vault` | `app/build.gradle.kts:77` |
| 上架 applicationId | `app.fae.vault` | `app/build.gradle.kts:81` |
| 版本 | 4.0.0（versionCode 400） | `app/build.gradle.kts:84-85` |
| minSdk / targetSdk / compileSdk | 26 / 35 / 35 | `app/build.gradle.kts:82-83,78` |

结论：官网使用「FAEVault / 保险库」品牌、`.pmv` 文件格式、本地优先、无账号体系等表述，与源码一致。

## 2. 加密设计（核心事实）

### 2.1 密钥派生 —— Argon2id v1.3（**非 scrypt**）

- 主密码 → 32 字节 KEK：`PmvKeySchedule.derivePasswordKek` 使用 `Argon2BytesGenerator`，
  `Argon2Parameters.ARGON2_id` + `ARGON2_VERSION_13`，`PmvKeySchedule.kt:97-108`。
- 参数：`ARGON2_MEMORY_KIB = 65_536`（64 MiB）、`ARGON2_ITERATIONS = 3`、`ARGON2_PARALLELISM = 1`、
  salt = 16 字节，`PmvKeySchedule.kt:13-16, 98-104`。
- KEK 经信封加密保护 Vault Root Key；随后 `HKDFBytesGenerator(SHA256Digest)` 做用途隔离，
  派生 8 把相互独立的根密钥（metadata / entry-root / attachment-root / index / search-index /
  integrity / sync-auth / key-wrap），`PmvKeySchedule.kt:111-141`。
- 权威规范：`spec/VAULT_FORMAT.md:13-16`（PMVE 体系，wire magic `PMVS`）、`README.md:24-33`。

> ⚠️ 官网原文案称「scrypt + AES-256-GCM / scrypt(N=2¹⁶, r=8, p=1)」——**与源码不符**。
> 实际为 **Argon2id v1.3**。已修正（见第 5 节）。

### 2.2 对称加密 —— AES-256-GCM（含 AAD）

- `PmvBlockCrypto`：`"AES/GCM/NoPadding"`，密钥 32 字节（256-bit），`PmvBlockCrypto.kt:9,50-51`；
  `PmvKeySchedule.KEY_SIZE = 32`，`PmvKeySchedule.kt:12`。
- 每块数据使用由根密钥经 HKDF 派生的**独立** AES-256-GCM 密钥，并绑定用途相关的 AAD，
  见 `PmvKeySchedule.deriveCommitBlockKey / deriveIndexPageKey / deriveEntryKey` 等（`:143-220`）。
- 备份 `.pmbak` 同样使用 Argon2id + AES-256-GCM（AAD 绑定 KDF 枚举与参数），`spec/VAULT_FORMAT.md:18-40`、
  `PmvBackupCrypto.kt:12,20-21`。

结论：官网「AES-256-GCM / 独立随机 Nonce / 完整性认证」表述与源码一致。

### 2.3 文件格式

- 主库 `.pmv`：PMVE 容器（wire magic `PMVS`），文件头携带 Argon2id salt 与版本；数据以
  **追加写（append-only）** 的分块方式存储（`PmvAppendOnlyFile.kt` 描述「追加写与双 Superblock 恢复」），
  与桌面端 `core/` 逐字节一致、可双向互导（`spec/VAULT_FORMAT.md:1-16`）。
- 备份 `.pmbak`：PMXB v2 布局，文件头 = `MAGIC("PMXB") + VERSION(0x02) + KDF_ID + MEMORY_KIB + ITERATIONS + PARALLELISM + SALT(16B) + NONCE(12B) + CIPHERTEXT + GCM TAG(16B)`，共 46 字节，`spec/VAULT_FORMAT.md:42-58`。
- CSV 导入/导出：`CsvExporter.kt` / `CsvImporter.kt`，`VaultViewModel.exportCsv`（`VaultViewModel.kt:3881`），
  `SettingsScreen.importCsvLauncher`（`SettingsScreen.kt:1019`）。

> ⚠️ 官网原「文件格式」项把 **.pmbak 备份布局** 当成了主库 `.pmv` 布局描述——**与源码不符**。已修正。

### 2.4 恢复机制 —— 随机 256-bit 恢复密钥（**非安全问题 + scrypt**）

- `RecoveryKeyCodec`：随机生成 256-bit 恢复密钥（`KEY_SIZE = 32`），Crockford Base32 编码 + 校验码，
  `RecoveryKeyCodec.kt:10-47`。
- 主密码丢失时以恢复密钥重置，并重新签发（每次使用后旧密钥失效），`AppRoot.kt:813-936`、
  `NotificationLocalizer.kt:41-43`（`恢复密钥已重新生成，旧密钥已失效`）。

> ⚠️ 官网原「恢复口令」称「预设安全问题 + 答案经 scrypt 派生」——**与源码不符**。已修正为恢复密钥。

## 3. 平台安全机制（均有源码依据）

| 机制 | 证据 |
|---|---|
| FLAG_SECURE 防截屏/录屏，可经主密码确认后临时关闭 | `security/WindowSecurity.kt:25,27`、`ScreenCapturePref.kt:11`、`MainActivity.kt` |
| 敏感剪贴板自动清空：范围 0–600 秒，默认 60 秒 | `storage/Clipboard.kt:23,42,52-54`、`storage/ClipboardTtlPref.kt:16-18` |
| 解锁失败冷却：前 4 次 0.25/0.5/1/2 秒；第 5 次进入 30 秒冷却，后续轮次按 60/90 秒递增 | `security/LockoutPref.kt:11-13,35-54` |
| 生物识别：AndroidKeyStore AES/GCM 密钥（要求 BIOMETRIC_STRONG）包裹设备解锁信封；模板变更后旧密文失效 | `security/BiometricVault.kt:24-33,139-154` |
| Android 自动备份关闭 | `AndroidManifest.xml:41`（`android:allowBackup="false"`） |
| 敏感信息门禁（查看银行卡/身份证/API 密钥详情、改主密码、导出需二次验证） | autofill / 密钥管理相关分支（UI 层） |

## 4. 功能与数据模型（均有源码依据）

| 功能 | 证据 |
|---|---|
| 条目类型：登录 / 银行卡 / 身份证 / Wi-Fi / API 密钥 | `model/Entry.kt:114-131`（`SecretType`）、`model/EntryModule.kt:54-89`、`spec/VAULT_FORMAT.md:88` |
| 系统自动填充（按应用包名或 HTTPS 主机匹配来源） | `autofill/FAEVaultAutofillService.kt:15,20,45`、`AssistStructureParser.kt:50-101`、`OriginMatcher.kt` |
| 通行密钥 / Credential Provider（Android 14+ / API 34） | `passkeys/FAEVaultCredentialProviderService.kt:31-32`、`AndroidManifest.xml:83-95`、`build.gradle.kts:82-83` |
| 端上 OCR（ML Kit，银行卡/身份证） | `ocr/Ocr.kt:17-51`、`ocr/CardParser.kt:79,191` |
| 局域网同步（HTTPS 服务端 + SPAKE2-P256 配对） | `storage/SyncServerHost.kt:56-64`、`storage/SyncClient.kt:25-30,52`、`Spake2P256.kt` |
| WebDAV 同步（HTTPS、可固定证书 SHA-256 指纹、拒绝 HTTPS→HTTP 降级） | `storage/WebDavCloud.kt:53,71-73,631-632,677-700` |
| 回收站（恢复 / 永久删除 / 自动清理） | `model/VaultOps.kt:131-210`、`ui/screens/TrashScreen.kt` |
| 数据库维护（重复检测、同服务合并、回收站保留期） | `model/VaultOps.kt:662-745`、`storage/TrashRetentionPref.kt` |
| 密码安全检查（泄露 / 弱 / 重复 / 近似重复） | `security/PasswordHealth.kt`、`security/LeakedPasswordCheck.kt`、`security/PwnedPasswordsCheck.kt` |
| 泄露检测：HIBP k-anonymity，仅发 SHA-1 前 5 位 | `security/PwnedPasswordsCheck.kt:12-13,30-43` |
| 自定义模块（用户可组合字段） | `model/EntryModule.kt:17-39,52-128`、`ui/screens/ModuleEditor.kt` |

## 5. 官网文案与源码不符之处（已修正）

| # | 官网原表述 | 实际源码 | 修正后 |
|---|---|---|---|
| 1 | 密钥派生用 `scrypt`（Home / Journey / Security 多处） | Argon2id v1.3（m=64MiB, t=3, p=1），`PmvKeySchedule.kt:97-108` | Argon2id + AES-256-GCM |
| 2 | `文件格式` 字节布局 MAGIC+VERSION+SALT+NONCE+CIPHERTEXT | 该布局实为 `.pmbak` 备份格式；主库为 PMVE 追加写容器 | 描述主库 PMVE 容器 + 备份 `.pmbak` 独立加密 |
| 3 | `恢复口令` = 安全问题 + 答案经 scrypt 派生 | 随机 256-bit 恢复密钥，使用后失效 | 随机 256-bit 恢复密钥（带校验码） |
| 4 | 生物识别「包裹 32 字节数据密钥」 | 包裹设备解锁信封（含主密码） | 包裹设备解锁信封，模板变更后失效 |
| 5 | WebDAV/局域网「仅接受 HTTPS」 | 允许 http scheme，但固定指纹/安全认证需 HTTPS；拒绝 HTTPS→HTTP 降级 | 均通过 HTTPS 传输并拒绝降级重定向 |

涉及文件：`src/components/HomePage.astro`、`src/components/JourneyPage.astro`、`src/components/SecurityPage.astro`。

## 6. 与源码一致、无需修改的官网表述

- 本地优先 / 离线 / 无账号体系（`README.md:5`、`PRIVACY_POLICY.md`）。
- AES-256-GCM、独立 Nonce、完整性认证。
- FLAG_SECURE、剪贴板敏感标记与自动清空、解锁失败冷却。
- 系统自动填充、Passkey / Credential Provider（Android 14+）、OCR、WebDAV 与局域网同步、CSV 导入导出。
- 条目类型（登录/银行卡/身份证/Wi-Fi/API 密钥）、回收站、维护、密码安全检查、HIBP k-anonymity。
