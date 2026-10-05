opopo# FAEVault 跨端库格式契约 v1

桌面端(Python `core/`)与安卓端(Kotlin)必须使用**完全一致**的加密与序列化格式,
才能互相打开同一个库文件 / 备份文件。本文件是唯一权威规范,任一端改动都要同步另一端。

> 验证手段:
> - 主库 PMVE 的二进制/JSON 规范位于 `spec/interop/pmv_next/v1/*.json`,由
>   `manifest.json` 声明;Kotlin 与 Python 加密层测试用同一套跨端向量验证互操作。
> - 备份 v2 的跨端向量为 `spec/backup_v2_fixture.json`(桌面端生成,两端测试共享读取)。

## 1. 主库加密(PMVE)

主库 `.pmv` 使用 PMVE(PMV Extended,wire magic `PMVS`)体系:**Argon2id v1.3** 派生
KEK → Vault Root Key 信封 → HKDF 用途隔离派生 8 根 RootKey → 分块 AES-256-GCM(带 AAD)。
权威规范与互操作向量见 `spec/interop/pmv_next/v1/`(argon2id / hkdf / block_aead /
container / vault_header / entry_codec 等)。

## 2. 备份加密(v2, PMXB, Argon2id + AAD)

`.pmbak` 备份使用独立的**导出口令**加密,与主库相互独立。格式:

### 2.1 KDF

| 参数 | 值 |
|------|-----|
| 算法 | Argon2id v1.3 |
| 内存 | 65536 KiB (64 MiB) |
| 迭代 | 3 |
| 并行度 | 1 |
| salt | 16 字节(随机,存于文件头) |
| 输出 | 32 字节 KEK(直接作为数据密钥) |

口令以 **UTF-8** 编码输入 Argon2id。

### 2.2 AEAD 与 AAD

- AES-256-GCM,nonce 12 字节随机,tag 16 字节追加在密文末尾。
- **AAD = 域前缀 `PMV backup v2\0` + MAGIC(PMXB) + VERSION(2) + KDF_ID(1) + MEMORY_KIB(4 BE)
  + ITERATIONS(4 BE) + PARALLELISM(4 BE) + SALT(16)**。
  AAD 绑定 KDF 枚举与参数,防止盐/参数被替换。

### 2.3 文件二进制布局

```
偏移      长度     内容
0         4        MAGIC = "PMXB"
4         1        VERSION = 0x02
5         1        KDF_ID = 0x01 (ARGON2ID v1.3)
6         4        MEMORY_KIB (u32 BE)
10        4        ITERATIONS (u32 BE)
14        4        PARALLELISM (u32 BE)
18        16       SALT
34        12       NONCE
46        N        CIPHERTEXT + GCM TAG(16B)
```

文件头长度 = 46 字节;短于 46、MAGIC 不匹配、VERSION≠2 或 KDF 参数不符 ⇒ 结构损坏(区别于密码错误)。
tag 验证失败 ⇒ 导出口令错误或文件损坏。

## 3. 明文载荷(解密后的 JSON,UTF-8)

主库:
```json
{ "version": 1, "entries": [ <Entry>... ], "trash": [ <Entry>... ] }
```
备份(`.pmbak`)没有 `trash`:
```json
{ "version": 2, "entries": [ <Entry>... ], "purge_tombstones": {...}, "sync_meta": {...}, "export_epoch": ... }
```

### Entry 字段(与 `core/models.py` 的 dataclass 字段名逐一对应)

| 字段 | 类型 | 默认 | 备注 |
|------|------|------|------|
| `title` | string | "" | |
| `username` | string | "" | |
| `password` | string | "" | |
| `url` | string | "" | |
| `notes` | string | "" | |
| `tags` | string[] | [] | 仅 `login` 类型可有标签,其它类型加载时被清空 |
| `id` | string | uuid4 hex(32位无连字符) | 跨端必须保持稳定,用于合并/去重 |
| `created_at` | number | Unix 秒(浮点) | |
| `updated_at` | number | Unix 秒(浮点) | |
| `secret_type` | string | `login` | 枚举见下 |
| `fields` | object | {} | 各类型的扩展字段,见下 |
| `deleted_at` | number\|null | null | 在回收站中的删除时间戳 |

`secret_type` 枚举:`login` / `credit_card` / `id_card` / `wifi` / `api_key`。
未知值在加载时回退为 `login`。

`fields` 按类型携带不同键(非穷举,Kotlin 侧用 `Map<String, JsonElement>` 宽松解析,
未知键原样保留以保证往返不丢数据):
- credit_card:`card_number_last4`, `cardholder`, `expiry_date`, `card_images_b64`(list,支持多图)
- id_card:`full_name`, `id_number`, `id_images_b64`(list,支持多图)
- wifi:`ssid`, `password`, `admin_password`
- api_key:`service`

> **图片与附件说明**: 逻辑字段仍与桌面端兼容；Android 解锁会话内使用 `img:` / `att:`
> 文件引用按需解码，避免 Base64 常驻内存。落盘时引用会转换为独立加密 blob，原文件
> 字节不转码；证件照和银行卡仅对前 2 张图片自动运行 OCR，其余图片原样保存。

### PMV3 大二进制 payload

含图片或附件的条目 payload 明文采用以下封装后再由条目级 AES-GCM 加密：

```
0x01 | payload JSON | 0x00 | blob record...
blob record = nonce(12) | ciphertext_length(u32-be) | AES-GCM ciphertext
```

JSON 中对应值写为 `blb:image:N` 或 `blb:attachment:N`。每个 blob 单独使用条目 payload AAD，
读写实现必须流式处理；删除、恢复及清空回收站只允许重写索引并原样复制 payload 密文块。

## 4. 序列化兼容性要点(易踩坑)

1. **往返不丢字段**:解析 Entry 时遇到未知键要保留(尤其 `fields` 内),
   否则安卓改一条目再存回,桌面端的新字段会丢失。
2. **时间戳规范写出为浮点秒**,不是毫秒。Kotlin 用 `Double`。为兼容旧库，
   PC 与 Android 读取时同时接受 JSON number、数字字符串和 ISO-8601 字符串；
   下次保存时统一规整为 JSON number。
3. **`tags` 类型规整**:Python 侧若 `tags` 为字符串会包成单元素数组;非 login 类型清空 tags。安卓侧照做以保持 dedup_key 一致。
4. **JSON 中文不转义**:Python 用 `ensure_ascii=False`。Kotlin 序列化默认即 UTF-8 不转义,一致。
5. **写入原子性**:桌面端写 `*.tmp` 再 `os.replace`,并保留 `*.bak`。安卓写本地库时建议同样 tmp+rename,避免半截文件。

## 5. 原子写与备份回退(与桌面端对齐)

- 保存:写 `vault.pmv.tmp` → 成功后把旧 `vault.pmv` 复制为 `vault.pmv.bak` → 原子 rename tmp 覆盖。
- 打开:主文件结构损坏(非密码错误)时,回退尝试 `vault.pmv.bak`。
- 回收站自动清理:打开时按保留天数(默认 30)清除 `deleted_at` 超期的 trash 条目。

## 6. 备份兼容性

- **导出**:一律写 v2 布局(见 §2)。
- **导入**:仅接受 v2 布局;结构损坏或版本不符视为无效备份文件。