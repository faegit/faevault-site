# SYNC_V2 — 多端同步规范

本规范定义保险库的多端双向同步语义。**桌面端与移动端必须实现同一份逻辑，并通过 `sync_v2_fixtures.json` 测试向量交叉校验。**

## 0. 设计原则

- **条目级粒度**：合并以 `Entry` 为单位，不到字段级
- **时间戳取胜（LWW）**：`updatedAt` 大者胜
- **原始时间戳比较**：`exportEpoch` 只作文件元数据，不改写条目时间
- **本地时间单调递增**：任一修改使用 `max(now, previousUpdatedAt + 1ms)`
- **墓碑替代物理删除**：`deletedAt != null` 即逻辑删除，参与同步
  - 注意：本规范的 `deletedAt` 是**条目级**墓碑，参与跨端同步。**账户容器级**的软删除（30 天回收站）由 [ACCOUNT_LIFECYCLE.md](ACCOUNT_LIFECYCLE.md) 定义，**不参与文件级同步**，每端独立维护
- **同秒并发 → 用户决定**：罕见，弹 UI 让用户选

## 1. Entry Schema

```
id          : string  (UUID v4，永不变)
createdAt   : i64     (秒，UTC)
updatedAt   : i64     (秒，UTC，任一字段变化必须刷新)
deletedAt   : i64?    (秒，UTC，null = 未删除)
... 其他业务字段（title / username / password / notes / tags / type / ...）
```

**写入约束**

| 操作 | updatedAt | deletedAt |
|---|---|---|
| 创建 | = now | null |
| 修改任一字段 | = max(now, previous + 1ms) | 保持不变（除非显式恢复） |
| 删除 | = max(now, previous + 1ms) | = updatedAt |
| 恢复（从墓碑回到正常） | = max(now, previous + 1ms) | null |

UI 渲染时 **必须过滤** `deletedAt != null` 的条目。"回收站"视图等价于 `entries.filter { deletedAt != null }`。

## 2. VaultPayload Schema 增量

```
entries       : List<Entry>
syncMeta      : SyncMeta = { deviceId: string }
exportEpoch   : f64       // 加密前由编码器写入：当下的 nowSeconds()
```

- `deviceId` 是保险库首次创建时生成的 UUID，**终生不变**，用作谱系校验
- `exportEpoch` 每次 `encode()` 时刷新为本地 nowSeconds()，仅作为导出元数据和旧格式兼容字段
- 老 `trash` 字段：v2 起不再单独维护，迁移时合并进 `entries`（见 §6）

## 3. .pmv 文件头（保持不变）

**不修改** VaultCrypto 二进制头，VERSION 字节不动。`exportEpoch` 与 `deviceId` 都在加密后的 JSON payload 内（§2），解密后即可拿到。

这些元数据放在加密 payload 内，不破坏既有头格式，也不向能读取加密文件的第三方泄露导出时间或保险库谱系。

## 4. 时钟与单调写入

合并时不得根据 `exportEpoch` 平移 `createdAt`、`updatedAt` 或 `deletedAt`。旧文件被再次导出会刷新 `exportEpoch`，若据此校准会把旧条目错误变成最新条目。

两端直接比较每条记录携带的原始 `updatedAt`。为抵御设备时钟回拨或另一台设备时钟超前，本地修改必须保证时间单调递增：

```
changedAt = max(nowSeconds(), previous.updatedAt + 0.001)
```

删除时 `deletedAt = updatedAt = changedAt`；恢复时清空 `deletedAt` 并令 `updatedAt = changedAt`；purge tombstone 必须晚于被彻底删除条目的 `updatedAt`。

## 5. 合并算法

```
fun merge(local: VaultPayload,
          incoming: List<Entry>,                   // 保留原始条目时间戳
          onConflict: (Entry, Entry) -> ConflictChoice): VaultPayload {

    byId = local.entries.associateBy { it.id }.toMutableMap()

    for (inc in incoming) {
        cur = byId[inc.id]
        if (cur == null) {
            byId[inc.id] = inc                     // 远端独有，加入
            continue
        }
        when {
            inc.updatedAt > cur.updatedAt -> byId[inc.id] = inc
            inc.updatedAt < cur.updatedAt -> { /* 保留本地 */ }
            else -> {
                if (cur.sameContent(inc)) continue          // 内容一致，跳过
                // 同秒且不同内容 = 真冲突
                when (onConflict(cur, inc)) {
                    KEEP_LOCAL  -> { /* 保留本地 */ }
                    KEEP_REMOTE -> byId[inc.id] = inc
                    KEEP_BOTH   -> {
                        dup = inc.copy(id = UUID.randomUUID().toString())
                        byId[dup.id] = dup
                    }
                }
            }
        }
    }

    return local.copy(entries = byId.values.toList())
}

enum ConflictChoice { KEEP_LOCAL, KEEP_REMOTE, KEEP_BOTH }
```

`Entry.sameContent(other)` 必须比较所有"用户可见字段"，**排除** `id` / `createdAt` / `updatedAt` / `deletedAt`。

## 6. v1 → v2 迁移

老库（无 `deletedAt`、无 `syncMeta`）首次以 v2 打开时：

```
entries' = old.entries.map { it.copy(deletedAt = null) }
         + old.trash.map   { it.copy(deletedAt = it.trashedAt ?: now) }
syncMeta = SyncMeta(deviceId = newRandomUuid())
```

迁移完成后写盘即升级为 v2 格式。

## 7. 墓碑回收（GC）

解锁时一次性清理：

```
cutoff = nowSeconds() - retentionDays * 86400
expired = entries.filter { it.deletedAt != null && it.deletedAt < cutoff }
for (entry in expired) {
    purgeTombstones[entry.id] = max(nowSeconds(), entry.updatedAt + 0.001)
}
entries = entries - expired
```

当前默认 `retentionDays = 7`，用户可在设置中调整。

**警告**：超过 retentionDays 没同步的设备拿不到墓碑，会让删除的条目"复活"。所以 retentionDays 必须 ≥ "最长可能离线时间"。

## 7.5 谱系护栏（cross-account guard）

`syncMeta.deviceId` 在语义上是**库谱系标识**（vault-lineage id），不是设备 id：

- 首次创建库时分配 UUID
- 库以任何方式（.pmv / .pmbak）导出再被其它设备导入时，谱系 id 随 JSON 一起带过去，被该新设备**继承**
- 因此"两份 vault 文件源自同一份原始库"⇔ `deviceId` 相同

合并方在执行 `.pmbak` / `.pmv` 导入合并前**必须比对** local 与 incoming 的 `syncMeta.deviceId`：

| local.deviceId | incoming.deviceId | 行为 |
|---|---|---|
| 非空且与 incoming 相同 | 同上 | 静默 LWW 合并 |
| 不同 | 不同 | **必须二次确认** —— 否则可能跨账户把两个不同的库混在一起 |
| 任一为空（老 v1 备份 / 第三方导出） | — | 同样触发二次确认（无法判断归属） |

二次确认的话术建议：明确告诉用户「这份备份不像是当前账户的库」，让其在「仍然合并」/「取消」之间选。

桌面端务必实现同款护栏，否则在用户多账户场景下会出现"导入了 A 的备份到 B 账户库里 → 两组凭据混在一处"的事故。

## 8. 云端与 WebDAV 同步事务

Android 与 PC 必须使用同一事务顺序：

1. 拉取远端加密文件并记录远端版本快照（SAF 原始字节，或 WebDAV ETag / 原始字节）
2. 本地解密并校验谱系
3. 使用本规范执行 LWW、回收站和 purge tombstone 合并
4. 计算解密逻辑摘要；若远端已经等于合并结果，则跳过上传
5. 上传前确认远端仍等于步骤 1 的快照；变化时中止并要求重新同步
6. 上传完整加密 `.pmv` 文件
7. 立即读回、解密，并验证谱系及完整逻辑摘要

逻辑摘要必须覆盖活动条目、回收站状态、所有用户字段、谱系标识和 purge tombstone；必须忽略条目顺序、标签顺序、`exportEpoch` 及每次加密产生的随机盐和 nonce。

云盘服务和 WebDAV 服务不执行条目合并，只负责存储加密文件。文件修改时间、目录修改时间和文件大小只能作为辅助元数据，不能决定条目新旧。

## 9. 冲突 UI 契约

云端自动同步遇到相同 `updatedAt` 但内容不同的条目时，两端统一使用 `KEEP_BOTH`，为远端副本生成新 UUID。保险库维护与手动去重仍通过对比界面让用户决定。

## 10. 互操作测试

`spec/sync_v2_fixtures.json` 列出 8 个核心场景。两端实现完合并函数后，必须用同一组 fixture 跑 assert：

```
for each fixture in fixtures:
    actual = merge(fixture.local, fixture.incoming, fixture.onConflict)
    assert actual == fixture.expected
```

桌面端跑通才算"实现完成"。

## 11. 不在本规范范围

- 字段级合并（未来 v3 考虑）
- Lamport / HLC / CRDT
- 服务端同步 / 端到端实时同步
- 增量传输（当前是全量 .pmv / .pmbak 交换）
