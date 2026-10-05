# 账户生命周期 — 软删除 / 回收站协议 v1

本规范定义"账户容器"（每个 `.pmv` 一个账户）的删除与恢复语义。

> 区别于 [SYNC_V2.md](SYNC_V2.md) 的"条目级墓碑"（`Entry.deletedAt`）：本规范处理的是**账户层**的删除标记，**不在 `.pmv` 文件内**，因此**不参与文件级同步**——每端独立维护自己的回收站。

PC 端与 Android 端实现各自的本地软删除时，应遵循下列约定，以便在跨端导入/恢复 UI 与 30 天清理窗口上保持一致体验。

## 0. 设计目标

- 用户误删账户后有 **30 天** 安全期可一键恢复
- 删除期间账户从所有可见入口消失，避免诱导误操作
- 二次注册同名账户时主页面提示恢复，原始数据/指纹绑定保持有效
- 真正物理删除只在 30 天过期后由启动期清理任务执行

## 1. 状态机

```
[Active] ──delete──▶ [Trashed(deletedAt)] ──restore──▶ [Active]
                              │
                              └── now ≥ deletedAt + RETENTION ──▶ [Purged]（不可逆）
```

| 状态 | 文件 | Keystore 别名 | 列表可见 | 可解锁 |
|---|---|---|---|---|
| Active | 在 | 在 | 是 | 是 |
| Trashed | 在 | 在 | 否（仅二次注册时探测） | 否 |
| Purged | 删 | 删 | 否 | 否 |

## 2. 删除（Active → Trashed）

写入回收站标记，**不动任何文件或密钥**：

```
trashedRegistry[name] = deletedAtMs    // 当前 wall-clock 毫秒
if currentAccount == name:
    currentAccount = null
```

不变量：
- `.pmv` / `.pmv.bak` / `<name>.recovery` 文件保持原状
- AndroidKeyStore 别名 `pmv_master_pw_<name>` / PC 端等价的指纹/Touch ID 绑定保留
- SharedPreferences 中其他与该账户相关的设置（如自动锁定）保留

## 3. 恢复（Trashed → Active）

```
trashedRegistry.remove(name)
```

恢复后立即可见，**不需要主密码**——真正的访问授权仍由解锁阶段的主密码保障。可选 UX：主页面"新建账户"输入到回收站同名时实时切换按钮文案为"恢复账户"。

## 4. 过期清理（Trashed → Purged）

每次 App 启动时（或后台周期任务）执行：

```
RETENTION = 30 * 24 * 3600 * 1000   // ms
cutoff = now - RETENTION
for (name, ts) in trashedRegistry:
    if ts <= cutoff:
        purgeNow(name)
```

`purgeNow(name)` 必须按此顺序：

1. 删除生物识别绑定（AndroidKeyStore 别名 / PC Touch ID Keychain item）
2. 删除 `.pmv`、`.pmv.bak`、`.pmv.tmp`
3. 删除 `<name>.recovery`
4. 删除 `trashedRegistry[name]`
5. 若 `currentAccount == name` 则清空

> **不可逆**：一旦 `purgeNow` 完成，用户**没有任何途径**找回数据。建议在 UI 上不暴露"立即彻底删除"按钮，强制 30 天缓冲期。

## 5. 存储格式（Android 参考实现）

Android 端把 `trashedRegistry` 存在 SharedPreferences `pmv_registry` 的字符串键 `trashed` 中，编码：

```
<entry>;<entry>;...      // ; 分隔 entry
<entry> := <escapedName>|<deletedAtMs>
escapedName: \ → \\,  | → \b,  ; → \s
deletedAtMs: 十进制 i64 字符串
```

PC 端的实现可自由选择存储介质（JSON / SQLite / Plist），**仅需保证语义等价**：
- map 键是账户名（与 `.pmv` 文件名一致，去 `.pmv` 扩展名）
- 值是删除时刻的 UTC 毫秒时间戳
- 保留期常量同为 30 天

## 6. 与 SYNC_V2 的交互

回收站标记**不参与文件级同步**：

- 用户在 Android 上软删除账户 A → A 的 `.pmv` 没变化 → 同步到 PC 后 PC 仍把 A 视为正常账户
- 反之亦然

这是有意为之：账户的可见性是**设备本地的用户偏好**，跨设备共享只会带来误操作风险。
如未来需要跨端"看见对方删了"，应在 `.pmv` 头部独立增加 `containerDeletedAt` 字段并写入 SYNC_V2 规范，本协议不背这部分语义。

## 7. 命名冲突与恢复入口

新建账户提交账户名时实时探测：

```
if name in trashedRegistry:
    UI:
        - 输入框标红
        - 密码栏 disabled
        - 主按钮文案: "恢复账户"
        - 点击 → restore(name)
    else:
        正常创建流程
```

这样既避免用户白填一遍密码，也防止"新建账户"路径意外覆盖回收站中的旧数据。

## 8. 版本

| 字段 | 值 |
|---|---|
| 协议版本 | 1 |
| 首次落地版本 | Android 2.3.3 / 桌面端 TBD |
| RETENTION_DAYS | 30 |
