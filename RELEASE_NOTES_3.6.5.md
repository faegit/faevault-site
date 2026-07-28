# FAEVault 3.6.5

发布日期：2026-07-28

## Android

- 多语言精简：移除日语、德语、西班牙语、繁体中文，仅保留简体中文和英文。
- Autofill 保存失败时通过通知 + startActivity 回退方案。
- 启动时自动请求 POST_NOTIFICATIONS 权限。
- HyperOS 系统 passkey 检测兼容性修复。
- PassManager 重命名重构为 FAEVault，更新 AAGUID 并启用 ABI 分包。
- 保存场景跳过自动生物识别认证，避免与登录冲突。
- 保存自动生物识别 + 独立 taskAffinity 修复弹出层行为。

## 安装

完整步骤见 [安装与升级指南](./INSTALLATION.md)，其中包含 Windows、Android、Chrome、Edge 和 Firefox 浏览器扩展教程。
