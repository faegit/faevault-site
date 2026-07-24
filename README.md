# FAEVault website

保险库 的公开官网、使用指南、开发历程、版本下载与赞助入口。

## 下载与安装

- [FAEVault 最新发布页](https://github.com/faegit/faevault-site/releases/latest)
- [在线下载页](https://faegit.github.io/faevault-site/zh-cn/download/)
- [Windows、Android 与浏览器扩展安装教程](./INSTALLATION.md)
- [3.6.4 更新日志](./RELEASE_NOTES_3.6.4.md)
- [3.6.4 SHA-256 校验值](./SHA256SUMS-3.6.4.txt)

## 本地运行

```powershell
npm install
npm run dev
```

## 验证

```powershell
npm run verify
```

## 部署

站点由 GitHub Actions 构建并发布到 GitHub Pages。所有内部链接都通过统一的 base path 生成，因此既可部署到 `faegit.github.io/faevault-site/`，也可在以后迁移到独立域名。
