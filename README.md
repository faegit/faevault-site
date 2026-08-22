# FAEVault website

保险库 的公开官网、使用指南、开发历程与赞助入口。

当前仓库仅保留项目网页，不提供版本安装包、发布日志或校验文件。

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
