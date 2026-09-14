# 发布说明

## Android 发布流程

1. 在 `vault_android` 执行 Release 构建：

   ```powershell
   .\gradlew.bat assembleRelease
   ```

2. 将 ARM64 安装包复制到网站仓库的 `public/downloads/`，文件名使用：
   `FAEVault-<版本>-arm64-v8a.apk`。

3. 在 `faevault-site/src/components/DownloadPage.astro` 更新 Android 卡片版本和下载地址。PC 尚未发布时保留 Windows 卡片并显示“等待发布”。

4. 在 `faevault-site` 提交并推送网站代码。GitHub Pages 会自动构建下载页。

5. 创建 GitHub Release，仓库为 `faegit/faevault-site`，标签格式为 `v<版本>`，并上传同一个 APK：

   ```powershell
   gh release create v<版本> public/downloads/FAEVault-<版本>-arm64-v8a.apk --repo faegit/faevault-site --title "FAEVault Android <版本>" --notes "Android <版本> 发布"
   ```

应用内更新从该仓库的 `releases/latest` API 获取版本，并从 Release assets 下载 APK；只更新网站目录而不创建 GitHub Release 会导致应用内更新返回 404。
