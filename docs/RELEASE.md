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

## 同版本修复发布（4.5.0）

- Android 仓库先补全 `CHANGELOG.md`，提交完整代码；本轮提交名称为 `v4.5.0`。构建成功后再上传，不能复用旧 APK。
- Release 同时保留 `app-arm64-v8a-release.apk`、`app-armeabi-v7a-release.apk`、`app-x86-release.apk`、`app-x86_64-release.apk`、`app-universal-release.apk`，供客户端按已安装架构选择。
- 下载页仍使用 `FAEVault-4.5.0-arm64-v8a.apk`，它必须与 `app-arm64-v8a-release.apk` 内容完全一致。更新两个文件，避免网页与应用内更新取得不同构建。
- 已存在的 Release 使用 `gh release upload v4.5.0 <文件列表> --repo faegit/faevault-site --clobber` 替换资产，并用 `gh release edit ... --notes-file <更新日志文件>` 更新说明。
- 上传后核对 Release 资产名称、大小和 SHA-256 digest；推送网站仓库后核对 Pages 构建结果。
- 本地 ARM64 副本放到 `C:\Users\21236\OneDrive\应用\FAEVault-release-arm64-v8a.apk`，复制后比较 SHA-256。OneDrive 远端同步是否完成由客户端负责。
- 同版本修复沿用版本号时，已经安装 4.5.0 的用户需要手动下载安装；需要自动发现新版本时应在下一轮提升客户端版本与发布标签。
