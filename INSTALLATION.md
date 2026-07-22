# FAEVault 3.6.2 安装与升级指南

## Windows

1. 在 [v3.6.2 发布页](https://github.com/faegit/faevault-site/releases/tag/v3.6.2) 下载 `FAEVault_v3.6.2_Setup.exe`。
2. 双击安装包，按中文向导安装。默认目录为 `C:\Program Files\vault`，需要管理员权限。
3. 安装器检测到旧版本时会提示先卸载旧程序。确认后会替换程序文件，但不会删除用户保险库数据。
4. 如果提示程序正在运行，请关闭保险库和浏览器自动填充宿主后重试。

升级前建议先在应用的同步页面导出一份加密备份。需要免安装使用时，可从同一发布页下载 Windows x64 便携压缩包。

## Android

绝大多数现代 Android 手机请选择 `app-arm64-v8a-release.apk`；不确定设备架构时请选择 `app-universal-release.apk`。系统提示是否允许安装未知来源应用时，只为当前浏览器或文件管理器授权，安装完成后可关闭该权限。

若安装时提示签名冲突，说明设备上已有不同签名的测试版。请先导出加密备份，再卸载旧应用并安装正式版；不要在未备份时清除应用数据。

## Chrome 与 Edge 浏览器扩展

1. 安装并启动 Windows 版保险库。
2. 进入“设置 → 浏览器自动填充”，验证主密码后点击“启用”。
3. Chrome 打开 `chrome://extensions`，Edge 打开 `edge://extensions`。
4. 开启“开发者模式”，选择“加载已解压的扩展程序”。
5. 选择保险库设置页打开的扩展目录，然后固定 FAEVault 扩展图标。

首次填充时需要解锁保险库。局域网私有 IP 页面还会显示来源授权提示，只有点击“允许授权”后才会填充。

## Firefox 浏览器扩展

1. 先在保险库“设置 → 浏览器自动填充”中点击“启用”。
2. 打开 `about:debugging#/runtime/this-firefox`。
3. 点击“临时载入附加组件”，选择扩展目录中的 `manifest.firefox.json`。
4. Firefox 重启后临时扩展会失效，需要再次载入。

如果应用提示“未找到组件”，请安装 v3.6.2 完整 Windows 安装包；旧版安装包或只复制主程序 EXE 的目录不包含完整的浏览器宿主和扩展资源。
