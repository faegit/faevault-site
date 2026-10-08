"""Small, runtime UI translation layer for the first supported language batch.

Chinese remains the canonical source copy so the existing layout and wording do
not drift.  Translations are deliberately product copy, not word-for-word
substitutions.  A show-event filter also covers dialogs and notifications that
are created after startup.
"""

from __future__ import annotations

import re
from typing import Final

from .i18n_en_complete import DYNAMIC as _EN_COMPLETE_DYNAMIC
from .i18n_en_complete import EXACT as _EN_COMPLETE

SUPPORTED_LOCALES: Final = ("zh-Hans", "en")
LANGUAGE_OPTIONS: Final = (
    ("跟随系统", "auto"),
    ("简体中文", "zh-Hans"),
    ("English", "en"),
)

_locale = "zh-Hans"


def resolve_locale(mode: str, system_name: str) -> str:
    if mode in SUPPORTED_LOCALES:
        return mode
    normalized = (system_name or "").replace("_", "-").lower()
    for prefix, locale in (("zh", "zh-Hans"), ("en", "en")):
        if normalized.startswith(prefix):
            return locale
    # Preserve the established Chinese UI on unsupported system languages.
    return "zh-Hans"


def set_locale(locale: str) -> None:
    global _locale, _tr_dynamic_cache
    _locale = locale if locale in SUPPORTED_LOCALES else "zh-Hans"
    _tr_dynamic_cache.clear()


def current_locale() -> str:
    return _locale


_EN = {
    "输入排除项，例如 chrome.exe 或 example.com": "Enter an exclusion, such as chrome.exe or example.com",
    "从运行中的程序选择…": "Choose a running app…",
    "选择正在运行的程序，包含后台程序": "Choose a running app, including background apps",
    "选择排除程序": "Choose an app to exclude",
    "请输入程序名（如 chrome.exe）或有效的网站域名": "Enter a process name (such as chrome.exe) or a valid website domain",
    "添加排除项后，对应目标将不再显示自动填充建议。": "Excluded targets will no longer show autofill suggestions.",
    "暂未添加排除项": "No exclusions yet",
    "启动与后台": "Startup and background",
    "开机启动": "Start at sign-in",
    "静默启动": "Start quietly",
    "登录 Windows 后自动运行，适用于当前 Windows 用户。": "Run automatically when the current Windows user signs in.",
    "下次启动时仅显示托盘图标；保险库保持锁定，点击托盘后显示解锁窗口。托盘不可用时仍显示窗口。": "Start in the system tray next time, with the vault locked. Click the tray icon to unlock. If the tray is unavailable, the unlock window opens.",
    "已开启开机启动，下次登录 Windows 后自动运行。": "Startup enabled. Vault will run when you next sign in to Windows.",
    "已关闭开机启动。": "Startup disabled.",
    "保险库": "Vault", "解锁保险库": "Unlock your vault", "选择用户并输入主密码以解锁。": "Choose a vault and enter its master password.",
    "＋ 新建": "+ Add", "新建账户": "Create vault", "导入 .pmv 文件": "Import .pmv file", "主密码": "Master password",
    "解锁": "Unlock",     "使用生物识别解锁": "Unlock with biometric", "忘记密码？": "Forgot your password?",
    "正在解锁…": "Unlocking…",
    "开始使用": "Get started", "还没有账户，请新建或从文件导入。": "Create a vault or import an existing .pmv file.",
    "暂无账户": "No accounts",
    "请点击“＋ 新建”，创建账户或从文件、局域网导入。": "Select “＋ New” to create an account or import one from a file or your local network.",
    "操作完成后可关闭": "You can close this window when the operation finishes",
    "正在检测本机已保存的 Wi-Fi…": "Checking saved Wi-Fi networks…",
    "无法检测本机 Wi-Fi 配置，请稍后重试。": "Could not read saved Wi-Fi networks. Try again later.",
    "无法打开密码库，请稍后重试": "Could not open the vault. Please try again.",
    "云端文件读回校验失败": "Cloud file read-back verification failed",
    "从 .pmv 文件导入": "Import a .pmv file", "退出": "Exit", "回收站": "Trash", "锁定": "Lock", "设置": "Settings",
    "关闭设置": "Close settings", "＋  新建条目": "+  New item", "安全中心": "Security", "导入、导出和整理": "Import, export and organize",
    "返回安全总览": "Back to overview",
    "同步": "Sync", "局域网同步": "Local network sync", "连接传输站": "Connect to a transfer station", "启用联网同步": "Enable online sync", "云端同步": "Cloud sync",
    "连接": "Connect", "断开连接": "Disconnect",
    "同步保险库": "Sync vault", "发送文本": "Send text", "发送文件": "Send file",
    "发送": "Send",
    "发送内容：输入文本，或直接粘贴图片发送": "Content: type text, or paste an image to send",
    "发送内容：输入文本，或直接粘贴图片/文件发送": "Content: type text, or paste an image or file to send",
    "选择要发送的文件（可多选）": "Select files to send (multi-select)",
    "服务器地址": "Server address", "选择要发送的文件": "Choose a file to send", "正在连接…": "Connecting…", "连接成功": "Connected",
    "PIN 码错误，请检查后重试": "Wrong PIN, please try again", "请输入地址和 6 位 PIN 码": "Enter the address and 6-digit PIN.",
    "正在同步保险库…": "Syncing vault…", "正在下载保险库…": "Downloading vault…", "正在上传保险库…": "Uploading vault…", "同步完成 · ": "Sync complete · ",
    "连接失败：": "Connection failed: ", "同步失败：": "Sync failed: ", "发送失败：": "Send failed: ",
    "设备认证失败：": "Device authentication failed: ",
    "仅 PMVE 支持分叉合并": "Only PMVE vaults support divergent merges",
    "远端不是同一份 PMVE 保险库": "The remote is not the same PMVE vault",
    "仅 DIVERGED 关系允许合并采纳": "Only a DIVERGED lineage can be merge-adopted",
    "本地 PMVE 在合并前发生并发修改": "The local PMVE changed concurrently before the merge",
    "PMVE 合并暂存文件复验不一致": "PMVE merged staging file verification mismatch",
    "PMVE 合并后身份复验失败": "PMVE identity verification failed after merge",
    "文件传输": "File transfer", "退出传输": "Exit transfer", "连接并导入": "Connect & import",
    "正在连接，等待对方确认导出…": "Connecting… waiting for the remote device to approve the export",
    "正在拉取对方保险库…": "Downloading the remote vault…",
    "无效的连接通道": "Invalid connection channel",
    "导出拉取需以导出通道连接": "Export pull requires an export-channel connection",
    "从另一台设备的传输站导出数据，导入为本机新账户。\n输入地址与连接码后连接；对方设备上需确认导出后才开始下载。": "Export data from another device's transfer station and import it as a new local vault.\nEnter the address and connection code to connect; the remote device must approve the export before the download starts.",
    "输入服务器地址与 PIN 码，连接另一台设备的传输站": "Enter the server address and PIN to connect to another device's transfer station.",
    "请用手机扫描二维码即可连接（无需输入 PIN）\n手机和电脑必须连接同一局域网，跨网络或移动数据无法连接\n连接码与二维码每 2 分钟自动刷新；等待连接 3 分钟；连接后处理期间自动续期": "Scan the QR code with your phone to connect (no PIN entry needed).\nPhone and PC must be on the same LAN; cross-network or mobile-data connections won't work.\nThe code and QR refresh every 2 minutes; waits up to 3 minutes for a connection; auto-extends while processing after connecting.",
    "输入要发送到对方设备的文本": "Enter text to send to the other device.", "收到文本并已复制，剪贴板将按设置自动清空": "Received text copied; clipboard will auto-clear per settings.",
    "文件已接收，但传输站未收到确认，可能还会再发一次": "File received, but the transfer station did not get the receipt and may send it again.",
    "建立传输站": "Set up a transfer station", "关闭传输站": "Close the transfer station",
    "传输站已关闭": "Transfer station closed",
    "当前连接正在进行，请先完成或断开后再切换模式": "A connection is active; finish or disconnect it before switching modes",
    "关闭连接": "Close connection",
    "同步/连接仍在进行，关闭将断开与手机端的连接，进度无法继续。确定要关闭吗？": "Sync/connection is still in progress. Closing will disconnect the phone and the progress cannot continue. Close it anyway?",
    "连接仍在进行，关闭窗口将断开与传输站的连接，进度无法继续。确定要关闭吗？": "Connection is still in progress. Closing the window will disconnect from the transfer station and the progress cannot continue. Close it anyway?",
    "局域网": "Local network",
    "扫码 / 输入地址同步": "Scan or enter an address to sync",
    "扫码 / 输入地址传输文件": "Scan or enter an address to transfer files",
    "粘贴图片": "Paste image",
    "剪贴板中没有可发送的图片": "No image is available in the clipboard",
    "本地备份": "Local backup",
    "更多功能": "More", "库维护": "Vault maintenance", "导入导出": "Import & export",
    "重复条目合并": "Merge duplicate items", "相同服务合并": "Merge same-service items",
    "更多功能：导入导出 / 本地备份 / 局域网 / 云端同步 / 库维护": "More: import & export / local backup / local network / cloud sync / vault maintenance",
    "启用本地备份": "Enable local backup",
    "选择备份目录": "Choose backup folder",
    "定期把保险库文件备份到本地目录（仅覆盖，不同步）；目录不可用或设备未连接时自动等待，不报错。": "Back up the vault file to a local folder periodically (overwrite only, no sync); it waits silently when the folder or device is unavailable.",
    "定期把保险库文件备份到本机目录或外接U盘/硬盘（仅覆盖，不同步）；目录不可用或设备未连接时自动等待，不报错。": "Back up the vault file to a local folder or external USB/disk periodically (overwrite only, no sync); it waits silently when the folder or device is unavailable.",
    "实时          每小时          每天          每周          每月": "Realtime      Hourly      Daily      Weekly      Monthly",
    "立即备份": "Back up now",
    "未选择备份目录": "No backup folder selected",
    "等待设备状态": "Waiting for device",
    "已备份 ": "Backed up ",
    "备份失败：": "Backup failed: ",
    "备份设备：": "Backup device: ",
    "无法识别稳定的设备身份，已拒绝备份": "Unable to identify a stable device identity; backup refused.",
    "允许此存储设备用于同步": "Allow this storage device for sync",
    "FAEVault 将在所选目录保存设备 UUID，并绑定本次目录授权。允许此存储设备用于同步？": "FAEVault will save a device UUID in the selected folder and bind it to this folder authorization. Allow this storage device for sync?",
    "检测到设备目录授权发生变化。确认这是原设备，并允许此存储设备用于同步？": "The device folder authorization changed. Confirm this is the original device and allow it for sync?",
    "设备 UUID 与已保存绑定不一致，自动同步已被阻止。确认重新绑定此设备？": "The device UUID does not match the saved binding, so automatic sync was blocked. Rebind this device?",
    "身份异常，已禁止自动同步": "Identity anomaly detected; automatic sync is blocked.",
    "设备身份已变化，请重新确认": "The device identity changed; confirm it again.",
    "检测到新存储设备，请选择目录并授权": "New storage device detected; select its folder and authorize it.",
    "设备 UUID 标记创建失败，已拒绝备份": "The device UUID marker could not be created; backup was refused.",
    "空间不足，已跳过本次备份": "Insufficient space; this backup was skipped.",
    "数据同步": "Sync data",
    "连接传输站 — 数据同步": "Connect to transfer station — data sync",
    "连接传输站 — 文件传输": "Connect to transfer station — file transfer",
    "扫码识别": "Scan QR code", "摄像头扫码": "Scan with camera", "从图片文件识别": "Scan from an image file",
    "选择二维码图片": "Choose a QR image",
    "图片 (*.png *.jpg *.jpeg *.bmp *.webp)": "Images (*.png *.jpg *.jpeg *.bmp *.webp)",
    "扫描传输站二维码": "Scan the transfer station QR code",
    "已识别传输站地址，可直接连接": "Transfer station address recognized — you can connect now",
    "未识别到二维码": "No QR code recognized",
    "画面中没有传输站二维码，请对准后重试": "No transfer-station QR in view. Reframe and try again.",
    "所选图片中没有可识别的传输站二维码": "No transfer-station QR could be read from the selected image.",
    "所选图片中没有可识别的二维码。": "No recognizable QR code was found in the selected image.",
    "图片超过 32 MB": "Image exceeds 32 MB",
    "无法打开摄像头": "Could not open the camera", "扫码失败": "QR scan failed",
    "无法查看图片": "Cannot view image",
    "图片无法读取": "Cannot read image",
    "无法打开图片": "Cannot open image",
    "图片保存失败": "Image save failed",
    "无法保存图片": "Cannot save image",
    "图片数据无法解码": "The image data cannot be decoded",
    "图片数据无法解码。": "The image data cannot be decoded.",
    "显示文件互传": "Show file transfer", "隐藏文件互传": "Hide file transfer",
    "选择要建立的连接通道：\n数据同步用于合并两端的保险库；\n文件传输用于互传文件与文本。": "Choose the connection channel:\ndata sync merges both vaults;\nfile transfer exchanges files and text.",
    "开启后，本机保险库会在 3 分钟内允许同局域网设备凭二维码和 PIN 同步数据或互传文件。\n\n确定要建立传输站吗？": "For 3 minutes, devices on the same local network can use the QR code and PIN to sync data or exchange files.\n\nStart the transfer station now?",
    "无法启动传输站": "Could not start the transfer station",
    "端口 18765 已被占用，请先关闭占用该端口的程序后重试。": "Port 18765 is already in use. Close the program using that port and try again.",
    "粘贴传输站的完整地址（已包含 PIN），或扫码识别自动填入": "Paste the full transfer station address (including its PIN), or scan the QR code to fill it in automatically.",
    "地址无效：请粘贴包含 pin=… 的完整传输站地址": "Invalid address: paste the full transfer station address, including pin=….",
    "导入": "Import", "浏览器导入": "Import from browser", "Wi-Fi 导入": "Import over Wi-Fi", "导入密码数据": "Import passwords",
    "导入加密备份": "Import encrypted backup", "导出": "Export", "导出 .pmv 库": "Export .pmv vault",
    "导出加密备份": "Export encrypted backup", "整理": "Organize", "合并重复条目": "Merge duplicates",
    "支持 Bitwarden CSV/未加密 JSON，以及 1Password、LastPass、KeePass 和主流浏览器 CSV；导入后与当前库合并。": "Supports Bitwarden CSV or unencrypted JSON, plus CSV exports from 1Password, LastPass, KeePass and major browsers. Imported items are merged into this vault.",
    "外观": "Appearance", "主题": "Theme", "浅色": "Light", "深色": "Dark", "跟随系统": "Use system setting", "语言": "Language",
    "简体中文": "Simplified Chinese", "安全": "Security", "自动锁定": "Auto-lock", "离开一段时间后重新要求主密码。": "Require the master password again after inactivity.",
    "超时时间": "Lock after", "复制后清空剪贴板": "Clear clipboard after",     "不自动清空": "Never clear automatically",
    "超过保留天数的条目会从回收站自动彻底删除。": "Items older than the retention period are permanently removed from Trash.",
    "修改主密码": "Change master password", "敏感内容需验证主密码": "Protect sensitive content with master password",
    "隐私": "Privacy", "防止截屏 / 录屏": "Block screenshots and screen recording", "用户": "Account", "删除当前用户": "Delete current vault",
    "关于": "About", "隐私政策": "Privacy policy", "更新日志": "Release notes", "取消": "Cancel", "确定": "OK", "关闭": "Close",
    "恢复密钥": "Recovery key", "重新生成": "Generate a new key", "泄露/丢失？重新生成": "Exposed or lost? Generate a new key",
    "已解锁": "Vault unlocked", "已切换主题": "Theme updated", "已从回收站恢复": "Restored from Trash", "无变化": "No changes",
    "保险库已自动压缩，历史空间已回收": "Vault compacted automatically; history space reclaimed",
    "已复制": "Copied", "邮箱已复制。": "Email address copied.", "语言将在重启后生效。": "The new language will be used after restart.",
}
_EN.update({
    "保险库中没有可填充的登录条目": "There are no login items available to fill.",
    "当前程序未允许读取密码输入框，无法保存": "This app does not allow its password field to be read, so the credential cannot be saved.",
    "所选条目已变化，请重新选择": "The selected item changed. Select it again.",
    "此网站已关闭自动填充": "Autofill is disabled for this website.",
    "所选条目未绑定当前程序，请新建条目保存": "The selected item is not linked to this app. Save it as a new item.",
    "未允许将所选条目填充到此网页": "Filling the selected item into this page was not approved.",
    "条目或网页权限已变化，请重试": "The item or website permissions changed. Please try again.",
    "确认自动填充来源": "Confirm autofill destination",
    "未设置": "Not set",
    "所选条目仅名称与此网页有单词匹配。\n\n条目：{title}\n保存的网站：{url}\n当前网页：{origin}\n\n确认信任当前网页后，允许仅本次填充所选条目？": "The selected item shares a matching word with this page.\n\nItem: {title}\nSaved website: {url}\nCurrent page: {origin}\n\nIf you trust this page, allow this item to be filled once?",
    "无法读取当前程序路径，程序可能以管理员身份运行": "Could not read the current app path. The app may be running as administrator.",
    "无法读取当前程序路径": "Could not read the current app path.",
    "不关联独立动态码": "No linked one-time code",
    "原关联动态码当前不可用": "The previously linked one-time code is unavailable",
    "关联动态码": "Linked one-time code",
    "关联填充内容": "Linked autofill content",
    "选择关联填充内容…": "Choose linked autofill content…",
    "暂无可关联内容": "No linkable content available",
    "自动填充来源冲突": "Autofill source conflict",
    "选择关联字段": "Choose fields to link",
    "普通字段默认关联；敏感字段需要你明确勾选。": "Regular fields are selected by default; select sensitive fields explicitly.",
    "关联所选字段": "Link selected fields",
    "本条目已有内建值": "already has a built-in value",
    "已有外部来源": "already has an external source",
    "“{role}”{conflicts}。\n\n改用“{source} · {field}”吗？\n选择取消会保留当前来源。": "{role} {conflicts}.\n\nUse “{source} · {field}” instead?\nCancel keeps the current source.",
    "搜索名称或账号…": "Search names or accounts…",
    "填充账号、密码和已关联动态码，不会自动提交；HOTP 仅在动态码写入成功后推进。": "Fills the account, password, and linked one-time code without submitting. HOTP advances only after the code is written successfully.",
    "新建当前账号": "Save as new account",
    "更新所选账号": "Update selected account",
    "分别管理原生程序和网站；排除后不会显示对应的自动填充建议。": "Manage excluded desktop apps and websites. Excluded targets do not receive autofill suggestions.",
    "安卓应用排除（随保险库同步）": "Excluded Android apps (synced with vault)",
    "网站排除": "Excluded websites",
    "输入网站，例如 example.com": "Enter a website, such as example.com",
    "移除所选网站": "Remove selected website",
    "请输入有效的网站域名，不支持 IP 地址": "Enter a valid website domain. IP addresses are not supported.",
    "该网站已在排除清单中": "This website is already excluded.",
    "检查更新": "Check for updates", "正在检查…": "Checking…", "检查失败": "Update check failed",
    "已是最新版本": "Up to date", "无法打开下载": "Could not open download",
    "无法自动更新": "Could not update automatically", "发布未提供校验文件，已为您打开下载页面。": "No checksum file is provided for this release. The download page has been opened instead.",
    "正在连接下载服务…": "Connecting to the download service…",
    "正在下载更新… {0} MB / {1} MB": "Downloading update… {0} MB of {1} MB",
    "正在下载更新… {0} MB": "Downloading update… {0} MB",
    "正在校验安装包完整性…": "Verifying package integrity…",
    "正在安装新版本…\n\n安装程序在后台运行，请勿关闭此窗口或手动结束安装程序。": "Installing the new version…\n\nThe installer is running in the background. Do not close this window or end the installer.",
    "安装完成。\n\n保险库即将退出，请重新启动以使用新版本。": "Installation complete.\n\nThe vault will exit now; relaunch to use the new version.",
    "安装程序返回错误代码 {0}": "The installer returned error code {0}",
    "更新失败：{0}\n\n可前往官网发布页手动下载。": "Update failed: {0}\n\nYou can download it manually from the release page.",
    "下载更新失败：{0}\n\n可前往官网发布页手动下载。": "Download failed: {0}\n\nYou can download it manually from the release page.",
    "下载更新 {0}": "Download update {0}",
    "账户与解锁": "Vault and unlock", "隐私与安全": "Privacy and security",
    "自动填充与通行密钥": "Autofill and passkeys", "关于与支持": "About and support",
    "桌面程序自动填充": "Desktop app autofill", "浏览器通行密钥": "Browser passkeys",
    "Windows 通行密钥": "Windows passkeys",
    "启用浏览器通行密钥": "Enable browser passkeys",
    "取消浏览器通行密钥关联": "Disconnect browser passkeys",
    "注册 Windows 通行密钥服务": "Register Windows passkey service",
    "取消 Windows 通行密钥注册": "Unregister Windows passkey service",
    "请先启用浏览器通行密钥。": "Enable browser passkeys first.",
    "修复 Windows 通行密钥缓存": "Repair Windows passkey cache",
    "会话与锁定": "Session and locking",     "自动填充": "Autofill", "安全设置": "Security settings",
    "自动检测周期": "Auto-check period", "检测设置": "Check settings", "账户设置": "Vault settings",
    "数据保留": "Data retention", "验证与保护": "Verification and protection", "允许截屏": "Allow screenshots",
    "启用密码检测": "Enable password breach check", "立即检测": "Check now", "联网检测密码泄露": "Online breach check",
    "正在准备检测条目…": "Preparing items for checking…", "使用密码哈希前 5 位进行查询。": "Queries use only the first 5 characters of the password hash.",
    "敏感信息二次验证": "Secondary verification for sensitive info",
    "支持主流密码管理器、CSV、JSON 导入后合并": "Import and merge data from popular password managers, CSV, and JSON",
    "在目标程序输入框中按快捷键；密码通过 Windows UI Automation 写入，不经过剪贴板。": "Press the shortcut in the target app. Passwords are written through Windows UI Automation without using the clipboard.",
    "通行密钥": "Passkey",
    "登录": "Login", "银行卡": "Payment cards", "卡证": "Cards & documents", "Wi-Fi": "Wi-Fi",
    "密钥": "Key", "动态码": "One-time codes", "安全笔记": "Secure notes", "服务器": "Servers", "自定义": "Custom",
    "卡片类型": "Card type", "身份证": "National ID card",
    "卡片名称": "Card name", "日期时间类型": "Date and time type",
    "直接输入": "Direct input", "日历选择": "Choose from calendar", "小时": "Hour", "分钟": "Minute", "是": "Yes", "否": "No",
    "仅日期": "Date only", "仅时间": "Time only", "日期和时间": "Date and time",
    "提示": "Notice", "导入失败": "Import failed", "导入成功": "Import complete", "导入结果": "Import summary",
    "导出失败": "Export failed", "同步失败": "Sync failed", "同步完成": "Sync complete", "下载完成": "Download complete",
    "下载覆盖失败": "Download failed", "上传完成": "Upload complete", "上传覆盖失败": "Upload failed", "关联失败": "Couldn’t connect",
    "连接失败": "Connection failed", "配置无效": "Invalid settings", "创建失败": "Couldn’t create vault", "启用失败": "Couldn’t enable",
    "已启用": "Enabled", "已修改": "Changes saved", "已重新生成": "New key generated", "确认删除": "Move to Trash?",
    "清空回收站": "Empty Trash?", "彻底删除": "Delete permanently?", "暂无标签": "No tags yet", "无重复条目": "No duplicates found",
    "没有可导出的条目": "There are no items to export.", "备份密码错误或文件已损坏。": "The backup password is incorrect or the file is damaged.",
    "已添加密码": "Password added", "已保存修改": "Changes saved", "已移入回收站": "Moved to Trash",
    "泄露检测已关闭": "Breach checks are disabled", "泄露检测正在进行": "A breach check is already running", "已打开密码库所在文件夹": "Vault folder opened",
    "下载更新": "Download update", "取消同步": "Cancel sync", "合并选中的 0 条": "Merge 0 selected items",
    "密钥内容已隐藏，请从你保存的位置参考。": "The key is hidden. Refer to the copy you saved.",
    "已确认": "Confirmed", "已跳过": "Skipped", "待处理": "Pending",
    "按网址或包名分组。点击分组标题可整组选中，点击条目可查看详情。": "Grouped by website or package name. Select a group from its heading, or open an item to view its details.",
    "相同服务处理": "Same-service items", "确认合并": "Confirm merge", "稍后": "Later",
    "重复条目对比": "Merge duplicates", "关闭标签": "Close tab", "已完成": "Done",
    "自动同步": "Automatic sync",
    "请用手机扫描二维码并输入 PIN 码\n手机和电脑必须连接同一局域网，跨网络或移动数据无法连接\n等待连接 3 分钟；连接后处理期间自动续期": "Scan the QR code with your phone and enter the PIN.\nThe phone and PC must be on the same local network; mobile data and other networks cannot connect.\nThe connection waits for 3 minutes and stays active while synchronization is in progress.",
    "返回修改": "Go back",
    "远端已有保险库数据。请选择同步合并、上传覆盖本地数据到远端，或下载覆盖远端数据到本地。": "The remote location already contains vault data. Merge it, overwrite it with local data, or replace the local vault with the remote copy.",
    "选中的条目包含不同的标题、用户名或密码，请指定合并后使用哪个。": "The selected items have different titles, usernames, or passwords. Choose the values to keep after merging.",
})
_EN.update(_EN_COMPLETE)

# The main surfaces must never fall back to Chinese in a supported locale.
# English is the complete catalog; Simplified Chinese is the canonical copy.
_CORE_UI_TRANSLATIONS = {
    " 秒": " sec", " 天": " days", " 天后删除": " days",
    "＋ 新增条目": "+ New item",
    "新增条目": "New item",
    "已泄露": "Exposed",
    "已泄露（弱密码）": "Exposed (weak password)",
    "已过期": "Expired",
    "即将过期": "Expiring soon",
    "规则通过率": "Rules passed",
    "搜索名称、用户名、标签…": "Search names, usernames or tags…",
    "条目详情": "Entry details",
    "用户名": "Username",
    "密码": "Password",
    "网址": "Website",
    "创建时间": "Created",
    "最后修改": "Last updated",
    "编辑": "Edit",
    "查看": "View",
    "删除": "Delete",
    "复制": "Copy",
    "支持 Markdown：标题、列表、代码、表格等": "Supports Markdown: headings, lists, code, tables, etc.",
    "Markdown 显示模式": "Markdown view mode",
    "原生程序自动填充": "Desktop app autofill",
    "通行密钥服务": "Passkey service",
    "保险库维护": "Vault maintenance",
    "赞助支持": "Support development",
    "打开赞助页面": "Open sponsorship page",
    "在浏览器中打开赞助页面了解支持方式。": "Open the sponsorship page in your browser to learn about ways to support the project.",
    "修改主密码": "Change master password",
    "打开密码库所在文件夹": "Open vault folder",
    "删除当前用户": "Delete current vault",
    "安全检测": "Security check",
    "密码安全总览": "Password security overview",
    "正在扫描": "Scanning",
    "高风险": "High risk",
    "需改进": "Needs attention",
    "未发现问题": "No issues found",
    "高风险检测": "High-risk findings",
    "重新执行本地检测": "Run local check again",
    "执行联网泄露检测": "Check for known breaches",
    "先执行本地规则检查；公开泄露状态只有在联网检测成功后才会更新。": "Local rules run first. Known-breach status is updated only after a successful online check.",
    "先执行本地规则扫描，检查重复、弱密码、常见模式和长期未更新；联网泄露状态只有在手动校验成功后才会更新。": "Local rules scan for reused, weak, common-pattern and long-unchanged passwords first. Known-breach status updates only after a manual online check succeeds.",
    "本地规则不会上传密码；联网泄露检测只发送密码哈希前缀。": "Local checks never upload passwords. Online breach checks send only a short hash prefix.",
    "本地规则不会上传密码；联网泄露检测使用密码哈希前 5 位校验。": "Local checks never upload passwords. Online breach checks use the first five password-hash characters.",
    "自动锁定": "Auto-lock",
    "外观": "Appearance",
    "安全": "Security",
    "隐私": "Privacy",
    "显示后自动隐藏": "Hide after revealing",
    "回收站自动清理": "Automatic Trash cleanup",
    "尚未授权局域网 IP 来源": "No local-network IP sources are authorized",
    "联系": "Contact",
    "输入紧急恢复密钥并设置新的主密码。成功后恢复密钥本身保持不变。": "Enter the full recovery key and choose a new master password. The recovery key remains valid.",
    "开启后，本机保险库会在 3 分钟内允许同局域网设备凭二维码和 PIN 拉取并同步数据。\n\n开启局域网同步需要验证当前主密码。": "For 3 minutes, devices on the same local network can use the QR code and PIN to download and synchronize this vault.\n\nYour current master password is required to start local sync.",
    "请用手机扫描二维码并输入 PIN 码": "Scan the QR code with your phone, then enter the PIN",
    "等待连接 3 分钟；连接后处理期间自动续期": "Waiting for 3 minutes; the session stays active while sync is in progress",
    "远端主密码": "Remote master password",
    "远端恢复密钥": "Remote recovery key",
    "验证远端凭据": "Verify remote credentials",
    "远端凭据验证通过，请选择保留哪一端密钥。": "Remote credentials verified. Choose which device's keys to keep.",
    "验证失败，请检查远端主密码和恢复密钥。": "Verification failed. Check the remote master password and recovery key.",
    "保留本端密钥": "Keep local keys",
    "采用远端密钥": "Use remote keys",
    "用户": "Account",
    "关于": "About",
}
_EN.update(_CORE_UI_TRANSLATIONS)

_FORM_AND_SETTINGS_TRANSLATIONS = {
    "类型": "Type", "条目名称": "Item name",
    "附加内容": "Additional content", "标签": "Tags",
    "基本信息": "Basic information", "用于识别和查找此条目": "Identify and find this item",
    "按需组合模块，可拖动调整顺序": "Add modules as needed; drag to reorder",
    "补充额外说明": "Additional notes", "不属于字段的附加说明": "Notes outside the fields",
    "填写基本信息，并按需添加附加内容": "Fill in basic information and add content as needed",
    "条目": "Item",
    "扫描卡证": "Scan card or document",
    "将卡证放入画面，或选择图片": "Place a card or document in view, or choose an image",
    "摄像头不可用，请选择图片": "Camera unavailable. Choose an image.",
    "保持卡证边缘稳定，检测后自动进入四角校正": "Hold the document steady; corner review starts automatically",
    "拖动四角调整裁切范围，然后确认": "Drag the four corners to adjust the crop, then confirm",
    "确认裁切并识别": "Confirm crop and recognize",
    "选择卡证图片": "Choose a card or document image",
    "图片不能超过 16 MB": "Image must be 16 MB or smaller",
    "扫描识别银行卡": "Scan bank card",
    "扫描识别身份证": "Scan ID card",
    "扫描获取图像": "Scan image",
    "卡证最多保存 2 张图片。": "Cards and documents can contain at most two images.",
    "完整卡号": "Full card number", "开户行": "Bank", "分行/支行": "Branch",
    "证件号": "ID number",
    "备注": "Notes", "内容": "Content",
    "主机 / IP": "Host / IP", "端口": "Port",
    "关联程序": "Linked app", "关联程序 / 包名": "Linked app / package",
    "关联自动填充内容": "Linked autofill sources",
    "来源不可用": "Source unavailable",
    "清除": "Remove",
    "拖动标签调整顺序，保存后更新标签栏。": "Drag tags to reorder; saving updates the tag bar.",
    "选择需要重命名的标签。": "Choose the tags to rename.",
    "批量添加标签": "Add tags in bulk",
    "输入或选择多个标签，追加到所选条目的现有标签。": "Enter or pick several tags; they are added to the existing tags of the selected entries.",
    "显示或隐藏密码": "Show or hide password",
    "未命名条目": "Untitled entry",
    "持卡人姓名": "Cardholder name", "卡号": "Card number",
    "取款密码": "ATM PIN", "有效期": "Expiry",
    "发卡行": "Issuer", "卡片图片": "Card images",
    "姓名": "Full name", "证件类型": "Document type",
    "自定义名称": "Custom name", "证件号码": "Document number",
    "签发日期": "Issued", "到期日期": "Expires",
    "签发机关": "Issuing authority", "证件图片": "Document images",
    "网络名称 (SSID)": "Network name (SSID)", "加密类型": "Security type",
    "路由器管理地址": "Router admin address", "服务名称": "Service name",
    "权限范围": "Scopes", "密钥": "Secret key",
    "发行方": "Issuer", "账户名": "Account name",
    "算法": "Algorithm", "位数": "Digits",
    "周期": "Period", "计数器": "Counter",
    "关联域名": "Associated domains", "逗号或换行分隔，如 example.com，www.example.com": "Separate with commas or new lines, e.g. example.com, www.example.com",
    "保存": "Save", "生成": "Generate", "选择…": "Choose…",
    "管理标签": "Manage tags", "搜索标签": "Search tags",
    "排序标签": "Sort tags", "重命名标签": "Rename tag",
    "选择标签后可重命名；拖动标签可调整筛选栏顺序。": "Select a tag to rename it, or drag tags to reorder the filter bar.",
    "高级选项": "Advanced options",
    "添加附件": "Add attachment", "添加图片": "Add image",
    "选择关联应用": "Select app to associate",
    "当前版本暂不支持此模块；数据将原样保留。": "This module is not supported in this version. Its data will be preserved.",
    "尚未添加内容": "No content added",
    "主题": "Theme", "语言": "Language",
    "离开一段时间后重新要求主密码。": "Require the master password again after inactivity.",
    "超时时间": "Lock after", "复制后清空剪贴板": "Clear clipboard after",
    "生物识别解锁": "Biometric unlock",
    "敏感内容需验证主密码": "Protect sensitive content with master password",
    "启用全局快捷键": "Enable global shortcut",
    "撤销全部局域网授权": "Revoke all local-network access",
    "启用通行密钥": "Enable passkeys",
    "取消通行密钥关联": "Disconnect passkey",
    "防止截屏 / 录屏": "Block screenshots and recording",
    "密码泄露检测": "Password breach checks",
    "联网查询泄露库": "Check known breaches online",
    "泄露检测复检周期": "Breach recheck interval",
    "当前用户": "Current vault", "隐私政策": "Privacy policy",
    "更新日志": "Release notes",
    "恢复密钥泄露/丢失？重新生成": "Recovery key exposed or lost? Generate a new one",
    "在主列表查看": "View in main list", "改进建议": "Recommendations",
}
_EN.update(_FORM_AND_SETTINGS_TRANSLATIONS)

_MODULE_TRANSLATIONS = {
    "模块": "Module", "添加模块": "Add module",
    "模块名称": "Module name", "删除模块": "Delete module",
    "文本": "Text", "Markdown": "Markdown",
    "图片": "Images", "附件": "Attachments",
    "登录": "Login", "API 凭证": "API credentials", "API凭证": "API credentials",
    "数据库连接": "Database connection",
    "地址": "Address", "恢复信息": "Recovery information",
    "对方设备": "Peer device", "本次连接": "This connection",
    "设备 ID": "Device ID", "密钥指纹": "Key fingerprint", "通道": "Channel",
    "连接时长": "Connected for",
    "通用": "General", "账号与网络": "Accounts and network",
    "身份与金融": "Identity and finance",
    "管理地址": "Admin address", "私钥": "Private key",
    "指纹": "Fingerprint", "数据库类型": "Database type",
    "数据库名": "Database name", "银行": "Bank",
    "国家 / 地区": "Country / region", "省 / 州": "State / province",
    "城市": "City", "详细地址": "Street address",
    "邮编": "Postal code", "安全问题": "Security question",
    "答案": "Answer", "无加密": "Open network",
    "扫描动态码": "Scan one-time code", "拍摄证件": "Capture document",
    "识别二维码": "Scan QR code", "拍摄": "Capture",
    "摄像头扫码": "Scan with camera", "选择二维码图片": "Choose QR image",
    "摄像头扫描": "Scan with camera", "使用当前位置": "Use current location",
    "正在定位…": "Locating…", "导出": "Export",
    "邮箱": "Email", "电话": "Phone", "自动填充类型": "Autofill type",
    "按名称精确匹配": "Match exact field name", "不自动填充": "Do not autofill",
    "不可用": "Unavailable", "一次性验证码": "One-time code", "姓名": "Full name",
    "持卡人": "Cardholder", "卡号": "Card number", "有效期": "Expiry",
    "安全码": "Security code", "证件号码": "Document number", "API 凭证": "API credentials",
    "API 密文": "API secret", "主机": "Host", "数据库": "Database",
    "Wi-Fi 名称": "Wi-Fi name", "Wi-Fi 密码": "Wi-Fi password",
    "恢复答案": "Recovery answer", "自定义文本": "Custom text", "自定义密文": "Custom secret",
}
_EN.update(_MODULE_TRANSLATIONS)

_SECURITY_FINDING_TRANSLATIONS = {
    "公开泄露命中": "Found in a known breach",
    "完全相同的密码": "Reused password",
    "强度极低": "Very weak password",
    "常见或默认模式": "Common or default pattern",
    "相似密码重复": "Similar passwords reused",
    "长度不足 12 位": "Fewer than 12 characters",
    "包含账户信息": "Contains account information",
    "条目超过 180 天未更新": "Item not updated for 180 days",
    "联网记录确认该密码出现在公开泄露数据中。": "An online check confirmed that this password appears in public breach data.",
    "至少两个条目正在使用完全相同的密码。": "At least two items use exactly the same password.",
    "密码少于 8 位、字符种类单一，或只由极少数不同字符组成。": "The password is under 8 characters or has very little character variety.",
    "立即更换，并避免在其他账户继续使用。": "Change it now and do not use it for any other account.",
    "为每个账户设置不同的随机密码。": "Use a different random password for every account.",
    "改用至少 12 位且难以猜测的随机密码。": "Use a hard-to-guess random password with at least 12 characters.",
    "不要用简单变体区分账户，改用彼此独立的密码。": "Do not distinguish accounts with simple variations; use independent passwords.",
    "在不复用旧密码的前提下增加长度。": "Make it longer without reusing an old password.",
    "移除可从账户资料推测出的内容。": "Remove information that can be guessed from the account profile.",
    "确认密码仍然有效且未泄露，必要时更换。": "Confirm the password is still valid and uncompromised; change it if needed.",
}
_EN.update(_SECURITY_FINDING_TRANSLATIONS)

_EN.update({
    "回收站 0": "Trash 0", "确认": "Confirm", "使用": "Use", "恢复": "Restore", "复原": "Reset view", "恢复默认": "Restore defaults", "＋\n添加图片": "+\nAdd image",
    "复制密钥": "Copy recovery key", "保存恢复单": "Save recovery sheet", "已保存恢复单": "Recovery sheet saved",
    "再次输入主密码": "Enter master password again", "当前主密码": "Current master password", "新主密码": "New master password",
    "再次输入新主密码": "Enter new master password again", "主密码不能为空": "Enter your master password",
    "备份密码": "Backup password", "再次输入备份密码": "Enter backup password again",
    "第 1 步 · 离线保存恢复密钥": "Step 1 · Save the recovery key offline", "第 2 步 · 核对已保存内容": "Step 2 · Confirm your saved copy",
    "请先复制密钥或将恢复单保存到安全位置，之后才能进行核对。": "Copy the key or save the recovery sheet somewhere safe before confirming it.",
    "请先复制密钥或成功保存恢复单，再进行核对。": "Copy the key or successfully save the recovery sheet before confirming it.",
    "输入紧急恢复密钥并设置新的主密码。成功后恢复密钥本身保持不变。": "Enter the full recovery key and choose a new master password. The recovery key remains valid.",
    "将为新用户创建独立的密码库与主密码，请妥善牢记。": "A separate vault and master password will be created. Keep the master password safe.",
    "该账户在回收站中，将原样恢复，无需重设主密码。": "This vault is in Trash. It will be restored unchanged with its existing master password.",
    "切换用户…": "Switch vault…",     "生物识别已失效": "Biometric is no longer valid",
    "修改后将立即用新密码重新加密整个密码库，请牢记新密码。": "The vault will immediately be protected with the new master password. Keep it safe.",
    "全部条目": "All items", "回收站是空的": "Trash is empty", "全部条目": "All items",
    "可以导出全部条目，也可以只导出某个标签下的条目，便于分类备份。": "Export all items or only items with a selected tag.",
    "新标签名称": "New tag name", "输入标签名称": "Enter a tag", "已有标签：": "Existing tags:", "跳过": "Skip", "确认保留": "Keep selected",
    "密码存在差异，下一步将要求逐组选择。": "The passwords differ. You will choose which version to keep for each group.",
    "对其余冲突也使用相同处理方式": "Use the same choice for remaining conflicts", "保留现有": "Keep current", "用导入版本覆盖": "Use imported version", "两者都保留": "Keep both",
    "长度": "Length", "大写": "Uppercase", "小写": "Lowercase", "数字": "Numbers", "符号": "Symbols",
    "从运行中的程序列表选择，或手动输入程序名称。": "Choose a running app or enter its process name.", "筛选运行中的程序…": "Filter running apps…",
    "或手动输入程序名，如：chrome.exe": "Or enter a process name, such as chrome.exe", "提示：仅填写可执行文件名称即可，如 chrome.exe": "Enter only the executable name, such as chrome.exe.",
    "选择运行中的程序或手动输入包名": "Choose a running app or enter a package name", "应用包名或程序名，例如 com.example.app": "Package or process name, such as com.example.app",
    "仅填充关联程序中的账号与密码，不会自动提交。": "Fills the linked app's username and password without submitting the form.",
    "从浏览器导入密码": "Import passwords from browser", "未检测到 Chrome / Edge / Brave 的本地数据。": "No local Chrome, Edge or Brave data was found.",
    "仅读取当前 Windows 用户自己保存的密码：": "Only passwords saved by the current Windows user are read:",
    "从系统 Wi-Fi 导入": "Import from Windows Wi-Fi", "未检测到本机已保存的 Wi-Fi 配置。": "No saved Wi-Fi networks were found.",
    "仅读取当前 Windows 用户已保存的 Wi-Fi 密码：": "Only Wi-Fi passwords saved by the current Windows user are read:",
    "识别中…": "Recognizing…", "识别填充（全部图片）": "Recognize and fill from all images", "请输入证件类型名称": "Enter a document type",
    "输入安全笔记内容…": "Enter secure note content…", "空格或逗号分隔，如：工作 邮箱": "Separate with spaces or commas, for example: work email",
    "开户行名称": "Bank branch", "开户行行号": "Branch routing code", "192.168.1.1 或 example.com": "192.168.1.1 or example.com", "YYYY-MM-DD 或 长期": "YYYY-MM-DD or No expiry",
    "TOTP（按时间刷新）": "TOTP (time-based)", "HOTP（按计数器）": "HOTP (counter-based)", "⌄  高级选项": "⌄  Advanced options",
    "正在启动摄像头…": "Starting camera…", "无法读取": "Unable to read", "添加图片": "Add image", "＋": "+",
    "二维码生成失败，请确认已安装 qrcode 依赖": "Could not create the QR code. Check that the qrcode dependency is installed.", "扫码连接": "Scan to connect",
    "请用手机扫描二维码并输入 PIN 码\n3 分钟无操作自动关闭": "Scan with your phone and enter the PIN.\nCloses after 3 minutes of inactivity.",
    "请用手机扫描二维码并输入 PIN 码\n等待连接 3 分钟；连接后处理期间自动续期": "Scan with your phone and enter the PIN.\nWaits 3 minutes for pairing; stays active while processing.",
    "使用 k-匿名查询，仅发送密码哈希前 5 位。": "Uses a k-anonymous query and sends only the first five hash characters.",
    "关闭后不显示泄露标签，也不会将泄露条目置顶。": "When disabled, breach badges are hidden and affected items are not prioritized.",
    "开启：进入这些条目的敏感字段前需输入当前主密码。关闭：仅靠主入口解锁保护。": "On: enter the master password before viewing sensitive fields of these entries. Off: protected only by the main unlock.",
    "在目标程序的登录输入框中按快捷键；密码通过 Windows UI Automation 写入，不经过剪贴板。": "Use the shortcut in the target app's sign-in fields. Passwords are inserted through Windows UI Automation, not the clipboard.",
    "开启后截图、录屏或投屏中隐藏窗口内容。": "Hides vault content from screenshots, recordings and screen sharing.",
    "当前系统不支持原生程序自动填充。": "Desktop app autofill is not supported on this system.", "原生程序自动填充已关闭。": "Desktop app autofill is disabled.",
    "快捷键 Ctrl + Shift + L 已就绪。仅填充与当前程序关联的登录条目。": "Ctrl + Shift + L is ready and fills only logins linked to the current app.",
    "快捷键 Ctrl + Shift + L 暂不可用，可能已被其他程序占用。": "Ctrl + Shift + L is unavailable and may be used by another app.",
    "本机宿主已注册 · 浏览器扩展目录已就绪": "Desktop host registered · Browser extension folder ready", "尚未关联浏览器": "Browser not connected",
    "每个条目依次完成本地风险检查和可选的联网泄露查询，进度按已完成条目数推进。": "Each item completes local risk checks and an optional online breach query. Progress follows completed items.",
    "尚未授权 IP 地址来源": "No IP address origins authorized", "撤销 IP 地址授权": "Revoke IP address access",
    "确定撤销全部 IP 地址自动填充授权吗？之后再次使用时需要重新确认。": "Revoke autofill access for every IP address origin? You will need to approve them again.",
    "自动云端同步": "Automatic cloud sync", "自动同步目标": "Automatic sync target", "同步周期": "Sync interval", "云端硬盘": "Cloud drive",
    "正在检测 Windows Hello 可用性…": "Checking Windows Hello availability…",
    "正在检测 Windows Passkey 提供程序状态…": "Checking Windows Passkey provider status…",
    "关联云端硬盘": "Connect cloud drive", "关联 WebDAV": "Connect WebDAV", "取消关联": "Disconnect", "重新检测": "Check again",
    "上传覆盖": "Overwrite remote", "下载覆盖本地": "Replace local vault", "同步合并": "Sync and merge", "强制覆盖": "Force overwrite",
    "同步完成 · ": "Sync complete · ", "同步完成 · 内容已是最新": "Sync complete · content is up to date", "同步完成 · 已采用远端较新版本": "Sync complete · adopted the newer remote version",
    "写入云端硬盘失败": "Failed to write to cloud drive", "云端上传失败": "Cloud upload failed", "WebDAV同步失败": "WebDAV sync failed",
    "等待检测远端数据": "Waiting to check remote data", "正在检测远端数据…": "Checking remote data…", "尚未关联云端硬盘": "Cloud drive not connected", "尚未关联 WebDAV": "WebDAV not connected",
    "正在检测云端保险库数据…": "Checking cloud vault data…", "正在检测 WebDAV 远端数据…": "Checking WebDAV remote data…",
    "正在认证远端 PMVE 数据…": "Authenticating remote PMVE data…",
    "远端文件不存在或为空": "The remote file does not exist or is empty",
    "同一提交，内容一致": "Same commit; both sides are identical",
    "远端为本地后代提交，可安全拉取": "Remote is a descendant commit of the local vault; safe to pull and merge",
    "本地为远端后代提交，可安全上传": "Local is a descendant commit of the remote vault; safe to upload",
    "双方提交分叉，可自动合并（LWW + 密钥版本收敛）": "Commits have diverged; auto-merge will apply LWW and key-version convergence",
    "远端不是同一份保险库，已拒绝": "The remote is not the same vault; rejected",
    "远端 PMVE Identity 无效": "Remote PMVE identity is invalid",
    "未知谱系关系": "Unknown lineage relationship",
    "远端 PMVE 无法认证或已损坏": "Remote PMVE could not be authenticated or is corrupted",
    "远端文件存在（旧格式）": "Remote file exists (legacy format)",
    "不使用文件时间判断，点击同步按内容合并 · 最近检测：": "Not judged by file time; sync merges by content. Last checked: ",
    "远端已有保险库数据。请选择同步合并，或使用当前本地保险库强制覆盖远端文件。": "The remote location already contains vault data. Merge it or explicitly overwrite it with the local vault.",
    "选择云盘客户端的同步目录，程序会先查找已有的 .pmv 文件；同步会拉取合并、上传并读回校验。": "Choose a cloud drive sync folder. Existing .pmv files are detected before data is merged, uploaded and read back for verification.",
    "用户名 / 密码（Basic）": "Username / password (Basic)", "用户名 / 密码（Digest）": "Username / password (Digest)", "OAuth 2.0 访问令牌": "OAuth 2.0 access token",
    "客户端证书（mTLS）": "Client certificate (mTLS)", "无认证": "No authentication", "密码或应用专用密码": "Password or app password", "Windows 域（可选）": "Windows domain (optional)",
    "选择 PKCS#12 客户端证书": "Choose PKCS#12 client certificate", "自签名证书 SHA-256 指纹（可选）": "Self-signed certificate SHA-256 fingerprint (optional)", "自动创建远端目录": "Create remote folders automatically",
    "没有符合条件的条目": "No matching items", "没有可参与密码安全检测的条目。": "No items contain passwords that can be checked.",
    "开发者：FAE": "Developer: FAE", "点击图像可放大预览，可用对应 App 扫码支持。": "Select an image to enlarge it, then scan it with the corresponding app.",
    "选择一个标签并输入新名称，将批量更新所有包含该标签的条目。": "Choose a tag and enter a new name to update every matching item.",
    "第 1 组 PMRK1 是恢复密钥格式标识，不参与校验。以下序号按上方完整密钥从左到右计算，请从每个下拉列表的 5 个候选中选出对应分组。": "PMRK1 is the recovery-key format marker and is not part of the check. Numbering starts with the first group after PMRK1; choose the requested group from each list of five options.",
    "保险库已在其他窗口更新，请重新登录": "The vault changed in another window. Sign in again.", "已同步浏览器保存的登录条目": "Saved browser logins synchronized",
    "已复制到剪贴板": "Copied to clipboard", "已复制（隐身）": "Copied privately", "已导出 .pmv 库": ".pmv vault exported", "已取消导入，本地数据未改动": "Import canceled; local data was not changed",
    "从左侧选择一个条目，或点击「新增条目」开始。": "Choose an item on the left, or select New item to get started.",
    "已泄露：该密码在常见泄露/弱密码字典中，强烈建议更换": "Exposed: this password appears in known breach or weak-password data. Change it now.",
    "没有可参与密码安全检测的条目。": "No items contain passwords that can be checked.",
    "采用远端密钥槽失败": "Failed to adopt the remote key slots",
    "PMVE 合并上传后远端文件消失": "The remote PMVE file disappeared after the merged upload",
    "PMVE 合并上传后文件身份认证失败": "The remote PMVE file failed identity authentication after the merged upload",
    "PMVE 合并上传后回读 Identity 不一致": "The remote PMVE identity mismatched after the merged upload",
    "PMVE CAS 连续竞争，请稍后重试": "PMVE CAS keeps conflicting; please retry later",
    "PMVE 同步只接受认证文件路径": "PMVE sync only accepts authenticated file paths",
    "PMVE 远端文件需要 PMVE 本地保险库认证": "A remote PMVE file requires a local PMVE vault for authentication",
    "WebDAV 同步失败": "WebDAV sync failed",
    "上传后远端文件不存在": "The remote file no longer exists after upload",
    "云端文件已覆盖并通过回读校验（PMVE）。": "Cloud file overwritten and verified by read-back (PMVE).",
    "本地保险库已被云端 PMVE 版本覆盖，并已保留 .sync.bak 备份。": "Local vault replaced by the cloud PMVE version; a .sync.bak backup was kept.",
    "云端未提供可用于并发保护的版本信息（强 ETag 或文件大小/修改时间）": "The cloud provider did not provide usable concurrency protection (strong ETag or file size/modified time).",
    "本地保险库已被远端 PMVE 版本覆盖，并已保留 .sync.bak 备份。": "Local vault replaced by the remote PMVE version; a .sync.bak backup was kept.",
    "本地保险库超过 2 GB 安全限制": "Local vault exceeds the 2 GB safety limit",
    "本地保险库缺失或超过 1 GB 安全限制": "Local vault is missing or exceeds the 1 GB safety limit",
    "云端 PMVE 文件超过 1 GB 安全限制": "Cloud PMVE file exceeds the 1 GB safety limit",
    "本地 PMVE 文件超过 1 GB 安全限制": "Local PMVE file exceeds the 1 GB safety limit",
    "关联路径不是文件或超过 1 GB 安全限制": "The linked path is not a file or exceeds the 1 GB safety limit",
    "远端保险库文件不存在或为空": "The remote vault file is missing or empty",
    "远端文件已覆盖并通过回读校验（PMVE）。": "Remote file overwritten and verified by read-back (PMVE).",
    "重命名账户": "Rename vault",
    "重命名当前用户…": "Rename current vault…",
    "重命名失败": "Rename failed",
    "重命名账户需要验证当前主密码。": "Verify the current master password before renaming the vault.",
    "新账户名：": "New vault name:",
    "主密码/密钥版本已更新": "Master password / key version updated",
    "已重命名账户，下次解锁将显示新名称。": "Vault renamed. The new name will be shown on the next unlock.",
    "账户名不合法": "Invalid vault name",
    "账户名不能为空": "The vault name cannot be empty.",
    "新账户名与原账户名相同": "The new name is the same as the current one.",
    "账户名已存在": "A vault with this name already exists",
    "账户不存在": "Vault does not exist",
    "局域网同步（扫码或输入地址）": "LAN sync (scan or enter address)",
    "文件传输（扫码或输入地址）": "File transfer (scan or enter address)",
    "云端同步（云端硬盘 / WebDAV）": "Cloud sync (Cloud Drive / WebDAV)",
    "启用联网同步": "Enable online sync",
    "开启后，“同步”下拉菜单将显示“云端同步”入口，可在其中关联云端硬盘或 WebDAV。": "When enabled, the Sync menu shows the Cloud sync entry, where you can connect a cloud drive or WebDAV.",
    "同步：建立传输站 / 局域网同步 / 文件传输 / 本地备份 / 云端同步": "Sync: transfer station / LAN sync / file transfer / local backup / cloud sync",
    "有设备请求导出当前保险库（整库导出）。是否允许？": "A device is requesting to export the current vault (full vault). Allow it?",
    "允许导出": "Allow export",
    "拒绝": "Reject",
    "导出确认": "Confirm export",
    "传输大文件": "Large file transfer",
    "局域网传输速度较慢，是否继续传输大文件？": "LAN transfer can be slow. Continue transferring this large file?",
})

_EN.update({
    "切到后台时从最近任务中隐藏。在 Windows 上同时最小化到系统托盘并自动锁定，可从托盘图标恢复；关闭后点击关闭按钮将直接退出程序。": "Hidden from background when switched away. On Windows it also minimizes to the system tray and auto-locks; restore from the tray icon. Closing the window exits the app.",
    "开启：进入这些条目的敏感字段前需输入当前主密码。关闭：仅靠主入口解锁保护，解锁后直接可见。": "On: enter the master password before viewing sensitive fields. Off: protected only by the main unlock; visible right after unlock.",
    "设备中登记的所有强生物特征均可解锁此保险库。多人共用设备时，建议仅使用主密码。": "Any strong biometric enrolled on this device can unlock the vault. On shared devices, prefer the master password.",
    "当前设备未配置生物识别（PIN / 指纹 / 人脸）或依赖不可用。": "No biometric (PIN / fingerprint / face) enrolled on this device, or the dependency is unavailable.",
    "默认关闭，仅在主动操作时连接云端。": "Off by default; connects to the cloud only on explicit action.",
    "标准（推荐）": "Standard (recommended)",

    "启用后，“同步”下拉菜单将显示“云端同步”入口，可在其中关联云端硬盘或 WebDAV。": "When enabled, the Sync menu shows the Cloud sync entry, where you can connect a cloud drive or WebDAV.",
    "浏览器自动填充 - 解锁保险库": "Browser autofill — Unlock Vault",
})

_EN.update({'请确认当前网站可以接收所选条目的填充内容。': 'Confirm that this website may receive the selected item’s autofill data.', '记住此网站与条目的关联': 'Remember this website association', '允许填充': 'Allow fill', '确认输入框映射': 'Confirm field mapping', '此设置仅适用于当前网站和所选条目。': 'This setting applies only to this website and the selected item.', '移除映射': 'Remove mapping', '记住此程序与条目的关联': 'Remember this application association', '已记住关联': 'Remembered association', '程序匹配': 'Application match', '名称相关': 'Related name', '手动搜索': 'Manual search'})

_EN.update({'记住此输入框的字段类型': 'Remember this field type', '填入当前输入框': 'Fill selected field', '自动填充记忆': 'Autofill memory', '移除已记住的关联或字段类型，下次填充时将重新选择。': 'Remove remembered associations or field types to choose again next time.', '移除所选记忆': 'Remove selected memory', '没有已记住的自动填充关联或字段类型。': 'No remembered autofill associations or field types.', '移除失败，条目可能已更新。请关闭后重新打开。': 'Could not remove: the item may have changed. Close and reopen this dialog.', '已移除所选记忆。': 'Selected memory removed.', '程序关联': 'Application association', '网站关联': 'Website association', '所选字段内容已不可用，请重新选择': 'The selected field value is unavailable. Choose again.', '此输入框没有稳定标识，无法记住映射': 'This field has no stable identifier; its mapping cannot be remembered.', '已填充所选字段': 'Selected field filled', '自动填充记忆已更新': 'Autofill memory updated'})

_EN.update({'选择状态无效': 'Invalid selection state', '字段角色无效': 'Invalid field role', '凭据不存在': 'Credential not found', '条目没有此字段角色': 'This item has no value for this field role', '未允许保存字段映射': 'Field mapping was not approved', '字段来源已变化，请重试': 'The field source changed. Try again.', '无法确认程序路径，请重试': 'Could not verify the application path. Try again.', '条目或程序身份已变化，请重试': 'The item or application identity changed. Try again.', '程序身份已变化，请重试': 'The application identity changed. Try again.', '目标窗口已关闭，请重新触发自动填充': 'The target window closed. Trigger autofill again.', '请松开快捷键后重新触发自动填充': 'Release the shortcut keys and trigger autofill again.', '填充过程中目标窗口失焦，已停止输入': 'The target lost focus during filling. Input stopped.', '开机启动仅支持 Windows': 'Startup launch is supported only on Windows.', '已准备填充：请在 30 秒内点回并清空目标输入框，再按自动填充快捷键': 'Ready to fill: return to and clear the target field within 30 seconds, then press the autofill shortcut again.', '待填充操作已取消，请在目标程序重新触发自动填充': 'The pending fill was cancelled. Trigger autofill again in the target app.'})

_EN.update({'检测远端更新': 'Check for remote updates', '每5分钟检查远端文件，仅提醒，不会自动同步。': 'Checks the remote file every 5 minutes. Only notifies; does not sync automatically.', '远端有更新': 'Remote update available', '远端文件已变化，尚未同步到本机': 'The remote file changed and has not been synced to this device.', '立即同步': 'Sync now', '稍后处理': 'Later', '发现时间：{time}': 'Detected: {time}', '远端更新检测失败': 'Could not check for remote updates', '远端文件已删除': 'The remote file was deleted'})

_EN.update({
    "设备": "Devices", "本机": "This device", "未知": "Unknown", "未知设备": "Unknown device",
    "已授权": "Authorized", "无有效授权记录": "No valid authorization record",
    "设备名称自动使用系统设置中的名称。": "Device names follow the name in system settings.",
    "设备记录": "Device records", "查看设备记录": "View device records",
    "授权状态来自保险库现有记录；此处不能撤销其他设备的云端访问权限。": "Authorization status comes from existing vault records. This page cannot revoke another device's cloud access.",
    "操作完成。": "Done.", "操作失败，请刷新后重试。": "Operation failed. Refresh and try again.",
    "最近写入设备：{name}": "Last writer: {name}",
    "写入设备仅在验证此远端版本后显示；旧版本可能无法识别设备。": "The writer is shown after this remote version is verified. Older versions may have an unknown device.",
    "远端版本已变化，请重新验证设备信息": "The remote version changed. Verify it again to view device information.",
})

_CATALOGS = {"en": _EN}


def tr(text: str) -> str:
    if not text or _locale == "zh-Hans":
        return text
    catalog = _CATALOGS.get(_locale, {})
    # English is the completeness fallback for a newly added string. This
    # prevents Chinese fragments in supported locales while the locale-specific
    # wording is filled in, and the source scanner keeps English exhaustive.
    return catalog.get(text, _EN.get(text, text))


_EN["解锁成功"] = "Unlocked"


_DYNAMIC = {
    "en": (
        *_EN_COMPLETE_DYNAMIC,
        (r"^保存排除项失败：(.+)$", r"Could not save exclusions: \1"),
        (r"^已保存 (.+) 的当前账号$", r"Saved the current account for \1"),
        (r"^已更新 (.+) 的所选账号$", r"Updated the selected account for \1"),
        (r"^(.+)\n(.+)  ·  动态码 (.+)  ·  (.+)$", r"\1\n\2  ·  One-time code \3  ·  \4"),
        (r"^回收站 (.+)$", r"Trash \1"),
        (r"^共 (\d+)/(\d+) 条$", r"\1/\2 items"), (r"^共 (\d+) 条$", r"\1 items"),
        (r"^当前用户：(.+)$", r"Current vault: \1"), (r"^已切换到「(.+)」$", r"Switched to “\1”"),
        (r"^创建时间：(.+)$", r"Created: \1"), (r"^最后修改：(.+)$", r"Last updated: \1"),
        (r"^本地检测失败：(.+)$", r"Local check failed: \1"),
        (r"^高风险 (\d+)$", r"High risk \1"), (r"^需改进 (\d+)$", r"Needs attention \1"), (r"^未发现问题 (\d+)$", r"No issues found \1"),
        (r"^(\d+) 个未发现问题$", r"\1 with no issues found"),
        (r"^共(?:检查|检测) (\d+) 个含密码条目$", r"\1 password items checked"),
        (r"^已(?:检查|扫描) (\d+) 个含密码条目：高风险 (\d+)，需改进 (\d+)，未发现问题 (\d+)。$", r"Checked \1 password items: \2 high risk, \3 need attention, \4 with no issues found."),
        (r"^正在扫描 (\d+) 项本地规则…$", r"Scanning \1 local rules…"),
        (r"^正在扫描本地规则：(\d+)/(\d+) 个含密码条目$", r"Scanning local rules: \1/\2 password items"),
        (r"^已泄露：该密码在公开泄露中出现了 (\d+) 次，强烈建议更换$", r"Exposed: found \1 times in public breach data. Change it now."),
        (r"^已泄露：命中常见弱密码字典，且在 Pwned Passwords 中出现过 (\d+) 次，强烈建议更换$", r"Exposed and weak: found \1 times in public breach data. Change it now."),
        (r"^已导入 (\d+) 条", r"Imported \1 items"), (r"^已导出 (\d+) 条", r"Exported \1 items"),
        (r"^已自动清理 (.+) 条过期回收站条目$", r"Removed \1 expired Trash items"),
        (r"^删除后移入账户回收站，(\d+) 天内可恢复，逾期自动删除。$", r"Moved to account Trash and kept for \1 days before permanent deletion."),
        (r"^联系：(.+)$", r"Contact: \1"),
        (r"^紧急恢复密钥已创建 · 指纹 (.+) · 密钥版本 v(.+) · (.+)$", r"Emergency recovery key created · fingerprint \1 · key version v\2 · \3"),
        (r"^紧急恢复密钥已创建 · 指纹 (.+) · (.+)$", r"Emergency recovery key created · fingerprint \1 · \2"),
        (r"^(.+)失败：(.+)$", r"\1 failed: \2"), (r"^正在(.+)$", r"Working: \1"),
        (r"^等待主机确认导出超时（HTTP 423）：(.+)$", r"Timed out waiting for the host to approve the export (HTTP 423): \1"),
        (r"^等待主机确认同步超时（HTTP 423）：(.+)$", r"Timed out waiting for the host to approve the sync (HTTP 423): \1"),
        (r"^设备认证失败（HTTP (.+)）：(.+)$", r"Device authentication failed (HTTP \1): \2"),
        (r"^设备认证确认失败（HTTP (.+)）：(.+)$", r"Device authentication confirmation failed (HTTP \1): \2"),
        (r"^无效的备份周期: (.+)$", r"Invalid backup interval: \1"),
        (r"^保险库文件不存在: (.+)$", r"Vault file does not exist: \1"),
        (r"^目标卷剩余空间不足：需要 (.+) 字节，可用 (.+) 字节$", r"Insufficient space on the target volume: need \1 bytes, available \2 bytes"),
        (r"^备份回读校验失败，目标文件已保留为 \.backup-partial$", r"Backup read-back verification failed; the file remains as .backup-partial"),
        (r"^文件提前结束，无法完成校验$", r"File ended early; verification could not be completed"),
        (r"^备份目录不可用，等待设备状态$", r"Backup folder unavailable; waiting for device"),
        (r"^导入失败：(.+)$", r"Import failed: \1"),
        (r"^保险库紧急恢复密钥 v(.+)$", r"FAEVault Emergency Recovery Key v\1"),
        (r"^自动同步周期：(.+)$", r"Auto-sync interval: \1"),
    ),
}


_DYNAMIC_COMPILED = {
    locale: tuple((re.compile(pattern), replacement) for pattern, replacement in patterns)
    for locale, patterns in _DYNAMIC.items()
}
_tr_dynamic_cache: dict = {}


def tr_dynamic(text: str) -> str:
    if not text or _locale == "zh-Hans":
        return text
    cached = _tr_dynamic_cache.get(text)
    if cached is not None:
        return cached
    translated = tr(text)
    if translated != text:
        _tr_dynamic_cache[text] = translated
        return translated
    for pattern, replacement in _DYNAMIC_COMPILED.get(_locale, ()):
        if pattern.search(text):
            result = pattern.sub(replacement, text)
            _tr_dynamic_cache[text] = result
            return result
    _tr_dynamic_cache[text] = text
    return text


def _tx(obj, getter, setter, fn, key) -> None:
    """Translate one attribute, skipping work when its displayed text is unchanged.

    The last displayed value is stored as a Qt dynamic property so repeated
    Show/UpdateRequest events on an unchanged widget cost only a compare.
    When the source text changes (e.g. a dynamic status label), it is re-translated.
    """
    cur = getter()
    if not cur:
        return
    last = obj.property(key)
    if last is not None and last == cur:
        return
    translated = fn(cur)
    obj.setProperty(key, translated if translated != cur else cur)
    if translated != cur:
        setter(translated)


def _translate_object(obj) -> None:
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import (
        QAbstractButton,
        QComboBox,
        QGroupBox,
        QLabel,
        QListWidget,
        QPlainTextEdit,
        QSpinBox,
        QTabWidget,
        QTableWidget,
        QTextEdit,
        QTreeWidget,
        QWidget,
    )

    objects = [obj]
    if isinstance(obj, QWidget):
        objects.extend(obj.findChildren(QWidget))
        objects.extend(obj.findChildren(QAction))
    for child in objects:
        if isinstance(child, (QLabel, QAbstractButton, QGroupBox)):
            _tx(child, child.text, child.setText, tr_dynamic, "_i18n_text")
        if isinstance(child, (QPlainTextEdit, QTextEdit)) or (
            hasattr(child, "placeholderText") and hasattr(child, "setPlaceholderText")
        ):
            _tx(child, child.placeholderText, child.setPlaceholderText, tr_dynamic, "_i18n_ph")
        if isinstance(child, QComboBox):
            for index in range(child.count()):
                _tx(child, lambda: child.itemText(index), lambda t: child.setItemText(index, t), tr_dynamic, f"_i18n_cmb_{index}")
        if isinstance(child, QListWidget):
            for index in range(child.count()):
                item = child.item(index)
                item.setText(tr_dynamic(item.text()))
        if isinstance(child, QTreeWidget):
            for column in range(child.columnCount()):
                header = child.headerItem()
                if header is not None:
                    header.setText(column, tr_dynamic(header.text(column)))
            iterator = child.invisibleRootItem()
            pending = [iterator.child(index) for index in range(iterator.childCount())]
            while pending:
                item = pending.pop()
                for column in range(child.columnCount()):
                    item.setText(column, tr_dynamic(item.text(column)))
                pending.extend(item.child(index) for index in range(item.childCount()))
        if isinstance(child, QTableWidget):
            for column in range(child.columnCount()):
                item = child.horizontalHeaderItem(column)
                if item is not None:
                    item.setText(tr_dynamic(item.text()))
            for row in range(child.rowCount()):
                for column in range(child.columnCount()):
                    item = child.item(row, column)
                    if item is not None:
                        item.setText(tr_dynamic(item.text()))
        if isinstance(child, QTabWidget):
            for index in range(child.count()):
                _tx(child, lambda: child.tabText(index), lambda t: child.setTabText(index, t), tr, f"_i18n_tab_{index}")
        if isinstance(child, QSpinBox):
            _tx(child, child.suffix, child.setSuffix, tr, "_i18n_suf")
        if isinstance(child, QAction):
            _tx(child, child.text, child.setText, tr, "_i18n_act")
        if hasattr(child, "toolTip"):
            _tx(child, child.toolTip, child.setToolTip, tr_dynamic, "_i18n_tip")
        if hasattr(child, "accessibleName"):
            _tx(child, child.accessibleName, child.setAccessibleName, tr_dynamic, "_i18n_an")
    if isinstance(obj, QWidget):
        _tx(obj, obj.windowTitle, obj.setWindowTitle, tr_dynamic, "_i18n_title")


def translate_widget_tree(widget) -> None:
    """Translate a newly populated widget immediately (before it is shown)."""
    _translate_object(widget)


def install(app, mode: str, system_name: str) -> None:
    from PySide6.QtCore import QEvent, QLocale, QObject

    resolved = resolve_locale(mode, system_name)
    set_locale(resolved)
    QLocale.setDefault(QLocale("en_US" if resolved == "en" else "zh_CN"))

    class _ShowTranslator(QObject):
        _busy = False

        def eventFilter(self, watched, event):
            if not self._busy and event.type() in (
                QEvent.Show,
                QEvent.LayoutRequest,
                QEvent.UpdateRequest,
            ):
                self._busy = True
                try:
                    _translate_object(watched)
                finally:
                    self._busy = False
            return False

    translator = _ShowTranslator(app)
    app.installEventFilter(translator)
    app._vault_i18n_filter = translator
