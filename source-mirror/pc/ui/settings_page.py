"""Embedded settings page for the editor workspace."""

from __future__ import annotations

import datetime
import os
import sys
import time
import tomllib
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QThread, QTimer, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import biometric, browser_install, config, pmv_kdf_policy, startup, updates
from core.passkey_provider_status import PasskeyProviderStatus
from core.pmv_kdf_policy import PmvKdfPolicy, PmvKdfProfile
from core.pmv_key_schedule import derive_password_kek
from core.storage import Vault

from . import i18n, screen_capture, widgets
from .dialogs import (
    AccountRenameDialog,
    ChangePasswordDialog,
    ConfirmPasswordDialog,
    NativeAutofillExcludeDialog,
    RecoveryKeyConfirmDialog,
    UpdateDialog,
    UpdateDownloadDialog,
    _NoScrollComboBox,
    _PROJECT_ROOT,
    _UpdateCheckWorker,
    _spinbox_row,
)
from .editor_workspace import EditorPage, page_shell


_CONTACT_EMAIL = "2123696066@qq.com"


class _KdfSettingsWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, vault: Vault, profile: PmvKdfProfile | None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._profile = profile

    def run(self) -> None:
        try:
            if self._profile is not None:
                self._vault.rewrap_kdf_profile(self._profile)
                result = self._profile
            else:
                dummy = bytearray(b"kdf-calibration")
                salt = bytes(16)
                try:
                    samples = []
                    for _ in range(3):
                        started = time.perf_counter_ns()
                        derived = bytearray(derive_password_kek(
                            bytes(dummy), salt, PmvKdfProfile.HARDENED.parameters,
                        ))
                        derived[:] = bytes(len(derived))
                        samples.append((time.perf_counter_ns() - started) // 1_000_000)
                    result = PmvKdfPolicy.recommended_profile(samples, 262_144)
                finally:
                    dummy[:] = bytes(len(dummy))
            self.completed.emit(result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class _SettingsEnvironmentWorker(QThread):
    """Probe optional Windows integrations without blocking the settings page."""

    completed = Signal(bool, object)

    def __init__(self, provider: PasskeyProviderStatus, parent=None):
        super().__init__(parent)
        self._provider = provider

    def run(self) -> None:
        hello_available = biometric.available()
        provider_status = self._provider.query()
        self.completed.emit(hello_available, provider_status)


class SettingsPage(EditorPage):
    """设置：外观主题、安全策略与隐私选项。"""

    accountDeleted = Signal()

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self._window = window
        self._orig_mode = config.theme_mode()
        self._orig_language = config.language_mode()
        self._delete_occurred = False

        shell = page_shell(self, i18n.tr("设置"))
        self.page_header = shell.header
        outer = shell.content

        # 各设置分组放入滚动区，避免设置项增多后页面越来越长。
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        content = QWidget()
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(12)
        self._content_lay = self.body
        self._scroll.setWidget(content)
        outer.addWidget(self._scroll, 1)
        self._sensitive_boxes: list[QFrame] = []  # 安全/隐私/数据/用户分组，需主密码门禁

        # ── 账户与解锁 ──
        g = self._group("账户与解锁", sensitive=True)
        user_lbl = QLabel(f"当前用户：{config.get_current_user() or ''}")
        user_lbl.setObjectName("Empty")
        g.addWidget(user_lbl)
        self._user_lbl = user_lbl

        rename_btn = widgets.set_button_icon(QPushButton(i18n.tr("重命名当前用户…")), "edit")
        rename_btn.setObjectName("SettingsBtn")
        rename_btn.clicked.connect(self._rename_user)
        g.addWidget(rename_btn)

        change_pw = QPushButton("修改主密码")
        change_pw.setObjectName("SettingsBtn")
        change_pw.clicked.connect(self._change_password)
        g.addWidget(change_pw)
        self._gate_exempt = {change_pw}

        self._hello_guard = False
        self.hello_enabled = QCheckBox("生物识别解锁")
        self.hello_enabled.setChecked(biometric.is_enabled(self._window.vault.path))
        self.hello_enabled.setEnabled(False)
        self.hello_enabled.setToolTip("正在检测 Windows Hello 可用性…")
        self.hello_enabled.toggled.connect(self._on_hello_toggled)
        g.addWidget(self.hello_enabled)
        self._hello_note = self._note(g, "正在检测 Windows Hello 可用性…")

        self._recovery_box = QVBoxLayout()
        self._recovery_box.setSpacing(8)
        g.addLayout(self._recovery_box)
        self._build_recovery_controls()

        open_folder = QPushButton("打开密码库所在文件夹")
        open_folder.setObjectName("SettingsBtn")
        open_folder.clicked.connect(self._open_vault_folder)
        g.addWidget(open_folder)

        delete_btn = QPushButton("删除当前用户")
        delete_btn.setObjectName("Danger")
        delete_btn.clicked.connect(self._delete_user)
        g.addWidget(delete_btn)
        self._note(g, f"删除后移入账户回收站，{config.ACCOUNT_RETENTION_DAYS} 天内可恢复，逾期自动删除。", object_name="SettingDangerNote")

        # ── 隐私与安全 ──
        g = self._group("隐私与安全", sensitive=True)

        sub = QLabel(i18n.tr("设备记录"))
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        self.devices_button = QPushButton(i18n.tr("查看设备记录"))
        self.devices_button.setObjectName("SettingsBtn")
        self.devices_button.clicked.connect(lambda: self._window._open_devices())
        g.addWidget(self.devices_button)
        self._note(g, i18n.tr("设备名称自动使用系统设置中的名称。"))

        sub = QLabel("会话与锁定")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        self.lock_enabled = QCheckBox("自动锁定")
        self.lock_enabled.setChecked(bool(config.get("lock_enabled", config.DEFAULT_LOCK_ENABLED)))
        g.addWidget(self.lock_enabled)
        self._note(g, "离开一段时间后重新要求主密码。")

        self.lock_seconds = _spinbox_row(
            g,
            "无操作超时后自动锁定",
            minimum=config.MIN_LOCK_SECONDS,
            maximum=config.MAX_LOCK_SECONDS,
            value=config.lock_seconds(),
            suffix=" 秒",
            step=30,
        )
        self.lock_seconds.setEnabled(self.lock_enabled.isChecked())
        self.lock_enabled.toggled.connect(self.lock_seconds.setEnabled)

        self.clipboard_seconds = _spinbox_row(
            g,
            "剪贴板自动清空",
            minimum=config.MIN_CLIPBOARD_CLEAR_SECONDS,
            maximum=config.MAX_CLIPBOARD_CLEAR_SECONDS,
            step=5,
            value=int(config.get("clipboard_clear_seconds", config.DEFAULT_CLIPBOARD_CLEAR_SECONDS)),
            suffix=" 秒",
        )
        self.clipboard_seconds.setSpecialValueText("不自动清空")

        self.reveal_seconds = _spinbox_row(
            g,
            "显示后自动隐藏",
            minimum=2,
            maximum=120,
            value=int(config.get("reveal_hide_seconds", 5) or 5),
            suffix=" 秒",
        )

        self.recycle_days = _spinbox_row(
            g,
            "回收站自动清理",
            minimum=1,
            maximum=365,
            value=int(
                config.get(
                    "recycle_bin_retention_days",
                    config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS,
                )
                or config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS
            ),
            suffix=" 天",
        )
        self._note(g, "超过保留天数的条目会从回收站自动彻底删除。")

        sub = QLabel("验证与保护")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)

        self.allow_capture = QCheckBox("允许截屏")
        self.allow_capture.setChecked(config.screen_capture_allowed())
        self.allow_capture.setEnabled(screen_capture.supported())
        self.allow_capture.setToolTip(
            "此功能仅在 Windows 上可用"
            if not screen_capture.supported()
            else "开启后允许其他程序截取或录制保险库窗口"
        )
        g.addWidget(self.allow_capture)
        self._note(g, "默认关闭：截图、录屏和投屏中窗口显示为黑屏；需要截图或远程调试时再开启。")

        self.background_hide = QCheckBox("后台界面隐藏")
        self.background_hide.setChecked(bool(config.get("background_hide", config.DEFAULT_BACKGROUND_HIDE)))
        g.addWidget(self.background_hide)
        self._note(
            g,
            "切到后台时从最近任务中隐藏。在 Windows 上同时最小化到系统托盘并自动锁定，可从托盘图标恢复；关闭后点击关闭按钮将直接退出程序。",
        )

        self.require_master = QCheckBox("敏感信息二次验证")
        self.require_master.setChecked(
            bool(config.get("require_master_for_sensitive", config.DEFAULT_REQUIRE_MASTER_FOR_SENSITIVE))
        )
        self.require_master.setToolTip("开启：进入这些条目的敏感字段前需输入当前主密码。关闭：仅靠主入口解锁保护，解锁后直接可见。")
        g.addWidget(self.require_master)
        self._note(g, "开启：进入这些条目的敏感字段前需输入当前主密码。关闭：仅靠主入口解锁保护。")

        g = self._advanced_group(g, "高级选项")
        sub = QLabel("KDF 安全等级")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        kdf_row = QHBoxLayout()
        kdf_row.addWidget(QLabel("安全等级"))
        kdf_row.addStretch()
        self.kdf_profile = _NoScrollComboBox()
        self.kdf_profile.addItem("标准（推荐）", PmvKdfProfile.STANDARD.name)
        self.kdf_profile.addItem("强化", PmvKdfProfile.HARDENED.name)
        saved_profile = str(config.get(self._kdf_config_key(), PmvKdfProfile.STANDARD.name) or "")
        self.kdf_profile.setCurrentIndex(max(0, self.kdf_profile.findData(saved_profile)))
        kdf_row.addWidget(self.kdf_profile)
        g.addLayout(kdf_row)
        self._kdf_status = QLabel()
        self._kdf_status.setObjectName("SettingNote")
        self._kdf_status.setWordWrap(True)
        g.addWidget(self._kdf_status)
        kdf_buttons = QHBoxLayout()
        self._kdf_recommend = QPushButton("根据设备性能推荐")
        self._kdf_recommend.setObjectName("SettingsBtn")
        self._kdf_recommend.clicked.connect(lambda: self._start_kdf_worker(None))
        self._kdf_apply = QPushButton("应用所选等级")
        self._kdf_apply.setObjectName("SettingsBtn")
        self._kdf_apply.clicked.connect(self._apply_kdf_profile)
        kdf_buttons.addWidget(self._kdf_recommend)
        kdf_buttons.addWidget(self._kdf_apply)
        g.addLayout(kdf_buttons)
        self._kdf_worker: _KdfSettingsWorker | None = None
        self._kdf_available = callable(getattr(self._window.vault, "rewrap_kdf_profile", None))
        self._kdf_apply.setEnabled(self._kdf_available)
        self._refresh_kdf_status()

        # ── 自动填充与通行密钥 ──
        g = self._group("自动填充与通行密钥", sensitive=True)

        sub = QLabel("桌面程序自动填充")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        self.native_autofill_enabled = QCheckBox("启用全局快捷键")
        self.native_autofill_enabled.setChecked(bool(config.get("native_autofill_enabled", True)))
        self.native_autofill_enabled.setEnabled(sys.platform == "win32")
        g.addWidget(self.native_autofill_enabled)
        self._native_autofill_status = QLabel()
        self._native_autofill_status.setObjectName("SettingNote")
        self._native_autofill_status.setWordWrap(True)
        if sys.platform != "win32":
            self._native_autofill_status.setText("当前系统不支持原生程序自动填充。")
        elif not self.native_autofill_enabled.isChecked():
            self._native_autofill_status.setText("原生程序自动填充已关闭。")
        elif self._window._native_hotkey_registered:
            self._native_autofill_status.setText("快捷键 Ctrl + Shift + L 已就绪。仅填充与当前程序关联的登录条目。")
        else:
            self._native_autofill_status.setText("快捷键 Ctrl + Shift + L 暂不可用，可能已被其他程序占用。")
        g.addWidget(self._native_autofill_status)
        self._note(g, "在目标程序输入框中按快捷键；密码通过 Windows UI Automation 写入，不经过剪贴板。")

        sub = QLabel("自动填充排除")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        exclude_row = QHBoxLayout()
        self._native_exclude_count = QLabel(i18n.tr("已排除 {count} 项").format(count=0))
        self._native_exclude_count.setObjectName("SettingNote")
        exclude_row.addWidget(self._native_exclude_count)
        exclude_row.addStretch()
        manage_exclude = QPushButton(i18n.tr("管理排除项…"))
        manage_exclude.setObjectName("SettingsBtn")
        manage_exclude.clicked.connect(self._manage_native_autofill_exclusions)
        exclude_row.addWidget(manage_exclude)
        g.addLayout(exclude_row)
        self._note(g, "添加排除项后，对应目标将不再显示自动填充建议。")
        self._refresh_native_exclude_count()

        sub = QLabel("浏览器通行密钥")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        self._browser_autofill_status = QLabel()
        self._browser_autofill_status.setObjectName("SettingNote")
        self._browser_autofill_status.setWordWrap(True)
        g.addWidget(self._browser_autofill_status)

        self._browser_private_status = QLabel()
        self._browser_private_status.setObjectName("SettingNote")
        self._browser_private_status.setWordWrap(True)
        g.addWidget(self._browser_private_status)
        self._browser_private_clear = widgets.set_button_icon(QPushButton("撤销全部局域网授权"), "unlink")
        self._browser_private_clear.setObjectName("SettingsBtn")
        self._browser_private_clear.clicked.connect(self._clear_browser_private_origins)
        g.addWidget(self._browser_private_clear)

        self._browser_autofill_install = widgets.set_button_icon(QPushButton("启用浏览器通行密钥"), "browser")
        self._browser_autofill_install.setObjectName("SettingsBtn")
        self._browser_autofill_install.clicked.connect(self._install_browser_autofill)
        g.addWidget(self._browser_autofill_install)
        self._browser_autofill_remove = widgets.set_button_icon(QPushButton("取消浏览器通行密钥关联"), "unlink")
        self._browser_autofill_remove.setObjectName("Danger")
        self._browser_autofill_remove.clicked.connect(self._remove_browser_autofill)
        g.addWidget(self._browser_autofill_remove)

        browser_row = QHBoxLayout()
        for label, browser in (("Chrome", "chrome"), ("Edge", "edge"), ("Firefox", "firefox")):
            button = QPushButton(label)
            button.setObjectName("SettingsBtn")
            button.clicked.connect(lambda _checked=False, name=browser: self._open_browser_extension_manager(name))
            browser_row.addWidget(button)
        g.addLayout(browser_row)
        self._refresh_browser_autofill_status()

        # ── Windows 通行密钥 ──
        sub = QLabel("Windows 通行密钥")
        sub.setObjectName("SettingGroup")
        g.addWidget(sub)
        self._passkey_provider = PasskeyProviderStatus()
        self._passkey_provider_status = QLabel()
        self._passkey_provider_status.setObjectName("SettingNote")
        self._passkey_provider_status.setWordWrap(True)
        self._passkey_provider_status.setText("正在检测 Windows Passkey 提供程序状态…")
        g.addWidget(self._passkey_provider_status)
        passkey_row = QHBoxLayout()
        register_passkey = QPushButton("注册 Windows 通行密钥服务")
        register_passkey.setObjectName("SettingsBtn")
        register_passkey.clicked.connect(self._register_passkey_provider)
        passkey_row.addWidget(register_passkey)
        open_passkey = QPushButton("打开 Windows 设置")
        open_passkey.setObjectName("SettingsBtn")
        open_passkey.clicked.connect(self._open_passkey_settings)
        passkey_row.addWidget(open_passkey)
        g.addLayout(passkey_row)
        repair_passkey = QPushButton("修复 Windows 通行密钥缓存")
        repair_passkey.setObjectName("SettingsBtn")
        repair_passkey.clicked.connect(self._repair_passkey_cache)
        g.addWidget(repair_passkey)
        unregister_passkey = QPushButton("取消 Windows 通行密钥注册")
        unregister_passkey.setObjectName("Danger")
        unregister_passkey.clicked.connect(self._unregister_passkey_provider)
        g.addWidget(unregister_passkey)
        self._note(g, "Windows 缓存仅保存账户元数据；私钥始终保存在加密保险库中。")

        # ── 外观 ──
        g = self._group("外观")
        row = QHBoxLayout()
        row.addWidget(QLabel("主题"))
        row.addStretch()
        self.theme = _NoScrollComboBox()
        for label, value in (
            ("跟随系统", "auto"),
            ("浅色", "light"),
            ("深色", "dark"),
        ):
            self.theme.addItem(label, value)
        self.theme.setCurrentIndex(max(0, self.theme.findData(self._orig_mode)))
        self.theme.currentIndexChanged.connect(self._on_theme_changed)
        row.addWidget(self.theme)
        g.addLayout(row)

        language_row = QHBoxLayout()
        language_row.addWidget(QLabel("语言"))
        language_row.addStretch()
        self.language = _NoScrollComboBox()
        for label, value in i18n.LANGUAGE_OPTIONS:
            self.language.addItem(label, value)
        selected_language = (
            self._orig_language
            if self.language.findData(self._orig_language) >= 0
            else i18n.current_locale()
        )
        self.language.setCurrentIndex(max(0, self.language.findData(selected_language)))
        self.language.currentIndexChanged.connect(self._on_language_changed)
        language_row.addWidget(self.language)
        g.addLayout(language_row)
        self._language_note = self._note(g, "语言将在重启后生效。")
        self._language_note.setVisible(False)

        # 外观是最常访问且不需要身份验证的设置，固定置于首行。
        appearance_content = g.parentWidget()
        appearance_box = appearance_content.parentWidget() if appearance_content is not None else None
        if appearance_box is not None:
            self._content_lay.removeWidget(appearance_box)
            self._content_lay.insertWidget(0, appearance_box)

        g = self._group("启动与后台")
        self.start_at_login = QCheckBox("开机启动")
        self.start_at_login.setEnabled(sys.platform == "win32")
        g.addWidget(self.start_at_login)
        self._startup_note = self._note(g, "登录 Windows 后自动运行，适用于当前 Windows 用户。")
        try:
            self.start_at_login.setChecked(startup.is_enabled())
        except OSError as exc:
            self.start_at_login.setEnabled(False)
            self._startup_note.setText(f"无法读取开机启动状态：{exc}")
        self.start_at_login.toggled.connect(self._on_start_at_login_toggled)
        self.silent_start = QCheckBox("静默启动")
        self.silent_start.setChecked(bool(config.get("silent_start", False)))
        g.addWidget(self.silent_start)
        self._note(g, "下次启动时仅显示托盘图标；保险库保持锁定，点击托盘后显示解锁窗口。托盘不可用时仍显示窗口。")

        # 云端同步的开关与关联都在「云端同步」页自带，这里不再重复一份设置。

        # ── 关于 ──
        self._build_about_section()

        self._connect_auto_save()

        # 安全/隐私/数据 分组：不在打开时设围栏，而是在用户首次操作其中任一选项时验证主密码，
        # 通过后本次设置会话内不再重复验证（缓存主密码供各敏感操作复用）；外观分组不需要。
        self._sensitive_verified = False
        self._session_master: str | None = None
        self._session_verified_until = 0.0
        # 普通设置（锁定时间、剪贴板、检测周期等）不做整区密码拦截；
        # 降低安全边界和高风险按钮由各自处理器按风险等级验证。
        self._environment_worker: _SettingsEnvironmentWorker | None = None
        QTimer.singleShot(0, self._start_environment_probe)

    # ---------- 生命周期 ----------

    def close_page(self, reason: str) -> None:
        self._save_all()
        self.clear_security_session()
        worker = self._kdf_worker
        if worker is not None and worker.isRunning():
            worker.requestInterruption()

    def can_close(self, reason: str) -> bool:
        return True

    def refresh(self, context: object) -> None:
        self._refresh_native_exclude_count()
        if hasattr(self, "_user_lbl"):
            self._user_lbl.setText(f"当前用户：{config.get_current_user() or ''}")

    def _start_environment_probe(self) -> None:
        if self._environment_worker is not None:
            return
        # The worker belongs to the main window so closing this page
        # cannot destroy a running QThread while PowerShell/WinRT is still returning.
        owner = self._window if isinstance(self._window, QObject) else QApplication.instance()
        worker = _SettingsEnvironmentWorker(self._passkey_provider, owner)
        self._environment_worker = worker
        worker.completed.connect(self._on_environment_probed)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_environment_probed(self, hello_available: bool, provider_status: object) -> None:
        self._environment_worker = None
        self.hello_enabled.setEnabled(hello_available)
        if hello_available:
            hello_text = "设备中登记的所有强生物特征均可解锁此保险库。多人共用设备时，建议仅使用主密码。"
            self.hello_enabled.setToolTip("通过 PIN / 指纹 / 人脸解锁；PMVE RootKey 经 Windows DPAPI 保护")
        else:
            hello_text = "当前设备未配置生物识别（PIN / 指纹 / 人脸）或依赖不可用。"
            self.hello_enabled.setToolTip(hello_text)
        self._hello_note.setText(hello_text)
        self._apply_passkey_provider_status(provider_status)

    def eventFilter(self, obj, event) -> bool:
        if (
            (not self._sensitive_verified or time.monotonic() >= self._session_verified_until)
            and event.type()
            in (
                QEvent.MouseButtonPress,
                QEvent.MouseButtonDblClick,
                QEvent.KeyPress,
            )
            and self._in_sensitive(obj)
        ):
            # 拦截首次操作：验证通过后立即对原控件补发动作，无需用户再点一次
            if self._require_master("验证身份", "修改 安全 / 隐私 / 数据 设置需要验证主密码。") is not None:
                self._sensitive_verified = True
                self._replay_action(obj)
            return True
        return super().eventFilter(obj, event)

    def _replay_action(self, obj) -> None:
        """验证通过后补发被拦截的操作：按钮/开关直接 click()，其余控件聚焦以便继续操作。"""
        if isinstance(obj, QAbstractButton):
            obj.click()
        elif isinstance(obj, QWidget):
            obj.setFocus()

    def _in_sensitive(self, obj) -> bool:
        # Viewing authenticated device records does not change a security setting.
        if isinstance(obj, QWidget) and (obj is self.devices_button or self.devices_button.isAncestorOf(obj)):
            return False
        return any(box.isAncestorOf(obj) for box in self._sensitive_boxes if isinstance(obj, QWidget))

    def _note(self, layout: QVBoxLayout, text: str, *, object_name: str = "SettingNote") -> QLabel:
        note = QLabel(text)
        note.setObjectName(object_name)
        note.setWordWrap(True)
        layout.addWidget(note)
        return note

    def _refresh_native_exclude_count(self) -> None:
        from core.autofill_exclusions import normalize
        from collections.abc import Mapping

        exclusions = getattr(self._window.vault, "autofill_exclusions", None)
        if not isinstance(exclusions, Mapping):
            exclusions = {
                "processes": config.get("native_autofill_excluded", []) or [],
                "hosts": config.get("browser_autofill_excluded_hosts", []) or [],
            }
        values = normalize(exclusions)
        count = sum(len(values[category]) for category in ("packages", "hosts", "processes"))
        if hasattr(self, "_native_exclude_count"):
            self._native_exclude_count.setText(i18n.tr("已排除 {count} 项").format(count=count))

    def _kdf_config_key(self) -> str:
        return pmv_kdf_policy.kdf_config_key_for(self._window.vault)

    def _selected_kdf_profile(self) -> PmvKdfProfile:
        return PmvKdfProfile[str(self.kdf_profile.currentData())]

    def _refresh_kdf_status(self) -> None:
        try:
            current = self._window.vault.kdf_parameters
        except (AttributeError, ValueError):
            self._kdf_status.setText(i18n.tr("当前会话不支持 KDF 参数升级。"))
            return
        selected = self._selected_kdf_profile()
        params = current
        if current == selected.parameters:
            status = "当前保险库已使用所选等级。"
        else:
            status = "当前保险库参数与所选等级不同；应用后仅重新包装数据密钥，不重加密库内容。"
        details = i18n.tr("当前参数：内存 {memory} KiB，迭代 {iterations}，并行 {parallelism}。").format(
            memory=params.memory_kib,
            iterations=params.iterations,
            parallelism=params.parallelism,
        )
        self._kdf_status.setText(f"{i18n.tr(status)} {details}")

    def _apply_kdf_profile(self) -> None:
        self._start_kdf_worker(self._selected_kdf_profile())

    def _start_kdf_worker(self, profile: PmvKdfProfile | None) -> None:
        if self._kdf_worker is not None and self._kdf_worker.isRunning():
            return
        self._kdf_apply.setEnabled(False)
        self._kdf_recommend.setEnabled(False)
        self._kdf_status.setText("正在后台升级…" if profile is not None else "正在后台校准本机性能…")
        worker = _KdfSettingsWorker(self._window.vault, profile, self)
        self._kdf_worker = worker
        worker.completed.connect(lambda result, upgrading=profile is not None: self._kdf_completed(result, upgrading))
        worker.failed.connect(self._kdf_failed)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _kdf_completed(self, profile: PmvKdfProfile, upgrading: bool) -> None:
        index = self.kdf_profile.findData(profile.name)
        if index >= 0:
            self.kdf_profile.setCurrentIndex(index)
        config.set(self._kdf_config_key(), profile.name)
        self._kdf_apply.setEnabled(True)
        self._kdf_recommend.setEnabled(True)
        self._refresh_kdf_status()
        if upgrading:
            widgets.message(self, "KDF 已升级", "主密码数据密钥已按所选参数重新包装。", kind="success")

    def _kdf_failed(self, message: str) -> None:
        self._kdf_apply.setEnabled(True)
        self._kdf_recommend.setEnabled(True)
        self._refresh_kdf_status()
        widgets.message(self, "KDF 操作失败", message, kind="error")

    def _manage_native_autofill_exclusions(self) -> None:
        dlg = NativeAutofillExcludeDialog(self, vault=self._window.vault)
        dlg.exec()
        self._refresh_native_exclude_count()

    def _refresh_passkey_provider_status(self) -> None:
        self._apply_passkey_provider_status(self._passkey_provider.query())

    def _apply_passkey_provider_status(self, status) -> None:
        if status is None:
            self._passkey_provider_status.setText("无法获取 Windows Passkey 提供程序状态。")
            return
        if not status.supported:
            text = "当前 Windows 版本不支持第三方 Passkey 提供程序。"
        elif not status.installed:
            text = (
                "提供程序尚未安装。带 Passkey Provider 的安装包会自动安装该组件；"
                "若当前版本未包含（构建时缺少受信任的代码签名证书），"
                "请改用包含该组件的版本重装。"
            )
        elif not status.registered:
            text = "提供程序已安装，但尚未向 Windows 注册。"
        elif not status.enabled:
            text = "提供程序已注册；请在 Windows 高级通行密钥设置中启用 FAE Vault。"
        elif status.cache_healthy:
            text = "FAE Vault 已作为 Windows Passkey 提供程序启用，缓存状态正常。"
        else:
            text = "FAE Vault 已作为 Windows Passkey 提供程序启用；缓存将在保险库解锁后自动协调。"
        if status.last_error:
            text += f"\n{status.last_error}"
        self._passkey_provider_status.setText(text)

    def _register_passkey_provider(self) -> None:
        try:
            status = self._passkey_provider.register()
            self._refresh_passkey_provider_status()
            message = "提供程序已注册。" if status.enabled else "提供程序已注册，请在 Windows 设置中启用 FAE Vault。"
            widgets.message(self, "注册完成", message, kind="success")
        except Exception as exc:
            widgets.message(self, "注册失败", str(exc), kind="error")

    def _unregister_passkey_provider(self) -> None:
        try:
            self._passkey_provider.unregister()
            self._refresh_passkey_provider_status()
            widgets.message(self, "已取消注册", "Windows 缓存已移除，保险库内的通行密钥未被删除。", kind="success")
        except Exception as exc:
            widgets.message(self, "取消注册失败", str(exc), kind="error")

    def _repair_passkey_cache(self) -> None:
        try:
            self._passkey_provider.repair_cache()
            self._refresh_passkey_provider_status()
            widgets.message(self, "修复完成", "Windows 通行密钥账户缓存已与当前保险库一致。", kind="success")
        except Exception as exc:
            widgets.message(self, "修复失败", str(exc), kind="error")

    def _open_passkey_settings(self) -> None:
        try:
            self._passkey_provider.open_settings()
        except Exception as exc:
            widgets.message(self, "无法打开", str(exc), kind="error")

    def _group(self, text: str, *, sensitive: bool = False) -> QVBoxLayout:
        box = QFrame()
        box.setObjectName("SettingGroupBox")
        outer = QVBoxLayout(box)
        outer.setContentsMargins(14, 10, 14, 12)
        outer.setSpacing(0)

        toggle = QPushButton(text)
        toggle.setObjectName("SettingGroupToggle")
        outer.addWidget(toggle)

        content = QWidget()
        lay = QVBoxLayout(content)
        lay.setContentsMargins(0, 10, 0, 2)
        lay.setSpacing(7)
        outer.addWidget(content)
        self._content_lay.addWidget(box)
        if sensitive:
            self._sensitive_boxes.append(content)
        return lay

    def _advanced_group(self, parent: QVBoxLayout, title: str) -> QVBoxLayout:
        toggle = QPushButton(i18n.tr(title))
        toggle.setObjectName("SettingGroupToggle")
        toggle.setCheckable(True)
        parent.addWidget(toggle)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(7)
        parent.addWidget(content)
        content.hide()
        toggle.toggled.connect(content.setVisible)
        self._advanced_toggle = toggle
        self._advanced_content = content
        return layout

    def _build_about_section(self) -> None:
        g = self._group("关于与支持")

        name = QLabel(f"保险库  v{self._app_version()}")
        name.setObjectName("TitleText")
        g.addWidget(name)
        self._note(g, "开发者：FAE")

        row = QHBoxLayout()
        email = QLabel(f"联系：{_CONTACT_EMAIL}")
        email.setObjectName("Empty")
        email.setWordWrap(True)
        row.addWidget(email, 1)
        self._contact_copy_btn = widgets.icon_only_button("copy", "复制邮箱", size=16)
        self._contact_copy_btn.clicked.connect(self._copy_contact_email)
        row.addWidget(self._contact_copy_btn)
        g.addLayout(row)

        btn_row = QHBoxLayout()
        privacy_btn = widgets.set_button_icon(QPushButton("隐私政策"), "info")
        privacy_btn.setObjectName("SettingsBtn")
        privacy_btn.clicked.connect(lambda: self._open_official_document("privacy"))
        changelog_btn = QPushButton("更新日志")
        changelog_btn.setObjectName("SettingsBtn")
        changelog_btn.clicked.connect(lambda: self._open_official_document("changelog"))
        btn_row.addWidget(privacy_btn)
        btn_row.addWidget(changelog_btn)
        g.addLayout(btn_row)

        self._update_btn = QPushButton("检查更新")
        self._update_btn.setObjectName("SettingsBtn")
        self._update_btn.clicked.connect(self._check_for_updates)
        g.addWidget(self._update_btn)

        # ── 赞助支持 ──
        self._note(g, "在浏览器中打开赞助页面了解支持方式。")
        button = widgets.set_button_icon(QPushButton("打开赞助页面"), "view")
        button.setObjectName("SettingsBtn")
        button.clicked.connect(self._open_sponsor_site)
        g.addWidget(button)

    def _check_for_updates(self) -> None:
        self._update_btn.setEnabled(False)
        self._update_btn.setText("正在检查…")
        worker = _UpdateCheckWorker(self)
        self._update_worker = worker
        worker.completed.connect(self._on_update_checked)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_update_checked(self, info: object, error: object) -> None:
        self._update_btn.setEnabled(True)
        self._update_btn.setText("检查更新")
        if error or not isinstance(info, updates.UpdateInfo):
            widgets.message(self, "检查失败", f"无法获取最新版本：{error or '返回内容无效'}", kind="error")
            return
        if not updates.is_newer(info.version, self._app_version()):
            widgets.message(self, "已是最新版本", f"当前版本 v{self._app_version()} 已是最新正式版。", kind="success")
            return
        notes = info.notes or "此版本未提供更新说明。"
        if UpdateDialog(self, info.version, notes).exec() == QDialog.Accepted:
            self._run_internal_update(info)

    def _run_internal_update(self, info: updates.UpdateInfo) -> None:
        """在应用内下载并安装新版本，安装完成后退出本进程。

        只有对话框 Accepted（即安装器确认退出成功）才退出应用：失败时保留窗口，
        用户能看到原因并决定重试还是去官网手动下载——原先无论成败都
        os._exit(0)，安装失败对用户完全不可见。
        """
        dlg = UpdateDownloadDialog(self, info)
        dlg.exec()
        if dlg.result() == QDialog.Accepted:
            os._exit(0)

    def _open_sponsor_site(self) -> None:
        url = QUrl("https://faegit.github.io/faevault-site/zh-cn/support/")
        if not QDesktopServices.openUrl(url):
            widgets.message(self, "无法打开", "请检查系统默认浏览器后重试。", kind="error")

    def _app_version(self) -> str:
        try:
            data = tomllib.loads((_PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
            return str(data.get("project", {}).get("version") or "1.0.0")
        except Exception:
            return "1.0.0"

    def _copy_contact_email(self) -> None:
        QApplication.clipboard().setText(_CONTACT_EMAIL)
        widgets.flash_copy_success(self._contact_copy_btn)

    def _open_official_document(self, anchor: str) -> None:
        """隐私政策与更新日志已迁至官网「关于」页，这里用默认浏览器打开对应锚点。

        官网按客户端分端（Android / PC），因此 PC 端用 ``pc-`` 前缀的深链；
        语言跟随界面，未显式选择时按系统语言判断。
        """
        locale = self.language.currentData() or i18n.current_locale()
        lang = "en" if str(locale).lower().startswith("en") else "zh-cn"
        url = f"https://faegit.github.io/faevault-site/{lang}/about/#pc-{anchor}"
        widgets._open_external_link(QUrl(url))

    def _on_theme_changed(self) -> None:
        mode = self.theme.currentData()
        self._queue_config_save("theme_mode", mode)
        self._window.apply_theme(mode)

    def _on_language_changed(self) -> None:
        selected = self.language.currentData()
        self._queue_config_save("language_mode", selected)
        self._language_note.setVisible(selected != self._orig_language)

    def _connect_auto_save(self) -> None:
        self._pending_config_saves: dict[str, object] = {}
        self._config_save_timer = QTimer(self)
        self._config_save_timer.setSingleShot(True)
        self._config_save_timer.setInterval(160)
        self._config_save_timer.timeout.connect(self._flush_config_saves)
        for w, key in [
            (self.lock_enabled, "lock_enabled"),
            (self.lock_seconds, "lock_seconds"),
            (self.clipboard_seconds, "clipboard_clear_seconds"),
            (self.reveal_seconds, "reveal_hide_seconds"),
            (self.recycle_days, "recycle_bin_retention_days"),
            (self.background_hide, "background_hide"),
            (self.silent_start, "silent_start"),
            (self.native_autofill_enabled, "native_autofill_enabled"),
        ]:
            if hasattr(w, "valueChanged"):
                w.valueChanged.connect(lambda v, k=key: self._queue_config_save(k, v))
            elif hasattr(w, "toggled"):
                w.toggled.connect(lambda checked, k=key: self._queue_config_save(k, checked))
            elif hasattr(w, "currentIndexChanged"):
                w.currentIndexChanged.connect(lambda _i, k=key, control=w: self._queue_config_save(k, control.currentData()))
        self.require_master.toggled.connect(self._on_require_master_toggled)
        self.allow_capture.toggled.connect(self._on_allow_capture_toggled)

    def _on_start_at_login_toggled(self, enabled: bool) -> None:
        try:
            startup.set_enabled(enabled)
        except OSError as exc:
            self.start_at_login.blockSignals(True)
            self.start_at_login.setChecked(not enabled)
            self.start_at_login.blockSignals(False)
            self._startup_note.setText(f"开机启动设置失败：{exc}")
            return
        self._startup_note.setText("已开启开机启动，下次登录 Windows 后自动运行。" if enabled else "已关闭开机启动。")

    def _queue_config_save(self, key: str, value: object) -> None:
        self._pending_config_saves[key] = value
        config.stage_many({key: value})
        self._config_save_timer.start()

    def _flush_config_saves(self) -> None:
        pending = self._pending_config_saves
        if not pending:
            return
        self._pending_config_saves = {}
        config.set_many(pending)

    def _on_require_master_toggled(self, checked: bool) -> None:
        if checked:
            config.set("require_master_for_sensitive", True)
            return
        if self._require_master("关闭敏感信息保护", "关闭后查看敏感字段将不再要求验证主密码。") is not None:
            config.set("require_master_for_sensitive", False)
            return
        self.require_master.blockSignals(True)
        self.require_master.setChecked(True)
        self.require_master.blockSignals(False)

    def _on_allow_capture_toggled(self, allowed: bool) -> None:
        if allowed:
            verified = self._require_master(
                "允许截屏",
                "允许截屏需要验证当前主密码。",
                force=True,
            ) is not None
            confirmed = verified and widgets.confirm(
                self,
                "允许截屏",
                "开启后，保险库内容可能出现在截图、录屏、投屏画面和窗口预览中。确定继续吗？",
                kind="warn",
            )
            if not confirmed:
                self.allow_capture.blockSignals(True)
                self.allow_capture.setChecked(False)
                self.allow_capture.blockSignals(False)
                return
        self._queue_config_save("screen_capture_allowed", allowed)
        # The main window and this settings surface already have native HWNDs.
        # Changing the saved preference alone does not clear their old affinity.
        from PySide6.QtWidgets import QApplication

        for window in QApplication.topLevelWidgets():
            if window.isVisible():
                screen_capture.apply_permission(window, allowed)

    def _save_all(self) -> None:
        self._config_save_timer.stop()
        # Controls already save their own changes. Writing every displayed value
        # here would overwrite updates made elsewhere while this page was open.
        self._flush_config_saves()
        self._window.apply_lock_settings()
        self._window.apply_privacy_settings()
        self._window.apply_native_autofill_settings()

    def _refresh_browser_autofill_status(self) -> None:
        try:
            state = browser_install.status()
        except Exception:
            state = None
        if state is not None and state.installed:
            self._browser_autofill_status.setText("本机宿主已注册 · 浏览器扩展目录已就绪")
            self._browser_autofill_install.setEnabled(False)
            self._browser_autofill_remove.setEnabled(True)
        else:
            self._browser_autofill_status.setText("尚未关联浏览器")
            self._browser_autofill_install.setEnabled(True)
            self._browser_autofill_remove.setEnabled(False)
        origins, origins_valid = config.browser_private_origins()
        count = len(origins) if origins_valid else 0
        self._browser_private_status.setText(f"已授权 {count} 个 IP 地址来源" if count else "尚未授权 IP 地址来源")
        self._browser_private_clear.setVisible(count > 0)

    def _clear_browser_private_origins(self) -> None:
        if not widgets.confirm(
            self,
            "撤销 IP 地址授权",
            "确定撤销全部 IP 地址自动填充授权吗？之后再次使用时需要重新确认。",
            kind="warn",
        ):
            return
        config.set_browser_private_origins([])
        self._refresh_browser_autofill_status()

    def _browser_extension_source(self) -> Path | None:
        candidates = (
            _PROJECT_ROOT / "browser_extension",
            Path(sys.executable).resolve().parent / "browser_extension",
            _PROJECT_ROOT / "dist" / "browser-autofill" / "chromium",
        )
        return next((path for path in candidates if (path / "manifest.json").is_file()), None)

    def _install_browser_autofill(self) -> None:
        if self._require_master(
            "启用浏览器通行密钥",
            "启用后，浏览器扩展可在您主动操作时向本机保险库请求匹配的网页登录凭据。",
        ) is None:
            return
        host = browser_install.find_built_host(_PROJECT_ROOT)
        source = self._browser_extension_source()
        if host is None or source is None:
            missing = []
            if host is None:
                missing.append("本机通信宿主 VaultBrowserHost.exe")
            if source is None:
                missing.append("浏览器扩展资源")
            widgets.message(
                self,
                "组件缺失",
                f"当前安装不完整，缺少：{'、'.join(missing)}。请安装包含通行密钥组件的完整版本。",
                kind="error",
            )
            return
        try:
            state = browser_install.install(host, source)
        except Exception as exc:
            widgets.message(self, "启用失败", f"无法注册通行密钥：{exc}", kind="error")
            return
        self._refresh_browser_autofill_status()
        if state.installed:
            widgets.message(self, "已启用", "本机宿主和浏览器扩展目录已准备完成。", kind="success")

    def _remove_browser_autofill(self) -> None:
        if self._require_master(
            "取消浏览器通行密钥关联",
            "取消关联需要验证当前主密码。",
        ) is None:
            return
        if not widgets.confirm(self, "取消浏览器通行密钥关联", "确定移除本机宿主注册和扩展文件吗？", kind="warn"):
            return
        try:
            browser_install.uninstall()
        except Exception as exc:
            widgets.message(self, "取消失败", f"无法移除浏览器关联：{exc}", kind="error")
            return
        config.set_browser_private_origins([])
        self._refresh_browser_autofill_status()

    def _open_browser_extension_manager(self, browser: str) -> None:
        state = browser_install.status()
        if not state.installed:
            widgets.message(self, "尚未启用", "请先启用浏览器通行密钥。", kind="info")
            return
        try:
            browser_install.launch_extension_manager(browser, state.extension_dir)
        except Exception as exc:
            widgets.message(self, "无法打开", str(exc), kind="error")

    def _require_master(self, title: str, text: str, *, force: bool = False) -> str | None:
        """重要操作前验证主密码，通过则返回主密码，否则返回 None。

        一次打开的设置页只需验证一次：首次通过后缓存主密码，后续敏感操作直接复用，
        页面关闭后缓存失效，再次打开需重新验证。
        ``force=True`` 时忽略缓存、强制重新验证（用于删除账户等不可逆的高危操作）。
        """
        if not force and self._session_master is not None and time.monotonic() < self._session_verified_until:
            return self._session_master
        if time.monotonic() >= self._session_verified_until:
            self._session_master = None
            self._sensitive_verified = False
        dlg = ConfirmPasswordDialog(self._window.vault.verify_password, title, text, confirm_text="验证", parent=self)
        if dlg.exec() == QDialog.Accepted and dlg.unlocked:
            self._session_master = dlg.password
            self._session_verified_until = time.monotonic() + 5 * 60
            self._sensitive_verified = True
            return dlg.password
        return None

    def clear_security_session(self) -> None:
        self._session_master = None
        self._session_verified_until = 0.0
        self._sensitive_verified = False

    def _open_vault_folder(self) -> None:
        if self._require_master("打开密码库文件夹", "打开密码库所在文件夹需要验证当前主密码。") is None:
            return
        self._window.open_vault_folder()

    def _rename_user(self) -> None:
        if self._require_master("重命名账户", "重命名账户需要验证当前主密码。") is None:
            return
        old = config.get_current_user() or ""
        dlg = AccountRenameDialog(old, [u["name"] for u in config.list_users()], parent=self)
        if dlg.exec() != QDialog.Accepted or dlg.new_name is None:
            return
        try:
            config.rename_user(old, dlg.new_name)
        except ValueError as exc:
            widgets.message(self, i18n.tr("重命名失败"), str(exc), kind="error")
            return
        if hasattr(self, "_user_lbl"):
            self._user_lbl.setText(f"当前用户：{config.get_current_user() or ''}")
        self._window.reload()

    def _change_password(self) -> None:
        # 修改主密码为高危操作，强制重新验证（忽略会话缓存），通过后免去对话框内再输旧密码
        master = self._require_master("修改主密码", "修改主密码需要验证当前主密码。", force=True)
        if master is None:
            return
        path = self._window.vault.path
        dlg = ChangePasswordDialog(self._window.vault, parent=self, known_master=master)
        if dlg.exec() == QDialog.Accepted:
            self._session_master = dlg.new_pw.text()  # 缓存随新主密码更新，避免后续复用旧密码
            self._session_verified_until = time.monotonic() + 5 * 60
            msg = "主密码已更新，请牢记新密码。"
            if biometric.is_enabled(path):
                msg += "\n\n生物识别直接保护数据密钥，修改主密码后仍可继续使用。"
            widgets.message(self, "已修改", msg, kind="success")

    def _set_hello_checked(self, value: bool) -> None:
        self._hello_guard = True
        self.hello_enabled.setChecked(value)
        self._hello_guard = False

    def _on_hello_toggled(self, checked: bool) -> None:
        if self._hello_guard:
            return
        path = self._window.vault.path
        if checked:
            master = self._require_master("启用生物识别", "启用生物识别解锁需要验证当前主密码。", force=True)
            if master is None:
                self._set_hello_checked(False)
                return
            if not biometric.enable_for_vault(self._window.vault):
                widgets.message(self, "启用失败", "无法启用生物识别，请重试。", kind="error")
                self._set_hello_checked(False)
                return
            widgets.message(self, "已启用", "下次登录可使用生物识别解锁。", kind="success")
        else:
            biometric.disable(path)

    # ---------- 紧急恢复密钥 ----------
    def _build_recovery_controls(self) -> None:
        """PMVE 恢复密钥不可删除，只能验证或原子重新生成。"""
        box = self._recovery_box
        while box.count():
            item = box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        created_at = getattr(self._window.vault, "key_updated_at", 0.0)
        created = (
            datetime.datetime.fromtimestamp(created_at).strftime("%Y-%m-%d")
            if created_at else i18n.tr("未知时间")
        )
        template = i18n.tr("紧急恢复密钥已创建 · 密钥版本 v{} · {}")
        box.addWidget(widgets.icon_text(
            template.format(getattr(self._window.vault, "key_revision", 0), created),
            "recovery", object_name="Empty", icon_size=18, word_wrap=True,
        ))
        regenerate = QPushButton("恢复密钥泄露/丢失？重新生成")
        regenerate.clicked.connect(self._regenerate_recovery_key)
        box.addWidget(regenerate)

    def _regenerate_recovery_key(self) -> None:
        password = self._require_master(
            "重新生成恢复密钥", "重新生成会使旧恢复密钥立即失效，需要验证当前主密码。", force=True
        )
        if password is None:
            return
        dlg = RecoveryKeyConfirmDialog(self, key_revision=self._window.vault.key_revision + 1)
        if dlg.exec() != QDialog.Accepted:
            return
        try:
            self._window.vault.regenerate_recovery_key_with_password(password, dlg.secret)
        except Exception:
            widgets.message(
                self,
                i18n.tr("重新生成失败"),
                i18n.tr("恢复密钥生成失败，请重试。"),
                kind="error",
            )
            return
        widgets.message(self, "已重新生成", "新恢复密钥已生效，旧恢复密钥已失效。", kind="success")
        self._build_recovery_controls()

    def _delete_user(self) -> None:
        name = config.get_current_user()
        if not name:
            return
        if not widgets.confirm(
            self,
            "删除账户",
            f"确定要删除账户「{name}」吗？\n\n"
            f"账户将被移入回收站，{config.ACCOUNT_RETENTION_DAYS} 天内可在「新建账户」处"
            "输入同名一键恢复（数据、恢复密钥、生物识别绑定均保留）。\n"
            "超过保留期后将自动彻底删除，无法找回。",
            kind="warn",
        ):
            return
        if self._require_master("确认身份", "删除账户需要验证当前主密码。", force=True) is None:
            return
        config.trash_account(name)
        self._delete_occurred = True
        self.accountDeleted.emit()
