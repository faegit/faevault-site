"""Embedded synchronization pages for the editor workspace."""

from __future__ import annotations

import base64
import datetime
import hashlib
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QPixmap
from shiboken6 import isValid
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import auto_cloud_sync, cloud, config, local_backup, sync
from core import log as _log_mod

from . import i18n, widgets
from .cloud_sync_controller import CloudSyncController
from .cloud_sync_page import CloudSyncPage
from .dialogs import _NoScrollComboBox, _NoScrollSlider
from .editor_workspace import EditorPage, page_shell
from .lan_panels import LanSyncStatusPanel, LanTransferPanel

_log = _log_mod.get("sync_pages")
_FILE_OPTS = QFileDialog.Option(0)
_AUTO_SYNC_INTERVALS = auto_cloud_sync.INTERVAL_MINUTES
_AUTO_SYNC_LABELS = ("15分钟", "30分钟", "1小时", "3小时", "6小时", "每天", "每周")
#: 传输站页底部状态按钮的限宽：铺满整行会像横幅而不像按钮。
ACTION_BUTTON_WIDTH = 220


def _confirm_master_password(*args, **kwargs):
    from .app import _confirm_master_password as impl

    return impl(*args, **kwargs)


def _safe_filename_part(text: str) -> str:
    import re

    return re.sub(r"[\\/:*?\"<>|]", "_", text).strip() or "tag"


@dataclass(slots=True)
class CloudSyncContext:
    vault: object
    vault_path: Path
    password: object
    cloud_vault_id: str
    window: object | None = None


class CloudSyncWorkspacePage(EditorPage):
    """A detachable view of the session-owned cloud controller."""

    def __init__(self, context: CloudSyncContext, parent=None):
        super().__init__(parent)
        self.context = context
        self._window = context.window
        self.ui = CloudSyncPage(self)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.ui)

        controller_parent = self._window if isinstance(self._window, QObject) else self
        existing = getattr(self._window, "_cloud_controller", None) if isinstance(self._window, QObject) else None
        if existing is not None and not existing._closed:
            self.controller = existing
            if context.password is not None:
                context.password.clear()
        else:
            self.controller = CloudSyncController(
                vault=context.vault,
                vault_path=context.vault_path,
                password=context.password,
                cloud_vault_id=context.cloud_vault_id,
                parent=controller_parent,
            )
            if isinstance(self._window, QObject):
                self._window._cloud_controller = self.controller
                self.controller.vaultReplaced.connect(self._window._adopt_cloud_vault)
                self.controller.localVaultReplaced.connect(self._window._reopen_local_vault)
                window = self._window
                self.controller.message.connect(lambda title, text, kind: window._flash(f"{title}：{text}"))

                def refresh_session():
                    active = getattr(window, "_cloud_controller", None)
                    if active is not None and not active._closed:
                        active.stateChanged.emit()

                self.controller.settled.connect(refresh_session)
        self._busy_targets: set[str] = set()
        self._subscriptions = []
        self._view_detached = False
        self._build_cloud_ui()
        if not self.controller.loaded:
            QTimer.singleShot(0, self.controller.load_async)

    @property
    def page_header(self):
        """薄包装页：统一头部由内嵌的 CloudSyncPage 提供。"""
        return self.ui.page_header

    def _subscribe(self, signal, slot):
        """订阅控制器信号，并给回调加一层「视图是否还在」的保护。

        控制器挂在主窗口上、页面关掉后仍在发信号（``refresh_session`` 也会主动
        重发 ``stateChanged``）。页面若在 ``close_page`` 之外的路径上被销毁，
        回调就会打到已删除的控件上，刷出
        ``RuntimeError: Internal C++ object (QAction) already deleted``。
        这里捕获后直接断开订阅，不再反复报错（与 ``_set_backup_status`` 同一手法）。
        """

        def guarded(*args, **kwargs):
            if self._view_detached:
                return None
            if not isValid(self) or not isValid(self.ui):
                self._detach_view()
                return None
            try:
                return slot(*args, **kwargs)
            except RuntimeError as exc:
                if not isValid(self) or not isValid(self.ui):
                    self._detach_view()
                else:
                    _log.exception("云端同步页面更新失败：%s", exc)
                return None

        signal.connect(guarded)
        self._subscriptions.append((signal, guarded))

    def _detach_view(self) -> None:
        if self._view_detached:
            return
        self._view_detached = True
        for signal, slot in self._subscriptions:
            try:
                signal.disconnect(slot)
            except (RuntimeError, TypeError):
                pass
        self._subscriptions.clear()

    def has_active_task(self) -> bool:
        return bool(self._busy_targets) or self.controller.any_busy

    def can_close(self, reason: str) -> bool:
        return True

    def close_page(self, reason: str) -> None:
        self._detach_view()
        if reason != "user" or self.controller.parent() is self:
            self.controller.cancel_active_operations()

    def refresh(self, context: object) -> None:
        pass

    def _build_cloud_ui(self) -> None:
        dlg = self
        vault = self._window.vault if self._window is not None else self.context.vault
        cloud_vault_id = self.context.cloud_vault_id
        drive_layout = self.ui.drive.layout
        drive_status = self.ui.drive.status
        drive_phase = self.ui.drive.phase
        drive_preview = self.ui.drive.preview
        drive_path_label = self.ui.drive.path
        drive_progress = self.ui.drive.progress
        drive_sync_btn = self.ui.drive.sync
        drive_check_btn = self.ui.drive.check
        drive_more_btn = self.ui.drive.more
        drive_overwrite_action = self.ui.drive.overwrite_action
        drive_download_action = self.ui.drive.download_action
        drive_relate_action = self.ui.drive.relate_action
        drive_clear_action = self.ui.drive.clear_action
        drive_relate_btn = self.ui.drive.relate

        nas_layout = self.ui.webdav.layout
        nas_status = self.ui.webdav.status
        nas_phase = self.ui.webdav.phase
        nas_preview = self.ui.webdav.preview
        nas_path_label = self.ui.webdav.path
        nas_progress = self.ui.webdav.progress
        nas_sync_btn = self.ui.webdav.sync
        nas_check_btn = self.ui.webdav.check
        nas_more_btn = self.ui.webdav.more
        nas_overwrite_action = self.ui.webdav.overwrite_action
        nas_download_action = self.ui.webdav.download_action
        nas_relate_action = self.ui.webdav.relate_action
        nas_clear_action = self.ui.webdav.clear_action
        nas_relate_btn = self.ui.webdav.relate

        auth_mode = _NoScrollComboBox()
        auth_mode.addItem("用户名 / 密码（Basic）", "basic")
        auth_mode.addItem("用户名 / 密码（Digest）", "digest")
        auth_mode.addItem("Bearer Token", "bearer")
        auth_mode.addItem("OAuth 2.0 访问令牌", "oauth2")
        auth_mode.addItem("客户端证书（mTLS）", "mtls")
        auth_mode.addItem("Cookie / Session", "cookie")
        auth_mode.addItem("Windows NTLM", "ntlm")
        auth_mode.addItem("Windows Kerberos / SSO", "kerberos")
        auth_mode.addItem("无认证", "none")
        if self.controller.webdav_config:
            auth_mode.setCurrentIndex(max(0, auth_mode.findData(self.controller.webdav_config.auth_mode)))
        url = QLineEdit(cloud.directory_url(self.controller.webdav_config.file_url) if self.controller.webdav_config else "")
        url.setPlaceholderText("https://server.example/dav/")
        username = QLineEdit(self.controller.webdav_config.username if self.controller.webdav_config else "")
        username.setPlaceholderText("用户名")
        password = QLineEdit(self.controller.webdav_config.password if self.controller.webdav_config else "")
        password.setPlaceholderText("密码或应用专用密码")
        password.setEchoMode(QLineEdit.Password)
        bearer = QLineEdit(self.controller.webdav_config.bearer_token if self.controller.webdav_config else "")
        bearer.setPlaceholderText("Bearer Token")
        bearer.setEchoMode(QLineEdit.Password)
        cookie = QLineEdit(self.controller.webdav_config.cookie if self.controller.webdav_config else "")
        cookie.setPlaceholderText("name=value; session=value")
        cookie.setEchoMode(QLineEdit.Password)
        domain = QLineEdit(self.controller.webdav_config.domain if self.controller.webdav_config else "")
        domain.setPlaceholderText("Windows 域（可选）")
        client_certificate = QLineEdit(self.controller.webdav_config.client_certificate if self.controller.webdav_config else "")
        client_certificate.setVisible(False)
        client_certificate_password = QLineEdit(self.controller.webdav_config.client_certificate_password if self.controller.webdav_config else "")
        client_certificate_password.setEchoMode(QLineEdit.Password)
        choose_certificate = QPushButton("选择 PKCS#12 客户端证书")
        certificate_name = QLabel("已配置客户端证书" if client_certificate.text() else "未选择客户端证书")

        def choose_client_certificate():
            path, _ = QFileDialog.getOpenFileName(
                dlg,
                i18n.tr("选择客户端证书"),
                str(Path.home()),
                "PKCS#12 (*.p12 *.pfx)",
            )
            if not path:
                return
            try:
                raw = Path(path).read_bytes()
                if len(raw) > 1024 * 1024:
                    raise ValueError("客户端证书超过 1 MB 安全限制")
                client_certificate.setText(base64.b64encode(raw).decode("ascii"))
                certificate_name.setText(Path(path).name)
            except (OSError, ValueError) as exc:
                widgets.message(dlg, "无法读取证书", str(exc), kind="warn")

        choose_certificate.clicked.connect(choose_client_certificate)
        certificate = QLineEdit(self.controller.webdav_config.certificate_sha256 if self.controller.webdav_config else "")
        certificate.setPlaceholderText("自签名证书 SHA-256 指纹（可选）")
        create_dirs = QCheckBox("自动创建远端目录")
        create_dirs.setChecked(self.controller.webdav_config.create_directories if self.controller.webdav_config else False)
        auth_fields = {}
        for label, field in (
            ("认证方式", auth_mode),
            ("远端目录地址", url),
            ("用户名", username),
            ("密码", password),
            ("Bearer Token", bearer),
            ("Cookie / Session", cookie),
            ("Windows 域", domain),
            ("客户端证书", choose_certificate),
            ("证书状态", certificate_name),
            ("客户端证书密码", client_certificate_password),
            ("自签名证书 SHA-256 指纹", certificate),
        ):
            caption = QLabel(label)
            auth_fields[label] = (caption, field)

        def update_auth_fields():
            mode = str(auth_mode.currentData())
            visible = {
                "用户名": mode in {"basic", "digest", "ntlm"},
                "密码": mode in {"basic", "digest", "ntlm"},
                "Bearer Token": mode in {"bearer", "oauth2"},
                "Cookie / Session": mode == "cookie",
                "Windows 域": mode == "ntlm",
                "客户端证书": mode == "mtls",
                "证书状态": mode == "mtls",
                "客户端证书密码": mode == "mtls",
            }
            for label, shown in visible.items():
                for widget in auth_fields[label]:
                    widget.setVisible(shown)

        nas_auth_form = QWidget()
        nas_form_layout = QVBoxLayout(nas_auth_form)
        nas_form_layout.setContentsMargins(0, 0, 0, 0)
        nas_form_layout.setSpacing(8)
        for label, field in auth_fields.values():
            nas_form_layout.addWidget(label)
            nas_form_layout.addWidget(field)
        nas_form_layout.addWidget(create_dirs)
        nas_layout.insertWidget(2, nas_auth_form)

        # Parent every field before showing it. A parentless QWidget becomes
        # a native top-level window when setVisible(True) is called, flashing
        # briefly on Windows before the layout reparents it.
        auth_mode.currentIndexChanged.connect(update_auth_fields)
        update_auth_fields()

        def make_auto_slider(tab_layout, target_name: str, after_widget, connected: bool = False):
            auto_enabled = bool(config.get(self._window._auto_sync_target_pref_key("enabled", target_name), False)) and connected
            interval_val = int(config.get(self._window._auto_sync_target_pref_key("interval", target_name), 60) or 60)
            interval_val = interval_val if interval_val in _AUTO_SYNC_INTERVALS else 60
            hline = QFrame()
            hline.setFrameShape(QFrame.HLine)
            hline.setFrameShadow(QFrame.Sunken)
            toggle = QCheckBox("自动云端同步")
            toggle.setChecked(auto_enabled)
            toggle.setEnabled(connected)
            slider = _NoScrollSlider(Qt.Horizontal)
            slider.setRange(0, len(_AUTO_SYNC_INTERVALS) - 1)
            slider.setValue(_AUTO_SYNC_INTERVALS.index(interval_val))
            slider.setEnabled(auto_enabled)
            interval_label = QLabel(f"自动同步周期：{_AUTO_SYNC_LABELS[slider.value()]}")
            interval_label.setObjectName("SettingNote")
            interval_label.setEnabled(auto_enabled)
            # 状态串是持久化下来的中文原文（写入时不能翻译：换语言后旧记录会停留在
            # 写入时的语言），所以要在渲染这一刻过一遍 i18n.tr。
            def _stored_status() -> str:
                return str(
                    config.get(self._window._auto_sync_target_pref_key("status", target_name), "")
                    or ""
                )

            def _status_text() -> str:
                raw = _stored_status()
                return i18n.tr(raw) if raw else i18n.tr("尚未执行自动同步")

            status = QLabel(_status_text())
            status.setWordWrap(True)
            status.setObjectName("SettingNote")
            tab_layout.insertWidget(tab_layout.indexOf(after_widget) + 1, hline)
            tab_layout.insertWidget(tab_layout.indexOf(after_widget) + 2, toggle)
            tab_layout.insertWidget(tab_layout.indexOf(after_widget) + 3, slider)
            tab_layout.insertWidget(tab_layout.indexOf(after_widget) + 4, interval_label)
            tab_layout.insertWidget(tab_layout.indexOf(after_widget) + 5, status)

            def save(en: bool | None = None, interval: int | None = None):
                en = toggle.isChecked() if en is None else en
                interval = _AUTO_SYNC_INTERVALS[slider.value()] if interval is None else interval
                config.set(self._window._auto_sync_target_pref_key("enabled", target_name), en)
                config.set(self._window._auto_sync_target_pref_key("interval", target_name), interval)
                if en and not float(config.get(self._window._auto_sync_target_pref_key("enabled_at", target_name), 0.0) or 0.0):
                    config.set(self._window._auto_sync_target_pref_key("enabled_at", target_name), time.time())
                st = _status_text()
                last_success = float(config.get(self._window._auto_sync_target_pref_key("last_success", target_name), 0.0) or 0.0)
                if en:
                    base = max(last_success, float(config.get(self._window._auto_sync_target_pref_key("enabled_at", target_name), 0.0) or 0.0))
                    next_text = datetime.datetime.fromtimestamp(base + interval * 60).strftime("%m-%d %H:%M") if base else i18n.tr("等待调度")
                    st += "\n" + i18n.tr("下次预计：") + next_text
                status.setText(st)

            def set_connected(val: bool) -> None:
                state["connected"] = val
                toggle.setEnabled(val)
                enabled = val and bool(config.get(self._window._auto_sync_target_pref_key("enabled", target_name), False))
                toggle.blockSignals(True)
                toggle.setChecked(enabled)
                toggle.blockSignals(False)
                slider.setEnabled(enabled)
                interval_label.setEnabled(enabled)

            state = {"connected": connected}

            def refresh() -> None:
                """从配置重读自动同步状态（供调度器写入后实时刷新标签）。"""
                set_connected(state["connected"])
                iv = int(config.get(self._window._auto_sync_target_pref_key("interval", target_name), 60) or 60)
                iv = iv if iv in _AUTO_SYNC_INTERVALS else 60
                slider.blockSignals(True)
                slider.setValue(_AUTO_SYNC_INTERVALS.index(iv))
                slider.blockSignals(False)
                interval_label.setText(f"自动同步周期：{_AUTO_SYNC_LABELS[slider.value()]}")
                st = _status_text()
                if toggle.isChecked():
                    last_success = float(config.get(self._window._auto_sync_target_pref_key("last_success", target_name), 0.0) or 0.0)
                    enabled_at = float(config.get(self._window._auto_sync_target_pref_key("enabled_at", target_name), 0.0) or 0.0)
                    base = max(last_success, enabled_at)
                    next_text = datetime.datetime.fromtimestamp(base + iv * 60).strftime("%m-%d %H:%M") if base else i18n.tr("等待调度")
                    st += "\n" + i18n.tr("下次预计：") + next_text
                status.setText(st)

            toggle.toggled.connect(lambda checked: (slider.setEnabled(checked), interval_label.setEnabled(checked), save()))
            slider.valueChanged.connect(lambda v: (interval_label.setText(f"自动同步周期：{_AUTO_SYNC_LABELS[v]}"), save()))
            return toggle, slider, interval_label, status, save, set_connected, refresh

        drive_auto_toggle, drive_auto_slider, drive_auto_label, drive_auto_status, save_drive, set_drive_connected, refresh_drive_auto = make_auto_slider(
            drive_layout, "drive", self.ui.drive.auto_anchor, connected=self.controller.drive_connected
        )
        nas_auto_toggle, nas_auto_slider, nas_auto_label, nas_auto_status, save_nas, set_nas_connected, refresh_nas_auto = make_auto_slider(
            nas_layout, "webdav", self.ui.webdav.auto_anchor, connected=self.controller.webdav_connected
        )

        def current_webdav() -> cloud.WebDavConfig:
            return cloud.WebDavConfig(
                "WebDAV",
                url.text().strip(),
                username.text(),
                password.text(),
                str(auth_mode.currentData()),
                bearer.text(),
                certificate.text(),
                create_dirs.isChecked(),
                cookie.text(),
                client_certificate.text(),
                client_certificate_password.text(),
                domain.text(),
            )

        def set_status(label: QLabel, health: str, connected_text: str) -> None:
            label.setVisible(bool(health))
            if not health:
                return
            label.setText("● " + connected_text)
            label.setProperty("state", "ok" if health == "ok" else "failed")
            label.style().unpolish(label)
            label.style().polish(label)

        last_form_config = [self.controller.webdav_config]

        def set_phase(label: QLabel, target: str) -> None:
            label.setText("● " + str(self.controller.status_text(target)))
            label.setProperty("state", str(self.controller.status_state(target)))
            label.style().unpolish(label)
            label.style().polish(label)

        def set_progress(bar: QProgressBar, target: str, busy: bool) -> None:
            bar.setVisible(busy)
            value = self.controller.progress_of(target)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                bar.setRange(0, 100)
                bar.setValue(int(max(0.0, min(1.0, float(value))) * 100))
            else:
                bar.setRange(0, 0)

        def refresh_result(target: str) -> None:
            controls = self.ui.drive if target == self.controller.DRIVE else self.ui.webdav
            notice = self.controller.notice_for(target)
            text = controls.preview.text().strip()
            state = self.controller.status_state(target)
            duplicate = text == self.controller.status_text(target).strip()
            if notice:
                duplicate = duplicate or text == str(notice[1]).strip() or (state == "failed" and notice[2] == "error")
            controls.preview.setVisible(bool(text) and not duplicate)
            connected = self.controller.drive_connected if target == self.controller.DRIVE else self.controller.webdav_connected
            controls.phase.setVisible((connected or state != "idle") and not (notice and state == "failed"))

        def refresh_controls() -> None:
            connection = self.controller.webdav_config
            if connection is not None and connection is not last_form_config[0]:
                last_form_config[0] = connection
                auth_mode.setCurrentIndex(max(0, auth_mode.findData(connection.auth_mode)))
                for field, value in (
                    (url, cloud.directory_url(connection.file_url)),
                    (username, connection.username),
                    (password, connection.password),
                    (bearer, connection.bearer_token),
                    (cookie, connection.cookie),
                    (domain, connection.domain),
                    (certificate, connection.certificate_sha256),
                    (client_certificate, connection.client_certificate),
                    (client_certificate_password, connection.client_certificate_password),
                ):
                    field.setText(value)
                create_dirs.setChecked(connection.create_directories)
                certificate_name.setText("已配置客户端证书" if connection.client_certificate else "未选择客户端证书")
            drive_connected = self.controller.drive_connected
            nas_connected = self.controller.webdav_connected
            cloud_busy = self.controller.any_busy or bool(getattr(self._window, "_auto_sync_workers", {}))
            if isinstance(self._window, QObject):
                cloud_busy = cloud_busy or not self.controller.can_start(self.controller.DRIVE)
            self._busy_targets = {target for target in (self.controller.DRIVE, self.controller.WEBDAV) if self.controller.is_busy(target)}
            drive_busy = self.controller.is_busy(self.controller.DRIVE)
            nas_busy = self.controller.is_busy(self.controller.WEBDAV)
            nas_auth_form.setVisible(not nas_connected)
            drive_text = {"ok": "关联正常", "missing": "文件已删除", "failed": "关联异常"}.get(self.controller.drive_health, "")
            set_status(drive_status, self.controller.drive_health, drive_text)
            set_status(
                nas_status,
                self.controller.webdav_health,
                "已连接" if (self.controller.webdav_health == "ok" and self.controller.webdav_config) else "关联异常",
            )
            set_phase(drive_phase, self.controller.DRIVE)
            set_phase(nas_phase, self.controller.WEBDAV)
            drive_path_label.setText(str(self.controller.drive_path) if self.controller.drive_path else "")
            drive_path_label.setToolTip(str(self.controller.drive_path) if self.controller.drive_path else "")
            drive_path_label.setVisible(drive_connected)
            nas_url = ""
            if isinstance(self.controller.webdav_config, cloud.WebDavConfig):
                nas_url = cloud.directory_url(self.controller.webdav_config.file_url)
            nas_path_label.setText(nas_url)
            nas_path_label.setToolTip(nas_url)
            nas_path_label.setVisible(nas_connected)
            # 未关联：主操作是「关联」；已关联：主操作是「重新检测 / 同步 / 更多操作」。
            drive_relate_btn.setVisible(not drive_connected)
            drive_relate_btn.setEnabled(not cloud_busy)
            for widget in (drive_check_btn, drive_sync_btn, drive_more_btn):
                widget.setVisible(drive_connected)
                widget.setEnabled(drive_connected and not cloud_busy)
            drive_overwrite_action.setEnabled(drive_connected and not cloud_busy)
            drive_download_action.setEnabled(drive_connected and not cloud_busy)
            drive_relate_action.setEnabled(drive_connected and not cloud_busy)
            drive_clear_action.setEnabled(drive_connected and not cloud_busy)
            nas_relate_btn.setVisible(not nas_connected)
            nas_relate_btn.setEnabled(not cloud_busy)
            for widget in (nas_check_btn, nas_sync_btn, nas_more_btn):
                widget.setVisible(nas_connected)
                widget.setEnabled(nas_connected and not cloud_busy)
            nas_overwrite_action.setEnabled(nas_connected and not cloud_busy)
            nas_download_action.setEnabled(nas_connected and not cloud_busy)
            nas_relate_action.setEnabled(nas_connected and not cloud_busy)
            nas_clear_action.setEnabled(nas_connected and not cloud_busy)
            set_drive_connected(drive_connected)
            set_nas_connected(nas_connected)
            refresh_drive_auto()
            refresh_nas_auto()
            set_progress(drive_progress, self.controller.DRIVE, drive_busy)
            set_progress(nas_progress, self.controller.WEBDAV, nas_busy)
            refresh_notice()

        def choose_existing(title: str) -> str | None:
            choice = {"value": None}
            prompt = widgets.ShadowDialog(title, dlg, width=420, simple_close=True)
            text = QLabel("远端已有保险库数据。请选择同步合并、上传覆盖本地数据到远端，或下载覆盖远端数据到本地。")
            text.setWordWrap(True)
            prompt.body.addWidget(text)
            merge_btn = QPushButton("同步合并")
            overwrite_btn_ = QPushButton("上传覆盖")
            overwrite_btn_.setObjectName("DangerGhost")
            download_btn = QPushButton("下载覆盖本地")
            download_btn.setObjectName("DangerGhost")
            cancel_btn = QPushButton("取消")
            for button in (merge_btn, overwrite_btn_, download_btn, cancel_btn):
                prompt.body.addWidget(button)
            merge_btn.clicked.connect(lambda: (choice.update(value="merge"), prompt.accept()))
            overwrite_btn_.clicked.connect(lambda: (choice.update(value="overwrite"), prompt.accept()))
            download_btn.clicked.connect(lambda: (choice.update(value="download"), prompt.accept()))
            cancel_btn.clicked.connect(prompt.reject)
            prompt.exec()
            return choice["value"]

        def confirm_download_overwrite(target: str) -> bool:
            if not widgets.confirm(
                dlg,
                "确认下载覆盖",
                f"将从{target}下载完整保险库并替换当前本地文件。此操作不会先执行合并。",
                kind="warn",
            ):
                return False
            return widgets.confirm(
                dlg,
                "再次确认本地数据风险",
                "本地独有条目、较新修改和本地删除记录都可能被远端版本覆盖。\n\n程序会保留 .sync.bak 备份，但仍建议先导出备份。确定继续吗？",
                kind="warn",
            )

        # ---- 控制器信号 -> 视图 ----
        self._subscribe(self.controller.stateChanged, refresh_controls)

        def on_preview(target: str, text: str) -> None:
            if target == self.controller.DRIVE:
                drive_preview.setText(text)
            else:
                nas_preview.setText(text)
            refresh_result(target)

        self._subscribe(self.controller.previewChanged, on_preview)

        def refresh_notice(*_args):
            for item in (self.controller.DRIVE, self.controller.WEBDAV):
                refresh_result(item)
            target = self.controller.DRIVE if self.ui.stack.currentIndex() == 0 else self.controller.WEBDAV
            notice = self.controller.notice_for(target)
            if not notice:
                self.ui.notice.clear()
                self.ui.notice.hide()
                return
            title, text, kind = notice
            self.ui.notice.setText(f"{title}\n{text}")
            self.ui.notice.setProperty("state", kind)
            self.ui.notice.style().unpolish(self.ui.notice)
            self.ui.notice.style().polish(self.ui.notice)
            self.ui.notice.show()

        self._subscribe(self.controller.message, refresh_notice)
        self.ui.targetChanged.connect(refresh_notice)

        def answer_existing(title, callback):
            self.controller.answer_question(choose_existing(title))

        self._subscribe(self.controller.askExistingRemote, answer_existing)
        for target, connected, empty in (
            (self.controller.DRIVE, self.controller.drive_connected, "尚未关联云端硬盘"),
            (self.controller.WEBDAV, self.controller.webdav_connected, "尚未关联 WebDAV"),
        ):
            on_preview(target, self.controller.previews.get(target, "点击同步或重新检测" if connected else empty))
        refresh_notice()
        if isinstance(self.controller.pending_question, tuple):
            QTimer.singleShot(0, self, lambda: answer_existing(*self.controller.pending_question) if self.controller.pending_question else None)

        # ---- 视图动作 -> 控制器 ----
        drive_sync_btn.clicked.connect(lambda: self.controller.drive_path and self.controller.sync_drive(self.controller.drive_path, associated=False))
        drive_overwrite_action.triggered.connect(
            lambda: (
                self.controller.drive_path
                and widgets.confirm(
                    dlg,
                    "确认上传覆盖",
                    "将使用当前本地保险库完整覆盖云端文件，云端独有或更新较新的内容将丢失。是否继续？",
                    kind="warn",
                )
                and self.controller.overwrite_drive(self.controller.drive_path, associated=False)
            )
        )
        drive_download_action.triggered.connect(
            lambda: self.controller.drive_path and confirm_download_overwrite("云端硬盘") and self.controller.download_drive(self.controller.drive_path)
        )

        def associate_drive() -> None:
            initial = str(self.controller.drive_path.parent if self.controller.drive_path else Path.home())
            account_name = _safe_filename_part(config.get_current_user() or vault.path.stem)[:80]
            selected = QFileDialog.getExistingDirectory(
                dlg,
                i18n.tr("选择云端硬盘同步目录"),
                initial,
                options=_FILE_OPTS,
            )
            if not selected:
                return
            directory = Path(selected)
            expected_name = f"{account_name}.pmv"
            try:
                pmv_files = sorted(directory.glob("*.pmv"), key=lambda item: item.name.lower())
            except OSError as exc:
                widgets.message(dlg, "关联失败", f"无法读取所选目录：{exc}", kind="error")
                return
            exact = [item for item in pmv_files if item.name.lower() == expected_name.lower()]
            if len(exact) == 1:
                target = exact[0]
            elif len(pmv_files) == 1:
                target = pmv_files[0]
            elif pmv_files:
                chosen, _ = QFileDialog.getOpenFileName(
                    dlg,
                    i18n.tr("目录中有多个保险库文件，请选择目标"),
                    str(directory),
                    i18n.tr("保险库文件(*.pmv)"),
                    options=_FILE_OPTS,
                )
                if not chosen:
                    return
                target = Path(chosen)
                try:
                    target.resolve().relative_to(directory.resolve())
                except ValueError:
                    widgets.message(dlg, "关联失败", "目标文件必须位于所选云端目录中", kind="error")
                    return
            else:
                target = directory / expected_name
                if not widgets.confirm(
                    dlg,
                    "创建云端保险库文件",
                    f"目录中没有发现 .pmv 文件。是否创建 {expected_name}？",
                    kind="warn",
                ):
                    return
            self.controller.associate_drive(target)

        def request_drive_association() -> None:
            if self.controller.drive_connected and not _confirm_master_password(
                self._window.vault,
                "重新关联云端硬盘",
                "重新关联云端硬盘需要验证当前主密码。",
                dlg,
                session_required=True,
            ):
                return
            associate_drive()

        drive_relate_btn.clicked.connect(request_drive_association)
        drive_relate_action.triggered.connect(request_drive_association)

        def clear_drive() -> None:
            if not _confirm_master_password(
                self._window.vault,
                "取消云端硬盘关联",
                "取消云端硬盘关联需要验证当前主密码。",
                dlg,
                session_required=True,
            ):
                return
            if not widgets.confirm(
                dlg,
                "确认取消关联",
                "将清除本机保存的云端硬盘关联，但不会删除云端文件。是否继续？",
                kind="warn",
            ):
                return
            self.controller.clear_drive()

        drive_clear_action.triggered.connect(clear_drive)

        nas_sync_btn.clicked.connect(lambda: self.controller.webdav_config and self.controller.sync_webdav(self.controller.webdav_config, associated=False))
        nas_overwrite_action.triggered.connect(
            lambda: (
                self.controller.webdav_config
                and widgets.confirm(
                    dlg,
                    "确认上传覆盖",
                    "将使用当前本地保险库完整覆盖远端文件，远端独有或更新较新的内容将丢失。是否继续？",
                    kind="warn",
                )
                and self.controller.overwrite_webdav(self.controller.webdav_config, associated=False)
            )
        )
        nas_download_action.triggered.connect(
            lambda: self.controller.webdav_config and confirm_download_overwrite("WebDAV") and self.controller.download_webdav(self.controller.webdav_config)
        )

        def associate_webdav() -> None:
            try:
                candidate = current_webdav()
                if not candidate.file_url.strip():
                    raise cloud.CloudError("请输入远端目录地址")
                account_name = config.get_current_user() or vault.path.stem
                candidate = cloud.config_for_directory(candidate, account_name)
            except Exception as exc:  # noqa: BLE001
                widgets.message(dlg, "配置无效", str(exc), kind="error")
                return
            self.controller.associate_webdav(candidate)

        def request_nas_association() -> None:
            if self.controller.webdav_connected and not _confirm_master_password(
                self._window.vault,
                "重新关联 WebDAV",
                "重新关联 WebDAV 需要验证当前主密码。",
                dlg,
                session_required=True,
            ):
                return
            associate_webdav()

        nas_relate_btn.clicked.connect(request_nas_association)
        nas_relate_action.triggered.connect(request_nas_association)

        def clear_nas() -> None:
            if not _confirm_master_password(
                self._window.vault,
                "取消 WebDAV 关联",
                "取消 WebDAV 关联需要验证当前主密码。",
                dlg,
                session_required=True,
            ):
                return
            if not widgets.confirm(
                dlg,
                "确认取消关联",
                "将清除本机保存的服务器地址和认证凭据，但不会删除远端文件。是否继续？",
                kind="warn",
            ):
                return
            self.controller.clear_webdav()
            password.clear()

        nas_clear_action.triggered.connect(clear_nas)
        drive_check_btn.clicked.connect(self.controller.inspect_drive)
        nas_check_btn.clicked.connect(self.controller.inspect_webdav)

        # ---- 总开关（对齐安卓：默认关闭，开启需主密码门禁与风险确认） ----
        master = self.ui.master_toggle

        def cloud_master_enabled() -> bool:
            fn = getattr(self._window, "cloud_sync_enabled", None)
            return bool(fn()) if callable(fn) else True

        def apply_master() -> None:
            enabled = cloud_master_enabled()
            master.blockSignals(True)
            master.setChecked(enabled)
            master.blockSignals(False)
            self.ui.content.setVisible(enabled)

        def on_master_toggled(checked: bool) -> None:
            setter = getattr(self._window, "set_cloud_sync_enabled", None)
            if not checked:
                if callable(setter):
                    setter(False)
                apply_master()
                return
            verified = _confirm_master_password(
                self._window.vault,
                "启用联网同步",
                "启用联网同步需要验证当前主密码。",
                dlg,
                session_required=True,
            )
            acknowledged = verified and widgets.confirm(
                dlg,
                "确认启用联网同步",
                "云端仅接收加密后的保险库文件，但数据安全仍依赖主密码强度、云端账户和设备安全。\n\n"
                "默认同步会先拉取并合并；“上传覆盖”会直接替换远端文件，可能丢失远端独有修改。\n\n"
                "请确认已了解这些密码数据安全与覆盖风险。",
                kind="warn",
            )
            if not acknowledged:
                apply_master()
                return
            if callable(setter):
                setter(True)
            apply_master()

        master.toggled.connect(on_master_toggled)
        apply_master()

        refresh_controls()

        # 窗口只在首次显示前计算一次尺寸。检测状态和目标切换不再反复
        # invalidate/resize，避免后台检测期间切页卡顿。


class LocalBackupPage(EditorPage):
    """本地备份：启用开关、目录选择、周期滑条与立即备份。"""

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self._window = window
        self.setObjectName("LocalBackupPage")

        shell = page_shell(self, i18n.tr("本地备份"), compact=True)
        self.page_header = shell.header
        self.page_header.set_subtitle(i18n.tr("定期把保险库文件备份到本机目录或外接U盘/硬盘（仅覆盖，不同步）；目录不可用或设备未连接时自动等待，不报错。"))
        body = shell.content
        self.body = body

        self.backup_enabled = QCheckBox(i18n.tr("启用本地备份"))
        self.backup_enabled.setChecked(bool(config.get("backup_enabled", False)))
        body.addWidget(self.backup_enabled)

        self._backup_dir_btn = QPushButton(i18n.tr("选择备份目录"))
        self._backup_dir_btn.setObjectName("SettingsBtn")
        self._backup_dir_btn.clicked.connect(self._choose_backup_dir)
        body.addWidget(self._backup_dir_btn)

        self._backup_status = QLabel(i18n.tr("未选择备份目录"))
        self._backup_status.setWordWrap(True)
        self._backup_status.setStyleSheet("color: #2563EB; font-size: 12px;")
        body.addWidget(self._backup_status)

        self._backup_now_btn = QPushButton(i18n.tr("立即备份"))
        self._backup_now_btn.setObjectName("SettingsBtn")
        if hasattr(window, "_backup_now"):
            self._backup_now_btn.clicked.connect(window._backup_now)
        self.page_header.add_action(self._backup_now_btn)

        self._backup_slider = _NoScrollSlider(Qt.Horizontal)
        self._backup_slider.setRange(0, 4)
        current_interval = config.get("backup_interval", "daily") or "daily"
        self._backup_slider.setValue(local_backup.ORDER.index(current_interval) if current_interval in local_backup.ORDER else 2)
        self._backup_slider.valueChanged.connect(self._on_backup_interval_changed)
        body.addWidget(self._backup_slider)

        self._backup_interval_label = QLabel()
        self._backup_interval_label.setObjectName("SettingNote")
        body.addWidget(self._backup_interval_label)
        self._update_backup_interval_label(self._backup_slider.value())

        self._refresh_backup_controls()
        self.backup_enabled.toggled.connect(self._on_backup_enabled_toggled)

        if hasattr(window, "_backup_status_label"):
            window._backup_status_label = self._backup_status
            window._set_backup_status(
                window._backup_status_text or (i18n.tr("等待设备状态") if bool(config.get("backup_dir", "")) else i18n.tr("未选择备份目录"))
            )

    def refresh(self, context: object) -> None:
        self._refresh_backup_controls()

    def close_page(self, reason: str) -> None:
        # 页面即将 deleteLater，先摘掉主窗口持有的状态标签引用。
        if getattr(self._window, "_backup_status_label", None) is self._backup_status:
            self._window._backup_status_label = None

    def _choose_backup_dir(self) -> None:
        import json

        directory = QFileDialog.getExistingDirectory(self, i18n.tr("选择备份目录"))
        if not directory:
            return
        fingerprint = local_backup.device_fingerprint(directory)
        access_id = local_backup.storage_access_id(directory)
        if fingerprint is None or not access_id:
            self._backup_status.setText(i18n.tr("无法识别稳定的设备身份，已拒绝备份"))
            return
        state, marker, _ = local_backup.binding_state_for_directory(
            directory,
            config.get("backup_device_uuid", "") or "",
            config.get("backup_access_id", "") or "",
        )
        if marker.state is local_backup.MarkerState.INVALID:
            self._backup_status.setText(i18n.tr("身份异常，已禁止自动同步"))
            return
        prompt = (
            "检测到设备目录授权发生变化。确认这是原设备，并允许此存储设备用于同步？"
            if state is local_backup.BindingState.SUSPECTED_ORIGINAL
            else "设备 UUID 与已保存绑定不一致，自动同步已被阻止。确认重新绑定此设备？"
            if state is local_backup.BindingState.IDENTITY_ANOMALY
            else "FAEVault 将在所选目录保存设备 UUID，并绑定本次目录授权。允许此存储设备用于同步？"
        )
        if not widgets.confirm(
            self,
            i18n.tr("允许此存储设备用于同步"),
            i18n.tr(prompt),
            kind="warn",
        ):
            return
        if marker.state is local_backup.MarkerState.MISSING:
            marker = local_backup.create_device_marker(directory)
        if marker.state is not local_backup.MarkerState.VALID:
            self._backup_status.setText(i18n.tr("设备 UUID 标记创建失败，已拒绝备份"))
            return
        config.set("backup_dir", directory)
        config.set("backup_device_uuid", marker.device_uuid)
        config.set("backup_access_id", access_id)
        config.set("backup_volume_id", fingerprint.identity_key())
        config.set("backup_device", json.dumps(fingerprint.to_dict()) if fingerprint else "")
        self._refresh_backup_controls()
        if fingerprint.identity_key():
            capacity = fingerprint.capacity_bytes
            capacity_text = (
                f"{capacity / (1024**4):.1f} TB"
                if capacity >= 1024**4
                else f"{capacity / (1024**3):.1f} GB"
                if capacity >= 1024**3
                else f"{capacity / (1024**2):.0f} MB"
            )
            # 卷名可能来自系统（中文卷标），兜底「备份设备」也是裸中文，都要过翻译；
            # 括号随语言切换，否则英文行里会夹着两个全角括号。
            name = i18n.tr(fingerprint.display_name())
            open_paren, close_paren = ("(", ")") if i18n.current_locale().startswith("en") else ("（", "）")
            self._backup_status.setText(
                i18n.tr("备份设备：")
                + f"{name}{open_paren}{fingerprint.display_id()}{close_paren}"
                + (" · " + i18n.tr(fingerprint.model) if fingerprint.model else "")
                + (f" · {capacity_text}" if capacity else "")
            )
        else:
            self._backup_status.setText(i18n.tr("无法识别稳定的设备身份，已拒绝备份"))
        if hasattr(self._window, "_maybe_local_backup"):
            self._window._maybe_local_backup(force=True)

    def _refresh_backup_controls(self) -> None:
        """未启用本地备份时，隐藏并禁用其余备份控件，避免误操作。"""
        enabled = self.backup_enabled.isChecked()
        has_dir = bool(config.get("backup_dir", ""))
        for widget in (
            self._backup_dir_btn,
            self._backup_status,
            self._backup_slider,
            self._backup_interval_label,
            self._backup_now_btn,
        ):
            widget.setVisible(enabled)
            widget.setEnabled(enabled and (has_dir or widget in (self._backup_dir_btn, self._backup_status)))

    def _on_backup_interval_changed(self, value: int) -> None:
        config.set("backup_interval", local_backup.ORDER[value])
        self._update_backup_interval_label(value)

    def _update_backup_interval_label(self, value: int) -> None:
        key = local_backup.ORDER[value]
        self._backup_interval_label.setText(i18n.tr(f"同步周期：{local_backup.LABELS[key]}"))

    def _on_backup_enabled_toggled(self, checked: bool) -> None:
        config.set("backup_enabled", checked)
        self._refresh_backup_controls()
        if checked and hasattr(self._window, "_maybe_local_backup"):
            self._window._maybe_local_backup(force=True)


@dataclass(slots=True)
class LanPageContext:
    """Dependencies an embedded LAN page needs from the main window."""

    vault: object
    copy_secret: Callable[[str], None]
    set_auto_lock_blocker: Callable[[str, bool], None]
    window: object | None = None


class KeyValueCard(QFrame):
    """标题 + 键值行卡片；值可以是文本，也可以内嵌自定义控件（如进度条）。"""

    LABELS = {
        "device_id": "设备 ID",
        "fingerprint": "密钥指纹",
        "cert_fingerprint": "证书指纹",
        "client_ip": "地址",
        "station_url": "传输站地址",
        "operation": "通道",
        "duration": "连接时长",
        "phase": "状态",
        "volume": "已用 / 共",
        "progress": "进度",
        "lineage": "谱系",
        "counts": "条目",
        "push": "回推",
        "verify": "校验",
    }

    def __init__(self, title: str, keys: tuple[str, ...], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SettingGroupBox")
        outer = QVBoxLayout(self)
        self._outer = outer
        outer.setContentsMargins(14, 10, 14, 12)
        outer.setSpacing(6)
        head = QLabel(title)
        head.setObjectName("FieldLabel")
        outer.addWidget(head)
        self.values: dict[str, QWidget] = {}
        for key in keys:
            row = QHBoxLayout()
            row.setSpacing(10)
            name = QLabel(i18n.tr(self.LABELS[key]))
            name.setObjectName("SettingNote")
            name.setFixedWidth(76)
            value = QLabel("—")
            value.setObjectName("SettingNote")
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            value.setWordWrap(True)
            row.addWidget(name)
            row.addWidget(value, 1)
            outer.addLayout(row)
            self.values[key] = value

    def set(self, key: str, text: str) -> None:
        widget = self.values.get(key)
        if widget is not None:
            widget.setText(text or "—")

    def add_full_width(self, widget: QWidget) -> None:
        """在所有键值行下方挂一个整宽控件（进度条等）。

        不要把某一行的值标签换成控件：那一行是「标题 + 值」的布局，换完标签会
        脱离原来的行，标题漂到卡片中间、控件跑到卡片底部。
        """
        self._outer.addWidget(widget)

    @staticmethod
    def peer_keys() -> tuple[str, ...]:
        return ("device_id", "fingerprint", "client_ip")

    @staticmethod
    def fill_peer(card: "KeyValueCard", info: dict | None) -> None:
        """按 peer_info 填「对方设备」卡；info 为 None 时不动。"""
        if not info:
            return
        card.set("device_id", str(info.get("device_id") or "—"))
        card.set("fingerprint", str(info.get("fingerprint") or "—"))
        card.set("client_ip", str(info.get("client_ip") or "—"))


class _SyncSessionView(QWidget):
    """同步页的会话视图：设备信息 + 同步状态（+ 结果），底部一个随阶段改名的按钮。

    连接方（我连别人）拿不到对方的 device_id 与设备公钥指纹，只显示同步状态卡，
    不硬凑一张设备信息卡出来。
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SyncSessionView")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)

        self.device_card = KeyValueCard(i18n.tr("设备信息"), KeyValueCard.peer_keys())
        self.state_card = KeyValueCard(i18n.tr("同步状态"), ("phase", "volume", "duration"))
        self.result_card = KeyValueCard(i18n.tr("同步结果"), ("lineage", "counts", "push", "verify"))

        self._progress = QProgressBar()
        self._progress.setTextVisible(True)
        self.state_card.add_full_width(self._progress)

        self._device_slot = QWidget()
        device_lay = QVBoxLayout(self._device_slot)
        device_lay.setContentsMargins(0, 0, 0, 0)
        device_lay.setSpacing(10)
        device_lay.addWidget(self.device_card)
        outer.addWidget(self._device_slot)

        outer.addWidget(self.state_card)
        outer.addWidget(self.result_card)

        self.action_row = QWidget()
        action_lay = QHBoxLayout(self.action_row)
        action_lay.setContentsMargins(0, 0, 0, 0)
        self.action_btn = QPushButton(i18n.tr("断开连接"))
        self.action_btn.setObjectName("Danger")
        self.action_btn.setMinimumHeight(40)
        self.action_btn.setMaximumWidth(ACTION_BUTTON_WIDTH)
        self.action_btn.setCursor(Qt.PointingHandCursor)
        action_lay.addStretch(1)
        action_lay.addWidget(self.action_btn)
        action_lay.addStretch(1)
        outer.addStretch(1)
        outer.addWidget(self.action_row)

        self.result_card.setVisible(False)

    # ---------- 展示 ----------

    def set_device(self, info: dict | None) -> None:
        """连接方拿不到设备身份，此时整张设备信息卡不出现。"""
        has_identity = bool(info and info.get("device_id"))
        self._device_slot.setVisible(has_identity)
        if has_identity:
            KeyValueCard.fill_peer(self.device_card, info)

    def set_phase(self, text: str, *, finished: bool = False) -> None:
        self.state_card.set("phase", text)
        self.action_btn.setText(i18n.tr("关闭页面") if finished else i18n.tr("断开连接"))

    def set_progress(self, transferred: int, total: int | None) -> None:
        if total:
            self._progress.setRange(0, 100)
            self._progress.setValue(min(100, int(transferred * 100 / total)))
            self._progress.setFormat(f"{self._progress.value()}%")
        else:
            self._progress.setRange(0, 0)
            self._progress.setFormat("")
        self.state_card.set("volume", _format_volume(transferred, total))

    def set_duration(self, seconds: float) -> None:
        self.state_card.set("duration", _format_duration(seconds))

    def show_result(self, rows: list[tuple[str, str]]) -> None:
        values = dict(rows)
        self.result_card.set("lineage", values.get("谱系", "—"))
        self.result_card.set("counts", values.get("条目", "—"))
        self.result_card.set("push", values.get("回推", "—"))
        self.result_card.set("verify", values.get("校验", "—"))
        self.result_card.setVisible(True)


def _format_volume(transferred: int, total: int | None) -> str:
    left = _format_bytes(transferred)
    return f"{left} / {_format_bytes(total)}" if total else left


def _format_bytes(value: int | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


class _StationPeerCards(QWidget):
    """传输站被接入后的两张信息卡：对方设备 + 本次连接。

    只显示身份与连接状态，不显示进度——进度在各自的挡位上已经有一份，
    这里再放一份只会让人怀疑两处数字对不上。
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("StationPeerCards")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(10)
        self.device_card = KeyValueCard(i18n.tr("对方设备"), KeyValueCard.peer_keys())
        self.session_card = KeyValueCard(i18n.tr("本次连接"), ("operation", "duration"))
        outer.addWidget(self.device_card)
        outer.addWidget(self.session_card)

    def update_peer(self, info: dict | None) -> None:
        """按 peer_info 刷新两张卡；info 为 None 时整体隐藏。"""
        if not info:
            self.setVisible(False)
            return
        self.setVisible(True)
        KeyValueCard.fill_peer(self.device_card, info)
        op = str(info.get("operation") or "")
        self.session_card.set("operation", i18n.tr("文件传输") if op == "transfer" else i18n.tr("局域网同步"))
        started = float(info.get("authenticated_at") or 0.0)
        # authenticated_at 是 time.time()（墙钟），不能拿 monotonic 去减。
        self.session_card.set("duration", _format_duration(time.time() - started) if started else "—")


#: 超过一周就当成时钟错位（两端墙钟被调整过），不显示时长而不是显示荒谬数字。
_MAX_PLAUSIBLE_DURATION = 7 * 24 * 3600


def _format_duration(seconds: float) -> str:
    """连接时长：超过一小时才带小时位，避免「00:12」和「1:02:03」两种格式混排。"""
    total = int(seconds)
    if total < 0 or total > _MAX_PLAUSIBLE_DURATION:
        return "—"
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


class LanStationPage(EditorPage):
    """建立传输站：二维码/PIN + 局域网同步/文件传输共用页面（主机角色）。"""

    #: 被其他设备连上时上报对方使用的通道（``sync`` / ``transfer``），
    #: 供三档滑块自动切到对应档位（对齐安卓端）。
    channel_changed = Signal(str)

    def __init__(self, context: LanPageContext, parent=None):
        super().__init__(parent)
        self.context = context
        self._window = context.window
        self.server = None
        self._channel = ""
        self._sync_started_at: float | None = None
        self._session_widgets: list[QWidget] = []
        self.poll_timer = QTimer(self)
        self.setObjectName("LanStationPage")
        # start_station 会持续往内容区追加控件，头部固定在根布局上。
        # 建立传输站会持续往内容区追加控件，页头保持固定。这里不用 compact：
        # compact 会在内容区之后补一段拉伸，把「钉在底部」的按钮顶回上方。
        shell = page_shell(self, i18n.tr("建立传输站"))
        self.page_header = shell.header
        self.body = shell.content

        # 页面结构：状态行 → 说明/二维码/会话控件（可增长）→ 底部按钮槽。
        # 会话控件由 start_station 逐个追加，所以先给它们一个容器，按钮槽才能稳定
        # 待在最底部，不会被追加的控件挤到中间。
        self.content_area = QWidget()
        self._content_lay = QVBoxLayout(self.content_area)
        self._content_lay.setContentsMargins(0, 0, 0, 0)
        self._content_lay.setSpacing(0)
        # 顶对齐：否则多余高度会被这些控件瓜分，说明文字被推到页面中间。
        self._content_lay.setAlignment(Qt.AlignTop)

        # 传输站连接状态：被对端连接后，同步状态面板、传输面板与批准弹窗都会挂到
        # 对应挡位（见 LanWorkspacePage._on_station_channel），本页就只剩「连接状态 +
        # 关闭传输站」。所以状态必须有自己常驻的标签，不能借用会被移走的 sync_panel。
        self.host_status = QLabel(i18n.tr("未开启"))
        self.host_status.setObjectName("SettingNote")
        self.host_status.setWordWrap(True)
        self._content_lay.addWidget(self.host_status)

        # 未开站时的说明：原先由菜单项直接调用 start_station，菜单收敛成单个「局域网」
        # 后，必须由页面自己给出可点击的入口，否则该档位是空面板。
        self.intro = QWidget()
        intro_lay = QVBoxLayout(self.intro)
        intro_lay.setContentsMargins(0, 0, 0, 0)
        intro_lay.setSpacing(8)
        intro_hint = QLabel(i18n.tr("开启后本机将在局域网开放连接，其他设备扫码或输入地址与 PIN 后，按对方的连接类型执行同步或文件互传。"))
        intro_hint.setObjectName("SettingNote")
        intro_hint.setWordWrap(True)
        intro_lay.addWidget(intro_hint)
        self._content_lay.addWidget(self.intro)

        # 已接入时的两张信息卡。传输站页面这时不再显示二维码/地址/提示，
        # 改由这里承载「对方是谁」和「这次连接怎么样」。
        self.peer_cards = _StationPeerCards()
        self._content_lay.addWidget(self.peer_cards)
        self.peer_cards.setVisible(False)

        self.body.addWidget(self.content_area, 1)

        # 底部共用按钮槽：「建立传输站」与「关闭传输站」互斥，永不同时出现。
        # 本页只管传输站自己的生死——断开对端会话的出口在同步/传输挡位上。
        # 两者并排夹在两段拉伸之间，任何一个可见时都是居中的；限宽避免铺满整行
        # 看起来像横幅而不像按钮。
        self.action_row = QWidget()
        action_lay = QHBoxLayout(self.action_row)
        action_lay.setContentsMargins(0, 0, 0, 0)
        self.start_btn = QPushButton(i18n.tr("建立传输站"))
        self.start_btn.setObjectName("Primary")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.setMaximumWidth(ACTION_BUTTON_WIDTH)
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setAccessibleName(i18n.tr("建立传输站"))
        self.start_btn.clicked.connect(self.start_station)
        self.stop_btn = QPushButton(i18n.tr("关闭传输站"))
        self.stop_btn.setObjectName("Danger")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setMaximumWidth(ACTION_BUTTON_WIDTH)
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setAccessibleName(i18n.tr("关闭传输站"))
        self.stop_btn.clicked.connect(self._stop_station)
        self.stop_btn.setVisible(False)
        action_lay.addStretch(1)
        action_lay.addWidget(self.start_btn)
        action_lay.addWidget(self.stop_btn)
        action_lay.addStretch(1)
        self.body.addWidget(self.action_row)

    def set_workspace(self, workspace) -> None:
        """记录所属的 LanWorkspacePage，用于被对端连接时跳转挡位、断开时改状态。"""
        self._workspace_page = workspace

    def _workspace(self):
        return getattr(self, "_workspace_page", None)

    def set_host_status(self, text: str) -> None:
        """更新传输站连接状态（被对端连接 / 已断开）。"""
        self.host_status.setText(text)
        self.host_status.setVisible(bool(text))

    def attach_host_panels(self, target, panel_names, *, hide_entry: bool = True) -> None:
        """把指定的主机侧会话面板挂到 target（本机被对端连接时使用）。

        挂走后本页只保留连接状态与「关闭传输站」，二维码/地址/提示也一并隐藏
        ——已经连上设备了，再给扫码入口只会让人以为还能再连一台。

        hide_entry=False 用于会话已经结束的场合：那时收尾刚把「建立传输站」入口
        放回来，不能因为挂结果面板又把它收掉，否则用户只剩一个「已断开」，
        既不能重新开站、也看不到发生了什么。
        """
        self.release_host_panels()
        panels = getattr(self, "_session_panels", None) or {}
        for name in panel_names:
            panel = panels.get(name)
            if panel is None:
                continue
            old_parent = panel.parentWidget()
            if old_parent is not None and old_parent.layout() is not None:
                old_parent.layout().removeWidget(panel)
            panel.setParent(target.host_attach)
            target.host_attach.layout().addWidget(panel)
            # 导出批准块由 refresh_export_approval() 自行决定显隐（没有待批准请求时
            # 必须藏着），搬过来时不能无条件显示，否则同步挡位会凭空多出一块
            # 「允许本次发送 / 不是我，断开」。
            if name != "export":
                panel.setVisible(True)
        self._host_targets = [target]
        for label in getattr(self, "_pairing_labels", ()):
            label.setVisible(False)
        if hide_entry:
            self.intro.setVisible(False)

    def release_host_panels(self) -> None:
        """把面板收回本页并隐藏，下次 start_station 仍按原样挂载。"""
        for target in getattr(self, "_host_targets", ()):
            layout = target.host_attach.layout()
            while layout.count():
                widget = layout.takeAt(0).widget()
                if widget is not None:
                    self._content_lay.addWidget(widget)
                    widget.setVisible(False)
        self._host_targets = ()

    def _restore_station_entry(self) -> None:
        """露出「建立传输站」入口：可见且可点。

        该按钮此前只靠父容器 intro 的可见性控制，全仓库从未 setEnabled 显式禁用。
        intro 一旦可见按钮就能点——包括刚 stop()、端口尚在释放的窗口期，会撞上端口
        占用。这里把「可见」和「可点」绑定到停服完成之后。
        """
        self.intro.setVisible(True)
        self.start_btn.setVisible(True)
        self.start_btn.setEnabled(True)
        self.stop_btn.setVisible(False)
        # 轮询已停，peer_cards 不会再被刷新，这里显式收起。
        self.peer_cards.setVisible(False)
        self.set_host_status(i18n.tr("未开启"))

    def _refresh_host_sync_view(self, server) -> None:
        """把传输站的同步进度投到同步页的会话视图（主机角色：别人连我）。"""
        workspace = self._workspace()
        if workspace is None:
            return
        view = workspace.sync_page.sync_view
        if not workspace.sync_page._host_mode:
            view.setVisible(False)
            return
        view.setVisible(True)
        view.set_device(getattr(server, "peer_info", None))

        phase = str(getattr(server, "sync_phase", "idle") or "idle")
        received = getattr(server, "sync_receive_progress", None)
        sent = getattr(server, "sync_send_progress", None)
        progress = received or sent
        transferred, total = progress if progress else (0, 0)
        texts = {
            "verifying": i18n.tr("正在检查两端数据…"),
            "receiving": i18n.tr("正在接收对方设备的数据…"),
            "sending": i18n.tr("正在把本机保险库发送到对方设备…"),
            "done": i18n.tr("同步已完成"),
            "failed": i18n.tr("同步未完成"),
            "idle": i18n.tr("已连接，等待同步…"),
        }
        finished = phase in ("done", "failed")
        view.set_phase(texts.get(phase, phase), finished=finished)
        view.set_progress(int(transferred or 0), int(total or 0) or None)
        started = self._sync_started_at
        if started is None and getattr(server, "_server", None) is not None:
            started = getattr(server._server, "authenticated_at", None)
            self._sync_started_at = started
        view.set_duration(time.time() - started if started else 0)

    def _stop_station(self) -> None:
        """关闭传输站：停服并回到可再次建立的初始状态。

        这里只隐藏会话控件、不销毁：停服瞬间可能还有排队中的单次回调引用它们；
        真正的回收放在下一次 start_station（它前面的确认弹窗已把事件队列抽干）。
        """
        if self.server is None:
            return
        if not self.can_close("user"):
            return
        self.poll_timer.stop()
        self.server.stop()
        self.server = None
        self._channel = ""
        if self._window is not None:
            self.context.set_auto_lock_blocker("lan-sync", False)
            self._window._flash(i18n.tr("传输站已关闭"))
        for widget in self._session_widgets:
            widget.setVisible(False)
        self._restore_station_entry()
        workspace = self._workspace()
        if workspace is not None:
            workspace._on_station_closed()

    def _add_session_widget(self, widget: QWidget) -> QWidget:
        """记录本次会话创建的控件：重新建立时整体回收。"""
        self._session_widgets.append(widget)
        self._content_lay.addWidget(widget)
        return widget

    def _clear_session_widgets(self) -> None:
        for widget in self._session_widgets:
            self._content_lay.removeWidget(widget)
            widget.setParent(None)
            widget.deleteLater()
        self._session_widgets.clear()

    def start_station(self) -> None:
        import io as _io

        import qrcode

        from core.sync_server import SyncServer

        if not widgets.confirm(
            self,
            i18n.tr("建立传输站"),
            i18n.tr("开启后，本机保险库会在 3 分钟内允许同局域网设备凭二维码和 PIN 同步数据或互传文件。\n\n确定要建立传输站吗？"),
        ):
            return

        # 重新建立时先清掉上一次会话的二维码与面板。
        self._clear_session_widgets()

        server = SyncServer(
            self.context.vault,
            lambda incoming_device_id: sync.same_lineage(self.context.vault.device_id, incoming_device_id),
        )
        server.device_auth_enabled = True
        # 与安卓一致：PC 作为主机时，未授权设备同步前需用户确认。
        server.sync_approval_enabled = True
        try:
            url, pin = server.start()
        except OSError as error:
            widgets.message(
                self,
                i18n.tr("无法启动传输站"),
                i18n.tr("端口 18765 已被占用，请先关闭占用该端口的程序后重试。") + (f"\n（{error}）" if str(error) else ""),
                kind="error",
            )
            return
        from urllib.parse import urlparse as _urlparse

        _parsed = _urlparse(url)
        _log.info("HTTPS 同步服务器启动 %s://%s:%s", _parsed.scheme, _parsed.hostname, _parsed.port)
        # 未开站 -> 已开站：说明文字收起，按钮换成「关闭传输站」
        self.intro.setVisible(False)
        self.start_btn.setVisible(False)
        self.stop_btn.setVisible(True)
        self.set_host_status(i18n.tr("等待设备接入"))

        lbl_img = QLabel()
        lbl_img.setAlignment(Qt.AlignCenter)
        self._add_session_widget(lbl_img)

        lbl_url = QLabel()
        lbl_url.setAlignment(Qt.AlignCenter)
        lbl_url.setWordWrap(True)
        lbl_url.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        lbl_url.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        lbl_url.setStyleSheet("color: #6B7280; font-size: 13px;")
        self._add_session_widget(lbl_url)

        last_pairing_url = None
        last_channel = ""

        def render_pairing_chrome() -> None:
            """按 server 当前的 pairing_url/pin 重建二维码与 PIN 显示（随周期轮换刷新）。"""
            nonlocal last_pairing_url
            current_url = server.pairing_url or url
            if current_url == last_pairing_url:
                return
            last_pairing_url = current_url
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
            qr.add_data(current_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = _io.BytesIO()
            img.save(buf, format="PNG")
            px = QPixmap()
            px.loadFromData(buf.getvalue())
            lbl_img.setPixmap(px)
            lbl_url.setText(f"服务器地址：\n{current_url}")
            QTimer.singleShot(0, fit_transfer_dialog)

        lbl_hint = QLabel(
            i18n.tr(
                "请用手机扫描二维码即可连接（无需输入 PIN）\n"
                "手机和电脑必须连接同一局域网，跨网络或移动数据无法连接\n"
                "连接码与二维码每 2 分钟自动刷新；等待连接 3 分钟；连接后处理期间自动续期"
            )
        )
        lbl_hint.setAlignment(Qt.AlignCenter)
        lbl_hint.setStyleSheet("color: gray;")
        self._add_session_widget(lbl_hint)

        # 供挡位跳转取用：被对端连接后要把这些面板挂到同步/文件传输挡位。
        self._pairing_labels = (lbl_img, lbl_url, lbl_hint)
        self._host_targets = ()
        self._session_panels: dict[str, QWidget | None] = {}

        # 局域网同步页（与连接方复用同一组件）
        sync_panel = LanSyncStatusPanel()
        self._add_session_widget(sync_panel)
        self._session_panels["sync"] = sync_panel

        # 文件传输页（与连接方复用同一组件）；有互传活动时自动显示
        transfer_panel = LanTransferPanel()
        transfer_panel.setVisible(False)
        transfer_panel.set_on_copy(lambda value: self.context.copy_secret(value))
        self._add_session_widget(transfer_panel)
        self._session_panels["transfer"] = transfer_panel

        # 导出批准（整库导出）：客户端以导出通道连接时在此确认/拒绝
        export_approval = QWidget()
        export_lay = QVBoxLayout(export_approval)
        export_lay.setContentsMargins(0, 0, 0, 0)
        export_lay.setSpacing(6)
        export_hint = QLabel(
            i18n.tr("另一台设备正在请求接收当前账户的完整数据，包括密码、验证码和附件。请确认这是你本人发起的连接。本次允许会在传输完成后自动失效。")
        )
        export_hint.setWordWrap(True)
        export_hint.setStyleSheet("color: #2563EB; font-size: 13px;")
        export_lay.addWidget(export_hint)
        export_btns = QHBoxLayout()
        allow_export_btn = QPushButton(i18n.tr("允许本次发送"))
        allow_export_btn.setObjectName("Primary")
        reject_export_btn = QPushButton(i18n.tr("不是我，断开"))
        reject_export_btn.setObjectName("Ghost")
        export_btns.addWidget(allow_export_btn)
        export_btns.addWidget(reject_export_btn)
        export_lay.addLayout(export_btns)
        export_approval.setVisible(False)
        self._add_session_widget(export_approval)
        self._session_panels["export"] = export_approval

        # 「结束传输」/「断开连接」是常驻控件，建在 __init__，这里不重复创建。

        export_prompted = {"v": False}
        sync_prompted = {"v": False}
        transfer_prompted = {"v": False}

        def refresh_export_approval() -> None:
            pending = getattr(server._server, "pending_export_device", None)
            export_approval.setVisible(pending is not None)
            if pending is None:
                export_prompted["v"] = False
                return
            if not export_prompted["v"]:
                export_prompted["v"] = True
                session_token, device_id, public_key = pending
                fingerprint = hashlib.sha256(public_key).hexdigest()[:24]
                if widgets.confirm(
                    self,
                    i18n.tr("允许发送账户数据？"),
                    i18n.tr(
                        f"请求设备：{device_id}\n密钥指纹：{fingerprint}\n另一台设备将收到当前账户的完整数据，包括密码、验证码和附件。请核对设备信息后再允许。本次允许会在传输完成后自动失效。"
                    ),
                    kind="warn",
                ):
                    server.approve_export(session_token)
                else:
                    server.reject_export(session_token)
                refresh_export_approval()
                return
            QTimer.singleShot(0, fit_transfer_dialog)

        allow_export_btn.clicked.connect(
            lambda: (server.approve_export((getattr(server._server, "pending_export_device", None) or (None,))[0]), refresh_export_approval())
        )
        reject_export_btn.clicked.connect(
            lambda: (server.reject_export((getattr(server._server, "pending_export_device", None) or (None,))[0]), refresh_export_approval())
        )

        def fit_transfer_dialog() -> None:
            pass

        last_transfer_signature = None
        auto_copied_text_ids: set[str] = set()
        pairing_chrome_hidden = False
        pairing_auto_collapsed = False
        large_file_warned = {"v": False}

        def set_pairing_chrome_hidden(hidden: bool) -> None:
            nonlocal pairing_chrome_hidden
            pairing_chrome_hidden = hidden
            # 连接信息连接后自动隐藏，不提供手动重新显示的入口，避免二次连接。
            lbl_img.setVisible(not hidden)
            lbl_url.setVisible(not hidden)
            lbl_hint.setVisible(not hidden)
            QTimer.singleShot(0, fit_transfer_dialog)

        def queue_text(value: str) -> None:
            try:
                server.queue_transfer_text(value)
                refresh_transfer_status()
            except Exception as error:
                widgets.message(self, i18n.tr("发送失败"), str(error), kind="error")

        def queue_paths(paths) -> None:
            pending: list[str] = []
            for raw in paths:
                source = Path(raw)
                try:
                    size = source.stat().st_size
                except OSError as exc:
                    widgets.message(self, i18n.tr("发送失败"), str(exc), kind="error")
                    continue
                if size > 10 * 1024 * 1024 * 1024 and not large_file_warned["v"]:
                    if not widgets.confirm(
                        self,
                        i18n.tr("传输大文件"),
                        i18n.tr("局域网传输速度较慢，是否继续传输大文件？"),
                        kind="warn",
                    ):
                        return
                    large_file_warned["v"] = True
                pending.append(raw)
            if not pending:
                return
            try:
                for path in pending:
                    server.queue_transfer_file(path)
                refresh_transfer_status()
            except Exception as error:
                widgets.message(self, i18n.tr("发送失败"), str(error), kind="error")

        transfer_panel.sendText.connect(queue_text)
        transfer_panel.sendPaths.connect(queue_paths)

        def end_station_transfer() -> None:
            """手动结束/离开本次传输。

            传输中：断开对端，交给既有的收尾流程停服（下一拍 poll 会把状态写成
            「已断开」），页面与传输记录都留着。
            已经断开后：这个按钮是退出传输视图的出口——同步/传输时滑块是锁住的，
            没有它用户就退不出这个页面、也没法重新连接设备。
            """
            if server._result is not None:
                transfer_panel.set_feedback(i18n.tr("已结束本次传输，可继续查看传输记录"))
                workspace = self._workspace()
                if workspace is not None:
                    workspace.leave_transfer_view()
                return
            if not widgets.confirm(
                self,
                i18n.tr("断开连接"),
                i18n.tr("将断开当前设备，传输站会继续运行、可以再接新设备。本页与已完成的传输记录会保留。"),
                kind="warn",
            ):
                return
            # 断开后发送区要收起来：只禁用的话控件仍在页面上占位，看着还能用
            # 其实发不出去。传输记录留着供查看。
            transfer_panel.set_send_enabled(False)
            transfer_panel.set_composer_visible(False)
            server._result = {"transfer_ended": True, "by": "local"}

        transfer_panel.endRequested.connect(end_station_transfer)

        def cancel_station_item(item_id: str) -> None:
            """主机侧取消单条传输：等待接收/发送中/接收中的条目立即终止。"""
            if server.cancel_transfer_item(item_id):
                transfer_panel.set_feedback(i18n.tr("已取消该传输项目"))
                QTimer.singleShot(2500, lambda: transfer_panel.set_feedback(""))
                refresh_transfer_status()

        transfer_panel.cancelRequested.connect(cancel_station_item)

        def refresh_transfer_status() -> None:
            nonlocal last_transfer_signature, pairing_auto_collapsed, last_channel
            render_pairing_chrome()
            refresh_export_approval()
            channel = "transfer" if server._transfer_active else ("sync" if server.connected else "")
            if channel != last_channel:
                last_channel = channel
                if channel:
                    self.channel_changed.emit(channel)
            pending_sync = getattr(server, "pending_sync_device", None)
            if pending_sync is not None and not sync_prompted["v"]:
                sync_prompted["v"] = True
                session_token, device_id, public_key = pending_sync
                fingerprint = hashlib.sha256(public_key).hexdigest()[:24]
                if widgets.confirm(
                    self,
                    i18n.tr("允许同步？"),
                    i18n.tr(f"请求设备：{device_id}\n密钥指纹：{fingerprint}\n另一台设备正在请求同步本机保险库数据。请核对设备信息后再允许。"),
                    kind="warn",
                ):
                    server.approve_sync(session_token)
                else:
                    server.reject_sync(session_token)
                QTimer.singleShot(0, refresh_transfer_status)
            elif pending_sync is None:
                sync_prompted["v"] = False
            pending_transfer = getattr(server._server, "pending_transfer_device", None)
            if pending_transfer is not None and not transfer_prompted["v"]:
                transfer_prompted["v"] = True
                session_token, device_id, public_key = pending_transfer
                fingerprint = hashlib.sha256(public_key).hexdigest()[:24]
                if widgets.confirm(
                    self,
                    i18n.tr("允许此设备进行文件传输？"),
                    i18n.tr(f"请求设备：{device_id}\n密钥指纹：{fingerprint}\n仅在确认是本人发起的连接后允许传输文件。"),
                    kind="warn",
                ):
                    server.approve_transfer(session_token)
                else:
                    server.reject_transfer(session_token)
                QTimer.singleShot(0, refresh_transfer_status)
            elif pending_transfer is None:
                transfer_prompted["v"] = False
            if (server.connected or server._transfer_active) and not pairing_auto_collapsed:
                pairing_auto_collapsed = True
                set_pairing_chrome_hidden(True)
            # 传输站页面：接入后显示对方设备 + 本次连接两张卡（无进度）。
            self.peer_cards.update_peer(getattr(server, "peer_info", None))
            workspace = self._workspace()
            if workspace is not None:
                busy = bool(server.connected or server._transfer_active)
                workspace.update_gear_notices("transfer" if server._transfer_active else "sync", active=busy, peer=getattr(server, "peer_info", None))
            self._refresh_host_sync_view(server)
            sync_panel.update_status(
                getattr(server, "sync_phase", "idle"),
                send_progress=server.sync_send_progress,
                receive_progress=server.sync_receive_progress,
                connected=server.connected,
                transfer_active=server._transfer_active,
            )
            # 断开后只保留记录供查看，发送区收起。
            transfer_panel.set_composer_visible(bool(server._transfer_active))
            if server._transfer_active and not transfer_panel.isVisible():
                transfer_panel.setVisible(True)
                # 进入文件传输视图后隐藏同步状态页，避免同屏出现两个“断开连接”按钮。
                sync_panel.setVisible(False)
                QTimer.singleShot(0, fit_transfer_dialog)
            # 传输中=「断开连接」，会话已结束=「退出传输」，与同步页同一套阶段逻辑。
            # 可见性判据用 _transfer_active 而不是 transfer_panel.isVisible()——后者
            # 取决于整条祖先链是否可见（面板已被挂到挡位容器上），不可靠。
            live = bool(server.connected or server._transfer_active)
            transfer_panel.set_end_visible(live)
            transfer_panel.set_end_active(live)
            received = server.transfer_received
            with server._transfer_lock:
                queued = [dict(item) for item in server._transfer_outgoing.values()]
            sent = server.transfer_sent
            records = (
                [dict(item, direction="接收") for item in received]
                + [dict(item, direction="发送") for item in queued]
                + [dict(item, direction="发送") for item in sent]
            )
            for record in records:
                status = str(record.get("status") or "")
                record["cancellable"] = status in {"等待接收", "发送中", "接收中"}
            records.sort(
                key=lambda item: float(item.get("completed_at") or item.get("received_at") or item.get("created_at") or 0),
                reverse=True,
            )
            for record in records:
                record_id = str(record.get("id") or "")
                if (
                    record_id
                    and record_id not in auto_copied_text_ids
                    and record.get("direction") == "接收"
                    and record.get("kind") == "text"
                    and record.get("status") == "已接收"
                    and int(record.get("size") or 0) <= 1024 * 1024
                    and record.get("path")
                ):
                    try:
                        value = Path(str(record["path"])).read_text(encoding="utf-8")
                        self.context.copy_secret(value)
                        auto_copied_text_ids.add(record_id)
                        transfer_panel.set_feedback(i18n.tr("文本已复制，剪贴板将按设置自动清空"))
                        QTimer.singleShot(2500, lambda: transfer_panel.set_feedback(""))
                    except (OSError, UnicodeError):
                        pass
            signature = tuple(
                (
                    item.get("id"),
                    item.get("direction"),
                    item.get("status"),
                    int(item.get("transferred") or 0),
                    item.get("path"),
                )
                for item in records
            )
            if signature == last_transfer_signature:
                return
            last_transfer_signature = signature
            transfer_panel.set_records(records)

        poll = QTimer(self)
        poll.setInterval(300)

        def _end_session_visuals() -> None:
            """会话结束后复位主机侧的视觉状态。

            refresh_transfer_status() 在停服前跑，那时 server.connected 仍为 True
            （sessions 只在 stop() 里清空），会再写一次「已连接，等待同步或传输…」；
            紧接着 poll 停止就再没人刷新，这句文案会被永久冻结。

            传输站主页在这一刻只允许留下「与连接状态有关」的内容：状态标签 +
            关闭传输站（以及未开站时的建立入口）。二维码、服务器地址、扫码提示
            一律不再放回——此时 server.stop() 已经执行，那张二维码指向的是一个
            已经不存在的传输站，留着会让人以为还能扫；同步状态与传输记录则已经
            挂到对应挡位去了。要重新建立传输站，点建立按钮会生成新的二维码。
            """
            sync_panel.set_text(i18n.tr("已断开"))
            transfer_panel.set_send_enabled(False)
            # 对方关闭连接后发送区同样要收起：只禁用会留下「看着能发、实际发不出去」
            # 的输入框，传输记录留着供查看。
            transfer_panel.set_composer_visible(False)
            # 断开后按钮保留但改名为「退出传输」：这时它是退出该视图、重新连接
            # 设备的出口，点「断开连接」已经没有对象可断。
            transfer_panel.set_end_visible(True)
            transfer_panel.set_end_active(False)
            transfer_panel.set_feedback(i18n.tr("已断开"))
            # 服务端已停，传输站不存在了：按钮换回「建立传输站」。
            self.stop_btn.setVisible(False)
            workspace = self._workspace()
            if workspace is not None:
                workspace._on_station_disconnected()

        def _finish_if_done() -> None:
            if server._result is None:
                refresh_transfer_status()
                return
            result = server._result
            # authenticated_at 必须在停服前取：stop() 会把 _server 置 None，之后
            # getattr 只会拿到 None，无法区分「从未配对」与「传输中超时」两条分支。
            authenticated_at = getattr(server._server, "authenticated_at", None)
            poll.stop()
            server.stop()
            _end_session_visuals()
            # 会话结束后重新露出入口，便于在同一页再次建立传输站（结果卡片保留）。
            self._restore_station_entry()
            if isinstance(result, dict) and result.get("transfer_ended"):
                transfer_panel.set_send_enabled(False)
                transfer_panel.set_composer_visible(False)
                if result.get("by") == "local":
                    transfer_panel.set_feedback(i18n.tr("已结束本次传输，可继续查看传输记录"))
                else:
                    transfer_panel.set_feedback(i18n.tr("对方已关闭连接，可继续查看传输记录"))
            elif isinstance(result, dict) and result.get("timeout"):
                if authenticated_at is None:
                    # 从未建立连接（配对超时/二维码失效）：保留页面，只内联提示。
                    lbl_hint.setText(i18n.tr("同步会话已超时，请重新生成二维码。"))
                    lbl_hint.setStyleSheet("color: #DC2626;")
                    transfer_panel.set_feedback(i18n.tr("同步会话已超时，请重新生成二维码。"))
                    return
                # 传输/会话超时：保留页面查看记录，弹窗提示并断开连接
                transfer_panel.set_feedback(i18n.tr("连接超时，已断开连接"))
                widgets.message(
                    self,
                    i18n.tr("连接超时"),
                    i18n.tr_dynamic(f"{i18n.tr(result['timeout'])}，已断开连接。可继续查看本次传输记录。"),
                    kind="warn",
                )
            elif isinstance(result, dict):
                # 同步/导出流程完成：结果留在页面内。
                self._handle_station_result(result)
            else:
                self.show_result(None)

        poll.timeout.connect(_finish_if_done)

        render_pairing_chrome()
        QTimer.singleShot(0, fit_transfer_dialog)
        poll.start()
        self.poll_timer = poll
        self.server = server
        self.context.set_auto_lock_blocker("lan-sync", True)

    def show_result(self, result) -> None:
        """同步/导出结果写到同步挡位的状态面板。

        传输站主页只承载「与连接状态有关」的内容，同步结论（包括「已采用对方的新
        内容」这类合并摘要）属于同步通道的信息，跟着同步状态一起放在同步挡位。
        """
        stats = result if isinstance(result, dict) else {}
        workspace = self._workspace()
        if workspace is not None:
            workspace.show_station_result(stats)

    def _handle_station_result(self, result) -> None:
        if not isinstance(result, dict) or result.get("transfer_ended") or result.get("timeout"):
            return
        from .app import _lan_sync_user_message

        if "error" in result:
            widgets.message(
                self,
                "同步失败",
                _lan_sync_user_message(RuntimeError(str(result["error"]))),
                kind="error",
            )
            return
        if self._window is not None:
            self._window.reload()
            self._window._update_recycle_btn()
        self.show_result(result)
        if self._window is None:
            return
        if result.get("key_converged"):
            self._window._prompt_key_convergence(bool(result.get("password_changed")))
        elif result.get("key_slots_adopted"):
            self._window._prompt_key_convergence(True)

    def is_busy(self) -> bool:
        """有设备正在同步或互传时为 True（此时三档滑块应禁用）。"""
        server = self.server
        return bool(server is not None and (server.connected or server._transfer_active))

    def can_close(self, reason: str) -> bool:
        if reason != "user" or self.server is None or self.server._result is not None:
            return True
        return widgets.confirm(
            self,
            i18n.tr("关闭传输站"),
            i18n.tr("同步/连接仍在进行，关闭将断开与手机端的连接，进度无法继续。确定要关闭吗？"),
            kind="warn",
        )

    def close_page(self, reason: str) -> None:
        self.poll_timer.stop()
        if self.server is not None:
            self.server.stop()
            self.server = None
        if self._window is not None:
            self.context.set_auto_lock_blocker("lan-sync", False)


#: 连接方轮询传输条目时连续失败多少次即判定「对方已关闭传输连接」。
#: 单次失败可能只是网络抖动；主机停服后该请求会持续失败，累积到阈值就收口，
#: 否则连接方对断开完全失明（发送区留着、按钮还写着「断开连接」）。
_POLL_FAILURES_TO_END = 3


class LanConnectionPage(EditorPage):
    """连接另一台设备的传输站（PC↔PC / PC→安卓），复用共享同步/传输组件。"""

    def __init__(self, context: LanPageContext, preset_mode: str | None = None, parent=None):
        super().__init__(parent)
        from core.sync_client import SYNC_OP, TRANSFER_OP

        self.context = context
        self._window = context.window
        self.setObjectName("LanConnectionPage")
        shell = page_shell(self, i18n.tr("连接传输站"), compact=True)
        self.page_header = shell.header
        self.body = shell.content
        self._preset_mode = preset_mode if preset_mode in (SYNC_OP, TRANSFER_OP) else SYNC_OP
        self.poll_timer = QTimer(self)
        self.keepalive_timer = QTimer(self)
        self._disconnect_now = None
        self._build_connection_ui()

    def set_busy_notice(self, text: str) -> None:
        """另一个通道正在进行时，本挡位只显示这句说明，不提供任何操作。

        切档是允许的，所以每个挡位都要能自证「为什么现在什么都做不了」。
        """
        self._busy_notice.setText(text)
        self._busy_notice.setVisible(bool(text))

    def set_peer_device(self, info: dict | None) -> None:
        """传输页顶部的对方设备标识（一行文本，不做成卡片）。

        这里没有「设备名称」这个数据——授权记录里只有 device_id、公钥与时间戳，
        PC 与 Android 都没有设备名概念，所以只能取 device_id 前 8 位。标签写
        「对方设备」而不是「名称」，免得把 ID 截断说成一个名字。
        """
        if not info or not info.get("device_id"):
            self.peer_device_label.setVisible(False)
            return
        short = str(info["device_id"])[:8]
        self.peer_device_label.setText(i18n.tr("对方设备：{short}").format(short=short))
        self.peer_device_label.setVisible(True)

    def _clear_busy_notice(self) -> None:
        self.set_busy_notice("")

    def set_workspace(self, workspace) -> None:
        """记录所属的 LanWorkspacePage：主机侧退出要经它回到 station 复原入口。"""
        self._workspace_page = workspace

    def _workspace(self):
        return getattr(self, "_workspace_page", None)

    def enter_host_mode(self) -> None:
        """本机已被对端连接：隐藏全部连接方 UI，只留主机侧会话状态。

        地址输入、扫码识别、连接按钮此时都没有意义——对端已经接入本机传输站，
        留着只会让人以为还能再连一台。
        """
        if self._host_mode:
            return
        self._host_mode = True
        self.connect_view.setVisible(False)
        self.status_label.setVisible(False)
        self.connector_sync_panel.setVisible(False)
        self.connector_transfer_panel.setVisible(False)
        self.host_attach.setVisible(True)

    def exit_host_mode(self) -> None:
        """对端断开或本机不再是主机：恢复连接方 UI。"""
        if not self._host_mode:
            return
        self._host_mode = False
        self.host_attach.setVisible(False)
        self.connect_view.setVisible(True)
        self.status_label.setVisible(True)
        # 同步/传输状态面板的显隐由 _apply_gear_visibility 按当前挡位统一决定，
        # 这里不手动设：enter_host_mode 藏起来的面板会在下一次挡位刷新时按 mode 归位。

    def _refresh_connector_sync_view(self, phase: str, transferred: int, total: int) -> None:
        """连接方（我连别人）的同步视图。

        这里刻意不显示设备信息卡：客户端只能拿到对方的临时 TLS 证书指纹，
        拿不到 device_id 与设备公钥指纹，硬凑一张表会让人误以为那是设备身份。
        """
        if self._state.get("client") is None:
            self.sync_view.setVisible(False)
            self.connector_sync_panel.setVisible(True)
            return
        self.sync_view.setVisible(True)
        self.sync_view.set_device(None)
        self.connector_sync_panel.setVisible(False)
        texts = {
            "verify": i18n.tr("正在检查两端数据…"),
            "download": i18n.tr("正在接收对方设备的数据…"),
            "upload": i18n.tr("正在把本机保险库发送到对方设备…"),
        }
        self.sync_view.set_phase(texts.get(phase, i18n.tr("已连接，等待同步…")))
        self.sync_view.set_progress(int(transferred or 0), int(total or 0) or None)
        started = self._state.get("connected_at")
        if started is None:
            started = time.time()
            self._state["connected_at"] = started
        self.sync_view.set_duration(time.time() - started)
        self.connect_view.setVisible(False)
        self.status_label.setVisible(False)

    def _on_exit_sync_session(self) -> None:
        """底部按钮：进行中=断开连接，同步结束/中断后=退出同步视图。

        主机角色（别人连我）走传输站自己的停服流程；连接方（我连别人）走客户端断开。
        """
        if self._host_mode:
            self._on_exit_host_session(finished=self._sync_finished)
            return
        if self._state.get("client") is not None:
            # 同步进行中断开要二次确认：中断的是合并写回，可能停在半合并状态，
            # 代价比传输中断大（传输只是丢条目，同步会丢合并进度）。
            if not widgets.confirm(
                self,
                i18n.tr("断开连接"),
                i18n.tr("同步仍在进行，中断会放弃本次合并与回传，尚未完成的部分需要重新同步。确定要断开吗？"),
                kind="warn",
            ):
                return
            self._state["stop"] = True
            if self._disconnect_now is not None:
                self._disconnect_now()
            return
        self.sync_view.setVisible(False)
        self.connect_view.setVisible(True)
        self.status_label.setVisible(True)
        self.status_label.setText(i18n.tr("粘贴传输站的完整地址（已包含 PIN），或扫码识别自动填入"))
        self._reset_sync_view()

    def _reset_sync_view(self) -> None:
        self.sync_view.result_card.setVisible(False)
        self._sync_finished = False

    def _on_exit_host_session(self, *, finished: bool) -> None:
        """主机侧的同一颗按钮：结束会话 / 退出同步视图。"""
        workspace = self._workspace()
        station = workspace.station_page if workspace is not None else None
        if station is not None and not finished:
            # 同步进行中停站同样要确认：对方正在合并写回，说停就停会留下半合并状态。
            if not widgets.confirm(
                self,
                i18n.tr("断开连接"),
                i18n.tr("同步仍在进行，中断会放弃本次合并与回传，尚未完成的部分需要重新同步。确定要断开吗？"),
                kind="warn",
            ):
                return
            station._stop_station()
            return
        self.sync_view.setVisible(False)
        self.exit_host_mode()
        self._reset_sync_view()

    def _show_sync_result(self, rows: list[tuple[str, str]], summary: str = "") -> None:
        """同步跑完：状态卡定格 + 结果卡就位，按钮切成「退出同步」。

        text 是既有的单行摘要，结果卡按同一份数据另起几行——口径都来自
        _lan_sync_result_rows，不会两处对不上。
        """
        values = dict(rows)
        self.sync_view.setVisible(True)
        self._sync_finished = True
        self.sync_view.set_phase(i18n.tr("同步已完成"), finished=True)
        self.sync_view.result_card.set("lineage", values.get("谱系", "—"))
        self.sync_view.result_card.set("counts", values.get("条目", "—"))
        self.sync_view.result_card.set("push", values.get("回推", "—"))
        self.sync_view.result_card.set("verify", values.get("校验", "—"))
        self.sync_view.result_card.setVisible(True)

    def select_mode(self, mode: str) -> bool:
        if self._state.get("client") is not None:
            return False
        self._state["mode"] = mode
        return True

    def _build_connection_ui(self) -> None:
        import threading as _threading

        from core.sync_client import (
            SYNC_OP,
            TRANSFER_OP,
            LanSyncClient,
            PinValidationError,
            SyncError,
            embedded_pin,
        )

        from .app import (
            _lan_connection_user_message,
            _lan_sync_result_rows,
            _lan_sync_result_summary,
            _lan_sync_user_message,
            _lan_transfer_user_message,
        )

        def safe_station_name(value: str) -> str:
            name = str(value).replace("\\", "/").split("/")[-1][:180]
            cleaned = "".join("_" if ord(char) < 32 or char in '<>:"/\\|?*' else char for char in name).strip(" .")
            return cleaned or "received.bin"

        def station_receive_path(offer: dict) -> Path:
            base = Path.home() / "Downloads" / "Vaultshare"
            base.mkdir(parents=True, exist_ok=True)
            name = safe_station_name(str(offer.get("name") or "received.bin"))
            candidate = base / name
            stem, suffix = candidate.stem, candidate.suffix
            index = 2
            while candidate.exists():
                candidate = base / f"{stem}_{index}{suffix}"
                index += 1
            return candidate

        url_edit = QLineEdit()
        url_edit.setPlaceholderText("https://192.168.1.100:18765/api/sync/vault?ticket=…&pin=…")
        scan_btn = QPushButton(i18n.tr("扫码识别"))
        addr_row = QHBoxLayout()
        addr_row.addWidget(url_edit, 1)
        addr_row.addWidget(scan_btn)

        connect_btn = QPushButton(i18n.tr("连接"))
        # 连接视图整体收进一个容器：连接成功后整体隐藏，直接跳转到对应通道 UI。
        connect_view = QWidget()
        connect_view_layout = QVBoxLayout(connect_view)
        connect_view_layout.setContentsMargins(0, 0, 0, 0)
        connect_view_layout.setSpacing(8)
        connect_view_layout.addLayout(addr_row)
        connect_view_layout.addWidget(connect_btn)
        # 对方设备标识放在内容区最前面：它回答的是「正在跟谁传」，压在页面
        # 最底部会跑到按钮下面，失去标识作用。只有文本，不做卡片。
        self.peer_device_label = QLabel("")
        self.peer_device_label.setObjectName("SettingNote")
        self.peer_device_label.setVisible(False)
        self.body.addWidget(self.peer_device_label)

        self.body.addWidget(connect_view)
        # 连接过程中的实时状态行：会被反复 setText，不能挪进页头小标题。
        status_label = QLabel(i18n.tr("粘贴传输站的完整地址（已包含 PIN），或扫码识别自动填入"))
        status_label.setStyleSheet("color: #6B7280; font-size: 12px;")
        status_label.setWordWrap(True)
        self.body.addWidget(status_label)

        # 局域网同步页 / 文件传输页：与主机端复用同一套共享组件
        sync_panel = LanSyncStatusPanel()
        sync_panel.setVisible(False)
        self.body.addWidget(sync_panel)

        transfer_panel = LanTransferPanel()
        transfer_panel.setVisible(False)
        transfer_panel.set_on_copy(lambda value: self.context.copy_secret(value))
        self.body.addWidget(transfer_panel)

        # 主机侧会话容器：本机作传输站并被对端连接后，传输站的同步/传输面板会挂到
        # 这里（见 LanStationPage.attach_host_panels）。未连接时整块隐藏，连接方 UI
        # 照常显示——同一档位在「我连别人」与「别人连我」两种角色下呈现不同内容。
        self.host_attach = QWidget()
        host_attach_layout = QVBoxLayout(self.host_attach)
        host_attach_layout.setContentsMargins(0, 0, 0, 0)
        host_attach_layout.setSpacing(10)
        self.host_attach.setVisible(False)
        self.body.addWidget(self.host_attach)

        # 同步会话视图：设备信息 + 同步状态（+ 结果）+ 底部按钮。
        # 互传页沿用传输面板自带的「退出传输」，这里只服务同步页。
        self.sync_view = _SyncSessionView(self)
        self.sync_view.setVisible(False)
        self.sync_view.action_btn.clicked.connect(self._on_exit_sync_session)
        self._sync_finished = False
        self.body.addWidget(self.sync_view)

        self._host_mode = False
        self.connect_view = connect_view

        # 「另一个通道正在进行」的说明条：本挡位此时不提供任何操作。
        # 这是状态告知而不是脚注，字号给得比 SettingNote 大一档。
        self._busy_notice = QLabel("")
        self._busy_notice.setObjectName("GearBusyNotice")
        self._busy_notice.setAlignment(Qt.AlignCenter)
        self._busy_notice.setWordWrap(True)
        self._busy_notice.setVisible(False)
        self.body.addWidget(self._busy_notice)
        self.status_label = status_label
        self.connector_sync_panel = sync_panel
        self.connector_transfer_panel = transfer_panel

        self._state: dict = {
            "client": None,
            "mode": self._preset_mode,
            "status": "",
            "phase": "",
            "progress": (0, 0),
            "received": [],
            "sent": [],
            "known_offers": set(),
            "active_sends": {},
            "text_to_copy": None,
            "sync_done": False,
            "sync_error": None,
            "sync_result": None,
            "stop": False,
            "large_file_warned": False,
            # 轮询线程判定「对方已关闭」后置位，由 poll 定时器在主线程收口 UI
            "connector_disconnected": False,
        }

        def _render_records() -> None:
            records = [dict(item, direction="接收") for item in self._state["received"]] + [dict(item, direction="发送") for item in self._state["sent"]]
            transfer_panel.set_records(records)

        def _update_receive_record(record: dict, transferred: int) -> None:
            if record.get("status") == "接收中":
                record["transferred"] = transferred

        def _download_one(offer: dict) -> None:
            """逐条下载新出现的传输项：独立线程运行，支持单条取消。"""
            client = self._state["client"]
            if client is None:
                return
            oid = str(offer.get("id") or "")
            target = station_receive_path(offer)
            record = {
                **offer,
                "path": "",
                "status": "接收中",
                "transferred": 0,
                "cancellable": True,
            }
            self._state["received"].append(record)
            try:
                client.download_transfer_item(
                    offer,
                    target,
                    on_progress=lambda sent, total: _update_receive_record(record, sent),
                    on_retry=lambda attempt, maximum: (
                        record.__setitem__("status", f"文件检查未通过，正在自动重试（{attempt}/{maximum}）")
                        if record.get("status") not in {"已取消", "已接收"}
                        else None
                    ),
                    transfer_key=oid,
                    cancel_check=lambda: record.get("status") == "已取消",
                )
                if record.get("status") == "已取消":
                    return
                record.update(
                    status="已接收",
                    path=str(target),
                    transferred=int(offer.get("size") or 0),
                    cancellable=False,
                )
                if offer.get("kind") == "text" and int(offer.get("size") or 0) <= 1024 * 1024:
                    self._state["text_to_copy"] = target.read_text(encoding="utf-8")
            except Exception as error:
                target.unlink(missing_ok=True)
                if record.get("status") == "已取消":
                    record["cancellable"] = False
                    return
                record.update(
                    status=_lan_transfer_user_message(error, sending=False),
                    path="",
                    transferred=record.get("transferred") or 0,
                    cancellable=False,
                )
                return
            # 确认回执单独处理：它只决定主机侧的待传列表是否清空，文件此时已完整
            # 落盘。若并入上面的失败路径，会把已收到的文件删掉并误标为「未能接收」。
            try:
                client.acknowledge_transfer_item(oid)
            except Exception:
                self._state["transfer_feedback"] = i18n.tr("文件已接收，但传输站未收到确认，可能还会再发一次")

        def cancel_connector_item(item_id: str) -> None:
            """连接方取消单条传输：正在接收/发送的条目立即终止。"""
            client = self._state["client"]
            if item_id.startswith("send:"):
                send_id = item_id[5:]
                if client is not None:
                    client.abort_transfer(send_id)
                for record in self._state["sent"]:
                    if record.get("id") == item_id and record.get("status") not in {"已发送", "已取消"}:
                        record["status"] = "已取消"
                        record["cancellable"] = False
                        break
            else:
                if client is not None:
                    client.abort_transfer(item_id)
                for record in self._state["received"]:
                    if record.get("id") == item_id and record.get("status") not in {"已接收", "已取消"}:
                        record["status"] = "已取消"
                        record["cancellable"] = False
                        break
            transfer_panel.set_feedback(i18n.tr("已取消该传输项目"))
            QTimer.singleShot(2500, lambda: transfer_panel.set_feedback(""))

        def _spawn_send(
            *,
            name: str,
            kind: str,
            size: int,
            source_path: str,
            send_fn,
        ) -> None:
            """后台线程发送并展示可取消的“发送中”记录。"""
            client = self._state["client"]
            if client is None:
                return
            send_id = str(uuid.uuid4())
            item_id = f"send:{send_id}"
            record = {
                "id": item_id,
                "name": name,
                "kind": kind,
                "size": size,
                "sha256": "",
                "path": source_path,
                "status": "发送中",
                "transferred": 0,
                "cancellable": True,
            }
            self._state["sent"].append(record)

            def _run() -> None:
                try:
                    item = send_fn(
                        send_id,
                        lambda: record.get("status") == "已取消",
                    )
                    if record.get("status") == "已取消":
                        return
                    record.update(
                        name=item.get("name") or name,
                        kind=item.get("kind") or kind,
                        size=int(item.get("size") or size or 0),
                        sha256=item.get("sha256") or "",
                        status="已发送",
                        transferred=int(item.get("size") or size or 0),
                        cancellable=False,
                    )
                except Exception as error:
                    if record.get("status") == "已取消":
                        return
                    record.update(
                        status=_lan_transfer_user_message(error, sending=True),
                        transferred=record.get("transferred") or 0,
                        cancellable=False,
                    )
                    self._state["transfer_feedback"] = _lan_transfer_user_message(error, sending=True)

            thread = _threading.Thread(target=_run, name="station-send", daemon=True)
            self._state["active_sends"][send_id] = thread
            thread.start()
            _render_records()

        # 连续轮询失败次数：主机停服后 list_transfer_items 每次都抛错，原来一律
        # pass 掉，于是连接方对「对方已关闭」完全失明——client 永不被置空，
        # 发送区留在页面上、按钮还写着「断开连接」。累计到阈值即判定会话结束。
        poll_failures = {"count": 0}

        def _poll_loop() -> None:
            while not self._state["stop"]:
                client = self._state["client"]
                if client is not None and self._state["mode"] == TRANSFER_OP:
                    try:
                        items = client.list_transfer_items()
                    except Exception:
                        poll_failures["count"] += 1
                        # 单次失败可能是网络抖动，连续多次才判定对方已关闭。
                        if poll_failures["count"] >= _POLL_FAILURES_TO_END:
                            self._state["stop"] = True
                            self._state["connector_disconnected"] = True
                            self._state["transfer_feedback"] = i18n.tr(
                                "对方已关闭连接，可继续查看传输记录"
                            )
                        time.sleep(1.0)
                        continue
                    poll_failures["count"] = 0
                    try:
                        for offer in items:
                            oid = str(offer.get("id") or "")
                            if oid in self._state["known_offers"]:
                                continue
                            self._state["known_offers"].add(oid)
                            _threading.Thread(
                                target=_download_one,
                                args=(offer,),
                                name="station-download",
                                daemon=True,
                            ).start()
                    except Exception:
                        pass
                time.sleep(1.0)

        # 同步通道保活：PC 客户端不发心跳时，安卓主机仅凭请求活跃度判活。
        ka_timer = QTimer(self)
        ka_timer.setInterval(15_000)
        ka_keepalive_running = {"active": False}

        def _keepalive_tick() -> None:
            client = self._state["client"]
            if client is None or self._state["mode"] != SYNC_OP or ka_keepalive_running["active"]:
                return
            ka_keepalive_running["active"] = True

            def _run() -> None:
                try:
                    client.keepalive()
                except Exception:
                    pass
                finally:
                    ka_keepalive_running["active"] = False

            _threading.Thread(target=_run, name="station-keepalive", daemon=True).start()

        ka_timer.timeout.connect(_keepalive_tick)

        def _fail(message: str) -> None:
            self._state["client"] = None
            status_label.setText(message)
            connect_btn.setEnabled(True)
            # 连接失败也是一次断开：发送区必须收起，按钮切成「关闭页面」，
            # 否则会留下一个看着能发、实际发不出去的输入框。
            _on_connector_disconnected()

        def _on_connector_disconnected() -> None:
            """连接方断开的统一收口：收起发送区 + 按钮切到「关闭页面」。

            对方关闭、超时、本地主动结束、连接失败都走这里。只禁用按钮不够——
            控件仍在页面上占位，看着还能用其实发不出去。传输记录保留供查看。
            """
            transfer_panel.set_send_enabled(False)
            transfer_panel.set_composer_visible(False)
            transfer_panel.set_end_visible(True)
            transfer_panel.set_end_active(False)

        def _connected() -> None:
            client = self._state["client"]
            if client is None:
                return
            show_sync = self._state["mode"] == SYNC_OP
            show_transfer = self._state["mode"] == TRANSFER_OP
            sync_panel.setVisible(show_sync)
            transfer_panel.setVisible(show_transfer)
            transfer_panel.set_send_enabled(show_transfer)
            # 传输通道建立后提供「结束传输」；同步通道没有就地结束的出口。
            transfer_panel.set_end_visible(show_transfer)
            # 断开后只保留记录供查看，发送区收起。连接方的存活判据就是 client
            # ——连接一断它就被置空，发送区随之收起。
            transfer_panel.set_composer_visible(show_transfer and self._state.get("client") is not None)
            connect_view.setVisible(False)
            if show_transfer:
                _threading.Thread(target=_poll_loop, name="station-poll", daemon=True).start()
            if show_sync:
                ka_timer.start()
                # 安卓允许后自动开始同步，无需手动点击。
                QTimer.singleShot(0, start_sync)

        def connect_now() -> None:
            url = url_edit.text().strip()
            pin = embedded_pin(url)
            if not url or len(pin) != 6:
                status_label.setText(i18n.tr("地址无效：请粘贴包含 pin=… 的完整传输站地址"))
                return
            self._state.update(
                stop=False,
                sync_done=False,
                sync_succeeded=False,
                sync_error=None,
                sync_result=None,
                phase="",
                progress=(0, 0),
                reload_pending=False,
                connected_at=None,
            )
            connect_btn.setEnabled(False)
            status_label.setText(i18n.tr("正在连接…"))
            # PMVE 同步通道：配对后、任何数据交换前完成设备授权认证。
            vault_id = None
            identity = None
            if self._state["mode"] in (SYNC_OP, TRANSFER_OP) and getattr(self._window.vault, "vault_identity", None) is not None:
                from core import device_identity

                vault_id = self._window.vault.vault_identity.vault_id
                self._window.vault.ensure_device_authorized()
                identity = device_identity.load_or_create(vault_id)

            def _establish() -> None:
                """配对与设备认证放后台线程：对方弹窗确认期间本端保持响应。"""
                try:
                    client = LanSyncClient(url, pin, op=self._state["mode"])
                    self._state["client"] = client
                    if identity is not None:
                        self._state["status"] = i18n.tr("正在等待对方确认设备…")
                        client.authenticate_device(vault_id, identity)
                    self._state["status"] = i18n.tr("连接成功")
                    # 主线程轮询检测到该标记后执行界面跳转（不能在后台线程直接操作 UI）。
                    self._state["connect_ready"] = True
                except PinValidationError:
                    self._state["connect_error"] = i18n.tr("PIN 码错误，请检查后重试")
                except SyncError as error:
                    self._state["connect_error"] = _lan_connection_user_message(error)
                except Exception as error:
                    self._state["connect_error"] = _lan_connection_user_message(error)

            # 立即启动轮询，让后台线程的状态（如“正在等待对方确认同步…”）及时上屏。
            poll.start()
            _threading.Thread(target=_establish, name="station-connect", daemon=True).start()

        connect_btn.clicked.connect(connect_now)

        def apply_scan_payloads(payloads: list[str]) -> bool:
            """把识别出的传输站地址填入地址栏（内嵌 PIN 一并填入），返回是否已填入。"""
            for payload in payloads:
                candidate = str(payload or "").strip()
                if not candidate.startswith("https://"):
                    continue
                url_edit.setText(candidate)
                status_label.setText(i18n.tr("已识别传输站地址，可直接连接"))
                return True
            return False

        def scan_qr() -> None:
            """打开扫码 UI 识别传输站二维码（内部含摄像头与从图片文件识别），自动填入地址与 PIN。"""
            try:
                from .module_editor import _CameraCaptureDialog

                cam = _CameraCaptureDialog(qr_mode=True, parent=self, qr_title=i18n.tr("扫描传输站二维码"))
                if cam.exec() != QDialog.Accepted:
                    return
                if apply_scan_payloads(cam.qr_payloads):
                    # 识别到有效地址后自动连接，无需再手动点击“连接”。
                    connect_now()
                    return
                widgets.message(self, i18n.tr("未识别到二维码"), i18n.tr("画面中没有传输站二维码，请对准后重试"), kind="warn")
            except RuntimeError as error:
                widgets.message(self, i18n.tr("无法打开摄像头"), str(error), kind="warn")
            except Exception as error:
                widgets.message(self, i18n.tr("扫码失败"), str(error), kind="error")

        scan_btn.clicked.connect(scan_qr)

        def start_sync() -> None:
            client = self._state["client"]
            if client is None or self._state["sync_done"]:
                return
            self._state["sync_done"] = True
            status_label.setText(i18n.tr("正在检查两端数据…"))

            def run() -> None:
                try:

                    def on_phase(phase: str, transferred: int, total: int) -> None:
                        if phase == "verify":
                            self._state["phase"] = "verify"
                            self._state["progress"] = (0, 0)
                            return
                        if transferred == 0 and total == 0 and phase in {"download", "upload"}:
                            self._state["phase"] = phase
                            self._state["progress"] = (0, 0)
                            self._state["status"] = i18n.tr("数据检查未通过，正在自动重试…")
                            return
                        self._state["phase"] = phase
                        self._state["progress"] = (transferred, total)

                    stats = client.sync_vault(self._window.vault, on_phase=on_phase)
                    self._state["sync_error"] = None
                    self._state["sync_succeeded"] = True
                    self._state["sync_result"] = stats
                    self._state["key_converged"] = bool(stats.get("key_converged"))
                    self._state["password_changed"] = bool(stats.get("password_changed"))
                    self._state["status"] = i18n.tr("局域网同步已完成 · ") + _lan_sync_result_summary(stats)
                except Exception as error:
                    self._state["sync_error"] = str(error)
                    self._state["sync_succeeded"] = False
                    self._state["status"] = _lan_sync_user_message(error)
                finally:
                    self._state["sync_done"] = False
                    self._state["phase"] = ""
                    self._state["progress"] = (0, 0)
                    self._state["reload_pending"] = True

            _threading.Thread(target=run, name="station-sync", daemon=True).start()

        def send_text_now(value: str) -> None:
            client = self._state["client"]
            if client is None or not value:
                return
            _spawn_send(
                name=i18n.tr("发送文本"),
                kind="text",
                size=len(value.encode("utf-8")),
                source_path="",
                send_fn=lambda send_key, cancel_check: client.upload_transfer_text(
                    value,
                    transfer_key=send_key,
                    cancel_check=cancel_check,
                ),
            )

        def queue_pasted_file(paths) -> None:
            client = self._state["client"]
            if client is None:
                return
            pending: list[str] = []
            for raw in paths:
                source = Path(raw)
                try:
                    size = source.stat().st_size
                except OSError as exc:
                    transfer_panel.set_feedback(i18n.tr("发送失败：") + str(exc))
                    continue
                if size > 10 * 1024 * 1024 * 1024 and not self._state["large_file_warned"]:
                    if not widgets.confirm(
                        self,
                        i18n.tr("传输大文件"),
                        i18n.tr("局域网传输速度较慢，是否继续传输大文件？"),
                        kind="warn",
                    ):
                        return
                    self._state["large_file_warned"] = True
                pending.append(raw)
            for raw in pending:
                source = Path(raw)
                _spawn_send(
                    name=source.name,
                    kind="file",
                    size=source.stat().st_size,
                    source_path=str(source),
                    send_fn=lambda send_key, cancel_check, path=raw: client.upload_transfer_file(
                        path,
                        transfer_key=send_key,
                        cancel_check=cancel_check,
                    ),
                )

        transfer_panel.sendText.connect(send_text_now)
        transfer_panel.sendPaths.connect(queue_pasted_file)
        transfer_panel.cancelRequested.connect(cancel_connector_item)

        def end_connector_transfer() -> None:
            """连接方先断开，再关闭传输视图并回到连接表单。"""
            if self._state.get("client") is None:
                transfer_panel.setVisible(False)
                transfer_panel.set_end_visible(False)
                self.connect_view.setVisible(True)
                self.status_label.setVisible(True)
                self.status_label.setText(i18n.tr("粘贴传输站的完整地址（已包含 PIN），或扫码识别自动填入"))
                self.peer_device_label.setVisible(False)
                connect_btn.setEnabled(True)
                return
            if not widgets.confirm(
                self,
                i18n.tr("关闭页面"),
                i18n.tr("将关闭当前传输页面并回到扫码连接页。已完成的传输记录会保留。"),
                kind="warn",
            ):
                return
            transfer_panel.set_end_visible(True)
            transfer_panel.set_end_active(False)
            transfer_panel.set_send_enabled(False)
            transfer_panel.set_composer_visible(False)
            transfer_panel.set_feedback(i18n.tr("已结束本次传输，可继续查看传输记录"))
            self._finish_connection()

        transfer_panel.endRequested.connect(end_connector_transfer)

        poll = QTimer(self)
        poll.setInterval(300)

        def _tick() -> None:
            if self._state.pop("connect_ready", False):
                _connected()
            connect_error = self._state.pop("connect_error", None)
            if connect_error is not None:
                _fail(connect_error)
            if self._state.pop("connector_disconnected", False):
                # 对方关闭了传输连接：置空 client 让 is_busy() 放行，停止轮询，
                # 并按断开统一收口——发送区收起、按钮切「关闭页面」，记录留着可看。
                self._state["client"] = None
                _on_connector_disconnected()
                self.poll_timer.stop()
            if self._state["status"]:
                status_label.setText(self._state["status"])
                self._state["status"] = ""
            phase = self._state.get("phase", "")
            transferred, total = self._state.get("progress", (0, 0))
            if phase == "verify":
                sync_panel.update_status("verifying")
            elif phase == "download":
                sync_panel.update_status("receiving", receive_progress=(transferred, total))
            elif phase == "upload":
                sync_panel.update_status("sending", send_progress=(transferred, total))
            if self._state.get("mode") == SYNC_OP:
                self._refresh_connector_sync_view(phase, transferred, total)
            transfer_feedback_text = self._state.pop("transfer_feedback", None)
            if transfer_feedback_text is not None:
                transfer_panel.set_feedback(transfer_feedback_text)
            if self._state["text_to_copy"] is not None:
                try:
                    self._window._copy(self._state["text_to_copy"], secret=True)
                    status_label.setText(i18n.tr("收到文本并已复制，剪贴板将按设置自动清空"))
                finally:
                    self._state["text_to_copy"] = None
            if self._state.get("reload_pending"):
                self._state["reload_pending"] = False
                self._window.reload()
                if self._state.get("sync_succeeded"):
                    sync_panel.update_status("done")
                    stats = self._state.get("sync_result") or {}
                    self._show_sync_result(
                        _lan_sync_result_rows(stats),
                        _lan_sync_result_summary(stats),
                    )
                elif self._state.get("sync_error"):
                    sync_panel.update_status("failed")
                # 同步成功：短暂展示结果后自动断开连接并关闭窗口（互传模式不关闭）。
                if self._state.get("sync_succeeded") and self._state["mode"] == SYNC_OP:
                    QTimer.singleShot(2500, self._finish_connection)
            if self._state.pop("key_converged", False):
                self._window._prompt_key_convergence(bool(self._state.pop("password_changed", False)))
            _render_records()

        poll.timeout.connect(_tick)

        def disconnect_now() -> None:
            """流程完成/窗口关闭时主动断开连接，通知主机端立即感知客户端已离开。"""
            client = self._state["client"]
            if client is None:
                return
            if self._state["mode"] == TRANSFER_OP:
                client.abort_all_transfers()
                _threading.Thread(target=client.end_transfer, daemon=True).start()
            else:
                _threading.Thread(target=client.cancel, daemon=True).start()

        self.poll_timer = poll
        self.keepalive_timer = ka_timer
        self._disconnect_now = disconnect_now
        self.context.set_auto_lock_blocker("station", True)

    def is_busy(self) -> bool:
        """连接建立后为 True：任务进行中不允许切档（对齐安卓端）。"""
        return self._state.get("client") is not None

    def can_close(self, reason: str) -> bool:
        if reason != "user" or self._state.get("sync_succeeded"):
            return True
        if self._state.get("client") is None:
            return True
        return widgets.confirm(
            self,
            i18n.tr("关闭连接"),
            i18n.tr("连接仍在进行，关闭窗口将断开与传输站的连接，进度无法继续。确定要关闭吗？"),
            kind="warn",
        )

    def _finish_connection(self) -> None:
        self.poll_timer.stop()
        self.keepalive_timer.stop()
        self._state["stop"] = True
        if self._disconnect_now is not None:
            self._disconnect_now()
        self._state["client"] = None
        if self._window is not None:
            self.context.set_auto_lock_blocker("station", False)

    def close_page(self, reason: str) -> None:
        self._finish_connection()


def _embed_panel(page: EditorPage) -> None:
    """收起被内嵌页自带的页头与边距：页头由外层的三档页统一提供。"""
    header = getattr(page, "page_header", None)
    if header is not None:
        header.title.hide()
        header.subtitle.hide()
    layout = page.layout()
    if layout is not None:
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)


class LanWorkspacePage(EditorPage):
    """局域网：一页承载三档（建立传输站 / 局域网同步 / 文件传输）。

    对齐安卓端——同一页内用胶囊滑块切档，不跳页、不换标题；档位之间只替换下方内容。
    有设备正在同步/互传时滑块禁用（任务进行中不允许切档）。
    """

    HOST, SYNC, TRANSFER = 0, 1, 2
    #: 档位文案与安卓端一致；键用于 ``channel_changed`` 的自动跳档。
    GEARS = (
        ("host", "建立传输站"),
        ("sync", "局域网同步"),
        ("transfer", "文件传输"),
    )

    def __init__(self, context: LanPageContext, preset_gear: int | None = None, parent=None):
        super().__init__(parent)
        self.context = context
        self._window = context.window
        self.setObjectName("LanWorkspacePage")
        shell = page_shell(self, i18n.tr("局域网"))
        self.page_header = shell.header
        self.body = shell.content
        self.page_header.set_subtitle(i18n.tr("连接其他设备，或让其他设备连接本机：三档分别是本机开站、局域网同步与文件互传。"))

        self.slider = widgets.CapsuleSegmentedControl(
            [(key, i18n.tr(label)) for key, label in self.GEARS],
            current=self.SYNC,
        )
        self.slider.setAccessibleName(i18n.tr("局域网功能"))
        self.body.addWidget(self.slider)

        self.stack = QStackedWidget()
        self.stack.setObjectName("LanGearStack")
        self.station_page = LanStationPage(context)
        self.station_page.set_workspace(self)
        self.sync_page = LanConnectionPage(context, "sync")
        self.transfer_page = LanConnectionPage(context, "transfer")
        self.pages = (self.station_page, self.sync_page, self.transfer_page)
        for page in self.pages:
            # 连接方两页也要拿工作区引用：主机侧「关闭页面」经 _on_exit_host_session
            # 要回到 station 复原入口。缺了这一步，那条路径会 AttributeError 崩掉，
            # 表现就是点「关闭页面」毫无反应。
            page.set_workspace(self)
            _embed_panel(page)
            self.stack.addWidget(page)
        self.body.addWidget(self.stack, 1)

        self.slider.changed.connect(self._on_gear_changed)
        self.station_page.channel_changed.connect(self._on_station_channel)

        # 任务进行中禁用滑块：轮询与内部页一致（它们本身就以 300ms 轮询）。
        self._busy = False
        self.busy_timer = QTimer(self)
        self.busy_timer.setInterval(400)
        self.busy_timer.timeout.connect(self._refresh_busy_state)
        self.busy_timer.start()

        self.select_gear(self.SYNC if preset_gear is None else preset_gear, animate=False)

    # ---------- 档位 ----------
    def current_gear(self) -> int:
        return self.slider.current_index()

    def select_gear(self, index: int, *, animate: bool = True) -> None:
        index = max(0, min(len(self.pages) - 1, int(index)))
        self.stack.setCurrentIndex(index)
        self.slider.set_current_index(index, animate=animate, notify=False)
        self._refresh_busy_state()

    def _on_gear_changed(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        self._refresh_busy_state()

    def _on_station_channel(self, channel: str) -> None:
        """本机作传输站且被对端连接：跳到对应挡位，展示该通道的会话状态。

        传输站主页此时只保留「连接状态 + 关闭传输站」，同步状态、导出批准与传输
        记录分别挂到同步/文件传输挡位，避免同屏出现两份状态。
        """
        station = self.station_page
        if not station.is_busy():
            return
        if channel == "transfer":
            target, gear = self.transfer_page, self.TRANSFER
            panels = ("transfer",)
        else:
            target, gear = self.sync_page, self.SYNC
            panels = ("sync", "export")
        # 另一档位若曾进入主机模式，先恢复成连接方 UI。
        for page in (self.sync_page, self.transfer_page):
            if page is not target:
                page.exit_host_mode()
        station.attach_host_panels(target, panels)
        # 同步挡位改用会话卡片呈现状态，旧状态面板收起——同一屏两份进度会让人
        # 怀疑对不上。面板引用仍留着，同步完成后写摘要用。
        if gear == self.SYNC:
            legacy = (getattr(station, "_session_panels", None) or {}).get("sync")
            if legacy is not None:
                legacy.setVisible(False)
        target.enter_host_mode()
        station.set_host_status(i18n.tr("已连接，等待同步或传输…"))
        self.stack.setCurrentWidget(self.pages[gear])
        self.slider.set_current_index(gear, animate=False, notify=False)
        self._refresh_busy_state()

    def leave_transfer_view(self) -> None:
        """退出文件传输视图：面板收回传输站主页，挡位恢复连接方 UI。

        断开之后滑块虽然解锁了，但用户可能仍停在传输视图里；没有这个出口就得先
        切走再回来才能重新连接设备。
        """
        self.station_page.release_host_panels()
        for page in (self.sync_page, self.transfer_page):
            page.exit_host_mode()
        self._refresh_busy_state()

    def _clear_gear_notices(self) -> None:
        """会话结束：两个挡位的说明与收起状态一并复位。

        update_gear_notices 挂在传输站的轮询上，而收尾时轮询已经停了，不会再有
        下一拍来复位，所以必须在这里显式撤掉。
        """
        self.update_gear_notices("", active=False)

    def _on_station_disconnected(self) -> None:
        """会话结束：留在当前挡位，把状态改成已断开。

        不把面板收回、也不恢复连接方 UI——刚断开就把扫码入口摆回同一个挡位，
        会和「已断开」自相矛盾。传输站主页同时复位成可再次建立的样子。
        """
        self._clear_gear_notices()
        self._refresh_busy_state()

    def _on_station_closed(self) -> None:
        """用户主动关闭传输站：会话彻底结束，挡位恢复成连接方 UI。"""
        self._clear_gear_notices()
        self.station_page.release_host_panels()
        for page in (self.sync_page, self.transfer_page):
            page.exit_host_mode()
        self._refresh_busy_state()

    def show_station_result(self, stats: dict) -> None:
        """把同步结果放到同步挡位：状态面板 + 结果卡片。"""
        from .app import _lan_sync_result_rows, _lan_sync_result_summary

        station = self.station_page
        panel = (getattr(station, "_session_panels", None) or {}).get("sync")
        if panel is None:
            return
        summary = _lan_sync_result_summary(stats) if stats else i18n.tr("已完成")
        station.attach_host_panels(self.sync_page, ("sync", "export"), hide_entry=False)
        # 旧摘要行与结果卡是同一份数据，attach 会把面板重新显示出来，这里再收一次。
        panel.setVisible(False)
        self.sync_page.enter_host_mode()
        self.sync_page._show_sync_result(_lan_sync_result_rows(stats), summary)
        self._refresh_busy_state()

    def update_gear_notices(self, channel: str, *, active: bool, peer: dict | None = None) -> None:
        """按当前通道给「另一个挡位」挂上说明，并把它自己的内容收起来。

        切档是允许的，所以没在跑的那个挡位不能是一张可点的连接表单——那会让人
        以为能再连一台，或者在这里发起同步。统一显示「正在进行 X，不可进行其他操作」。
        """
        sync_page, transfer_page = self.sync_page, self.transfer_page
        if not active:
            for page in (sync_page, transfer_page):
                page.set_busy_notice("")
                page.set_peer_device(None)
                if not page._host_mode:
                    page.connect_view.setVisible(True)
                    page.status_label.setVisible(True)
                    page.sync_view.setVisible(False)
            return
        busy_label = i18n.tr("当前正在进行「文件传输」，不可进行其他操作") if channel == "transfer" else i18n.tr("当前正在进行局域网同步，不可进行其他操作")
        idle, busy = (transfer_page, sync_page) if channel == "transfer" else (sync_page, transfer_page)
        busy.set_busy_notice(busy_label)
        busy.connect_view.setVisible(False)
        busy.status_label.setVisible(False)
        busy.sync_view.setVisible(False)
        busy.set_peer_device(None)
        idle.set_busy_notice("")
        # 传输页只有一行对方设备文本；同步页的设备信息在会话视图的卡片里。
        idle.set_peer_device(peer if idle is self.transfer_page else None)

    def _refresh_busy_state(self) -> None:
        """会话进行中**不**锁滑块。

        早先按 station.is_busy() 锁过，结果用户被钉在当前挡位：既看不了别的通道，
        也没就地中断的入口。现在改成允许切档，由每个挡位自己说明「另一个通道正在
        进行 X，不可进行其他操作」，用户随时能过去看状态、也能就近退出。
        """
        self._busy = any(page.is_busy() for page in self.pages)
        self.slider.setEnabled(True)

    # ---------- 页面契约 ----------
    def can_close(self, reason: str) -> bool:
        for page in self.pages:
            if not page.can_close(reason):
                return False
        return True

    def close_page(self, reason: str) -> None:
        self.busy_timer.stop()
        for page in self.pages:
            page.close_page(reason)

    def refresh(self, context: object) -> None:
        for page in self.pages:
            refresh = getattr(page, "refresh", None)
            if callable(refresh):
                refresh(context)
