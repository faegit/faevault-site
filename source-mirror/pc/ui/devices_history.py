"""Local device activity and encrypted, selective history recovery workspace."""
from __future__ import annotations

import datetime
import threading

from PySide6.QtCore import QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (QApplication, QAbstractItemView, QInputDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton)

from core import device_activity
from core.storage import Vault
from . import i18n
from .editor_workspace import EditorPage, page_shell

_WORKERS = set()  # Workers must outlive a closing workspace until secrets are cleared.


def preview_rows(preview):
    """Only non-secret active entry identifiers, titles and usernames cross to Qt."""
    return [{"id": entry.id, "title": entry.title, "username": entry.username}
            for entry in preview.entries if entry.deleted_at is None]


def _finished_worker(worker):
    _WORKERS.discard(worker)
    worker.deleteLater()


class HistoryWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)
    passwordRequired = Signal()

    def __init__(self, vault, action, generation, *, snapshot_id="", entry_ids=(),
                 name="", historical_password=None, expected_head=None):
        super().__init__(QApplication.instance())
        self.path = vault.path
        self.password = vault._password.clone()
        self.root_key = None
        if self.password.is_empty():
            from core.crypto import SecureString
            key = bytearray(vault.root_key_for_device_unlock())
            try:
                self.root_key = SecureString.from_utf8(key)
            finally:
                key[:] = bytes(len(key))
        self.expected_identity = vault.pmve_identity
        self.expected_head = bytes.fromhex(expected_head) if isinstance(expected_head, str) else (expected_head or self.expected_identity.root_digest)
        self.action, self.generation = action, generation
        self.snapshot_id, self.entry_ids, self.name = snapshot_id, tuple(entry_ids), name
        self.historical_password = historical_password
        self.cancelled = threading.Event()

    def run(self):
        from core.vault_history import HistoryStore, HistoricalPasswordRequired
        vault = None
        try:
            if self.cancelled.is_set():
                return
            if self.root_key is not None:
                with self.root_key.bytes() as key:
                    vault = Vault.open_with_root_key(self.path, bytes(key))
            else:
                with self.password.bytes() as password:
                    vault = Vault.open_with_password_buffer(self.path, password)
            if self.cancelled.is_set():
                return
            store = HistoryStore(vault)
            if self.action in ("restore", "rename") and vault.pmve_identity.root_digest != self.expected_head:
                raise RuntimeError(i18n.tr("保险库已变化，请刷新后重试。"))
            if self.action == "capture":
                store.capture()
                result = {"versions": store.list(), "devices": device_activity.devices(vault)}
            elif self.action == "load":
                result = {"versions": store.list(), "devices": device_activity.devices(vault)}
            elif self.action in ("preview", "restore"):
                historical = self.historical_password
                with historical.bytes() if historical is not None else _NoPassword() as old_password:
                    preview = store.preview(self.snapshot_id, password=old_password)
                try:
                    if self.cancelled.is_set():
                        return
                    if self.action == "preview":
                        result = {"rows": preview_rows(preview), "snapshot_id": self.snapshot_id, "expected_head": preview.current_head.hex()}
                    else:
                        if self.cancelled.is_set():
                            return
                        store.restore(preview, self.entry_ids, is_cancelled=self.cancelled.is_set)
                        result = {"adopt": True}
                finally:
                    preview.close()
            elif self.action == "rename":
                if self.cancelled.is_set():
                    return
                device_activity.rename(vault, self.name)
                result = {"adopt": True}
            else:
                raise ValueError("Unknown history action")
            if not self.cancelled.is_set():
                self.completed.emit(result)
        except HistoricalPasswordRequired:
            if not self.cancelled.is_set():
                self.passwordRequired.emit()
        except Exception as error:
            if not self.cancelled.is_set():
                self.failed.emit(str(error))
        finally:
            if vault is not None:
                vault.close()
            self.password.clear()
            if self.root_key is not None:
                self.root_key.clear()
            if self.historical_password is not None:
                self.historical_password.clear()


class _NoPassword:
    def __enter__(self):
        return None

    def __exit__(self, *_):
        return False


def _time(value):
    if not value:
        return i18n.tr("未知")
    value = float(value)
    import math
    if not math.isfinite(value) or value < 0 or value > 253402300799000:
        return i18n.tr("未知")
    if value > 100_000_000_000:
        value /= 1000
    return datetime.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


class DevicesHistoryPage(EditorPage):
    restoreRequested = Signal()

    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self._generation = 0
        self._closed = False
        self._worker = None
        self._snapshot_id = ""
        self._preview_head = None
        self._historical_password = None
        shell = page_shell(self, i18n.tr("设备与历史"))
        self.page_header = shell.header
        self.page_header.set_subtitle(i18n.tr("本地保留20个常规加密版本及恢复前安全版本，无需配置云端同步。"))
        self.refresh_button = QPushButton(i18n.tr("刷新"))
        shell.header.add_action(self.refresh_button)
        self.refresh_button.clicked.connect(lambda: self.refresh(self.vault))
        self.devices_list = QListWidget()
        self.devices_list.setMaximumHeight(160)
        shell.content.addWidget(QLabel(i18n.tr("设备")))
        shell.content.addWidget(self.devices_list)
        self.rename_button = QPushButton(i18n.tr("重命名本机"))
        self.rename_button.clicked.connect(self._rename)
        shell.content.addWidget(self.rename_button)
        note = QLabel(i18n.tr("授权状态来自保险库现有记录；此处不能撤销其他设备的云端访问权限。"))
        note.setWordWrap(True)
        shell.content.addWidget(note)
        shell.content.addWidget(QLabel(i18n.tr("历史版本")))
        shell.content.addWidget(QLabel(i18n.tr("历史恢复暂不支持通行密钥和已永久删除的条目")))
        self.versions_list = QListWidget()
        shell.content.addWidget(self.versions_list, 1)
        self.capture_button = QPushButton(i18n.tr("保存当前版本"))
        self.capture_button.clicked.connect(lambda: self._start("capture"))
        shell.content.addWidget(self.capture_button)
        self.preview_button = QPushButton(i18n.tr("预览所选版本"))
        self.preview_button.clicked.connect(self._preview)
        shell.content.addWidget(self.preview_button)
        self.entries_list = QListWidget()
        self.entries_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        shell.content.addWidget(self.entries_list, 1)
        self.restore_button = QPushButton(i18n.tr("恢复所选条目"))
        self.restore_button.clicked.connect(self._restore)
        shell.content.addWidget(self.restore_button)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        shell.content.addWidget(self.status)
        self.versions_list.currentItemChanged.connect(self._version_changed)
        self.entries_list.itemSelectionChanged.connect(self._buttons)
        self.refresh(vault)

    def _buttons(self):
        idle = self._worker is None and not self._closed
        for button in (self.refresh_button, self.capture_button, self.rename_button):
            button.setEnabled(idle)
        self.preview_button.setEnabled(idle and self.versions_list.currentItem() is not None)
        self.restore_button.setEnabled(idle and bool(self._snapshot_id) and bool(self.entries_list.selectedItems()))

    def _clear_preview(self):
        self.entries_list.clear()
        self._snapshot_id = ""
        self._preview_head = None
        if self._historical_password is not None:
            self._historical_password.clear()
            self._historical_password = None

    def _version_changed(self, *_):
        self._clear_preview()
        self._buttons()

    def refresh(self, vault):
        if self._closed:
            return
        self.vault = vault
        if self._worker is not None:
            self._worker.cancelled.set()
        self._generation += 1
        self._worker = None
        self._clear_preview()
        self._start("load")

    def _start(self, action, **kwargs):
        if self._closed or self._worker is not None:
            return
        worker = HistoryWorker(self.vault, action, self._generation, **kwargs)
        self._worker = worker
        _WORKERS.add(worker)
        worker.completed.connect(self._completed)
        worker.failed.connect(self._failed)
        worker.passwordRequired.connect(self._password_required)
        worker.finished.connect(lambda w=worker: _finished_worker(w))
        self.status.setText(i18n.tr("正在处理…"))
        self._buttons()
        worker.start()

    def _current_sender(self):
        worker = self.sender()
        return worker if not self._closed and worker is self._worker and worker.generation == self._generation else None

    @Slot(object)
    def _completed(self, result):
        worker = self._current_sender()
        if worker is None:
            return
        self._worker = None
        if result.get("adopt"):
            self._clear_preview()
            self.restoreRequested.emit()
            self.statusMessage.emit(i18n.tr("保险库已更新。"))
            return
        if "devices" in result:
            self.devices_list.clear()
            for profile in result["devices"]:
                current = i18n.tr("本机") if profile["is_current"] else profile["platform"]
                authorized = i18n.tr("已授权") if profile["authorized"] else i18n.tr("无有效授权记录")
                self.devices_list.addItem(f"{i18n.tr(profile['name'])} · {current} · {authorized} · {_time(profile['last_seen_at'])}")
            self.versions_list.clear()
            for version in result["versions"]:
                writer = version.get("writer_name") or i18n.tr("未知设备")
                item = QListWidgetItem(f"{_time(version['created_at'])} · {version.get('size_bytes', 0)} B · {writer}")
                item.setData(Qt.UserRole, version["snapshot_id"])
                self.versions_list.addItem(item)
        if "rows" in result:
            self.entries_list.clear()
            self._snapshot_id = result["snapshot_id"]
            self._preview_head = result.get("expected_head")
            for row in result["rows"]:
                item = QListWidgetItem(f"{row['title'] or i18n.tr('未命名')} · {row['username']}")
                item.setData(Qt.UserRole, row["id"])
                self.entries_list.addItem(item)
        self.status.setText(i18n.tr("操作完成。"))
        self._buttons()

    @Slot(str)
    def _failed(self, message):
        if self._current_sender() is None:
            return
        self._worker = None
        self.status.setText(i18n.tr("操作失败，请刷新后重试。") + "\n" + i18n.tr(message))
        self._buttons()

    @Slot()
    def _password_required(self):
        worker = self._current_sender()
        if worker is None:
            return
        self._worker = None
        self._buttons()
        password, accepted = QInputDialog.getText(self, i18n.tr("历史版本密码"),
            i18n.tr("此版本使用旧主密码，请输入以解密。"), QLineEdit.Password)
        if accepted:
            from core.crypto import SecureString
            secret = SecureString(password)
            password = ""
            self._start(worker.action, snapshot_id=worker.snapshot_id, entry_ids=worker.entry_ids,
                        historical_password=secret, expected_head=worker.expected_head)

    def _preview(self):
        item = self.versions_list.currentItem()
        if item is not None:
            self._clear_preview()
            self._start("preview", snapshot_id=item.data(Qt.UserRole))

    def _restore(self):
        ids = [item.data(Qt.UserRole) for item in self.entries_list.selectedItems()]
        if not ids or not self._snapshot_id:
            return
        answer = QMessageBox.question(self, i18n.tr("恢复所选条目"),
            i18n.tr("将以历史内容更新所选条目，保留其他当前条目。恢复前自动保存当前版本，并创建新提交。"))
        if answer == QMessageBox.Yes:
            self._start("restore", snapshot_id=self._snapshot_id, entry_ids=ids, expected_head=self._preview_head)

    def _rename(self):
        name, accepted = QInputDialog.getText(self, i18n.tr("重命名本机"), i18n.tr("设备名称（1–64 个字符）"))
        if accepted and name.strip():
            self._start("rename", name=name)

    def close_page(self, reason):
        self._closed = True
        self._generation += 1
        if self._worker is not None:
            self._worker.cancelled.set()
        self._clear_preview()
