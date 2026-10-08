"""Authenticated device activity and signed revocation workspace."""
import datetime
import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QListWidget, QListWidgetItem, QPushButton

from core import device_activity
from . import i18n, widgets
from .editor_workspace import EditorPage, page_shell


def _time(value):
    if not value:
        return i18n.tr("未知")
    value = float(value)
    if not math.isfinite(value) or value < 0 or value > 253402300799000:
        return i18n.tr("未知")
    if value > 100_000_000_000:
        value /= 1000
    return datetime.datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


class DevicesPage(EditorPage):
    def __init__(self, vault, parent=None):
        super().__init__(parent)
        self.vault = vault
        self._closed = False
        self._busy = False
        shell = page_shell(self, i18n.tr("设备记录"))
        self.page_header = shell.header
        self.page_header.set_subtitle(i18n.tr("设备名称自动使用系统设置中的名称。"))
        self.refresh_button = QPushButton(i18n.tr("刷新"))
        shell.header.add_action(self.refresh_button)
        self.refresh_button.clicked.connect(lambda: self.refresh(self.vault))
        self.devices_list = QListWidget()
        shell.content.addWidget(self.devices_list, 1)
        self.remove_button = QPushButton(i18n.tr("删除设备记录"))
        self.remove_button.clicked.connect(self._remove_selected)
        self.devices_list.currentItemChanged.connect(self._update_remove_button)
        shell.content.addWidget(self.remove_button)
        note = QLabel(i18n.tr("删除会撤销此设备的应用同步授权；不会删除任何设备的保险库文件，也不会撤销云服务凭据。"))
        note.setWordWrap(True)
        shell.content.addWidget(note)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        shell.content.addWidget(self.status)
        QApplication.instance().applicationStateChanged.connect(self._application_state_changed)
        self.refresh(vault)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh(self.vault)

    def _application_state_changed(self, state):
        if state == Qt.ApplicationActive and self.isVisible():
            self.refresh(self.vault)

    def refresh(self, vault):
        if self._closed:
            return
        self.vault = vault
        self.devices_list.clear()
        try:
            for profile in device_activity.devices(vault):
                current = i18n.tr("本机") if profile["is_current"] else profile["platform"]
                authorized = i18n.tr("已授权") if profile["authorized"] else i18n.tr("无有效授权记录")
                item = QListWidgetItem(f"{profile['name']} · {current} · {authorized} · {_time(profile['last_seen_at'])}")
                item.setData(Qt.UserRole, profile.get("device_id"))
                item.setData(Qt.UserRole + 1, profile["is_current"])
                self.devices_list.addItem(item)
            self.status.setText(i18n.tr("操作完成。"))
        except Exception as error:
            self.status.setText(i18n.tr("操作失败，请刷新后重试。") + "\n" + i18n.tr(str(error)))

        self._update_remove_button()

    def _update_remove_button(self, *_):
        item = self.devices_list.currentItem()
        self.remove_button.setEnabled(not self._closed and not self._busy and item is not None
                                      and bool(item.data(Qt.UserRole)) and not item.data(Qt.UserRole + 1))

    def _remove_selected(self):
        item = self.devices_list.currentItem()
        if self._closed or self._busy or item is None or item.data(Qt.UserRole + 1):
            return
        target = item.data(Qt.UserRole)
        if not target:
            return
        vault = self.vault
        store = getattr(vault, "_pmve_store", None)
        vault_id = getattr(getattr(store, "identity", None), "vault_id", None)
        self._busy = True
        self._update_remove_button()
        self.refresh_button.setEnabled(False)
        try:
            confirmed = widgets.confirm(self, "删除设备记录", "确定删除所选设备记录并撤销其应用同步授权吗？保险库文件和云服务凭据将保留。", kind="warn")
            if not confirmed or self._closed or self.vault is not vault or getattr(vault, "_pmve_store", None) is not store or store is None:
                return
            if getattr(getattr(store, "identity", None), "vault_id", None) != vault_id:
                return
            vault.remove_device_record(target)
            if not self._closed:
                self.refresh(vault)
                self.status.setText(i18n.tr("设备记录已删除，应用同步授权已撤销。"))
        except Exception as error:
            if not self._closed:
                self.status.setText(i18n.tr("操作失败，请刷新后重试。") + "\n" + i18n.tr(str(error)))
        finally:
            self._busy = False
            self.refresh_button.setEnabled(not self._closed)
            self._update_remove_button()

    def close_page(self, reason):
        self._closed = True
        self.refresh_button.setEnabled(False)
        self._update_remove_button()
