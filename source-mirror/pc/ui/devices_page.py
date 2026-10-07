"""Read-only authenticated device activity workspace."""
import datetime
import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QListWidget, QPushButton

from core import device_activity
from . import i18n
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
        shell = page_shell(self, i18n.tr("设备记录"))
        self.page_header = shell.header
        self.page_header.set_subtitle(i18n.tr("设备名称自动使用系统设置中的名称。"))
        self.refresh_button = QPushButton(i18n.tr("刷新"))
        shell.header.add_action(self.refresh_button)
        self.refresh_button.clicked.connect(lambda: self.refresh(self.vault))
        self.devices_list = QListWidget()
        shell.content.addWidget(self.devices_list, 1)
        note = QLabel(i18n.tr("授权状态来自保险库现有记录；此处不能撤销其他设备的云端访问权限。"))
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
                self.devices_list.addItem(f"{profile['name']} · {current} · {authorized} · {_time(profile['last_seen_at'])}")
            self.status.setText(i18n.tr("操作完成。"))
        except Exception as error:
            self.status.setText(i18n.tr("操作失败，请刷新后重试。") + "\n" + i18n.tr(str(error)))

    def close_page(self, reason):
        self._closed = True
