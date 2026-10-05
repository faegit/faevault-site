"""Cancelling entry creation must preserve the existing list and detail selection."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QAbstractItemView, QListWidget
from ui import app as app_module


@pytest.mark.parametrize("show_type_selector", [True, False])
def test_cancel_new_entry_preserves_selection_and_detail(monkeypatch, show_type_selector):
    qt_app = QApplication.instance() or QApplication([])
    view = QListWidget()
    view.setSelectionMode(QAbstractItemView.ExtendedSelection)
    view.addItems(["First", "Second", "Third"])
    view.setCurrentRow(1)
    view.item(0).setSelected(True)
    selected = list(view.selectedItems())
    detail_changes = []
    view.currentItemChanged.connect(lambda current, previous: detail_changes.append(current))
    released = []

    class CancelledDialog:
        def __init__(self, **kwargs):
            pass
        def exec(self):
            return 0
        def deleteLater(self):
            released.append(True)

    monkeypatch.setattr(app_module, "EntryDialog", CancelledDialog)
    window = SimpleNamespace(list=view)
    app_module.MainWindow.add_entry(window, "login", show_type_selector=show_type_selector)
    assert view.currentItem() is view.item(1)
    assert view.selectedItems() == selected
    assert detail_changes == [], "取消新增不应触发详情清空或重新加载"
    assert released == [True]
    view.close()
