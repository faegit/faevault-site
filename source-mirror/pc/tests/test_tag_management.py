"""Current-category tag ordering and rename dialogs."""

import os

import pytest
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QAbstractItemView
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest

from ui import app as app_ui
from ui.dialogs import BatchTagInputDialog, TagRenameDialog, TagSortDialog


def test_sort_mouse_drag_in_row_gap_matches_marker_and_preserves_content():
    app = QApplication.instance() or QApplication([])
    dialog = TagSortDialog(["first", "second", "third", "fourth"])
    dialog.show()
    app.processEvents()
    view = dialog.tag_list
    first = view.visualItemRect(view.item(0))
    second = view.visualItemRect(view.item(1))
    third = view.visualItemRect(view.item(2))
    gap = QPoint(second.center().x(), (second.bottom() + third.top() + 1) // 2)
    assert view.itemAt(gap) is None
    assert view._row_at(gap) == 2
    QTest.mousePress(view.viewport(), Qt.LeftButton, pos=first.center())
    QTest.mouseMove(view.viewport(), gap)
    assert view._dragging
    assert view._insert_row == 2
    assert second.bottom() < view._indicator_y(2) < third.top()
    QTest.mouseRelease(view.viewport(), Qt.LeftButton, pos=gap)
    assert [view.item(i).text() for i in range(view.count())] == ["second", "first", "third", "fourth"]
    assert view._insert_row is None
    # Move the same item back upward, using the upper half of the first row.
    source = view.visualItemRect(view.item(1)).center()
    target = view.visualItemRect(view.item(0)).topLeft() + QPoint(10, 2)
    QTest.mousePress(view.viewport(), Qt.LeftButton, pos=source)
    QTest.mouseMove(view.viewport(), target)
    assert view._insert_row == 0
    QTest.mouseRelease(view.viewport(), Qt.LeftButton, pos=target)
    assert [view.item(i).text() for i in range(view.count())] == ["first", "second", "third", "fourth"]
    dialog.close()


def test_sort_cancel_drag_and_self_drop_keep_tags():
    app = QApplication.instance() or QApplication([])
    dialog = TagSortDialog(["first", "second", "third"])
    dialog.show()
    app.processEvents()
    view = dialog.tag_list
    rect = view.visualItemRect(view.item(1))
    QTest.mousePress(view.viewport(), Qt.LeftButton, pos=rect.center())
    QTest.mouseMove(view.viewport(), rect.topLeft() + QPoint(10, 2))
    assert view._insert_row is None
    QTest.mouseRelease(view.viewport(), Qt.LeftButton, pos=rect.topLeft() + QPoint(10, 2))
    QTest.mousePress(view.viewport(), Qt.LeftButton, pos=rect.center())
    QTest.mouseMove(view.viewport(), view.visualItemRect(view.item(0)).topLeft() + QPoint(10, 2))
    QTest.keyClick(view, Qt.Key_Escape)
    QTest.mouseRelease(view.viewport(), Qt.LeftButton, pos=QPoint(10, 2))
    assert [view.item(i).text() for i in range(view.count())] == ["first", "second", "third"]
    assert not view._scroll_timer.isActive()
    dialog.close()


def test_sort_drag_scrolls_long_list_and_outside_release_cancels():
    app = QApplication.instance() or QApplication([])
    tags = [str(i) for i in range(30)]
    dialog = TagSortDialog(tags)
    dialog.show()
    app.processEvents()
    view = dialog.tag_list
    QTest.mousePress(view.viewport(), Qt.LeftButton, pos=view.visualItemRect(view.item(0)).center())
    QTest.mouseMove(view.viewport(), QPoint(30, view.viewport().height() - 4))
    QTest.qWait(100)
    assert view.verticalScrollBar().value() > 0
    assert view._insert_row == view._row_at(view._pointer_pos)
    QTest.mouseRelease(view.viewport(), Qt.LeftButton, pos=QPoint(-10, 30))
    assert [view.item(i).text() for i in range(view.count())] == tags
    assert not view._scroll_timer.isActive()
    dialog.close()


def test_tag_sort_dialog_moves_only_the_dragged_item():
    QApplication.instance() or QApplication([])
    dialog = TagSortDialog(["工作", "苹果", "私人"])
    tag_list = dialog.tag_list
    tag_list._dragged_item = tag_list.item(1)
    for target in (1, 2):
        tag_list._move_dragged_item(target)
        assert [tag_list.item(i).text() for i in range(tag_list.count())] == ["工作", "苹果", "私人"]
    tag_list._move_dragged_item(3)
    dialog.accept()
    assert dialog.ordered_tags == ["工作", "私人", "苹果"]
    assert tag_list.count() == 3
    dialog.close()


def test_tag_rename_dialog_filters_and_preserves_choice():
    QApplication.instance() or QApplication([])
    dialog = TagRenameDialog(["工作", "苹果", "私人"])
    assert dialog.tag_list.dragDropMode() == QAbstractItemView.NoDragDrop
    dialog.filter_edit.setText("pingguo")
    assert [dialog.tag_list.item(i).text() for i in range(dialog.tag_list.count())] == ["苹果"]
    dialog.new_name.setText("水果")
    dialog.accept()
    assert (dialog.old_tag, dialog.new_tag) == ("苹果", "水果")
    dialog.close()


def test_tag_order_is_scoped_to_current_category(monkeypatch):
    saved = {"login": ["工作", "私人"], "wifi": ["家庭"]}
    monkeypatch.setattr(app_ui.config, "get", lambda key, default=None: saved if key == "tag_order_by_type" else default)
    host = SimpleNamespace(_active_type="login")
    assert app_ui.MainWindow._ordered_tags_for_type(host, {"私人", "新标签", "工作"}) == [
        "工作", "私人", "新标签"
    ]
    host._active_type = "wifi"
    assert app_ui.MainWindow._ordered_tags_for_type(host, {"家庭", "公司"}) == ["家庭", "公司"]


def test_tag_order_save_keeps_other_categories(monkeypatch):
    saved = {"login": ["工作", "私人"], "wifi": ["家庭"]}
    writes = []
    monkeypatch.setattr(app_ui.config, "get", lambda key, default=None: saved if key == "tag_order_by_type" else default)
    monkeypatch.setattr(app_ui.config, "set", lambda key, value: writes.append((key, value)))
    host = SimpleNamespace(_active_type="login", _last_tag_state=True, _rebuild_tag_chips=lambda: None)
    app_ui.MainWindow._save_tag_order(host, ["私人", "工作"])
    assert writes == [("tag_order_by_type", {"login": ["私人", "工作"], "wifi": ["家庭"]})]
    assert host._last_tag_state is None


def test_rename_keeps_selected_tag():
    QApplication.instance() or QApplication([])
    dialog = TagRenameDialog(["工作", "私人"])
    dialog.tag_list.setCurrentRow(1)
    dialog.new_name.setText("家庭")
    dialog.accept()
    assert (dialog.old_tag, dialog.new_tag) == ("私人", "家庭")
    dialog.close()


def test_batch_tag_picker_only_shows_selected_category_and_allows_multiple_additions():
    QApplication.instance() or QApplication([])
    entries = [
        SimpleNamespace(secret_type="login", tags=["工作", "私人"]),
        SimpleNamespace(secret_type="wifi", tags=["家庭"]),
    ]
    parent = app_ui.QWidget()
    parent.vault = SimpleNamespace(entries=entries)
    dialog = BatchTagInputDialog("添加标签", "选择标签", parent, category="login", mode="add")
    assert set(dialog._tag_buttons) == {"工作", "私人"}
    dialog._pick_tag("工作")
    dialog._pick_tag("私人")
    dialog.tag_input.setText(dialog.tag_input.text() + "，新标签")
    dialog.accept()
    assert dialog.tags == ["工作", "私人", "新标签"]
    dialog.close()
    parent.close()


def test_batch_move_tag_picker_keeps_single_target():
    QApplication.instance() or QApplication([])
    parent = app_ui.QWidget()
    parent.vault = SimpleNamespace(entries=[SimpleNamespace(secret_type="wifi", tags=["家庭"])])
    dialog = BatchTagInputDialog("移入标签", "选择标签", parent, category="wifi", mode="move")
    assert set(dialog._tag_buttons) == {"家庭"}
    dialog._pick_tag("家庭")
    dialog.accept()
    assert dialog.tags == ["家庭"]
    dialog.close()
    parent.close()


@pytest.mark.parametrize("secret_type", ["login", "passkey"])
def test_batch_add_applies_every_selected_tag(monkeypatch, secret_type):
    entries = [SimpleNamespace(id="one", secret_type=secret_type), SimpleNamespace(id="two", secret_type=secret_type)]
    metadata = {"one": {"tags": ["工作"]}, "two": {"tags": []}}
    saved = []
    vault = SimpleNamespace(_entry_meta=metadata, save=lambda: saved.append(True))
    host = SimpleNamespace(vault=vault, reload=lambda: None, _flash=lambda message: None)

    class AcceptedDialog:
        tags = ["工作", "私人"]

        def __init__(self, *_args, **_kwargs):
            pass

        def exec(self):
            return app_ui.QDialog.Accepted

    monkeypatch.setattr(app_ui, "BatchTagInputDialog", AcceptedDialog)
    app_ui.MainWindow._batch_add_tag(host, entries)
    assert metadata["one"]["tags"] == ["工作", "私人"]
    assert metadata["two"]["tags"] == ["工作", "私人"]
    assert len(saved) == 1


@pytest.mark.parametrize("count", [1, 2])
def test_passkey_context_menu_exposes_tag_actions(monkeypatch, count):
    QApplication.instance() or QApplication([])
    from core.models import Entry, SecretType

    entries = [Entry(title=f"Passkey {index}", secret_type=SecretType.PASSKEY) for index in range(count)]
    items = [app_ui.EntryListItem(entry, leaked=False) for entry in entries]
    captured = []

    class Menu:
        def __init__(self, *_args):
            pass

        def addAction(self, text):
            captured.append(text)
            return SimpleNamespace(triggered=SimpleNamespace(connect=lambda callback: None))

        def addSeparator(self):
            pass

        def exec(self, *_args):
            pass

    host = SimpleNamespace(
        _active_type=SecretType.PASSKEY,
        list=SimpleNamespace(itemAt=lambda pos: items[0], selectedItems=lambda: items,
                             viewport=lambda: SimpleNamespace(mapToGlobal=lambda pos: pos)),
        edit_entry=lambda: None, delete_entry=lambda: None,
        _batch_delete=lambda items: None, _batch_add_tag=lambda entries: None,
        _batch_move_tag=lambda entries: None,
    )
    monkeypatch.setattr(app_ui, "QMenu", Menu)
    app_ui.MainWindow._show_context_menu(host, QPoint())
    assert any("添加标签" in text for text in captured)
    assert any("移入标签" in text for text in captured)
    assert "编辑" not in captured
