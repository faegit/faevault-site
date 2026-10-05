"""Embedded recycle bin and merge workflow pages for the editor workspace."""

from __future__ import annotations

import datetime
import time

from PySide6.QtCore import QEvent, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from core import config, modules
from core.models import Entry, SecretType

from . import i18n, theme, widgets
from .dialogs import ConfirmPasswordDialog, _MergeConflictDialog
from .smooth_scroll import enable_smooth_scroll
from .editor_workspace import EditorPage, page_shell
from .floating_actions import BottomFloatingAction, TranslucentActionButton, TranslucentPanel

_RECYCLE_SENSITIVE_TYPES = (SecretType.CARD_DOCUMENT, SecretType.API_KEY)


class _RecycleItemDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), 64)

    def paint(self, painter: QPainter, option, index) -> None:
        entry = index.data(Qt.UserRole)
        if entry is None:
            super().paint(painter, option, index)
            return

        c = theme.active()
        rect = option.rect.adjusted(4, 4, -4, -4)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing, True)
        bg = QColor(c["surface"])
        border = QColor(c["border"])
        border_width = 1
        if option.state & QStyle.State_Selected:
            bg = QColor(c["accent_soft"])
            border = QColor(c["accent"])
            border_width = 2
        pen = painter.pen()
        pen.setColor(border)
        pen.setWidth(border_width)
        painter.setPen(pen)
        painter.setBrush(bg)
        painter.drawRoundedRect(QRectF(rect).adjusted(1, 1, -1, -1), 8, 8)

        painter.drawPixmap(
            rect.left() + 12,
            rect.top() + 12,
            widgets.category_icon(entry.secret_type).pixmap(24, 24),
        )

        left = rect.left() + 48
        right = rect.right() - 12
        title_rect = QRectF(left, rect.top() + 8, right - left, 22)
        font = painter.font()
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor(c["text"]))
        title = painter.fontMetrics().elidedText(
            entry.title or i18n.tr("未命名"),
            Qt.ElideRight,
            int(title_rect.width()),
        )
        painter.drawText(title_rect, Qt.AlignLeft | Qt.AlignVCenter, title)

        font.setBold(False)
        painter.setFont(font)
        days_ago = RecycleBinPage._days_ago(entry.deleted_at)
        sub_rect = QRectF(left, rect.top() + 32, right - left, 22)
        painter.setPen(QColor(c["muted"]))
        painter.drawText(
            sub_rect,
            Qt.AlignLeft | Qt.AlignVCenter,
            i18n.tr_dynamic(f"删除于 {days_ago} 天前"),
        )
        painter.restore()


class RecycleBinPage(EditorPage):
    """回收站：恢复或彻底删除已被移入回收站的条目。"""

    def __init__(self, vault, on_purge_all=None, parent=None):
        super().__init__(parent)
        self.vault = vault
        self.on_purge_all = on_purge_all
        self.restore_occurred = False

        shell = page_shell(self, i18n.tr("回收站"))
        self.page_header = shell.header
        layout = shell.content

        days = int(
            config.get(
                "recycle_bin_retention_days",
                config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS,
            )
            or config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS
        )
        self.page_header.set_subtitle(
            i18n.tr_dynamic(f"超过 {days} 天的条目将被自动彻底删除。")
        )

        self.list_card = QWidget()
        self.list_card.setObjectName("RecycleListCard")
        list_card_lay = QVBoxLayout(self.list_card)
        list_card_lay.setContentsMargins(12, 12, 12, 12)
        list_card_lay.setSpacing(8)

        self.list = QListWidget()
        self._list_transition = widgets.ContentTransition(self.list.viewport())
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list.setFrameShape(QFrame.NoFrame)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list.setMinimumHeight(220)
        self.list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.list.setUniformItemSizes(True)
        enable_smooth_scroll(self.list)
        self.list.setItemDelegate(_RecycleItemDelegate(self.list))
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._show_context_menu)
        self.list.itemSelectionChanged.connect(self._update_batch_buttons)
        list_card_lay.addWidget(self.list, 1)

        self.empty_lbl = QLabel("回收站是空的")
        self.empty_lbl.setObjectName("Empty")
        self.empty_lbl.setAlignment(Qt.AlignCenter)
        self.empty_lbl.setMinimumHeight(120)
        list_card_lay.addWidget(self.empty_lbl)
        layout.addWidget(self.list_card, 1)

        self.clear_btn = TranslucentActionButton("清空回收站", self.list_card)
        self.clear_btn.setObjectName("FloatingDangerAction")
        self.clear_btn.setFixedHeight(48)
        self.clear_btn.clicked.connect(self._clear_all)

        self.batch_bar = TranslucentPanel(self.list_card)
        self.batch_bar.setObjectName("FloatingActionGroup")
        self.batch_bar.setFixedHeight(48)
        bar = QHBoxLayout(self.batch_bar)
        bar.setContentsMargins(4, 0, 4, 0)
        bar.setSpacing(0)
        self.select_all_btn = QPushButton("全选")
        self.select_all_btn.setObjectName("FloatingActionItem")
        self.select_all_btn.clicked.connect(self._toggle_all_selection)
        bar.addWidget(self.select_all_btn, 1)
        self.restore_btn = QPushButton("恢复")
        self.restore_btn.setObjectName("FloatingActionItem")
        self.restore_btn.setEnabled(False)
        self.restore_btn.clicked.connect(self._do_restore)
        bar.addWidget(self.restore_btn, 1)
        self.purge_btn = QPushButton("彻底删除")
        self.purge_btn.setObjectName("FloatingDangerItem")
        self.purge_btn.setEnabled(False)
        self.purge_btn.clicked.connect(self._do_purge)
        bar.addWidget(self.purge_btn, 1)
        self.list_card.installEventFilter(self)

        self._refresh()

    def refresh(self, context: object) -> None:
        if hasattr(context, "trash"):
            self.vault = context
        self._refresh()

    def _after_change(self, message: str = "") -> None:
        self.refresh(self.vault)
        self.vaultChanged.emit(self.vault)
        if message:
            self.statusMessage.emit(message)

    def _refresh(self) -> None:
        self.list.clear()
        trash = sorted(self.vault.trash, key=lambda e: e.deleted_at or 0, reverse=True)
        self.list.setVisible(bool(trash))
        self.empty_lbl.setVisible(not trash)
        if self.list.isVisible():
            self._list_transition.begin()
        self.clear_btn.setVisible(bool(trash))

        for entry in trash:
            item = QListWidgetItem()
            item.entry_id = entry.id
            item.setData(Qt.UserRole, entry)
            item.setSizeHint(QSize(self._recycle_item_width(), 64))
            self.list.addItem(item)

        self._update_batch_buttons()
        self._position_actions()

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if obj is self.list_card and event.type() in (QEvent.Resize, QEvent.Show):
            self._position_actions()
        return super().eventFilter(obj, event)

    def _position_actions(self) -> None:
        if not hasattr(self, "batch_bar"):
            return
        width = self.list_card.width()
        action_width = min(max(220, int(width * 0.5)), max(120, width - 32))
        x = max(16, (width - action_width) // 2)
        y = max(16, self.list_card.height() - 48 - 20)
        self.clear_btn.setGeometry(x, y, action_width, 48)
        self.batch_bar.setGeometry(x, y, action_width, 48)
        self.clear_btn.raise_()
        self.batch_bar.raise_()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "list"):
            width = self._recycle_item_width()
            for i in range(self.list.count()):
                self.list.item(i).setSizeHint(QSize(width, 64))

    def _recycle_item_width(self) -> int:
        viewport_width = self.list.viewport().width()
        if viewport_width <= 0:
            viewport_width = self.list.width()
        return max(320, viewport_width - 6)

    @staticmethod
    def _days_ago(deleted_at: float | None) -> int:
        if not deleted_at:
            return 0
        return max(0, int((time.time() - deleted_at) // 86400))

    def _confirm_password(self, title: str, text: str) -> bool:
        confirm = ConfirmPasswordDialog(
            self.vault.verify_password,
            title,
            text,
            confirm_text="确认",
            parent=self,
        )
        return confirm.exec() == QDialog.Accepted and confirm.unlocked

    def _restore(self, entry_id: str) -> None:
        self.vault.restore(entry_id)
        self.restore_occurred = True
        self._after_change("已从回收站恢复")

    def _selected_ids(self) -> list[str]:
        return [item.entry_id for item in self.list.selectedItems() if hasattr(item, "entry_id")]

    def _update_batch_buttons(self) -> None:
        selected = len(self._selected_ids())
        has_selection = selected > 0
        if hasattr(self, "restore_btn"):
            self.restore_btn.setEnabled(has_selection)
            self.purge_btn.setEnabled(has_selection)
            self.restore_btn.setText(f"恢复（{selected}）" if selected else "恢复")
            self.purge_btn.setText(f"彻底删除（{selected}）" if selected else "彻底删除")
            self.select_all_btn.setText("取消全选" if selected == self.list.count() and selected else "全选")
            has_trash = self.list.count() > 0
            self.batch_bar.setVisible(has_trash and has_selection)
            self.clear_btn.setVisible(has_trash and not has_selection)

    def _toggle_all_selection(self) -> None:
        if len(self.list.selectedItems()) == self.list.count():
            self.list.clearSelection()
        else:
            self.list.selectAll()

    def _show_context_menu(self, pos) -> None:
        item = self.list.itemAt(pos)
        if not item or not hasattr(item, "entry_id"):
            return

        items = self.list.selectedItems()
        entry_items = [i for i in items if hasattr(i, "entry_id")]

        if item not in entry_items:
            self.list.clearSelection()
            item.setSelected(True)
            entry_items = [item]

        menu = QMenu(self)
        if len(entry_items) == 1:
            _eid = item.entry_id
            menu.addAction("恢复").triggered.connect(lambda: self._restore_one(_eid))
            menu.addAction("彻底删除").triggered.connect(lambda: self._purge_one(_eid))
        else:
            _ids = [i.entry_id for i in entry_items]
            menu.addAction(f"恢复（{len(_ids)}）").triggered.connect(lambda: self._restore_ids(_ids))
            menu.addAction(f"彻底删除（{len(_ids)}）").triggered.connect(lambda: self._purge_ids(_ids))
        menu.exec(self.list.viewport().mapToGlobal(pos))

    def _restore_one(self, entry_id: str) -> None:
        self.vault.restore(entry_id)
        self.restore_occurred = True
        self._after_change("已从回收站恢复")

    def _restore_ids(self, ids: list[str]) -> None:
        restored = self.vault.restore_many(ids)
        if restored:
            self.restore_occurred = True
        self._after_change("已从回收站恢复" if restored else "")

    def _do_restore(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        self._restore_ids(ids)

    def _purge_ids(self, ids: list[str]) -> None:
        selected_entries = [e for e in self.vault.trash if e.id in set(ids)]
        n = len(selected_entries)
        if n == 0:
            return
        label = "彻底删除" if len(ids) == 1 else f"批量彻底删除（{n} 条）"
        if not widgets.confirm(
            self,
            label,
            f"确定{'彻底删除' if len(ids) == 1 else '彻底删除选中的'}「{selected_entries[0].title}」{'等条目' if len(ids) > 1 else ''}吗？此操作不可恢复。",
            kind="error",
        ):
            return
        if any(e.secret_type in _RECYCLE_SENSITIVE_TYPES for e in selected_entries):
            if not self._confirm_password(label, f"{'彻底删除' if len(ids) == 1 else '彻底删除选中的条目'}需要验证当前主密码。"):
                return
        self.vault.purge_many(ids)
        self._after_change()

    def _do_purge(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        self._purge_ids(ids)

    def _purge_one(self, entry_id: str) -> None:
        entry = next((e for e in self.vault.trash if e.id == entry_id), None)
        if entry is None:
            return
        if not widgets.confirm(self, "彻底删除", f"确定彻底删除「{entry.title}」吗？此操作不可恢复。", kind="error"):
            return
        if entry.secret_type in _RECYCLE_SENSITIVE_TYPES:
            if not self._confirm_password("彻底删除", "彻底删除该条目需要验证当前主密码。"):
                return
        self.vault.purge(entry_id)
        self._after_change()

    def _clear_all(self) -> None:
        n = len(self.vault.trash)
        if n == 0:
            return
        if not widgets.confirm(self, "清空回收站", f"确定清空回收站吗？全部 {n} 个条目将被彻底删除，无法恢复。", kind="error"):
            return
        if any(e.secret_type in _RECYCLE_SENSITIVE_TYPES for e in self.vault.trash):
            if not self._confirm_password("清空回收站", "清空回收站需要验证当前主密码。"):
                return
        self.vault.purge_all()
        self._after_change()
        if self.on_purge_all is not None:
            # 批量清空后立即回收追加写死空间；逐条彻底删除不触发，避免反复重写整库。
            self.on_purge_all()

    def close_page(self, reason: str) -> None:
        pass

    def can_close(self, reason: str) -> bool:
        return True


def _distinct_field_values(entries: list[Entry], field_name: str) -> tuple[list[str] | None, dict[str, Entry]]:
    """Collect distinct values, most-recent-entry first.

    Returns (values, {value: most_recent_entry_with_value}).
    Returns (None, {}) if all entries have blank/empty values for this field.
    """
    sorted_entries = sorted(entries, key=lambda e: e.updated_at, reverse=True)
    seen: set[str] = set()
    values: list[str] = []
    val_entry: dict[str, Entry] = {}
    has_blank = False
    for e in sorted_entries:
        v = _get_entry_field(e, field_name)
        if not v:
            has_blank = True
        elif v not in seen:
            seen.add(v)
            values.append(v)
            val_entry[v] = e
    if not values:
        return None, {}
    if has_blank:
        values.append("")
        for e in sorted_entries:
            if not _get_entry_field(e, field_name):
                val_entry[""] = e
                break
    return values, val_entry


def _get_entry_field(entry: Entry, field_name: str) -> str:
    if field_name == "password":
        return entry.password
    if field_name == "notes":
        return entry.notes
    return getattr(entry, field_name, "")


class _CompareFieldCard(QWidget):
    """One field's distinct-value comparison block inside the dedup compare page."""

    def __init__(self, entries: list[Entry], field_name: str, label: str, chosen: dict[str, str], parent=None):
        super().__init__(parent)
        self._field_name = field_name
        self._distinct, self._distinct_entry = _distinct_field_values(entries, field_name)
        self._values = self._distinct

        card = QFrame()
        card.setObjectName("ModuleCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 12, 12, 12)
        card_layout.setSpacing(6)

        field_label = QLabel(label)
        field_label.setObjectName("FieldLabel")
        card_layout.addWidget(field_label)

        if self._values is None:
            val_lbl = QLabel("（空）")
            val_lbl.setObjectName("SettingNote")
            card_layout.addWidget(val_lbl)
            chosen[field_name] = ""
        elif len(self._values) == 1:
            display = self._values[0] if self._values[0] else "（空）"
            if field_name == "password" and display and display != "（空）":
                display = "•" * min(len(display), 12)
            val_lbl = QLabel(display)
            val_lbl.setWordWrap(True)
            val_lbl.setObjectName("SettingNote")
            card_layout.addWidget(val_lbl)
            chosen[field_name] = self._values[0] if self._values[0] else ""
        else:
            bg = QButtonGroup(self)
            bg.setExclusive(True)
            val_to_entry = self._distinct_entry or {}

            for idx, val in enumerate(self._values):
                entry_for_val = val_to_entry.get(val, entries[0])
                ts = datetime.datetime.fromtimestamp(entry_for_val.updated_at).strftime("%Y-%m-%d %H:%M")
                row = QHBoxLayout()
                row.setSpacing(8)

                rb = QRadioButton()
                rb.setChecked(idx == 0)
                bg.addButton(rb, idx)
                row.addWidget(rb)

                if field_name == "password":
                    pw_edit = QLineEdit(val if val else "（空）")
                    pw_edit.setEchoMode(QLineEdit.Password if val else QLineEdit.Normal)
                    pw_edit.setReadOnly(True)
                    reveal = widgets.set_button_icon(QPushButton(), "view", size=18)
                    reveal.setObjectName("RevealIconBtn")
                    reveal.setCheckable(True)
                    reveal.setFixedSize(44, 34)
                    reveal.setToolTip("显示或隐藏")
                    reveal.toggled.connect(lambda on, f=pw_edit: f.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
                    row.addWidget(pw_edit, 1)
                    row.addWidget(reveal)
                else:
                    val_display = val if val else "（空）"
                    val_lbl = QLabel(val_display)
                    val_lbl.setWordWrap(True)
                    row.addWidget(val_lbl, 1)

                ts_lbl = QLabel(ts)
                ts_lbl.setObjectName("FieldLabel")
                ts_lbl.setFixedWidth(120)
                ts_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                row.addWidget(ts_lbl)

                card_layout.addLayout(row)

            chosen[field_name] = self._values[0] if self._values[0] else ""

            def on_radio_toggled(fn: str, group: QButtonGroup):
                def _on(checked: bool, _g=group, _fn=fn):
                    if checked:
                        idx = _g.checkedId()
                        vals = self._values or []
                        if 0 <= idx < len(vals):
                            chosen[_fn] = vals[idx] if vals[idx] else ""

                return _on

            for rb in bg.buttons():
                rb.toggled.connect(on_radio_toggled(field_name, bg))

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)


class DedupPage(EditorPage):
    """展示所有重复组，逐组对比后统一合并（对齐 Android）。"""

    mergeRequested = Signal(object)

    def __init__(self, groups: list[list], parent=None):
        super().__init__(parent)
        self.groups = groups
        self.pending_results: dict[int, tuple[list[Entry], dict[str, str]]] = {}
        self._status_labels: dict[int, QLabel] = {}
        self._card_frames: dict[int, QFrame] = {}
        self._confirm_btn: QPushButton | None = None
        self._current_idx = 0

        # 头部挂在根布局上：两个子页的 _clear_layout 会反复重建各自内容，
        # 头部放在子页里会被一起清掉。
        shell = page_shell(self, i18n.tr("重复条目对比"))
        self.page_header = shell.header

        self.stack = QStackedWidget(self)
        self.list_page = QWidget()
        self.list_layout = QVBoxLayout(self.list_page)
        self.list_layout.setContentsMargins(0, 0, 0, 0)
        self.compare_page = QWidget()
        self.compare_layout = QVBoxLayout(self.compare_page)
        self.compare_layout.setContentsMargins(0, 0, 0, 0)
        self.stack.addWidget(self.list_page)
        self.stack.addWidget(self.compare_page)
        shell.content.addWidget(self.stack, 1)

        self._rebuild_list()

    def reset(self, groups: list[list]) -> None:
        self.groups = groups
        self.pending_results = {}
        self._rebuild_list()
        self.stack.setCurrentWidget(self.list_page)

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _rebuild_list(self) -> None:
        self._clear_layout(self.list_layout)
        groups = self.groups

        self.page_header.set_subtitle(
            i18n.tr_dynamic(
                f"检测到 {len(groups)} 组重复条目。点击分组可对比并选择要保留的字段值。"
            )
        )

        scroll = QScrollArea()
        enable_smooth_scroll(scroll)
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        for idx, group in enumerate(groups):
            card = QFrame()
            card.setObjectName("ModuleCard")
            card.setCursor(Qt.PointingHandCursor)
            self._card_frames[idx] = card
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 12, 12, 12)
            card_layout.setSpacing(6)

            header_row = QHBoxLayout()
            header_row.setSpacing(8)
            winner = group[0]
            title = QLabel(winner.title or "未命名条目")
            title.setObjectName("FieldLabel")
            header_row.addWidget(title, 1)

            status = QLabel("待处理")
            status.setObjectName("SettingNote")
            header_row.addWidget(status)
            self._status_labels[idx] = status

            card_layout.addLayout(header_row)

            for index, entry in enumerate(group):
                ts = datetime.datetime.fromtimestamp(entry.updated_at).strftime("%Y-%m-%d %H:%M")
                package = entry.target_app or modules.target_app_value(entry.fields) or "无关联包名"
                row = QLabel(
                    f"{'保留' if index == 0 else '合并'} · {entry.username or '无账号'} · {ts}\n包名：{package} · 密码：{'已设置' if entry.password else '空'}"
                )
                row.setWordWrap(True)
                card_layout.addWidget(row)

            layout.addWidget(card)

            def make_card_click(card_idx: int, grp: list):
                def _on_click(_e=None):
                    self._open_group_compare(card_idx, grp)

                card.mousePressEvent = _on_click
                for child in card.findChildren(QWidget):
                    if child is not card:
                        child.mousePressEvent = _on_click

            make_card_click(idx, group)

        layout.addStretch()
        scroll.setWidget(content)
        self.list_layout.addWidget(scroll, 1)

        self._confirm_btn = BottomFloatingAction(f"确认合并 (0/{len(groups)})", scroll)
        self._confirm_btn.setObjectName("FloatingPrimaryAction")
        self._confirm_btn.setEnabled(False)
        self._confirm_btn.clicked.connect(lambda: self.mergeRequested.emit(dict(self.pending_results)))
        self._confirm_btn._position()
        self._confirm_btn.show()

    def _open_group_compare(self, idx: int, group: list) -> None:
        self._current_idx = idx
        self._current_group = group
        self._build_compare(group, idx)
        self.stack.setCurrentWidget(self.compare_page)

    def _build_compare(self, group: list, index: int) -> None:
        self._clear_layout(self.compare_layout)
        chosen: dict[str, str] = {}

        head = QLabel(f"「{group[0].title or '未命名条目'} · {group[0].username or '—'}」")
        head.setObjectName("Empty")
        head.setWordWrap(True)
        self.compare_layout.addWidget(head)

        if len(self.groups) > 1:
            prog = QLabel(f"第 {index + 1} / {len(self.groups)} 组")
            prog.setObjectName("FieldLabel")
            self.compare_layout.addWidget(prog)

        scroll = QScrollArea()
        enable_smooth_scroll(scroll)
        scroll.setWidgetResizable(True)
        content = QWidget()
        fields_layout = QVBoxLayout(content)
        fields_layout.setContentsMargins(0, 0, 0, 0)
        fields_layout.setSpacing(8)

        for field_name, label in (
            ("title", "标题"),
            ("username", "用户名"),
            ("password", "密码"),
            ("url", "网址"),
            ("notes", "备注"),
        ):
            card = _CompareFieldCard(group, field_name, label, chosen)
            fields_layout.addWidget(card)

        fields_layout.addStretch()
        scroll.setWidget(content)
        self.compare_layout.addWidget(scroll, 1)

        bar = QHBoxLayout()
        skip_btn = QPushButton("跳过")
        skip_btn.setAutoDefault(False)
        skip_btn.clicked.connect(self._skip_group)
        confirm_btn = QPushButton("确认合并")
        confirm_btn.setObjectName("Primary")
        confirm_btn.setAutoDefault(False)
        confirm_btn.clicked.connect(lambda: self._confirm_group(group, chosen))
        bar.addWidget(skip_btn)
        bar.addStretch()
        bar.addWidget(confirm_btn)
        self.compare_layout.addLayout(bar)

    def _skip_group(self) -> None:
        idx = self._current_idx
        self.pending_results.pop(idx, None)
        self._status_labels[idx].setText("已跳过")
        self._status_labels[idx].setObjectName("")
        self._status_labels[idx].setStyleSheet("color: #9CA3AF;")
        self._update_confirm_btn()
        self.stack.setCurrentWidget(self.list_page)

    def _confirm_group(self, group: list, chosen: dict[str, str]) -> None:
        idx = self._current_idx
        self.pending_results[idx] = (group, dict(chosen))
        self._status_labels[idx].setText("已确认")
        self._status_labels[idx].setObjectName("")
        self._status_labels[idx].setStyleSheet("color: #2FA84F; font-weight: 600;")
        self._update_confirm_btn()
        self.stack.setCurrentWidget(self.list_page)

    def _update_confirm_btn(self) -> None:
        count = len(self.pending_results)
        self._confirm_btn.setText(f"确认合并 ({count}/{len(self.groups)})")
        self._confirm_btn.setEnabled(count > 0)

    def can_close(self, reason: str) -> bool:
        return reason != "user" or not self.pending_results or widgets.confirm(self, "放弃合并", "尚未提交的字段选择将丢失。确定关闭吗？", kind="warn")

    def close_page(self, reason: str) -> None:
        self.pending_results = {}


class SameServicePage(EditorPage):
    """按域名/包名分组的同服务条目手动合并（对齐 Android）。"""

    mergeRequested = Signal(object, object)

    def __init__(self, groups: list, parent=None):
        super().__init__(parent)
        self.groups = groups
        self._checkboxes: dict[str, QCheckBox] = {}
        self._group_entries: dict[str, list[Entry]] = {}
        self._merge_btn: QPushButton | None = None

        # _clear_body 会反复重建内容区，头部挂在根布局上不受影响。
        shell = page_shell(self, i18n.tr("相同服务处理"))
        self.page_header = shell.header
        self.page_header.set_subtitle(
            i18n.tr("按网址或包名分组。点击分组标题可整组选中，点击条目可查看详情。")
        )
        self._body_layout = shell.content

        self._rebuild()

    def reset(self, groups: list) -> None:
        self.groups = groups
        self._rebuild()

    def _clear_body(self) -> None:
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def request_entry(self, entry_id: str) -> None:
        self.entryRequested.emit(entry_id)

    def _rebuild(self) -> None:
        self._clear_body()
        groups = self.groups
        self._checkboxes = {}
        self._group_entries = {}

        scroll = QScrollArea()
        enable_smooth_scroll(scroll)
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        for group in groups:
            key = group.service_key
            entries = group.entries
            self._group_entries[key] = entries

            card = QFrame()
            card.setObjectName("ModuleCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 12, 12, 12)
            card_layout.setSpacing(6)

            header = QLabel(f"{key}（{len(entries)} 条）")
            header.setObjectName("FieldLabel")
            header.setCursor(Qt.PointingHandCursor)
            group_ids = {e.id for e in entries}

            def make_header_click(hdr: QLabel, gids: set[str]):
                def _toggle(_e=None):
                    any_selected = any(self._checkboxes[eid].isChecked() for eid in gids if eid in self._checkboxes)
                    for eid, cb in self._checkboxes.items():
                        if eid not in gids:
                            cb.setChecked(False)
                    for eid in gids:
                        cb = self._checkboxes.get(eid)
                        if cb:
                            cb.setChecked(not any_selected)

                hdr.mousePressEvent = _toggle

            make_header_click(header, group_ids)
            card_layout.addWidget(header)

            for entry in entries:
                row_widget = QWidget()
                row_widget.setCursor(Qt.PointingHandCursor)
                row = QHBoxLayout(row_widget)
                row.setContentsMargins(0, 0, 0, 0)
                row.setSpacing(8)

                cb = QCheckBox()
                self._checkboxes[entry.id] = cb
                row.addWidget(cb)

                ts = datetime.datetime.fromtimestamp(entry.updated_at).strftime("%Y-%m-%d %H:%M")
                info = QLabel(f"{entry.title or '未命名条目'} · {entry.username or '无账号'} · {ts}")
                info.setWordWrap(True)
                row.addWidget(info, 1)

                card_layout.addWidget(row_widget)

                eid = entry.id

                def _click(_e=None, _id=eid):
                    self.request_entry(_id)

                row_widget.mousePressEvent = _click
                for i in range(row.count()):
                    w = row.itemAt(i).widget()
                    if w and w != cb:
                        w.mousePressEvent = _click

            layout.addWidget(card)

        layout.addStretch()
        scroll.setWidget(content)
        self._body_layout.addWidget(scroll, 1)

        self._merge_btn = BottomFloatingAction("合并选中的 0 条", scroll)
        self._merge_btn.setObjectName("FloatingPrimaryAction")
        self._merge_btn.setEnabled(False)
        self._merge_btn.clicked.connect(self._on_merge)

        for cb in self._checkboxes.values():
            cb.toggled.connect(self._update_merge_btn)

        self._merge_btn._position()
        self._merge_btn.show()

    def _update_merge_btn(self) -> None:
        count = sum(1 for cb in self._checkboxes.values() if cb.isChecked())
        self._merge_btn.setText(f"合并选中的 {count} 条")
        self._merge_btn.setEnabled(count >= 2)

    def _on_merge(self) -> None:
        selected_ids = [eid for eid, cb in self._checkboxes.items() if cb.isChecked()]
        if len(selected_ids) < 2:
            return

        all_entries: list[Entry] = []
        for entries in self._group_entries.values():
            for e in entries:
                if e.id in selected_ids:
                    all_entries.append(e)
        if len(all_entries) < 2:
            return

        titles = sorted({e.title for e in all_entries if e.title}, reverse=True)
        passwords = sorted({e.password for e in all_entries if e.password}, reverse=True)
        usernames = sorted({e.username for e in all_entries if e.username}, reverse=True)

        if len(titles) <= 1 and len(passwords) <= 1 and len(usernames) <= 1:
            chosen = {
                "title": titles[0] if titles else "",
                "username": usernames[0] if usernames else "",
                "password": passwords[0] if passwords else "",
            }
            self.mergeRequested.emit(all_entries, chosen)
            return

        conflict = _MergeConflictDialog(
            titles or [""],
            usernames or [""],
            passwords or [""],
            parent=self,
        )
        if conflict.exec() != QDialog.Accepted:
            return
        self.mergeRequested.emit(all_entries, conflict.chosen)

    def can_close(self, reason: str) -> bool:
        return True

    def close_page(self, reason: str) -> None:
        pass
