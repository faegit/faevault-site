"""Tabbed workspace for the fixed entry detail and feature editor pages."""

from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QStackedWidget, QTabBar, QVBoxLayout, QWidget

from . import i18n


class EditorTabBar(QTabBar):
    """编辑器标签栏。

    选中标签使用内容背景色，与下方内容连成一片，不绘制底部或竖向分割线。
    """

    def tabSizeHint(self, index):
        size = super().tabSizeHint(index)
        size.setWidth(max(128, size.width()))
        return size

    def minimumTabSizeHint(self, index):
        # Preserve readable labels; overflow uses the tab bar's scroll buttons.
        return self.tabSizeHint(index)

# 编辑器功能页统一的内容边距：所有嵌入式页面共用同一条安全边距。
PAGE_MARGINS = (20, 20, 20, 20)

# 页面骨架的默认行距，与安全中心保持一致。
PAGE_SPACING = 12

# 条目详情页统一模板：标题卡、关联自动填充卡与字段内容的内边距/行距都从这里取，
# 详情页内部不再各写各的字面量（对齐功能页统一走 PAGE_MARGINS 的做法）。
#: 详情页卡片（标题卡 / 关联自动填充卡）的外框内边距。
DETAIL_CARD_MARGINS = (12, 12, 12, 12)
#: 详情页卡片内部的列容器不加内边距，只靠行距分隔。
DETAIL_COLUMN_MARGINS = (0, 0, 0, 0)
#: 排版节奏「近」：同一块内标题与其内容贴紧，标题属于内容的一部分。
DETAIL_FIELD_SPACING = 3
#: 排版节奏「远」：块与块之间留白，上一个标题与下一个标题明显分开。
DETAIL_BLOCK_SPACING = 12
#: 内容行内元素（复制、显示/隐藏按钮）之间的行距。
DETAIL_FIELD_ROW_SPACING = 6


class PageHeader:
    """功能页统一头部：大标题 + 可选小标题 + 标题行右侧的页面级操作。"""

    def __init__(self, title: str = "") -> None:
        self.row = QHBoxLayout()
        self.row.setSpacing(8)
        self.title = QLabel(title)
        self.title.setObjectName("WorkspacePageTitle")
        self.row.addWidget(self.title, 1)
        self.subtitle = QLabel()
        self.subtitle.setObjectName("SettingNote")
        self.subtitle.setWordWrap(True)
        self.subtitle.hide()

    def add_action(self, widget: QWidget) -> QWidget:
        """把非破坏性的页面级操作放到标题行右侧。"""
        self.row.addWidget(widget)
        return widget

    def set_title(self, text: str) -> None:
        self.title.setText(text)

    def set_subtitle(self, text: str) -> None:
        """空文案表示该页没有小标题，不占高度。"""
        self.subtitle.setText(text)
        self.subtitle.setVisible(bool(text))


class PageShell(NamedTuple):
    root: QVBoxLayout
    header: PageHeader
    content: QVBoxLayout


def page_shell(
    page: QWidget, title: str = "", *, spacing: int = PAGE_SPACING,
    compact: bool = False,
) -> PageShell:
    """按安全中心模板搭页面骨架：大标题、小标题、内容区。

    骨架不翻译文案：静态文案由调用方走 i18n.tr，含运行期数值的走 i18n.tr_dynamic。
    """
    root = QVBoxLayout(page)
    root.setContentsMargins(*PAGE_MARGINS)
    root.setSpacing(spacing)
    header = PageHeader(title)
    root.addLayout(header.row)
    root.addWidget(header.subtitle)
    content = QVBoxLayout()
    content.setContentsMargins(0, 0, 0, 0)
    content.setSpacing(spacing)
    root.addLayout(content, 0 if compact else 1)
    if compact:
        root.addStretch(1)
    return PageShell(root, header, content)


class EditorPage(QWidget):
    """Lifecycle contract shared by embeddable workspace feature pages."""

    entryRequested = Signal(str)
    vaultChanged = Signal(object)
    statusMessage = Signal(str)
    finished = Signal(str)

    def can_close(self, reason: str) -> bool:
        return True

    def close_page(self, reason: str) -> None:
        pass

    def refresh(self, context: object) -> None:
        pass

    def set_page_title(self, title: str) -> None:
        """由工作区把标签页标题灌进页面头部，保证大标题与标签名一致。"""
        header = getattr(self, "page_header", None)
        if header is not None:
            header.set_title(title)


class EditorWorkspace(QWidget):
    """Host a permanent detail page alongside closeable feature pages."""

    currentChanged = Signal(str)

    def __init__(
        self,
        detail_page: QWidget,
        *,
        detail_title: str = "条目详情",
        parent=None,
    ):
        super().__init__(parent)
        self._keys: list[str] = ["detail"]
        self._pages: dict[str, QWidget] = {"detail": detail_page}

        self.tabs = EditorTabBar(self)
        self.tabs.setObjectName("EditorTabBar")
        self.tabs.setMovable(False)
        self.tabs.setExpanding(False)
        self.tabs.setElideMode(Qt.ElideRight)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setTabsClosable(True)
        self.tabs.addTab(detail_title)
        self.tabs.setTabButton(0, QTabBar.ButtonPosition.LeftSide, None)
        self.tabs.setTabButton(0, QTabBar.ButtonPosition.RightSide, None)

        self.stack = QStackedWidget(self)
        self.stack.addWidget(detail_page)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        # 标题栏与内容直接衔接，不绘制分割线。
        layout.addWidget(self.tabs)
        layout.addWidget(self.stack, 1)
        self.tabs.currentChanged.connect(self._activate_index)
        self.tabs.tabCloseRequested.connect(self._request_close_index)

    def page_keys(self) -> tuple[str, ...]:
        return tuple(self._keys)

    def current_key(self) -> str:
        return self._keys[self.tabs.currentIndex()]

    def page(self, key: str) -> QWidget | None:
        return self._pages.get(key)

    def show_detail(self) -> None:
        self.tabs.setCurrentIndex(0)

    def open_page(
        self,
        key: str,
        title: str,
        factory: Callable[[], QWidget],
    ) -> QWidget:
        existing = self._pages.get(key)
        if existing is not None:
            self.tabs.setCurrentIndex(self._keys.index(key))
            return existing

        page = factory()
        self._keys.append(key)
        self._pages[key] = page
        self.stack.addWidget(page)
        self.tabs.addTab(title)
        self._refresh_close_name(len(self._keys) - 1)
        self.tabs.setCurrentIndex(len(self._keys) - 1)
        return page

    def _refresh_close_name(self, index: int) -> None:
        """功能标签的关闭按钮提供无障碍名称，随标签标题更新。"""
        button = self.tabs.tabButton(index, QTabBar.ButtonPosition.RightSide)
        if button is not None:
            button.setAccessibleName(f"{i18n.tr('关闭标签')}：{self.tabs.tabText(index)}")

    def request_close(self, key: str, reason: str = "user") -> bool:
        if key == "detail" or key not in self._pages:
            return False
        page = self._pages[key]
        can_close = getattr(page, "can_close", None)
        if callable(can_close) and not can_close(reason):
            return False

        index = self._keys.index(key)
        close_page = getattr(page, "close_page", None)
        if callable(close_page):
            close_page(reason)

        signals_were_blocked = self.tabs.blockSignals(True)
        try:
            self.tabs.removeTab(index)
            self.stack.removeWidget(page)
            self._keys.pop(index)
            self._pages.pop(key)
        finally:
            self.tabs.blockSignals(signals_were_blocked)

        # removeTab 已把当前标签落到左侧邻居（关闭活动页）或在原位保留（关闭非活动页），
        # 但页面栈的当前索引可能仍指向被移除页。仅当可见页面与标签栏不一致时才强制同步，
        # 避免对未变化的页面重复发放 currentChanged 信号。
        current_index = self.tabs.currentIndex()
        current_widget = self.stack.currentWidget()
        if 0 <= current_index < len(self._keys) and current_widget is not self._pages[self._keys[current_index]]:
            self._activate_index(current_index)
        page.deleteLater()
        return True

    def close_all_pages(self, reason: str) -> None:
        for key in tuple(self._keys[1:]):
            self.request_close(key, reason)

    def _request_close_index(self, index: int) -> None:
        if 0 <= index < len(self._keys):
            self.request_close(self._keys[index])

    def _activate_index(self, index: int) -> None:
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)
            self.currentChanged.emit(self._keys[index])
