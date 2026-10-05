"""云端同步页面的纯 UI 组件。

布局对齐安卓端“云端同步”卡片：
总开关 → 目标切换 → 状态行（阶段）→ 预览摘要 → 主操作（重新检测 / 同步 / 更多操作）。
同步、合并和认证仍由主窗口负责；本模块只定义稳定、可复用的页面结构。
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QLabel,
    QMenu,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from . import widgets
from .editor_workspace import page_shell


@dataclass(slots=True)
class CloudTargetControls:
    page: QWidget
    layout: QVBoxLayout
    status: QLabel  # 健康状态：● 关联正常 / 关联异常
    phase: QLabel  # 阶段状态行：● 正在同步到云端硬盘…
    preview: QLabel  # 结构化预览摘要
    progress: QProgressBar
    check: QPushButton  # 重新检测
    sync: QPushButton  # 同步
    more: QPushButton  # 更多操作 ▼
    menu: QMenu  # Keep the menu and its actions alive with the target view.
    relate: QPushButton  # 关联（未关联时显示）
    overwrite_action: QAction
    download_action: QAction
    relate_action: QAction
    clear_action: QAction
    auto_anchor: QWidget
    path: QLabel | None = None


class CloudSyncPage(QWidget):
    """双目标云同步页面，不包含任何传输业务逻辑。"""

    targetChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("CloudSyncPage")

        shell = page_shell(self, "云端同步")
        self.page_header = shell.header
        self.page_header.set_subtitle("同步会在后台合并并校验数据，切换或关闭此页不影响任务。")
        root = shell.content

        # 总开关（对齐安卓：默认关闭，开启需主密码门禁与风险确认）。
        master = QFrame()
        master.setObjectName("CloudMasterSwitch")
        master_layout = QVBoxLayout(master)
        master_layout.setContentsMargins(12, 10, 12, 10)
        master_layout.setSpacing(4)
        self.master_toggle = QCheckBox("启用联网同步")
        master_layout.addWidget(self.master_toggle)
        self.master_hint = QLabel("默认关闭；开启后可关联云端硬盘或 WebDAV，并按需启用自动同步。")
        self.master_hint.setObjectName("SettingNote")
        self.master_hint.setWordWrap(True)
        master_layout.addWidget(self.master_hint)
        root.addWidget(master)

        # 总开关关闭时整块内容隐藏（仅保留开关本身）。
        self.content = QWidget()
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        self.notice = QLabel()
        self.notice.setObjectName("CloudInlineNotice")
        self.notice.setWordWrap(True)
        self.notice.setTextFormat(Qt.PlainText)
        self.notice.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.notice.hide()
        root.addWidget(self.notice)

        switch = widgets.CapsuleSegmentedControl(
            [("drive", "云端硬盘"), ("webdav", "WebDAV")],
            current=0,
        )
        switch.setObjectName("CloudTargetSwitch")
        switch.setAccessibleName("云端同步目标")
        self.target_switch = switch
        content_layout.addWidget(switch)

        self.stack = QStackedWidget()
        self.drive = self._build_target("云端硬盘", "选择云盘客户端的同步目录。保险库始终以加密文件形式保存。", "关联云端硬盘", include_path=True)
        self.webdav = self._build_target("WebDAV", "连接支持 WebDAV 的 NAS 或云服务。凭据仅保存在当前设备。", "关联 WebDAV", include_path=True)
        # Separate scroll areas prevent the hidden WebDAV form from forcing a
        # large minimum height and an empty scrollbar on the shorter drive page.
        self._target_scrolls = []
        for target in (self.drive, self.webdav):
            scroll = QScrollArea()
            scroll.setObjectName("CloudContentScroll")
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            scroll.setWidget(target.page)
            self._target_scrolls.append(scroll)
            self.stack.addWidget(scroll)
        content_layout.addWidget(self.stack, 1)
        root.addWidget(self.content, 1)

        self.target_switch.changed.connect(self._on_target_changed)

    @property
    def scroll(self) -> QScrollArea:
        return self._target_scrolls[self.stack.currentIndex()]

    def _on_target_changed(self, index: int) -> None:
        self._select_target(index)

    def select_target(self, index: int, *, animate: bool = True) -> None:
        """静默切档：只移动 thumb 与内容，不向外发 ``targetChanged``。"""
        self.target_switch.set_current_index(index, animate=animate, notify=False)
        self._select_target(index)

    def _select_target(self, index: int) -> None:
        self.scroll.verticalScrollBar().setValue(0)
        self.stack.setCurrentIndex(index)
        self.scroll.verticalScrollBar().setValue(0)
        self.targetChanged.emit(index)

    @staticmethod
    def _build_target(
        title: str,
        description: str,
        relate_text: str,
        *,
        include_path: bool = False,
    ) -> CloudTargetControls:
        page = QWidget()
        page.setObjectName("CloudPanel")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        heading = QLabel(title)
        heading.setObjectName("CloudSectionTitle")
        layout.addWidget(heading)
        note = QLabel(description)
        note.setObjectName("SettingNote")
        note.setWordWrap(True)
        layout.addWidget(note)

        # 依序：健康状态 → 阶段状态行 → 预览摘要 → 路径 → 进度 → 主操作。
        status = QLabel()
        status.setObjectName("CloudStatus")
        status.setWordWrap(True)
        layout.addWidget(status)

        phase = QLabel()
        phase.setObjectName("CloudPhaseStatus")
        phase.setWordWrap(True)
        layout.addWidget(phase)

        preview = QLabel("等待检测远端数据")
        preview.setObjectName("CloudResult")
        preview.setWordWrap(True)
        preview.setTextFormat(Qt.PlainText)
        preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(preview)

        path = QLabel() if include_path else None
        if path is not None:
            path.setObjectName("CloudPath")
            path.setWordWrap(True)
            path.setTextFormat(Qt.PlainText)
            path.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(path)

        progress = QProgressBar()
        progress.setRange(0, 0)
        progress.setAccessibleName(f"{title}同步进度")
        progress.hide()
        layout.addWidget(progress)

        relate = QPushButton(relate_text)
        relate.setAccessibleName(f"{relate_text}")
        layout.addWidget(relate)

        check = QPushButton("重新检测")
        check.setAccessibleName(f"重新检测{title}")

        sync = QPushButton("同步")
        sync.setObjectName("Primary")
        sync.setAccessibleName(f"同步到{title}")

        # 破坏性操作收进“更多操作”菜单，避免与主操作并排误触。
        more = QPushButton("更多操作")
        more.setObjectName("CloudMoreButton")
        more.setAccessibleName(f"{title}更多操作")
        menu = QMenu(more)
        # Explicit actions avoid temporary wrappers created by addAction(text)
        # while the global translator handles menu layout events.
        overwrite_action = QAction("上传覆盖", menu)
        download_action = QAction("下载覆盖本地", menu)
        menu.addAction(overwrite_action)
        menu.addAction(download_action)
        menu.addSeparator()
        relate_action = QAction("重新关联", menu)
        clear_action = QAction("取消关联", menu)
        menu.addAction(relate_action)
        menu.addAction(clear_action)
        more.setMenu(menu)
        layout.addWidget(sync)
        layout.addWidget(check)
        layout.addWidget(more)

        # 自动同步设置块在更多操作之后插入。
        auto_anchor = QWidget()
        auto_anchor.setFixedHeight(0)
        auto_anchor.setAccessibleName(f"{title}自动同步设置位置")
        layout.addWidget(auto_anchor)
        layout.addStretch()

        return CloudTargetControls(
            page=page,
            layout=layout,
            status=status,
            phase=phase,
            preview=preview,
            progress=progress,
            check=check,
            sync=sync,
            more=more,
            menu=menu,
            relate=relate,
            overwrite_action=overwrite_action,
            download_action=download_action,
            relate_action=relate_action,
            clear_action=clear_action,
            auto_anchor=auto_anchor,
            path=path,
        )
