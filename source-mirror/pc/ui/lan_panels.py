"""局域网同步 / 文件传输的共享页面组件。

无论 PC 作为传输站（主机）还是连接方（客户端），同步状态页与文件传输页都
复用这里的同一套组件与渲染逻辑，避免在多个窗口里重复定义。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PySide6.QtCore import QMimeData, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import i18n


def _transfer_parent_directory(record: dict) -> str:
    """Return the user-facing parent directory without exposing staging paths."""
    if record.get("direction") == "发送" and record.get("kind") == "text":
        return ""
    raw_path = record.get("source_path") if record.get("direction") == "发送" else record.get("path")
    if not raw_path:
        raw_path = record.get("path")
    return str(Path(str(raw_path)).parent) if raw_path else ""


def _paste_clipboard_image(status_label, send) -> None:
    """读取系统剪贴板图片并作为 PNG 通过传输连接发送。"""
    clipboard = QApplication.clipboard()
    image = clipboard.image()
    if image.isNull():
        if status_label is not None:
            status_label.setText(i18n.tr("剪贴板中没有可发送的图片"))
        return
    descriptor, name = tempfile.mkstemp(prefix="vault-paste-", suffix=".png")
    os.close(descriptor)
    temp = Path(name)
    try:
        image.save(str(temp), "PNG")
        send(temp)
    except Exception as error:
        if status_label is not None:
            status_label.setText(i18n.tr("发送失败：") + str(error))
    finally:
        temp.unlink(missing_ok=True)


def _clipboard_local_files(mime) -> list[str]:
    """从剪贴板 MIME 数据中提取本地文件路径（资源管理器/桌面复制、剪切）。

    仅返回真实存在的普通文件；链接、网络 URL、文件夹会被忽略，由调用方决定回退行为。
    """
    if mime is None or not mime.hasUrls():
        return []
    paths: list[str] = []
    for url in mime.urls():
        local = url.toLocalFile()
        if not local:
            continue
        path = Path(local)
        if path.is_file():
            paths.append(str(path))
    return paths


class _TransferTextEdit(QTextEdit):
    """发送内容输入框：文本输入；粘贴剪贴板图片或资源管理器文件时直接发送（与安卓对齐）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._on_image_paste = None
        self._on_files_paste = None
        self._on_enter = None

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                # Shift+Enter 换行
                super().keyPressEvent(event)
            elif self._on_enter is not None:
                # Enter 直接发送；输入法组词确认由输入法吞掉该按键，不会误触发。
                self._on_enter()
                event.accept()
            else:
                super().keyPressEvent(event)
            return
        super().keyPressEvent(event)

    def _handle_mime(self, mime: QMimeData) -> bool:
        """文件/图片优先直接发送；返回 True 表示已处理，不再作为文本插入。"""
        files = _clipboard_local_files(mime)
        if not files:
            # 部分程序把文件复制为纯文本路径（file:///…）：若指向真实存在的文件，
            # 同样按文件发送，而不是把路径字符串当文本发出去。
            text = str(mime.text() or "").strip()
            if text.startswith("file://"):
                local = QUrl(text).toLocalFile()
                if local and Path(local).is_file():
                    files = [str(Path(local))]
        if files and self._on_files_paste is not None:
            self._on_files_paste(files)
            return True
        if mime.hasImage() and self._on_image_paste is not None:
            self._on_image_paste()
            return True
        return False

    def paste(self):
        clipboard = QApplication.clipboard()
        if self._handle_mime(clipboard.mimeData()):
            return
        image = clipboard.image()
        if not image.isNull() and self._on_image_paste is not None:
            self._on_image_paste()
            return
        super().paste()

    def insertFromMimeData(self, source):
        # 拖拽文件/右键粘贴同样拦截：发送文件本体，而不是插入 file:// 文本。
        if self._handle_mime(source):
            return
        super().insertFromMimeData(source)


class LanSyncStatusPanel(QWidget):
    """同步状态页：验证 / 接收 / 发送的真实进度与状态（主机与连接方共用）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self._status = QLabel("")
        self._status.setAlignment(Qt.AlignCenter)
        self._status.setWordWrap(True)
        self._status.setStyleSheet("color: #2563EB; font-size: 12px;")
        layout.addWidget(self._status)
        self._progress = QProgressBar()
        self._progress.setObjectName("TransferProgress")
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(True)
        self._progress.setFormat("")
        self._progress.setVisible(False)
        self._progress.setMaximumHeight(16)
        layout.addWidget(self._progress)

    def update_status(
        self,
        phase: str = "idle",
        *,
        send_progress: tuple[int, int] | None = None,
        receive_progress: tuple[int, int] | None = None,
        connected: bool = False,
        transfer_active: bool = False,
    ) -> None:
        if phase == "sending":
            sent, total = send_progress or (0, 0)
            pct = min(100, max(0, sent * 100 // total)) if total else 0
            self._status.setText(
                i18n.tr("正在把本机保险库发送到对方设备… {pct}%").format(pct=pct)
                if total
                else i18n.tr("正在把本机保险库发送到对方设备…")
            )
            self._progress.setRange(0, 100)
            self._progress.setValue(pct)
            self._progress.setFormat(f"{pct}%")
            self._progress.setVisible(True)
        elif phase == "receiving":
            received, total = receive_progress or (0, 0)
            pct = min(100, max(0, received * 100 // total)) if total else 0
            self._status.setText(
                i18n.tr("正在接收对方设备的数据… {pct}%").format(pct=pct)
                if total
                else i18n.tr("正在接收对方设备的数据…")
            )
            self._progress.setRange(0, 100)
            self._progress.setValue(pct)
            self._progress.setFormat(f"{pct}%")
            self._progress.setVisible(True)
        elif phase == "verifying":
            self._status.setText(i18n.tr("正在验证并合并数据…"))
            self._progress.setRange(0, 0)
            self._progress.setFormat("")
            self._progress.setVisible(True)
        elif phase == "done":
            self._status.setText(i18n.tr("同步已完成"))
            self._progress.setRange(0, 100)
            self._progress.setVisible(False)
        elif phase == "failed":
            self._status.setText(i18n.tr("同步未完成"))
            self._progress.setRange(0, 100)
            self._progress.setVisible(False)
        elif transfer_active:
            self._status.setText(i18n.tr("文件传输进行中…"))
            self._progress.setVisible(False)
        elif connected:
            self._status.setText(i18n.tr("已连接，等待同步或传输…"))
            self._progress.setVisible(False)
        else:
            self._status.setText("")
            self._progress.setVisible(False)

    def set_text(self, text: str) -> None:
        self._status.setText(text)
        self._progress.setVisible(False)

    def set_progress_visible(self, visible: bool) -> None:
        self._progress.setVisible(visible)



def render_transfer_records(
    transfer_list: QTreeWidget,
    records: list[dict],
    on_cancel=None,
) -> None:
    """把收发记录渲染到传输列表（主机与连接方共用同一渲染逻辑）。

    可取消条目（等待接收/进行中）显示单条“取消”按钮，点击后回调 [on_cancel](item_id)。
    """
    transfer_list.clear()
    if not records:
        empty = QTreeWidgetItem([i18n.tr("尚无传输记录"), "", "", "", ""])
        empty.setFlags(empty.flags() & ~Qt.ItemIsSelectable)
        transfer_list.addTopLevelItem(empty)
        return
    for record in records:
        size = int(record.get("size") or 0)
        transferred = int(record.get("transferred") or 0)
        progress = 100 if size == 0 and record.get("status") in {"已发送", "已接收"} else (
            min(100, max(0, int(transferred * 100 / size))) if size else 0
        )
        preview = str(record.get("preview") or "").replace("\n", " ").strip()
        name = (
            f"{i18n.tr('文本：')}{preview[:80]}"
            if record.get("kind") == "text" and preview
            else str(record.get("name") or "")
        )
        direction_text = i18n.tr(str(record.get("direction") or ""))
        status_text = i18n.tr(str(record.get("status") or "等待中"))
        directory = _transfer_parent_directory(record)
        tree_item = QTreeWidgetItem(
            [name, f"{direction_text} · {status_text}", "", directory, ""],
        )
        for column in (0, 1, 3, 4):
            tree_item.setTextAlignment(column, Qt.AlignLeft | Qt.AlignVCenter)
        tree_item.setData(0, Qt.UserRole, record)
        if record.get("kind") == "text" and record.get("direction") == "发送":
            # 已发送的文本只是本次会话的暂存副本，没有可打开/复制的本地文件。
            action = i18n.tr("已发送的文本")
        else:
            action = i18n.tr("点击复制文本") if record.get("kind") == "text" else i18n.tr("点击打开文件")
        directory_hint = f"\n{directory}" if directory else ""
        tree_item.setToolTip(0, f"{action}{directory_hint}")
        if directory:
            tree_item.setToolTip(3, i18n.tr("点击打开目录"))
        transfer_list.addTopLevelItem(tree_item)
        bar = QProgressBar()
        bar.setObjectName("TransferProgress")
        bar.setRange(0, 100)
        bar.setValue(progress)
        bar.setTextVisible(True)
        bar.setFormat(f"{progress}%")
        bar.setMaximumHeight(16)
        if record.get("status") in {"已发送", "已接收"}:
            bar.setStyleSheet(
                "QProgressBar#TransferProgress { background: #EEF0FE; border: none;"
                " border-radius: 4px; color: #111827; font-size: 8.5pt; }"
                " QProgressBar#TransferProgress::chunk { background: #22a06b; border-radius: 4px; }"
            )
        progress_cell = QWidget()
        progress_layout = QHBoxLayout(progress_cell)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.addWidget(bar, 1, Qt.AlignVCenter)
        transfer_list.setItemWidget(tree_item, 2, progress_cell)
        if bool(record.get("cancellable")) and on_cancel is not None:
            item_id = str(record.get("id") or "")
            action_cell = QWidget()
            action_layout = QHBoxLayout(action_cell)
            action_layout.setContentsMargins(0, 0, 0, 0)
            cancel_btn = QPushButton(i18n.tr("取消"))
            cancel_btn.setObjectName("Ghost")
            cancel_btn.setMaximumWidth(72)
            cancel_btn.clicked.connect(lambda _checked=False, rid=item_id: on_cancel(rid))
            action_layout.addWidget(cancel_btn, 0, Qt.AlignVCenter)
            transfer_list.setItemWidget(tree_item, 4, action_cell)


class LanTransferPanel(QWidget):
    """文件传输页：传输列表 + 文本/文件/图片发送（主机与连接方共用同一页面）。

    ``sendText`` / ``sendPaths`` 信号由所属窗口接上自己的传输通道。
    """

    sendText = Signal(str)
    sendPaths = Signal(list)
    cancelRequested = Signal(str)
    #: 用户手动结束本次传输会话（断开对端，但页面与传输记录保留）。
    endRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._on_copy = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        title = QLabel(i18n.tr("<b>文件传输</b>"))
        title.setTextFormat(Qt.RichText)
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        layout.addWidget(header)

        hint = QLabel(i18n.tr("接收文本会自动复制；文件点击后打开，收发进度会实时更新"))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6B7280; font-size: 12px;")
        layout.addWidget(hint)

        self._list = QTreeWidget()
        self._list.setObjectName("TransferList")
        self._list.setHeaderLabels(
            [i18n.tr("内容"), i18n.tr("状态"), i18n.tr("进度"), i18n.tr("目录"), i18n.tr("操作")]
        )
        self._list.setRootIsDecorated(False)
        self._list.setUniformRowHeights(True)
        self._list.setSelectionMode(QAbstractItemView.SingleSelection)
        self._list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._list.setAlternatingRowColors(True)
        self._list.setMinimumHeight(150)
        self._list.setMaximumHeight(210)
        self._list.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self._list.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._list.header().setSectionResizeMode(2, QHeaderView.Fixed)
        self._list.setColumnWidth(2, 110)
        self._list.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self._list.header().setSectionResizeMode(4, QHeaderView.Fixed)
        self._list.setColumnWidth(4, 84)
        self._list.setToolTip(i18n.tr("点击文件打开，点击文本复制"))
        self._list.itemClicked.connect(self._activate_item)
        layout.addWidget(self._list)

        self._send_text = _TransferTextEdit()
        self._send_text.setPlaceholderText(i18n.tr("发送内容：输入文本，或直接粘贴图片/文件发送"))
        self._send_text.setMaximumHeight(64)
        layout.addWidget(self._send_text)

        actions = QWidget()
        self._actions = actions
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        self._send_text_btn = QPushButton(i18n.tr("发送"))
        self._send_text_btn.setEnabled(False)
        self._send_file_btn = QPushButton(i18n.tr("发送文件"))
        actions_layout.addWidget(self._send_text_btn)
        actions_layout.addWidget(self._send_file_btn)
        layout.addWidget(actions)

        self._feedback = QLabel("")
        self._feedback.setStyleSheet("color: #2563EB; font-size: 12px;")
        layout.addWidget(self._feedback)

        # 退出传输视图：断开对端但不关闭页面，传输记录与「已断开」留在原地。
        # 同步/传输进行中三档滑块是锁住的，没有这个按钮用户就无处可去。
        self._end_btn = QPushButton(i18n.tr("关闭页面"))
        self._end_btn.setObjectName("Ghost")
        self._end_btn.setMinimumHeight(34)
        self._end_btn.setCursor(Qt.PointingHandCursor)
        self._end_btn.setAccessibleName(i18n.tr("关闭页面"))
        self._end_btn.clicked.connect(self.endRequested.emit)
        self._end_btn.setVisible(False)
        layout.addWidget(self._end_btn)

        self._send_text.textChanged.connect(
            lambda: self._send_text_btn.setEnabled(bool(self._send_text.toPlainText().strip()))
        )
        self._send_text_btn.clicked.connect(self._on_send_text)
        self._send_file_btn.clicked.connect(self._on_choose_files)
        self._send_text._on_enter = self._on_send_text
        self._send_text._on_files_paste = self._on_files_pasted
        self._send_text._on_image_paste = self._on_image_pasted

    @property
    def transfer_list(self) -> QTreeWidget:
        return self._list

    def set_records(self, records: list[dict]) -> None:
        render_transfer_records(
            self._list,
            records,
            on_cancel=lambda item_id: self.cancelRequested.emit(item_id),
        )

    def set_feedback(self, text: str) -> None:
        self._feedback.setText(text)

    def clear_input(self) -> None:
        self._send_text.clear()

    def set_send_enabled(self, enabled: bool) -> None:
        self._send_text.setEnabled(enabled)
        self._send_text_btn.setEnabled(enabled and bool(self._send_text.toPlainText().strip()))
        self._send_file_btn.setEnabled(enabled)

    def set_composer_visible(self, visible: bool) -> None:
        """发送区整块收起/展开。

        断开后只保留传输记录供查看：输入框与发送按钮都收起来。set_send_enabled 只
        能禁用它们，控件仍在页面上占位，看着还能用其实发不出去。
        """
        self._send_text.setVisible(visible)
        self._actions.setVisible(visible)

    def set_end_visible(self, visible: bool) -> None:
        """「退出传输」只在传输视图里提供，闲置时不必占位。"""
        self._end_btn.setVisible(bool(visible))

    def set_end_active(self, active: bool) -> None:
        """按阶段改文案：进行中是「断开连接」，结束后是「退出传输」。

        与同步页同一套逻辑——同一颗按钮在会话前后承担两件事，避免用户在传输
        结束后点一个名为「断开」但其实已经断开的按钮。
        """
        label = i18n.tr("断开连接") if active else i18n.tr("关闭页面")
        self._end_btn.setText(label)
        self._end_btn.setAccessibleName(label)

    def set_on_copy(self, callback) -> None:
        """文本点击复制时回调（所属窗口提供隐私复制实现）。"""
        self._on_copy = callback

    def _on_send_text(self) -> None:
        value = self._send_text.toPlainText().strip()
        if not value:
            return
        self.sendText.emit(value)
        self.clear_input()

    def _on_choose_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            i18n.tr("选择要发送的文件（可多选）"),
            "",
            i18n.tr("所有文件 (*)"),
        )
        if paths:
            self.sendPaths.emit(list(paths))

    def _on_files_pasted(self, paths) -> None:
        self.sendPaths.emit(list(paths))

    def _on_image_pasted(self) -> None:
        _paste_clipboard_image(
            self._feedback,
            lambda path: self.sendPaths.emit([path]),
        )

    def _activate_item(self, tree_item: QTreeWidgetItem, column: int) -> None:
        record = tree_item.data(0, Qt.UserRole)
        if not isinstance(record, dict):
            return
        # 已发送的文本没有可打开/复制的本地文件：点击不生效，避免报错。
        if record.get("kind") == "text" and record.get("direction") == "发送":
            return
        if column == 3:
            directory = _transfer_parent_directory(record)
            if directory and Path(directory).is_dir() and QDesktopServices.openUrl(QUrl.fromLocalFile(directory)):
                self.set_feedback(i18n.tr("已打开目录"))
                QTimer.singleShot(2500, lambda: self.set_feedback(""))
            return
        if not record.get("path"):
            return
        if record.get("direction") == "接收" and record.get("status") != "已接收":
            self.set_feedback(i18n.tr("传输完成后即可打开或复制"))
            QTimer.singleShot(2500, lambda: self.set_feedback(""))
            return
        path = Path(str(record["path"]))
        try:
            if record.get("kind") == "text":
                if int(record.get("size") or 0) > 1024 * 1024:
                    raise ValueError(i18n.tr("文本超过 1 MB，请作为文件打开"))
                value = path.read_text(encoding="utf-8")
                if self._on_copy is not None:
                    self._on_copy(value)
                self.set_feedback(i18n.tr("文本已复制，剪贴板将按设置自动清空"))
            else:
                if not path.is_file() or not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
                    raise OSError(i18n.tr("文件不存在或没有可用的打开程序"))
                self.set_feedback(i18n.tr("已打开文件"))
            QTimer.singleShot(2500, lambda: self.set_feedback(""))
        except Exception as error:
            from . import widgets

            widgets.message(self.window(), i18n.tr("无法处理传输内容"), str(error), kind="error")
