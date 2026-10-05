"""现代风格的自定义窗口与对话框基类，替换原生 QMessageBox / 系统窗口边框。

- ``FramelessMain``：无系统边框的主窗口，自带标题栏（拖动 / 最小化 / 最大化 / 关闭）
  与边缘缩放。
- ``ShadowDialog``：无边框、圆角、带投影的模态对话框基类，内容放进 ``self.body``。
- ``message`` / ``confirm``：替代 ``QMessageBox`` 的自绘提示框。
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from shiboken6 import isValid

from PySide6.QtCore import QAbstractAnimation, Property, QEasingCurve, QEvent, QObject, QPoint, QPointF, QPropertyAnimation, QRectF, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QDesktopServices, QFont, QFontMetrics, QIcon, QKeyEvent, QPainter, QPalette, QPen, QPixmap
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtQuickWidgets import QQuickWidget
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
      QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core import config
from core.markdown_html import render_markdown_document, render_markdown_html

from . import encrypted_document_cache, i18n, render_jobs, screen_capture, theme

_ASSETS = Path(__file__).resolve().parent / "assets"
_ICON_ICO_PATH = str(_ASSETS / "icon.ico")
_ICON_SVG_PATH = str(_ASSETS / "icon.svg")
_CATEGORY_ICON_DIR = _ASSETS / "category-icons"
_MODULE_ICON_DIR = _ASSETS / "module-icons"
_UI_ICON_DIR = _ASSETS / "ui-icons"
_CATEGORY_ICON_FILES = {
    "login": "login.svg",
    "wifi": "wifi.svg",
    "card_document": "credit-card.svg",
    "api_key": "api-key.svg",
    "otp": "otp.svg",
    "secure_note": "secure_note.svg",
    "server": "server.svg",
    "custom": "custom.svg",
    "passkey": "passkey.svg",
}

_icon_cache: QIcon | None = None
_MODULE_ICON_FILES: dict[str, str] = {
    "text": "text.svg",
    "password": "password.svg",
    "multiline": "markdown.svg",
    "images": "images.svg",
    "attachments": "attachments.svg",
    "boolean": "boolean.svg",
    "datetime": "datetime.svg",
    "login_account": "login_account.svg",
    "target_app": "target_app.svg",
    "api_credential": "api_credential.svg",
    "wifi": "wifi.svg",
    "server_connection": "server_connection.svg",
    "ssh": "ssh.svg",
    "database": "database.svg",
    "otp": "otp.svg",
    "card_document": "card_document.svg",
    "address": "address.svg",
    "recovery": "recovery.svg",
    "passkey": "passkey.svg",
}

_module_icon_cache: dict[str, QIcon] = {}


class RepeatSafeLineEdit(QLineEdit):
    """QLineEdit 的自动重复按键压缩防御。

    主线程繁忙（例如输入触发的防抖重载正在同步搜索全库）时，操作系统仍以固定频率
    投递 auto-repeat 按键，Qt 会把这些重复事件合并成单个 count>1 的 QKeyEvent。
    QLineEdit 对 Backspace/Delete 只按一次删除处理，导致"光标移动快于文本删除，
    松开后还有内容残留"。这里拦截压缩事件，按 count 逐字符执行删除，同时保证
    count==1 时行为与原生一致（交由 Qt 处理，含组合输入等边界）。
    """

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.count() > 1 and event.key() in (Qt.Key_Backspace, Qt.Key_Delete):
            delete = self.backspace if event.key() == Qt.Key_Backspace else self.del_
            for _ in range(event.count()):
                delete()
            return
        super().keyPressEvent(event)


# ---------------------------------------------------------------------------
# 收起的下拉框不接收滚轮改值；展开后由弹出列表处理滚动和选择。
# ---------------------------------------------------------------------------
class _ComboWheelGuard(QObject):
    def eventFilter(self, watched, event):
        if event.type() == QEvent.Wheel and isinstance(watched, QComboBox) and not watched.view().isVisible():
            event.ignore()
            return True
        return False


def install_combobox_wheel_guard() -> None:
    """Application filter covers native Qt combos and Python subclasses alike."""
    app = QApplication.instance()
    if app is None or getattr(app, "_vault_combo_wheel_guard", None) is not None:
        return
    app._vault_combo_wheel_guard = _ComboWheelGuard(app)
    app.installEventFilter(app._vault_combo_wheel_guard)


install_combobox_wheel_guard()


def _prepare_dynamic_content_surface(window: QWidget) -> None:
    # Qt 6 recreates an already-visible native window when its first RHI-backed
    # child (including WebEngine's internal Quick widget) is added. Establish
    # composition before first show, without starting a browser/page process.
    # Retain this zero-size child when detail/editor pages are removed.
    if os.name == "nt" and QApplication.platformName() == "windows":
        window._composition_anchor = QQuickWidget(window)
        window._composition_anchor.setFixedSize(0, 0)
        window._composition_anchor.hide()


def _open_external_link(url: QUrl) -> None:
    """在系统默认浏览器中打开外部链接（对齐安卓端 External 链接行为）。

    独立成模块级函数，便于测试替换为无害实现。
    """
    QDesktopServices.openUrl(url)


class MarkdownPage(QWebEnginePage):
    """Markdown 文档页：页内锚点原地滚动，外部 http/https 交给系统浏览器。

    安全约束：
    - http/https 链接不会在 WebEngine 内导航（避免把外部页面载入文档视图），
      而是调用 ``_open_external_link``；
    - 仅允许本地同文档 fragment 导航，其余一律拒绝。
    """

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):  # noqa: N802
        if navigation_type != QWebEnginePage.NavigationType.NavigationTypeLinkClicked:
            return True
        if url.scheme().lower() in ("http", "https"):
            _open_external_link(url)
            return False
        return bool(url.fragment()) and url.isLocalFile()


class ContentTransition(QWidget):
    """Paint a short themed veil without effects on native browser surfaces."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._opacity = 1.0
        self._animation = QPropertyAnimation(self, b"opacity", self)
        self._animation.setDuration(140)
        self._animation.setStartValue(1.0)
        self._animation.setEndValue(0.0)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.finished.connect(self.hide)
        parent.installEventFilter(self)
        self.hide()

    def _set_opacity(self, value):
        self._opacity = value
        self.update()

    opacity = Property(float, lambda self: self._opacity, _set_opacity)

    def begin(self):
        self._animation.stop()
        self._set_opacity(1.0)
        self.setGeometry(self.parentWidget().rect())
        self.show()
        self.raise_()
        QTimer.singleShot(0, self, self._animation.start)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Resize:
            self.setGeometry(obj.rect())
        return False

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setOpacity(self._opacity)
        painter.fillRect(self.rect(), QColor(theme.active()["bg"]))


class UpwardMenu(QMenu):
    """Open above the anchor while keeping the popup inside its window."""

    def showEvent(self, event):
        super().showEvent(event)
        anchor = self.parentWidget()
        if anchor is None:
            return
        window = anchor.window()
        bounds = window.rect().translated(window.mapToGlobal(QPoint())).adjusted(4, 4, -4, -4)
        screen = anchor.screen()
        if screen is not None:
            bounds = bounds.intersected(screen.availableGeometry())
        self.resize(min(anchor.width(), bounds.width()), min(self.height(), bounds.height()))
        origin = anchor.mapToGlobal(QPoint())
        x = max(bounds.left(), min(origin.x(), bounds.right() - self.width() + 1))
        y = max(bounds.top(), min(origin.y() - self.height() - 4, bounds.bottom() - self.height() + 1))
        self.move(x, y)


class MarkdownViewer(QWebEngineView):
    """只读 Markdown 渲染浏览器：整文档 Web 视图渲染（主题样式 + Mermaid 图表）。

    安全约束：
    - 关闭 JavaScript 的远程/本地任意文件访问（QWebEngineProfile 只允许自身文件）；
    - HTML 在生成端已做白名单消毒 + CSP，见 ``core.markdown_html``；
    - 资源（mermaid.min.js）从 ``ui/assets`` 本地文件加载。
    """

    def __init__(self, text: str = "", *, min_height: int = 120, parent=None):
        super().__init__(parent)
        self.setObjectName("DocumentViewer")
        self.setMinimumHeight(min_height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setPage(MarkdownPage(self))
        background = QColor(theme.active()["bg"])
        self.page().setBackgroundColor(background)
        palette = self.palette()
        palette.setColor(QPalette.Window, background)
        self.setPalette(palette)
        self.setAutoFillBackground(True)
        self.settings().setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls,
            False,
        )
        self._mermaid_base = _ASSETS
        self._render_future = None
        self._pending_document = None
        self._document_epoch = 0
        self._job_holder = [None]
        holder = self._job_holder
        self.destroyed.connect(lambda: holder[0].cancel() if holder[0] else None)
        self.loadFinished.connect(self._install_document)
        self._render_timer = QTimer(self)
        self._render_timer.setInterval(20)
        self._render_timer.timeout.connect(self._finish_markdown_render)
        self.set_markdown_text(text)

    def set_markdown_text(self, text: str) -> None:
        self._document_epoch += 1
        colors = theme.active()
        if self._render_future is not None:
            self._render_future.cancel()
        self._render_future = render_jobs.markdown_executor.submit(
            self._prepare_document, text or "", colors,
        )
        self._job_holder[0] = self._render_future
        self._pending_document = None
        self._render_timer.start()

    @staticmethod
    def _render_document(text: str, colors: dict) -> str:
        cached = encrypted_document_cache.read(text, colors)
        if cached is not None:
            return cached
        html = render_jobs.render_document(text, colors)
        encrypted_document_cache.write(text, colors, html)
        return html

    @staticmethod
    def _prepare_document(text: str, colors: dict) -> tuple[str, ...]:
        html = MarkdownViewer._render_document(text, colors)
        return tuple(json.dumps(html[offset:offset + 65536], ensure_ascii=False)
                     for offset in range(0, len(html), 65536))

    def _finish_markdown_render(self) -> None:
        future = self._render_future
        if future is None or not future.done():
            return
        self._render_timer.stop()
        self._render_future = None
        try:
            html = future.result()
        except Exception:
            self.setHtml("<p>Markdown 无法显示</p>")
            return
        base = QUrl.fromLocalFile(str(self._mermaid_base / "mermaid.html"))
        # setHtml percent-encodes its argument into a size-limited data URL.
        # Only the tiny bootstrap travels that route; the full sanitized document
        # stays in memory and is installed after the local origin is established.
        self._pending_document = html
        background = QColor(theme.active()["bg"]).name()
        self.setHtml(
            f'<!doctype html><html><body style="background:{background}"></body></html>', base,
        )

    def _install_document(self, ok):
        html = self._pending_document
        if not ok or html is None:
            return
        self._pending_document = None
        epoch = self._document_epoch
        self.page().runJavaScript("document.open();", lambda _result:
            self._queue_document_chunk(html, 0, epoch))

    def _queue_document_chunk(self, chunks: tuple[str, ...], index: int, epoch: int) -> None:
        if isValid(self) and epoch == self._document_epoch:
            QTimer.singleShot(0, self, lambda: self._write_document_chunk(chunks, index, epoch))

    def _write_document_chunk(self, chunks: tuple[str, ...], index: int, epoch: int) -> None:
        if epoch != self._document_epoch:
            return
        if index == len(chunks):
            self.page().runJavaScript("document.close();")
            return
        self.page().runJavaScript("document.write(" + chunks[index] + ");", lambda _result:
            self._queue_document_chunk(chunks, index + 1, epoch))


def module_icon(module_type: str) -> QIcon:
    icon = _module_icon_cache.get(module_type)
    if icon is not None:
        return icon
    filename = _MODULE_ICON_FILES.get(module_type)
    path = _MODULE_ICON_DIR / filename if filename else None
    icon = QIcon(str(path)) if path and path.exists() else QIcon()
    _module_icon_cache[module_type] = icon
    return icon


_category_icon_cache: dict[str, QIcon] = {}
_category_pixmap_cache: dict[str, QPixmap] = {}
_ui_icon_cache: dict[str, QIcon] = {}


def app_icon() -> QIcon:
    """应用图标：优先直接使用 ico，缺失时用 svg。"""
    global _icon_cache
    if _icon_cache is not None:
        return _icon_cache

    icon = QIcon(_ICON_ICO_PATH)
    if icon.isNull():
        icon = QIcon(_ICON_SVG_PATH)
    _icon_cache = icon
    return _icon_cache


def category_icon(secret_type: str) -> QIcon:
    icon = _category_icon_cache.get(secret_type)
    if icon is not None:
        return icon
    filename = _CATEGORY_ICON_FILES.get(secret_type)
    path = _CATEGORY_ICON_DIR / filename if filename else None
    icon = QIcon(str(path)) if path and path.exists() else QIcon()
    _category_icon_cache[secret_type] = icon
    return icon


def category_pixmap(secret_type: str, size: int = 28) -> QPixmap:
    key = f"{secret_type}_{size}"
    cached = _category_pixmap_cache.get(key)
    if cached is not None:
        return cached
    pm = category_icon(secret_type).pixmap(size, size)
    _category_pixmap_cache[key] = pm
    return pm


def ui_icon(name: str) -> QIcon:
    """返回界面语义图标；图标缺失时返回空 QIcon。"""
    icon = _ui_icon_cache.get(name)
    if icon is not None:
        return icon
    path = _UI_ICON_DIR / f"{name}.svg"
    icon = QIcon(str(path)) if path.exists() else QIcon()
    _ui_icon_cache[name] = icon
    return icon


def selection_combo(parent=None) -> QComboBox:
    """Create a value selector whose current/default item carries the shared blue dot."""
    combo = QComboBox(parent)

    def refresh(*_args) -> None:
        selected = combo.currentIndex()
        dot = ui_icon("selected-dot")
        for index in range(combo.count()):
            combo.setItemIcon(index, dot if index == selected else QIcon())

    combo.currentIndexChanged.connect(refresh)
    combo.model().rowsInserted.connect(refresh)
    combo.model().rowsRemoved.connect(refresh)
    return combo


class Switch(QAbstractButton):
    """Android/iOS 风格的开关（可勾选），作为 ``普通模块 / 敏感模块`` 切换控件。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setObjectName("Switch")
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(44, 24)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    def sizeHint(self) -> QSize:
        return QSize(44, 24)

    def minimumSizeHint(self) -> QSize:
        return QSize(44, 24)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()
        radius = height / 2
        knob = height - 6
        track = (
            QApplication.palette().color(QPalette.Highlight)
            if self.isChecked()
            else QColor("#C7CBD1")
        )
        if not self.isEnabled():
            track = track.toHsl()
            track.setHslF(track.hueF(), track.saturationF(), 0.80, track.alphaF())
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(track))
        painter.drawRoundedRect(0, 0, width, height, radius, radius)
        knob_x = width - knob - 3 if self.isChecked() else 3
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.drawEllipse(knob_x, 3, knob, knob)
        painter.end()


def set_button_icon(button: QPushButton, name: str, *, size: int = 18) -> QPushButton:
    button.setIcon(ui_icon(name))
    button.setIconSize(QSize(size, size))
    return button


def icon_only_button(
    name: str,
    tooltip: str,
    *,
    size: int = 18,
    width: int = 44,
    height: int = 32,
    object_name: str = "IconBtn",
    parent=None,
) -> QPushButton:
    """Create an accessible icon-only action button."""
    button = set_button_icon(QPushButton(parent), name, size=size)
    button.setObjectName(object_name)
    button.setFixedSize(width, height)
    button.setToolTip(tooltip)
    button.setAccessibleName(tooltip)
    return button


def flash_copy_success(button: QPushButton, *, duration_ms: int = 1500) -> None:
    """Temporarily replace a copy icon with a check mark, then restore it."""
    token = int(button.property("copyFeedbackToken") or 0) + 1
    original_tooltip = button.property("copyTooltip") or button.toolTip() or "复制"
    button.setProperty("copyFeedbackToken", token)
    button.setProperty("copyTooltip", original_tooltip)
    button.setText("")
    button.setIcon(ui_icon("success"))
    button.setToolTip(i18n.tr("已复制"))
    button.setAccessibleName(i18n.tr("已复制"))

    def restore() -> None:
        try:
            if int(button.property("copyFeedbackToken") or 0) != token:
                return
            button.setText("")
            button.setIcon(ui_icon("copy"))
            button.setToolTip(str(original_tooltip))
            button.setAccessibleName(str(original_tooltip))
        except RuntimeError:
            return

    QTimer.singleShot(max(0, int(duration_ms)), restore)


def set_eye_icon(button: QPushButton, shown: bool) -> None:
    """按显示状态切换小眼睛图标：隐藏中显示睁眼，显示中显示闭眼（安卓同款）。"""
    button.setIcon(ui_icon("view-off" if shown else "view"))


def add_password_reveal(edit: QLineEdit) -> QAction:
    """Put the reveal control inside a password line edit as a trailing action."""
    edit.setEchoMode(QLineEdit.Password)
    edit.setTextMargins(0, 0, 30, 0)
    action = QAction(ui_icon("view"), i18n.tr("显示或隐藏密码"), edit)
    action.setCheckable(True)
    edit.addAction(action, QLineEdit.TrailingPosition)

    def toggle(shown: bool) -> None:
        action.setIcon(ui_icon("view-off" if shown else "view"))
        edit.setEchoMode(QLineEdit.Normal if shown else QLineEdit.Password)

    action.toggled.connect(toggle)
    return action


def icon_text(
    text: str,
    icon_source: str | QIcon,
    *,
    object_name: str = "",
    icon_size: int = 22,
    word_wrap: bool = False,
    center_icon: bool = False,
) -> QWidget:
    """构造对齐稳定的“多色 SVG + 文本”行。"""
    host = QWidget()
    row = QHBoxLayout(host)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(9)
    icon = QLabel()
    icon.setFixedSize(icon_size, icon_size)
    icon.setAlignment(Qt.AlignCenter)
    source = ui_icon(icon_source) if isinstance(icon_source, str) else icon_source
    icon.setPixmap(source.pixmap(icon_size, icon_size))
    row.addWidget(icon, 0, Qt.AlignVCenter if center_icon else Qt.AlignTop)
    label = QLabel(text)
    if object_name:
        label.setObjectName(object_name)
    label.setWordWrap(word_wrap)
    row.addWidget(label, 1)
    host.text_label = label
    return host


def apply_capture_permission(window: QWidget) -> None:
    """按“允许截屏”设置更新窗口的捕获状态。"""
    screen_capture.apply_permission(window, config.screen_capture_allowed())


class LockBus(QObject):
    """全局信号总线：敏感操作二次验证记满失败上限时通知主窗口锁定应用。

    二次验证的失败计数与解锁页共享同一份记录（config.record_password_failure），
    但对话框本身拿不到主窗口，因此由此总线转发。对齐安卓
    ``VaultViewModel.verifySessionPassword`` 记满 5 次即 lock() 的行为。
    """

    lock_requested = Signal(str)


lock_bus = LockBus()





class HScrollArea(QScrollArea):
    """把垂直滚轮转为横向滚动的 ScrollArea，用于横向排列的图片/标签列表。"""

    def wheelEvent(self, event):
        bar = self.horizontalScrollBar()
        if bar.maximum() <= bar.minimum():
            event.ignore()
            return

        pixel_delta = event.pixelDelta()
        angle_delta = event.angleDelta()
        if not pixel_delta.isNull():
            delta = pixel_delta.x() or pixel_delta.y()
        else:
            delta = angle_delta.x() or angle_delta.y()
            delta //= 2

        if not delta:
            event.ignore()
            return

        previous = bar.value()
        bar.setValue(previous - delta)
        if bar.value() == previous:
            event.ignore()
        else:
            event.accept()


_STRENGTH_COLORS = {
    "无": "#C9CDD8",
    "弱": "#E5484D",
    "中": "#E0A100",
    "强": "#2FA84F",
    "极强": "#6366F1",
}


class StrengthBar(QWidget):
    """自绘的密码强度条：圆角轨道 + 按等级着色的填充 + 文字。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self._label = "无"
        self.setFixedHeight(30)

    def set_value(self, score: int, label: str) -> None:
        self._score = max(0, min(100, score))
        self._label = label
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        pal = theme.active()
        color = QColor(_STRENGTH_COLORS.get(self._label, pal["muted"]))
        track_h = 7
        track_y = self.height() - track_h
        w = self.width()

        # 轨道
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(pal["surface_alt"]))
        p.drawRoundedRect(QRectF(0, track_y, w, track_h), 3.5, 3.5)

        # 填充
        fill_w = max(track_h, w * self._score / 100)
        p.setBrush(color)
        p.drawRoundedRect(QRectF(0, track_y, fill_w, track_h), 3.5, 3.5)

        # 文字
        p.setPen(QColor(pal["muted"]))
        font = QFont(self.font())
        font.setPointSize(9)
        p.setFont(font)
        p.drawText(
            0, 0, w, self.height() - track_h - 2,
            Qt.AlignLeft | Qt.AlignVCenter, i18n.tr("密码强度"),
        )
        p.setPen(color)
        p.drawText(0, 0, w, self.height() - track_h - 2, Qt.AlignRight | Qt.AlignVCenter, self._label)
        p.end()


class ClickToWheelSpinBox(QSpinBox):
    """Ignore wheel changes until the user explicitly clicks this control."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._wheel_armed = False
        self.setFocusPolicy(Qt.StrongFocus)

    def mousePressEvent(self, event) -> None:
        self._wheel_armed = True
        super().mousePressEvent(event)

    def focusInEvent(self, event) -> None:
        if event.reason() == Qt.MouseFocusReason:
            self._wheel_armed = True
        super().focusInEvent(event)

    def focusOutEvent(self, event) -> None:
        self._wheel_armed = False
        super().focusOutEvent(event)

    def wheelEvent(self, event) -> None:
        if self._wheel_armed and self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class _WindowControlButton(QPushButton):
    """Theme-aware window control whose glyph never depends on an icon file."""

    def __init__(self, kind: str, slot, tooltip: str, parent=None):
        super().__init__(parent)
        self._kind = kind
        self._suppress_hover_feedback = False
        self._keyboard_focus = False
        self.setObjectName("WinClose" if kind == "close" else "WinBtn")
        # Keep the target comfortably larger than the glyph.  The old 30 px
        # icon buttons were easy to miss on high-DPI displays and their coloured
        # SVGs did not follow the active theme.
        self.setFixedSize(44, 36)
        self.setToolTip(tooltip)
        self.setAccessibleName(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAutoDefault(False)
        self.setDefault(False)
        self.clicked.connect(self._reset_visual_feedback)
        self.clicked.connect(slot)

    def set_kind(self, kind: str, tooltip: str) -> None:
        self._kind = kind
        self.setToolTip(tooltip)
        self.setAccessibleName(tooltip)
        self.update()

    def _reset_visual_feedback(self) -> None:
        """Return to the neutral glyph immediately after an action completes."""
        self._suppress_hover_feedback = True
        self.clearFocus()
        self.update()

    def mousePressEvent(self, event) -> None:
        self._suppress_hover_feedback = False
        super().mousePressEvent(event)

    def leaveEvent(self, event) -> None:
        self._suppress_hover_feedback = False
        # A mouse click leaves focus on the button; without clearing it here the
        # docked hover surface stays visible after the cursor moves away (and
        # after minimize/restore re-activates the window).  Keyboard focus is
        # tracked separately in focusInEvent so Tab users keep the affordance.
        self.clearFocus()
        super().leaveEvent(event)
        self.update()

    def focusInEvent(self, event) -> None:
        self._keyboard_focus = event.reason() in (
            Qt.TabFocusReason,
            Qt.BacktabFocusReason,
            Qt.ShortcutFocusReason,
            Qt.MenuBarFocusReason,
        )
        super().focusInEvent(event)

    def focusOutEvent(self, event) -> None:
        self._keyboard_focus = False
        super().focusOutEvent(event)

    def paintEvent(self, event) -> None:
        del event
        colors = theme.active()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        pressed = self.isDown()
        hovered = self._hover_feedback_active()
        button_rect = QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)
        background = QColor(Qt.transparent)
        border = QColor(Qt.transparent)
        if self._kind == "close" and hovered:
            background = QColor(colors["danger_soft"])
            glyph = QColor(colors["danger"])
        elif self._kind in {"minimize", "maximize", "restore"} and hovered:
            background = QColor(colors["surface_alt"])
            glyph = QColor(colors["accent"])
        else:
            glyph = QColor(colors["text"])
        if pressed:
            background = QColor(colors["surface_alt"] if self._kind != "close" else colors["danger_soft"])
            glyph.setAlpha(150)
        if not self.isEnabled():
            glyph = QColor(colors["muted"])

        # The neutral state is glyph-only. Draw a docked surface strictly as
        # interaction feedback, so close buttons never look like white tiles.
        if self.isEnabled() and (hovered or pressed):
            painter.setPen(border)
            painter.setBrush(background)
            painter.drawRoundedRect(button_rect, 6, 6)

        pen = painter.pen()
        pen.setColor(glyph)
        pen.setWidthF(1.75)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)

        cx = self.width() / 2.0
        cy = self.height() / 2.0 + (1.0 if pressed else 0.0)
        if self._kind == "minimize":
            # Geometric centering avoids the visibly low minus used previously.
            painter.drawLine(QPointF(cx - 6, cy), QPointF(cx + 6, cy))
        elif self._kind == "maximize":
            painter.drawRect(QRectF(cx - 6, cy - 6, 12, 12))
        elif self._kind == "restore":
            # 与 restore.svg 一致：后块（右上）先描边，前块（左下）用所在表面颜色
            # 填充后再描边，让前块盖住后块在重叠处的线条，而不是两道轮廓交叉显示。
            back_rect = QRectF(cx - 4, cy - 6, 10, 10)
            front_rect = QRectF(cx - 7, cy - 3, 10, 10)
            fill_color = (
                QColor(background)
                if self.isEnabled() and (hovered or pressed)
                else QColor(colors["surface"])
            )
            painter.drawRect(back_rect)
            painter.setBrush(fill_color)
            painter.drawRect(front_rect)
            painter.setBrush(Qt.NoBrush)
        else:
            painter.drawLine(QPointF(cx - 5, cy - 5), QPointF(cx + 5, cy + 5))
            painter.drawLine(QPointF(cx + 5, cy - 5), QPointF(cx - 5, cy + 5))

        painter.end()

    def _glyph_center_y(self) -> float:
        """Testable visual center; pressed feedback moves the glyph down by 1 px."""
        return self.height() / 2.0 + (1.0 if self.isDown() else 0.0)

    def _hover_feedback_active(self) -> bool:
        return not self._suppress_hover_feedback and (self.underMouse() or self._keyboard_focus)


def _deepest_child_at(widget: QWidget, pos: QPoint) -> QWidget:
    child = widget.childAt(pos)
    if child is None:
        return widget
    return _deepest_child_at(child, child.mapFromParent(pos))


def _is_native_caption_area(title_bar: QWidget, global_pos: QPoint) -> bool:
    """标题栏空白区域返回 True，系统将整条标题栏当作可拖动标题（HTCAPTION）。"""
    if not title_bar.isVisible():
        return False
    pos = title_bar.mapFromGlobal(global_pos)
    if pos.y() < 0 or pos.y() > title_bar.height():
        return False
    target = _deepest_child_at(title_bar, pos)
    return not isinstance(target, QAbstractButton)


class _WindowButtons(QWidget):
    """标题栏右侧的 最小化 / 最大化 / 关闭 按钮，按钮内带可辨识的图标。"""

    def __init__(self, window: QWidget, *, with_min_max: bool = True, simple_close: bool = False):
        super().__init__()
        self._window = window
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)

        if with_min_max:
            minimize = getattr(window, "animateMinimize", window.showMinimized)
            lay.addWidget(self._btn("WinBtn", "minimize", minimize, "最小化"))
            self._max = self._btn("WinBtn", "maximize", self._toggle_max, "最大化")
            lay.addWidget(self._max)
        del simple_close
        self._close = self._btn("WinClose", "close", window.close, "关闭")
        lay.addWidget(self._close)

    def _btn(self, name: str, icon_name: str, slot, tooltip: str) -> QPushButton:
        del name
        return _WindowControlButton(icon_name, slot, tooltip, self)

    def _text_btn(self, name: str, text: str, slot, tooltip: str) -> QPushButton:
        b = QPushButton(text)
        b.setObjectName(name)
        b.setFixedSize(30, 30)
        b.setToolTip(tooltip)
        b.setAccessibleName(tooltip)
        b.setCursor(Qt.PointingHandCursor)
        b.setAutoDefault(False)
        b.setDefault(False)
        b.clicked.connect(slot)
        return b

    def _toggle_max(self) -> None:
        animated_toggle = getattr(self._window, "animateToggleMaximize", None)
        if animated_toggle is not None:
            animated_toggle()
            return
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()
        self.refresh_max_icon()

    def refresh_max_icon(self) -> None:
        if hasattr(self, "_max"):
            maximized = self._window.isMaximized()
            self._max.set_kind("restore" if maximized else "maximize", "还原" if maximized else "最大化")


class TitleBar(QWidget):
    """可拖动的自定义标题栏。"""

    def __init__(
        self,
        window: QWidget,
        title: str,
        *,
        with_min_max: bool = True,
        with_logo: bool = False,
        simple_close: bool = False,
    ):
        super().__init__()
        self.setObjectName("TitleBar")
        self.setFixedHeight(44)
        self._window = window
        self._with_min_max = with_min_max
        self._dragging = False
        self._drag_offset = QPoint()

        lay = QHBoxLayout(self)
        self._layout = lay
        lay.setContentsMargins(16, 0, 12, 0)
        lay.setSpacing(8)

        self.logo = QLabel() if with_logo else None
        if self.logo is not None:
            self.logo.setPixmap(app_icon().pixmap(20, 20))
            lay.addWidget(self.logo)

        self._title = QLabel(title)
        self._title.setObjectName("TitleText")
        lay.addWidget(self._title)
        lay.addStretch()
        self._buttons = _WindowButtons(window, with_min_max=with_min_max, simple_close=simple_close)
        lay.addWidget(self._buttons)

    def setCentralWidget(self, widget: QWidget) -> None:
        """Insert application navigation while preserving a draggable empty region."""
        self._layout.insertWidget(max(0, self._layout.count() - 2), widget, 1)
        widget.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        """Let empty navigation-bar space behave like the surrounding title bar."""
        if event.type() == QEvent.MouseButtonPress:
            self.mousePressEvent(event)
            return True
        if event.type() == QEvent.MouseMove:
            self.mouseMoveEvent(event)
            return True
        if event.type() == QEvent.MouseButtonRelease:
            self.mouseReleaseEvent(event)
            return True
        if event.type() == QEvent.MouseButtonDblClick:
            self.mouseDoubleClickEvent(event)
            return True
        return super().eventFilter(watched, event)

    def setTitle(self, text: str) -> None:
        self._title.setText(text)
        self._window.setWindowTitle(text)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._drag_offset = event.globalPosition().toPoint() - self._window.pos()

    def mouseMoveEvent(self, event) -> None:
        if not self._dragging or not (event.buttons() & Qt.LeftButton):
            return
        global_pos = event.globalPosition().toPoint()
        if self._with_min_max and self._window.isMaximized():
            ratio = self._drag_offset.x() / max(self._window.width(), 1)
            self._window.showNormal()
            self._buttons.refresh_max_icon()
            self._drag_offset = QPoint(int(self._window.width() * ratio), self._drag_offset.y())
        self._window.move(global_pos - self._drag_offset)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self._dragging:
            self._dragging = False

    def mouseDoubleClickEvent(self, event) -> None:
        if not self._with_min_max:
            return
        animated_toggle = getattr(self._window, "animateToggleMaximize", None)
        if animated_toggle is not None:
            animated_toggle()
            return
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()
        self._buttons.refresh_max_icon()


class FramelessMain(QWidget):
    """无系统边框的主窗口。子类把内容放进 ``self.content``。"""

    def __init__(self, title: str = "", *, min_size=(880, 560)):
        super().__init__()
        install_combobox_wheel_guard()
        _prepare_dynamic_content_surface(self)
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setWindowTitle(title)
        self.setMinimumSize(*min_size)
        self.setObjectName("Root")
        self.setWindowIcon(app_icon())
        self._native_frame_ready = False
        self._first_frame_pending = True
        # On Windows, adding the native DWM frame during showEvent can expose a
        # tiny unlaid-out native window. Keep the first frame invisible until
        # the final geometry and native styles are both ready.
        self.setWindowOpacity(0.0)

        self._shell = QVBoxLayout(self)
        self._shell.setContentsMargins(0, 0, 0, 0)
        self._shell.setSpacing(0)

        self.title_bar = TitleBar(self, title, with_logo=True)
        self._shell.addWidget(self.title_bar)

        # 贯穿整个窗口顶部的分割线：标题栏左右两端（图标、窗口控制按钮）之外
        # 仍需一条连续的线，单独用全宽控件保证跨越左右，不依赖标题栏内边距。
        self._header_divider = QWidget()
        self._header_divider.setObjectName("HeaderDivider")
        self._shell.addWidget(self._header_divider)

        self.content = QWidget()
        self._shell.addWidget(self.content, 1)

    def animateMinimize(self) -> None:
        if self.isMinimized():
            return
        if not self._show_native_window(6):  # SW_MINIMIZE
            self.showMinimized()

    def animateToggleMaximize(self) -> None:
        command = 9 if self.isMaximized() else 3  # SW_RESTORE / SW_MAXIMIZE
        if not self._show_native_window(command):
            self.showNormal() if self.isMaximized() else self.showMaximized()
        QTimer.singleShot(0, self.title_bar._buttons.refresh_max_icon)
        QTimer.singleShot(0, self._apply_native_corners)

    def _show_native_window(self, command: int) -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes

            ctypes.windll.user32.ShowWindow(int(self.winId()), command)
            return True
        except Exception:
            return False

    def _enable_native_frame(self) -> None:
        """Keep custom chrome while restoring styles required for DWM animations."""
        if os.name != "nt" or self._native_frame_ready:
            return
        try:
            import ctypes
            from ctypes import wintypes

            hwnd = int(self.winId())
            get_style = ctypes.windll.user32.GetWindowLongPtrW
            set_style = ctypes.windll.user32.SetWindowLongPtrW
            # LONG_PTR 是 64 位：不声明 argtypes 时 ctypes 会用 32 位 int 转换样式值，
            # 带 WS_POPUP(0x80000000) 的样式会抛 OverflowError，原生边框从未生效。
            get_style.argtypes = [wintypes.HWND, ctypes.c_int]
            get_style.restype = ctypes.c_longlong
            set_style.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_longlong]
            set_style.restype = ctypes.c_longlong
            style = int(get_style(hwnd, -16))  # GWL_STYLE
            # 去掉 WS_POPUP：DWM 的圆角与贴靠不作用于弹出式窗口，需保持标准
            # 重叠窗口（WS_OVERLAPPED + 标题/粗边框），外观仍由 WM_NCCALCSIZE 自绘。
            style &= ~0x80000000
            style |= 0x00CF0000  # WS_CAPTION | THICKFRAME | SYSMENU | MIN/MAX boxes
            set_style(hwnd, -16, style)
            set_pos = ctypes.windll.user32.SetWindowPos
            set_pos.argtypes = [
                wintypes.HWND,
                wintypes.HWND,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint,
            ]
            set_pos(
                hwnd,
                0,
                0,
                0,
                0,
                0,
                0x0037,  # NOMOVE | NOSIZE | NOZORDER | NOACTIVATE | FRAMECHANGED
            )
            self._native_frame_ready = True
        except Exception:
            self._native_frame_ready = False

    def nativeEvent(self, event_type, message):
        """把缩放、拖动、贴靠与最大化恢复交给 Windows 窗口管理器处理。"""
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes

                msg = wintypes.MSG.from_address(int(message))
                if msg.message == 0x0083:  # WM_NCCALCSIZE
                    # 整个窗口都作为客户区，隐藏系统标题栏与边框；最大化时同样
                    # 处理，避免最大化后原生标题栏重新出现。
                    return True, 0
                if msg.message == 0x0084:  # WM_NCHITTEST
                    x = ctypes.c_short(msg.lParam & 0xFFFF).value
                    y = ctypes.c_short((msg.lParam >> 16) & 0xFFFF).value
                    if not self.isMaximized() and not self.isFullScreen():
                        local = self.mapFromGlobal(QPoint(x, y))
                        margin = 7  # Qt coordinates are already DPI-independent.
                        left = local.x() < margin
                        right = local.x() >= self.width() - margin
                        top = local.y() < margin
                        bottom = local.y() >= self.height() - margin
                        hit = 0
                        if top and left:
                            hit = 13  # HTTOPLEFT
                        elif top and right:
                            hit = 14  # HTTOPRIGHT
                        elif bottom and left:
                            hit = 16  # HTBOTTOMLEFT
                        elif bottom and right:
                            hit = 17  # HTBOTTOMRIGHT
                        elif left:
                            hit = 10  # HTLEFT
                        elif right:
                            hit = 11  # HTRIGHT
                        elif top:
                            hit = 12  # HTTOP
                        elif bottom:
                            hit = 15  # HTBOTTOM
                        if hit:
                            return True, hit
                    # 标题栏空白区（含最大化状态）交给系统：拖动、Aero Snap、
                    # 从最大化下拉还原、双击最大化/还原都由窗口管理器处理。
                    if not self.isFullScreen() and _is_native_caption_area(
                        self.title_bar, QPoint(x, y)
                    ):
                        return True, 2  # HTCAPTION
            except Exception:
                pass
        return super().nativeEvent(event_type, message)

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.WindowStateChange:
            self.title_bar._buttons.refresh_max_icon()
            QTimer.singleShot(0, self._apply_native_corners)

    def showEvent(self, event):
        super().showEvent(event)
        self._enable_native_frame()
        self._apply_native_corners()
        apply_capture_permission(self)
        if self._first_frame_pending:
            self._first_frame_pending = False
            QTimer.singleShot(0, self._reveal_first_frame)

    def _reveal_first_frame(self) -> None:
        self.layout().activate()
        size = self.size().expandedTo(self.minimumSize())
        if size != self.size():
            self.resize(size)
        self.setWindowOpacity(1.0)

    def _apply_native_corners(self) -> None:
        """Use the Windows 11 compositor's real rounded window corners."""
        if os.name != "nt":
            return
        try:
            import ctypes

            # DWMWCP_ROUND(2)=标准圆角，与系统默认/其他程序一致；
            # ROUNDSMALL(3) 是小圆角，会显得比别的程序更方。
            # 最大化时用 DONOTROUND(1) 保持直角，与原生最大化行为一致。
            preference = ctypes.c_int(1 if self.isMaximized() else 2)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                int(self.winId()),
                33,  # DWMWA_WINDOW_CORNER_PREFERENCE
                ctypes.byref(preference),
                ctypes.sizeof(preference),
            )
        except Exception:
            pass


class SpinnerWidget(QWidget):
    """不确定进度旋转动画，用于阻塞等待时缓解用户焦虑（参考登录界面的旋转动画）。

    品牌色取自 ``theme.active()["accent"]``，暗/亮主题自动跟随；大小由 ``size``
    控制。放在深色控件（如主按钮）内时用 ``color`` 指定前景色。调用
    :meth:`start` / :meth:`stop` 控制显隐与旋转。
    """

    def __init__(self, parent=None, *, size: int = 22, line_width: int = 2, color: str | None = None):
        super().__init__(parent)
        self._size = size
        self._line = line_width
        self._color = color
        self._angle = 0
        self._spinning = False
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setCursor(Qt.ArrowCursor)
        self._anim = QPropertyAnimation(self, b"angle", self)
        self._anim.setDuration(900)
        self._anim.setStartValue(0)
        self._anim.setEndValue(360)
        self._anim.setLoopCount(-1)

    def _get_angle(self) -> int:
        return self._angle

    def _set_angle(self, value: int) -> None:
        self._angle = value
        self.update()

    angle = Property(int, _get_angle, _set_angle)

    def set_color(self, color: str | None) -> None:
        """指定前景色；``None`` 表示跟随主题强调色。"""
        self._color = color
        self.update()

    def start(self) -> None:
        if self._spinning:
            return
        self._spinning = True
        self.setVisible(True)
        if self._anim.state() != QAbstractAnimation.Running:
            self._anim.start()

    def stop(self) -> None:
        if not self._spinning:
            return
        self._spinning = False
        self._anim.stop()
        self.setVisible(False)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if self._spinning and self._anim.state() != QAbstractAnimation.Running:
            self._anim.start()

    def paintEvent(self, event) -> None:
        if not self._spinning:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        pen = QPen(QColor(self._color or theme.active()["accent"]))
        pen.setWidth(self._line)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        arc_rect = QRectF(self.rect()).adjusted(self._line, self._line, -self._line, -self._line)
        span = 300 * 16
        start = ((-self._angle) % 360) * 16
        painter.drawArc(arc_rect, start, span)


class ShadowDialog(QDialog):
    """无边框圆角对话框基类：半透明背景 + 投影 + 自定义标题栏。

    子类把内容控件加入 ``self.body``（QVBoxLayout）。
    """

    def __init__(self, title: str, parent=None, *, width: int = 400, simple_close: bool = True):
        super().__init__(parent)
        install_combobox_wheel_guard()
        _prepare_dynamic_content_surface(self)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowIcon(app_icon())
        self.setModal(True)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        # 不使用 QGraphicsDropShadowEffect：在半透明无边框分层窗口上，子控件
        # 重新布局/重绘会触发该特效在越界区域重建，导致 Windows 原生崩溃。
        # 这里只保留半透明背景以呈现圆角卡片，投影由窗口本身省略。
        self.card = QFrame()
        self.card.setObjectName("Dialog")
        self.card.setMinimumWidth(width)
        outer.addWidget(self.card)

        wrap = QVBoxLayout(self.card)
        wrap.setContentsMargins(0, 0, 0, 0)
        wrap.setSpacing(0)

        self.title_bar = TitleBar(
            self,
            title,
            with_min_max=False,
            simple_close=simple_close,
        )
        wrap.addWidget(self.title_bar)

        body_host = QWidget()
        self.body = QVBoxLayout(body_host)
        self.body.setContentsMargins(24, 8, 24, 22)
        self.body.setSpacing(12)
        wrap.addWidget(body_host)

    def set_close_enabled(self, enabled: bool) -> None:
        """Keep modal background work alive until it reaches a safe boundary."""

        close_button = self.title_bar._buttons._close
        close_button.setEnabled(bool(enabled))
        close_button.setToolTip(i18n.tr("关闭" if enabled else "操作完成后可关闭"))
        close_button.setAccessibleName(close_button.toolTip())

    def _prepare_for_exec(self) -> None:
        """Keep the native window invisible until its frameless surface is ready."""
        self.setWindowOpacity(0.0)
        self.adjustSize()
        QTimer.singleShot(0, lambda: self.setWindowOpacity(1.0))

    def exec(self):
        # Do not call winId() before entering the dialog event loop. On Windows
        # that can briefly expose an unpainted native caption containing only
        # the minimize/maximize/close buttons.
        self._prepare_for_exec()
        return super().exec()

    def showEvent(self, event):
        super().showEvent(event)
        self.setWindowIcon(app_icon())
        apply_capture_permission(self)


class MessageDialog(ShadowDialog):
    """替代 QMessageBox：标题 + 正文 + 一/两个按钮。"""

    def __init__(self, parent, title, text, *, kind="info", confirm=False):
        super().__init__(title, parent, width=380)
        icon_name = {
            "info": "info",
            "success": "success",
            "warn": "warning",
            "error": "error",
        }.get(kind, "info")

        head = QHBoxLayout()
        head.setSpacing(12)
        icon = QLabel()
        icon.setObjectName(f"MsgIcon_{kind}")
        icon.setAlignment(Qt.AlignCenter)
        icon.setPixmap(ui_icon(icon_name).pixmap(24, 24))
        head.addWidget(icon)

        msg = QLabel(text)
        msg.setObjectName("MsgText")
        msg.setWordWrap(True)
        head.addWidget(msg, 1)
        self.body.addLayout(head)
        self.body.addSpacing(4)

        bar = QHBoxLayout()
        bar.addStretch()
        if confirm:
            cancel = QPushButton("取消")
            cancel.clicked.connect(self.reject)
            bar.addWidget(cancel)
        ok = QPushButton("确定")
        ok.setObjectName("Danger" if kind == "error" else "Primary")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        bar.addWidget(ok)
        self.body.addLayout(bar)


def message(parent, title, text, *, kind="info") -> None:
    MessageDialog(_top(parent), i18n.tr_dynamic(title), i18n.tr_dynamic(text), kind=kind).exec()


def confirm(parent, title, text, *, kind="warn") -> bool:
    return MessageDialog(
        _top(parent), i18n.tr_dynamic(title), i18n.tr_dynamic(text), kind=kind, confirm=True
    ).exec() == QDialog.Accepted


def _top(widget):
    return widget.window() if isinstance(widget, QWidget) else widget


class CapsuleSegmentedControl(QWidget):
    """胶囊分段滑块：全圆角轨道 + 滑动 thumb，用于在同一页内切换几档视图。

    对齐安卓端的 ``LanModeSlider``：轨道用 ``surface_alt``、thumb 用 ``surface`` 内缩
    4px 滑动，切换只平移 thumb（220ms），不重排内容；选中文字加粗、未选中用弱化色。

    横向始终铺满父容器（页面顶部档位条、模块内 Markdown 的编辑/查看都用同一形态），
    高度由 ``height`` 决定：页面顶部用默认 46，行内切换条可传更矮的值。
    """

    changed = Signal(int)

    _PADDING = 4
    _ANIM_MS = 220
    _FONT_PT = 9

    def __init__(self, options, current: int = 0, *, height: int = 46, parent=None):
        super().__init__(parent)
        self._options = [(str(key), str(label)) for key, label in options]
        if not self._options:
            # 编程错误而非用户可见文案，不进 i18n 目录。
            raise ValueError("CapsuleSegmentedControl requires at least one segment")
        self._index = max(0, min(len(self._options) - 1, int(current)))
        self._thumb = float(self._index)
        self.setFixedHeight(int(height))
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._anim = QPropertyAnimation(self, b"thumbPosition", self)
        self._anim.setDuration(self._ANIM_MS)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    # ---------- 属性（供动画使用） ----------
    def thumb_position(self) -> float:
        return self._thumb

    def set_thumb_position(self, value: float) -> None:
        self._thumb = float(value)
        self.update()

    thumbPosition = Property(float, thumb_position, set_thumb_position)

    # ---------- 对外接口 ----------
    def current_index(self) -> int:
        return self._index

    def current_key(self) -> str:
        return self._options[self._index][0]

    def label_at(self, index: int) -> str:
        return self._options[index][1]

    def count(self) -> int:
        return len(self._options)

    def set_current_index(self, index: int, *, animate: bool = True, notify: bool = True) -> None:
        index = max(0, min(len(self._options) - 1, int(index)))
        changed = index != self._index
        self._index = index
        self._anim.stop()
        if animate:
            self._anim.setStartValue(self._thumb)
            self._anim.setEndValue(float(index))
            self._anim.start()
        else:
            self.set_thumb_position(float(index))
        self.update()
        if changed and notify:
            self.changed.emit(index)

    # ---------- 尺寸与绘制 ----------
    def _segment_font(self, bold: bool) -> QFont:
        font = QFont(self.font())
        font.setPointSize(self._FONT_PT)
        font.setBold(bold)
        return font

    def _segment_width(self) -> float:
        return max((self.width() - self._PADDING * 2) / len(self._options), 1.0)

    def _index_at(self, x: float) -> int:
        offset = (x - self._PADDING) / self._segment_width()
        return max(0, min(len(self._options) - 1, int(offset)))

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if not self.isEnabled():
            return
        self.set_current_index(self._index_at(event.position().x()))
        event.accept()

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pal = theme.active()
        width, height = float(self.width()), float(self.height())
        radius = height / 2
        p.setOpacity(0.56 if not self.isEnabled() else 1.0)
        p.setPen(Qt.NoPen)

        p.setBrush(QColor(pal["surface_alt"]))
        p.drawRoundedRect(QRectF(0, 0, width, height), radius, radius)

        segment = self._segment_width()
        thumb_h = height - self._PADDING * 2
        p.setBrush(QColor(pal["surface"]))
        p.drawRoundedRect(
            QRectF(self._PADDING + self._thumb * segment, self._PADDING, segment, thumb_h),
            thumb_h / 2,
            thumb_h / 2,
        )

        for i, (_, label) in enumerate(self._options):
            selected = i == self._index
            p.setFont(self._segment_font(selected))
            metrics = p.fontMetrics()
            rect = QRectF(self._PADDING + i * segment, 0, segment, height)
            p.setPen(QColor(pal["text"] if selected else pal["muted"]))
            p.drawText(
                rect,
                Qt.AlignCenter,
                metrics.elidedText(label, Qt.ElideRight, int(segment) - 8),
            )
        p.end()


class NoticeBar(QFrame):
    """顶部悬浮通知条：新消息出现时浮在内容之上，不占布局、不阻挡内容。

    对齐安卓端的顶部通知条：顶部居中、宽度取 ``min(宿主宽 - 32, 560)``、反色胶囊
    （浅色主题为深底浅字，深色主题相反）、停留 4 秒后淡出、点击立即关闭。同一时刻
    只显示一条，新消息直接替换旧消息并重新计时。
    """

    _MAX_WIDTH = 560
    _SIDE_MARGIN = 16
    _TOP_MARGIN = 12
    _DURATION_MS = 4_000
    _FADE_IN_MS = 180
    _FADE_OUT_MS = 240

    def __init__(self, host: QWidget):
        super().__init__(host)
        self._host = host
        self.setObjectName("NoticeBar")
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.NoFocus)
        # 悬浮层不该抢鼠标：只在自身范围内响应点击（用于关闭）。
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 10, 18, 10)
        self.label = QLabel("")
        self.label.setObjectName("NoticeBarText")
        self.label.setTextFormat(Qt.PlainText)
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)

        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(0.0)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.finished.connect(self._on_fade_finished)

        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self._fade_out)

        self.hide()

    # ---------- 对外接口 ----------
    def show_message(self, text: str) -> None:
        text = str(text or "")
        if not text:
            return
        self.label.setText(text)
        # 先 show 再定位：未显示的控件拿不到有效宿主尺寸，reposition 会算错。
        self.show()
        self.raise_()
        self.reposition()
        self._fade.stop()
        self._fade.setDuration(self._FADE_IN_MS)
        self._fade.setStartValue(self._effect.opacity())
        self._fade.setEndValue(1.0)
        self._fade.start()
        self._hide_timer.start(self._DURATION_MS)

    def dismiss(self) -> None:
        if self.isVisible():
            self._fade_out()

    def reposition(self) -> None:
        available = max(self._host.width() - self._SIDE_MARGIN * 2, 120)
        self.setFixedWidth(min(available, self._MAX_WIDTH))
        self._resize_to_text()
        self.move((self._host.width() - self.width()) // 2, self._TOP_MARGIN)

    # ---------- 内部 ----------
    def _resize_to_text(self) -> None:
        """固定宽度后重新量高：换行后的高度要由布局按宽度算出，不能用 sizeHint。"""
        layout = self.layout()
        if layout is not None:
            layout.activate()
            height = layout.totalHeightForWidth(self.width()) if layout.hasHeightForWidth() else layout.sizeHint().height()
        else:
            height = self.sizeHint().height()
        self.setFixedHeight(max(height, 36))

    def _fade_out(self) -> None:
        self._hide_timer.stop()
        self._fade.stop()
        self._fade.setDuration(self._FADE_OUT_MS)
        self._fade.setStartValue(self._effect.opacity())
        self._fade.setEndValue(0.0)
        self._fade.start()

    def _on_fade_finished(self) -> None:
        if self._effect.opacity() <= 0.01:
            self.hide()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self.dismiss()
        event.accept()


def shake(target: QWidget) -> None:
    """左右抖动目标控件，用作密码错误视觉反馈。"""
    try:
        prev = getattr(target, "_shake_anim", None)
        if prev is not None and prev.state() == QAbstractAnimation.Running:
            # 动画仍在进行中，此时 pos() 是抖动中的偏移位置，不能当作原点；
            # 复用已记录的原点，并停掉旧动画以免两个动画同时争夺 pos 属性。
            home = target._shake_home
            prev.stop()
        else:
            home = target.pos()
        target._shake_home = home
        anim = QPropertyAnimation(target, b"pos", target)
        anim.setDuration(360)
        offsets = (0, -12, 11, -9, 7, -5, 3, 0)
        last = len(offsets) - 1
        for i, dx in enumerate(offsets):
            anim.setKeyValueAt(i / last, QPoint(home.x() + dx, home.y()))
        anim.finished.connect(lambda: target.move(home))
        target._shake_anim = anim
        # 不用 DeleteWhenStopped：那会在动画结束时删除底层 C++ 对象，
        # 导致下次 shake() 读取 _shake_anim.state() 时因对象已销毁而抛出
        # RuntimeError（被下面的 except 吞掉），表现为"只能抖动一次"。
        # 动画的父对象是 target，会随 target 一起被清理，无需手动删除。
        anim.start()
    except Exception:
        pass
