"""主窗口。"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QEvent,
    QFileSystemWatcher,
    QObject,
    QPoint,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import QColor, QDesktopServices, QGuiApplication, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsBlurEffect,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from core import (
    auto_cloud_sync,
    autofill_otp,
    autofill_resolver,
    backup,
    cloud,
    cloud_sync_prefs,
    config,
    crypto,
    importers,
    leak,
    maintenance,
    media_files,
    native_autofill,
    otp,
    password_health,
    pmv_kdf_policy,
    sync,
    window_tracker,
)
from core import export_archive as archive_exporter
from core import log as _log_mod
from core import modules as entry_modules
from core.models import Entry, SecretType
from core.pinyin import pinyin_first_letter
from core.storage import ExternalVaultChange, StaleEntryChange, Vault, _make_entry_meta, _make_entry_payload

from . import _clipboard, i18n, render_jobs, theme, widgets
from .theme_reveal import ThemeRevealOverlay
from .cloud_sync_controller import InteractiveCloudSyncWorker
from .dialogs import (
    ArchivePasswordDialog,
    BackupPasswordDialog,
    BatchTagInputDialog,
    BrowserImportDialog,
    ConfirmPasswordDialog,
    ConflictDialog,
    EntryDialog,
    NativeAutofillPickerDialog,
    RelockDialog,
    TagFilterDialog,
    TagRenameDialog,
    TagSortDialog,
    UnlockDialog,
    WifiImportDialog,
    _NoScrollComboBox,
    _NoScrollSlider,
    show_image_viewer,
)
from .smooth_scroll import enable_smooth_scroll
from .editor_workspace import (
    DETAIL_BLOCK_SPACING,
    DETAIL_CARD_MARGINS,
    DETAIL_COLUMN_MARGINS,
    DETAIL_FIELD_ROW_SPACING,
    DETAIL_FIELD_SPACING,
    PAGE_MARGINS,
    EditorPage,
    EditorWorkspace,
)
from .image_preview import IMAGE_CLIPBOARD_MAX_BYTES, load_image_thumbnail
from .floating_actions import TranslucentActionButton as _TranslucentActionButton
from .lan_panels import (
    LanSyncStatusPanel,
    LanTransferPanel,
)
from .maintenance_pages import DedupPage, RecycleBinPage, SameServicePage
from .devices_history import DevicesHistoryPage
from .module_editor import AUTOFILL_ROLE_LABELS, passkey_display_rows
from .security_page import SecurityCenterPage
from .settings_page import SettingsPage
from .sync_pages import (
    CloudSyncContext,
    CloudSyncWorkspacePage,
    LanConnectionPage,
    LanPageContext,
    LanStationPage,
    LanWorkspacePage,
    LocalBackupPage,
)

_log = _log_mod.get("app")

_FILE_OPTS = QFileDialog.Option(0)
_NATIVE_AUTOFILL_HOTKEY_ID = 0x5641
_WM_HOTKEY = 0x0312
_WM_WTSSESSION_CHANGE = 0x02B1
_WTS_SESSION_LOCK = 7
_WM_POWERBROADCAST = 0x0218
_PBT_APMSUSPEND = 4
_AUTO_SYNC_INTERVALS = auto_cloud_sync.INTERVAL_MINUTES
_AUTO_SYNC_LABELS = ("15分钟", "30分钟", "1小时", "3小时", "6小时", "每天", "每周")
_DETAIL_TYPE_COLORS = {
    SecretType.LOGIN: "#1E88E5",
    SecretType.WIFI: "#06B6D4",
    SecretType.CARD_DOCUMENT: "#3F51B5",
    SecretType.API_KEY: "#43A047",
    SecretType.OTP: "#00BFA5",
    SecretType.SECURE_NOTE: "#546E7A",
    SecretType.SERVER: "#00897B",
    SecretType.CUSTOM: "#6D4C41",
    SecretType.PASSKEY: "#7C3AED",
}


class _MainThreadPasskeyBroker(QObject):
    """Run every Vault mutation on the Qt/UI thread while the pipe stays responsive."""

    _invoke = Signal(object)

    def __init__(self, broker, parent: QObject):
        super().__init__(parent)
        self._broker = broker
        self._invoke.connect(self._dispatch_queued, Qt.ConnectionType.BlockingQueuedConnection)

    @property
    def challenge(self):
        return self._broker.challenge

    def dispatch(self, peer, request):
        if QThread.currentThread() is self.thread():
            return self._broker.dispatch(peer, request)
        call = {"peer": peer, "request": request}
        self._invoke.emit(call)
        if "error" in call:
            raise call["error"]
        return call["result"]

    def _dispatch_queued(self, call) -> None:
        try:
            call["result"] = self._broker.dispatch(call["peer"], call["request"])
        except BaseException as exc:
            call["error"] = exc


def _auto_sync_controls_enabled(*, toggle_checked: bool, target_count: int) -> bool:
    """自动同步已开启且已有目标时，周期控件应立即可用。"""
    return bool(toggle_checked and target_count > 0)


def _detail_type_color(secret_type: str) -> str:
    return _DETAIL_TYPE_COLORS.get(secret_type, _DETAIL_TYPE_COLORS[SecretType.LOGIN])


def _rgba(hex_color: str, alpha: float) -> str:
    color = QColor(hex_color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {max(0.0, min(1.0, alpha)):.3f})"


def _lan_connection_user_message(error: Exception) -> str:
    text = " ".join(str(item) for item in _exception_chain(error)).lower()
    # 配对/票据判定必须排在 403 之前：传输站对旧二维码、旧 PIN、错配 ticket 一律回 403，
    # 若按状态码归类会误报成「对方尚未授权本设备」，把用户引去主机点授权而真正要做的
    # 是重新扫码。
    if "pin" in text or "配对" in text or "票据" in text:
        return "连接码或配对地址已失效，请使用最新二维码或完整地址重新连接"
    if "设备尚未" in text or "未完成授权" in text or "设备未授权" in text:
        return "对方尚未授权本设备。请在传输站一方允许本次同步，并保持两端页面开启"
    if "forbidden" in text:
        # 会话令牌失效（传输站已关闭/重启，或主机侧已释放该会话）。
        return "对方已关闭传输站或连接已失效，请让对方重新建立传输站后用最新二维码连接"
    # 锁定与「等待确认」是两回事，且锁定态同样会用 423 上报：安卓主机在保险库锁定时
    # 回 423 +「PMVE 会话已锁定」，本机作为客户端会原样收到。必须先判锁定，否则
    # 「去解锁」会被说成「重新建立传输站」。
    if "已锁定" in text:
        return "对方保险库已锁定，无法读取或写入。请让对方先解锁本机保险库，再重新建立传输站并在主机端允许本次同步"
    if "423" in text:
        return "对方尚未确认本次连接。请在传输站一方允许本次请求；若已超时，请让对方重新建立传输站后用最新二维码连接"
    if any(value in text for value in ("timed out", "timeout", "refused", "unreachable")):
        return "暂时无法连接，请确认两台设备在同一网络并保持传输窗口开启"
    if "certificate" in text or "证书" in text:
        return "连接的设备身份发生变化，为保护数据已停止连接"
    if "10 gb" in text or "413" in text:
        return "账户数据超过 10 GB 的传输上限，暂时无法通过局域网同步；请改用文件传输或先精简账户"
    return "暂时无法建立连接，请检查网络后重试"


def _lan_sync_user_message(error: Exception) -> str:
    text = " ".join(str(item) for item in _exception_chain(error)).lower()
    if "integrity" in text or "安全检查" in text or "不完整" in text:
        return "传输内容多次检查仍未通过，本次同步未保存任何不完整数据，请保持网络稳定后重试"
    if "不是同一份" in text or "谱系" in text:
        return "两端不是同一份保险库，已停止同步；请打开同一账户，或先通过数据导入复制完整账户"
    if "身份" in text or "签名" in text or "认证失败" in text:
        return "对方保险库未通过当前账户的安全认证，本地数据未被覆盖"
    # 不再按 409 归类：传输站对同步冲突只回两种 409 body——谱系不同与远端 PMVE
    # 认证失败，已分别被上面两档命中；分叉/较旧提交早已改为自动合并保留本端。
    return _lan_connection_user_message(error)


def _exception_chain(error: BaseException):
    current: BaseException | None = error
    while current is not None:
        yield current
        current = current.__cause__ or current.__context__


_LINEAGE_TEXT = {
    "SAME": "双方内容一致",
    "FAST_FORWARD": "已采用对方的新内容",
    "REMOTE_STALE": "已保留本机的新内容",
    "DIVERGED": "双方修改已自动合并",
}


def _lan_sync_result_rows(stats: dict) -> list[tuple[str, str]]:
    """同步结果的键值行；摘要与结果卡片共用同一份口径，避免两处数字对不上。"""
    local = int(stats.get("local_count", 0) or 0)
    merged = int(stats.get("merged_count", local) or 0)
    relationship = str(stats.get("lineage") or "").upper()
    return [
        ("谱系", _LINEAGE_TEXT.get(relationship, "双方数据已合并")),
        ("条目", f"本地 {local} 项 → 合并后 {merged} 项"),
        ("回推", "已回推更新" if stats.get("uploaded") or stats.get("pushed") else "无需回推"),
        ("校验", "已通过安全校验" if stats.get("verified", True) else "尚未完成回读校验"),
    ]


def _lan_sync_result_summary(stats: dict) -> str:
    return " · ".join(text for _, text in _lan_sync_result_rows(stats))


def _lan_transfer_user_message(error: Exception, *, sending: bool) -> str:
    text = str(error).lower()
    if "integrity" in text or "校验" in text or "不完整" in text:
        return "多次检查仍未通过，文件未发送" if sending else "多次检查仍未通过，文件未保存"
    if "10 gb" in text or "10 tib" in text or "413" in text or "too large" in text:
        return "文件过大，当前设备暂时无法传输"
    if "broken pipe" in text or "connection reset" in text or "connection aborted" in text or "reset by peer" in text or "closed by peer" in text:
        return "对方已取消或拒绝接收该文件，已停止发送" if sending else "对方已取消发送该文件，已停止接收"
    return "未能发送文件，请稍后重试" if sending else "未能接收文件，请稍后重试"


def _fit_dialog_to_visible_content(
    dialog: QDialog,
    *,
    preferred_width: int,
    min_height: int = 320,
    extra_height: int = 0,
) -> None:
    """Resize a dynamic dialog to visible content without allowing a mini window."""
    layout = dialog.layout()
    if layout is not None:
        layout.invalidate()
        layout.activate()
    card = getattr(dialog, "card", None)
    if card is not None and card.layout() is not None:
        card.layout().invalidate()
        card.layout().activate()
        card.updateGeometry()
    dialog.updateGeometry()

    hint = dialog.sizeHint()
    if not hint.isValid():
        return

    screen = dialog.screen() or QGuiApplication.primaryScreen()
    available = screen.availableGeometry() if screen is not None else None
    max_width = max(320, available.width() - 48) if available is not None else 1600
    max_height = max(min_height, available.height() - 48) if available is not None else 1000
    target = QSize(
        min(max_width, max(preferred_width, hint.width())),
        min(max_height, max(min_height, hint.height() + extra_height)),
    )

    # Clear stale constraints left by a previous larger visible state, then
    # apply a bounded size explicitly. adjustSize() alone does not reliably
    # shrink a visible frameless dialog on Windows.
    dialog.setMinimumHeight(0)
    dialog.setMaximumHeight(max_height)
    dialog.resize(target)

    if available is not None:
        frame = dialog.frameGeometry()
        dx = 0
        dy = 0
        if frame.left() < available.left():
            dx = available.left() - frame.left()
        elif frame.right() > available.right():
            dx = available.right() - frame.right()
        if frame.top() < available.top():
            dy = available.top() - frame.top()
        elif frame.bottom() > available.bottom():
            dy = available.bottom() - frame.bottom()
        if dx or dy:
            dialog.move(dialog.pos() + QPoint(dx, dy))


class _PasswordStatsWorker(QThread):
    """在后台线程计算密码健康统计（风险/重复/弱密码）与筛选集合。

    原实现在主线程对每条目调用 ``leak.entry_secret`` 解密全部密码，云端同步等
    导致条目集合变化时会触发上千次 AES 解密，阻塞 UI 数秒（卡片卡死）。
    此处仅主线程算廉价签名，真正解密搬到子线程，结果回写缓存后刷新界面。
    """

    result = Signal(str, dict, dict)

    def __init__(self, vault, signature: str, weak_fn, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._signature = signature
        self._weak_fn = weak_fn

    def run(self) -> None:
        secrets: list = []
        try:
            for e in self._vault.entries:
                try:
                    secret = leak.entry_secret(e)
                except Exception:  # noqa: BLE001
                    secret = ""
                secrets.append((e, secret))
            weak: set = set()
            dup_counts: dict = {}
            for _e, s in secrets:
                if s:
                    if self._weak_fn(s):
                        weak.add(_e.id)
                    dup_counts[s] = dup_counts.get(s, 0) + 1
            duplicate = {eid for eid, s2 in ((e.id, s) for e, s in secrets) if s2 and dup_counts[s2] > 1}
            risk = {e.id for e, s in secrets if s and (leak.is_entry_leaked_cached(e) or leak.is_common_weak(s))}
            counts = {"risk": len(risk), "duplicate": len(duplicate), "weak": len(weak)}
            self.result.emit(self._signature, counts, {"risk": risk, "duplicate": duplicate, "weak": weak})
        except Exception:  # noqa: BLE001
            _log.exception("后台密码统计计算失败")
        finally:
            for e, _s in secrets:
                release = getattr(e, "release_sensitive", None)
                if release is not None:
                    release()


class _AutoCloudSyncWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_path: Path, password: crypto.SecureString, target: str, payload, parent=None):
        super().__init__(parent)
        self.vault_path = vault_path
        self.password = password
        self.target = target
        self.payload = payload

    def run(self) -> None:
        try:
            with self.password.bytes() as password:
                if self.target == "drive":
                    result = auto_cloud_sync.sync_drive(self.vault_path, password, self.payload)
                elif self.target == "webdav":
                    result = auto_cloud_sync.sync_webdav(self.vault_path, password, self.payload)
                else:
                    raise cloud.CloudError("自动同步目标无效")
            self.completed.emit(result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
        finally:
            self.password.clear()


# 视为"用户活动"的事件类型：用于超时自动锁定的计时重置
_ACTIVITY_EVENTS = frozenset(
    (
        QEvent.MouseMove,
        QEvent.MouseButtonPress,
        QEvent.MouseButtonRelease,
        QEvent.KeyPress,
        QEvent.KeyRelease,
        QEvent.Wheel,
    )
)
_INVALID_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]+')

# 标签筛选中的特殊值，代表"无标签"，与真实标签名（_active_tag is None 表示"全部"）区分
_UNTAGGED_TAG = "\x00untagged"

_ALPHA_NAV = ["#"] + [chr(c) for c in range(ord("A"), ord("Z") + 1)]


def _safe_filename_part(text: str) -> str:
    return _INVALID_FILENAME_CHARS.sub("_", text).strip() or "tag"


def _format_attachment_size(size: int) -> str:
    size = max(0, int(size))
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _format_storage_size(size: int) -> str:
    size = max(0, int(size))
    if size >= 1024**3:
        return f"{size / 1024**3:.2f} GB"
    if size >= 1024**2:
        return f"{size / 1024**2:.1f} MB"
    if size >= 1024:
        return f"{size // 1024} KB"
    return f"{size} B"


# 编辑/删除前需要二次验证主密码的敏感条目类型
_GUARDED_SECRET_TYPES = (
    SecretType.CARD_DOCUMENT,
    SecretType.API_KEY,
    SecretType.OTP,
    SecretType.SECURE_NOTE,
)


_OTP_ACCENT_COLOR = "#00BFA5"
_SECURITY_SESSION_SECONDS = 5 * 60
_SECURITY_SESSIONS: dict[str, float] = {}


def _security_session_key(vault: Vault) -> str:
    return str(vault.path.resolve())


def _clear_security_sessions() -> None:
    _SECURITY_SESSIONS.clear()


def _confirm_master_password(
    vault: Vault,
    title: str,
    text: str,
    parent=None,
    *,
    always: bool = False,
    session_required: bool = False,
) -> bool:
    """弹出二次密码确认对话框，返回是否验证通过。

    ``always=False`` 时受「查看敏感内容需验证主密码」开关控制：开关关闭则直接放行；
    数据导出类操作应传 ``always=True``，始终强制验证。
    """
    if (
        not always
        and not session_required
        and not config.get(
            "require_master_for_sensitive",
            config.DEFAULT_REQUIRE_MASTER_FOR_SENSITIVE,
        )
    ):
        return True
    key = _security_session_key(vault)
    if not always and time.monotonic() < _SECURITY_SESSIONS.get(key, 0.0):
        return True
    dlg = ConfirmPasswordDialog(vault.verify_password, title, text, confirm_text="验证", parent=parent)
    verified = dlg.exec() == QDialog.Accepted and dlg.unlocked
    if verified:
        _SECURITY_SESSIONS[key] = time.monotonic() + _SECURITY_SESSION_SECONDS
    return verified


_BLUR_CACHE: dict[str, QPixmap] = {}


def _blur_pixmap(px: QPixmap, radius: float, cache_key: str = "") -> QPixmap:
    """对 pixmap 应用高斯模糊，返回同尺寸的新 pixmap（结果可缓存）。"""
    if cache_key:
        cached = _BLUR_CACHE.get(cache_key)
        if cached is not None:
            return cached
    scene = QGraphicsScene()
    item = QGraphicsPixmapItem(px)
    effect = QGraphicsBlurEffect()
    effect.setBlurRadius(radius)
    item.setGraphicsEffect(effect)
    scene.addItem(item)
    result = QPixmap(px.size())
    result.fill(Qt.transparent)
    painter = QPainter(result)
    scene.render(painter, QRectF(result.rect()), QRectF(px.rect()))
    painter.end()
    if cache_key:
        _BLUR_CACHE[cache_key] = result
    return result


class _DetailImgCard(QWidget):
    """详情页只读图片卡：hover 放大 + 显示圆角按钮栏（复制/保存），点击放大查看。"""

    W, H = 200, 150

    def __init__(
        self,
        b64: object,
        parent=None,
        guarded: bool = False,
        *,
        large: bool = False,
        gallery: list[object] | None = None,
        gallery_index: int = 0,
    ):
        super().__init__(parent)
        self._b64 = b64
        self._gallery = list(gallery) if gallery else [b64]
        self._gallery_index = min(max(0, int(gallery_index)), len(self._gallery) - 1)
        self._guarded = guarded
        self._scale_val = 1.0
        self._width = 252 if large else self.W
        self._height = 190 if large else self.H
        self._load_error = ""
        self.setFixedSize(self._width, self._height)
        self.setCursor(Qt.PointingHandCursor)

        self._px = QPixmap()
        self._thumbnail_future = render_jobs.thumbnail_executor.submit(load_image_thumbnail, b64)
        self._thumbnail_timer = QTimer(self)
        self._thumbnail_timer.setInterval(20)
        self._thumbnail_timer.timeout.connect(self._finish_thumbnail)
        self._thumbnail_timer.start()

        bar_w, bar_h = 128, 36
        self._bar = QFrame(self)
        self._bar.setObjectName("ImgBtnBar")
        self._bar.setFixedSize(bar_w, bar_h)
        self._bar.move((self._width - bar_w) // 2, self._height - bar_h - 8)
        self._bar.hide()

        bar_lay = QHBoxLayout(self._bar)
        bar_lay.setContentsMargins(8, 4, 8, 4)
        bar_lay.setSpacing(8)

        self._copy_btn = QPushButton("复制", self._bar)
        self._copy_btn.setObjectName("ImgAction")
        self._copy_btn.setFixedHeight(26)
        self._copy_btn.setToolTip("复制图片")
        self._copy_btn.setAccessibleName("复制图片")
        self._copy_btn.clicked.connect(self._do_copy)
        bar_lay.addWidget(self._copy_btn)

        save_btn = QPushButton("保存", self._bar)
        save_btn.setObjectName("ImgAction")
        save_btn.setFixedHeight(26)
        save_btn.setToolTip("保存原图")
        save_btn.clicked.connect(self._do_save)
        bar_lay.addWidget(save_btn)

        self._anim = QPropertyAnimation(self, b"card_scale", self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def _finish_thumbnail(self) -> None:
        future = self._thumbnail_future
        if not future.done():
            return
        self._thumbnail_timer.stop()
        try:
            image = future.result()
            if not image.isNull():
                self._px = QPixmap.fromImage(image)
                if self._effective_guarded():
                    self._px = _blur_pixmap(
                        self._px, radius=18, cache_key=media_files.cache_key(self._b64)
                    )
        except Exception as exc:
            self._load_error = i18n.tr_dynamic(str(exc) or "图片无法读取")
        self.update()

    def _effective_guarded(self) -> bool:
        if not self._guarded:
            return False
        return bool(config.get("require_master_for_sensitive", config.DEFAULT_REQUIRE_MASTER_FOR_SENSITIVE))

    def _get_scale(self):
        return self._scale_val

    def _set_scale(self, v: float):
        self._scale_val = v
        self.update()

    card_scale = Property(float, _get_scale, _set_scale)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.SmoothPixmapTransform)

        c = theme.active()
        clip = QPainterPath()
        clip.addRoundedRect(0, 0, self._width, self._height, 8, 8)
        p.setClipPath(clip)
        p.fillRect(self.rect(), QColor(c["surface_alt"]))

        if not self._px.isNull():
            p.save()
            p.translate(self._width / 2.0, self._height / 2.0)
            p.scale(self._scale_val, self._scale_val)
            p.translate(-self._width / 2.0, -self._height / 2.0)
            scaled = self._px.scaled(self._width, self._height, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            p.drawPixmap((self._width - scaled.width()) // 2, (self._height - scaled.height()) // 2, scaled)
            p.restore()
        elif self._load_error:
            p.setPen(QColor(c["muted"]))
            p.drawText(self.rect().adjusted(14, 0, -14, 0), Qt.AlignCenter | Qt.TextWordWrap, self._load_error)

        if self._effective_guarded():
            p.fillRect(self.rect(), QColor(0, 0, 0, 160))
            p.setPen(QColor("#ffffff"))
            lock_pm = widgets.ui_icon("lock").pixmap(24, 24)
            p.drawPixmap((self.width() - 24) // 2, self.height() // 2 - 30, lock_pm)
            p.drawText(
                self.rect().adjusted(0, 20, 0, 0),
                Qt.AlignCenter,
                i18n.tr("点击验证主密码查看"),
            )

        p.setClipping(False)
        p.setPen(QColor(c["border"]))
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(0, 0, self._width - 1, self._height - 1, 8, 8)

    def enterEvent(self, event):
        self._anim.stop()
        self._anim.setStartValue(self._scale_val)
        self._anim.setEndValue(1.06)
        self._anim.start()
        self._bar.show()

    def leaveEvent(self, event):
        from PySide6.QtGui import QCursor

        if not self.rect().contains(self.mapFromGlobal(QCursor.pos())):
            self._anim.stop()
            self._anim.setStartValue(self._scale_val)
            self._anim.setEndValue(1.0)
            self._anim.start()
            self._bar.hide()

    def _verify_master(self) -> bool:
        win = self.window()
        if not isinstance(win, MainWindow):
            return False
        return _confirm_master_password(win.vault, "查看图片", "查看该图片需要验证当前主密码。", win)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            if self._load_error:
                widgets.message(self.window(), "图片无法读取", self._load_error, kind="warning")
                return
            if self._effective_guarded() and not self._verify_master():
                return
            try:
                show_image_viewer(
                    self._gallery,
                    self.window(),
                    initial_index=self._gallery_index,
                )
            except Exception as exc:
                widgets.message(self.window(), "图片无法读取", i18n.tr_dynamic(str(exc) or "无法打开图片"), kind="warning")

    def _do_copy(self):
        if self._effective_guarded() and not self._verify_master():
            return
        try:
            _clipboard.copy_image(media_files.to_base64(self._b64, IMAGE_CLIPBOARD_MAX_BYTES))
        except Exception as exc:
            widgets.message(
                self.window(),
                "复制图片失败",
                i18n.tr_dynamic(str(exc) or "图片过大或无法读取"),
                "warning",
            )
            return
        win = self.window()
        if isinstance(win, MainWindow):
            if win._clipboard_clear_ms:
                win._flash(f"已复制（隐身，{win._clipboard_clear_ms // 1000} 秒后自动清除）")
                QTimer.singleShot(win._clipboard_clear_ms, lambda: _clipboard.clear_image_if_present())
            else:
                win._flash("已复制（隐身）")
        self._flash_copy_text()

    def _flash_copy_text(self, *, duration_ms: int = 1500) -> None:
        token = int(self._copy_btn.property("copyFeedbackToken") or 0) + 1
        self._copy_btn.setProperty("copyFeedbackToken", token)
        self._copy_btn.setText("已复制")
        self._copy_btn.setAccessibleName("已复制")
        self._copy_btn.setToolTip("已复制")

        def restore() -> None:
            try:
                if int(self._copy_btn.property("copyFeedbackToken") or 0) != token:
                    return
                self._copy_btn.setText("复制")
                self._copy_btn.setAccessibleName("复制图片")
                self._copy_btn.setToolTip("复制图片")
            except RuntimeError:
                return

        QTimer.singleShot(max(0, int(duration_ms)), restore)

    def _do_save(self):
        from pathlib import Path

        if self._effective_guarded() and not self._verify_master():
            return
        source = media_files.resolve_ref(self._b64)
        default_name = f"image{source.suffix}" if source is not None else "image.jpg"
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n.tr("保存图片"),
            default_name,
            i18n.tr("JPEG 图片 (*.jpg);;PNG 图片 (*.png);;GIF 图片 (*.gif);;WebP 图片 (*.webp)"),
            options=_FILE_OPTS,
        )
        if not path:
            return
        try:
            media_files.export_value(self._b64, Path(path))
        except Exception as exc:
            widgets.message(self, "图片保存失败", i18n.tr_dynamic(str(exc) or "无法保存图片"), "warning")


class _EntryListCard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("EntryListCard")
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

        row = QHBoxLayout(self)
        row.setContentsMargins(14, 12, 14, 12)
        row.setSpacing(12)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(8)

        self.icon = QLabel()
        self.icon.setFixedSize(32, 32)
        self.icon.setAlignment(Qt.AlignCenter)
        row.addWidget(self.icon, 0, Qt.AlignTop)

        self.title = QLabel()
        self.title.setObjectName("EntryTitle")
        self.title.setTextFormat(Qt.PlainText)
        self.title.setWordWrap(True)
        self.title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        text_col.addWidget(self.title)

        self.otp_code = QLabel()
        self.otp_code.setObjectName("OtpCodeCard")
        self.otp_code.setTextFormat(Qt.PlainText)
        self.otp_code.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.otp_code.setVisible(False)
        text_col.addWidget(self.otp_code)

        self.sub = QLabel()
        self.sub.setObjectName("EntrySub")
        self.sub.setTextFormat(Qt.PlainText)
        self.sub.setWordWrap(True)
        self.sub.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        text_col.addWidget(self.sub)

        row.addLayout(text_col, 1)

        self.badges = QVBoxLayout()
        self.badges.setContentsMargins(0, 0, 0, 0)
        self.badges.setSpacing(6)
        self.badges.setAlignment(Qt.AlignRight | Qt.AlignTop)
        row.addLayout(self.badges)

    def refresh(self, item: "EntryListItem") -> None:
        e = item.entry
        self.icon.setPixmap(widgets.category_pixmap(item.display_type, 28))
        self.title.setText(e.title)

        self.sub.setVisible(e.secret_type != SecretType.SECURE_NOTE)
        if e.secret_type != SecretType.SECURE_NOTE:
            self.sub.setText(e.display_secret or e.url or "—")
        if e.secret_type == SecretType.OTP:
            self._refresh_otp(e)
            self.otp_code.setVisible(True)
        else:
            self.otp_code.setVisible(False)

        specs = item.badge_specs()
        if not specs:
            if self.badges.count():
                self._clear_badges()
            return

        if self.badges.count():
            self._clear_badges()
        for text, kind in specs:
            badge = QLabel(text)
            badge.setObjectName(f"EntryBadge_{kind}")
            badge.setAlignment(Qt.AlignCenter)
            self.badges.addWidget(badge, 0, Qt.AlignRight)

    def _refresh_otp(self, entry: Entry) -> None:
        try:
            fields = otp.normalize_fields(entry.fields)
            self.otp_code.setText(otp.code_from_fields(fields))
        finally:
            release = getattr(entry, "release_sensitive", None)
            if callable(release):
                release()

    def _clear_badges(self) -> None:
        while self.badges.count():
            layout_item = self.badges.takeAt(0)
            widget = layout_item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()

    def sizeHint(self) -> QSize:
        if self.layout() is not None:
            self.layout().activate()
            hint = self.layout().sizeHint()
        else:
            hint = super().sizeHint()
        return QSize(min(hint.width(), 280), max(76, hint.height()))

    def apply_width(self, w: int) -> None:
        self.setFixedWidth(w)
        self.layout().activate()
        h = self.layout().sizeHint().height()
        self.setFixedHeight(max(76, h))


class EntryListItem(QListWidgetItem):
    def __init__(self, entry: Entry, leaked: bool | None = None, *, display_type: str | None = None):
        super().__init__()
        self.entry = entry
        self.display_type = display_type or entry.secret_type
        self.leaked = leak.is_entry_leaked(entry) if leaked is None else leaked
        self.card_widget: _EntryListCard | None = None
        self._otp_cache_code: str | None = None
        self._otp_cache_key = None

    def status(self) -> str | None:
        if self.entry.secret_type != SecretType.CARD_DOCUMENT:
            return None
        try:
            return self.entry.expiry_status()
        finally:
            release = getattr(self.entry, "release_sensitive", None)
            if callable(release):
                release()

    def badge_specs(self) -> list[tuple[str, str]]:
        badges: list[tuple[str, str]] = []
        if self.leaked:
            badges.append((i18n.tr("已泄露"), "danger"))
        status = self.status()
        if status == "expired":
            badges.append((i18n.tr("已过期"), "danger"))
        elif status == "expiring_soon":
            badges.append((i18n.tr("即将过期"), "warn"))
        return badges

    def refresh(self) -> None:
        self.setText("")
        c = theme.active()
        self.setForeground(QColor(c["text"]))
        if self.card_widget is not None:
            self.card_widget.refresh(self)
            self.setSizeHint(self.card_widget.sizeHint())


class _EntryListDelegate(QStyledItemDelegate):
    """Paint entry rows without per-row QWidget creation."""

    def sizeHint(self, option, index) -> QSize:
        return QSize(option.rect.width(), 96)

    def paint(self, painter: QPainter, option, index) -> None:
        item = index.data(Qt.UserRole)
        if not isinstance(item, EntryListItem):
            super().paint(painter, option, index)
            return

        e = item.entry
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

        content_top = int(rect.center().y() - 14) if e.secret_type == SecretType.SECURE_NOTE else rect.top() + 14
        icon = widgets.category_pixmap(item.display_type, 28)
        painter.drawPixmap(rect.left() + 12, content_top, icon)

        left = rect.left() + 52
        right = rect.right() - 12
        badge_specs = item.badge_specs()
        badge_right = right
        badge_height = 22
        for text, kind in reversed(badge_specs):
            fm = painter.fontMetrics()
            badge_w = max(54, fm.horizontalAdvance(text) + 18)
            badge_rect = QRectF(badge_right - badge_w, rect.top() + 12, badge_w, badge_height)
            color_key = "danger" if kind == "danger" else "warn"
            painter.setPen(Qt.NoPen)
            badge_color = QColor(c[color_key])
            badge_color.setAlpha(38)
            painter.setBrush(badge_color)
            painter.drawRoundedRect(badge_rect, 6, 6)
            painter.setPen(QColor(c[color_key]))
            painter.drawText(badge_rect, Qt.AlignCenter, text)
            badge_right -= badge_w + 6

        title_right = max(left + 40, badge_right - 8)
        title_top = rect.center().y() - 12 if e.secret_type == SecretType.SECURE_NOTE else rect.top() + 12
        title_rect = QRectF(left, title_top, title_right - left, 24)
        font = painter.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() + 0.75)
        painter.setFont(font)
        painter.setPen(QColor(c["text"]))
        title = painter.fontMetrics().elidedText(
            e.title or i18n.tr("未命名"),
            Qt.ElideRight,
            int(title_rect.width()),
        )
        painter.drawText(title_rect, Qt.AlignLeft | Qt.AlignVCenter, title)

        if e.secret_type == SecretType.OTP:
            fields_norm = otp.normalize_fields(e.fields)
            if fields_norm.get("type") == "hotp":
                wkey = ("hotp", fields_norm.get("counter"))
            else:
                wkey = ("totp", int(time.time() // max(1, int(fields_norm.get("period", 30)))))
            if item._otp_cache_key != wkey or item._otp_cache_code is None:
                try:
                    item._otp_cache_code = otp.code_from_fields(e.fields)
                except Exception:
                    item._otp_cache_code = ""
                finally:
                    release = getattr(e, "release_sensitive", None)
                    if callable(release):
                        release()
                item._otp_cache_key = wkey
            code = item._otp_cache_code or "------"
            code_rect = QRectF(left, rect.top() + 34, right - left, 28)
            code_font = painter.font()
            code_font.setBold(True)
            code_font.setPointSize(c.get("otp_card_font_size", 12))
            code_font.setFamilies(["Cascadia Code", "JetBrains Mono", "Fira Code", "Consolas", "monospace"])
            painter.setFont(code_font)
            painter.setPen(QColor(_OTP_ACCENT_COLOR))
            painter.drawText(code_rect, Qt.AlignLeft | Qt.AlignVCenter, code or "------")

            font.setBold(False)
            font.setPointSizeF(font.pointSizeF() - 0.75)
            painter.setFont(font)
            sub = e.display_secret or e.url or "-"
            sub_rect = QRectF(left, rect.top() + 58, right - left, 20)
            painter.setPen(QColor(c["muted"]))
            sub = painter.fontMetrics().elidedText(sub, Qt.ElideRight, int(sub_rect.width()))
            painter.drawText(sub_rect, Qt.AlignLeft | Qt.AlignVCenter, sub)
        elif e.secret_type != SecretType.SECURE_NOTE:
            font.setBold(False)
            font.setPointSizeF(font.pointSizeF() - 0.75)
            painter.setFont(font)
            sub = e.display_secret or e.url or "-"
            sub_rect = QRectF(left, rect.top() + 44, right - left, 24)
            painter.setPen(QColor(c["muted"]))
            sub = painter.fontMetrics().elidedText(sub, Qt.ElideRight, int(sub_rect.width()))
            painter.drawText(sub_rect, Qt.AlignLeft | Qt.AlignVCenter, sub)

            # Draw tags
            if e.tags:
                tag_font = painter.font()
                tag_font.setPointSizeF(tag_font.pointSizeF() - 1)
                tag_font.setBold(False)
                painter.setFont(tag_font)
                tag_x = left
                tag_y = rect.top() + 70
                tag_h = 18
                margin = 6
                for tag in e.tags[:3]:  # max 3 tags
                    tag_w = painter.fontMetrics().horizontalAdvance(tag) + margin * 2 + 4
                    if tag_x + tag_w > right:
                        break
                    tag_rect = QRectF(tag_x, tag_y, tag_w, tag_h)
                    painter.setPen(Qt.NoPen)
                    chip_bg = QColor(c["accent_soft"])
                    painter.setBrush(chip_bg)
                    painter.drawRoundedRect(tag_rect, 4, 4)
                    painter.setPen(QColor(c["accent_text"]))
                    painter.drawText(tag_rect, Qt.AlignCenter, tag)
                    tag_x += tag_w + 4
        painter.restore()


class _OtpCodeWidget(QWidget):
    def __init__(self, otp_fields: dict, copy_callback, parent=None):
        super().__init__(parent)
        self._fields = otp.normalize_fields(otp_fields)

        card = QFrame()
        card.setObjectName("Card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(20, 20, 20, 16)
        card_lay.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(12)
        self._code = QLabel("------")
        self._code.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._code.setObjectName("OtpDigitDisplay")
        self._code.setAlignment(Qt.AlignCenter)
        top.addWidget(self._code, 1)
        copy = widgets.icon_only_button("copy", "复制", size=16, object_name="Ghost")
        copy.clicked.connect(lambda: self._copy_callback(self._code.text(), copy, secret=True))
        top.addWidget(copy)
        card_lay.addLayout(top)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(8)
        self._progress = QProgressBar()
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(6)
        progress_row.addWidget(self._progress, 1)
        self._countdown = QLabel("30s")
        self._countdown.setObjectName("OtpCountdown")
        self._countdown.setFixedWidth(42)
        self._countdown.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        progress_row.addWidget(self._countdown)
        card_lay.addLayout(progress_row)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._refresh()
        if self._fields.get("type") == "totp":
            self._timer.start()

    def _refresh(self) -> None:
        code = otp.code_from_fields(self._fields)
        self._code.setText(code)
        typ = self._fields.get("type", "totp")
        if typ == "hotp":
            self._progress.hide()
            self._countdown.hide()
            return
        self._progress.show()
        self._countdown.show()
        period = max(1, int(self._fields.get("period", "30")))
        remaining = otp.seconds_remaining(self._fields)
        self._progress.setRange(0, period)
        self._progress.setValue(remaining)
        self._countdown.setText(f"{remaining}s")


class _LeakAuditWorker(QThread):
    """顺序执行未缓存的泄露检测；相同密码在本轮中只查询一次。"""

    progress = Signal(int, int)
    completed = Signal(object)

    def __init__(self, snapshots: list[tuple[str, float, str]], *, manual: bool = False, parent=None):
        super().__init__(parent)
        self._snapshots = snapshots
        self.manual = manual

    def run(self) -> None:
        try:
            results = leak.audit_snapshots(
                self._snapshots,
                should_stop=self.isInterruptionRequested,
                on_progress=self.progress.emit,
            )
        finally:
            self._snapshots = []
        self.completed.emit(results)


class _AutoCompactWorker(QThread):
    """后台执行一次 PMVE 压缩，任务由调用方选择策略（阈值判定或强制）。"""

    completed = Signal(bool)
    failed = Signal(str)

    def __init__(self, task, vault, parent=None):
        super().__init__(parent)
        self._task = task
        self._vault = vault

    def run(self) -> None:
        try:
            compacted = bool(self._task())
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        finally:
            self._task = None
            self._vault = None
        self.completed.emit(compacted)


class _TempCleanupWorker(QThread):
    """后台回收崩溃残留的临时文件（启动与解锁后自动执行，无手动入口）。"""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_path, parent=None):
        super().__init__(parent)
        self._vault_path = vault_path

    def run(self) -> None:
        try:
            report = maintenance.clean_stale_temp_files(self._vault_path)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        finally:
            self._vault_path = None
        self.completed.emit(report)


FLOATING_ACTION_BOTTOM_MARGIN = 18
# 侧边栏底部安全距离：同时作用于「分隔线 + ＋ 新增条目」这一组的下方留白，
# 使整组不贴窗口下沿。
SIDEBAR_BOTTOM_SAFE_MARGIN = 20
# 两侧按钮相对卡片底边使用相同留白，详情页已不再内缩边框。
LIST_ADD_BOTTOM_MARGIN = FLOATING_ACTION_BOTTOM_MARGIN


class _FloatingOverlay:
    """贴在宿主底边悬浮、不占布局空间的浮层控件。"""

    _H_MARGIN = 16
    _BOTTOM_MARGIN = FLOATING_ACTION_BOTTOM_MARGIN

    def float_over(self, host: QWidget) -> None:
        self._float_host = host
        host.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if obj is getattr(self, "_float_host", None) and event.type() in (QEvent.Resize, QEvent.Show):
            self._reposition()
        return super().eventFilter(obj, event)

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._reposition()

    def _reposition(self) -> None:
        if not self.isVisible():
            return
        self.adjustSize()
        x = (self._float_host.width() - self.width()) // 2
        y = self._float_host.height() - self.height() - self._BOTTOM_MARGIN
        self.move(max(self._H_MARGIN, x), max(self._H_MARGIN, y))
        self.raise_()


BOTTOM_ACTION_HEIGHT = 48
MAIN_SPLITTER_HANDLE_WIDTH = 6
MIN_LIST_PANE_WIDTH = 240
MIN_DETAIL_PANE_WIDTH = 360


class _FloatingDetailActions(QObject):
    _GAP = 8
    _H_MARGIN = 16
    _BOTTOM_MARGIN = FLOATING_ACTION_BOTTOM_MARGIN

    def __init__(self, host: QWidget, *, on_edit, on_delete, parent=None) -> None:
        super().__init__(parent if parent is not None else host)
        self._host = host
        self._visible = False

        self.edit_button = _TranslucentActionButton(i18n.tr("编辑"), host)
        self.edit_button.setObjectName("DetailAction")
        self.edit_button.setFixedHeight(BOTTOM_ACTION_HEIGHT)
        self.edit_button.setCursor(Qt.PointingHandCursor)
        self.edit_button.setAccessibleName(i18n.tr("编辑"))
        self.edit_button.clicked.connect(on_edit)
        self.edit_button.hide()

        self.delete_button = _TranslucentActionButton(i18n.tr("删除"), host)
        self.delete_button.setObjectName("DetailDeleteAction")
        self.delete_button.setFixedHeight(BOTTOM_ACTION_HEIGHT)
        self.delete_button.setCursor(Qt.PointingHandCursor)
        self.delete_button.setAccessibleName(i18n.tr("删除"))
        self.delete_button.clicked.connect(on_delete)
        self.delete_button.hide()

        host.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if obj is self._host and event.type() in (QEvent.Resize, QEvent.Show):
            self._reposition()
        return super().eventFilter(obj, event)

    def setVisible(self, visible: bool) -> None:  # noqa: N802
        self._visible = visible
        self.edit_button.setVisible(visible)
        self.delete_button.setVisible(visible)
        if visible:
            self._reposition()

    def _reposition(self) -> None:
        if not self._visible:
            return
        pair_width = min(max(244, int(self._host.width() * 0.6)), self._host.width() - 2 * self._H_MARGIN)
        button_width = (pair_width - self._GAP) // 2
        self.edit_button.setFixedWidth(button_width)
        self.delete_button.setFixedWidth(button_width)
        pair_width = button_width * 2 + self._GAP
        x = max(self._H_MARGIN, (self._host.width() - pair_width) // 2)
        y = max(self._H_MARGIN, self._host.height() - BOTTOM_ACTION_HEIGHT - self._BOTTOM_MARGIN)
        self.edit_button.move(x, y)
        self.delete_button.move(x + self.edit_button.width() + self._GAP, y)
        self.edit_button.raise_()
        self.delete_button.raise_()


class _LinkedAutofillDetailGroup:
    """详情页「关联自动填充内容」的一组：来源条目 + 它提供的填充角色。"""

    __slots__ = ("source_entry_id", "source", "roles")

    def __init__(self, source_entry_id: str, source, roles: list[str]) -> None:
        self.source_entry_id = source_entry_id
        self.source = source
        self.roles = roles


def linked_autofill_detail_groups(entry: Entry, sources) -> list[_LinkedAutofillDetailGroup]:
    """按来源条目分组本条目的自动填充关联，供详情页展示。

    与 Android ``linkedAutofillDetailGroups`` 语义一致：同一来源的多个 link 合并为
    一组，角色去重；已删除的来源不参与匹配（``source`` 为 ``None`` 时仅展示占位）。
    """
    live = {item.id: item for item in sources if not item.deleted_at}
    grouped: dict[str, list[str]] = {}
    for link in entry.autofill_links():
        roles = grouped.setdefault(link.source_entry_id, [])
        for ref in link.fields:
            if ref.role not in roles:
                roles.append(ref.role)
    return [
        _LinkedAutofillDetailGroup(source_id, live.get(source_id), roles)
        for source_id, roles in grouped.items()
    ]


def detail_status_badges(entry: Entry, shown_type: str) -> list[tuple[str, str]]:
    """详情页标题卡内的状态徽章，对齐 Android 的已泄露 / 已过期 / 即将到期 BadgeChip。"""
    badges: list[tuple[str, str]] = []
    try:
        leaked = leak.is_entry_leaked(entry)
    except AttributeError:
        leaked = False
    if leaked:
        count = getattr(entry, "leak_pwned_count", 0) or 0
        if count > 0:
            text = f"已泄露 {count} 次"
        elif getattr(entry, "leak_common_weak", False):
            text = i18n.tr("已泄露（弱密码）")
        else:
            text = i18n.tr("已泄露")
        badges.append((text, "danger"))
    if shown_type == SecretType.CARD_DOCUMENT:
        status = entry.expiry_status()
        expiry = entry.expiry_date_str()
        if status == "expired":
            badges.append((f"已过期（到期日：{expiry or '未知'}）", "danger"))
        elif status:
            badges.append((f"即将到期（到期日：{expiry or '未知'}）", "warn"))
    return badges


class _FloatingAddButton(_FloatingOverlay, _TranslucentActionButton):
    """列表栏底部悬浮的「＋ 新增条目」按钮。

    不进布局（浮在条目之上），贴底居中且宽度随内容自适应；不单独配色，
    与详情页操作条里的「编辑」共用通用 ``QPushButton`` 规则，样式与
    悬停/按下反馈一致。
    """

    _H_MARGIN = 12
    _BOTTOM_MARGIN = LIST_ADD_BOTTOM_MARGIN

    def __init__(self, host: QWidget, text: str, parent=None) -> None:
        super().__init__(text, parent if parent is not None else host)
        self.setObjectName("FloatingAddButton")
        self.setFixedHeight(BOTTOM_ACTION_HEIGHT)
        self.setCursor(Qt.PointingHandCursor)
        self.float_over(host)
        self.hide()

    def _reposition(self) -> None:
        if self.isVisible():
            width = min(max(146, int(self._float_host.width() * 0.48)), self._float_host.width() - 2 * self._H_MARGIN)
            self.setFixedWidth(width)
        super()._reposition()


class MainWindow(widgets.FramelessMain):
    def __init__(self, vault: Vault):
        window_title = "FAEVault" if i18n.current_locale() == "en" else "保险库"
        super().__init__(window_title, min_size=(900, 640))
        _clipboard.sweep_expired_text()
        self.vault = vault
        from core.autofill_exclusions import sync_local_config
        sync_local_config(self.vault, migrate=True)
        self._backup_status_text = ""
        self._backup_status_label = None
        self._install_local_backup_hooks()
        # 首屏稳定后跑一次后台维护。用随窗口销毁的定时器，而不是 singleShot：
        # 窗口已析构时仍排在事件队列里的回调会打到已释放对象上。
        self._maintenance_timer = QTimer(self)
        self._maintenance_timer.setSingleShot(True)
        self._maintenance_timer.setInterval(2_000)
        self._maintenance_timer.timeout.connect(self._run_auto_maintenance)
        self._maintenance_timer.start()
        media_files.ensure_vault_context(self.vault)
        self.resize(1280, 760)
        self.title_bar.setFixedHeight(60)

        self._locked = False
        self._passkey_broker_server = None
        self._passkey_unlock_event = None
        self._passkey_unlock_timer = None
        self._start_passkey_broker()
        self._native_autofill_backend = native_autofill.WindowsUiaBackend()
        self._native_autofill_prepared: native_autofill.PreparedFill | None = None
        self._native_autofill_busy = False
        self._native_autofill_pending = None
        self._native_hotkey_registered = False
        self._session_notifications_registered = False
        self._lock_enabled = True  # 初始值，UI 构建后由 apply_lock_settings 覆盖
        self._pending_select = None
        self._active_type: str | None = None
        self._active_app: str | None = None
        self._app_filter_enabled = False
        self._app_timer = QTimer(self)
        self._app_timer.setInterval(2000)
        self._app_timer.timeout.connect(self._check_foreground_app)
        self._app_timer.start()

        self._reorder_active = False
        self._reorder_order: list[str] = []
        self._drag_row: QWidget | None = None
        self._drag_active = False
        self._drag_timer = QTimer(self)
        self._drag_timer.setSingleShot(True)
        self._drag_timer.setInterval(400)
        self._drag_timer.timeout.connect(self._on_reorder_drag_activate)
        self._leak_worker: _LeakAuditWorker | None = None
        self._leak_worker_vault_path = None
        self._leak_attempted_revisions: set[tuple[str, float]] = set()
        self._leak_rescan_requested = False
        self._leak_audit_started = 0.0
        self._leak_audit_manual = False
        self._leak_audit_total = 0
        self._security_report = password_health.EMPTY_REPORT
        self._temp_cleanup_worker: _TempCleanupWorker | None = None

        self._password_filter = None
        self._password_stats_cache = None
        self._password_stats_sig = None
        self._pw_stats_id_sets = None
        self._pw_stats_sig = None
        self._pw_stats_worker = None
        self._password_stat_buttons: dict = {}

        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._on_idle_timeout)
        self._auto_lock_blockers: set[str] = set()

        self._select_timer = QTimer(self)
        self._select_timer.setSingleShot(True)
        self._select_timer.setInterval(0)
        self._select_timer.timeout.connect(self._do_show_selected)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(120)
        self._search_timer.timeout.connect(lambda: self.reload(data_changed=False))

        self._otp_ticker = QTimer(self)
        self._otp_ticker.setInterval(1000)
        self._otp_ticker.timeout.connect(self._tick_otp_cards)
        self._otp_ticker.start()

        self._leak_recheck_timer = QTimer(self)
        self._leak_recheck_timer.setInterval(60 * 60 * 1000)
        self._leak_recheck_timer.timeout.connect(self._schedule_leak_audit)
        self._leak_recheck_timer.start()

        self._vault_watcher = QFileSystemWatcher([str(self.vault.path)], self)
        self._vault_watcher.fileChanged.connect(self._on_vault_file_changed)
        self._external_refresh_timer = QTimer(self)
        self._external_refresh_timer.setSingleShot(True)
        self._external_refresh_timer.setInterval(180)
        self._external_refresh_timer.timeout.connect(self._refresh_external_vault)

        self._auto_sync_workers: dict[str, _AutoCloudSyncWorker] = {}
        self._auto_sync_timer = QTimer(self)
        self._auto_sync_timer.setInterval(60_000)
        self._auto_sync_timer.timeout.connect(self._auto_sync_tick)
        self._auto_sync_timer.timeout.connect(self._remote_update_tick)
        QTimer.singleShot(0, self._remote_update_tick)
        self._auto_sync_timer.start()
        QTimer.singleShot(2_000, self._auto_sync_tick)

        root = QVBoxLayout(self.content)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.title_bar.setCentralWidget(self._build_top_bar())

        cols = QHBoxLayout()
        cols.setContentsMargins(0, 0, 0, 0)
        cols.setSpacing(0)
        cols.addWidget(self._build_sidebar())

        self._list_pane = self._build_list_pane()
        self._detail_pane = self._build_detail_pane()
        self._list_pane.setMinimumWidth(MIN_LIST_PANE_WIDTH)
        self._detail_pane.setMinimumWidth(MIN_DETAIL_PANE_WIDTH)

        self._list_detail = QSplitter(Qt.Horizontal, self.content)
        self._list_detail.setObjectName("MainSplitter")
        self._list_detail.setChildrenCollapsible(False)
        self._list_detail.setHandleWidth(MAIN_SPLITTER_HANDLE_WIDTH)
        self._list_detail.setStretchFactor(0, 4)
        self._list_detail.setStretchFactor(1, 6)
        self._list_detail.addWidget(self._list_pane)
        self._list_detail.addWidget(self._detail_pane)

        self._list_pane_ratio_save_timer = QTimer(self)
        self._list_pane_ratio_save_timer.setSingleShot(True)
        self._list_pane_ratio_save_timer.setInterval(400)
        self._list_pane_ratio_save_timer.timeout.connect(self._save_list_pane_ratio)
        self._list_detail.splitterMoved.connect(self._schedule_list_pane_ratio_save)
        QTimer.singleShot(0, self._restore_list_pane_ratio)

        # 默认选中第一个类目。必须在标签筛选区创建后执行，首次 reload 即按类目刷新标签分区。
        order = self._get_type_order()
        # 跨类目视图仅由安全中心的密码健康筛选进入（见 _apply_password_filter）。
        self._cross_type_filter = False
        if order:
            self._active_type = order[0]
            self._update_chip_styles()
            self._update_add_button()

        cols.addWidget(self._list_detail, 1)
        root.addLayout(cols, 1)

        # 通知走内容区上方的悬浮条，不再占用底部布局（对齐安卓端顶部通知条）。
        self._notice_bar = widgets.NoticeBar(self.content)

        self.reload()

        QApplication.instance().installEventFilter(self)
        self.apply_lock_settings()
        self.apply_privacy_settings()
        QGuiApplication.styleHints().colorSchemeChanged.connect(self._on_system_theme_changed)
        widgets.lock_bus.lock_requested.connect(self._on_lock_requested)
        QTimer.singleShot(0, self.apply_native_autofill_settings)
        QTimer.singleShot(0, self._register_session_notifications)
        self._setup_tray()

    def _schedule_list_pane_ratio_save(self, *_args) -> None:
        timer = getattr(self, "_list_pane_ratio_save_timer", None)
        if timer is not None:
            timer.start()

    def _save_list_pane_ratio(self) -> None:
        splitter = getattr(self, "_list_detail", None)
        if splitter is None:
            return
        sizes = splitter.sizes()
        total = sum(sizes)
        if total <= 0:
            return
        ratio = max(20, min(80, round(sizes[0] * 100 / total)))
        config.set("list_pane_ratio", ratio)

    def _restore_list_pane_ratio(self) -> None:
        splitter = getattr(self, "_list_detail", None)
        if splitter is None:
            return
        total_width = splitter.width() - splitter.handleWidth()
        if total_width <= 0:
            return
        try:
            ratio = int(config.get("list_pane_ratio", config.DEFAULT_LIST_PANE_RATIO))
        except (TypeError, ValueError):
            ratio = config.DEFAULT_LIST_PANE_RATIO
        ratio = max(20, min(80, ratio))
        list_width = round(total_width * ratio / 100)
        min_list_width = MIN_LIST_PANE_WIDTH
        max_list_width = total_width - MIN_DETAIL_PANE_WIDTH
        if max_list_width < min_list_width:
            splitter.setSizes([min_list_width, MIN_DETAIL_PANE_WIDTH])
            return
        list_width = max(min_list_width, min(list_width, max_list_width))
        splitter.setSizes([list_width, total_width - list_width])

    # ---------- 原生程序自动填充 ----------
    def nativeEvent(self, event_type, message):
        try:
            from ctypes import wintypes

            msg = wintypes.MSG.from_address(int(message))
            if (msg.message == _WM_WTSSESSION_CHANGE and msg.wParam == _WTS_SESSION_LOCK) or (
                msg.message == _WM_POWERBROADCAST and msg.wParam == _PBT_APMSUSPEND
            ):
                QTimer.singleShot(0, lambda: self._enter_locked_state("Windows 会话锁定或休眠"))
            if msg.message == _WM_HOTKEY and msg.wParam == _NATIVE_AUTOFILL_HOTKEY_ID:
                if not self._native_autofill_busy and bool(config.get("native_autofill_enabled", True)):
                    self._native_autofill_busy = True
                    try:
                        if self._native_autofill_pending is not None:
                            self._native_autofill_prepared = native_autofill.PreparedFill(
                                self._native_autofill_backend.capture_target(), (),
                            )
                        else:
                            self._native_autofill_prepared = self._native_autofill_backend.prepare()
                    except native_autofill.NativeAutofillError as exc:
                        self._native_autofill_busy = False
                        QTimer.singleShot(0, lambda text=str(exc): self._native_autofill_failed(text))
                    else:
                        QTimer.singleShot(0, self._complete_native_autofill)
                return True, 0
        except Exception:
            pass
        return super().nativeEvent(event_type, message)

    def _register_session_notifications(self) -> None:
        if os.name != "nt" or self._session_notifications_registered:
            return
        try:
            import ctypes

            self._session_notifications_registered = bool(
                ctypes.windll.wtsapi32.WTSRegisterSessionNotification(int(self.winId()), 0)
            )
        except Exception as exc:
            _log.warning("无法注册 Windows 会话锁定通知：%s", exc)

    def _unregister_session_notifications(self) -> None:
        if not self._session_notifications_registered:
            return
        try:
            import ctypes

            ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(int(self.winId()))
        finally:
            self._session_notifications_registered = False

    def apply_native_autofill_settings(self) -> None:
        self._unregister_native_autofill_hotkey()
        if os.name != "nt" or not bool(config.get("native_autofill_enabled", True)):
            return
        try:
            import ctypes

            modifiers = 0x0002 | 0x0004 | 0x4000  # Ctrl + Shift + no-repeat
            self._native_hotkey_registered = bool(ctypes.windll.user32.RegisterHotKey(int(self.winId()), _NATIVE_AUTOFILL_HOTKEY_ID, modifiers, ord("L")))
        except Exception:
            self._native_hotkey_registered = False
        if not self._native_hotkey_registered:
            _log.warning("无法注册原生自动填充快捷键 Ctrl+Shift+L")

    def _unregister_native_autofill_hotkey(self) -> None:
        if not self._native_hotkey_registered:
            return
        try:
            import ctypes

            ctypes.windll.user32.UnregisterHotKey(int(self.winId()), _NATIVE_AUTOFILL_HOTKEY_ID)
        except Exception:
            pass
        self._native_hotkey_registered = False

    def _complete_native_autofill(self) -> None:
        prepared = self._native_autofill_prepared
        self._native_autofill_prepared = None
        try:
            if prepared is None:
                return
            if getattr(prepared.target, "executable_path", "") and not getattr(prepared.target, "signer_sha256", ""):
                from dataclasses import replace
                prepared = replace(prepared, target=replace(prepared.target, signer_sha256=native_autofill.signer_certificate_sha256(prepared.target.executable_path)))
            pending = getattr(self, "_native_autofill_pending", None)
            self._native_autofill_pending = None
            if pending is not None:
                target, entry_id, role, deadline = pending[:4]
                approved = pending[4] if len(pending) > 4 else None
                if self._locked or time.monotonic() > deadline or (prepared.target.hwnd, prepared.target.process_id, prepared.target.executable_path) != (target.hwnd, target.process_id, target.executable_path):
                    raise native_autofill.NativeAutofillError("待填充操作已取消，请在目标程序重新触发自动填充")
                if callable(getattr(self.vault, "reopen", None)):
                    self.vault = self.vault.reopen()
                entry = self.vault.read_entry(entry_id)
                if entry is None or entry.deleted_at is not None or not native_autofill.allowed_for_explicit_fill(entry, prepared.target):
                    raise native_autofill.NativeAutofillError("所选条目已变化，请重新选择")
                sources = [source for link in entry.autofill_links()
                           if (source := self.vault.read_entry(link.source_entry_id)) is not None]
                if native_autofill.is_excluded(prepared.target.process_name, config.get("native_autofill_excluded", [])):
                    return
                if approved is not None and approved != [item.to_dict() for item in [entry, *sources]]:
                    raise native_autofill.NativeAutofillError("所选条目已变化，请重新选择")
                resolved = autofill_resolver.resolve_snapshot(entry, [entry, *sources])
                value = resolved.values.get(role)
                if value is None or not value.value:
                    raise native_autofill.NativeAutofillError("所选字段内容已不可用，请重新选择")
                otp_value = None
                if role == "one_time_code":
                    otp_source = self.vault.read_entry(value.source_entry_id)
                    otp_value = autofill_otp.snapshot(self.vault, otp_source) if otp_source is not None else None
                    if otp_value is None:
                        raise native_autofill.NativeAutofillError("所选字段内容已不可用，请重新选择")
                self._native_autofill_backend.fill_focused(
                    native_autofill.PreparedFill(prepared.target, ()),
                    otp_value.code if otp_value is not None else value.value, role=role,
                )
                if otp_value is not None and otp_value.kind == "hotp":
                    autofill_otp.advance_hotp(self.vault, otp_value.source_id)
                self._flash(i18n.tr("已填充所选字段"))
                return
            if self._locked and not self._unlock_for_native_autofill(prepared):
                return
            if prepared.target.process_id == os.getpid():
                raise native_autofill.NativeAutofillError("不能向保险库自身填充数据")
            if native_autofill.is_excluded(
                prepared.target.process_name,
                config.get("native_autofill_excluded", []),
            ):
                # 与安卓端一致：被排除的程序不提供自动填充建议，直接静默跳过。
                return
            entries = native_autofill.matching_vault_entries(
                self.vault,
                prepared.target.process_name,
                target=prepared.target,
            )
            fallback = not entries or not any(
                native_autofill.entry_matches_target(entry, prepared.target)
                for entry in entries
            )
            if not entries:
                from core.autofill_sources import entry_is_fillable, with_linked_sources
                all_candidates = [entry for entry_id in self.vault.list_entry_ids(SecretType.LOGIN)
                    if (entry := self.vault.read_entry(entry_id)) is not None and entry.deleted_at is None]
                resolved_sources = with_linked_sources(self.vault, all_candidates)
                entries = [entry for entry in all_candidates if entry_is_fillable(entry, resolved_sources)
                    and native_autofill.allowed_for_explicit_fill(entry, prepared.target)]
            if not entries:
                raise native_autofill.NativeAutofillError("保险库中没有可填充的登录条目")
            otp_sources = {entry.id: source for entry in entries if (source := autofill_otp.resolve_source(self.vault, entry)) is not None}
            captured = self._native_autofill_backend.capture_credentials(prepared)
            entry = entries[0]
            from core.autofill_field_mapping import apply_native_mappings, native_origin, native_field_key, with_mapping
            if len(entries) == 1:
                prepared = apply_native_mappings(entry, prepared)
            manual_focus = not prepared.fields or any(getattr(field, "focused", False) and getattr(field, "role", "") == "unknown" for field in prepared.fields)
            available_roles = {}
            approved_snapshots = {}
            for candidate in entries:
                sources = [source for link in candidate.autofill_links() if (source := self.vault.read_entry(link.source_entry_id)) is not None]
                available_roles[candidate.id] = tuple(autofill_resolver.resolve_snapshot(candidate, [candidate, *sources]).values)
                approved_snapshots[candidate.id] = [item.to_dict() for item in [candidate, *sources]]
            action = "fill"
            remember_binding = False
            remember_mapping = False
            if len(entries) > 1 or fallback or bool(captured.password) or manual_focus:
                dialog = NativeAutofillPickerDialog(
                    entries,
                    prepared.target.process_name,
                    self,
                    otp_sources=otp_sources,
                    fallback=fallback,
                    can_save=bool(captured.password),
                    manual_focus=manual_focus,
                    available_roles=available_roles,
                    reasons={item.id: ("exact" if native_autofill.entry_matches_target(item, prepared.target) else "name") for item in entries},
                )
                if dialog.exec() != QDialog.Accepted or dialog.selected_entry is None:
                    if dialog.action != "create":
                        return
                if dialog.action in {"create", "update"}:
                    self._save_native_autofill_credentials(
                        prepared.target,
                        captured,
                        dialog.selected_entry if dialog.action == "update" else None,
                    )
                    return
                entry = dialog.selected_entry
                action = dialog.action
                remember_binding = bool(getattr(dialog, "remember_binding", None) and dialog.remember_binding.isChecked())
                remember_mapping = bool(getattr(dialog, "remember_mapping", None) and dialog.remember_mapping.isChecked())
            if callable(getattr(self.vault, "reopen", None)):
                self.vault = self.vault.reopen()
                refreshed = self.vault.read_entry(entry.id)
                sources = [source for link in refreshed.autofill_links() if (source := self.vault.read_entry(link.source_entry_id)) is not None] if refreshed is not None else []
                if refreshed is None or approved_snapshots.get(entry.id) != [item.to_dict() for item in [refreshed, *sources]]:
                    raise native_autofill.NativeAutofillError("所选条目已变化，请重新选择")
                entry = refreshed
            if not native_autofill.allowed_for_explicit_fill(entry, prepared.target):
                raise native_autofill.NativeAutofillError("程序身份已变化，请重试")
            if remember_binding:
                entry = native_autofill.remember_native_binding(self.vault, entry, prepared.target)
            prepared = apply_native_mappings(entry, prepared)
            linked_entries = [source for link in entry.autofill_links() if (source := self.vault.read_entry(link.source_entry_id)) is not None]
            resolved = autofill_resolver.resolve_snapshot(entry, [entry, *linked_entries])
            otp_resolved = resolved.values.get("one_time_code")
            otp_source = (
                next(
                    (source for source in [entry, *linked_entries] if source.id == otp_resolved.source_entry_id),
                    entry,
                )
                if otp_resolved is not None
                else entry
            )
            otp_value = autofill_otp.snapshot(self.vault, otp_source)
            if action.startswith("manual_"):
                role = action.removeprefix("manual_")
                if role not in resolved.values:
                    raise native_autofill.NativeAutofillError("所选字段内容已不可用，请重新选择")
                focused = next((field for field in prepared.fields if getattr(field, "focused", False)), None)
                if focused is not None:
                    if remember_mapping:
                        origin, key = native_origin(prepared.target), native_field_key(focused, prepared.fields)
                        if not origin or not key:
                            raise native_autofill.NativeAutofillError("此输入框没有稳定标识，无法记住映射")
                        entry = with_mapping(entry, origin, key, role)
                        self.vault.update(entry)
                    from dataclasses import replace
                    selected_field = replace(focused, role="otp" if role == "one_time_code" else role)
                    result = self._native_autofill_backend.fill(replace(prepared, fields=(selected_field,)), entry,
                        otp_code=otp_value.code if otp_value is not None else "", resolved=resolved)
                    if result.otp_filled and otp_value is not None and otp_value.kind == "hotp":
                        autofill_otp.advance_hotp(self.vault, otp_value.source_id)
                    self._flash(i18n.tr("已填充所选字段"))
                    return
                self._native_autofill_pending = (prepared.target, entry.id, role, time.monotonic() + 30, [item.to_dict() for item in [entry, *linked_entries]])
                self._flash("已准备填充：请在 30 秒内点回并清空目标输入框，再按自动填充快捷键")
                return
            else:
                result = self._native_autofill_backend.fill(
                    prepared,
                    entry,
                    otp_code=otp_value.code if otp_value is not None else "",
                    resolved=resolved,
                )
            if result.otp_filled and otp_value is not None and otp_value.kind == "hotp":
                autofill_otp.advance_hotp(self.vault, otp_value.source_id)
            parts = []
            if result.username_filled:
                parts.append("账号")
            if result.password_filled:
                parts.append("密码")
            if result.otp_filled:
                parts.append("动态码")
            parts.extend(result.additional_roles)
            self._flash(f"已向 {prepared.target.process_name} 填充{'和'.join(parts)}")
        except native_autofill.NativeAutofillError as exc:
            self._native_autofill_failed(str(exc))
        finally:
            self._native_autofill_busy = False

    def _save_native_autofill_credentials(
        self,
        target: native_autofill.NativeTarget,
        captured: native_autofill.CapturedCredentials,
        existing: Entry | None,
    ) -> None:
        if not captured.password:
            raise native_autofill.NativeAutofillError("当前程序未允许读取密码输入框，无法保存")
        if existing is not None and not native_autofill.entry_matches_target(existing, target):
            raise native_autofill.NativeAutofillError("所选条目未绑定当前程序，请新建条目保存")
        if existing is None:
            entry = Entry(
                title=target.window_title.strip()[:100] or target.process_name,
                username=captured.username,
                password=captured.password,
                target_app=target.process_name,
            )
        else:
            entry = Entry.from_dict(existing.to_dict())
            entry.username = captured.username
            entry.password = captured.password
            entry.target_app = target.process_name
        if target.executable_path:
            entry.fields[native_autofill.APP_PATH_FIELD] = target.executable_path
        signer_sha256 = target.signer_sha256 or native_autofill.signer_certificate_sha256(target.executable_path)
        if signer_sha256:
            entry.fields[native_autofill.APP_SIGNER_FIELD] = signer_sha256
        if existing is None:
            self.vault.add(entry)
            self.reload()
            self._flash(f"已保存 {target.process_name} 的当前账号")
        else:
            try:
                self.vault.update(entry)
            except StaleEntryChange as exc:
                raise native_autofill.NativeAutofillError("所选条目已变化，请重新选择") from exc
            self.reload()
            self._flash(f"已更新 {target.process_name} 的所选账号")

    def _unlock_for_native_autofill(self, prepared: native_autofill.PreparedFill) -> bool:
        """Unlock only for the pending fill while keeping the main window hidden."""
        if not self._locked:
            return True
        if getattr(self, "_native_autofill_unlock_open", False):
            return False
        self._native_autofill_unlock_open = True
        try:
            process_name = prepared.target.process_name
            dialog = RelockDialog(
                config.get_current_user() or "",
                verify=self.vault.verify_password,
                expected_pmve_identity=(self.vault.pmve_identity if self.vault.device_unlock_key_format == "pmve-root-key" else None),
                auto_hello=True,
                heading="解锁并自动填充",
                description=(f"验证后将直接向「{process_name}」填充，保险库主页面不会打开。"),
            )
            if dialog.exec() != QDialog.Accepted or not dialog.unlocked:
                return False
            media_files.ensure_vault_context(self.vault)
            self._locked = False
            QTimer.singleShot(0, self._remote_update_tick)
            self._reset_idle_timer()
            QTimer.singleShot(0, self._run_auto_maintenance)
            _log.info("后台自动填充解锁成功，主界面保持隐藏")
            return True
        finally:
            self._native_autofill_unlock_open = False

    def _native_autofill_failed(self, message: str) -> None:
        widgets.message(self, "无法自动填充", message, kind="warn")

    # ---------- 锁定 ----------
    def _on_vault_file_changed(self, _path: str) -> None:
        self._external_refresh_timer.start()

    def _refresh_external_vault(self) -> None:
        if self._cloud_threads_running() or any(worker.isRunning() for worker in self.findChildren(InteractiveCloudSyncWorker)):
            # The worker is atomically reconciling this same vault file. Reopening
            # it mid-commit would both stall the UI and race the verified install.
            self._external_refresh_timer.start(250)
            return
        path = str(self.vault.path)
        if path not in self._vault_watcher.files() and self.vault.path.exists():
            self._vault_watcher.addPath(path)
        if not self.vault.has_external_change():
            return
        try:
            self.vault = self.vault.reopen()
        except Exception:
            _log.exception("外部保险库更新后重新载入失败")
            self._flash("保险库已在其他窗口更新，请重新登录")
            return
        media_files.ensure_vault_context(self.vault)
        self.reload()
        self._flash("已同步浏览器保存的登录条目")

    def _sync_kdf_profile_to_config(self) -> None:
        """局域网/云端同步后，将实际的主密钥派生强度写回按保险库隔离的配置，
        使设置页「KDF 安全等级」与同步后的库保持一致（自动识别等级）。"""
        try:
            params = self.vault.kdf_parameters
        except (AttributeError, ValueError):
            return
        try:
            profile = pmv_kdf_policy.PmvKdfProfile.from_parameters(params)
        except Exception:
            return
        key = pmv_kdf_policy.kdf_config_key_for(self.vault)
        if config.get(key) != profile.name:
            config.set(key, profile.name)

    def apply_lock_settings(self) -> None:
        """从配置重新加载超时锁定设置（设置面板保存后调用）。"""
        self._lock_enabled = bool(config.get("lock_enabled", config.DEFAULT_LOCK_ENABLED))
        self._lock_ms = config.lock_seconds() * 1000
        self._reset_idle_timer()

    def _reset_idle_timer(self) -> None:
        if self._locked or not self._lock_enabled or self._auto_lock_blockers:
            self._idle_timer.stop()
            return
        self._idle_timer.start(self._lock_ms)

    def _set_auto_lock_blocker(self, name: str, active: bool) -> None:
        if active:
            self._auto_lock_blockers.add(name)
            self._idle_timer.stop()
        else:
            self._auto_lock_blockers.discard(name)
            self._reset_idle_timer()

    def _on_idle_timeout(self) -> None:
        if self._auto_lock_blockers:
            self._idle_timer.stop()
            return
        self.lock_now()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_top_nav_layout()
        notice = getattr(self, "_notice_bar", None)
        if notice is not None:
            notice.reposition()

    def eventFilter(self, obj, event) -> bool:
        if event.type() == QEvent.ContextMenu and obj in getattr(self, "_tag_context_widgets", ()):
            self._show_tag_context_menu(event.globalPos())
            return True
        if event.type() == QEvent.WindowActivate and obj is self:
            _clipboard.sweep_expired_text()
        if self._lock_enabled and not self._locked and event.type() in _ACTIVITY_EVENTS:
            self._reset_idle_timer()
        if self._reorder_active and isinstance(obj, QWidget) and self._chip_container.isAncestorOf(obj):
            return self._filter_reorder_event(obj, event)
        return super().eventFilter(obj, event)

    def _filter_reorder_event(self, obj, event) -> bool:
        row = obj
        while row is not None and row not in self._type_chips.values():
            row = row.parent()
        if row is None:
            return False
        et = event.type()
        if et == QEvent.MouseButtonPress:
            self._drag_timer.start()
            self._drag_row = row
            self._drag_active = False
            self._set_reorder_row_state(row, "pressed")
            return True
        if et == QEvent.MouseMove:
            if self._drag_active:
                self._reorder_drag_move(event)
            return True
        if et == QEvent.MouseButtonRelease:
            self._drag_timer.stop()
            if self._drag_active:
                self._end_reorder_drag()
            elif self._drag_row is not None:
                self._set_reorder_row_state(self._drag_row, None)
            self._drag_row = None
            return True
        return False

    def _show_sidebar_context_menu(self, pos) -> None:
        if self._reorder_active:
            return
        menu = QMenu(self)
        menu.addAction("调整类目顺序", self._enter_reorder_mode)
        menu.exec(self._chip_container.mapToGlobal(pos))

    def _enter_reorder_mode(self) -> None:
        if self._reorder_active:
            return
        sidebar = self._sidebar_widget
        self._reorder_sidebar_limits = (sidebar.minimumWidth(), sidebar.maximumWidth())
        sidebar.setFixedWidth(sidebar.width())
        self._reorder_active = True
        self._reorder_order = list(self._get_type_order())
        self._sidebar_create_section.hide()
        self._sidebar_separator.hide()
        self._rebuild_reorder_chips()

    def _rebuild_reorder_chips(self) -> None:
        while self._chip_lay.count():
            item = self._chip_lay.takeAt(0)
            if w := item.widget():
                w.deleteLater()
            elif sub := item.layout():
                while sub.count():
                    if sw := sub.takeAt(0).widget():
                        sw.deleteLater()
        self._type_chips.clear()

        for t in self._reorder_order:
            row = QWidget()
            row.setObjectName("ReorderChip")
            row.setFixedHeight(38)
            row.setCursor(Qt.OpenHandCursor)
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(6, 0, 8, 0)
            row_lay.setSpacing(4)

            icon = QLabel()
            icon.setPixmap(widgets.category_icon(t).pixmap(20, 20))
            icon.setFixedSize(20, 20)

            handle = QLabel("⠿")
            handle.setObjectName("ReorderHandle")
            handle.setFixedSize(24, 30)
            handle.setCursor(Qt.OpenHandCursor)
            handle.setAlignment(Qt.AlignCenter)

            label = QLabel(SecretType.LABELS[t])
            label.setObjectName("ReorderChipLabel")

            row_lay.addWidget(handle)
            row_lay.addWidget(icon)
            row_lay.addWidget(label, 1)

            self._type_chips[t] = row
            self._chip_lay.addWidget(row)
            row.installEventFilter(self)
            label.installEventFilter(self)
            handle.installEventFilter(self)

        actions = getattr(self, "_reorder_actions", None)
        if actions is None:
            actions = QWidget(self._sidebar_widget)
            actions_layout = QVBoxLayout(actions)
            actions_layout.setContentsMargins(0, 0, 0, 0)
            actions_layout.setSpacing(4)
            self._sidebar_lay.addWidget(actions)
            self._reorder_actions = actions
        actions_layout = actions.layout()
        while actions_layout.count():
            old = actions_layout.takeAt(0).widget()
            if old is not None:
                old.hide()
                old.deleteLater()

        reset_btn = QPushButton("恢复默认")
        reset_btn.setObjectName("Ghost")
        reset_btn.setFixedHeight(36)
        reset_btn.clicked.connect(self._reset_default_order)
        actions_layout.addWidget(reset_btn)

        ok_btn = QPushButton("确认")
        ok_btn.setObjectName("Primary")
        ok_btn.setFixedHeight(36)
        ok_btn.clicked.connect(self._save_reorder)
        actions_layout.addWidget(ok_btn)
        actions.show()

    def _reset_default_order(self) -> None:
        if not widgets.confirm(
            self,
            "恢复默认顺序",
            "确定将类目顺序恢复为默认吗？当前调整会被重置。",
            kind="warn",
        ):
            return
        self._reorder_order = list(SecretType.NAV_TYPES)
        self._rebuild_reorder_chips()

    def _on_reorder_drag_activate(self) -> None:
        self._drag_active = True
        if self._drag_row:
            self._set_reorder_row_state(self._drag_row, "dragging")
            self._drag_row.raise_()

    def _reorder_drag_move(self, event) -> None:
        if self._drag_row is None:
            return
        max_idx = self._chip_lay.count()
        for i in range(self._chip_lay.count()):
            item = self._chip_lay.itemAt(i)
            if item.widget() is None and item.spacerItem() is not None:
                max_idx = i
                break
        cursor_y = event.globalPos().y()
        target_idx = max_idx
        for i in range(max_idx):
            w = self._chip_lay.itemAt(i).widget()
            if w is None or w is self._drag_row or w not in self._type_chips.values():
                continue
            if cursor_y < w.mapToGlobal(QPoint(0, w.height() // 2)).y():
                target_idx = i
                break
        current_idx = self._get_reorder_index(self._drag_row)
        if target_idx == current_idx:
            return
        item = self._chip_lay.takeAt(current_idx)
        if target_idx > current_idx:
            target_idx -= 1
        self._chip_lay.insertWidget(target_idx, item.widget())

    def _end_reorder_drag(self) -> None:
        if self._drag_row:
            self._set_reorder_row_state(self._drag_row, None)
        self._drag_row = None
        self._drag_active = False

    def _set_reorder_row_state(self, row: QWidget, state: str | None) -> None:
        row.setProperty("pressed", state == "pressed")
        row.setProperty("dragging", state == "dragging")
        cursor = Qt.ClosedHandCursor if state else Qt.OpenHandCursor
        row.setCursor(cursor)
        for child in row.findChildren(QWidget):
            child.setCursor(cursor)
        row.style().unpolish(row)
        row.style().polish(row)
        row.update()

    def _get_reorder_index(self, row) -> int:
        for i in range(self._chip_lay.count()):
            if self._chip_lay.itemAt(i).widget() is row:
                return i
        return -1

    def _save_reorder(self) -> None:
        order = []
        for i in range(self._chip_lay.count()):
            w = self._chip_lay.itemAt(i).widget()
            if w is not None and w in self._type_chips.values():
                t = next(kt for kt, kw in self._type_chips.items() if kw is w)
                order.append(t)
        config.set("category_order", order)
        self._rebuild_add_menu()
        self._exit_reorder_mode()

    def _exit_reorder_mode(self) -> None:
        self._reorder_active = False
        actions = getattr(self, "_reorder_actions", None)
        if actions is not None:
            actions.hide()
        self._rebuild_type_chips()
        self._sidebar_separator.show()
        self._sidebar_create_section.show()
        limits = getattr(self, "_reorder_sidebar_limits", None)
        if limits is not None:
            self._sidebar_widget.setMinimumWidth(limits[0])
            self._sidebar_widget.setMaximumWidth(limits[1])
            self._reorder_sidebar_limits = None

    # ---------- 前台程序检测 ----------
    def _check_foreground_app(self) -> None:
        app = window_tracker.foreground_process_name()
        if app == self._active_app:
            if app and not self._app_timer.property("update_pending"):
                self._app_timer.setProperty("update_pending", True)
                QTimer.singleShot(300, self._refresh_app_indicator)
            return
        self._active_app = app
        if app and self._app_filter_enabled:
            self.reload()
        else:
            self._refresh_app_indicator()

    def _refresh_app_indicator(self) -> None:
        self._app_timer.setProperty("update_pending", False)
        app = self._active_app
        if not app:
            self._app_label.setVisible(False)
            return
        count = (
            sum(1 for e in self.vault.entries if e.deleted_at is None and e.secret_type == SecretType.LOGIN and e.target_app and e.target_app.lower() == app)
            if app
            else 0
        )
        if count > 0:
            icon = "🔍" if self._app_filter_enabled else "📍"
            self._app_label.setText(f"{icon} {app} ({count})")
            self._app_label.setProperty("active", "true" if self._app_filter_enabled else "false")
            self._app_label.style().unpolish(self._app_label)
            self._app_label.style().polish(self._app_label)
            self._app_label.setVisible(True)
        else:
            self._app_label.setVisible(False)

    def _toggle_app_filter(self) -> None:
        self._app_filter_enabled = not self._app_filter_enabled
        self._refresh_app_indicator()
        if self._app_filter_enabled and self._active_app:
            self.reload()
        elif not self._app_filter_enabled:
            self.reload()

    def _prompt_key_convergence(self, password_changed: bool) -> None:
        """同步自动收敛密钥/主密码后：红色警示弹窗（仅确认，不可取消）。

        仅主密码槽更新时，确认后锁定并用新密码重新解锁；恢复密钥等密钥槽
        更新只提示、不锁定。
        """
        if password_changed:
            body = "同步后已自动采用最新的主密码/密钥版本。\n\n确认后将锁定保险库，请使用最新主密码重新解锁。"
        else:
            body = "同步后已自动采用最新的恢复密钥版本，本端密钥数据已更新。\n\n确认后继续使用。"
        widgets.message(self, "主密码/密钥版本已更新", body, kind="error")
        if password_changed:
            self.lock_now()

    def lock_now(self) -> None:
        """手动或超时触发锁定：隐藏主界面，要求重新输入主密码后才能继续。"""
        self._do_lock(None)

    def _on_lock_requested(self, reason: str) -> None:
        """敏感操作二次验证连续失败达到上限：强制锁定应用并说明原因。

        此时库本来是解锁态，能连续猜错主密码的持机者很可能不是用户，
        立即降级为锁定态。对齐安卓 VaultViewModel.verifySessionPassword。
        """
        self._do_lock(reason)

    def _do_lock(self, reason: str | None) -> None:
        if self._locked:
            return
        self._enter_locked_state(reason)
        QApplication.processEvents()
        self._relock_prompt(reason)

    def _enter_locked_state(self, reason: str | None) -> None:
        """标记锁定并清理安全会话，不弹解锁框（供托盘隐藏等静默锁定场景）。"""
        if self._locked:
            return
        self._close_workspace_pages("lock")
        self._locked = True
        _clear_security_sessions()
        media_files.clear_media_context()
        if self._leak_worker is not None and self._leak_worker.isRunning():
            self._leak_worker.requestInterruption()
        self._idle_timer.stop()
        _log.info("锁定主界面（%s）", reason or "托盘隐藏")
        for w in QApplication.instance().topLevelWidgets():
            if isinstance(w, QDialog):
                w.reject()
        self.hide()

    def _start_passkey_broker(self) -> None:
        """Expose this unlocked Vault session to the signed Windows provider."""
        if os.name != "nt" or self._passkey_broker_server is not None:
            return
        try:
            from pathlib import Path

            from core.passkey_broker import PasskeyBroker
            from core.passkey_broker_server import (
                ProcessIdentity,
                WindowsNamedPipeServer,
                _pipe_security_attributes,
                current_user_sid,
                unlock_event_name_for_sid,
                validate_provider_identity,
                verified_peer,
            )
            from core.passkey_service import PasskeyService

            sid = current_user_sid()
            windows_apps = Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "WindowsApps"

            def peer_allowed(peer) -> bool:
                identity = ProcessIdentity(peer.process_id, peer.image_path, peer.package_family_name)
                return peer.user_sid == sid and validate_provider_identity(identity, install_root=windows_apps)

            service = PasskeyService(lambda: None if self._locked else self.vault)
            broker = _MainThreadPasskeyBroker(PasskeyBroker(service, peer_validator=peer_allowed), self)
            server = WindowsNamedPipeServer(broker, install_root=windows_apps, peer_factory=verified_peer, user_sid=sid)
            server.start()
            self._passkey_broker_server = server
            import win32event

            self._passkey_unlock_event = win32event.CreateEvent(_pipe_security_attributes(sid), True, False, unlock_event_name_for_sid(sid))
            self._passkey_unlock_timer = QTimer(self)
            self._passkey_unlock_timer.setInterval(250)
            self._passkey_unlock_timer.timeout.connect(self._check_passkey_unlock_request)
            self._passkey_unlock_timer.start()
            self._passkey_cache_reconcile_running = False
            self._passkey_cache_reconcile_next = 0.0
            self._passkey_cache_reconcile_failures = 0
            self._passkey_cache_timer = QTimer(self)
            self._passkey_cache_timer.setInterval(60_000)
            self._passkey_cache_timer.timeout.connect(self._schedule_passkey_cache_reconcile)
            self._passkey_cache_timer.start()
            QTimer.singleShot(1_000, self._schedule_passkey_cache_reconcile)
            QApplication.instance().aboutToQuit.connect(self._stop_passkey_broker)
            _log.info("Windows Passkey 受保护代理已启动")
        except RuntimeError as exc:
            self._stop_passkey_broker()
            if str(exc) == "Passkey broker pipe is unavailable":
                _log.info("Windows Passkey 代理管道已由其他进程占用，跳过本窗口的缓存协调")
            else:
                _log.exception("Windows Passkey 受保护代理启动失败")
        except Exception:
            self._stop_passkey_broker()
            _log.exception("Windows Passkey 受保护代理启动失败")

    def _stop_passkey_broker(self) -> None:
        cache_timer = getattr(self, "_passkey_cache_timer", None)
        self._passkey_cache_timer = None
        if cache_timer is not None:
            cache_timer.stop()
        timer = self._passkey_unlock_timer
        self._passkey_unlock_timer = None
        if timer is not None:
            timer.stop()
        event = self._passkey_unlock_event
        self._passkey_unlock_event = None
        if event is not None:
            event.Close()
        server = self._passkey_broker_server
        self._passkey_broker_server = None
        if server is not None:
            server.stop()

    def _schedule_passkey_cache_reconcile(self) -> None:
        """Repair Windows metadata in the background after unlock and later Vault changes."""
        if self._locked or getattr(self, "_passkey_cache_reconcile_running", False):
            return
        server = self._passkey_broker_server
        if server is None or not server.is_listening():
            return
        if time.monotonic() < getattr(self, "_passkey_cache_reconcile_next", 0.0):
            return
        self._passkey_cache_reconcile_running = True

        def work() -> None:
            try:
                from core.passkey_provider_status import PasskeyProviderStatus

                provider = PasskeyProviderStatus()
                if not provider.query().enabled:
                    self._passkey_cache_reconcile_failures = 0
                    self._passkey_cache_reconcile_next = 0.0
                    return
                provider.repair_cache()
                self._passkey_cache_reconcile_failures = 0
                self._passkey_cache_reconcile_next = 0.0
            except Exception as exc:
                _log.warning("Windows Passkey 缓存协调暂未完成：%s", exc)
                failures = getattr(self, "_passkey_cache_reconcile_failures", 0) + 1
                self._passkey_cache_reconcile_failures = failures
                self._passkey_cache_reconcile_next = time.monotonic() + min(3600, 60 * (2 ** min(failures, 6)))
            finally:
                self._passkey_cache_reconcile_running = False

        threading.Thread(target=work, name="passkey-cache-reconcile", daemon=True).start()

    def _check_passkey_unlock_request(self) -> None:
        event = self._passkey_unlock_event
        if event is None:
            return
        try:
            import win32event

            if win32event.WaitForSingleObject(event, 0) != win32event.WAIT_OBJECT_0:
                return
            win32event.ResetEvent(event)
        except Exception:
            _log.exception("读取 Windows Passkey 解锁请求失败")
            return
        if self._locked:
            self._relock_prompt("Windows 正在请求使用 FAE Vault Passkey")

    def _relock_prompt(self, reason: str | None) -> None:
        """交互式重新解锁；用户取消或放弃时退出程序。"""
        if getattr(self, "_relock_prompt_open", False):
            # 托盘双击可能连发两次激活，避免同时弹出多个解锁窗口。
            return
        self._relock_prompt_open = True
        try:
            while True:
                dlg = RelockDialog(
                    config.get_current_user() or "",
                    verify=self.vault.verify_password,
                    reason=reason,
                    expected_pmve_identity=(self.vault.pmve_identity if self.vault.device_unlock_key_format == "pmve-root-key" else None),
                )
                if dlg.exec() == QDialog.Accepted:
                    _log.info("重新解锁成功，恢复主界面")
                    break
                if dlg.switch_requested:
                    _log.info("用户请求切换账号")
                    udlg = UnlockDialog()
                    if udlg.exec() != QDialog.Accepted:
                        _log.info("用户放弃登录，退出程序")
                        QApplication.instance().quit()
                        return
                    if udlg.vault.path != self.vault.path:
                        self._switch_vault(udlg.vault)
                    _log.info("切换账号成功，恢复主界面")
                    break
                _log.info("用户放弃解锁，退出程序")
                QApplication.instance().quit()
                return

            media_files.ensure_vault_context(self.vault)
            self._locked = False
            QTimer.singleShot(0, self._remote_update_tick)
            self.show()
            self._reset_idle_timer()
            self._flash("已解锁")
            QTimer.singleShot(0, self._run_auto_maintenance)
        finally:
            self._relock_prompt_open = False

    def _switch_vault(self, vault: Vault) -> None:
        """切换到另一个用户的密码库，并刷新整个界面状态。"""
        self._close_workspace_pages("account-switch")
        self.vault = vault
        from core.autofill_exclusions import sync_local_config
        sync_local_config(self.vault, migrate=True)
        self._install_local_backup_hooks()
        media_files.ensure_vault_context(self.vault)
        self._leak_attempted_revisions.clear()
        self.search.clear()
        self.reload()
        self._flash(f"已切换到「{config.get_current_user() or ''}」")
        QTimer.singleShot(0, self._run_auto_maintenance)

    def _wire_workspace_page(self, page: QWidget) -> None:
        """Connect the common page contract once a feature page is embedded."""
        if not isinstance(page, EditorPage):
            return
        page.entryRequested.connect(self._show_workspace_entry)
        page.vaultChanged.connect(self._on_workspace_vault_changed)
        page.statusMessage.connect(self._flash)

    def _open_workspace_page(self, key: str, title: str, factory) -> QWidget:
        page = self.editor_workspace.open_page(key, i18n.tr(title), factory)
        if not bool(page.property("workspaceWired")):
            self._wire_workspace_page(page)
            page.setProperty("workspaceWired", True)
        if isinstance(page, EditorPage):
            page.set_page_title(i18n.tr(title))
        return page

    def _show_workspace_entry(self, entry_id: str) -> None:
        """从功能页跳到条目：目标可能不在当前筛选结果里，先解除筛选再选中。"""
        if self._select_by_id(entry_id):
            return
        entry = next((item for item in self.vault.entries if item.id == entry_id), None)
        if entry is None:
            return
        if self._reveal_entry(entry):
            self._select_by_id(entry_id)

    def _on_workspace_vault_changed(self, replacement: object = None) -> None:
        if isinstance(replacement, Vault) and replacement is not self.vault:
            self.vault = replacement
            media_files.ensure_vault_context(self.vault)
        self.reload()
        self._update_recycle_btn()
        self._refresh_open_feature_pages()

    def _refresh_open_feature_pages(self) -> None:
        """让已打开的功能页（回收站等）跟随库变化立即重载。

        主窗口直接改动库（如删除条目）不会发出 ``vaultChanged``，因此这里显式
        刷新所有已嵌入工作区的功能页，保证回收站等内容与主列表同步。
        """
        workspace = getattr(self, "editor_workspace", None)
        if workspace is None:
            return
        for key in workspace.page_keys()[1:]:
            page = workspace.page(key)
            if isinstance(page, EditorPage):
                page.refresh(self.vault)

    def _close_workspace_pages(self, reason: str) -> None:
        workspace = getattr(self, "editor_workspace", None)
        if workspace is not None:
            workspace.close_all_pages(reason)
        controller = getattr(self, "_cloud_controller", None)
        if controller is not None and reason != "user":
            controller.cancel_active_operations()
            self._cloud_controller = None

    # ---------- 本地定期备份 ----------

    def _install_local_backup_hooks(self) -> None:
        """挂钩每次保险库保存（实时备份）并启动周期检查定时器。"""
        if not getattr(self, "_local_backup_hooked", False):
            self._local_backup_timer = QTimer(self)
            self._local_backup_timer.setInterval(60_000)
            self._local_backup_timer.timeout.connect(self._maybe_local_backup)
            self._local_backup_timer.start()
            self._local_backup_hooked = True
        original_save = self.vault.save

        def save_with_backup(with_lock: bool = True):
            original_save(with_lock=with_lock)
            QTimer.singleShot(0, lambda: self._maybe_local_backup(force=True))
            QTimer.singleShot(0, self._maybe_auto_compact)

        if getattr(self.vault, "_faevault_backup_wrapped", False) is False:
            self.vault.save = save_with_backup  # type: ignore[method-assign]
            self.vault._faevault_backup_wrapped = True  # type: ignore[attr-defined]

    def _run_auto_maintenance(self) -> None:
        """启动/解锁后的统一后台维护（对齐安卓端解锁后台维护）。

        临时文件回收、过期回收站清理与 PMVE 压缩都在后台自动完成，不再要求
        用户手动触发；清理出过期条目时立即压缩一次，回收追加写产生的死空间。
        """
        if getattr(self, "vault", None) is None:
            return
        self._start_temp_cleanup()
        purged = self._purge_expired_trash()
        if not purged:
            self._maybe_auto_compact()
            return
        self._flash(f"已自动清理 {purged} 条过期回收站条目")
        self._refresh_open_feature_pages()
        self._start_compact(self.vault.compact_after_purge, silent=True)

    def _start_temp_cleanup(self) -> None:
        worker = _TempCleanupWorker(self.vault.path, parent=self)
        worker.completed.connect(self._on_temp_cleanup_done)
        worker.failed.connect(lambda message: _log.warning("临时文件清理失败：%s", message))
        worker.finished.connect(worker.deleteLater)
        self._temp_cleanup_worker = worker
        worker.start()

    def _on_temp_cleanup_done(self, report: object) -> None:
        self._temp_cleanup_worker = None
        removed = int(getattr(report, "removed_files", 0) or 0)
        if removed:
            _log.info(
                "已清理临时文件 %d 个（%s）",
                removed,
                _format_storage_size(int(getattr(report, "freed_bytes", 0) or 0)),
            )

    def _purge_expired_trash(self) -> int:
        """解锁后清理超过保留期的回收站条目，返回移除的条目数。

        即使回收站为空也要调用：``purge_expired`` 同时回收过期的删除日志，
        不调用会让日志线性增长（安卓端同样在每次解锁时无条件执行）。
        """
        days = int(
            config.get("recycle_bin_retention_days", config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS)
            or config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS
        )
        if days <= 0:
            return 0
        before = len(self.vault.trash)
        try:
            self.vault.purge_expired(days)
        except Exception as exc:  # noqa: BLE001
            _log.warning("清理过期回收站失败：%s", exc)
            return 0
        return before - len(self.vault.trash)

    def _maybe_auto_compact(self) -> None:
        """解锁/保存后按阈值在后台自动压缩 PMVE 保险库（无手动入口）。"""
        self._start_compact(self.vault.maybe_auto_compact)

    def _maybe_compact_large_media(self) -> None:
        """媒体提交后机会式压缩：独立阈值（最短间隔 + 最小增长）。"""
        self._start_compact(self.vault.maybe_compact_after_large_media, silent=True)

    def _compact_after_trash_purge(self) -> None:
        """清空回收站后立即压缩，不受自动压缩门槛限制。"""
        self._start_compact(self.vault.compact_after_purge, silent=True)

    def _start_compact(self, task, *, silent: bool = False) -> None:
        vault = self.vault
        if getattr(self, "_auto_compact_running", False):
            return
        self._auto_compact_running = True
        worker = _AutoCompactWorker(task, vault, parent=self)

        def _on_done(compacted: bool) -> None:
            self._auto_compact_running = False
            if compacted and not silent and self.vault is vault:
                self._flash(i18n.tr("保险库已自动压缩，历史空间已回收"))

        def _on_failed(message: str) -> None:
            self._auto_compact_running = False
            _log.warning("自动压缩失败：%s", message)

        worker.completed.connect(_on_done)
        worker.failed.connect(_on_failed)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _set_backup_status(self, text: str) -> None:
        self._backup_status_text = text
        label = self._backup_status_label
        if label is None:
            return
        try:
            label.setText(text)
        except RuntimeError:
            # 备份页已关闭并 deleteLater，仅保留文本供下次打开时回填。
            self._backup_status_label = None

    def _maybe_local_backup(self, force: bool = False) -> None:
        from core import local_backup

        if not config.get("backup_enabled", False):
            return
        backup_dir = config.get("backup_dir", "") or ""
        if not backup_dir:
            self._set_backup_status(i18n.tr("未选择备份目录"))
            return
        interval_key = config.get("backup_interval", "daily") or "daily"
        try:
            if not local_backup.should_run(
                time.time(),
                float(config.get("backup_last_at", 0) or 0),
                interval_key,
                force=force,
            ):
                return
        except ValueError:
            return
        binding_state, marker, access_id = local_backup.binding_state_for_directory(
            backup_dir,
            config.get("backup_device_uuid", "") or "",
            config.get("backup_access_id", "") or "",
        )
        if not access_id:
            self._set_backup_status(i18n.tr("等待设备状态"))
            return
        if marker.state is local_backup.MarkerState.INVALID or binding_state is local_backup.BindingState.IDENTITY_ANOMALY:
            self._set_backup_status(i18n.tr("身份异常，已禁止自动同步"))
            return
        if binding_state is local_backup.BindingState.SUSPECTED_ORIGINAL:
            self._set_backup_status(i18n.tr("设备身份已变化，请重新确认"))
            return
        if binding_state is local_backup.BindingState.NEW_DEVICE:
            self._set_backup_status(i18n.tr("检测到新存储设备，请选择目录并授权"))
            return
        if binding_state is not local_backup.BindingState.KNOWN:
            self._set_backup_status(i18n.tr("等待设备状态"))
            return
        try:
            journal = Path(self.vault.path).with_name(".local_backup_journal.json")
            local_backup.perform_backup(self.vault.path, backup_dir, journal_path=journal, resume=True)
            config.set("backup_last_at", int(time.time()))
            self._set_backup_status(i18n.tr("已备份 ") + time.strftime("%m-%d %H:%M"))
        except local_backup.BackupWaitingDevice:
            self._set_backup_status(i18n.tr("等待设备状态"))
        except local_backup.BackupInsufficientSpace:
            self._set_backup_status(i18n.tr("空间不足，已跳过本次备份"))
        except Exception as error:
            self._set_backup_status(i18n.tr("备份失败：") + str(error))

    def _backup_now(self) -> None:
        self._maybe_local_backup(force=True)

    # ---------- 顶部迷你栏 ----------
    def _build_top_bar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(58)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 4, 0)
        lay.setSpacing(4)

        # 导航按钮右对齐，依次贴近应用筛选标签与锁定按钮。
        lay.addStretch()

        # 更多功能：聚合“同步”与“库维护”两组二级菜单
        self._more_btn = QPushButton(i18n.tr("更多功能"))
        self._more_btn.setObjectName("TopNavButton")
        self._more_btn.setToolTip(i18n.tr("更多功能：导入导出 / 本地备份 / 局域网 / 云端同步 / 库维护"))
        self._more_btn.setAccessibleName(i18n.tr("更多功能"))
        self._more_btn.setCursor(Qt.PointingHandCursor)
        self._more_menu = QMenu(self._more_btn)
        self._more_menu.addMenu(self._build_sync_menu(self._more_menu))
        self._more_menu.addMenu(self._build_maintenance_menu(self._more_menu))
        self._more_btn.setMenu(self._more_menu)
        lay.addWidget(self._more_btn)

        self._security_btn = QPushButton("安全中心")
        self._security_btn.setObjectName("TopNavButton")
        self._security_btn.setToolTip("安全中心")
        self._security_btn.setAccessibleName("安全中心")
        self._security_btn.clicked.connect(self._open_security_center)
        lay.addWidget(self._security_btn)

        self._recycle_btn = QPushButton("回收站 0")
        self._recycle_btn.setObjectName("TopNavButton")
        self._recycle_btn.setToolTip("回收站")
        self._recycle_btn.setAccessibleName("回收站")
        self._recycle_btn.clicked.connect(self.open_recycle_bin)
        lay.addWidget(self._recycle_btn)

        self._settings_btn = QPushButton("设置")
        self._settings_btn.setObjectName("TopNavButton")
        self._settings_btn.setToolTip("设置")
        self._settings_btn.setAccessibleName("设置")
        self._settings_btn.clicked.connect(self.open_settings)
        lay.addWidget(self._settings_btn)

        self._app_label = QPushButton()
        self._app_label.setObjectName("TopNavButton")
        self._app_label.setVisible(False)
        self._app_label.setCursor(Qt.PointingHandCursor)
        self._app_label.clicked.connect(self._toggle_app_filter)
        lay.addWidget(self._app_label)

        self._top_lock_btn = widgets.set_button_icon(QPushButton(), "lock", size=18)
        self._top_lock_btn.setObjectName("TopUtilityButton")
        self._top_lock_btn.setToolTip("锁定")
        self._top_lock_btn.setAccessibleName("锁定保险库")
        self._top_lock_btn.clicked.connect(self.lock_now)
        lay.addWidget(self._top_lock_btn)
        for button in bar.findChildren(QPushButton):
            button.setMinimumHeight(36)
            button.setMaximumHeight(36)
            button.setCursor(Qt.PointingHandCursor)
            button.setFocusPolicy(Qt.NoFocus)
        self._compact_top_nav = False
        return bar

    def _build_sync_menu(self, parent: QMenu) -> QMenu:
        menu = QMenu(i18n.tr("同步"), parent)
        io_menu = menu.addMenu(i18n.tr("导入导出"))
        for label, handler in (
            ("导入加密备份", self.import_backup),
            ("导出加密备份", self.export_backup),
        ):
            io_menu.addAction(i18n.tr(label), handler)
        io_menu.addSeparator()
        for label, handler in (
            ("浏览器导入", self.import_browser),
            ("Wi-Fi 导入", self.import_wifi),
            ("导入密码数据", self.import_csv),
        ):
            io_menu.addAction(i18n.tr(label), handler)
        io_menu.addSeparator()
        for label, handler in (
            ("导出压缩包", self.export_archive),
            ("导出 .pmv 库", self.export_pmv),
        ):
            io_menu.addAction(i18n.tr(label), handler)

        menu.addAction(i18n.tr("本地备份"), self._open_local_backup)
        # 局域网是一个页内三档（建立传输站 / 局域网同步 / 文件传输），因此只保留一个入口。
        menu.addAction(i18n.tr("局域网"), self._open_lan_page)

        # 总开关已收敛到「云端同步」页自带的 master 开关，入口因此必须常驻：
        # 若关闭后隐藏入口，用户就再也进不去那个页面、无法重新开启。
        menu.addAction(i18n.tr("云端同步"), self._open_cloud_sync)
        return menu

    def _build_maintenance_menu(self, parent: QMenu) -> QMenu:
        menu = QMenu(i18n.tr("库维护"), parent)
        menu.addAction(i18n.tr("设备与历史"), self._open_devices_history)
        menu.addAction(i18n.tr("重复条目合并"), self.dedup_entries)
        menu.addAction(i18n.tr("相同服务合并"), self.merge_same_service_entries)
        return menu

    def _update_top_nav_layout(self) -> None:
        if not hasattr(self, "_security_btn"):
            return
        compact = self.width() < 1180
        if compact != self._compact_top_nav:
            self._compact_top_nav = compact
            labels = (
                (self._security_btn, "安全中心"),
                (self._settings_btn, "设置"),
            )
            for button, label in labels:
                button.setText("" if compact else label)
            self._more_btn.setText("" if compact else i18n.tr("更多功能"))
            self._update_recycle_btn()
        self._app_label.setVisible(self._app_filter_enabled and self.width() >= 1260)

    # ---------- 侧边栏 ----------
    def _build_sidebar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Sidebar")
        bar.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self._sidebar_widget = bar
        self._sidebar_lay = QVBoxLayout(bar)
        # 左侧留出安全距离：最大化后窗口贴屏幕左缘，若边距过小，
        # “新建条目”下拉按钮会紧贴屏幕边缘。底部同样留出安全距离，让分隔线与
        # “＋ 新增条目”按钮整体不贴窗口下沿。
        self._sidebar_lay.setContentsMargins(16, 12, 8, SIDEBAR_BOTTOM_SAFE_MARGIN)
        self._sidebar_lay.setSpacing(4)
        self._sidebar_lay.setAlignment(Qt.AlignTop)

        self._sidebar_create_section = QWidget()
        self._sidebar_create_section.setObjectName("SidebarCreateSection")
        create_lay = QVBoxLayout(self._sidebar_create_section)
        create_lay.setContentsMargins(0, 0, 0, 0)
        create_lay.setSpacing(0)

        add = QPushButton("＋  新建条目")
        add.setObjectName("SidebarAddMenuButton")
        add.setFixedHeight(40)
        self._add_btn = add
        self._add_menu = widgets.UpwardMenu(add)
        self._rebuild_add_menu()
        self._add_menu.aboutToShow.connect(lambda: self._add_menu.setFixedWidth(self._add_btn.width()))
        self._add_btn_slot = None
        self._update_add_button()
        create_lay.addWidget(add)

        self._sidebar_separator = QWidget()
        self._sidebar_separator.setObjectName("SidebarSeparator")
        self._sidebar_separator.setFixedHeight(1)

        self._chip_container = QWidget()
        self._chip_lay = QVBoxLayout(self._chip_container)
        self._chip_lay.setContentsMargins(0, 0, 0, 0)
        self._chip_lay.setSpacing(4)
        self._sidebar_lay.addWidget(self._chip_container)

        self._type_chips: dict = {}
        self._tag_chips: dict = {}
        self._rebuild_type_chips()

        self._sidebar_lay.addStretch()
        self._sidebar_lay.addWidget(self._sidebar_separator)
        self._sidebar_lay.addWidget(self._sidebar_create_section)

        self._chip_container.setContextMenuPolicy(Qt.CustomContextMenu)
        self._chip_container.customContextMenuRequested.connect(self._show_sidebar_context_menu)

        bar.adjustSize()
        return bar

    def _get_type_order(self) -> list[str]:
        custom = config.get("category_order")
        if isinstance(custom, list):
            known = [item for item in custom if item in SecretType.NAV_TYPES]
            return known + [item for item in SecretType.NAV_TYPES if item not in known]
        return SecretType.NAV_TYPES

    def _rebuild_type_chips(self) -> None:
        while self._chip_lay.count():
            item = self._chip_lay.takeAt(0)
            if w := item.widget():
                w.deleteLater()
            elif sub := item.layout():
                while sub.count():
                    if sw := sub.takeAt(0).widget():
                        sw.deleteLater()
        self._type_chips.clear()
        order = self._get_type_order()
        for t in order:
            btn = QPushButton(i18n.tr(SecretType.LABELS[t]))
            btn.setIcon(widgets.category_icon(t))
            btn.setIconSize(QSize(20, 20))
            btn.setObjectName("TypeFilterChip")
            btn.setFixedHeight(38)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, v=t: self._set_type_filter(v))
            self._type_chips[t] = btn
            self._chip_lay.addWidget(btn)
        self._update_chip_styles()

    def _rebuild_add_menu(self) -> None:
        self._add_menu.clear()
        for t in self._get_type_order():
            if t == SecretType.PASSKEY:
                continue
            self._add_menu.addAction(
                widgets.category_icon(t),
                i18n.tr(SecretType.LABELS[t]),
                lambda checked=False, st=t: self.add_entry(st),
            )

    # ---------- 中间列表 ----------
    def _build_list_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(18, 16, 12, 18)
        lay.setSpacing(8)

        self.search = widgets.RepeatSafeLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText("搜索名称、用户名、标签…")
        self.search.addAction(widgets.ui_icon("search"), QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self._search_timer.start)
        lay.addWidget(self.search)

        # ── 筛选面板（始终可见） ──────────────────────────────────────
        self._active_tag: str | None = None
        self._tag_chips: dict = {}
        self._alpha_buttons: dict[str, QPushButton] = {}
        self._alpha_index: dict[str, int] = {}

        self.filter_panel = QFrame()
        self.filter_panel.setObjectName("FilterPanel")
        self.filter_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        fp_lay = QVBoxLayout(self.filter_panel)
        fp_lay.setContentsMargins(0, 0, 0, 0)
        fp_lay.setSpacing(4)

        self._tag_section = QWidget()
        self._tag_context_widgets = set()
        tag_sec_lay = QHBoxLayout(self._tag_section)
        tag_sec_lay.setContentsMargins(0, 0, 0, 0)
        tag_sec_lay.setSpacing(6)
        self._tag_scroll = widgets.HScrollArea()
        self._tag_scroll.setObjectName("TagScroll")
        self._tag_scroll.setWidgetResizable(True)
        self._tag_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._tag_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._tag_scroll.setFrameShape(QFrame.NoFrame)
        self._tag_scroll.setFixedHeight(38)
        self._tag_transition = widgets.ContentTransition(self._tag_scroll.viewport())
        self._tag_chips_widget = QWidget()
        self._tag_chips_lay = QHBoxLayout(self._tag_chips_widget)
        self._tag_chips_lay.setContentsMargins(0, 0, 0, 0)
        self._tag_chips_lay.setSpacing(6)
        self._tag_chips_lay.addStretch()
        self._tag_scroll.setWidget(self._tag_chips_widget)
        tag_sec_lay.addWidget(self._tag_scroll, 1)
        for widget in (self._tag_section, self._tag_scroll.viewport(), self._tag_chips_widget):
            widget.installEventFilter(self)
            self._tag_context_widgets.add(widget)
        self._tag_section.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        self._tag_section.setVisible(False)
        fp_lay.addWidget(self._tag_section)

        lay.addWidget(self.filter_panel)

        list_card = QFrame()
        list_card.setObjectName("ListCard")
        list_card_lay = QVBoxLayout(list_card)
        list_card_lay.setContentsMargins(8, 8, 8, 8)
        list_card_lay.setSpacing(4)

        self.count_label = QLabel("")
        self.count_label.setObjectName("StatTitle")
        self.count_label.setAlignment(Qt.AlignCenter)
        list_card_lay.addWidget(self.count_label)

        list_body = QWidget()
        list_body_lay = QHBoxLayout(list_body)
        list_body_lay.setContentsMargins(0, 0, 0, 0)
        list_body_lay.setSpacing(6)

        self.list = QListWidget()
        self._list_transition = widgets.ContentTransition(self.list.viewport())
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 行高固定，按行步进时每次滚动后的布局都完全一致，看着像原地换内容；
        # 逐像素滚动才有真正的位移，且 uniformItemSizes 下开销不变。
        enable_smooth_scroll(self.list)
        self.list.setWordWrap(True)
        self.list.setTextElideMode(Qt.ElideRight)
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list.setUniformItemSizes(True)
        self.list.setItemDelegate(_EntryListDelegate(self.list))
        self.list.currentItemChanged.connect(self._on_select)
        self.list.itemDoubleClicked.connect(self._on_double_click)
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._show_context_menu)
        list_body_lay.addWidget(self.list, 1)

        alpha_nav = QWidget()
        alpha_nav.setObjectName("AlphaNav")
        alpha_nav_lay = QVBoxLayout(alpha_nav)
        alpha_nav_lay.setContentsMargins(0, 2, 0, 2)
        alpha_nav_lay.setSpacing(1)
        for key in _ALPHA_NAV:
            btn = QPushButton(key)
            btn.setObjectName("AlphaNavBtn")
            btn.setFixedSize(24, 18)
            btn.setEnabled(False)
            btn.clicked.connect(lambda _=False, k=key: self._jump_to_alpha(k))
            self._alpha_buttons[key] = btn
            alpha_nav_lay.addWidget(btn)
        alpha_nav_lay.addStretch()
        list_body_lay.addWidget(alpha_nav)
        list_card_lay.addWidget(list_body, 1)

        # 贴底居中浮在条目之上，不占布局、也不单独占一行。
        self._list_add_btn = _FloatingAddButton(list_card, i18n.tr("＋ 新增条目"))
        self._list_add_btn.set_backdrop_source(self.list)
        self._list_add_btn.clicked.connect(lambda: self.add_entry(self._active_type, show_type_selector=False))

        lay.addWidget(list_card, 1)
        return pane

    # ---------- 右侧详情 ----------
    def _build_detail_pane(self) -> QWidget:
        pane = QWidget()
        outer = QVBoxLayout(pane)
        # 详情标题栏贴合面板边框，内容留白由详情页自身管理。
        outer.setContentsMargins(0, 0, 0, 18)

        card = QFrame()
        card.setObjectName("DetailPaneCard")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(0, 0, 0, 0)
        card_lay.setSpacing(0)

        detail_page = QWidget()
        detail_page.setObjectName("EntryDetailPage")
        detail_page_layout = QVBoxLayout(detail_page)
        detail_page_layout.setContentsMargins(0, 0, 0, 0)
        detail_page_layout.setSpacing(0)

        self.detail_card = QWidget()
        self.detail = QVBoxLayout(self.detail_card)
        self.detail.setContentsMargins(*PAGE_MARGINS)
        self.detail.setSpacing(DETAIL_BLOCK_SPACING)
        self.detail.setAlignment(Qt.AlignTop)
        self.detail_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        self.detail_scroll = QScrollArea()
        self.detail_scroll.setWidgetResizable(True)
        enable_smooth_scroll(self.detail_scroll)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.detail_scroll.setWidget(self.detail_card)
        self._detail_transition = widgets.ContentTransition(self.detail_scroll.viewport())
        detail_page_layout.addWidget(self.detail_scroll)

        # 悬浮在详情内容之上的条目操作条（不占布局空间，随详情页尺寸自动贴底）。
        self._detail_fab = _FloatingDetailActions(
            detail_page,
            on_edit=self.edit_entry,
            on_delete=self.delete_entry,
        )

        self._detail_fab.edit_button.set_backdrop_source(self.detail_scroll)
        self._detail_fab.delete_button.set_backdrop_source(self.detail_scroll)

        self.editor_workspace = EditorWorkspace(
            detail_page,
            detail_title=i18n.tr("条目详情"),
            parent=card,
        )
        card_lay.addWidget(self.editor_workspace)

        outer.addWidget(card, 1)

        self._show_empty()
        return pane

    # ---------- 筛选 ----------
    def _set_type_filter(self, value: str | None) -> None:
        if value == self._active_type and not self._password_filter:
            return
        self._search_timer.stop()
        self._select_timer.stop()
        self._password_filter = None
        # 选定具体类目即退出跨类目视图，标签筛选随之按该类目隔离。
        self._cross_type_filter = False
        self._active_type = value
        # 标签筛选只在当前类目内开放；失效标签由 _rebuild_tag_chips 统一清除。
        self._list_add_btn.setVisible(value != SecretType.PASSKEY)
        self._update_chip_styles()
        self.reload(data_changed=False)
        self._pending_select = self.list.currentItem()
        self._select_timer.start(0)

    def _update_add_button(self) -> None:
        if self._add_btn_slot is not None:
            self._add_btn.clicked.disconnect(self._add_btn_slot)
            self._add_btn_slot = None
        self._add_btn.setMenu(self._add_menu)

    def _set_tag_filter(self, value: str | None) -> None:
        changed = self._active_tag != value
        self._active_tag = value
        self._update_chip_styles()
        self.reload(data_changed=False)
        transition = getattr(self, "_tag_transition", None)
        if changed and transition is not None and transition.parentWidget().isVisible():
            transition.begin()

    def _update_chip_styles(self) -> None:
        for v, btn in self._type_chips.items():
            active = "true" if v == self._active_type else "false"
            if btn.property("active") == active:
                continue
            btn.setProperty("active", active)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        for v, btn in self._tag_chips.items():
            active = "true" if v == self._active_tag else "false"
            if btn.property("active") == active:
                continue
            btn.setProperty("active", active)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _rebuild_tag_chips(self) -> None:
        # 标签按类目隔离（与 Android 端 listIndex.tagsByType 一致）：只在选定具体类目
        # 时收集该类目的标签；跨类目的密码健康筛选下 tagsByType[null] 为空、筛选区不
        # 显示。否则不同类目的同名标签会并成同一个 chip，选中后同时筛出跨类条目。
        source = getattr(self, "_filter_source_entries", None)
        if source is None:
            source = self.vault.entries
        if self._active_type:
            scoped = [e for e in source if e.secret_type == self._active_type]
        elif getattr(self, "_cross_type_filter", False):
            # 安全中心的跨类目视图：标签本身仍按类目隔离，这里不提供标签筛选。
            scoped = []
        else:
            scoped = []
        tags = self._ordered_tags_for_type({t for e in scoped for t in e.tags})
        has_untagged = any(not e.tags for e in scoped)
        # 无任何标签时隐藏筛选区（与 Android 端一致），如 Passkey 类目。
        self._tag_section.setVisible(bool(tags) or has_untagged)
        last = getattr(self, "_last_tag_state", None)
        if last == (tags, has_untagged):
            return
        self._last_tag_state = (tags, has_untagged)
        lay = self._tag_chips_lay
        while lay.count() > 1:
            item = lay.takeAt(0)
            if item.widget():
                self._tag_context_widgets.discard(item.widget())
                item.widget().deleteLater()
        self._tag_chips = {}
        if self._active_tag == _UNTAGGED_TAG:
            if not has_untagged:
                self._active_tag = None
        elif self._active_tag and self._active_tag not in tags:
            self._active_tag = None
        chip_values = [None] + tags
        if has_untagged:
            chip_values.append(_UNTAGGED_TAG)
        for i, tag in enumerate(chip_values):
            if tag is None:
                lbl = "全部"
            elif tag == _UNTAGGED_TAG:
                lbl = "无标签"
            else:
                lbl = tag
            btn = QPushButton(lbl)
            btn.setObjectName("FilterChip")
            btn.setCursor(Qt.PointingHandCursor)
            if tag not in (None, _UNTAGGED_TAG):
                btn.setToolTip(tag)
                btn.setMaximumWidth(156)
                btn.setText(btn.fontMetrics().elidedText(tag, Qt.ElideRight, 126))
            btn.clicked.connect(lambda _, v=tag: self._set_tag_filter(v))
            btn.installEventFilter(self)
            self._tag_context_widgets.add(btn)
            self._tag_chips[tag] = btn
            lay.insertWidget(i, btn)
        self._update_chip_styles()
        transition = getattr(self, "_tag_transition", None)
        if transition is not None and transition.parentWidget().isVisible():
            transition.begin()

    def _ordered_tags_for_type(self, available: set[str]) -> list[str]:
        saved = config.get("tag_order_by_type", {})
        order = saved.get(self._active_type, []) if isinstance(saved, dict) else []
        if not isinstance(order, list):
            order = []
        known = [tag for tag in order if isinstance(tag, str) and tag in available]
        return list(dict.fromkeys(known)) + sorted(available.difference(known))

    def _save_tag_order(self, order: list[str]) -> None:
        saved = config.get("tag_order_by_type", {})
        saved = dict(saved) if isinstance(saved, dict) else {}
        saved[self._active_type] = list(dict.fromkeys(order))
        config.set("tag_order_by_type", saved)
        self._last_tag_state = None
        self._rebuild_tag_chips()

    # ---------- 数据刷新 ----------
    def reload(self, *, data_changed: bool = True) -> None:
        # A category/tag/search change projects the current snapshot. Mutations,
        # synchronization and settings keep calling reload() to invalidate it.
        if getattr(self, "_filter_source_vault", None) is not self.vault:
            data_changed = True
        if data_changed and not getattr(self, "_locked", False):
            from core.autofill_exclusions import sync_local_config
            sync_local_config(self.vault, migrate=True)
            workspace = getattr(self, "editor_workspace", None)
            if workspace is not None:
                settings_page = workspace.page("settings")
                if settings_page is not None:
                    settings_page.refresh(self.vault)
        if data_changed:
            self._filter_source_vault = self.vault
            self._filter_source_entries = tuple(self.vault.entries)
            self._filter_query = None
        query = self.search.text()
        if self._filter_query != query:
            self._filter_query_entries = tuple(self.vault.search(query))
            by_type = {}
            for entry in self._filter_query_entries:
                by_type.setdefault(entry.secret_type, []).append(entry)
            self._filter_query_by_type = by_type
            self._filter_query = query
        # 任何重新载入（局域网同步合并、云同步刷新、外部变更重开等）后，
        # 媒体上下文必须与当前 self.vault 保持一致，否则图片读取会报"数据库未解锁"。
        # 锁定态下不主动恢复，避免重新暴露受保护的媒体文件。
        if data_changed and not getattr(self, "_locked", False):
            media_files.ensure_vault_context(self.vault)
            self._sync_kdf_profile_to_config()

        current_id = None
        if isinstance(self.list.currentItem(), EntryListItem):
            current_id = self.list.currentItem().entry.id

        self._rebuild_tag_chips()
        self._list_add_btn.setVisible(self._active_type != SecretType.PASSKEY)

        self.list.setUpdatesEnabled(False)
        self.list.blockSignals(True)

        matched = []
        password_filter = getattr(self, "_password_filter", None)
        password_filter_ids = None
        if password_filter:
            sig = self._stats_signature()[1]
            cached = getattr(self, "_pw_stats_id_sets", None)
            if cached is not None and getattr(self, "_pw_stats_sig", None) == sig:
                password_filter_ids = cached.get(password_filter)
            elif cached is not None:
                # 统计过期但本帧先沿用上次结果，后台刷新完成后会重载并修正筛选。
                password_filter_ids = cached.get(password_filter)
        candidates = (
            self._filter_query_by_type.get(self._active_type, ())
            if self._active_type else self._filter_query_entries
        )
        for entry in candidates:
            if password_filter_ids is not None and entry.id not in password_filter_ids:
                continue
            if self._active_tag == _UNTAGGED_TAG:
                if entry.tags:
                    continue
            elif self._active_tag and self._active_tag not in entry.tags:
                continue
            if self._app_filter_enabled and self._active_app:
                if entry.secret_type != SecretType.LOGIN:
                    continue
                if entry.target_app.lower() != self._active_app.lower():
                    continue
            matched.append(entry)

        # 泄露检测与排序合并为一次遍历
        if matched:
            leaked_map = {}
            leaked_entries = []
            safe_entries = []
            for e in matched:
                if leak.is_entry_leaked_cached(e):
                    leaked_map[e.id] = True
                    leaked_entries.append(e)
                else:
                    leaked_map[e.id] = False
                    safe_entries.append(e)
            ordered = leaked_entries + safe_entries
        else:
            leaked_map = {}
            leaked_entries = []
            ordered = []

        self._alpha_index = {}
        avail_w = self.list.viewport().width() - 36
        # 与安卓端一致：泄露条目置顶归入 “#”，字母定位只作用于未泄露条目。
        if leaked_entries:
            self._alpha_index["#"] = 0
        pos = 0
        for entry in ordered:
            if not leaked_map[entry.id]:
                key = self._alpha_key(entry.title)
                self._alpha_index.setdefault(key, pos)
            pos += 1

        # A filter change is a new projection. Reset the Qt model once instead
        # of emitting one row-removal event per old item before inserting rows.
        self.list.clear()
        display_type_passkey = self._active_type == SecretType.PASSKEY
        for e in ordered:
            it = EntryListItem(
                e,
                leaked=leaked_map[e.id],
                display_type=SecretType.PASSKEY if display_type_passkey else e.secret_type,
            )
            it.setData(Qt.UserRole, it)
            it.setSizeHint(QSize(max(120, avail_w), 96))
            self.list.addItem(it)

        self.list.blockSignals(False)
        self.list.setUpdatesEnabled(True)

        transition = getattr(self, "_list_transition", None)
        if transition is not None and self.list.isVisible():
            transition.begin()

        workspace = getattr(self, "editor_workspace", None)
        security_page = workspace.page("security") if workspace is not None else None
        if data_changed and isinstance(security_page, SecurityCenterPage):
            revision = self._security_logical_revision()
            if security_page._revision != revision:
                security_page.update_entries(list(self.vault.entries), revision)
        self.count_label.setText(f"共 {len(ordered)}/{len(self._filter_source_entries)} 条")
        self._update_alpha_nav()
        if data_changed:
            self._update_recycle_btn()
            self._update_password_stats()
            QTimer.singleShot(0, self._schedule_leak_audit)

        self._restoring_list_selection = True
        try:
            if current_id:
                for i in range(self.list.count()):
                    item = self.list.item(i)
                    if isinstance(item, EntryListItem) and item.entry.id == current_id:
                        self.list.setCurrentRow(i)
                        self._update_alpha_nav()
                        return
            if ordered:
                self.list.setCurrentRow(0)
            else:
                self._show_empty()
            self._update_alpha_nav()
        finally:
            self._restoring_list_selection = False

    @staticmethod
    def _password_is_weak(password: str) -> bool:
        if len(password) < 10:
            return True
        classes = sum(
            (
                any(ch.islower() for ch in password),
                any(ch.isupper() for ch in password),
                any(ch.isdigit() for ch in password),
                any(not ch.isalnum() for ch in password),
            )
        )
        return classes < 3

    def _password_filter_entries(self, kind: str | None) -> list[Entry]:
        report = getattr(self, "_security_report", password_health.EMPTY_REPORT)
        normalized = {"risk": "leaked"}.get(kind, kind)
        if (
            normalized
            and normalized
            in {
                password_health.HIGH,
                password_health.IMPROVEMENT,
                password_health.HEALTHY,
                password_health.ALL,
                *password_health.FINDING_BY_KEY,
            }
            and report.total
        ):
            return list(report.entries_for(normalized))
        entries_with_secret: list[tuple[Entry, str]] = []
        try:
            for entry in self.vault.entries:
                secret = leak.entry_secret(entry)
                if secret:
                    entries_with_secret.append((entry, secret))
            if kind == "risk":
                return [entry for entry, _secret in entries_with_secret if leak.is_entry_leaked(entry)]
            if kind == "duplicate":
                counts: dict[str, int] = {}
                for _entry, secret in entries_with_secret:
                    counts[secret] = counts.get(secret, 0) + 1
                repeated = {secret for secret, count in counts.items() if count > 1}
                return [entry for entry, secret in entries_with_secret if secret in repeated]
            if kind == "weak":
                return [entry for entry, secret in entries_with_secret if self._password_is_weak(secret)]
            return [entry for entry, _secret in entries_with_secret]
        finally:
            for entry, _secret in entries_with_secret:
                release = getattr(entry, "release_sensitive", None)
                if release is not None:
                    release()

    def _stats_signature(self):
        # Cheap, decryption-free fingerprint of the entry set that drives the
        # global password-health counts. Recomputing these counts otherwise
        # decrypts every secret on every list reload (search keystroke, filter
        # toggle) even though the counts are search/filter independent.
        h = hashlib.sha1()
        n = 0
        for e in self.vault.entries:
            n += 1
            h.update(repr((e.id, e.updated_at, getattr(e, "leak_pwned_count", 0), getattr(e, "leak_common_weak", False))).encode("utf-8"))
        return n, h.hexdigest()

    def _request_password_stats(self) -> None:
        """异步计算密码健康统计；主线程仅用缓存，必要时在子线程解密全量密码。"""
        sig = self._stats_signature()[1]
        if self._password_stats_sig == sig and self._password_stats_cache is not None:
            self._update_password_stats_labels()
            return
        if self._pw_stats_worker is not None and self._pw_stats_worker.isRunning():
            return
        worker = _PasswordStatsWorker(self.vault, sig, self._password_is_weak)
        worker.result.connect(self._on_password_stats_done)
        worker.finished.connect(lambda: setattr(self, "_pw_stats_worker", None))
        worker.finished.connect(worker.deleteLater)
        self._pw_stats_worker = worker
        worker.start()

    def _on_password_stats_done(self, sig: str, counts: dict, id_sets: dict) -> None:
        if self._stats_signature()[1] != sig:
            return  # 保险库已变化，丢弃过期结果避免错误筛选
        self._password_stats_cache = counts
        self._password_stats_sig = sig
        self._pw_stats_id_sets = id_sets
        self._pw_stats_sig = sig
        self._update_password_stats_labels()
        if getattr(self, "_password_filter", None):
            self.reload()

    def _update_password_stats(self) -> None:
        self._request_password_stats()
        self._update_password_stats_labels()

    def _update_password_stats_labels(self) -> None:
        buttons = getattr(self, "_password_stat_buttons", {})
        labels = {"risk": "风险密码", "duplicate": "重复密码", "weak": "安全程度低"}
        counts = self._password_stats_cache or {}
        for key, button in buttons.items():
            button.setText(f"{labels[key]}  {counts.get(key, 0)}")

    def _security_page(self) -> SecurityCenterPage | None:
        page = self.editor_workspace.page("security")
        return page if isinstance(page, SecurityCenterPage) else None

    def _open_security_center(self) -> None:
        page = self._open_workspace_page(
            "security",
            "安全中心",
            lambda: SecurityCenterPage(list(self.vault.entries), self._security_logical_revision(), self),
        )
        revision = self._security_logical_revision()
        if page._revision != revision:
            page.update_entries(list(self.vault.entries), revision)
        page.onlineAuditRequested.connect(self.start_manual_leak_audit, Qt.ConnectionType.UniqueConnection)
        page.passwordViewRequested.connect(
            self._on_security_password_view_requested,
            Qt.ConnectionType.UniqueConnection,
        )

    def _on_security_password_view_requested(self, kind: str, report: object) -> None:
        self._apply_password_filter(kind, report)

    def _security_logical_revision(self) -> str:
        digest = hashlib.sha256()
        digest.update(str(self.vault.path.resolve()).encode("utf-8"))
        digest.update(b"\0")
        for entry in sorted(self.vault.entries, key=lambda value: value.id):
            values = (
                entry.id,
                entry.updated_at,
                entry.deleted_at,
                getattr(entry, "leak_check_revision", None),
                getattr(entry, "leak_pwned_count", None),
                getattr(entry, "leak_common_weak", False),
            )
            digest.update(repr(values).encode("utf-8"))
            digest.update(b"\0")
        return digest.hexdigest()

    def _apply_password_filter(
        self,
        kind: str,
        report: password_health.HealthReport | None = None,
        entry_id: str | None = None,
    ) -> None:
        if report is not None:
            self._security_report = report
            self._password_filter = kind
        else:
            self._password_filter = None if self._password_filter == kind else kind
        # 安全中心的密码健康筛选天然跨类目（弱密码可能出现在登录、Wi-Fi、银行卡），
        # 因此进入跨类目视图：清掉类目选中，并显式置位 _cross_type_filter。
        # 侧边栏没有「全部」类目，_active_type 为 None 只在此路径出现。
        self._cross_type_filter = self._password_filter is not None
        self._active_type = None
        self._active_tag = None
        self.search.clear()
        self._update_chip_styles()
        self.reload()
        if entry_id:
            for index in range(self.list.count()):
                item = self.list.item(index)
                if isinstance(item, EntryListItem) and item.entry.id == entry_id:
                    self.list.setCurrentItem(item)
                    self.list.scrollToItem(item, QAbstractItemView.PositionAtCenter)
                    break

    @staticmethod
    def _alpha_key(text: str) -> str:
        return pinyin_first_letter(text)

    def _jump_to_alpha(self, key: str) -> None:
        idx = self._alpha_index.get(key)
        if idx is None:
            return
        item = self.list.item(idx)
        if item is None:
            return
        self.list.scrollToItem(item)
        self.list.setCurrentRow(idx)

    # ---------- 右键菜单 ----------
    def _show_context_menu(self, pos) -> None:
        item = self.list.itemAt(pos)
        if not isinstance(item, EntryListItem):
            return

        items = self.list.selectedItems()
        entry_items = [i for i in items if isinstance(i, EntryListItem)]

        if item not in entry_items:
            self.list.clearSelection()
            item.setSelected(True)
            self.list.setCurrentItem(item)
            entry_items = [item]

        menu = QMenu(self)

        if len(entry_items) == 1:
            entry = entry_items[0].entry
            if self._active_type != SecretType.PASSKEY:
                edit_a = menu.addAction("编辑")
                edit_a.triggered.connect(self.edit_entry)
                menu.addSeparator()
            del_a = menu.addAction("删除")
            del_a.triggered.connect(self.delete_entry)
            menu.addSeparator()
            _entry = entry
            add_t = menu.addAction("添加标签")
            add_t.triggered.connect(lambda: self._batch_add_tag([_entry]))
            move_t = menu.addAction("移入标签")
            move_t.triggered.connect(lambda: self._batch_move_tag([_entry]))
        else:
            _items = entry_items
            batch_delete = menu.addAction(f"批量删除（{len(_items)} 条）")
            batch_delete.triggered.connect(lambda: self._batch_delete(_items))
            if len({i.entry.secret_type for i in _items}) == 1:
                _entries = [i.entry for i in _items]
                menu.addSeparator()
                add_t = menu.addAction(f"批量添加标签（{len(_entries)} 条）")
                add_t.triggered.connect(lambda: self._batch_add_tag(_entries))
                move_t = menu.addAction(f"批量移入标签（{len(_entries)} 条）")
                move_t.triggered.connect(lambda: self._batch_move_tag(_entries))

        menu.exec(self.list.viewport().mapToGlobal(pos))

    def _update_alpha_nav(self) -> None:
        current_key = ""
        current = self.list.currentItem()
        if isinstance(current, EntryListItem):
            # 泄露条目属于 # 分组，高亮 # 而非其标题字母。
            current_key = "#" if leak.is_entry_leaked_cached(current.entry) else self._alpha_key(current.entry.title)
        for key, btn in self._alpha_buttons.items():
            enabled = key in self._alpha_index
            active = "true" if enabled and key == current_key else "false"
            if btn.isEnabled() == enabled and btn.property("active") == active:
                continue
            btn.setEnabled(enabled)
            btn.setProperty("active", active)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _current_category_tags(self) -> list[str]:
        if not self._active_type:
            return []
        return self._ordered_tags_for_type({
            tag for entry in self.vault.entries
            if entry.secret_type == self._active_type
            for tag in entry.tags
        })

    def _show_tag_context_menu(self, global_pos: QPoint) -> None:
        if not self._current_category_tags():
            return
        menu = QMenu(self)
        sort_action = menu.addAction(i18n.tr("排序标签"))
        rename_action = menu.addAction(i18n.tr("重命名标签"))
        chosen = menu.exec(global_pos)
        if chosen is sort_action:
            self.sort_tags()
        elif chosen is rename_action:
            self.rename_tag()

    def sort_tags(self) -> None:
        tags = self._current_category_tags()
        if not tags:
            return
        dialog = TagSortDialog(tags, self)
        if dialog.exec() == QDialog.Accepted and dialog.ordered_tags != tags:
            self._save_tag_order(dialog.ordered_tags)

    def rename_tag(self) -> None:
        tags = self._current_category_tags()
        if not tags:
            return
        dialog = TagRenameDialog(tags, self)
        if dialog.exec() == QDialog.Accepted and dialog.old_tag and dialog.new_tag:
            self._apply_tag_rename(dialog.old_tag, dialog.new_tag)

    def _apply_tag_rename(self, old_tag: str, new_tag: str) -> None:
        if old_tag and new_tag:
            previous_order = self._ordered_tags_for_type({
                t for entry in self.vault.entries
                if entry.secret_type == self._active_type
                for t in entry.tags
            })
            count = self.vault.rename_tag(old_tag, new_tag)
            if self._active_tag == old_tag:
                self._active_tag = new_tag
            self.reload()
            self._save_tag_order([new_tag if item == old_tag else item for item in previous_order])
            self._flash(f"已将标签「{old_tag}」重命名为「{new_tag}」，影响 {count} 个条目")

    def _on_select(self, current, _previous) -> None:
        self._update_alpha_nav()
        self._pending_select = current
        if not getattr(self, "_restoring_list_selection", False):
            self.editor_workspace.show_detail()
        self._select_timer.start()

    def _on_double_click(self, item) -> None:
        if self._active_type != SecretType.PASSKEY and isinstance(item, EntryListItem):
            self.edit_entry()

    def _do_show_selected(self) -> None:
        current = self._pending_select
        if isinstance(current, EntryListItem):
            self._show_entry(current.entry, display_type=current.display_type)
        else:
            self._show_empty()

    # ---------- 详情渲染 ----------
    def _clear_detail(self) -> None:
        # 还原 _show_empty 临时设置的撑满策略：清空后若停在空状态，card 高度会
        # 一直是视口高，影响随后加入的控件布局。
        card = getattr(self, "detail_card", None)
        if card is not None:
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        transition = getattr(self, "_detail_transition", None)
        if transition is not None and transition.parentWidget().isVisible():
            transition.begin()
        while self.detail.count():
            item = self.detail.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
            elif item.layout() is not None:
                self._delete_layout(item.layout())

    def _delete_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
            elif item.layout() is not None:
                self._delete_layout(item.layout())
        layout.deleteLater()

    def _tick_otp_cards(self) -> None:
        for i in range(self.list.count()):
            item = self.list.item(i)
            if not isinstance(item, EntryListItem):
                continue
            if item.entry.secret_type != SecretType.OTP:
                continue
            card = item.card_widget
            if card is not None:
                card._refresh_otp(item.entry)
            else:
                rect = self.list.visualItemRect(item)
                if rect.isValid():
                    self.list.viewport().update(rect)

    def _show_empty(self) -> None:
        self._clear_detail()
        previous = getattr(self, "_detail_entry", None)
        if previous is not None:
            release = getattr(previous, "release_sensitive", None)
            if callable(release):
                release()
        self._detail_entry = None
        fab = getattr(self, "_detail_fab", None)
        if fab is not None:
            fab.setVisible(False)
        if self._active_type == SecretType.PASSKEY:
            text = "暂无通行密钥。通行密钥由 Android 端创建，PC 端负责查看、管理与同步。"
        else:
            text = "从左侧选择一个条目，或点击「新增条目」开始。"
        msg = QLabel(text)
        msg.setObjectName("Empty")
        msg.setWordWrap(True)
        msg.setAlignment(Qt.AlignCenter)
        # 空状态要让文案在视口内垂直居中，需两处配合：
        # detail 默认 AlignTop 会让 addStretch 失效；detail_card 默认
        # SizePolicy.Maximum 只按内容高度布局（实测 66px vs 视口 640px），
        # 即使改成 AlignCenter 也没有可分配的空间。故临时把两者都切到撑满+居中，
        # 并在 _show_entry 里还原。
        self.detail.setAlignment(Qt.AlignCenter)
        self.detail_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.detail.addWidget(msg)

    def _show_entry(self, entry: Entry, *, display_type: str | None = None) -> None:
        self._clear_detail()
        # 还原 _show_empty 临时设置的居中/撑满：条目内容应按顶部排布、高度贴合内容。
        self.detail.setAlignment(Qt.AlignTop)
        previous = getattr(self, "_detail_entry", None)
        if previous is not None and previous is not entry:
            release = getattr(previous, "release_sensitive", None)
            if callable(release):
                release()
        self._detail_entry = entry

        # 类型标识 + 标题
        shown_type = display_type or entry.secret_type
        self.detail.addWidget(MainWindow._detail_title_card(self, entry, shown_type))

        fab = getattr(self, "_detail_fab", None)
        if fab is not None:
            fab.setVisible(shown_type != SecretType.PASSKEY)

        if entry.tags:
            scroll = QScrollArea()
            scroll.setObjectName("TagScroll")
            scroll.setWidgetResizable(False)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setFixedHeight(38)
            container = QWidget()
            row = QHBoxLayout(container)
            row.setContentsMargins(*DETAIL_COLUMN_MARGINS)
            row.setSpacing(DETAIL_FIELD_ROW_SPACING)
            for t in entry.tags:
                lbl = QLabel(t)
                lbl.setObjectName("Tag")
                row.addWidget(lbl)
            row.addStretch()
            scroll.setWidget(container)
            self.detail.addWidget(scroll)

        if shown_type == SecretType.PASSKEY:
            self._render_passkey_modules(entry)
            return

        st = entry.secret_type
        _leaked = leak.is_entry_leaked(entry)
        if st == SecretType.LOGIN:
            self._render_login(entry, leaked=_leaked)
        elif st == SecretType.CARD_DOCUMENT:
            self._render_credit_card(entry)
        elif st == SecretType.WIFI:
            self._render_wifi(entry, leaked=_leaked)
        elif st == SecretType.API_KEY:
            self._render_api_key(entry, leaked=_leaked)
        elif st == SecretType.OTP:
            self._render_otp(entry)
        elif st == SecretType.SECURE_NOTE:
            self._render_secure_note(entry)
        elif st == SecretType.SERVER:
            self._render_server(entry)
        elif st == SecretType.CUSTOM:
            pass
        else:
            self._render_login(entry, leaked=_leaked)

        self._render_modules(entry)

        if entry.notes:
            self.detail.addWidget(self._field("备注", entry.notes))

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setObjectName("SettingSep")
        self.detail.addWidget(sep)

        created = datetime.datetime.fromtimestamp(entry.created_at).strftime("%Y-%m-%d %H:%M")
        updated = datetime.datetime.fromtimestamp(entry.updated_at).strftime("%Y-%m-%d %H:%M")
        created_lbl = QLabel(f"创建时间：{created}")
        created_lbl.setObjectName("Empty")
        created_lbl.setAlignment(Qt.AlignCenter)
        self.detail.addWidget(created_lbl)
        updated_lbl = QLabel(f"最后修改：{updated}")
        updated_lbl.setObjectName("Empty")
        updated_lbl.setAlignment(Qt.AlignCenter)
        self.detail.addWidget(updated_lbl)

        self.detail.addSpacing(88)

    def _detail_title_card(self, entry: Entry, shown_type: str) -> QFrame:
        accent = _detail_type_color(shown_type)
        card = QFrame()
        card.setObjectName("DetailTitleCard")
        # 主题配色留在全局样式表里，切换主题时才会随之刷新；这里只补类型强调色。
        card.setStyleSheet(f"QFrame#DetailTitleCard {{ border-left: 4px solid {accent}; }}")
        card.setProperty("accent", accent)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(*DETAIL_CARD_MARGINS)
        layout.setSpacing(10)

        type_icon = QLabel()
        type_icon.setObjectName("DetailTitleIcon")
        type_icon.setFixedSize(34, 34)
        type_icon.setAlignment(Qt.AlignCenter)
        type_icon.setPixmap(widgets.category_icon(shown_type).pixmap(24, 24))
        type_icon.setStyleSheet(f"background: {_rgba(accent, 0.14)}; border-radius: 6px;")
        layout.addWidget(type_icon, 0, Qt.AlignTop)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        text_col.setSpacing(DETAIL_FIELD_SPACING)

        label = SecretType.LABELS.get(shown_type, "")
        type_lbl = QLabel(label)
        type_lbl.setObjectName("DetailTypeBadge")
        type_lbl.setStyleSheet(f"color: {accent}; background: {_rgba(accent, 0.12)};")
        type_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        text_col.addWidget(type_lbl, 0, Qt.AlignLeft)

        title_text = label if shown_type == SecretType.PASSKEY else (entry.title or "未命名")
        title = QLabel(title_text)
        title.setObjectName("DetailTitle")
        title.setWordWrap(True)
        title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        text_col.addWidget(title)

        badges = detail_status_badges(entry, shown_type)
        if badges:
            badge_row = QHBoxLayout()
            badge_row.setContentsMargins(*DETAIL_COLUMN_MARGINS)
            badge_row.setSpacing(6)
            for text, state in badges:
                chip = QLabel(text)
                chip.setObjectName("DetailStatusChip")
                chip.setProperty("state", state)
                badge_row.addWidget(chip, 0, Qt.AlignLeft)
            badge_row.addStretch()
            text_col.addSpacing(DETAIL_BLOCK_SPACING)
            text_col.addLayout(badge_row)

        layout.addLayout(text_col, 1)
        return card

    def _render_login(self, entry: Entry, leaked: bool = False) -> None:
        self.detail.addWidget(self._field("用户名", entry.username, copyable=True))
        self.detail.addWidget(self._field("密码", entry.password, copyable=True, secret=True, leaked=leaked))
        if entry.url:
            self.detail.addWidget(self._field("网址", entry.url, copyable=True))
        otp_source = None
        if entry.has_otp():
            otp_source = entry.otp_fields()
        else:
            bound_id = entry.otp_binding_id()
            if bound_id:
                bound_vault = getattr(self, "vault", None)
                candidate = bound_vault.read_entry(bound_id) if bound_vault is not None else None
                if candidate is not None and candidate.secret_type == SecretType.OTP and not candidate.deleted_at:
                    otp_source = candidate.otp_fields()
        if otp_source and otp_source.get("secret"):
            section = QLabel("动态码")
            section.setObjectName("FieldLabel")
            self.detail.addWidget(section)
            self.detail.addWidget(_OtpCodeWidget(otp_source, self._copy, self))
        associated_app = entry.target_app or entry_modules.target_app_value(entry.fields)
        if associated_app:
            # 与「用户名 / 密码 / 网址」一致：标题一行、内容一行，长包名换行显示而不是右对齐裁切。
            self.detail.addWidget(self._field("关联程序 / 包名", associated_app, copyable=True))
        self._render_linked_autofill(entry)
        if any(entry.fields.get(key) for key in ("_autofill_bindings", "_autofill_origin", "_autofill_field_mappings")):
            memory = QPushButton(i18n.tr("自动填充记忆"))
            memory.setObjectName("SettingsBtn")
            memory.clicked.connect(lambda: self._show_autofill_memory(entry))
            self.detail.addWidget(memory)

    def _show_autofill_memory(self, entry: Entry) -> None:
        from .autofill_memory import AutofillMemoryDialog
        dialog = AutofillMemoryDialog(self.vault, entry, self)
        dialog.exec()
        if dialog.changed:
            self._flash(i18n.tr("自动填充记忆已更新"))
            refreshed = self.vault.read_entry(entry.id)
            if refreshed is not None:
                self._show_entry(refreshed)

    def _render_linked_autofill(self, entry: Entry) -> None:
        """展示本条目关联的自动填充来源，对齐 Android 详情页的「关联自动填充内容」。

        卡片视觉与 Android ``LinkedAutofillDetails`` 一致：圆形类型图标（按来源
        类目着色）、标题、``类目 · 角色`` 副标题、右侧跳转箭头；来源已删除时用
        链接图标占位且不可点击。
        """
        groups = linked_autofill_detail_groups(entry, self.vault.entries)
        if not groups:
            return

        section = QLabel(i18n.tr("关联自动填充内容"))
        section.setObjectName("FieldLabel")
        self.detail.addWidget(section)

        for index, group in enumerate(groups):
            role_text = "、".join(
                i18n.tr(AUTOFILL_ROLE_LABELS.get(role, role)) for role in group.roles
            )
            source = group.source
            if source is not None:
                title = source.title.strip() or i18n.tr("未命名条目")
                category = i18n.tr(SecretType.LABELS.get(source.secret_type, ""))
                source_id = group.source_entry_id
            else:
                # 来源条目已被删除：仍展示占位，让用户知道关联存在但已失效。
                title = i18n.tr("来源不可用")
                category = ""
                source_id = None

            card = QFrame()
            card.setObjectName("LinkedAutofillCard")
            row = QHBoxLayout(card)
            row.setContentsMargins(*DETAIL_CARD_MARGINS)
            row.setSpacing(10)

            # 圆形类型图标，底色按来源类目着色（对齐 Android categoryIconBackground）
            badge = QLabel()
            badge.setObjectName("DetailTitleIcon")
            badge.setFixedSize(36, 36)
            badge.setAlignment(Qt.AlignCenter)
            badge.setPixmap(
                widgets.category_pixmap(source.secret_type, 20)
                if source is not None
                else widgets.ui_icon("merge").pixmap(20, 20)
            )
            accent = _detail_type_color(source.secret_type) if source is not None else ""
            if accent:
                badge.setStyleSheet(f"background: {_rgba(accent, 0.16)}; border-radius: 18px;")
            else:
                badge.setStyleSheet("border-radius: 18px;")
            row.addWidget(badge, 0, Qt.AlignVCenter)

            text_col = QVBoxLayout()
            text_col.setContentsMargins(*DETAIL_COLUMN_MARGINS)
            text_col.setSpacing(DETAIL_FIELD_SPACING)
            headline = QLabel(title)
            headline.setObjectName("LinkedAutofillTitle")
            headline.setWordWrap(True)
            text_col.addWidget(headline)
            subtitle_text = f"{category} · {role_text}" if category else role_text
            sub = QLabel(subtitle_text)
            sub.setObjectName("FieldLabel")
            sub.setWordWrap(True)
            text_col.addWidget(sub)
            row.addLayout(text_col, 1)

            if source_id is not None:
                card.setProperty("linked", True)
                card.setCursor(Qt.PointingHandCursor)
                card.mouseReleaseEvent = lambda event, sid=source_id: (
                    None
                    if event.button() != Qt.LeftButton
                    else self._goto_entry(sid)
                )
            else:
                card.setEnabled(False)

            self.detail.addWidget(card)
            if index != len(groups) - 1:
                self.detail.addSpacing(DETAIL_BLOCK_SPACING)

    def _goto_entry(self, entry_id: str) -> None:
        """解除筛选并选中条目，用于详情页的关联跳转。"""
        try:
            entry = self.vault._lazy(entry_id)
        except (KeyError, IndexError):
            return
        if self._reveal_entry(entry):
            self._select_by_id(entry_id)

    def _render_credit_card(self, entry: Entry) -> None:
        card_type = entry.get_field("card_type") or entry_modules.CARD_BANK
        self.detail.addWidget(self._field("卡片类型", entry_modules.CARD_TYPE_LABELS.get(card_type, card_type)))
        rows = {
            entry_modules.CARD_BANK: (
                ("持卡人姓名", "cardholder", False),
                ("完整卡号", "card_number", True),
                ("发卡行", "bank", False),
                ("开户行名称", "bank_branch", False),
                ("开户行行号", "bank_branch_code", False),
                ("有效期", "expiry", False),
                ("CVV", "cvv", True),
                ("取款密码", "withdrawal_password", True),
            ),
            entry_modules.CARD_ID_CARD: (
                ("姓名", "full_name", False),
                ("证件号码", "id_number", True),
                ("签发日期", "issue_date", False),
                ("到期日期", "expiry_date", False),
                ("签发机关", "issuing_authority", False),
            ),
            entry_modules.CARD_CUSTOM: (
                ("自定义卡证名称", "card_name", False),
                ("卡号", "card_number", True),
                ("有效期", "expiry", False),
            ),
        }
        active_keys = set(entry_modules.CARD_FIELDS.get(card_type, entry_modules.CARD_FIELDS[entry_modules.CARD_CUSTOM]))
        for label, key, secret in rows.get(card_type, rows[entry_modules.CARD_CUSTOM]):
            value = entry.get_field(key)
            if value:
                self.detail.addWidget(self._field(label, value, copyable=True, secret=secret, guarded=secret, no_select=secret))
        imgs = entry.fields.get("card_images_b64") or []
        if imgs:
            self.detail.addWidget(self._images_field("卡片图片", imgs, guarded=True))

    def _render_wifi(self, entry: Entry, leaked: bool = False) -> None:
        self.detail.addWidget(self._field("网络名称 (SSID)", entry.get_field("ssid"), copyable=True))
        self.detail.addWidget(self._field("Wi-Fi 密码", entry.get_field("wifi_password"), copyable=True, secret=True, leaked=leaked))
        self.detail.addWidget(self._field("加密类型", entry.get_field("security_type")))
        if entry.get_field("router_admin_url"):
            self.detail.addWidget(self._field("路由器管理地址", entry.get_field("router_admin_url"), copyable=True))
        if entry.get_field("admin_password"):
            self.detail.addWidget(self._field("管理密码", entry.get_field("admin_password"), copyable=True, secret=True, leaked=leaked))
        ssid = entry.get_field("ssid")
        if ssid:
            self.detail.addWidget(self._wifi_qrcode_widget(entry))

    _QR_CACHE: dict[str, QPixmap] = {}

    @classmethod
    def _wifi_qrcode_widget(cls, entry: Entry) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        lay.setSpacing(DETAIL_FIELD_SPACING)

        lbl = QLabel("扫码连接")
        lbl.setObjectName("FieldLabel")
        lay.addWidget(lbl)

        img_lbl = QLabel()
        img_lbl.setAlignment(Qt.AlignCenter)
        lay.addWidget(img_lbl)

        cached = cls._QR_CACHE.get(entry.id)
        if cached is not None:
            img_lbl.setPixmap(cached)
            return wrap

        try:
            import io as _io

            import qrcode

            ssid = entry.get_field("ssid")
            password = entry.get_field("wifi_password")
            security = entry.get_field("security_type") or "WPA2-Personal"

            def _esc(s: str) -> str:
                result = []
                for c in s:
                    if c in '\\;,":':
                        result.append("\\")
                    result.append(c)
                return "".join(result)

            auth = entry_modules.wifi_qr_auth_token(security, bool(password))
            qr_str = f"WIFI:T:{auth};S:{_esc(ssid)};P:{_esc(password)};H:false;;"

            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=4,
                border=3,
            )
            qr.add_data(qr_str)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = _io.BytesIO()
            img.save(buf, format="PNG")

            px = QPixmap()
            px.loadFromData(buf.getvalue())
            cls._QR_CACHE[entry.id] = px
            img_lbl.setPixmap(px)
        except Exception:
            img_lbl.setText("二维码生成失败，请确认已安装 qrcode 依赖")

        return wrap

    def _render_api_key(self, entry: Entry, leaked: bool = False) -> None:
        if entry.get_field("service"):
            self.detail.addWidget(self._field("服务名称", entry.get_field("service"), copyable=True))
        if entry.get_field("api_key"):
            self.detail.addWidget(self._field("API 凭证", entry.get_field("api_key"), copyable=True, secret=True, guarded=True, leaked=leaked))
        if entry.get_field("api_secret"):
            # Treat API secret as a guarded sensitive field (like CVV): viewing/copying
            # requires re-confirming the master password.
            self.detail.addWidget(self._field("API Secret", entry.get_field("api_secret"), copyable=True, secret=True, guarded=True))
        if entry.get_field("base_url"):
            self.detail.addWidget(self._field("Base URL", entry.get_field("base_url"), copyable=True))
        if entry.get_field("scopes"):
            self.detail.addWidget(self._field("权限范围", entry.get_field("scopes")))

    def _render_otp(self, entry: Entry) -> None:
        fields = otp.normalize_fields(entry.otp_fields())
        self.detail.addWidget(_OtpCodeWidget(entry.otp_fields(), self._copy, self))
        if fields.get("issuer"):
            self.detail.addWidget(self._field("发行方", fields.get("issuer", ""), copyable=True))
        if fields.get("label"):
            self.detail.addWidget(self._field("账户标签", fields.get("label", ""), copyable=True))
        self.detail.addWidget(self._field("算法", fields.get("algorithm", "SHA1")))
        self.detail.addWidget(self._field("位数", fields.get("digits", "6")))
        if fields.get("type") == "hotp":
            self.detail.addWidget(self._field("计数器", fields.get("counter", "0")))
        else:
            self.detail.addWidget(self._field("周期", fields.get("period", "30") + " 秒"))
        if fields.get("otp_domains"):
            self.detail.addWidget(self._field("关联域名", fields.get("otp_domains", ""), copyable=True))
        self.detail.addWidget(self._field("Base32 密钥", fields.get("secret", ""), copyable=True, secret=True, guarded=True))

    def _render_secure_note(self, entry: Entry) -> None:
        text = entry.get_field("note")
        if not text:
            for module in entry_modules.modules_from_fields(entry.fields):
                if module.get("type") == entry_modules.MULTILINE:
                    text = str(module.get("value", ""))
                    break
        if text:
            self.detail.addWidget(
                self._field(
                    "安全笔记内容",
                    text,
                    copyable=True,
                    secret=True,
                    guarded=True,
                )
            )

    def _render_server(self, entry: Entry) -> None:
        labels = {"host": "主机 / IP", "port": "端口", "username": "用户名", "password": "密码"}
        field_map = {"host": "server_host", "port": "server_port", "username": "server_user", "password": "server_pass"}
        server_fields = {k: entry.get_field(field_map[k]) for k in field_map}
        if not any(server_fields.values()):
            for module in entry_modules.modules_from_fields(entry.fields):
                if module.get("type") == entry_modules.SERVER_CONNECTION:
                    value = module.get("value")
                    if isinstance(value, dict):
                        server_fields = {k: str(value.get(k, "")) for k in field_map}
                    break
        if any(server_fields.values()):
            section = QLabel("服务器")
            section.setObjectName("FieldLabel")
            self.detail.addWidget(section)
            for key in ("host", "port", "username", "password"):
                text = server_fields.get(key, "")
                if text:
                    sensitive = key == "password"
                    self.detail.addWidget(
                        self._field(
                            labels[key],
                            text,
                            copyable=True,
                            secret=sensitive,
                            guarded=sensitive,
                        )
                    )

    def _render_modules(self, entry: Entry) -> None:
        labels = {
            "username": "用户名",
            "password": "密码",
            "api_key": "API Key",
            "api_secret": "API Secret",
            "ssid": "SSID",
            "wifi_password": "Wi-Fi 密码",
            "security_type": "加密类型",
            "router_admin_url": "路由器管理地址",
            "admin_password": "管理密码",
            "host": "主机 / IP",
            "port": "端口",
            "engine": "数据库引擎",
            "private_key": "私钥",
            "fingerprint": "指纹",
            "database": "数据库名",
            "secret": "密钥",
            "issuer": "发行方",
            "label": "账户名",
            "algorithm": "算法",
            "digits": "位数",
            "period": "周期",
            "type": "类型",
            "counter": "计数器",
            "cardholder": "持卡人",
            "card_number": "卡号",
            "cvv": "CVV",
            "withdrawal_password": "取款密码",
            "bank": "银行",
            "card_type": "卡片类型",
            "card_name": "卡片名称",
            "notes": "备注",
            "full_name": "姓名",
            "id_number": "证件号码",
            "issue_date": "签发日期",
            "issuing_authority": "签发机关",
            "country": "国家 / 地区",
            "region": "省 / 州",
            "city": "城市",
            "address": "详细地址",
            "postal_code": "邮政编码",
            "question": "安全问题",
            "answer": "答案",
            "expiry": "有效期",
            "expiry_date": "到期日期",
        }
        for module in entry_modules.detail_modules(entry.fields, getattr(entry, "secret_type", "")):
            title = str(module.get("title") or "模块")
            module_type = str(module.get("type") or "")
            if module_type not in entry_modules.CATALOG:
                note = QLabel(f"{title}：当前版本暂不支持，数据已保留")
                note.setObjectName("SettingDangerNote")
                note.setWordWrap(True)
                self.detail.addWidget(note)
                continue
            value = module.get("value")
            guarded_all = bool(module.get("sensitive"))
            if module_type == entry_modules.PASSKEY:
                section = QLabel("通行密钥")
                section.setObjectName("FieldLabel")
                self.detail.addWidget(section)
                self._render_passkey_rows(module)
                continue
            if module_type == entry_modules.IMAGES and isinstance(value, list):
                if value:
                    self.detail.addWidget(self._images_field(title, value, guarded=guarded_all))
                continue
            if module_type == entry_modules.ATTACHMENTS and isinstance(value, list):
                if value:
                    self.detail.addWidget(self._attachments_field(title, value, guarded=guarded_all))
                continue
            if isinstance(value, dict):
                config = module.get("config") if isinstance(module.get("config"), dict) else {}
                sensitive_fields = entry_modules.mandatory_sensitive_fields(module_type)
                extra = config.get("sensitiveFields")
                if isinstance(extra, list):
                    sensitive_fields.update(str(key) for key in extra)
                section = QLabel(title)
                section.setObjectName("FieldLabel")
                self.detail.addWidget(section)
                active_card_fields = (
                    set(entry_modules.CARD_FIELDS.get(str(value.get("card_type") or entry_modules.CARD_BANK), ())) | {"images"}
                    if module_type == entry_modules.CARD_DOCUMENT
                    else set()
                )
                for key, raw in entry_modules.ordered_value(module).items():
                    if module_type == entry_modules.CARD_DOCUMENT and key not in active_card_fields and key != "images":
                        continue
                    if key == "images" and isinstance(raw, list):
                        images = [item for item in raw if isinstance(item, str) and item]
                        if images:
                            self.detail.addWidget(
                                self._images_field(
                                    "图片",
                                    images,
                                    guarded=guarded_all or module_type == entry_modules.CARD_DOCUMENT,
                                )
                            )
                        continue
                    if isinstance(raw, (dict, list)):
                        text = json.dumps(raw, ensure_ascii=False, separators=(",", ":")) if raw else ""
                    else:
                        text = str(raw or "")
                    if key == "card_type":
                        text = entry_modules.CARD_TYPE_LABELS.get(text, text)
                    if not text:
                        continue
                    sensitive = guarded_all or key in sensitive_fields
                    self.detail.addWidget(
                        self._field(
                            labels.get(key, key),
                            text,
                            copyable=True,
                            secret=sensitive,
                            guarded=sensitive,
                        )
                    )
            elif module_type == entry_modules.MULTILINE and isinstance(value, str):
                text = value
                if text.strip():
                    self.detail.addWidget(self._markdown_field(title, text, guarded=guarded_all))
            else:
                text = "是" if module_type == entry_modules.BOOLEAN and value is True else ("否" if module_type == entry_modules.BOOLEAN else str(value or ""))
                if text:
                    self.detail.addWidget(
                        self._field(
                            title,
                            text,
                            copyable=True,
                            secret=guarded_all,
                            guarded=guarded_all,
                        )
                    )

    def _markdown_field(self, label: str, text: str, *, guarded: bool = False) -> QWidget:
        wrap = QWidget()
        wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        lay.setSpacing(DETAIL_FIELD_SPACING)

        head = QHBoxLayout()
        head.setSpacing(DETAIL_FIELD_ROW_SPACING)
        lbl = QLabel(label)
        lbl.setObjectName("FieldLabel")
        head.addWidget(lbl, 1)
        if text:
            copy = widgets.icon_only_button("copy", "复制", size=16, object_name="Ghost")
            if guarded:
                copy.clicked.connect(lambda _=False, btn=copy, val=text: self._guarded_copy(btn, val, field_label=label))
            else:
                copy.clicked.connect(lambda _=False, btn=copy: self._copy(text, btn))
            head.addWidget(copy)
        lay.addLayout(head)

        viewer = widgets.MarkdownViewer(text or "*（空）*", min_height=440)
        viewer.setFixedHeight(440)
        lay.addWidget(viewer)
        return wrap

    def _render_passkey_modules(self, entry: Entry) -> None:
        passkey_modules = [module for module in entry_modules.modules_from_fields(entry.fields) if module.get("type") == entry_modules.PASSKEY]
        for index, module in enumerate(passkey_modules, start=1):
            section = QLabel("通行密钥" if len(passkey_modules) == 1 else f"通行密钥 {index}")
            section.setObjectName("FieldLabel")
            self.detail.addWidget(section)
            self._render_passkey_rows(module)

    def _render_passkey_rows(self, module: object) -> None:
        for label, text in passkey_display_rows(module):
            self.detail.addWidget(self._field(label, text, no_select=True))

    def _images_field(self, label: str, images: list[object], guarded: bool = False) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        lay.setSpacing(DETAIL_FIELD_SPACING)

        lbl = QLabel(label)
        lbl.setObjectName("FieldLabel")
        lay.addWidget(lbl)

        scroll = widgets.HScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setFixedHeight(_DetailImgCard.H + 12)

        inner = QWidget()
        row = QHBoxLayout(inner)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(8)
        for index, b64 in enumerate(images):
            row.addWidget(
                _DetailImgCard(
                    b64,
                    guarded=guarded,
                    gallery=images,
                    gallery_index=index,
                )
            )
        row.addStretch()

        scroll.setWidget(inner)
        lay.addWidget(scroll)
        return wrap

    def _photo_module_field(self, label: str, images: list[object], guarded: bool = False) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        lay.setSpacing(DETAIL_FIELD_SPACING)

        lbl = QLabel(f"{label} · {len(images)}")
        lbl.setObjectName("FieldLabel")
        lay.addWidget(lbl)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        for index, value in enumerate(images):
            grid.addWidget(
                _DetailImgCard(
                    value,
                    guarded=guarded,
                    large=True,
                    gallery=images,
                    gallery_index=index,
                ),
                index // 2,
                index % 2,
            )
        lay.addLayout(grid)
        return wrap

    def _attachments_field(self, label: str, attachments: list[dict], *, guarded: bool = False) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        valid_attachments = [item for item in attachments if isinstance(item, dict)]

        def attachment_size(item: dict) -> int:
            try:
                return max(0, int(item.get("size") or 0))
            except (TypeError, ValueError):
                return 0

        total_size = sum(attachment_size(item) for item in valid_attachments)
        lbl = QLabel(f"{label} · {len(valid_attachments)} · {_format_attachment_size(total_size)}")
        lbl.setObjectName("FieldLabel")
        lay.addWidget(lbl)
        for item in valid_attachments:
            row = QHBoxLayout()
            name = Path(str(item.get("name") or "attachment.bin")).name
            size = attachment_size(item)
            mime = str(item.get("mime") or "application/octet-stream")
            info = QWidget()
            info_lay = QVBoxLayout(info)
            info_lay.setContentsMargins(0, 2, 0, 2)
            info_lay.setSpacing(2)
            info_lay.addWidget(QLabel(name))
            metadata = QLabel(f"{_format_attachment_size(size)} · {mime}")
            metadata.setObjectName("SettingNote")
            info_lay.addWidget(metadata)
            row.addWidget(info, 1)
            export = widgets.set_button_icon(QPushButton(), "download", size=18)
            export.setObjectName("RevealIconBtn")
            export.setFixedSize(44, 32)
            export.setToolTip("下载附件")
            export.setAccessibleName("下载附件")
            export.clicked.connect(lambda _=False, value=item, protect=guarded: self._export_attachment(value, guarded=protect))
            row.addWidget(export)
            lay.addLayout(row)
        return wrap

    def _export_attachment(self, item: dict, *, guarded: bool = False) -> None:
        if guarded and not _confirm_master_password(
            self.vault,
            "导出敏感附件",
            "导出敏感附件需要验证当前主密码。",
            self,
        ):
            return
        name = Path(str(item.get("name") or "attachment.bin")).name
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n.tr("导出附件"),
            str(Path.home() / name),
            i18n.tr("所有文件 (*)"),
        )
        if not path:
            return
        try:
            destination = Path(path)
            media_files.export_value(item.get("data") or "", destination)
            widgets.message(self, "导出完成", f"附件已保存到：{path}", kind="success")
        except (OSError, ValueError) as exc:
            widgets.message(self, "导出失败", str(exc), kind="error")

    def _field(self, label: str, value: str, *, copyable=False, secret=False, guarded=False, no_select=False, leaked=False) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)
        lay.setSpacing(DETAIL_FIELD_SPACING)

        lbl = QLabel(label)
        lbl.setObjectName("FieldLabel")
        if leaked:
            lbl.setProperty("leaked", True)
        lay.addWidget(lbl)

        row = QHBoxLayout()
        row.setSpacing(DETAIL_FIELD_ROW_SPACING)
        shown = ("•" * 10) if secret and value else (value or "—")
        val = QLabel(shown)
        val.setObjectName("FieldValue")
        # 短字段（如 CVV/取款密码）禁掉选中以杜绝 Ctrl+C / 右键复制
        if not no_select:
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        val.setWordWrap(True)
        val.setMinimumWidth(0)
        val.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Minimum)
        row.addWidget(val, 1)

        if secret and value:
            eye = widgets.set_button_icon(QPushButton(), "view", size=18)
            eye.setObjectName("RevealIconBtn")
            eye.setCheckable(True)
            eye.setFixedSize(44, 32)
            eye.setToolTip("显示或隐藏")
            if guarded:
                eye.toggled.connect(lambda on, e=eye, v=val: self._on_guarded_reveal_toggled(e, v, value, on, label))
            else:
                eye.toggled.connect(lambda on, e=eye, v=val: self._on_reveal_toggled(e, v, value, on))
            row.addWidget(eye)
        if copyable and value:
            copy = widgets.icon_only_button("copy", "复制", size=16, object_name="Ghost")
            if guarded:
                copy.clicked.connect(lambda _=False, btn=copy, val=value, sec=secret, fl=label: self._guarded_copy(btn, val, secret=sec, field_label=fl))
            else:
                copy.clicked.connect(lambda _=False, btn=copy: self._copy(value, btn, secret=secret))
            row.addWidget(copy)

        lay.addLayout(row)
        return wrap

    def _on_reveal_toggled(self, eye: QPushButton, label: QLabel, value: str, shown: bool) -> None:
        widgets.set_eye_icon(eye, shown)
        try:
            label.setText(value if shown else "•" * 10)
        except RuntimeError:
            return
        if shown:
            QTimer.singleShot(self._reveal_hide_ms, lambda: self._auto_rehide(eye))

    def _on_guarded_reveal_toggled(self, eye: QPushButton, label: QLabel, value: str, shown: bool, field_label: str) -> None:
        if shown:
            if not _confirm_master_password(self.vault, f"查看{field_label}", f"查看{field_label}需要验证当前主密码。", self):
                eye.blockSignals(True)
                eye.setChecked(False)
                eye.blockSignals(False)
                widgets.set_eye_icon(eye, False)
                return
        self._on_reveal_toggled(eye, label, value, shown)

    def _guarded_copy(self, btn: QPushButton, value: str, *, secret: bool = False, field_label: str = "敏感信息") -> None:
        if not _confirm_master_password(self.vault, f"查看{field_label}", f"查看{field_label}需要验证当前主密码。", self):
            return
        self._copy(value, btn, secret=secret)

    @staticmethod
    def _auto_rehide(eye: QPushButton) -> None:
        try:
            if eye.isChecked():
                eye.setChecked(False)
        except RuntimeError:
            pass

    # ---------- 隐私 ----------
    def apply_privacy_settings(self) -> None:
        reveal_seconds = max(2, int(config.get("reveal_hide_seconds", 5) or 5))
        self._reveal_hide_ms = reveal_seconds * 1000
        try:
            clipboard_seconds = int(
                config.get(
                    "clipboard_clear_seconds",
                    config.DEFAULT_CLIPBOARD_CLEAR_SECONDS,
                )
            )
        except (TypeError, ValueError):
            clipboard_seconds = config.DEFAULT_CLIPBOARD_CLEAR_SECONDS
        clipboard_seconds = max(
            config.MIN_CLIPBOARD_CLEAR_SECONDS,
            min(config.MAX_CLIPBOARD_CLEAR_SECONDS, clipboard_seconds),
        )
        self._clipboard_clear_ms = clipboard_seconds * 1000
        if self.isVisible():
            widgets.apply_capture_permission(self)
        QTimer.singleShot(0, self._schedule_leak_audit)

    # ---------- 泄露自检 ----------
    def _schedule_leak_audit(self) -> None:
        if self._locked or not leak.check_enabled():
            return
        if self._leak_worker is not None and self._leak_worker.isRunning():
            self._leak_rescan_requested = True
            return

        entries = self.vault.entries
        current_revisions = {(entry.id, entry.updated_at) for entry in entries}
        self._leak_attempted_revisions.intersection_update(current_revisions)

        snapshots: list[tuple[str, float, str]] = []
        canonical_passwords: dict[str, str] = {}
        for entry in entries:
            try:
                key = (entry.id, entry.updated_at)
                if key in self._leak_attempted_revisions or not leak.needs_leak_check(entry):
                    continue
                password = leak.entry_secret(entry)
                if not password:
                    continue
                password = canonical_passwords.setdefault(password, password)
                snapshots.append((entry.id, entry.updated_at, password))
                self._leak_attempted_revisions.add(key)
            finally:
                release = getattr(entry, "release_sensitive", None)
                if release is not None:
                    release()

        if not snapshots:
            return
        self._leak_rescan_requested = False
        self._leak_worker_vault_path = self.vault.path
        self._leak_audit_started = time.perf_counter()
        self._leak_audit_total = len(snapshots)
        worker = _LeakAuditWorker(snapshots, parent=self)
        worker.completed.connect(self._on_leak_audit_completed)
        self._leak_worker = worker
        self._leak_audit_manual = False
        _log.info(
            "开始后台泄露自检：%d 个未检测版本，%d 个不同密码",
            len(snapshots),
            len({password for _, _, password in snapshots}),
        )
        worker.start()

    def start_manual_leak_audit(self) -> bool:
        if self._locked:
            if self._security_page() is not None:
                widgets.message(self._security_page(), "无法执行联网检测", "保险库已锁定，请重新解锁后再试。", kind="warn")
                self._hide_leak_progress()
            return False
        if not leak.check_enabled():
            if self._security_page() is not None:
                widgets.message(self._security_page(), "联网检测已关闭", "请先在设置中开启“密码泄露检测”。", kind="warn")
                self._hide_leak_progress()
            else:
                self._flash("泄露检测已关闭")
            return False
        if self._leak_worker is not None and self._leak_worker.isRunning():
            if self._security_page() is not None:
                widgets.message(self._security_page(), "正在检测", "已有一项联网泄露检测正在进行，请等待完成。")
                self._hide_leak_progress()
            else:
                self._flash("泄露检测正在进行")
            return False
        snapshots: list[tuple[str, float, str]] = []
        canonical_passwords: dict[str, str] = {}
        for entry in self.vault.entries:
            try:
                password = leak.entry_secret(entry)
                if password:
                    snapshots.append((entry.id, entry.updated_at, canonical_passwords.setdefault(password, password)))
            finally:
                release = getattr(entry, "release_sensitive", None)
                if release is not None:
                    release()
        if not snapshots:
            if self._security_page() is not None:
                widgets.message(self._security_page(), "没有可检测条目", "保险库中没有包含可检测密码的条目。")
                self._hide_leak_progress()
            return False

        self._leak_rescan_requested = False
        self._leak_worker_vault_path = self.vault.path
        self._leak_audit_started = time.perf_counter()
        self._leak_audit_manual = True
        self._leak_audit_total = len(snapshots)
        self._show_leak_progress(0, len(snapshots), "正在检测密码泄露")
        worker = _LeakAuditWorker(snapshots, manual=True, parent=self)
        worker.progress.connect(self._on_leak_audit_progress)
        worker.completed.connect(self._on_leak_audit_completed)
        self._leak_worker = worker
        _log.info(
            "开始手动泄露检测：%d 个条目，%d 个不同密码",
            len(snapshots),
            len({password for _, _, password in snapshots}),
        )
        worker.start()
        return True

    def _show_leak_progress(self, done: int, total: int, text: str) -> None:
        target = self._security_page()
        if target is None:
            return
        total = max(0, total)
        percent = int(100 * done / max(total, 1))
        target._scan_bar.setValue(percent)
        target._scan_bar.show()
        target._analysis_status.setText(f"{text}：{done}/{total}")

    def _hide_leak_progress(self) -> None:
        target = self._security_page()
        if target is None:
            return
        target._scan_bar.hide()
        if target._report.total:
            target._analysis_status.setText(
                f"已扫描 {target._report.total} 个含密码条目："
                f"高风险 {len(target._report.high_risk)}，"
                f"需改进 {len(target._report.improvement)}，未发现问题 {len(target._report.healthy)}。"
            )

    def _on_leak_audit_progress(self, done: int, total: int) -> None:
        if self._leak_audit_manual:
            self._show_leak_progress(done, total, "正在检测密码泄露")

    def _on_leak_audit_completed(self, results: list[leak.LeakCheckResult]) -> None:
        worker = self._leak_worker
        manual = bool(worker.manual) if worker is not None else self._leak_audit_manual
        if worker is not None:
            worker.deleteLater()
        self._leak_worker = None
        for result in results:
            self._leak_attempted_revisions.discard((result.entry_id, result.revision))
        applied = 0
        if self.vault.path == self._leak_worker_vault_path:
            applied = self.vault.apply_leak_checks(results)
        elapsed_ms = int((time.perf_counter() - self._leak_audit_started) * 1000)
        _log.info(
            "后台泄露自检完成：成功 %d，写入 %d，耗时 %d ms",
            len(results),
            applied,
            elapsed_ms,
        )
        rescan = self._leak_rescan_requested
        self._leak_rescan_requested = False
        target = self._security_page()
        total = self._leak_audit_total
        self._leak_audit_total = 0
        if applied:
            self.reload()
        if manual:
            if target is not None:
                failed = max(0, total - len(results))
                stale = max(0, len(results) - applied)
                breached = sum(1 for result in results if int(result.pwned_count or 0) > 0)
                not_found = max(0, len(results) - breached)
                lines = [
                    f"请求检查 {total} 个条目",
                    f"发现公开泄露 {breached} 个 · 未发现公开泄露 {not_found} 个",
                ]
                if failed:
                    lines.append(f"网络失败 {failed} 个：保留原检测状态")
                if stale:
                    lines.append(f"内容已变化 {stale} 个：结果未写入")
                lines.append("“未发现公开泄露”只表示本次数据源未命中，不等同于密码绝对安全。")
                target._manual_refresh = False
                target._re_scanning = True
                target.update_entries(list(self.vault.entries), self._security_logical_revision())
                widgets.message(
                    target,
                    "联网泄露检测完成",
                    "\n".join(lines),
                    kind="warn" if breached or failed or stale else "success",
                )
        elif rescan:
            self._schedule_leak_audit()

    def open_vault_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.vault.path.parent)))
        self._flash("已打开密码库所在文件夹")

    # ---------- 操作 ----------

    def _copy(self, text: str, btn: QPushButton | None = None, *, secret: bool = False) -> None:
        if secret:
            _clipboard.copy_stealth(text)
            if self._clipboard_clear_ms:
                self._flash(f"已复制（隐身，{self._clipboard_clear_ms // 1000} 秒后自动清除）")
            else:
                self._flash("已复制（隐身）")
        else:
            QGuiApplication.clipboard().setText(text)
            if self._clipboard_clear_ms:
                self._flash(f"已复制到剪贴板（{self._clipboard_clear_ms // 1000} 秒后自动清除）")
            else:
                self._flash("已复制到剪贴板")
        if self._clipboard_clear_ms:
            _clipboard.remember_text_expiry(text, self._clipboard_clear_ms // 1000)
            QTimer.singleShot(self._clipboard_clear_ms, lambda t=text: _clipboard.clear_if_match(t))
        if btn is not None:
            widgets.flash_copy_success(btn)

    def add_entry(self, secret_type: str | None = None, *, show_type_selector: bool = True) -> None:
        dlg = EntryDialog(parent=self, default_type=secret_type, show_type_selector=show_type_selector)
        try:
            if dlg.exec():
                _log.info("用户新增条目（类型=%s）", dlg.entry.secret_type)
                try:
                    dlg._entry = self._persist_entry(dlg.entry)
                except (OSError, ValueError, StaleEntryChange, ExternalVaultChange) as exc:
                    widgets.message(self, "保存失败", str(exc), kind="error")
                    return
                self._cache_dialog_leak_result(dlg)
                self.reload()
                self._select_by_id(dlg.entry.id)
                QTimer.singleShot(0, self._schedule_leak_audit)
                self._flash("已添加密码")
        finally:
            dlg.deleteLater()  # 及时释放表单与解密后的图片/密码

    def edit_entry(self) -> None:
        if self._active_type == SecretType.PASSKEY:
            return
        item = self.list.currentItem()
        if not isinstance(item, EntryListItem):
            return
        if item.entry.secret_type == SecretType.PASSKEY:
            return
        if item.entry.secret_type in _GUARDED_SECRET_TYPES or entry_modules.has_sensitive_modules(item.entry.fields):
            label = SecretType.LABELS[item.entry.secret_type]
            if not _confirm_master_password(self.vault, f"编辑{label}", f"编辑{label}信息需要验证当前主密码。", self):
                return
        dlg = EntryDialog(entry=item.entry, parent=self)
        try:
            if dlg.exec():
                _log.info("用户编辑条目：「%s」", _log_mod.redact(dlg.entry.title))
                try:
                    dlg._entry = self._persist_entry(dlg.entry, previous=item.entry)
                except (StaleEntryChange, ExternalVaultChange) as exc:
                    widgets.message(self, "条目已变化", str(exc), kind="warn")
                    self._refresh_external_vault()
                    return
                except (OSError, ValueError) as exc:
                    widgets.message(self, "保存失败", str(exc), kind="error")
                    return
                self._cache_dialog_leak_result(dlg)
                self.reload()
                self._select_by_id(dlg.entry.id)
                QTimer.singleShot(0, self._schedule_leak_audit)
                self._flash("已保存修改")
        finally:
            dlg.deleteLater()  # 及时释放表单与解密后的图片/密码

    def _open_entry_by_id(self, entry_id: str) -> None:
        """Open the entry editor for a specific entry ID."""
        try:
            entry = self.vault._lazy(entry_id)
        except (KeyError, IndexError):
            return
        if entry.secret_type == SecretType.PASSKEY:
            return
        if entry.secret_type in _GUARDED_SECRET_TYPES or entry_modules.has_sensitive_modules(entry.fields):
            label = SecretType.LABELS[entry.secret_type]
            if not _confirm_master_password(self.vault, f"编辑{label}", f"编辑{label}信息需要验证当前主密码。", self):
                return
        dlg = EntryDialog(entry=entry, parent=self)
        try:
            if dlg.exec():
                try:
                    dlg._entry = self._persist_entry(dlg.entry, previous=entry)
                except (StaleEntryChange, ExternalVaultChange) as exc:
                    widgets.message(self, "条目已变化", str(exc), kind="warn")
                    self._refresh_external_vault()
                    return
                except (OSError, ValueError) as exc:
                    widgets.message(self, "保存失败", str(exc), kind="error")
                    return
                self._cache_dialog_leak_result(dlg)
                self.reload()
                self._select_by_id(dlg.entry.id)
                QTimer.singleShot(0, self._schedule_leak_audit)
        finally:
            dlg.deleteLater()

    def _persist_entry(self, entry: Entry, previous: Entry | None = None) -> Entry:
        """Publish staged PMVE media together with its Entry."""
        if media_files.has_pending_imports(entry):
            committed = media_files.commit_entry_imports(
                self.vault,
                entry,
                expected_entry_updated_at=(previous.updated_at if previous is not None else None),
            )
            # 大媒体落盘会显著撑大追加写文件，提交后按媒体阈值机会式回收死空间。
            QTimer.singleShot(0, self._maybe_compact_large_media)
            return committed
        if previous is None:
            self.vault.add(entry)
        else:
            self.vault.update(entry)
        return entry

    def _cache_dialog_leak_result(self, dialog: EntryDialog) -> None:
        if not leak.check_enabled():
            return
        count = dialog.checked_pwned_count
        if count is None:
            return
        self.vault.apply_leak_checks([leak.make_check_result(dialog.entry, pwned_count=count)])

    def delete_entry(self) -> None:
        item = self.list.currentItem()
        if not isinstance(item, EntryListItem):
            return
        if item.entry.secret_type in _GUARDED_SECRET_TYPES:
            label = SecretType.LABELS[item.entry.secret_type]
            if not _confirm_master_password(self.vault, f"删除{label}", f"删除{label}信息需要验证当前主密码。", self):
                return
        if widgets.confirm(self, "确认删除", f"确定将「{item.entry.title}」移入回收站吗？", kind="error"):
            _log.info("用户删除条目：「%s」", _log_mod.redact(item.entry.title))
            self.vault.delete(item.entry.id)
            self._update_recycle_btn()
            self.reload()
            self._refresh_open_feature_pages()
            self._flash("已移入回收站")

    # ---------- 批量操作 ----------
    def _batch_delete(self, items: list[EntryListItem]) -> None:
        if not items:
            return
        names = "、".join(i.entry.title for i in items[:5])
        if len(items) > 5:
            names += f"…等 {len(items)} 条"
        if not widgets.confirm(self, "批量删除", f"确定将以下 {len(items)} 个条目移入回收站吗？\n{names}", kind="error"):
            return
        for i in items:
            self.vault.delete(i.entry.id)
        self._update_recycle_btn()
        self.reload()
        self._refresh_open_feature_pages()
        self._flash(f"已批量删除 {len(items)} 个条目")

    def _batch_add_tag(self, entries: list[Entry]) -> None:
        if not entries:
            return
        dlg = BatchTagInputDialog(
            i18n.tr("批量添加标签"), i18n.tr("输入或选择多个标签，追加到所选条目的现有标签。"),
            parent=self, category=entries[0].secret_type, mode="add",
        )
        if dlg.exec() != QDialog.Accepted:
            return
        tags = dlg.tags
        now = time.time()
        affected = 0
        for e in entries:
            meta = self.vault._entry_meta.get(e.id)
            if meta is None:
                continue
            existing = meta.get("tags", [])
            additions = [tag for tag in tags if tag not in existing]
            if not additions:
                continue
            existing = existing.copy()
            existing.extend(additions)
            meta["tags"] = existing
            meta["updated_at"] = now
            affected += 1
        if affected:
            self.vault.save()
        self.reload()
        label = "、".join(f"「{tag}」" for tag in tags)
        self._flash(f"已为 {affected} 个条目添加标签{label}" if affected else f"所选条目已全部包含标签{label}")

    def _batch_move_tag(self, entries: list[Entry]) -> None:
        if not entries:
            return
        dlg = BatchTagInputDialog(
            "批量移入标签", "输入目标标签名称，所选条目的标签将被替换为此标签。",
            parent=self, category=entries[0].secret_type, mode="move",
        )
        if dlg.exec() != QDialog.Accepted:
            return
        tag = dlg.tag
        now = time.time()
        affected = 0
        for e in entries:
            meta = self.vault._entry_meta.get(e.id)
            if meta is None:
                continue
            existing = meta.get("tags", [])
            if existing == [tag]:
                continue
            meta["tags"] = [tag]
            meta["updated_at"] = now
            affected += 1
        if affected:
            self.vault.save()
        self.reload()
        self._flash(f"已将 {affected} 个条目移入标签「{tag}」")

    def _select_by_id(self, entry_id: str) -> bool:
        """在*当前列表*中选中条目。返回是否命中：没命中说明它被筛选挡在外面。"""
        for i in range(self.list.count()):
            if self.list.item(i).entry.id == entry_id:
                self.list.setCurrentRow(i)
                return True
        return False

    def _reveal_entry(self, entry) -> bool:
        """解除会把目标条目挡在列表外的筛选（搜索词 / 标签 / 类目 / 安全筛选）。

        安全中心等页面按条目自身类型列出结果，与左侧当前类目无关，
        因此跨类目点击时必须先让目标条目出现在列表里，否则选中会静默失败。
        """
        changed = False
        if self.search.text():
            self.search.blockSignals(True)
            self.search.clear()
            self.search.blockSignals(False)
            changed = True
        if self._active_tag is not None:
            self._active_tag = None
            changed = True
        # 跨类目视图下（安全中心）若目标条目类型与当前不同，切换到它的类目；
        # 同时清掉密码筛选与跨类目标志，回到单类目视图。
        if self._active_type is not None and self._active_type != entry.secret_type:
            self._active_type = entry.secret_type
            self._list_add_btn.setVisible(self._active_type != SecretType.PASSKEY)
            changed = True
        if self._password_filter is not None:
            self._password_filter = None
            changed = True
        if getattr(self, "_cross_type_filter", False):
            self._cross_type_filter = False
            changed = True
        if changed:
            self._search_timer.stop()
            self._select_timer.stop()
            self._update_chip_styles()
            self.reload(data_changed=False)
        return changed

    # ---------- 整理 ----------
    def _open_devices_history(self) -> None:
        page = self._open_workspace_page(
            "devices-history", "设备与历史",
            lambda: DevicesHistoryPage(self.vault, self),
        )
        if not page.property("historyRestoreWired"):
            page.restoreRequested.connect(self._adopt_history_vault)
            page.setProperty("historyRestoreWired", True)

    def _adopt_history_vault(self) -> None:
        refreshed = self.vault.reopen()
        self._adopt_cloud_vault(refreshed)
        media_files.ensure_vault_context(self.vault)
        self._update_recycle_btn()
        self._refresh_open_feature_pages()

    def dedup_entries(self) -> None:
        scan = self.vault.scan_duplicates()
        if scan["exact"] + scan["pw_conflict"] == 0:
            widgets.message(self, "无重复条目", "当前库中没有检测到重复条目。", kind="info")
            return

        groups = self.vault.duplicate_groups()
        page = self._open_workspace_page(
            "dedup",
            "重复条目对比",
            lambda: DedupPage(groups, self),
        )
        page.mergeRequested.connect(self._apply_dedup_results, Qt.ConnectionType.UniqueConnection)
        page.reset(groups)

    def _apply_dedup_results(self, results: dict) -> None:
        merged_count = len(results)
        remove_ids: set[str] = set()
        replacements: list[Entry] = []

        for _idx, (group, chosen) in results.items():
            merged = self.vault.merge_entries_manual(
                group,
                resolved_title=chosen.get("title", ""),
                resolved_username=chosen.get("username", ""),
                resolved_password=chosen.get("password", ""),
            )
            for e in group:
                remove_ids.add(e.id)
            replacements.append(merged)

        self.vault._entry_order = [eid for eid in self.vault._entry_order if eid not in remove_ids] + [r.id for r in replacements]
        for e in replacements:
            self.vault._entry_meta[e.id] = _make_entry_meta(e)
            self.vault._payloads[e.id] = self.vault._encrypt_payload(e.id, _make_entry_payload(e))
        self.vault.save()
        self.reload()
        self._flash(f"合并去重完成：合并 {merged_count} 组")
        self.editor_workspace.request_close("dedup", "done")

    def merge_same_service_entries(self) -> None:
        groups = self.vault.scan_same_service()
        if not groups:
            widgets.message(self, "无同服务条目", "当前没有检测到多条指向同一服务的条目。", kind="info")
            return

        page = self._open_workspace_page(
            "same_service",
            "相同服务处理",
            lambda: SameServicePage(groups, self),
        )
        page.mergeRequested.connect(self._apply_same_service_result, Qt.ConnectionType.UniqueConnection)
        page.reset(groups)

    def _apply_same_service_result(self, entries: list[Entry], chosen: dict) -> None:
        merged = self.vault.merge_entries_manual(
            entries,
            resolved_title=chosen.get("title", ""),
            resolved_username=chosen.get("username", ""),
            resolved_password=chosen.get("password", ""),
        )
        remove_ids = {e.id for e in entries}
        self.vault._entry_order = [eid for eid in self.vault._entry_order if eid not in remove_ids] + [merged.id]
        self.vault._entry_meta[merged.id] = _make_entry_meta(merged)
        self.vault._payloads[merged.id] = self.vault._encrypt_payload(merged.id, _make_entry_payload(merged))
        self.vault.save()
        self.reload()
        self._flash(f"已合并 {len(entries)} 条为「{merged.title or '未命名条目'}」")
        self.editor_workspace.request_close("same_service", "done")

    def _update_recycle_btn(self) -> None:
        count = len(self.vault.trash)
        label = f"回收站 {'99+' if count > 99 else count}"
        self._recycle_btn.setText("" if getattr(self, "_compact_top_nav", False) else label)
        self._recycle_btn.setToolTip(label)
        self._recycle_btn.setAccessibleName(label)

    def open_recycle_bin(self) -> None:
        page = self._open_workspace_page(
            "recycle",
            "回收站",
            lambda: RecycleBinPage(self.vault, self._compact_after_trash_purge, parent=self),
        )
        page.refresh(self.vault)

    # ---------- 导入 / 导出 ----------
    def _flash(self, text: str) -> None:
        self._notice_bar.show_message(i18n.tr_dynamic(text))

    def _merge(self, entries: list[Entry], source: str) -> dict:
        """把外部条目合并进库，冲突（同账号但内容不同）弹窗交用户处理。"""
        state = {"all": None}

        def resolver(existing: Entry, incoming: Entry) -> str:
            if state["all"] is not None:
                return state["all"]
            dlg = ConflictDialog(existing, incoming, self)
            if not dlg.exec():
                return "cancel"
            if dlg.apply_all:
                state["all"] = dlg.action
            return dlg.action

        stats = self.vault.merge(entries, resolver)
        self.reload()
        return stats

    @staticmethod
    def _format_import_summary(added: int, updated: int, skipped: int, conflicts: int, identical: int) -> str:
        if added == 0 and updated == 0 and skipped == 0 and conflicts == 0 and identical > 0:
            return "没有新变化"
        parts = [f"新增 {added}", f"更新 {updated}", f"跳过 {skipped}"]
        if conflicts:
            parts.append(f"冲突 {conflicts}")
        return "导入完成：" + "，".join(parts)

    @classmethod
    def _summary(cls, source: str, stats: dict) -> str:
        msg = cls._format_import_summary(
            stats["added"],
            stats["overwritten"],
            stats["skipped"],
            stats["kept_both"],
            stats["identical"],
        )
        if stats["cancelled"]:
            msg += "\n（已取消，部分条目未处理）"
        return msg

    def _apply_import(self, result: importers.ImportResult) -> None:
        if not result.ok:
            widgets.message(self, "导入失败", result.error, kind="error")
            return
        stats = self._merge(result.entries, result.source)
        msg = self._summary(result.source, stats)
        if result.warning:
            msg += f"\n\n注意：{result.warning}"
        if result.source.endswith(("CSV", "JSON")):
            msg += "\n\n导入文件含明文密码，请确认导入结果后安全删除原文件。"
        widgets.message(self, "导入结果", msg, kind="success")

    # ---------- 导出范围 ----------
    def _select_export_entries(self, include_trash: bool = True) -> tuple[list[Entry], str | None] | None:
        """弹出标签筛选对话框，返回 (待导出条目, 所选标签)；用户取消则返回 None。

        没有标签可选时直接导出全部，不打扰用户。
        加密备份包含回收站条目；CSV 等迁移格式只导出活跃条目。
        """
        all_entries = list(self.vault.entries)
        if include_trash:
            all_entries += list(self.vault.trash)
        tags = sorted({t for e in all_entries for t in e.tags})
        if not tags:
            return all_entries, None
        dlg = TagFilterDialog(tags, self)
        if dlg.exec() != QDialog.Accepted:
            return None
        tag = dlg.tag
        if tag is None:
            return all_entries, None
        return [e for e in all_entries if tag in e.tags], tag

    # ---------- 加密备份 ----------
    def export_backup(self) -> None:
        if not self.vault.entries and not self.vault.trash:
            widgets.message(self, "提示", "没有可导出的条目", kind="info")
            return
        if not _confirm_master_password(self.vault, "导出加密备份", "导出加密备份需要验证当前主密码。", self, session_required=True):
            return
        entries = list(self.vault.entries) + list(self.vault.trash)
        dlg = BackupPasswordDialog("export", self)
        if not dlg.exec():
            return
        if backup.contains_syncable_passkeys(entries) and not backup.is_strong_passphrase(dlg.password):
            widgets.message(
                self,
                "提示",
                "备份包含可同步 Passkey，口令至少需要 14 位，并包含大小写字母、数字、符号中的至少三类。",
                kind="warn",
            )
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n.tr("导出加密备份"),
            f"vault-backup{backup.SUFFIX}",
            i18n.tr_dynamic(f"加密备份 (*{backup.SUFFIX})"),
            options=_FILE_OPTS,
        )
        if not path:
            return
        backup.export_encrypted(
            entries,
            path,
            dlg.password,
            device_id=self.vault.device_id,
            purge_tombstones=self.vault._purge_tombstones,
            autofill_exclusions=self.vault.autofill_exclusions,
        )
        _log.info("加密备份导出：%d 条 → %s", len(entries), path)
        self._flash(f"已导出加密备份（{len(entries)} 条）")
        widgets.message(
            self,
            "导出完成",
            f"已加密导出全部 {len(entries)} 条到：\n{path}",
            kind="success",
        )

    # ---------- 导出 .pmv ----------
    def export_pmv(self) -> None:
        if not self.vault.entries and not self.vault.trash:
            widgets.message(self, "提示", "没有可导出的条目", kind="info")
            return
        if not _confirm_master_password(
            self.vault,
            i18n.tr("导出 .pmv 库"),
            "导出原始 .pmv 库需要验证当前主密码。",
            self,
            session_required=True,
        ):
            return
        vault_user = config.get_current_user() or self.vault.path.stem
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n.tr("导出 .pmv 库"),
            f"{vault_user}.pmv",
            i18n.tr("密码库 (*.pmv)"),
            options=_FILE_OPTS,
        )
        if not path:
            return
        self.vault.save()
        try:
            shutil.copy2(self.vault.path, path)
        except OSError as exc:
            widgets.message(self, "导出失败", f"无法导出：{exc}", kind="error")
            return
        _log.info("导出 .pmv 库：%s → %s", self.vault.path, path)
        self._flash("已导出 .pmv 库")

    @classmethod
    def _sync_summary(cls, source: str, stats: dict) -> str:
        """Sync v2（LWW）合并统计文案。"""
        return cls._format_import_summary(
            stats.get("added", 0),
            stats.get("remote_wins", 0),
            stats.get("local_wins", 0),
            stats.get("kept_both", 0),
            stats.get("identical", 0),
        )

    def _cloud_sync_vault_id(self) -> str:
        return self.vault.device_id or str(self.vault.path.resolve())

    def _cloud_sync_pref_key(self) -> str:
        return cloud_sync_prefs.master_key(self._cloud_sync_vault_id())

    def _cloud_sync_enabled(self) -> bool:
        return cloud_sync_prefs.master_enabled(self._cloud_sync_vault_id())

    def cloud_sync_enabled(self) -> bool:
        """云端同步总开关（设置页读取用）。"""
        return self._cloud_sync_enabled()

    def set_cloud_sync_enabled(self, enabled: bool) -> None:
        """开启/关闭云端同步总开关（入口常驻，开关只影响后台行为与页面内容）。"""
        cloud_sync_prefs.set_master_enabled(self._cloud_sync_vault_id(), enabled)

    def _auto_sync_pref_key(self, name: str) -> str:
        return cloud_sync_prefs.key(self._cloud_sync_vault_id(), name)

    def _auto_sync_target_pref_key(self, name: str, target: str | None = None) -> str:
        if target is None:
            target = str(config.get(self._auto_sync_pref_key("target"), "") or "")
        return cloud_sync_prefs.key(self._cloud_sync_vault_id(), f"{target}_{name}")

    def _auto_sync_tick(self) -> None:
        if self._locked or not self._cloud_sync_enabled():
            return
        controller = getattr(self, "_cloud_controller", None)
        if (controller is not None and controller.any_busy) or self._cloud_threads_running():
            return
        vault_id = self._cloud_sync_vault_id()
        for target in ("drive", "webdav"):
            if self._auto_sync_workers:
                # Every target writes the same local PMVE file. Start at most one
                # reconciliation per scheduler pass and pick up the next when it
                # becomes due again.
                break
            if target in self._auto_sync_workers:
                continue
            tkey = lambda n: self._auto_sync_target_pref_key(n, target)
            if not bool(config.get(tkey("enabled"), False)):
                continue
            interval = int(config.get(tkey("interval"), 60) or 60)
            interval = interval if interval in _AUTO_SYNC_INTERVALS else 60
            last_success = float(config.get(tkey("last_success"), 0.0) or 0.0)
            enabled_at = float(config.get(tkey("enabled_at"), 0.0) or 0.0)
            if not cloud_sync_prefs.is_due(enabled_at, last_success, interval, time.time()):
                continue
            if target == "drive":
                payload = cloud.load_cloud_drive(vault_id)
            else:
                root_key = bytearray(self.vault.root_key_for_device_unlock())
                try:
                    payload = cloud.load_webdav(
                        vault_id,
                        vault_uuid=self.vault.pmve_identity.vault_id,
                        root_key=bytes(root_key),
                    )
                finally:
                    root_key[:] = bytes(len(root_key))
            if payload is None:
                config.set(tkey("enabled"), False)
                config.set(tkey("status"), "自动同步目标未关联，已暂停")
                continue
            secret = self.vault._password.clone()
            worker = _AutoCloudSyncWorker(self.vault.path, secret, target, payload, self)
            self._auto_sync_workers[target] = worker
            if controller is not None:
                controller.stateChanged.emit()
            config.set(tkey("last_attempt"), time.time())
            config.set(tkey("status"), "正在自动同步")
            worker.completed.connect(lambda result, t=target: self._auto_sync_completed(result, t))
            worker.failed.connect(lambda msg, t=target: self._auto_sync_failed(msg, t))
            worker.finished.connect(lambda t=target: self._set_auto_lock_blocker(f"auto-sync:{t}", False))
            worker.finished.connect(worker.deleteLater)
            self._set_auto_lock_blocker(f"auto-sync:{target}", True)
            worker.start()

    def _auto_sync_completed(self, result: auto_cloud_sync.AutoSyncResult, target: str) -> None:
        self._auto_sync_workers.pop(target, None)
        controller = getattr(self, "_cloud_controller", None)
        if controller is not None:
            controller.acknowledge_remote_update(target, result.stats.get("remote_update_version", ""),
                                                 result.stats.get("remote_update_consumed_version", ""))
            controller.stateChanged.emit()
        cloud_sync_prefs.success(
            self._cloud_sync_vault_id(),
            "自动同步完成" if result.uploaded or result.changed else "双方内容一致",
            target,
        )
        if result.changed:
            self._external_refresh_timer.start()

    def _auto_sync_failed(self, message: str, target: str) -> None:
        self._auto_sync_workers.pop(target, None)
        controller = getattr(self, "_cloud_controller", None)
        if controller is not None:
            controller.stateChanged.emit()
        vault_id = self._cloud_sync_vault_id()
        cloud_sync_prefs.record_failure(vault_id, target, message)
        severe = any(token in message for token in ("已删除", "不属于当前保险库", "密码", "损坏", "校验失败"))
        if severe:
            cloud_sync_prefs.failure(vault_id, f"自动同步已暂停：{message}", target)
            cloud_sync_prefs.save(vault_id, False, target, cloud_sync_prefs.load(vault_id).interval_minutes)
        else:
            failures = cloud_sync_prefs.failure(vault_id, f"本次自动同步已跳过：{message}", target)
            if failures >= 3:
                cloud_sync_prefs.save(vault_id, False, target, cloud_sync_prefs.load(vault_id).interval_minutes)

    def _remote_update_tick(self) -> None:
        from PySide6.QtCore import QObject
        from shiboken6 import isValid
        if isinstance(self, QObject) and not isValid(self):
            return
        from core import remote_update
        from .cloud_sync_controller import CloudSyncController
        if self._locked or not self._cloud_sync_enabled():
            return
        vault_id = self._cloud_sync_vault_id()
        if not any(remote_update.enabled(vault_id, target) for target in ("drive", "webdav")):
            return
        controller = getattr(self, "_cloud_controller", None)
        if controller is None:
            controller = CloudSyncController(vault=self.vault, vault_path=self.vault.path,
                                             password=self.vault._password.clone(), cloud_vault_id=vault_id, parent=self)
            self._cloud_controller = controller
            controller.vaultReplaced.connect(self._adopt_cloud_vault)
            controller.localVaultReplaced.connect(self._reopen_local_vault)
            controller.message.connect(lambda title, text, kind: self._flash(f"{title}：{text}"))
            controller.load_async()
        self._connect_remote_notifications(controller)
        controller.check_remote_updates()

    def _connect_remote_notifications(self, controller):
        if getattr(controller, "_update_notification_connected", False):
            return
        controller._update_notification_connected = True
        vault_id = self._cloud_sync_vault_id()
        controller.remoteUpdateFound.connect(lambda target: self._remote_update_notice(vault_id, target))

    def _remote_update_notice(self, vault_id, target):
        from . import tray
        label = i18n.tr("云端硬盘" if target == "drive" else "WebDAV")
        # Qt supplies no balloon identity: every click opens the same overview.
        tray.show_update_notification(self._open_remote_update_overview,
                                      i18n.tr("远端有更新"), label + "：" + i18n.tr("远端文件已变化，尚未同步到本机"))

    def _open_remote_update_overview(self):
        from PySide6.QtCore import QObject
        from shiboken6 import isValid
        if isinstance(self, QObject) and not isValid(self):
            return
        # Windows may deliver clicks from older Action Center notifications.
        # Show the active window; a locked session requires the user's normal unlock action.
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()
        if self._locked:
            return
        self._open_cloud_sync()

    def _open_cloud_sync(self) -> None:
        """云端同步：在编辑器工作区中打开单实例页面。"""
        existing = self.editor_workspace.page("cloud-sync")
        if existing is not None:
            self.editor_workspace.open_page("cloud-sync", i18n.tr("云端同步"), lambda: existing)
            return
        vault = self.vault
        cloud_vault_id = vault.device_id or str(vault.path.resolve())
        context = CloudSyncContext(
            vault=vault,
            vault_path=vault.path,
            password=None if getattr(self, "_cloud_controller", None) is not None else vault._password.clone(),
            cloud_vault_id=cloud_vault_id,
            window=self,
        )
        self._open_workspace_page(
            "cloud-sync",
            "云端同步",
            lambda: CloudSyncWorkspacePage(context, self),
        )


    def _adopt_cloud_vault(self, refreshed: Vault) -> None:
        """同步已产生新保险库对象：替换主窗口引用并刷新列表。"""
        old = self.vault
        self.vault = refreshed
        old.close()
        self.reload()

    def _reopen_local_vault(self) -> None:
        """下载覆盖已替换磁盘文件：重新打开本地保险库并刷新列表。"""
        path = self.vault.path
        old = self.vault
        with old._password.bytes() as password:
            self.vault = Vault.open_with_password_buffer(path, password)
        old.close()
        media_files.ensure_vault_context(self.vault)
        self.reload()

    def _open_local_backup(self) -> None:
        """同步下拉「本地备份」：在编辑器工作区中打开单实例页面。"""
        page = self._open_workspace_page(
            "local-backup",
            "本地备份",
            lambda: LocalBackupPage(self, self),
        )
        page.refresh(self.vault)

    # ---------- 局域网：传输站 / 连接（编辑器工作区页面） ----------

    def _lan_page_context(self) -> LanPageContext:
        return LanPageContext(
            vault=self.vault,
            copy_secret=lambda value: self._copy(value, secret=True),
            set_auto_lock_blocker=self._set_auto_lock_blocker,
            window=self,
        )

    def _open_lan_station_page(self) -> None:
        """建立传输站：打开局域网三档页并切到「建立传输站」档、启动主机端。"""
        page = self._open_lan_page()
        if not isinstance(page, LanWorkspacePage):
            return
        page.select_gear(LanWorkspacePage.HOST)
        if page.station_page.server is None:
            page.station_page.start_station()

    def _open_lan_connection_page(self, preset_op: str | None = None) -> None:
        """连接传输站：打开局域网三档页并切到对应通道档位。

        每个档位各自持有一个已按通道配置好的连接页，切档即切通道。
        """
        from core.sync_client import TRANSFER_OP

        page = self._open_lan_page()
        if isinstance(page, LanWorkspacePage):
            page.select_gear(
                LanWorkspacePage.TRANSFER if preset_op == TRANSFER_OP else LanWorkspacePage.SYNC
            )

    def _open_lan_page(self) -> QWidget:
        """打开局域网页（单实例）。已打开的页面保留用户当前所在档位。"""
        context = self._lan_page_context()
        return self._open_workspace_page(
            "lan",
            "局域网",
            lambda: LanWorkspacePage(context, LanWorkspacePage.SYNC, self),
        )

    def _sync_merge(
        self,
        entries: list[Entry],
        export_epoch: float | None,
        source: str,
        purge_tombstones: dict[str, float] | None = None,
        autofill_exclusions: dict | None = None,
    ) -> dict:
        """Sync v2 合并：按 id 做 LWW，同秒冲突自动保留双份（无需用户逐条选择）。"""
        stats = self.vault.sync_merge(
            entries,
            export_epoch,
            on_conflict=lambda l, r: sync.ConflictChoice.KEEP_BOTH,
            incoming_purge_tombstones=purge_tombstones,
            incoming_autofill_exclusions=autofill_exclusions,
        )
        self.reload()
        self._update_recycle_btn()
        return stats

    def _lineage_allows_merge(self, incoming_device_id: str, source: str) -> bool:
        """跨账户库合并护栏（SYNC_V2 §7.5）。

        谱系一致（local 与 incoming 的 deviceId 非空且相同）→ 静默合并；
        不同或任一为空（无法判断归属）→ 弹窗要求用户显式确认，取消则不合并。
        """
        local = self.vault.device_id or ""
        if sync.same_lineage(local, incoming_device_id):
            return True
        _log.warning(
            "谱系护栏触发：local=%s incoming=%s（来源：%s）",
            local[:8] or "∅",
            incoming_device_id[:8] or "∅",
            source,
        )
        return widgets.confirm(
            self,
            "跨账户合并提醒",
            f"这份{source}不像是当前账户的库（谱系标识不一致或缺失）。\n\n继续合并可能把另一个账户的凭据混入当前库。确定要仍然合并吗？",
            kind="warn",
        )

    def import_backup(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            i18n.tr("选择加密备份"),
            "",
            i18n.tr_dynamic(f"加密备份 (*{backup.SUFFIX});;所有文件 (*)"),
            options=_FILE_OPTS,
        )
        if not path:
            return
        dlg = BackupPasswordDialog("import", self)
        if not dlg.exec():
            return
        try:
            payload = backup.import_encrypted_with_meta(path, dlg.password)
        except crypto.DecryptError:
            _log.warning("加密备份导入失败：密码错误或文件损坏 %s", path)
            widgets.message(self, "导入失败", "备份密码错误或文件已损坏。", kind="error")
            return
        except ValueError as exc:
            _log.warning("加密备份导入失败：Passkey 元数据无效 %s", path)
            widgets.message(
                self,
                "导入失败",
                f"备份中的 Passkey 元数据无效：{exc}",
                kind="error",
            )
            return
        _log.info("加密备份导入：解密 %d 条，来自 %s", len(payload.entries), path)
        if not self._lineage_allows_merge(payload.device_id, "加密备份"):
            self._flash("已取消导入，本地数据未改动")
            return
        try:
            stats = self._sync_merge(
                payload.entries,
                payload.export_epoch,
                "加密备份",
                payload.purge_tombstones,
                payload.autofill_exclusions,
            )
        except ValueError as exc:
            _log.warning("Passkey 加密备份导入被拒绝：%s", exc)
            widgets.message(self, "导入失败", str(exc), kind="error")
            return
        widgets.message(self, "导入结果", self._sync_summary("加密备份", stats), kind="success")

    def import_browser(self) -> None:
        dlg = BrowserImportDialog(self)
        if dlg.exec() and dlg.result:
            self._apply_import(dlg.result)

    def import_wifi(self) -> None:
        dlg = WifiImportDialog(self)
        if dlg.exec() and dlg.result:
            self._apply_import(dlg.result)

    def import_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            i18n.tr("选择密码管理器导出文件"),
            "",
            i18n.tr("密码管理器导出 (*.csv *.json);;CSV 文件 (*.csv);;JSON 文件 (*.json)"),
            options=_FILE_OPTS,
        )
        if path:
            _log.info("密码管理器导入：%s", path)
            self._apply_import(importers.import_password_manager(path))

    # ---------- 导出压缩包 ----------
    def export_archive(self) -> None:
        if not self.vault.entries:
            widgets.message(self, "提示", "没有可导出的条目", kind="info")
            return
        if not _confirm_master_password(self.vault, "导出压缩包", "导出压缩包需要验证当前主密码。", self, always=True):
            return
        if not widgets.confirm(
            self,
            "导出为加密压缩包",
            "压缩包内含解密后的明文（CSV、JSON、图片、附件），将用 AES-256 口令加密。是否继续？",
            kind="warn",
        ):
            return
        dlg = ArchivePasswordDialog(self)
        if not dlg.exec():
            return
        vault_name = config.get_current_user() or self.vault.path.stem
        path, _ = QFileDialog.getSaveFileName(
            self,
            i18n.tr("导出压缩包"),
            archive_exporter.suggested_filename(vault_name),
            i18n.tr("压缩包 (*.zip)"),
            options=_FILE_OPTS,
        )
        if not path:
            return
        entries = [e for e in self.vault.entries if e.deleted_at is None]
        try:
            with open(path, "wb") as raw:
                stats = archive_exporter.export_archive(
                    raw,
                    vault_name,
                    dlg.password,
                    entries,
                    archive_exporter.VaultMediaSource(self.vault),
                    app_version=archive_exporter.app_version(),
                )
        except Exception as exc:
            widgets.message(self, "导出失败", f"无法导出压缩包：{exc}", kind="error")
            return
        _log.info(
            "压缩包导出：%d 条（登录 %d / 其他 %d / 媒体 %d）→ %s",
            len(entries),
            stats.login_count,
            stats.other_count,
            stats.media_count,
            path,
        )
        self._flash(f"已导出压缩包（{len(entries)} 条）")
        widgets.message(
            self,
            "导出完成",
            f"已导出 {len(entries)} 条（含 {stats.media_count} 个媒体文件）到：\n{path}",
            kind="success",
        )

    # ---------- 设置 / 主题 ----------
    def open_settings(self) -> None:
        page = self._open_workspace_page(
            "settings",
            "设置",
            lambda: SettingsPage(self, self),
        )
        page.accountDeleted.connect(self._on_settings_account_deleted, Qt.ConnectionType.UniqueConnection)

    def _on_settings_account_deleted(self) -> None:
        remaining = config.list_users()
        if not remaining:
            QApplication.instance().quit()
            return
        self._close_workspace_pages("account-switch")
        udlg = UnlockDialog()
        if udlg.exec() == QDialog.Accepted:
            self._switch_vault(udlg.vault)
            self.show()
        else:
            QApplication.instance().quit()

    def closeEvent(self, event) -> None:
        self._save_list_pane_ratio()
        # “切到后台时最小化到托盘”：点击关闭按钮不退出程序，而是隐藏到系统托盘
        # 继续运行，云端同步、传输站等后台任务不受影响；关闭该选项则直接退出。
        if config.get("background_hide", config.DEFAULT_BACKGROUND_HIDE):
            event.ignore()
            self._background_hide()
            return
        self._close_workspace_pages("exit")
        if self._cloud_threads_running():
            event.ignore()
            self._quit_app()
            return
        self._unregister_native_autofill_hotkey()
        self._unregister_session_notifications()
        super().closeEvent(event)

    # ---------- 系统托盘 ----------
    def _setup_tray(self) -> None:
        """复用应用级托盘（登录阶段即可能已创建）；托盘不可用时静默降级。"""
        if os.name != "nt":
            return
        try:
            from . import tray as app_tray

            shared = app_tray.setup_tray(
                self._show_from_tray,
                extra_actions=[
                    (i18n.tr("立即锁定"), self.lock_now),
                    (i18n.tr("清空剪贴板"), self._clear_clipboard_now),
                    (i18n.tr("建立传输站"), self._open_lan_station_page),
                ],
            )
            if shared is not None:
                self._tray = shared
                self._tray_menu = app_tray.context_menu()
                return
            self._tray = None
            self._tray_menu = None
        except Exception:
            self._tray = None
            self._tray_menu = None

    def _clear_clipboard_now(self) -> None:
        """托盘菜单：立即清空系统剪贴板（文本/图片等），防止敏感内容残留。"""
        try:
            QGuiApplication.clipboard().clear()
        except Exception:
            pass

    def _on_tray_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self._show_from_tray()

    def _show_from_tray(self) -> None:
        """从托盘恢复主窗口；退托盘时已自动锁定则先完成重新解锁。"""
        if self._locked:
            self._relock_prompt(None)
            return
        if self.isMinimized():
            self.showNormal()
        else:
            self.show()
        self.raise_()
        self.activateWindow()

    def _background_hide(self) -> None:
        """隐藏到托盘并自动锁定；托盘不可用时退回任务栏最小化，保证窗口可恢复。"""
        tray = getattr(self, "_tray", None)
        if tray is not None and tray.isVisible():
            self._enter_locked_state(None)
        else:
            self.showMinimized()

    def _quit_app(self) -> None:
        """托盘菜单退出：注销热键后结束进程，不经过关闭按钮的后台隐藏逻辑。"""
        self._save_list_pane_ratio()
        self._unregister_native_autofill_hotkey()
        self._close_workspace_pages("exit")
        if self._cloud_threads_running():
            self._flash("正在结束后台同步，完成后自动退出")
            QTimer.singleShot(100, self._quit_app)
            return
        QApplication.instance().quit()

    def _cloud_threads_running(self):
        from .cloud_sync_controller import CloudSyncController
        return any(controller._workers for controller in self.findChildren(CloudSyncController))

    def apply_theme(self, mode: str, *, animate: bool = True) -> None:
        old_mode = "dark" if theme.active() is theme.DARK else "light"
        new_mode = theme.resolve_mode(mode)
        previous = getattr(self, "_theme_reveal_overlay", None)
        if previous is not None:
            previous.finish()
        old_frame = None
        origin = None
        if animate and self.isVisible() and old_mode != new_mode:
            logo = self.title_bar.logo
            if logo is not None and logo.isVisible():
                origin = logo.mapTo(self, logo.rect().center())
                old_frame = self.grab()
        QApplication.instance().setStyleSheet(theme.stylesheet(mode))
        # 列表项使用自定义 widget，主题切换后刷新徽标与尺寸。
        lst = getattr(self, "list", None)
        if lst is not None:
            for i in range(lst.count()):
                item = lst.item(i)
                if isinstance(item, EntryListItem):
                    item.refresh()
        if old_frame is not None and origin is not None:
            self._theme_reveal_overlay = ThemeRevealOverlay(self, old_frame, origin)
        self._flash("已切换主题")

    def _on_system_theme_changed(self, _scheme) -> None:
        """系统主题切换时，若当前为「跟随系统」则实时刷新界面配色。"""
        mode = config.theme_mode()
        if mode == "auto":
            self.apply_theme("auto", animate=False)
