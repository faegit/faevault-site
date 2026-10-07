"""各类对话框，统一使用无边框圆角的 ShadowDialog 基类。"""

from __future__ import annotations

import atexit
import copy
import datetime
import hashlib
import math
import os
import re
import shutil
import secrets
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from core.pinyin import pinyin_sort_key

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPointF,
    QPropertyAnimation,
    QRect,
    QRectF,
    QRegularExpression,
    QSize,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QImage,
    QImageIOHandler,
    QImageReader,
    QPainter,
    QPalette,
    QPixmap,
    QRegularExpressionValidator,
)
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSlider,
QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionButton,
    QStylePainter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import (
    biometric,
    browser_install,
    config,
    crypto,
    importers,
    leak,
    local_backup,
    media_files,
    master_password_policy,
    otp,
    recovery_key,
    updates,
    utils,
    window_tracker,
)
from core import autofill_sources
from core.autofill_resolver import source_values
from core import log as _log_mod
from core import modules as entry_modules
from core.models import Entry, SecretType
from core.passkey_provider_status import PasskeyProviderStatus
from core.storage import Vault
from core import pmv_kdf_policy
from core.pmv_kdf_policy import PmvKdfPolicy, PmvKdfProfile
from core.pmv_key_schedule import derive_password_kek

from . import i18n, screen_capture, theme, widgets
from .image_preview import load_image_thumbnail, load_thumbnail_into
from . import large_image_decode
from .module_editor import ModuleEditor
from .document_scanner import DocumentScannerDialog

_log = _log_mod.get("dialogs")
_hello_probe_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault-hello-probe")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_PMVE_MAGIC = b"PMVS"


def _supports_recovery_unlock(vault_path: Path | str) -> bool:
    """Whether the vault format exposes the shared emergency-recovery entry point."""

    try:
        with Path(vault_path).open("rb") as stream:
            return stream.read(4) == _PMVE_MAGIC
    except OSError:
        return False


def _create_new_vault(
    path: Path,
    password: bytearray,
    recovery_secret: bytes,
):
    """Create the single supported PMVE format."""
    return Vault.create_pmve_with_password_buffer(path, password, recovery_secret)


def _master_password_policy_allows(parent, password: str, high_security_mode: bool) -> tuple[bool, str | None]:
    """Validate a prospective master password without ever sending it over the network."""
    assessment = master_password_policy.assess_master_password(password)
    bits = round(assessment.estimated_entropy_bits)
    if assessment.risk is master_password_policy.PasswordRisk.BLOCKED:
        if assessment.issue is master_password_policy.PasswordIssue.COMMON_PASSWORD:
            return False, "该主密码命中本地常见或泄露密码词典，不能使用。"
        return False, "该主密码太容易被离线猜中，不能使用。请改用随机密码或至少 5 个无关单词。"
    if assessment.risk is master_password_policy.PasswordRisk.STRONG:
        return True, None
    if high_security_mode:
        return False, f"该主密码未达到推荐强度（估计 {bits} bit），高安全模式下不能使用。"
    confirmed = widgets.confirm(
        parent,
        "确认使用偏弱主密码",
        "复制保险库文件后可离线猜测主密码，应用内冷却无法阻止这种攻击。\n\n"
        f"当前估计抗猜强度约 {bits} bit。建议返回并改用随机密码或至少 5 个无关单词。\n\n"
        "仍然使用这个主密码吗？",
        kind="warn",
    )
    return confirmed, None


class _VaultImportCopyWorker(QThread):
    """在后台复制导入库，避免网络盘或大文件阻塞 Qt 主线程。"""

    def __init__(self, source: Path, destination: Path, parent=None):
        super().__init__(parent)
        self.source = Path(source)
        self.destination = Path(destination)
        self.error: str | None = None

    def run(self) -> None:
        try:
            shutil.copy2(self.source, self.destination)
        except OSError as exc:
            self.error = str(exc)


class _LanImportWorker(QThread):
    """在后台完成局域网配对、确认等待、下载与完整性校验。"""

    completed = Signal(object, object)
    status_changed = Signal(str)

    def __init__(self, url: str, pin: str, target: Path, parent=None):
        super().__init__(parent)
        self.url = url
        self.pin = pin
        self.target = target

    def run(self) -> None:
        client = None
        try:
            from core import device_auth_wire, device_identity
            from core.sync_client import EXPORT_OP, LanSyncClient

            self.status_changed.emit("正在安全连接…")
            client = LanSyncClient(self.url, self.pin, op=EXPORT_OP)
            self.status_changed.emit("请在另一台设备上允许本次发送")
            client.authenticate_device(
                device_auth_wire.ZERO_UUID,
                device_identity.load_or_create(device_auth_wire.ZERO_UUID),
            )
            self.status_changed.emit("正在接收并检查账户数据…")
            client.download_vault(self.target)
            self.completed.emit(self.target, None)
        except Exception as error:
            self.target.unlink(missing_ok=True)
            self.completed.emit(None, error)
        finally:
            if client is not None:
                try:
                    client.cancel()
                except Exception:
                    pass


class _UpdateCheckWorker(QThread):
    completed = Signal(object, object)

    def run(self) -> None:
        try:
            self.completed.emit(updates.check_latest(), None)
        except Exception as exc:
            self.completed.emit(None, str(exc))


class _WifiProfileWorker(QThread):
    """Discover saved Wi-Fi profiles without blocking dialog creation."""

    completed = Signal(object, object)

    def run(self) -> None:
        try:
            self.completed.emit(importers.available_wifi_profiles(), None)
        except Exception as exc:  # pragma: no cover - platform command boundary
            self.completed.emit([], str(exc))

# ── 输入限制辅助函数 ─────────────────────────────────────────────────────────


def _fmt_card_number(field: QLineEdit) -> None:
    """卡号自动分组：XXXX XXXX XXXX XXXX [XXX]，仅允许数字，最多19位。"""
    field.setMaxLength(23)
    _busy = [False]

    def _on(text: str) -> None:
        if _busy[0]:
            return
        digits = re.sub(r"\D", "", text)[:19]
        formatted = " ".join(digits[i : i + 4] for i in range(0, len(digits), 4))
        if formatted == text:
            return
        _busy[0] = True
        cur = field.cursorPosition()
        n_before = sum(1 for c in text[:cur] if c.isdigit())
        field.setText(formatted)
        new_cur, seen = len(formatted), 0
        for i, c in enumerate(formatted):
            if seen == n_before:
                new_cur = i
                break
            if c.isdigit():
                seen += 1
        field.setCursorPosition(new_cur)
        _busy[0] = False

    field.textChanged.connect(_on)
    _on(field.text())  # 立即格式化构造时已设置的初始值（如编辑已有条目）


def _fmt_expiry(field: QLineEdit) -> None:
    """有效期自动补斜杠：MM/YY。"""
    field.setMaxLength(5)
    _busy = [False]

    def _on(text: str) -> None:
        if _busy[0]:
            return
        digits = re.sub(r"\D", "", text)[:4]
        formatted = (digits[:2] + "/" + digits[2:]) if len(digits) > 2 else digits
        if formatted == text:
            return
        _busy[0] = True
        field.setText(formatted)
        field.setCursorPosition(len(formatted))
        _busy[0] = False

    field.textChanged.connect(_on)


def _fmt_date(field: QLineEdit, *, allow_free: bool = False) -> None:
    """日期自动补横线：YYYY-MM-DD。allow_free=True 时非数字开头不做处理（如"长期"）。"""
    field.setMaxLength(10)
    _busy = [False]

    def _on(_text: str) -> None:
        if _busy[0]:
            return
        text = field.text()
        if allow_free and text and not text[0].isdigit():
            return
        digits = re.sub(r"\D", "", text)[:8]
        if len(digits) < 8:
            return  # 未输完 8 位数字，不格式化
        formatted = digits[:4] + "-" + digits[4:6] + "-" + digits[6:]
        if formatted == text:
            return
        _busy[0] = True
        field.setText(formatted)
        field.setCursorPosition(len(formatted))
        _busy[0] = False

    field.textChanged.connect(_on)


def _restrict_digits(field: QLineEdit) -> None:
    """只允许输入数字。"""
    field.setValidator(QRegularExpressionValidator(QRegularExpression(r"\d*")))


def _restrict_url(field: QLineEdit) -> None:
    """禁止输入空白字符。"""
    field.setValidator(QRegularExpressionValidator(QRegularExpression(r"\S*")))


def _confirm_bar(
    dialog: QDialog,
    *,
    cancel_text: str = "取消",
    ok_text: str = "确定",
    ok_object: str = "Primary",
    ok_slot=None,
    cancel_slot=None,
    align: str = "left",
    auto_default: bool = True,
    show_cancel: bool = True,
) -> QHBoxLayout:
    """构造"取消 + 主操作"按钮行。

    ``align="right"`` 在按钮前插入伸缩占位使其靠右对齐，``"left"``（默认）则不插入。
    ``show_cancel=False`` 时只保留主操作按钮（用于不可取消的流程）。
    """
    bar = QHBoxLayout()
    if align == "right":
        bar.addStretch()
    if not show_cancel:
        ok = QPushButton(ok_text)
        ok.setObjectName(ok_object)
        if auto_default:
            ok.setAutoDefault(False)
        ok.clicked.connect(ok_slot or dialog.accept)
        bar.addStretch()
        bar.addWidget(ok)
        return bar
    cancel = QPushButton(cancel_text)
    ok = QPushButton(ok_text)
    ok.setObjectName(ok_object)
    if auto_default:
        cancel.setAutoDefault(False)
        ok.setAutoDefault(False)
    cancel.clicked.connect(cancel_slot or dialog.reject)
    ok.clicked.connect(ok_slot or dialog.accept)
    bar.addWidget(cancel)
    bar.addWidget(ok)
    return bar


class _NoScrollSpinBox(QSpinBox):
    """未聚焦时忽略滚轮：悬停滚动不会误改数值，事件交还给滚动区滚动页面；
    点击或 Tab 聚焦后才允许滚轮调整。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFocusPolicy(Qt.StrongFocus)

    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class _NoScrollComboBox(QComboBox):
    """与 :class:`_NoScrollSpinBox` 同理：未聚焦时忽略滚轮。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFocusPolicy(Qt.StrongFocus)

    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class _NoScrollSlider(QSlider):
    """滑条只允许拖动调整：滚轮一律不改变数值，事件交还给滚动区滚动页面。"""

    def wheelEvent(self, event):
        event.ignore()


def _spinbox_row(
    layout: QVBoxLayout,
    label: str,
    *,
    minimum: int,
    maximum: int,
    value: int,
    suffix: str = "",
    step: int | None = None,
) -> QSpinBox:
    """添加一行"标签 + 数值微调框"，返回该 QSpinBox 供调用方进一步设置。"""
    row = QHBoxLayout()
    row.addWidget(QLabel(label))
    row.addStretch()
    box = _NoScrollSpinBox()
    box.setRange(minimum, maximum)
    if step is not None:
        box.setSingleStep(step)
    if suffix:
        box.setSuffix(suffix)
    box.setValue(value)
    row.addWidget(box)
    layout.addLayout(row)
    return box


# 主密码输入失败锁定策略：阈值与冷却时长由 config.PASSWORD_* 统一定义，
# 此处只保留用于「还可尝试 N 次」文案的阈值副本。
MAX_ATTEMPTS = 5

class RecoveryKeyConfirmDialog(widgets.ShadowDialog):
    """Generate a mandatory recovery key and commit it only after three-group confirmation."""

    def __init__(self, parent=None, *, migration: bool = False, key_revision: int = 0, mandatory: bool = False):
        super().__init__(f"保险库紧急恢复密钥 v{key_revision}", parent, width=520)
        self._mandatory = mandatory
        if mandatory:
            self.set_close_enabled(False)
        self.secret, self.recovery_key = recovery_key.generate()
        # 该恢复密钥生效后所属的保险库密钥版本（新建为 1，重新生成为当前版本 +1）。
        self.key_revision = key_revision
        groups = self.recovery_key.removeprefix("PMRK1-").split("-")
        self._checks = sorted(secrets.SystemRandom().sample(range(len(groups)), 3))
        self._groups = groups

        self._content_scroll = QScrollArea()
        self._content_scroll.setFrameShape(QFrame.NoFrame)
        self._content_scroll.setWidgetResizable(True)
        self._content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._content_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._content_scroll.setMinimumHeight(240)
        self._content_scroll.setMaximumHeight(240)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        self._content_scroll.setWidget(content)
        self.body.addWidget(self._content_scroll)

        title = widgets.icon_text("紧急恢复密钥", "recovery", object_name="DetailTitle", icon_size=24)
        note = QLabel(
            ("检测到旧版保险库。升级后旧版客户端将无法打开，请先更新另一端。\n\n" if migration else "")
            + "这是忘记主密码后的最终恢复方式。任何获得此密钥的人都可以解锁整个保险库；应用不会再次显示它。"
        )
        note.setObjectName("FieldError")
        note.setWordWrap(True)
        content_layout.addWidget(title)
        content_layout.addWidget(note)

        key_card = QFrame()
        key_card.setObjectName("Card")
        key_layout = QVBoxLayout(key_card)
        key_layout.setContentsMargins(14, 12, 14, 12)
        key_layout.setSpacing(8)
        step_one = QLabel("第 1 步 · 离线保存恢复密钥")
        step_one.setObjectName("DetailTitle")
        key_layout.addWidget(step_one)

        key_view = QPlainTextEdit(self.recovery_key)
        key_view.setReadOnly(True)
        key_view.setAccessibleName("恢复密钥，仅显示一次")
        key_view.setMaximumHeight(76)
        key_view.setStyleSheet("QPlainTextEdit { color: #111111; background: #ffffff; selection-color: #ffffff; selection-background-color: #2563eb; }")
        key_layout.addWidget(key_view)

        self._key_hidden_label = QLabel("密钥内容已隐藏，请从你保存的位置参考。")
        self._key_hidden_label.setObjectName("Empty")
        self._key_hidden_label.setWordWrap(True)
        self._key_hidden_label.hide()
        key_layout.addWidget(self._key_hidden_label)

        actions = QHBoxLayout()
        copy_btn = widgets.icon_only_button("copy", "复制密钥")
        save_btn = QPushButton("保存恢复单")
        actions.addWidget(copy_btn)
        actions.addWidget(save_btn)
        actions.addStretch()
        key_layout.addLayout(actions)

        self._save_status = QLabel("请先复制密钥或将恢复单保存到安全位置，之后才能进行核对。")
        self._save_status.setObjectName("Empty")
        self._save_status.setWordWrap(True)
        key_layout.addWidget(self._save_status)
        content_layout.addWidget(key_card)

        self._verification_panel = QFrame()
        self._verification_panel.setObjectName("Card")
        verification_layout = QVBoxLayout(self._verification_panel)
        verification_layout.setContentsMargins(14, 12, 14, 12)
        verification_layout.setSpacing(8)
        step_two = QLabel("第 2 步 · 核对已保存内容")
        step_two.setObjectName("DetailTitle")
        verification_layout.addWidget(step_two)

        prompt = QLabel(
            "第 1 组 PMRK1 是恢复密钥格式标识，不参与校验。以下序号按上方完整密钥从左到右计算，"
            "请从每个下拉列表的 5 个候选中选出对应分组。"
        )
        prompt.setWordWrap(True)
        prompt.setObjectName("Empty")
        verification_layout.addWidget(prompt)
        self._inputs: list[QComboBox] = []
        row = QHBoxLayout()
        row.setSpacing(8)
        rng = secrets.SystemRandom()
        for index in self._checks:
            field = widgets.selection_combo()
            field.setAccessibleName(f"恢复密钥第 {index + 2} 组")
            field.addItem(f"请选择第 {index + 2} 组", "")
            alternatives = rng.sample([i for i in range(len(groups)) if i != index], 4)
            candidates = [groups[i] for i in alternatives] + [groups[index]]
            rng.shuffle(candidates)
            for candidate in candidates:
                field.addItem(f"第 {index + 2} 组：{candidate}", candidate)
            row.addWidget(field)
            self._inputs.append(field)
        verification_layout.addLayout(row)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.hide()
        verification_layout.addWidget(self.hint)
        self._warn_field = self._inputs[0]
        verification_layout.addLayout(_confirm_bar(self, ok_text="完成核对并继续", show_cancel=not self._mandatory))
        self._verification_panel.hide()
        content_layout.addWidget(self._verification_panel)
        content_layout.addStretch()
        self._save_action_taken = False

        def reveal_verification(method: str) -> None:
            self._save_action_taken = True
            self._save_status.setText(f"已执行{method}。请使用刚保存的内容完成下方核对。")
            key_view.hide()
            self._key_hidden_label.show()
            self._verification_panel.show()
            QTimer.singleShot(0, self._fit_after_reveal)

        def sheet_text() -> str:
            title = (
                f"FAEVault Emergency Recovery Key v{self.key_revision}"
                if i18n.current_locale() == "en"
                else f"保险库紧急恢复密钥 v{self.key_revision}"
            )
            date_line = (
                f"Saved on: {datetime.date.today().isoformat()}"
                if i18n.current_locale() == "en"
                else f"保存日期：{datetime.date.today().isoformat()}"
            )
            warning = (
                "Anyone with this key can unlock the vault. Keep it offline."
                if i18n.current_locale() == "en"
                else "任何获得此密钥的人都可以解锁保险库，请离线保管。"
            )
            return f"{title}\n{date_line}\n\n{self.recovery_key}\n\n{warning}\n"

        def copy_key() -> None:
            text = sheet_text()
            QApplication.clipboard().setText(text)
            QTimer.singleShot(60_000, lambda: QApplication.clipboard().clear() if QApplication.clipboard().text() == text else None)
            widgets.flash_copy_success(copy_btn)
            reveal_verification("复制密钥")

        def save_key() -> None:
            path, _ = QFileDialog.getSaveFileName(
                self, i18n.tr("保存恢复单"), "vault-recovery-key.txt", i18n.tr("文本文件 (*.txt)"),
            )
            if path:
                Path(path).write_text(sheet_text(), encoding="utf-8")
                save_btn.setText("已保存恢复单")
                reveal_verification("保存恢复单")

        copy_btn.clicked.connect(copy_key)
        save_btn.clicked.connect(save_key)

    def _fit_after_reveal(self) -> None:
        content = self._content_scroll.widget()
        if content is not None:
            if content.layout() is not None:
                content.layout().activate()
            content.adjustSize()
            content_hint = content.sizeHint()
        else:
            content_hint = self._content_scroll.sizeHint()
        screen = self.screen() or QApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        max_dialog_w = max(520, available.width() - 80) if available else 920
        max_dialog_h = max(360, available.height() - 80) if available else 760
        extra_chrome_w = max(0, self.width() - self._content_scroll.viewport().width())
        extra_chrome_h = max(0, self.height() - self._content_scroll.viewport().height())
        max_scroll_w = max(320, max_dialog_w - extra_chrome_w)
        max_scroll_h = max(360, max_dialog_h - extra_chrome_h)
        target_scroll_w = min(content_hint.width() + 8, max_scroll_w)
        target_scroll_h = min(content_hint.height() + 8, max_scroll_h)

        self._content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._content_scroll.setMinimumWidth(target_scroll_w)
        self._content_scroll.setMaximumWidth(target_scroll_w)
        self._content_scroll.setMaximumHeight(target_scroll_h)
        self._content_scroll.setMinimumHeight(target_scroll_h)
        self.setMaximumSize(max_dialog_w, max_dialog_h)
        self.adjustSize()
        self.resize(
            min(max_dialog_w, extra_chrome_w + target_scroll_w),
            min(max_dialog_h, extra_chrome_h + target_scroll_h),
        )
        self._content_scroll.ensureWidgetVisible(self._verification_panel, 0, 12)

    def accept(self) -> None:
        if not self._save_action_taken:
            self._save_status.setText("请先复制密钥或成功保存恢复单，再进行核对。")
            widgets.shake(self._save_status)
            return
        for field, index in zip(self._inputs, self._checks):
            if str(field.currentData() or "") != self._groups[index]:
                self._warn(f"第 {index + 2} 组不正确，请对照已保存的完整恢复密钥。", field)
                return
        super().accept()

    def _warn(self, message: str, field: QWidget) -> None:
        self.hint.setText(message)
        self.hint.show()
        widgets.shake(field)

    def reject(self) -> None:
        if getattr(self, "_mandatory", False):
            return
        super().reject()

    def closeEvent(self, event) -> None:
        if getattr(self, "_mandatory", False):
            event.ignore()
            return
        super().closeEvent(event)


class RecoveryKeyUnlockDialog(widgets.ShadowDialog):
    """Step 1 of the recovery flow: unlock the vault with the emergency recovery key.

    Mirrors Android: entering the recovery key only unlocks the vault; setting a new
    master password and re-saving a new recovery key are separate mandatory steps.
    """

    def __init__(self, vault_path: Path, parent=None):
        super().__init__("使用紧急恢复密钥", parent, width=500)
        self._path = Path(vault_path)
        self.vault: Vault | None = None
        self.secret: bytes | None = None
        self.body.addWidget(widgets.icon_text("恢复保险库", "recovery", object_name="DetailTitle", icon_size=24))
        note = QLabel(
            i18n.tr(
                "输入紧急恢复密钥以解锁保险库。解锁后将进入「设置新主密码」与「重新保存恢复密钥」"
                "两步流程，且不可取消。"
            )
        )
        note.setObjectName("Empty")
        note.setWordWrap(True)
        self.body.addWidget(note)
        self.key = QPlainTextEdit()
        self.key.setPlaceholderText("PMRK1-…")
        self.key.setMaximumHeight(90)
        self.body.addWidget(self.key)
        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.hide()
        self.body.addWidget(self.hint)
        self._warn_field = self.key
        self.body.addLayout(_confirm_bar(self, ok_text="解锁"))

    def accept(self) -> None:
        try:
            secret = recovery_key.decode(self.key.toPlainText())
        except recovery_key.RecoveryKeyError:
            self._warn("恢复密钥无效", self.key)
            return
        try:
            vault = Vault.open_with_recovery_key(self._path, secret)
        except Exception:
            self._warn("恢复密钥错误或保险库已损坏", self.key)
            return
        self.secret = secret
        self.vault = vault
        super().accept()

    def _warn(self, message: str, field: QWidget) -> None:
        self.hint.setText(message)
        self.hint.show()
        widgets.shake(field)


class _RecoveryResetPasswordDialog(widgets.ShadowDialog):
    """Step 2 of the recovery flow: set a new master password (non-cancellable)."""

    def __init__(self, parent=None):
        super().__init__("设置新的主密码", parent, width=500)
        self.set_close_enabled(False)
        self.body.addWidget(widgets.icon_text(i18n.tr("设置新的主密码"), "lock", object_name="DetailTitle", icon_size=24))
        note = QLabel(
            i18n.tr(
                "请先设置新的主密码，恢复密钥仍然有效；完成后下一步重新保存恢复密钥。"
                "此流程不可取消。"
            )
        )
        note.setObjectName("Empty")
        note.setWordWrap(True)
        self.body.addWidget(note)
        self.new_pw = QLineEdit()
        self.new_pw.setEchoMode(QLineEdit.Password)
        self.new_pw.setPlaceholderText("新主密码")
        self.body.addWidget(self.new_pw)
        self.new_pw2 = QLineEdit()
        self.new_pw2.setEchoMode(QLineEdit.Password)
        self.new_pw2.setPlaceholderText("再次输入新主密码")
        self.body.addWidget(self.new_pw2)
        self.high_security = QCheckBox("主密码高安全模式（拒绝未达到推荐强度的密码）")
        self.high_security.setChecked(True)
        self.body.addWidget(self.high_security)
        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.body.addWidget(self.hint)
        ok = QPushButton(i18n.tr("完成并进入保险库"))
        ok.setObjectName("Primary")
        ok.clicked.connect(self.accept)
        bar = QHBoxLayout()
        bar.addStretch()
        bar.addWidget(ok)
        self.body.addLayout(bar)

    @property
    def password(self) -> str:
        return self.new_pw.text()

    def accept(self) -> None:
        password = self.new_pw.text()
        if not password:
            self._warn(i18n.tr("主密码不能为空"), self.new_pw)
            return
        if password != self.new_pw2.text():
            self._warn(i18n.tr("两次输入的新主密码不一致"), self.new_pw2)
            return
        allowed, message = _master_password_policy_allows(self, password, self.high_security.isChecked())
        if not allowed:
            if message:
                self._warn(message, self.new_pw)
            return
        super().accept()

    def reject(self) -> None:
        return

    def closeEvent(self, event) -> None:
        event.ignore()

    def _warn(self, message: str, field: QWidget) -> None:
        self.hint.setText(message)
        self.hint.show()
        widgets.shake(field)


class _MandatoryRecoveryReissueDialog(RecoveryKeyConfirmDialog):
    """Step 3 of the recovery flow: re-save a new recovery key (non-cancellable)."""

    def __init__(self, parent=None, *, key_revision: int = 0):
        super().__init__(parent, key_revision=key_revision, mandatory=True)

    def reject(self) -> None:
        return

    def closeEvent(self, event) -> None:
        event.ignore()


class HintMixin:
    """统一的内联错误提示：设置红字提示并抖动相关输入框。

    使用方需提供 ``self.hint``（QLabel）与 ``self._warn_field``（默认抖动控件）。
    """

    def _warn(self, msg: str, field: QWidget | None = None) -> None:
        self.hint.setText(msg)
        self.hint.setVisible(True)
        focus_field = field or self._warn_field
        widgets.shake(focus_field)
        if focus_field is not None:
            focus_field.setFocus()


class _BusyButton(QPushButton):
    """主操作按钮：等待期间在文字左侧显示三个依次缩放的圆点。

    圆点保留最大绘制空间；过长文字会省略，行高不变，对话框不会因为
    等待状态的出现与消失而改变尺寸。
    """

    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self._idle_text = text
        self._busy = False
        self._spinner = widgets.WaitingDotsWidget(self)
        self._spinner.setVisible(False)
        self._check = widgets.CompletionCheckWidget(self)
        self.setMinimumWidth(self.minimumSizeHint().width())

    def start_busy(self, text: str) -> None:
        self._busy = True
        self._check.reset()
        self.setText(text)
        self._refresh_spinner_color()
        self._spinner.start()
        self._reposition()

    def stop_busy(self) -> None:
        self._busy = False
        self._spinner.stop()
        self._check.reset()
        self.setText(self._idle_text)

    def complete_busy(self) -> None:
        was_busy = self._busy
        self._busy = True
        self._spinner.stop()
        self.setText(i18n.tr("解锁成功"))
        if not was_busy:
            self._reposition()
        self._check.move(self._spinner.x() + 6, self._spinner.y())
        self._check.start(self.palette().color(QPalette.ButtonText).name())

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.EnabledChange:
            self._refresh_spinner_color()

    def _refresh_spinner_color(self) -> None:
        """跟随按钮文字色：可点击时是深色主按钮上的白色，禁用后被 QSS 调成灰色。"""
        self._spinner.set_color(self.palette().color(QPalette.ButtonText).name())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._reposition()

    def sizeHint(self):
        base = super().sizeHint()
        width = max(self.fontMetrics().horizontalAdvance(self.text()),
                    self.fontMetrics().horizontalAdvance(self._idle_text))
        return QSize(max(base.width(), width + 30 + 8 + 32), max(base.height(), 30))

    def minimumSizeHint(self):
        base = super().minimumSizeHint()
        return QSize(30 + 8 + 32 + self.fontMetrics().horizontalAdvance("…"), max(base.height(), 30))

    def _content_rects(self):
        width = self.fontMetrics().horizontalAdvance(self.text())
        available = max(0, self.width() - 32 - 30 - 8)
        text_width = min(width, available)
        left = max(16, (self.width() - 30 - 8 - text_width) // 2)
        return (QRect(left, (self.height() - 18) // 2, 30, 18),
                QRect(left + 38, 0, text_width, self.height()))

    def paintEvent(self, event):
        if not self._busy:
            super().paintEvent(event)
            return
        painter = QStylePainter(self)
        option = QStyleOptionButton()
        self.initStyleOption(option)
        option.text = ""
        painter.drawControl(QStyle.CE_PushButton, option)
        _, text_rect = self._content_rects()
        painter.setPen(self.palette().color(QPalette.ButtonText))
        text = self.fontMetrics().elidedText(self.text(), Qt.ElideRight, text_rect.width())
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, text)

    def _reposition(self) -> None:
        if not self._busy:
            return
        icon_rect, _ = self._content_rects()
        self._spinner.move(icon_rect.topLeft())
        self._check.move(icon_rect.x() + 6, icon_rect.y())


def _password_row(
    edit: QLineEdit,
    *,
    hint: str = "主密码",
    max_length: int = 128,
) -> QLineEdit:
    """密码输入框，小眼睛内嵌在输入框右侧（对齐安卓 OutlinedTextField 的 trailingIcon）。

    小眼睛作为 QLineEdit 的 trailing action 挂在输入框内部，不额外占一行，
    点击切换明文/密文。图标与既有 RevealIconBtn 一致（widgets.set_eye_icon）。
    """
    edit.setEchoMode(QLineEdit.Password)
    edit.setPlaceholderText(hint)
    edit.setMaxLength(max_length)
    edit.setTextMargins(0, 0, 30, 0)

    action = QAction(edit)
    action.setIcon(widgets.ui_icon("view"))
    action.setToolTip(i18n.tr("显示或隐藏密码"))
    action.setCheckable(True)
    edit.addAction(action, QLineEdit.TrailingPosition)

    def _toggle(checked: bool) -> None:
        # 隐藏态显示睁眼（点击展开），显示态显示闭眼（点击收起）。
        action.setIcon(widgets.ui_icon("view-off" if checked else "view"))
        edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)

    action.toggled.connect(_toggle)
    return edit


def _nested_wait(seconds: float) -> None:
    """阻塞 seconds 秒，期间维持界面重绘。

    密码框回车会直接触发 accept()，只禁用按钮挡不住重复尝试，因此退避必须靠
    嵌套事件循环维持，而不是 setEnabled。
    """
    from PySide6.QtCore import QEventLoop

    loop = QEventLoop()
    QTimer.singleShot(int(seconds * 1000), loop.quit)
    loop.exec()


class LockoutMixin:
    @staticmethod
    def _cooldown_text(sec: int) -> str:
        """冷却/退避期的统一倒计时文案（措辞对齐安卓 MasterPasswordDialog）。"""
        return i18n.tr_dynamic(f"验证已冷却，请等待 {sec} 秒后重试")

    def init_lockout(self, hint: QLabel, fields: list[QWidget], button: QPushButton) -> None:
        self._lk_hint = hint
        self._lk_fields = fields
        self._lk_button = button
        self._lk_button_text = button.text()
        self._lk_remaining = 0
        self._lk_retry_hint = None
        self._lk_timer = QTimer(self)
        self._lk_timer.setInterval(200)
        self._lk_timer.timeout.connect(self._lk_tick)
        remaining = config.password_cooling_remaining()
        if remaining > 0:
            self._begin_cooldown(math.ceil(remaining))

    @property
    def cooling_down(self) -> bool:
        return self._lk_timer.isActive() or config.password_cooling_remaining() > 0

    def _shake_fields(self) -> None:
        for field in self._lk_fields:
            widgets.shake(field)

    def _focus_first_field(self) -> None:
        if self._lk_fields:
            self._lk_fields[0].setFocus()

    def warn(self, msg: str) -> None:
        self._shake_fields()
        self._set_hint(msg)

    def _apply_delay(self, seconds: float) -> None:
        """退避使用同一持久化截止时间和定时器，不嵌套事件循环。"""
        if seconds > 0:
            self._begin_cooldown(math.ceil(seconds))

    def wrong_password(self, msg: str = "主密码不正确") -> None:
        self._shake_fields()
        new_count, delay, entered_cooldown, cooldown = config.record_password_failure()
        if entered_cooldown:
            self._enter_lockout(cooldown)
            return
        remaining = MAX_ATTEMPTS - new_count
        _log.warning("密码错误，累计失败 %d 次，剩余尝试 %d 次", new_count, max(remaining, 0))
        # 先翻译正文再套动态模板，否则英文界面下会残留中文（“主密码不正确 (…)”）。
        self._lk_retry_hint = i18n.tr_dynamic(f"{i18n.tr(msg)}（还可尝试 {remaining} 次）")
        self._set_hint(self._lk_retry_hint)
        self._apply_delay(delay)
        self._focus_first_field()

    def passed(self) -> None:
        _log.info("密码校验通过，重置失败计数与锁定状态")
        config.clear_password_lockout()

    def _enter_lockout(self, seconds: int) -> None:
        _log.warning("失败次数达到上限，进入锁定，时长 %d 秒", seconds)
        self._lk_retry_hint = None
        self._begin_cooldown(int(seconds))

    def _begin_cooldown(self, seconds: int) -> None:
        self._lk_remaining = max(1, int(seconds))
        self._lk_button.setEnabled(False)
        self._set_hint(self._cooldown_text(self._lk_remaining))
        self._lk_timer.start()

    def _lk_tick(self) -> None:
        # 按真实截止时间重算，后台暂停或窗口重开不会延长或提前结束冷却。
        self._lk_remaining = math.ceil(config.password_cooling_remaining())
        if self._lk_remaining <= 0:
            self._end_cooldown()
            return
        self._set_hint(self._cooldown_text(self._lk_remaining))

    def _end_cooldown(self) -> None:
        self._lk_timer.stop()
        self._lk_remaining = 0
        # UI 不改安全状态，避免一个旧窗口清掉另一入口刚产生的冷却。
        has_user = not hasattr(self, "_current_record") or self._current_record() is not None
        self._lk_button.setEnabled(has_user)
        self._lk_button.setText(self._lk_button_text)
        retry_hint = getattr(self, "_lk_retry_hint", None)
        self._lk_retry_hint = None
        self._set_hint(retry_hint or "")

    def _set_hint(self, text: str) -> None:
        if getattr(self, "_lk_remaining", 0) > 0:
            text = self._cooldown_text(self._lk_remaining)
            retry_hint = getattr(self, "_lk_retry_hint", None)
            if retry_hint:
                text = retry_hint + "\n" + text
        # 登录窗口不再保留独立提示行：错误提示与冷却倒计时都并入副标题并标红，
        # 省掉一行常驻空白（副标题已有，切换用户时会刷新为默认文案）。
        if getattr(self, "sub_label", None) is not None:
            self.sub_label.setText(text or self._sub_default)
            self.sub_label.setObjectName("FieldError" if text else "Empty")
            self.sub_label.style().unpolish(self.sub_label)
            self.sub_label.style().polish(self.sub_label)
            return
        self._lk_hint.setText(text)


class AddUserDialog(HintMixin, widgets.ShadowDialog):
    """收集新用户的名称与主密码，校验通过后只产出数据，不落盘。"""

    def __init__(self, existing_names: list[str], parent=None, trashed_names: list[str] | None = None):
        super().__init__("添加用户", parent, width=380)
        self._existing = {n.strip().lower() for n in existing_names}
        self._trashed = {n.strip().lower() for n in (trashed_names or [])}
        self.user_name: str | None = None
        self.password: bytearray | None = None
        self.restore_name: str | None = None

        title = widgets.icon_text("添加用户", "user", object_name="DetailTitle", icon_size=24)
        sub = QLabel("将为新用户创建独立的密码库与主密码，请妥善牢记。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self.name = QLineEdit()
        self.name.setPlaceholderText("用户名")
        self.name.setMaxLength(40)
        self.name.textChanged.connect(self._on_name_changed)
        self._warn_field = self.name
        self.body.addWidget(self.name)

        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("主密码")
        self.pw.setMaxLength(128)
        self.body.addWidget(self.pw)

        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.Password)
        self.pw2.setPlaceholderText("再次输入主密码")
        self.pw2.setMaxLength(128)
        self.body.addWidget(self.pw2)
        self.high_security = QCheckBox("主密码高安全模式（拒绝未达到推荐强度的密码）")
        self.high_security.setChecked(True)
        self.body.addWidget(self.high_security)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.body.addWidget(self.hint)

        bar = _confirm_bar(self, ok_text="创建")
        self._ok_btn = bar.itemAt(bar.count() - 1).widget()
        self.body.addLayout(bar)
        self.name.setFocus()

    def _on_name_changed(self, text: str) -> None:
        """输入到回收站中的同名账户时切换为「恢复账户」模式（ACCOUNT_LIFECYCLE §7）。"""
        is_trashed = text.strip().lower() in self._trashed
        for w in (self.pw, self.pw2, self.high_security):
            w.setEnabled(not is_trashed)
        self._ok_btn.setText("恢复账户" if is_trashed else "创建")
        if is_trashed:
            self.hint.setText("该账户在回收站中，将原样恢复，无需重设主密码。")
            self.hint.setVisible(True)
        elif self.hint.isVisible():
            self.hint.setVisible(False)

    def accept(self) -> None:
        name = self.name.text().strip()
        if not name:
            self._warn("请输入用户名")
            return
        if name.lower() in self._trashed:
            # 命中回收站账户：走账户恢复流程。
            self.restore_name = name
            super().accept()
            return
        if name.lower() in self._existing:
            self._warn("该用户名已存在", self.name)
            return
        pw = self.pw.text()
        if pw != self.pw2.text():
            self._warn("两次输入的主密码不一致", self.pw2)
            return
        allowed, message = _master_password_policy_allows(self, pw, self.high_security.isChecked())
        if not allowed:
            if message:
                self._warn(message, self.pw)
            return
        self.user_name = name
        self.password = bytearray(pw.encode("utf-8"))
        self.pw.clear()
        self.pw2.clear()
        super().accept()


class ImportVaultDialog(HintMixin, widgets.ShadowDialog):
    """导入外部 `.pmv` 文件为新账户：填写账户名即可，密码在解锁时验证。"""

    def __init__(self, existing_names: list[str], src_path: Path, parent=None):
        super().__init__("导入 .pmv 账户", parent, width=380)
        self._existing = {n.strip().lower() for n in existing_names}
        self._src = Path(src_path)
        self.user_name: str | None = None

        title = widgets.icon_text("导入 .pmv 账户", "import", object_name="DetailTitle", icon_size=24)
        sub = QLabel(f"文件：{self._src.name}\n请填写账户名，解锁时将用该库原有的主密码验证。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self._default_name = re.sub(r"^vault[-_]|\.pmv$", "", self._src.stem) or "导入账户"
        self.name = QLineEdit(self._default_name)
        self.name.setPlaceholderText("账户名")
        self.name.setMaxLength(40)
        self._warn_field = self.name
        self.name.returnPressed.connect(self.accept)
        self.body.addWidget(self.name)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.body.addWidget(self.hint)

        self.body.addLayout(_confirm_bar(self, ok_text="导入"))
        self.name.setFocus()

    def accept(self) -> None:
        name = self.name.text().strip()
        if not name:
            self._warn("请输入账户名")
            return
        if name.lower() in self._existing:
            self._warn("该账户名已存在", self.name)
            return
        self.user_name = name
        super().accept()


class RelockDialog(LockoutMixin, widgets.ShadowDialog):
    """主界面锁定后的恢复对话框：验证当前用户的主密码即可继续；
    也可点击"切换用户"改为弹出完整的多用户登录对话框。"""

    def __init__(
        self,
        username: str,
        verify,
        parent=None,
        *,
        reason: str | None = None,
        expected_pmve_identity=None,
        auto_hello: bool = False,
        heading: str | None = None,
        description: str | None = None,
    ):
        super().__init__("保险库", parent, width=380)
        self._verify = verify
        self.unlocked = False
        self.switch_requested = False
        self._username = username
        self._auto_hello = bool(auto_hello)
        self._auto_hello_started = False
        parent_vault = getattr(parent, "vault", None)
        self._expected_pmve_identity = expected_pmve_identity
        if (
            self._expected_pmve_identity is None
            and getattr(parent_vault, "device_unlock_key_format", None) == "pmve-root-key"
        ):
            self._expected_pmve_identity = parent_vault.pmve_identity

        title = widgets.icon_text(
            heading or "已锁定",
            widgets.app_icon(),
            object_name="DetailTitle",
            icon_size=30,
            center_icon=True,
        )
        self.body.addWidget(title)

        if reason:
            reason_lbl = widgets.icon_text(reason, "warning", object_name="LockReason", icon_size=18, word_wrap=True)
            self.body.addWidget(reason_lbl)

        sub = QLabel(description or f"当前用户「{username}」，输入主密码以继续。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(sub)
        self._sub_default = sub.text()

        self.pw = QLineEdit()
        self.pw.setPlaceholderText("主密码")
        self.pw.setMaxLength(128)
        self.pw.returnPressed.connect(self.accept)
        self.body.addWidget(_password_row(self.pw))
        self.sub_label = sub
        self._hint = QLabel()
        self._hint.setObjectName("FieldError")
        self._hint.hide()

        # 解锁 / 生物识别 / 切换用户 同属一组操作，收紧组内间距。
        action_box = QWidget()
        action_lay = QVBoxLayout(action_box)
        action_lay.setContentsMargins(0, 0, 0, 0)
        action_lay.setSpacing(4)

        btn = QPushButton("解锁")
        btn.setObjectName("Primary")
        btn.setAutoDefault(False)
        btn.clicked.connect(self.accept)
        action_lay.addWidget(btn)

        self._hello_ok = False
        self.hello_btn = widgets.set_button_icon(QPushButton("使用生物识别解锁"), "hello")
        self.hello_btn.setObjectName("Ghost")
        self.hello_btn.setAutoDefault(False)
        self.hello_btn.clicked.connect(self._unlock_with_hello)
        # 生物识别是否可用要到 showEvent 之后的 _check_hello 才能确定。若那时才插入按钮，
        # 对话框会先按无按钮布局、再突然长高一行。让按钮始终占据固定高度、不可用时
        # 只隐藏不折叠，窗口尺寸从出现到消失保持不变。
        self.hello_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.hello_btn.setFixedHeight(btn.sizeHint().height())
        self.hello_btn.setVisible(False)
        action_lay.addWidget(self.hello_btn)

        switch_btn = QPushButton("切换用户…")
        switch_btn.setObjectName("Ghost")
        switch_btn.setAutoDefault(False)
        switch_btn.clicked.connect(self._switch_user)
        action_lay.addWidget(switch_btn)
        self.body.addWidget(action_box)
        self.pw.setFocus()

        self.init_lockout(self._hint, [self.pw], btn)

        # 等解锁窗口完成首帧后再探测 Hello；自动填充场景会在确认已绑定后
        # 立即发起系统验证，普通托盘解锁仍保留手动按钮行为。
        if username:
            # 绑定到 self：对话框销毁后定时器自动取消，避免对已删除控件调用。
            QTimer.singleShot(0, self, lambda: self._load_hello_availability(username))

    def _load_hello_availability(self, username: str) -> None:
        self._hello_ok = biometric.available()
        self._check_hello(username)

    def _check_hello(self, username: str) -> None:
        if not self._hello_ok:
            return
        record = config._user_record(username)
        if record is None:
            return
        path = config.user_vault_path(record)
        enabled = biometric.is_enabled(path)
        try:
            self.hello_btn.setText("使用生物识别解锁")
            self.hello_btn.setEnabled(enabled)
            self.hello_btn.setVisible(enabled)
        except RuntimeError:
            # 对话框已销毁（C++ 对象已删除），直接忽略。
            return
        if enabled and self._auto_hello and not self._auto_hello_started:
            self._auto_hello_started = True
            QTimer.singleShot(0, self, self._unlock_with_hello)

    def _mark_hello_expired(self) -> None:
        """保留按钮占位，避免隐藏按钮与输入框抖动同时触发布局错位。"""
        try:
            self.hello_btn.setText("生物识别已失效")
            self.hello_btn.setEnabled(False)
        except RuntimeError:
            return

    def _unlock_with_hello(self) -> None:
        if getattr(self, "_unlocking", False) or not self._username:
            return
        path = config.user_vault_path(config._user_record(self._username))
        try:
            opened = biometric.open_vault(path)
        except biometric.DeviceEnvelopeError as exc:
            self._mark_hello_expired()
            self.warn(str(exc))
            return
        except crypto.DecryptError:
            biometric.disable(path)
            self._mark_hello_expired()
            self.warn("生物识别凭据已失效，请用主密码登录后重新启用")
            return
        if opened is None:
            self.warn("生物识别验证未通过")
            return
        matches = False
        try:
            if self._expected_pmve_identity is not None:
                matches = (
                    opened.device_unlock_key_format == "pmve-root-key"
                    and opened.pmve_identity == self._expected_pmve_identity
                )
        finally:
            opened.close()
        if not matches:
            biometric.disable(path)
            self._mark_hello_expired()
            self.warn("生物识别凭据已失效，请用主密码登录后重新启用")
            return
        self.unlocked = True
        self.passed()
        super().accept()

    def _switch_user(self) -> None:
        if self.cooling_down:
            return
        self.switch_requested = True
        self.reject()

    def accept(self) -> None:
        if self.cooling_down:
            return
        pw = self.pw.text()
        if not pw:
            self.warn("主密码不能为空")
            return
        if not self._verify(pw):
            self.pw.clear()
            self.wrong_password()
            return
        self.unlocked = True
        self.passed()
        super().accept()


class ConfirmPasswordDialog(LockoutMixin, widgets.ShadowDialog):
    """通用主密码二次确认对话框，用于查看敏感字段、导出明文等操作前的身份验证。

    与安卓 MasterPasswordDialog 对齐：共用同一份失败计数与冷却记录（config 侧
    ``record_password_failure``，语义对齐 security.LockoutPref），阈值 5 次、
    失败退避 250ms×2ⁿ、记满后冷却 30s×轮次。解锁页、自动填充与本对话框共享
    同一计数空间，因此本路径记满时会一并触发锁库——库已解锁却连续猜错主密码，
    持机者很可能不是用户，此时应立即降级为锁定态（对齐
    VaultViewModel.verifySessionPassword）。

    注意 verify_password 的快速路径走 SessionSecret.matches（hmac.compare_digest）
    而不跑 Argon2id，单次成本接近零；这正是这里必须有计数与退避的原因。
    """

    def __init__(self, verify, title: str, message: str, confirm_text: str = "确认", parent=None, on_lockout=None):
        super().__init__(title, parent, width=360)
        self._verify = verify
        self._title = title
        self._on_lockout = on_lockout
        self.unlocked = False
        self.password = ""

        title_lbl = widgets.icon_text(title, "warning", object_name="DetailTitle", icon_size=20)
        title_lbl.setMaximumWidth(320)
        sub = QLabel(message)
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        sub.setMaximumWidth(320)
        self.body.addWidget(title_lbl)
        self.body.addWidget(sub)

        self.pw = QLineEdit()
        self.pw.setMaximumWidth(320)
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("主密码")
        self.pw.setMaxLength(128)
        self.pw.returnPressed.connect(self.accept)
        self.body.addWidget(self.pw)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.body.addWidget(self.hint)

        # 确认按钮要交给 LockoutMixin 才能在冷却期被禁用，因此自建按钮行而不是
        # 走 _confirm_bar（后者只返回 layout，拿不到按钮引用）。
        self.btn = _BusyButton(confirm_text)
        self.btn.setObjectName("Primary")
        self.btn.clicked.connect(self.accept)
        self.btn_row = QHBoxLayout()
        self.btn_row.setContentsMargins(0, 0, 0, 0)
        self.btn_row.addStretch(1)
        self.btn_row.addWidget(self.btn)
        self.body.addLayout(self.btn_row)
        self.pw.setFocus()
        self.init_lockout(self.hint, [self.pw], self.btn)
        # 对齐安卓：改一个字符即清掉错误提示，允许就地重输，不强制清空输入框。
        self.pw.textEdited.connect(lambda _text: self._set_hint(""))

    def accept(self) -> None:
        if self.cooling_down:
            return
        pw = self.pw.text()
        if not pw:
            self._set_hint(i18n.tr("主密码不能为空"))
            return
        if not self._verify(pw):
            self._wrong_password()
            return
        self.passed()
        self.unlocked = True
        self.password = pw
        super().accept()

    def _notify_lockout(self, reason: str) -> None:
        if self._on_lockout is not None:
            self._on_lockout(reason)
        else:
            widgets.lock_bus.lock_requested.emit(reason)

    def _wrong_password(self) -> None:
        """记录一次失败，按 Android MasterPasswordDialog 的规则退避或冷却。

        与安卓逐条对齐：
        - 失败只提示「主密码不正确」，不显示剩余次数（解锁页才有那条文案）
        - 不 shake、不清空输入框：用户改一个字就会清掉错误态，允许就地重试
        - 未记满时靠 next_attempt 退避（复用 LockoutMixin._apply_delay）
        - 记满 5 次进入冷却，此时库本来是解锁态，连续猜错主密码的持机者很可能
          不是用户，直接锁库（对齐 verifySessionPassword 的 lock()）
        """
        _count, delay, entered_cooldown, cooldown = config.record_password_failure()
        if entered_cooldown:
            self._begin_cooldown(cooldown)
            reason = i18n.tr_dynamic(
                f"主密码连续错误 {MAX_ATTEMPTS} 次，验证已冷却 {cooldown} 秒，应用已锁定。"
            )
            # 主窗口会弹重锁框；先把本对话框收掉，避免两个模态框叠在一起。
            # 信号在主线程同步发射，这里排到事件队列尾部，等 reject 返回、
            # exec() 退出之后再锁。
            QTimer.singleShot(0, lambda: self._notify_lockout(reason))
            self.reject()
            return
        _log.warning("二次验证主密码错误")
        self._set_hint(i18n.tr("主密码不正确"))
        self._apply_delay(delay)


class _UnlockVerifyWorker(QThread):
    """后台线程校验主密码：避免 Argon2 KDF + 解密阻塞 UI 线程。

    校验期间 UI 显示旋转动画；密码缓冲区在任务结束后于本线程内清零。
    """

    succeeded = Signal(object)
    failed = Signal(str, str)

    def __init__(self, path, password: bytearray):
        super().__init__()
        self._path = path
        self._password = password

    def run(self) -> None:
        try:
            vault = Vault.open_with_password_buffer(self._path, self._password)
        except crypto.DecryptError:
            self.failed.emit("decrypt", "")
            return
        except Exception as exc:  # noqa: BLE001
            _log_mod.exception("解锁校验异常")
            self.failed.emit("error", "")
            return
        finally:
            self._password[:] = b"\x00" * len(self._password)
        self.succeeded.emit(vault)


class UnlockDialog(LockoutMixin, widgets.ShadowDialog):
    def __init__(self, parent=None, *, prepare_handoff=None):
        super().__init__("保险库", parent, width=380, simple_close=True)
        self.vault = None
        self._prepare_handoff = prepare_handoff
        self._completion_started = False
        self._handoff_done = False
        self._completion_queued = False
        self._handoff_preparing = False
        self._completion_hold_timer = QTimer(self)
        self._completion_hold_timer.setSingleShot(True)
        self._completion_hold_timer.setInterval(80)
        self._completion_hold_timer.setTimerType(Qt.PreciseTimer)
        self._completion_hold_timer.timeout.connect(self._prepare_completed_unlock)
        self._users: list[dict] = []

        title = widgets.icon_text(
            "解锁保险库",
            widgets.app_icon(),
            object_name="DetailTitle",
            icon_size=30,
            center_icon=True,
        )
        sub = QLabel("选择用户并输入主密码以解锁。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        # The same subtitle hosts errors and cooldown notices. Keep its font and
        # three-line space stable instead of resizing the login form on failure.
        sub.setStyleSheet("font-size: 9.5pt; font-weight: 400;")
        sub.ensurePolished()
        sub.setFixedHeight(sub.fontMetrics().lineSpacing() * 3 + 4)
        self.body.addWidget(title)
        self.body.addWidget(sub)
        self.sub_label = sub
        self._sub_default = sub.text()

        user_row = QHBoxLayout()
        self.user_combo = widgets.selection_combo()
        self.user_combo.currentIndexChanged.connect(self._on_user_changed)
        new_btn = QPushButton("＋ 新建")
        new_btn.setObjectName("UnlockNewMenuButton")
        new_btn.setMinimumWidth(104)
        new_btn.setAutoDefault(False)
        # 与用户名下拉同高：两者并排在同一行，高度不一致会让按钮显得偏小。
        new_btn.setFixedHeight(self.user_combo.sizeHint().height())
        new_menu = QMenu(new_btn)
        new_menu.addAction(i18n.tr("新建账户"), self._add_user_pmve)
        new_menu.addAction("导入 .pmv 文件", self._import_vault)
        new_menu.addAction("局域网导入", self._lan_import_vault)
        new_btn.setMenu(new_menu)
        self._new_user_btn = new_btn
        user_row.addWidget(self.user_combo, 1)
        user_row.addWidget(new_btn)
        self.body.addLayout(user_row)

        self.pw = QLineEdit()
        self.pw.setPlaceholderText("主密码")
        self.pw.setMaxLength(128)
        self.pw.returnPressed.connect(self.accept)
        self.body.addWidget(_password_row(self.pw))
        self._hint = QLabel()
        self._hint.setObjectName("FieldError")
        self._hint.hide()

        # 解锁 / 生物识别 / 忘记密码 三者同属一组操作，收紧组内间距（body 的
        # 12px 适合分隔不同语义区块，这里按钮之间不需要那么大的呼吸感）。
        action_box = QWidget()
        action_lay = QVBoxLayout(action_box)
        action_lay.setContentsMargins(0, 0, 0, 0)
        action_lay.setSpacing(4)

        self.btn = _BusyButton("解锁")
        self.btn._check._anim.finished.connect(self._on_completion_drawn)
        self.btn.setObjectName("Primary")
        self.btn.setAutoDefault(False)
        self.btn.ensurePolished()
        # The disabled style adds a 1px border on each side. Reserve that height
        # so entering cooldown cannot grow the action group or the dialog.
        self.btn.setFixedHeight(self.btn.sizeHint().height() + 2)
        self.btn.clicked.connect(self.accept)
        action_lay.addWidget(self.btn)

        # The WinRT availability probe can take noticeably longer on the first
        # call (and may wait for a Windows service). It is not needed to paint
        # the initial unlock form, so let the dialog become interactive first.
        self._hello_ok = False
        self._hello_probe_future = None
        self._hello_probe_timer = QTimer(self)
        self._hello_probe_timer.setInterval(20)
        self._hello_probe_timer.timeout.connect(self._finish_hello_availability)
        self.hello_btn = widgets.set_button_icon(QPushButton("使用生物识别解锁"), "hello")
        self.hello_btn.setObjectName("Ghost")
        self.hello_btn.setAutoDefault(False)
        self.hello_btn.clicked.connect(self._unlock_with_hello)
        # 同上：始终占位，避免 _check_hello 判定可用后按钮才出现导致窗口瞬间变高。
        self.hello_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.hello_btn.setFixedHeight(self.btn.height())
        self.hello_btn.setVisible(False)
        action_lay.addWidget(self.hello_btn)

        self.forgot_btn = QPushButton("忘记密码？")
        self.forgot_btn.setObjectName("Link")
        self.forgot_btn.setCursor(Qt.PointingHandCursor)
        self.forgot_btn.setAutoDefault(False)
        self.forgot_btn.clicked.connect(self._forgot_password)
        action_lay.addWidget(self.forgot_btn)
        self.body.addWidget(action_box)

        # 解锁等待动画直接显示在解锁按钮上，不额外占用一行。
        self._unlocking = False
        self._unlock_worker = None

        self.init_lockout(self._hint, [self.pw], self.btn)
        self._reload_users(select=config.get_current_user())
        QTimer.singleShot(250, self, self._load_hello_availability)

    # ---------- 用户切换 ----------
    def _reload_users(self, select: str | None = None) -> None:
        self._users = config.list_users()
        self.user_combo.blockSignals(True)
        self.user_combo.clear()
        for record in self._users:
            self.user_combo.addItem(widgets.ui_icon("user"), record["name"], record)
        if not self._users:
            self.user_combo.addItem("暂无账户", None)
        self.user_combo.blockSignals(False)
        idx = 0
        for i, record in enumerate(self._users):
            if record["name"] == select:
                idx = i
                break
        if self._users:
            self.user_combo.setCurrentIndex(idx)
        can_switch = len(self._users) > 1
        self.user_combo.setEnabled(can_switch)
        self.user_combo.setStyleSheet("" if can_switch else "QComboBox::drop-down { width: 0px; border: none; } QComboBox::down-arrow { image: none; }")
        self._on_user_changed(idx)

    def _current_record(self) -> dict | None:
        return self.user_combo.currentData()

    def _on_user_changed(self, _index: int) -> None:
        self._lk_timer.stop()
        self._lk_remaining = 0
        self._lk_retry_hint = None
        record = self._current_record()
        config.set_current_user(record["name"] if record else None)
        remaining = config.password_cooling_remaining()
        if remaining > 0:
            self._begin_cooldown(math.ceil(remaining))
        self.pw.clear()
        self._set_hint("")
        record = self._current_record()
        has_user = record is not None
        self.pw.setEnabled(has_user)
        self.btn.setEnabled(has_user and not self.cooling_down)
        has_recovery = bool(has_user and _supports_recovery_unlock(config.user_vault_path(record)))
        self.forgot_btn.setVisible(has_recovery)
        self._refresh_hello_button(record)
        if has_user:
            self._set_hint("")
            self.pw.setFocus()
        else:
            self._set_hint("请点击“＋ 新建”，创建账户或从文件、局域网导入。")

    def _load_hello_availability(self) -> None:
        """Keep slow WinRT service checks off the UI thread."""
        if self._hello_probe_future is not None:
            return
        self._hello_probe_future = _hello_probe_executor.submit(biometric.available)
        self._hello_probe_timer.start()

    def _finish_hello_availability(self) -> None:
        future = self._hello_probe_future
        if future is None or not future.done():
            return
        self._hello_probe_timer.stop()
        try:
            self._hello_ok = bool(future.result())
        except Exception:
            _log.exception("Windows Hello 可用性检测失败")
            self._hello_ok = False
        if not self._unlocking:
            self._refresh_hello_button(self._current_record())

    def _refresh_hello_button(self, record: dict | None) -> None:
        hello_on = bool(
            record is not None
            and self._hello_ok
            and biometric.is_enabled(config.user_vault_path(record))
        )
        self.hello_btn.setText("使用生物识别解锁")
        self.hello_btn.setEnabled(hello_on)
        self.hello_btn.setVisible(hello_on)

    def _lan_import_vault(self) -> None:
        """从其他设备的传输站经「导出」通道拉取数据，导入为本机新账户。

        对方（安卓端传输站）会弹出导出确认，确认后才放行下载。
        """
        from core.sync_client import EXPORT_OP, LanSyncClient, PinValidationError, SyncError, embedded_pin

        dlg = widgets.ShadowDialog("局域网导入", self, width=560, simple_close=True)
        hint = QLabel("在另一台设备上打开传输站，然后复制完整连接地址。\n发送前，另一台设备会再次要求本人确认。")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #6B7280; font-size: 12px;")
        dlg.body.addWidget(hint)
        url_edit = QLineEdit()
        url_edit.setPlaceholderText("https://192.168.1.100:18765/api/sync/vault?ticket=…&pin=…")
        url_edit.setMinimumWidth(360)
        dlg.body.addWidget(url_edit)
        connect_btn = QPushButton("开始接收")
        dlg.body.addWidget(connect_btn)
        status_label = QLabel(" ")
        status_label.setStyleSheet("color: #6B7280; font-size: 12px;")
        status_label.setWordWrap(True)
        dlg.body.addWidget(status_label)

        def connect_and_import() -> None:
            url = url_edit.text().strip()
            pin = embedded_pin(url)
            if not url:
                status_label.setText("请粘贴另一台设备显示的完整连接地址")
                return
            if len(pin) != 6:
                status_label.setText("连接地址不完整或已失效，请从另一台设备重新复制")
                return
            connect_btn.setEnabled(False)
            dlg.set_close_enabled(False)
            descriptor, name = tempfile.mkstemp(prefix="vault-lan-import-", suffix=".pmv")
            os.close(descriptor)
            tmp = Path(name)
            worker = _LanImportWorker(url, pin, tmp, dlg)

            def finished(path, error) -> None:
                connect_btn.setEnabled(True)
                dlg.set_close_enabled(True)
                if error is not None:
                    if isinstance(error, PinValidationError):
                        status_label.setText("连接地址已失效，请从另一台设备重新复制")
                    elif isinstance(error, SyncError):
                        status_label.setText(str(error))
                    else:
                        status_label.setText("未能完成接收，请确认两台设备仍在同一网络后重试")
                    return
                status_label.setText("账户数据已安全接收")
                dlg.accept()
                try:
                    self._import_vault_file(Path(path))
                finally:
                    Path(path).unlink(missing_ok=True)

            worker.status_changed.connect(status_label.setText)
            worker.completed.connect(finished)
            dlg._lan_import_worker = worker
            worker.start()

        connect_btn.clicked.connect(connect_and_import)
        dlg.exec()

    def _add_user_pmve(self) -> None:
        self._add_user()

    def _add_user(self) -> None:
        names = [u["name"] for u in self._users]
        trashed = list(config.trashed_accounts().keys())
        dlg = AddUserDialog(names, parent=self, trashed_names=trashed)
        if dlg.exec() != QDialog.Accepted:
            return
        if dlg.restore_name:
            config.restore_account(dlg.restore_name)
            config.set_current_user(dlg.restore_name)
            self._reload_users(select=dlg.restore_name)
            self.pw.setFocus()
            return
        filename = config.unique_vault_filename(dlg.user_name)
        recovery_key_dialog = RecoveryKeyConfirmDialog(self, key_revision=1)
        if recovery_key_dialog.exec() != QDialog.Accepted:
            return
        password_utf8 = dlg.password
        try:
            vault = _create_new_vault(
                config.vault_dir() / filename,
                password_utf8,
                recovery_key_dialog.secret,
            )
        except Exception as exc:
            widgets.message(self, "创建失败", f"无法创建密码库：{exc}", kind="error")
            return
        finally:
            password_utf8[:] = b"\x00" * len(password_utf8)
        record = config.register_user(dlg.user_name, filename)
        config.set_current_user(record["name"])
        self._reload_users(select=record["name"])
        self._on_unlock_success(record, vault)

    def _import_vault(self) -> None:
        src, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("选择 .pmv 库文件"), "", i18n.tr("密码库 (*.pmv)"),
        )
        if not src:
            return
        self._import_vault_file(Path(src))

    def _import_vault_file(self, src_path: Path) -> None:
        names = [u["name"] for u in self._users] + list(config.trashed_accounts().keys())
        dlg = ImportVaultDialog(names, src_path, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        filename = config.unique_vault_filename(dlg.user_name)
        dest = config.vault_dir() / filename
        progress = QProgressDialog("正在复制保险库，请稍候…", None, 0, 0, self)
        progress.setWindowTitle("正在导入 .pmv")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setWindowFlag(Qt.WindowCloseButtonHint, False)
        worker = _VaultImportCopyWorker(src_path, dest, self)
        worker.finished.connect(progress.accept)
        worker.start()
        progress.exec()
        worker.wait()
        if worker.error is not None:
            if dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            widgets.message(self, "导入失败", f"无法复制文件：{worker.error}", kind="error")
            return
        record = config.register_user(dlg.user_name, filename)
        config.set_current_user(record["name"])
        config.record_import(filename)
        _log.info("导入 .pmv 为新账户「%s」", record["name"])
        self._reload_users(select=record["name"])
        widgets.message(self, "导入成功", f"账户「{record['name']}」已导入，请输入密码解锁。", kind="info")

    def _unlock_with_hello(self) -> None:
        if self._unlocking:
            return
        record = self._current_record()
        if record is None:
            return
        path = config.user_vault_path(record)
        try:
            self.vault = biometric.open_vault(path)
        except biometric.DeviceEnvelopeError as exc:
            self.hello_btn.setText("生物识别已失效")
            self.hello_btn.setEnabled(False)
            self.warn(str(exc))
            return
        except crypto.DecryptError:
            biometric.disable(path)
            self.hello_btn.setText("生物识别已失效")
            self.hello_btn.setEnabled(False)
            self.warn("生物识别凭据已失效，请用主密码登录后重新启用")
            return
        except Exception as exc:
            self.warn(f"无法打开密码库：{exc}")
            return
        if self.vault is None:
            self.warn("生物识别验证未通过")
            return
        self._on_unlock_success(record, self.vault)

    # ---------- 紧急恢复密钥 ----------
    def _forgot_password(self) -> None:
        if self._unlocking:
            return
        record = self._current_record()
        if record is None:
            return
        path = config.user_vault_path(record)
        had_hello_binding = biometric.is_enabled(path)

        # Step 1: unlock with the emergency recovery key (no password change yet).
        unlock = RecoveryKeyUnlockDialog(path, parent=self)
        if unlock.exec() != QDialog.Accepted or unlock.vault is None or unlock.secret is None:
            return
        vault = unlock.vault
        secret = unlock.secret

        # Step 2: set a new master password (recovery key still valid). Mandatory.
        reset = _RecoveryResetPasswordDialog(parent=self)
        if reset.exec() != QDialog.Accepted:
            return
        try:
            vault.reset_password_with_recovery(secret, reset.password)
        except Exception:
            widgets.message(
                self,
                i18n.tr("重置失败"),
                i18n.tr("主密码重置失败，请重新使用「忘记密码」流程。"),
                kind="error",
            )
            return

        # Step 3: re-save a new recovery key (old key revoked after confirmation). Mandatory.
        reissue = _MandatoryRecoveryReissueDialog(
            self, key_revision=int(vault.key_revision or 0) + 1
        )
        if reissue.exec() != QDialog.Accepted:
            return
        try:
            vault.regenerate_recovery_key(reissue.secret, old_recovery_secret=secret)
        except Exception:
            widgets.message(
                self,
                i18n.tr("恢复密钥更新失败"),
                i18n.tr("新恢复密钥保存失败，请在设置中重新生成恢复密钥。"),
                kind="error",
            )

        self.vault = vault
        if had_hello_binding:
            biometric.disable(path)
        config.set_current_user(record["name"])
        self.passed()
        recovery_message = i18n.tr("主密码已重置，旧紧急恢复密钥已失效；请妥善保管新的恢复密钥。")
        if had_hello_binding:
            recovery_message += "\n\n" + i18n.tr(
                "生物识别凭据已失效，请用主密码登录后重新启用"
            )
        widgets.message(
            self,
            i18n.tr("恢复成功"),
            recovery_message,
            kind="success",
        )
        self._on_unlock_success(record, vault)

    # ---------- 解锁 ----------
    def closeEvent(self, event) -> None:
        if getattr(self, "_unlocking", False):
            event.ignore()
            return
        super().closeEvent(event)

    def accept(self) -> None:
        if self.cooling_down or self._unlocking:
            return
        record = self._current_record()
        if record is None:
            return
        password_utf8 = bytearray(self.pw.text().encode("utf-8"))
        self.pw.clear()
        if not password_utf8:
            self.warn("主密码不能为空")
            return
        self._begin_unlock(record, password_utf8)

    def _begin_unlock(self, record: dict, password: bytearray) -> None:
        self._unlocking = True
        self._set_hint("")
        for widget in (self.pw, self.btn, self.user_combo, self.hello_btn, self.forgot_btn, self._new_user_btn):
            widget.setEnabled(False)
        self.set_close_enabled(False)
        self.btn.start_busy(i18n.tr("正在解锁…"))
        worker = _UnlockVerifyWorker(config.user_vault_path(record), password)
        self._unlock_worker = worker
        worker.succeeded.connect(lambda vault: self._on_unlock_success(record, vault))
        worker.failed.connect(self._on_unlock_failure)
        worker.start()

    def _finish_busy(self) -> None:
        self._completion_hold_timer.stop()
        self._completion_queued = False
        self._handoff_preparing = False
        self._unlocking = False
        self.btn.stop_busy()
        self.set_close_enabled(True)
        for widget in (self.pw, self.btn, self.user_combo, self.hello_btn, self.forgot_btn, self._new_user_btn):
            widget.setEnabled(True)
        self.user_combo.setEnabled(len(self._users) > 1)
        self._refresh_hello_button(self._current_record())

    def reject(self) -> None:
        if self._unlocking:
            return
        super().reject()

    def finish_handoff(self) -> None:
        if self._handoff_done or not self._completion_started or not self._handoff_preparing:
            return
        self._handoff_done = True
        self._completion_hold_timer.stop()
        super().accept()

    def _on_completion_drawn(self) -> None:
        if (not self._completion_started or self._completion_queued
                or self._handoff_done or self.btn._check._progress < 1.0):
            return
        self._completion_queued = True
        self._completion_hold_timer.start()

    def _prepare_completed_unlock(self) -> None:
        if self._handoff_done or self._handoff_preparing or not self._completion_started:
            return
        self._handoff_preparing = True
        if self._prepare_handoff is None:
            self.finish_handoff()
            return
        try:
            self._prepare_handoff(self)
        except Exception:
            _log.exception("主窗口准备失败")
            if self.vault is not None:
                try:
                    self.vault.close()
                except Exception:
                    _log.exception("清理已解锁保险库失败")
            self.vault = None
            self._completion_started = False
            self._finish_busy()
            self.warn(i18n.tr("无法打开密码库，请稍后重试"))

    def _on_unlock_success(self, record: dict, vault) -> None:
        if self._completion_started:
            return
        self._completion_started = True
        self._unlocking = True
        for widget in (self.pw, self.btn, self.user_combo, self.hello_btn, self.forgot_btn, self._new_user_btn):
            widget.setEnabled(False)
        self.set_close_enabled(False)
        self.vault = vault
        config.set_current_user(record["name"])
        self.passed()
        self.btn.complete_busy()

    def _on_unlock_failure(self, kind: str, msg: str) -> None:
        if self._completion_started:
            return
        self._finish_busy()
        if kind == "decrypt":
            self.wrong_password()
        else:
            if msg:
                _log.warning("解锁校验失败：%s", msg)
            self.warn(i18n.tr("无法打开密码库，请稍后重试"))


class _TagLineEdit(QLineEdit):
    """标签输入框：空格键自动转换为 ", " 分隔符。"""

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Space:
            pos = self.cursorPosition()
            before = self.text()[:pos].rstrip()
            if before and not before.endswith(","):
                self.insert(", ")
            return
        super().keyPressEvent(event)


# ── 多图片画廊控件 ────────────────────────────────────────────────────────────


def image_viewer_paging_enabled(zoom: float) -> bool:
    """适配视图由分页手势接管；放大后拖动只平移当前图片。"""

    return float(zoom) <= 1.0001


def image_viewer_swaps_dimensions(transformation: QImageIOHandler.Transformation) -> bool:
    """EXIF 变换是否交换宽高（90/270 度旋转，含镜像组合）。"""

    return transformation in (
        QImageIOHandler.Transformation.TransformationRotate90,
        QImageIOHandler.Transformation.TransformationRotate270,
        QImageIOHandler.Transformation.TransformationFlipAndRotate90,
        QImageIOHandler.Transformation.TransformationMirrorAndRotate90,
    )


def image_viewer_double_click_target(zoom: float, fit: float) -> float:
    """双击目标倍率，与 Android 一致：

    - 普通图片：适配 -> 2x -> 适配；
    - 2x 后仍低于原图 1:1 的高清图：适配 -> 2x -> 原图 1:1 -> 适配。
    """

    fit = float(fit)
    maximum = max(1.0, 4.0 / fit) if fit > 0.0 else 1.0
    if maximum <= 1.0:
        return 1.0
    two_times = min(2.0, maximum)
    native = max(1.0, 1.0 / fit) if fit > 0.0 else 1.0
    has_native_stage = fit > 0.0 and fit * two_times < 1.0 - 0.001
    current = float(zoom)
    if current <= 1.001:
        return two_times
    if has_native_stage and current < native - 0.001:
        return native
    return 1.0


def image_viewer_display_clip_to_encoded(
    clip: QRect,
    display_size: QSize,
    transformation: QImageIOHandler.Transformation,
) -> QRect:
    """把显示方向的可视区域映射回解码器使用的原始图像坐标。

    QImageReader 的 scaledClipRect 在“缩放后但尚未旋转”的坐标系里解释，
    EXIF 变换由 read() 最后统一施加，因此旋转图必须先把显示区域换算回
    编码方向，否则高清层会贴到错误区域并颠倒方向。
    """

    left, top = clip.x(), clip.y()
    width, height = clip.width(), clip.height()
    display_w, display_h = display_size.width(), display_size.height()
    if transformation == QImageIOHandler.Transformation.TransformationRotate90:
        return QRect(top, display_w - left - width, height, width)
    if transformation == QImageIOHandler.Transformation.TransformationRotate270:
        return QRect(display_h - top - height, left, height, width)
    if transformation == QImageIOHandler.Transformation.TransformationFlipAndRotate90:
        return QRect(top, left, height, width)
    if transformation == QImageIOHandler.Transformation.TransformationMirrorAndRotate90:
        return QRect(display_h - top - height, display_w - left - width, height, width)
    if transformation == QImageIOHandler.Transformation.TransformationRotate180:
        return QRect(display_w - left - width, display_h - top - height, width, height)
    if transformation == QImageIOHandler.Transformation.TransformationMirror:
        return QRect(display_w - left - width, top, width, height)
    if transformation == QImageIOHandler.Transformation.TransformationFlip:
        return QRect(left, display_h - top - height, width, height)
    return QRect(left, top, width, height)


def image_viewer_window_size(available: QSize) -> QSize:
    """图像窗口默认足够大，同时给小屏幕保留四周可操作边距。"""

    screen_w = max(320, int(available.width()))
    screen_h = max(320, int(available.height()))
    maximum_w = max(320, screen_w - 48)
    maximum_h = max(320, screen_h - 48)
    width = min(max(900, round(screen_w * 0.82)), maximum_w, 1400)
    height = min(max(680, round(screen_h * 0.82)), maximum_h, 980)
    return QSize(width, height)


def image_viewer_release_target(
    *,
    offset_x: float,
    viewport_width: int,
    velocity_x: float,
    index: int,
    image_count: int,
) -> tuple[int, float]:
    """返回分页松手后的目标索引与吸附距离，首尾越界始终回弹。"""

    width = max(1, int(viewport_width))
    count = max(1, int(image_count))
    current = min(max(0, int(index)), count - 1)
    distance_switch = abs(float(offset_x)) >= width * 0.22
    velocity_switch = abs(float(velocity_x)) >= 850.0
    direction = -1 if offset_x > 0 or (offset_x == 0 and velocity_x > 0) else 1
    target = current + direction if distance_switch or velocity_switch else current
    if target < 0 or target >= count:
        return current, 0.0
    if target == current:
        return current, 0.0
    return target, float(-direction * width)


class _ImageSourceWorker(QThread):
    """在后台把一张保险库图片物化一次，并生成适配视口的单层预览。"""

    completed = Signal(int, object, object, object, object)

    def __init__(self, token: int, value: object, viewport: QSize, parent=None):
        super().__init__(parent)
        self._token = token
        self._value = value
        self._viewport = QSize(max(1, viewport.width()), max(1, viewport.height()))

    def run(self) -> None:
        with large_image_decode.decode_lock:
            if not self.isInterruptionRequested():
                self._decode()

    def _decode(self) -> None:
        reader = None
        try:
            raw = large_image_decode.ImageSource()
            media_files.export_value(self._value, raw.path)
            if self.isInterruptionRequested():
                return
            reader = QImageReader(str(raw.path))
            reader.setDecideFormatFromContent(True)
            reader.setAutoTransform(True)
            encoded_size = reader.size()
            if not encoded_size.isValid() or encoded_size.width() <= 0 or encoded_size.height() <= 0:
                raise ValueError("图片数据无法解码")
            transform = reader.transformation()
            rotated = image_viewer_swaps_dimensions(transform)
            display_size = QSize(
                encoded_size.height() if rotated else encoded_size.width(),
                encoded_size.width() if rotated else encoded_size.height(),
            )
            fit = min(
                self._viewport.width() / display_size.width(),
                self._viewport.height() / display_size.height(),
                1.0,
            )
            reader.setScaledSize(
                QSize(
                    max(1, round(encoded_size.width() * fit)),
                    max(1, round(encoded_size.height() * fit)),
                )
            )
            preview = (
                large_image_decode.preview(raw.path, self._viewport.width(), self._viewport.height())
                if encoded_size.width() * encoded_size.height() > large_image_decode.QT_SAFE_PIXELS
                else reader.read()
            )
            if preview.isNull():
                preview = large_image_decode.preview(raw.path, self._viewport.width(), self._viewport.height())
            if preview.isNull():
                raise ValueError("图片数据无法解码")
            if not self.isInterruptionRequested():
                self.completed.emit(self._token, raw, display_size, preview, "")
        except Exception as exc:
            self.completed.emit(self._token, None, None, None, str(exc) or "图片无法读取")
        finally:
            reader = None


class _ImageDetailWorker(QThread):
    """静止后在后台按显示坐标解码一个高清可视区域。"""

    completed = Signal(int, object, object, object)

    def __init__(
        self,
        token: int,
        raw: bytes | large_image_decode.ImageSource,
        display_size: QSize,
        viewport: QSize,
        zoom: float,
        offset: QPointF,
        parent=None,
    ):
        super().__init__(parent)
        self._token = token
        self._raw = raw
        self._display_size = QSize(display_size)
        self._viewport = QSize(viewport)
        self._zoom = float(zoom)
        self._offset = QPointF(offset)

    def run(self) -> None:
        with large_image_decode.decode_lock:
            if not self.isInterruptionRequested():
                self._decode()

    def _decode(self) -> None:
        try:
            from PySide6.QtCore import QBuffer, QIODevice

            fit = min(
                self._viewport.width() / self._display_size.width(),
                self._viewport.height() / self._display_size.height(),
            )
            scale = fit * self._zoom
            if scale <= 0:
                return
            left = max(0.0, -self._offset.x() / scale)
            top = max(0.0, -self._offset.y() / scale)
            right = min(
                float(self._display_size.width()),
                (self._viewport.width() - self._offset.x()) / scale,
            )
            bottom = min(
                float(self._display_size.height()),
                (self._viewport.height() - self._offset.y()) / scale,
            )
            if right <= left or bottom <= top:
                return
            margin_x = (right - left) * 0.08
            margin_y = (bottom - top) * 0.08
            clip = QRect(
                max(0, math.floor(left - margin_x)),
                max(0, math.floor(top - margin_y)),
                1,
                1,
            )
            clip.setRight(min(self._display_size.width() - 1, math.ceil(right + margin_x) - 1))
            clip.setBottom(min(self._display_size.height() - 1, math.ceil(bottom + margin_y) - 1))

            fallback_source = self._raw.path if isinstance(self._raw, large_image_decode.ImageSource) else self._raw
            if isinstance(fallback_source, Path):
                reader = QImageReader(str(fallback_source))
            else:
                source = QBuffer()
                source.setData(fallback_source)
                source.open(QIODevice.ReadOnly)
                reader = QImageReader(source)
            reader.setAutoTransform(True)
            transformation = reader.transformation()
            rotated = image_viewer_swaps_dimensions(transformation)
            encoded_size = QSize(
                self._display_size.height() if rotated else self._display_size.width(),
                self._display_size.width() if rotated else self._display_size.height(),
            )
            encoded_clip = image_viewer_display_clip_to_encoded(
                clip, self._display_size, transformation
            )
            full_scaled = QSize(
                max(1, round(encoded_size.width() * scale)),
                max(1, round(encoded_size.height() * scale)),
            )
            scaled_clip = QRect(
                round(encoded_clip.x() * scale),
                round(encoded_clip.y() * scale),
                max(1, round(encoded_clip.width() * scale)),
                max(1, round(encoded_clip.height() * scale)),
            )
            if (encoded_size.width() * encoded_size.height() > large_image_decode.QT_SAFE_PIXELS
                    or full_scaled.width() * full_scaled.height() > large_image_decode.QT_SAFE_PIXELS):
                detail = large_image_decode.region(
                    fallback_source,
                    encoded_clip.x(), encoded_clip.y(),
                    encoded_clip.x() + encoded_clip.width(),
                    encoded_clip.y() + encoded_clip.height(),
                    scaled_clip.width(), scaled_clip.height(),
                )
            else:
                reader.setScaledSize(full_scaled)
                reader.setScaledClipRect(scaled_clip)
                detail = reader.read()
                if detail.isNull():
                    detail = large_image_decode.region(
                        fallback_source,
                        encoded_clip.x(), encoded_clip.y(),
                        encoded_clip.x() + encoded_clip.width(),
                        encoded_clip.y() + encoded_clip.height(),
                        scaled_clip.width(), scaled_clip.height(),
                    )
            if detail.isNull():
                return
            if not self.isInterruptionRequested():
                self.completed.emit(self._token, detail, clip, scaled_clip)
        except Exception:
            return


_active_image_workers: set[QThread] = set()


def _shutdown_image_workers() -> None:
    workers = list(_active_image_workers)
    for worker in workers:
        worker.requestInterruption()
    for worker in workers:
        worker.wait()


atexit.register(_shutdown_image_workers)


class _ImageViewerCanvas(QWidget):
    """与 Android 一致的单预览/单高清层画布及水平分页手势。"""

    page_changed = Signal(int)

    def __init__(self, images: list[object], initial_index: int, parent=None):
        super().__init__(parent)
        self._images = images
        self._index = min(max(0, initial_index), len(images) - 1)
        self._zoom = 1.0
        self._offset = QPointF()
        self._preview = QImage()
        self._detail = QImage()
        self._detail_rect = QRect()
        self._display_size = QSize()
        self._raw: large_image_decode.ImageSource | None = None
        self._closed = False
        self._workers: set[QThread] = set()
        self._detail_epoch = 0
        self._page_preview: dict[int, tuple[QImage, QSize]] = {}
        self._page_label: QLabel | None = None
        self._dragging = False
        self._paging = False
        self._last_pos = QPointF()
        self._drag_x = 0.0
        self._velocity_x = 0.0
        self._last_move_ns = 0
        self._token = 0
        self._load_worker: _ImageSourceWorker | None = None
        self._detail_worker: _ImageDetailWorker | None = None
        self.setMinimumSize(680, 480)
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAttribute(Qt.WA_OpaquePaintEvent)

        self._detail_timer = QTimer(self)
        self._detail_timer.setSingleShot(True)
        self._detail_timer.setInterval(120)
        self._detail_timer.timeout.connect(self._decode_detail)

        self._page_animation = QPropertyAnimation(self, b"pageOffset", self)
        self._page_animation.setDuration(220)
        self._page_animation.setEasingCurve(QEasingCurve.OutCubic)
        self._page_animation.finished.connect(self._finish_page_animation)
        QTimer.singleShot(0, self._load_current)

    def getPageOffset(self) -> float:
        return self._drag_x

    def setPageOffset(self, value: float) -> None:
        self._drag_x = float(value)
        self.update()

    from PySide6.QtCore import Property

    pageOffset = Property(float, getPageOffset, setPageOffset)

    @property
    def index(self) -> int:
        return self._index

    def set_page_label(self, label: QLabel) -> None:
        self._page_label = label
        label.setParent(self)
        label.setAttribute(Qt.WA_TransparentForMouseEvents)
        label.show()
        self._position_page_label()

    def _position_page_label(self) -> None:
        label = self._page_label
        if label is None:
            return
        label.adjustSize()
        label.move((self.width() - label.width()) // 2, self.height() - label.height() - 12)

    def _fit_scale(self, size: QSize | None = None) -> float:
        source = size or self._display_size
        if not source.isValid() or source.width() <= 0 or source.height() <= 0:
            return 1.0
        return min(self.width() / source.width(), self.height() / source.height())

    def _center_offset(self) -> QPointF:
        scale = self._fit_scale() * self._zoom
        return QPointF(
            (self.width() - self._display_size.width() * scale) / 2.0,
            (self.height() - self._display_size.height() * scale) / 2.0,
        )

    def _clamp_offset(self, value: QPointF) -> QPointF:
        if not self._display_size.isValid():
            return value
        scale = self._fit_scale() * self._zoom
        shown_w = self._display_size.width() * scale
        shown_h = self._display_size.height() * scale
        if shown_w <= self.width():
            x = (self.width() - shown_w) / 2.0
        else:
            x = min(0.0, max(self.width() - shown_w, value.x()))
        if shown_h <= self.height():
            y = (self.height() - shown_h) / 2.0
        else:
            y = min(0.0, max(self.height() - shown_h, value.y()))
        return QPointF(x, y)

    def _load_current(self) -> None:
        if self._closed or not self._images or self.width() <= 0 or self.height() <= 0:
            return
        for old_worker in self._workers:
            old_worker.requestInterruption()
        self._token += 1
        self._detail_epoch += 1
        self._page_preview = {page: value for page, value in self._page_preview.items() if abs(page - self._index) <= 1}
        token = self._token
        cached = self._page_preview.get(self._index)
        self._preview = QImage(cached[0]) if cached is not None else QImage()
        self._detail = QImage()
        self._raw = None
        self._display_size = QSize(cached[1]) if cached is not None else QSize()
        self._zoom = 1.0
        self._offset = self._center_offset() if cached is not None else QPointF()
        self.update()
        worker = _ImageSourceWorker(token, self._images[self._index], self.size())
        worker.completed.connect(self._source_ready)
        self._load_worker = worker
        self._start_worker(worker)

    def _start_worker(self, worker: QThread) -> None:
        self._workers.add(worker)
        _active_image_workers.add(worker)

        def finished():
            self._workers.discard(worker)
            _active_image_workers.discard(worker)
            if self._detail_worker is worker:
                self._detail_worker = None
            worker.deleteLater()

        worker.finished.connect(finished)
        worker.start()

    def _source_ready(self, token, raw, display_size, preview, error) -> None:
        if self._closed or token != self._token:
            return
        if error:
            self._preview = QImage()
            self._raw = None
            self.setToolTip(i18n.tr_dynamic(str(error)))
            self.update()
            return
        self.setToolTip("")
        self._raw = raw
        self._display_size = QSize(display_size)
        self._preview = QImage(preview)
        self._page_preview[self._index] = (QImage(preview), QSize(display_size))
        self._offset = self._center_offset()
        self.update()
        self._detail_timer.start()
        self._preload_neighbors()

    def _preload_neighbors(self) -> None:
        for page in (self._index - 1, self._index + 1):
            if page < 0 or page >= len(self._images) or page in self._page_preview:
                continue
            worker = _ImageSourceWorker(-(page + 1), self._images[page], self.size())
            worker.completed.connect(
                lambda token, _raw, size, preview, error, page=page:
                self._neighbor_ready(page, size, preview, error)
            )
            self._start_worker(worker)

    def _neighbor_ready(self, page: int, size: object, preview: object, error: object) -> None:
        if not self._closed and abs(page - self._index) <= 1 and not error and isinstance(preview, QImage) and not preview.isNull():
            self._page_preview[page] = (QImage(preview), QSize(size))
            self.update()

    def _decode_detail(self) -> None:
        if (self._closed or self._dragging or self._paging or self._zoom <= 1.01
                or self._raw is None or not self._display_size.isValid()):
            return
        if self._detail_worker is not None:
            self._detail_timer.start()
            return
        token = self._detail_epoch
        worker = _ImageDetailWorker(
            token,
            self._raw,
            self._display_size,
            self.size(),
            self._zoom,
            self._offset,
        )
        worker.completed.connect(self._detail_ready)
        self._detail_worker = worker
        self._start_worker(worker)

    def _detail_ready(self, token, detail, clip, _scaled_clip) -> None:
        if self._closed or token != self._detail_epoch or not isinstance(detail, QImage) or detail.isNull():
            return
        self._detail = QImage(detail)
        self._detail_rect = QRect(clip)
        self.update()

    @staticmethod
    def _draw_fitted(painter: QPainter, image: QImage, rect: QRectF) -> None:
        if image.isNull():
            return
        fit = min(rect.width() / image.width(), rect.height() / image.height())
        width = image.width() * fit
        height = image.height() * fit
        destination = QRectF(
            rect.x() + (rect.width() - width) / 2.0,
            rect.y() + (rect.height() - height) / 2.0,
            width,
            height,
        )
        painter.drawImage(destination, image)

    def _draw_page(self, painter: QPainter, page: int, x: float) -> None:
        cached = self._page_preview.get(page)
        if cached is None or cached[0].isNull():
            return
        self._draw_fitted(painter, cached[0], QRectF(x, 0.0, self.width(), self.height()))

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#000000"))
        painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
        if self._paging:
            self._draw_page(painter, self._index, self._drag_x)
            if self._drag_x < 0 and self._index + 1 < len(self._images):
                self._draw_page(painter, self._index + 1, self._drag_x + self.width())
            elif self._drag_x > 0 and self._index > 0:
                self._draw_page(painter, self._index - 1, self._drag_x - self.width())
            painter.end()
            return
        if not self._preview.isNull() and self._display_size.isValid():
            scale = self._fit_scale() * self._zoom
            image_rect = QRectF(
                self._offset.x(),
                self._offset.y(),
                self._display_size.width() * scale,
                self._display_size.height() * scale,
            )
            painter.drawImage(image_rect, self._preview)
            if not self._detail.isNull() and self._detail_rect.isValid():
                detail_rect = QRectF(
                    self._offset.x() + self._detail_rect.x() * scale,
                    self._offset.y() + self._detail_rect.y() * scale,
                    self._detail_rect.width() * scale,
                    self._detail_rect.height() * scale,
                )
                painter.drawImage(detail_rect, self._detail)
        elif self.toolTip():
            painter.setPen(QColor("#ffffff"))
            painter.drawText(self.rect().adjusted(24, 24, -24, -24), Qt.AlignCenter | Qt.TextWordWrap, self.toolTip())
        painter.end()

    def wheelEvent(self, event) -> None:
        self._detail_epoch += 1
        delta = event.angleDelta().y()
        if delta == 0 or not self._display_size.isValid():
            event.ignore()
            return
        old_zoom = self._zoom
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        self._zoom = min(max(1.0, old_zoom * factor), max(1.0, 4.0 / self._fit_scale()))
        position = event.position()
        ratio = self._zoom / old_zoom
        self._offset = self._clamp_offset((self._offset - position) * ratio + position)
        self._detail = QImage()
        self._detail_timer.start()
        self.update()
        event.accept()

    def mouseDoubleClickEvent(self, event) -> None:
        self._detail_epoch += 1
        if event.button() != Qt.LeftButton or not self._display_size.isValid():
            return
        old_zoom = self._zoom
        self._zoom = image_viewer_double_click_target(self._zoom, self._fit_scale())
        if image_viewer_paging_enabled(self._zoom):
            self._offset = self._center_offset()
        else:
            ratio = self._zoom / old_zoom
            self._offset = self._clamp_offset((self._offset - event.position()) * ratio + event.position())
        self._detail = QImage()
        self._detail_timer.start()
        self.update()

    def mousePressEvent(self, event) -> None:
        self._detail_epoch += 1
        if event.button() != Qt.LeftButton:
            return
        self._page_animation.stop()
        self._dragging = True
        self._paging = image_viewer_paging_enabled(self._zoom) and len(self._images) > 1
        self._last_pos = event.position()
        self._velocity_x = 0.0
        self._last_move_ns = time.monotonic_ns()
        self._detail_timer.stop()
        self.setCursor(Qt.ClosedHandCursor)
        event.accept()

    def mouseMoveEvent(self, event) -> None:
        if not self._dragging:
            return
        position = event.position()
        delta = position - self._last_pos
        now = time.monotonic_ns()
        elapsed = max(1e-6, (now - self._last_move_ns) / 1_000_000_000)
        self._velocity_x = delta.x() / elapsed
        self._last_move_ns = now
        self._last_pos = position
        if self._paging:
            resistance = 0.32 if (
                (self._index == 0 and self._drag_x + delta.x() > 0)
                or (self._index == len(self._images) - 1 and self._drag_x + delta.x() < 0)
            ) else 1.0
            self._drag_x += delta.x() * resistance
        else:
            self._offset = self._clamp_offset(self._offset + delta)
        self.update()
        event.accept()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() != Qt.LeftButton or not self._dragging:
            return
        self._dragging = False
        self.unsetCursor()
        if not self._paging:
            self._detail_timer.start()
            return
        target_index, target_offset = image_viewer_release_target(
            offset_x=self._drag_x,
            viewport_width=self.width(),
            velocity_x=self._velocity_x,
            index=self._index,
            image_count=len(self._images),
        )
        self._pending_index = target_index
        self._page_animation.setStartValue(self._drag_x)
        self._page_animation.setEndValue(target_offset)
        self._page_animation.start()
        event.accept()

    def _finish_page_animation(self) -> None:
        target = getattr(self, "_pending_index", self._index)
        changed = target != self._index
        self._index = target
        self._drag_x = 0.0
        self._paging = False
        if changed:
            self.page_changed.emit(self._index)
            self._load_current()
        else:
            self.update()
            self._detail_timer.start()

    def reset_zoom(self) -> None:
        self._detail_epoch += 1
        self._zoom = 1.0
        self._offset = self._center_offset()
        self._detail = QImage()
        self._detail_timer.start()
        self.update()

    def resizeEvent(self, event) -> None:
        self._detail_epoch += 1
        super().resizeEvent(event)
        self._position_page_label()
        if self._display_size.isValid():
            self._offset = self._clamp_offset(self._offset)
            self._detail_timer.start()

    def close_workers(self) -> None:
        self._closed = True
        self._detail_timer.stop()
        self._page_animation.stop()
        for worker in self._workers:
            worker.requestInterruption()
        self._raw = None
        self._preview = QImage()
        self._detail = QImage()
        self._page_preview.clear()


def show_image_viewer(
    images: object | list[object],
    parent=None,
    *,
    initial_index: int = 0,
) -> None:
    """多图高清查看器：适配视图水平分页，放大后 GPU 绘制平移，静止后补高清层。"""

    values = list(images) if isinstance(images, (list, tuple)) else [images]
    if not values:
        return
    index = min(max(0, int(initial_index)), len(values) - 1)
    dlg = widgets.ShadowDialog("图片预览", parent, width=900, simple_close=True)
    dlg.body.setContentsMargins(0, 0, 0, 0)
    dlg.body.setSpacing(0)
    screen = dlg.screen() or QApplication.primaryScreen()
    available = screen.availableGeometry().size() if screen is not None else QSize(1200, 800)
    default_size = image_viewer_window_size(available)
    # ShadowDialog.exec() 会在显示前 adjustSize；把期望尺寸设为最小值可阻止它再次压小。
    dlg.setMinimumSize(default_size)
    dlg.resize(default_size)

    canvas = _ImageViewerCanvas(values, index, dlg)
    dlg.body.addWidget(canvas, 1)

    controls = QWidget()
    controls.setStyleSheet("background: #000000;")
    btn_bar = QHBoxLayout(controls)
    btn_bar.setContentsMargins(12, 6, 12, 8)
    page_label = QLabel(f"{index + 1} / {len(values)}", canvas)
    page_label.setAlignment(Qt.AlignCenter)
    page_label.setStyleSheet("color: #FFFFFF; background: rgba(255, 255, 255, 24); border-radius: 8px; padding: 4px 10px;")
    canvas.set_page_label(page_label)
    btn_bar.addStretch()
    zoom_reset = QPushButton("复原")
    zoom_reset.setObjectName("Primary")
    zoom_reset.setFixedWidth(100)
    zoom_reset.clicked.connect(canvas.reset_zoom)
    btn_bar.addWidget(zoom_reset)
    btn_bar.addStretch()
    dlg.body.addWidget(controls)
    def update_page_label(page: int) -> None:
        page_label.setText(f"{page + 1} / {len(values)}")
        canvas._position_page_label()

    canvas.page_changed.connect(update_page_label)

    def _key(event) -> None:
        if event.key() in (Qt.Key_Escape, Qt.Key_Return, Qt.Key_Space):
            dlg.accept()

    dlg.keyPressEvent = _key
    dlg.finished.connect(lambda _result: canvas.close_workers())
    widgets.apply_capture_permission(dlg)
    dlg.exec()


class _ImageCard(QWidget):
    """单张图片缩略图：点击放大，悬停显示预览/删除按钮，保持原始比例。"""

    removed = Signal(object)
    preview_clicked = Signal(object)
    W, H = 180, 114

    def __init__(self, b64: object, parent=None):
        super().__init__(parent)
        self.b64 = b64
        self.setFixedSize(self.W, self.H)
        self.setCursor(Qt.PointingHandCursor)

        self._img = QLabel(self)
        self._img.setFixedSize(self.W, self.H)
        self._img.setAlignment(Qt.AlignCenter)
        self._img.setObjectName("ImgPreview")
        self._set_pixmap(b64)

        # 半透明蒙版（仅视觉，鼠标事件穿透）
        self._overlay = QWidget(self)
        self._overlay.setObjectName("ImgOverlay")
        self._overlay.setFixedSize(self.W, self.H)
        self._overlay.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._overlay.hide()

        # 预览按钮（居中）
        self._preview_btn = widgets.set_button_icon(QPushButton(self), "view", size=24)
        self._preview_btn.setObjectName("ImgReplace")
        self._preview_btn.setToolTip("放大预览")
        self._preview_btn.setFixedSize(52, 52)
        self._preview_btn.move(self.W // 2 - 26, self.H // 2 - 26)
        self._preview_btn.setCursor(Qt.PointingHandCursor)
        self._preview_btn.hide()
        self._preview_btn.clicked.connect(lambda: self.preview_clicked.emit(self))

        # 删除按钮（右上角）
        self._close = QPushButton("×", self)
        self._close.setObjectName("ImgClose")
        self._close.setFixedSize(22, 22)
        self._close.move(self.W - 26, 4)
        self._close.setCursor(Qt.PointingHandCursor)
        self._close.hide()
        self._close.clicked.connect(lambda: self.removed.emit(self))

    def _set_pixmap(self, b64: object) -> None:
        load_thumbnail_into(self._img, b64, self.W, self.H)

    def enterEvent(self, e):
        self._overlay.show()
        self._preview_btn.show()
        self._preview_btn.raise_()
        self._close.show()
        self._close.raise_()

    def leaveEvent(self, e):
        self._overlay.hide()
        self._preview_btn.hide()
        self._close.hide()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.preview_clicked.emit(self)

    def update_pixmap(self, b64: object) -> None:
        self.b64 = b64
        self._set_pixmap(b64)


class ImageGallery(QWidget):
    """横向可滚动多图片画廊，支持添加/更换/删除，滚轮横向滚动。"""

    changed = Signal()
    image_added = Signal(bytes)
    MAX_IMAGES = 8

    def __init__(self, images: list[object], parent=None):
        super().__init__(parent)
        self._cards: list[_ImageCard] = []
        self.add_handler = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._scroll = widgets.HScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setFixedHeight(_ImageCard.H + 18)

        self._inner = QWidget()
        self._row = QHBoxLayout(self._inner)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(8)

        self._add_btn = QPushButton("＋\n添加图片")
        self._add_btn.setObjectName("ImgAdd")
        self._add_btn.setFixedSize(100, _ImageCard.H)
        self._add_btn.setCursor(Qt.PointingHandCursor)
        self._add_btn.clicked.connect(self._on_add)
        self._row.addWidget(self._add_btn)
        self._row.addStretch()

        self._scroll.setWidget(self._inner)
        outer.addWidget(self._scroll)

        for b64 in images:
            self._insert_card(b64)

    # ── 内部操作 ──────────────────────────────────────────────────────

    def _insert_card(self, b64: object) -> None:
        card = _ImageCard(b64)
        card.removed.connect(self._on_remove)
        card.preview_clicked.connect(self._on_preview)
        self._row.insertWidget(len(self._cards), card)
        self._cards.append(card)
        self._add_btn.setVisible(len(self._cards) < self.MAX_IMAGES)

    def _on_remove(self, card: _ImageCard) -> None:
        self._cards.remove(card)
        self._row.removeWidget(card)
        card.deleteLater()
        self._add_btn.setVisible(len(self._cards) < self.MAX_IMAGES)
        self.changed.emit()

    def _on_preview(self, card: _ImageCard) -> None:
        show_image_viewer(self.images(), self, initial_index=self._cards.index(card))

    def _on_add(self) -> None:
        if self.add_handler is not None:
            self.add_handler()
            return
        b64 = self._pick_file()
        if b64:
            self._insert_card(b64)
            self.changed.emit()
            self.image_added.emit(media_files.read_bytes(b64, 16 * 1024 * 1024))

    def add_image_bytes(self, data: bytes) -> bool:
        if len(self._cards) >= self.MAX_IMAGES:
            return False
        ref = media_files.import_bytes(data, "image")
        self._insert_card(ref)
        self.changed.emit()
        self.image_added.emit(data)
        return True

    def _pick_file(self) -> str | None:
        from pathlib import Path

        pictures = Path.home() / "Pictures"
        start = pictures if pictures.is_dir() else Path.home()
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("选择图片"), str(start), i18n.tr("图片 (*.jpg *.jpeg *.png *.webp *.bmp *.gif)"),
        )
        if not path:
            return None
        source = Path(path)
        if source.stat().st_size > 10 * 1024 * 1024:
            widgets.message(self, "图片过大", "请选择 10 MB 以内的图片。", kind="warn")
            return None
        raw = source.read_bytes()
        img = QImage()
        img.loadFromData(raw)
        if img.isNull():
            widgets.message(self, "无法读取", "不支持的图片格式。", kind="warn")
            return None
        # 图片会随保险库同步。此前这里会缩小到 1200px 后再以 JPEG 82 重编码，
        # 导致卡号和证件小字在预览、放大与导出时都不可逆地变糊。
        # 缩略图由 _ImageCard 按显示尺寸平滑缩放，保存时保留用户选中的原始字节。
        return media_files.import_file(source, "image", source.name)

    # ── 公共接口 ─────────────────────────────────────────────────────

    def images(self) -> list[object]:
        return [c.b64 for c in self._cards]

    def first_bytes(self) -> bytes | None:
        return media_files.read_bytes(self._cards[0].b64, 16 * 1024 * 1024) if self._cards else None

    def all_bytes(self) -> list[bytes]:
        return [media_files.read_bytes(c.b64, 16 * 1024 * 1024) for c in self._cards]


class _PwnedWorker(QThread):
    """后台线程执行 Pwned Passwords 在线查询，避免网络阻塞主界面。"""

    done = Signal(str, int)  # (查询的密码, 出现次数；-1 表示网络异常)

    def __init__(self, password: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._password = password

    def run(self) -> None:
        count = leak.pwned_count(self._password)
        self.done.emit(self._password, count)


class _OcrWorker(QThread):
    """后台线程执行 OCR 识别与字段解析，避免阻塞主界面。"""

    finished_ok = Signal(dict)
    failed = Signal(str)

    def __init__(self, images: list[bytes], card_type: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._images = images
        self._card_type = card_type

    def run(self) -> None:
        from core import ocr as _ocr

        parser = _ocr.parse_id_card if self._card_type == entry_modules.CARD_ID_CARD else _ocr.parse_credit_card
        merged: dict = {}
        any_text = False
        last_error: str | None = None
        for img_bytes in self._images:
            try:
                text = _ocr.ocr_image(img_bytes)
            except Exception as exc:
                last_error = str(exc)
                continue
            if not text.strip():
                continue
            any_text = True
            # 多张图片（如身份证正反面）的字段合并：先到先得，
            # 避免后一张图的字段覆盖已识别的同名字段
            parsed = parser(text)
            if self._card_type == entry_modules.CARD_ID_CARD:
                parsed = {k: v for k, v in parsed.items() if k in {"full_name", "id_number", "issue_date", "expiry_date", "issuing_authority"}}
            for k, v in parsed.items():
                merged.setdefault(k, v)
        if not any_text:
            self.failed.emit(last_error or "未识别到内容")
            return
        if not merged:
            self.failed.emit("解析失败")
            return
        self.finished_ok.emit(merged)


def _editor_section_heading(title: str, subtitle: str) -> QWidget:
    heading = QWidget()
    heading.setObjectName("EditorSectionHeading")
    row = QHBoxLayout(heading)
    row.setContentsMargins(0, 8, 0, 2)
    row.setSpacing(10)
    marker = QFrame()
    marker.setObjectName("EditorSectionMarker")
    marker.setFixedSize(4, 28)
    row.addWidget(marker)
    text = QVBoxLayout()
    text.setSpacing(1)
    title_label = QLabel(i18n.tr(title))
    title_label.setObjectName("EditorSectionTitle")
    subtitle_label = QLabel(i18n.tr(subtitle))
    subtitle_label.setObjectName("EditorSectionSubtitle")
    text.addWidget(title_label)
    text.addWidget(subtitle_label)
    row.addLayout(text, 1)
    return heading


class EntryDialog(widgets.ShadowDialog):
    """新增或编辑一个条目，支持多种敏感信息类型。"""

    def __init__(self, entry: Entry | None = None, parent=None, default_type: str | None = None, *, show_type_selector: bool = True):
        _title = "编辑条目" if entry else ("新增条目" if not show_type_selector else "新建条目")
        super().__init__(_title, parent, width=500)
        # 使用深拷贝，避免直接修改原条目对象，导致 Vault.update() 中
        # entry.content_equals(e) 因两者是同一对象而恒为 True，更新时间不刷新
        self._entry = copy.deepcopy(entry) if entry else Entry()
        self._pending_card_ocr: list[bytes] = []
        self._entry.migrate_autofill_links()
        vault = getattr(parent, "vault", None)
        self._autofill_entries: list[Entry] = []
        if vault is not None:
            self._autofill_entries = [value for value in vault.entries if value.deleted_at is None]

        # 类型选择行（新增且 show_type_selector=True 时显示）
        type_row = QHBoxLayout()
        type_row.setSpacing(8)
        type_lbl = QLabel("类型")
        type_lbl.setObjectName("FieldLabel")
        self.type_combo = widgets.selection_combo()
        for t in SecretType.CREATABLE:
            self.type_combo.addItem(widgets.category_icon(t), SecretType.LABELS[t], t)
        init_type = self._entry.secret_type if entry else (default_type or SecretType.LOGIN)
        init_index = SecretType.CREATABLE.index(init_type) if init_type in SecretType.CREATABLE else 0
        self.type_combo.setCurrentIndex(init_index)
        self.identity_card = QFrame()
        self.identity_card.setObjectName("EditorIdentityCard")
        identity_row = QHBoxLayout(self.identity_card)
        identity_row.setContentsMargins(14, 12, 14, 12)
        identity_row.setSpacing(12)
        self.identity_icon = QLabel()
        self.identity_icon.setObjectName("EditorIdentityIcon")
        self.identity_icon.setFixedSize(44, 44)
        self.identity_icon.setAlignment(Qt.AlignCenter)
        identity_row.addWidget(self.identity_icon)
        identity_text = QVBoxLayout()
        identity_text.setSpacing(2)
        self.identity_title = QLabel()
        self.identity_title.setObjectName("EditorIdentityTitle")
        self.identity_subtitle = QLabel(i18n.tr("填写基本信息，并按需添加附加内容"))
        self.identity_subtitle.setObjectName("EditorSectionSubtitle")
        identity_text.addWidget(self.identity_title)
        identity_text.addWidget(self.identity_subtitle)
        identity_row.addLayout(identity_text, 1)
        self.body.addWidget(self.identity_card)
        type_row.addWidget(type_lbl)
        type_row.addWidget(self.type_combo, 1)
        self.body.addLayout(type_row)
        if entry or not show_type_selector:
            type_lbl.hide()
            self.type_combo.hide()

        self.body.addWidget(_editor_section_heading("基本信息", "用于识别和查找此条目"))

        # 名称（所有类型共用）
        self.title_edit = QLineEdit(self._entry.title)
        self.title_edit.setPlaceholderText("条目名称")
        self.title_edit.setMaxLength(100)
        self.body.addWidget(self.title_edit)

        # 类型专属内容
        self.stacked = QStackedWidget()
        self._pages: list[QWidget] = []
        for index, t in enumerate(SecretType.CREATABLE):
            page = self._build_page(t) if index == init_index else QWidget()
            page.setProperty("lazyEntryPage", index != init_index)
            self._pages.append(page)
            self.stacked.addWidget(page)
        self.body.addWidget(self.stacked)

        modules_label = _editor_section_heading("附加内容", "按需组合模块，可拖动调整顺序")
        initial_modules = entry_modules.modules_from_fields(self._entry.fields)
        if not entry and not initial_modules:
            initial_modules = entry_modules.preset_modules(init_type)
        # 有专属编辑页的类型：迁移模块数据到直接字段，并从附加内容中彻底删除主模块
        if init_type == SecretType.SECURE_NOTE:
            migrated = []
            for m in initial_modules:
                if m.get("type") == entry_modules.MULTILINE:
                    if "note" not in self._entry.fields:
                        self._entry.fields["note"] = str(m.get("value", ""))
                else:
                    migrated.append(m)
            initial_modules = migrated
        elif init_type == SecretType.SERVER:
            migrated = []
            for m in initial_modules:
                if m.get("type") == entry_modules.SERVER_CONNECTION:
                    if not any(self._entry.fields.get(k) for k in ("server_host", "server_port", "server_user", "server_pass")):
                        value = m.get("value")
                        if isinstance(value, dict):
                            for k in ("host", "port", "username", "password"):
                                v = str(value.get(k, ""))
                                if v:
                                    self._entry.fields["server_" + ("user" if k == "username" else "pass" if k == "password" else k)] = v
                else:
                    migrated.append(m)
            initial_modules = migrated
        self.modules_editor = ModuleEditor(initial_modules, self)
        self.modules_editor.layout_changed.connect(self._refit_entry_dialog)
        self._module_type = init_type
        self._module_states = {init_type: initial_modules}

        # 密码强度条（登录/Wi-Fi/API 类型可见）
        self.meter = widgets.StrengthBar()
        self.body.addWidget(self.meter)

        # 泄露警告：离线字典即时 + 在线 Pwned Passwords 防抖后台查询
        self.leak_label = QLabel()
        self.leak_label.setObjectName("LeakWarning")
        self.leak_label.setWordWrap(True)
        self.leak_label.setStyleSheet("color: #E5484D;")
        self.leak_label.hide()
        self.body.addWidget(self.leak_label)

        self._leak_checked_pw: str | None = None  # 已发起在线查询的密码（防抖去重）
        self._pwned_count: int | None = None  # 最近一次在线结果，None=未知/未查
        self._pwned_worker: _PwnedWorker | None = None
        self._leak_timer = QTimer(self)
        self._leak_timer.setSingleShot(True)
        self._leak_timer.setInterval(600)
        self._leak_timer.timeout.connect(self._start_pwned_check)

        # 标签（仅登录凭证）
        self.tags_widget = QWidget()
        tags_lay = QVBoxLayout(self.tags_widget)
        tags_lay.setContentsMargins(0, 0, 0, 0)
        tags_lay.setSpacing(4)
        tags_label = QLabel("标签")
        tags_label.setObjectName("FieldLabel")
        _init_tags = list(self._entry.tags)
        self.tags_edit = _TagLineEdit(", ".join(_init_tags))
        self.tags_edit.setPlaceholderText("空格或逗号分隔，如：工作 邮箱")
        self.tags_edit.setMaxLength(300)
        tags_lay.addWidget(tags_label)
        tags_lay.addWidget(self.tags_edit)

        vault = getattr(self.parent(), "vault", None)
        # 标签按类别隔离：只提供与本条目同类型的已有标签，避免登录类的标签
        # 出现在银行卡等类别的编辑页（与 Android 的 existingTags 一致）。
        entry_type = self._entry.secret_type
        existing_tags = sorted({
            t
            for e in (vault.entries if vault else [])
            if e.deleted_at is None and e.secret_type == entry_type
            for t in e.tags
        })
        if existing_tags:
            tag_scroll = widgets.HScrollArea()
            tag_scroll.setWidgetResizable(True)
            tag_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            tag_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            tag_scroll.setFrameShape(QFrame.NoFrame)
            tag_scroll.setFixedHeight(34)
            tag_chips_widget = QWidget()
            tag_chips_lay = QHBoxLayout(tag_chips_widget)
            tag_chips_lay.setContentsMargins(0, 0, 0, 0)
            tag_chips_lay.setSpacing(6)
            for tag in existing_tags:
                btn = QPushButton(tag)
                btn.setObjectName("FilterChip")
                btn.setCursor(Qt.PointingHandCursor)
                btn.clicked.connect(lambda _, t=tag: self._add_tag(t))
                tag_chips_lay.addWidget(btn)
            tag_chips_lay.addStretch()
            tag_scroll.setWidget(tag_chips_widget)
            tags_lay.addWidget(tag_scroll)

        self.body.addWidget(self.tags_widget)

        # 所有类别统一把附加模块放在备注之前，避免模块区穿插在专属字段或标签前。
        self.body.addWidget(modules_label)
        self.body.addWidget(self.modules_editor)

        # 备注（所有类型共用）
        notes_label = _editor_section_heading("补充额外说明", "不属于字段的附加说明")
        self.notes_edit = QTextEdit(self._entry.notes)
        self.notes_edit.setFixedHeight(60)
        self.body.addWidget(notes_label)
        self.body.addWidget(self.notes_edit)

        # 将正文内容包入滚动区域，防止内容过多超出屏幕
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        parent_h = self.parent().height() if self.parent() else 600
        scroll.setMaximumHeight(int(parent_h * 0.65))
        scroll_content = QWidget()
        scroll_lay = QVBoxLayout(scroll_content)
        scroll_lay.setContentsMargins(0, 0, 0, 0)
        scroll_lay.setSpacing(12)
        while self.body.count():
            item = self.body.takeAt(0)
            w = item.widget()
            if w:
                scroll_lay.addWidget(w)
            elif item.layout():
                scroll_lay.addLayout(item.layout())
        scroll.setWidget(scroll_content)
        self.body.addWidget(scroll)

        self.body.addLayout(_confirm_bar(self, ok_text="保存", align="right"))

        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        self._on_type_changed(self.type_combo.currentIndex())
        self.title_edit.setFocus()

    # ---- 页面构建 ----

    def _build_page(self, secret_type: str) -> QWidget:
        builders = {
            SecretType.LOGIN: self._build_page_login,
            SecretType.CARD_DOCUMENT: self._build_page_credit,
            SecretType.WIFI: self._build_page_wifi,
            SecretType.API_KEY: self._build_page_api,
            SecretType.OTP: self._build_page_otp,
            SecretType.SECURE_NOTE: self._build_page_secure_note,
            SecretType.SERVER: self._build_page_server,
            SecretType.CUSTOM: self._build_page_empty,
        }
        return builders[secret_type]()

    @staticmethod
    def _build_page_empty() -> QWidget:
        page = QWidget()
        page.setFixedHeight(0)
        return page

    def _build_page_secure_note(self) -> QWidget:
        page, form = self._form_page()
        note_text = str(self._entry.fields.get("note", "") or "")
        if not note_text:
            for m in entry_modules.modules_from_fields(self._entry.fields):
                if m.get("type") == entry_modules.MULTILINE:
                    note_text = str(m.get("value", ""))
                    break
        page.note_edit = QPlainTextEdit(note_text)
        page.note_edit.setPlaceholderText("输入安全笔记内容…")
        form.addRow("内容", page.note_edit)
        return page

    def _build_page_server(self) -> QWidget:
        page, form = self._form_page()
        host = str(self._entry.fields.get("server_host", "") or "")
        port = str(self._entry.fields.get("server_port", "") or "")
        username = str(self._entry.fields.get("server_user", "") or "")
        password = str(self._entry.fields.get("server_pass", "") or "")
        if not any((host, port, username, password)):
            for m in entry_modules.modules_from_fields(self._entry.fields):
                if m.get("type") == entry_modules.SERVER_CONNECTION:
                    value = m.get("value")
                    if isinstance(value, dict):
                        host = str(value.get("host", ""))
                        port = str(value.get("port", ""))
                        username = str(value.get("username", ""))
                        password = str(value.get("password", ""))
                    break
        page.host = QLineEdit(host)
        page.host.setMaxLength(200)
        page.host.setPlaceholderText("192.168.1.1 或 example.com")
        page.port = QLineEdit(port)
        page.port.setMaxLength(10)
        page.port.setPlaceholderText("22")
        _restrict_digits(page.port)
        page.sv_username = QLineEdit(username)
        page.sv_username.setMaxLength(200)
        pw_wrap, page.sv_password_edit = self._secret_field(password)
        form.addRow("主机 / IP", page.host)
        form.addRow("端口", page.port)
        form.addRow("用户名", page.sv_username)
        form.addRow("密码", pw_wrap)
        return page

    def _form_page(self) -> tuple[QWidget, QFormLayout]:
        page = QWidget()
        form = QFormLayout(page)
        form.setSpacing(8)
        form.setContentsMargins(0, 0, 0, 0)
        form.setLabelAlignment(Qt.AlignLeft)
        return page, form

    def _secret_field(self, initial: str = "", max_len: int = 256, with_gen: bool = False) -> tuple[QWidget, QLineEdit]:
        """返回 (行容器Widget, QLineEdit)，含遮盖切换按钮，可选生成按钮。"""
        wrap = QWidget()
        row = QHBoxLayout(wrap)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        edit = QLineEdit(initial)
        widgets.add_password_reveal(edit)
        edit.setMaxLength(max_len)
        row.addWidget(edit)
        if with_gen:
            gen = QPushButton("生成")
            gen.setAutoDefault(False)
            gen.clicked.connect(lambda: self._open_gen(edit))
            row.addWidget(gen)
        return wrap, edit

    def _open_gen(self, target: QLineEdit) -> None:
        dlg = GeneratorDialog(self)
        if dlg.exec() == QDialog.Accepted and dlg.result_password:
            target.setText(dlg.result_password)
            target.setEchoMode(QLineEdit.Normal)

    def _recognize(self, images: list[bytes], fill_callback, card_type: str) -> None:
        worker = getattr(self, "_ocr_worker", None)
        if worker is not None and worker.isRunning():
            self._pending_card_ocr.extend(images)
            return
        if not images:
            return

        def _next() -> None:
            if self._pending_card_ocr:
                pending = self._pending_card_ocr[:]
                self._pending_card_ocr.clear()
                QTimer.singleShot(0, lambda: self._recognize(pending, fill_callback, card_type))

        def _on_ok(fields: dict) -> None:
            fill_callback(fields)

        def _on_fail(msg: str) -> None:
            # Keep the image and allow manual entry if OCR finds no fields.
            pass

        worker = _OcrWorker(images, card_type, self)
        self._ocr_worker = worker
        worker.finished_ok.connect(_on_ok)
        worker.failed.connect(_on_fail)
        worker.finished.connect(_next)
        worker.start()

    def _image_section(self, images: list[object], fill_callback, card_type_getter) -> tuple[ImageGallery, QWidget]:
        gallery = ImageGallery(images, self)
        gallery.MAX_IMAGES = 2
        gallery._add_btn.setVisible(len(gallery.images()) < gallery.MAX_IMAGES)
        gallery.image_added.connect(lambda data: self._recognize([data], fill_callback, card_type_getter()))
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)
        lay.addWidget(gallery)
        return gallery, wrap

    def _build_page_login(self) -> QWidget:
        page, form = self._form_page()
        page.username = QLineEdit(self._entry.username)
        page.username.setMaxLength(200)
        pw_wrap, page.password = self._secret_field(self._entry.password, with_gen=True)
        page.password.textChanged.connect(self._update_meter)
        page.url = QLineEdit(self._entry.url)
        page.url.setMaxLength(500)
        page.url.setPlaceholderText("https://")
        _restrict_url(page.url)
        form.addRow("用户名", page.username)
        form.addRow("密码", pw_wrap)
        form.addRow("网址", page.url)

        # 关联程序
        associated_app = self._entry.target_app or entry_modules.target_app_value(self._entry.fields)
        page.target_app = QLineEdit(associated_app)
        page.target_app.setPlaceholderText("应用包名或程序名，例如 com.example.app")
        page.target_app.setMaxLength(200)
        page.target_app_path = self._entry.get_field("native_app_path")
        page.target_app_signer = self._entry.get_field("native_app_signer_sha256")
        page.target_app.textEdited.connect(lambda _value: self._clear_target_identity(page))
        app_row = QHBoxLayout()
        app_row.setContentsMargins(0, 0, 0, 0)
        app_row.setSpacing(6)
        app_row.addWidget(page.target_app, 1)
        pick_btn = QPushButton("选择…")
        pick_btn.setObjectName("Ghost")
        pick_btn.setFixedWidth(70)
        pick_btn.setMinimumHeight(36)
        pick_btn.clicked.connect(lambda: self._pick_target_app(page))
        app_row.addWidget(pick_btn)
        app_wrap = QWidget()
        app_wrap.setLayout(app_row)
        form.addRow("关联程序", app_wrap)

        page.autofill_links = list(self._entry.autofill_links())
        page.autofill_button = QPushButton()
        page.autofill_button.setMinimumHeight(38)
        page.autofill_button.clicked.connect(lambda: self._show_autofill_source_menu(page))
        # 已关联项逐条展示，每条可独立删除（对齐 Android EntryEditScreen 的
        # autofillLinks.forEach + 单条 IconButton 清除）。每条独占一行，关联增多时
        # 只增加高度，不会横向撑开编辑页窗口。
        page.autofill_link_row = QWidget()
        page.autofill_link_lay = QVBoxLayout(page.autofill_link_row)
        page.autofill_link_lay.setContentsMargins(0, 0, 0, 0)
        page.autofill_link_lay.setSpacing(4)
        page.autofill_link_row.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        page.autofill_link_lay.addWidget(page.autofill_button)
        self._update_autofill_button(page)
        form.addRow(i18n.tr("关联填充内容"), page.autofill_link_row)
        return page

    _AUTOFILL_ROLE_LABELS = {
        "username": "用户名", "email": "邮箱", "password": "密码", "one_time_code": "动态码",
        "full_name": "姓名", "phone": "电话", "country": "国家/地区", "region": "省/州",
        "city": "城市", "street_address": "街道地址", "postal_code": "邮编",
        "cardholder": "持卡人", "card_number": "卡号", "card_expiry": "有效期", "card_cvv": "CVV",
        "id_number": "证件号码", "api_key": "API Key", "api_secret": "API Secret",
        "host": "主机", "port": "端口", "database": "数据库", "ssid": "SSID",
        "wifi_password": "Wi-Fi 密码", "recovery_answer": "恢复答案",
        "custom_text": "自定义文本", "custom_secret": "自定义敏感文本",
    }

    def _show_autofill_source_menu(self, page) -> None:
        menu = QMenu(page.autofill_button)
        current_id = self._entry.id
        grouped: dict[str, list[Entry]] = {}
        for source in sorted(self._autofill_entries, key=lambda item: (item.title.casefold(), item.id)):
            # A login is the consumer of these links and a passkey has no
            # user-visible fill fields.  Keep the first level focused on the
            # standalone data categories Android exposes for association.
            if source.id == current_id or source.secret_type in {SecretType.LOGIN, SecretType.PASSKEY}:
                continue
            if source_values(source):
                grouped.setdefault(source.secret_type, []).append(source)
        for secret_type in SecretType.CREATABLE:
            entries = grouped.get(secret_type, [])
            if not entries:
                continue
            category_menu = menu.addMenu(SecretType.LABELS.get(secret_type, secret_type))
            for source in entries:
                action = category_menu.addAction(source.title or "未命名条目")
                action.triggered.connect(
                    lambda _checked=False, s=source: self._choose_autofill_source_entry(page, s)
                )
        if not menu.actions():
            unavailable = menu.addAction(i18n.tr("暂无可关联内容"))
            unavailable.setEnabled(False)
        menu.exec(page.autofill_button.mapToGlobal(page.autofill_button.rect().bottomLeft()))

    def _source_field_label(self, source: Entry, value) -> str:
        if value.module_id is None:
            return self._AUTOFILL_ROLE_LABELS.get(value.role, value.source_key)
        module = next((item for item in entry_modules.modules_from_fields(source.fields) if item.get("id") == value.module_id), None)
        title = str(module.get("title") or value.source_key) if module else value.source_key
        return f"{title} · {self._AUTOFILL_ROLE_LABELS.get(value.role, value.role)}"

    def _choose_autofill_source_entry(self, page, source: Entry) -> None:
        values = source_values(source)
        dialog = widgets.ShadowDialog(i18n.tr("选择关联字段"), self, width=400)
        dialog.body.addWidget(QLabel(source.title or "未命名条目"))
        dialog.body.addWidget(QLabel(i18n.tr("普通字段默认关联；敏感字段需要你明确勾选。")))
        choices: list[tuple[object, QCheckBox]] = []
        for value in values:
            label = self._source_field_label(source, value)
            checkbox = QCheckBox(f"{self._AUTOFILL_ROLE_LABELS.get(value.role, value.role)} · {label}")
            checkbox.setChecked(value.role not in autofill_sources.SENSITIVE_ROLES)
            choices.append((value, checkbox))
            dialog.body.addWidget(checkbox)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton(i18n.tr("取消"))
        cancel.clicked.connect(dialog.reject)
        buttons.addWidget(cancel)
        apply = QPushButton(i18n.tr("关联所选字段"))
        apply.setObjectName("Primary")
        apply.clicked.connect(dialog.accept)
        buttons.addWidget(apply)
        dialog.body.addLayout(buttons)
        if dialog.exec() != QDialog.Accepted:
            return
        for value, checkbox in choices:
            if checkbox.isChecked():
                self._choose_autofill_source(page, source, value)

    def _choose_autofill_source(self, page, source: Entry, value) -> None:
        existing = [ref for link in page.autofill_links for ref in link.fields if ref.role == value.role]
        internal = [candidate for candidate in source_values(self._entry) if candidate.role == value.role]
        conflicts: list[str] = []
        if internal:
            conflicts.append(i18n.tr("本条目已有内建值"))
        if existing:
            conflicts.append(i18n.tr("已有外部来源"))
        if conflicts and not widgets.confirm(
            self,
            i18n.tr("自动填充来源冲突"),
            i18n.tr("“{role}”{conflicts}。\n\n改用“{source} · {field}”吗？\n选择取消会保留当前来源。").format(
                role=self._AUTOFILL_ROLE_LABELS.get(value.role, value.role),
                conflicts="、".join(conflicts),
                source=source.title,
                field=self._source_field_label(source, value),
            ),
            kind="warn",
        ):
            return
        remaining = []
        for link in page.autofill_links:
            fields = tuple(ref for ref in link.fields if ref.role != value.role)
            if fields:
                remaining.append(autofill_sources.AutofillLink(link.id, link.source_entry_id, fields))
        ref = autofill_sources.AutofillFieldRef(
            value.module_id,
            value.source_key,
            value.role,
            value.requires_verification,
        )
        remaining.append(autofill_sources.AutofillLink(str(uuid.uuid4()), source.id, (ref,)))
        page.autofill_links = remaining
        self._update_autofill_button(page)

    def _update_autofill_button(self, page) -> None:
        """渲染已关联项：每条一个 chip（类型图标 + 来源标题 · 角色），可独立删除。

        对齐 Android EntryEditScreen 中 autofillLinks.forEach 的逐条展示：每条
        Surface 内含来源图标、``标题 · 角色`` 文案与一个清除按钮。
        """
        lay = page.autofill_link_lay
        # 清掉旧的 chip，保留添加按钮（它是第一个加入的子项）。
        while lay.count() > 1:
            item = lay.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        sources = {entry.id: entry for entry in self._autofill_entries}
        for link in page.autofill_links:
            source = sources.get(link.source_entry_id)
            roles = "、".join(
                i18n.tr(self._AUTOFILL_ROLE_LABELS.get(ref.role, ref.role))
                for ref in link.fields
            )
            title = source.title if source is not None else i18n.tr("来源不可用")

            chip = QWidget()
            chip.setObjectName("AutofillLinkChip")
            chip.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            row = QHBoxLayout(chip)
            row.setContentsMargins(8, 4, 4, 4)
            row.setSpacing(6)
            if source is not None:
                icon = QLabel()
                icon.setPixmap(widgets.category_icon(source.secret_type).pixmap(16, 16))
                icon.setFixedSize(16, 16)
                row.addWidget(icon)
            label = QLabel(f"{title} · {roles}")
            label.setObjectName("AutofillLinkChipText")
            row.addWidget(label)
            remove = widgets.icon_only_button(
                "close", i18n.tr("清除"), size=14, object_name="AutofillLinkRemove"
            )
            link_id = link.id
            remove.clicked.connect(
                lambda _=False, page=page, lid=link_id: self._remove_autofill_link(page, lid)
            )
            row.addWidget(remove)
            lay.addWidget(chip)


        count = sum(len(link.fields) for link in page.autofill_links)
        text = "选择关联填充内容…" if count == 0 else "继续选择…"
        page.autofill_button.setText(i18n.tr_dynamic(text))

    def _remove_autofill_link(self, page, link_id: str) -> None:
        """按 link id 移除单条关联，其余关联与角色保持不变。"""
        page.autofill_links = [link for link in page.autofill_links if link.id != link_id]
        self._update_autofill_button(page)

    def _pick_target_app(self, page) -> None:
        current = page.target_app.text().strip()
        dlg = ProgramPickerDialog(current, self)
        if dlg.exec() == QDialog.Accepted:
            page.target_app.setText(dlg.selected_program)
            page.target_app_path = dlg.selected_path
            page.target_app_signer = dlg.selected_signer_sha256

    @staticmethod
    def _clear_target_identity(page) -> None:
        page.target_app_path = ""
        page.target_app_signer = ""

    def _build_page_credit(self) -> QWidget:
        page, form = self._form_page()
        page.card_type = widgets.selection_combo()
        for stored, label in entry_modules.CARD_TYPE_LABELS.items():
            page.card_type.addItem(label, stored)
        current_type = str(self._entry.get_field("card_type") or entry_modules.CARD_BANK)
        page.card_type.setCurrentIndex(max(0, page.card_type.findData(current_type)))
        page.cardholder = QLineEdit(self._entry.get_field("cardholder"))
        page.cardholder.setMaxLength(100)
        page.card_number = QLineEdit(self._entry.get_field("card_number"))
        page.card_number.setPlaceholderText("1234 5678 9012 3456")
        _fmt_card_number(page.card_number)
        pw_wrap, page.cvv = self._secret_field(self._entry.get_field("cvv"), max_len=4)
        _restrict_digits(page.cvv)
        pin_wrap, page.withdrawal_password = self._secret_field(self._entry.get_field("withdrawal_password"), max_len=6)
        _restrict_digits(page.withdrawal_password)
        page.expiry = QLineEdit(self._entry.get_field("expiry"))
        page.expiry.setPlaceholderText("MM/YY")
        _fmt_expiry(page.expiry)
        page.bank = QLineEdit(self._entry.get_field("bank"))
        page.bank.setMaxLength(80)
        page.bank_branch = QLineEdit(self._entry.get_field("bank_branch"))
        page.bank_branch.setMaxLength(120)
        page.bank_branch_code = QLineEdit(self._entry.get_field("bank_branch_code"))
        page.bank_branch_code.setMaxLength(20)
        page.full_name = QLineEdit(self._entry.get_field("full_name"))
        page.card_name = QLineEdit(self._entry.get_field("card_name"))
        page.custom_notes = QTextEdit(self._entry.get_field("notes"))
        page.custom_notes.setFixedHeight(70)
        doc_wrap, page.id_number = self._secret_field(self._entry.get_field("id_number"), max_len=60)
        page.issue_date = QLineEdit(self._entry.get_field("issue_date"))
        page.issue_date.setPlaceholderText("YYYY-MM-DD")
        _fmt_date(page.issue_date)
        page.expiry_date = QLineEdit(self._entry.get_field("expiry_date"))
        page.expiry_date.setPlaceholderText("YYYY-MM-DD 或 长期")
        _fmt_date(page.expiry_date, allow_free=True)
        page.authority = QLineEdit(self._entry.get_field("issuing_authority"))
        page.authority.setMaxLength(100)

        def _fill_card(f: dict) -> None:
            selected = str(page.card_type.currentData() or entry_modules.CARD_BANK)
            targets = {
                "card_number": page.card_number, "cardholder": page.cardholder,
                "expiry": page.expiry, "bank": page.bank, "cvv": page.cvv,
                "full_name": page.full_name, "id_number": page.id_number,
                "issue_date": page.issue_date, "expiry_date": page.expiry_date,
                "issuing_authority": page.authority,
            }
            allowed = set(entry_modules.CARD_FIELDS.get(selected, ()))
            for key, value in f.items():
                target = targets.get(key)
                if key in allowed and target is not None and value and not target.text().strip():
                    target.setText(value)

        init_imgs = self._entry.fields.get("card_images_b64") or []
        page.img_gallery, img_section = self._image_section(
            init_imgs, _fill_card,
            lambda: str(page.card_type.currentData() or entry_modules.CARD_BANK),
        )
        form.addRow("卡片类型", page.card_type)
        page.scan_button = QPushButton()
        page.scan_button.setObjectName("Primary")
        page.scan_button.setAutoDefault(False)

        def _scan_card(*, start_file: bool = False) -> None:
            if len(page.img_gallery.images()) >= page.img_gallery.MAX_IMAGES:
                widgets.message(self, "已达上限", "卡证最多保存 2 张图片。", kind="info")
                return
            try:
                scan = DocumentScannerDialog(parent=self, start_camera=not start_file, start_file=start_file)
            except Exception as exc:
                widgets.message(self, "摄像头不可用", str(exc), kind="warn")
                return
            if scan.exec() == QDialog.Accepted and scan.image_bytes:
                page.img_gallery.add_image_bytes(scan.image_bytes)

        page.scan_button.clicked.connect(lambda: _scan_card())
        page.img_gallery.add_handler = lambda: _scan_card(start_file=True)
        form.addRow(page.scan_button)
        form.addRow("卡片图片", img_section)
        rows = {
            "card_name": ("自定义卡证名称", page.card_name),
            "cardholder": ("持卡人", page.cardholder),
            "card_number": ("完整卡号", page.card_number),
            "bank": ("开户行", page.bank),
            "bank_branch": ("分行/支行", page.bank_branch),
            "expiry": ("有效期", page.expiry),
            "cvv": ("CVV", pw_wrap),
            "withdrawal_password": ("取款密码", pin_wrap),
            "bank_branch_code": ("开户行行号", page.bank_branch_code),
            "full_name": ("姓名", page.full_name),
            "id_number": ("证件号", doc_wrap),
            "issue_date": ("签发日期", page.issue_date),
            "expiry_date": ("到期日期", page.expiry_date),
            "issuing_authority": ("签发机关", page.authority),
            "notes": ("备注", page.custom_notes),
        }
        for label, widget in rows.values():
            form.addRow(label, widget)

        def _refresh_card_type() -> None:
            selected = str(page.card_type.currentData() or entry_modules.CARD_BANK)
            active = set(entry_modules.CARD_FIELDS.get(selected, entry_modules.CARD_FIELDS[entry_modules.CARD_CUSTOM])) - {"notes"}
            for key, (_label, widget) in rows.items():
                form.setRowVisible(widget, key in active)
            page.scan_button.setText(i18n.tr({
                entry_modules.CARD_BANK: "扫描识别银行卡",
                entry_modules.CARD_ID_CARD: "扫描识别身份证",
            }.get(selected, "扫描获取图像")))

        page.card_type.currentIndexChanged.connect(_refresh_card_type)
        _refresh_card_type()
        return page

    def _build_page_wifi(self) -> QWidget:
        page, form = self._form_page()
        page.ssid = QLineEdit(self._entry.get_field("ssid"))
        page.ssid.setMaxLength(32)
        pw_wrap, page.wifi_password = self._secret_field(self._entry.get_field("wifi_password"), max_len=256)
        page.wifi_password.textChanged.connect(self._update_meter)
        page.security_type = widgets.selection_combo()
        for t in entry_modules.WIFI_SECURITY_OPTIONS:
            page.security_type.addItem(t)
        saved_sec = entry_modules.normalize_wifi_security(self._entry.get_field("security_type"))
        idx = page.security_type.findText(saved_sec)
        if idx >= 0:
            page.security_type.setCurrentIndex(idx)
        page.router_url = QLineEdit(self._entry.get_field("router_admin_url"))
        page.router_url.setMaxLength(200)
        page.router_url.setPlaceholderText("http://192.168.1.1")
        _restrict_url(page.router_url)
        admin_wrap, page.admin_password = self._secret_field(self._entry.get_field("admin_password"), max_len=256)
        form.addRow("网络名称 (SSID)", page.ssid)
        form.addRow("Wi-Fi 密码", pw_wrap)
        form.addRow("加密类型", page.security_type)
        form.addRow("路由器管理地址", page.router_url)
        form.addRow("管理密码", admin_wrap)
        return page

    def _build_page_api(self) -> QWidget:
        page, form = self._form_page()
        page.service = QLineEdit(self._entry.get_field("service"))
        page.service.setMaxLength(100)
        pw_wrap_key, page.api_key = self._secret_field(self._entry.get_field("api_key"), max_len=512)
        page.api_key.textChanged.connect(self._update_meter)
        pw_wrap_sec, page.api_secret = self._secret_field(self._entry.get_field("api_secret"), max_len=512)
        page.base_url = QLineEdit(self._entry.get_field("base_url"))
        page.base_url.setMaxLength(300)
        page.base_url.setPlaceholderText("https://api.example.com")
        _restrict_url(page.base_url)
        page.scopes = QLineEdit(self._entry.get_field("scopes"))
        page.scopes.setMaxLength(300)
        page.scopes.setPlaceholderText("read write admin")
        form.addRow("服务名称", page.service)
        form.addRow("API 凭证", pw_wrap_key)
        form.addRow("API Secret", pw_wrap_sec)
        form.addRow("Base URL", page.base_url)
        form.addRow("权限范围", page.scopes)
        return page

    def _build_page_otp(self) -> QWidget:
        page, form = self._form_page()
        fields = otp.normalize_fields(self._entry.fields)

        page.secret = QLineEdit(fields.get("secret", ""))
        page.secret.setMaxLength(256)

        page.issuer = QLineEdit(fields.get("issuer", ""))
        page.issuer.setMaxLength(100)

        page.label = QLineEdit(fields.get("label", ""))
        page.label.setMaxLength(200)

        page.otp_domains = QLineEdit(fields.get("otp_domains", ""))
        page.otp_domains.setMaxLength(2000)
        page.otp_domains.setPlaceholderText("逗号或换行分隔，如 example.com，www.example.com")

        page.uri = QLineEdit()
        page.uri.setMaxLength(1200)

        page.otp_type = _NoScrollComboBox()
        page.otp_type.addItem("TOTP（按时间刷新）", "totp")
        page.otp_type.addItem("HOTP（按计数器）", "hotp")
        page.otp_type.setCurrentIndex(1 if fields.get("type") == "hotp" else 0)

        page.algorithm = _NoScrollComboBox()
        for algo in otp.ALGORITHMS:
            page.algorithm.addItem(algo, algo)
        idx = page.algorithm.findData(fields.get("algorithm", "SHA1"))
        if idx >= 0:
            page.algorithm.setCurrentIndex(idx)

        page.digits = _NoScrollSpinBox()
        page.digits.setRange(6, 8)
        page.digits.setValue(int(fields.get("digits", "6")))

        page.period = _NoScrollSpinBox()
        page.period.setRange(1, 3600)
        page.period.setSuffix(" 秒")
        page.period.setValue(int(fields.get("period", "30")))

        page.counter = _NoScrollSpinBox()
        page.counter.setRange(0, 2**31 - 1)
        page.counter.setValue(min(int(fields.get("counter", "0")), 2**31 - 1))

        def _apply_uri() -> None:
            source = page.uri.text().strip()
            if not source:
                return
            parsed = otp.parse_otpauth_uri(source)
            if not parsed:
                widgets.message(self, "提示", "未识别到有效的 otpauth:// URI", kind="warn")
                return
            page.otp_type.setCurrentIndex(1 if parsed.get("type") == "hotp" else 0)
            page.secret.setText(parsed.get("secret", ""))
            idx = page.algorithm.findData(parsed.get("algorithm", "SHA1"))
            if idx >= 0:
                page.algorithm.setCurrentIndex(idx)
            page.digits.setValue(int(parsed.get("digits", "6")))
            page.period.setValue(int(parsed.get("period", "30")))
            page.counter.setValue(min(int(parsed.get("counter", "0")), 2**31 - 1))
            page.issuer.setText(parsed.get("issuer", ""))
            page.label.setText(parsed.get("label", ""))
            if not self.title_edit.text().strip():
                self.title_edit.setText(parsed.get("issuer") or parsed.get("label") or "动态码")

        page.uri.editingFinished.connect(_apply_uri)

        def _on_type_changed() -> None:
            is_hotp = page.otp_type.currentData() == "hotp"
            if getattr(page, "_advanced_visible", False):
                form.setRowVisible(page.period, not is_hotp)
                form.setRowVisible(page.counter, is_hotp)

        page.otp_type.currentIndexChanged.connect(_on_type_changed)

        toggle_wrap = QWidget()
        toggle_lay = QHBoxLayout(toggle_wrap)
        toggle_lay.setContentsMargins(0, 0, 0, 0)
        toggle_lay.addStretch()
        toggle = QPushButton("⌄  高级选项")
        toggle.setObjectName("Ghost")
        toggle.setToolTip("显示高级选项")
        toggle.setMinimumWidth(120)
        toggle_lay.addWidget(toggle)
        toggle_lay.addStretch()

        def _set_advanced_visible(shown: bool) -> None:
            page._advanced_visible = shown
            is_hotp = page.otp_type.currentData() == "hotp"
            form.setRowVisible(page.otp_type, shown)
            form.setRowVisible(page.algorithm, shown)
            form.setRowVisible(page.digits, shown)
            form.setRowVisible(page.period, shown and not is_hotp)
            form.setRowVisible(page.counter, shown and is_hotp)
            form.setRowVisible(page.uri, shown)

        def _toggle_advanced() -> None:
            shown = not getattr(page, "_advanced_visible", False)
            _set_advanced_visible(shown)
            toggle.setText("⌃  高级选项" if shown else "⌄  高级选项")
            toggle.setToolTip("隐藏高级选项" if shown else "显示高级选项")
            self._refit_entry_dialog()

        toggle.clicked.connect(_toggle_advanced)

        form.addRow("密钥", page.secret)
        form.addRow("发行方", page.issuer)
        form.addRow("账户名", page.label)
        form.addRow("关联域名", page.otp_domains)
        form.addRow(toggle_wrap)
        form.addRow("类型", page.otp_type)
        form.addRow("算法", page.algorithm)
        form.addRow("位数", page.digits)
        form.addRow("周期", page.period)
        form.addRow("计数器", page.counter)
        form.addRow("URI", page.uri)
        _set_advanced_visible(False)
        _on_type_changed()
        return page

    def _refit_entry_dialog(self) -> None:
        """Recompute the frameless dialog size after rows are shown/hidden."""
        for widget in (self.stacked.currentWidget(), self.stacked, self.card):
            if widget is not None:
                widget.updateGeometry()
                layout = widget.layout()
                if layout is not None:
                    layout.activate()
        if self.layout() is not None:
            self.layout().activate()
        self.adjustSize()

        def _resize_to_hint() -> None:
            for widget in (self.stacked.currentWidget(), self.stacked, self.card):
                if widget is not None:
                    widget.updateGeometry()
                    layout = widget.layout()
                    if layout is not None:
                        layout.activate()
            if self.layout() is not None:
                self.layout().activate()
            hint = self.sizeHint()
            self.resize(max(self.width(), hint.width()), hint.height())

        QTimer.singleShot(0, self, _resize_to_hint)

    # ---- 交互 ----

    def _ensure_type_page(self, idx: int) -> QWidget:
        page = self._pages[idx]
        if not page.property("lazyEntryPage"):
            return page
        replacement = self._build_page(SecretType.CREATABLE[idx])
        self.stacked.removeWidget(page)
        page.deleteLater()
        self.stacked.insertWidget(idx, replacement)
        self._pages[idx] = replacement
        return replacement

    def _add_tag(self, tag: str) -> None:
        current = [t for t in re.split(r"[,\s]+", self.tags_edit.text().strip()) if t]
        if tag in current:
            return
        current.append(tag)
        self.tags_edit.setText(", ".join(current))

    def _on_type_changed(self, idx: int) -> None:
        self._ensure_type_page(idx)
        self.stacked.setCurrentIndex(idx)
        for i, page in enumerate(self._pages):
            sp = page.sizePolicy()
            if i == idx:
                sp.setVerticalPolicy(QSizePolicy.Preferred)
            else:
                sp.setVerticalPolicy(QSizePolicy.Ignored)
            page.setSizePolicy(sp)
        t = SecretType.CREATABLE[idx] if idx < len(SecretType.CREATABLE) else SecretType.LOGIN
        self.identity_title.setText(i18n.tr(SecretType.LABELS.get(t, "条目")))
        self.identity_icon.setPixmap(widgets.category_icon(t).pixmap(30, 30))
        if t != self._module_type:
            self._module_states[self._module_type] = self.modules_editor.modules()
            raw = self._module_states.get(t, entry_modules.preset_modules(t))
            if t == SecretType.SECURE_NOTE:
                raw = [m for m in raw if m.get("type") != entry_modules.MULTILINE]
            elif t == SecretType.SERVER:
                raw = [m for m in raw if m.get("type") != entry_modules.SERVER_CONNECTION]
            self.modules_editor.set_modules(raw)
            self._module_type = t
        # 标签对所有可编辑条目类型开放（与 Android 端一致），随类型切换保持可见。
        self.tags_widget.setVisible(True)
        show_meter = t in (SecretType.LOGIN, SecretType.WIFI, SecretType.API_KEY)
        self.meter.setVisible(show_meter)
        self._update_meter()
        self._refit_entry_dialog()

    def _update_meter(self) -> None:
        t = self.type_combo.currentData()
        page = self.stacked.currentWidget()
        if t == SecretType.LOGIN:
            pw = getattr(page, "password", None)
        elif t == SecretType.WIFI:
            pw = getattr(page, "wifi_password", None)
        elif t == SecretType.API_KEY:
            pw = getattr(page, "api_key", None)
        else:
            pw = None
        text = pw.text() if pw else ""
        score, label = utils.strength(text)
        self.meter.set_value(score, label)
        self._update_leak(text)

    # ---- 泄露检测 ----

    def _update_leak(self, text: str) -> None:
        """密码变化时驱动泄露检测：离线即时判断，在线查询防抖后台执行。"""
        if not self.meter.isVisible() or not leak.check_enabled():
            self._leak_timer.stop()
            self.leak_label.hide()
            return
        # 在线状态随密码变化而失效，待防抖后重新查询
        self._pwned_count = None
        self._leak_checked_pw = None
        self._leak_timer.stop()
        if leak.online_check_enabled() and len(text) >= 4:
            self._leak_timer.start()
        self._refresh_leak_label(text)

    def _start_pwned_check(self) -> None:
        text = self._current_password()
        if not text or len(text) < 4 or not leak.online_check_enabled():
            return
        if self._pwned_worker is not None and self._pwned_worker.isRunning():
            return
        self._leak_checked_pw = text
        worker = _PwnedWorker(text, self)
        worker.done.connect(self._on_pwned_done)
        self._pwned_worker = worker
        worker.start()

    def _on_pwned_done(self, password: str, count: int) -> None:
        # 结果回来时密码可能已变，丢弃过期结果
        if password != self._current_password():
            return
        self._pwned_count = count
        self._refresh_leak_label(password)

    def _current_password(self) -> str:
        t = self.type_combo.currentData()
        page = self.stacked.currentWidget()
        if t == SecretType.LOGIN:
            pw = getattr(page, "password", None)
        elif t == SecretType.WIFI:
            pw = getattr(page, "wifi_password", None)
        elif t == SecretType.API_KEY:
            pw = getattr(page, "api_key", None)
        else:
            pw = None
        return pw.text() if pw else ""

    def _refresh_leak_label(self, text: str) -> None:
        if not leak.check_enabled():
            self.leak_label.hide()
            return
        weak = bool(text) and leak.is_common_weak(text)
        breaches = self._pwned_count if self._pwned_count and self._pwned_count > 0 else 0
        if weak and breaches:
            msg = f"已泄露：命中常见弱密码字典，且在 Pwned Passwords 中出现过 {breaches} 次，强烈建议更换"
        elif weak:
            msg = "已泄露：该密码在常见泄露/弱密码字典中，强烈建议更换"
        elif breaches:
            msg = f"已泄露：该密码在公开泄露中出现了 {breaches} 次，强烈建议更换"
        else:
            self.leak_label.hide()
            return
        self.leak_label.setText(msg)
        self.leak_label.show()

    def done(self, result: int) -> None:
        self._leak_timer.stop()
        for attr in ("_ocr_worker", "_pwned_worker"):
            worker = getattr(self, attr, None)
            if worker is not None and worker.isRunning():
                worker.wait()
        super().done(result)

    # ---- 保存 ----

    def accept(self) -> None:
        if not self.title_edit.text().strip():
            widgets.message(self, "提示", "名称不能为空", kind="warn")
            return
        e = self._entry
        e.title = self.title_edit.text().strip()
        e.secret_type = self.type_combo.currentData()
        e.tags = [t for t in re.split(r"[,\s]+", self.tags_edit.text().strip()) if t]
        e.notes = self.notes_edit.toPlainText().strip()
        previous_fields = dict(e.fields) if isinstance(e.fields, dict) else {}
        e.username = ""
        e.password = ""
        e.url = ""
        e.fields = {}

        page = self.stacked.currentWidget()
        st = e.secret_type

        if st == SecretType.LOGIN:
            e.username = page.username.text().strip()
            e.password = page.password.text()
            e.url = page.url.text().strip()
            e.target_app = page.target_app.text().strip()
            if page.target_app_path:
                e.fields["native_app_path"] = page.target_app_path
                if page.target_app_signer:
                    e.fields["native_app_signer_sha256"] = page.target_app_signer

        elif st == SecretType.CARD_DOCUMENT:
            e.fields = dict(previous_fields)
            raw = page.card_number.text().replace(" ", "").replace("-", "")
            e.fields["card_type"] = str(page.card_type.currentData() or entry_modules.CARD_BANK)
            e.fields["card_number"] = raw
            e.fields["card_number_last4"] = raw[-4:] if len(raw) >= 4 else raw
            e.fields["cardholder"] = page.cardholder.text().strip()
            e.fields["expiry"] = page.expiry.text().strip()
            e.fields["cvv"] = page.cvv.text().strip()
            e.fields["withdrawal_password"] = page.withdrawal_password.text().strip()
            e.fields["bank"] = page.bank.text().strip()
            e.fields["bank_branch"] = page.bank_branch.text().strip()
            e.fields["bank_branch_code"] = page.bank_branch_code.text().strip()
            e.fields["full_name"] = page.full_name.text().strip()
            e.fields["card_name"] = page.card_name.text().strip()
            e.fields["notes"] = page.custom_notes.toPlainText().strip()
            e.fields["id_number"] = page.id_number.text().strip()
            e.fields["issue_date"] = page.issue_date.text().strip()
            e.fields["expiry_date"] = page.expiry_date.text().strip()
            e.fields["issuing_authority"] = page.authority.text().strip()
            imgs = page.img_gallery.images()
            e.fields["card_images_b64"] = imgs

        elif st == SecretType.WIFI:
            e.fields = dict(previous_fields)
            e.fields["ssid"] = page.ssid.text().strip()
            e.fields["wifi_password"] = page.wifi_password.text()
            sec = entry_modules.normalize_wifi_security(page.security_type.currentText())
            if sec == "无加密" and e.fields["wifi_password"]:
                sec = "WPA2-Personal"
            e.fields["security_type"] = sec
            e.fields["router_admin_url"] = page.router_url.text().strip()
            e.fields["admin_password"] = page.admin_password.text()

        elif st == SecretType.API_KEY:
            e.fields = dict(previous_fields)
            e.fields["service"] = page.service.text().strip()
            e.fields["api_key"] = page.api_key.text()
            e.fields["api_secret"] = page.api_secret.text()
            e.fields["base_url"] = page.base_url.text().strip()
            e.fields["scopes"] = page.scopes.text().strip()

        elif st == SecretType.OTP:
            fields = {k: v for k, v in previous_fields.items() if k not in otp.OTP_FIELD_KEYS}
            fields.update(
                {
                    "secret": page.secret.text().strip(),
                    "algorithm": page.algorithm.currentData(),
                    "digits": str(page.digits.value()),
                    "period": str(page.period.value()),
                    "issuer": page.issuer.text().strip(),
                    "label": page.label.text().strip(),
                    "type": page.otp_type.currentData(),
                    "counter": str(page.counter.value()),
                    "otp_domains": page.otp_domains.text().strip(),
                }
            )
            e.fields = otp.normalize_fields(fields)
            if not e.fields.get("secret"):
                widgets.message(self, "提示", "动态码密钥不能为空", kind="warn")
                return

        if st == SecretType.SECURE_NOTE:
            note_text = page.note_edit.toPlainText().strip()
            if note_text:
                e.fields["note"] = note_text
            else:
                e.fields.pop("note", None)
        elif st == SecretType.SERVER:
            e.fields = dict(previous_fields)
            _set = lambda k, v: e.fields.__setitem__(k, v) if v else e.fields.pop(k, None)
            _set("server_host", page.host.text().strip())
            _set("server_port", page.port.text().strip())
            _set("server_user", page.sv_username.text().strip())
            pw = page.sv_password_edit.text()
            if pw:
                e.fields["server_pass"] = pw
            else:
                e.fields.pop("server_pass", None)

        e.fields = entry_modules.fields_with_modules(e.fields, self.modules_editor.modules())
        if st == SecretType.LOGIN:
            e.fields = autofill_sources.encode_links_into_fields(e.fields, page.autofill_links)

        e.invalidate_haystack()
        e._title_lower = e.title.lower()
        super().accept()

    @property
    def entry(self) -> Entry:
        return self._entry

    @property
    def checked_pwned_count(self) -> int | None:
        """最终密码已在编辑框中成功查过时，供保存后复用该结果。"""
        if self._leak_checked_pw == self._current_password() and self._pwned_count is not None and self._pwned_count >= 0:
            return self._pwned_count
        return None


class BrowserImportDialog(widgets.ShadowDialog):
    """选择已安装的 Chromium 浏览器进行导入。"""

    def __init__(self, parent=None):
        super().__init__("从浏览器导入", parent, width=360)
        self.result: importers.ImportResult | None = None

        title = QLabel("从浏览器导入密码")
        title.setObjectName("DetailTitle")
        self.body.addWidget(title)

        found = importers.available_browsers()
        if not found:
            tip = QLabel("未检测到 Chrome / Edge / Brave 的本地数据。")
            tip.setObjectName("Empty")
            tip.setWordWrap(True)
            self.body.addWidget(tip)
            close = QPushButton("关闭")
            close.clicked.connect(self.reject)
            self.body.addWidget(close)
            return

        tip = QLabel("仅读取当前 Windows 用户自己保存的密码：")
        tip.setObjectName("Empty")
        tip.setWordWrap(True)
        self.body.addWidget(tip)

        self.combo = widgets.selection_combo()
        self.combo.addItems(found)
        self.body.addWidget(self.combo)

        bar = QHBoxLayout()
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        run = QPushButton("导入")
        run.setObjectName("Primary")
        run.clicked.connect(self._run)
        bar.addWidget(cancel)
        bar.addStretch()
        bar.addWidget(run)
        self.body.addLayout(bar)

    def _run(self) -> None:
        name = self.combo.currentText()
        self.result = importers.import_browser(name)
        if not self.result.ok:
            widgets.message(self, "导入失败", self.result.error, kind="error")
            return
        self.accept()


class WifiImportDialog(widgets.ShadowDialog):
    """从系统已保存的 Wi-Fi 配置中选择要导入的网络。"""

    def __init__(self, parent=None):
        super().__init__("从系统 Wi-Fi 导入", parent, width=360)
        self.result: importers.ImportResult | None = None

        title = QLabel("从系统 Wi-Fi 导入")
        title.setObjectName("DetailTitle")
        self.body.addWidget(title)

        self._status = QLabel("正在检测本机已保存的 Wi-Fi…")
        self._status.setObjectName("Empty")
        self._status.setWordWrap(True)
        self.body.addWidget(self._status)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setMaximumHeight(220)
        self._list_widget = QWidget()
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._checks: list[QCheckBox] = []
        self._scroll.setWidget(self._list_widget)
        self._scroll.hide()
        self.body.addWidget(self._scroll)

        bar = QHBoxLayout()
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        self._run_button = QPushButton("导入")
        self._run_button.setObjectName("Primary")
        self._run_button.setEnabled(False)
        self._run_button.clicked.connect(self._run)
        bar.addWidget(cancel)
        bar.addStretch()
        bar.addWidget(self._run_button)
        self.body.addLayout(bar)
        self._profile_worker: _WifiProfileWorker | None = None

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._start_profile_scan()

    def _start_profile_scan(self) -> None:
        if self._profile_worker is not None:
            return
        worker = _WifiProfileWorker(self)
        self._profile_worker = worker
        worker.completed.connect(self._on_profiles_loaded)
        worker.finished.connect(worker.deleteLater)
        worker.start()

    def _on_profiles_loaded(self, names: object, error: object) -> None:
        profiles = [str(name) for name in names] if isinstance(names, list) else []
        if error:
            self._status.setText("无法检测本机 Wi-Fi 配置，请稍后重试。")
            return
        if not profiles:
            self._status.setText("未检测到本机已保存的 Wi-Fi 配置。")
            return
        self._status.setText("仅读取当前 Windows 用户已保存的 Wi-Fi 密码：")
        for name in profiles:
            checkbox = QCheckBox(name)
            checkbox.setChecked(True)
            self._list_layout.addWidget(checkbox)
            self._checks.append(checkbox)
        self._list_layout.addStretch()
        self._scroll.show()
        self._run_button.setEnabled(True)

    def _run(self) -> None:
        names = [cb.text() for cb in self._checks if cb.isChecked()]
        if not names:
            widgets.message(self, "提示", "请至少选择一个 Wi-Fi 网络", kind="info")
            return
        self.result = importers.import_wifi(names)
        if not self.result.ok:
            widgets.message(self, "导入失败", self.result.error, kind="error")
            return
        self.accept()


class GeneratorDialog(widgets.ShadowDialog):
    def __init__(self, parent=None):
        super().__init__("生成密码", parent, width=380)
        self.result_password = ""

        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setObjectName("Search")
        self.body.addWidget(self.output)

        form = QFormLayout()
        self.length = QSpinBox()
        self.length.setRange(6, 64)
        self.length.setValue(18)
        self.length.valueChanged.connect(self._regen)
        form.addRow("长度", self.length)
        self.body.addLayout(form)

        opts = QHBoxLayout()
        self.upper = QCheckBox("大写")
        self.lower = QCheckBox("小写")
        self.digits = QCheckBox("数字")
        self.symbols = QCheckBox("符号")
        for cb in (self.upper, self.lower, self.digits, self.symbols):
            cb.setChecked(True)
            cb.toggled.connect(self._regen)
            opts.addWidget(cb)
        self.body.addLayout(opts)

        bar = QHBoxLayout()
        regen = QPushButton("重新生成")
        regen.clicked.connect(self._regen)
        use = QPushButton("使用")
        use.setObjectName("Primary")
        use.clicked.connect(self.accept)
        bar.addWidget(regen)
        bar.addStretch()
        bar.addWidget(use)
        self.body.addLayout(bar)

        self._regen()

    def _regen(self) -> None:
        self.output.setText(
            utils.generate_password(
                self.length.value(),
                upper=self.upper.isChecked(),
                lower=self.lower.isChecked(),
                digits=self.digits.isChecked(),
                symbols=self.symbols.isChecked(),
            )
        )

    def accept(self) -> None:
        self.result_password = self.output.text()
        super().accept()


class ProgramPickerDialog(widgets.ShadowDialog):
    """从当前运行进程中选择单个可执行文件。"""

    def __init__(self, selected: str, parent=None, *, title: str = "选择关联程序", verify_identity: bool = True):
        super().__init__(title, parent, width=420)
        self._verify_identity = verify_identity
        self.selected_program: str = selected.lower() if selected else ""
        self.selected_path = ""
        self.selected_signer_sha256 = ""

        title = widgets.icon_text(title, "key", object_name="DetailTitle", icon_size=24)
        self.body.addWidget(title)

        sub = QLabel("从运行中的程序列表选择，或手动输入程序名称。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(sub)

        self._search = QLineEdit()
        self._search.setPlaceholderText("筛选运行中的程序…")
        self._search.textChanged.connect(self._filter)
        self.body.addWidget(self._search)

        self._all_processes = window_tracker.running_process_identities()
        self._list = QListWidget()
        self._list.setFrameShape(QFrame.NoFrame)
        self._list.setMinimumHeight(200)
        self._list.setMaximumHeight(300)
        self._list.setSelectionMode(QAbstractItemView.SingleSelection)
        for name, path in self._all_processes:
            item = QListWidgetItem(name + (f"\n{path}" if path else ""))
            item.setData(Qt.UserRole, name.lower())
            item.setData(Qt.UserRole + 1, path)
            if name.lower() == self.selected_program:
                item.setSelected(True)
            self._list.addItem(item)
        self._list.currentRowChanged.connect(self._on_list_select)
        self._list.itemDoubleClicked.connect(self.accept)
        self.body.addWidget(self._list)

        self._manual = QLineEdit()
        self._manual.setPlaceholderText("或手动输入程序名，如：chrome.exe")
        if self.selected_program and self.selected_program not in {name.lower() for name, _path in self._all_processes}:
            self._manual.setText(self.selected_program)
        self._manual.textChanged.connect(self._on_manual_change)
        self.body.addWidget(self._manual)

        self.hint = QLabel("提示：仅填写可执行文件名称即可，如 chrome.exe")
        self.hint.setObjectName("Empty")
        self.hint.setWordWrap(True)
        self.body.addWidget(self.hint)

        self.body.addLayout(_confirm_bar(self, ok_text="确认", align="right"))

    def _filter(self, text: str) -> None:
        q = text.strip().lower()
        for i in range(self._list.count()):
            item = self._list.item(i)
            item.setHidden(not (not q or q in item.text().lower()))

    def _on_list_select(self, row: int) -> None:
        if row < 0:
            return
        self._manual.blockSignals(True)
        self._manual.clear()
        self._manual.blockSignals(False)

    def _on_manual_change(self, text: str) -> None:
        self._list.blockSignals(True)
        self._list.clearSelection()
        self._list.blockSignals(False)

    def accept(self) -> None:
        selected = self._list.currentItem()
        if selected is not None:
            self.selected_program = selected.data(Qt.UserRole)
            self.selected_path = str(selected.data(Qt.UserRole + 1) or "")
            from core import native_autofill

            self.selected_signer_sha256 = native_autofill.signer_certificate_sha256(self.selected_path) if self._verify_identity else ""
        else:
            manual = self._manual.text().strip().lower()
            self.selected_program = manual if manual else ""
            self.selected_path = ""
            self.selected_signer_sha256 = ""
        super().accept()


class NativeAutofillPickerDialog(widgets.ShadowDialog):
    """选择一个关联登录条目，列表中不呈现密码。"""

    def __init__(self, entries: list[Entry], process_name: str, parent=None, *, otp_sources: dict[str, Entry] | None = None, fallback: bool = False, can_save: bool = False, manual_focus: bool = False, reasons: dict[str, str] | None = None, available_roles: dict[str, tuple[str, ...]] | None = None):
        super().__init__("原生程序自动填充", parent, width=430)
        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.selected_entry: Entry | None = None
        self.action = "fill"
        self._otp_sources = otp_sources or {}
        self._manual_focus = manual_focus
        self._reasons = reasons or {}
        self._available_roles = available_roles

        self.body.addWidget(widgets.icon_text("选择要填充的账号", "key", object_name="DetailTitle", icon_size=24))
        target = QLabel(
            f"目标程序：{process_name}"
            + (" · 未找到关联条目，请搜索后选择" if fallback else "")
        )
        target.setObjectName("SettingNote")
        target.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.body.addWidget(target)

        self._search = QLineEdit()
        self._search.setPlaceholderText("搜索名称或账号…")
        self._search.textChanged.connect(self._filter_entries)
        self.body.addWidget(self._search)

        self._list = QListWidget()
        self._list.setObjectName("AutofillEntryList")
        self._list.setFrameShape(QFrame.NoFrame)
        self._list.setMinimumHeight(min(300, max(120, len(entries) * 58)))
        self._list.setSelectionMode(QAbstractItemView.SingleSelection)
        for entry in entries:
            title = entry.title.strip() or "未命名登录"
            account = entry.username.strip() or "未填写账号"
            item = QListWidgetItem()
            item.setData(Qt.UserRole, entry)
            item.setIcon(widgets.category_icon(SecretType.LOGIN))
            item.setSizeHint(QSize(0, 72))
            self._list.addItem(item)
        if self._list.count():
            self._list.setCurrentRow(0)
        if not manual_focus:
            self._list.itemClicked.connect(lambda _item: self.accept())
        self.body.addWidget(self._list)

        self._otp_timer = QTimer(self)
        self._otp_timer.setInterval(1000)
        self._otp_timer.timeout.connect(self._refresh_otp_rows)
        self._refresh_otp_rows()
        if self._otp_sources:
            self._otp_timer.start()

        note = QLabel(
            "当前程序未提供可识别的输入框。选择内容后，请在 30 秒内点回并清空目标输入框，再按自动填充快捷键；不会自动提交。"
            if manual_focus else
            "填充账号、密码和已关联动态码，不会自动提交；HOTP 仅在动态码写入成功后推进。"
        )
        note.setObjectName("Empty")
        note.setWordWrap(True)
        self.body.addWidget(note)
        self.remember_binding = QCheckBox(i18n.tr("记住此程序与条目的关联"))
        self.body.addWidget(self.remember_binding)
        self.remember_mapping = QCheckBox(i18n.tr("记住此输入框的字段类型"))
        self.remember_mapping.setVisible(manual_focus)
        self.body.addWidget(self.remember_mapping)
        if manual_focus:
            self._role_selector = QComboBox()
            self.body.addWidget(self._role_selector)
            self._manual_fill = QPushButton(i18n.tr("填入当前输入框"))
            self._manual_fill.setObjectName("Primary")
            self._manual_fill.clicked.connect(lambda: self._choose_manual(self._role_selector.currentData()))
            self._list.currentItemChanged.connect(lambda *_: self._refresh_manual_roles())
            self._refresh_manual_roles()
        buttons = QHBoxLayout()
        if can_save:
            create = QPushButton("新建当前账号")
            create.setObjectName("SettingsBtn")
            create.clicked.connect(lambda: self._choose_action("create"))
            buttons.addWidget(create)
            update = QPushButton("更新所选账号")
            update.setObjectName("SettingsBtn")
            update.clicked.connect(lambda: self._show_update_menu(update))
            buttons.addWidget(update)
        buttons.addStretch()
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        if manual_focus:
            buttons.addWidget(self._manual_fill)
        else:
            fill = QPushButton("填充")
            fill.setObjectName("Primary")
            fill.clicked.connect(self.accept)
            buttons.addWidget(fill)
        self.body.addLayout(buttons)

    def _refresh_manual_roles(self) -> None:
        from core.autofill_resolver import resolve_snapshot
        from core.autofill_sources import AUTOFILL_ROLES
        from .module_editor import AUTOFILL_ROLE_LABELS
        self._role_selector.clear()
        current = self._list.currentItem()
        if current is not None:
            entry = current.data(Qt.UserRole)
            roles = (self._available_roles.get(entry.id, ()) if self._available_roles is not None
                     else resolve_snapshot(entry, [entry, *self._otp_sources.values()]).values)
            for role in AUTOFILL_ROLES:
                if role in roles:
                    self._role_selector.addItem(i18n.tr(AUTOFILL_ROLE_LABELS.get(role, role)), role)
        self._manual_fill.setEnabled(self._role_selector.count() > 0)

    def _choose_manual(self, role: str) -> None:
        if not role or self._role_selector.findData(role) < 0:
            return
        self.action = f"manual_{role}"
        self.accept()

    def _refresh_otp_rows(self) -> None:
        for index in range(self._list.count()):
            item = self._list.item(index)
            entry = item.data(Qt.UserRole)
            title = entry.title.strip() or "未命名登录"
            account = entry.username.strip() or "未填写账号"
            reason = i18n.tr({"confirmed": "已记住关联", "exact": "程序匹配", "name": "名称相关", "manual": "手动搜索"}.get(self._reasons.get(entry.id), "程序匹配"))
            source = self._otp_sources.get(entry.id)
            if source is None:
                item.setText(f"{title}\n{account}\n{reason}")
                continue
            fields = otp.normalize_fields(source.otp_fields())
            code = otp.code_from_fields(fields)
            grouped = " ".join(code[i : i + 3] for i in range(0, len(code), 3))
            timing = "填充后计数 +1" if fields.get("type") == "hotp" else f"{otp.seconds_remaining(fields)}s"
            item.setText(f"{title}\n{account}  ·  {i18n.tr('动态码')} {grouped}  ·  {timing}\n{reason}")

    def _filter_entries(self, value: str) -> None:
        query = value.strip().casefold()
        first_visible = -1
        for index in range(self._list.count()):
            item = self._list.item(index)
            entry = item.data(Qt.UserRole)
            visible = not query or query in f"{entry.title} {entry.username}".casefold()
            item.setHidden(not visible)
            if visible and first_visible < 0:
                first_visible = index
        if first_visible >= 0:
            self._list.setCurrentRow(first_visible)
        else:
            self._list.clearSelection()
            self._list.setCurrentRow(-1)

    def _choose_action(self, action: str) -> None:
        if action == "update" and self._list.currentItem() is None:
            return
        self.action = action
        if action == "update":
            self.selected_entry = self._list.currentItem().data(Qt.UserRole)
        super().accept()

    def _show_update_menu(self, button: QPushButton) -> None:
        menu = QMenu(button)
        for index in range(self._list.count()):
            item = self._list.item(index)
            if item.isHidden():
                continue
            entry = item.data(Qt.UserRole)
            label = entry.title.strip() or entry.username.strip() or "未命名登录"
            action = menu.addAction(label)
            action.triggered.connect(lambda _checked=False, selected=entry: self._choose_update(selected))
        if menu.actions():
            menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def _choose_update(self, entry: Entry) -> None:
        self.action = "update"
        self.selected_entry = entry
        super().accept()

    def accept(self) -> None:
        if self._manual_focus and (not self.action.startswith("manual_") or self._role_selector.findData(self.action.removeprefix("manual_")) < 0):
            return
        current = self._list.currentItem()
        if current is None:
            return
        self.selected_entry = current.data(Qt.UserRole)
        super().accept()


class NativeAutofillExcludeDialog(widgets.ShadowDialog):
    """统一管理程序、网站与同步的安卓应用排除项。"""

    def __init__(self, parent=None, *, vault=None):
        super().__init__(i18n.tr("自动填充排除"), parent, width=480, simple_close=True)
        self._vault = vault
        self.body.setContentsMargins(24, 8, 24, 20)
        self.body.setSpacing(10)

        self.body.addWidget(
            widgets.icon_text(i18n.tr("自动填充排除"), "security", object_name="DetailTitle", icon_size=24)
        )
        note = QLabel(i18n.tr("添加排除项后，对应目标将不再显示自动填充建议。"))
        note.setObjectName("SettingNote")
        note.setWordWrap(True)
        self.body.addWidget(note)

        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText(i18n.tr("输入排除项，例如 chrome.exe 或 example.com"))
        self._input.returnPressed.connect(self._add_from_input)
        input_row.addWidget(self._input, 1)
        add_btn = QPushButton(i18n.tr("添加"))
        add_btn.setObjectName("SettingsBtn")
        add_btn.clicked.connect(self._add_from_input)
        input_row.addWidget(add_btn)
        self.body.addLayout(input_row)

        self._choose_program = QPushButton(i18n.tr("从运行中的程序选择…"))
        self._choose_program.setObjectName("SettingsBtn")
        self._choose_program.setToolTip(i18n.tr("选择正在运行的程序，包含后台程序"))
        self._choose_program.clicked.connect(self._select_running_program)
        self.body.addWidget(self._choose_program)

        self._list_container = QScrollArea()
        self._list_container.setWidgetResizable(True)
        self._list_container.setFrameShape(QFrame.NoFrame)
        self._list_container.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._list_container.setMaximumHeight(260)
        list_host = QWidget()
        self._list_lay = QVBoxLayout(list_host)
        self._list_lay.setContentsMargins(0, 0, 0, 0)
        self._list_lay.setSpacing(4)
        self._list_container.setWidget(list_host)
        self.body.addWidget(self._list_container)

        self._empty = QLabel(i18n.tr("暂未添加排除项"))
        self._empty.setObjectName("SettingNote")
        self._empty.setAlignment(Qt.AlignCenter)
        self.body.addWidget(self._empty)


        self._hint = QLabel()
        self._hint.setObjectName("SettingDangerNote")
        self._hint.setWordWrap(True)
        self._hint.setVisible(False)
        self.body.addWidget(self._hint)
        self._reload()

    def _excluded(self) -> list[str]:
        if self._vault is not None:
            return list(self._vault.autofill_exclusions["processes"])
        return [str(name) for name in (config.get("native_autofill_excluded", []) or [])]

    def _save(self, values: list[str]) -> bool:
        return self._save_category("processes", "native_autofill_excluded", values)

    def _save_category(self, category: str, key: str | None, values: list[str]) -> bool:
        try:
            if self._vault is not None:
                self._vault.set_autofill_exclusions(category, values)
                values = self._vault.autofill_exclusions[category]
            if key is not None:
                config.set(key, sorted(set(values)))
        except Exception as exc:
            self._warn(f"保存排除项失败：{exc}")
            return False
        return True

    def _warn(self, msg: str) -> None:
        self._hint.setText(msg)
        self._hint.setVisible(True)

    def _clear_hint(self) -> None:
        self._hint.setVisible(False)

    def _reload(self) -> None:
        while self._list_lay.count():
            item = self._list_lay.takeAt(0)
            if w := item.widget():
                w.deleteLater()
        exclusions = [
            ("processes", name) for name in self._excluded()
        ] + [
            ("hosts", name) for name in self._excluded_sites()
        ] + [
            ("packages", name)
            for name in (self._vault.autofill_exclusions["packages"] if self._vault is not None else [])
        ]
        for category, name in sorted(exclusions, key=lambda item: (item[1].casefold(), item[0])):
            row = QWidget()
            row.setProperty("exclusion_category", category)
            row.setProperty("exclusion_value", name)
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(0, 0, 0, 0)
            row_lay.setSpacing(8)
            label = QLabel(name)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row_lay.addWidget(label, 1)
            remove = widgets.icon_only_button(
                "close", i18n.tr("移除排除项"), size=16, width=30, height=30,
            )
            remove.setAccessibleName(i18n.tr("移除排除项") + " " + name)
            remove.clicked.connect(lambda _checked=False, c=category, value=name: self._remove_exclusion(c, value))
            row_lay.addWidget(remove)
            self._list_lay.addWidget(row)
        self._empty.setVisible(not exclusions)
        self._list_container.setVisible(bool(exclusions))

    def _remove_exclusion(self, category: str, value: str) -> None:
        key = {"processes": "native_autofill_excluded", "hosts": "browser_autofill_excluded_hosts", "packages": None}[category]
        if category == "processes":
            values = self._excluded()
        elif category == "hosts":
            values = self._excluded_sites()
        elif self._vault is not None:
            values = list(self._vault.autofill_exclusions["packages"])
        else:
            return
        if not self._save_category(category, key, [name for name in values if name != value]):
            return
        self._clear_hint()
        self._reload()

    def _add(self, value: str) -> None:
        from core import native_autofill

        normalized = native_autofill.normalize_process_name(value)
        if not normalized:
            self._warn(i18n.tr("请输入有效的程序名"))
            return
        values = self._excluded()
        if normalized in values:
            self._warn(i18n.tr("该程序已在排除清单中"))
            return
        values.append(normalized)
        if not self._save(values):
            return
        self._input.clear()
        self._clear_hint()
        self._reload()

    def _add_from_input(self) -> None:
        value = self._input.text().strip()
        if "://" not in value and value.strip('"').lower().endswith(".exe"):
            self._add(value)
        else:
            self._add_site(value)

    def _select_running_program(self) -> None:
        dialog = ProgramPickerDialog("", self, title="选择排除程序", verify_identity=False)
        if dialog.exec() == QDialog.Accepted and dialog.selected_program:
            self._add(dialog.selected_program)

    def _remove(self, value: str) -> None:
        values = [item for item in self._excluded() if item != value]
        if not self._save(values):
            return
        self._clear_hint()
        self._reload()

    def _excluded_sites(self) -> list[str]:
        if self._vault is not None:
            return list(self._vault.autofill_exclusions["hosts"])
        return [str(host) for host in (config.get("browser_autofill_excluded_hosts", []) or [])]

    def _add_site(self, value: str) -> None:
        from core.browser_autofill import normalize_excluded_host

        host = normalize_excluded_host(value)
        if not host:
            self._warn(i18n.tr("请输入程序名（如 chrome.exe）或有效的网站域名"))
            return
        values = self._excluded_sites()
        if host in values:
            self._warn("该网站已在排除清单中")
            return
        if not self._save_category("hosts", "browser_autofill_excluded_hosts", sorted({*values, host})):
            return
        self._input.clear()
        self._clear_hint()
        self._reload()


class ChangePasswordDialog(HintMixin, widgets.ShadowDialog):
    """修改当前用户的主密码：校验旧密码后用新密码重新加密整个库。"""

    def __init__(self, vault: Vault, parent=None, *, known_master: str | None = None):
        super().__init__("修改主密码", parent, width=380)
        self._vault = vault
        self._known_master = known_master  # 本会话已验证则跳过"当前主密码"输入

        title = widgets.icon_text("修改主密码", "key", object_name="DetailTitle", icon_size=24)
        sub = QLabel("修改后将立即用新密码重新加密整个密码库，请牢记新密码。")
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self.old_pw = QLineEdit()
        _password_row(self.old_pw, hint="当前主密码")
        self._warn_field = self.old_pw
        if known_master is None:
            self.body.addWidget(self.old_pw)
        else:
            self.old_pw.hide()
            self._warn_field = None

        _password_row(self.new_pw, hint="新主密码")

        self.new_pw2 = QLineEdit()
        _password_row(self.new_pw2, hint="再次输入新主密码")
        self.new_pw2.returnPressed.connect(self.accept)
        self.body.addWidget(self.new_pw2)
        self.high_security = QCheckBox("主密码高安全模式（拒绝未达到推荐强度的密码）")
        self.high_security.setChecked(True)
        self.body.addWidget(self.high_security)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.body.addWidget(self.hint)

        self.body.addLayout(_confirm_bar(self, ok_text="修改"))
        (self.new_pw if known_master is not None else self.old_pw).setFocus()

    def accept(self) -> None:
        old = self._known_master if self._known_master is not None else self.old_pw.text()
        if not self._vault.verify_password(old):
            self._warn("当前主密码不正确", self.old_pw)
            return
        new = self.new_pw.text()
        if new != self.new_pw2.text():
            self._warn("两次输入的新密码不一致", self.new_pw2)
            return
        if new == old:
            self._warn("新密码不能与当前密码相同", self.new_pw)
            return
        allowed, message = _master_password_policy_allows(self, new, self.high_security.isChecked())
        if not allowed:
            if message:
                self._warn(message, self.new_pw)
            return
        self._vault.change_password(new)
        super().accept()


class UpdateDialog(widgets.ShadowDialog):
    """Markdown 格式的版本更新通知。"""

    def __init__(self, parent, version: str, notes: str):
        super().__init__(f"发现新版本 v{version}", parent, width=500)
        viewer = widgets.MarkdownViewer(notes, min_height=360)
        viewer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.body.addWidget(viewer)

        bar = QHBoxLayout()
        bar.addStretch()
        later = QPushButton("稍后")
        later.clicked.connect(self.reject)
        bar.addWidget(later)
        download = QPushButton("下载更新")
        download.setObjectName("Primary")
        download.setDefault(True)
        download.clicked.connect(self.accept)
        bar.addWidget(download)
        self.body.addLayout(bar)


class _UpdateDownloadWorker(QThread):
    """后台下载、校验并安装新版本。

    安装阶段必须把 Popen 句柄留在这里并等它结束：原先 install_update() 的
    返回值被直接丢弃，UI 打印一句「安装程序将立即在后台运行」就退出，
    安装成功与否应用这边完全不知道。
    """

    progress = Signal(int, int)
    stage = Signal(object)
    finished_ok = Signal(str)
    failed = Signal(str)

    def __init__(self, info: updates.UpdateInfo, parent=None):
        super().__init__(parent)
        self._info = info

    def run(self) -> None:
        try:
            setup_path = updates.download_update(
                self._info,
                progress=lambda received, total: self.progress.emit(received, total),
                on_stage=self.stage.emit,
            )
            proc = updates.install_update(setup_path)
            self.stage.emit(updates.InstallStage.INSTALLING)
            code = updates.wait_for_install(proc)
            if code not in (0, None):
                self.failed.emit(i18n.tr("安装程序返回错误代码 {0}").format(code))
                return
            self.stage.emit(updates.InstallStage.DONE)
            self.finished_ok.emit(str(setup_path))
        except Exception as exc:  # pragma: no cover - UI thread boundary
            self.failed.emit(str(exc))


class UpdateDownloadDialog(widgets.ShadowDialog):
    """在应用内下载并安装新版本，逐阶段展示进度。

    四个阶段：下载（百分比）→ 校验 → 安装 → 完成。安装阶段起外部进程已经
    发出，用户点关闭只能得到一个「已经在装了」的半吊子状态，所以从校验开始
    就锁掉关闭键与取消按钮——让用户明确知道现在没有回头路。
    """

    def __init__(self, parent, info: updates.UpdateInfo):
        super().__init__(i18n.tr("下载更新 {0}").format(info.version), parent, width=440)
        self._info = info

        self._label = QLabel(i18n.tr("正在连接下载服务…"))
        self._label.setObjectName("Empty")
        self._label.setWordWrap(True)
        self.body.addWidget(self._label)

        self._bar = QProgressBar()
        # 复用传输页的进度条样式：theme 里没有裸 QProgressBar 规则，原先写
        # objectName("Progress") 会渲染成未主题化的原生外观。
        self._bar.setObjectName("TransferProgress")
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self.body.addWidget(self._bar)

        self._spinner = widgets.SpinnerWidget(self, size=22)
        self._spinner.setVisible(False)
        self._spinner_row = QHBoxLayout()
        self._spinner_row.addStretch()
        self._spinner_row.addWidget(self._spinner)
        self._spinner_row.addStretch()
        self.body.addLayout(self._spinner_row)

        bar = QHBoxLayout()
        bar.addStretch()
        self._cancel_btn = QPushButton(i18n.tr("取消"))
        self._cancel_btn.clicked.connect(self.reject)
        bar.addWidget(self._cancel_btn)
        self.body.addLayout(bar)

        self._worker = _UpdateDownloadWorker(info, self)
        self._worker.progress.connect(self._on_progress)
        self._worker.stage.connect(self._on_stage)
        self._worker.finished_ok.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._worker.deleteLater)

    def showEvent(self, event):
        # 构造期不 start：下载是十几秒起步的外部请求，进度条得让人先看见
        # 窗口再动，否则 exec() 还没来得及显示就开始计时了。
        super().showEvent(event)
        if not self._worker.isRunning():
            self._worker.start()

    def _on_progress(self, received: int, total: int) -> None:
        if total > 0:
            self._bar.setMaximum(100)
            self._bar.setValue(int(received * 100 / total))
            self._label.setText(
                i18n.tr("正在下载更新… {0} MB / {1} MB").format(received // 1048576, total // 1048576)
            )
        else:
            self._bar.setRange(0, 0)
            self._label.setText(i18n.tr("正在下载更新… {0} MB").format(received // 1048576))

    def _on_stage(self, stage: object) -> None:
        """切阶段文案。校验与安装都没有可换算的百分比，进度条走不确定态。"""
        if not isinstance(stage, updates.InstallStage):
            return
        if stage is updates.InstallStage.DOWNLOADING:
            return
        # 从校验开始就不能再让用户关窗了：安装器一旦启动，关闭只会让用户
        # 以为取消了，实际文件替换仍在进行。
        self.set_close_enabled(False)
        self._cancel_btn.setEnabled(False)
        self._bar.setRange(0, 0)
        self._spinner.setVisible(True)
        self._spinner.start()
        if stage is updates.InstallStage.VERIFYING:
            self._label.setText(i18n.tr("正在校验安装包完整性…"))
        elif stage is updates.InstallStage.INSTALLING:
            self._label.setText(
                i18n.tr("正在安装新版本…\n\n安装程序在后台运行，请勿关闭此窗口或手动结束安装程序。")
            )
        elif stage is updates.InstallStage.DONE:
            self._spinner.stop()
            self._spinner.setVisible(False)
            self._bar.setRange(0, 100)
            self._bar.setValue(100)
            self._label.setText(i18n.tr("安装完成。\n\n保险库即将退出，请重新启动以使用新版本。"))

    def _on_finished(self, setup_path: str) -> None:
        self._cancel_btn.setEnabled(False)
        self._bar.setRange(0, 100)
        self._bar.setValue(100)
        # 安装器已经确认退出成功，这里才允许收尾退出应用。
        QTimer.singleShot(1600, self.accept)

    def _on_failed(self, message: str) -> None:
        self._cancel_btn.setEnabled(True)
        self._spinner.stop()
        self._spinner.setVisible(False)
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        self._label.setText(i18n.tr("更新失败：{0}\n\n可前往官网发布页手动下载。").format(message))


class DocumentDialog(widgets.ShadowDialog):
    """显示项目 Markdown 文档。"""

    def __init__(self, title: str, path: Path, parent=None):
        super().__init__(title, parent, width=700)
        text = path.read_text(encoding="utf-8") if path.exists() else f"无法加载 {path.name}"

        viewer = widgets.MarkdownViewer(text, min_height=500)
        viewer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.body.addWidget(viewer)

        bar = QHBoxLayout()
        bar.addStretch()
        close_btn = QPushButton("关闭")
        close_btn.setObjectName("Primary")
        close_btn.clicked.connect(self.accept)
        bar.addWidget(close_btn)
        self.body.addLayout(bar)




class AccountRenameDialog(HintMixin, widgets.ShadowDialog):
    """自定义样式：输入新的账户名（替代原生 QInputDialog）。"""

    def __init__(self, old_name: str, existing_names: list[str], parent=None):
        super().__init__(i18n.tr("重命名账户"), parent, width=360)
        self.new_name: str | None = None
        self._old_name = old_name
        self._existing = set(existing_names) - {old_name}

        title = widgets.icon_text(i18n.tr("重命名账户"), "edit", object_name="DetailTitle", icon_size=24)
        sub = QLabel(i18n.tr("新账户名："))
        sub.setObjectName("Empty")
        self.body.addWidget(title)
        self.body.addWidget(sub)

        self.name_input = QLineEdit()
        self.name_input.setText(old_name)
        self.name_input.setMaxLength(64)
        self.name_input.returnPressed.connect(self.accept)
        self._warn_field = self.name_input
        self.body.addWidget(self.name_input)

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.body.addWidget(self.hint)

        self.body.addLayout(_confirm_bar(self, ok_text=i18n.tr("确定")))
        self.name_input.setFocus()
        self.name_input.selectAll()

    def accept(self) -> None:
        new = self.name_input.text().strip()
        if not new:
            self._warn(i18n.tr("账户名不能为空"))
            return
        if new == self._old_name:
            self._warn(i18n.tr("新账户名与原账户名相同"))
            return
        if new in self._existing:
            self._warn(i18n.tr("账户名已存在"))
            return
        self.new_name = new
        super().accept()


class BackupPasswordDialog(widgets.ShadowDialog):
    """导出/导入加密备份时输入独立的备份密码。"""

    def __init__(self, mode: str, parent=None):
        assert mode in ("export", "import")
        super().__init__("导出加密备份" if mode == "export" else "导入加密备份", parent, width=380)
        self.mode = mode
        self.password = ""

        title = widgets.icon_text(
            "导出加密备份" if mode == "export" else "导入加密备份",
            "backup" if mode == "export" else "backup-import",
            object_name="DetailTitle",
            icon_size=24,
        )
        self.body.addWidget(title)

        tip = QLabel("设置一个独立的备份密码，导入时需要它来解密。请妥善保管，遗失将无法恢复。" if mode == "export" else "请输入该备份文件的导出密码。")
        tip.setObjectName("Empty")
        tip.setWordWrap(True)
        self.body.addWidget(tip)

        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("备份密码")
        self.pw.setMaxLength(128)
        self.pw.returnPressed.connect(self.accept)
        self.body.addWidget(self.pw)

        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.Password)
        self.pw2.setPlaceholderText("再次输入备份密码")
        self.pw2.setMaxLength(128)
        self.pw2.returnPressed.connect(self.accept)
        if mode == "export":
            self.body.addWidget(self.pw2)

        ok_text = "导出" if mode == "export" else "导入"
        self.body.addLayout(_confirm_bar(self, ok_text=ok_text, align="right", auto_default=False))
        self.pw.setFocus()

    def accept(self) -> None:
        pw = self.pw.text()
        if not pw:
            widgets.message(self, "提示", "备份密码不能为空", kind="warn")
            return
        if self.mode == "export":
            if len(pw) < 4:
                widgets.message(self, "提示", "备份密码至少 4 位", kind="warn")
                return
            if pw != self.pw2.text():
                widgets.message(self, "提示", "两次输入的备份密码不一致", kind="warn")
                return
        self.password = pw
        super().accept()


class ArchivePasswordDialog(widgets.ShadowDialog):
    """导出压缩包时输入独立的导出口令（WinZip AES-256 加密）。"""

    def __init__(self, parent=None):
        super().__init__("导出压缩包", parent, width=380)
        self.password = ""

        title = widgets.icon_text(
            "导出压缩包", "backup", object_name="DetailTitle", icon_size=24,
        )
        self.body.addWidget(title)

        tip = QLabel(
            "压缩包内含解密后的明文（CSV、JSON、图片、附件），将用 AES-256 口令加密。"
            "请设置并妥善保管导出口令，遗失将无法解压。"
        )
        tip.setObjectName("Empty")
        tip.setWordWrap(True)
        self.body.addWidget(tip)

        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("导出口令")
        self.pw.setMaxLength(128)
        self.pw.returnPressed.connect(self.accept)
        self.body.addWidget(self.pw)

        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.Password)
        self.pw2.setPlaceholderText("再次输入导出口令")
        self.pw2.setMaxLength(128)
        self.pw2.returnPressed.connect(self.accept)
        self.body.addWidget(self.pw2)

        self.body.addLayout(_confirm_bar(self, ok_text="导出", align="right", auto_default=False))
        self.pw.setFocus()

    def accept(self) -> None:
        pw = self.pw.text()
        if not pw:
            widgets.message(self, "提示", "导出口令不能为空", kind="warn")
            return
        if len(pw) < 4:
            widgets.message(self, "提示", "导出口令至少 4 位", kind="warn")
            return
        if pw != self.pw2.text():
            widgets.message(self, "提示", "两次输入的导出口令不一致", kind="warn")
            return
        self.password = pw
        super().accept()


class TagFilterDialog(widgets.ShadowDialog):
    """导出前选择导出范围：全部条目，或仅某个标签下的条目。"""

    def __init__(self, tags: list[str], parent=None):
        super().__init__("选择导出范围", parent, width=360)
        self.tag: str | None = None

        title = widgets.icon_text("选择导出范围", "export", object_name="DetailTitle", icon_size=24)
        self.body.addWidget(title)

        tip = QLabel("可以导出全部条目，也可以只导出某个标签下的条目，便于分类备份。")
        tip.setObjectName("Empty")
        tip.setWordWrap(True)
        self.body.addWidget(tip)

        self.combo = widgets.selection_combo()
        self.combo.addItem(widgets.ui_icon("tag"), "全部条目", None)
        for t in tags:
            self.combo.addItem(widgets.ui_icon("tag"), f"仅「{t}」", t)
        self.body.addWidget(self.combo)

        self.body.addLayout(_confirm_bar(self, ok_text="继续", align="right", auto_default=False))

    def accept(self) -> None:
        self.tag = self.combo.currentData()
        super().accept()


class TagSortDialog(widgets.ShadowDialog):
    """Manually reorder the complete tag list for one category."""

    def __init__(self, tags: list[str], parent=None):
        super().__init__("排序标签", parent, width=420)
        from .tag_popup import _ReorderTagList

        self.ordered_tags = list(tags)
        hint = QLabel(i18n.tr("拖动标签调整顺序，保存后更新标签栏。"))
        hint.setObjectName("Empty")
        self.body.addWidget(hint)
        self.tag_list = _ReorderTagList()
        self.tag_list.setObjectName("TagManagerList")
        self.tag_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tag_list.setSpacing(4)
        self.tag_list.setMinimumHeight(180)
        self.tag_list.setMaximumHeight(320)
        for tag in tags:
            item = QListWidgetItem(tag)
            item.setData(Qt.UserRole, tag)
            self.tag_list.addItem(item)
        self.body.addWidget(self.tag_list)
        self.body.addLayout(_confirm_bar(self, ok_text="保存", align="right", auto_default=False))

    def accept(self) -> None:
        self.ordered_tags = [self.tag_list.item(index).data(Qt.UserRole) for index in range(self.tag_list.count())]
        super().accept()


class TagRenameDialog(HintMixin, widgets.ShadowDialog):
    """Choose a tag in the current category and rename it."""

    def __init__(self, tags: list[str], parent=None):
        super().__init__("重命名标签", parent, width=420)
        self._tags = list(tags)
        self.old_tag: str | None = None
        self.new_tag: str | None = None

        sub = QLabel(i18n.tr("选择需要重命名的标签。"))
        sub.setObjectName("Empty")
        sub.setWordWrap(True)
        self.body.addWidget(sub)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("搜索标签")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self._filter_tags)
        self.body.addWidget(self.filter_edit)

        self.tag_list = QListWidget()
        self.tag_list.setObjectName("TagManagerList")
        self.tag_list.setDragDropMode(QAbstractItemView.NoDragDrop)
        self.tag_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tag_list.setSpacing(4)
        self.tag_list.setMinimumHeight(180)
        self.tag_list.setMaximumHeight(300)
        self.tag_list.currentItemChanged.connect(self._prefill)
        self.body.addWidget(self.tag_list)

        self.new_name = QLineEdit()
        self.new_name.setPlaceholderText("新标签名称")
        self.new_name.setMaxLength(30)
        self.new_name.returnPressed.connect(self.accept)
        self._warn_field = self.new_name
        self.body.addWidget(self.new_name)
        self._filter_tags("")

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setWordWrap(True)
        self.hint.setVisible(False)
        self.body.addWidget(self.hint)

        buttons = _confirm_bar(self, ok_text="保存", align="right", auto_default=False)
        for index in range(buttons.count()):
            button = buttons.itemAt(index).widget()
            if isinstance(button, QPushButton):
                button.setMinimumWidth(104)
        self.body.addLayout(buttons)

        self._prefill()
    def _filter_tags(self, query: str) -> None:
        selected = self.tag_list.currentItem()
        selected_tag = selected.data(Qt.UserRole) if selected else None
        self.tag_list.clear()
        search = query.strip().casefold()
        for tag in self._tags:
            if search and search not in tag.casefold() and search not in pinyin_sort_key(tag):
                continue
            item = QListWidgetItem(tag)
            item.setData(Qt.UserRole, tag)
            self.tag_list.addItem(item)
        if self.tag_list.count():
            matches = self.tag_list.findItems(selected_tag, Qt.MatchExactly) if selected_tag else []
            self.tag_list.setCurrentItem(matches[0] if matches else self.tag_list.item(0))

    def _prefill(self, *_args) -> None:
        item = self.tag_list.currentItem()
        self.new_name.setText(item.data(Qt.UserRole) if item else "")
        self.new_name.selectAll()

    def accept(self) -> None:
        item = self.tag_list.currentItem()
        old = item.data(Qt.UserRole) if item else None
        new = self.new_name.text().strip()
        if old and not new:
            self._warn("新标签名称不能为空")
            return
        if "," in new or "，" in new:
            self._warn("标签名称不能包含逗号")
            return
        if old and new != old and new in self._tags:
            if not widgets.confirm(
                self,
                "合并标签",
                f"已存在标签「{new}」，重命名后两者将合并为同一个标签，此操作不可撤销。是否继续？",
                kind="warn",
            ):
                return
        if old and new != old:
            self.old_tag = old
            self.new_tag = new
        super().accept()


class BatchTagInputDialog(HintMixin, widgets.ShadowDialog):
    """批量添加／移入标签时输入标签名称的对话框。"""

    def __init__(self, title: str, prompt: str, parent=None, *, category: str | None = None, mode: str = "move"):
        super().__init__(title, parent, width=360)
        self.tag: str | None = None
        self.tags: list[str] = []
        self.mode = mode
        self._tag_buttons: dict[str, QPushButton] = {}

        self.hint = QLabel()
        self.hint.setObjectName("FieldError")
        self.hint.setVisible(False)
        self.hint.setWordWrap(True)
        self.body.addWidget(self.hint)

        tip = QLabel(prompt)
        tip.setObjectName("Empty")
        tip.setWordWrap(True)
        self.body.addWidget(tip)

        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("输入标签名称")
        self.tag_input.setMaxLength(300 if mode == "add" else 30)
        self.tag_input.textChanged.connect(self._update_tag_chips)
        self.body.addWidget(self.tag_input)

        vault = getattr(parent, "vault", None) if parent else None
        if vault:
            existing_tags = sorted({
                t for e in vault.entries
                if category is not None and e.secret_type == category
                for t in e.tags
            })
            if existing_tags:
                tag_label = QLabel("已有标签：")
                tag_label.setObjectName("FieldLabel")
                self.body.addWidget(tag_label)
                scroll = widgets.HScrollArea()
                chips_wrap = QWidget()
                chips_lay = QHBoxLayout(chips_wrap)
                chips_lay.setContentsMargins(0, 0, 0, 0)
                chips_lay.setSpacing(4)
                for tag in existing_tags:
                    btn = QPushButton(tag)
                    btn.setObjectName("FilterChip")
                    btn.setCursor(Qt.PointingHandCursor)
                    btn.clicked.connect(lambda _, t=tag: self._pick_tag(t))
                    self._tag_buttons[tag] = btn
                    chips_lay.addWidget(btn)
                chips_lay.addStretch()
                scroll.setWidget(chips_wrap)
                self.body.addWidget(scroll)

        self.body.addLayout(_confirm_bar(self, ok_text="确定"))

        self.tag_input.setFocus()

    def _pick_tag(self, tag: str) -> None:
        if self.mode == "add":
            current = self._split_tags(self.tag_input.text())
            self.tag_input.setText(", ".join(
                [value for value in current if value != tag] if tag in current else current + [tag]
            ))
        else:
            self.tag_input.setText(tag)

    @staticmethod
    def _split_tags(value: str) -> list[str]:
        return list(dict.fromkeys(t for t in re.split(r"[,，\s　]+", value.strip()) if t))

    def _update_tag_chips(self, *_args) -> None:
        selected = set(self._split_tags(self.tag_input.text())) if self.mode == "add" else {self.tag_input.text().strip()}
        for tag, button in self._tag_buttons.items():
            button.setProperty("active", "true" if tag in selected else "false")
            button.style().unpolish(button)
            button.style().polish(button)

    def accept(self) -> None:
        tags = self._split_tags(self.tag_input.text()) if self.mode == "add" else [self.tag_input.text().strip()]
        if not tags or not tags[0]:
            self._warn("请输入标签名称")
            return
        if self.mode == "move" and ("," in tags[0] or "，" in tags[0]):
            self._warn("标签名称不能包含逗号")
            return
        self.tags = tags
        self.tag = tags[0]
        super().accept()






class _MergeConflictDialog(widgets.ShadowDialog):
    """合并字段冲突解决弹窗——选择合并后的标题/用户名/密码。"""

    def __init__(
        self,
        titles: list[str],
        usernames: list[str],
        passwords: list[str],
        parent=None,
    ):
        super().__init__("合并冲突确认", parent, width=460)
        self.chosen: dict[str, str] = {"title": "", "username": "", "password": ""}

        note = QLabel("选中的条目包含不同的标题、用户名或密码，请指定合并后使用哪个。")
        note.setObjectName("Empty")
        note.setWordWrap(True)
        self.body.addWidget(note)

        self._fields: dict[str, tuple[QComboBox, list[str]]] = {}
        for field_name, label, options in (
            ("title", "合并后标题", titles),
            ("username", "合并后用户名", usernames),
            ("password", "合并后密码", passwords),
        ):
            caption = QLabel(label)
            caption.setObjectName("FieldLabel")
            self.body.addWidget(caption)
            cb = widgets.selection_combo()
            for opt in options:
                cb.addItem(opt if opt else "（空）", opt)
            self.body.addWidget(cb)
            self._fields[field_name] = (cb, options)

        bar = QHBoxLayout()
        cancel_btn = QPushButton("返回修改")
        cancel_btn.clicked.connect(self.reject)
        confirm_btn = QPushButton("确认合并")
        confirm_btn.setObjectName("Primary")
        confirm_btn.clicked.connect(self.accept)
        bar.addWidget(cancel_btn)
        bar.addStretch()
        bar.addWidget(confirm_btn)
        self.body.addLayout(bar)

    def accept(self) -> None:
        for field_name, (cb, _options) in self._fields.items():
            self.chosen[field_name] = cb.currentData() or ""
        super().accept()


class EntryDetailDialog(widgets.ShadowDialog):
    """只读条目详情弹窗（对齐 Android 详情页）。"""

    def __init__(self, entry: Entry, parent=None):
        title_text = entry.title or "未命名条目"
        super().__init__(title_text, parent, width=460)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumHeight(200)
        scroll.setMaximumHeight(500)
        content = QWidget()
        form = QVBoxLayout(content)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)

        # Type label
        type_lbl = QLabel(SecretType.LABELS.get(entry.secret_type, entry.secret_type))
        type_lbl.setObjectName("SettingNote")
        form.addWidget(type_lbl)

        # Standard fields
        fields = [
            ("用户名", entry.username),
            ("密码", entry.password),
            ("网址", entry.url),
            ("关联程序", entry.target_app),
            ("备注", entry.notes),
        ]
        for label, value in fields:
            if not value:
                continue
            caption = QLabel(label)
            caption.setObjectName("FieldLabel")
            form.addWidget(caption)
            val = QLabel(value)
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            if label == "密码":
                pw_row = QHBoxLayout()
                pw_edit = QLineEdit(value)
                widgets.add_password_reveal(pw_edit)
                pw_edit.setReadOnly(True)
                pw_row.addWidget(pw_edit, 1)
                form.addLayout(pw_row)
            else:
                form.addWidget(val)

        # Tags
        if entry.tags:
            tags_row = QHBoxLayout()
            tags_row.setSpacing(6)
            for t in entry.tags:
                lbl = QLabel(t)
                lbl.setObjectName("Tag")
                tags_row.addWidget(lbl)
            tags_row.addStretch()
            form.addLayout(tags_row)

        # Timestamps
        ts = QLabel(
            f"创建时间：{datetime.datetime.fromtimestamp(entry.created_at).strftime('%Y-%m-%d %H:%M')}\n"
            f"最后修改：{datetime.datetime.fromtimestamp(entry.updated_at).strftime('%Y-%m-%d %H:%M')}"
        )
        ts.setObjectName("SettingNote")
        form.addWidget(ts)

        form.addStretch()
        scroll.setWidget(content)
        self.body.addWidget(scroll)

        close_btn = QPushButton("关闭")
        close_btn.setObjectName("Primary")
        close_btn.clicked.connect(self.accept)
        self.body.addWidget(close_btn)




_FIELD_LABELS = {
    "card_number": "完整卡号",
    "cardholder": "持卡人姓名",
    "expiry": "有效期",
    "cvv": "CVV",
    "withdrawal_password": "取款密码",
    "bank": "发卡行",
    "bank_branch": "开户行名称",
    "bank_branch_code": "开户行行号",
    "full_name": "姓名",
    "id_number": "证件号码",
    "issue_date": "签发日期",
    "expiry_date": "到期日期",
    "issuing_authority": "签发机关",
    "ssid": "网络名称 (SSID)",
    "wifi_password": "Wi-Fi 密码",
    "security_type": "加密类型",
    "router_admin_url": "路由器管理地址",
    "admin_password": "管理密码",
    "service": "服务名称",
    "api_key": "API 凭证",
    "api_secret": "API Secret",
    "base_url": "Base URL",
    "scopes": "权限范围",
}
_FIELD_SECRET_KEYS = {"card_number", "cvv", "withdrawal_password", "id_number", "wifi_password", "admin_password", "api_key", "api_secret"}
_FIELD_SKIP_KEYS = {
    "card_number_last4",
    "card_images_b64",
    "id_images_b64",
    "_vault_import_source_created_at",
    "_vault_import_source_updated_at",
    "_vault_imported_at",
}


class ConflictDialog(widgets.ShadowDialog):
    """导入时，同名同账号但内容不同的冲突，交由用户人工处理。"""

    def __init__(self, existing: Entry, incoming: Entry, parent=None):
        super().__init__("发现冲突条目", parent, width=460)
        self.action = "skip"
        self.apply_all = False

        head = QLabel(f"「{existing.title} · {existing.username or '—'}」已存在，但内容不同：")
        head.setObjectName("Empty")
        head.setWordWrap(True)
        self.body.addWidget(head)

        self.body.addWidget(self._compare(existing, incoming))

        self.apply_all_cb = QCheckBox("对其余冲突也使用相同处理方式")
        self.body.addWidget(self.apply_all_cb)

        bar = QHBoxLayout()
        keep = QPushButton("保留现有")
        keep.clicked.connect(lambda: self._choose("skip"))
        overwrite = QPushButton("用导入版本覆盖")
        overwrite.setObjectName("Primary")
        overwrite.clicked.connect(lambda: self._choose("overwrite"))
        both = QPushButton("两者都保留")
        both.clicked.connect(lambda: self._choose("keep_both"))
        bar.addWidget(keep)
        bar.addWidget(both)
        bar.addStretch()
        bar.addWidget(overwrite)
        self.body.addLayout(bar)

    def _compare(self, existing: Entry, incoming: Entry) -> QWidget:
        box = QFrame()
        box.setObjectName("Card")
        lay = QFormLayout(box)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(8)

        def mask(p: str) -> str:
            return "•" * min(len(p), 12) if p else "—"

        rows = []
        if existing.secret_type != incoming.secret_type:
            rows.append(
                (
                    "类型",
                    SecretType.LABELS.get(existing.secret_type, existing.secret_type),
                    SecretType.LABELS.get(incoming.secret_type, incoming.secret_type),
                )
            )

        rows += [
            ("密码", mask(existing.password), mask(incoming.password)),
            ("网址", existing.url or "—", incoming.url or "—"),
            ("备注", existing.notes or "—", incoming.notes or "—"),
            ("标签", ", ".join(existing.tags) or "—", ", ".join(incoming.tags) or "—"),
        ]

        for key in {**existing.fields, **incoming.fields}:
            if key in _FIELD_SKIP_KEYS:
                continue
            old_v = str(existing.fields.get(key, "") or "")
            new_v = str(incoming.fields.get(key, "") or "")
            if old_v == new_v:
                continue
            if key in _FIELD_SECRET_KEYS:
                old_v, new_v = mask(old_v), mask(new_v)
            else:
                old_v, new_v = old_v or "—", new_v or "—"
            rows.append((_FIELD_LABELS.get(key, key), old_v, new_v))

        for label, old, new in rows:
            if old == new:
                continue
            cell = QLabel(f"现有：{old}\n导入：{new}")
            cell.setWordWrap(True)
            lay.addRow(label, cell)
        return box

    def _choose(self, action: str) -> None:
        self.action = action
        self.apply_all = self.apply_all_cb.isChecked()
        self.accept()
