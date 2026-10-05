"""Reusable module editor for vault entries."""

from __future__ import annotations

import copy
import hashlib
import mimetypes
import asyncio
import datetime as _datetime
import weakref
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QDate, QPointF, Qt, QRegularExpression, QSize, QThread, QTimer, Signal
from PySide6.QtGui import (
    QColor, QImage, QPainter, QPen, QPixmap, QRegularExpressionValidator,
)
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDateEdit, QDialog, QFileDialog, QFormLayout, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea, QSizePolicy, QSlider, QTextEdit,
    QVBoxLayout, QWidget,
)

from core import media_files, modules, otp, passkeys, window_tracker
from . import i18n, theme, widgets
from .image_preview import load_thumbnail_into

#: Markdown 模块编辑框的高度下限：模块多时也不允许被兄弟模块压扁到看不见。
_MARKDOWN_EDITOR_MIN_HEIGHT = 160


_ACTIVE_WORKERS: set[QThread] = set()

AUTOFILL_ROLE_LABELS = {
    "username": "用户名", "email": "邮箱", "password": "密码",
    "one_time_code": "一次性验证码", "full_name": "姓名", "phone": "电话",
    "country": "国家 / 地区", "region": "省 / 州", "city": "城市",
    "street_address": "详细地址", "postal_code": "邮编", "cardholder": "持卡人",
    "card_number": "卡号", "card_expiry": "有效期", "card_cvv": "安全码",
    "id_number": "证件号码", "api_key": "API 凭证", "api_secret": "API 密文",
    "host": "主机", "port": "端口", "database": "数据库", "ssid": "Wi-Fi 名称",
    "wifi_password": "Wi-Fi 密码", "recovery_answer": "恢复答案",
    "custom_text": "自定义文本", "custom_secret": "自定义密文",
}


class _FocusWheelMixin:
    """滚轮仅在控件获得焦点（点击后）时改变取值，否则忽略并让事件冒泡给外层滚动区域。

    解决模块卡片内的滑块 / 下拉框在列表滚动时被滚轮误改的问题。
    """

    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
        else:
            event.ignore()


class _FocusSlider(_FocusWheelMixin, QSlider):
    """滑块：滚轮需先点击聚焦，否则滚动外层列表。"""
    pass


class ModuleRemoveButton(QPushButton):
    """Small, theme-aware remove control without an icon asset or backdrop."""

    def __init__(self, tooltip: str, *, size: int = 24, parent=None):
        super().__init__(parent)
        self.setObjectName("ModuleRemoveButton")
        self.setFixedSize(size, size)
        self.setToolTip(tooltip)
        self.setAccessibleName(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAutoDefault(False)
        self.setDefault(False)

    def paintEvent(self, event) -> None:
        del event
        colors = theme.active()
        color = QColor(colors["danger"])
        if not self.isEnabled():
            color.setAlpha(80)
        elif self.isDown():
            color.setAlpha(150)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        hovered = self.underMouse() or self.hasFocus()
        if hovered and self.isEnabled():
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(colors["danger_soft"]))
            painter.drawRoundedRect(self.rect(), 10, 10)
        # 叉号笔必须新建，不能用 pen = painter.pen() 继承上面那支 NoPen：
        # setColor/setWidthF 改不回线条样式，两条 drawLine 会什么都不画，
        # 界面上只剩一坨粉色圆角块、叉号消失（点击拿到焦点后色块还会一直留着）。
        pen = QPen(color)
        pen.setWidthF(1.9)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        center_x = self.width() / 2.0
        center_y = self.height() / 2.0 + (1.0 if self.isDown() else 0.0)
        radius = 4.5
        painter.drawLine(
            QPointF(center_x - radius, center_y - radius),
            QPointF(center_x + radius, center_y + radius),
        )
        painter.drawLine(
            QPointF(center_x + radius, center_y - radius),
            QPointF(center_x - radius, center_y + radius),
        )
        painter.end()


class ModuleDragHandle(QWidget):
    moved = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(30, 34)
        self.setCursor(Qt.OpenHandCursor)
        self.setToolTip(i18n.tr("拖动以调整模块顺序"))
        self.setAccessibleName(i18n.tr("拖动以调整模块顺序"))
        self._press_y: float | None = None

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self.isEnabled():
            self._press_y = event.globalPosition().y()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if self._press_y is not None:
            distance = event.globalPosition().y() - self._press_y
            self._press_y = None
            self.setCursor(Qt.OpenHandCursor)
            if abs(distance) >= 24:
                self.moved.emit(1 if distance > 0 else -1)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:
        del event
        color = QColor(theme.active()["muted"])
        if not self.isEnabled():
            color.setAlpha(80)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        for x in (11, 19):
            for y in (10, 17, 24):
                painter.drawEllipse(QPointF(x, y), 1.6, 1.6)
        painter.end()


@dataclass(frozen=True)
class PasskeyStatus:
    code: str
    label: str
    detail: str


_PASSKEY_SYNCABLE = PasskeyStatus(
    "syncable",
    "已加密同步",
    "PC 可无损保存和同步；使用时需在已授权 Android 设备上释放访问密钥。",
)
_PASSKEY_DEVICE_BOUND = PasskeyStatus(
    "device_bound",
    "仅原设备可用",
    "私钥保存在绑定的 Android Keystore 中，PC 仅保存公开元数据。",
)
_PASSKEY_CONFLICT = PasskeyStatus(
    "key_conflict",
    "通行密钥冲突",
    "请在可信设备上保留正确凭据并重新同步。",
)
_PASSKEY_CORRUPT = PasskeyStatus(
    "corrupt",
    "通行密钥数据损坏",
    "请从可信设备重新同步该通行密钥。",
)


def _validated_passkey(module: object) -> tuple[PasskeyStatus, passkeys.ValidatedPasskey | None]:
    if type(module) is dict:
        config_value = module.get("config")
        conflict_status = (
            config_value.get("passkeyConflictStatus")
            if type(config_value) is dict
            else None
        )
        if type(conflict_status) is str and conflict_status == "key_mismatch":
            return _PASSKEY_CONFLICT, None
    module_type = module.get("type") if type(module) is dict else None
    if type(module_type) is not str or module_type != modules.PASSKEY:
        return _PASSKEY_CORRUPT, None
    try:
        parsed = passkeys.parse_record(module.get("value"))
        if parsed.key_mode == "syncable":
            return _PASSKEY_SYNCABLE, parsed
        return _PASSKEY_DEVICE_BOUND, parsed
    except Exception:
        return _PASSKEY_CORRUPT, None


def passkey_status(module: object) -> PasskeyStatus:
    """Return an immutable, fully redacted presentation status for a Passkey module."""
    return _validated_passkey(module)[0]


def passkey_display_rows(module: object) -> tuple[tuple[str, str], ...]:
    """Return only the validated, non-key Passkey fields permitted in PC UI."""
    _, parsed = _validated_passkey(module)
    if parsed is None:
        return ()
    value = parsed.value
    account = value.get("user_display_name") or value.get("user_name") or "—"
    rows = [
        ("依赖方", parsed.rp_id),
        ("账户", account),
        ("创建时间", value.get("created_at") or "—"),
        ("最后使用", value.get("last_used_at") or "从未使用"),
        ("计数器模式", "同步零计数"),
    ]
    if parsed.schema_version == 2:
        storage_mode = "待安全升级（旧版软件私钥）"
    elif parsed.key_mode == "syncable":
        storage_mode = "PMV 同步型"
    else:
        storage_mode = "本设备高安全性"
    rows.append(("存储模式", storage_mode))
    return tuple(rows)


def _image_dialog_start() -> str:
    pictures = Path.home() / "Pictures"
    return str(pictures if pictures.is_dir() else Path.home())


FIELD_LABELS = {
    "username": "用户名", "password": "密码", "api_key": "API Key", "api_secret": "API Secret",
    "ssid": "SSID", "wifi_password": "Wi-Fi 密码", "security_type": "加密类型",
    "router_admin_url": "管理地址", "admin_password": "管理密码", "host": "主机 / IP", "port": "端口",
    "private_key": "私钥", "fingerprint": "指纹", "engine": "数据库类型",
    "database": "数据库名", "secret": "密钥", "issuer": "发行方", "label": "账户名",
    "algorithm": "算法", "digits": "位数", "period": "周期", "type": "类型",
    "counter": "计数器", "otp_domains": "关联域名", "cardholder": "持卡人", "card_number": "卡号", "cvv": "CVV",
    "withdrawal_password": "取款密码", "expiry": "有效期", "bank": "银行",
    "card_type": "卡片类型", "card_name": "自定义卡证名称", "notes": "备注",
    "full_name": "姓名", "id_number": "证件号码",
    "issue_date": "签发日期", "expiry_date": "到期日期", "issuing_authority": "签发机关",
    "country": "国家 / 地区", "region": "省 / 州", "city": "城市", "address": "详细地址",
    "postal_code": "邮编", "question": "安全问题", "answer": "答案",
}

MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
MAX_ATTACHMENT_TOTAL_BYTES = 64 * 1024 * 1024
# 附件/图片数量理论上限：PMVE 支持大量媒体同时添加，仅保留格式与磁盘约束。
MAX_ATTACHMENTS = 10_000
MAX_IMAGES = 10_000

SELECT_OPTIONS = {
    modules.OTP: {
        "type": (("TOTP", "totp"), ("HOTP", "hotp")),
        "algorithm": (("SHA-1", "SHA1"), ("SHA-256", "SHA256"), ("SHA-512", "SHA512")),
        "digits": (("6 位", "6"), ("7 位", "7"), ("8 位", "8")),
        "period": (("30 秒", "30"), ("60 秒", "60")),
    },
    modules.WIFI: {
        "security_type": tuple((value, value) for value in modules.WIFI_SECURITY_OPTIONS),
    },
    modules.DATABASE: {
        "engine": tuple((value, value) for value in (
            "MySQL", "PostgreSQL", "SQL Server", "Oracle", "SQLite", "MongoDB", "Redis",
        )),
    },
    modules.CARD_DOCUMENT: {
        "card_type": tuple((label, stored) for stored, label in modules.CARD_TYPE_LABELS.items()),
    },
}


def _decode_qr_bytes(data: bytes) -> list[str]:
    """Decode every distinct QR payload in an image without accepting partial garbage."""
    import cv2
    import numpy as np

    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []
    payloads: list[str] = []
    try:
        import zxingcpp
        payloads.extend(result.text for result in zxingcpp.read_barcodes(image) if result.text)
    except Exception:
        pass
    detector = cv2.QRCodeDetector()
    logging_api = getattr(getattr(cv2, "utils", None), "logging", None)
    previous_log_level = logging_api.getLogLevel() if logging_api is not None else None
    if logging_api is not None:
        # 部分二维码带 ECI 头，OpenCV 会打印 WARN: qrcode.cpp ECI is not supported；
        # 解码结果不受影响，静音避免刷屏。
        logging_api.setLogLevel(logging_api.LOG_LEVEL_SILENT)
    try:
        try:
            ok, decoded, _points, _ = detector.detectAndDecodeMulti(image)
            if ok:
                payloads.extend(value for value in decoded if value)
        except Exception:
            pass
        if not payloads:
            value, _points, _ = detector.detectAndDecode(image)
            if value:
                payloads.append(value)
    finally:
        if previous_log_level is not None:
            logging_api.setLogLevel(previous_log_level)
    return list(dict.fromkeys(payloads))


def _parse_wifi_qr(raw: str) -> dict[str, str] | None:
    """Parse a standard WIFI QR payload with escaped delimiters and strict limits."""
    if not isinstance(raw, str) or len(raw) > 1024 or not raw.strip().lower().startswith("wifi:"):
        return None
    body = raw.strip()[5:].rstrip(";")
    fields: dict[str, str] = {}
    index = 0
    while index < len(body):
        key_end = body.find(":", index)
        if key_end < 0:
            break
        key = body[index:key_end].strip().upper()
        index = key_end + 1
        value: list[str] = []
        while index < len(body):
            char = body[index]
            if char == "\\" and index + 1 < len(body):
                value.append(body[index + 1])
                index += 2
                continue
            if char == ";":
                index += 1
                break
            value.append(char)
            index += 1
        fields[key] = "".join(value)
    ssid = fields.get("S", "")
    password = fields.get("P", "")
    if not ssid or len(ssid.encode("utf-8")) > 32 or len(password.encode("utf-8")) > 63:
        return None
    security = modules.normalize_wifi_security(fields.get("T", ""))
    return {"ssid": ssid, "wifi_password": password, "security_type": security}


class _CameraCaptureDialog(widgets.ShadowDialog):
    """Small OpenCV camera surface used for QR and document capture."""

    def __init__(self, *, qr_mode: bool, parent=None, qr_title: str = "扫描动态码"):
        super().__init__(qr_title if qr_mode else "拍摄证件", parent, width=700)
        import cv2

        self._cv2 = cv2
        self._qr_mode = qr_mode
        self.image_bytes: bytes | None = None
        self.qr_payloads: list[str] = []
        self._frame = None
        self._qr_scan_counter = 0
        self._qr_found = False
        self._document_stable = 0
        self._document_last_center = None
        self._document_last_quad = None
        logging_api = getattr(getattr(cv2, "utils", None), "logging", None)
        previous_log_level = logging_api.getLogLevel() if logging_api is not None else None
        if logging_api is not None:
            logging_api.setLogLevel(logging_api.LOG_LEVEL_SILENT)
        try:
            # 依次尝试 0-5 号摄像头，每个索引先试 DSHOW 再试 MSMF 驱动；
            # 全部不可用才判定为“未连接摄像头”。
            self._capture = None
            for index in range(6):
                opened = False
                for backend in (cv2.CAP_DSHOW, cv2.CAP_MSMF):
                    candidate = cv2.VideoCapture(index, backend)
                    if candidate.isOpened():
                        self._capture = candidate
                        opened = True
                        break
                    candidate.release()
                if opened:
                    break
        finally:
            if previous_log_level is not None:
                logging_api.setLogLevel(previous_log_level)
        if self._capture is None:
            raise RuntimeError("未检测到可用摄像头，或摄像头正被其他程序占用")

        self._preview = QLabel("正在启动摄像头…")
        self._preview.setAlignment(Qt.AlignCenter)
        self._preview.setMinimumSize(620, 360)
        self._preview.setStyleSheet("background:#111; color:#eee; border-radius:8px;")
        self.body.addWidget(self._preview)
        hint = QLabel("自动识别中，请将二维码完整对准画面" if qr_mode else "将卡片或证件放入画面，保持平整，检测到边缘后自动扫描")
        hint.setObjectName("SettingNote")
        hint.setAlignment(Qt.AlignCenter)
        self.body.addWidget(hint)

        actions = QHBoxLayout()
        actions.addStretch()
        cancel = QPushButton("取消")
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)
        if qr_mode:
            gallery = QPushButton("从图片文件识别")
            gallery.clicked.connect(self._pick_image)
            actions.addWidget(gallery)
        if qr_mode:
            capture = QPushButton("识别二维码")
            capture.setObjectName("Primary")
            capture.clicked.connect(self._take)
            actions.addWidget(capture)
        self.body.addLayout(actions)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update_frame)
        self._timer.start(33)

    def _auto_scan_qr(self, frame) -> None:
        """取景时自动解码二维码：识别到即自动完成，无需手动点击。"""
        if self._qr_found:
            return
        try:
            ok, encoded = self._cv2.imencode(
                ".jpg", frame, [self._cv2.IMWRITE_JPEG_QUALITY, 80]
            )
            if not ok:
                return
            payloads = _decode_qr_bytes(encoded.tobytes())
        except Exception:
            return
        if payloads:
            self._qr_found = True
            self.qr_payloads = payloads
            self.accept()

    def _pick_image(self) -> None:
        """从图片文件识别二维码（并入扫码 UI，不再单独设置入口按钮）。"""
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("选择二维码图片"), _image_dialog_start(),
            i18n.tr("图片 (*.png *.jpg *.jpeg *.webp *.bmp *.gif)"),
        )
        if not path:
            return
        try:
            data = Path(path).read_bytes()
            if len(data) > 32 * 1024 * 1024:
                raise ValueError("图片超过 32 MB")
            payloads = _decode_qr_bytes(data)
        except Exception as exc:
            widgets.message(self, "二维码识别失败", str(exc) or "无法读取图片。", kind="error")
            return
        if not payloads:
            widgets.message(self, "未识别到二维码", "所选图片中没有可识别的二维码。", kind="warn")
            return
        self.image_bytes = data
        self.qr_payloads = payloads
        self.accept()

    def _update_frame(self) -> None:
        ok, frame = self._capture.read()
        if not ok:
            return
        self._frame = frame
        preview_frame = frame.copy()
        if not self._qr_mode:
            self._qr_scan_counter += 1
            if self._qr_scan_counter % 4 == 0:
                self._auto_scan_document(frame)
            if self._document_last_quad is not None:
                self._cv2.polylines(preview_frame, [self._document_last_quad], True, (0, 220, 255), 2)
        rgb = self._cv2.cvtColor(preview_frame, self._cv2.COLOR_BGR2RGB)
        height, width, channels = rgb.shape
        image = QImage(rgb.data, width, height, channels * width, QImage.Format_RGB888).copy()
        self._preview.setPixmap(QPixmap.fromImage(image).scaled(
            self._preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation,
        ))
        if self._qr_mode:
            # 约每 165ms 解码一次，避免逐帧解码占用过高 CPU。
            self._qr_scan_counter += 1
            if self._qr_scan_counter % 5 == 0:
                self._auto_scan_qr(frame)

    def _auto_scan_document(self, frame) -> None:
        """Capture a stable card/document quadrilateral without a shutter click."""
        import numpy as np

        cv2 = self._cv2
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        quad = None
        for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:8]:
            if cv2.contourArea(contour) < frame.shape[0] * frame.shape[1] * 0.15:
                break
            polygon = cv2.approxPolyDP(contour, 0.025 * cv2.arcLength(contour, True), True)
            if len(polygon) == 4 and cv2.isContourConvex(polygon):
                quad = polygon.reshape(4, 2)
                break
        self._document_last_quad = quad
        if quad is None:
            self._document_stable = 0
            self._document_last_center = None
            return
        center = quad.mean(axis=0)
        if self._document_last_center is not None and np.linalg.norm(center - self._document_last_center) < min(frame.shape[:2]) * 0.08:
            self._document_stable += 1
        else:
            self._document_stable = 1
        self._document_last_center = center
        if self._document_stable < 4:
            return
        points = quad.astype("float32")
        ordered = np.array([
            points[np.argmin(points.sum(axis=1))], points[np.argmin(points[:, 1] - points[:, 0])],
            points[np.argmax(points.sum(axis=1))], points[np.argmax(points[:, 1] - points[:, 0])],
        ], dtype="float32")
        width = int(max(np.linalg.norm(ordered[1] - ordered[0]), np.linalg.norm(ordered[2] - ordered[3])))
        height = int(max(np.linalg.norm(ordered[3] - ordered[0]), np.linalg.norm(ordered[2] - ordered[1])))
        if width < 100 or height < 60:
            return
        target = np.array([[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]], dtype="float32")
        cropped = cv2.warpPerspective(frame, cv2.getPerspectiveTransform(ordered, target), (width, height))
        ok, encoded = cv2.imencode(".jpg", cropped, [cv2.IMWRITE_JPEG_QUALITY, 92])
        if ok:
            self.image_bytes = encoded.tobytes()
            self.accept()

    def _take(self) -> None:
        if self._frame is None:
            widgets.message(self, "摄像头未就绪", "尚未取得摄像头画面，请稍后重试。", kind="warn")
            return
        ok, encoded = self._cv2.imencode(".jpg", self._frame, [self._cv2.IMWRITE_JPEG_QUALITY, 92])
        if not ok:
            widgets.message(self, "拍摄失败", "无法编码摄像头画面。", kind="error")
            return
        self.image_bytes = encoded.tobytes()
        if self._qr_mode:
            self.qr_payloads = _decode_qr_bytes(self.image_bytes)
            if not self.qr_payloads:
                widgets.message(self, "未识别到二维码", "请调整距离、角度或光线后重试。", kind="warn")
                return
        self.accept()

    def done(self, result: int) -> None:
        self._timer.stop()
        self._capture.release()
        super().done(result)


class _OcrWorker(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def __init__(self, images: list[bytes], *, card_type: str = modules.CARD_BANK, parent=None):
        super().__init__(parent)
        self._images = images
        self._card_type = card_type

    def run(self) -> None:
        from core import ocr as ocr_core

        parser = ocr_core.parse_id_card if self._card_type == modules.CARD_ID_CARD else ocr_core.parse_credit_card
        result: dict[str, str] = {}
        try:
            for data in self._images:
                try:
                    text = ocr_core.ocr_image(data)
                except Exception:
                    continue
                allowed = set(modules.CARD_FIELDS.get(self._card_type, modules.CARD_FIELDS[modules.CARD_CUSTOM]))
                for key, value in parser(text).items():
                    if value and key in FIELD_LABELS and key in allowed:
                        result.setdefault(key, str(value))
        except Exception as exc:
            self.failed.emit(str(exc) or "OCR 识别失败")
            return
        if result:
            self.succeeded.emit(result)
        else:
            self.failed.emit("未识别到可填入的字段，请确认图片清晰且内容完整")


class _LocationWorker(QThread):
    succeeded = Signal(dict)
    failed = Signal(str)

    def run(self) -> None:
        async def _locate() -> dict[str, str]:
            from winrt.windows.devices.geolocation import Geolocator

            position = await Geolocator().get_geoposition_async()
            coordinate = position.coordinate
            point = coordinate.point.position
            civic = getattr(position, "civic_address", None)
            values = {
                "country": str(getattr(civic, "country", "") or ""),
                "region": str(getattr(civic, "state", "") or ""),
                "city": str(getattr(civic, "city", "") or ""),
                "postal_code": str(getattr(civic, "postal_code", "") or ""),
            }
            if not any(values.values()):
                values["address"] = f"{point.latitude:.6f}, {point.longitude:.6f}"
            return {key: value for key, value in values.items() if value}

        try:
            self.succeeded.emit(asyncio.run(_locate()))
        except ImportError:
            self.failed.emit("当前安装缺少 Windows 定位组件，请更新依赖后重试")
        except Exception as exc:
            self.failed.emit(str(exc) or "无法读取系统位置，请检查 Windows 定位权限")


class ModulePickerDialog(widgets.ShadowDialog):
    selected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(i18n.tr("添加模块"), parent, width=420)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(4, 4, 4, 8)
        layout.setSpacing(6)
        for group in modules.GROUPS:
            label = QLabel(i18n.tr(group))
            label.setObjectName("ModulePickerGroup")
            layout.addWidget(label)
            for module_type, spec in modules.CATALOG.items():
                if spec["group"] != group:
                    continue
                if module_type == modules.PASSKEY:
                    continue
                icon = widgets.module_icon(module_type)
                button = QPushButton(icon, i18n.tr(spec["title"]))
                button.setObjectName("PickerItem")
                button.setIconSize(QSize(22, 22))
                button.setCursor(Qt.PointingHandCursor)
                button.clicked.connect(lambda _=False, t=module_type: self._choose(t))
                layout.addWidget(button)
        layout.addStretch()
        scroll.setWidget(content)
        self.body.addWidget(scroll)

    def _choose(self, module_type: str) -> None:
        self.selected.emit(module_type)
        self.accept()


class ModuleCard(QFrame):
    changed = Signal()
    layout_changed = Signal()
    move_requested = Signal(object, int)
    delete_requested = Signal(object)

    def __init__(self, module: dict, parent=None):
        super().__init__(parent)
        self.module = copy.deepcopy(module)
        self._worker: QThread | None = None
        self.setObjectName("ModuleCard")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        module_type = str(module.get("type") or "")
        # Passkey 凭据只能由 Android Provider 维护；普通敏感模块仍可自由编排。
        provider_managed = module_type == modules.PASSKEY
        header_surface = QFrame(self)
        header_surface.setObjectName("ModuleCardHeader")
        header = QHBoxLayout(header_surface)
        header.setContentsMargins(12, 10, 8, 10)
        header.setSpacing(10)
        icon = QLabel(header_surface)
        icon.setObjectName("ModuleCardIcon")
        icon.setAlignment(Qt.AlignCenter)
        icon.setFixedSize(40, 40)
        icon.setPixmap(widgets.module_icon(module_type).pixmap(28, 28))
        header.addWidget(icon)
        title_column = QVBoxLayout()
        title_column.setContentsMargins(0, 0, 0, 0)
        title_column.setSpacing(2)
        default_title = str(modules.CATALOG.get(module_type, {}).get("title") or "未知模块")
        self._canonical_default_title = default_title
        self._localized_default_title = i18n.tr(default_title)
        if provider_managed:
            self.title = QLabel(i18n.tr("通行密钥"))
            self.title.setObjectName("FieldLabel")
        else:
            stored_title = str(module.get("title") or default_title)
            self._title_started_as_canonical_default = stored_title == default_title
            self.title = QLineEdit(self._localized_default_title if stored_title == default_title else stored_title)
            self.title.setObjectName("ModuleTitle")
            self.title.setPlaceholderText(modules.CATALOG.get(module.get("type"), {}).get("title", "模块名称"))
            self.title.textChanged.connect(self.changed)
        title_column.addWidget(self.title)
        self._build_sensitive_toggle(title_column, module_type)
        header.addLayout(title_column, 1)
        drag_handle = ModuleDragHandle(header_surface)
        drag_handle.setEnabled(not provider_managed)
        drag_handle.moved.connect(lambda delta: self.move_requested.emit(self, delta))
        header.addWidget(drag_handle)
        delete = ModuleRemoveButton(i18n.tr("删除模块"), size=36)
        delete.setEnabled(not bool(module.get("required")) and not provider_managed)
        if provider_managed:
            delete.setToolTip("Passkey 只能由 Android Passkey Provider 管理")
        delete.clicked.connect(lambda: self.delete_requested.emit(self))
        header.addWidget(delete)
        root.addWidget(header_surface)
        body = QVBoxLayout()
        body.setContentsMargins(14, 14, 14, 14)
        body.setSpacing(10)
        root.addLayout(body)
        root = body

        self._editors: dict[str, QWidget] = {}
        self._build_autofill_role(root, module_type)
        if module_type not in modules.CATALOG:
            note = QLabel("当前版本暂不支持此模块；数据将原样保留。")
            note.setObjectName("SettingDangerNote")
            root.addWidget(note)
            self.title.setReadOnly(True)
        elif module_type == modules.IMAGES:
            self._images = list(module.get("value") or []) if isinstance(module.get("value"), list) else []
            self._image_limit = MAX_IMAGES
            self._image_add_handler = self._add_images
            self._build_horizontal_image_strip(root)
            self._refresh_images()
        elif module_type == modules.ATTACHMENTS:
            self._attachments = [item for item in (module.get("value") or []) if isinstance(item, dict)]
            self._attachment_layout = QVBoxLayout()
            self._attachment_layout.setContentsMargins(0, 0, 0, 0)
            root.addLayout(self._attachment_layout)
            self._refresh_attachments()
            add_attachment = QPushButton("添加附件")
            add_attachment.clicked.connect(self._add_attachments)
            root.addWidget(add_attachment)
        elif module_type == modules.PASSKEY:
            rows = passkey_display_rows(module)
            for label, text in rows:
                if label == "最后使用" and text == "从未使用":
                    text = i18n.tr(text)
                elif label == "计数器模式":
                    text = i18n.tr(text)
                elif label == "存储模式":
                    text = i18n.tr(text)
                row = QLabel(f"{i18n.tr(label)}: {text}")
                row.setWordWrap(True)
                row.setObjectName("SettingNote")
                root.addWidget(row)
        elif module_type == modules.TARGET_APP:
            combo = widgets.selection_combo()
            combo.setEditable(True)
            combo.setInsertPolicy(QComboBox.NoInsert)
            current = str(module.get("value") or "")
            processes = window_tracker.running_processes()
            if current and current.lower() not in processes:
                processes.insert(0, current)
            combo.addItems(processes)
            combo.setCurrentText(current)
            combo.lineEdit().setPlaceholderText("选择运行中的程序或手动输入包名")
            combo.currentTextChanged.connect(self.changed)
            self._editors["value"] = combo
            app_row = QHBoxLayout()
            app_row.addWidget(combo, 1)
            choose = QPushButton("选择关联应用")
            choose.clicked.connect(combo.showPopup)
            app_row.addWidget(choose)
            root.addLayout(app_row)
        elif module_type == modules.BOOLEAN:
            checked = QCheckBox(i18n.tr("是"))
            checked.setChecked(module.get("value") is True or str(module.get("value") or "").lower() == "true")
            checked.toggled.connect(lambda on: checked.setText(i18n.tr("是" if on else "否")))
            checked.toggled.connect(self.changed)
            self._editors["value"] = checked
            root.addWidget(checked)
        elif module_type == modules.DATETIME:
            self._build_datetime(root)
        elif isinstance(module.get("value"), dict):
            self._build_compound(root, module_type)
        elif module_type == modules.MULTILINE:
            mode_row = QHBoxLayout()
            mode_row.setContentsMargins(0, 0, 0, 0)
            # 与页面顶部的档位切换条一致横向铺满，只把高度压到行内档。
            mode_toggle = widgets.CapsuleSegmentedControl(
                [("edit", i18n.tr("编辑")), ("view", i18n.tr("查看"))],
                current=0,
                height=30,
            )
            mode_toggle.setAccessibleName(i18n.tr("Markdown 显示模式"))
            mode_row.addWidget(mode_toggle)
            root.addLayout(mode_row)

            edit = QTextEdit()
            edit.setPlainText(str(module.get("value") or ""))
            edit.setAcceptRichText(False)
            edit.setPlaceholderText(i18n.tr("支持 Markdown：标题、列表、代码、表格等"))
            # 同一滚动区里模块多时，Expanding 的编辑框会被兄弟模块瓜分到最小高度而变得看不见。
            # 给一个高度下限，并改用 Minimum 策略不与兄弟争抢纵向空间。
            edit.setMinimumHeight(_MARKDOWN_EDITOR_MIN_HEIGHT)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            edit.textChanged.connect(self.changed)
            self._editors["value"] = edit
            root.addWidget(edit)

            preview = None
            preview_text = None

            def set_mode(index: int) -> None:
                nonlocal preview, preview_text
                show_view = index == 1
                edit.setVisible(not show_view)
                if show_view:
                    text = edit.toPlainText() or "*（空）*"
                    if preview is None:
                        preview = widgets.MarkdownViewer(text, min_height=220)
                        root.addWidget(preview)
                        preview_text = text
                    elif text != preview_text:
                        preview.set_markdown_text(text)
                        preview_text = text
                if preview is not None:
                    preview.setVisible(show_view)

            mode_toggle.changed.connect(set_mode)
            set_mode(mode_toggle.current_index())
        elif module_type == modules.TEXT:
            edit = QTextEdit()
            edit.setPlainText(str(module.get("value") or ""))
            edit.setAcceptRichText(False)
            edit.setFixedHeight(96)
            edit.textChanged.connect(self.changed)
            self._editors["value"] = edit
            root.addWidget(edit)
        else:
            edit = QLineEdit(str(module.get("value") or ""))
            if module_type == modules.PASSWORD or bool(module.get("sensitive")):
                widgets.add_password_reveal(edit)
            edit.textChanged.connect(self.changed)
            self._editors["value"] = edit
            if module_type == modules.PASSWORD or bool(module.get("sensitive")):
                root.addWidget(edit)
            else:
                root.addWidget(edit)

    def _build_sensitive_toggle(self, root: QVBoxLayout, module_type: str) -> None:
        # Passkey 由 Android Provider 托管，未识别模块只读；二者均不暴露敏感开关。
        if module_type == modules.PASSKEY or module_type not in modules.CATALOG:
            return
        spec = modules.CATALOG.get(module_type, {})
        locked = bool(spec.get("locked"))
        row = QHBoxLayout()
        row.setContentsMargins(0, 2, 0, 2)
        label = QLabel(i18n.tr("强制敏感" if locked else ("敏感模块" if self.module.get("sensitive") else "普通模块")))
        label.setObjectName("ModuleSensitivity")
        row.addWidget(label)
        switch = widgets.Switch()
        switch.setChecked(bool(self.module.get("sensitive")))
        switch.setEnabled(not locked)
        switch.setToolTip(
            i18n.tr("开启后，查看或复制此模块内容需先验证主密码（与 Android 端一致）。")
        )
        def update_sensitive(on: bool) -> None:
            label.setText(i18n.tr("敏感模块" if on else "普通模块"))
            self._on_sensitive_toggled()

        switch.toggled.connect(update_sensitive)
        row.addWidget(switch)
        root.addLayout(row)
        self._sensitive_switch = switch

    def _on_sensitive_toggled(self) -> None:
        self.module["sensitive"] = bool(self._sensitive_switch.isChecked())
        self.changed.emit()

    def _build_autofill_role(self, root: QVBoxLayout, module_type: str) -> None:
        roles = modules.autofill_role_options(module_type, sensitive=bool(self.module.get("sensitive")))
        if not roles:
            return
        config = self.module.get("config") if isinstance(self.module.get("config"), dict) else {}
        raw_role = config.get("autofill_role") if type(config.get("autofill_role")) is str else ""
        combo = widgets.selection_combo()
        blank_label = "按名称精确匹配" if module_type == modules.TEXT else "不自动填充"
        combo.addItem(i18n.tr(blank_label), "")
        for role in roles:
            combo.addItem(i18n.tr(AUTOFILL_ROLE_LABELS[role]), role)
        if raw_role and raw_role not in roles:
            combo.addItem(f"{i18n.tr('不可用')}: {raw_role}", raw_role)
        combo.setCurrentIndex(max(0, combo.findData(raw_role)))
        self._autofill_role_changed = False

        def mark_changed(_index: int) -> None:
            self._autofill_role_changed = True
            self.changed.emit()

        combo.currentIndexChanged.connect(mark_changed)
        root.addWidget(QLabel(i18n.tr("自动填充类型")))
        root.addWidget(combo)
        self._autofill_role = combo

    def _build_datetime(self, root: QVBoxLayout) -> None:
        config = self.module.get("config") if isinstance(self.module.get("config"), dict) else {}
        mode = str(config.get("mode") or "datetime")
        if mode not in {"date", "time", "datetime"}:
            mode = "datetime"

        mode_combo = widgets.selection_combo()
        for label, stored in (("仅日期", "date"), ("仅时间", "time"), ("日期和时间", "datetime")):
            mode_combo.addItem(i18n.tr(label), stored)
        mode_combo.setCurrentIndex(mode_combo.findData(mode))
        root.addWidget(QLabel(i18n.tr("日期时间类型")))
        root.addWidget(mode_combo)

        direct = QLineEdit(str(self.module.get("value") or ""))
        direct.setPlaceholderText({"date": "YYYY-MM-DD", "time": "HH:mm", "datetime": "YYYY-MM-DDTHH:mm"}[mode])
        root.addWidget(QLabel(i18n.tr("直接输入")))
        root.addWidget(direct)

        now = _datetime.datetime.now().replace(second=0, microsecond=0)
        current = direct.text()
        date_text = current.split("T", 1)[0] if "T" in current else current
        try:
            selected_date = _datetime.date.fromisoformat(date_text)
        except ValueError:
            selected_date = now.date()
        date_edit = QDateEdit(QDate(selected_date.year, selected_date.month, selected_date.day))
        date_edit.setCalendarPopup(True)
        date_edit.setDisplayFormat("yyyy-MM-dd")
        date_label = QLabel(i18n.tr("日历选择"))
        root.addWidget(date_label)
        root.addWidget(date_edit)

        time_text = current.split("T", 1)[-1] if "T" in current else current
        try:
            selected_time = _datetime.time.fromisoformat(time_text)
        except ValueError:
            selected_time = now.time()
        hour_label = QLabel()
        hour = _FocusSlider(Qt.Horizontal)
        hour.setRange(0, 23)
        hour.setValue(selected_time.hour)
        minute_label = QLabel()
        minute = _FocusSlider(Qt.Horizontal)
        minute.setRange(0, 59)
        minute.setValue(selected_time.minute)
        root.addWidget(hour_label)
        root.addWidget(hour)
        root.addWidget(minute_label)
        root.addWidget(minute)

        self._datetime_mode = mode_combo
        self._datetime_value = direct
        self._datetime_date = date_edit
        self._datetime_hour = hour
        self._datetime_minute = minute
        self._datetime_hour_label = hour_label
        self._datetime_minute_label = minute_label
        self._datetime_syncing = False

        def current_mode() -> str:
            return str(mode_combo.currentData() or "datetime")

        def update_labels() -> None:
            hour_label.setText(f"{i18n.tr('小时')}：{hour.value():02d}")
            minute_label.setText(f"{i18n.tr('分钟')}：{minute.value():02d}")
            uses_date = current_mode() != "time"
            uses_time = current_mode() != "date"
            date_label.setVisible(uses_date)
            date_edit.setVisible(uses_date)
            hour_label.setVisible(uses_time)
            hour.setVisible(uses_time)
            minute_label.setVisible(uses_time)
            minute.setVisible(uses_time)
            direct.setPlaceholderText({"date": "YYYY-MM-DD", "time": "HH:mm", "datetime": "YYYY-MM-DDTHH:mm"}[current_mode()])

        def compose_value() -> str:
            date_value = date_edit.date().toString("yyyy-MM-dd")
            time_value = f"{hour.value():02d}:{minute.value():02d}"
            if current_mode() == "date":
                return date_value
            if current_mode() == "time":
                return time_value
            return f"{date_value}T{time_value}"

        def picker_changed() -> None:
            if self._datetime_syncing:
                return
            self._datetime_syncing = True
            direct.setText(compose_value())
            self._datetime_syncing = False
            update_labels()
            self.changed.emit()

        def direct_changed(text: str) -> None:
            if not modules.valid_datetime_value(current_mode(), text):
                direct.setProperty("invalid", bool(text))
                direct.style().unpolish(direct)
                direct.style().polish(direct)
            else:
                direct.setProperty("invalid", False)
            self.changed.emit()

        def mode_changed() -> None:
            update_labels()
            picker_changed()

        mode_combo.currentIndexChanged.connect(mode_changed)
        date_edit.dateChanged.connect(picker_changed)
        hour.valueChanged.connect(picker_changed)
        minute.valueChanged.connect(picker_changed)
        direct.textChanged.connect(direct_changed)
        update_labels()

    def _add_images(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, i18n.tr("选择图片"), _image_dialog_start(),
            i18n.tr("图片 (*.png *.jpg *.jpeg *.webp *.gif)"),
        )
        for path in paths:
            if len(self._images) >= self._image_limit:
                widgets.message(self, "已达上限", f"此模块最多保存 {self._image_limit} 张图片。", kind="warn")
                break
            try:
                source = Path(path)
                if source.stat().st_size > 8 * 1024 * 1024:
                    widgets.message(self, "图片过大", f"{source.name} 超过 8 MB，已跳过。", kind="warn")
                    continue
                data = source.read_bytes()
            except OSError:
                continue
            image = QImage.fromData(data)
            if image.isNull():
                widgets.message(self, "无法读取", f"{Path(path).name} 不是受支持的图片，已跳过。", kind="warn")
                continue
            ref = media_files.import_file(source, "image", source.name)
            if ref not in self._images:
                self._images.append(ref)
        self._refresh_images()
        self.changed.emit()
        self.layout_changed.emit()

    def _delete_image(self, index: int) -> None:
        if index < 0 or index >= len(self._images):
            return
        self._images.pop(index)
        self._refresh_images()
        self.changed.emit()
        self.layout_changed.emit()

    def _add_attachments(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, i18n.tr("添加附件"), str(Path.home()), i18n.tr("所有文件 (*)"),
        )
        existing = {str(item.get("sha256") or "") for item in self._attachments}
        total = sum(int(item.get("size") or 0) for item in self._attachments)
        for path in paths:
            if len(self._attachments) >= MAX_ATTACHMENTS:
                widgets.message(self, "已达上限", f"每个附件模块最多保存 {MAX_ATTACHMENTS} 个文件。", kind="warn")
                break
            try:
                source = Path(path)
                size = source.stat().st_size
                if size <= 0 or size > MAX_ATTACHMENT_BYTES:
                    raise ValueError("单个附件必须大于 0 字节且不超过 16 MB")
                if total + size > MAX_ATTACHMENT_TOTAL_BYTES:
                    raise ValueError("单个附件模块总容量不能超过 64 MB")
                ref = media_files.import_file(source, "attachment", source.name)
                digest = media_files.value_sha256(ref)
                if digest in existing:
                    continue
                self._attachments.append({
                    "name": source.name[:255],
                    "mime": mimetypes.guess_type(source.name)[0] or "application/octet-stream",
                    "size": size,
                    "sha256": digest,
                    "data": ref,
                })
                existing.add(digest)
                total += size
            except (OSError, ValueError) as exc:
                widgets.message(self, "无法添加附件", f"{Path(path).name}：{exc}", kind="warn")
        self._refresh_attachments()
        self.changed.emit()
        self.layout_changed.emit()

    def _refresh_attachments(self) -> None:
        while self._attachment_layout.count():
            item = self._attachment_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        for index, attachment in enumerate(self._attachments):
            row_widget = QWidget()
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(0, 0, 0, 0)
            name = str(attachment.get("name") or "附件")
            size = int(attachment.get("size") or 0)
            row.addWidget(QLabel(f"{name}  ·  {size / 1024:.1f} KB"), 1)
            save = QPushButton("导出")
            save.clicked.connect(lambda _=False, i=index: self._export_attachment(i))
            row.addWidget(save)
            remove = QPushButton("删除")
            remove.clicked.connect(lambda _=False, i=index: self._delete_attachment(i))
            row.addWidget(remove)
            self._attachment_layout.addWidget(row_widget)

    def _export_attachment(self, index: int) -> None:
        if not 0 <= index < len(self._attachments):
            return
        item = self._attachments[index]
        name = Path(str(item.get("name") or "attachment.bin")).name
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("导出附件"), str(Path.home() / name), i18n.tr("所有文件 (*)"),
        )
        if not path:
            return
        try:
            destination = Path(path)
            media_files.export_value(item.get("data") or "", destination)
            digest = hashlib.sha256()
            with destination.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            if destination.stat().st_size != int(item.get("size") or -1) or digest.hexdigest() != item.get("sha256"):
                destination.unlink(missing_ok=True)
                raise ValueError("附件完整性校验失败")
        except (OSError, ValueError) as exc:
            widgets.message(self, "导出失败", str(exc), kind="error")

    def _delete_attachment(self, index: int) -> None:
        if 0 <= index < len(self._attachments):
            self._attachments.pop(index)
            self._refresh_attachments()
            self.changed.emit()
            self.layout_changed.emit()

    def _refresh_images(self) -> None:
        while self._image_grid.count():
            item = self._image_grid.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        items: list[QWidget] = []
        for index, encoded in enumerate(self._images):
            tile = QWidget()
            tile.setFixedSize(112, 112)
            preview = QLabel(tile)
            preview.setGeometry(0, 0, 112, 112)
            preview.setAlignment(Qt.AlignCenter)
            preview.setCursor(Qt.PointingHandCursor)
            preview.setStyleSheet("background: palette(alternate-base); border: 1px solid palette(mid); border-radius: 8px;")
            load_thumbnail_into(preview, encoded, 106, 106)
            preview.mousePressEvent = lambda event, value=index: self._preview_image(value)
            remove = ModuleRemoveButton(i18n.tr("删除图片"), size=26, parent=tile)
            remove.move(82, 4)
            remove.clicked.connect(lambda _=False, value=index: self._delete_image(value))
            remove.raise_()
            items.append(tile)
        add = QPushButton("＋\n添加图片")
        add.setObjectName("ImageAddTile")
        add.setToolTip("添加图片")
        add.setFixedSize(112, 112)
        add.setEnabled(len(self._images) < self._image_limit)
        add.clicked.connect(self._image_add_handler)
        items.append(add)
        for position, widget in enumerate(items):
            self._image_grid.addWidget(widget)
        self._image_grid.addStretch()
        self.updateGeometry()

    def _build_horizontal_image_strip(self, root: QVBoxLayout) -> None:
        scroll = widgets.HScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setFixedHeight(124)

        inner = QWidget()
        self._image_grid = QHBoxLayout(inner)
        self._image_grid.setContentsMargins(0, 4, 0, 4)
        self._image_grid.setSpacing(8)
        scroll.setWidget(inner)
        root.addWidget(scroll)

    def _preview_image(self, index: int) -> None:
        if index < 0 or index >= len(self._images):
            return
        # 延迟导入避免 module_editor 与 dialogs 的模块级循环依赖。
        from .dialogs import show_image_viewer

        show_image_viewer(self._images, self, initial_index=index)

    def _build_compound(self, root: QVBoxLayout, module_type: str) -> None:
        if module_type == modules.OTP:
            camera = QPushButton("摄像头扫码")
            camera.clicked.connect(self._scan_otp_camera)
            root.addWidget(camera)
        elif module_type == modules.WIFI:
            camera = QPushButton("摄像头扫码")
            camera.clicked.connect(self._scan_wifi_camera)
            root.addWidget(camera)
        elif module_type == modules.CARD_DOCUMENT:
            stored_images = self.module.get("value", {}).get("images", [])
            self._images = list(stored_images) if isinstance(stored_images, list) else []
            self._image_limit = 2
            self._image_add_handler = self._scan_document_camera
            self._build_horizontal_image_strip(root)
            self._refresh_images()
            actions = QHBoxLayout()
            camera = QPushButton("扫描卡证")
            camera.clicked.connect(lambda _=False: self._scan_document_camera())
            actions.addWidget(camera, 1)
            self._document_scan_button = camera
            root.addLayout(actions)
        elif module_type == modules.ADDRESS:
            locate = QPushButton("使用当前位置")
            locate.clicked.connect(self._locate_address)
            self._locate_button = locate
            root.addWidget(locate)

        form = QFormLayout()
        mandatory = modules.mandatory_sensitive_fields(module_type)
        choices = SELECT_OPTIONS.get(module_type, {})
        template = modules.CATALOG.get(module_type, {}).get("default", {})
        field_values = dict(template) if isinstance(template, dict) else {}
        field_values.update(self.module["value"])
        if module_type == modules.CARD_DOCUMENT:
            card_type = str(field_values.get("card_type") or modules.CARD_BANK)
            field_values = modules.card_value_for_type(field_values, card_type)
            for keys in modules.CARD_FIELDS.values():
                for key in keys:
                    field_values.setdefault(key, "")
        ordered_values = modules.ordered_value({"type": module_type, "value": field_values})
        otp_advanced = {"algorithm", "digits", "period", "type", "counter"} if module_type == modules.OTP else set()
        self._otp_advanced_visible = False
        self._otp_advanced_editors: dict[str, QWidget] = {}
        self._card_row_widgets: dict[str, QWidget] = {}
        for key, initial in ordered_values.items():
            if key == "images":
                continue
            if key in choices:
                edit = widgets.selection_combo()
                for label, stored in choices[key]:
                    edit.addItem(i18n.tr(label), stored)
                index = edit.findData(str(initial or ""))
                if index < 0 and str(initial or ""):
                    edit.addItem(f"{initial}（自定义）", str(initial))
                    index = edit.count() - 1
                edit.setCurrentIndex(max(0, index))
                edit.currentIndexChanged.connect(self.changed)
                field_widget: QWidget = edit
            elif key == "private_key":
                edit = QTextEdit(str(initial or ""))
                edit.setFixedHeight(88)
                edit.textChanged.connect(self.changed)
                field_widget = edit
            else:
                edit = QLineEdit(str(initial or ""))
                if key in {"port", "counter", "card_number", "cvv", "postal_code"}:
                    max_digits = {"port": 5, "counter": 20, "card_number": 19, "cvv": 4, "postal_code": 12}[key]
                    edit.setMaxLength(max_digits)
                    edit.setValidator(QRegularExpressionValidator(QRegularExpression(rf"\d{{0,{max_digits}}}"), edit))
                edit.textChanged.connect(self.changed)
                field_widget = edit
            if key in mandatory and isinstance(edit, (QLineEdit, QTextEdit)):
                if isinstance(edit, QLineEdit):
                    widgets.add_password_reveal(edit)
            self._editors[key] = edit
            form.addRow(i18n.tr(FIELD_LABELS.get(key, key)), field_widget)
            if module_type == modules.CARD_DOCUMENT:
                self._card_row_widgets[key] = field_widget
            if key in otp_advanced:
                self._otp_advanced_editors[key] = field_widget
                form.setRowVisible(field_widget, False)
        root.addLayout(form)
        if module_type == modules.CARD_DOCUMENT:
            def refresh_card_template() -> None:
                active_type = self._card_type_value()
                active = (set(modules.CARD_FIELDS.get(active_type, modules.CARD_FIELDS[modules.CARD_CUSTOM])) | {"images"}) - {"notes"}
                for key, widget in self._card_row_widgets.items():
                    form.setRowVisible(widget, key in active)
                if hasattr(self, "_document_scan_button"):
                    self._document_scan_button.setVisible(True)
                self.changed.emit()
                self.layout_changed.emit()

            card_type_editor = self._editors.get("card_type")
            if isinstance(card_type_editor, QComboBox):
                card_type_editor.currentIndexChanged.connect(refresh_card_template)
            for key, editor in self._editors.items():
                if key != "card_type" and isinstance(editor, (QLineEdit, QTextEdit)):
                    editor.textChanged.connect(refresh_card_template)
            QTimer.singleShot(0, refresh_card_template)
        if module_type == modules.OTP:
            toggle_wrap = QWidget()
            toggle_lay = QHBoxLayout(toggle_wrap)
            toggle_lay.setContentsMargins(0, 0, 0, 0)
            toggle_lay.addStretch()
            toggle = QPushButton("⌄  高级选项")
            toggle.setObjectName("Ghost")
            toggle.setToolTip("显示高级选项")
            toggle_lay.addWidget(toggle)
            toggle_lay.addStretch()
            root.addWidget(toggle_wrap)

            def _toggle_otp_advanced(shown: bool) -> None:
                self._otp_advanced_visible = shown
                for widget in self._otp_advanced_editors.values():
                    form.setRowVisible(widget, shown)
                toggle.setText("⌃  高级选项" if shown else "⌄  高级选项")
                toggle.setToolTip("隐藏高级选项" if shown else "显示高级选项")

            toggle.clicked.connect(lambda: _toggle_otp_advanced(not self._otp_advanced_visible))
            _toggle_otp_advanced(False)

    def _card_type_value(self) -> str:
        editor = self._editors.get("card_type")
        if isinstance(editor, QComboBox):
            return str(editor.currentData() or modules.CARD_BANK)
        value = self.module.get("value") if isinstance(self.module.get("value"), dict) else {}
        return str(value.get("card_type") or modules.CARD_BANK)

    def _apply_fields(self, values: dict[str, str], *, overwrite: bool = False) -> None:
        applied = 0
        for key, value in values.items():
            editor = self._editors.get(key)
            if editor is None or not str(value).strip():
                continue
            current = self._editor_text(editor)
            if current and not overwrite:
                continue
            if isinstance(editor, QComboBox):
                index = editor.findData(str(value))
                if index < 0:
                    editor.addItem(f"{value}（自定义）", str(value))
                    index = editor.count() - 1
                editor.setCurrentIndex(index)
                applied += 1
            elif isinstance(editor, QTextEdit):
                editor.setPlainText(str(value))
                applied += 1
            else:
                editor.setText(str(value))
                applied += 1
        if applied:
            self.changed.emit()

    @staticmethod
    def _editor_text(editor: QWidget) -> str:
        if isinstance(editor, QComboBox):
            data = editor.currentData()
            return str(data if data is not None else editor.currentText())
        if isinstance(editor, QTextEdit):
            return editor.toPlainText()
        if isinstance(editor, QCheckBox):
            return "true" if editor.isChecked() else "false"
        return editor.text() if isinstance(editor, QLineEdit) else ""

    def _choose_otp(self, payloads: list[str]) -> str | None:
        valid = [(payload, otp.parse_otpauth_uri(payload)) for payload in payloads]
        valid = [(payload, fields) for payload, fields in valid if fields]
        if not valid:
            widgets.message(self, "未识别到动态码", "图片中没有有效的 TOTP/HOTP 二维码。", kind="warn")
            return None
        if len(valid) == 1:
            return valid[0][0]
        dialog = widgets.ShadowDialog("选择动态码", self, width=440)
        combo = widgets.selection_combo()
        for payload, fields in valid:
            name = fields.get("issuer") or fields.get("label") or "动态码"
            combo.addItem(f"{name} ({fields['type'].upper()})", payload)
        dialog.body.addWidget(QLabel(f"检测到 {len(valid)} 个有效动态码，请选择要导入的项目。"))
        dialog.body.addWidget(combo)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("取消")
        cancel.clicked.connect(dialog.reject)
        buttons.addWidget(cancel)
        use = QPushButton("导入")
        use.setObjectName("Primary")
        use.clicked.connect(dialog.accept)
        buttons.addWidget(use)
        dialog.body.addLayout(buttons)
        return str(combo.currentData()) if dialog.exec() == QDialog.Accepted else None

    def _apply_otp_payloads(self, payloads: list[str]) -> None:
        selected = self._choose_otp(payloads)
        if selected:
            self._apply_fields(otp.parse_otpauth_uri(selected), overwrite=True)

    def _scan_otp_camera(self) -> None:
        try:
            dialog = _CameraCaptureDialog(qr_mode=True, parent=self)
        except Exception as exc:
            widgets.message(self, "摄像头不可用", str(exc), kind="warn")
            return
        if dialog.exec() == QDialog.Accepted:
            self._apply_otp_payloads(dialog.qr_payloads)

    def _choose_wifi(self, payloads: list[str]) -> dict[str, str] | None:
        valid = [(payload, _parse_wifi_qr(payload)) for payload in payloads]
        valid = [(payload, fields) for payload, fields in valid if fields]
        if not valid:
            widgets.message(self, "未识别到 Wi-Fi", "图片中没有有效的 Wi-Fi 二维码。", kind="warn")
            return None
        if len(valid) == 1:
            return valid[0][1]
        dialog = widgets.ShadowDialog("选择 Wi-Fi 网络", self, width=440)
        combo = widgets.selection_combo()
        for _payload, fields in valid:
            combo.addItem(f"{fields['ssid']} ({fields['security_type']})", fields)
        dialog.body.addWidget(combo)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("取消")
        cancel.clicked.connect(dialog.reject)
        buttons.addWidget(cancel)
        confirm = QPushButton("导入")
        confirm.setObjectName("Primary")
        confirm.clicked.connect(dialog.accept)
        buttons.addWidget(confirm)
        dialog.body.addLayout(buttons)
        return dict(combo.currentData()) if dialog.exec() == QDialog.Accepted else None

    def _apply_wifi_payloads(self, payloads: list[str]) -> None:
        fields = self._choose_wifi(payloads)
        if not fields:
            return
        for key in ("ssid", "wifi_password", "security_type"):
            editor = self._editors.get(key)
            value = fields[key]
            if isinstance(editor, QComboBox):
                index = editor.findData(value)
                if index < 0:
                    editor.addItem(f"{value}（自定义）", value)
                    index = editor.count() - 1
                editor.setCurrentIndex(index)
            elif isinstance(editor, QLineEdit):
                editor.setText(value)
        self.changed.emit()

    def _scan_wifi_camera(self) -> None:
        try:
            dialog = _CameraCaptureDialog(qr_mode=True, parent=self, qr_title="扫描 Wi-Fi 二维码")
        except Exception as exc:
            widgets.message(self, "摄像头不可用", str(exc), kind="warn")
            return
        if dialog.exec() == QDialog.Accepted:
            self._apply_wifi_payloads(dialog.qr_payloads)

    def _scan_document_images(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            i18n.tr("选择银行卡图片"),
            _image_dialog_start(),
            i18n.tr("图片 (*.png *.jpg *.jpeg *.webp *.bmp *.gif)"),
        )
        if not paths:
            return
        images: list[bytes] = []
        for path in paths[:4]:
            try:
                source = Path(path)
                if source.stat().st_size > 12 * 1024 * 1024:
                    continue
                data = source.read_bytes()
                if len(data) <= 12 * 1024 * 1024 and not QImage.fromData(data).isNull():
                    images.append(data)
            except OSError:
                pass
        if not images:
            widgets.message(self, "无法读取", "所选图片为空、格式不受支持或超过 12 MB。", kind="warn")
            return
        added = self._append_document_images(images)
        if added:
            self._start_ocr(added)

    def _scan_document_camera(self) -> None:
        from .document_scanner import DocumentScannerDialog

        dialog = DocumentScannerDialog(parent=self)
        if dialog.exec() == QDialog.Accepted and dialog.image_bytes:
            added = self._append_document_images([dialog.image_bytes])
            if added:
                self._start_ocr(added)

    def _append_document_images(self, images: list[bytes]) -> list[bytes]:
        added: list[bytes] = []
        for data in images:
            if len(self._images) >= self._image_limit:
                widgets.message(self, "已达上限", f"此模块最多保存 {self._image_limit} 张图片。", kind="warn")
                break
            if len(data) > 12 * 1024 * 1024 or QImage.fromData(data).isNull():
                continue
            ref = media_files.import_bytes(data, "image")
            if ref in self._images:
                continue
            self._images.append(ref)
            added.append(data)
        if added:
            self._refresh_images()
            self.changed.emit()
            self.layout_changed.emit()
        return added

    def _start_ocr(self, images: list[bytes]) -> None:
        if self._worker_is_running():
            widgets.message(self, "正在识别", "请等待当前 OCR 任务完成。", kind="info")
            return
        worker = _OcrWorker(images, card_type=self._card_type_value())
        self._worker = worker
        card_ref = weakref.ref(self)
        worker.succeeded.connect(lambda values: _with_live_card(card_ref, lambda card: card._apply_fields(values, overwrite=False)))
        worker.failed.connect(lambda message: _with_live_card(
            card_ref, lambda card: widgets.message(card, "识别失败", message, kind="warn"),
        ))
        worker.finished.connect(lambda: _with_live_card(card_ref, lambda card: card._finish_worker(worker)))
        _retain_worker(worker)
        worker.start()

    def _locate_address(self) -> None:
        if self._worker_is_running():
            return
        button = getattr(self, "_locate_button", None)
        if button is not None:
            button.setEnabled(False)
            button.setText("正在定位…")
        worker = _LocationWorker()
        self._worker = worker
        card_ref = weakref.ref(self)
        worker.succeeded.connect(lambda values: _with_live_card(card_ref, lambda card: card._apply_fields(values, overwrite=False)))
        worker.failed.connect(lambda message: _with_live_card(
            card_ref, lambda card: widgets.message(card, "定位失败", message, kind="warn"),
        ))
        worker.finished.connect(lambda: _with_live_card(card_ref, lambda card: card._finish_worker(worker)))
        _retain_worker(worker)
        worker.start()

    def _worker_is_running(self) -> bool:
        worker = self._worker
        if worker is None:
            return False
        try:
            return worker.isRunning()
        except RuntimeError:
            self._worker = None
            return False

    def _finish_worker(self, worker: QThread) -> None:
        if self._worker is worker:
            self._worker = None
        button = getattr(self, "_locate_button", None)
        if button is not None:
            button.setEnabled(True)
            button.setText("使用当前位置")

    def value(self) -> dict:
        result = copy.deepcopy(self.module)
        if result.get("type") == modules.PASSKEY:
            return result
        visible_title = self.title.text().strip()
        result["title"] = (
            self._canonical_default_title
            if self._title_started_as_canonical_default and visible_title == self._localized_default_title
            else visible_title or self._canonical_default_title
        )
        if hasattr(self, "_autofill_role") and self._autofill_role_changed:
            config = result.get("config") if isinstance(result.get("config"), dict) else {}
            result["config"] = config
            role = self._autofill_role.currentData()
            if type(role) is str and role:
                config["autofill_role"] = role
            else:
                config.pop("autofill_role", None)
        if result.get("type") == modules.IMAGES and hasattr(self, "_images"):
            result["value"] = list(self._images)
        elif result.get("type") == modules.ATTACHMENTS and hasattr(self, "_attachments"):
            result["value"] = copy.deepcopy(self._attachments)
        elif result.get("type") == modules.BOOLEAN and isinstance(self._editors.get("value"), QCheckBox):
            result["value"] = self._editors["value"].isChecked()
        elif result.get("type") == modules.DATETIME and hasattr(self, "_datetime_value"):
            config = result.get("config") if isinstance(result.get("config"), dict) else {}
            result["config"] = dict(config, mode=str(self._datetime_mode.currentData() or "datetime"))
            result["value"] = self._datetime_value.text().strip()
        elif isinstance(result.get("value"), dict) and self._editors:
            value = {key: self._editor_text(editor) for key, editor in self._editors.items()}
            if result.get("type") == modules.CARD_DOCUMENT:
                value["images"] = list(self._images)
                value = modules.card_value_for_type(value, str(value.get("card_type") or modules.CARD_BANK))
            result["value"] = modules.compact_compound_value(value)
        elif "value" in self._editors:
            editor = self._editors["value"]
            result["value"] = self._editor_text(editor)
        return result

    def has_content(self) -> bool:
        value = self.value().get("value")
        if self.module.get("type") == modules.BOOLEAN and type(value) is bool:
            return True
        if isinstance(value, dict):
            return any(str(item).strip() for item in value.values())
        if isinstance(value, list):
            return bool(value)
        return bool(str(value or "").strip())


def _with_live_card(reference, action) -> None:
    card = reference()
    if card is None:
        return
    try:
        import shiboken6
        if shiboken6.isValid(card):
            action(card)
    except RuntimeError:
        pass


def _retain_worker(worker: QThread) -> None:
    _ACTIVE_WORKERS.add(worker)

    def _release() -> None:
        _ACTIVE_WORKERS.discard(worker)
        worker.deleteLater()

    worker.finished.connect(_release)



class ModuleEditor(QWidget):
    changed = Signal()
    layout_changed = Signal()

    def __init__(self, value: list[dict] | None = None, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(12)
        self._cards: list[ModuleCard] = []
        self._empty = QLabel("尚未添加内容")
        self._empty.setObjectName("ModuleEmpty")
        self._empty.setAlignment(Qt.AlignCenter)
        self._empty.setMinimumHeight(76)
        self._layout.addWidget(self._empty)
        self._add = QPushButton(i18n.tr("＋  添加第一个模块"))
        self._add.setObjectName("ModuleAdd")
        self._add.setToolTip("添加模块")
        self._add.clicked.connect(self._open_picker)
        self._layout.addWidget(self._add)
        self.set_modules(value or [])

    def set_modules(self, value: list[dict]) -> None:
        for card in self._cards:
            self._layout.removeWidget(card)
            card.hide()
            card.deleteLater()
        self._cards.clear()
        for module in modules.normalize_modules(value):
            self._insert(module)
        self._empty.setVisible(not self._cards)
        self._add.setText(i18n.tr("＋  添加第一个模块" if not self._cards else "＋  继续添加模块"))
        self.layout_changed.emit()

    def _insert(self, module: dict) -> None:
        card = ModuleCard(module, self)
        card.move_requested.connect(self._move)
        card.delete_requested.connect(self._delete)
        card.changed.connect(self.changed)
        card.layout_changed.connect(self.layout_changed)
        self._cards.append(card)
        self._layout.insertWidget(self._layout.indexOf(self._add), card)

    def _open_picker(self) -> None:
        picker = ModulePickerDialog(self)
        picker.selected.connect(self.add_module)
        picker.exec()

    def add_module(self, module_type: str) -> None:
        self._insert(modules.new_module(module_type))
        self._empty.hide()
        self._add.setText(i18n.tr("＋  继续添加模块"))
        self.changed.emit()
        self.layout_changed.emit()

    def _move(self, card: ModuleCard, delta: int) -> None:
        index = self._cards.index(card)
        target = max(0, min(len(self._cards) - 1, index + delta))
        if target == index:
            return
        self._cards.pop(index)
        self._cards.insert(target, card)
        self._layout.removeWidget(card)
        self._layout.insertWidget(target + 1, card)
        self.changed.emit()

    def _delete(self, card: ModuleCard) -> None:
        if card.has_content() and not widgets.confirm(
            self, "删除模块", "此模块已有内容，确定删除吗？",
        ):
            return
        self._cards.remove(card)
        self._layout.removeWidget(card)
        card.hide()
        card.deleteLater()
        self._empty.setVisible(not self._cards)
        self._add.setText(i18n.tr("＋  添加第一个模块" if not self._cards else "＋  继续添加模块"))
        self.changed.emit()
        self.layout_changed.emit()

    def modules(self) -> list[dict]:
        return modules.normalize_modules([card.value() for card in self._cards])
