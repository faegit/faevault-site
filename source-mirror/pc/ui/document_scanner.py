"""Camera and file based document scanning with four-corner review."""

from __future__ import annotations

import io

import cv2
import numpy as np
from PIL import Image, ImageOps
from PySide6.QtCore import QPointF, QRectF, Qt, QTimer
from PySide6.QtGui import QColor, QImage, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from . import i18n, widgets


def _decode_image(data: bytes) -> np.ndarray:
    with Image.open(io.BytesIO(data)) as source:
        oriented = ImageOps.exif_transpose(source).convert("RGB")
        return cv2.cvtColor(np.asarray(oriented), cv2.COLOR_RGB2BGR)


def _ordered_quad(points: np.ndarray) -> np.ndarray:
    points = np.asarray(points, dtype=np.float32).reshape(4, 2)
    total = points.sum(axis=1)
    delta = points[:, 1] - points[:, 0]
    return np.array([points[np.argmin(total)], points[np.argmin(delta)],
                     points[np.argmax(total)], points[np.argmax(delta)]], dtype=np.float32)


def detect_document_corners(frame: np.ndarray) -> np.ndarray | None:
    """Return TL, TR, BR, BL corners for the largest plausible document."""
    height, width = frame.shape[:2]
    if height < 80 or width < 80:
        return None
    scale = min(1.0, 900 / max(height, width))
    small = cv2.resize(frame, None, fx=scale, fy=scale) if scale < 1 else frame
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 45, 140)
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    area_min = small.shape[0] * small.shape[1] * 0.12
    for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:20]:
        if cv2.contourArea(contour) < area_min:
            break
        perimeter = cv2.arcLength(contour, True)
        polygon = cv2.approxPolyDP(contour, 0.02 * perimeter, True)
        if len(polygon) == 4 and cv2.isContourConvex(polygon):
            return _ordered_quad(polygon.reshape(4, 2) / scale)
    return None


def crop_document(frame: np.ndarray, corners: np.ndarray) -> bytes:
    quad = _ordered_quad(corners)
    width = int(max(np.linalg.norm(quad[1] - quad[0]), np.linalg.norm(quad[2] - quad[3])))
    height = int(max(np.linalg.norm(quad[3] - quad[0]), np.linalg.norm(quad[2] - quad[1])))
    if width < 60 or height < 40:
        raise ValueError("Invalid crop area")
    cap = min(1.0, 3000 / max(width, height))
    width, height = max(1, int(width * cap)), max(1, int(height * cap))
    target = np.array([[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]], dtype=np.float32)
    warped = cv2.warpPerspective(frame, cv2.getPerspectiveTransform(quad, target), (width, height))
    ok, encoded = cv2.imencode(".jpg", warped, [cv2.IMWRITE_JPEG_QUALITY, 92])
    if not ok:
        raise ValueError("Could not encode crop")
    return encoded.tobytes()


class DocumentCropView(QWidget):
    """Image review: drag a corner, or click one corner then its new location."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(620, 360)
        self.setMouseTracking(True)
        self._frame: np.ndarray | None = None
        self._image = QImage()
        self._corners = np.zeros((4, 2), dtype=np.float32)
        self._dragging: int | None = None
        self._selected: int | None = None

    def set_frame(self, frame: np.ndarray, corners: np.ndarray | None = None) -> None:
        self._frame = frame.copy()
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        self._image = QImage(rgb.data, rgb.shape[1], rgb.shape[0], rgb.strides[0], QImage.Format_RGB888).copy()
        h, w = frame.shape[:2]
        default = np.array([[.06*w, .06*h], [.94*w, .06*h], [.94*w, .94*h], [.06*w, .94*h]], dtype=np.float32)
        self._corners = _ordered_quad(corners) if corners is not None else default
        self._dragging = self._selected = None
        self.update()

    def corners(self) -> np.ndarray:
        return self._corners.copy()

    def cropped_bytes(self) -> bytes:
        if self._frame is None:
            raise ValueError("No image")
        return crop_document(self._frame, self._corners)

    def _image_rect(self) -> QRectF:
        if self._image.isNull():
            return QRectF()
        scale = min(self.width() / self._image.width(), self.height() / self._image.height())
        w, h = self._image.width() * scale, self._image.height() * scale
        return QRectF((self.width()-w)/2, (self.height()-h)/2, w, h)

    def _screen_point(self, point: np.ndarray) -> QPointF:
        rect = self._image_rect()
        return QPointF(rect.left() + float(point[0]) * rect.width() / self._image.width(),
                       rect.top() + float(point[1]) * rect.height() / self._image.height())

    def _image_point(self, point: QPointF) -> np.ndarray:
        rect = self._image_rect()
        return np.array([np.clip((point.x()-rect.left()) * self._image.width()/rect.width(), 0, self._image.width()-1),
                         np.clip((point.y()-rect.top()) * self._image.height()/rect.height(), 0, self._image.height()-1)], dtype=np.float32)

    def _move_corner(self, index: int, point: QPointF) -> None:
        candidate = self._corners.copy()
        candidate[index] = self._image_point(point)
        vectors = np.roll(candidate, -1, axis=0) - candidate
        following = np.roll(vectors, -1, axis=0)
        cross = vectors[:, 0] * following[:, 1] - vectors[:, 1] * following[:, 0]
        if np.all(cross > 0) and abs(float(cv2.contourArea(candidate))) > 1500:
            self._corners = candidate
            self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#151820"))
        if not self._image.isNull():
            painter.setRenderHint(QPainter.Antialiasing)
            painter.drawImage(self._image_rect(), self._image)
            points = [self._screen_point(point) for point in self._corners]
            path = QPainterPath(points[0])
            for point in points[1:]:
                path.lineTo(point)
            path.closeSubpath()
            painter.setPen(QPen(QColor("#F6C94A"), 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)
            for index, point in enumerate(points):
                painter.setPen(QPen(QColor("#172033"), 2))
                painter.setBrush(QColor("#FFFFFF" if index != self._selected else "#F6C94A"))
                painter.drawEllipse(point, 10, 10)
        painter.end()

    def mousePressEvent(self, event) -> None:
        if self._image.isNull():
            return
        distances = [((self._screen_point(point)-event.position()).manhattanLength(), index)
                     for index, point in enumerate(self._corners)]
        distance, index = min(distances)
        if distance <= 24:
            self._selected = self._dragging = index
            self.update()
        elif self._selected is not None and self._image_rect().contains(event.position()):
            self._move_corner(self._selected, event.position())
            self._selected = None
        else:
            self._selected = None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._dragging is not None:
            self._move_corner(self._dragging, event.position())
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._dragging = None
        super().mouseReleaseEvent(event)


class DocumentScannerDialog(widgets.ShadowDialog):
    """One scanner for live camera and local images, followed by crop review."""

    def __init__(self, parent=None, *, start_camera: bool = True, start_file: bool = False):
        super().__init__(i18n.tr("扫描卡证"), parent, width=760)
        self.image_bytes: bytes | None = None
        self._capture = None
        self._frame_index = 0
        self._last_center = None
        self._stable = 0
        self._reviewing = False
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._update_camera)

        self.status = QLabel(i18n.tr("将卡证放入画面，或选择图片"))
        self.status.setAlignment(Qt.AlignCenter)
        self.body.addWidget(self.status)
        self.preview = DocumentCropView(self)
        self.body.addWidget(self.preview)
        row = QHBoxLayout()
        self.camera_button = QPushButton(i18n.tr("摄像头"))
        self.camera_button.clicked.connect(self._start_camera)
        row.addWidget(self.camera_button)
        choose = QPushButton(i18n.tr("选择图片"))
        choose.clicked.connect(self._choose_image)
        row.addWidget(choose)
        self.body.addLayout(row)
        actions = QHBoxLayout()
        actions.addStretch()
        cancel = QPushButton(i18n.tr("取消"))
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)
        self.confirm_button = QPushButton(i18n.tr("确认裁切并识别"))
        self.confirm_button.setObjectName("Primary")
        self.confirm_button.setEnabled(False)
        self.confirm_button.clicked.connect(self._confirm)
        actions.addWidget(self.confirm_button)
        self.body.addLayout(actions)
        if start_file:
            QTimer.singleShot(0, self._choose_image)
        elif start_camera:
            QTimer.singleShot(0, self._start_camera)

    def _stop_camera(self) -> None:
        self._timer.stop()
        if self._capture is not None:
            self._capture.release()
            self._capture = None

    def _start_camera(self) -> None:
        self._stop_camera()
        self._reviewing = False
        self.confirm_button.setEnabled(False)
        self._stable = 0
        self._last_center = None
        for index in range(6):
            for backend in (cv2.CAP_DSHOW, cv2.CAP_MSMF):
                candidate = cv2.VideoCapture(index, backend)
                if candidate.isOpened():
                    self._capture = candidate
                    break
                candidate.release()
            if self._capture is not None:
                break
        if self._capture is None:
            self.status.setText(i18n.tr("摄像头不可用，请选择图片"))
            return
        self.status.setText(i18n.tr("保持卡证边缘稳定，检测后自动进入四角校正"))
        self._timer.start()

    def _update_camera(self) -> None:
        if self._capture is None:
            return
        ok, frame = self._capture.read()
        if not ok:
            return
        self.preview.set_frame(frame)
        self._frame_index += 1
        if self._frame_index % 4:
            return
        corners = detect_document_corners(frame)
        if corners is None:
            self._stable = 0
            self._last_center = None
            return
        center = corners.mean(axis=0)
        if self._last_center is not None and np.linalg.norm(center-self._last_center) < min(frame.shape[:2])*.07:
            self._stable += 1
        else:
            self._stable = 1
        self._last_center = center
        if self._stable >= 3:
            self._show_review(frame, corners)

    def _show_review(self, frame: np.ndarray, corners: np.ndarray | None) -> None:
        self._stop_camera()
        self._reviewing = True
        self.preview.set_frame(frame, corners)
        self.status.setText(i18n.tr("拖动四角调整裁切范围，然后确认"))
        self.confirm_button.setEnabled(True)

    def _choose_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("选择卡证图片"), "", i18n.tr("图片 (*.jpg *.jpeg *.png *.webp *.bmp)"),
        )
        if not path:
            return
        try:
            from pathlib import Path
            source = Path(path)
            if source.stat().st_size > 16 * 1024 * 1024:
                raise ValueError(i18n.tr("图片不能超过 16 MB"))
            frame = _decode_image(source.read_bytes())
            self._show_review(frame, detect_document_corners(frame))
        except Exception as exc:
            widgets.message(self, "无法读取", str(exc), kind="warn")

    def _confirm(self) -> None:
        try:
            self.image_bytes = self.preview.cropped_bytes()
        except ValueError as exc:
            widgets.message(self, "无法读取", str(exc), kind="warn")
            return
        self.accept()

    def done(self, result: int) -> None:
        self._stop_camera()
        super().done(result)
