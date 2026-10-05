"""预览卡片缩略图解码：与 Android 的取样解码思路一致。

先通过 QImageReader 读取宽高，再按输出尺寸（最长边）缩放解码，
内存随输出像素数受限而不是随输入文件大小增长；解密内容流式落盘，
不再依赖 read_bytes 的整文件字节上限。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PySide6.QtCore import QSize, QTimer, Qt
from PySide6.QtGui import QImage, QImageIOHandler, QImageReader, QPixmap

from core import media_files
from . import encrypted_thumbnail_cache
from . import large_image_decode

# 复制图片到系统剪贴板的内存上限：与媒体整块读取的默认上限一致。
# 导出/保存原图走流式解密，不在此上限内。
IMAGE_CLIPBOARD_MAX_BYTES = 64 * 1024 * 1024

_ROTATING_TRANSFORMATIONS = (
    QImageIOHandler.Transformation.TransformationRotate90,
    QImageIOHandler.Transformation.TransformationRotate270,
    QImageIOHandler.Transformation.TransformationFlipAndRotate90,
    QImageIOHandler.Transformation.TransformationMirrorAndRotate90,
)


def load_image_thumbnail(value: object, longest_side: int = 512) -> QImage:
    with large_image_decode.decode_lock:
        return _load_image_thumbnail(value, longest_side)


def load_thumbnail_into(label, value: object, width: int, height: int) -> None:
    """Decode off the GUI thread and publish only the latest request on a label."""
    from .render_jobs import thumbnail_executor

    previous = getattr(label, "_thumbnail_request", None)
    if previous is not None:
        previous.cancel()
    future = thumbnail_executor.submit(load_image_thumbnail, value, max(width, height) * 2)
    label._thumbnail_request = future
    label.setText("加载中…")
    timer = QTimer(label)
    timer.setInterval(20)

    def finish():
        if label._thumbnail_request is not future:
            timer.stop()
            timer.deleteLater()
            return
        if not future.done():
            return
        timer.stop()
        timer.deleteLater()
        try:
            image = future.result()
            pixmap = QPixmap.fromImage(image)
            label.setPixmap(pixmap.scaled(width, height, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except Exception:
            label.setText("无法读取")

    timer.timeout.connect(finish)
    label.destroyed.connect(lambda *_args: future.cancel())
    timer.start()


def _load_image_thumbnail(value: object, longest_side: int = 512) -> QImage:
    """解码一张按最长边受限的预览缩略图。

    解密内容流式写入临时文件（内存不随输入大小增长），QImageReader
    对 JPEG/WebP/GIF 等格式按输出像素数受限解码；PNG 由 Qt 回退为
    整图解码后缩放，但结果仍只保留缩略图尺寸。失败时抛出异常。
    """

    cached = encrypted_thumbnail_cache.read(value, longest_side)
    if cached is not None:
        return cached
    fd, temporary_name = tempfile.mkstemp(prefix="vault-thumb-", suffix=".media")
    os.close(fd)
    temporary = Path(temporary_name)
    reader = None
    try:
        media_files.export_value(value, temporary)
        reader = QImageReader(str(temporary))
        reader.setDecideFormatFromContent(True)
        reader.setAutoTransform(True)
        source_size = reader.size()
        if not source_size.isValid() or source_size.width() <= 0 or source_size.height() <= 0:
            raise ValueError("图片无法解码")
        longest = max(source_size.width(), source_size.height())
        if longest > longest_side:
            ratio = longest_side / longest
            reader.setScaledSize(
                QSize(
                    max(1, round(source_size.width() * ratio)),
                    max(1, round(source_size.height() * ratio)),
                )
            )
        image = (
            large_image_decode.preview(temporary, longest_side, longest_side)
            if source_size.width() * source_size.height() > large_image_decode.QT_SAFE_PIXELS
            else reader.read()
        )
        if image.isNull():
            image = large_image_decode.preview(temporary, longest_side, longest_side)
        if image.isNull():
            raise ValueError("图片无法解码")
        # 深拷贝，确保返回的位图不依赖即将释放的 reader 内部缓冲。
        result = image.copy()
        encrypted_thumbnail_cache.write(value, longest_side, result)
        return result
    finally:
        # Windows 下必须先释放 reader 的文件句柄才能删除临时文件。
        reader = None
        temporary.unlink(missing_ok=True)
