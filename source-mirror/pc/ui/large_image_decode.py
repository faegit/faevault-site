"""Bounded preview and visible-region decoding for images Qt cannot allocate."""

from __future__ import annotations

import io
import math
import os
import tempfile
import threading
from pathlib import Path

from PIL import Image, ImageOps
from PySide6.QtGui import QImage

QT_SAFE_PIXELS = 48 * 1024 * 1024
MAX_SOURCE_PIXELS = 160 * 1024 * 1024
MAX_DETAIL_PIXELS = 8 * 1024 * 1024
decode_lock = threading.Lock()


class ImageSource:
    """A streamed source shared by preview/detail jobs until their last reference ends."""

    def __init__(self):
        fd, name = tempfile.mkstemp(prefix="vault-viewer-", suffix=".media")
        os.close(fd)
        self.path = Path(name)

    def __del__(self):
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def _open(source: bytes | Path):
    image = Image.open(io.BytesIO(source) if isinstance(source, bytes) else source)
    if image.width * image.height > MAX_SOURCE_PIXELS:
        image.close()
        raise ValueError("图片尺寸过大，超过安全解码上限")
    return image


def _to_qimage(image: Image.Image) -> QImage:
    rgba = image.convert("RGBA")
    pixels = rgba.tobytes()
    return QImage(pixels, rgba.width, rgba.height, rgba.width * 4, QImage.Format_RGBA8888).copy()


def preview(source: bytes | Path, width: int, height: int) -> QImage:
    with _open(source) as image:
        if image.getexif().get(274, 1) in (5, 6, 7, 8):
            width, height = height, width
        image.draft("RGB", (max(1, width), max(1, height)))
        image.thumbnail((max(1, width), max(1, height)), Image.Resampling.LANCZOS, reducing_gap=3)
        return _to_qimage(ImageOps.exif_transpose(image))


def region(source: bytes | Path, left: int, top: int, right: int, bottom: int,
           output_width: int, output_height: int) -> QImage:
    width = max(1, right - left)
    height = max(1, bottom - top)
    scale = min(1.0, math.sqrt(MAX_DETAIL_PIXELS / max(1, output_width * output_height)))
    target = (max(1, round(output_width * scale)), max(1, round(output_height * scale)))
    with _open(source) as image:
        original_width, original_height = image.size
        # JPEG can subsample in its decoder before cropping, avoiding a full-size
        # bitmap when only a screen-sized region is needed.
        ratio = min(1.0, max(target[0] / width, target[1] / height))
        image.draft("RGB", (max(1, math.ceil(original_width * ratio)), max(1, math.ceil(original_height * ratio))))
        sx, sy = image.width / original_width, image.height / original_height
        cropped = image.crop((math.floor(left * sx), math.floor(top * sy),
                              math.ceil((left + width) * sx), math.ceil((top + height) * sy)))
        if cropped.size != target:
            cropped = cropped.resize(target, Image.Resampling.BILINEAR)
        return _to_qimage(ImageOps.exif_transpose(cropped))
