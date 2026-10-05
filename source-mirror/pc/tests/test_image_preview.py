"""预览缩略图：QImageReader 先读宽高、按输出尺寸缩放解码，无输入字节上限。"""

from __future__ import annotations

import base64
import struct
import uuid
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QBuffer, QIODevice, QSize
from PySide6.QtGui import QImage, QImageWriter

from core import media_files
from core.pmv_attachment import AttachmentKind
from core.pmv_media_ref import MediaRef
from ui import encrypted_thumbnail_cache
from ui.image_preview import load_image_thumbnail


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    yield
    while media_files._context_stack:
        media_files.clear_media_context()


def _ctx() -> None:
    media_files.set_media_context("vault-test", bytes(range(32)))


def _encode_image(size: QSize, fmt: bytes = b"jpeg") -> bytes:
    image = QImage(size.width(), size.height(), QImage.Format_RGB32)
    image.fill(0xFF4080)
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    writer = QImageWriter(buffer, fmt)
    writer.setQuality(95)
    assert writer.write(image), writer.errorString()
    buffer.close()
    return bytes(buffer.data())


def test_thumbnail_scales_to_longest_side_before_decode() -> None:
    _ctx()
    ref = media_files.import_bytes(_encode_image(QSize(4000, 3000)), "image", "photo.jpg")
    thumb = load_image_thumbnail(ref)
    assert not thumb.isNull()
    assert max(thumb.width(), thumb.height()) <= 512
    assert abs(thumb.width() / thumb.height() - 4.0 / 3.0) < 0.02
    pixel = thumb.pixel(thumb.width() // 2, thumb.height() // 2) & 0xFFFFFF
    for channel in range(3):  # JPEG 有损编码允许小幅色差
        assert abs(((pixel >> (8 * channel)) & 0xFF) - ((0xFF4080 >> (8 * channel)) & 0xFF)) <= 8


def test_thumbnail_accepts_payload_larger_than_old_32mb_cap(monkeypatch) -> None:
    # 预览不再走 read_bytes 的 32 MB 整块上限：读取完全交给流式 export_value。
    import ui.image_preview as image_preview

    raw = _encode_image(QSize(800, 600))
    monkeypatch.setattr(
        image_preview.media_files,
        "export_value",
        lambda value, destination: destination.write_bytes(raw),
    )

    def fail_read_bytes(*_args, **_kwargs):
        raise AssertionError("预览必须禁止调用 read_bytes")

    monkeypatch.setattr(image_preview.media_files, "read_bytes", fail_read_bytes)
    thumb = load_image_thumbnail("payload-over-32mb")
    assert not thumb.isNull()
    assert max(thumb.width(), thumb.height()) <= 512


def test_thumbnail_png_falls_back_to_full_decode_then_scale() -> None:
    _ctx()
    ref = media_files.import_bytes(_encode_image(QSize(2000, 1500), fmt=b"png"), "image", "photo.png")
    thumb = load_image_thumbnail(ref)
    assert not thumb.isNull()
    assert max(thumb.width(), thumb.height()) <= 512


def test_thumbnail_respects_exif_orientation() -> None:
    _ctx()
    jpeg = _encode_image(QSize(60, 100))
    tiff = (
        b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHI", 0x0112, 3, 1) + struct.pack("<H", 6) + b"\x00\x00"
        + struct.pack("<I", 0)
    )
    payload = b"Exif\x00\x00" + tiff
    raw = jpeg[:2] + b"\xff\xe1" + struct.pack(">H", len(payload)) + payload + jpeg[2:]
    ref = media_files.import_bytes(raw, "image", "photo.jpg")
    thumb = load_image_thumbnail(ref)
    assert not thumb.isNull()
    assert thumb.width() > thumb.height()  # 90 度旋转后按横图显示


def test_thumbnail_inline_base64_without_vault_context() -> None:
    raw = _encode_image(QSize(1200, 900))
    value = "data:image/jpeg;base64," + base64.b64encode(raw).decode("ascii")
    thumb = load_image_thumbnail(value)
    assert not thumb.isNull()
    assert max(thumb.width(), thumb.height()) <= 512


def test_thumbnail_raises_on_undecodable_input() -> None:
    _ctx()
    ref = media_files.import_bytes(b"not an image", "image", "bad.bin")
    with pytest.raises(ValueError):
        load_image_thumbnail(ref)


def test_pmve_thumbnail_cache_is_encrypted_and_reused(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    vault_id = uuid.uuid4()
    vault = SimpleNamespace(
        pmve_identity=SimpleNamespace(vault_id=vault_id),
        root_key_for_device_unlock=lambda: bytes(range(32)),
    )
    ref = MediaRef(uuid.uuid4(), 1, AttachmentKind.IMAGE, 0, bytes(range(32))).to_json()
    raw = _encode_image(QSize(800, 600))
    calls = []

    def export(_value, destination):
        calls.append(True)
        destination.write_bytes(raw)

    monkeypatch.setattr(media_files, "export_value", export)
    media_files.set_vault_context(vault)
    first = load_image_thumbnail(ref)
    second = load_image_thumbnail(ref)
    assert not first.isNull() and not second.isNull()
    assert len(calls) == 1
    cache_path = encrypted_thumbnail_cache._cache_parts(ref, 512)[0]
    ciphertext = cache_path.read_bytes()
    assert ciphertext.startswith(b"FVTC1")
    assert b"PNG" not in ciphertext[:32]

    cache_path.write_bytes(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    load_image_thumbnail(ref)
    assert len(calls) == 2
