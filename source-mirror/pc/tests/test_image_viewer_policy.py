from __future__ import annotations

from ui.dialogs import (
    ImageGallery,
    _ImageDetailWorker,
    _ImageSourceWorker,
    _ImageViewerCanvas,
    image_viewer_paging_enabled,
    image_viewer_double_click_target,
    image_viewer_display_clip_to_encoded,
    image_viewer_release_target,
    image_viewer_swaps_dimensions,
    image_viewer_window_size,
)
import struct
import io
import zlib
from PySide6.QtCore import QBuffer, QIODevice, QRect, QSize
from PySide6.QtCore import QPointF
from PySide6.QtGui import QImage, QImageIOHandler, QImageReader, QImageWriter
from PySide6.QtWidgets import QApplication, QLabel
from core import media_files
from ui.image_preview import load_image_thumbnail


def _oversized_solid_png(width: int = 8500, height: int = 8500) -> bytes:
    output = io.BytesIO()
    output.write(b"\x89PNG\r\n\x1a\n")

    def chunk(kind: bytes, data: bytes) -> None:
        output.write(struct.pack(">I", len(data)) + kind + data)
        output.write(struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))

    chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    compressor = zlib.compressobj(1)
    row = b"\0" + b"\x50\x90\xd0\xff" * width
    for _ in range(height):
        block = compressor.compress(row)
        if block:
            chunk(b"IDAT", block)
    block = compressor.flush()
    if block:
        chunk(b"IDAT", block)
    chunk(b"IEND", b"")
    return output.getvalue()


def test_oversized_png_uses_bounded_viewer_preview(monkeypatch) -> None:
    raw = _oversized_solid_png()
    monkeypatch.setattr(media_files, "export_value", lambda _value, path: path.write_bytes(raw))
    thumbnail = load_image_thumbnail("synthetic-large-png")
    assert not thumbnail.isNull() and thumbnail.size() == QSize(512, 512)
    monkeypatch.setattr(media_files, "read_bytes", lambda *_args: raw)
    received = []
    worker = _ImageSourceWorker(1, "image", QSize(1200, 800))
    worker.completed.connect(lambda *args: received.append(args))
    worker.run()
    assert received
    token, _raw, display_size, preview, error = received[0]
    assert (token, error) == (1, "")
    assert display_size == QSize(8500, 8500)
    assert not preview.isNull() and preview.size() == QSize(800, 800)

    detail_results = []
    detail_worker = _ImageDetailWorker(
        1, raw, display_size, QSize(1200, 800), 2.0, QPointF(-600, -400)
    )
    detail_worker.completed.connect(lambda *args: detail_results.append(args))
    detail_worker.run()
    assert detail_results
    assert not detail_results[0][1].isNull()
    assert detail_results[0][1].width() * detail_results[0][1].height() <= 8 * 1024 * 1024


def test_image_viewer_pages_only_at_fit_zoom() -> None:
    assert image_viewer_paging_enabled(1.0)
    assert image_viewer_paging_enabled(1.0001)
    assert not image_viewer_paging_enabled(1.01)
    assert not image_viewer_paging_enabled(2.0)


def test_viewer_streams_source_and_releases_temporary_file(monkeypatch):
    import gc
    from ui.large_image_decode import ImageSource

    raw = _build_exif_jpeg(6)
    monkeypatch.setattr(media_files, "export_value", lambda _value, destination: destination.write_bytes(raw))
    monkeypatch.setattr(media_files, "read_bytes", lambda *_args: (_ for _ in ()).throw(AssertionError("whole-file read")))
    results = []
    worker = _ImageSourceWorker(1, "image", QSize(1200, 800))
    worker.completed.connect(lambda *args: results.append(args))
    worker.run()
    source = results[0][1]
    assert isinstance(source, ImageSource)
    path = source.path
    assert path.exists()
    results.clear()
    del source
    gc.collect()
    assert not path.exists()


def test_canvas_discards_outdated_detail_and_bounds_neighbor_cache(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("ui.dialogs.QTimer.singleShot", lambda *_args: None)
    canvas = _ImageViewerCanvas(["one", "two", "three", "four"], 1)
    canvas._detail_epoch = 3
    image = QImage(20, 20, QImage.Format_RGB32)
    canvas._detail_ready(2, image, QRect(0, 0, 20, 20), None)
    assert canvas._detail.isNull()
    canvas._neighbor_ready(3, QSize(20, 20), image, "")
    assert 3 not in canvas._page_preview
    canvas._neighbor_ready(2, QSize(20, 20), image, "")
    assert 2 in canvas._page_preview
    canvas.close_workers()
    canvas._detail_ready(3, image, QRect(0, 0, 20, 20), None)
    assert canvas._detail.isNull()
    canvas.deleteLater()
    app.processEvents()


def test_image_viewer_page_count_stays_over_black_canvas_on_resize() -> None:
    app = QApplication.instance() or QApplication([])
    canvas = _ImageViewerCanvas(["one", "two"], 0)
    label = QLabel("1 / 2")
    canvas.set_page_label(label)
    canvas.show()
    canvas.resize(900, 600)
    app.processEvents()
    assert label.parent() is canvas
    assert abs(label.geometry().center().x() - canvas.width() // 2) <= 1
    assert label.geometry().bottom() < canvas.height()
    canvas.close_workers()
    canvas.deleteLater()


def test_high_resolution_double_click_cycles_fit_two_times_native_then_fit() -> None:
    fit = 0.1
    assert image_viewer_double_click_target(1.0, fit) == 2.0
    assert image_viewer_double_click_target(2.0, fit) == 10.0
    assert image_viewer_double_click_target(10.0, fit) == 1.0


def test_ordinary_image_double_click_cycles_fit_two_times_then_fit() -> None:
    fit = 0.75
    assert image_viewer_double_click_target(1.0, fit) == 2.0
    assert image_viewer_double_click_target(2.0, fit) == 1.0


def test_rotated_detail_clip_maps_back_to_encoded_coordinates() -> None:
    # QImageReader 的 scaledClipRect 在未旋转的原始图像坐标系里解释，
    # 旋转由 read() 最后施加；下面的期望值已按该行为实测校准。
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 60, 50),
        QSize(100, 60),
        QImageIOHandler.Transformation.TransformationRotate90,
    ) == QRect(0, 40, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 60, 50),
        QSize(100, 60),
        QImageIOHandler.Transformation.TransformationRotate270,
    ) == QRect(10, 0, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 60, 50),
        QSize(100, 60),
        QImageIOHandler.Transformation.TransformationFlipAndRotate90,
    ) == QRect(0, 0, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 60, 50),
        QSize(100, 60),
        QImageIOHandler.Transformation.TransformationMirrorAndRotate90,
    ) == QRect(10, 40, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 50, 60),
        QSize(60, 100),
        QImageIOHandler.Transformation.TransformationRotate180,
    ) == QRect(10, 40, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 50, 60),
        QSize(60, 100),
        QImageIOHandler.Transformation.TransformationMirror,
    ) == QRect(10, 0, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 50, 60),
        QSize(60, 100),
        QImageIOHandler.Transformation.TransformationFlip,
    ) == QRect(0, 40, 50, 60)
    assert image_viewer_display_clip_to_encoded(
        QRect(0, 0, 50, 60),
        QSize(60, 100),
        QImageIOHandler.Transformation.TransformationNone,
    ) == QRect(0, 0, 50, 60)


def test_rotated_transformation_swaps_dimensions() -> None:
    T = QImageIOHandler.Transformation
    assert image_viewer_swaps_dimensions(T.TransformationRotate90)
    assert image_viewer_swaps_dimensions(T.TransformationRotate270)
    assert image_viewer_swaps_dimensions(T.TransformationFlipAndRotate90)
    assert image_viewer_swaps_dimensions(T.TransformationMirrorAndRotate90)
    assert not image_viewer_swaps_dimensions(T.TransformationNone)
    assert not image_viewer_swaps_dimensions(T.TransformationMirror)
    assert not image_viewer_swaps_dimensions(T.TransformationFlip)
    assert not image_viewer_swaps_dimensions(T.TransformationRotate180)


def _build_exif_jpeg(orientation: int) -> bytes:
    """生成 60x100 的色块 JPEG 并注入 EXIF 方向标签。"""

    image = QImage(60, 100, QImage.Format_RGB32)
    for y in range(100):
        for x in range(60):
            r = (x // 10) * 40 + 8
            g = (y // 10) * 28 + 4
            image.setPixel(x, y, (r | (g << 8) | (128 << 16)) | 0xFF000000)
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    writer = QImageWriter(buffer, b"jpeg")
    writer.setQuality(95)
    assert writer.write(image)
    buffer.close()
    jpeg = bytes(buffer.data())
    tiff = (
        b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHI", 0x0112, 3, 1) + struct.pack("<H", orientation) + b"\x00\x00"
        + struct.pack("<I", 0)
    )
    payload = b"Exif\x00\x00" + tiff
    return jpeg[:2] + b"\xff\xe1" + struct.pack(">H", len(payload)) + payload + jpeg[2:]


def _reference_display(raw: bytes) -> QImage:
    source = QBuffer()
    source.setData(raw)
    source.open(QIODevice.ReadOnly)
    reader = QImageReader(source)
    reader.setAutoTransform(True)
    image = reader.read()
    source.close()
    return image


def test_rotated_detail_decode_matches_display_region() -> None:
    cases = [
        (6, QSize(100, 60)),  # TransformationRotate90
        (8, QSize(100, 60)),  # TransformationRotate270
        (3, QSize(60, 100)),  # TransformationRotate180
    ]
    for orientation, display_size in cases:
        raw = _build_exif_jpeg(orientation)
        reference = _reference_display(raw)
        assert reference.size() == display_size
        captured: list[object] = []
        # 2 倍放大并偏移后，可视区域是显示坐标 (20,10,50,30) 的子矩形。
        worker = _ImageDetailWorker(
            token=1,
            raw=raw,
            display_size=display_size,
            viewport=display_size,
            zoom=2.0,
            offset=QPointF(-40.0, -20.0),
        )
        worker.completed.connect(lambda *args: captured.append(args))
        worker.run()
        assert captured
        _token, detail, clip, _scaled_clip = captured[0]
        assert isinstance(detail, QImage) and not detail.isNull()
        # 高清层应覆盖可见区域并留出预取边距，输出像素按 2 倍率对应显示坐标。
        # 偏移 (-40,-20) 下可见区域：横图为 (20,10,50,30)，竖图为 (20,10,30,50)。
        visible_right = 69 if display_size.width() > display_size.height() else 49
        visible_bottom = 39 if display_size.width() > display_size.height() else 59
        assert clip.left() <= 20 and clip.top() <= 10
        assert clip.right() >= visible_right and clip.bottom() >= visible_bottom
        for ox, oy in [
            (0, 0),
            (clip.width() - 1, 0),
            (0, clip.height() - 1),
            (clip.width() - 1, clip.height() - 1),
            (clip.width() // 2, clip.height() // 2),
        ]:
            dx = clip.x() + ox // 2
            dy = clip.y() + oy // 2
            detail_pixel = detail.pixel(ox, oy) & 0xFFFFFF
            reference_pixel = reference.pixel(dx, dy) & 0xFFFFFF
            for channel in range(3):
                assert abs(
                    ((detail_pixel >> (8 * channel)) & 0xFF)
                    - ((reference_pixel >> (8 * channel)) & 0xFF)
                ) <= 24, (
                    f"orient {orientation} pixel ({ox},{oy}) mismatch: "
                    f"{detail_pixel:06x} vs {reference_pixel:06x}"
                )


def test_image_viewer_horizontal_drag_snaps_to_the_next_page() -> None:
    assert image_viewer_release_target(
        offset_x=-260.0,
        viewport_width=900,
        velocity_x=-100.0,
        index=1,
        image_count=5,
    ) == (2, -900.0)


def test_image_viewer_short_drag_springs_back_to_the_current_page() -> None:
    assert image_viewer_release_target(
        offset_x=-80.0,
        viewport_width=900,
        velocity_x=-100.0,
        index=1,
        image_count=5,
    ) == (1, 0.0)


def test_image_viewer_last_page_always_springs_back() -> None:
    assert image_viewer_release_target(
        offset_x=-500.0,
        viewport_width=900,
        velocity_x=-1400.0,
        index=4,
        image_count=5,
    ) == (4, 0.0)


def test_image_viewer_fast_flick_can_change_page_before_distance_threshold() -> None:
    assert image_viewer_release_target(
        offset_x=60.0,
        viewport_width=900,
        velocity_x=1000.0,
        index=2,
        image_count=5,
    ) == (1, 900.0)


def test_image_viewer_defaults_to_a_large_screen_relative_window() -> None:
    assert image_viewer_window_size(QSize(1920, 1080)) == QSize(1400, 886)
    assert image_viewer_window_size(QSize(1366, 768)) == QSize(1120, 680)


def test_image_viewer_still_fits_on_a_small_screen() -> None:
    assert image_viewer_window_size(QSize(800, 600)) == QSize(752, 552)


def test_image_gallery_opens_the_full_list_at_the_clicked_index(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    shown: list[tuple[list[object], int]] = []
    monkeypatch.setattr("ui.dialogs.media_files.read_bytes", lambda *_args: b"")
    monkeypatch.setattr(
        "ui.dialogs.show_image_viewer",
        lambda images, _parent, *, initial_index=0: shown.append((images, initial_index)),
    )
    gallery = ImageGallery(["one", "two", "three"])
    try:
        gallery._on_preview(gallery._cards[1])
        assert shown == [(["one", "two", "three"], 1)]
    finally:
        gallery.close()
        gallery.deleteLater()
        app.processEvents()


def test_image_canvas_starts_at_requested_page_without_decoding_on_constructor(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("ui.dialogs.QTimer.singleShot", lambda *_args: None)
    canvas = _ImageViewerCanvas(["one", "two", "three"], 2)
    try:
        canvas.resize(QSize(900, 600))
        assert canvas.index == 2
        assert image_viewer_paging_enabled(canvas._zoom)
    finally:
        canvas.close()
        canvas.deleteLater()
        app.processEvents()


def test_preloaded_page_is_centered_before_its_full_source_finishes(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("ui.dialogs.QTimer.singleShot", lambda *_args: None)
    monkeypatch.setattr("ui.dialogs._ImageSourceWorker.start", lambda _self: None)
    canvas = _ImageViewerCanvas(["one", "two"], 1)
    try:
        canvas.resize(QSize(900, 600))
        canvas._page_preview[1] = (QImage(400, 200, QImage.Format_RGB32), QSize(400, 200))

        canvas._load_current()

        assert canvas._offset == QPointF(0.0, 75.0)
    finally:
        canvas.close()
        canvas.deleteLater()
        app.processEvents()
