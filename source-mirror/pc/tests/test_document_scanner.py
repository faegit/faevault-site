"""Card document scan and four-corner review regressions."""

import cv2
import numpy as np
from PySide6.QtCore import QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFormLayout, QLineEdit

from core.models import SecretType
from core import modules
from ui.dialogs import EntryDialog
from ui.document_scanner import DocumentCropView, crop_document, detect_document_corners


def _sample_document():
    frame = np.full((500, 700, 3), 35, dtype=np.uint8)
    quad = np.array([[90, 70], [610, 88], [590, 430], [75, 410]], dtype=np.int32)
    cv2.fillConvexPoly(frame, quad, (240, 240, 240))
    cv2.polylines(frame, [quad], True, (15, 15, 15), 4)
    return frame


def test_document_edges_and_four_corner_crop():
    QApplication.instance() or QApplication([])
    frame = _sample_document()
    corners = detect_document_corners(frame)
    assert corners is not None and corners.shape == (4, 2)
    view = DocumentCropView()
    view.resize(700, 500)
    view.set_frame(frame, corners)
    before = view.corners()
    anchor = view._screen_point(before[0])
    QTest.mouseClick(view, Qt.LeftButton, pos=QPoint(int(anchor.x()), int(anchor.y())))
    QTest.mouseClick(view, Qt.LeftButton, pos=QPoint(120, 90))
    assert not np.array_equal(view.corners(), before)
    cropped = cv2.imdecode(np.frombuffer(view.cropped_bytes(), dtype=np.uint8), cv2.IMREAD_COLOR)
    assert cropped is not None and cropped.shape[0] > 250 and cropped.shape[1] > 400
    assert len(crop_document(frame, corners)) > 1000


def test_card_editor_places_scan_and_images_before_fields_and_autofills_empty_fields(monkeypatch):
    from core import ocr

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ocr, "ocr_image", lambda _data: "sample")
    monkeypatch.setattr(ocr, "parse_credit_card", lambda _text: {
        "card_number": "1234567890123456", "cardholder": "OCR NAME", "bank": "OCR BANK",
    })
    dialog = EntryDialog(default_type=SecretType.CARD_DOCUMENT, show_type_selector=False)
    try:
        page = dialog.stacked.currentWidget()
        form = page.layout()
        assert isinstance(form, QFormLayout)
        assert form.getWidgetPosition(page.card_type)[0] < form.getWidgetPosition(page.scan_button)[0]
        assert form.getWidgetPosition(page.scan_button)[0] < form.getWidgetPosition(page.img_gallery.parentWidget())[0]
        assert form.getWidgetPosition(page.img_gallery.parentWidget())[0] < form.getWidgetPosition(page.cardholder)[0]
        assert page.img_gallery.MAX_IMAGES == 2
        assert page.img_gallery.add_handler is not None
        assert page.cvv.actions() and page.cvv.actions()[0].isCheckable()
        page.cardholder.setText("Existing name")
        page.img_gallery.image_added.emit(b"sample image")
        worker = dialog._ocr_worker
        assert worker.wait(5000)
        app.processEvents()
        assert page.cardholder.text() == "Existing name"
        assert page.card_number.text().replace(" ", "") == "1234567890123456"
        assert page.bank.text() == "OCR BANK"
        page.card_type.setCurrentIndex(page.card_type.findData(modules.CARD_ID_CARD))
        assert "身份证" in page.scan_button.text()
    finally:
        dialog.close()


def test_id_card_ocr_routes_to_document_parser_and_keeps_existing_values(monkeypatch):
    from core import ocr

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ocr, "ocr_image", lambda _data: "sample")
    monkeypatch.setattr(ocr, "parse_id_card", lambda _text: {
        "full_name": "OCR NAME", "id_number": "123456789012345678", "address": "Ignore me",
    })
    dialog = EntryDialog(default_type=SecretType.CARD_DOCUMENT, show_type_selector=False)
    try:
        page = dialog.stacked.currentWidget()
        page.card_type.setCurrentIndex(page.card_type.findData(modules.CARD_ID_CARD))
        page.full_name.setText("Existing name")
        page.img_gallery.image_added.emit(b"sample image")
        assert dialog._ocr_worker.wait(5000)
        app.processEvents()
        assert page.full_name.text() == "Existing name"
        assert page.id_number.text() == "123456789012345678"
    finally:
        dialog.close()


def test_card_module_uses_same_scanner_and_id_parser(monkeypatch):
    from core import ocr
    from ui.module_editor import ModuleCard, _OcrWorker

    QApplication.instance() or QApplication([])
    card = ModuleCard(modules.new_module(modules.CARD_DOCUMENT))
    try:
        card.show()
        QApplication.instance().processEvents()
        assert card._image_limit == 2
        assert card._image_add_handler == card._scan_document_camera
        card._editors["card_type"].setCurrentIndex(
            card._editors["card_type"].findData(modules.CARD_ID_CARD)
        )
        assert card._document_scan_button.isVisible()
        assert card._editors["id_number"].actions()[0].isCheckable()
    finally:
        card.close()

    monkeypatch.setattr(ocr, "ocr_image", lambda _data: "sample")
    monkeypatch.setattr(ocr, "parse_id_card", lambda _text: {
        "full_name": "OCR NAME", "id_number": "123456789012345678", "address": "ignored",
    })
    worker = _OcrWorker([b"sample image"], card_type=modules.CARD_ID_CARD)
    results = []
    worker.succeeded.connect(results.append)
    worker.run()
    assert results == [{"full_name": "OCR NAME", "id_number": "123456789012345678"}]


def test_password_module_reveal_is_inside_the_input():
    from ui.module_editor import ModuleCard

    QApplication.instance() or QApplication([])
    card = ModuleCard(modules.new_module(modules.PASSWORD))
    try:
        edit = card._editors["value"]
        assert edit.actions() and edit.actions()[0].isCheckable()
        edit.actions()[0].setChecked(True)
        assert edit.echoMode() == QLineEdit.Normal
    finally:
        card.close()
