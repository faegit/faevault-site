"""导出压缩包测试：对齐 Android ArchiveExporter 格式（manifest/data.json/logins.csv/媒体目录）。"""

from __future__ import annotations

import io
import json
import uuid
from pathlib import Path

import pytest
import pyzipper

from core.export_archive import Stats, export_archive, suggested_filename
from core.models import Entry, SecretType
from core.pmv_attachment import AttachmentKind
from core.pmv_media_ref import MediaRef

PASSWORD = "export-password"


def _ref(content: bytes, kind: AttachmentKind = AttachmentKind.ATTACHMENT, generation: int = 1) -> MediaRef:
    import hashlib

    return MediaRef(uuid.uuid4(), generation, kind, len(content), hashlib.sha256(content).digest())


class FakeMedia:
    """内存版 MediaSource：按 (object_id, generation) 存明文内容。"""

    def __init__(self) -> None:
        self._contents: dict[tuple[uuid.UUID, int], bytes] = {}

    def add(self, ref: MediaRef, content: bytes) -> None:
        self._contents[(ref.object_id, ref.generation)] = content

    def read_prefix(self, ref: MediaRef, length: int) -> bytes:
        return self._contents[(ref.object_id, ref.generation)][:length]

    def read_all(self, ref: MediaRef, output) -> None:
        output.write(self._contents[(ref.object_id, ref.generation)])


def _open_archive(path: Path):
    archive = pyzipper.AESZipFile(path)
    archive.setpassword(PASSWORD.encode("utf-8"))
    return archive


def _names(archive) -> set[str]:
    return {info.filename for info in archive.infolist()}


def _entry_with_attachment(title: str, name: str, mime: str, content: bytes) -> tuple[Entry, MediaRef]:
    ref = _ref(content, AttachmentKind.ATTACHMENT)
    entry = Entry(
        title=title,
        secret_type=SecretType.CUSTOM,
        fields={
            "attachments": [
                {
                    "name": name,
                    "mime": mime,
                    "size": len(content),
                    "sha256": content_hex(content),
                    "data": ref.to_json(),
                }
            ]
        },
    )
    return entry, ref


def content_hex(content: bytes) -> str:
    import hashlib

    return hashlib.sha256(content).digest().hex()


def test_export_archive_basic_structure(tmp_path: Path) -> None:
    login = Entry(title="GitHub", username="alice", password="secret", url="https://github.com")
    entry, ref = _entry_with_attachment("文档", "合同.pdf", "application/pdf", b"%PDF-1.7 hello")
    media = FakeMedia()
    media.add(ref, b"%PDF-1.7 hello")
    image_ref = _ref(b"\x89PNG\r\n\x1a\nimage", AttachmentKind.IMAGE)
    note = Entry(
        title="备忘",
        secret_type=SecretType.SECURE_NOTE,
        fields={"images": [image_ref.to_json()]},
    )
    media.add(image_ref, b"\x89PNG\r\n\x1a\nimage")
    entries = [login, entry, note]

    path = tmp_path / "out.zip"
    with path.open("wb") as raw:
        stats = export_archive(raw, "测试库", PASSWORD, entries, media, app_version="vault-pc-test")

    assert stats == Stats(login_count=1, other_count=2, media_count=2)

    with _open_archive(path) as archive:
        assert _names(archive) >= {"manifest.json", "logins.csv", "data.json"}
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "faevault-export"
        assert manifest["formatVersion"] == 1
        assert manifest["vaultName"] == "测试库"
        assert manifest["entryCount"] == 3
        assert manifest["loginCount"] == 1
        assert manifest["otherCount"] == 2
        assert manifest["mediaCount"] == 2
        assert manifest["appVersion"] == "vault-pc-test"

        attachment_files = [f for f in manifest["files"] if f["kind"] == "attachment"]
        image_files = [f for f in manifest["files"] if f["kind"] == "image"]
        assert len(attachment_files) == 1
        assert len(image_files) == 1
        # 附件还原原始文件名与格式
        assert attachment_files[0]["path"] == "attachments/合同.pdf"
        assert attachment_files[0]["originalName"] == "合同.pdf"
        assert attachment_files[0]["mime"] == "application/pdf"
        assert attachment_files[0]["sha256"] == content_hex(b"%PDF-1.7 hello")
        assert attachment_files[0]["entryId"] == entry.id
        # 图片无原始名，魔数嗅探
        assert image_files[0]["path"].startswith("images/")
        assert image_files[0]["path"].endswith(".png")

        # logins.csv：仅登录条目，列与 Android 对齐
        csv_text = archive.read("logins.csv").decode("utf-8-sig")
        assert "GitHub" in csv_text and "alice" in csv_text
        assert "合同" not in csv_text

        # data.json：仅非登录条目，媒体引用重写为文件路径
        data = json.loads(archive.read("data.json"))
        assert data["format"] == "faevault-export"
        assert data["formatVersion"] == 1
        assert len(data["entries"]) == 2
        note_entry = next(e for e in data["entries"] if e["secret_type"] == "secure_note")
        image_ref_out = note_entry["fields"]["images"][0]
        assert image_ref_out["type"] == "file"
        assert image_ref_out["path"] == image_files[0]["path"]
        assert image_ref_out["sha256"] == content_hex(b"\x89PNG\r\n\x1a\nimage")

        # 媒体明文
        assert archive.read("attachments/合同.pdf") == b"%PDF-1.7 hello"
        assert archive.read(image_files[0]["path"]) == b"\x89PNG\r\n\x1a\nimage"


def test_export_archive_attachment_mime_fallback_and_dedup(tmp_path: Path) -> None:
    a, ref_a = _entry_with_attachment("A", "noext", "text/plain", b"plain text")
    b, ref_b = _entry_with_attachment("B", "报告.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"docx bytes")
    b2, ref_b2 = _entry_with_attachment("C", "报告.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", b"other bytes")
    media = FakeMedia()
    for ref, content in [(ref_a, b"plain text"), (ref_b, b"docx bytes"), (ref_b2, b"other bytes")]:
        media.add(ref, content)

    path = tmp_path / "out.zip"
    with path.open("wb") as raw:
        export_archive(raw, "库", PASSWORD, [a, b, b2], media)

    with _open_archive(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        paths = sorted(f["path"] for f in manifest["files"])
        assert "attachments/noext.txt" in paths
        assert "attachments/报告.docx" in paths
        assert "attachments/报告_2.docx" in paths


def test_export_archive_image_sniff_jpg_fallback(tmp_path: Path) -> None:
    ref = _ref(b"\xff\xd8\xff\xe0 jpeg!", AttachmentKind.IMAGE)
    entry = Entry(
        title="图片",
        secret_type=SecretType.CUSTOM,
        fields={"images": [ref.to_json()]},
    )
    media = FakeMedia()
    media.add(ref, b"\xff\xd8\xff\xe0 jpeg!")

    path = tmp_path / "out.zip"
    with path.open("wb") as raw:
        export_archive(raw, "库", PASSWORD, [entry], media)

    with _open_archive(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["files"][0]["path"].endswith(".jpg")


def test_export_archive_requires_password(tmp_path: Path) -> None:
    login = Entry(title="GitHub", username="alice", password="secret")
    path = tmp_path / "out.zip"
    with path.open("wb") as raw:
        export_archive(raw, "库", PASSWORD, [login], FakeMedia())

    with pytest.raises(Exception):
        with pyzipper.AESZipFile(path) as archive:
            archive.read("logins.csv")


def test_export_archive_excludes_trash_and_empty_vault(tmp_path: Path) -> None:
    trashed = Entry(title="已删", deleted_at=1_700_000_000.0)
    path = tmp_path / "out.zip"
    with path.open("wb") as raw:
        stats = export_archive(raw, "库", PASSWORD, [trashed], FakeMedia())

    assert stats == Stats(login_count=0, other_count=0, media_count=0)
    with _open_archive(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["entryCount"] == 0
        assert "已删" not in archive.read("data.json").decode("utf-8")


def test_suggested_filename_sanitizes_vault_name() -> None:
    import datetime

    date = datetime.date(2026, 8, 17)
    assert suggested_filename("我的 保险库/测试", date) == "Vault_我的_保险库_测试_20260817.zip"
    assert suggested_filename("", date) == "Vault_item_20260817.zip"