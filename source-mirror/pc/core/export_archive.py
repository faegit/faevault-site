"""导出压缩包（对齐 Android ArchiveExporter 格式）。

结构（WinZip AES-256 加密，口令为导出口令）：

    Vault_<账户名>_<yyyyMMdd>.zip
    ├── manifest.json     导出元信息与媒体文件清单
    ├── logins.csv        登录条目（复用 importers 的 Android 对齐 CSV 列，明文）
    ├── data.json         非登录条目完整 JSON；PMVE 媒体引用重写为相对路径
    ├── images/           图片媒体明文
    └── attachments/      附件媒体明文（还原入库时的原始文件名/扩展名）

全程不落明文临时文件；压缩包内为解密后的明文，加密与保护由 AES-256 口令承担，
仅主密码守门后允许触发。
"""

from __future__ import annotations

import datetime
import io
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
from uuid import UUID

import pyzipper

from . import pmv_media_ref
from .importers import _csv_export_payload
from .models import Entry, SecretType
from .pmv_attachment import AttachmentKind
from .pmv_media_ref import MediaRef

FORMAT_VERSION = 1

_MIME_TO_EXT: dict[str, str] = {
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-7z-compressed": ".7z",
    "application/x-rar-compressed": ".rar",
    "application/x-tar": ".tar",
    "application/gzip": ".gz",
    "application/x-bzip2": ".bz2",
    "application/json": ".json",
    "application/xml": ".xml",
    "application/javascript": ".js",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.android.package-archive": ".apk",
    "application/x-httpd-php": ".php",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/html": ".html",
    "text/xml": ".xml",
    "text/markdown": ".md",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/heic": ".heic",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "image/svg+xml": ".svg",
    "font/otf": ".otf",
    "font/ttf": ".ttf",
}

_IMAGE_DIR = "images"
_ATTACHMENT_DIR = "attachments"


@dataclass(frozen=True)
class Stats:
    login_count: int
    other_count: int
    media_count: int


class MediaSource(Protocol):
    """PMVE 媒体顺序读取接入：实现方负责按块流式解码（见 Vault.open_media_object / open_media_range）。"""

    def read_prefix(self, ref: MediaRef, length: int) -> bytes:
        """读取对象前 ``length`` 字节用于嗅探扩展名；对象更短时返回实际字节。"""

    def read_all(self, ref: MediaRef, output: BinaryIO) -> None:
        """将对象全部明文顺序写入 ``output``。"""


class VaultMediaSource:
    """基于打开状态的 PMVE 保险库的 [MediaSource] 实现。"""

    def __init__(self, vault: object) -> None:
        self._vault = vault

    def read_prefix(self, ref: MediaRef, length: int) -> bytes:
        if ref.size <= 0 or length <= 0:
            return b""
        if length >= ref.size:
            output = io.BytesIO()
            self._vault.open_media_object(ref, output)
            return output.getvalue()
        output = io.BytesIO()
        self._vault.open_media_range(ref, 0, length, output)
        return output.getvalue()

    def read_all(self, ref: MediaRef, output: BinaryIO) -> None:
        self._vault.open_media_object(ref, output)


@dataclass(frozen=True)
class _MediaMeta:
    name: str | None
    mime: str | None


@dataclass(frozen=True)
class _MediaEntry:
    ref: MediaRef
    kind: AttachmentKind
    path: str
    entry_id: str
    original_name: str | None
    mime: str | None


def app_version() -> str:
    """读取 pyproject.toml 版本；打包环境缺失时回退。"""
    try:
        root = Path(__file__).resolve().parent.parent
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        return str(data.get("project", {}).get("version") or "1.0.0")
    except Exception:
        return "1.0.0"


def suggested_filename(vault_name: str, date: datetime.date | None = None) -> str:
    date = date or datetime.date.today()
    return f"Vault_{sanitize_segment(vault_name)}_{date.strftime('%Y%m%d')}.zip"


def export_archive(
    raw: BinaryIO,
    vault_name: str,
    password: str,
    entries: list[Entry],
    media: MediaSource,
    *,
    app_version: str = "vault-pc",
) -> Stats:
    """把库内全部活跃条目导出为 AES-256 加密压缩包，写入 ``raw``。

    与 Android ``ArchiveExporter.writeToZip`` 同格式；纯 JVM/Python 侧入口，
    不依赖桌面 UI 与打开状态之外的上下文（媒体读取经 ``media`` 注入）。
    """
    entries = [e for e in entries if e.deleted_at is None]
    logins = [e for e in entries if e.secret_type == SecretType.LOGIN]
    others = [e for e in entries if e.secret_type != SecretType.LOGIN]

    # 附件媒体对象在条目里带原始文件名/MIME 兄弟字段（data 引用 + name/mime），
    # 先全量收集用于还原原始文件名与扩展名。
    attachment_meta: dict[tuple[UUID, int], _MediaMeta] = {}
    for entry in entries:
        _walk_media_meta(entry.fields, attachment_meta)

    # 收集全部 PMVE 媒体出现点，按对象去重并分配导出路径。
    object_by_key: dict[tuple[UUID, int], _MediaEntry] = {}
    used_names: dict[str, int] = {}
    for entry in entries:
        index = 0
        for occurrence in pmv_media_ref.scan(entry):
            ref = occurrence.ref
            if ref is None or occurrence.classification is not pmv_media_ref.Classification.OBJECT:
                continue
            key = (ref.object_id, ref.generation)
            if key in object_by_key:
                continue
            kind = occurrence.kind or ref.kind
            directory = _IMAGE_DIR if kind is AttachmentKind.IMAGE else _ATTACHMENT_DIR
            if kind is AttachmentKind.IMAGE:
                ext = _sniff_extension(ref, media, kind)
                object_by_key[key] = _MediaEntry(
                    ref, kind, f"{directory}/{sanitize_segment(entry.id)}_{index}{ext}", entry.id, None, None,
                )
                index += 1
            else:
                meta = attachment_meta.get(key)
                ext = _sniff_extension(ref, media, kind)
                name = _resolve_attachment_name(meta.name if meta else None, meta.mime if meta else None, ext)
                object_by_key[key] = _MediaEntry(
                    ref, kind, f"{directory}/{_unique_name(used_names, name)}", entry.id,
                    meta.name if meta else None, meta.mime if meta else None,
                )

    # 1) manifest.json
    files: list[dict[str, object]] = []
    for media_entry in object_by_key.values():
        item: dict[str, object] = {
            "path": media_entry.path,
            "kind": "image" if media_entry.kind is AttachmentKind.IMAGE else "attachment",
            "entryId": media_entry.entry_id,
            "sha256": media_entry.ref.sha256.hex(),
            "size": media_entry.ref.size,
        }
        if media_entry.original_name:
            item["originalName"] = media_entry.original_name
        if media_entry.mime:
            item["mime"] = media_entry.mime
        files.append(item)
    manifest = {
        "format": "faevault-export",
        "formatVersion": FORMAT_VERSION,
        "exportedAt": datetime.datetime.now().astimezone().isoformat(),
        "appVersion": app_version,
        "vaultName": vault_name,
        "entryCount": len(entries),
        "loginCount": len(logins),
        "otherCount": len(others),
        "mediaCount": len(object_by_key),
        "files": files,
    }

    # 2) logins.csv
    csv_bytes = _csv_export_payload(logins)

    # 3) data.json：非登录条目完整 JSON，媒体引用重写为相对路径
    data_entries: list[dict[str, object]] = []
    for entry in others:
        replacements: dict[str, object] = {}
        for occurrence in pmv_media_ref.scan(entry):
            ref = occurrence.ref
            if ref is None or occurrence.classification is not pmv_media_ref.Classification.OBJECT:
                continue
            media_entry = object_by_key[(ref.object_id, ref.generation)]
            value: dict[str, object] = {
                "type": "file",
                "path": media_entry.path,
                "sha256": media_entry.ref.sha256.hex(),
                "size": media_entry.ref.size,
            }
            if media_entry.original_name:
                value["originalName"] = media_entry.original_name
            if media_entry.mime:
                value["mime"] = media_entry.mime
            replacements[occurrence.path] = value
        fields = {
            key: pmv_media_ref._replace(value, f"/fields/{pmv_media_ref._escape(key)}", replacements)
            for key, value in entry.fields.items()
        }
        payload = entry.to_dict()
        payload["fields"] = fields
        data_entries.append(payload)
    data_json = {"format": "faevault-export", "formatVersion": FORMAT_VERSION, "entries": data_entries}

    # 4) 写压缩包：全部条目 WinZip AES-256 加密
    with pyzipper.AESZipFile(
        raw, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zip_file:
        zip_file.setpassword(password.encode("utf-8"))
        zip_file.setencryption(pyzipper.WZ_AES, nbits=256)
        zip_file.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, allow_nan=False))
        zip_file.writestr("logins.csv", csv_bytes)
        zip_file.writestr("data.json", json.dumps(data_json, ensure_ascii=False, allow_nan=False))
        for media_entry in object_by_key.values():
            buffer = io.BytesIO()
            media.read_all(media_entry.ref, buffer)
            zip_file.writestr(media_entry.path, buffer.getvalue())

    return Stats(len(logins), len(others), len(object_by_key))


def _sniff_extension(ref: MediaRef, media: MediaSource, kind: AttachmentKind) -> str:
    prefix = media.read_prefix(ref, 32)
    if len(prefix) >= 3 and prefix[:3] == b"GIF":
        return ".gif"
    if len(prefix) >= 4 and prefix[:4] == b"\x89PNG":
        return ".png"
    if len(prefix) >= 12 and prefix[:4] == b"RIFF" and prefix[8:12] == b"WEBP":
        return ".webp"
    if len(prefix) >= 12 and prefix[4:12].startswith(b"ftyphei"):
        return ".heic"
    if len(prefix) >= 2 and prefix[:2] == b"\xff\xd8":
        return ".jpg"
    if len(prefix) >= 5 and prefix[:5] == b"%PDF-":
        return ".pdf"
    if len(prefix) >= 2 and prefix[:2] == b"PK":
        return ".zip"
    return ".jpg" if kind is AttachmentKind.IMAGE else ".bin"


def sanitize_segment(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "_-" else "_" for c in name)
    return cleaned or "item"


def _resolve_attachment_name(original_name: str | None, mime: str | None, sniffed_ext: str) -> str:
    base = _sanitize_file_name(original_name) if original_name else ""
    if base:
        dot = base.rfind(".")
        name_ext = base[dot + 1:] if dot > 0 else ""
        if name_ext and len(name_ext) <= 8 and name_ext.isalnum():
            return base
        return base + (mime_to_ext(mime) or sniffed_ext)
    return "attachment" + (mime_to_ext(mime) or sniffed_ext)


def _sanitize_file_name(name: str) -> str:
    base = name.split("/")[-1].split("\\")[-1].strip()
    base = "".join(c if c.isalnum() or c in "._- " else "_" for c in base)
    base = base.lstrip(".")
    return base[:120]


def _unique_name(used: dict[str, int], name: str) -> str:
    count = used.get(name, 0) + 1
    used[name] = count
    if count == 1:
        return name
    dot = name.rfind(".")
    if dot > 0:
        return name[:dot] + f"_{count}" + name[dot:]
    return name + f"_{count}"


def mime_to_ext(mime: str | None) -> str | None:
    if not mime:
        return None
    return _MIME_TO_EXT.get(mime.split(";")[0].strip().lower())


def _walk_media_meta(value: object, out: dict[tuple[UUID, int], _MediaMeta]) -> None:
    """递归收集附件对象（data 引用 + name/mime 兄弟字段）的原始文件名与 MIME。"""
    if isinstance(value, dict):
        data = value.get("data")
        if data is not None:
            ref = _parse_media_ref(data)
            if ref is not None:
                name = value.get("name")
                mime = value.get("mime")
                if not isinstance(name, str) or not name.strip():
                    name = None
                if not isinstance(mime, str) or not mime.strip():
                    mime = None
                if name is not None or mime is not None:
                    out.setdefault((ref.object_id, ref.generation), _MediaMeta(name, mime))
        for child in value.values():
            _walk_media_meta(child, out)
    elif isinstance(value, list):
        for child in value:
            _walk_media_meta(child, out)


def _parse_media_ref(value: object) -> MediaRef | None:
    try:
        if isinstance(value, dict):
            return pmv_media_ref.from_json(value)
        if isinstance(value, str):
            return pmv_media_ref.from_external_string(value)
    except (TypeError, ValueError):
        return None
    return None