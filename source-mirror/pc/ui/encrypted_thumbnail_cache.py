"""Encrypted, size-bounded PMVE thumbnail cache. Plain pixels never reach disk."""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from PySide6.QtCore import QBuffer, QIODevice
from PySide6.QtGui import QImage

from core import media_files

_MAGIC = b"FVTC1"
_MAX_FILES = 128
_MAX_ENCODED = 4 * 1024 * 1024


def _cache_parts(value: object, longest_side: int):
    if not media_files.is_ref(value):
        return None
    vault = media_files._active_vault_context()
    if vault is None or not hasattr(vault, "root_key_for_device_unlock"):
        return None
    identity = vault.pmve_identity
    vault_id = str(identity.vault_id)
    root = bytearray(vault.root_key_for_device_unlock())
    try:
        key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=uuid.UUID(vault_id).bytes,
            info=b"faevault-thumbnail-cache-v1",
        ).derive(root)
    finally:
        root[:] = b"\0" * len(root)
    digest = hashlib.sha256(
        f"{media_files.cache_key(value)}:{longest_side}".encode("utf-8")
    ).digest()
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    path = base / "FAEVault" / "encrypted-thumbnails" / vault_id / (digest.hex() + ".bin")
    return path, key, digest


def read(value: object, longest_side: int) -> QImage | None:
    try:
        parts = _cache_parts(value, longest_side)
    except (OSError, ValueError, RuntimeError, AttributeError):
        return None
    if parts is None:
        return None
    path, key, digest = parts
    try:
        payload = path.read_bytes()
        if not payload.startswith(_MAGIC) or len(payload) > _MAX_ENCODED + 64:
            return None
        image = QImage.fromData(AESGCM(key).decrypt(payload[5:17], payload[17:], digest))
        return image if not image.isNull() else None
    except (OSError, ValueError, InvalidTag):
        return None


def write(value: object, longest_side: int, image: QImage) -> None:
    try:
        parts = _cache_parts(value, longest_side)
    except (OSError, ValueError, RuntimeError, AttributeError):
        return
    if parts is None or image.isNull():
        return
    path, key, digest = parts
    buffer = QBuffer()
    if not buffer.open(QIODevice.WriteOnly) or not image.save(buffer, "PNG"):
        return
    encoded = bytes(buffer.data())
    if len(encoded) > _MAX_ENCODED:
        return
    nonce = os.urandom(12)
    payload = _MAGIC + nonce + AESGCM(key).encrypt(nonce, encoded, digest)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(payload)
        os.replace(temporary, path)
        files = list(path.parent.glob("*.bin"))
        if len(files) > _MAX_FILES:
            for old in sorted(files, key=lambda item: item.stat().st_mtime)[:len(files) - _MAX_FILES]:
                old.unlink(missing_ok=True)
    except OSError:
        pass
    finally:
        temporary.unlink(missing_ok=True)
