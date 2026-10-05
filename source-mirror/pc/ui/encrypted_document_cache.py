"""Encrypted local cache for rendered Markdown documents."""

from __future__ import annotations

import hashlib
import os
import uuid
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import media_files

_MAGIC = b"FVMD1"
_MAX_FILES = 64
_MAX_COMPRESSED = 16 * 1024 * 1024


def _parts(text: str, colors: dict):
    vault = media_files._active_vault_context()
    if vault is None or not hasattr(vault, "root_key_for_device_unlock"):
        return None
    vault_id = str(vault.pmve_identity.vault_id)
    root = bytearray(vault.root_key_for_device_unlock())
    try:
        key = HKDF(
            algorithm=hashes.SHA256(), length=32,
            salt=uuid.UUID(vault_id).bytes,
            info=b"faevault-markdown-cache-v1",
        ).derive(root)
    finally:
        root[:] = b"\0" * len(root)
    digest = hashlib.sha256()
    digest.update(b"markdown-renderer-v3-lazy-diagrams\0")
    digest.update(text.encode("utf-8"))
    digest.update(repr(sorted(colors.items())).encode("utf-8"))
    name = digest.digest()
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    path = base / "FAEVault" / "encrypted-documents" / vault_id / (name.hex() + ".bin")
    return path, key, name


def read(text: str, colors: dict) -> str | None:
    try:
        parts = _parts(text, colors)
        if parts is None:
            return None
        path, key, digest = parts
        payload = path.read_bytes()
        if not payload.startswith(_MAGIC) or len(payload) > _MAX_COMPRESSED + 64:
            return None
        compressed = AESGCM(key).decrypt(payload[5:17], payload[17:], digest)
        decompressor = zlib.decompressobj()
        plain = decompressor.decompress(compressed, 32 * 1024 * 1024 + 1)
        if len(plain) > 32 * 1024 * 1024 or not decompressor.eof:
            return None
        return plain.decode("utf-8")
    except (OSError, ValueError, RuntimeError, AttributeError, InvalidTag, zlib.error):
        return None


def write(text: str, colors: dict, html: str) -> None:
    try:
        parts = _parts(text, colors)
        if parts is None:
            return
        path, key, digest = parts
        compressed = zlib.compress(html.encode("utf-8"), level=3)
        if len(compressed) > _MAX_COMPRESSED:
            return
        nonce = os.urandom(12)
        payload = _MAGIC + nonce + AESGCM(key).encrypt(nonce, compressed, digest)
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_bytes(payload)
            os.replace(temporary, path)
            files = list(path.parent.glob("*.bin"))
            if len(files) > _MAX_FILES:
                for old in sorted(files, key=lambda item: item.stat().st_mtime)[:len(files) - _MAX_FILES]:
                    old.unlink(missing_ok=True)
        finally:
            temporary.unlink(missing_ok=True)
    except (OSError, ValueError, RuntimeError, AttributeError):
        return
