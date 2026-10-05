"""Per-vault device identity persistence for the PC client.

Each vault gets an independent Ed25519 device keypair. Identities live in the
same authenticated, DPAPI-protected config channel as all other local settings.
The former plaintext ``device_identities.json`` is migrated once.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .storage import default_vault_path
from . import config


_DEVICE_FILE = "device_identities.json"
_CONFIG_KEY = "device_identities"
_lock = threading.RLock()


def device_public_key(seed: bytes) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("device private seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _path() -> Path:
    return default_vault_path().with_name(_DEVICE_FILE)


def _validate(data: object) -> dict:
    if not isinstance(data, dict):
        raise config.ConfigIntegrityError("设备身份配置格式无效")
    for vault_text, record in data.items():
        try:
            uuid.UUID(vault_text)
            if not isinstance(record, dict):
                raise ValueError
            seed = bytes.fromhex(record["seed_hex"])
            device_id = uuid.UUID(record["device_id"])
            expected = record["public_key_hex"]
            if len(seed) != 32 or device_public_key(seed).hex() != expected:
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise config.ConfigIntegrityError("设备身份配置完整性验证失败") from error
    return data


def _load() -> dict:
    stored = config.get(_CONFIG_KEY)
    if stored is not None:
        return _validate(stored)
    legacy = _path()
    if not legacy.exists():
        return {}
    try:
        migrated = _validate(json.loads(legacy.read_text(encoding="utf-8")))
    except Exception as error:
        if isinstance(error, config.ConfigIntegrityError):
            raise
        raise config.ConfigIntegrityError("旧设备身份配置无法验证") from error
    config.set(_CONFIG_KEY, migrated)
    legacy.unlink()
    return migrated


def load_or_create(vault_id: uuid.UUID) -> tuple[uuid.UUID, bytes]:
    """Return (device_id, private_seed) for the vault, creating and persisting it on first use."""
    if not isinstance(vault_id, uuid.UUID):
        raise TypeError("vault_id must be a UUID")
    with _lock:
        data = _load()
        key = str(vault_id)
        record = data.get(key)
        if isinstance(record, dict):
            seed_hex = record.get("seed_hex", "")
            device_text = record.get("device_id", "")
            if len(seed_hex) == 64 and device_text:
                try:
                    seed = bytes.fromhex(seed_hex)
                    device_id = uuid.UUID(device_text)
                    expected = record.get("public_key_hex", "")
                    if device_public_key(seed).hex() == expected:
                        return device_id, seed
                except (ValueError, TypeError):
                    pass
        device_id = uuid.uuid4()
        seed = secrets.token_bytes(32)
        data[key] = {
            "device_id": str(device_id),
            "seed_hex": seed.hex(),
            "public_key_hex": device_public_key(seed).hex(),
        }
        config.set(_CONFIG_KEY, data)
        return device_id, seed


def delete(vault_id: uuid.UUID) -> None:
    """Remove the persisted identity (used when the vault account is purged)."""
    with _lock:
        data = _load()
        data.pop(str(vault_id), None)
        config.set(_CONFIG_KEY, data)
