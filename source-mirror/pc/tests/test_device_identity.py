"""Device identity persistence tests (tmp vault dir isolation via monkeypatch)."""

import os
import uuid

import pytest

import core.device_identity as device_identity


def _isolate(monkeypatch, tmp_path):
    vault = tmp_path / "vaults" / "default.pmv"
    monkeypatch.setattr("core.device_identity.default_vault_path", lambda: vault)
    monkeypatch.setattr("core.config.default_vault_path", lambda: vault)
    monkeypatch.setattr("core.config._protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr("core.config._unprotect_key", lambda value: value.removeprefix(b"protected:"))
    device_identity.config.invalidate_cache()
    return vault


def test_load_or_create_is_stable_and_derives_public_key(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    vault_id = uuid.uuid4()
    first = device_identity.load_or_create(vault_id)
    second = device_identity.load_or_create(vault_id)
    assert first[0] == second[0]
    assert first[1] == second[1]
    assert len(device_identity.device_public_key(first[1])) == 32
    identity_file = tmp_path / "vaults" / "device_identities.json"
    assert not identity_file.exists()
    encrypted = (tmp_path / "vaults" / "config.json").read_text("utf-8")
    assert first[1].hex() not in encrypted


def test_delete_removes_only_the_target_vault(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    a = uuid.uuid4()
    b = uuid.uuid4()
    a_first = device_identity.load_or_create(a)[0]
    b_identity = device_identity.load_or_create(b)[0]
    device_identity.delete(a)
    a_second = device_identity.load_or_create(a)[0]
    assert a_second != a_first
    assert device_identity.load_or_create(b)[0] == b_identity


def test_tampered_identity_store_fails_closed_without_key_rotation(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    vault_id = uuid.uuid4()
    original = device_identity.load_or_create(vault_id)
    data = device_identity.config.load()
    data["device_identities"][str(vault_id)]["public_key_hex"] = "00" * 32
    device_identity.config.save(data)
    with pytest.raises(device_identity.config.ConfigIntegrityError):
        device_identity.load_or_create(vault_id)
    assert original[0] != uuid.UUID(int=0)


def test_plaintext_identity_store_migrates_atomically(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    vault_id = uuid.uuid4()
    seed = bytes(range(32))
    identity = uuid.uuid4()
    legacy = tmp_path / "vaults" / "device_identities.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text(__import__("json").dumps({str(vault_id): {
        "device_id": str(identity), "seed_hex": seed.hex(),
        "public_key_hex": device_identity.device_public_key(seed).hex(),
    }}), "utf-8")
    assert device_identity.load_or_create(vault_id) == (identity, seed)
    assert not legacy.exists()
    assert seed.hex() not in (tmp_path / "vaults" / "config.json").read_text("utf-8")
