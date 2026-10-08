import uuid
import pytest
from core import config, deletion_baseline as d

REAL_UPDATE = config.update

def test_protected_floor_transaction_is_global_and_failed_commit_does_not_advance(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "update", REAL_UPDATE)
    monkeypatch.setattr(config, "default_vault_path", lambda: tmp_path / "default.pmv")
    monkeypatch.setattr(config, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(config, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    monkeypatch.setattr(config, "_config_cache", None)
    monkeypatch.setattr(config, "_config_integrity_failed", False)
    config.set("current_user", "first-account")
    vault_id = str(uuid.uuid4())
    current = {"schema_version": 1, "generation": 1, "epoch": str(uuid.uuid4()), "checkpoint": None}
    d.accept_floor(vault_id, current)
    config.set("current_user", "second-account")
    with pytest.raises(ValueError):
        d.accept_floor(vault_id, None)
    new = dict(current, generation=2, epoch=str(uuid.uuid4()))
    def failed():
        raise RuntimeError("atomic commit rejected")
    with pytest.raises(RuntimeError):
        d.commit_with_floor(vault_id, new, failed)
    assert config.load()[d.FLOOR_KEY][vault_id] == current
    assert current["epoch"] not in (tmp_path / "config.json").read_text(encoding="utf-8")
    other = str(uuid.uuid4())
    d.accept_floor(other, new)
    assert set(config.load()[d.FLOOR_KEY]) == {vault_id, other}
