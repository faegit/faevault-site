import copy
import uuid
import pytest
from core import deletion_baseline as d

OWN = str(uuid.uuid4())
OTHER = str(uuid.uuid4())
ENTRY = str(uuid.uuid4())

def metadata():
    return {"purge_tombstones": {ENTRY: 1.0}, "_device_activity_v1": {"version": 1, "profiles": [{"device_id": OWN, "platform": "pc"}, {"device_id": OTHER, "platform": "android"}]}}

def test_all_devices_need_checkpoint_ack_not_last_seen():
    m = d.start(metadata(), OWN)
    assert not d.ready(m, OWN)
    m = d.acknowledge(m, OTHER)
    assert d.ready(m, OWN)
    cp = m[d.FIELD]["checkpoint"]["checkpoint_id"]
    updated = d.finish(m, OWN, cp)
    assert updated["purge_tombstones"] == {}
    assert updated[d.FIELD]["generation"] == 1
    with pytest.raises(ValueError):
        d.guard(updated[d.FIELD], None)

def test_new_deletion_or_device_invalidates_readiness():
    m = d.acknowledge(d.start(metadata(), OWN), OTHER)
    cp = m[d.FIELD]["checkpoint"]["checkpoint_id"]
    changed = copy.deepcopy(m)
    changed["purge_tombstones"][str(uuid.uuid4())] = 2.0
    with pytest.raises(ValueError):
        d.finish(changed, OWN, cp)
    changed = copy.deepcopy(m)
    changed["_device_activity_v1"]["profiles"].append({"device_id": str(uuid.uuid4()), "platform": "pc"})
    assert not d.ready(changed, OWN)

def test_concurrent_checkpoints_fail_closed():
    a, b = d.start(metadata(), OWN), d.start(metadata(), OWN)
    assert d.merge(a[d.FIELD], b[d.FIELD])["checkpoint"] is None

def test_generations_and_epochs_block_old_copies():
    a = {"schema_version": 1, "generation": 1, "epoch": str(uuid.uuid4()), "checkpoint": None}
    b = dict(a, epoch=str(uuid.uuid4()))
    with pytest.raises(ValueError):
        d.guard(a, b)
    with pytest.raises(ValueError):
        d.guard(a, None)
    d.guard_adoption(None, a)
    with pytest.raises(ValueError):
        d.guard_adoption(a, None)

def test_unknown_schema_and_empty_members_block():
    with pytest.raises(ValueError):
        d.baseline({"schema_version": 2})
    m = d.start(metadata(), OWN)[d.FIELD]
    m["checkpoint"]["member_ids"] = []
    with pytest.raises(ValueError):
        d.baseline(m)

def test_persisted_floor_rejects_restart_downgrade():
    a = {"schema_version": 1, "generation": 1, "epoch": str(uuid.uuid4()), "checkpoint": None}
    vault_id = str(uuid.uuid4())
    d.accept_floor(vault_id, a)
    with pytest.raises(ValueError):
        d.accept_floor(vault_id, None)

def test_shared_vectors():
    import json
    from pathlib import Path
    cases = json.loads((Path(__file__).parents[1] / "spec" / "deletion_baseline_v1_fixtures.json").read_text(encoding="utf-8"))["cases"]
    for case in cases:
        if case["op"] == "guard":
            if case["allowed"]:
                d.guard(case["local"], case["remote"])
            else:
                with pytest.raises(ValueError):
                    d.guard(case["local"], case["remote"])
        else:
            assert d.merge(case["local"], case["remote"]) == case["expected"], case["name"]

def test_vault_cleanup_and_stale_backup(tmp_path):
    from core.storage import Vault
    from core import backup
    vault = Vault.create(tmp_path / "test.pmv", "test-password")
    own = __import__("core.device_activity", fromlist=["current_device_id"]).current_device_id(vault)
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    vault.start_deletion_cleanup()
    value, ready = vault.deletion_cleanup_state()
    assert ready
    vault.finish_deletion_cleanup(value["checkpoint"]["checkpoint_id"])
    assert vault._purge_tombstones == {}
    assert vault.metadata[d.FIELD]["generation"] == 1
    with pytest.raises(ValueError):
        vault.sync_merge([], None)
    output = tmp_path / "new.pmbak"
    backup.export_encrypted([], output, "password", deletion_baseline=vault.metadata[d.FIELD])
    assert backup.import_encrypted_with_meta(output, "password").deletion_baseline == vault.metadata[d.FIELD]
    vault.close()

def test_vault_cleanup_sequence_race_rejects(tmp_path):
    from core.storage import Vault, ExternalVaultChange
    vault = Vault.create(tmp_path / "race.pmv", "test-password")
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    vault.start_deletion_cleanup()
    value, ready = vault.deletion_cleanup_state()
    assert ready
    other = Vault.open(tmp_path / "race.pmv", "test-password")
    other._purge_tombstones[str(uuid.uuid4())] = 2.0
    other.save()
    with pytest.raises(ExternalVaultChange):
        vault.finish_deletion_cleanup(value["checkpoint"]["checkpoint_id"])
    assert vault._purge_tombstones[ENTRY] == 1.0
    assert vault.metadata[d.FIELD]["generation"] == 0
    other.close()
    vault.close()

def test_unknown_activity_platform_cannot_omit_holder():
    m = metadata()
    m["_device_activity_v1"]["profiles"][1]["platform"] = "future-platform"
    with pytest.raises(ValueError):
        d.start(m, OWN)

def test_future_activity_survives_ordinary_save_but_blocks_cleanup(tmp_path):
    from core.storage import Vault
    from core import device_activity
    vault = Vault.create(tmp_path / "future.pmv", "password")
    future = {"version": 2, "future": {"retained": True}}
    vault._pmve_metadata[device_activity.FIELD] = future
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    vault.ensure_device_authorized()
    assert vault.metadata[device_activity.FIELD] == future
    with pytest.raises(ValueError):
        vault.start_deletion_cleanup()
    vault.close()

def test_historical_members_survive_registry_removal():
    from core import pmv_device_registry
    m = metadata()
    m[d.KNOWN_FIELD] = [str(uuid.uuid4())]
    expected = d.members(m, OWN)
    stripped = pmv_device_registry.with_registry(m, [])
    assert d.members(stripped, OWN) == expected

def test_floor_is_scoped_by_vault():
    a = {"schema_version": 1, "generation": 1, "epoch": str(uuid.uuid4()), "checkpoint": None}
    d.accept_floor(str(uuid.uuid4()), a)
    d.accept_floor(str(uuid.uuid4()), None)

def test_malformed_descriptive_activity_does_not_omit_device():
    m = metadata()
    m["_device_activity_v1"]["profiles"][1]["last_seen_at"] = "invalid"
    assert OTHER in d.members(m, OWN)

def test_two_device_adoption_persists_ack_and_merges_back(tmp_path, monkeypatch):
    import shutil
    from core.storage import Vault
    from core import device_activity
    a = Vault.create(tmp_path / "a.pmv", "password")
    own = device_activity.current_device_id(a)
    a._pmve_metadata.setdefault(device_activity.FIELD, {"version": 1, "profiles": []})["profiles"].append({"device_id": OTHER, "name": "B", "platform": "android", "last_seen_at": 0, "updated_at": 0})
    a._purge_tombstones[ENTRY] = 1.0
    a.save()
    shutil.copy2(a.path, tmp_path / "b.pmv")
    b = Vault.open(tmp_path / "b.pmv", "password")
    monkeypatch.setattr(device_activity, "current_device_id", lambda v: OTHER if v.path.name == "b.pmv" else own)
    a.start_deletion_cleanup()
    assert not a.deletion_cleanup_state()[1]
    b.replace_authenticated_file(a.path)
    assert b.acknowledge_deletion_checkpoint()
    cp = b.metadata[d.FIELD]["checkpoint"]
    assert cp["acknowledgements"][OTHER] == cp["checkpoint_id"]
    a.replace_authenticated_file(b.path)
    assert a.deletion_cleanup_state()[1]
    a.finish_deletion_cleanup(a.deletion_cleanup_state()[0]["checkpoint"]["checkpoint_id"])
    b.replace_authenticated_file(a.path)
    assert b.metadata[d.FIELD]["generation"] == 1
    a.close()
    b.close()

def test_ordinary_save_retains_holder_with_bad_description(tmp_path):
    from core.storage import Vault
    from core import device_activity
    vault = Vault.create(tmp_path / "bad-profile.pmv", "password")
    vault._pmve_metadata[device_activity.FIELD] = metadata()[device_activity.FIELD]
    vault._pmve_metadata[device_activity.FIELD]["profiles"][1]["last_seen_at"] = "bad"
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    assert OTHER in vault.metadata[d.KNOWN_FIELD]
    vault.start_deletion_cleanup()
    assert not vault.deletion_cleanup_state()[1]
    vault.close()

def test_replacement_retains_local_only_holder_and_rejected_floor_cannot_write(tmp_path):
    import shutil
    from core.storage import Vault
    a = Vault.create(tmp_path / "a.pmv", "password")
    a.save()
    shutil.copy2(a.path, tmp_path / "remote.pmv")
    remote = Vault.open(tmp_path / "remote.pmv", "password")
    remote.save()
    a._pmve_metadata[d.KNOWN_FIELD] = sorted(set(a._pmve_metadata[d.KNOWN_FIELD]) | {OTHER})
    a.save()
    a.replace_authenticated_file(remote.path, force=True)
    assert OTHER in a.metadata[d.KNOWN_FIELD]
    floor = {"schema_version": 1, "generation": 1, "epoch": str(uuid.uuid4()), "checkpoint": None}
    d.accept_floor(a._vault_id, floor)
    before = a.path.read_bytes()
    with pytest.raises(ValueError):
        a.save()
    assert a.path.read_bytes() == before
    a.close()
    remote.close()

def test_cloud_descendant_retains_local_holder_and_uploads_followup(tmp_path, monkeypatch):
    import shutil
    from core.storage import Vault
    from core.auto_cloud_sync import sync_webdav
    from core.cloud import WebDavConfig
    from tests.test_pmve_cloud_sync import _install_fake
    local = tmp_path / "local.pmv"
    remote_path = tmp_path / "remote.pmv"
    a = Vault.create(local, "password")
    a._pmve_metadata[d.KNOWN_FIELD] = [OTHER]
    a.save()
    a.close()
    shutil.copy2(local, remote_path)
    remote = Vault.open(remote_path, "password")
    remote._pmve_metadata[d.KNOWN_FIELD] = [m for m in remote.metadata[d.KNOWN_FIELD] if m != OTHER]
    remote.save()
    remote.close()
    _install_fake(monkeypatch, remote_path)
    result = sync_webdav(local, "password", WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    assert result.changed and result.uploaded
    reopened = Vault.open(local, "password")
    assert OTHER in reopened.metadata[d.KNOWN_FIELD]
    assert local.read_bytes() == remote_path.read_bytes()
    reopened.close()


def test_new_baseline_can_be_uploaded_over_older_remote_but_not_downgraded(tmp_path):
    import shutil
    from core.storage import Vault
    from core import crypto
    vault = Vault.create(tmp_path / "local.pmv", "test-password")
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    vault.start_deletion_cleanup()
    value, ready = vault.deletion_cleanup_state()
    assert ready
    remote = tmp_path / "remote.pmv"
    shutil.copyfile(vault.path, remote)
    vault.finish_deletion_cleanup(value["checkpoint"]["checkpoint_id"])
    original = vault.path.read_bytes()
    # Observation is read-only and supports deciding to upload the newer local head.
    assert vault.authenticate_external_file(remote).vault_id == vault.pmve_identity.vault_id
    with pytest.raises((ValueError, crypto.DecryptError)):
        vault.replace_authenticated_file(remote, force=True)
    assert vault.path.read_bytes() == original
    assert vault.metadata[d.FIELD]["generation"] == 1
    vault.close()


def test_cloud_publishes_cleanup_baseline_over_previous_remote(tmp_path, monkeypatch):
    import shutil
    from core.storage import Vault
    from core.auto_cloud_sync import sync_webdav
    from core.cloud import WebDavConfig
    from tests.test_pmve_cloud_sync import _install_fake
    local, remote = tmp_path / "local.pmv", tmp_path / "remote.pmv"
    vault = Vault.create(local, "password")
    vault._purge_tombstones[ENTRY] = 1.0
    vault.save()
    vault.start_deletion_cleanup()
    value, ready = vault.deletion_cleanup_state()
    assert ready
    shutil.copyfile(local, remote)
    vault.finish_deletion_cleanup(value["checkpoint"]["checkpoint_id"])
    vault.close()
    _install_fake(monkeypatch, remote)
    result = sync_webdav(local, "password", WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    assert result.uploaded
    assert local.read_bytes() == remote.read_bytes()
    updated = Vault.open(remote, "password")
    try:
        assert updated.metadata[d.FIELD]["generation"] == 1
        assert updated._purge_tombstones == {}
    finally:
        updated.close()
