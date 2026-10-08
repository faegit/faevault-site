import uuid
import pytest
from core.models import Entry
from core.storage import Vault
from core import device_activity

@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setattr('core.device_identity.load_or_create', lambda v: (uuid.UUID(int=7), b's'*32))
    monkeypatch.setattr('core.storage.vault_dir', lambda: tmp_path/'private')
    values={}
    monkeypatch.setattr('core.config.get', lambda key, default=None: values.get(key,default))
    monkeypatch.setattr('core.config.set', lambda key,value: values.update({key:value}))
    value=Vault.create_pmve(tmp_path/'vault.pmv', 'master', b'r'*32)
    yield value
    value.close()

def test_profile_merge_commutative():
    key=str(uuid.UUID(int=2))
    left={'profiles':[{'device_id':key,'name':'a','platform':'pc','updated_at':4,'last_seen_at':6}]}
    right={'profiles':[{'device_id':key,'name':'b','platform':'android','updated_at':4,'last_seen_at':7}]}
    assert device_activity.merge(left,right)==device_activity.merge(right,left)

def test_shared_writer_binding_fixtures():
    import json
    from pathlib import Path
    from types import SimpleNamespace
    data=json.loads(Path('spec/device_activity_v1_fixtures.json').read_text())
    for case in data['writer_cases']:
        store=SimpleNamespace(metadata=lambda: {device_activity.FIELD:case['metadata']},
             identity=SimpleNamespace(parent_commit_id=uuid.UUID(case['parent_commit_id'])))
        result=device_activity.verified_last_writer(store)
        assert (result['device_id'] if result else None)==case['expected_device_id'],case['name']


def test_unsupported_device_schema_is_preserved(vault):
    future={"version":2,"future":{"secret":"retained"}}
    assert device_activity.stamp({device_activity.FIELD:future},uuid.UUID(int=7))[device_activity.FIELD]==future


def test_authorization_keeps_unknown_device_activity_schema(vault):
    future={"version":2,"future":{"retained":True}}
    vault._pmve_metadata[device_activity.FIELD]=future
    vault.save()
    vault.ensure_device_authorized()
    assert vault._pmve_store.metadata()[device_activity.FIELD]==future


def test_os_name_refreshes_on_save_and_display(vault, monkeypatch):
    monkeypatch.setattr(device_activity.socket, "gethostname", lambda: "Old OS name")
    vault.save()
    vault.ensure_device_authorized()
    own = str(uuid.UUID(int=7))
    profile = next(p for p in vault._pmve_metadata[device_activity.FIELD]["profiles"] if p["device_id"] == own)
    profile["name"] = "old custom nickname"
    remote = {"device_id": str(uuid.UUID(int=8)), "name": "Remote name", "platform": "android", "updated_at": 1, "last_seen_at": 1}
    vault._pmve_metadata[device_activity.FIELD]["profiles"].append(remote)
    monkeypatch.setattr(device_activity.socket, "gethostname", lambda: "New OS name")
    assert next(p for p in device_activity.devices(vault) if p["is_current"])["name"] == "New OS name"
    vault.save()
    profiles = vault._pmve_store.metadata()[device_activity.FIELD]["profiles"]
    assert next(p for p in profiles if p["device_id"] == own)["name"] == "New OS name"
    assert next(p for p in profiles if p["device_id"] == remote["device_id"])["name"] == "Remote name"
    assert device_activity.verified_last_writer(vault._pmve_store)["name"] == "New OS name"


def test_system_name_fallback(monkeypatch):
    monkeypatch.setattr(device_activity.socket, "gethostname", lambda: "")
    monkeypatch.setattr(device_activity.platform, "node", lambda: "hostname")
    assert device_activity.system_device_name() == "hostname"


def test_durable_operations_do_not_generate_history(vault, tmp_path):
    vault.add(Entry(title="saved"))
    vault.ensure_device_authorized()
    vault.change_password("next")
    vault.regenerate_recovery_key(b"n" * 32, old_recovery_secret=b"r" * 32)
    vault.regenerate_recovery_key_with_password("next", b"m" * 32)
    vault.reset_password_with_recovery(b"m" * 32, "final")
    assert vault.verify_password("final")
    assert not any("history" in path.name.lower() for path in tmp_path.rglob("*"))


@pytest.mark.parametrize("error", [OSError, UnicodeError])
def test_system_name_failure_does_not_block_save(vault, monkeypatch, error):
    def unavailable():
        raise error("unavailable")
    monkeypatch.setattr(device_activity.socket, "gethostname", unavailable)
    monkeypatch.setattr(device_activity.platform, "node", lambda: "fallback")
    vault.save()
    assert device_activity.verified_last_writer(vault._pmve_store)["name"] == "fallback"
    monkeypatch.setattr(device_activity.platform, "node", unavailable)
    vault.save()
    assert device_activity.verified_last_writer(vault._pmve_store)["name"] == "PC"


def test_device_view_hides_missing_revoked_and_expired_authorizations(monkeypatch):
    from types import SimpleNamespace
    ids = [uuid.UUID(int=value) for value in range(1, 7)]
    scope = uuid.UUID(int=100)
    profiles = [{"device_id": str(key), "name": str(key), "platform": "pc", "updated_at": 1, "last_seen_at": 1} for key in ids]
    records = [
        SimpleNamespace(vault_id=scope, device_id=ids[0], epoch=1, active_at=lambda now: True),
        SimpleNamespace(vault_id=scope, device_id=ids[1], epoch=1, active_at=lambda now: False),
        SimpleNamespace(vault_id=scope, device_id=ids[2], epoch=1, active_at=lambda now: False),
        SimpleNamespace(vault_id=scope, device_id=ids[3], epoch=1, active_at=lambda now: False),
        SimpleNamespace(vault_id=uuid.UUID(int=200), device_id=ids[5], epoch=1, active_at=lambda now: True),
    ]
    monkeypatch.setattr("core.pmv_device_registry.decode", lambda metadata: records)
    monkeypatch.setattr("core.pmv_device_registry.verify_all", lambda records, public: records)
    monkeypatch.setattr(device_activity, "current_device_id", lambda vault: str(ids[0]))
    vault = SimpleNamespace(_pmve_store=SimpleNamespace(metadata=lambda: {device_activity.FIELD: {"version": 1, "profiles": profiles}},
                            identity=SimpleNamespace(signing_public_key=b"public", vault_id=scope)))
    assert [record["device_id"] for record in device_activity.devices(vault)] == [str(ids[0])]


def test_deleted_profile_max_union_and_reauthorization():
    key = str(uuid.UUID(int=8))
    stale = {"version": 1, "profiles": [{"device_id": key, "name": "old", "platform": "pc", "updated_at": 4, "last_seen_at": 7}]}
    removed = device_activity.remove_profile({device_activity.FIELD: stale}, key, 10)[device_activity.FIELD]
    assert device_activity.merge(removed, stale)["profiles"] == []
    assert device_activity.merge(stale, removed) == device_activity.merge(removed, stale)
    renewed = device_activity.stamp({device_activity.FIELD: removed}, key, 1)[device_activity.FIELD]
    assert renewed["profiles"][0]["updated_at"] > removed["deleted_profiles"][key]
    with pytest.raises(ValueError):
        device_activity.remove_profile({device_activity.FIELD: {"version": 2}}, key)


def _authorize_remote(vault):
    from core import pmv_device_registry, pmv_sync_authorization
    from core.device_identity import device_public_key
    store = vault._pmve_store
    target = uuid.UUID(int=8)
    record = store.sign_device_authorization(pmv_sync_authorization.DeviceAuthorization(
        vault_id=store.identity.vault_id, device_id=target, device_public_key=device_public_key(b"t" * 32),
        permissions=3, issued_at_epoch_millis=1, expires_at_epoch_millis=0, revoked_at_epoch_millis=0, epoch=1))
    metadata = pmv_device_registry.with_registry(store.metadata(), [record])
    metadata[device_activity.FIELD] = {"version": 1, "profiles": [{"device_id": str(target), "name": "remote", "platform": "android", "updated_at": 2, "last_seen_at": 2}]}
    store.save_full(expected_sequence=store.identity.sequence, metadata=metadata, entries=[])
    vault._pmve_metadata = metadata
    vault._pmve_sequence = store.identity.sequence
    return target, record


def test_remove_device_revocation_is_durable_and_dominates_old_grant(vault):
    from core import pmv_device_registry
    target, grant = _authorize_remote(vault)
    sequence = vault._pmve_sequence
    vault.remove_device_record(target)
    metadata = vault._pmve_store.metadata()
    revoke = pmv_device_registry.latest(pmv_device_registry.decode(metadata), target)
    assert revoke.epoch > grant.epoch and not revoke.active_at(10)
    assert pmv_device_registry.latest([grant, revoke], target) == revoke
    assert vault._pmve_sequence == sequence + 1
    assert str(target) in metadata[device_activity.FIELD]["deleted_profiles"]
    assert not any(p["device_id"] == str(target) for p in metadata[device_activity.FIELD]["profiles"])
    assert not any(p["device_id"] == str(target) for p in device_activity.devices(vault))
    reopened = Vault.open(vault.path, "master")
    try:
        persisted = pmv_device_registry.latest(pmv_device_registry.decode(reopened._pmve_store.metadata()), target)
        assert persisted == revoke
        assert not any(p["device_id"] == str(target) for p in device_activity.devices(reopened))
    finally:
        reopened.close()
    with pytest.raises(ValueError):
        vault.remove_device_record(uuid.UUID(int=7))


def test_remove_failure_keeps_memory_and_disk(vault, monkeypatch):
    import copy
    target, _ = _authorize_remote(vault)
    metadata = copy.deepcopy(vault._pmve_metadata)
    sequence = vault._pmve_sequence
    def fail(**kwargs):
        raise OSError("commit failed")
    monkeypatch.setattr(vault._pmve_store, "save_full", fail)
    with pytest.raises(OSError):
        vault.remove_device_record(target)
    assert vault._pmve_metadata == metadata
    assert vault._pmve_sequence == sequence
    assert vault._pmve_store.metadata() == metadata


def test_shared_device_removal_fixtures():
    import json
    from pathlib import Path
    cases = json.loads(Path("spec/device_removal_v1_fixtures.json").read_text())["cases"]
    for case in cases:
        result = device_activity.merge(case["left"], case["right"])
        assert result == device_activity.merge(case["right"], case["left"]), case["name"]
        assert [p["device_id"] for p in result["profiles"]] == case["expected_ids"], case["name"]
        assert result.get("deleted_profiles", {}) == case["expected_deleted"], case["name"]


def test_future_activity_removal_fails_without_commit(vault):
    target, _ = _authorize_remote(vault)
    metadata = vault._pmve_store.metadata()
    metadata[device_activity.FIELD] = {"version": 2, "future": "keep"}
    store = vault._pmve_store
    store.save_full(expected_sequence=store.identity.sequence, metadata=metadata, entries=[])
    sequence = store.identity.sequence
    with pytest.raises(ValueError):
        vault.remove_device_record(target)
    assert store.identity.sequence == sequence
    assert store.metadata() == metadata


def test_max_profile_timestamp_removal_fails_atomically(vault):
    import copy
    target, _ = _authorize_remote(vault)
    store = vault._pmve_store
    metadata = store.metadata()
    metadata[device_activity.FIELD]["profiles"][0]["updated_at"] = 2**63 - 1
    store.save_full(expected_sequence=store.identity.sequence, metadata=metadata, entries=[])
    vault._pmve_metadata = copy.deepcopy(metadata)
    vault._pmve_sequence = store.identity.sequence
    sequence = store.identity.sequence
    with pytest.raises(ValueError):
        vault.remove_device_record(target)
    assert store.identity.sequence == sequence
    assert store.metadata() == metadata
    assert vault._pmve_metadata == metadata
    assert vault._pmve_sequence == sequence


def test_canonical_deletion_aliases_keep_max_timestamp():
    key = "abcdefab-abcd-4abc-8abc-abcdefabcdef"
    profile = {"device_id": key, "name": "old", "platform": "pc", "updated_at": 50, "last_seen_at": 50}
    left = {"version": 1, "profiles": [profile], "deleted_profiles": {key: 99, key.upper(): 1}}
    right = {"version": 1, "profiles": [profile], "deleted_profiles": {key.upper(): 1, key: 99}}
    assert device_activity.normalize(left) == device_activity.normalize(right)
    assert device_activity.normalize(left)["deleted_profiles"] == {key: 99}
    assert device_activity.normalize(left)["profiles"] == []


@pytest.mark.parametrize("opaque", [[], ["future"], "future", None, {"version": True}, {"version": "1"}])
def test_opaque_activity_removal_fails_atomically(vault, opaque):
    import copy
    target, _ = _authorize_remote(vault)
    store = vault._pmve_store
    metadata = store.metadata()
    metadata[device_activity.FIELD] = opaque
    store.save_full(expected_sequence=store.identity.sequence, metadata=metadata, entries=[])
    vault._pmve_metadata = copy.deepcopy(metadata)
    vault._pmve_sequence = store.identity.sequence
    sequence = store.identity.sequence
    with pytest.raises(ValueError):
        vault.remove_device_record(target)
    assert store.identity.sequence == sequence
    assert store.metadata() == metadata
    assert vault._pmve_metadata == metadata
    assert vault._pmve_sequence == sequence
