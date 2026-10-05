from __future__ import annotations

import os
import io
import json
import uuid
from pathlib import Path

import pytest

from core.pmv_kdf_policy import PmvKdfProfile

from core.pmv_container import BLOCK_HEADER_SIZE, DATA_START, BlockType
from core.pmv_compression import CODEC_ZSTD_FRAME_V1
from core.pmv_attachment import AttachmentKind
from core.pmv_vault_header import (
    HEADER_SIZE,
    PRIMARY_OFFSET,
    SECONDARY_OFFSET,
    create_header,
)
from core.pmv_vault_store import MutationContent, ObjectImport, PmvVaultStore
from core.pmv_entry_reader import PmvEntryReader
from core.pmv_media_ref import from_store_ref


PASSWORD = "correct horse 电池".encode("utf-8")
NEW_PASSWORD = "new password 密码".encode("utf-8")
RECOVERY = bytes(range(32))


def _entry(entry_id: uuid.UUID, *, password: str = "secret", updated_at: float = 2.0) -> dict:
    return {
        "id": str(entry_id),
        "title": "Example",
        "username": "alice",
        "password": password,
        "url": "https://www.example.com/login",
        "target_app": "com.example.app",
        "notes": "note",
        "tags": ["work"],
        "created_at": 1.0,
        "updated_at": updated_at,
        "secret_type": "login",
        "fields": {"future_module": {"version": 9, "opaque": [1, 2, 3]}},
        "deleted_at": None,
        "leak_check_revision": None,
        "leak_pwned_count": None,
        "leak_common_weak": False,
        "leak_checked_at": None,
    }


def _metadata(entry_id: uuid.UUID) -> dict:
    return {
        "schema": "pmv-vault-metadata",
        "version": 1,
        # create() owns vault_id and replaces this placeholder.
        "vault_id": str(uuid.UUID(int=1)),
        "entry_order": [str(entry_id)],
        "trash_order": [],
        "sync_meta": {
            "device_id": "11111111-2222-3333-4444-555555555555",
            "future_counter": 7,
        },
        "key_revision": 1,
        "export_epoch": None,
        "purge_tombstones": {},
        "future_extension": {"label": "kept", "enabled": True},
    }


def _install_newer_header_with_wrong_signer(path, store: PmvVaultStore) -> None:
    incompatible = create_header(
        vault_id=store.identity.vault_id,
        key_revision=store.identity.key_revision,
        header_revision=store.identity.header_revision + 100,
        password_utf8=PASSWORD,
        recovery_secret=RECOVERY,
        vault_root_key=store.copy_root_key(),
        signing_private_seed=os.urandom(32),
        salt=os.urandom(16),
    )
    with path.open("r+b", buffering=0) as stream:
        stream.seek(PRIMARY_OFFSET)
        stream.write(incompatible)
        stream.flush()
        os.fsync(stream.fileno())


def _corrupt_block_payload(path, offset: int) -> None:
    with path.open("r+b", buffering=0) as stream:
        stream.seek(offset + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        assert original
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())


def test_create_opens_with_both_credentials_and_round_trips_full_state(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")

    created = PmvVaultStore.create(
        path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)]
    )
    vault_id = created.identity.vault_id
    assert created.identity.sequence == 1
    assert created.identity.signing_public_key != bytes(32)
    assert next(created._authenticated_snapshots()).vault_root.login is not None
    assert created.list()[0].entry_id == entry_id
    assert created.read_entry(entry_id).fields["future_module"]["opaque"] == [1, 2, 3]
    assert created.query_domain("login.example.com") == (entry_id,)
    assert created.query_package("com.example.app") == (entry_id,)
    assert created.metadata()["vault_id"] == str(vault_id)
    assert created.metadata()["future_extension"] == {"label": "kept", "enabled": True}
    created.close()

    with path.open("rb") as stream:
        stream.seek(PRIMARY_OFFSET)
        assert stream.read(4) == b"PMVH"
        stream.seek(SECONDARY_OFFSET)
        assert stream.read(4) == b"PMVH"
        assert path.stat().st_size > SECONDARY_OFFSET + HEADER_SIZE

    by_password = PmvVaultStore.open_password(path, PASSWORD)
    by_recovery = PmvVaultStore.open_recovery(path, RECOVERY)
    assert by_password.identity.vault_id == by_recovery.identity.vault_id == vault_id
    assert by_password.read_entry(entry_id).password == "secret"
    assert by_recovery.metadata()["sync_meta"]["future_counter"] == 7
    by_password.close()
    by_recovery.close()


def test_wrong_credentials_fail_closed(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)]).close()

    with pytest.raises(ValueError, match="credential|header"):
        PmvVaultStore.open_password(path, b"wrong")
    with pytest.raises(ValueError, match="credential|header"):
        PmvVaultStore.open_recovery(path, bytes(32))


def test_rp_id_index_reads_passkey_modules_from_every_active_entry_and_deduplicates(tmp_path) -> None:
    path = tmp_path / "rp-id-modules.pmv"
    fixture_path = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))["records"][0]["record"]

    def module(rp_id: str) -> dict:
        return {"type": "passkey", "value": {**fixture, "rp_id": rp_id}}

    login_id, note_id, legacy_id, deleted_id, invalid_id = (uuid.UUID(int=value) for value in range(21, 26))
    login = _entry(login_id)
    login["fields"] = {"modules": [module("example.com"), module("example.com")]}
    note = _entry(note_id)
    note["secret_type"] = "secure_note"
    note["fields"] = {"modules": [module("note.example")]}
    legacy = _entry(legacy_id)
    legacy["secret_type"] = "passkey"
    legacy["fields"] = {"rp_id": "legacy.example"}
    deleted = _entry(deleted_id)
    deleted["deleted_at"] = 3.0
    deleted["fields"] = {"modules": [module("deleted.example")]}
    invalid = _entry(invalid_id)
    invalid["fields"] = {"rp_id": "ignored-top.example", "modules": [
        "not-an-object",
        {"type": "password", "value": {"rp_id": "wrong-type.example"}},
        {"type": "passkey", "value": "invalid"},
        {"type": "passkey", "value": {"rp_id": 7}},
    ]}

    store = PmvVaultStore.create(
        path, PASSWORD, RECOVERY, _metadata(login_id), [login, note, legacy, deleted, invalid]
    )
    assert store.query_rp_id("example.com") == (login_id,)
    assert store.query_rp_id("note.example") == (note_id,)
    assert store.query_rp_id("legacy.example") == (legacy_id,)
    assert store.query_rp_id("deleted.example") == ()
    assert store.query_rp_id("wrong-type.example") == ()
    assert store.query_rp_id("ignored-top.example") == ()
    store.close()


def test_metadata_orders_active_entries_before_trash_and_overrides_stale_input_order(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    active_id = uuid.UUID("20000000-0000-0000-0000-000000000002")
    trash_id = uuid.UUID("10000000-0000-0000-0000-000000000001")
    active = _entry(active_id)
    trash = _entry(trash_id)
    trash["deleted_at"] = 3.0
    metadata = _metadata(active_id)
    metadata["entry_order"] = [str(trash_id)]
    metadata["trash_order"] = [str(active_id)]

    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, metadata, [trash, active])

    assert store.metadata()["entry_order"] == [str(active_id)]
    assert store.metadata()["trash_order"] == [str(trash_id)]
    assert [item.entry_id for item in store.list()] == [active_id, trash_id]
    assert store.read_entry(trash_id).deleted_at == 3.0
    assert store.query_domain("example.com") == (active_id,)
    store.close()


def test_save_binds_parent_rejects_stale_sequence_and_rewraps_only_password(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    first_commit = store.identity.commit_id

    identity = store.save_full(
        expected_sequence=1,
        metadata=_metadata(entry_id),
        entries=[_entry(entry_id, password="changed", updated_at=3.0)],
    )
    assert identity.sequence == 2
    assert identity.parent_commit_id == first_commit
    with pytest.raises(ValueError, match="stale"):
        store.save_full(
            expected_sequence=1,
            metadata=_metadata(entry_id),
            entries=[_entry(entry_id)],
        )

    store.rewrap_password(PASSWORD, NEW_PASSWORD)
    store.close()
    with pytest.raises(ValueError):
        PmvVaultStore.open_password(path, PASSWORD)
    by_new_password = PmvVaultStore.open_password(path, NEW_PASSWORD)
    by_recovery = PmvVaultStore.open_recovery(path, RECOVERY)
    assert by_new_password.read_entry(entry_id).password == "changed"
    assert by_recovery.read_entry(entry_id).password == "changed"
    by_new_password.close()
    by_recovery.close()


def test_profile_rewrap_updates_only_header_parameters_and_keeps_recovery(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    before = store.identity
    assert store.kdf_parameters == PmvKdfProfile.STANDARD.parameters

    after = store.rewrap_password_profile(PASSWORD, PmvKdfProfile.HARDENED)
    assert store.kdf_parameters == PmvKdfProfile.HARDENED.parameters
    assert after.key_revision == before.key_revision
    assert after.header_revision == before.header_revision + 1
    store.close()

    by_password = PmvVaultStore.open_password(path, PASSWORD)
    by_recovery = PmvVaultStore.open_recovery(path, RECOVERY)
    assert by_password.kdf_parameters == PmvKdfProfile.HARDENED.parameters
    assert by_recovery.read_entry(entry_id).password == "secret"
    by_password.close()
    by_recovery.close()


def test_one_damaged_header_slot_falls_back_to_the_other(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)]).close()

    with path.open("r+b", buffering=0) as stream:
        stream.seek(PRIMARY_OFFSET + 200)
        original = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())

    reopened = PmvVaultStore.open_password(path, PASSWORD)
    assert reopened.read_entry(entry_id).password == "secret"
    reopened.close()


def test_damaged_newest_entry_falls_back_to_previous_complete_snapshot(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    store.save_full(
        expected_sequence=1,
        metadata=_metadata(entry_id),
        entries=[_entry(entry_id, password="newest", updated_at=3.0)],
    )
    newest_entry_offset = store._entry_offset_for_test(entry_id)  # corruption-fixture seam
    store.close()

    with path.open("r+b", buffering=0) as stream:
        stream.seek(newest_entry_offset + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())

    recovered = PmvVaultStore.open_password(path, PASSWORD)
    assert recovered.read_entry(entry_id).password == "secret"
    recovered.close()


def test_open_and_targeted_reads_never_use_path_read_bytes(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)]).close()

    monkeypatch.setattr(type(path), "read_bytes", lambda self: (_ for _ in ()).throw(AssertionError()))
    reopened = PmvVaultStore.open_password(path, PASSWORD)
    assert reopened.list()[0].entry_id == entry_id
    assert reopened.read_entry(entry_id).username == "alice"
    assert reopened.metadata()["future_extension"]["label"] == "kept"
    reopened.close()


def test_read_entry_only_uses_the_selected_entry_leaf_and_entry_block(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    observed: list[BlockType | None] = []
    original = store._container.read_block

    def tracked(snapshot, offset, expected_type=None):
        observed.append(expected_type)
        return original(snapshot, offset, expected_type)

    monkeypatch.setattr(store._container, "read_block", tracked)
    assert store.read_entry(entry_id).password == "secret"
    assert observed == [BlockType.INDEX_PAGE, BlockType.ENTRY]
    store.close()


def test_batch_entry_read_reuses_authenticated_leaf(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    ids = [uuid.uuid4(), uuid.uuid4()]
    metadata = _metadata(ids[0])
    metadata["entry_order"] = [str(entry_id) for entry_id in ids]
    store = PmvVaultStore.create(
        path, PASSWORD, RECOVERY, metadata,
        [_entry(ids[0], password="first"), _entry(ids[1], password="second")],
    )
    observed: list[BlockType | None] = []
    original = store._container.read_block

    def tracked(snapshot, offset, expected_type=None):
        observed.append(expected_type)
        return original(snapshot, offset, expected_type)

    monkeypatch.setattr(store._container, "read_block", tracked)
    loaded = store.read_entries(ids)

    assert [loaded[entry_id].password for entry_id in ids] == ["first", "second"]
    assert observed.count(BlockType.INDEX_PAGE) == 1
    assert observed.count(BlockType.ENTRY) == 2
    store.close()


def test_batch_entry_read_keeps_single_entry_fallback(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    original = PmvEntryReader._read_leaf
    attempts = 0

    def one_bad_batch_leaf(self, snapshot, directory):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("temporary batch leaf failure")
        return original(self, snapshot, directory)

    monkeypatch.setattr(PmvEntryReader, "_read_leaf", one_bad_batch_leaf)
    assert store.read_entries([entry_id])[entry_id].password == "secret"
    assert attempts >= 2
    store.close()


def test_close_zeroes_session_key_buffers_and_rejects_future_operations(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    buffers = tuple(store._secret_buffers_for_test())
    assert buffers and all(any(buffer) for buffer in buffers)

    store.close()

    assert all(not any(buffer) for buffer in buffers)
    with pytest.raises(ValueError, match="closed"):
        store.list()
    with pytest.raises(ValueError, match="closed"):
        store.apply_mutation(
            expected_sequence=1,
            prepare=lambda _refs: MutationContent(_metadata(entry_id), []),
        )


@pytest.mark.parametrize("new_value", ["https://new.example.net", None])
def test_login_query_fails_closed_when_latest_modified_or_deleted_index_is_damaged(
    tmp_path, new_value
) -> None:
    path = tmp_path / "vault.pmv"
    changed_id = uuid.UUID("10000000-0000-0000-0000-000000000001")
    keeper_id = uuid.UUID("20000000-0000-0000-0000-000000000002")
    changed = _entry(changed_id)
    keeper = _entry(keeper_id)
    keeper["url"] = "https://keeper.example.org"
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(changed_id), [changed, keeper])
    replacement = _entry(changed_id, updated_at=3.0)
    if new_value is None:
        replacement["deleted_at"] = 3.0
    else:
        replacement["url"] = new_value
    store.save_full(
        expected_sequence=1,
        metadata=_metadata(changed_id),
        entries=[replacement, keeper],
    )
    login_offset = store._latest_authenticated_snapshot().vault_root.login.offset
    store.close()
    _corrupt_block_payload(path, login_offset)

    reopened = PmvVaultStore.open_password(path, PASSWORD)
    with pytest.raises(ValueError, match="login-index"):
        reopened.query_domain("example.com")
    reopened.close()


def test_openers_skip_newer_header_that_cannot_authenticate_the_current_commit(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    root_key = store.copy_root_key()
    _install_newer_header_with_wrong_signer(path, store)
    store.close()

    sessions = (
        PmvVaultStore.open_password(path, PASSWORD),
        PmvVaultStore.open_recovery(path, RECOVERY),
        PmvVaultStore.open_root_key(path, root_key),
    )
    for session in sessions:
        assert session.identity.header_revision == 1
        assert session.read_entry(entry_id).password == "secret"
        session.close()


def test_identity_uses_latest_commit_and_does_not_require_metadata_plaintext(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    store.save_full(
        expected_sequence=1,
        metadata=_metadata(entry_id),
        entries=[_entry(entry_id, password="newest", updated_at=3.0)],
    )
    snapshot = store._latest_authenticated_snapshot()
    expected_digest = snapshot.commit.root_digest
    metadata_offset = snapshot.vault_root.metadata.offset
    store.close()
    _corrupt_block_payload(path, metadata_offset)

    reopened = PmvVaultStore.open_password(path, PASSWORD)
    assert reopened.identity.sequence == 2
    assert reopened.identity.root_digest == expected_digest
    reopened.close()


def test_root_key_open_and_dual_slot_credential_rotation(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [_entry(entry_id)])
    root_key = store.copy_root_key()
    assert root_key == bytes(store._vault_root_key)
    store.rotate_recovery(RECOVERY, bytes(reversed(RECOVERY)))
    store.reset_password_with_recovery(bytes(reversed(RECOVERY)), NEW_PASSWORD)
    store.close()

    with pytest.raises(ValueError):
        PmvVaultStore.open_password(path, PASSWORD)
    with pytest.raises(ValueError):
        PmvVaultStore.open_recovery(path, RECOVERY)
    by_root = PmvVaultStore.open_root_key(path, root_key)
    by_new_password = PmvVaultStore.open_password(path, NEW_PASSWORD)
    assert by_root.identity.root_digest == by_new_password.identity.root_digest
    by_root.close()
    by_new_password.close()


def test_login_url_extraction_accepts_scheme_bare_unicode_and_port_but_rejects_invalid(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entries = []
    urls = (
        "HTTP://WWW.Example.COM:8443/login",
        "sub.example.org:9443/path",
        "https://www.例子.测试:443/登录",
        "mailto:user@stale.example.com",
    )
    for index, url in enumerate(urls, 1):
        value = _entry(uuid.UUID(int=index))
        value["url"] = url
        entries.append(value)
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(uuid.UUID(int=1)), entries)

    assert store.query_domain("example.com") == (uuid.UUID(int=1),)
    assert store.query_domain("sub.example.org") == (uuid.UUID(int=2),)
    assert store.query_domain("例子.测试") == (uuid.UUID(int=3),)
    assert uuid.UUID(int=4) not in store.query_domain("stale.example.com")
    store.close()


def test_vault_mutation_publishes_entries_metadata_and_two_objects_in_one_commit(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id, first_id, second_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    first, second = b"first atomic object", b"second atomic object"
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [])

    def prepare(refs):
        assert tuple(ref.object_id for ref in refs) == (first_id, second_id)
        linked = _entry(entry_id)
        linked["fields"] = {"media_refs": [from_store_ref(ref).to_json() for ref in refs]}
        return MutationContent(_metadata(entry_id), [linked])

    result = store.apply_mutation(
        expected_sequence=1,
        object_imports=(
            ObjectImport(io.BytesIO(first), len(first), first_id, 2, AttachmentKind.IMAGE),
            ObjectImport(io.BytesIO(second), len(second), second_id, 7, AttachmentKind.ATTACHMENT),
        ),
        prepare=prepare,
    )
    assert result.identity.sequence == 2
    assert len(result.object_refs) == 2
    assert store.read_entry(entry_id).fields["media_refs"][1]["object_id"] == str(second_id)
    output = io.BytesIO()
    store.open_object(second_id, 7, output)
    assert output.getvalue() == second

    store.save_full(expected_sequence=2, metadata=_metadata(entry_id), entries=[store.read_entry(entry_id)])
    preserved = io.BytesIO()
    store.open_object(first_id, 2, preserved)
    assert preserved.getvalue() == first
    assert store.identity.sequence == 3
    store.close()


def test_compact_streams_reachable_object_and_preserves_signed_identity(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id, object_id = uuid.uuid4(), uuid.uuid4()
    payload = bytes((index * 17) & 0xFF for index in range(1024 * 1024 + 37))
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [])

    def prepare(refs):
        linked = _entry(entry_id)
        linked["fields"] = {"media": from_store_ref(refs[0]).to_json()}
        return MutationContent(_metadata(entry_id), [linked])

    store.apply_mutation(
        expected_sequence=1,
        object_imports=(ObjectImport(
            io.BytesIO(payload), len(payload), object_id, 1, AttachmentKind.IMAGE,
        ),),
        prepare=prepare,
    )
    current = store.read_entry(entry_id).to_dict()
    current["title"] = "after update"
    current["updated_at"] = 3.0
    store.save_full(expected_sequence=2, metadata=_metadata(entry_id), entries=[current])
    identity = store.identity
    before_size = path.stat().st_size

    assert store.compact() == identity
    assert path.stat().st_size < before_size
    assert store.read_entry(entry_id).title == "after update"
    output = io.BytesIO()
    store.open_object(object_id, 1, output)
    assert output.getvalue() == payload
    store.close()


def test_second_mutation_object_eof_rolls_back_first_object_and_entry_changes(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id, first_id, second_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [])
    committed_length = path.stat().st_size
    with pytest.raises(ValueError):
        store.apply_mutation(
            expected_sequence=1,
            object_imports=(
                ObjectImport(io.BytesIO(b"ok"), 2, first_id, 1, AttachmentKind.ATTACHMENT),
                ObjectImport(io.BytesIO(b"x"), 2, second_id, 1, AttachmentKind.ATTACHMENT),
            ),
            prepare=lambda _refs: MutationContent(_metadata(entry_id), [_entry(entry_id)]),
        )
    assert store.identity.sequence == 1
    assert path.stat().st_size == committed_length
    assert store.read_entry(entry_id) is None
    with pytest.raises(ValueError):
        store.open_object(first_id, 1, io.BytesIO())
    store.close()


def test_stale_and_cancelled_vault_mutations_do_not_publish(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [])
    empty_result = store.apply_mutation(
        expected_sequence=1,
        prepare=lambda _refs: MutationContent(_metadata(entry_id), []),
    )
    assert empty_result.identity.sequence == 2
    assert empty_result.object_refs == ()
    prepared = False

    def stale_prepare(_refs):
        nonlocal prepared
        prepared = True
        return MutationContent(_metadata(entry_id), [])

    with pytest.raises(ValueError, match="stale"):
        store.apply_mutation(expected_sequence=1, prepare=stale_prepare)
    assert not prepared

    class Cancelled(BaseException):
        pass

    class CancelledStream:
        def read(self, _size=-1):
            raise Cancelled()

    with pytest.raises(Cancelled):
        store.apply_mutation(
            expected_sequence=2,
            object_imports=(ObjectImport(CancelledStream(), 1, uuid.uuid4(), 1,
                                         AttachmentKind.ATTACHMENT),),
            prepare=lambda _refs: MutationContent(_metadata(entry_id), []),
        )
    assert store.identity.sequence == 2
    store.close()


def test_autofill_origin_metadata_is_indexed_and_rebuilt_after_update(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    entry = _entry(entry_id)
    entry["url"] = ""
    entry["target_app"] = ""
    entry["fields"] = {"_autofill_origin": {"kind": "web", "host": "accounts.example.com"}}
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [entry])
    assert store.query_domain("accounts.example.com") == (entry_id,)

    entry["updated_at"] = 3.0
    entry["fields"] = {"_autofill_origin": {"kind": "android", "package": "com.example.login"}}
    store.save_full(expected_sequence=1, metadata=_metadata(entry_id), entries=[entry])
    assert store.query_domain("accounts.example.com") == ()
    assert store.query_package("com.example.login") == (entry_id,)
    store.close()


def test_large_structured_entry_is_adaptively_compressed_and_round_trips(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    entry = _entry(entry_id)
    entry["notes"] = "repeatable secret text " * 10_000
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(entry_id), [entry])
    assert store.read_entry(entry_id).notes == entry["notes"]
    state = store._container.candidate_states()[0]
    end = state.superblock.committed_file_end
    offset = DATA_START
    entry_blocks = []
    while offset < end:
        block = store._container.read_block(state, offset)
        if block.header.block_type is BlockType.ENTRY:
            entry_blocks.append(block)
        offset += BLOCK_HEADER_SIZE + len(block.ciphertext)
    assert len(entry_blocks) == 1
    assert entry_blocks[0].header.codec_id == CODEC_ZSTD_FRAME_V1
    store.close()
