import io
import uuid

import pytest

from core import config, crypto
from core.models import Entry
from core.pmv_attachment import AttachmentKind
from core.pmv_media_ref import LegacyStream, plan
from core.storage import ExternalVaultChange, Vault


PASSWORD = "correct horse 电池"
NEW_PASSWORD = "new password 密码"
RECOVERY = bytes(range(32))
NEW_RECOVERY = bytes(reversed(RECOVERY))


def _entry(*, deleted: bool = False) -> Entry:
    return Entry(
        id=str(uuid.uuid4()),
        title="Example",
        username="alice",
        password="secret",
        url="https://example.com/login",
        target_app="com.example.app",
        notes="note",
        tags=["work"],
        created_at=1.0,
        updated_at=2.0,
        deleted_at=3.0 if deleted else None,
    )


def test_pmve_facade_create_open_save_and_preserve_trash(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    active = _entry()
    deleted = _entry(deleted=True)

    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    assert vault.device_unlock_key_format == "pmve-root-key"
    vault.entries = [active]
    vault.trash = [deleted]
    vault.save()
    vault.close()

    assert path.read_bytes()[:4] == b"PMVS"
    reopened = Vault.open(path, PASSWORD)
    assert [entry.id for entry in reopened.entries] == [active.id]
    assert [entry.id for entry in reopened.trash] == [deleted.id]
    assert reopened.entries[0].password == "secret"
    assert reopened.trash[0].deleted_at == 3.0
    reopened.close()


def test_pmve_facade_supports_recovery_and_os_wrapped_root_key(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    created = Vault.create_pmve(path, PASSWORD, RECOVERY)
    root_key = created.root_key_for_device_unlock()
    identity = created.pmve_identity
    assert identity.vault_id
    assert len(identity.signing_public_key) == 32
    assert identity.key_revision == 1
    created.close()

    by_recovery = Vault.open_with_recovery_key(path, RECOVERY)
    assert by_recovery.device_unlock_key_format == "pmve-root-key"
    by_recovery.close()

    with pytest.raises(crypto.DecryptError):
        Vault.open_with_root_key(path, bytes(32))
    by_device = Vault.open_with_root_key(path, root_key)
    by_device.close()


def test_pmve_facade_maps_stale_save_and_rewraps_credentials(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    first = Vault.create_pmve(path, PASSWORD, RECOVERY)
    second = Vault.open(path, PASSWORD)

    first.entries = [_entry()]
    first.save()
    with pytest.raises(ExternalVaultChange):
        second.save()
    second.close()

    first.change_password(NEW_PASSWORD)
    first.regenerate_recovery_key(NEW_RECOVERY, old_recovery_secret=RECOVERY)
    first.close()

    with pytest.raises(crypto.DecryptError):
        Vault.open(path, PASSWORD)
    with pytest.raises(crypto.DecryptError):
        Vault.open_with_recovery_key(path, RECOVERY)
    Vault.open(path, NEW_PASSWORD).close()
    Vault.open_with_recovery_key(path, NEW_RECOVERY).close()


def test_config_recognizes_pmve_superblock_magic(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    assert config._valid_vault_file(path)


def test_vault_open_rejects_non_pmve_database(tmp_path) -> None:
    path = tmp_path / "legacy.pmv"
    path.write_bytes(b"VAULT" + bytes(32))

    with pytest.raises(crypto.DecryptError, match="格式已不再支持"):
        Vault.open(path, PASSWORD)


def test_recovery_secret_can_reset_password_without_old_password(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.reset_password_with_recovery(RECOVERY, NEW_PASSWORD)
    vault.close()

    with pytest.raises(crypto.DecryptError):
        Vault.open(path, PASSWORD)
    reopened = Vault.open(path, NEW_PASSWORD)
    reopened.close()


def test_wrong_recovery_secret_never_changes_password(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)

    with pytest.raises(crypto.DecryptError, match="恢复密钥"):
        vault.reset_password_with_recovery(bytes(32), NEW_PASSWORD)
    vault.close()

    reopened = Vault.open(path, PASSWORD)
    reopened.close()
    with pytest.raises(crypto.DecryptError):
        Vault.open(path, NEW_PASSWORD)


def test_pmve_facade_streams_media_and_commits_plan_atomically(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    stored = _entry()
    stored.leak_check_revision = stored.updated_at
    stored.leak_pwned_count = 7
    stored.leak_common_weak = True
    stored.leak_checked_at = stored.updated_at + 0.5
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [stored]
    vault.save()
    before = vault.pmve_identity.sequence
    entry = Entry.from_dict(stored.to_dict())
    entry.fields = {"images": ["img:legacy.enc"]}
    content = b"streamed image object"
    transform = plan(entry, (
        LegacyStream(
            "/fields/images/0",
            io.BytesIO(content),
            len(content),
            uuid.uuid4(),
            1,
            AttachmentKind.IMAGE,
        ),
    ))

    refs = vault.import_media_mutation(
        transform,
        expected_sequence=before,
        expected_entry_updated_at=stored.updated_at,
    )

    assert len(refs) == 1
    assert vault.pmve_identity.sequence == before + 1
    assert vault.entries[0].fields["images"][0] == refs[0].to_json()
    assert vault.entries[0].updated_at > stored.updated_at
    assert vault.entries[0].leak_check_revision == vault.entries[0].updated_at
    assert vault.entries[0].leak_pwned_count == 7
    assert vault.entries[0].leak_common_weak is True
    assert vault.entries[0].leak_checked_at == stored.leak_checked_at
    whole = io.BytesIO()
    vault.open_media_object(refs[0], whole)
    assert whole.getvalue() == content
    partial = io.BytesIO()
    vault.open_media_range(refs[0].to_external_string(), 3, 5, partial)
    assert partial.getvalue() == content[3:8]
    vault.close()


def test_pmve_media_mutation_maps_stale_sequence_without_changing_entry(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    stored = _entry()
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [stored]
    vault.save()
    entry = Entry.from_dict(stored.to_dict())
    entry.fields = {"images": ["img:legacy.enc"]}
    transform = plan(entry, (
        LegacyStream(
            "/fields/images/0", io.BytesIO(b"x"), 1, uuid.uuid4(), 1,
            AttachmentKind.IMAGE,
        ),
    ))

    with pytest.raises(ExternalVaultChange):
        vault.atomic_import_media_mutation(
            transform, expected_sequence=vault.pmve_identity.sequence - 1
        )
    assert vault.entries[0].fields == {}
    vault.close()


def test_pmve_media_mutation_creates_new_entry_and_object_in_one_commit(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    before = vault.pmve_identity.sequence
    entry = _entry()
    entry.fields = {"images": ["img:new.enc"]}
    created_at, updated_at = entry.created_at, entry.updated_at
    content = b"new entry object"
    transform = plan(entry, (
        LegacyStream(
            "/fields/images/0", io.BytesIO(content), len(content), uuid.uuid4(), 1,
            AttachmentKind.IMAGE,
        ),
    ))

    refs = vault.import_media_mutation(
        transform,
        target_entry=entry,
        expected_sequence=before,
    )

    assert vault.pmve_identity.sequence == before + 1
    assert [value.id for value in vault.entries] == [entry.id]
    assert vault.entries[0].fields["images"] == [refs[0].to_json()]
    assert vault.entries[0].created_at == created_at
    assert vault.entries[0].updated_at == updated_at
    output = io.BytesIO()
    vault.open_media_object(refs[0], output)
    assert output.getvalue() == content
    vault.close()


def test_pmve_media_mutation_rejects_duplicate_without_expected_entry_revision(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    stored = _entry()
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [stored]
    vault.save()
    entry = Entry.from_dict(stored.to_dict())
    entry.fields = {"images": ["img:legacy.enc"]}
    transform = plan(entry, (
        LegacyStream(
            "/fields/images/0", io.BytesIO(b"x"), 1, uuid.uuid4(), 1,
            AttachmentKind.IMAGE,
        ),
    ))

    with pytest.raises(ExternalVaultChange, match="revision|更新"):
        vault.import_media_mutation(
            transform,
            target_entry=entry,
            expected_sequence=vault.pmve_identity.sequence,
        )
    vault.close()


def test_pmve_media_mutation_clears_leak_cache_when_secret_changes(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    stored = _entry()
    stored.leak_check_revision = stored.updated_at
    stored.leak_pwned_count = 11
    stored.leak_common_weak = True
    stored.leak_checked_at = stored.updated_at + 1.0
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [stored]
    vault.save()
    edited = Entry.from_dict(stored.to_dict())
    edited.password = "changed secret"
    edited.fields = {"images": ["img:legacy.enc"]}
    transform = plan(edited, (
        LegacyStream(
            "/fields/images/0", io.BytesIO(b"x"), 1, uuid.uuid4(), 1,
            AttachmentKind.IMAGE,
        ),
    ))

    vault.import_media_mutation(
        transform,
        expected_sequence=vault.pmve_identity.sequence,
        expected_entry_updated_at=stored.updated_at,
    )

    committed = vault.entries[0]
    assert committed.updated_at > stored.updated_at
    assert committed.leak_check_revision is None
    assert committed.leak_pwned_count is None
    assert committed.leak_common_weak is False
    assert committed.leak_checked_at is None
    vault.close()


def test_pmve_logical_key_revision_increments_on_key_changes_and_survives_reopen(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    assert vault.key_revision == 1

    vault.change_password(NEW_PASSWORD)
    assert vault.key_revision == 2
    vault.regenerate_recovery_key(NEW_RECOVERY, old_recovery_secret=RECOVERY)
    assert vault.key_revision == 3
    vault.save()
    vault.close()

    reopened = Vault.open(path, NEW_PASSWORD)
    assert reopened.key_revision == 3
    reopened.close()


def test_pmve_plain_save_does_not_reset_logical_key_revision(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.change_password(NEW_PASSWORD)
    bumped = vault.key_revision
    assert bumped == 2

    vault.entries = [_entry()]
    vault.save()
    assert vault.key_revision == bumped

    vault.close()
    reopened = Vault.open(path, NEW_PASSWORD)
    assert reopened.key_revision == bumped
    reopened.close()
