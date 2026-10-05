import copy
import datetime as dt
import json
from pathlib import Path

import pytest

from core import modules
from core.models import Entry, SecretType
from core.passkey_service import (
    DuplicateCredential,
    PasskeyService,
    UnusableCredential,
    VaultLocked,
)


def fixture_record():
    doc = json.loads((Path(__file__).parents[1] / "spec/passkey_v3_fixtures.json").read_text("utf-8"))
    return copy.deepcopy(doc["records"][0]["record"])


class FakeVault:
    def __init__(self, entries=()):
        self.entries = list(entries)

    def add(self, entry):
        self.entries.append(copy.deepcopy(entry))

    def update(self, entry):
        for index, current in enumerate(self.entries):
            if current.id == entry.id:
                self.entries[index] = copy.deepcopy(entry)
                return
        raise AssertionError("missing entry")


def module(record, *, conflict=False):
    return {
        "id": "passkey-module",
        "type": "passkey",
        "title": "通行密钥",
        "sensitive": True,
        "config": {"passkeyConflictStatus": "key_mismatch"} if conflict else {},
        "value": record,
    }


def entry(record, *, conflict=False):
    return Entry(
        id="00000000-0000-0000-0000-000000000001",
        secret_type=SecretType.PASSKEY,
        fields=modules.fields_with_modules({}, [module(record, conflict=conflict)]),
    )


def test_locked_service_fails_closed():
    with pytest.raises(VaultLocked):
        PasskeyService(lambda: None).list_metadata()


def test_make_commit_is_atomic_and_rejects_duplicate_identity():
    vault = FakeVault()
    service = PasskeyService(lambda: vault)
    service.commit_created(fixture_record())
    assert len(vault.entries) == 1
    assert vault.entries[0].secret_type == SecretType.PASSKEY
    with pytest.raises(DuplicateCredential):
        service.commit_created(fixture_record())
    assert len(vault.entries) == 1


def test_metadata_is_filtered_by_normalized_rp_and_repr_is_redacted():
    service = PasskeyService(lambda: FakeVault([entry(fixture_record())]))
    metadata = service.list_metadata("EXAMPLE.COM.")
    assert len(metadata) == 1
    assert metadata[0].user_name == "alice@example.com"
    assert "user-1" not in repr(metadata[0])
    assert "android-credential-id" not in repr(metadata[0])


def test_get_rejects_conflicted_credentials():
    record = fixture_record()
    service = PasskeyService(lambda: FakeVault([entry(record, conflict=True)]))
    credential_id = service._find([entry(record)], ("example.com", __import__("base64").urlsafe_b64decode(record["credential_id"] + "=")))[0][2].credential_id_bytes
    with pytest.raises(UnusableCredential):
        service.get_for_assertion("example.com", credential_id)


def test_commit_use_updates_time_and_preserves_synced_zero():
    vault = FakeVault([entry(fixture_record())])
    service = PasskeyService(lambda: vault)
    metadata = service.list_metadata()[0]
    material = service.get_for_assertion(metadata.rp_id, metadata.credential_id)
    service.commit_use(material, used_at=dt.datetime(2026, 8, 28, tzinfo=dt.timezone.utc))
    value = modules.modules_from_fields(vault.entries[0].fields)[0]["value"]
    assert value["last_used_at"] == "2026-08-28T00:00:00Z"
    assert value["sign_count"] == "0"
