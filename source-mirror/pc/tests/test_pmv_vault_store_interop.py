from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import uuid

from core.pmv_vault_store import PmvVaultStore


def _spec_root() -> Path:
    configured = os.environ.get("VAULT_SHARED_SPEC_DIR")
    root = Path(configured) if configured else Path(__file__).resolve().parents[2] / "vault_android" / "spec" / "interop" / "pmv_next" / "v1"
    if not root.is_dir():
        raise AssertionError(f"required shared PMV spec is missing: {root}")
    return root


def test_android_and_pc_complete_store_fixtures_are_mutually_readable() -> None:
    root = _spec_root()
    document = json.loads((root / "store_interop.json").read_text(encoding="utf-8"))
    password = document["passwordUtf8"].encode("utf-8")
    recovery = bytes.fromhex(document["recoverySecretHex"])
    for case in document["cases"]:
        fixture = root / case["blob"]
        assert fixture.is_file()
        assert fixture.stat().st_size == case["size"]
        with fixture.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == case["sha256"]
        for opener in (
            lambda: PmvVaultStore.open_password(fixture, password),
            lambda: PmvVaultStore.open_recovery(fixture, recovery),
        ):
            with opener() as store:
                identity = store.identity
                assert identity.vault_id == uuid.UUID(case["vaultId"])
                assert identity.sequence == case["sequence"]
                assert identity.commit_id == uuid.UUID(case["commitId"])
                if "parentCommitId" in case:
                    assert identity.parent_commit_id == uuid.UUID(case["parentCommitId"])
                assert identity.root_digest == bytes.fromhex(case["rootDigestHex"])
                assert [item.display_title for item in store.list()] == case["titles"]
                assert store.metadata()["interop_marker"] == case["metadataMarker"]
                login_id = uuid.UUID(case["loginId"])
                login = store.read_entry(login_id)
                assert login is not None
                assert login.fields["future_extension"]["answer"] == case["extensionAnswer"]
                trash = store.read_entry(uuid.UUID(case["trashId"]))
                assert trash is not None and trash.deleted_at is not None
                passkey_id = uuid.UUID(case["passkeyId"])
                passkey = store.read_entry(passkey_id)
                assert passkey is not None and passkey.fields["rp_id"] == case["rpId"]
                assert store.query_domain(case["domain"]) == (login_id,)
                assert store.query_package(case["package"]) == (login_id,)
                assert store.query_rp_id(case["rpId"]) == (passkey_id,)
