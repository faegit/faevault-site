from __future__ import annotations

import io
import json
import uuid
from pathlib import Path

import pytest

from core.models import Entry
from core.pmv_attachment import AttachmentKind
from core.pmv_media_ref import (
    Classification,
    LegacyStream,
    from_external_string,
    from_json,
    plan,
    scan,
)
from core.pmv_vault_store import MutationContent, ObjectImport, ObjectRef, PmvVaultStore


def _case() -> dict:
    path = (Path(__file__).resolve().parents[2] / "vault_android" / "spec" /
            "interop" / "pmv_next" / "v1" / "media_ref.json")
    return json.loads(path.read_text(encoding="utf-8"))["cases"][0]


def _entry() -> Entry:
    return Entry.from_dict({"id": str(uuid.UUID(int=1)), "fields": _case()["fields"]})


def test_shared_vector_fixes_json_and_string_representation() -> None:
    case = _case()
    ref = from_json(case["json"])
    assert ref.to_json() == case["json"]
    assert ref.to_external_string() == case["string"]
    assert from_external_string(ref.to_external_string()) == ref
    with pytest.raises(ValueError):
        from_external_string(ref.to_external_string().replace("attachment", "ATTACHMENT"))


def test_shared_vector_classifies_object_legacy_inline_and_unknown_media_fields() -> None:
    actual = {item.path: item.classification.value for item in scan(_entry())}
    assert actual == _case()["classifications"]
    for case in _case()["closure_cases"]:
        available = set(case["available"])
        imported = case["imported"]
        referenced = set(case["referenced"])
        valid = (len(imported) == len(set(imported)) and referenced <= available and
                 set(imported) <= referenced)
        assert valid is case["valid"]


def test_deleted_identity_image_field_is_not_classified_as_current_media() -> None:
    entry = Entry(fields={"id_images_b64": ["aW1hZ2UtYnl0ZXM="]})

    assert scan(entry) == ()


def test_declarative_plan_creates_imports_and_replaces_only_resolved_legacy_paths() -> None:
    image_id, attachment_id = uuid.UUID(int=2), uuid.UUID(int=3)
    transform = plan(_entry(), (
        LegacyStream("/fields/modules/0/value/0", io.BytesIO(b"12"), 2,
                     image_id, 4, AttachmentKind.IMAGE),
        LegacyStream("/fields/modules/1/value/0/data", io.BytesIO(b"3"), 1,
                     attachment_id, 5, AttachmentKind.ATTACHMENT),
    ))
    assert tuple(item.object_id for item in transform.object_imports) == (image_id, attachment_id)
    updated = transform.transform((
        ObjectRef(image_id, 4, AttachmentKind.IMAGE, 2, bytes((1,)) * 32),
        ObjectRef(attachment_id, 5, AttachmentKind.ATTACHMENT, 1, bytes((2,)) * 32),
    ))
    occurrences = {item.path: item for item in scan(updated)}
    assert occurrences["/fields/modules/0/value/0"].classification is Classification.OBJECT
    assert occurrences["/fields/modules/0/value/0"].ref.object_id == image_id
    assert occurrences["/fields/modules/1/value/0/data"].classification is Classification.OBJECT
    assert occurrences["/fields/modules/1/value/0/data"].ref.object_id == attachment_id
    assert occurrences["/fields/modules/0/value/1"].classification is Classification.INLINE


def test_plan_rejects_object_unknown_and_kind_mismatch_sources() -> None:
    entry = _entry()
    with pytest.raises(ValueError, match="not legacy or inline"):
        plan(entry, (LegacyStream("/fields/modules/1/value/1/data", io.BytesIO(), 0,
                                  uuid.uuid4(), 1, AttachmentKind.ATTACHMENT),))
    with pytest.raises(ValueError, match="kind"):
        plan(entry, (LegacyStream("/fields/modules/0/value/0", io.BytesIO(), 0,
                                  uuid.uuid4(), 1, AttachmentKind.ATTACHMENT),))


def test_plan_bridges_stream_into_one_commit_and_closure_rejects_invalid_states(tmp_path) -> None:
    path = tmp_path / "media-ref.pmv"
    password, recovery = b"media-password", bytes(range(32))
    plain, object_id = b"streamed legacy image", uuid.UUID(int=22)
    store = PmvVaultStore.create(path, password, recovery, _metadata(), [])
    legacy = Entry.from_dict({
        "id": str(uuid.UUID(int=11)),
        "fields": {"images": ["img:legacy.enc"]},
    })
    transform = plan(legacy, (LegacyStream(
        "/fields/images/0", io.BytesIO(plain), len(plain), object_id, 1, AttachmentKind.IMAGE,
    ),))
    committed = store.apply_mutation(
        expected_sequence=1,
        object_imports=transform.object_imports,
        prepare=lambda refs: transform.prepare(refs, _metadata()),
    )
    assert committed.identity.sequence == 2
    output = io.BytesIO()
    store.open_object(object_id, 1, output)
    assert output.getvalue() == plain

    dangling = {
        "$pmv_media_ref": "pmv4-object-v1",
        "object_id": str(uuid.UUID(int=99)),
        "generation": 1,
        "kind": "image",
        "size": 0,
        "sha256": bytes(32).hex(),
    }
    dangling_entry = Entry.from_dict({"id": str(uuid.UUID(int=12)), "fields": {"images": [dangling]}})
    with pytest.raises(ValueError, match="dangling"):
        store.apply_mutation(
            expected_sequence=2,
            prepare=lambda _refs: MutationContent(_metadata(), (dangling_entry,)),
        )
    current = store.read_entry(uuid.UUID(legacy.id))
    with pytest.raises(ValueError, match="orphan"):
        store.apply_mutation(
            expected_sequence=2,
            object_imports=(ObjectImport(io.BytesIO(b"x"), 1, uuid.UUID(int=33), 1,
                                         AttachmentKind.ATTACHMENT),),
            prepare=lambda _refs: MutationContent(_metadata(), (current,)),
        )
    duplicate = ObjectImport(io.BytesIO(b"x"), 1, uuid.UUID(int=44), 1, AttachmentKind.IMAGE)
    with pytest.raises(ValueError, match="duplicate"):
        store.apply_mutation(
            expected_sequence=2,
            object_imports=(duplicate, duplicate),
            prepare=lambda _refs: MutationContent(_metadata(), ()),
        )
    assert store.identity.sequence == 2
    store.close()


def _metadata() -> dict:
    return {
        "schema": "pmv-vault-metadata",
        "version": 1,
        "vault_id": str(uuid.UUID(int=1)),
        "entry_order": [],
        "trash_order": [],
        "sync_meta": {"device_id": str(uuid.UUID(int=2))},
        "key_revision": 0,
        "export_epoch": None,
        "purge_tombstones": {},
    }
