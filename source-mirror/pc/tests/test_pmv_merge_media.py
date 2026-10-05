from dataclasses import replace
from io import BytesIO
import shutil
import uuid

import pytest

from core.models import Entry
from core.pmv_attachment import AttachmentKind, CHUNK_SIZE
from core.pmv_media_ref import from_store_ref
from core.pmv_vault_store import MutationContent, ObjectImport, PmvVaultStore


def fork(tmp_path):
    local, remote = tmp_path / "local.pmv", tmp_path / "remote.pmv"
    metadata = {"schema": "pmv-vault-metadata", "version": 1, "vault_id": str(uuid.uuid4()),
                "entry_order": [], "trash_order": [], "sync_meta": {"device_id": str(uuid.uuid4())}, "key_revision": 0,
                "export_epoch": None, "purge_tombstones": {}}
    with PmvVaultStore.create(local, b"merge-test", bytes(32), metadata, []) as store:
        key = store.copy_root_key()
    shutil.copy2(local, remote)
    return PmvVaultStore.open_root_key(local, key), PmvVaultStore.open_root_key(remote, key)


def add_media(store, plain, *, object_id=None, placement="entry"):
    object_id = object_id or uuid.uuid4()
    metadata = store.metadata()
    entries = [store.read_entry(s.entry_id) for s in store.list()]

    def prepare(refs):
        ref = from_store_ref(refs[0]).to_json()
        if placement == "metadata":
            metadata["media_extension"] = ref
        else:
            entries.append(Entry(title="media", deleted_at=1.0 if placement == "trash" else None,
                                 fields={"images": [ref, ref]}))
        return MutationContent(metadata, entries)

    result = store.apply_mutation(expected_sequence=store.identity.sequence,
                                  object_imports=[ObjectImport(BytesIO(plain), len(plain), object_id, 1,
                                                               AttachmentKind.IMAGE)], prepare=prepare)
    return from_store_ref(result.object_refs[0])


@pytest.mark.parametrize("placement,size", [("entry", CHUNK_SIZE + 17), ("trash", 3), ("metadata", 0)])
def test_merge_copies_reachable_media_once_and_preserves_both_sides(tmp_path, placement, size):
    source, target = fork(tmp_path)
    with source:
        with target:
            plain = b"a" * size
            local_ref = add_media(source, plain, placement=placement)
            remote_ref = add_media(target, b"remote")
            entries = [s.read_entry(e.entry_id) for s in (source, target) for e in s.list()]
            metadata = {**target.metadata(), **source.metadata()}
            head = target.identity
            target.save_merged(source, expected_sequence=head.sequence, metadata=metadata, entries=entries)
            assert target.identity.sequence == head.sequence + 1
            assert target.identity.parent_commit_id == head.commit_id
            for ref, expected in ((local_ref, plain), (remote_ref, b"remote")):
                output = BytesIO()
                target.open_object(ref.object_id, ref.generation, output)
                assert output.getvalue() == expected
            # A second merge must reuse existing objects rather than import duplicate keys.
            target.save_merged(source, expected_sequence=target.identity.sequence, metadata=metadata, entries=entries)


@pytest.mark.parametrize("failure", ["missing", "digest", "collision", "conflicting_refs", "transfer"])
def test_invalid_merge_keeps_original_files(tmp_path, failure, monkeypatch):
    source, target = fork(tmp_path)
    with source, target:
        ref = add_media(source, b"local")
        if failure == "collision":
            add_media(target, b"other", object_id=ref.object_id)
        if failure == "missing":
            ref = replace(ref, object_id=uuid.uuid4())
        elif failure == "digest":
            ref = replace(ref, sha256=bytes(32))
        values = [ref.to_json()]
        if failure == "conflicting_refs":
            values.append(replace(ref, sha256=bytes(32)).to_json())
        if failure == "transfer":
            import core.pmv_vault_store as module
            def corrupt(*args):
                args[-1].write(b"wrong")
            monkeypatch.setattr(module, "open_object_range_to", corrupt)
        original = {store.path: store.path.read_bytes() for store in (source, target)}
        with pytest.raises(ValueError):
            target.save_merged(source, expected_sequence=target.identity.sequence, metadata=target.metadata(),
                               entries=[Entry(fields={"images": values})])
        for path, content in original.items():
            assert path.read_bytes() == content
