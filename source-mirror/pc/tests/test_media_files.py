"""媒体静态加密：文件落盘为密文，仅解锁会话内可读，旧明文惰性迁移。"""

import base64
import hashlib
import os
import uuid

import pytest

from core import media_files
from core.models import Entry
from core.pmv_attachment import AttachmentKind
from core.pmv_media_ref import MediaRef
from core.pmv_vault_store import ObjectRef


@pytest.fixture(autouse=True)
def _isolated_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    yield
    while media_files._context_stack:
        media_files.clear_media_context()


def _ctx():
    media_files.set_media_context("vault-test", bytes(range(32)))


class _FakeObjectVault:
    def __init__(self, chunks=()):
        self.chunks = tuple(chunks)
        self.opened = []
        self.ranges = []

    def open_media_object(self, ref, output):
        self.opened.append(ref)
        for chunk in self.chunks:
            output.write(chunk)

    def open_media_range(self, ref, offset, length, output):
        self.ranges.append((ref, offset, length))
        payload = b"".join(self.chunks)[offset : offset + length]
        output.write(payload)


def _pmve_ref(*, size: int, kind=AttachmentKind.ATTACHMENT, digest: bytes | None = None):
    return MediaRef(
        uuid.UUID("12345678-1234-5678-9234-567812345678"),
        7,
        kind,
        size,
        digest or bytes.fromhex("ab" * 32),
    )


def test_import_writes_ciphertext_and_roundtrips(tmp_path):
    _ctx()
    source = tmp_path / "photo.png"
    payload = b"\x89PNG\r\n\x1a\n" + os.urandom(64 * 1024)
    source.write_bytes(payload)
    ref = media_files.import_file(source, "image", "photo.png")
    path = media_files.resolve_ref(ref)
    assert path is not None
    raw = path.read_bytes()
    assert raw != payload                      # 不再是明文
    assert raw.startswith(b"VMED\x01")         # 加密格式头
    assert media_files.read_bytes(ref) == payload


def test_large_file_streaming_roundtrip(tmp_path):
    _ctx()
    source = tmp_path / "big.bin"
    payload = os.urandom(3 * 1024 * 1024 + 17)
    source.write_bytes(payload)
    ref = media_files.import_file(source, "attachment", "big.bin")
    dest = tmp_path / "out.bin"
    media_files.export_value(ref, dest)
    assert dest.read_bytes() == payload


def test_export_inline_base64_with_data_uri_prefix(tmp_path):
    payload = os.urandom(300 * 1024)
    value = "data:image/jpeg;base64," + base64.b64encode(payload).decode("ascii")
    destination = tmp_path / "export.bin"
    media_files.export_value(value, destination)
    assert destination.read_bytes() == payload


def test_read_requires_context(tmp_path):
    source = tmp_path / "photo.png"
    source.write_bytes(b"abc")
    media_files.set_media_context("vault-test", bytes(range(32)))
    ref = media_files.import_file(source, "image", "photo.png")
    media_files.clear_media_context()
    with pytest.raises(RuntimeError):
        media_files.read_bytes(ref)


def test_legacy_plaintext_is_migrated_and_deleted(tmp_path):
    _ctx()
    # 模拟升级前的旧明文文件：放在旧全局目录，未加密
    legacy = media_files._legacy_kind_dir("image")
    legacy.mkdir(parents=True, exist_ok=True)
    legacy_file = legacy / "deadbeef.jpg"
    legacy_file.write_bytes(b"LEGACYPLAINTEXT")
    ref = "img:deadbeef.jpg"

    assert media_files.read_bytes(ref) == b"LEGACYPLAINTEXT"
    assert not legacy_file.exists()                       # 迁移后删除旧明文
    migrated = media_files.resolve_ref(ref)
    assert migrated is not None and migrated.parent != legacy
    assert media_files.read_bytes(ref) == b"LEGACYPLAINTEXT"


def test_media_key_derived_from_dek_is_stable():
    media_files.set_media_context("vault-x", bytes(range(32)))
    k1 = media_files._media_key()
    media_files.clear_media_context()
    media_files.set_media_context("vault-x", bytes(range(32)))
    assert media_files._media_key() == k1
    # 不同库（不同 DEK）→ 不同媒体密钥
    media_files.set_media_context("vault-y", bytes(range(33)))
    assert media_files._media_key() != k1
    media_files.clear_media_context()


def test_pmve_object_ref_read_and_range_use_vault_facade():
    vault = _FakeObjectVault((b"abc", b"def"))
    ref = _pmve_ref(size=6, digest=hashlib.sha256(b"abcdef").digest())
    media_files.set_vault_context(vault)

    assert media_files.read_bytes(ref.to_json()) == b"abcdef"
    assert media_files.read_range(ref.to_external_string(), 2, 3) == b"cde"
    assert vault.opened == [ref]
    assert vault.ranges == [(ref, 2, 3)]


def test_vault_context_removal_does_not_pop_unrelated_active_vault():
    first = _FakeObjectVault((b"first",))
    second = _FakeObjectVault((b"second",))
    ref = _pmve_ref(size=6, digest=hashlib.sha256(b"second").digest())
    media_files.set_vault_context(first)
    media_files.set_vault_context(second)

    media_files.remove_vault_context(first)

    assert media_files.read_bytes(ref.to_json()) == b"second"
    assert first.opened == []
    assert second.opened == [ref]


def test_ensure_vault_context_replaces_stale_context_for_same_vault():
    vault = _FakeObjectVault((b"old",))
    media_files.set_vault_context(vault)
    vault.chunks = (b"new",)
    ref = _pmve_ref(size=3, digest=hashlib.sha256(b"new").digest())

    media_files.ensure_vault_context(vault)

    assert media_files.read_bytes(ref.to_json()) == b"new"


def test_pmve_read_rejects_over_64mb_before_opening_object():
    vault = _FakeObjectVault((b"must not be requested",))
    ref = _pmve_ref(size=64 * 1024 * 1024 + 1)
    media_files.set_vault_context(vault)

    with pytest.raises(ValueError, match="过大"):
        media_files.read_bytes(ref.to_json())

    assert vault.opened == []


def test_pmve_export_streams_object_without_read_bytes(tmp_path):
    chunks = (b"a" * (1024 * 1024), b"b" * (1024 * 1024), b"tail")
    vault = _FakeObjectVault(chunks)
    ref = _pmve_ref(
        size=sum(map(len, chunks)),
        digest=hashlib.sha256(b"".join(chunks)).digest(),
    )
    destination = tmp_path / "export.bin"
    media_files.set_vault_context(vault)

    media_files.export_value(ref.to_json(), destination)

    assert vault.opened == [ref]
    with destination.open("rb") as exported:
        assert exported.read(4) == b"aaaa"
        exported.seek(-4, os.SEEK_END)
        assert exported.read() == b"tail"
    assert destination.stat().st_size == ref.size


def test_pmve_value_metadata_does_not_open_object():
    vault = _FakeObjectVault((b"must not be requested",))
    ref = _pmve_ref(size=70 * 1024 * 1024)
    media_files.set_vault_context(vault)

    assert media_files.is_ref(ref.to_json())
    assert media_files.value_size(ref.to_json()) == ref.size
    assert media_files.value_sha256(ref.to_json()) == ref.sha256.hex()
    assert vault.opened == []


def test_pmve_staged_file_is_imported_with_entry_in_one_facade_call(tmp_path):
    source = tmp_path / "photo.png"
    payload = b"\x89PNG\r\n\x1a\ncontent"
    source.write_bytes(payload)

    class Vault(_FakeObjectVault):
        pmve_identity = type("Identity", (), {"sequence": 12})()

        def import_media_mutation(self, transform, **kwargs):
            self.mutation = (transform, kwargs)
            self.imported_payloads = tuple(request.stream.read() for request in transform.object_imports)
            return tuple(
                ObjectRef(request.object_id, request.generation, request.kind,
                          request.expected_size, hashlib.sha256(imported).digest())
                for request, imported in zip(transform.object_imports, self.imported_payloads)
            )

    vault = Vault()
    media_files.set_vault_context(vault)
    staged = media_files.import_file(source, "image", source.name)
    entry = Entry.from_dict({
        "id": "00000000-0000-0000-0000-000000000123",
        "fields": {"images": [staged]},
    })

    committed = media_files.commit_entry_imports(vault, entry)

    assert media_files.is_ref(committed.fields["images"][0])
    transform, kwargs = vault.mutation
    assert vault.imported_payloads == (payload,)
    assert kwargs == {
        "expected_sequence": 12,
        "target_entry": entry,
        "expected_entry_updated_at": None,
    }


def test_pmve_import_bytes_stays_inline_only_until_atomic_commit():
    vault = _FakeObjectVault()
    media_files.set_vault_context(vault)

    staged = media_files.import_bytes(b"camera image", "image")
    entry = Entry.from_dict({
        "id": "00000000-0000-0000-0000-000000000124",
        "fields": {"images": [staged]},
    })

    assert media_files.read_bytes(staged) == b"camera image"
    assert media_files.has_pending_imports(entry)


def test_second_pmve_import_stream_failure_does_not_publish_entry(tmp_path):
    first = tmp_path / "first.png"
    second = tmp_path / "second.png"
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    class FailingVault(_FakeObjectVault):
        pmve_identity = type("Identity", (), {"sequence": 20})()
        entries = ()
        published = False

        def import_media_mutation(self, transform, **_kwargs):
            assert transform.object_imports[0].stream.read() == b"first"
            transform.object_imports[1].stream.close()
            raise OSError("second stream failed")

    vault = FailingVault()
    media_files.set_vault_context(vault)
    entry = Entry.from_dict({
        "id": "00000000-0000-0000-0000-000000000125",
        "fields": {"images": [str(first.resolve()), str(second.resolve())]},
    })

    with pytest.raises(OSError, match="second stream"):
        media_files.commit_entry_imports(vault, entry)

    assert vault.published is False
