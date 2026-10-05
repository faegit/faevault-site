from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from core import auto_cloud_sync, cloud
from core.auto_cloud_sync import sync_webdav
from core.cloud import CloudConflict, CloudError, RemoteFileSnapshot, WebDavConfig
from core.models import Entry
from core.storage import Vault, VaultLineage


def _spec_root() -> Path:
    configured = os.environ.get("VAULT_SHARED_SPEC_DIR")
    return (
        Path(configured)
        if configured
        else Path(__file__).resolve().parents[2]
        / "vault_android"
        / "spec"
        / "interop"
        / "pmv_next"
        / "v1"
    )


def _fixture_pair(writer: str = "android") -> tuple[Path, Path, str]:
    root = _spec_root()
    document = json.loads((root / "store_interop.json").read_text(encoding="utf-8"))
    seq1 = next(case for case in document["cases"] if case["writer"] == writer and case["sequence"] == 1)
    seq2 = next(case for case in document["cases"] if case.get("continuedFrom") == seq1["id"])
    return root / seq1["blob"], root / seq2["blob"], document["passwordUtf8"]


_REAL_WEBDAV_CLIENT = cloud.WebDavClient


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while part := stream.read(64 * 1024):
            value.update(part)
    return value.hexdigest()


class FakeFileWebDav:
    instance = None
    remote_path: Path
    conflict_once = False

    def __init__(self, _config):
        type(self).instance = self
        self.downloads = 0
        self.uploads = 0

    def download_to(self, target: Path) -> RemoteFileSnapshot:
        self.downloads += 1
        with self.remote_path.open("rb") as source, Path(target).open("wb") as output:
            shutil.copyfileobj(source, output, 64 * 1024)
        stat = self.remote_path.stat()
        return RemoteFileSnapshot(Path(target), f'"{_digest(self.remote_path)}"', True, stat.st_mtime, stat.st_size)

    def download_to_if_exists(self, target: Path) -> RemoteFileSnapshot | None:
        return self.download_to(target) if self.remote_path.exists() else None

    def upload_file_if_unchanged(self, source: Path, expected: RemoteFileSnapshot) -> str:
        self.uploads += 1
        if type(self).conflict_once:
            type(self).conflict_once = False
            with Path(source).open("rb") as input_stream, self.remote_path.open("wb") as output:
                shutil.copyfileobj(input_stream, output, 64 * 1024)
            raise CloudConflict("simulated CAS race")
        current = f'"{_digest(self.remote_path)}"' if self.remote_path.exists() else None
        weak_changed = (
            expected.exists
            and expected.revision is None
            and _digest(self.remote_path) != _digest(expected.path)
        )
        if expected.exists != self.remote_path.exists() or (
            expected.exists and expected.revision is not None and current != expected.revision
        ) or weak_changed:
            raise CloudConflict("stale snapshot")
        with Path(source).open("rb") as input_stream, self.remote_path.open("wb") as output:
            shutil.copyfileobj(input_stream, output, 64 * 1024)
        return f'"{_digest(self.remote_path)}"'


def _install_fake(monkeypatch, remote_path: Path, *, conflict_once: bool = False) -> None:
    FakeFileWebDav.remote_path = remote_path
    FakeFileWebDav.conflict_once = conflict_once
    monkeypatch.setattr(auto_cloud_sync.cloud, "WebDavClient", FakeFileWebDav)


class WeakEtagWebDav:
    """Real WebDavClient over an in-memory server that only emits weak ETags.

    ``FakeFileWebDav`` hands back a strong ETag, which routes the upload through
    ``If-Match`` and never exercises the weak-version content gate.  Servers
    without a strong ETag are common (nginx gzip, many NAS), so the production
    client must be driven against one here.
    """

    def __init__(self, config):
        self.config = config
        self.remote = b""
        self.uploads = 0

    def _make_client(self):
        outer = self

        class _Body:
            def __init__(self, payload):
                self._payload = payload
                self._pos = 0

            def read(self, size=-1):
                chunk = (
                    self._payload[self._pos:]
                    if size is None or size < 0
                    else self._payload[self._pos:self._pos + size]
                )
                self._pos += len(chunk)
                return chunk

            def close(self):
                pass

        def request(method, *, url=None, data=None, headers=None, retry=False, stream=False):
            del retry, stream
            headers = headers or {}
            if method in {"HEAD", "GET"}:
                if not outer.remote:
                    raise CloudError("服务器返回 HTTP 404")
                body = outer.remote
                response_headers = {
                    "Content-Length": str(len(body)),
                    "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                    # 弱 ETag：客户端必须拒绝把它当作强版本号。
                    "ETag": f'W/"{hashlib.md5(body).hexdigest()}"',  # noqa: S324 - test double
                }
                if method == "HEAD":
                    return 200, response_headers, _Body(b"")
                if "Range" in headers:
                    return 206, {**response_headers, "Content-Range": f"bytes 0-0/{len(body)}"}, _Body(body[:1])
                return 200, response_headers, _Body(body)
            if method == "PUT":
                if "If-Match" in headers:
                    raise AssertionError("weak ETag must never be sent as If-Match")
                outer.uploads += 1
                outer.remote = data if isinstance(data, bytes) else data.read()
                return 201, {}, _Body(b"")
            return 405, {}, _Body(b"")

        # Bound at import time: _install_weak_etag replaces cloud.WebDavClient,
        # so looking it up lazily here would resolve to the fake itself.
        client = _REAL_WEBDAV_CLIENT.__new__(_REAL_WEBDAV_CLIENT)
        client.config = self.config
        client.timeout = 45.0
        client._opener = None
        client._request = request
        return client

    def download_to_if_exists(self, target: Path) -> RemoteFileSnapshot | None:
        if not self.remote:
            return None
        return self._make_client().download_to(target)

    def upload_file_if_unchanged(self, source: Path, expected, *, force: bool = False):
        return self._make_client().upload_file_if_unchanged(source, expected, force=force)


def _install_weak_etag(monkeypatch, remote: Path) -> WeakEtagWebDav:
    fake = WeakEtagWebDav(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    fake.remote = remote.read_bytes()
    monkeypatch.setattr(auto_cloud_sync.cloud, "WebDavClient", lambda _config: fake)
    return fake


def test_pmve_webdav_fast_forward_adopts_authenticated_remote_file(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq1, local)
    shutil.copy2(seq2, remote)
    _install_fake(monkeypatch, remote)

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.changed is True
    assert result.uploaded is False
    reopened = Vault.open(local, password)
    assert reopened.pmve_identity.sequence == 2
    reopened.close()


def test_pmve_webdav_remote_stale_streams_file_and_never_calls_path_read_bytes(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(seq1, remote)
    _install_fake(monkeypatch, remote)
    original = Path.read_bytes

    def reject_vault_read_bytes(path):
        if Path(path) in {local, remote}:
            raise AssertionError("PMVE cloud sync must use file streams")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", reject_vault_read_bytes)
    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert _digest(local) == _digest(remote)
    assert FakeFileWebDav.instance.uploads == 1


def test_pmve_webdav_repulls_after_cas_race(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(seq1, remote)
    _install_fake(monkeypatch, remote, conflict_once=True)

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert FakeFileWebDav.instance.downloads == 2
    assert FakeFileWebDav.instance.uploads == 1


def test_pmve_webdav_rejects_different_signer_and_converges_diverged_history(tmp_path, monkeypatch) -> None:
    android_seq1, _android_seq2, password = _fixture_pair("android")
    pc_seq1, _pc_seq2, _ = _fixture_pair("pc")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(android_seq1, local)
    shutil.copy2(pc_seq1, remote)
    _install_fake(monkeypatch, remote)
    with pytest.raises(CloudError, match="身份|认证|签名"):
        sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    shutil.copy2(android_seq1, local)
    shutil.copy2(android_seq1, remote)
    local_vault = Vault.open(local, password)
    remote_vault = Vault.open(remote, password)
    local_entry = Entry.from_dict(local_vault.entries[0].to_dict())
    remote_entry = Entry.from_dict(remote_vault.entries[0].to_dict())
    local_entry.title = "local branch"
    remote_entry.title = "remote branch"
    local_vault.update(local_entry)
    remote_vault.update(remote_entry)
    local_vault.close()
    remote_vault.close()
    # 分叉不再暂停：自动以远端 Head 为基线合并（条目 LWW + 密钥版本自动收敛）并上传。
    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    assert result.uploaded is True
    assert _digest(local) == _digest(remote)
    Vault.open(local, password).close()


def test_pmve_webdav_diverged_repulls_and_converges_after_cas_race(tmp_path, monkeypatch) -> None:
    seq1, _seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq1, local)
    shutil.copy2(seq1, remote)
    local_vault = Vault.open(local, password)
    remote_vault = Vault.open(remote, password)
    local_entry = Entry.from_dict(local_vault.entries[0].to_dict())
    remote_entry = Entry.from_dict(remote_vault.entries[0].to_dict())
    local_entry.title = "local branch"
    remote_entry.title = "remote branch"
    local_vault.update(local_entry)
    remote_vault.update(remote_entry)
    local_vault.close()
    remote_vault.close()
    _install_fake(monkeypatch, remote, conflict_once=True)

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert FakeFileWebDav.instance.downloads == 2
    assert FakeFileWebDav.instance.uploads == 1
    assert _digest(local) == _digest(remote)


def test_put_file_sends_if_unmodified_since_when_no_strong_etag(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source.pmv"
    source.write_bytes(b"x" * 1024)
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    seen = {}

    def request(method, *, url=None, data=None, headers=None, retry=False, stream=False):
        seen["headers"] = dict(headers or {})
        return 201, {}, b""

    monkeypatch.setattr(client, "_request", request)
    client._put_file(client.config.file_url, source, unmodified_since=1_785_636_000.0)

    assert "If-Unmodified-Since" in seen["headers"]
    assert seen["headers"]["If-Unmodified-Since"] == "Sun, 02 Aug 2026 02:00:00 GMT"
    assert "If-Match" not in seen["headers"]


def test_same_version_falls_back_to_size_and_modified_without_strong_etag() -> None:
    expected = cloud.RemoteFileSnapshot(Path("unused.pmv"), None, True, 100.0, 3)
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert client._same_version(expected, cloud.RemoteMetadata(True, 3, 100.0, None))
    assert not client._same_version(expected, cloud.RemoteMetadata(True, 4, 100.0, None))
    assert not client._same_version(expected, cloud.RemoteMetadata(True, 3, 101.0, None))
    weak = cloud.RemoteFileSnapshot(Path("unused.pmv"), 'W/"weak"', True, 100.0, 3)
    assert client._same_version(weak, cloud.RemoteMetadata(True, 3, 100.0, None))


def test_auto_sync_matches_android_with_authenticated_weak_webdav_version(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(seq1, remote)
    _install_fake(monkeypatch, remote)
    original = FakeFileWebDav.download_to

    def without_etag(self, target):
        snapshot = original(self, target)
        return RemoteFileSnapshot(snapshot.path, None, True, snapshot.modified_at, snapshot.size)

    monkeypatch.setattr(FakeFileWebDav, "download_to", without_etag)
    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert FakeFileWebDav.instance.uploads == 1
    assert _digest(remote) == _digest(local)


def test_webdav_file_primitives_stream_request_bodies_and_downloads(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source.pmv"
    target = tmp_path / "target.pmv"
    source.write_bytes(b"x" * (1024 * 1024 + 3))
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    seen = {}

    def request(method, *, url=None, data=None, headers=None, retry=False, stream=False):
        seen["is_bytes"] = isinstance(data, bytes)
        seen["content_length"] = headers["Content-Length"]
        seen["body"] = data.read()
        return 201, {}, b""

    monkeypatch.setattr(client, "_request", request)
    client._put_file(client.config.file_url, source, require_missing=True)
    assert seen["is_bytes"] is False
    assert int(seen["content_length"]) == source.stat().st_size
    assert hashlib.sha256(seen["body"]).hexdigest() == _digest(source)

    response = type("Response", (), {
        "headers": {"Content-Length": str(source.stat().st_size), "ETag": '"one"'},
        "read": lambda self, size=-1: self.handle.read(size),
        "close": lambda self: self.handle.close(),
        "handle": source.open("rb"),
    })()
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: (200, response.headers, response))
    snapshot = client.download_to(target)
    assert snapshot.path == target
    assert snapshot.revision == '"one"'
    assert _digest(target) == _digest(source)


def test_put_file_treats_lost_response_as_success_after_matching_readback(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source.pmv"
    source.write_bytes(b"committed-content")
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    requests = 0

    def lost_response(*args, **kwargs):
        nonlocal requests
        requests += 1
        raise CloudError("response lost")

    monkeypatch.setattr(client, "_request", lost_response)
    monkeypatch.setattr(client, "_remote_file_matches", lambda url, size, digest: True)

    client._put_file(client.config.file_url, source)
    assert requests == 1


def test_put_file_preserves_error_when_lost_response_cannot_be_verified(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source.pmv"
    source.write_bytes(b"not-committed")
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args, **kwargs: (_ for _ in ()).throw(CloudError("response lost")),
    )
    monkeypatch.setattr(client, "_remote_file_matches", lambda url, size, digest: False)

    with pytest.raises(CloudError, match="response lost"):
        client._put_file(client.config.file_url, source)


def test_pmve_drive_auto_sync_matches_android_with_content_cas(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("pc")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(seq1, remote)
    original = Path.read_bytes

    def reject_vault_read_bytes(path):
        if Path(path) in {local, remote}:
            raise AssertionError("PMVE cloud drive must use file streams")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", reject_vault_read_bytes)
    result = auto_cloud_sync.sync_drive(local, password, remote)

    assert result.uploaded is True
    assert _digest(remote) == _digest(local)


def test_pmve_cloud_uses_file_only_entry_points(tmp_path, monkeypatch) -> None:
    seq1, _seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    shutil.copy2(seq1, local)
    vault = Vault.open(local, password)
    assert not hasattr(auto_cloud_sync, "_upload_payload")
    assert not hasattr(auto_cloud_sync, "_merge")
    vault.close()

    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _path: (_ for _ in ()).throw(AssertionError("must reject before read_bytes")),
    )
    with pytest.raises(CloudError, match="file-only|文件"):
        cloud.read_cloud_drive(local)
    client = cloud.WebDavClient(WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))
    with pytest.raises(CloudError, match="file-only|文件"):
        client.upload(b"PMVS" + bytes(32))


def _diverged_pair(tmp_path: Path, password: str) -> tuple[Path, Path]:
    """两个都从同一祖先分叉的副本：本地改一条，远端改另一条。"""
    seq1, _seq2, _ = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq1, local)
    shutil.copy2(seq1, remote)
    local_vault = Vault.open(local, password)
    remote_vault = Vault.open(remote, password)
    local_entry = Entry.from_dict(local_vault.entries[0].to_dict())
    remote_entry = Entry.from_dict(remote_vault.entries[0].to_dict())
    local_entry.title = "local branch"
    remote_entry.title = "remote branch"
    local_vault.update(local_entry)
    remote_vault.update(remote_entry)
    local_vault.close()
    remote_vault.close()
    return local, remote


def test_pmve_webdav_diverged_merge_converges_on_a_weak_etag_server(tmp_path, monkeypatch) -> None:
    """弱 ETag 服务器上 DIVERGED 合并必须成功，而不是耗尽 CAS 重试后报冲突。

    合并流程会原地改写下载暂存文件；内容闸门必须比对下载时记录的远端副本哈希，
    否则每次尝试都会误判「远端已被他人更新」。
    """
    _seq1, _seq2, password = _fixture_pair("android")
    local, remote = _diverged_pair(tmp_path, password)
    fake = _install_weak_etag(monkeypatch, remote)

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert result.changed is True
    assert result.stats["lineage"] == VaultLineage.DIVERGED.value
    assert result.stats["cas_retries"] == 0
    assert fake.uploads == 1
    assert hashlib.sha256(fake.remote).hexdigest() == _digest(local)
    Vault.open(local, password).close()


def test_pmve_webdav_remote_stale_uploads_on_a_weak_etag_server(tmp_path, monkeypatch) -> None:
    _seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(_seq1, remote)
    fake = _install_weak_etag(monkeypatch, remote)

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert result.uploaded is True
    assert fake.uploads == 1
    assert hashlib.sha256(fake.remote).hexdigest() == _digest(local)


def test_pmve_webdav_converges_when_the_remote_changes_mid_upload_on_a_weak_etag_server(
    tmp_path, monkeypatch
) -> None:
    """弱 ETag 上的抢跑必须被内容闸门看见，并在有界重试内收敛，而不是静默覆盖。

    内容闸门的作用是「发现远端已变」，随后由重拉 + 重新合并收敛；它必须继续
    有效，不能因为合并原地改写了暂存文件而变成永远放行。
    """
    seq1, seq2, password = _fixture_pair("android")
    local = tmp_path / "local.pmv"
    remote = tmp_path / "remote.pmv"
    shutil.copy2(seq2, local)
    shutil.copy2(seq1, remote)
    # 抢跑方写出一个与本地不同的新版本，确保收敛必须真的重拉并重新合并。
    rival = tmp_path / "rival.pmv"
    shutil.copy2(seq2, rival)
    rival_vault = Vault.open(rival, password)
    rival_entry = Entry.from_dict(rival_vault.entries[0].to_dict())
    rival_entry.title = "rival device edit"
    rival_vault.update(rival_entry)
    rival_vault.close()

    fake = _install_weak_etag(monkeypatch, remote)
    real_upload = fake.upload_file_if_unchanged
    state = {"raced": 0, "rejections": 0}

    def upload_then_race(source, expected, *, force=False):
        if state["raced"] == 0:
            state["raced"] = 1
            fake.remote = rival.read_bytes()  # 另一台设备抢跑
        try:
            return real_upload(source, expected, force=force)
        except CloudConflict:
            state["rejections"] += 1
            raise

    fake.upload_file_if_unchanged = upload_then_race

    result = sync_webdav(local, password, WebDavConfig("fake", "https://fake/vault.pmv", auth_mode="none"))

    assert state["raced"] == 1, "第一次上传前应发生远端抢跑"
    assert state["rejections"] >= 1, "内容闸门必须发现远端已被他人改写"
    assert result.stats["cas_retries"] >= 1
    # 抢跑方是本地的新祖先，所以收敛方式是快进采纳而非再次上传；本地内容不能
    # 被静默回退，抢跑方的修改也必须保留下来。
    assert result.changed is True
    assert result.stats["lineage"] == VaultLineage.FAST_FORWARD.value
    assert hashlib.sha256(fake.remote).hexdigest() == _digest(local)
    assert "rival device edit" in _titles(local, password)


def _titles(path: Path, password: str) -> list[str]:
    vault = Vault.open(path, password)
    try:
        return [entry.title for entry in vault.entries]
    finally:
        vault.close()
