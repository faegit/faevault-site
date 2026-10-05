import hashlib
import io
import json
import uuid
from email.message import Message
from urllib.error import HTTPError

import pytest
from core import cloud
from core.auto_cloud_sync import is_due, sync_drive
from core.cloud import (
    CloudConflict,
    CloudError,
    RemoteFileSnapshot,
    RemoteMetadata,
    RemoteSnapshot,
    WebDavClient,
    WebDavConfig,
    _config_path,
    clear_cloud_drive,
    clear_webdav,
    cloud_drive_metadata,
    load_cloud_drive,
    load_cloud_drive_logical_revision,
    load_cloud_drive_revision,
    load_webdav,
    logical_vault_revision,
    read_cloud_drive,
    remote_logical_changed,
    save_cloud_drive,
    save_cloud_drive_sync,
    save_webdav,
    write_cloud_drive,
)
from core.models import Entry
from core.storage import Vault


def test_sync_candidate_filter_rejects_backup_and_migration_artifacts():
    assert cloud.is_sync_candidate_name("vault.pmv") is True
    assert cloud.is_sync_candidate_name("FAE.pre-migration-20260821-145303.pmv") is False
    assert cloud.is_sync_candidate_name("FAE.pre-migration-20260821-145303.pmv.bak") is False
    assert cloud.is_sync_candidate_name("vault.pmv.tmp") is False
    assert cloud.is_sync_candidate_name("backup-archive.pmv") is False


def test_cloud_drive_metadata_reads_only_stat(tmp_path):
    target = tmp_path / "vault.pmv"
    target.write_bytes(b"encrypted")
    target.touch()

    metadata = cloud_drive_metadata(target)

    assert metadata.exists
    assert metadata.size == len(b"encrypted")
    assert metadata.modified_at == pytest.approx(target.stat().st_mtime)


def test_missing_cloud_drive_metadata_does_not_open_file(tmp_path):
    assert cloud_drive_metadata(tmp_path / "missing.pmv") == RemoteMetadata(False)


class Response:
    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self._body = io.BytesIO(body)
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, size=-1):
        return self._body.read(size)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)

    def open(self, request, timeout):
        response = self.responses.pop(0)
        if isinstance(response, int):
            raise HTTPError(request.full_url, response, "error", Message(), None)
        return response


def test_webdav_metadata_uses_head_without_downloading_body():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", auth_mode="none"))
    client._opener = Opener(
        [
            Response(
                body=b"must-not-be-read",
                headers={
                    "Content-Length": "123",
                    "Last-Modified": "Sun, 02 Aug 2026 10:00:00 GMT",
                    "ETag": '"v1"',
                },
            ),
        ]
    )

    metadata = client.metadata()

    assert metadata.exists
    assert metadata.size == 123
    assert metadata.modified_at > 0
    assert metadata.revision == '"v1"'


def test_pmve_webdav_upload_writes_only_final_database_path(tmp_path, monkeypatch):
    source = tmp_path / "local.pmv"
    source.write_bytes(b"PMVS-encrypted-database")
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/dav/vault.pmv", create_directories=False))
    expected = RemoteFileSnapshot(
        tmp_path / "remote.pmv",
        '"old"',
        modified_at=10.0,
        size=source.stat().st_size,
    )
    uploaded_urls = []

    def metadata(*, verify_size=False):
        del verify_size
        return RemoteMetadata(
            True,
            source.stat().st_size,
            10.0,
            '"new"' if client.config.file_url in uploaded_urls else '"old"',
        )

    def download_to(url, target):
        target.write_bytes(source.read_bytes())
        return RemoteFileSnapshot(
            target,
            '"temporary"',
            modified_at=10.0,
            size=source.stat().st_size,
        )

    monkeypatch.setattr(client, "metadata", metadata)
    monkeypatch.setattr(client, "_put_file", lambda url, *_args, **_kwargs: uploaded_urls.append(url))
    monkeypatch.setattr(client, "_download_to", download_to)
    monkeypatch.setattr(client, "_delete", lambda _url: None)

    assert client.upload_file_if_unchanged(source, expected) == '"new"'
    assert uploaded_urls == [client.config.file_url]
    assert all(".upload-" not in url and not url.endswith(".tmp") for url in uploaded_urls)


def test_pmve_cloud_limit_matches_android_one_gibibyte(tmp_path):
    assert cloud.MAX_CLOUD_VAULT_BYTES == 1024**3

    source = tmp_path / "oversized.pmv"
    with source.open("wb") as stream:
        stream.truncate(cloud.MAX_CLOUD_VAULT_BYTES + 1)
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", auth_mode="none"))
    expected = RemoteFileSnapshot(tmp_path / "remote.pmv", None, exists=False, size=0)

    with pytest.raises(CloudError, match="1 GB"):
        client.upload_file_if_unchanged(source, expected)


def test_pmve_webdav_download_rejects_android_incompatible_size(tmp_path, monkeypatch):
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", auth_mode="none"))
    response = Response(headers={"Content-Length": str(cloud.MAX_CLOUD_VAULT_BYTES + 1)})
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: (200, response.headers, response))

    with pytest.raises(CloudError, match="1 GB"):
        client.download_to(tmp_path / "download.pmv")


def test_legacy_webdav_upload_also_writes_only_final_path(monkeypatch):
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/dav/vault.pmv", create_directories=False))
    uploaded_urls = []
    monkeypatch.setattr(client, "_head", lambda *_args, **_kwargs: '"revision"')
    monkeypatch.setattr(client, "_put", lambda url, *_args, **_kwargs: uploaded_urls.append(url))
    monkeypatch.setattr(client, "_download", lambda _url: (b"legacy-vault", '"revision"'))
    monkeypatch.setattr(client, "_move", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(client, "_delete", lambda _url: None)

    assert client.upload_overwrite(b"legacy-vault") == '"revision"'
    assert uploaded_urls == [client.config.file_url]


def test_webdav_metadata_verifies_stale_positive_head_size_when_requested():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", auth_mode="none"))
    client._opener = Opener(
        [
            Response(
                headers={
                    "Content-Length": "1024",
                    "Last-Modified": "Sun, 02 Aug 2026 10:00:00 GMT",
                    "ETag": '"stale"',
                },
            ),
            Response(
                status=206,
                body=b"v",
                headers={"Content-Range": "bytes 0-0/4096"},
            ),
        ]
    )

    metadata = client.metadata(verify_size=True)

    assert metadata.exists
    assert metadata.size == 4096
    assert metadata.modified_at > 0
    assert metadata.revision == '"stale"'


def test_webdav_metadata_accepts_range_416_as_a_truly_empty_file():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", auth_mode="none"))
    client._opener = Opener(
        [
            Response(headers={"Content-Length": "0", "ETag": '"empty"'}),
            416,
        ]
    )

    metadata = client.metadata()

    assert metadata.exists
    assert metadata.size == 0
    assert metadata.revision == '"empty"'


def test_webdav_requires_remote_file_name():
    with pytest.raises(CloudError):
        WebDavConfig("NAS", "https://nas.example/dav/").validate()


def test_webdav_rejects_cleartext_even_without_credentials():
    with pytest.raises(CloudError, match="HTTPS"):
        WebDavConfig("NAS", "http://nas.example/vault.pmv").validate()


def test_webdav_rejects_incomplete_certificate_fingerprint():
    with pytest.raises(CloudError, match="64"):
        WebDavConfig("NAS", "https://nas.example/vault.pmv", certificate_sha256="1234").validate()


@pytest.mark.parametrize("mode", ["bearer", "oauth2", "cookie", "mtls", "ntlm", "kerberos"])
def test_sensitive_webdav_auth_modes_require_https(mode):
    kwargs = {"auth_mode": mode}
    if mode in {"bearer", "oauth2"}:
        kwargs["bearer_token"] = "token"
    if mode == "cookie":
        kwargs["cookie"] = "sid=value"
    if mode == "mtls":
        kwargs["client_certificate"] = "AA=="
    if mode == "ntlm":
        kwargs.update(username="user", password="password")
    with pytest.raises(CloudError, match="HTTPS"):
        WebDavConfig("NAS", "http://nas.example/vault.pmv", **kwargs).validate()


def test_basic_auth_rejects_partial_credentials_but_preserves_anonymous_legacy_config():
    WebDavConfig("NAS", "https://nas.example/vault.pmv").validate()
    with pytest.raises(CloudError, match="同时填写"):
        WebDavConfig("NAS", "https://nas.example/vault.pmv", username="user").validate()


def test_cloud_settings_are_isolated_per_vault():
    assert _config_path("vault-a") != _config_path("vault-b")


def test_webdav_probe_atomic_upload_and_download():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/dav/vault.pmv", "u", "p", create_directories=False))
    client._opener = Opener(
        [
            Response(204, headers={"DAV": "1, 2", "Allow": "GET, PUT"}),
            404,
            404,
            Response(204),
            Response(200, b"vault-bytes"),
            Response(200, headers={"ETag": '"new"'}),
            Response(200, b"vault-bytes"),
        ]
    )
    client.test()
    assert client.upload(b"vault-bytes") == '"new"'
    assert client.download() == b"vault-bytes"


def test_webdav_stops_when_remote_etag_changes_during_upload():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/dav/vault.pmv", create_directories=False))
    client._opener = Opener(
        [
            Response(200, headers={"ETag": '"old"'}),
            412,
        ]
    )
    with pytest.raises(CloudConflict):
        client.upload_if_unchanged(b"vault-bytes", RemoteSnapshot(b"remote", '"old"'))


def test_webdav_accepts_capability_probe_when_options_is_incomplete():
    client = WebDavClient(WebDavConfig("自定义云", "https://cloud.example/vault.pmv", create_directories=False))
    client._opener = Opener([Response(204), Response(204), Response(204), 404])
    client.test()


def test_webdav_sync_upload_rejects_revision_changed_after_pull():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", create_directories=False))
    client._opener = Opener([Response(200, headers={"ETag": '"new"'})])
    with pytest.raises(CloudConflict, match="重新同步"):
        client.upload_if_unchanged(b"local", RemoteSnapshot(b"remote", '"old"'))


def test_webdav_force_upload_bypasses_existing_revision():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", create_directories=False))
    client._opener = Opener(
        [
            Response(204),  # HEAD (file_url) — no ETag
            Response(200, b"local"),  # GET (file_url) — SHA-256 fallback in _head()
            Response(201),  # PUT (file_url)
            Response(200, b"local"),  # GET (file_url) — readback verify
            Response(200, headers={"ETag": '"forced"'}),  # HEAD (file_url) — final etag
        ]
    )
    assert client.upload_overwrite(b"local") == '"forced"'


def test_webdav_download_if_exists_returns_none_for_missing_file():
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/vault.pmv", create_directories=False))
    client._opener = Opener([404])
    assert client.download_if_exists() is None


def test_cloud_drive_settings_are_isolated_and_removable(tmp_path, monkeypatch):
    from core import config as cfg

    monkeypatch.setattr(cfg, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(cfg, "_config_cache", None)
    target = tmp_path / "OneDrive" / "vault.pmv"
    save_cloud_drive("vault-a", target)
    save_cloud_drive_sync("vault-a", revision="abc123", logical_revision="logical123")
    assert load_cloud_drive("vault-a") == target.resolve()
    assert load_cloud_drive_revision("vault-a") == "abc123"
    assert load_cloud_drive_logical_revision("vault-a") == "logical123"
    assert load_cloud_drive("vault-b") is None
    clear_cloud_drive("vault-a")
    assert load_cloud_drive("vault-a") is None


def test_cloud_drive_legacy_file_migrates_into_config(tmp_path, monkeypatch):
    from core import config as cfg

    monkeypatch.setattr(cfg, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(cfg, "_config_cache", None)
    monkeypatch.setattr("core.cloud.vault_dir", lambda: tmp_path)
    digest = hashlib.sha256("vault-a".encode("utf-8")).hexdigest()[:24]
    legacy = tmp_path / f"cloud-drive-{digest}.json"
    legacy.write_text(
        json.dumps(
            {
                "path": str(tmp_path / "OneDrive" / "vault.pmv"),
                "revision": "abc123",
                "logical_revision": "logical123",
            }
        ),
        encoding="utf-8",
    )

    assert load_cloud_drive("vault-a") == (tmp_path / "OneDrive" / "vault.pmv").resolve()
    assert load_cloud_drive_revision("vault-a") == "abc123"
    assert load_cloud_drive_logical_revision("vault-a") == "logical123"
    # 旧独立文件已迁移进配置文件并被移除
    assert not legacy.exists()
    assert (tmp_path / "config.json").exists()


def test_cloud_drive_old_conflated_config_migrates_into_split_keys(tmp_path, monkeypatch):
    """旧版把 path/revision/logical_revision 混在一个 config 键里，读取时自动拆分迁移。"""
    from core import cloud as cloud_mod
    from core import config as cfg

    monkeypatch.setattr(cfg, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(cfg, "_config_cache", None)
    monkeypatch.setattr("core.cloud.vault_dir", lambda: tmp_path)
    digest = cloud_mod._vault_digest("vault-a")
    target = tmp_path / "OneDrive" / "vault.pmv"
    cfg.set(
        f"cloud_drive_{digest}",
        {"path": str(target), "revision": "r-old", "logical_revision": "l-old"},
    )

    assert load_cloud_drive("vault-a") == target.resolve()
    assert load_cloud_drive_revision("vault-a") == "r-old"
    assert load_cloud_drive_logical_revision("vault-a") == "l-old"
    # 迁移后关联键只含 path，同步元数据已写入独立键
    migrated = cfg.get(f"cloud_drive_{digest}")
    assert migrated == {"path": str(target.resolve())}
    assert cfg.get(f"cloud_drive_sync_{digest}") == {"revision": "r-old", "logical_revision": "l-old"}
    # 再次读取不重复迁移
    assert load_cloud_drive_revision("vault-a") == "r-old"


def test_webdav_settings_roundtrip_in_config(tmp_path, monkeypatch):
    from core import config as cfg

    monkeypatch.setattr(cfg, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(cfg, "_config_cache", None)
    saved = WebDavConfig("NAS", "https://nas.example/vault.pmv", username="user", password="secret")
    vault_uuid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    root_key = bytes(range(32))
    save_webdav("vault-a", saved, vault_uuid=vault_uuid, root_key=root_key)
    assert load_webdav("vault-a", vault_uuid=vault_uuid, root_key=root_key) == saved
    # 凭据存放在配置文件里，而不是散落的独立文件
    assert (tmp_path / "config.json").exists()
    persisted = (tmp_path / "config.json").read_text(encoding="utf-8")
    assert "secret" not in persisted
    assert '"username": "user"' not in persisted
    clear_webdav("vault-a")
    assert load_webdav("vault-a", vault_uuid=vault_uuid, root_key=root_key) is None


def test_logical_vault_revision_ignores_entry_and_tag_order():
    first = [
        {"id": "b", "title": "B", "tags": ["two", "one"]},
        {"id": "a", "title": "A", "tags": []},
    ]
    second = [
        {"id": "a", "title": "A", "tags": []},
        {"id": "b", "title": "B", "tags": ["one", "two"]},
    ]
    assert logical_vault_revision(first, "vault", {"x": 1.0}) == logical_vault_revision(
        second,
        "vault",
        {"x": 1.0},
    )


def test_logical_vault_revision_covers_content_and_purge_log():
    base = [{"id": "a", "title": "A", "updated_at": 100.0}]
    changed = [{"id": "a", "title": "B", "updated_at": 100.0}]
    revision = logical_vault_revision(base, "vault", {})

    assert logical_vault_revision(changed, "vault", {}) != revision
    assert logical_vault_revision(base, "vault", {"a": 101.0}) != revision


def test_remote_change_ignores_reencrypted_copy_of_current_logical_vault():
    assert not remote_logical_changed("current", "old-baseline", "current")
    assert remote_logical_changed("remote-edit", "old-baseline", "current")


def test_logical_vault_revision_survives_encrypted_file_round_trip(tmp_path):
    path = tmp_path / "round-trip.pmv"
    vault = Vault.create(path, "master")
    vault.add(Entry(title="Example", username="user", password="secret", tags=["b", "a"]))

    local_revision = logical_vault_revision(
        list(vault.entries) + list(vault.trash),
        vault.device_id,
        vault._purge_tombstones,
    )
    vault.close()
    reopened = Vault.open(path, "master")

    assert (
        logical_vault_revision(
            list(reopened.entries) + list(reopened.trash),
            reopened.device_id,
            reopened._purge_tombstones,
        )
        == local_revision
    )
    reopened.close()


def test_logical_revision_is_stable_after_pmve_reopen(tmp_path):
    path = tmp_path / "reopened.pmv"
    vault = Vault.create(path, "master")
    vault.add(Entry(title="Example", username="user", password="secret"))
    first = logical_vault_revision(
        list(vault.entries) + list(vault.trash),
        vault.device_id,
        vault._purge_tombstones,
    )
    vault.close()
    reopened = Vault.open(path, "master")
    second = logical_vault_revision(
        list(reopened.entries) + list(reopened.trash),
        reopened.device_id,
        reopened._purge_tombstones,
    )
    reopened.close()
    assert second == first


def test_headless_drive_sync_matches_android_without_etag_cas(tmp_path):
    local_path = tmp_path / "local.pmv"
    remote_path = tmp_path / "remote.pmv"
    vault = Vault.create(local_path, "master")
    vault.add(Entry(title="First", username="one", password="secret"))
    remote_path.write_bytes(local_path.read_bytes())
    vault.add(Entry(title="Second", username="two", password="secret"))
    vault.close()

    result = sync_drive(local_path, "master", remote_path)

    assert result.uploaded is True
    remote = Vault.open(remote_path, "master")
    try:
        assert {entry.title for entry in remote.entries} == {"First", "Second"}
    finally:
        remote.close()


def test_auto_sync_due_supports_daily_and_weekly_intervals():
    day = 1_440
    week = 10_080
    started = 1_000.0

    assert not is_due(started, 0.0, day, started + day * 60 - 1)
    assert is_due(started, 0.0, day, started + day * 60)
    assert not is_due(started, 0.0, week, started + week * 60 - 1)
    assert is_due(started, 0.0, week, started + week * 60)


def test_cloud_drive_sync_detects_concurrent_change(tmp_path):
    target = tmp_path / "vault.pmv"
    target.write_bytes(b"remote-old")
    expected = read_cloud_drive(target)
    assert expected is not None
    target.write_bytes(b"remote-new")
    with pytest.raises(CloudConflict):
        write_cloud_drive(target, b"local", expected=expected)
    assert target.read_bytes() == b"remote-new"


def test_cloud_drive_missing_file_creation_is_conditional(tmp_path):
    target = tmp_path / "vault.pmv"
    missing = RemoteSnapshot(b"", None, exists=False)
    write_cloud_drive(target, b"first", expected=missing)
    assert target.read_bytes() == b"first"
    with pytest.raises(CloudConflict):
        write_cloud_drive(target, b"second", expected=missing)


def test_cloud_drive_force_overwrite_and_readback(tmp_path):
    target = tmp_path / "vault.pmv"
    target.write_bytes(b"remote")
    write_cloud_drive(target, b"local", force=True)
    snapshot = read_cloud_drive(target)
    assert snapshot is not None
    assert snapshot.data == b"local"


class _FakeWebDavTransport:
    """In-process WebDAV stand-in that records what the client published."""

    def __init__(self, *, strong_etag: bool = True):
        self.files: dict[str, bytes] = {}
        self.strong_etag = strong_etag
        self.puts: list[bytes] = []

    def etag(self, key: str) -> str:
        digest = hashlib.md5(self.files[key]).hexdigest()  # noqa: S324 - test double only
        return f'"{digest}"' if self.strong_etag else f'W/"{digest}"'

    def request(self, method, url, headers=None, data=None):
        headers = headers or {}
        key = url.split("://", 1)[-1].split("/", 1)[-1]
        if method in {"HEAD", "GET"}:
            if key not in self.files:
                raise CloudError("服务器返回 HTTP 404")
            body = self.files[key]
            response_headers = {
                "Content-Length": str(len(body)),
                "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
            }
            if self.strong_etag:
                response_headers["ETag"] = self.etag(key)
            if method == "HEAD":
                return 200, response_headers, b""
            if "Range" in headers:
                return 206, {**response_headers, "Content-Range": f"bytes 0-0/{len(body)}"}, body[:1]
            return 200, response_headers, body
        if method == "PUT":
            if "If-Match" in headers and headers["If-Match"] != self.etag(key):
                raise CloudConflict("云端文件已被其他设备更新或锁定")
            if "If-None-Match" in headers and key in self.files:
                raise CloudConflict("云端文件已被其他设备更新或锁定")
            payload = data if isinstance(data, bytes) else data.read()
            self.files[key] = payload
            self.puts.append(payload)
            return 201, {}, b""
        return 405, {}, b""


def _install_fake_transport(client, transport):
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
        status, response_headers, body = transport.request(
            method, (url or client.config.file_url).strip(), headers, data
        )
        return status, response_headers, _Body(body)

    client._request = request
    return client


def _weak_etag_client(transport):
    client = WebDavClient(WebDavConfig("NAS", "https://nas.example/dav/vault.pmv", auth_mode="none"))
    return _install_fake_transport(client, transport)


def test_download_to_records_remote_witness_hash_for_weak_etag_servers(tmp_path):
    transport = _FakeWebDavTransport(strong_etag=False)
    transport.files["dav/vault.pmv"] = b"PMVS-remote-copy"
    client = _weak_etag_client(transport)

    snapshot = client.download_to(tmp_path / "downloaded.pmv")

    assert snapshot.revision.startswith("sha256:")
    assert snapshot.witness_sha256 == hashlib.sha256(b"PMVS-remote-copy").digest()


def test_weak_etag_upload_accepts_merged_file_using_the_download_time_witness(tmp_path):
    """合并流程会原地改写 expected.path；内容闸门必须仍比对下载时的远端副本。"""
    transport = _FakeWebDavTransport(strong_etag=False)
    transport.files["dav/vault.pmv"] = b"PMVS-remote-copy"
    client = _weak_etag_client(transport)

    witness_path = tmp_path / "downloaded.pmv"
    snapshot = client.download_to(witness_path)
    merged = b"PMVS-merged-copy"
    witness_path.write_bytes(merged)  # merge_and_adopt 原地改写同一个暂存文件
    source = tmp_path / "merged.pmv"
    source.write_bytes(merged)

    revision = client.upload_file_if_unchanged(source, snapshot)

    assert transport.files["dav/vault.pmv"] == merged
    assert revision is None  # 服务器只给弱 ETag，客户端不伪造强版本号


def test_weak_etag_upload_still_rejects_a_genuinely_changed_remote(tmp_path):
    transport = _FakeWebDavTransport(strong_etag=False)
    transport.files["dav/vault.pmv"] = b"PMVS-remote-copy"
    client = _weak_etag_client(transport)

    snapshot = client.download_to(tmp_path / "downloaded.pmv")
    transport.files["dav/vault.pmv"] = b"PMVS-someone-else"  # 另一台设备改写了远端
    source = tmp_path / "merged.pmv"
    source.write_bytes(b"PMVS-merged-copy")

    with pytest.raises(CloudConflict):
        client.upload_file_if_unchanged(source, snapshot)
    assert transport.files["dav/vault.pmv"] == b"PMVS-someone-else"


def test_upload_without_expected_is_rejected_unless_forced(tmp_path):
    transport = _FakeWebDavTransport(strong_etag=False)
    client = _weak_etag_client(transport)
    source = tmp_path / "local.pmv"
    source.write_bytes(b"PMVS-local")

    with pytest.raises(CloudError, match="远端版本信息"):
        client.upload_file_if_unchanged(source, None)
    assert transport.puts == []


def test_forced_upload_skips_every_cas_gate(tmp_path):
    transport = _FakeWebDavTransport(strong_etag=False)
    transport.files["dav/vault.pmv"] = b"PMVS-remote-copy"
    client = _weak_etag_client(transport)
    source = tmp_path / "local.pmv"
    source.write_bytes(b"PMVS-local")

    client.upload_file_if_unchanged(source, None, force=True)

    assert transport.files["dav/vault.pmv"] == b"PMVS-local"


def test_cloud_module_exposes_the_limit_the_upload_workers_guard_on():
    """cloud_sync_controller 的 push_file/overwrite_file 分支按这个常量设闸门。"""
    assert cloud.MAX_CLOUD_VAULT_BYTES == 1024**3
