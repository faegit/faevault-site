"""Hardened WebDAV transport and DPAPI-protected per-vault settings."""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import io
import json
import os
import shutil
import ssl
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from . import config
from .cloud_credential_crypto import open_field, seal_field
from .pmv_key_schedule import derive_cloud_credential_key, derive_root_keys
from .storage import MAX_VAULT_BYTES, vault_dir

MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
# Cross-platform cloud contract: Android's SAF and WebDAV implementations both
# cap a remote PMVE vault at 1 GiB.  Keep desktop cloud transport at the same
# boundary so it can never publish a database that Android will reject.
MAX_CLOUD_VAULT_BYTES = MAX_VAULT_BYTES
RETRY_CODES = {408, 429, 500, 502, 503, 504}


class CloudError(RuntimeError):
    pass


class CloudConflict(CloudError):
    pass


@dataclass(frozen=True, slots=True)
class RemoteSnapshot:
    data: bytes
    revision: str | None
    exists: bool = True
    modified_at: float = 0.0


@dataclass(frozen=True, slots=True)
class RemoteFileSnapshot:
    path: Path
    revision: str | None
    exists: bool = True
    modified_at: float = 0.0
    size: int = -1
    #: 下载当时远端内容的 SHA-256。弱 ETag 服务器的并发保护需要比对「远端副本」，
    #: 而 ``path`` 可能被合并流程原地改写，因此单独留存哈希。
    witness_sha256: bytes | None = None


@dataclass(frozen=True, slots=True)
class RemoteMetadata:
    exists: bool
    size: int = -1
    modified_at: float = 0.0
    revision: str | None = None



@dataclass(slots=True)
class WebDavConfig:
    label: str
    file_url: str
    username: str = ""
    password: str = ""
    auth_mode: str = "basic"
    bearer_token: str = ""
    certificate_sha256: str = ""
    create_directories: bool = False
    cookie: str = ""
    client_certificate: str = ""
    client_certificate_password: str = ""
    domain: str = ""

    def validate(self) -> None:
        parsed = urllib.parse.urlparse(self.file_url.strip())
        if parsed.scheme != "https" or not parsed.netloc:
            raise CloudError("云端同步地址必须是有效的 HTTPS URL")
        if parsed.path.endswith("/") or not Path(parsed.path).name:
            raise CloudError("地址必须包含远端 .pmv 文件名")
        if not is_sync_candidate_name(Path(parsed.path).name):
            raise CloudError("远端同步文件必须是正式的 .pmv 保险库文件，不能使用备份/临时/迁移工件")
        if self.auth_mode not in {"none", "basic", "digest", "bearer", "oauth2", "cookie", "mtls", "ntlm", "kerberos"}:
            raise CloudError("不支持的认证方式")
        if self.auth_mode == "basic" and bool(self.username.strip()) != bool(self.password):
            raise CloudError("Basic 认证的用户名和密码必须同时填写")
        if self.auth_mode in {"digest", "ntlm"} and not self.username.strip():
            raise CloudError("当前认证方式需要用户名")
        if self.auth_mode in {"digest", "ntlm"} and not self.password:
            raise CloudError("当前认证方式需要密码")
        if self.auth_mode in {"bearer", "oauth2"} and not self.bearer_token.strip():
            raise CloudError("当前认证方式需要访问令牌")
        if "\r" in self.bearer_token or "\n" in self.bearer_token:
            raise CloudError("访问令牌不能包含换行符")
        if self.auth_mode == "cookie" and not self.cookie.strip():
            raise CloudError("Cookie / Session 认证需要 Cookie")
        if "\r" in self.cookie or "\n" in self.cookie:
            raise CloudError("Cookie 不能包含换行符")
        if self.auth_mode == "mtls" and not self.client_certificate.strip():
            raise CloudError("客户端证书认证需要 PKCS#12 证书")
        if self.auth_mode in {"bearer", "oauth2", "cookie", "mtls", "ntlm", "kerberos"} and parsed.scheme != "https":
            raise CloudError("此认证方式只允许使用 HTTPS")
        if self.certificate_sha256 and parsed.scheme != "https":
            raise CloudError("证书指纹仅适用于 HTTPS")
        fingerprint = "".join(ch for ch in self.certificate_sha256.lower() if ch.isalnum())
        if fingerprint and (len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint)):
            raise CloudError("证书 SHA-256 指纹必须是 64 位十六进制")


def is_sync_candidate_name(name: str) -> bool:
    """Reject helper/temp migration artifacts before they can be treated as real vault uploads."""
    basename = Path(name).name.strip()
    if not basename:
        return False
    lowered = basename.lower()
    if not lowered.endswith(".pmv"):
        return False
    banned_tokens = (
        ".pmv.bak",
        ".pmv.tmp",
        ".bak",
        ".tmp",
        "pre-migration",
        "pre_migration",
        "migration-backup",
        "migration_backup",
        "backup-archive",
        "backup_archive",
    )
    if any(token in lowered for token in banned_tokens):
        return False
    if "backup" in lowered and lowered != "backup.pmv":
        return False
    return True


def is_sync_candidate_path(path: str | os.PathLike[str]) -> bool:
    return is_sync_candidate_name(str(path))


def directory_url(file_url: str) -> str:
    parsed = urllib.parse.urlparse(file_url.strip())
    path = parsed.path.rstrip("/")
    dir_path = path[: path.rfind("/")] + "/" if "/" in path else "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, dir_path, parsed.params, None, None))


def config_for_directory(config: WebDavConfig, account_name: str) -> WebDavConfig:
    safe = account_name.strip()
    for ch in '\\/:*?"<>|':
        safe = safe.replace(ch, "_")
    safe = safe.strip(". ")[:80] or "vault"
    # 命名统一：云端文件 = <账户名>.pmv，不再加 vault_ 前缀。
    file_name = f"{safe}.pmv"
    if not is_sync_candidate_name(file_name):
        raise CloudError("云端同步文件名不能是迁移备份或临时文件，必须使用正式的 .pmv 保险库名")
    parsed = urllib.parse.urlparse(config.file_url.strip())
    if parsed.query or parsed.fragment:
        raise CloudError("目录地址不能包含查询参数或片段")
    path = parsed.path.rstrip("/") + "/" + file_name
    file_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, None, None))
    result = replace(config, file_url=file_url)
    result.validate()
    return result


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if old.hostname != new.hostname or (old.scheme == "https" and new.scheme != "https"):
            raise CloudError("拒绝携带凭据跳转到其他主机或降级到 HTTP")
        if code not in {301, 302, 307, 308}:
            return None
        forwarded = {key: value for key, value in req.headers.items() if key.lower() not in {"host", "content-length"}}
        return urllib.request.Request(newurl, data=req.data, headers=forwarded, method=req.get_method())


class _RequestsResponse:
    def __init__(self, response):
        self._response = response
        self.status = response.status_code
        self.headers = response.headers

    def read(self, size: int = -1) -> bytes:
        return self._response.raw.read(size, decode_content=True)

    def close(self) -> None:
        self._response.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
        return False


class WebDavClient:
    def __init__(self, config: WebDavConfig, *, timeout: float = 45.0):
        config.validate()
        self.config = config
        self.timeout = timeout
        self._opener = self._build_opener()

    def test(self) -> None:
        if self.config.create_directories:
            self._ensure_directories()
        _, headers, _ = self._request("OPTIONS", retry=True)
        allow = {item.strip().upper() for item in headers.get("Allow", "").split(",")}
        if not headers.get("DAV") and "PUT" not in allow:
            self._probe_write()
        self._head(self.config.file_url, allow_missing=True)

    def upload(self, data: bytes) -> str | None:
        return self._upload(data)

    def upload_if_unchanged(self, data: bytes, expected: RemoteSnapshot) -> str | None:
        return self._upload(data, expected=expected)

    def upload_overwrite(self, data: bytes) -> str | None:
        return self._upload(data, force=True)

    def _upload(self, data: bytes, *, expected: RemoteSnapshot | None = None, force: bool = False) -> str | None:
        if data[:4] == b"PMVS":
            raise CloudError("PMVE WebDAV 是 file-only，禁止 bytes RemoteSnapshot 上传")
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise CloudError("本地保险库超过 128 MB 安全限制")
        if self.config.create_directories:
            self._ensure_directories()
        initial_etag = self._head(self.config.file_url, allow_missing=True)
        if expected is not None:
            if not expected.exists:
                if initial_etag is not None:
                    raise CloudConflict("云端文件已被其他设备创建，请重新同步")
            elif expected.revision is not None:
                if initial_etag != expected.revision:
                    raise CloudConflict("云端文件已被其他设备更新，请重新同步")
            else:
                current = self.download()
                if not hmac.compare_digest(hashlib.sha256(current).digest(), hashlib.sha256(expected.data).digest()):
                    raise CloudConflict("云端文件已被其他设备更新，请重新同步")
        self._put(
            self.config.file_url,
            data,
            etag=None if force else initial_etag,
            require_missing=not force and initial_etag is None,
        )
        downloaded, _ = self._download(self.config.file_url)
        if not hmac.compare_digest(hashlib.sha256(downloaded).digest(), hashlib.sha256(data).digest()):
            raise CloudError("云端文件读回校验失败")
        return self._head(self.config.file_url, allow_missing=False)

    def download(self) -> bytes:
        data = self._download(self.config.file_url)[0]
        if data[:4] == b"PMVS":
            raise CloudError("PMVE WebDAV 是 file-only，请使用 download_to")
        return data

    def download_snapshot(self) -> RemoteSnapshot:
        data, etag = self._download(self.config.file_url)
        if data[:4] == b"PMVS":
            raise CloudError("PMVE WebDAV 是 file-only，禁止 bytes RemoteSnapshot")
        metadata = self.metadata()
        return RemoteSnapshot(data, etag, modified_at=metadata.modified_at)

    def download_if_exists(self) -> RemoteSnapshot | None:
        try:
            return self.download_snapshot()
        except CloudError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise

    def download_to(self, target: str | Path) -> RemoteFileSnapshot:
        return self._download_to(self.config.file_url, Path(target))

    def download_to_if_exists(self, target: str | Path) -> RemoteFileSnapshot | None:
        try:
            return self.download_to(target)
        except CloudError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise

    def upload_file_if_unchanged(
        self,
        source: str | Path,
        expected: RemoteFileSnapshot | None,
        *,
        force: bool = False,
    ) -> str | None:
        """Stream the database once to its final URL with HTTP CAS protection.

        ``force=True`` 用于用户显式「上传覆盖」：跳过全部 CAS 闸门，无条件发布。
        ``expected`` 只在 ``expected.witness_sha256`` 提供时才用于弱 ETag 的
        内容闸门——合并流程会原地改写 ``expected.path``，那时它已不再是远端副本。
        """

        source_path = Path(source)
        if not source_path.is_file() or source_path.stat().st_size > MAX_CLOUD_VAULT_BYTES:
            raise CloudError("本地保险库缺失或超过 1 GB 安全限制")
        if self.config.create_directories:
            self._ensure_directories()
        if force:
            self._put_file(self.config.file_url, source_path)
            return self.metadata(verify_size=True).revision
        if expected is None:
            raise CloudError("云端同步缺少远端版本信息，已中止上传")
        current = self.metadata(verify_size=True)
        if expected.exists != current.exists:
            raise CloudConflict("云端文件存在状态已变化，请重新同步")
        if expected.exists:
            if not _is_http_etag(expected.revision or "") and expected.size < 0 and expected.modified_at <= 0:
                raise CloudConflict("云端未提供可用于并发保护的版本信息（强 ETag 或文件大小/修改时间）")
            if not self._same_version(expected, current):
                raise CloudConflict("云端文件已被其他设备更新，请重新同步")
            if not _is_http_etag(expected.revision or ""):
                # Size/mtime can be stale or coarse on WebDAV.  Android
                # authenticates a fresh remote copy before a weak-version
                # overwrite; desktop performs an equivalent exact-content
                # check against the authenticated snapshot it downloaded.
                # ``witness_sha256`` 优先：合并流程会原地改写 ``expected.path``，
                # 此时只有下载时记录的哈希仍然代表真正的远端内容。
                witness = expected.witness_sha256
                if witness is None:
                    if not expected.path.is_file():
                        raise CloudConflict("云端文件已被其他设备更新，请重新同步")
                    witness = _file_sha256(expected.path)
                if not self._remote_file_matches(self.config.file_url, expected.size, witness):
                    raise CloudConflict("云端文件已被其他设备更新，请重新同步")

        self._put_file(
            self.config.file_url,
            source_path,
            etag=expected.revision if _is_http_etag(expected.revision or "") else None,
            require_missing=not expected.exists,
            unmodified_since=(expected.modified_at if expected.exists and not _is_http_etag(expected.revision or "") and expected.modified_at > 0 else None),
        )
        return self.metadata(verify_size=True).revision

    @staticmethod
    def _same_version(expected: RemoteFileSnapshot, current: RemoteMetadata) -> bool:
        """版本一致性：强 ETag 优先；无强 ETag 时退回 大小+Last-Modified（与安卓一致）。"""
        if _is_http_etag(expected.revision or ""):
            return current.revision == expected.revision
        if expected.size < 0 and expected.modified_at <= 0:
            return False
        size_ok = expected.size >= 0 and current.size == expected.size
        time_ok = expected.modified_at > 0 and current.modified_at == expected.modified_at
        if expected.size >= 0 and expected.modified_at > 0:
            return size_ok and time_ok
        return size_ok or time_ok

    def metadata(self, *, verify_size: bool = False) -> RemoteMetadata:
        def convert(headers) -> RemoteMetadata:
            size_text = headers.get("Content-Range", "").rsplit("/", 1)[-1]
            size = int(size_text) if size_text.isdigit() else int(headers.get("Content-Length", "-1") or -1)
            modified = 0.0
            if headers.get("Last-Modified"):
                parsed = email.utils.parsedate_to_datetime(headers["Last-Modified"])
                modified = parsed.timestamp()
            return RemoteMetadata(True, size, modified, _strong_etag(headers))

        def probe(base: RemoteMetadata | None = None) -> RemoteMetadata:
            base = base or RemoteMetadata(True)
            try:
                status, headers, response = self._request(
                    "GET",
                    url=self.config.file_url,
                    headers={"Range": "bytes=0-0"},
                    retry=True,
                    stream=True,
                )
            except CloudError as exc:
                if "HTTP 404" in str(exc):
                    return RemoteMetadata(False)
                if "HTTP 416" in str(exc):
                    return replace(base, size=0)
                raise
            ranged = convert(headers)
            try:
                size = ranged.size
                if size <= 0:
                    size = -1 if response.read(1) else 0
            finally:
                response.close()
            return RemoteMetadata(
                True,
                size,
                ranged.modified_at or base.modified_at,
                ranged.revision or base.revision,
            )

        try:
            _, headers, response = self._request("HEAD", url=self.config.file_url, retry=True, stream=True)
            response.close()
            metadata = convert(headers)
            return metadata if metadata.size > 0 and not verify_size else probe(metadata)
        except CloudError as exc:
            if "HTTP 404" in str(exc):
                return RemoteMetadata(False)
            if "HTTP 405" not in str(exc) and "HTTP 501" not in str(exc):
                raise
        return probe()

    def _download(self, url: str) -> tuple[bytes, str | None]:
        _, headers, response = self._request("GET", url=url, retry=True, stream=True)
        declared = int(headers.get("Content-Length", "0") or 0)
        if declared > MAX_DOWNLOAD_BYTES:
            response.close()
            raise CloudError("云端文件超过 128 MB 安全限制")
        output = io.BytesIO()
        total = 0
        try:
            while chunk := response.read(32 * 1024):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise CloudError("云端文件超过 128 MB 安全限制")
                output.write(chunk)
        finally:
            response.close()
        return output.getvalue(), _strong_etag(headers)

    def _download_to(self, url: str, target: Path) -> RemoteFileSnapshot:
        _, headers, response = self._request("GET", url=url, retry=True, stream=True)
        declared = int(headers.get("Content-Length", "0") or 0)
        if declared > MAX_CLOUD_VAULT_BYTES:
            response.close()
            raise CloudError("云端 PMVE 文件超过 1 GB 安全限制")
        digest = hashlib.sha256()
        total = 0
        try:
            with target.open("wb") as output:
                while chunk := response.read(64 * 1024):
                    total += len(chunk)
                    if total > MAX_CLOUD_VAULT_BYTES:
                        raise CloudError("云端 PMVE 文件超过 1 GB 安全限制")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
        except Exception:
            target.unlink(missing_ok=True)
            raise
        finally:
            response.close()
        if declared and declared != total:
            target.unlink(missing_ok=True)
            raise CloudError("云端 PMVE 文件下载不完整")
        modified = 0.0
        if headers.get("Last-Modified"):
            modified = email.utils.parsedate_to_datetime(headers["Last-Modified"]).timestamp()
        revision = _strong_etag(headers) or "sha256:" + digest.hexdigest()
        # 无强 ETag 时 revision 是 "sha256:<hex>"，仍不足以区分「远端被他人改动」
        # 与「合并流程原地改写了同一个暂存文件」，因此单独留存原始字节哈希。
        return RemoteFileSnapshot(target, revision, True, modified, total, digest.digest())

    def _put(self, url: str, data: bytes, *, etag: str | None = None, require_missing: bool = False) -> None:
        headers = {"Content-Type": "application/octet-stream"}
        if etag and _is_http_etag(etag):
            headers["If-Match"] = etag
        if require_missing:
            headers["If-None-Match"] = "*"
        self._request("PUT", url=url, data=data, headers=headers, retry=True)

    def _put_file(
        self,
        url: str,
        source: str | Path,
        *,
        etag: str | None = None,
        require_missing: bool = False,
        unmodified_since: float | None = None,
    ) -> None:
        path = Path(source)
        size = path.stat().st_size
        if size > MAX_CLOUD_VAULT_BYTES:
            raise CloudError("本地 PMVE 文件超过 1 GB 安全限制")
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
        }
        if etag and _is_http_etag(etag):
            headers["If-Match"] = etag
        if require_missing:
            headers["If-None-Match"] = "*"
        if unmodified_since:
            headers["If-Unmodified-Since"] = email.utils.formatdate(unmodified_since, usegmt=True)
        expected_sha256 = _file_sha256(path)
        try:
            with path.open("rb") as stream:
                # 文件 PUT 不可盲目重试：服务器可能已提交，只是响应在途中丢失。
                self._request("PUT", url=url, data=stream, headers=headers)
        except CloudConflict:
            raise
        except CloudError:
            if not self._remote_file_matches(url, size, expected_sha256):
                raise

    def _remote_file_matches(self, url: str, expected_size: int, expected_sha256: bytes) -> bool:
        descriptor, name = tempfile.mkstemp(prefix="vault-cloud-commit-check-", suffix=".pmv")
        os.close(descriptor)
        readback = Path(name)
        try:
            snapshot = self._download_to(url, readback)
            return snapshot.size == expected_size and hmac.compare_digest(_file_sha256(readback), expected_sha256)
        except CloudError:
            return False
        finally:
            readback.unlink(missing_ok=True)

    def _move(self, source: str, destination: str, etag: str | None) -> bool:
        headers = {"Destination": destination, "Overwrite": "T"}
        if etag and _is_http_etag(etag):
            headers["If"] = f"<{destination}> ([{etag}])"
        try:
            self._request("MOVE", url=source, headers=headers)
            return True
        except CloudError as exc:
            if "HTTP 405" in str(exc) or "HTTP 501" in str(exc):
                return False
            if isinstance(exc, CloudConflict):
                return False
            raise

    def _delete(self, url: str) -> None:
        try:
            self._request("DELETE", url=url, retry=True)
        except CloudError as exc:
            if "HTTP 404" not in str(exc):
                raise

    def _probe_write(self) -> None:
        temp = f"{self.config.file_url}.probe-{uuid.uuid4().hex}.tmp"
        try:
            self._put(temp, b"")
        finally:
            try:
                self._delete(temp)
            except Exception:
                pass

    def _head(self, url: str, *, allow_missing: bool) -> str | None:
        try:
            _, headers, _ = self._request("HEAD", url=url, retry=True)
            if _strong_etag(headers):
                return _strong_etag(headers)
            data, _ = self._download(url)
            return "sha256:" + hashlib.sha256(data).hexdigest()
        except CloudError as exc:
            if allow_missing and "HTTP 404" in str(exc):
                return None
            if "HTTP 405" not in str(exc) and "HTTP 501" not in str(exc):
                raise
        try:
            _, headers, response = self._request("GET", url=url, headers={"Range": "bytes=0-0"}, retry=True, stream=True)
            response.close()
            if _strong_etag(headers):
                return _strong_etag(headers)
            data, _ = self._download(url)
            return "sha256:" + hashlib.sha256(data).hexdigest()
        except CloudError as exc:
            if allow_missing and "HTTP 404" in str(exc):
                return None
            raise

    def _ensure_directories(self) -> None:
        parsed = urllib.parse.urlparse(self.config.file_url)
        path = ""
        for segment in [part for part in parsed.path.split("/") if part][:-1]:
            path += "/" + segment
            url = urllib.parse.urlunparse(parsed._replace(path=path + "/", params="", query="", fragment=""))
            try:
                self._request("MKCOL", url=url, retry=True)
            except CloudError as exc:
                if not any(f"HTTP {code}" in str(exc) for code in (301, 302, 405)):
                    raise

    def _request(self, method: str, *, url: str | None = None, data: bytes | None = None, headers=None, retry=False, stream=False):
        target = (url or self.config.file_url).strip()
        request_headers = {"Accept": "application/octet-stream", **(headers or {})}
        if self.config.auth_mode in {"ntlm", "kerberos"}:
            return self._request_sspi(method, target, data, request_headers, retry, stream)
        if self.config.auth_mode in {"bearer", "oauth2"}:
            request_headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        elif self.config.auth_mode == "basic":
            token = base64.b64encode(f"{self.config.username}:{self.config.password}".encode()).decode("ascii")
            request_headers["Authorization"] = f"Basic {token}"
        elif self.config.auth_mode == "cookie":
            request_headers["Cookie"] = self.config.cookie.strip()
        attempts = 3 if retry else 1
        for attempt in range(attempts):
            request = urllib.request.Request(target, data=data, headers=request_headers, method=method)
            try:
                response = self._opener.open(request, timeout=self.timeout)
                self._verify_certificate(response)
                if stream:
                    return response.status, response.headers, response
                with response:
                    return response.status, response.headers, response.read()
            except urllib.error.HTTPError as exc:
                if exc.code in {409, 412, 423}:
                    raise CloudConflict("云端文件已被其他设备更新或锁定") from exc
                if retry and exc.code in RETRY_CODES and attempt + 1 < attempts:
                    time.sleep(0.5 * (2**attempt))
                    continue
                if exc.code in {401, 403}:
                    raise CloudError("认证失败，请检查认证方式、凭据和访问权限") from exc
                raise CloudError(f"服务器返回 HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                if retry and attempt + 1 < attempts:
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise CloudError(f"无法连接服务器：{exc.reason}") from exc
        raise CloudError("云端请求失败")

    def _request_sspi(self, method, target, data, headers, retry, stream):
        try:
            import requests
            from requests_negotiate_sspi import HttpNegotiateAuth
        except ImportError as exc:
            raise CloudError("当前安装缺少 Windows NTLM/Kerberos 认证组件") from exc
        auth = HttpNegotiateAuth(
            username=self.config.username or None,
            password=self.config.password or None,
            domain=self.config.domain or None,
        )
        attempts = 3 if retry else 1
        for attempt in range(attempts):
            try:
                current = target
                for redirect_count in range(6):
                    response = requests.request(
                        method,
                        current,
                        data=data,
                        headers=headers,
                        auth=auth,
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,
                        verify=True,
                    )
                    if response.status_code not in {301, 302, 307, 308}:
                        break
                    location = response.headers.get("Location", "")
                    next_url = urllib.parse.urljoin(current, location)
                    old, new = urllib.parse.urlparse(current), urllib.parse.urlparse(next_url)
                    response.close()
                    if old.hostname != new.hostname or (old.scheme == "https" and new.scheme != "https"):
                        raise CloudError("拒绝携带凭据跳转到其他主机或降级到 HTTP")
                    current = next_url
                else:
                    raise CloudError("云端重定向次数过多")
                self._verify_requests_certificate(response)
                if response.status_code in {409, 412, 423}:
                    response.close()
                    raise CloudConflict("云端文件已被其他设备更新或锁定")
                if response.status_code in {401, 403}:
                    response.close()
                    raise CloudError("Windows 身份验证失败，请检查域凭据、SPN 和 Kerberos 票据")
                if response.status_code >= 400:
                    code = response.status_code
                    response.close()
                    if retry and code in RETRY_CODES and attempt + 1 < attempts:
                        time.sleep(0.5 * (2**attempt))
                        continue
                    raise CloudError(f"服务器返回 HTTP {code}")
                adapter = _RequestsResponse(response)
                if stream:
                    return response.status_code, response.headers, adapter
                with adapter:
                    return response.status_code, response.headers, adapter.read()
            except CloudError:
                raise
            except requests.RequestException as exc:
                if retry and attempt + 1 < attempts:
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise CloudError(f"无法连接服务器：{exc}") from exc
        raise CloudError("云端请求失败")

    def _verify_requests_certificate(self, response) -> None:
        expected = "".join(ch for ch in self.config.certificate_sha256.lower() if ch.isalnum())
        if not expected:
            return
        try:
            sock = response.raw.connection.sock
            actual = hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()
        except Exception as exc:
            response.close()
            raise CloudError("无法读取服务器证书进行指纹校验") from exc
        if not hmac.compare_digest(actual, expected):
            response.close()
            raise CloudError("服务器证书 SHA-256 指纹不匹配")

    def _build_opener(self):
        handlers: list = [_SafeRedirect()]
        if self.config.auth_mode == "digest":
            passwords = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passwords.add_password(None, self.config.file_url, self.config.username, self.config.password)
            handlers.append(urllib.request.HTTPDigestAuthHandler(passwords))
        context = None
        if self.config.certificate_sha256:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.config.auth_mode == "mtls":
            context = context or ssl.create_default_context()
            self._load_client_certificate(context)
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        return urllib.request.build_opener(*handlers)

    def _load_client_certificate(self, context: ssl.SSLContext) -> None:
        try:
            raw = base64.b64decode(self.config.client_certificate, validate=True)
            if len(raw) > 1024 * 1024:
                raise CloudError("客户端证书超过 1 MB 安全限制")
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs12

            key, cert, chain = pkcs12.load_key_and_certificates(
                raw,
                self.config.client_certificate_password.encode() or None,
            )
            if key is None or cert is None:
                raise CloudError("PKCS#12 中缺少客户端私钥或证书")
            cert_pem = cert.public_bytes(serialization.Encoding.PEM) + b"".join(item.public_bytes(serialization.Encoding.PEM) for item in chain or ())
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            cert_file = key_file = None
            try:
                cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
                key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
                cert_file.write(cert_pem)
                cert_file.close()
                key_file.write(key_pem)
                key_file.close()
                context.load_cert_chain(cert_file.name, key_file.name)
            finally:
                for item in (cert_file, key_file):
                    if item is not None:
                        try:
                            os.unlink(item.name)
                        except OSError:
                            pass
        except CloudError:
            raise
        except Exception as exc:
            raise CloudError("无法读取 PKCS#12 客户端证书，请检查文件和密码") from exc

    def _verify_certificate(self, response) -> None:
        expected = "".join(ch for ch in self.config.certificate_sha256.lower() if ch.isalnum())
        if not expected:
            return
        try:
            cert = response.fp.raw._sock.getpeercert(binary_form=True)  # CPython HTTPSResponse socket
        except Exception as exc:
            response.close()
            raise CloudError("无法读取服务器证书进行指纹校验") from exc
        actual = hashlib.sha256(cert).hexdigest()
        if not hmac.compare_digest(actual, expected):
            response.close()
            raise CloudError("服务器证书 SHA-256 指纹不匹配")


def _vault_digest(vault_id: str) -> str:
    return hashlib.sha256(vault_id.encode("utf-8")).hexdigest()[:24]


def _webdav_key(vault_id: str) -> str:
    return f"cloud_webdav_{_vault_digest(vault_id)}"


def _drive_key(vault_id: str) -> str:
    return f"cloud_drive_{_vault_digest(vault_id)}"


def _drive_sync_key(vault_id: str) -> str:
    return f"cloud_drive_sync_{_vault_digest(vault_id)}"


def _config_path(vault_id: str) -> Path:
    """旧版 WebDAV 凭据文件路径（仅用于迁移旧数据）。"""
    return vault_dir() / f"cloud-webdav-{_vault_digest(vault_id)}.dat"


def _is_http_etag(value: str) -> bool:
    # 弱 ETag（W/"…"）不能用于 If-Match，强制并发保护只接受强 ETag。
    return value.startswith('"')


def _strong_etag(headers) -> str | None:
    """优先 Nextcloud 规范 OC-ETag，其次标准 ETag；仅接受强 ETag。"""
    for name in ("OC-ETag", "ETag"):
        value = headers.get(name) or ""
        if value.startswith('"'):
            return value
    return None


def _protect_webdav(webdav_config: WebDavConfig) -> bytes:
    raw = json.dumps(asdict(webdav_config), ensure_ascii=False).encode("utf-8")
    try:
        import win32crypt

        protected = bytes(win32crypt.CryptProtectData(raw, "Vault WebDAV", None, None, None, 0))
    except Exception as exc:
        raise CloudError(f"无法使用 Windows DPAPI 保存云端凭据：{exc}") from exc
    return protected


def _unprotect_webdav(blob: bytes) -> WebDavConfig | None:
    try:
        import win32crypt

        raw = win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
        return WebDavConfig(**json.loads(raw.decode("utf-8")))
    except Exception:
        return None


_WEBDAV_SENSITIVE_FIELDS = (
    "username", "password", "bearer_token", "cookie", "client_certificate",
    "client_certificate_password", "domain",
)


def _cloud_key(vault_uuid: uuid.UUID, root_key: bytes) -> bytes:
    return derive_cloud_credential_key(derive_root_keys(root_key, vault_uuid).key_wrap_key)


def save_webdav(vault_id: str, webdav_config: WebDavConfig, *,
                vault_uuid: uuid.UUID, root_key: bytes) -> None:
    """Persist only vault-bound per-field ciphertext plus non-sensitive metadata."""
    key = bytearray(_cloud_key(vault_uuid, root_key))
    try:
        fields = {
            name: base64.b64encode(seal_field(
                bytes(key), vault_uuid, "webdav", name, 1,
                str(getattr(webdav_config, name)).encode("utf-8"), os.urandom(12),
            )).decode("ascii")
            for name in _WEBDAV_SENSITIVE_FIELDS
        }
        stored = {
            "format_version": 2,
            "metadata": {
                "label": webdav_config.label,
                "file_url": webdav_config.file_url,
                "auth_mode": webdav_config.auth_mode,
                "certificate_sha256": webdav_config.certificate_sha256,
                "create_directories": webdav_config.create_directories,
            },
            "fields": fields,
        }
        config.set(_webdav_key(vault_id), stored)
    finally:
        key[:] = bytes(len(key))
    try:
        _config_path(vault_id).unlink(missing_ok=True)
    except OSError:
        pass


def load_webdav(vault_id: str, *, vault_uuid: uuid.UUID, root_key: bytes) -> WebDavConfig | None:
    stored = config.get(_webdav_key(vault_id))
    if isinstance(stored, dict) and stored.get("format_version") == 2:
        try:
            metadata = stored["metadata"]
            encrypted = stored["fields"]
            key = bytearray(_cloud_key(vault_uuid, root_key))
            try:
                values = {
                    name: open_field(
                        bytes(key), vault_uuid, "webdav", name, 1,
                        base64.b64decode(encrypted[name]),
                    ).decode("utf-8")
                    for name in _WEBDAV_SENSITIVE_FIELDS
                }
            finally:
                key[:] = bytes(len(key))
            return WebDavConfig(**metadata, **values)
        except Exception:
            return None
    # Migrate the former DPAPI blob only while this vault's RootKey is available.
    if isinstance(stored, str) and stored:
        try:
            parsed = _unprotect_webdav(base64.b64decode(stored))
        except Exception:
            parsed = None
        if parsed is not None:
            save_webdav(vault_id, parsed, vault_uuid=vault_uuid, root_key=root_key)
            verified = load_webdav(vault_id, vault_uuid=vault_uuid, root_key=root_key)
            if verified == parsed:
                return verified
            return None
    # 旧版独立凭据文件：读取并迁移进配置文件
    legacy = _config_path(vault_id)
    if legacy.exists():
        parsed = _unprotect_webdav(legacy.read_bytes())
        if parsed is not None:
            save_webdav(vault_id, parsed, vault_uuid=vault_uuid, root_key=root_key)
            return load_webdav(vault_id, vault_uuid=vault_uuid, root_key=root_key)
    return None


def clear_webdav(vault_id: str) -> None:
    config.set(_webdav_key(vault_id), None)
    try:
        _config_path(vault_id).unlink(missing_ok=True)
    except OSError as exc:
        raise CloudError(f"无法清除云端凭据：{exc}") from exc


def _drive_config_path(vault_id: str) -> Path:
    """旧版云盘关联文件路径（仅用于迁移旧数据）。"""
    return vault_dir() / f"cloud-drive-{_vault_digest(vault_id)}.json"


def save_cloud_drive(vault_id: str, path: str | Path) -> None:
    """保存云端硬盘关联（目标文件路径），与同步元数据分离存储。"""
    target = Path(path).expanduser().resolve()
    if not is_sync_candidate_path(target):
        raise CloudError("云端硬盘同步只允许正式的 .pmv 保险库文件，禁止备份/临时/迁移工件")
    config.set(
        _drive_key(vault_id),
        {
            "path": str(target),
        },
    )
    try:
        _drive_config_path(vault_id).unlink(missing_ok=True)
    except OSError:
        pass


def save_cloud_drive_sync(vault_id: str, *, revision: str | None = None, logical_revision: str | None = None) -> None:
    """保存云端硬盘同步元数据（远端修订号 / 逻辑修订号），与关联分离。"""
    config.set(
        _drive_sync_key(vault_id),
        {
            "revision": revision or "",
            "logical_revision": logical_revision or "",
        },
    )


def _drive_record(vault_id: str) -> dict | None:
    """返回当前关联记录；兼容并迁移旧版独立文件与旧版混存格式。"""
    value = config.get(_drive_key(vault_id))
    if isinstance(value, dict) and value.get("path"):
        # 旧版把 path/revision/logical_revision 混在一个记录里：拆分迁移。
        if value.get("revision") or value.get("logical_revision"):
            save_cloud_drive(vault_id, value["path"])
            save_cloud_drive_sync(
                vault_id,
                revision=value.get("revision") or None,
                logical_revision=value.get("logical_revision") or None,
            )
            return config.get(_drive_key(vault_id))
        return value
    # 旧版独立关联文件：读取并迁移进配置文件
    legacy = _drive_config_path(vault_id)
    if legacy.exists():
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, AttributeError):
            return None
        if isinstance(data, dict) and data.get("path"):
            save_cloud_drive(vault_id, data["path"])
            save_cloud_drive_sync(
                vault_id,
                revision=data.get("revision") or None,
                logical_revision=data.get("logical_revision") or None,
            )
            return config.get(_drive_key(vault_id))
    return None


def _drive_sync_record(vault_id: str) -> dict | None:
    record = _drive_record(vault_id)
    if record is None:
        return None
    value = config.get(_drive_sync_key(vault_id))
    return value if isinstance(value, dict) else None


def load_cloud_drive(vault_id: str) -> Path | None:
    record = _drive_record(vault_id)
    value = record.get("path", "") if record else ""
    return Path(value) if value else None


def load_cloud_drive_revision(vault_id: str) -> str | None:
    record = _drive_sync_record(vault_id)
    value = record.get("revision", "") if record else ""
    return str(value) or None


def load_cloud_drive_logical_revision(vault_id: str) -> str | None:
    record = _drive_sync_record(vault_id)
    value = record.get("logical_revision", "") if record else ""
    return str(value) or None


def logical_vault_revision(entries, device_id: str, purge_tombstones: dict[str, float]) -> str:
    """Hash decrypted logical state; stable across re-encryption and entry ordering."""
    normalized_entries = []
    for entry in entries:
        value = entry.to_dict() if hasattr(entry, "to_dict") else dict(entry)
        value = dict(value)
        # Derived index-only metadata is present on LazyEntry but is recomputed
        # when the same encrypted record is decoded into a regular Entry.
        value.pop("display_secret", None)
        if isinstance(value.get("tags"), list):
            value["tags"] = sorted(str(tag) for tag in value["tags"])
        normalized_entries.append(value)
    normalized_entries.sort(key=lambda value: str(value.get("id", "")))
    canonical = json.dumps(
        {
            "device_id": str(device_id or ""),
            "entries": normalized_entries,
            "purge_tombstones": {str(k): float(v) for k, v in purge_tombstones.items()},
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def remote_logical_changed(
    remote_revision: str | None,
    saved_revision: str | None,
    current_revision: str | None,
) -> bool:
    """Report a meaningful remote change, ignoring byte-only re-encryption changes."""
    if not remote_revision or not saved_revision:
        return False
    return remote_revision != saved_revision and remote_revision != current_revision


def clear_cloud_drive(vault_id: str) -> None:
    config.set(_drive_key(vault_id), None)
    config.set(_drive_sync_key(vault_id), None)
    try:
        _drive_config_path(vault_id).unlink(missing_ok=True)
    except OSError as exc:
        raise CloudError(f"无法清除云端硬盘关联：{exc}") from exc


def read_cloud_drive(path: str | Path, *, allow_missing: bool = False) -> RemoteSnapshot | None:
    target = Path(path)
    try:
        size = target.stat().st_size
    except FileNotFoundError:
        if allow_missing:
            return None
        raise CloudError("关联的云端文件不存在，请重新关联") from None
    except OSError as exc:
        raise CloudError(f"无法访问云端文件：{exc}") from exc
    if not target.is_file():
        raise CloudError("关联路径不是文件")
    with target.open("rb") as stream:
        if stream.read(4) == b"PMVS":
            raise CloudError("PMVE 云端硬盘同步是 file-only，禁止 bytes RemoteSnapshot")
    if size > MAX_DOWNLOAD_BYTES:
        raise CloudError("云端文件超过 128 MB 安全限制")
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise CloudError(f"无法读取云端文件：{exc}") from exc
    return RemoteSnapshot(data, hashlib.sha256(data).hexdigest(), modified_at=target.stat().st_mtime)


def read_cloud_drive_to(
    path: str | Path,
    target: str | Path,
    *,
    allow_missing: bool = False,
) -> RemoteFileSnapshot | None:
    source = Path(path)
    destination = Path(target)
    try:
        before = source.stat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise CloudError("关联的云端文件不存在，请重新关联") from None
    except OSError as exc:
        raise CloudError(f"无法访问云端文件：{exc}") from exc
    if not source.is_file() or before.st_size > MAX_CLOUD_VAULT_BYTES:
        raise CloudError("关联路径不是文件或超过 1 GB 安全限制")
    digest = hashlib.sha256()
    try:
        with source.open("rb") as input_stream, destination.open("wb") as output:
            while part := input_stream.read(64 * 1024):
                output.write(part)
                digest.update(part)
            output.flush()
            os.fsync(output.fileno())
        after = source.stat()
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        destination.unlink(missing_ok=True)
        raise CloudConflict("云端文件在下载期间发生变化，请重新同步")
    return RemoteFileSnapshot(
        destination,
        digest.hexdigest(),
        True,
        after.st_mtime,
        after.st_size,
        digest.digest(),
    )


def cloud_drive_metadata(path: str | Path) -> RemoteMetadata:
    target = Path(path)
    try:
        stat = target.stat()
    except FileNotFoundError:
        return RemoteMetadata(False)
    except OSError as exc:
        raise CloudError(f"无法访问云端文件：{exc}") from exc
    if not target.is_file():
        raise CloudError("关联路径不是文件")
    return RemoteMetadata(True, stat.st_size, stat.st_mtime)


def write_cloud_drive(
    path: str | Path,
    data: bytes,
    *,
    expected: RemoteSnapshot | None = None,
    force: bool = False,
) -> None:
    if data[:4] == b"PMVS":
        raise CloudError("PMVE 云端硬盘同步是 file-only，禁止 bytes RemoteSnapshot")
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise CloudError("本地保险库超过 128 MB 安全限制")
    target = Path(path)
    if not target.parent.is_dir():
        raise CloudError("云端文件所在目录不存在")
    if not force and expected is not None:
        current = read_cloud_drive(target, allow_missing=True)
        changed = (
            (not expected.exists and current is not None)
            or (expected.exists and current is None)
            or (expected.exists and current is not None and not hmac.compare_digest(current.revision or "", expected.revision or ""))
        )
        if changed:
            raise CloudConflict("云端文件已被其他设备更新，请重新同步")
    temporary = target.with_name(f".{target.name}.upload-{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(3):
            try:
                os.replace(temporary, target)
                break
            except PermissionError as exc:
                if attempt == 2:
                    raise CloudError("云端文件正被其他程序占用，请稍后重试") from exc
                time.sleep(0.2 * (attempt + 1))
        verified = read_cloud_drive(target)
        if verified is None or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), verified.revision or ""):
            raise CloudError("云端文件写入后读回校验失败")
    finally:
        temporary.unlink(missing_ok=True)


def write_cloud_drive_file(
    path: str | Path,
    source: str | Path,
    *,
    expected: RemoteFileSnapshot,
    force: bool = False,
) -> str:
    target = Path(path)
    source_path = Path(source)
    if not is_sync_candidate_path(target):
        raise CloudError("云端硬盘同步只允许正式的 .pmv 保险库文件，禁止备份/临时/迁移工件")
    if not source_path.is_file() or source_path.stat().st_size > MAX_CLOUD_VAULT_BYTES:
        raise CloudError("本地保险库缺失或超过 1 GB 安全限制")
    if not target.parent.is_dir():
        raise CloudError("云端文件所在目录不存在")
    current_revision = _file_sha256(target).hex() if target.is_file() else None
    if not force and (expected.exists != target.is_file() or (expected.exists and current_revision != expected.revision)):
        raise CloudConflict("云端文件已被其他设备更新，请重新同步")
    temporary = target.with_name(f".{target.name}.upload-{uuid.uuid4().hex}.tmp")
    try:
        with source_path.open("rb") as input_stream, temporary.open("xb") as output:
            shutil.copyfileobj(input_stream, output, 64 * 1024)
            output.flush()
            os.fsync(output.fileno())
        latest_revision = _file_sha256(target).hex() if target.is_file() else None
        if not force and (expected.exists != target.is_file() or (expected.exists and latest_revision != expected.revision)):
            raise CloudConflict("云端文件在上传期间发生变化，请重新同步")
        os.replace(temporary, target)
        return _file_sha256(target).hex()
    finally:
        temporary.unlink(missing_ok=True)


def _file_sha256(path: str | Path) -> bytes:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while part := stream.read(64 * 1024):
            digest.update(part)
    return digest.digest()
