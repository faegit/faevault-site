"""局域网「连接传输站」HTTPS 客户端。

与安卓端 ``SyncClient.kt`` 语义一致，可连入 PC 端或安卓端传输站：
- SPAKE2 PIN 配对 + 临时证书指纹通道绑定
- 库双向同步（LWW 合并，复用 ``storage.Vault.sync_merge``）
- 双向文件/文本传输

注意：SPAKE2 身份串固定为 ``vault-android-client``/``vault-pc-server``
（协议级常量，与真实角色无关），本客户端同样沿用，与两端保持一致。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import mimetypes
import os
import secrets
import socket
import ssl
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from . import spake2

_log = logging.getLogger(__name__)

PORT = 18765
SPAKE2_VERSION = "spake2-rfc9382-p256-sha256-v1"
PAIRING_HEADER = "X-Vault-Sync-Ticket"
SESSION_HEADER = "X-Vault-Sync-Session"
CLIENT_ID = b"vault-android-client"
SERVER_ID = b"vault-pc-server"
MAX_SYNC_BYTES = 10 * 1024 * 1024 * 1024
MAX_TRANSFER_BYTES = 10 * 1024 * 1024 * 1024 * 1024  # 10 TiB 溢出护栏；大文件由 UI 单次提示放行
MAX_TRANSFER_TEXT_BYTES = 1024 * 1024
MAX_LAN_URL_CHARS = 2048
STREAM_CHUNK = 64 * 1024
# 配对声明的会话通道：sync=双向同步 / transfer=文件互传 / export=仅导出拉库
SYNC_OP = "sync"
TRANSFER_OP = "transfer"
EXPORT_OP = "export"
# 导出通道拉库等待主机确认的最长时长（秒）：主机侧约 150s 自动断开
EXPORT_APPROVAL_TIMEOUT = 150


class SyncError(Exception):
    """传输站连接/同步/传输失败。"""


class IntegrityError(SyncError):
    """内容长度或 SHA-256 校验失败；仅此类错误允许自动重试。"""


MAX_INTEGRITY_ATTEMPTS = 3
CONTENT_SHA256_HEADER = "X-Vault-Content-Sha256"


def _force_close_connection(conn) -> None:
    """可靠打断阻塞读写：先 shutdown 底层 socket 再关闭（Windows 上仅 close 不可靠）。"""
    sock = getattr(conn, "sock", None)
    if sock is not None:
        raw = getattr(sock, "_sock", sock)
        try:
            raw.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    try:
        conn.close()
    except Exception:
        pass


class PinValidationError(SyncError):
    """PIN 码错误（配对确认阶段）。"""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str, expected: int) -> bytes:
    if (
        not value
        or len(value) > max(256, ((expected + 2) // 3) * 4)
        or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value)
    ):
        raise SyncError("缺少 base64 数据")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise SyncError("无效的 SPAKE2 响应") from error
    if len(raw) != expected:
        raise SyncError("无效的 SPAKE2 响应")
    return raw


def pairing_ticket(url: str) -> str:
    query = urlparse(url).query
    values = parse_qs(query).get("ticket", [])
    return values[0] if len(values) == 1 else ""


def embedded_pin(url: str) -> str:
    """从同步连接地址中提取内嵌的一次性 6 位 PIN；不存在或格式无效返回空串。"""
    values = parse_qs(urlparse(url).query).get("pin", [])
    if len(values) != 1:
        return ""
    value = values[0]
    return value if len(value) == 6 and value.isdigit() else ""


def _spake2_aad(ticket: str, fingerprint: str, op: str) -> bytes:
    return (
        b"Vault LAN Sync SPAKE2 RFC9382 v2\0"
        + op.encode("ascii")
        + b"\0"
        + ticket.encode("utf-8")
        + b"\0"
        + fingerprint.encode("ascii")
    )


def _safe_name(value: str) -> str:
    name = str(value).replace("\\", "/").split("/")[-1][:180]
    cleaned = "".join("_" if ord(char) < 32 or char in '<>:"/\\|?*' else char for char in name).strip(" .")
    return cleaned or "received.bin"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(STREAM_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class LanSyncClient:
    """一次传输站会话。构造时即完成 SPAKE2 配对。"""

    def __init__(self, url: str, pin: str, op: str = SYNC_OP):
        if op not in (SYNC_OP, TRANSFER_OP, EXPORT_OP):
            raise SyncError("无效的连接通道")
        self.url = url.rstrip("/")
        self.ticket = pairing_ticket(self.url)
        if len(self.ticket) < 12:
            raise SyncError("配对票据无效，请检查连接地址（需含 ?ticket=…）")
        self.pin = pin
        self.op = op
        self._session: str | None = None
        self._fingerprint: str | None = None
        # 在途传输连接注册表：按传输项 key 关联底层连接，单条取消时只关对应连接。
        self._inflight: dict[str, http.client.HTTPSConnection] = {}
        self._inflight_lock = threading.Lock()
        self.pair()

    def _track_connection(self, key: str, conn: http.client.HTTPSConnection) -> None:
        with self._inflight_lock:
            self._inflight[key] = conn

    def _untrack_connection(self, key: str, conn: http.client.HTTPSConnection) -> None:
        with self._inflight_lock:
            if self._inflight.get(key) is conn:
                self._inflight.pop(key, None)

    def abort_transfer(self, key: str) -> None:
        """单条传输取消：关闭该传输项对应的底层连接，使阻塞的读写立刻抛错退出。"""
        with self._inflight_lock:
            conn = self._inflight.pop(key, None)
        if conn is not None:
            _force_close_connection(conn)

    def abort_all_transfers(self) -> None:
        """断连时立即中止所有在途传输。"""
        with self._inflight_lock:
            conns = list(self._inflight.values())
            self._inflight.clear()
        for conn in conns:
            _force_close_connection(conn)

    # ── 底层连接 ──────────────────────────────────────────────────────────

    def _host_port(self) -> tuple[str, int]:
        if not self.url or len(self.url) > MAX_LAN_URL_CHARS:
            raise SyncError("连接地址无效")
        parsed = urlparse(self.url)
        if parsed.scheme != "https":
            raise SyncError("传输站仅支持 HTTPS 地址")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise SyncError("连接地址包含不允许的内容")
        host = parsed.hostname or ""
        if not host:
            raise SyncError("连接地址无效")
        try:
            address = ipaddress.ip_address(host)
            port = parsed.port or PORT
        except ValueError as error:
            raise SyncError("连接地址必须使用局域网 IP") from error
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise SyncError("连接地址不是局域网地址")
        return host, port

    def _connect(self, path: str) -> http.client.HTTPSConnection:
        host, port = self._host_port()
        context = ssl._create_unverified_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(host, port, timeout=120, context=context)
        conn.connect()
        return conn

    @staticmethod
    def _peer_fingerprint(conn: http.client.HTTPSConnection) -> str:
        der = conn.sock.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest()

    def _check_pinned(self, conn: http.client.HTTPSConnection) -> None:
        if self._fingerprint is None:
            return
        if self._peer_fingerprint(conn) != self._fingerprint:
            raise SyncError("传输站证书已变化")

    def _headers(self, extra: dict | None = None) -> dict:
        headers = {
            "Connection": "close",
            PAIRING_HEADER: self.ticket,
        }
        if self._session:
            headers[SESSION_HEADER] = self._session
        if extra:
            headers.update(extra)
        return headers

    # ── SPAKE2 配对 ───────────────────────────────────────────────────────

    def pair(self) -> None:
        if len(self.pin) != 6 or not self.pin.isdigit():
            raise SyncError("PIN 码格式无效")
        w = spake2.derive_w(self.pin, self.ticket)
        x, p_a = spake2.start_a(w)

        conn = self._connect("/api/sync/pair")
        fingerprint = self._peer_fingerprint(conn)
        body = json.dumps({"version": SPAKE2_VERSION, "op": self.op, "share": _b64encode(p_a)}).encode("utf-8")
        conn.request("POST", "/api/sync/pair", body=body, headers={
            "Content-Type": "application/json",
            "Connection": "close",
            PAIRING_HEADER: self.ticket,
        })
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            raise SyncError(f"配对失败（HTTP {resp.status}）")
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        if data.get("version") != SPAKE2_VERSION:
            raise SyncError("传输站不支持当前 SPAKE2 协议")
        handshake = data.get("handshake", "")
        if len(handshake) < 24:
            raise SyncError("配对响应无效")
        p_b = _b64decode(data.get("share", ""), 65)
        keys = spake2.finish_a(w, x, p_a, p_b, CLIENT_ID, SERVER_ID, _spake2_aad(self.ticket, fingerprint, self.op))

        conn = self._connect("/api/sync/pair/confirm")
        self._check_pinned(conn)
        body = json.dumps({
            "handshake": handshake,
            "confirmation": _b64encode(keys.confirm_a),
        }).encode("utf-8")
        conn.request("POST", "/api/sync/pair/confirm", body=body, headers={
            "Content-Type": "application/json",
            "Connection": "close",
            PAIRING_HEADER: self.ticket,
        })
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            raise PinValidationError("PIN 码错误")
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        if data.get("version") != SPAKE2_VERSION or not hmac.compare_digest(
            _b64decode(data.get("confirmation", ""), 32), keys.confirm_b
        ):
            raise PinValidationError("PIN 码错误")
        self._session = _b64encode(keys.session_token(self.ticket))
        self._fingerprint = fingerprint
        _log.info("传输站配对成功 %s", self._host_port()[0])

    def authenticate_device(self, vault_id: uuid.UUID, identity) -> None:
        """SPAKE2 配对后完成设备授权握手（PMVE）；导出通道用零 vault_id 占位。

        [identity] 为 device_identity.load_or_create 返回的 (device_id, seed)。
        """
        operations = ("read", "write") if self.op == SYNC_OP else ("read",)
        for operation in operations:
            self._authenticate_one(vault_id, identity, operation)

    def _authenticate_one(self, vault_id: uuid.UUID, identity, operation: str) -> None:
        from . import device_auth_wire, device_identity, pmv_sync_authorization

        device_id, seed = identity
        claimed_vault = device_auth_wire.ZERO_UUID if self.op == EXPORT_OP else vault_id
        client_nonce = secrets.token_bytes(32)
        body = json.dumps(
            {
                "v": device_auth_wire.PROTOCOL_VERSION,
                "clientNonce": _b64encode(client_nonce),
                "deviceId": str(device_id),
                "vaultId": str(claimed_vault),
                "op": operation,
                "devicePublicKey": _b64encode(device_identity.device_public_key(seed)),
                "requestedCommitId": None,
                "requestDigest": _b64encode(bytes(32)),
            },
            ensure_ascii=False,
        ).encode("utf-8")
        deadline = time.monotonic() + EXPORT_APPROVAL_TIMEOUT
        while True:
            conn = self._connect("/api/auth/challenge")
            self._check_pinned(conn)
            conn.request(
                "POST",
                "/api/auth/challenge",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Connection": "close",
                    PAIRING_HEADER: self.ticket,
                    SESSION_HEADER: self._session,
                },
            )
            resp = conn.getresponse()
            if resp.status == 423:
                detail = resp.read(1024).decode("utf-8", "replace")
                conn.close()
                if time.monotonic() >= deadline:
                    if self.op == SYNC_OP:
                        raise SyncError(f"等待主机确认同步超时（HTTP 423）：{detail}")
                    raise SyncError(f"等待主机确认导出超时（HTTP 423）：{detail}")
                time.sleep(2)
                continue
            if resp.status != 200:
                detail = resp.read(4096).decode("utf-8", "replace")
                conn.close()
                raise SyncError(f"设备认证失败（HTTP {resp.status}）：{detail}")
            challenge = _b64decode(
                json.loads(resp.read().decode("utf-8"))["challenge"],
                pmv_sync_authorization.CHALLENGE_SIZE,
            )
            conn.close()
            signature = device_auth_wire.sign_challenge(challenge, device_id, seed)
            confirm_body = json.dumps(
                {
                    "v": device_auth_wire.PROTOCOL_VERSION,
                    "challenge": _b64encode(challenge),
                    "signature": _b64encode(signature),
                },
                ensure_ascii=False,
            ).encode("utf-8")
            conn = self._connect("/api/auth/challenge/confirm")
            self._check_pinned(conn)
            conn.request(
                "POST",
                "/api/auth/challenge/confirm",
                body=confirm_body,
                headers={
                    "Content-Type": "application/json",
                    "Connection": "close",
                    PAIRING_HEADER: self.ticket,
                    SESSION_HEADER: self._session,
                },
            )
            resp = conn.getresponse()
            if resp.status != 200:
                detail = resp.read(4096).decode("utf-8", "replace")
                conn.close()
                raise SyncError(f"设备认证确认失败（HTTP {resp.status}）：{detail}")
            resp.read()
            conn.close()
            return

    # ── 库同步 ────────────────────────────────────────────────────────────

    def sync_vault(self, vault, on_phase=None) -> dict:
        """拉取远端库 → 校验 → LWW 合并到本机 → 推回。返回合并统计。"""
        descriptor, name = tempfile.mkstemp(prefix="vault-sync-", suffix=".pmv")
        os.close(descriptor)
        remote = Path(name)
        try:
            self._pull_vault_file(
                remote,
                on_progress=(lambda sent, total: on_phase("download", sent, total)) if on_phase else None,
            )
            if on_phase is not None:
                on_phase("verify", 0, 0)
            result = self._merge_into(
                vault,
                remote,
                on_upload=(lambda sent, total: on_phase("upload", sent, total)) if on_phase else None,
            )
            result["remote_bytes"] = remote.stat().st_size
            return result
        finally:
            remote.unlink(missing_ok=True)
            # Android closes every sync session after the fixed pull/adopt/push
            # flow, on both success and failure.  Do the same so either host
            # releases its one-shot pairing state immediately.
            try:
                self.cancel()
            except Exception:
                pass

    def _pull_vault_file(self, target: Path, on_progress=None) -> None:
        last_error = None
        for attempt in range(1, MAX_INTEGRITY_ATTEMPTS + 1):
            try:
                self._pull_vault_file_once(target, on_progress=on_progress)
                return
            except IntegrityError as error:
                target.unlink(missing_ok=True)
                last_error = error
                if on_progress is not None and attempt < MAX_INTEGRITY_ATTEMPTS:
                    on_progress(0, 0)
        raise last_error or IntegrityError("收到的数据未通过安全检查")

    def _pull_vault_file_once(self, target: Path, on_progress=None) -> None:
        # 导出通道下主机需要用户确认后才放行，等待期间返回 423；每 2s 重试，直至超时
        deadline = time.monotonic() + EXPORT_APPROVAL_TIMEOUT
        while True:
            conn = self._connect("/api/sync/vault")
            self._check_pinned(conn)
            conn.request("GET", "/api/sync/vault", headers=self._headers())
            resp = conn.getresponse()
            if resp.status == 423:
                detail = resp.read(1024).decode("utf-8", "replace")
                conn.close()
                if time.monotonic() >= deadline:
                    if self.op == SYNC_OP:
                        raise SyncError(f"等待主机确认同步超时（HTTP 423）：{detail}")
                    raise SyncError(f"等待主机确认导出超时（HTTP 423）：{detail}")
                time.sleep(2)
                continue
            if resp.status != 200:
                detail = resp.read(4096).decode("utf-8", "replace")
                conn.close()
                raise SyncError(f"拉取保险库失败（HTTP {resp.status}）：{detail}")
            length = resp.getheader("Content-Length")
            expected_hash = str(resp.getheader("X-Vault-Sha256") or "").lower()
            try:
                length_int = int(length) if length else -1
            except ValueError:
                length_int = -1
            if length_int <= 0 or length_int > MAX_SYNC_BYTES:
                resp.read(1024)
                conn.close()
                raise SyncError("对方发送的数据大小无效或超过 10 GB")
            if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
                resp.read(1024)
                conn.close()
                raise IntegrityError("对方未提供有效的安全校验信息")
            total = 0
            digest = hashlib.sha256()
            try:
                with target.open("wb") as out:
                    while True:
                        chunk = resp.read(STREAM_CHUNK)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > length_int or total > MAX_SYNC_BYTES:
                            raise IntegrityError("收到的数据长度与发送方不一致")
                        digest.update(chunk)
                        out.write(chunk)
                        if on_progress is not None:
                            on_progress(total, length_int)
                    out.flush()
                    os.fsync(out.fileno())
            except Exception:
                target.unlink(missing_ok=True)
                raise
            finally:
                conn.close()
            break
        if length_int != total:
            target.unlink(missing_ok=True)
            raise IntegrityError("收到的数据不完整")
        if not hmac.compare_digest(expected_hash, digest.hexdigest()):
            target.unlink(missing_ok=True)
            raise IntegrityError("收到的数据未通过安全检查")

    def download_vault(self, target: Path) -> None:
        """导出通道专用：仅从主机拉取 .pmv 裸文件到 [target]，不做本地合并。

        用于「局域网导入」把安卓传输站的数据导出为可导入的 .pmv 文件。
        """
        if self.op != EXPORT_OP:
            raise SyncError("导出拉取需以导出通道连接")
        self._pull_vault_file(target)

    def _merge_into(self, vault, remote_path: Path, on_upload=None) -> dict:
        from .storage import VaultLineage, pmve_key_convergence_kind

        try:
            remote_identity = vault.authenticate_external_file(remote_path)
        except Exception as exc:
            raise SyncError("远端 PMVE Header/Commit/PMVR 认证失败") from exc
        lineage = vault.classify_lineage(vault.pmve_identity, remote_identity)
        local_count = len(vault.entries)
        result: dict = {"lineage": lineage.value, "local_count": local_count}
        if lineage is VaultLineage.SAME:
            result["replaced"] = False
        elif lineage is VaultLineage.FAST_FORWARD:
            convergence = pmve_key_convergence_kind(vault, remote_path)
            vault.replace_authenticated_file(remote_path)
            result.update(
                replaced=True,
                key_converged=convergence != "NONE",
                password_changed=convergence == "PASSWORD",
            )
        elif lineage is VaultLineage.REMOTE_STALE:
            # 本端已更新：保留本端，仍按双向流程回推给传输站。
            result["replaced"] = False
        elif lineage is VaultLineage.DIFFERENT:
            raise SyncError("两端不是同一份 PMVE 保险库，已取消同步")
        elif lineage is VaultLineage.DIVERGED:
            convergence = pmve_key_convergence_kind(vault, remote_path)
            vault.merge_and_adopt_authenticated_file(remote_path)
            result.update(
                replaced=True,
                merged=True,
                key_converged=convergence != "NONE",
                password_changed=convergence == "PASSWORD",
            )
        else:
            raise SyncError("远端 PMVE Identity 无效")
        # 简化后的双向流程：拉取并校验/采纳后固定回推，
        # 由传输站校验对方身份并合并，随后断开连接。
        vault.acknowledge_deletion_checkpoint()
        push_result = self._push_vault_file(vault, on_progress=on_upload)
        if isinstance(push_result, dict):
            result["remote_result"] = push_result
            result["verified"] = "error" not in push_result
        result["pushed"] = True
        result["uploaded"] = True
        result.setdefault("verified", True)
        result["merged_count"] = len(vault.entries)
        return result

    def _push_vault_file(self, vault, on_progress=None) -> dict:
        last_error = None
        for _attempt in range(1, MAX_INTEGRITY_ATTEMPTS + 1):
            try:
                return self._push_vault_file_once(vault, on_progress=on_progress)
            except IntegrityError as error:
                last_error = error
                if on_progress is not None and _attempt < MAX_INTEGRITY_ATTEMPTS:
                    on_progress(0, 0)
        raise last_error or IntegrityError("发送的数据未通过接收方检查")

    def _push_vault_file_once(self, vault, on_progress=None) -> dict:
        from .storage import _vault_write_lock

        with _vault_write_lock(vault.path):
            path = Path(vault.path)
            with path.open("rb") as source:
                source.seek(0, os.SEEK_END)
                size = source.tell()
                source.seek(0)
                if size > MAX_SYNC_BYTES:
                    raise SyncError("当前账户数据超过 10 GB，暂时无法发送")
                # 摘要和请求体来自同一个已打开文件；即使路径被外部原子替换，
                # 也不会把旧摘要和新响应体拼成一次必然失败的上传。
                digest = hashlib.sha256()
                while True:
                    chunk = source.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                source.seek(0)
                conn = self._connect("/api/sync/vault")
                self._check_pinned(conn)
                headers = self._headers({
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                    CONTENT_SHA256_HEADER: digest.hexdigest(),
                })
                conn.putrequest("PUT", "/api/sync/vault")
                for name, value in headers.items():
                    conn.putheader(name, value)
                conn.endheaders()
                sent = 0
                while True:
                    chunk = source.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    conn.send(chunk)
                    sent += len(chunk)
                    if on_progress is not None:
                        on_progress(sent, size)
        resp = conn.getresponse()
        if resp.status not in (200, 201, 204):
            detail = resp.read(4096).decode("utf-8", "replace")
            conn.close()
            if resp.status == 422:
                raise IntegrityError("接收方检查未通过，正在重新发送")
            raise SyncError(f"推送保险库失败（HTTP {resp.status}）：{detail}")
        raw = resp.read(64 * 1024)
        conn.close()
        if resp.status == 204 and not raw:
            return {}
        try:
            result = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrityError("接收方未返回有效的同步校验结果") from exc
        if not isinstance(result, dict):
            raise IntegrityError("接收方未返回有效的同步校验结果")
        return result

    # ── 文件/文本传输 ─────────────────────────────────────────────────────

    def list_transfer_items(self) -> list[dict]:
        conn = self._connect("/api/transfer/items")
        self._check_pinned(conn)
        conn.request("GET", "/api/transfer/items", headers=self._headers())
        resp = conn.getresponse()
        if resp.status != 200:
            conn.close()
            raise SyncError(f"获取传输列表失败（HTTP {resp.status}）")
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return [item for item in data.get("items", []) if isinstance(item, dict)]

    def download_transfer_item(
        self,
        item: dict,
        target: Path,
        on_progress=None,
        on_retry=None,
        transfer_key: str | None = None,
        cancel_check=None,
    ) -> None:
        last_error = None
        for _attempt in range(1, MAX_INTEGRITY_ATTEMPTS + 1):
            if cancel_check is not None and cancel_check():
                raise SyncError("传输已取消")
            try:
                self._download_transfer_item_once(
                    item,
                    target,
                    on_progress=on_progress,
                    transfer_key=transfer_key,
                )
                return
            except IntegrityError as error:
                target.unlink(missing_ok=True)
                last_error = error
                if on_retry is not None and _attempt < MAX_INTEGRITY_ATTEMPTS:
                    on_retry(_attempt + 1, MAX_INTEGRITY_ATTEMPTS)
        raise last_error or IntegrityError("文件未通过安全检查")

    def _download_transfer_item_once(
        self,
        item: dict,
        target: Path,
        on_progress=None,
        transfer_key: str | None = None,
    ) -> None:
        query = urlencode({"id": item["id"]})
        key = transfer_key or str(item["id"])
        conn = self._connect(f"/api/transfer/item?{query}")
        self._track_connection(key, conn)
        try:
            self._check_pinned(conn)
            conn.request("GET", f"/api/transfer/item?{query}", headers=self._headers())
            resp = conn.getresponse()
            if resp.status != 200:
                conn.close()
                raise SyncError(f"接收失败（HTTP {resp.status}）")
            length = resp.getheader("Content-Length")
            total = 0
            with target.open("wb") as out:
                while True:
                    chunk = resp.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    out.write(chunk)
                    total += len(chunk)
                    if on_progress:
                        on_progress(total, int(length) if length else total)
            conn.close()
        finally:
            self._untrack_connection(key, conn)
        if length and int(length) != total:
            target.unlink(missing_ok=True)
            raise IntegrityError("收到的文件不完整")
        remote_hash = str(item.get("sha256") or "").lower()
        if len(remote_hash) == 64 and all(ch in "0123456789abcdef" for ch in remote_hash):
            digest = hashlib.sha256()
            with target.open("rb") as handle:
                while True:
                    chunk = handle.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
            if digest.hexdigest() != remote_hash:
                target.unlink(missing_ok=True)
                raise IntegrityError("文件未通过安全检查")
        else:
            target.unlink(missing_ok=True)
            raise IntegrityError("发送方未提供有效的文件校验信息")

    def upload_transfer_file(
        self,
        source: Path,
        name: str | None = None,
        mime: str | None = None,
        kind: str = "file",
        on_progress=None,
        on_retry=None,
        transfer_key: str | None = None,
        cancel_check=None,
    ) -> dict:
        size = source.stat().st_size
        if size > MAX_TRANSFER_BYTES:
            raise SyncError("发送内容超过 10 TiB 安全限制")
        expected_hash = _sha256_path(source)
        last_error = None
        for _attempt in range(1, MAX_INTEGRITY_ATTEMPTS + 1):
            if cancel_check is not None and cancel_check():
                raise SyncError("传输已取消")
            try:
                return self._upload_transfer_file_once(
                    source,
                    expected_hash,
                    name,
                    mime,
                    kind,
                    on_progress,
                    transfer_key,
                )
            except IntegrityError as error:
                last_error = error
                if on_retry is not None and _attempt < MAX_INTEGRITY_ATTEMPTS:
                    on_retry(_attempt + 1, MAX_INTEGRITY_ATTEMPTS)
        raise last_error or IntegrityError("文件未通过安全检查")

    def _upload_transfer_file_once(
        self,
        source: Path,
        expected_hash: str,
        name=None,
        mime=None,
        kind="file",
        on_progress=None,
        transfer_key: str | None = None,
    ) -> dict:
        size = source.stat().st_size
        item_id = str(uuid.uuid4())
        safe_name = _safe_name(name or source.name)
        mime = mime or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"
        key = transfer_key or item_id
        conn = self._connect("/api/transfer/item")
        self._track_connection(key, conn)
        try:
            self._check_pinned(conn)
            conn.putrequest("PUT", "/api/transfer/item")
            for header, value in self._headers({
                "Content-Type": "application/octet-stream",
                "X-Vault-Transfer-Id": item_id,
                "X-Vault-Transfer-Name": _b64encode(safe_name.encode("utf-8")),
                "X-Vault-Transfer-Mime": _b64encode(mime.encode("utf-8")),
                "X-Vault-Transfer-Kind": kind,
                "Content-Length": str(size),
                CONTENT_SHA256_HEADER: expected_hash,
            }).items():
                conn.putheader(header, value)
            conn.endheaders()
            total = 0
            with source.open("rb") as handle:
                while True:
                    chunk = handle.read(STREAM_CHUNK)
                    if not chunk:
                        break
                    conn.send(chunk)
                    total += len(chunk)
                    if on_progress:
                        on_progress(total, size)
            resp = conn.getresponse()
            if resp.status not in (200, 201):
                detail = resp.read(4096).decode("utf-8", "replace")
                conn.close()
                if resp.status == 422:
                    raise IntegrityError("接收方文件校验未通过")
                raise SyncError(f"发送失败（HTTP {resp.status}）：{detail}")
            data = json.loads(resp.read().decode("utf-8"))
            conn.close()
        finally:
            self._untrack_connection(key, conn)
        accepted = str(data.get("sha256") or "").lower()
        if not hmac.compare_digest(accepted, expected_hash):
            raise IntegrityError("接收方文件校验未通过")
        return {"id": item_id, "name": safe_name, "mime": mime, "kind": kind, "size": size, "sha256": expected_hash}

    def upload_transfer_text(
        self,
        text: str,
        on_progress=None,
        on_retry=None,
        transfer_key: str | None = None,
        cancel_check=None,
    ) -> dict:
        last_error = None
        for attempt in range(1, MAX_INTEGRITY_ATTEMPTS + 1):
            if cancel_check is not None and cancel_check():
                raise SyncError("传输已取消")
            try:
                return self._upload_transfer_text_once(
                    text,
                    on_progress=on_progress,
                    transfer_key=transfer_key,
                )
            except IntegrityError as error:
                last_error = error
                if on_retry is not None and attempt < MAX_INTEGRITY_ATTEMPTS:
                    on_retry(attempt + 1, MAX_INTEGRITY_ATTEMPTS)
        raise last_error or IntegrityError("文本未通过安全检查")

    def _upload_transfer_text_once(self, text: str, on_progress=None, transfer_key: str | None = None) -> dict:
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_TRANSFER_TEXT_BYTES:
            raise SyncError("发送文本超过 1 MB 安全限制")
        item_id = str(uuid.uuid4())
        name = f"message_{time.strftime('%Y%m%d-%H%M%S')}.txt"
        expected_hash = hashlib.sha256(encoded).hexdigest()
        key = transfer_key or item_id
        conn = self._connect("/api/transfer/item")
        self._track_connection(key, conn)
        try:
            self._check_pinned(conn)
            conn.putrequest("PUT", "/api/transfer/item")
            for header, value in self._headers({
                "Content-Type": "text/plain; charset=utf-8",
                "X-Vault-Transfer-Id": item_id,
                "X-Vault-Transfer-Name": _b64encode(name.encode("utf-8")),
                "X-Vault-Transfer-Mime": _b64encode("text/plain; charset=utf-8".encode("utf-8")),
                "X-Vault-Transfer-Kind": "text",
                "Content-Length": str(len(encoded)),
                CONTENT_SHA256_HEADER: expected_hash,
            }).items():
                conn.putheader(header, value)
            conn.endheaders()
            conn.send(encoded)
            if on_progress:
                on_progress(len(encoded), len(encoded))
            resp = conn.getresponse()
            if resp.status not in (200, 201):
                detail = resp.read(4096).decode("utf-8", "replace")
                conn.close()
                if resp.status == 422:
                    raise IntegrityError("接收方文本校验未通过")
                raise SyncError(f"发送失败（HTTP {resp.status}）：{detail}")
            data = json.loads(resp.read().decode("utf-8"))
            conn.close()
        finally:
            self._untrack_connection(key, conn)
        if not hmac.compare_digest(str(data.get("sha256") or "").lower(), expected_hash):
            raise IntegrityError("接收方文本校验未通过")
        return {"id": item_id, "name": name, "mime": "text/plain; charset=utf-8", "kind": "text", "size": len(encoded), "sha256": expected_hash}

    def acknowledge_transfer_item(self, item_id: str) -> None:
        query = urlencode({"id": item_id})
        conn = self._connect(f"/api/transfer/item?{query}")
        self._check_pinned(conn)
        conn.request("DELETE", f"/api/transfer/item?{query}", headers=self._headers())
        resp = conn.getresponse()
        conn.close()
        if resp.status != 204:
            raise SyncError(f"确认接收失败（HTTP {resp.status}）")

    def end_transfer(self) -> None:
        # 先立即中止在途传输（关闭底层连接使阻塞读写立刻退出），再通知主机。
        self.abort_all_transfers()
        conn = self._connect("/api/transfer/end")
        self._check_pinned(conn)
        conn.request("POST", "/api/transfer/end", body=b"", headers=self._headers({"Content-Length": "0"}))
        resp = conn.getresponse()
        conn.close()
        if resp.status != 204:
            raise SyncError(f"结束传输失败（HTTP {resp.status}）")

    def keepalive(self) -> None:
        conn = self._connect("/api/sync/keepalive")
        self._check_pinned(conn)
        conn.request("GET", "/api/sync/keepalive", headers=self._headers())
        resp = conn.getresponse()
        conn.close()
        if resp.status != 204:
            raise SyncError(f"会话续期失败（HTTP {resp.status}）")

    def cancel(self) -> None:
        # 先中止在途同步/传输，再通知主机端会话结束。
        self.abort_all_transfers()
        conn = self._connect("/api/sync/cancel")
        self._check_pinned(conn)
        conn.request("GET", "/api/sync/cancel", headers=self._headers())
        resp = conn.getresponse()
        if resp.status != 204:
            detail = resp.read(4096).decode("utf-8", "replace")
            conn.close()
            raise SyncError(f"取消同步会话失败（HTTP {resp.status}）：{detail}")
        resp.read()
        conn.close()
