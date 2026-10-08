"""局域网同步 HTTPS 服务器，使用 RFC 9382 SPAKE2 完成 PIN 配对。"""

from __future__ import annotations

import http.server
import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import hmac
import tempfile
import threading
import time
import shutil
import mimetypes
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import (
    device_auth_wire,
    pmv_device_registry,
    pmv_sync_authorization,
    spake2,
)

_log = logging.getLogger(__name__)

PORT = 18765
PAIRING_TIMEOUT = 180
# 一次性 PIN 周期轮换间隔（秒）：即使无人配对也按时刷新，避免二维码/PIN 被拍照后冒用（120 秒）。
PIN_ROTATE_INTERVAL = 120
# 同步配对声明的会话通道：sync=双向同步 / transfer=文件互传 / export=仅导出拉库。
SYNC_OP = "sync"
TRANSFER_OP = "transfer"
EXPORT_OP = "export"
#: 导出下发完成后的兜底关闭宽限期（秒）。客户端校验并入库通常只需几秒，期间它会发
#: cancel 让本机立即关闭；这段宽限只兜住「客户端没发」的情况。
EXPORT_AUTO_CLOSE_GRACE_SECONDS = 30.0
ACTIVE_IDLE_TIMEOUT = 40
ACTIVE_SESSION_TIMEOUT = 600
SESSION_HARD_TIMEOUT = 900
TRANSFER_IDLE_TIMEOUT = 120
TRANSFER_SESSION_HARD_TIMEOUT = 6 * 60 * 60
CERTIFICATE_VALIDITY_SECONDS = TRANSFER_SESSION_HARD_TIMEOUT + 120
MAX_SYNC_BYTES = 10 * 1024 * 1024 * 1024
MAX_AUTH_FAILURES = 10
AUTH_FAILURE_WINDOW_SECONDS = 60
AUTH_LOCKOUT_SECONDS = 30
MAX_AUTH_FAILURE_CLIENTS = 256
PAIRING_HEADER = "X-Vault-Sync-Ticket"
SESSION_HEADER = "X-Vault-Sync-Session"
SPAKE2_VERSION = "spake2-rfc9382-p256-sha256-v1"
SPAKE2_CLIENT_ID = b"vault-android-client"
SPAKE2_SERVER_ID = b"vault-pc-server"
MAX_PAIRING_MESSAGE_BYTES = 4096
MAX_TRANSFER_BYTES = 10 * 1024 * 1024 * 1024 * 1024  # 10 TiB 溢出护栏；大文件由 UI 单次提示放行
MAX_TRANSFER_TEXT_BYTES = 1024 * 1024
TRANSFER_CHUNK_BYTES = 64 * 1024
# 传输连接无数据超时：传输中数据持续流动不会触发，断连/静默丢包时让阻塞读/写及时报错。
TRANSFER_READ_TIMEOUT = 120.0

class _SyncHandler(http.server.BaseHTTPRequestHandler):
    """单次同步会话的请求处理。每次请求验证 PIN，GET 返回 .pmv，PUT 接收 .pmv。"""

    # HTTP/1.1：安卓 HttpsURLConnection 在流式 POST 前会发送 Expect: 100-continue，
    # 只有 HTTP/1.1 才会触发 BaseHTTPRequestHandler.handle_expect_100 回 100 Continue，
    # 否则两端互等造成读超时。
    protocol_version = "HTTP/1.1"
    timeout = TRANSFER_READ_TIMEOUT

    def setup(self):
        super().setup()
        owner = getattr(self.server, "owner", None)
        if owner is not None:
            owner._register_active_connection(self.connection)

    def finish(self):
        owner = getattr(self.server, "owner", None)
        if owner is not None:
            owner._unregister_active_connection(self.connection)
        super().finish()

    def _note_disconnect(self) -> None:
        """传输中检测到连接断开：立即结束会话，让传输窗口及时展示断连状态。"""
        owner = self.server.owner
        if owner._result is None:
            owner._result = {"transfer_ended": True}

    def _send_bytes(self, status: int, body: bytes, content_type: str, message: str | None = None) -> None:
        if message:
            self.send_response(status, message)
        else:
            self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
            self.wfile.flush()
        self.close_connection = True

    _REASON_PHRASE = {
        400: "Bad Request",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        410: "Gone",
        500: "Internal Server Error",
    }

    def send_json_error(self, status: int, message: str) -> None:
        """导入端点错误响应：与安卓 sendJsonError 一致，body 为 {\"error\": msg}。

        BaseHTTPRequestHandler.send_error 会把 message 写入 HTTP 原因短语（仅
        latin-1），中文会抛 UnicodeEncodeError，因此中文消息必须走 JSON body。
        """
        reason = self._REASON_PHRASE.get(status, "Error")
        body = json.dumps({"error": message}, ensure_ascii=False).encode("utf-8")
        self.send_response(status, reason)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/api/sync/vault":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(SYNC_OP, EXPORT_OP):
                return
            self._touch_session()
            self._serve_vault()
        elif parts.path == "/api/sync/keepalive":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if self.server.authenticated_at is None:
                self.send_error(409, "Sync session has not started")
                return
            self._touch_session()
            self._send_bytes(204, b"", "application/octet-stream")
        elif parts.path == "/api/sync/cancel":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if self.server.authenticated_at is None:
                self.send_error(409, "Sync session has not started")
                return
            owner = self.server.owner
            # Android always sends cancel after a completed pull/adopt/push.
            # Preserve an already committed result instead of relabelling a
            # successful bidirectional sync as user cancellation.
            if owner._result is None:
                owner._result = "cancelled"
            self._send_bytes(204, b"", "application/octet-stream")
            # Match Android host behavior: respond first, then tear down the
            # one-shot listener and authenticated session promptly.
            timer = threading.Timer(0.05, owner.stop)
            timer.daemon = True
            timer.start()
        elif parts.path == "/api/transfer/items":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(TRANSFER_OP):
                return
            if not self._require_transfer_authorized():
                return
            self._enter_transfer_mode()
            self._touch_session()
            self._serve_transfer_items()
        elif parts.path == "/api/transfer/item":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(TRANSFER_OP):
                return
            if not self._require_transfer_authorized():
                return
            self._enter_transfer_mode()
            self._touch_session()
            self._serve_transfer_item(parts)
        else:
            self.send_error(404)

    def do_POST(self):
        parts = urlparse(self.path)
        if parts.path == "/api/sync/pair":
            with self.server.pairing_lock:
                self._handle_pair_start()
        elif parts.path == "/api/sync/pair/confirm":
            with self.server.pairing_lock:
                self._handle_pair_confirm()
        elif parts.path == "/api/auth/challenge":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(SYNC_OP, EXPORT_OP, TRANSFER_OP):
                return
            self._touch_session()
            self._handle_device_challenge()
        elif parts.path == "/api/auth/challenge/confirm":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(SYNC_OP, EXPORT_OP, TRANSFER_OP):
                return
            self._touch_session()
            self._handle_device_challenge_confirm()
        elif parts.path == "/api/transfer/end":
            if not self._check_session():
                self.send_error(403, "Forbidden")
                return
            if not self._require_op(TRANSFER_OP):
                return
            if not self._require_transfer_authorized():
                return
            self._enter_transfer_mode()
            self._touch_session()
            self.server.owner._result = {"transfer_ended": True}
            self._send_bytes(204, b"", "application/octet-stream")
        else:
            self.send_error(404)

    def do_PUT(self):
        if not self._check_session():
            self.send_error(403, "Forbidden")
            return
        parts = urlparse(self.path)
        if parts.path == "/api/sync/vault":
            if not self._require_op(SYNC_OP):
                return
            self._touch_session()
            self._receive_vault()
        elif parts.path == "/api/transfer/item":
            if not self._require_op(TRANSFER_OP):
                return
            if not self._require_transfer_authorized():
                return
            self._enter_transfer_mode()
            self._touch_session()
            self._receive_transfer_item()
        else:
            self.send_error(404)

    def do_DELETE(self):
        parts = urlparse(self.path)
        if parts.path != "/api/transfer/item":
            self.send_error(404)
            return
        if not self._check_session():
            self.send_error(403, "Forbidden")
            return
        if not self._require_op(TRANSFER_OP):
            return
        if not self._require_transfer_authorized():
            return
        self._enter_transfer_mode()
        self._touch_session()
        item_id = (parse_qs(parts.query).get("id") or [""])[0]
        with self.server.owner._transfer_lock:
            item = self.server.owner._transfer_outgoing.pop(item_id, None)
        if item is None:
            self.send_error(404, "Transfer item not found")
            return
        staged_path = Path(item["path"])
        completed = dict(item)
        completed.update(
            status="已发送",
            transferred=int(item["size"]),
            path=str(item.get("source_path") or staged_path),
            completed_at=time.time(),
        )
        with self.server.owner._transfer_lock:
            self.server.owner._transfer_sent.append(completed)
        if item.get("temporary"):
            staged_path.unlink(missing_ok=True)
        self._send_bytes(204, b"", "application/octet-stream")

    def _read_pairing_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except (TypeError, ValueError):
            return None
        if length <= 0 or length > MAX_PAIRING_MESSAGE_BYTES:
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _ticket_matches(self, expected_ticket: str | None = None) -> bool:
        got = str(self.headers.get(PAIRING_HEADER, "") or "")
        expected = str(
            getattr(self.server, "pairing_ticket", "") if expected_ticket is None else expected_ticket
        )
        return bool(got and expected and hmac.compare_digest(got, expected))

    def _handle_pair_start(self) -> None:
        if self._client_is_locked():
            self.send_error(403, "Forbidden")
            return
        if not self._record_pairing_start():
            self.send_error(403, "Forbidden")
            return
        body = self._read_pairing_json()
        ticket = str(getattr(self.server, "pairing_ticket", "") or "")
        ticket_matches = self._ticket_matches(ticket)
        version_matches = body is not None and body.get("version") == SPAKE2_VERSION
        if not ticket_matches or body is None or not version_matches:
            _log.warning(
                "配对开始请求无效：ticket=%s body=%s version=%s",
                ticket_matches,
                body is not None,
                version_matches,
            )
            self._record_auth_failure()
            self.send_error(403, "Forbidden")
            return
        # 通道声明：sync=双向同步 / transfer=文件互传 / export=仅导出拉库。绑定进 SPAKE2 AAD，配对后不可更改。
        op = str(body.get("op") or SYNC_OP)
        if op not in (SYNC_OP, TRANSFER_OP, EXPORT_OP):
            self.send_error(400, "Bad Request")
            return
        try:
            client_share = _b64decode(str(body.get("share") or ""), expected_length=65)
            server_share, keys = spake2.finish_b(
                self.server.spake_w,
                client_share,
                SPAKE2_CLIENT_ID,
                SPAKE2_SERVER_ID,
                _spake2_aad(ticket, self.server.cert_fingerprint, op),
                masks=self.server.spake_masks,
            )
        except (ValueError, TypeError) as error:
            _log.warning("配对开始计算失败：%s", type(error).__name__)
            self._record_auth_failure()
            self.send_error(403, "Forbidden")
            return
        handshake = secrets.token_urlsafe(24)
        self.server.pending_handshakes[handshake] = (keys, time.time() + 30, op, ticket)
        body = json.dumps(
            {
                "version": SPAKE2_VERSION,
                "handshake": handshake,
                "share": _b64encode(server_share),
            }
        ).encode("utf-8")
        self._send_bytes(200, body, "application/json; charset=utf-8")

    def _handle_pair_confirm(self) -> None:
        if self._client_is_locked():
            self.send_error(403, "Forbidden")
            return
        body = self._read_pairing_json()
        handshake_id = str((body or {}).get("handshake") or "")
        pending = getattr(self.server, "pending_handshakes", {}).pop(handshake_id, None)
        ticket = str(pending[3]) if pending is not None and len(pending) > 3 else ""
        if not self._ticket_matches(ticket) or body is None or pending is None:
            self._record_auth_failure()
            self.send_error(403, "Forbidden")
            return
        keys, deadline, op, ticket = pending
        try:
            confirmation = _b64decode(str(body.get("confirmation") or ""), expected_length=32)
        except ValueError:
            confirmation = b""
        if (
            time.time() > deadline
            or not hmac.compare_digest(handshake_id, str(body.get("handshake") or ""))
            or not hmac.compare_digest(confirmation, keys.confirm_a)
        ):
            self._record_auth_failure()
            self.send_error(403, "Forbidden")
            return
        # 每个配对生成独立会话令牌并加入集合：多个通道/设备配对后旧会话不被顶掉，
        # 否则缓存会话的客户端会在服务器被其他配对覆盖令牌后收到 403/超时。
        token = _b64encode(keys.session_token(ticket))
        self.server.sessions[token] = {
            "op": op,
            "session_token": token,
            "pairing_ticket": ticket,
            "authorized_device_id": None,
            "authorized_public_key": None,
            "pending_public_key": None,
            # 建会话时留一份对端地址：_client_ip() 只在请求处理期间可用，
            # 之后 UI 想显示「谁连上来了」就取不到了。
            "client_ip": self._client_ip(),
            "pending_export_device": None,
            "pending_transfer_device": None,
            "export_approved": False,
            "pending_sync_device": None,
            "pending_challenge": None,
        }
        self._touch_session()
        # 连接建立后立即轮换配对 PIN：已展示的 PIN 不可再被用于新的配对
        self.server.owner._rotate_pin()
        response = json.dumps(
            {"version": SPAKE2_VERSION, "confirmation": _b64encode(keys.confirm_b)}
        ).encode("utf-8")
        self._send_bytes(200, response, "application/json; charset=utf-8")

    # ── 设备授权（Challenge-Response，PMVE）──────────────────────────

    def _require_device_authorized(self, operation: pmv_sync_authorization.Operation) -> bool:
        if not getattr(self.server, "device_auth_enabled", False):
            return True  # 未显式启用设备授权（旧客户端/旧流程）时保持兼容
        registry = self.server.owner._device_registry()
        if registry is None:
            self.send_error(503, "PMVE authorization registry unavailable")
            return False
        session = getattr(self, "_lan_session", None) or {}
        device_id = session.get("authorized_device_id")
        if device_id is None:
            self._send_bytes(
                403,
                json.dumps({"error": "设备尚未完成授权认证"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return False
        if not registry.is_authorized(device_id, operation):
            self._send_bytes(
                403,
                json.dumps({"error": "设备未授权或权限不足"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return False
        return True

    def _handle_device_challenge(self) -> None:
        try:
            registry = self.server.owner._device_registry()
        except ValueError:
            _log.exception("保险库设备授权记录无法读取")
            self._send_bytes(
                500,
                json.dumps({"error": "保险库设备授权记录无效，请检查 PC 日志中的具体字段"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        if registry is None:
            self._send_bytes(
                500,
                json.dumps({"error": "设备认证未就绪"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length <= 0 or length > MAX_PAIRING_MESSAGE_BYTES:
                raise ValueError("invalid content length")
            request = device_auth_wire.parse_challenge_request(
                self.rfile.read(length).decode("utf-8")
            )
        except Exception as error:
            self._send_bytes(
                400,
                json.dumps({"error": str(error)}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        if not registry.is_authorized(request.device_id, request.operation):
            session = getattr(self, "_lan_session", None) or {}
            # 公钥在这里还拿得到（confirm 阶段解出的 Challenge 里已经没有这个字段），
            # 先存一份，供传输站页面在连接期间持续显示对方设备的密钥指纹。
            session["pending_public_key"] = request.device_public_key
            if session.get("op", SYNC_OP) in (EXPORT_OP, TRANSFER_OP):
                if session.get("export_approved"):
                    authorization = self.server.owner._transient_export_authorization(
                        request.device_id, request.device_public_key
                    )
                    if authorization is not None:
                        registry.install(authorization, transient=True)
                if not registry.is_authorized(request.device_id, request.operation):
                    pending_key = "pending_transfer_device" if session.get("op") == TRANSFER_OP else "pending_export_device"
                    session[pending_key] = (session["session_token"], request.device_id, request.device_public_key)
                    if session.get("op") == TRANSFER_OP:
                        self.server.owner._refresh_pending_transfer_device()
                    else:
                        self.server.owner._refresh_pending_export_device()
                    self._send_bytes(
                        423,
                        json.dumps({"error": "等待主机确认导出"}, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8",
                    )
                    return
            else:
                owner = self.server.owner
                if owner.sync_approval_enabled:
                    # 与安卓一致：同步通道需主机确认后才允许读写本机库。
                    if not registry.is_authorized(request.device_id, request.operation):
                        session["pending_sync_device"] = (
                            session["session_token"], request.device_id, request.device_public_key
                        )
                        owner._refresh_pending_sync_device()
                        self._send_bytes(
                            423,
                            json.dumps({"error": "等待主机确认同步"}, ensure_ascii=False).encode("utf-8"),
                            "application/json; charset=utf-8",
                        )
                        return
                else:
                    # 与安卓流程一致：配对成功后首次挑战即“先授权”，把设备写入注册表再继续。
                    authorization = owner._authorize_connecting_device(
                        request.device_id,
                        request.device_public_key,
                    )
                    if authorization is None:
                        self._send_bytes(
                            403,
                            json.dumps({"error": "设备未授权或已撤销"}, ensure_ascii=False).encode("utf-8"),
                            "application/json; charset=utf-8",
                        )
                        return
                    registry.install(authorization)
        try:
            challenge = registry.issue(
                request.device_id,
                request.operation,
                request.client_nonce,
                request.requested_commit_id,
                request.request_digest,
            )
        except Exception as error:
            self._send_bytes(
                403,
                json.dumps({"error": str(error)}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        response = device_auth_wire.challenge_response(
            pmv_sync_authorization.encode_challenge(challenge)
        )
        session = getattr(self, "_lan_session", None)
        if session is not None:
            session["pending_challenge"] = pmv_sync_authorization.encode_challenge(challenge)
        self._send_bytes(200, response.encode("utf-8"), "application/json; charset=utf-8")

    def _handle_device_challenge_confirm(self) -> None:
        try:
            registry = self.server.owner._device_registry()
        except ValueError:
            _log.exception("保险库设备授权记录无法读取")
            self._send_bytes(
                500,
                json.dumps({"error": "保险库设备授权记录无效，请检查 PC 日志中的具体字段"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        if registry is None:
            self._send_bytes(
                500,
                json.dumps({"error": "设备认证未就绪"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length <= 0 or length > MAX_PAIRING_MESSAGE_BYTES:
                raise ValueError("invalid content length")
            confirm = device_auth_wire.parse_confirm_request(
                self.rfile.read(length).decode("utf-8")
            )
            session = getattr(self, "_lan_session", None) or {}
            expected = session.get("pending_challenge")
            if expected is None or not hmac.compare_digest(expected, confirm.challenge):
                raise ValueError("challenge does not belong to this session")
            challenge = pmv_sync_authorization.decode_challenge(confirm.challenge)
            registry.consume(challenge, confirm.signature)
        except Exception:
            self._send_bytes(
                403,
                json.dumps({"error": "设备认证失败"}, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        session["authorized_device_id"] = challenge.device_id
        # 公钥在挑战请求阶段就存下了（见 _handle_device_challenge）：过了这一步
        # pending_* 会被清掉，传输站页面就没法再显示对方设备的指纹了。
        session["authorized_public_key"] = session.pop("pending_public_key", None)
        session["pending_challenge"] = None
        response = device_auth_wire.confirm_response()
        self._send_bytes(200, response.encode("utf-8"), "application/json; charset=utf-8")

    def _check_session(self) -> bool:
        got = str(self.headers.get(SESSION_HEADER, "") or "")
        got_ticket = str(self.headers.get(PAIRING_HEADER, "") or "")
        sessions = getattr(self.server, "sessions", {})
        session = next(
            (value for token, value in sessions.items() if hmac.compare_digest(got, token)),
            None,
        ) if got else None
        ok = bool(
            session is not None
            and got_ticket
            and hmac.compare_digest(got_ticket, str(session.get("pairing_ticket", "")))
        )
        if not ok:
            self._record_auth_failure()
            self._lan_session = None
        else:
            self._lan_session = session
        return ok

    def _client_ip(self) -> str:
        try:
            return str(ipaddress.ip_address(self.client_address[0]))
        except (AttributeError, IndexError, ValueError):
            return "unknown"

    def _client_is_locked(self) -> bool:
        now = time.monotonic()
        failures = getattr(self.server, "auth_failures_by_ip", {})
        attempts = getattr(self.server, "pairing_attempts_by_ip", {})
        failure_state = failures.get(self._client_ip())
        attempt_state = attempts.get(self._client_ip())
        return bool((failure_state and failure_state[1] > now) or (attempt_state and attempt_state[1] > now))

    def _record_pairing_start(self) -> bool:
        now = time.monotonic()
        ip = self._client_ip()
        attempts = getattr(self.server, "pairing_attempts_by_ip", None)
        if attempts is None:
            attempts = self.server.pairing_attempts_by_ip = {}
        lock = getattr(self.server, "auth_failures_lock", None)
        if lock is None:
            lock = self.server.auth_failures_lock = threading.Lock()
        with lock:
            state = attempts.get(ip)
            count = state[0] + 1 if state and now - state[2] <= AUTH_FAILURE_WINDOW_SECONDS else 1
            locked_until = now + AUTH_LOCKOUT_SECONDS if count > MAX_AUTH_FAILURES else 0.0
            attempts[ip] = (count, locked_until, now)
            if len(attempts) > MAX_AUTH_FAILURE_CLIENTS:
                oldest = min(attempts, key=lambda key: attempts[key][2])
                if oldest != ip:
                    attempts.pop(oldest, None)
        return locked_until == 0.0

    def _record_auth_failure(self) -> None:
        now = time.monotonic()
        ip = self._client_ip()
        failures = getattr(self.server, "auth_failures_by_ip", None)
        if failures is None:
            failures = self.server.auth_failures_by_ip = {}
            self.server.auth_failures_lock = threading.Lock()
        with self.server.auth_failures_lock:
            state = failures.get(ip)
            count = state[0] + 1 if state and now - state[2] <= AUTH_FAILURE_WINDOW_SECONDS else 1
            locked_until = now + AUTH_LOCKOUT_SECONDS if count >= MAX_AUTH_FAILURES else 0.0
            failures[ip] = (count, locked_until, now)
            if len(failures) > MAX_AUTH_FAILURE_CLIENTS:
                oldest = min(failures, key=lambda key: failures[key][2])
                if oldest != ip:
                    failures.pop(oldest, None)
        count_for_ip = count
        _log.warning(
            "同步认证失败：method=%s path=%s failures=%d locked=%s",
            self.command,
            urlparse(self.path).path,
            count_for_ip,
            self._client_is_locked(),
        )

    def _require_op(self, *allowed) -> bool:
        """通道权限：仅当会话声明的通道属于 [allowed] 才放行，否则返回 False（已发送 403）。"""
        session = getattr(self, "_lan_session", None) or {}
        if session.get("op", SYNC_OP) in allowed:
            return True
        self.send_error(403, "Forbidden")
        return False

    def _require_transfer_authorized(self) -> bool:
        session = getattr(self, "_lan_session", None) or {}
        if session.get("authorized_device_id") is not None:
            return True
        self._send_bytes(
            403,
            json.dumps({"error": "设备尚未完成传输授权"}, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )
        return False

    def _touch_session(self) -> None:
        now = time.time()
        if self.server.authenticated_at is None:
            self.server.authenticated_at = now
        self.server.access_time = now

    def _enter_transfer_mode(self) -> None:
        self.server.owner._transfer_active = True
        self.server.transfer_active = True

    def _serve_vault(self):
        session = getattr(self, "_lan_session", None) or {}
        if session.get("op") == EXPORT_OP and not session.get("export_approved", False):
            self.send_error(423, "Export approval required")
            return
        if not self._require_device_authorized(pmv_sync_authorization.Operation.READ):
            return
        vault = self.server.vault
        from .storage import _vault_write_lock
        with _vault_write_lock(vault.path):
            # PMVE GET 只传输已提交文件，不能为了导出凭空追加新 Commit。
            path = Path(vault.path)
            with path.open("rb") as source:
                source.seek(0, os.SEEK_END)
                size = source.tell()
                source.seek(0)
                if size > MAX_SYNC_BYTES:
                    body = json.dumps(
                        {"error": "账户数据超过 10 GB，暂时无法通过局域网传输"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                    self._send_bytes(413, body, "application/json; charset=utf-8")
                    return
                # 摘要和响应体必须来自同一个已打开文件快照。若另一个进程原子替换
                # 了路径，重新 open 会读到新文件，导致响应头摘要与响应体永久不一致。
                digest = hashlib.sha256()
                while True:
                    chunk = source.read(TRANSFER_CHUNK_BYTES)
                    if not chunk:
                        break
                    digest.update(chunk)
                source.seek(0)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                # Export header carries the real account name (stem minus the vault_ convention
                # prefix), so importers register the same account without a stray prefix.
                self.send_header("X-Vault-Name", _vault_display_name(vault.path))
                # 导出文件 SHA-256：客户端下载后校验，防止传输链路损坏导致导入坏库。
                self.send_header("X-Vault-Sha256", digest.hexdigest())
                self.send_header("Connection", "close")
                self.end_headers()
                self.server.owner.sync_phase = "sending"
                sent = 0
                while True:
                    chunk = source.read(TRANSFER_CHUNK_BYTES)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    self.server.owner.sync_send_progress = (sent, size)
                    # 大库发送期间持续刷新活跃时间，避免空闲超时误杀进行中的同步
                    self.server.access_time = time.time()
            self.wfile.flush()
            if session.get("op") == EXPORT_OP:
                # 导出下发达成：与双向同步一致，由本机主动断开，不把收尾只交给
                # 客户端的 cancel——那条路要靠会话头找回会话，一旦 403 就静默失败
                # （客户端把非 204 吞掉），传输站会一直挂在「已连接」。
                #
                # 仍留一段宽限期：客户端还要做完整性校验与入库，期间可能因校验失败
                # 在同一会话里重新申请下载；正常路径客户端会在几秒内发 cancel，那时
                # 立即关闭，不等宽限期。
                self.server.owner._schedule_export_auto_close()

    def _serve_transfer_items(self) -> None:
        with self.server.owner._transfer_lock:
            items = [
                {key: value for key, value in item.items() if key not in {"path", "source_path", "preview"}}
                for item in self.server.owner._transfer_outgoing.values()
                if len(str(item.get("sha256") or "")) == 64
            ]
        self._send_bytes(
            200,
            json.dumps({"items": items}, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _serve_transfer_item(self, parts) -> None:
        item_id = (parse_qs(parts.query).get("id") or [""])[0]
        with self.server.owner._transfer_lock:
            item = self.server.owner._transfer_outgoing.get(item_id)
        if item is None:
            self.send_error(404, "Transfer item not found")
            return
        path = Path(item["path"])
        if not path.is_file() or path.stat().st_size != item["size"]:
            self.send_error(410, "Transfer item is no longer available")
            return
        self.server.owner._transfer_active_connections[item_id] = self.connection
        if self.server.owner._transfer_outgoing.get(item_id) is not item:
            # 登记前已被取消：停止发送，保持“已取消”记录。
            self.server.owner._transfer_active_connections.pop(item_id, None)
            self.send_error(410, "Transfer item is no longer available")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(item["size"]))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            transferred = 0
            with self.server.owner._transfer_lock:
                item["status"] = "发送中"
                item["transferred"] = 0
            with path.open("rb") as source:
                while True:
                    chunk = source.read(TRANSFER_CHUNK_BYTES)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    transferred += len(chunk)
                    with self.server.owner._transfer_lock:
                        item["transferred"] = transferred
                    # 大文件发送期间持续刷新活跃时间，避免空闲超时误杀进行中的传输
                    self.server.access_time = time.time()
            self.wfile.flush()
        except (OSError, ConnectionError) as error:
            with self.server.owner._transfer_lock:
                if item.get("status") != "已取消":
                    text = str(error).lower()
                    if (
                        "broken pipe" in text
                        or "connection reset" in text
                        or "connection aborted" in text
                        or "reset by peer" in text
                        or "closed by peer" in text
                    ):
                        # 对端取消/拒绝接收：按对方操作提示，不误报成本机发送失败。
                        item["status"] = "对方已取消接收该文件"
                    else:
                        item["status"] = "发送失败"
            # 不在此结束会话：真实断连由客户端 /api/transfer/end 或会话空闲超时兜底，
            # 单条取消/单个连接失败不应关闭整个传输站（与安卓行为一致）。
            return
        finally:
            self.server.owner._transfer_active_connections.pop(item_id, None)
            self.close_connection = True

    def _receive_transfer_item(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except (TypeError, ValueError):
            self.send_error(411, "Content-Length required")
            return
        if length < 0 or length > MAX_TRANSFER_BYTES:
            self.send_error(413, "Transfer payload too large")
            return
        expected_hash = str(self.headers.get("X-Vault-Content-Sha256", "") or "").lower()
        if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
            self.send_error(400, "Missing file integrity information")
            return
        try:
            item_id = str(uuid.UUID(str(self.headers.get("X-Vault-Transfer-Id", ""))))
            name = _decode_transfer_header(self.headers.get("X-Vault-Transfer-Name", ""))
            mime = _decode_transfer_header(self.headers.get("X-Vault-Transfer-Mime", ""))
        except (ValueError, UnicodeError):
            self.send_error(400, "Invalid transfer metadata")
            return
        kind = str(self.headers.get("X-Vault-Transfer-Kind", "file") or "file")
        if kind not in {"file", "text"}:
            self.send_error(400, "Invalid transfer kind")
            return
        safe_name = _safe_transfer_name(name or ("message.txt" if kind == "text" else "received.bin"))
        mime = (mime or "application/octet-stream")[:255]
        incoming_dir = _downloads_transfer_dir()
        destination = _unique_path(incoming_dir, safe_name)
        part = self.server.owner._transfer_dir / f"incoming-{item_id}.part"
        item = {
            "id": item_id,
            "name": safe_name,
            "mime": mime,
            "kind": kind,
            "size": length,
            "sha256": "",
            "path": str(destination),
            "received_at": time.time(),
            "status": "接收中",
            "transferred": 0,
        }
        with self.server.owner._transfer_lock:
            self.server.owner._transfer_received.append(item)
        self.server.owner._transfer_active_connections[item_id] = self.connection
        digest = hashlib.sha256()
        remaining = length
        try:
            with part.open("wb") as output:
                while remaining:
                    chunk = self.rfile.read(min(TRANSFER_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise OSError("transfer body was truncated")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                    with self.server.owner._transfer_lock:
                        item["transferred"] = length - remaining
                    # 大文件接收期间持续刷新活跃时间，避免空闲超时误杀进行中的传输
                    self.server.access_time = time.time()
            actual_hash = digest.hexdigest()
            if not hmac.compare_digest(expected_hash, actual_hash):
                raise ValueError("file integrity check failed")
            shutil.move(str(part), destination)
        except (OSError, ValueError) as error:
            part.unlink(missing_ok=True)
            with self.server.owner._transfer_lock:
                if item.get("status") != "已取消":
                    self.server.owner._transfer_received = [
                        existing for existing in self.server.owner._transfer_received
                        if existing is not item
                    ]
            # 不在此结束会话：真实断连由客户端 /api/transfer/end 或会话空闲超时兜底，
            # 单条取消/单个连接失败不应关闭整个传输站（与安卓行为一致）。
            try:
                self.send_error(422 if isinstance(error, ValueError) else 400, "File integrity check failed")
            except OSError:
                # 连接已被取消/关闭：响应无法送达，静默结束即可。
                pass
            return
        finally:
            self.server.owner._transfer_active_connections.pop(item_id, None)
        preview = ""
        if kind == "text" and length <= MAX_TRANSFER_TEXT_BYTES:
            try:
                preview = destination.read_text(encoding="utf-8", errors="replace")[:160]
            except OSError:
                preview = ""
        with self.server.owner._transfer_lock:
            item["sha256"] = actual_hash
            item["status"] = "已接收"
            item["transferred"] = length
            item["preview"] = preview
        body = json.dumps({"id": item_id, "sha256": item["sha256"], "path": item["path"]}, ensure_ascii=False).encode("utf-8")
        self._send_bytes(201, body, "application/json; charset=utf-8")

    def _receive_vault(self):
        if not self._require_device_authorized(pmv_sync_authorization.Operation.WRITE):
            return
        vault = self.server.vault
        try:
            length = int(self.headers.get("Content-Length", ""))
        except (TypeError, ValueError):
            self.send_error(411, "Content-Length required")
            return
        if length <= 0 or length > MAX_SYNC_BYTES:
            self.send_error(413, "Payload too large or empty")
            return
        expected_hash = str(self.headers.get("X-Vault-Content-Sha256", "") or "").lower()
        if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
            self.send_error(400, "Missing vault integrity information")
            return
        tmp = Path(vault.path).with_name(f"__sync_{uuid.uuid4().hex}.pmv")
        try:
            self.server.owner.sync_phase = "receiving"
            self.server.owner.sync_receive_progress = (0, length)
            total = 0
            digest = hashlib.sha256()
            with tmp.open("wb") as output:
                while total < length:
                    chunk = self.rfile.read(min(TRANSFER_CHUNK_BYTES, length - total))
                    if not chunk:
                        raise OSError("同步保险库 body 被截断")
                    output.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
                    self.server.owner.sync_receive_progress = (total, length)
                    # 大库上传期间持续刷新活跃时间，避免空闲超时误杀进行中的同步
                    self.server.access_time = time.time()
                output.flush()
                os.fsync(output.fileno())
            self.server.owner.sync_phase = "verifying"
            if not hmac.compare_digest(expected_hash, digest.hexdigest()):
                self.server.owner.sync_phase = "failed"
                self.send_error(422, "Vault integrity check failed")
                return

            from .storage import VaultLineage, pmve_key_convergence_kind

            try:
                remote_identity = vault.authenticate_external_file(tmp)
                lineage = vault.classify_lineage(vault.pmve_identity, remote_identity)
            except Exception:
                lineage = VaultLineage.INVALID
            if lineage is VaultLineage.SAME:
                stats = {"lineage": lineage.value, "replaced": False}
            elif lineage is VaultLineage.FAST_FORWARD:
                convergence = pmve_key_convergence_kind(vault, tmp)
                vault.replace_authenticated_file(tmp)
                stats = {
                    "lineage": lineage.value,
                    "replaced": True,
                    "key_converged": convergence != "NONE",
                    "password_changed": convergence == "PASSWORD",
                }
            elif lineage is VaultLineage.REMOTE_STALE:
                # 简化后的双向流程：连接方固定回推，若其提交较旧说明本端已更新，
                # 直接保留本端并视为同步成功（不再 409 拒绝导致流程失败）。
                stats = {"lineage": lineage.value, "replaced": False, "local_wins": True}
            elif lineage is VaultLineage.DIVERGED:
                # 与安卓一致：传输站侧分叉也自动合并，而不是拒绝覆盖。
                convergence = pmve_key_convergence_kind(vault, tmp)
                vault.merge_and_adopt_authenticated_file(tmp)
                stats = {
                    "lineage": lineage.value,
                    "replaced": True,
                    "merged": True,
                    "key_converged": convergence != "NONE",
                    "password_changed": convergence == "PASSWORD",
                }
            else:
                messages = {
                    VaultLineage.DIFFERENT: "两端不是同一份 PMVE 保险库",
                    VaultLineage.INVALID: "远端 PMVE Header/Commit/PMVR 认证失败",
                }
                message = messages.get(lineage, "PMVE Identity 无效")
                self.server.owner._result = {"error": message, "lineage": lineage.value}
                self.server.owner.sync_phase = "failed"
                body = json.dumps(
                    {"error": message, "lineage": lineage.value}, ensure_ascii=False
                ).encode("utf-8")
                self._send_bytes(
                    409,
                    body,
                    "application/json; charset=utf-8",
                    "PMVE lineage conflict",
                )
                return
            stats.update(
                local_count=len(vault.entries),
                merged_count=len(vault.entries),
                uploaded=True,
                verified=True,
            )
            self.server.owner._result = stats
            self.server.owner.sync_phase = "done"
            self._send_bytes(
                200,
                json.dumps(stats).encode("utf-8"),
                "application/json; charset=utf-8",
            )
            return
        except OSError:
            self._note_disconnect()
            self.server.owner.sync_phase = "failed"
            self.send_error(400, "Sync vault body was truncated")
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler includes the complete request target in its
        # default log message. Never allow pairing metadata to reach logs.
        _log.debug("HTTPS %s %s", self.command, urlparse(self.path).path)


class SyncServer:
    """启动一个短暂存活的 HTTPS 服务器，用于单次同步配对。

    用法：
        server = SyncServer(vault, lineage_check)
        url, pin = server.start()
        # 显示 QR 码（含 url）
        stats = server.wait()  # 阻塞直到完成或超时
        server.stop()
    """

    def __init__(self, vault, lineage_check):
        self.vault = vault
        self.vault_cls = type(vault)
        self.lineage_check = lineage_check
        self.pin = f"{secrets.randbelow(1_000_000):06d}"
        self.pairing_ticket = secrets.token_urlsafe(18)
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._result: dict | str | None = None
        # 活动连接注册表：stop()/断开时关闭全部连接，立即终止在途传输。
        self._active_connections: set = set()
        self._active_connections_lock = threading.Lock()
        self._tls_paths: tuple[Path, Path] | None = None
        self._transfer_lock = threading.Lock()
        self._transfer_outgoing: dict[str, dict] = {}
        self._transfer_received: list[dict] = []
        self._transfer_sent: list[dict] = []
        # 单条传输正在服务的连接（按传输项 id）：取消该条目时关闭连接以中断阻塞读写。
        self._transfer_active_connections: dict[str, object] = {}
        self._transfer_dir = Path(tempfile.mkdtemp(prefix="vault-transfer-"))
        self._transfer_active = False
        # 同步确认（与安卓一致）：主机 UI 开启后，未授权设备拉/推保险库前需用户确认。
        self.sync_approval_enabled = False
        self.pending_sync_device = None
        # 同步进度（供 UI 轮询）：phase ∈ idle/sending/receiving/verifying/done/failed；
        # 进度元组为 (已传输字节, 总字节)。
        self.sync_phase = "idle"
        self.sync_send_progress: tuple[int, int] | None = None
        self.sync_receive_progress: tuple[int, int] | None = None
        # 设备授权（PMVE）：当前会话完成 Challenge-Response 后的设备 ID，与待批准的导出设备。
        self._auth_registry = None
        self.device_auth_enabled = False
        self.pending_export_device = None
        self.pending_transfer_device = None
        # 同步二维码完整地址（内嵌一次性 PIN）；周期轮换时随之重建。
        self.pairing_url = ""
        self._pairing_host = ""
        self._pairing_port = 0
        self._last_pin_rotate = 0.0

    def _register_active_connection(self, sock) -> None:
        with self._active_connections_lock:
            self._active_connections.add(sock)

    def _unregister_active_connection(self, sock) -> None:
        with self._active_connections_lock:
            self._active_connections.discard(sock)

    def close_active_connections(self) -> None:
        """关闭所有活动连接，使阻塞中的收发立刻报错退出。"""
        with self._active_connections_lock:
            sockets = list(self._active_connections)
            self._active_connections.clear()
        for sock in sockets:
            _force_close_socket(sock)

    def _device_registry(self):
        """从已解锁的 PMVE 库元数据构建授权注册表。"""
        if self._auth_registry is None:
            vault = self.vault
            if vault._pmve_store is None:
                return None
            identity = vault.vault_identity
            if identity is None:
                return None
            records = pmv_device_registry.verify_all(
                pmv_device_registry.decode(vault._pmve_store.metadata()),
                identity.signing_public_key,
            )
            registry = pmv_sync_authorization.AuthorizationRegistry(
                identity.vault_id, identity.signing_public_key
            )
            for record in records:
                registry.install(record)
            self._auth_registry = registry
        return self._auth_registry

    def approve_export(self, session_token: str | None = None) -> bool:
        """批准当前导出会话；授权仅存活于内存，并在五分钟后失效。"""
        if self._server is None:
            return False
        target = next((s for s in self._server.sessions.values()
                       if s.get("op") == EXPORT_OP
                       and (session_token is None or s.get("session_token") == session_token)
                       and s.get("pending_export_device") is not None), None)
        if target is None:
            return False
        _session_token, device_id, public_key = target["pending_export_device"]
        authorization = self._transient_export_authorization(device_id, public_key)
        registry = self._device_registry()
        approved = authorization is not None and registry is not None
        if approved:
            registry.install(authorization, transient=True)
            target["pending_export_device"] = None
            target["export_approved"] = True
        self._refresh_pending_export_device()
        return approved

    def _transient_export_authorization(
        self,
        device_id: uuid.UUID,
        device_public_key: bytes,
    ):
        """签发一次短期只读授权，不写回保险库元数据。"""
        vault = self.vault
        if vault._pmve_store is None:
            return None
        try:
            store = vault._pmve_store
            identity = store.identity
            now_millis = int(time.time() * 1000)
            authorization = store.sign_device_authorization(
                pmv_sync_authorization.DeviceAuthorization(
                    vault_id=identity.vault_id,
                    device_id=device_id,
                    device_public_key=bytes(device_public_key),
                    permissions=pmv_sync_authorization.PERMISSION_READ,
                    issued_at_epoch_millis=now_millis,
                    expires_at_epoch_millis=now_millis + 5 * 60 * 1000,
                    revoked_at_epoch_millis=0,
                    epoch=now_millis,
                )
            )
            return authorization
        except Exception:
            return None

    def _refresh_pending_export_device(self) -> None:
        if self._server is None:
            self.pending_export_device = None
            return
        pending = next(
            (
                session.get("pending_export_device")
                for session in self._server.sessions.values()
                if session.get("op") == EXPORT_OP and session.get("pending_export_device") is not None
            ),
            None,
        )
        self._server.pending_export_device = pending
        self.pending_export_device = pending

    def approve_transfer(self, session_token: str | None = None) -> bool:
        if self._server is None:
            return False
        target = next((s for s in self._server.sessions.values()
                       if s.get("op") == TRANSFER_OP
                       and (session_token is None or s.get("session_token") == session_token)
                       and s.get("pending_transfer_device") is not None), None)
        if target is None:
            return False
        _token, device_id, public_key = target["pending_transfer_device"]
        authorization = self._transient_export_authorization(device_id, public_key)
        registry = self._device_registry()
        if authorization is None or registry is None:
            return False
        registry.install(authorization, transient=True)
        target["pending_transfer_device"] = None
        target["export_approved"] = True
        self._refresh_pending_transfer_device()
        return True

    def reject_transfer(self, session_token: str | None = None) -> bool:
        self._reject_pending_session(TRANSFER_OP, "pending_transfer_device", session_token)
        self._refresh_pending_transfer_device()
        return True

    def _reject_pending_session(self, op: str, pending_key: str, session_token: str | None) -> None:
        if self._server is None:
            return
        token = session_token or next((s.get("session_token") for s in self._server.sessions.values()
                                       if s.get("op") == op and s.get(pending_key) is not None), None)
        if token is not None:
            session = self._server.sessions.get(token)
            if session is not None and session.get("op") == op:
                self._server.sessions.pop(token, None)

    def _refresh_pending_transfer_device(self) -> None:
        pending = None if self._server is None else next(
            (s.get("pending_transfer_device") for s in self._server.sessions.values()
             if s.get("op") == TRANSFER_OP and s.get("pending_transfer_device") is not None), None
        )
        if self._server is not None:
            self._server.pending_transfer_device = pending
        self.pending_transfer_device = pending

    def _authorize_connecting_device(
        self,
        device_id: uuid.UUID,
        device_public_key: bytes,
    ):
        """配对成功后首次挑战即授权设备（与安卓“先授权”流程一致）：
        写入 READ|WRITE 授权到 PMVE 库元数据，返回签名后的授权记录；失败返回 None。"""
        vault = self.vault
        if vault._pmve_store is None:
            return None
        try:
            store = vault._pmve_store
            identity = store.identity
            metadata = store.metadata()
            records = pmv_device_registry.decode(metadata)
            existing = max(
                (record for record in records if record.device_id == device_id),
                key=lambda record: record.epoch,
                default=None,
            )
            authorization = store.sign_device_authorization(
                pmv_sync_authorization.DeviceAuthorization(
                    vault_id=identity.vault_id,
                    device_id=device_id,
                    device_public_key=bytes(device_public_key),
                    permissions=pmv_sync_authorization.PERMISSION_READ
                    | pmv_sync_authorization.PERMISSION_WRITE,
                    issued_at_epoch_millis=int(time.time() * 1000),
                    expires_at_epoch_millis=0,
                    revoked_at_epoch_millis=0,
                    epoch=(existing.epoch if existing else 0) + 1,
                )
            )
            updated = pmv_device_registry.with_registry(metadata, records + [authorization])
            entries = []
            for summary in store.list():
                entry = store.read_entry(summary.entry_id)
                if entry is not None:
                    entries.append(entry)
            store.save_full(
                expected_sequence=identity.sequence,
                metadata=updated,
                entries=entries,
            )
            self._auth_registry = None  # 下次访问时重建，包含新授权
            return authorization
        except Exception:
            return None

    def reject_export(self, session_token: str | None = None) -> bool:
        """拒绝待确认导出设备。"""
        if self._server is not None:
            self._reject_pending_session(EXPORT_OP, "pending_export_device", session_token)
            self._refresh_pending_export_device()
        return True

    def approve_sync(self, session_token: str | None = None) -> bool:
        """允许已配对客户端读写本机保险库（同步确认，与安卓一致）。"""
        if self._server is None:
            return False
        target = next((s for s in self._server.sessions.values()
                       if s.get("op") == SYNC_OP
                       and (session_token is None or s.get("session_token") == session_token)
                       and s.get("pending_sync_device") is not None), None)
        if target is None:
            return False
        registry = self._device_registry()
        _token, device_id, device_public_key = target["pending_sync_device"]
        authorization = self._authorize_connecting_device(device_id, device_public_key)
        approved = authorization is not None and registry is not None
        if approved:
            registry.install(authorization)
            target["pending_sync_device"] = None
        self._refresh_pending_sync_device()
        return approved

    def reject_sync(self, session_token: str | None = None) -> bool:
        """拒绝待确认同步设备。"""
        if self._server is not None:
            self._reject_pending_session(SYNC_OP, "pending_sync_device", session_token)
            self._refresh_pending_sync_device()
        return True

    def _refresh_pending_sync_device(self) -> None:
        if self._server is None:
            self.pending_sync_device = None
            return
        pending = next(
            (
                session.get("pending_sync_device")
                for session in self._server.sessions.values()
                if session.get("op") == SYNC_OP and session.get("pending_sync_device") is not None
            ),
            None,
        )
        self._server.pending_sync_device = pending
        self.pending_sync_device = pending

    @property
    def transfer_received(self) -> list[dict]:
        with self._transfer_lock:
            return [dict(item) for item in self._transfer_received]

    @property
    def transfer_sent(self) -> list[dict]:
        with self._transfer_lock:
            return [dict(item) for item in self._transfer_sent]

    def cancel_transfer_item(self, item_id: str) -> bool:
        """取消单条传输（本机作为传输站）：等待接收/发送中/接收中的条目立即终止。"""
        with self._transfer_lock:
            outgoing = self._transfer_outgoing.pop(item_id, None)
            if outgoing is not None:
                outgoing["canceled"] = True
                outgoing["status"] = "已取消"
                completed = dict(outgoing)
                completed.update(status="已取消", completed_at=time.time())
                self._transfer_sent.append(completed)
                if outgoing.get("temporary"):
                    try:
                        Path(str(outgoing.get("path") or "")).unlink(missing_ok=True)
                    except OSError:
                        # 摘要线程可能仍持有句柄（Windows）：稍后由会话清理目录兜底。
                        pass
            else:
                received = next(
                    (item for item in self._transfer_received if item.get("id") == item_id),
                    None,
                )
                if received is None:
                    return False
                received["canceled"] = True
                received["status"] = "已取消"
                received["completed_at"] = time.time()
        conn = self._transfer_active_connections.pop(item_id, None)
        if conn is not None:
            _force_close_socket(conn)
        return True

    @property
    def peer_info(self) -> dict | None:
        """当前接入设备的详细信息，供传输站页面显示；未接入时为 None。

        只读快照，不含任何可用于冒充的凭据：指纹取公钥的 SHA-256 前 24 位十六进制，
        与同步/传输确认弹窗里展示的是同一个值，用户可以据此核对两端是否一致。
        """
        server = self._server
        if server is None or not getattr(server, "authenticated_at", None):
            return None
        for session in list(getattr(server, "sessions", {}).values()):
            device_id = session.get("authorized_device_id")
            if not device_id:
                continue
            public_key = session.get("authorized_public_key")
            fingerprint = ""
            if public_key:
                fingerprint = hashlib.sha256(public_key).hexdigest()[:24]
            return {
                "device_id": str(device_id),
                "fingerprint": fingerprint,
                "client_ip": str(session.get("client_ip") or "unknown"),
                "operation": str(session.get("op") or ""),
                "authenticated_at": float(server.authenticated_at),
            }
        return None

    @property
    def connected(self) -> bool:
        """是否已有设备完成配对（会话建立）；用于连接后隐藏二维码/连接信息。"""
        server = self._server
        return bool(server is not None and server.sessions)

    def queue_transfer_file(
        self,
        source: str | Path,
        *,
        name: str | None = None,
        mime: str | None = None,
        kind: str = "file",
        preview: str = "",
        temporary: bool = False,
    ) -> dict:
        source_path = Path(source)
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        size = source_path.stat().st_size
        if size > MAX_TRANSFER_BYTES:
            raise ValueError("发送文件超过 10 TiB 安全限制")
        item_id = str(uuid.uuid4())
        safe_name = _safe_transfer_name(name or source_path.name)
        item = {
            "id": item_id,
            "name": safe_name,
            "mime": (mime or mimetypes.guess_type(safe_name)[0] or "application/octet-stream")[:255],
            "kind": kind if kind in {"file", "text"} else "file",
            "size": size,
            "sha256": "",
            "path": str(source_path),
            "source_path": str(source_path),
            "temporary": bool(temporary),
            "preview": preview[:160],
            "status": "等待接收",
            "transferred": 0,
            "created_at": time.time(),
        }
        with self._transfer_lock:
            self._transfer_outgoing[item_id] = item

        def _digest() -> None:
            digest = hashlib.sha256()
            try:
                with source_path.open("rb") as input_file:
                    while True:
                        chunk = input_file.read(TRANSFER_CHUNK_BYTES)
                        if not chunk:
                            break
                        digest.update(chunk)
                with self._transfer_lock:
                    item["sha256"] = digest.hexdigest()
            except OSError:
                with self._transfer_lock:
                    item["sha256"] = ""

        threading.Thread(target=_digest, name="transfer-digest", daemon=True).start()
        return dict(item)

    def queue_transfer_text(self, text: str) -> dict:
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_TRANSFER_TEXT_BYTES:
            raise ValueError("发送文本超过 1 MB 安全限制")
        item_id = str(uuid.uuid4())
        staged = self._transfer_dir / f"text-{item_id}.txt"
        staged.write_bytes(encoded)
        return self.queue_transfer_file(
            staged,
            name=f"message_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.txt",
            mime="text/plain; charset=utf-8",
            kind="text",
            preview=text,
            temporary=True,
        )

    def start(self) -> tuple[str, str]:
        host = _local_ip()
        cert_pem, key_pem, fingerprint = _ephemeral_certificate(host)
        cert_file = tempfile.NamedTemporaryFile(prefix="vault-sync-", suffix=".crt", delete=False)
        key_file = tempfile.NamedTemporaryFile(prefix="vault-sync-", suffix=".key", delete=False)
        try:
            cert_file.write(cert_pem)
            key_file.write(key_pem)
        finally:
            cert_file.close()
            key_file.close()
        self._tls_paths = (Path(cert_file.name), Path(key_file.name))

        self._server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), _SyncHandler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        self._server.socket = tls.wrap_socket(self._server.socket, server_side=True)
        actual_port = self._server.server_port
        self._server.pin = self.pin
        self._server.pairing_ticket = self.pairing_ticket
        self._server.sessions = {}
        self._server.pending_handshakes = {}
        self._server.pairing_lock = threading.Lock()
        self._server.auth_failures_by_ip = {}
        self._server.pairing_attempts_by_ip = {}
        self._server.auth_failures_lock = threading.Lock()
        self._server.transfer_active = False
        self._server.pending_sync_device = None
        self._server.spake_w = spake2.derive_w(self.pin, self.pairing_ticket)
        self._server.spake_masks = spake2.password_masks(self._server.spake_w)
        self._server.cert_fingerprint = fingerprint
        self._server.owner = self
        self._server.vault = self.vault
        self._server.vault_cls = self.vault_cls
        self._server.lineage_check = self.lineage_check
        self._server.device_auth_enabled = self.device_auth_enabled
        self._server.pending_export_device = None
        self._server.pending_transfer_device = None
        now = time.time()
        self._server.started_at = now
        self._server.access_time = now
        self._server.authenticated_at = None
        self._server.timeout = 1

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

        pairing = urlencode({"ticket": self.pairing_ticket, "pin": self.pin})
        url = f"https://{host}:{actual_port}/api/sync/vault?{pairing}"
        self.pairing_url = url
        self._pairing_host = host
        self._pairing_port = actual_port
        self._last_pin_rotate = time.time()
        return url, self.pin

    def _rotate_pin(self) -> None:
        """配对连接建立后或按周期轮换 PIN，使已展示的 PIN 无法继续使用。

        已建立的会话通过 session_token 认证，不受影响；新配对必须使用新 PIN。
        与安卓一致：连接建立后仍持续轮换，避免二维码/PIN 长期可复用。
        """
        self.pin = f"{secrets.randbelow(1_000_000):06d}"
        self.pairing_ticket = secrets.token_urlsafe(18)
        if self._pairing_host and self._pairing_port:
            pairing = urlencode({"ticket": self.pairing_ticket, "pin": self.pin})
            self.pairing_url = f"https://{self._pairing_host}:{self._pairing_port}/api/sync/vault?{pairing}"
        server = self._server
        if server is not None:
            server.pending_handshakes = {}
            server.pin = self.pin
            server.pairing_ticket = self.pairing_ticket
            server.spake_w = spake2.derive_w(self.pin, self.pairing_ticket)
            server.spake_masks = spake2.password_masks(server.spake_w)
        self._last_pin_rotate = time.time()

    def _serve(self):
        server = self._server
        while True:
            try:
                server.handle_request()
            except (OSError, ValueError):
                # 正常关闭（stop() 关闭监听 socket）时干净退出
                break
            except Exception:
                # 单个连接/握手错误不应杀死 accept 循环：记录后继续监听
                _log.exception("同步服务器 accept 循环异常，继续监听")
                time.sleep(0.05)
                continue
            if self._result is not None:
                break
            # 一次性 PIN 周期轮换：已连接后不再刷新（由 _rotate_pin 内拦截），
            # 进行中的配对不打断；顺便清除已超时的握手，防止未确认请求堆积。
            now = time.time()
            server.pending_handshakes = {
                handshake: pending
                for handshake, pending in server.pending_handshakes.items()
                if pending[1] >= now
            }
            if (
                not server.pending_handshakes
                and now - self._last_pin_rotate >= PIN_ROTATE_INTERVAL
            ):
                with server.pairing_lock:
                    self._rotate_pin()
            reason = self._expiry_reason(time.time())
            if reason is not None:
                if self._result is None:
                    self._result = {"timeout": reason}
                _log.info("同步会话已关闭：%s", reason)
                break

    def _expiry_reason(self, now: float) -> str | None:
        server = self._server
        if server is None:
            return "服务器已停止"
        transfer_active = bool(
            getattr(server, "transfer_active", False)
            or self.__dict__.get("_transfer_active", False)
        )
        hard_timeout = TRANSFER_SESSION_HARD_TIMEOUT if transfer_active else SESSION_HARD_TIMEOUT
        if now - server.started_at > hard_timeout:
            return "达到传输会话上限" if transfer_active else "达到 15 分钟会话上限"
        if server.authenticated_at is None:
            if now - server.started_at > PAIRING_TIMEOUT:
                return "3 分钟内未建立连接"
            return None
        if not transfer_active and now - server.authenticated_at > ACTIVE_SESSION_TIMEOUT:
            return "同步处理超过 10 分钟"
        idle_timeout = TRANSFER_IDLE_TIMEOUT if transfer_active else ACTIVE_IDLE_TIMEOUT
        if now - server.access_time > idle_timeout:
            return "2 分钟未收到传输心跳" if transfer_active else "40 秒未收到同步心跳"
        return None

    def wait(self) -> dict | str | None:
        self._thread.join(timeout=SESSION_HARD_TIMEOUT + 5)
        return self._result

    def _schedule_export_auto_close(self):
        """导出下发达成后的兜底关闭：宽限期内客户端若发来 cancel 会立即关闭。

        这里只负责「客户端没发」的情况（例如它在校验阶段就退出了）。给得比正常
        cancel 慢，客户端先到先关，不会被拖住。
        """
        import threading

        def close_later():
            import time as _time

            _time.sleep(EXPORT_AUTO_CLOSE_GRACE_SECONDS)
            # 期间若已被 cancel/其它路径关掉，_server 已为 None，这里自然无事可做。
            if self._server is not None:
                self.stop()

        threading.Thread(target=close_later, name="vault-host-export-close", daemon=True).start()

    def stop(self):
        # 先复位会话级状态。UI 每 300ms 轮询 connected / _transfer_active / sync_phase，
        # 这些标志只有在这里才有机会归零：_transfer_active 原先仅在 __init__ 置 False，
        # stop() 不清，于是传输跑完后 is_busy() 恒为 True，三档滑块被永久禁用。
        self._transfer_active = False
        self.sync_phase = "idle"
        self.sync_send_progress = None
        self.sync_receive_progress = None
        # 先关闭活动连接：立即终止在途的同步/文件传输，而不是等服务端自行收尾。
        self.close_active_connections()
        if self._server:
            self._server.pending_handshakes = {}
            self._server.sessions = {}
            self._server.spake_w = 0
            self._server.spake_masks = (None, None)
            self._server.server_close()
            self._server = None
        for conn in list(self._transfer_active_connections.values()):
            _force_close_socket(conn)
        self._transfer_active_connections.clear()
        self.pin = ""
        self.pairing_ticket = ""
        if self._tls_paths:
            for path in self._tls_paths:
                # 尽力删除：Windows 上杀软/索引器可能仍占着句柄，
                # 这里若抛出去会中断整个停止流程，剩下的清理都做不完。
                try:
                    path.unlink(missing_ok=True)
                except OSError as exc:
                    _log.warning("无法删除传输站临时文件 %s：%s", path.name, exc)
            self._tls_paths = None
        shutil.rmtree(self._transfer_dir, ignore_errors=True)
        if self._result is None:
            self._result = "cancelled"


def _ephemeral_certificate(host: str) -> tuple[bytes, bytes, str]:
    """Generate a short-lived ECDSA certificate and its SHA-256 fingerprint."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vault LAN Sync")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(seconds=CERTIFICATE_VALIDITY_SECONDS))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert.fingerprint(hashes.SHA256()).hex()


def _local_ip() -> str:
    """获取本机局域网 IP。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _force_close_socket(sock) -> None:
    """可靠打断阻塞读写：先 shutdown 底层 socket 再关闭（Windows 上仅 close 不可靠）。"""
    raw = getattr(sock, "_sock", sock)
    try:
        raw.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _decode_transfer_header(value: str) -> str:
    raw = str(value or "")
    if not raw or len(raw) > 2048:
        raise ValueError("invalid transfer header")
    padding = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw + padding).decode("utf-8")


def _safe_transfer_name(value: str) -> str:
    name = Path(str(value).replace("\\", "/")).name[:180]
    cleaned = "".join("_" if ord(char) < 32 or char in '<>:"/\\|?*' else char for char in name).strip(" .")
    return cleaned or "received.bin"


def _vault_display_name(path) -> str:
    # 命名统一：文件名去掉后缀即为账户名，不再处理 vault_ 前缀。
    return Path(path).stem


def _downloads_transfer_dir() -> Path:
    path = Path.home() / "Downloads" / "Vaultshare"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _unique_path(directory: Path, name: str) -> Path:
    candidate = directory / name
    stem = candidate.stem
    suffix = candidate.suffix
    index = 2
    while candidate.exists():
        # 数字后缀插在扩展名之前、无括号：file_2.txt / app_2.apk
        candidate = directory / f"{stem}_{index}{suffix}"
        index += 1
    return candidate


def _spake2_aad(ticket: str, certificate_fingerprint: str, op: str) -> bytes:
    return (
        b"Vault LAN Sync SPAKE2 RFC9382 v2\0"
        + op.encode("ascii")
        + b"\0"
        + ticket.encode("utf-8")
        + b"\0"
        + certificate_fingerprint.encode("ascii")
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str, expected_length: int) -> bytes:
    if not value or len(value) > 256 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        raise ValueError("invalid base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != expected_length:
        raise ValueError("invalid decoded length")
    return raw
