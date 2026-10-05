import hashlib
import base64
import hmac
import io
import json
from pathlib import Path
import ssl
import time
from types import SimpleNamespace
import urllib.parse
import urllib.error
import urllib.request
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from core import spake2, sync_server
from core.models import Entry
from core.storage import Vault
from core.sync_server import (
    ACTIVE_IDLE_TIMEOUT,
    ACTIVE_SESSION_TIMEOUT,
    MAX_AUTH_FAILURES,
    PAIRING_HEADER,
    PAIRING_TIMEOUT,
    SPAKE2_CLIENT_ID,
    SPAKE2_SERVER_ID,
    SPAKE2_VERSION,
    SESSION_HARD_TIMEOUT,
    SESSION_HEADER,
    SyncServer,
    TRANSFER_IDLE_TIMEOUT,
    TRANSFER_SESSION_HARD_TIMEOUT,
    _SyncHandler,
    _b64decode,
    _b64encode,
    _ephemeral_certificate,
    _spake2_aad,
)


RECOVERY_SECRET = bytes(range(32))


def _auth_headers(pairing_url: str, pin: str, op: str = sync_server.SYNC_OP, **extra: str) -> dict[str, str]:
    ticket = urllib.parse.parse_qs(urllib.parse.urlparse(pairing_url).query)["ticket"][0]
    token = _pair(pairing_url, pin, op=op)
    return {SESSION_HEADER: token, PAIRING_HEADER: ticket, **extra}


def _pair(
    pairing_url: str,
    pin: str,
    fingerprint_override: str | None = None,
    op: str = sync_server.SYNC_OP,
) -> str:
    parsed = urllib.parse.urlparse(pairing_url)
    ticket = urllib.parse.parse_qs(parsed.query)["ticket"][0]
    base = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    w = spake2.derive_w(pin, ticket)
    x, client_share = spake2.start_a(w)
    start_body = json.dumps(
        {"version": SPAKE2_VERSION, "op": op, "share": _b64encode(client_share)}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/api/sync/pair",
        data=start_body,
        headers={PAIRING_HEADER: ticket, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=3) as response:
        certificate = response.fp.raw._sock.getpeercert(binary_form=True)
        body = json.loads(response.read())
    fingerprint = fingerprint_override or hashlib.sha256(certificate).hexdigest()
    keys = spake2.finish_a(
        w,
        x,
        client_share,
        _b64decode(body["share"], 65),
        SPAKE2_CLIENT_ID,
        SPAKE2_SERVER_ID,
        _spake2_aad(ticket, fingerprint, op),
    )
    confirm_body = json.dumps(
        {"handshake": body["handshake"], "confirmation": _b64encode(keys.confirm_a)}
    ).encode("utf-8")
    confirm_request = urllib.request.Request(
        f"{base}/api/sync/pair/confirm",
        data=confirm_body,
        headers={PAIRING_HEADER: ticket, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(confirm_request, context=ssl._create_unverified_context(), timeout=3) as response:
        confirmation = json.loads(response.read())
    assert hmac.compare_digest(_b64decode(confirmation["confirmation"], 32), keys.confirm_b)
    return _b64encode(keys.session_token(ticket))


def _handler(pin: str = "123456") -> _SyncHandler:
    handler = _SyncHandler.__new__(_SyncHandler)
    handler.headers = {}
    handler.path = "/api/sync/vault?ticket=pairing-ticket"
    handler.command = "GET"
    handler.server = SimpleNamespace(
        pin=pin,
        pairing_ticket="pairing-ticket",
        sessions={
            "session-token": {
            "op": sync_server.SYNC_OP,
            "pairing_ticket": "pairing-ticket",
                "authorized_device_id": None,
                "pending_export_device": None,
                "export_approved": False,
                "pending_challenge": None,
            }
        },
        auth_failures_by_ip={},
        auth_failures_lock=__import__("threading").Lock(),
    )
    handler.client_address = ("192.0.2.10", 12345)
    return handler


def test_sync_session_is_accepted_only_after_pairing():
    handler = _handler()
    assert not handler._check_session()
    handler.headers = {"X-Vault-Sync-PIN": "123456"}
    assert not handler._check_session()
    handler.headers = {PAIRING_HEADER: "pairing-ticket"}
    assert not handler._check_session()
    handler.headers = {SESSION_HEADER: "session-token", PAIRING_HEADER: "pairing-ticket"}
    assert handler._check_session()


def test_device_challenge_keeps_waiting_session_alive(monkeypatch):
    handler = _handler()
    handler.path = "/api/auth/challenge"
    handler.headers = {SESSION_HEADER: "session-token", PAIRING_HEADER: "pairing-ticket"}
    handler.server.authenticated_at = 100.0
    handler.server.access_time = 100.0
    called = []
    monkeypatch.setattr(handler, "_require_op", lambda *ops: True)
    monkeypatch.setattr(handler, "_handle_device_challenge", lambda: called.append(True))

    handler.do_POST()

    assert called == [True]
    assert handler.server.access_time > 100.0


def test_invalid_device_registry_returns_an_http_error_instead_of_dropping_connection(monkeypatch):
    handler = _handler()
    handler.server.owner = SimpleNamespace(_device_registry=lambda: (_ for _ in ()).throw(ValueError("invalid record")))
    responses = []
    monkeypatch.setattr(handler, "_send_bytes", lambda status, body, content_type: responses.append((status, body)))

    handler._handle_device_challenge()

    assert responses[0][0] == 500
    assert "设备授权记录无效" in responses[0][1].decode("utf-8")


def test_sync_auth_failure_budget_is_per_ip_and_does_not_lock_established_sessions():
    handler = _handler()
    handler.headers = {SESSION_HEADER: "bad-session", PAIRING_HEADER: "pairing-ticket"}
    for _ in range(MAX_AUTH_FAILURES):
        assert not handler._check_session()
    assert handler._client_is_locked()
    handler.headers = {SESSION_HEADER: "session-token", PAIRING_HEADER: "pairing-ticket"}
    assert handler._check_session()
    handler.client_address = ("192.0.2.11", 12345)
    handler.headers = {SESSION_HEADER: "bad-session", PAIRING_HEADER: "pairing-ticket"}
    assert not handler._check_session()
    assert not handler._client_is_locked()


def test_pairing_start_budget_is_temporary_and_per_ip():
    handler = _handler()
    handler.server.pairing_attempts_by_ip = {}
    for _ in range(MAX_AUTH_FAILURES):
        assert handler._record_pairing_start()
    assert not handler._record_pairing_start()
    assert handler._client_is_locked()
    handler.client_address = ("192.0.2.11", 12345)
    assert not handler._client_is_locked()
    assert handler._record_pairing_start()


def test_ephemeral_certificate_matches_advertised_fingerprint_and_ip():
    cert_pem, key_pem, fingerprint = _ephemeral_certificate("192.168.1.5")
    cert = x509.load_pem_x509_certificate(cert_pem)
    serialization.load_pem_private_key(key_pem, password=None)
    assert hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest() == fingerprint
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "192.168.1.5" in {str(value) for value in san.get_values_for_type(x509.IPAddress)}


def test_sync_server_serves_vault_over_tls_and_requires_header(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Password:
        def reveal(self):
            return "unused"

    class Vault:
        path = vault_path
        _password = Password()

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    request_url = urllib.parse.urlunparse(parsed._replace(query=""))
    context = ssl._create_unverified_context()
    try:
        request = urllib.request.Request(request_url, headers=_auth_headers(pairing_url, pin))
        with urllib.request.urlopen(request, context=context, timeout=3) as response:
            peer_certificate = response.fp.raw._sock.getpeercert(binary_form=True)
            assert response.read() == b"encrypted-vault"
        assert parsed.scheme == "https"
        query = urllib.parse.parse_qs(parsed.query)
        assert len(query.get("pin", [""])[0]) == 6  # 同步码内嵌一次性 PIN
        assert len(query.get("ticket", [""])[0]) >= 12
        assert hashlib.sha256(peer_certificate).hexdigest()
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
    assert server._tls_paths is None


def test_sync_server_hashes_and_streams_one_open_vault_snapshot(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    original = b"authenticated-vault-snapshot"
    replacement = original[::-1]
    vault_path.write_bytes(original)

    class Vault:
        path = vault_path

    real_sha256 = hashlib.sha256
    replaced = False

    def sha256_then_switch(data=b""):
        nonlocal replaced
        digest = real_sha256(data)

        class ReplacingDigest:
            def update(self, chunk):
                digest.update(chunk)

            def digest(self):
                return digest.digest()

            def hexdigest(self):
                nonlocal replaced
                replaced = True
                return digest.hexdigest()

        return ReplacingDigest()

    real_path_open = Path.open

    def open_snapshot(path, mode="r", *args, **kwargs):
        if path == vault_path and mode == "rb":
            return io.BytesIO(replacement if replaced else original)
        return real_path_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    request_url = urllib.parse.urlunparse(urllib.parse.urlparse(pairing_url)._replace(query=""))
    try:
        headers = _auth_headers(pairing_url, pin)
        monkeypatch.setattr(Path, "open", open_snapshot)
        monkeypatch.setattr(sync_server.hashlib, "sha256", sha256_then_switch)
        request = urllib.request.Request(request_url, headers=headers)
        with urllib.request.urlopen(
            request, context=ssl._create_unverified_context(), timeout=3,
        ) as response:
            body = response.read()
            advertised_hash = response.headers["X-Vault-Sha256"]
        assert replaced is True
        assert body == original
        assert advertised_hash == real_sha256(body).hexdigest()
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_sync_server_rejects_wrong_pin_and_certificate_substitution(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Vault:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    try:
        wrong_pin = "000000" if pin != "000000" else "999999"
        with pytest.raises(urllib.error.HTTPError) as wrong_pin_error:
            _pair(pairing_url, wrong_pin)
        assert wrong_pin_error.value.code == 403

        with pytest.raises(urllib.error.HTTPError) as certificate_error:
            _pair(pairing_url, pin, fingerprint_override="00" * 32)
        assert certificate_error.value.code == 403
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_sync_server_rejects_legacy_pairing_protocol(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Vault:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, _pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    ticket = urllib.parse.parse_qs(parsed.query)["ticket"][0]
    base = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    request = urllib.request.Request(
        f"{base}/api/sync/pair",
        data=json.dumps({"version": "pin-hmac-v1", "share": "invalid"}).encode("utf-8"),
        headers={PAIRING_HEADER: ticket, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=3)
        assert error.value.code == 403
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_sync_server_stop_tolerates_locked_tls_temp_file(tmp_path, monkeypatch):
    """Windows 上杀软/索引器可能占着临时文件句柄。

    ``stop()`` 里删不掉该文件时不能抛出去：那会中断整个停止流程，
    后面的传输目录清理与结果收尾都做不完。
    """
    import threading
    from pathlib import Path as _Path

    from core.sync_server import SyncServer

    server = SyncServer.__new__(SyncServer)
    server._server = None
    server._active_connections = set()
    server._active_connections_lock = threading.Lock()
    server._transfer_active_connections = {}
    server.pin = "123456"
    server.pairing_ticket = "ticket"
    server._result = None
    locked = tmp_path / "vault-sync-locked.key"
    locked.write_bytes(b"key")
    server._tls_paths = [locked]
    server._transfer_dir = tmp_path / "transfer"
    server._transfer_dir.mkdir()
    (server._transfer_dir / "payload.bin").write_bytes(b"data")

    def deny(self, missing_ok=False):
        raise PermissionError(5, "拒绝访问")

    monkeypatch.setattr(_Path, "unlink", deny)

    SyncServer.stop(server)  # 不应抛出

    assert server._tls_paths is None
    assert not server._transfer_dir.exists()
    assert server._result == "cancelled"


def test_sync_keepalive_extends_authenticated_session(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Password:
        def reveal(self):
            return "unused"

    class Vault:
        path = vault_path
        _password = Password()

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    base = f"https://{parsed.hostname}:{parsed.port}"
    context = ssl._create_unverified_context()
    try:
        headers = _auth_headers(pairing_url, pin)
        vault_request = urllib.request.Request(f"{base}/api/sync/vault", headers=headers)
        with urllib.request.urlopen(vault_request, context=context, timeout=3) as response:
            response.read()
        before = server._server.access_time
        keepalive = urllib.request.Request(f"{base}/api/sync/keepalive", headers=headers)
        with urllib.request.urlopen(keepalive, context=context, timeout=3) as response:
            assert response.status == 204
        assert server._server.access_time >= before
        assert server._server.authenticated_at is not None
        cancel = urllib.request.Request(f"{base}/api/sync/cancel", headers=headers)
        with urllib.request.urlopen(cancel, context=context, timeout=3) as response:
            assert response.status == 204
        server._thread.join(timeout=2)
        assert server._result == "cancelled"
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_sync_server_rotates_pin_after_pairing(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Vault:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    old_pin = pin
    parsed = urllib.parse.urlparse(pairing_url)
    base = f"https://{parsed.hostname}:{parsed.port}"
    try:
        token = _pair(pairing_url, old_pin)
        # 与安卓一致：配对成功后立即轮换一次性 PIN，已展示的 PIN 不再可用于新配对
        assert server.pin != old_pin
        assert server.pairing_ticket != urllib.parse.parse_qs(parsed.query)["ticket"][0]
        assert server.pin == server._server.pin
        assert len(server.pin) == 6
        assert server._server.spake_w == spake2.derive_w(server.pin, server.pairing_ticket)
        assert server.connected is True
        # 已建立的会话可正常认证
        ticket = urllib.parse.parse_qs(parsed.query)["ticket"][0]
        headers = {SESSION_HEADER: token, PAIRING_HEADER: ticket}
        keepalive = urllib.request.Request(f"{base}/api/sync/keepalive", headers=headers)
        with urllib.request.urlopen(keepalive, context=ssl._create_unverified_context(), timeout=3) as response:
            assert response.status == 204
        # 旧 PIN 和旧 ticket 都不能用于新配对。
        with pytest.raises(urllib.error.HTTPError) as second_pairing:
            _pair(pairing_url, old_pin)
        assert second_pairing.value.code == 403
        with pytest.raises(urllib.error.HTTPError):
            _pair(server.pairing_url, old_pin)
        # 当前凭据仍可为新设备建立会话。
        _pair(server.pairing_url, server.pin)
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_sync_session_uses_separate_pairing_idle_and_hard_limits():
    server = SyncServer.__new__(SyncServer)
    server._server = SimpleNamespace(started_at=1000.0, authenticated_at=None, access_time=1000.0)
    assert server._expiry_reason(1000.0 + PAIRING_TIMEOUT - 1) is None
    assert server._expiry_reason(1000.0 + PAIRING_TIMEOUT + 1) is not None

    server._server.authenticated_at = 1100.0
    server._server.access_time = 1200.0
    assert server._expiry_reason(1200.0 + ACTIVE_IDLE_TIMEOUT - 1) is None
    assert server._expiry_reason(1200.0 + ACTIVE_IDLE_TIMEOUT + 1) is not None
    server._server.access_time = 1600.0
    assert server._expiry_reason(1100.0 + ACTIVE_SESSION_TIMEOUT + 1) is not None
    assert server._expiry_reason(1000.0 + SESSION_HARD_TIMEOUT + 1) is not None


def test_transfer_session_uses_transfer_idle_and_hard_limits():
    server = SyncServer.__new__(SyncServer)
    server._transfer_active = True
    server._server = SimpleNamespace(
        started_at=1000.0,
        authenticated_at=1100.0,
        access_time=1200.0,
        transfer_active=True,
    )

    server._server.access_time = 1100.0 + ACTIVE_SESSION_TIMEOUT + 1
    assert server._expiry_reason(1100.0 + ACTIVE_SESSION_TIMEOUT + 1) is None
    server._server.access_time = 1200.0
    # 传输会话按 TRANSFER_IDLE_TIMEOUT 判活，不按 ACTIVE_IDLE_TIMEOUT
    assert server._expiry_reason(1200.0 + TRANSFER_IDLE_TIMEOUT - 1) is None
    assert server._expiry_reason(1200.0 + TRANSFER_IDLE_TIMEOUT + 1) is not None

    server._server.access_time = 2000.0
    assert server._expiry_reason(1000.0 + SESSION_HARD_TIMEOUT + 1) is None
    assert server._expiry_reason(1000.0 + TRANSFER_SESSION_HARD_TIMEOUT + 1) is not None


def test_transfer_session_streams_files_in_both_directions(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class VaultStub:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    downloads = tmp_path / "downloads"
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(sync_server, "_downloads_transfer_dir", lambda: downloads)
    downloads.mkdir()
    server = SyncServer(VaultStub(), lambda **_: True)
    outbound = tmp_path / "from-pc.bin"
    outbound.write_bytes(b"pc-to-android")
    queued = server.queue_transfer_file(outbound)
    pairing_url, pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    base = f"https://{parsed.hostname}:{parsed.port}"
    context = ssl._create_unverified_context()
    headers = _auth_headers(pairing_url, pin, op=sync_server.TRANSFER_OP)
    # Route tests start from the post-device-authenticated session state; separate
    # device-auth tests cover the approval and signature handshake.
    server._server.sessions[headers[SESSION_HEADER]]["authorized_device_id"] = uuid.uuid4()
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/api/transfer/items", headers=headers),
            context=context,
            timeout=3,
        ) as response:
            items = json.loads(response.read())["items"]
        assert items[0]["id"] == queued["id"]
        assert items[0]["name"] == "from-pc.bin"

        item_url = f"{base}/api/transfer/item?id={urllib.parse.quote(queued['id'])}"
        with urllib.request.urlopen(
            urllib.request.Request(item_url, headers=headers),
            context=context,
            timeout=3,
        ) as response:
            assert response.read() == b"pc-to-android"
        with urllib.request.urlopen(
            urllib.request.Request(item_url, headers=headers, method="DELETE"),
            context=context,
            timeout=3,
        ) as response:
            assert response.status == 204
        assert server.transfer_sent[0]["status"] == "已发送"
        assert server.transfer_sent[0]["transferred"] == len(b"pc-to-android")

        incoming = b"android-to-pc"
        encode_header = lambda value: base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")
        upload_headers = {
            **headers,
            "Content-Type": "application/octet-stream",
            "X-Vault-Transfer-Id": "11111111-2222-4333-8444-555555555555",
            "X-Vault-Transfer-Name": encode_header("手机文件.txt"),
            "X-Vault-Transfer-Mime": encode_header("text/plain"),
            "X-Vault-Transfer-Kind": "text",
            "X-Vault-Content-Sha256": hashlib.sha256(incoming).hexdigest(),
        }
        with urllib.request.urlopen(
            urllib.request.Request(
                f"{base}/api/transfer/item",
                data=incoming,
                headers=upload_headers,
                method="PUT",
            ),
            context=context,
            timeout=3,
        ) as response:
            accepted = json.loads(response.read())
        assert accepted["sha256"] == hashlib.sha256(incoming).hexdigest()
        received = server.transfer_received
        assert len(received) == 1
        assert Path(received[0]["path"]).read_bytes() == incoming
        assert received[0]["status"] == "已接收"
        assert received[0]["transferred"] == len(incoming)
        assert received[0]["preview"] == "android-to-pc"

        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/api/transfer/end", data=b"", headers=headers, method="POST"),
            context=context,
            timeout=3,
        ) as response:
            assert response.status == 204
        server._thread.join(timeout=2)
        assert server._result == {"transfer_ended": True}
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_transfer_upload_rejects_bad_sha_without_publishing_file(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class VaultStub:
        path = vault_path

    receive_dir = tmp_path / "Vaultshare"
    receive_dir.mkdir()
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(sync_server, "_downloads_transfer_dir", lambda: receive_dir)
    server = SyncServer(VaultStub(), lambda **_: True)
    pairing_url, pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    base = urllib.parse.urlunparse(parsed._replace(path="", query="", fragment=""))
    headers = _auth_headers(pairing_url, pin, op=sync_server.TRANSFER_OP)
    server._server.sessions[headers[SESSION_HEADER]]["authorized_device_id"] = uuid.uuid4()
    encode_header = lambda value: base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
    try:
        upload_headers = {
            **headers,
            "Content-Type": "application/octet-stream",
            "X-Vault-Transfer-Id": str(uuid.uuid4()),
            "X-Vault-Transfer-Name": encode_header("damaged.bin"),
            "X-Vault-Transfer-Mime": encode_header("application/octet-stream"),
            "X-Vault-Transfer-Kind": "file",
            "X-Vault-Content-Sha256": "0" * 64,
        }
        request = urllib.request.Request(
            f"{base}/api/transfer/item", data=b"actual", headers=upload_headers, method="PUT"
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=3)
        assert error.value.code == 422
        assert server.transfer_received == []
        assert not (receive_dir / "damaged.bin").exists()
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_cancel_transfer_item_removes_queued_outgoing(tmp_path):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class VaultStub:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    server = SyncServer(VaultStub(), lambda **_: True)
    outbound = tmp_path / "from-pc.bin"
    outbound.write_bytes(b"pc-to-android")
    queued = server.queue_transfer_file(outbound, temporary=True)
    try:
        # 等摘要线程释放文件句柄后再取消，避免 Windows 独占句柄导致删除失败。
        deadline = time.time() + 5
        while time.time() < deadline:
            with server._transfer_lock:
                sha = server._transfer_outgoing[queued["id"]]["sha256"]
            if len(sha) == 64:
                break
            time.sleep(0.01)
        assert server.cancel_transfer_item(queued["id"]) is True
        with server._transfer_lock:
            assert server._transfer_outgoing == {}
        assert server.transfer_sent[0]["status"] == "已取消"
        assert server.transfer_sent[0]["id"] == queued["id"]
        # 临时源文件在取消后清理
        assert not outbound.exists()
    finally:
        server.stop()


def test_cancel_transfer_item_marks_received_cancelled(tmp_path):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class VaultStub:
        path = vault_path

        def save(self, with_lock: bool = False):
            pass

    server = SyncServer(VaultStub(), lambda **_: True)
    item_id = str(uuid.uuid4())
    item = {
        "id": item_id,
        "name": "incoming.bin",
        "mime": "application/octet-stream",
        "kind": "file",
        "size": 10,
        "sha256": "",
        "path": str(tmp_path / "incoming.bin"),
        "received_at": time.time(),
        "status": "接收中",
        "transferred": 3,
    }
    with server._transfer_lock:
        server._transfer_received.append(item)
    closed: list[str] = []

    class FakeConn:
        def close(self):
            closed.append(item_id)

    server._transfer_active_connections[item_id] = FakeConn()
    try:
        assert server.cancel_transfer_item(item_id) is True
        assert item["status"] == "已取消"
        assert closed == [item_id]
        assert server.transfer_received[0]["status"] == "已取消"
        assert server.cancel_transfer_item("missing-id") is False
    finally:
        server.stop()


def test_channels_are_crypto_bound_and_endpoints_enforced(tmp_path, monkeypatch):
    """三条通道（sync/transfer/export）在配对时经 SPAKE2 AAD 绑定，端点按通道强制隔离。

    验证：
    - sync 通道可拉库/推库，但不能访问传输端点
    - transfer 通道可互传，但不能拉库/推库
    - export 通道仅可拉库，不能推库、不能互传
    - 客户端无法借已建立的会话混用其他通道（认证通过后仍需 op 匹配）
    """
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    class Password:
        def reveal(self):
            return "unused"

    class Vault:
        path = vault_path
        _password = Password()

        def save(self, with_lock: bool = False):
            pass

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "MAX_AUTH_FAILURES", 100)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = SyncServer(Vault(), lambda **_: True)
    pairing_url, pin = server.start()
    parsed = urllib.parse.urlparse(pairing_url)
    base = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
    context = ssl._create_unverified_context()
    def status(op: str, method: str, path: str) -> int:
        nonlocal pin
        current_url = server.pairing_url
        current_ticket = urllib.parse.parse_qs(urllib.parse.urlparse(current_url).query)["ticket"][0]
        # 配对成功后 PIN 与 ticket 一起轮换；新会话使用新二维码凭据，旧会话仍保留其 ticket。
        # 每次请求前重新以该通道配对，并用配对后轮换出的新 PIN 进行下一次配对。
        token = _pair(current_url, pin, op=op)
        pin = server.pin
        headers = {SESSION_HEADER: token, PAIRING_HEADER: current_ticket}
        if op == sync_server.TRANSFER_OP:
            server._server.sessions[token]["authorized_device_id"] = uuid.uuid4()
        if method == "PUT" and path == "/api/transfer/item":
            headers = {
                **headers,
                "Content-Type": "application/octet-stream",
                "X-Vault-Content-Sha256": hashlib.sha256(b"x").hexdigest(),
            }
            request = urllib.request.Request(
                f"{base}{path}", data=b"x", headers=headers, method=method,
            )
        elif method in ("PUT", "POST"):
            request = urllib.request.Request(
                f"{base}{path}", data=b"", headers=headers, method=method,
            )
        else:
            request = urllib.request.Request(f"{base}{path}", headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, context=context, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    try:
        # sync 通道：可拉库/推库（PUT 对空 body 返回 413，说明未被通道拦截），传输端点被拒
        assert status(sync_server.SYNC_OP, "GET", "/api/sync/vault") == 200
        assert status(sync_server.SYNC_OP, "PUT", "/api/sync/vault") != 403
        assert status(sync_server.SYNC_OP, "GET", "/api/transfer/items") == 403
        assert status(sync_server.SYNC_OP, "GET", "/api/transfer/item") == 403
        assert status(sync_server.SYNC_OP, "PUT", "/api/transfer/item") == 403

        # transfer 通道：可互传，拉库/推库被拒
        assert status(sync_server.TRANSFER_OP, "GET", "/api/transfer/items") == 200
        assert status(sync_server.TRANSFER_OP, "GET", "/api/sync/vault") == 403
        assert status(sync_server.TRANSFER_OP, "PUT", "/api/sync/vault") == 403

        # export 通道：仅拉库且必须由主机逐次批准；未经批准返回 423
        assert status(sync_server.EXPORT_OP, "GET", "/api/sync/vault") == 423
        assert status(sync_server.EXPORT_OP, "PUT", "/api/sync/vault") == 403
        assert status(sync_server.EXPORT_OP, "GET", "/api/transfer/items") == 403
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_export_channel_waits_for_host_approval_and_downloads_full_vault(tmp_path, monkeypatch):
    """二维码通吃：传输站二维码 + 导出通道 = 整库导出；主机批准后客户端才能下载。"""
    import threading as _threading
    import time as _time
    import uuid as _uuid

    from core import device_identity
    from core.sync_client import EXPORT_OP, LanSyncClient

    vault_path = tmp_path / "vault.pmv"
    Vault.create_pmve(vault_path, "correct horse battery staple", RECOVERY_SECRET).close()
    vault = Vault.open(vault_path, "correct horse battery staple")

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(device_identity, "default_vault_path", lambda: tmp_path / "device.pmv")
    server = SyncServer(vault, lambda **_: True)
    server.device_auth_enabled = True
    url, pin = server.start()
    approved = {"v": False}

    def watcher() -> None:
        deadline = _time.time() + 20
        while _time.time() < deadline and not approved["v"]:
            if getattr(server._server, "pending_export_device", None) is not None:
                assert server.approve_export() is True
                approved["v"] = True
                return
            _time.sleep(0.05)

    thread = _threading.Thread(target=watcher, daemon=True)
    thread.start()
    try:
        client = LanSyncClient(url, pin, op=EXPORT_OP)
        client.authenticate_device(
            _uuid.UUID(int=0),
            device_identity.load_or_create(_uuid.UUID(int=0)),
        )
        target = tmp_path / "downloaded.pmv"
        client.download_vault(target)
        assert target.read_bytes() == vault_path.read_bytes()
        assert approved["v"] is True
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        vault.close()


def test_transfer_name_is_sanitized_against_path_traversal():
    """上传文件名中的目录穿越/非法字符必须被清理，落盘路径始终位于接收目录内。"""
    from core.sync_server import _safe_transfer_name

    assert _safe_transfer_name("../../evil.txt") == "evil.txt"
    assert _safe_transfer_name("a/b\\c:*.txt") == "c__.txt"
    assert _safe_transfer_name("a\\..\\..\\x") == "x"
    assert _safe_transfer_name("\x00evil") == "_evil"
    assert _safe_transfer_name("   ") == "received.bin"
