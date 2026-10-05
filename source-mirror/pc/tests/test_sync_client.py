"""sync_client.LanSyncClient ↔ sync_server.SyncServer 协议兼容测试。

同步客户端与传输站（主机）使用同一 SPAKE2/HTTPS 协议；这些测试用真实
SyncServer 作为对端，验证客户端配对、拉库、传输上传/下载/确认、结束。
安卓端 SyncServerHost 与 SyncServer 协议逐字对齐，因此这些测试同样约束安卓主机的行为。
"""

import hashlib
import io
import json
from pathlib import Path
import threading
import time

import pytest

from core import sync_server
from core.sync_client import IntegrityError, LanSyncClient, PinValidationError, SyncError


def _wait_for_transfer_offer(client: LanSyncClient, name: str, timeout: float = 2.0) -> dict:
    """Wait for the server's asynchronous SHA-256 preparation, not a guessed delay."""
    deadline = time.monotonic() + timeout
    while True:
        offer = next((item for item in client.list_transfer_items() if item.get("name") == name), None)
        if offer is not None:
            return offer
        if time.monotonic() >= deadline:
            pytest.fail(f"transfer offer {name!r} did not become ready within {timeout:.1f}s")
        time.sleep(0.01)


def _make_server(tmp_path, monkeypatch, vault_bytes: bytes = b"encrypted-vault", receive_dir: Path | None = None):
    vault_path = tmp_path / "test.pmv"
    vault_path.write_bytes(vault_bytes)

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
    if receive_dir is not None:
        monkeypatch.setattr(sync_server, "_downloads_transfer_dir", lambda: receive_dir)
    server = sync_server.SyncServer(Vault(), lambda **_: True)
    return server


def _prepare_transfer_authorization(server, tmp_path, monkeypatch):
    """Exercise the real device challenge, rather than bypassing the transfer gate."""
    from core import device_identity
    from core.storage import Vault

    monkeypatch.setattr(device_identity, "default_vault_path", lambda: tmp_path / "default.pmv")
    vault = Vault.create_pmve(
        tmp_path / "transfer.pmv", "correct horse battery staple", bytes(range(32)),
    )
    vault.ensure_device_authorized()
    server.vault = vault
    server.vault_cls = type(vault)
    server.device_auth_enabled = True
    return device_identity.load_or_create(vault.vault_identity.vault_id)


def test_client_pairs_and_pulls_vault(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    try:
        client = LanSyncClient(pairing_url, pin)
        assert client.ticket
        target = tmp_path / "pulled.pmv"
        client._pull_vault_file(target)
        assert target.read_bytes() == b"encrypted-vault"
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_client_hashes_and_pushes_one_open_vault_snapshot(tmp_path, monkeypatch):
    vault_path = tmp_path / "test.pmv"
    original = b"authenticated-vault-snapshot"
    replacement = original[::-1]
    vault_path.write_bytes(original)

    class Vault:
        path = vault_path

    class Response:
        status = 204

        @staticmethod
        def read(_limit=None):
            return b""

    class Connection:
        def __init__(self):
            self.headers = {}
            self.sent = bytearray()

        def putrequest(self, *_args):
            pass

        def putheader(self, name, value):
            self.headers[name] = value

        def endheaders(self):
            pass

        def send(self, chunk):
            self.sent.extend(chunk)

        def getresponse(self):
            return Response()

        def close(self):
            pass

    client = object.__new__(LanSyncClient)
    connection = Connection()
    monkeypatch.setattr(client, "_connect", lambda _path: connection)
    monkeypatch.setattr(client, "_check_pinned", lambda _conn: None)
    monkeypatch.setattr(client, "_headers", lambda headers=None: headers or {})
    real_open = Path.open
    opens = 0

    def open_snapshot(path, mode="r", *args, **kwargs):
        nonlocal opens
        if path == vault_path and mode == "rb":
            opens += 1
            return io.BytesIO(original if opens == 1 else replacement)
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_snapshot)
    client._push_vault_file_once(Vault())

    assert opens == 1
    assert bytes(connection.sent) == original
    assert connection.headers["X-Vault-Content-Sha256"] == hashlib.sha256(original).hexdigest()


def test_client_rejects_wrong_pin(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    pairing_url, _pin = server.start()
    try:
        with pytest.raises(PinValidationError):
            LanSyncClient(pairing_url, "000000")
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_client_rejects_bad_ticket(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    try:
        bad_url = pairing_url.replace("ticket=", "ticket=short")
        with pytest.raises(SyncError):
            LanSyncClient(bad_url, pin)
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_client_uploads_and_downloads_transfer_file(tmp_path, monkeypatch):
    receive_dir = tmp_path / "Vaultshare"
    receive_dir.mkdir()
    server = _make_server(tmp_path, monkeypatch, receive_dir=receive_dir)
    identity = _prepare_transfer_authorization(server, tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    try:
        client = LanSyncClient(pairing_url, pin, op=sync_server.TRANSFER_OP)
        client.authenticate_device(server.vault.vault_identity.vault_id, identity)

        source = tmp_path / "hello.txt"
        source.write_bytes(b"hello transfer")
        sent = client.upload_transfer_file(source)
        assert sent["name"] == "hello.txt"
        assert server.transfer_received and server.transfer_received[0]["size"] == len(b"hello transfer")

        # 服务端排队一个文件，客户端列出并下载
        outgoing = tmp_path / "server-file.bin"
        outgoing.write_bytes(b"server says hi")
        server.queue_transfer_file(outgoing)
        offer = _wait_for_transfer_offer(client, "server-file.bin")
        offers = client.list_transfer_items()
        assert all(item["id"] != sent["id"] for item in offers)  # 客户端上传的项在服务端是「已接收」，不出现在出站队列
        target = tmp_path / "downloaded.bin"
        client.download_transfer_item(offer, target)
        assert target.read_bytes() == b"server says hi"

        client.acknowledge_transfer_item(offer["id"])
        remaining = client.list_transfer_items()
        assert not any(item["id"] == offer["id"] for item in remaining)
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_transfer_channel_pairing_consumes_pin_after_connection(tmp_path, monkeypatch):
    """与安卓一致：任一配对都会消耗当前一次性 PIN；sync 先配对后，
    再用旧 PIN 建立 transfer 二次配对必然失败。"""
    server = _make_server(tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    try:
        sync_client = LanSyncClient(pairing_url, pin, op=sync_server.SYNC_OP)
        # sync 通道先配对并拉库，消耗当前一次性 PIN
        pulled = tmp_path / "after-transfer-pairing.pmv"
        sync_client._pull_vault_file(pulled)
        assert pulled.read_bytes() == b"encrypted-vault"
        # 旧 PIN 已失效：transfer 客户端用同一 PIN 配对失败
        with pytest.raises(SyncError):
            LanSyncClient(pairing_url, pin, op=sync_server.TRANSFER_OP)
        assert server._transfer_active is False
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_client_ends_transfer(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    identity = _prepare_transfer_authorization(server, tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    try:
        client = LanSyncClient(pairing_url, pin, op=sync_server.TRANSFER_OP)
        client.authenticate_device(server.vault.vault_identity.vault_id, identity)
        client.end_transfer()
        assert server._result == {"transfer_ended": True}
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_server_close_active_connections_aborts_inflight_upload(tmp_path, monkeypatch):
    server = _make_server(tmp_path, monkeypatch)
    identity = _prepare_transfer_authorization(server, tmp_path, monkeypatch)
    pairing_url, pin = server.start()
    result: dict = {}
    try:
        client = LanSyncClient(pairing_url, pin, op=sync_server.TRANSFER_OP)
        client.authenticate_device(server.vault.vault_identity.vault_id, identity)
        payload = tmp_path / "big.bin"
        payload.write_bytes(b"x" * (64 * 1024 * 1024))

        def upload():
            try:
                client.upload_transfer_file(payload)
                result["ok"] = True
            except Exception as exc:  # noqa: BLE001
                result["error"] = str(exc)

        thread = threading.Thread(target=upload, daemon=True)
        thread.start()
        deadline = time.time() + 20
        while not server._active_connections and time.time() < deadline:
            time.sleep(0.005)
        assert server._active_connections  # 上传进行中已注册活动连接
        server.close_active_connections()
        thread.join(timeout=8)
        # 在途上传被立即中止，而不是等服务端收尾
        assert "error" in result
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)


def test_download_retries_integrity_failure_then_succeeds(tmp_path, monkeypatch):
    client = object.__new__(LanSyncClient)
    target = tmp_path / "received.bin"
    attempts = []
    retries = []

    def receive_once(_item, output, on_progress=None, transfer_key=None):
        attempts.append(1)
        if len(attempts) < 3:
            output.write_bytes(b"damaged")
            raise IntegrityError("校验失败")
        output.write_bytes(b"verified")

    monkeypatch.setattr(client, "_download_transfer_item_once", receive_once)
    client.download_transfer_item(
        {"id": "item"}, target,
        on_retry=lambda attempt, maximum: retries.append((attempt, maximum)),
    )

    assert target.read_bytes() == b"verified"
    assert len(attempts) == 3
    assert retries == [(2, 3), (3, 3)]


def test_abort_transfer_closes_only_target_connection():
    client = object.__new__(LanSyncClient)
    client._inflight = {}
    client._inflight_lock = threading.Lock()
    closed: list[str] = []

    class FakeConn:
        def __init__(self, name: str):
            self.name = name

        def close(self):
            closed.append(self.name)

    client._track_connection("a", FakeConn("a"))
    client._track_connection("b", FakeConn("b"))
    client.abort_transfer("a")
    assert closed == ["a"]
    assert list(client._inflight.keys()) == ["b"]
    client.abort_all_transfers()
    assert closed == ["a", "b"]
    assert client._inflight == {}


def test_cancel_and_end_transfer_abort_all_inflight_before_notifying(monkeypatch):
    client = object.__new__(LanSyncClient)
    client._inflight = {}
    client._inflight_lock = threading.Lock()
    closed = []

    class FakeConn:
        def close(self):
            closed.append(True)

    def _raise_on_use():
        raise AssertionError("连接已中止，不应再发起通知请求")

    client._track_connection("a", FakeConn())
    client._track_connection("b", FakeConn())
    # cancel / end_transfer 必须先中止在途连接，避免安卓端继续传输。
    monkeypatch.setattr(client, "_connect", lambda _path: _raise_on_use())
    monkeypatch.setattr(client, "_check_pinned", lambda _conn: None)
    monkeypatch.setattr(client, "_headers", lambda **_: {})

    # end_transfer 先 abort_all_transfers，再尝试通知（通知请求本身会失败，但中止已生效）
    try:
        client.end_transfer()
    except Exception:
        pass
    assert closed == [True, True]
    assert client._inflight == {}

    # cancel 同样先中止在途连接
    closed.clear()
    client._track_connection("c", FakeConn())
    try:
        client.cancel()
    except Exception:
        pass
    assert closed == [True]
    assert client._inflight == {}


def test_upload_retries_integrity_failure_then_succeeds(tmp_path, monkeypatch):
    client = object.__new__(LanSyncClient)
    source = tmp_path / "send.bin"
    source.write_bytes(b"verified")
    attempts = []
    retries = []

    def send_once(*_args, **_kwargs):
        attempts.append(1)
        if len(attempts) < 3:
            raise IntegrityError("校验失败")
        return {"id": "item", "sha256": "ok"}

    monkeypatch.setattr(client, "_upload_transfer_file_once", send_once)
    result = client.upload_transfer_file(
        source,
        on_retry=lambda attempt, maximum: retries.append((attempt, maximum)),
    )

    assert result["id"] == "item"
    assert len(attempts) == 3
    assert retries == [(2, 3), (3, 3)]


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.2:18765/api/sync/vault?ticket=abcdefghijkl&pin=123456",
        "https://user@192.168.1.2:18765/api/sync/vault?ticket=abcdefghijkl&pin=123456",
        "https://example.com:18765/api/sync/vault?ticket=abcdefghijkl&pin=123456",
        "https://8.8.8.8:18765/api/sync/vault?ticket=abcdefghijkl&pin=123456",
        "https://192.168.1.2:18765/api/sync/vault?ticket=one&ticket=two&pin=123456",
    ],
)
def test_client_rejects_unsafe_or_ambiguous_station_url(url):
    with pytest.raises(SyncError):
        LanSyncClient(url, "123456")
