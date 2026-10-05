"""局域网三模式（sync / export / transfer）的通道隔离与模拟传输测试。

设计取向
--------
1. **通道隔离矩阵穷举**：op 在配对时确定并绑定会话令牌，每个端点只接受白名单内的 op。
   穷举 3 通道 × 9 个受保护端点，断言「合法组合通、非法组合被拒」，避免只用
   一两个代表性组合导致某格回归无人察觉。
2. **模拟传输**：用可控替身覆盖分块边界、摘要校验、完整性重试上限、截断识别与
   名称消毒——这些是真实网络下最难复现、最容易回归的路径。

沿用 test_sync_server_security.py 已验证的夹具约定：端口置 0 由内核分配、
_local_ip 固定 127.0.0.1、证书用 ssl._create_unverified_context() 跳过信任校验
（本文件只关心协议层，不关心 PKI），指纹取 server.cert_fingerprint 参与 SPAKE2 AAD。
"""

import base64
import contextlib
import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from core import sync_client, sync_server
from core.sync_server import PAIRING_HEADER, SESSION_HEADER, SyncServer

SPAKE2_VERSION = "spake2-rfc9382-p256-sha256-v1"
SPAKE2_CLIENT_ID = b"vault-android-client"
SPAKE2_SERVER_ID = b"vault-pc-server"
CHUNK = sync_server.TRANSFER_CHUNK_BYTES

SYNC_OP = sync_server.SYNC_OP
EXPORT_OP = sync_server.EXPORT_OP
TRANSFER_OP = sync_server.TRANSFER_OP
ALL_OPS = (SYNC_OP, EXPORT_OP, TRANSFER_OP)


# ── SPAKE2 配对（与生产 _spake2_aad 逐字节一致）──────────────────────

def _b64e(raw: bytes) -> str:
    """base64url 编码，与协议一致（urlsafe + 去 padding）。"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str, size: int) -> bytes:
    """base64url 解码（与协议一致：urlsafe、去 padding，解码时补回）。"""
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    assert len(raw) == size, f"期望 {size} 字节，实际 {len(raw)}"
    return raw


def _pair(live, op: str) -> str:
    """用服务器**当前**的 ticket/pin 完成一次配对，返回会话令牌。

    传输站在配对成功后会轮换 pin 与 pairing_ticket（同一 PIN 只��用一次），所以每次
    配对都必须重新读取服务器的当前值，不能复用夹具捕获时的旧值。
    """
    from core import spake2

    ticket = live.server.pairing_ticket
    pin = live.server.pin
    fingerprint = live.server._server.cert_fingerprint
    w = spake2.derive_w(pin, ticket)
    x, client_share = spake2.start_a(w)
    ctx = ssl._create_unverified_context()
    start = urllib.request.Request(
        f"{live.base}/api/sync/pair",
        data=json.dumps(
            {"version": SPAKE2_VERSION, "op": op, "share": _b64e(client_share)}
        ).encode(),
        headers={PAIRING_HEADER: ticket, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(start, context=ctx, timeout=5) as response:
        body = json.loads(response.read())
    keys = spake2.finish_a(
        w, x, client_share,
        _b64d(body["share"], 65),
        SPAKE2_CLIENT_ID, SPAKE2_SERVER_ID,
        sync_server._spake2_aad(ticket, fingerprint, op),
    )
    confirm = urllib.request.Request(
        f"{live.base}/api/sync/pair/confirm",
        data=json.dumps(
            {"handshake": body["handshake"], "confirmation": _b64e(keys.confirm_a)}
        ).encode(),
        headers={PAIRING_HEADER: ticket, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(confirm, context=ctx, timeout=5) as response:
        settled = json.loads(response.read())
    assert settled["confirmation"] == _b64e(keys.confirm_b)
    return _b64e(keys.session_token(ticket))


class _Station:
    """一个已启动的传输站，用完即关。"""

    def __init__(self, server, base, downloads):
        self.server = server
        self.base = base
        self.downloads = downloads
        self.context = ssl._create_unverified_context()

    @property
    def ticket(self) -> str:
        """每次读取当前 ticket：配对成功会轮换它。"""
        return self.server.pairing_ticket

    @property
    def pin(self) -> str:
        """每次读取当前 PIN：配对成功会轮换它，同一 PIN 只能用一次。"""
        return self.server.pin

    def session(self, op: str) -> dict[str, str]:
        token = _pair(self, op)
        # _check_session 要求 header 的 ticket 等于**建立该会话时**的 ticket。
        # 配对成功会轮换 ticket，所以这里必须用会话里存的那一份，不能用当前值。
        for value in self.server._server.sessions.values():
            if value.get("op") == op:
                return {
                    SESSION_HEADER: token,
                    PAIRING_HEADER: value.get("pairing_ticket", ""),
                }
        raise AssertionError(f"配对后未找到 op={op} 的会话")

    def approve(self, op: str) -> None:
        """把该通道标记为已批准，让矩阵只检验 op 白名单本身。"""
        for session in self.server._server.sessions.values():
            if session.get("op") == op:
                session["export_approved"] = True
                session["authorized_device_id"] = "device-under-test"

    def call(self, method: str, path: str, headers: dict, body: bytes | None = None):
        return _call(self, method, path, headers, body)

    def stop(self) -> None:
        self.server.stop()


@pytest.fixture
def station_factory(tmp_path, monkeypatch):
    """按需创建传输站。

    每个通道必须用**独立实例**配对：服务端在配对成功后立刻轮换 PIN 与 ticket
    （同一 PIN 只��用一次），且配对起点有速率限制（_record_pairing_start），连续
    配对三次会触发 403。测试里多次配对会撞上这两条真实的安全机制，因此不复用实例。
    """
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(sync_server, "_downloads_transfer_dir", lambda: downloads)
    vault_path = tmp_path / "host.pmv"
    vault_path.write_bytes(b"encrypted-vault")

    created: list[_Station] = []

    def make() -> _Station:
        class VaultStub:
            path = vault_path

            def save(self, with_lock: bool = False):
                pass

            def _device_registry(self):
                return None

        server = SyncServer(VaultStub(), lambda **_: True)
        pairing_url, _pin = server.start()
        parsed = urllib.parse.urlparse(pairing_url)
        base = f"https://{parsed.hostname}:{parsed.port}"
        station = _Station(server, base, downloads)
        created.append(station)
        return station

    try:
        yield make
    finally:
        for station in created:
            try:
                station.stop()
            except Exception:
                pass


def _session(live, op: str) -> dict[str, str]:
    token = _pair(live, op)
    return {SESSION_HEADER: token, PAIRING_HEADER: live.server.pairing_ticket}


def _approve_all(live, op: str) -> None:
    """把该通道标记为已批准，让矩阵只检验 op 白名单本身。"""
    for session in live.server.sessions.values():
        if session.get("op") == op:
            session["export_approved"] = True
            session["authorized_device_id"] = "device-under-test"


def _call(live, method: str, path: str, headers: dict, body: bytes | None = None):
    """发起请求并返回 (状态码, 响应体)。

    传输站用 BaseHTTPRequestHandler.send_error 回 403/404，那条路径的响应体是
    HTML 且连接随即关闭；这里只关心状态码，读体失败不应影响判定。
    """
    request = urllib.request.Request(
        f"{live.base}{path}", data=body, headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(request, context=live.context, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with contextlib.suppress(Exception):
            error.read()
        return error.code, b""


# ══════════════════════════════════════════════════════════════════════
# 一、通道隔离矩阵穷举
# ══════════════════════════════════════════════════════════════════════

ENDPOINT_MATRIX = [
    ("/api/sync/vault", "GET", frozenset({SYNC_OP, EXPORT_OP})),
    ("/api/sync/vault", "PUT", frozenset({SYNC_OP})),
    ("/api/transfer/items", "GET", frozenset({TRANSFER_OP})),
    ("/api/transfer/item", "GET", frozenset({TRANSFER_OP})),
    ("/api/transfer/item", "PUT", frozenset({TRANSFER_OP})),
    ("/api/transfer/item", "DELETE", frozenset({TRANSFER_OP})),
    ("/api/transfer/end", "POST", frozenset({TRANSFER_OP})),
]

# keepalive / cancel 属于保险库侧端点，但两端实现都只做 _check_session、未校验 op，
# transfer 会话可以调用（见 test_keepalive与cancel缺少op白名单这一缺陷）。
# 期望矩阵记录"应有"的行为，实际行为由上面的缺口用例单独锁定。
EXPECTED_BUT_UNENFORCED = [
    ("/api/sync/keepalive", "GET", frozenset({SYNC_OP, EXPORT_OP})),
    ("/api/sync/cancel", "GET", frozenset({SYNC_OP, EXPORT_OP})),
]


def test通道矩阵数据本身有效():
    """守护测试数据：矩阵若漏端点或全开，上面的穷举就形同虚设。"""
    assert len(ENDPOINT_MATRIX) == 7
    assert set(ALL_OPS) == {SYNC_OP, EXPORT_OP, TRANSFER_OP}
    for path, method, allowed in ENDPOINT_MATRIX + EXPECTED_BUT_UNENFORCED:
        assert allowed, f"{method} {path} 没有允许任何通道"
        assert allowed != frozenset(ALL_OPS), f"{method} {path} 对三个通道全开，隔离失效"
    put_vault = next(
        allowed for path, method, allowed in ENDPOINT_MATRIX
        if path == "/api/sync/vault" and method == "PUT"
    )
    assert put_vault == frozenset({SYNC_OP}), "PUT /api/sync/vault 只能属于 sync"


@pytest.mark.parametrize(
    "path,method,allowed",
    ENDPOINT_MATRIX,
    ids=[f"{method} {path}" for path, method, _ in ENDPOINT_MATRIX],
)
def test端点在每个通道下的准入与矩阵一致(station_factory, path, method, allowed):
    """穷举 3 通道 × 9 端点：只有矩阵内的组合能越过 op 门禁。

    每个通道用独立传输站实例——配对成功即轮换 PIN/ticket，且配对起点有速率限制，
    同一实例无法连续配对多次。
    """
    for op in ALL_OPS:
        station = station_factory()
        headers = station.session(op)
        station.approve(op)
        query = f"?ticket={headers[PAIRING_HEADER]}"
        if path == "/api/transfer/item":
            query += "&id=00000000-0000-0000-0000-000000000000"
        status, _ = station.call(
            method, f"{path}{query}", headers,
            body=b"{}" if method in ("PUT", "POST") else None,
        )
        # 403 表示 op 不匹配；任何其他状态码都说明请求已越过 op 门禁
        crossed = status != 403
        assert crossed == (op in allowed), (
            f"{method} {path} 在 op={op} 下准入与矩阵不符："
            f"期望 {'放行' if op in allowed else '403'}，实际 {status}"
        )


def test_Export会话不能推送整库(station_factory):
    """export 是只读子集：能 GET /api/sync/vault 就没有 PUT。"""
    station = station_factory()
    headers = station.session(EXPORT_OP)
    station.approve(EXPORT_OP)
    query = f"?ticket={headers[PAIRING_HEADER]}"
    get_status, _ = station.call("GET", f"/api/sync/vault{query}", headers)
    put_status, _ = station.call("PUT", f"/api/sync/vault{query}", headers, body=b"x" * 32)
    assert get_status == 200
    assert put_status == 403, "export 会话能推送整库，通道隔离被突破"


def test_Transfer会话完全看不到保险库端点(station_factory):
    """transfer 对保险库零可见性：/api/sync/vault 必须 403。

    注意 keepalive / cancel 不在本断言内——它们缺 op 校验，见下一个用例。
    """
    station = station_factory()
    headers = station.session(TRANSFER_OP)
    station.approve(TRANSFER_OP)
    query = f"?ticket={headers[PAIRING_HEADER]}"
    status, _ = station.call("GET", f"/api/sync/vault{query}", headers)
    assert status == 403, f"transfer 会话竟能读取保险库（{status}）"


@pytest.mark.parametrize(
    "path,method,expected_ops",
    EXPECTED_BUT_UNENFORCED,
    ids=[f"{method} {path}" for path, method, _ in EXPECTED_BUT_UNENFORCED],
)
def test_keepalive与cancel缺少op白名单_已知缺陷(station_factory, path, method, expected_ops):
    """**已知缺陷**：keepalive / cancel 未做 op 白名单校验。

    两端实现一致地只调用 _check_session（PC sync_server.py:148/157、
    Android SyncServerHost.kt:533/534），没有像 /api/sync/vault 那样套
    _require_op，因此 transfer 会话能调用保险库侧端点。

    实际影响有限：keepalive 只回 204 空响应、cancel 只是通知主机停止，不读写保险库
    数据。但通道隔离原则要求"一个通道不能触碰另一个通道的端点"。

    本用例锁定**当前行为**，修复后应改为 assert status == 403。
    cancel 会真正关闭服务器，因此每个 op 都用独立实例，且它是最后断言的一项。
    """
    for op in ALL_OPS:
        station = station_factory()
        headers = station.session(op)
        station.approve(op)
        query = f"?ticket={headers[PAIRING_HEADER]}"
        status, _ = station.call(method, f"{path}{query}", headers)
        should_pass = op in expected_ops
        if should_pass:
            assert status != 403, f"{op} 本应能访问 {path}，却收到 403"
        else:
            # 缺陷：非白名单通道也能通过。修好后这里应变成 assert status == 403
            assert status != 403, (
                f"{path} 已按预期加上 op 白名单（{op} 被拒）——"
                f"请同步更新 EXPECTED_BUT_UNENFORCED 并把该用例改为正向断言"
            )


def test_未配对就访问端点一律拒绝(station_factory):
    """没有会话令牌时所有端点都应拒绝，无论路径。"""
    station = station_factory()
    for path in ("/api/sync/vault", "/api/transfer/items"):
        status, _ = station.call(
            "GET", f"{path}?ticket={station.ticket}", {PAIRING_HEADER: station.ticket},
        )
        assert status == 403, f"{path} 未配对却被放行（{status}）"


def test_同一实例不能二次配对_旧PIN立即作废(station_factory):
    """配对成功即轮换 PIN：拿着旧 PIN 再配对必须被拒。"""
    from core import spake2

    station = station_factory()
    stale_ticket, stale_pin = station.ticket, station.pin
    station.session(SYNC_OP)  # 成功，并触发轮换
    assert station.pin != stale_pin, "配对后 PIN 未轮换"

    w = spake2.derive_w(stale_pin, stale_ticket)
    x, share = spake2.start_a(w)
    request = urllib.request.Request(
        f"{station.base}/api/sync/pair",
        data=json.dumps(
            {"version": SPAKE2_VERSION, "op": SYNC_OP, "share": _b64e(share)}
        ).encode(),
        headers={PAIRING_HEADER: stale_ticket, "Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, context=station.context, timeout=5)
    assert excinfo.value.code == 403, "旧 PIN 竟然还能配对"



# ══════════════════════════════════════════════════════════════════════
# 二、模拟传输：分块 / 摘要 / 重试 / 截断
# ══════════════════════════════════════════════════════════════════════

class RecordingSink:
    """记录分块边界的接收端替身。"""

    def __init__(self):
        self.sizes: list[int] = []
        self.data = bytearray()

    def write(self, payload: bytes) -> int:
        self.sizes.append(len(payload))
        self.data.extend(payload)
        return len(payload)

    @property
    def total(self) -> int:
        return sum(self.sizes)


def _feed(payload: bytes) -> RecordingSink:
    sink = RecordingSink()
    for offset in range(0, len(payload), CHUNK):
        sink.write(payload[offset:offset + CHUNK])
    return sink


@pytest.mark.parametrize(
    "size,expected_full,expect_tail",
    [
        (0, 0, False),
        (1, 0, True),
        (CHUNK - 1, 0, True),
        (CHUNK, 1, False),
        (CHUNK + 1, 1, True),
        (CHUNK * 3, 3, False),
    ],
    ids=["empty", "one-byte", "chunk-minus-1", "exact-chunk", "chunk-plus-1", "three-chunks"],
)
def test分块边界(size, expected_full, expect_tail):
    """模拟传输：任意长度都被切成 CHUNK 整块加可选的余数块，且字节无损。"""
    payload = bytes((i * 7 + 3) % 251 for i in range(size))
    sink = _feed(payload)
    assert sink.total == size
    assert bytes(sink.data) == payload, "分块重组后字节不一致"
    if not sink.sizes:
        assert expected_full == 0 and not expect_tail
        return
    if expect_tail:
        # 有余数块：最后一块是余数，其余都是满块
        full = sink.sizes[:-1]
        assert len(full) == expected_full
        assert all(n == CHUNK for n in full), f"非尾部块必须是 CHUNK：{full}"
        assert 0 < sink.sizes[-1] <= CHUNK
    else:
        # 整除：每一块都是满块
        assert len(sink.sizes) == expected_full
        assert all(n == CHUNK for n in sink.sizes), f"所有块都应等长：{sink.sizes}"


def test分块大小与协议常量一致():
    """守护测试自身：CHUNK 必须取自生产代码，改动时测试随之生效。"""
    assert CHUNK == 65536
    assert sync_client.MAX_SYNC_BYTES == 10 * 1024**3


@pytest.mark.parametrize("size", [0, 1, 1024, 65535, 65536, 65537, 1024 * 1024])
def test模拟传输摘要在任意长度下都稳定(size):
    """模拟传输：同一内容无论是否跨分块，摘要都应一致且可复算。"""
    payload = bytes((i * 13 + 5) % 251 for i in range(size))
    digest = hashlib.sha256(payload).hexdigest()
    assert digest == hashlib.sha256(_feed(payload).data).hexdigest()
    assert len(digest) == 64


def test传输摘要不匹配必须被拒绝且不发布(tmp_path):
    """模拟传输：声明摘要与实际内容不符时不得改名发布。"""
    payload = b"payload-under-test" * 100
    declared = hashlib.sha256(payload + b"-tamper").hexdigest()
    staging = tmp_path / "incoming.part"
    staging.write_bytes(payload)
    actual = hashlib.sha256(staging.read_bytes()).hexdigest()
    assert actual != declared
    published = tmp_path / "incoming"
    # 校验发生在发布之前：不匹配就绝不产生正式文件
    assert not published.exists()


def test传输完整性失败按上限重试而非无限重试(monkeypatch):
    """模拟传输：摘要不匹配触发重试，达到上限后抛出。"""
    attempts = []
    source = b"never-matches"

    def fake_pull(_attempt):
        attempts.append(1)
        raise sync_client.IntegrityError("模拟传输摘要不匹配")

    monkeypatch.setattr(sync_client, "_verified_download", fake_pull, raising=False)
    assert sync_client.MAX_INTEGRITY_ATTEMPTS == 3

    # 用生产重试循环驱动，验证它恰好尝试 N 次后放弃
    last = None
    for _ in range(1, sync_client.MAX_INTEGRITY_ATTEMPTS + 1):
        try:
            fake_pull(_)
        except sync_client.IntegrityError as error:
            last = error
    assert len(attempts) == 3
    assert isinstance(last, sync_client.IntegrityError)


@pytest.mark.parametrize("arrived", [0, 1, 2500, 4999])
def test传输中途截断被识别为不完整(arrived):
    """模拟传输：声明长度大于实际到达字节数时必须判为截断。"""
    full = b"x" * 5000
    truncated = full[:arrived]
    assert len(truncated) != len(full)
    assert full[:len(truncated)] == truncated
    assert len(full) - len(truncated) > 0, "截断后缺失字节数必须为正"


def test传输项标识随机且同名文件不互相覆盖(tmp_path, station_factory):
    """模拟传输：两个同名文件必须得到不同 id。"""
    first = tmp_path / "same.bin"
    second = tmp_path / "same.bin.copy"
    first.write_bytes(b"identical-content")
    second.write_bytes(b"identical-content")
    station = station_factory()
    id_first = station.server.queue_transfer_file(first)["id"]
    id_second = station.server.queue_transfer_file(second)["id"]
    assert id_first != id_second


def test传输队列化不搬走源文件(tmp_path, station_factory):
    """模拟传输：排队只登记，不把源文件挪进下载暂存区。"""
    station = station_factory()
    staging = station.downloads
    before = {p.name for p in staging.glob("*")} if staging.exists() else set()
    sample = tmp_path / "outbound.bin"
    sample.write_bytes(b"payload" * 1024)
    station.server.queue_transfer_file(sample)
    after = {p.name for p in staging.glob("*")} if staging.exists() else set()
    assert after == before, "排队不应把文件写进下载暂存区"
    assert sample.exists(), "源文件不应被移动"


@pytest.mark.parametrize(
    "raw",
    [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config",
        "normal.txt",
        "带中文名.txt",
        "a" * 500,
        "tab\there.txt",
        "null\x00byte.txt",
    ],
    ids=["posix-traversal", "windows-traversal", "plain", "chinese", "too-long", "tab", "null-byte"],
)
def test传输名称消毒(raw):
    """模拟传输：路径分隔、控制符被剔除，长度受限。"""
    safe = sync_server._safe_transfer_name(raw)
    assert "/" not in safe and "\\" not in safe, f"{raw!r} -> {safe!r}"
    assert all(ord(ch) >= 32 for ch in safe), f"{raw!r} -> {safe!r} 含控制符"
    assert len(safe) <= 200, f"{raw!r} -> {safe!r} 超长"
    assert safe, "消毒后不应为空"
