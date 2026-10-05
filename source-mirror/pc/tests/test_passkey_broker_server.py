import json
import struct
import uuid
from pathlib import Path

from core.passkey_broker import PasskeyBroker, VerifiedPeer
from core.passkey_broker_protocol import encode_frame
from core.passkey_broker_server import (
    ConnectionHandler,
    ProcessIdentity,
    pipe_name_for_sid,
    validate_provider_identity,
)
from core.passkey_service import PasskeyService


PEER = VerifiedPeer(7, "S-1-5-21-test", "FAE.Vault.PasskeyProvider_abcd", "provider.exe", "thumb")


def unpack(frame):
    size = struct.unpack_from("<I", frame)[0]
    return json.loads(frame[4:4 + size])


def test_pipe_name_is_stable_without_exposing_sid():
    first = pipe_name_for_sid("S-1-5-21-100")
    assert first == pipe_name_for_sid("S-1-5-21-100")
    assert first != pipe_name_for_sid("S-1-5-21-101")
    assert "S-1-5" not in first


def test_provider_identity_requires_pinned_package_and_installed_binary(tmp_path, monkeypatch):
    root = tmp_path / "package"
    root.mkdir()
    executable = root / "PasskeyManager.exe"
    executable.write_bytes(b"MZ")
    valid = ProcessIdentity(
        1,
        str(executable),
        "FAE.Vault.PasskeyProvider_74rz453p8683c",
    )
    # WindowsApps denies normal users the directory traversal performed by
    # Path.resolve(strict=True), even though the kernel image path is valid.
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("protected package root")),
    )
    assert validate_provider_identity(valid, install_root=root)
    assert not validate_provider_identity(
        ProcessIdentity(1, str(executable), "FAE.Vault.PasskeyProvider_attacker"),
        install_root=root,
    )
    outside = tmp_path / "PasskeyManager.exe"
    outside.write_bytes(b"MZ")
    assert not validate_provider_identity(ProcessIdentity(1, str(outside), valid.package_family_name), install_root=root)


def test_connection_handler_sends_challenge_and_bounds_invalid_request():
    class Vault:
        entries = []
    broker = PasskeyBroker(PasskeyService(lambda: Vault()), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    handler = ConnectionHandler(broker, PEER)
    greeting = unpack(handler.greeting)
    assert greeting["type"] == "challenge"
    assert len(greeting["challenge"]) == 43
    assert unpack(handler.handle(b"bad", now_ms=1000)) == {"ok": False, "error": "invalid_request"}


def test_connection_handler_dispatches_framed_request():
    class Vault:
        entries = []
    broker = PasskeyBroker(PasskeyService(lambda: Vault()), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    handler = ConnectionHandler(broker, PEER)
    frame = encode_frame({"v": 1, "type": "status", "requestId": str(uuid.uuid4()), "deadlineMs": 2000})
    assert unpack(handler.handle(frame, now_ms=1000)) == {"ok": True, "result": {"locked": False}}
