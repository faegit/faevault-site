"""Windows named-pipe host for the native WebAuthn plugin.

The transport deliberately owns no vault secrets.  It authenticates the kernel-
reported client process, decodes one bounded request at a time, and delegates to
``PasskeyBroker``.  The actual WebAuthn key generation and signing stay native.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .passkey_broker import PasskeyBroker, VerifiedPeer
from .passkey_broker_protocol import MAX_FRAME, ProtocolError, decode_request, encode_frame


PIPE_BASENAME = "FAEVault.PasskeyBroker.v1"
EXPECTED_PACKAGE_FAMILY_NAME = "FAE.Vault.PasskeyProvider_74rz453p8683c"
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008


class PipeSecurityError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    image_path: str
    package_family_name: str


def pipe_name_for_sid(user_sid: str) -> str:
    return rf"\\.\pipe\{PIPE_BASENAME}.{_sid_suffix(user_sid)}"


def unlock_event_name_for_sid(user_sid: str) -> str:
    return rf"Local\FAEVault.PasskeyUnlock.v1.{_sid_suffix(user_sid)}"


def _sid_suffix(user_sid: str) -> str:
    return hashlib.sha256(user_sid.encode("ascii", "strict")).hexdigest()[:24]


def validate_provider_identity(identity: ProcessIdentity, *, install_root: Path) -> bool:
    """Fail closed unless the client is the installed packaged provider binary."""
    if identity.package_family_name != EXPECTED_PACKAGE_FAMILY_NAME:
        return False
    try:
        image_path = Path(identity.image_path)
        root_path = Path(install_root)
        if not image_path.is_absolute() or not root_path.is_absolute():
            return False
        # QueryFullProcessImageNameW supplies the kernel-backed executable path.
        # Avoid resolving WindowsApps itself: its ACL intentionally rejects
        # directory traversal for an ordinary desktop process.
        image = os.path.normcase(os.path.abspath(os.fspath(image_path)))
        root = os.path.normcase(os.path.abspath(os.fspath(root_path)))
        if os.path.commonpath((image, root)) != root:
            return False
    except (OSError, ValueError, TypeError):
        return False
    return Path(image).name.casefold() == "passkeymanager.exe"


def current_user_sid() -> str:
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    sid, _attributes = win32security.GetTokenInformation(token, win32security.TokenUser)
    return win32security.ConvertSidToStringSid(sid)


def process_identity(pid: int) -> ProcessIdentity:
    import win32api
    import win32con
    access = win32con.PROCESS_QUERY_LIMITED_INFORMATION
    process = win32api.OpenProcess(access, False, pid)
    try:
        capacity = ctypes.c_ulong(32768)
        image_buffer = ctypes.create_unicode_buffer(capacity.value)
        if not ctypes.windll.kernel32.QueryFullProcessImageNameW(
            ctypes.c_void_p(int(process)), 0, image_buffer, ctypes.byref(capacity)
        ):
            raise ctypes.WinError()
        image = image_buffer.value
        family = _package_family_name(int(process))
        return ProcessIdentity(pid, image, family)
    finally:
        process.Close()


def verified_peer(pid: int) -> VerifiedPeer:
    identity = process_identity(pid)
    return VerifiedPeer(
        process_id=pid,
        user_sid=current_user_sid(),
        package_family_name=identity.package_family_name,
        image_path=identity.image_path,
        publisher_thumbprint="package-identity-verified",
    )


class ConnectionHandler:
    """Platform-neutral connection loop used by the real pipe and unit tests."""

    def __init__(self, broker: PasskeyBroker, peer: VerifiedPeer):
        self._broker = broker
        self._peer = peer

    @property
    def greeting(self) -> bytes:
        import base64
        challenge = base64.urlsafe_b64encode(self._broker.challenge).rstrip(b"=").decode("ascii")
        return encode_frame({"v": 1, "type": "challenge", "challenge": challenge})

    def handle(self, frame: bytes, *, now_ms: int | None = None) -> bytes:
        try:
            request = decode_request(frame, now_ms=now_ms)
            reply = self._broker.dispatch(self._peer, request)
        except ProtocolError:
            reply = {"ok": False, "error": "invalid_request"}
        return encode_frame(reply)


class WindowsNamedPipeServer:
    """Single-user local named-pipe server with kernel-derived peer identity."""

    def __init__(
        self,
        broker: PasskeyBroker,
        *,
        install_root: Path,
        peer_factory: Callable[[int], VerifiedPeer],
        user_sid: str,
    ):
        if sys.platform != "win32":
            raise OSError("Windows Passkey broker is only available on Windows")
        self._broker = broker
        self._install_root = install_root
        self._peer_factory = peer_factory
        self._name = pipe_name_for_sid(user_sid)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pipe = None
        self._ready = threading.Event()
        self._startup_error: Exception | None = None

    @property
    def name(self) -> str:
        return self._name

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._ready.clear()
        self._startup_error = None
        self._thread = threading.Thread(target=self._run, name="passkey-broker", daemon=True)
        self._thread.start()
        if not self._ready.wait(2):
            self._stop.set()
            self._thread.join(1)
            self._thread = None
            raise TimeoutError("Passkey broker did not open its pipe")
        if self._startup_error is not None:
            error = self._startup_error
            self._thread.join(1)
            self._thread = None
            raise RuntimeError("Passkey broker pipe is unavailable") from error

    def is_listening(self) -> bool:
        return self._pipe is not None and self._thread is not None and self._thread.is_alive()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        # Opening the pipe wakes ConnectNamedPipe without sharing secret data.
        try:
            import win32file
            wake = win32file.CreateFile(self._name, 0, 0, None, 3, 0, None)
            win32file.CloseHandle(wake)
        except Exception:
            pass
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _run(self) -> None:
        import win32api
        import win32file
        import win32pipe

        while not self._stop.is_set():
            try:
                pipe = win32pipe.CreateNamedPipe(
                    self._name,
                    win32pipe.PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT
                    | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    MAX_FRAME + 4,
                    MAX_FRAME + 4,
                    3000,
                    _pipe_security_attributes(current_user_sid()),
                )
            except Exception as exc:
                if not self._ready.is_set():
                    self._startup_error = exc
                    self._ready.set()
                elif getattr(exc, "winerror", None) == 231 or (exc.args and exc.args[0] == 231):
                    if not self._stop.wait(1):
                        continue
                return
            self._pipe = pipe
            self._ready.set()
            try:
                win32pipe.ConnectNamedPipe(pipe, None)
                if self._stop.is_set():
                    continue
                pid = _client_process_id(int(pipe))
                peer = self._peer_factory(pid)
                identity = ProcessIdentity(pid, peer.image_path, peer.package_family_name)
                if not validate_provider_identity(identity, install_root=self._install_root):
                    raise PipeSecurityError("unexpected provider identity")
                handler = ConnectionHandler(self._broker, peer)
                win32file.WriteFile(pipe, handler.greeting)
                while not self._stop.is_set():
                    frame = _read_frame(pipe)
                    win32file.WriteFile(pipe, handler.handle(frame))
            except Exception:
                pass
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(pipe)
                except Exception:
                    pass
                win32api.CloseHandle(pipe)
                self._pipe = None


def _read_frame(pipe) -> bytes:
    import win32file
    header = _read_exact(pipe, 4)
    (size,) = struct.unpack("<I", header)
    if size < 2 or size > MAX_FRAME:
        raise ProtocolError("invalid frame size")
    return header + _read_exact(pipe, size)


def _read_exact(pipe, size: int) -> bytes:
    import win32file
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        _status, chunk = win32file.ReadFile(pipe, remaining)
        if not chunk:
            raise EOFError("pipe closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _client_process_id(pipe_handle: int) -> int:
    pid = ctypes.c_ulong()
    if not ctypes.windll.kernel32.GetNamedPipeClientProcessId(ctypes.c_void_p(pipe_handle), ctypes.byref(pid)):
        raise ctypes.WinError()
    return int(pid.value)


def _package_family_name(process_handle: int) -> str:
    length = ctypes.c_uint32()
    result = ctypes.windll.kernel32.GetPackageFamilyName(
        ctypes.c_void_p(process_handle), ctypes.byref(length), None
    )
    if result not in (0, 122):  # ERROR_SUCCESS / ERROR_INSUFFICIENT_BUFFER
        return ""
    buffer = ctypes.create_unicode_buffer(length.value)
    result = ctypes.windll.kernel32.GetPackageFamilyName(
        ctypes.c_void_p(process_handle), ctypes.byref(length), buffer
    )
    return buffer.value if result == 0 else ""


def _pipe_security_attributes(user_sid: str):
    """Allow only this user and packaged apps; process identity is pinned next."""
    import pywintypes
    import win32security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;{user_sid})(A;;GRGW;;;AC)",
        win32security.SDDL_REVISION_1,
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes
