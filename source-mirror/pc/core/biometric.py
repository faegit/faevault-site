"""Windows Hello 解锁。

Hello 验证用户在场，DPAPI 包裹身份绑定的 PMVE RootKey
RootKey，不保存主密码。两种密钥材料使用不同入口，不能互相冒充。

局限：DPAPI 为当前 Windows 用户作用域，Hello 验证是 UI 在场确认而非密码学绑定，
理论上以当前用户身份运行的代码可绕过 Hello 直接 DPAPI 解密。该模型用"主密码不明文落盘
+ 解锁需本人在场"换取便利，安全性介于纯主密码与硬件密钥之间。
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .log import get
from .pmve_device_envelope import (
    DeviceEnvelopeBindingError,
    DeviceEnvelopeError,
    PmvEDeviceEnvelope,
    PmvEDeviceIdentity,
    authenticated_vault_identity,
    decode_device_envelope,
    encode_device_envelope,
    validate_device_envelope,
)

if TYPE_CHECKING:
    from .storage import Vault

_log = get("biometric")

SUFFIX = ".hello"
_PMVE_MAGIC = b"PMVS"

_available_cache: bool | None = None


def hello_path(vault_path: Path | str) -> Path:
    p = Path(vault_path)
    return p.with_name(p.name + SUFFIX)


def is_enabled(vault_path: Path | str) -> bool:
    return hello_path(vault_path).exists()


def _run_async(coro_factory, timeout: float):
    """在独立线程的事件循环中运行 winrt 协程并阻塞取结果（避免干扰 Qt 主循环）。"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro_factory())).result(timeout=timeout)


def available() -> bool:
    """当前设备是否可用 Windows Hello（已配置 PIN/生物识别且依赖就绪）。结果缓存。"""
    global _available_cache
    if _available_cache is not None:
        return _available_cache
    _available_cache = _probe_available()
    return _available_cache


def _probe_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import win32crypt  # noqa: F401
        from winrt.windows.security.credentials.ui import (
            UserConsentVerifier,
            UserConsentVerifierAvailability,
        )
    except Exception as exc:
        _log.info("Windows Hello 依赖不可用：%s", exc)
        return False

    async def _check():
        return await UserConsentVerifier.check_availability_async()

    try:
        result = _run_async(_check, timeout=8)
        return result == UserConsentVerifierAvailability.AVAILABLE
    except Exception as exc:
        _log.info("Windows Hello 不可用：%s", exc)
        return False


def _allow_foreground() -> None:
    """允许凭据代理（CredentialUIBroker）抢占前台，避免 Hello 弹窗被主窗口盖住。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.AllowSetForegroundWindow(-1)  # ASFW_ANY
    except Exception:  # noqa: BLE001
        pass


# Windows Hello / 凭据对话框（CredentialUIBroker 进程）的顶层窗口类名，不随系统语言变化
_CRED_DIALOG_CLASS = "Credential Dialog Xaml Host"


def _force_credential_dialog_topmost(stop: threading.Event, timeout: float = 12.0) -> None:
    """轮询查找 Hello 凭据对话框窗口并强制置顶 + 拉到前台。

    仅靠 ``AllowSetForegroundWindow`` 不足以把代理进程的弹窗顶上来，这里在验证期间
    主动定位该窗口并 ``SetWindowPos(HWND_TOPMOST)`` + ``SetForegroundWindow``。
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # noqa: BLE001
        return

    user32 = ctypes.windll.user32
    HWND_TOPMOST = -1
    SWP_FLAGS = 0x0001 | 0x0002 | 0x0040  # NOSIZE | NOMOVE | SHOWWINDOW

    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    found: list[int] = []

    def _cb(hwnd, _lparam):
        buf = ctypes.create_unicode_buffer(64)
        user32.GetClassNameW(hwnd, buf, 64)
        if buf.value == _CRED_DIALOG_CLASS and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False  # 找到即停止枚举
        return True

    cb = enum_proc(_cb)
    deadline = time.time() + timeout
    while not stop.is_set() and time.time() < deadline:
        found.clear()
        try:
            user32.EnumWindows(cb, 0)
        except Exception:  # noqa: BLE001
            return
        if found:
            hwnd = found[0]
            try:
                user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_FLAGS)
                user32.BringWindowToTop(hwnd)
                user32.SetForegroundWindow(hwnd)
            except Exception:  # noqa: BLE001
                pass
            return
        time.sleep(0.05)


def verify(message: str = "请通过 Windows Hello 验证以解锁密码库") -> bool:
    """弹出 Hello 验证，通过返回 True。用户取消 / 失败 / 不可用均返回 False。"""
    try:
        from winrt.windows.security.credentials.ui import (
            UserConsentVerificationResult,
            UserConsentVerifier,
        )
    except Exception as exc:
        _log.warning("无法加载 Windows Hello：%s", exc)
        return False

    _allow_foreground()

    stop = threading.Event()
    topmost_thread = threading.Thread(target=_force_credential_dialog_topmost, args=(stop,), daemon=True)
    topmost_thread.start()

    async def _request():
        return await UserConsentVerifier.request_verification_async(message)

    try:
        result = _run_async(_request, timeout=60)
        return result == UserConsentVerificationResult.VERIFIED
    except Exception as exc:
        _log.warning("Windows Hello 验证失败：%s", exc)
        return False
    finally:
        stop.set()


def _protect(data: bytes) -> bytes:
    import win32crypt

    return win32crypt.CryptProtectData(data, "FAEVault Hello", None, None, None, 0)


def _unprotect(blob: bytes) -> bytes:
    import win32crypt

    return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]




def disable(vault_path: Path | str) -> None:
    p = hello_path(vault_path)
    if p.exists():
        try:
            p.unlink()
            _log.info("已关闭 Windows Hello 解锁：%s", p.name)
        except OSError as exc:
            _log.warning("删除 Hello 旁挂文件失败：%s", exc)




def enable_pmve(vault_path: Path | str, root_key: bytes | bytearray | memoryview) -> bool:
    """Seal a typed PMVE RootKey envelope bound to the authenticated vault header."""

    root_buffer = bytearray(root_key)
    encoded = bytearray()
    try:
        if _vault_magic(vault_path) != _PMVE_MAGIC:
            raise ValueError("目标不是 PMVE 保险库")
        if len(root_buffer) != 32:
            raise ValueError("RootKey 长度无效")
        identity = _authenticated_pmve_identity(vault_path, root_buffer)
        encoded = encode_device_envelope(root_buffer, identity)
        protected = _protect(bytes(encoded))
        _write_sidecar(vault_path, bytes(protected))
        _log.info("已启用 PMVE Windows Hello 解锁：%s", hello_path(vault_path).name)
        return True
    except Exception as exc:
        _log.error("启用 PMVE Windows Hello 失败：%s", exc)
        return False
    finally:
        root_buffer[:] = bytes(len(root_buffer))
        encoded[:] = bytes(len(encoded))


def enable_for_vault(vault) -> bool:
    root_buffer = bytearray(vault.root_key_for_device_unlock())
    try:
        return enable_pmve(vault.path, root_buffer)
    finally:
        root_buffer[:] = bytes(len(root_buffer))



def unlock_pmve(vault_path: Path | str) -> PmvEDeviceEnvelope | None:
    """Verify presence and return a validated PMVE RootKey envelope.

    The caller owns the returned object and must call ``clear()`` after opening
    the vault. Invalid, stale, and transplanted sidecars are
    removed so that the user must explicitly register this device again.
    """

    path = hello_path(vault_path)
    if not path.exists():
        return None
    if _vault_magic(vault_path) != _PMVE_MAGIC:
        raise DeviceEnvelopeError("目标不是 PMVE 保险库")
    if not verify():
        return None

    plain_buffer = bytearray()
    envelope: PmvEDeviceEnvelope | None = None
    try:
        plain_buffer = bytearray(_unprotect(path.read_bytes()))
        envelope = decode_device_envelope(plain_buffer)
        root_buffer = envelope.copy_root_key_buffer()
        try:
            current_identity = authenticated_vault_identity(vault_path, root_buffer)
        finally:
            root_buffer[:] = bytes(len(root_buffer))
        validate_device_envelope(envelope, current_identity)
        return envelope
    except (DeviceEnvelopeError, TypeError, ValueError) as exc:
        if envelope is not None:
            envelope.clear()
        disable(vault_path)
        if isinstance(exc, DeviceEnvelopeBindingError):
            raise
        raise DeviceEnvelopeBindingError(
            "Windows Hello PMVE 凭据已失效；请用主密码登录后重新登记"
        ) from exc
    except Exception as exc:
        if envelope is not None:
            envelope.clear()
        disable(vault_path)
        _log.error("Windows Hello 解出 PMVE RootKey 失败：%s", exc)
        raise DeviceEnvelopeBindingError(
            "Windows Hello PMVE 凭据已失效；请用主密码登录后重新登记"
        ) from exc
    finally:
        plain_buffer[:] = bytes(len(plain_buffer))


def open_vault(vault_path: Path | str, *, vault_type=None):
    if vault_type is None:
        from .storage import Vault as vault_type

    path = Path(vault_path)
    if _vault_magic(path) != _PMVE_MAGIC:
        raise DeviceEnvelopeError("此保险库格式已不再支持，请使用 PMVE 文件")
    envelope = unlock_pmve(path)
    if envelope is None:
        return None
    root = envelope.copy_root_key_buffer()
    try:
        return vault_type.open_with_root_key(path, bytes(root))
    finally:
        root[:] = bytes(len(root))
        envelope.clear()



def _vault_magic(vault_path: Path | str) -> bytes:
    try:
        with Path(vault_path).open("rb") as stream:
            return stream.read(4)
    except OSError:
        return b""


def _authenticated_pmve_identity(
    vault_path: Path | str,
    root_key: bytes | bytearray | memoryview,
) -> PmvEDeviceIdentity:
    """Authenticate the current Commit/PMVR, not only the bootstrap header."""

    from .storage import Vault

    root_buffer = bytearray(root_key)
    opened = None
    try:
        # The facade delegates to PmvVaultStore.open_root_key, which verifies
        # both the header and the newest authenticated PMV snapshot.
        opened = Vault.open_with_root_key(Path(vault_path), bytes(root_buffer))
        identity = opened.pmve_identity
        return PmvEDeviceIdentity(
            identity.vault_id,
            identity.signing_public_key,
            identity.key_revision,
        )
    finally:
        if opened is not None:
            opened.close()
        root_buffer[:] = bytes(len(root_buffer))


def _write_sidecar(vault_path: Path | str, protected: bytes) -> None:
    target = hello_path(vault_path)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=target.name + ".",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        ) as stream:
            temporary_name = stream.name
            stream.write(protected)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
