"""Windows native application autofill through UI Automation.

Autofill is deliberately user initiated. Values are written through UIA's
ValuePattern and never pass through the clipboard.
"""

from __future__ import annotations

import os
import re
import unicodedata
import subprocess
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Iterable

from . import modules as entry_modules
from .autofill_sources import shares_matching_word, entry_matching_text, entry_binding_values, entry_bindings, entry_is_fillable, with_linked_sources, AUTOFILL_BINDINGS_KEY, AUTOFILL_ROLES
from .autofill_resolver import AutofillSnapshot
from .models import Entry, SecretType

if TYPE_CHECKING:
    from .storage import Vault


class NativeAutofillError(RuntimeError):
    """A recoverable native autofill failure safe to show to the user."""


@dataclass(frozen=True)
class NativeTarget:
    hwnd: int
    process_id: int
    process_name: str
    window_title: str = ""
    executable_path: str = ""
    signer_sha256: str = ""


@dataclass(frozen=True)
class FieldInfo:
    control: Any
    role: str
    name: str = ""
    automation_id: str = ""
    top: int = 0
    left: int = 0
    focused: bool = False


@dataclass(frozen=True)
class FillResult:
    username_filled: bool
    password_filled: bool
    otp_filled: bool = False
    additional_roles: tuple[str, ...] = ()

    @property
    def count(self) -> int:
        return int(self.username_filled) + int(self.password_filled) + int(self.otp_filled) + len(self.additional_roles)


@dataclass(frozen=True)
class PreparedFill:
    target: NativeTarget
    fields: tuple[FieldInfo, ...]
    focused_control: Any = None


@dataclass(frozen=True)
class CapturedCredentials:
    username: str = ""
    password: str = ""


_USERNAME_TOKENS = (
    "username", "user name", "userid", "user id", "login", "account",
    "email", "e-mail", "mail", "用户名", "用户", "账号", "帐号", "邮箱",
)
_PASSWORD_TOKENS = (
    "password", "passcode", "passwd", "pwd", "pin", "密码", "口令",
)
_OTP_TOKENS = (
    "one-time-code", "one time code", "otp", "totp", "2fa", "two-factor",
    "verification code", "auth code", "验证码", "动态码", "一次性密码",
)
_SEARCH_TOKENS = ("search", "find", "filter", "query", "搜索", "查找", "筛选")
_AUTOFILL_ROLE_TOKENS = (
    ("postal_code", ("postal code", "postcode", "zip code", "zipcode", "邮编")),
    ("phone", ("phone", "telephone", "mobile", "手机号", "电话")),
    ("email", ("email", "e-mail", "邮箱", "邮件")),
    ("full_name", ("full name", "real name", "姓名")),
    ("card_number", ("card number", "cc number", "银行卡号", "卡号")),
    ("card_expiry", ("card expiry", "expiration date", "有效期")),
    ("card_cvv", ("cvv", "cvc", "security code", "安全码")),
    ("street_address", ("street address", "address line", "详细地址")),
    ("city", ("city", "城市")),
    ("region", ("state", "province", "region", "省份", "州")),
    ("country", ("country", "国家")),
)
APP_PATH_FIELD = "native_app_path"
APP_SIGNER_FIELD = "native_app_signer_sha256"


def normalize_process_name(value: str | None) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    return os.path.basename(text).lower()


def entry_target_app(entry: Entry) -> str:
    return normalize_process_name(entry.target_app or entry_modules.target_app_value(entry.fields))


def normalize_executable_path(value: str | None) -> str:
    text = str(value or "").strip().strip('"')
    return os.path.normcase(os.path.abspath(text)) if text else ""


def entry_identity_matches(entry: Entry, target: NativeTarget) -> bool:
    stored_path = normalize_executable_path(entry.get_field(APP_PATH_FIELD))
    stored_signer = entry.get_field(APP_SIGNER_FIELD).strip().lower()
    if not stored_path and not stored_signer:
        return True
    if not stored_path or stored_path != normalize_executable_path(target.executable_path):
        return False
    return not stored_signer or stored_signer == target.signer_sha256.strip().lower()


def signer_certificate_sha256(executable_path: str) -> str:
    """Return the Authenticode signer certificate SHA-256 fingerprint."""
    path = normalize_executable_path(executable_path)
    if os.name != "nt" or not path:
        return ""
    env = os.environ.copy()
    env["FAEVAULT_TARGET_EXE"] = path
    command = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:FAEVAULT_TARGET_EXE;"
        "if($s.Status -eq 'Valid' -and $s.SignerCertificate){"
        "$s.SignerCertificate.GetCertHashString('SHA256')}"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    value = completed.stdout.strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def entry_matches_target(entry: Entry, target: NativeTarget) -> bool:
    """Trusted association; word suggestions never qualify as identity."""
    process = normalize_process_name(target.process_name)
    bindings = [b for b in entry_bindings(entry) if b.get("kind") == "windows"
                and normalize_process_name(b.get("process")) == process]
    if (entry.get_field(APP_SIGNER_FIELD).strip() or any(b.get("signer") for b in bindings)) and target.executable_path and not target.signer_sha256:
        target = replace(target, signer_sha256=signer_certificate_sha256(target.executable_path))
    if not entry_identity_matches(entry, target):
        return False
    if bindings:
        return any(bool(normalize_executable_path(b.get("path")))
                   and normalize_executable_path(b.get("path")) == normalize_executable_path(target.executable_path)
                   and (not b.get("signer") or b["signer"] == target.signer_sha256.strip().lower()) for b in bindings)
    return any(normalize_process_name(value) == process for value in entry_binding_values(entry, "windows"))



def allowed_for_explicit_fill(entry: Entry, target: NativeTarget) -> bool:
    if entry.deleted_at is not None or not entry_identity_matches(entry, target):
        return False
    stored = [binding for binding in entry_bindings(entry) if binding.get("kind") == "windows" and normalize_process_name(binding.get("process")) == normalize_process_name(target.process_name)]
    return not stored or entry_matches_target(entry,target)

def matching_entries(entries: Iterable[Entry], process_name: str, *, window_title: str = "") -> list[Entry]:
    target = normalize_process_name(process_name)
    if not target:
        return []
    entries = list(entries)
    eligible = [entry for entry in entries if entry.deleted_at is None
                and entry.secret_type == SecretType.LOGIN and entry_is_fillable(entry, entries)]
    exact = [entry for entry in eligible if any(normalize_process_name(v) == target for v in entry_binding_values(entry, "windows"))
             or any(b.get("kind") == "windows" and normalize_process_name(b.get("process")) == target for b in entry_bindings(entry))]
    # Suggestions are secondary to explicit associations and require a picker.
    words = target.removesuffix(".exe") + " " + window_title
    matched = exact + [entry for entry in eligible if entry not in exact and shares_matching_word(
        entry_matching_text(entry), words)]
    return sorted(matched, key=lambda entry: (entry not in exact, entry.title.casefold(), entry.username.casefold(), entry.id))


def matching_vault_entries(vault: "Vault", process_name: str, *, target: NativeTarget | None = None) -> list[Entry]:
    """Return explicit associations and suggestions concurrently."""
    normalized = normalize_process_name(process_name)
    if not normalized:
        return []
    candidates = [entry for entry_id in vault.list_entry_ids(SecretType.LOGIN)
                  if (entry := vault.read_entry(entry_id)) is not None]
    if target is not None and target.executable_path and not target.signer_sha256 and any(
            e.get_field(APP_SIGNER_FIELD).strip() or any(b.get("signer") for b in entry_bindings(e)) for e in candidates):
        target = replace(target, signer_sha256=signer_certificate_sha256(target.executable_path))
    matched = matching_entries(with_linked_sources(vault, candidates), normalized, window_title=target.window_title if target else "")
    return [entry for entry in matched if target is None or (entry_identity_matches(entry, target)
            and (not any(b.get("kind") == "windows" and normalize_process_name(b.get("process")) == normalized
                         for b in entry_bindings(entry)) or entry_matches_target(entry, target)))]


def remember_native_binding(vault: "Vault", entry: Entry, target: NativeTarget) -> Entry:
    if not normalize_executable_path(target.executable_path):
        raise NativeAutofillError("无法确认程序路径，请重试")
    if not target.signer_sha256:
        target = replace(target, signer_sha256=signer_certificate_sha256(target.executable_path))
    current = vault.read_entry(entry.id)
    if current is None or current.to_dict() != entry.to_dict() or not entry_identity_matches(current, target):
        raise NativeAutofillError("条目或程序身份已变化，请重试")
    existing = [b for b in entry_bindings(current) if b.get("kind") == "windows" and normalize_process_name(b.get("process")) == normalize_process_name(target.process_name)]
    if existing and not entry_matches_target(current, target):
        raise NativeAutofillError("程序身份已变化，请重试")
    changed = Entry.from_dict(current.to_dict())
    binding = {"kind": "windows", "process": normalize_process_name(target.process_name),
               "path": normalize_executable_path(target.executable_path), "signer": target.signer_sha256.strip().lower()}
    bindings = list(entry_bindings(changed))
    if binding not in bindings:
        bindings.append(binding)
    changed.fields[AUTOFILL_BINDINGS_KEY] = bindings
    vault.update(changed)
    return changed


def is_excluded(process_name: str | None, excluded: Iterable[str] | None) -> bool:
    """前台程序是否在自动填充排除清单中（与安卓端按包名排除的行为一致）。"""
    target = normalize_process_name(process_name)
    if not target:
        return False
    blocklist = {normalize_process_name(name) for name in (excluded or ())}
    return target in blocklist


def classify_field(*, name: str = "", automation_id: str = "", help_text: str = "", is_password: bool = False) -> str:
    if is_password:
        return "password"
    text = unicodedata.normalize("NFKC", " ".join((name, automation_id, help_text))).strip()
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text).casefold()
    compact = re.sub(r"[^\w\u4e00-\u9fff]+", " ", text)
    def matches(token):
        normalized = re.sub(r"[^\w\u4e00-\u9fff]+", " ", token)
        if re.search(r"[\u3400-\u9fff]", normalized):
            return normalized in compact
        return re.search(r"(?<!\w)" + re.escape(normalized) + r"(?!\w)", compact) is not None
    if any(matches(token) for token in _SEARCH_TOKENS):
        return "other"
    if any(matches(token) for token in _OTP_TOKENS):
        return "otp"
    if any(matches(token) for token in _PASSWORD_TOKENS):
        return "password"
    for role, tokens in _AUTOFILL_ROLE_TOKENS:
        if any(matches(token) for token in tokens):
            return role
    if any(matches(token) for token in _USERNAME_TOKENS):
        return "username"
    return "unknown"


def choose_fields(fields: Iterable[FieldInfo]) -> tuple[FieldInfo | None, FieldInfo | None]:
    candidates = list(fields)
    focused = next((field for field in candidates if field.focused), None)
    passwords = [field for field in candidates if field.role == "password"]
    usernames = [field for field in candidates if field.role in {"username", "email"}]

    password = focused if focused and focused.role == "password" else None
    if password is None and passwords:
        password = min(passwords, key=lambda field: _field_distance(field, focused))

    username = focused if focused and focused.role in {"username", "email"} else None
    if username is None and usernames:
        anchor = password or focused
        before = [field for field in usernames if anchor is None or field.top <= anchor.top]
        pool = before or usernames
        username = min(pool, key=lambda field: _field_distance(field, anchor))

    return username, password


def choose_otp_field(fields: Iterable[FieldInfo]) -> FieldInfo | None:
    candidates = [field for field in fields if field.role == "otp"]
    if not candidates:
        return None
    focused = next((field for field in candidates if field.focused), None)
    return focused or min(candidates, key=lambda field: (field.top, field.left))


def _field_distance(field: FieldInfo, anchor: FieldInfo | None) -> tuple[int, int]:
    if anchor is None:
        return (field.top, field.left)
    return (abs(field.top - anchor.top), abs(field.left - anchor.left))


class WindowsUiaBackend:
    """Small adapter around the third-party ``uiautomation`` package."""

    MAX_FIELDS = 64
    MAX_DEPTH = 12

    def capture_target(self) -> NativeTarget:
        if os.name != "nt":
            raise NativeAutofillError("原生程序自动填充仅支持 Windows")
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        hwnd = int(user32.GetForegroundWindow() or 0)
        if not hwnd:
            raise NativeAutofillError("未检测到当前程序窗口")
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            raise NativeAutofillError("无法识别当前程序")
        title_length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(max(1, title_length + 1))
        user32.GetWindowTextW(hwnd, title, len(title))
        executable_path = self._process_path(int(pid.value))
        process_name = normalize_process_name(executable_path) or self._process_name(int(pid.value))
        return NativeTarget(
            hwnd,
            int(pid.value),
            process_name,
            title.value,
            executable_path,
            "",
        )

    def discover_fields(self, target: NativeTarget) -> list[FieldInfo]:
        try:
            import uiautomation as auto

            root = auto.ControlFromHandle(target.hwnd)
            focused_control = auto.GetFocusedControl()
            if root is None:
                raise NativeAutofillError("当前程序未提供可访问的输入控件")
            result: list[FieldInfo] = []
            for control, _depth in auto.WalkControl(root, includeTop=True, maxDepth=self.MAX_DEPTH):
                if len(result) >= self.MAX_FIELDS:
                    break
                try:
                    if control.ControlType != auto.ControlType.EditControl:
                        continue
                    if not control.IsEnabled or control.IsOffscreen:
                        continue
                    rect = control.BoundingRectangle
                    role = classify_field(
                        name=control.Name,
                        automation_id=control.AutomationId,
                        help_text=control.HelpText,
                        is_password=bool(control.IsPassword),
                    )
                    result.append(
                        FieldInfo(
                            control=control,
                            role=role,
                            name=str(control.Name or ""),
                            automation_id=str(control.AutomationId or ""),
                            top=int(rect.top),
                            left=int(rect.left),
                            focused=bool(focused_control and auto.ControlsAreSame(control, focused_control)),
                        )
                    )
                except Exception:
                    continue
            if not result:
                raise NativeAutofillError("当前页面没有可自动填充的标准输入框")
            return result
        except NativeAutofillError:
            raise
        except Exception as exc:
            raise NativeAutofillError("无法读取当前程序的输入框") from exc

    def prepare(self) -> PreparedFill:
        target = self.capture_target()
        try:
            import uiautomation as auto

            focused_control = auto.GetFocusedControl()
            if focused_control is not None and focused_control.ProcessId != target.process_id:
                focused_control = None
        except Exception:
            focused_control = None
        # Epic's embedded login page exposes its window but no editable UIA controls.
        # Avoid a synchronous tree walk on every hotkey there.
        if target.process_name == "epicgameslauncher.exe":
            return PreparedFill(target, (), focused_control)
        try:
            fields = tuple(self.discover_fields(target))
        except NativeAutofillError as exc:
            if str(exc) != "当前页面没有可自动填充的标准输入框":
                raise
            fields = ()
        return PreparedFill(target, fields, focused_control)

    def fill_focused(self, prepared: PreparedFill, value: str, *, role: str) -> FillResult:
        if prepared.fields or role not in AUTOFILL_ROLES or not value:
            raise NativeAutofillError("请选择有效的当前输入框填充内容")
        # The caller arms this operation, then the user refocuses the field and
        # triggers the hotkey again. Never activate a window or guess a control.
        self._send_focused_text(prepared.target, value)
        return FillResult(role == "username", role == "password", role == "one_time_code",
                          (role,) if role not in {"username", "password", "one_time_code"} else ())

    @staticmethod
    def _send_focused_text(target: NativeTarget, value: str) -> None:
        import ctypes
        from ctypes import wintypes

        import time

        user32 = ctypes.windll.user32
        # WM_HOTKEY arrives before Ctrl/Alt/Shift/Win are necessarily released.
        # Unicode input must not inherit those modifiers.
        deadline = time.monotonic() + 1.0
        while any(user32.GetAsyncKeyState(key) & 0x8000 for key in (0x10, 0x11, 0x12, 0x5B, 0x5C)):
            if time.monotonic() >= deadline:
                raise NativeAutofillError("请松开快捷键后重新触发自动填充")
            time.sleep(0.01)
        hwnd = int(user32.GetForegroundWindow() or 0)
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if hwnd != target.hwnd or pid.value != target.process_id:
            raise NativeAutofillError("目标程序没有回到前台，请重新聚焦输入框后重试")
        if target.executable_path and normalize_executable_path(WindowsUiaBackend._process_path(pid.value)) != normalize_executable_path(target.executable_path):
            raise NativeAutofillError("目标程序已变化，请重新触发自动填充")

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                        ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.c_void_p)]

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                        ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_void_p)]

        class INPUTUNION(ctypes.Union):
            _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]

        class INPUT(ctypes.Structure):
            _fields_ = [("type", wintypes.DWORD), ("data", INPUTUNION)]

        # Deliver one Unicode character at a time. Some Qt/embedded providers
        # process surrogate pairs separately from adjacent BMP characters and
        # move the caret when a whole password is queued in one SendInput call.
        for character in value:
            if int(user32.GetForegroundWindow() or 0) != target.hwnd:
                raise NativeAutofillError("填充过程中目标窗口失焦，已停止输入")
            encoded = character.encode("utf-16-le")
            units = [int.from_bytes(encoded[i:i + 2], "little") for i in range(0, len(encoded), 2)]
            events = (INPUT * (len(units) * 2))()
            for index, unit in enumerate(units):
                events[index * 2] = INPUT(1, INPUTUNION(ki=KEYBDINPUT(0, unit, 0x0004, 0, None)))
                events[index * 2 + 1] = INPUT(1, INPUTUNION(ki=KEYBDINPUT(0, unit, 0x0004 | 0x0002, 0, None)))
            if user32.SendInput(len(events), events, ctypes.sizeof(INPUT)) != len(events):
                raise NativeAutofillError("无法向当前输入框输入内容，请确认程序未以管理员身份运行")
            time.sleep(0.01)

    def fill(
        self,
        prepared: PreparedFill,
        entry: Entry,
        *,
        otp_code: str = "",
        resolved: AutofillSnapshot | None = None,
    ) -> FillResult:
        self._validate_target(prepared.target)
        username_field, password_field = choose_fields(prepared.fields)
        otp_field = choose_otp_field(prepared.fields)
        role_values = {role: item.value for role, item in resolved.values.items()} if resolved is not None else {}
        preferred_username_role = "email" if username_field is not None and username_field.role == "email" else "username"
        fallback_username_role = "username" if preferred_username_role == "email" else "email"
        username = role_values.get(preferred_username_role) or role_values.get(fallback_username_role) or entry.username
        password = role_values.get("password", entry.password)
        username_filled = bool(username_field and username and self._set_value(username_field.control, username))
        password_filled = bool(password_field and password and self._set_value(password_field.control, password))
        otp_filled = bool(otp_field and otp_code and self._set_value(otp_field.control, otp_code))
        used_controls = {id(field.control) for field in (username_field, password_field, otp_field) if field is not None}
        additional: list[str] = []
        for field in prepared.fields:
            if id(field.control) in used_controls:
                continue
            role = "one_time_code" if field.role == "otp" else field.role
            value = role_values.get(role, "")
            if value and self._set_value(field.control, value):
                additional.append(role)
        result = FillResult(username_filled, password_filled, otp_filled, tuple(additional))
        if result.count == 0:
            raise NativeAutofillError("当前输入框不支持安全写入，请确认程序未以管理员身份运行")
        return result

    def capture_credentials(self, prepared: PreparedFill) -> CapturedCredentials:
        username_field, password_field = choose_fields(prepared.fields)
        return CapturedCredentials(
            self._get_value(username_field.control) if username_field is not None else "",
            self._get_value(password_field.control) if password_field is not None else "",
        )

    @staticmethod
    def _validate_target(target: NativeTarget) -> None:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        pid = wintypes.DWORD()
        if not user32.IsWindow(target.hwnd):
            raise NativeAutofillError("目标窗口已关闭，请重新触发自动填充")
        user32.GetWindowThreadProcessId(target.hwnd, ctypes.byref(pid))
        if pid.value != target.process_id:
            raise NativeAutofillError("目标程序已变化，请重新触发自动填充")
        if target.executable_path and normalize_executable_path(WindowsUiaBackend._process_path(pid.value)) != normalize_executable_path(target.executable_path):
            raise NativeAutofillError("目标程序已变化，请重新触发自动填充")

    @staticmethod
    def _set_value(control: Any, value: str) -> bool:
        try:
            pattern = control.GetValuePattern()
            if pattern is None or pattern.IsReadOnly:
                return False
            return bool(pattern.SetValue(value, waitTime=0))
        except Exception:
            return False

    @staticmethod
    def _get_value(control: Any) -> str:
        try:
            pattern = control.GetValuePattern()
            if pattern is None:
                return ""
            return str(pattern.Value or "")
        except Exception:
            return ""

    @staticmethod
    def _process_name(pid: int) -> str:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            raise NativeAutofillError("无法读取当前程序信息，程序可能以管理员身份运行")
        try:
            buffer = ctypes.create_unicode_buffer(260)
            if not psapi.GetModuleBaseNameW(handle, None, buffer, len(buffer)):
                raise NativeAutofillError("无法读取当前程序名称")
            return normalize_process_name(buffer.value)
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _process_path(pid: int) -> str:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            raise NativeAutofillError("无法读取当前程序路径，程序可能以管理员身份运行")
        try:
            size = ctypes.c_ulong(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                raise NativeAutofillError("无法读取当前程序路径")
            return buffer.value
        finally:
            kernel32.CloseHandle(handle)
