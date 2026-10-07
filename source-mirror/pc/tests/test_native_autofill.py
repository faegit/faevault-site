import pytest
from core import modules, native_autofill
from core.models import Entry, SecretType
from core.native_autofill import FieldInfo, PreparedFill, NativeTarget, WindowsUiaBackend, choose_fields, choose_otp_field, classify_field, is_excluded, matching_entries, normalize_process_name
from core.storage import Vault


def _field(role: str, top: int, *, focused: bool = False) -> FieldInfo:
    return FieldInfo(object(), role, top=top, focused=focused)


def test_normalize_process_name_accepts_paths_and_case() -> None:
    assert normalize_process_name(r'"C:\Program Files\Example\APP.EXE"') == "app.exe"


def test_is_excluded_matches_normalized_process_names_case_insensitively() -> None:
    assert is_excluded("chrome.exe", ["Chrome.EXE"])
    assert is_excluded(r"C:\Program Files\App\APP.EXE", ["app.exe"])
    assert is_excluded("app.exe", []) is False
    assert is_excluded("", ["chrome.exe"]) is False
    assert is_excluded(None, ["chrome.exe"]) is False
    assert is_excluded("app.exe", ["chrome.exe", "firefox.exe"]) is False


def test_matching_entries_requires_live_login_with_password_and_association() -> None:
    direct = Entry(title="A", username="u", password="p", target_app="APP.EXE")
    module = Entry(
        title="B",
        username="u2",
        password="p2",
        fields={modules.MODULES_KEY: [{"type": modules.TARGET_APP, "value": "app.exe"}]},
    )
    deleted = Entry(title="C", username="u", password="p", target_app="app.exe", deleted_at=1)
    note = Entry(title="D", password="p", target_app="app.exe", secret_type=SecretType.SECURE_NOTE)
    empty_password = Entry(title="E", target_app="app.exe")

    assert [entry.title for entry in matching_entries([module, note, direct, deleted, empty_password], "app.exe")] == ["A", "B"]


def test_matching_vault_entries_decrypts_only_package_index_candidates(tmp_path, monkeypatch) -> None:
    path = tmp_path / "native-autofill.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    wanted = Entry(title="Wanted", username="alice", password="secret", target_app="APP.EXE")
    unrelated = Entry(title="Other", username="mallory", password="hidden", target_app="other.exe")
    vault.add(wanted)
    vault.add(unrelated)
    vault.close()

    opened = Vault.open(path, "master")
    original = Vault.read_entry
    reads = []

    def recording_read(self, entry_id):
        reads.append(entry_id)
        return original(self, entry_id)

    monkeypatch.setattr(Vault, "read_entry", recording_read)

    matches = native_autofill.matching_vault_entries(opened, r"C:\Program Files\App\app.exe")

    assert [entry.id for entry in matches] == [wanted.id]
    assert set(reads) == {wanted.id, unrelated.id}
    opened.close()


def test_matching_vault_entries_looks_up_signer_only_for_bound_candidates(tmp_path, monkeypatch) -> None:
    path = tmp_path / "native-autofill-signer.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    plain = Entry(title="Plain", username="alice", password="secret", target_app="app.exe")
    vault.add(plain)
    vault.close()
    opened = Vault.open(path, "master")
    lookups = []
    monkeypatch.setattr(native_autofill, "signer_certificate_sha256", lambda path: lookups.append(path) or "a" * 64)
    target = NativeTarget(1, 2, "app.exe", executable_path=r"C:\App\app.exe")
    assert [entry.id for entry in native_autofill.matching_vault_entries(opened, "app.exe", target=target)] == [plain.id]
    assert lookups == []
    opened.close()

    vault = Vault.open(path, "master")
    bound = Entry(title="Bound", username="bob", password="secret", target_app="app.exe", fields={
        native_autofill.APP_PATH_FIELD: target.executable_path,
        native_autofill.APP_SIGNER_FIELD: "a" * 64,
    })
    vault.add(bound)
    assert {entry.id for entry in native_autofill.matching_vault_entries(vault, "app.exe", target=target)} == {plain.id, bound.id}
    assert lookups == [target.executable_path]
    vault.close()


def test_native_identity_rejects_same_name_from_different_path() -> None:
    entry = Entry(
        title="Bound",
        username="alice",
        password="secret",
        target_app="app.exe",
        fields={
            native_autofill.APP_PATH_FIELD: r"C:\Program Files\Trusted\app.exe",
            native_autofill.APP_SIGNER_FIELD: "a" * 64,
        },
    )
    trusted = NativeTarget(1, 2, "app.exe", executable_path=r"C:\Program Files\Trusted\app.exe", signer_sha256="a" * 64)
    copied = NativeTarget(1, 3, "app.exe", executable_path=r"D:\Temp\app.exe", signer_sha256="a" * 64)
    replaced = NativeTarget(1, 4, "app.exe", executable_path=r"C:\Program Files\Trusted\app.exe", signer_sha256="b" * 64)

    assert native_autofill.entry_identity_matches(entry, trusted)
    assert not native_autofill.entry_identity_matches(entry, copied)
    assert not native_autofill.entry_identity_matches(entry, replaced)
    assert native_autofill.entry_identity_matches(Entry(target_app="app.exe"), copied)


def test_classify_field_handles_password_username_and_search() -> None:
    assert classify_field(name="Password") == "password"
    assert classify_field(name="任意", is_password=True) == "password"
    assert classify_field(automation_id="accountEmail") == "email"
    assert classify_field(name="搜索账号") == "other"
    assert classify_field(name="验证码") == "otp"
    assert classify_field(automation_id="one-time-code") == "otp"


def test_choose_fields_prefers_username_before_focused_password() -> None:
    search = _field("other", 10)
    username = _field("username", 50)
    password = _field("password", 90, focused=True)
    later_username = _field("username", 140)

    assert choose_fields([search, username, password, later_username]) == (username, password)


def test_choose_fields_uses_email_field_as_login_username() -> None:
    email = _field("email", 50)
    password = _field("password", 90, focused=True)
    assert choose_fields([email, password]) == (email, password)


def test_prepare_keeps_target_when_program_has_no_standard_fields(monkeypatch) -> None:
    backend = WindowsUiaBackend()
    target = NativeTarget(1, 2, "other.exe")
    monkeypatch.setattr(backend, "capture_target", lambda: target)

    def no_fields(_target):
        raise native_autofill.NativeAutofillError("当前页面没有可自动填充的标准输入框")

    monkeypatch.setattr(backend, "discover_fields", no_fields)
    assert backend.prepare() == PreparedFill(target, ())


def test_prepare_skips_unavailable_epic_uia_tree(monkeypatch) -> None:
    backend = WindowsUiaBackend()
    target = NativeTarget(1, 2, "epicgameslauncher.exe")
    monkeypatch.setattr(backend, "capture_target", lambda: target)
    monkeypatch.setattr(backend, "discover_fields", lambda _target: (_ for _ in ()).throw(AssertionError("slow scan")))
    assert backend.prepare() == PreparedFill(target, ())


def test_manual_focus_sends_only_explicitly_selected_role(monkeypatch) -> None:
    backend = WindowsUiaBackend()
    prepared = PreparedFill(NativeTarget(1, 2, "epicgameslauncher.exe"), ())
    sent = []
    monkeypatch.setattr(backend, "_validate_target", lambda target: None)
    monkeypatch.setattr(backend, "_send_focused_text", lambda target, value: sent.append(value))
    result = backend.fill_focused(prepared, "test@example.invalid", role="username")
    assert sent == ["test@example.invalid"]
    assert result.username_filled and not result.password_filled


def test_manual_focus_never_steals_or_guesses_focus(monkeypatch) -> None:
    backend = WindowsUiaBackend()
    actions = []

    class FocusedControl:
        def SetFocus(self):
            actions.append("focus")

    prepared = PreparedFill(NativeTarget(1, 2, "epicgameslauncher.exe"), (), FocusedControl())
    monkeypatch.setattr(backend, "_validate_target", lambda _target: actions.append("activate"))
    monkeypatch.setattr(backend, "_send_focused_text", lambda _target, _value: actions.append("type"))

    backend.fill_focused(prepared, "secret", role="password")
    assert actions == ["type"]


def test_choose_fields_treats_unknown_focus_as_username_next_to_password() -> None:
    unknown = _field("unknown", 30, focused=True)
    password = _field("password", 70)

    assert choose_fields([unknown, password]) == (None, password)


def test_choose_fields_can_fill_only_focused_unknown_field() -> None:
    unknown = _field("unknown", 30, focused=True)

    assert choose_fields([unknown]) == (None, None)


def test_choose_fields_uses_nearest_unknown_before_password_as_username() -> None:
    tenant = _field("unknown", 10)
    username = _field("unknown", 50)
    password = _field("password", 90, focused=True)

    assert choose_fields([tenant, username, password]) == (None, password)


def test_choose_otp_field_prefers_focused_candidate() -> None:
    first = _field("otp", 30)
    focused = _field("otp", 70, focused=True)
    assert choose_otp_field([first, focused]) is focused


class _Pattern:
    def __init__(self, *, read_only: bool = False, succeeds: bool = True):
        self.IsReadOnly = read_only
        self.succeeds = succeeds
        self.value = None

    @property
    def Value(self):
        return self.value

    def SetValue(self, value: str, *, waitTime: int) -> bool:
        self.value = value
        return self.succeeds and waitTime == 0


class _Control:
    def __init__(self, pattern):
        self.pattern = pattern

    def GetValuePattern(self):
        return self.pattern


def test_set_value_uses_value_pattern_without_clipboard_fallback() -> None:
    pattern = _Pattern()

    assert WindowsUiaBackend._set_value(_Control(pattern), "secret")
    assert pattern.value == "secret"
    assert not WindowsUiaBackend._set_value(_Control(_Pattern(read_only=True)), "secret")
    assert not WindowsUiaBackend._set_value(_Control(None), "secret")


def test_fill_writes_otp_alongside_login_fields() -> None:
    username = _Pattern()
    password = _Pattern()
    otp_code = _Pattern()
    prepared = PreparedFill(
        NativeTarget(1, 2, "app.exe"),
        (
            FieldInfo(_Control(username), "username", top=10),
            FieldInfo(_Control(password), "password", top=20),
            FieldInfo(_Control(otp_code), "otp", top=30),
        ),
    )
    backend = WindowsUiaBackend()
    backend._validate_target = lambda _target: None

    result = backend.fill(prepared, Entry(username="alice", password="secret"), otp_code="123456")

    assert result.count == 3
    assert (username.value, password.value, otp_code.value) == ("alice", "secret", "123456")


def test_capture_credentials_reads_standard_uia_value_patterns() -> None:
    username = _Pattern()
    username.value = "alice"
    password = _Pattern()
    password.value = "secret"
    prepared = PreparedFill(
        NativeTarget(1, 2, "app.exe"),
        (
            FieldInfo(_Control(username), "username", top=10),
            FieldInfo(_Control(password), "password", top=20),
        ),
    )

    assert WindowsUiaBackend().capture_credentials(prepared) == native_autofill.CapturedCredentials("alice", "secret")


def test_word_suggestions_use_complete_casefolded_words_and_exact_priority():
    word = Entry(title="My EXAMPLE account", password="p")
    substring = Entry(title="exampleplus", password="p")
    module = Entry(title="Other", password="p", fields={"modules": [
        {"type": "target_app", "value": "Example Desktop"}]})
    assert {e.id for e in matching_entries([word, substring, module], "EXAMPLE.exe")} == {word.id, module.id}
    exact = Entry(title="Exact", password="p", target_app="example.exe")
    assert matching_entries([word, exact], "EXAMPLE.exe") == [exact, word]
    assert matching_entries([word], "unrelated.exe", window_title="Example - sign in") == [word]


def test_word_suggestions_reach_pmve_index_miss_and_respect_bound_identity(tmp_path):
    path = tmp_path / "word-candidates.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    wanted = Entry(title="EXAMPLE account", password="secret")
    blocked = Entry(title="Example account", password="secret", fields={
        native_autofill.APP_PATH_FIELD: r"C:\Other\other.exe"})
    vault.add(wanted)
    vault.add(blocked)
    vault.close()
    opened = Vault.open(path, "master")
    target = NativeTarget(1, 2, "example.exe", executable_path=r"C:\Example\example.exe")
    assert [e.id for e in native_autofill.matching_vault_entries(opened, "example.exe", target=target)] == [wanted.id]
    assert not native_autofill.entry_matches_target(wanted, target)
    opened.close()


def test_exact_target_verifies_missing_signer_before_allowing_update(monkeypatch):
    path = r"C:\App\app.exe"
    entry = Entry(target_app="app.exe", fields={native_autofill.APP_PATH_FIELD: path,
                  native_autofill.APP_SIGNER_FIELD: "a" * 64})
    target = NativeTarget(1, 2, "APP.EXE", executable_path=path)
    monkeypatch.setattr(native_autofill, "signer_certificate_sha256", lambda _: "a" * 64)
    assert native_autofill.entry_matches_target(entry, target)
    monkeypatch.setattr(native_autofill, "signer_certificate_sha256", lambda _: "b" * 64)
    assert not native_autofill.entry_matches_target(entry, target)


def test_selected_native_word_candidate_fills_custom_module_and_linked_field_controls(tmp_path):
    from core import autofill_sources
    from core.autofill_resolver import resolve_snapshot

    path = tmp_path / "custom-native-fill.pmv"
    source_module = modules.with_autofill_role(modules.new_module(modules.TEXT), "phone")
    source_module["value"] = "+86 13800138000"
    name_module = modules.with_autofill_role(modules.new_module(modules.TEXT), "full_name")
    name_module["value"] = "Ada Example"
    source = Entry(title="Contact profile", secret_type=SecretType.SECURE_NOTE,
                   fields=modules.fields_with_modules({}, [source_module]))
    selected = Entry(title="EXAMPLE account", password="login-secret",
        fields=autofill_sources.encode_links_into_fields(modules.fields_with_modules({}, [name_module]), [
            autofill_sources.AutofillLink("phone-link", source.id, (
                autofill_sources.AutofillFieldRef(source_module["id"], "value", "phone", False),))]))
    vault = Vault.create(path, "master")
    vault.add(source)
    vault.add(selected)
    vault.close()
    opened = Vault.open(path, "master")
    target = NativeTarget(1, 2, "example.exe")
    candidates = native_autofill.matching_vault_entries(opened, target.process_name, target=target)
    assert [entry.id for entry in candidates] == [selected.id]
    assert not native_autofill.entry_matches_target(candidates[0], target)
    snapshot = resolve_snapshot(candidates[0], [candidates[0], opened.read_entry(source.id)])
    password, full_name, phone = _Pattern(), _Pattern(), _Pattern()
    prepared = PreparedFill(target, (
        FieldInfo(_Control(password), "password", top=10),
        FieldInfo(_Control(full_name), "full_name", top=20),
        FieldInfo(_Control(phone), "phone", top=30),
    ))
    backend = WindowsUiaBackend()
    backend._validate_target = lambda _target: None
    result = backend.fill(prepared, candidates[0], resolved=snapshot)
    assert (password.value, full_name.value, phone.value) == ("login-secret", "Ada Example", "+86 13800138000")
    assert result.additional_roles == ("full_name", "phone")
    opened.close()


def test_keyboard_fallback_paces_unicode_characters_and_stops_on_focus_loss(monkeypatch):
    import ctypes
    import time
    from types import SimpleNamespace
    from ctypes import wintypes
    packets = []
    foreground = [1]

    class User32:
        def GetAsyncKeyState(self, key):
            return 0

        def GetForegroundWindow(self):
            return foreground[0]

        def GetWindowThreadProcessId(self, hwnd, pid):
            ctypes.cast(pid, ctypes.POINTER(wintypes.DWORD))[0] = 2

        def SendInput(self, count, events, size):
            packets.append([events[i].data.ki.wScan for i in range(0, count, 2)])
            return count

    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(user32=User32()))
    sleeps = []
    monkeypatch.setattr(time, "sleep", lambda duration: sleeps.append(duration))
    WindowsUiaBackend._send_focused_text(NativeTarget(1, 2, "test.exe"), "A测试🔑")
    assert packets == [[ord("A")], [ord("测")], [ord("试")], [0xD83D, 0xDD11]]
    assert len(sleeps) == 4
    packets.clear()

    def lose_focus(duration):
        foreground[0] = 3

    monkeypatch.setattr(time, "sleep", lose_focus)
    with pytest.raises(native_autofill.NativeAutofillError, match="失焦"):
        WindowsUiaBackend._send_focused_text(NativeTarget(1, 2, "test.exe"), "AB")
    assert packets == [[ord("A")]]


def test_native_email_role_uses_email_value_not_username(monkeypatch):
    from types import SimpleNamespace
    backend=WindowsUiaBackend(); written=[]
    monkeypatch.setattr(backend,"_validate_target",lambda target:None)
    monkeypatch.setattr(backend,"_set_value",lambda control,value:written.append(value) or True)
    snapshot=SimpleNamespace(values={"username":SimpleNamespace(value="account-name"),"email":SimpleNamespace(value="mail@example.com")})
    backend.fill(PreparedFill(NativeTarget(1,2,"app.exe"),(FieldInfo(object(),"email"),)),Entry(username="account-name"),resolved=snapshot)
    assert written==["mail@example.com"]
