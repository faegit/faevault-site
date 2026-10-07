from pathlib import Path
from uuid import UUID

import pytest

from core.browser_autofill import BrowserRequest, ProtocolError, normalize_excluded_host, origin_is_excluded
from core.browser_host import BrowserAutofillController, SaveSelection
from core import modules
from core.models import Entry, SecretType
from core.storage import ExternalVaultChange, Vault

ENTRY_ID = "00000000-0000-0000-0000-000000000001"
NAS_ID = "00000000-0000-0000-0000-000000000002"


def request(action: str, **kwargs) -> BrowserRequest:
    return BrowserRequest("r", action, **kwargs)


def make_vault(path: Path) -> Vault:
    vault = Vault.create(path, "master")
    vault.add(Entry(id=ENTRY_ID, title="Example", url="https://example.com", username="alice", password="old"))
    return vault


def test_controller_unlocks_lists_and_revalidates_get(tmp_path):
    path = tmp_path / "v.pmv"
    make_vault(path).close()
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        lock_after_seconds=lambda: 60,
    )

    listed = controller.handle(request("list", origin="https://example.com"))
    assert listed["credentials"] == [
        {"id": ENTRY_ID, "title": "Example", "username": "alice", "origin": "https://example.com", "kind": "login", "matchReason": "exact"}
    ]
    assert controller.handle(request("get", origin="https://example.com", credential_id=ENTRY_ID)) == {
        "username": "alice",
        "password": "old",
        "fields": {"username": "alice", "password": "old"},
        "unavailableRoles": [],
    }
    with pytest.raises(ProtocolError):
        controller.handle(request("get", origin="https://other.example", credential_id=ENTRY_ID))


def test_session_expires_and_clears_vault(tmp_path):
    path = tmp_path / "v.pmv"
    make_vault(path).close()
    now = [10.0]
    unlocks = [0]

    def unlock():
        unlocks[0] += 1
        return Vault.open(path, "master")

    controller = BrowserAutofillController(
        unlock,
        lambda _request, _matches: SaveSelection("cancel"),
        lock_after_seconds=lambda: 30,
        clock=lambda: now[0],
    )
    controller.handle(request("list", origin="https://example.com"))
    now[0] = 41.0
    controller.handle(request("list", origin="https://example.com"))
    assert unlocks[0] == 2


def test_browser_password_unlock_establishes_session_without_native_dialog(tmp_path):
    path = tmp_path / "v.pmv"
    make_vault(path).close()
    desktop_unlocks = [0]
    received = []

    def desktop_unlock():
        desktop_unlocks[0] += 1
        return None

    def password_unlock(password):
        received.append(password)
        if password != "master":
            raise ProtocolError("WRONG_PASSWORD", "主密码不正确", retryable=True)
        return Vault.open(path, password)

    controller = BrowserAutofillController(
        desktop_unlock,
        lambda _request, _matches: SaveSelection("cancel"),
        unlock_with_password=password_unlock,
        lock_after_seconds=lambda: 60,
    )

    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("unlock", master_password="wrong"))
    assert caught.value.code == "WRONG_PASSWORD"
    assert controller.handle(request("unlock", master_password="master")) == {
        "locked": False,
        "alreadyUnlocked": False,
    }
    assert controller.handle(request("unlock", master_password="ignored")) == {
        "locked": False,
        "alreadyUnlocked": True,
    }
    assert controller.handle(request("list", origin="https://example.com"))["credentials"][0]["id"] == ENTRY_ID
    assert received == ["wrong", "master"]
    assert desktop_unlocks == [0]


def test_private_ip_requires_exact_origin_authorization(tmp_path):
    path = tmp_path / "private.pmv"
    vault = Vault.create(path, "master")
    vault.add(Entry(id=NAS_ID, title="NAS", url="https://192.168.1.10:8443/login", username="admin", password="p"))
    vault.close()
    requested = []
    allowed = set()
    save_requests = []

    def authorize(origin):
        requested.append(origin)
        if origin == "https://192.168.1.10:8443":
            allowed.add(origin)
            return True
        return False

    def confirm_save(browser_request, _matches):
        save_requests.append(browser_request)
        return SaveSelection("cancel")

    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        confirm_save,
        is_origin_authorized=lambda origin: origin in allowed,
        authorize_origin=authorize,
        lock_after_seconds=lambda: 60,
    )

    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("list", origin="https://192.168.1.10:8443"))
    assert caught.value.code == "ORIGIN_NOT_AUTHORIZED"
    assert requested == []

    assert controller.handle(request("authorize", origin="https://192.168.1.10:8443")) == {
        "authorized": True,
        "origin": "https://192.168.1.10:8443",
    }
    result = controller.handle(request("list", origin="https://192.168.1.10:8443"))
    assert [item["id"] for item in result["credentials"]] == [NAS_ID]
    assert requested == ["https://192.168.1.10:8443"]

    save_result = controller.handle(
        request(
            "save",
            origin="https://192.168.1.10:8443",
            title="NAS",
            username="admin",
            password="updated",
        )
    )
    assert save_result == {"status": "cancelled"}
    assert [item.action for item in save_requests] == ["save"]

    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("list", origin="https://192.168.1.10"))
    assert caught.value.code == "ORIGIN_NOT_AUTHORIZED"


def test_save_requires_confirmation_and_can_create_or_update(tmp_path):
    path = tmp_path / "v.pmv"
    make_vault(path).close()
    selections = iter((SaveSelection("update", ENTRY_ID), SaveSelection("create")))
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: next(selections),
        lock_after_seconds=lambda: 60,
    )

    updated = controller.handle(
        request("save", origin="https://example.com", title="Example", username="alice", password="new")
    )
    created = controller.handle(
        request("save", origin="https://example.com", title="Other", username="bob", password="secret")
    )

    assert updated["status"] == "updated"
    assert created["status"] == "created"
    entries = Vault.open(path, "master").entries
    assert {(entry.username, entry.password) for entry in entries} == {("alice", "new"), ("bob", "secret")}


def test_unchanged_save_skips_confirmation(tmp_path):
    path = tmp_path / "v.pmv"
    make_vault(path).close()
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda *_args: pytest.fail("confirmation should not be shown"),
        lock_after_seconds=lambda: 60,
    )

    result = controller.handle(
        request("save", origin="https://example.com", username="alice", password="old")
    )
    assert result == {"status": "unchanged", "credentialId": ENTRY_ID}


def test_stale_vault_write_is_rejected(tmp_path):
    path = tmp_path / "v.pmv"
    first = make_vault(path)
    second = Vault.open(path, "master")
    first.add(Entry(title="newer"))

    with pytest.raises(ExternalVaultChange):
        second.add(Entry(title="stale"))
    assert {entry.title for entry in Vault.open(path, "master").entries} == {"Example", "newer"}


def test_pmve_browser_list_decrypts_only_login_index_candidates(tmp_path, monkeypatch):
    path = tmp_path / "indexed.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    wanted = Entry(title="Wanted", url="https://example.com", username="alice", password="secret")
    unrelated = Entry(title="Other", url="https://other.example", username="mallory", password="hidden")
    vault.add(wanted)
    vault.add(unrelated)
    vault.close()

    original = Vault.read_entry
    reads = []

    def recording_read(self, entry_id):
        reads.append(entry_id)
        return original(self, entry_id)

    monkeypatch.setattr(Vault, "read_entry", recording_read)
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        lock_after_seconds=lambda: 60,
    )

    listed = controller.handle(request("list", origin="https://example.com"))

    assert [item["id"] for item in listed["credentials"]] == [str(UUID(wanted.id)), str(UUID(unrelated.id))]
    assert set(reads) == {str(UUID(wanted.id)), str(UUID(unrelated.id))}


def test_pmve_private_ip_index_miss_does_not_decrypt_entries(tmp_path, monkeypatch):
    path = tmp_path / "private-index-miss.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    vault.add(Entry(title="NAS", url="https://192.168.1.10:8443/login", username="admin", password="secret"))
    vault.add(Entry(title="Other", url="https://example.com", username="alice", password="hidden"))
    vault.close()

    original = Vault.read_entry
    reads = []

    def recording_read(self, entry_id):
        reads.append(entry_id)
        return original(self, entry_id)

    monkeypatch.setattr(Vault, "read_entry", recording_read)
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        is_origin_authorized=lambda origin: origin == "https://192.168.1.10:8443",
        lock_after_seconds=lambda: 60,
    )

    listed = controller.handle(request("list", origin="https://192.168.1.10:8443"))

    assert len(listed["credentials"]) == 1
    assert listed["credentials"][0]["matchReason"] == "exact"
    assert reads


def test_browser_lists_and_gets_bound_totp_without_full_materialization(tmp_path, monkeypatch):
    path = tmp_path / "otp.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    otp_module = modules.new_module(modules.OTP)
    otp_module["value"].update(
        secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        issuer="Example",
        label="alice",
        otp_domains="example.com",
    )
    source = Entry(title="Example code", secret_type=SecretType.OTP, fields=modules.fields_with_modules({}, [otp_module]))
    login = Entry(
        title="Example",
        url="https://example.com",
        username="alice",
        password="secret",
        fields={"bound_otp_id": source.id},
    )
    vault.add(source)
    vault.add(login)
    vault.close()

    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        lock_after_seconds=lambda: 60,
        otp_clock=lambda: 59,
    )
    listed = controller.handle(request("list", origin="https://example.com"))

    assert len(listed["credentials"]) == 1
    assert listed["credentials"][0]["otp"] == {
        "code": "287082",
        "type": "totp",
        "remaining": 1,
        "expiresAt": 60000,
        "issuer": "Example",
        "label": "alice",
    }
    assert controller.handle(request("get", origin="https://example.com", credential_id=login.id))["otp"]["code"] == "287082"


def test_browser_standalone_hotp_is_domain_scoped_and_advances_after_get(tmp_path):
    path = tmp_path / "standalone-hotp.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    otp_module = modules.new_module(modules.OTP)
    otp_module["value"].update(
        secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        type="hotp",
        counter="0",
        otp_domains="example.com",
    )
    source = Entry(title="Example code", secret_type=SecretType.OTP, fields=modules.fields_with_modules({}, [otp_module]))
    vault.add(source)
    vault.close()
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        lock_after_seconds=lambda: 60,
    )

    listed = controller.handle(request("list", origin="https://example.com"))
    assert [(item["id"], item["kind"]) for item in listed["credentials"]] == [(source.id, "otp")]
    result = controller.handle(request("get", origin="https://example.com", credential_id=source.id))

    assert result == {
        "username": "",
        "password": "",
        "fields": {"one_time_code": "755224"},
        "unavailableRoles": [],
        "otp": {"code": "755224", "type": "hotp", "remaining": None, "expiresAt": None, "issuer": "", "label": ""},
    }
    reopened = Vault.open(path, "master")
    assert reopened.read_entry(source.id).otp_fields()["counter"] == "1"


def test_browser_site_exclusion_normalizes_and_covers_subdomains() -> None:
    assert normalize_excluded_host("https://例子.测试/login") == "xn--fsqu00a.xn--0zwm56d"
    assert normalize_excluded_host("localhost") == ""
    assert normalize_excluded_host("192.168.1.1") == ""
    assert origin_is_excluded("https://login.example.com", ["example.com"])
    assert not origin_is_excluded("https://notexample.com", ["example.com"])


def test_excluded_browser_origin_returns_no_suggestions_and_rejects_get(tmp_path) -> None:
    path = tmp_path / "excluded.pmv"
    vault = make_vault(path)
    vault.set_autofill_exclusions("hosts", ["example.com"])
    vault.close()
    controller = BrowserAutofillController(
        lambda: Vault.open(path, "master"),
        lambda _request, _matches: SaveSelection("cancel"),
        is_origin_excluded=lambda origin: origin == "https://example.com",
        lock_after_seconds=lambda: 60,
    )

    assert controller.handle(request("list", origin="https://example.com")) == {
        "locked": False,
        "credentials": [],
        "excluded": True,
    }
    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("get", origin="https://example.com", credential_id=ENTRY_ID))
    assert caught.value.code == "ORIGIN_EXCLUDED"


def _word_controller(path, *, confirm=None, save=None):
    return BrowserAutofillController(lambda: Vault.open(path, "master"),
        save or (lambda *_: SaveSelection("cancel")), confirm_word_match=confirm,
        lock_after_seconds=lambda: 60)


def test_browser_word_candidates_reach_index_miss_and_require_single_release_consent(tmp_path):
    path = tmp_path / "words.pmv"
    vault = Vault.create(path, "master")
    entry = Entry(title="EXAMPLE login", password="secret", url="https://different.test",
                  fields={"modules": [{"type": "otp", "value": {"secret": "JBSWY3DPEHPK3PXP"}}]})
    vault.add(entry)
    vault.close()
    prompts = []
    controller = _word_controller(path, confirm=lambda origin, item: prompts.append((origin, item.id)) or True)
    listed = controller.handle(request("list", origin="https://example.com"))
    assert [e["id"] for e in listed["credentials"]] == [entry.id]
    assert listed["credentials"][0]["requiresSelection"] is True
    assert "otp" not in listed["credentials"][0]
    assert not prompts
    for _ in range(2):
        assert controller.handle(request("get", origin="https://example.com", credential_id=entry.id))["password"] == "secret"
    assert prompts == [("https://example.com", entry.id)] * 2
    controller.close()
    denied = _word_controller(path)
    with pytest.raises(ProtocolError) as caught:
        denied.handle(request("get", origin="https://example.com", credential_id=entry.id))
    assert caught.value.code == "ORIGIN_NOT_AUTHORIZED"
    denied.close()


def test_browser_word_match_cannot_update_different_origin(tmp_path):
    path = tmp_path / "word-update.pmv"
    vault = make_vault(path)
    vault.close()
    controller = _word_controller(path, save=lambda _req, matches: SaveSelection("update", ENTRY_ID))
    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("save", origin="https://example.net", username="other", password="new"))
    assert caught.value.code == "CONFLICT"
    controller.close()
    vault = Vault.open(path, "master")
    assert vault.read_entry(ENTRY_ID).password == "old"
    vault.close()


def test_browser_word_match_consent_cannot_release_changed_revision(tmp_path):
    path = tmp_path / "word-revision.pmv"
    make_vault(path).close()
    def confirm(_origin, _entry):
        other = Vault.open(path, "master")
        entry = other.read_entry(ENTRY_ID)
        entry.password = "changed"
        other.update(entry)
        other.close()
        return True
    controller = _word_controller(path, confirm=confirm)
    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("get", origin="https://example.net", credential_id=ENTRY_ID))
    assert caught.value.code == "CONFLICT"
    controller.close()


def test_vault_rule_removal_does_not_revive_stale_browser_callback(tmp_path):
    path = tmp_path / "removed-exclusion.pmv"
    vault = make_vault(path)
    vault.set_autofill_exclusions("hosts", ["example.com"])
    vault.set_autofill_exclusions("hosts", [])
    vault.close()
    controller = BrowserAutofillController(lambda: Vault.open(path, "master"),
        lambda *_: SaveSelection("cancel"), is_origin_excluded=lambda _: True,
        lock_after_seconds=lambda: 60)
    assert len(controller.handle(request("list", origin="https://example.com"))["credentials"]) == 1
    controller.close()


def test_word_selected_login_resolves_custom_module_and_explicit_source_fields(tmp_path):
    from core.autofill_sources import AutofillFieldRef, AutofillLink, encode_links_into_fields

    path = tmp_path / "custom-word-fill.pmv"
    vault = Vault.create(path, "master")
    source = Entry(title="Customer profile", secret_type=SecretType.SECURE_NOTE,
        fields={"modules": [{"id": "customer-code", "type": "text", "value": "CUSTOMER-73", "config": {"autofill_role": "custom_text"}}]})
    selected = Entry(title="EXAMPLE account", password="login-secret", url="https://different.test",
        fields=encode_links_into_fields({"modules": [
            {"id": "name", "type": "text", "value": "Ada Example", "config": {"autofill_role": "full_name"}},
            {"id": "placeholder", "type": "text", "value": "WRONG-LOCAL-CODE", "config": {"autofill_role": "custom_text"}},
        ]}, [AutofillLink("customer-link", source.id, (
            AutofillFieldRef("customer-code", "value", "custom_text", False),))]))
    unrelated = Entry(title="EXAMPLEPLUS", password="wrong-secret", fields={"modules": [
        {"id": "other", "type": "text", "value": "WRONG-OTHER-CODE"}]})
    for entry in (source, selected, unrelated):
        vault.add(entry)
    vault.close()
    confirmed = []
    controller = _word_controller(path, confirm=lambda origin, entry: confirmed.append(entry.id) or True)
    listed = controller.handle(request("list", origin="https://example.com"))
    assert [item["id"] for item in listed["credentials"]] == [selected.id]
    assert "fields" not in listed["credentials"][0]
    assert not confirmed
    result = controller.handle(request("get", origin="https://example.com", credential_id=selected.id))
    assert result["fields"] == {
        "password": "login-secret", "full_name": "Ada Example", "custom_text": "CUSTOMER-73"}
    assert confirmed == [selected.id]
    with pytest.raises(ProtocolError) as caught:
        controller.handle(request("get", origin="https://example.com", credential_id=unrelated.id))
    assert caught.value.code == "NOT_FOUND"
    controller.close()
    denied = _word_controller(path, confirm=lambda *_: False)
    with pytest.raises(ProtocolError) as caught:
        denied.handle(request("get", origin="https://example.com", credential_id=selected.id))
    assert caught.value.code == "ORIGIN_NOT_AUTHORIZED"
    denied.close()
