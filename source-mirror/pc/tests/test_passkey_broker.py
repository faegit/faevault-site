import base64
import datetime as dt
import uuid

from core.passkey_broker import OperationRegistry, OperationState, PasskeyBroker, VerifiedPeer
from core.passkey_broker_protocol import Request
from core.passkey_service import CredentialMetadata, PasskeyService


PEER = VerifiedPeer(123, "S-1-5-21-test", "Fae.Vault.Passkeys_test", "provider.exe", "thumb")


def request(kind="status", payload=None, *, request_id=None, deadline=2000):
    return Request(kind, request_id or uuid.uuid4(), deadline, payload or {})


def test_locked_broker_never_returns_assertion_material():
    broker = PasskeyBroker(PasskeyService(lambda: None), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    assert broker.dispatch(PEER, request()) == {"ok": False, "error": "vault_locked"}


def test_unverified_peer_is_rejected_before_vault_access():
    called = False
    def vault():
        nonlocal called
        called = True
    broker = PasskeyBroker(PasskeyService(vault), peer_validator=lambda peer: False, now_ms=lambda: 1000)
    assert broker.dispatch(PEER, request()) == {"ok": False, "error": "unauthorized_peer"}
    assert called is False


def test_expired_and_replayed_requests_are_rejected():
    class Vault:
        entries = []
    broker = PasskeyBroker(PasskeyService(lambda: Vault()), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    assert broker.dispatch(PEER, request(deadline=1000))["error"] == "request_expired"
    item = request()
    assert broker.dispatch(PEER, item)["ok"] is True
    assert broker.dispatch(PEER, item)["error"] == "duplicate_or_busy"


def test_cancel_wins_over_late_completion():
    registry = OperationRegistry()
    request_id = uuid.uuid4()
    assert registry.begin(request_id)
    assert registry.cancel(request_id)
    assert registry.complete(request_id) is False
    assert registry.state(request_id) is OperationState.CANCELLED


def test_challenge_is_random_and_not_textual_secret():
    service = PasskeyService(lambda: None)
    first = PasskeyBroker(service, peer_validator=lambda peer: True)
    second = PasskeyBroker(service, peer_validator=lambda peer: True)
    assert len(first.challenge) == 32
    assert first.challenge != second.challenge


def test_hello_requires_connection_challenge():
    class Vault:
        entries = []
    broker = PasskeyBroker(PasskeyService(lambda: Vault()), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    challenge = base64.urlsafe_b64encode(broker.challenge).rstrip(b"=").decode("ascii")
    assert broker.dispatch(PEER, request("hello", {"challenge": challenge}))["ok"] is True
    wrong = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
    assert broker.dispatch(PEER, request("hello", {"challenge": wrong}))["error"] == "challenge_mismatch"


def test_commit_use_dispatches_zero_counter(monkeypatch):
    calls = []
    material = object()
    class Service:
        def get_for_assertion(self, rp_id, credential_id):
            assert rp_id == "example.com"
            assert credential_id == b"credential-id-123"
            return material
        def commit_use(self, selected, *, used_at):
            calls.append((selected, used_at))
    broker = PasskeyBroker(Service(), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    encoded = base64.urlsafe_b64encode(b"credential-id-123").rstrip(b"=").decode()
    reply = broker.dispatch(PEER, request("commit-use", {
        "rpId": "example.com", "credentialId": encoded,
        "lastUsedAt": "2026-08-28T08:00:00Z", "signCount": "0",
    }))
    assert reply == {"ok": True, "result": {"committed": True}}
    assert calls == [(material, dt.datetime(2026, 8, 28, 8, tzinfo=dt.timezone.utc))]


def test_list_applies_platform_allow_credential_ids():
    first = CredentialMetadata("example.com", b"first-credential", b"user-1", "one", "One")
    second = CredentialMetadata("example.com", b"second-credential", b"user-2", "two", "Two")
    class Service:
        def list_metadata(self, rp_id):
            assert rp_id == "example.com"
            return (first, second)
    broker = PasskeyBroker(Service(), peer_validator=lambda peer: True, now_ms=lambda: 1000)
    allowed = base64.urlsafe_b64encode(second.credential_id).rstrip(b"=").decode()
    reply = broker.dispatch(PEER, request("list", {
        "rpId": "example.com", "allowCredentialIds": [allowed],
    }))
    assert reply["ok"] is True
    assert [item["userName"] for item in reply["result"]["credentials"]] == ["two"]
