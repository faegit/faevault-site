from core import autofill_otp, modules
from core.models import Entry, SecretType
from core.storage import Vault


def _otp_entry(*, kind="totp", counter="0", domains="example.com") -> Entry:
    module = modules.new_module(modules.OTP)
    module["value"].update(
        secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        type=kind,
        counter=counter,
        issuer="Example",
        label="alice",
        otp_domains=domains,
    )
    return Entry(
        title="Example code",
        secret_type=SecretType.OTP,
        fields=modules.fields_with_modules({}, [module]),
    )


def test_bound_otp_is_resolved_by_id_without_materializing_vault(tmp_path, monkeypatch) -> None:
    path = tmp_path / "bound.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    source = _otp_entry()
    login = Entry(title="Login", username="alice", password="secret", fields={"bound_otp_id": source.id})
    vault.add(source)
    vault.add(login)

    reads = []
    original = Vault.read_entry

    def recording_read(self, entry_id):
        reads.append(entry_id)
        return original(self, entry_id)

    monkeypatch.setattr(Vault, "read_entry", recording_read)
    result = autofill_otp.snapshot(vault, login, now=59)

    assert result is not None
    assert result.source_id == source.id
    assert result.code == "287082"
    assert result.remaining == 1
    assert reads == [source.id]


def test_embedded_otp_has_priority_over_bound_external_otp(tmp_path, monkeypatch) -> None:
    path = tmp_path / "priority.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    external = _otp_entry()
    internal_module = modules.new_module(modules.OTP)
    internal_module["value"].update(
        secret="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        issuer="Internal",
    )
    login = Entry(
        title="Login",
        username="alice",
        password="secret",
        fields=modules.fields_with_modules({"bound_otp_id": external.id}, [internal_module]),
    )
    vault.add(external)
    vault.add(login)

    reads = []
    monkeypatch.setattr(vault, "read_entry", lambda entry_id: reads.append(entry_id))
    result = autofill_otp.snapshot(vault, login, now=59)

    assert result is not None
    assert result.source_id == login.id
    assert result.issuer == "Internal"
    assert reads == []


def test_standalone_otp_search_reads_only_otp_summaries(tmp_path, monkeypatch) -> None:
    path = tmp_path / "standalone.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    wanted = _otp_entry()
    other = _otp_entry(domains="other.example")
    login = Entry(title="Login", username="alice", password="secret", url="https://example.com")
    vault.add(wanted)
    vault.add(other)
    vault.add(login)

    reads = []
    original = Vault.read_entry

    def recording_read(self, entry_id):
        reads.append(entry_id)
        return original(self, entry_id)

    monkeypatch.setattr(Vault, "read_entry", recording_read)
    matches = autofill_otp.matching_standalone(vault, "https://example.com")

    assert [entry.id for entry in matches] == [wanted.id]
    assert reads == [wanted.id, other.id]


def test_hotp_counter_advances_in_latest_entry(tmp_path) -> None:
    path = tmp_path / "hotp.pmv"
    vault = Vault.create_pmve(path, "master", b"r" * 32)
    source = _otp_entry(kind="hotp", counter="0")
    vault.add(source)

    autofill_otp.advance_hotp(vault, source.id)

    latest = vault.read_entry(source.id)
    assert latest is not None
    assert latest.otp_fields()["counter"] == "1"
