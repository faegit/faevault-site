"""OTP resolution shared by browser and native autofill.

Login candidates continue to come from LoginFastIndex.  A bound standalone OTP
is resolved by id, while an explicit OTP chooser enumerates only OTP summaries
from EntryIndex and decrypts those entries on demand.
"""

from __future__ import annotations

import copy
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import modules, otp
from .models import Entry, SecretType
from .storage import Vault


@dataclass(frozen=True, slots=True)
class OtpSnapshot:
    source_id: str
    code: str
    kind: str
    remaining: int | None
    expires_at: int | None
    issuer: str
    label: str


def resolve_source(vault: Vault, entry: Entry) -> Entry | None:
    """Return an embedded OTP login or its live bound standalone OTP entry."""
    if entry.deleted_at is None and entry.has_otp():
        return entry
    bound_id = entry.otp_binding_id()
    if not bound_id:
        return None
    source = vault.read_entry(bound_id)
    if source is None or source.deleted_at is not None or source.secret_type != SecretType.OTP:
        return None
    return source if source.has_otp() else None


def snapshot(vault: Vault, entry: Entry, *, now: float | None = None) -> OtpSnapshot | None:
    source = resolve_source(vault, entry)
    if source is None:
        return None
    fields = otp.normalize_fields(source.otp_fields())
    code = otp.code_from_fields(fields, now)
    if code == "ERROR":
        return None
    kind = fields["type"]
    remaining = otp.seconds_remaining(fields, now) if kind == "totp" else None
    current = time.time() if now is None else now
    expires_at = int((current + remaining) * 1000) if remaining is not None else None
    return OtpSnapshot(
        source_id=source.id,
        code=code,
        kind=kind,
        remaining=remaining,
        expires_at=expires_at,
        issuer=fields.get("issuer", ""),
        label=fields.get("label", ""),
    )


def matching_standalone(vault: Vault, origin: str) -> list[Entry]:
    """Find standalone OTP entries explicitly associated with a web host."""
    host = (urlsplit(origin).hostname or "").rstrip(".").casefold()
    if not host:
        return []
    result: list[Entry] = []
    for entry_id in vault.list_entry_ids(SecretType.OTP):
        entry = vault.read_entry(entry_id)
        if entry is None or entry.deleted_at is not None or not entry.has_otp():
            continue
        domains = {value.rstrip(".").casefold() for value in entry.otp_domains()}
        if host in domains:
            result.append(entry)
    return sorted(result, key=lambda value: (value.title.casefold(), value.id))


def advance_hotp(vault: Vault, source_id: str) -> None:
    """Advance the latest stored HOTP counter after a code is consumed."""
    current = vault.read_entry(source_id)
    if current is None or current.deleted_at is not None:
        return
    fields = otp.normalize_fields(current.otp_fields())
    if fields.get("type") != "hotp" or not fields.get("secret"):
        return
    changed = copy.deepcopy(current)
    next_counter = str(int(fields.get("counter", "0")) + 1)
    module_values = modules.modules_from_fields(changed.fields)
    for module in module_values:
        if module.get("type") == modules.OTP and isinstance(module.get("value"), dict):
            module["value"]["counter"] = next_counter
            changed.fields = modules.fields_with_modules(changed.fields, module_values)
            break
    else:
        changed.fields["counter"] = next_counter
    vault.update(changed)
