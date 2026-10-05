"""Resolve internal and explicitly linked external values into one fill snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from . import autofill_sources, modules, otp
from .models import Entry


@dataclass(frozen=True, slots=True)
class ResolvedAutofillValue:
    role: str
    value: str
    source_entry_id: str
    module_id: str | None
    source_key: str
    requires_verification: bool


@dataclass(frozen=True, slots=True)
class AutofillSnapshot:
    values: Mapping[str, ResolvedAutofillValue]
    unavailable_roles: frozenset[str]

    def __getitem__(self, role: str) -> ResolvedAutofillValue:
        return self.values[role]

    def get(self, role: str) -> ResolvedAutofillValue | None:
        return self.values.get(role)


def resolve_snapshot(entry: Entry, entries: Iterable[Entry], *, now: float | None = None) -> AutofillSnapshot:
    """Build an immutable snapshot; remembered external choices win per role."""
    by_id = {candidate.id: candidate for candidate in entries if candidate.deleted_at is None}
    by_id.setdefault(entry.id, entry)
    values: dict[str, ResolvedAutofillValue] = {}
    unavailable: set[str] = set()

    for candidate in _entry_values(entry, now=now):
        values.setdefault(candidate.role, candidate)

    for link in entry.autofill_links():
        source = by_id.get(link.source_entry_id)
        for ref in link.fields:
            resolved = _resolve_ref(source, ref, now=now)
            if resolved is None:
                values.pop(ref.role, None)
                unavailable.add(ref.role)
            else:
                values[ref.role] = resolved
                unavailable.discard(ref.role)

    return AutofillSnapshot(MappingProxyType(values), frozenset(unavailable))


def source_values(entry: Entry, *, now: float | None = None) -> tuple[ResolvedAutofillValue, ...]:
    """List fields that a user may explicitly select as an external source."""
    return tuple(_entry_values(entry, now=now))


def _entry_values(entry: Entry, *, now: float | None) -> list[ResolvedAutofillValue]:
    result: list[ResolvedAutofillValue] = []
    for key in ("username", "password"):
        policy = autofill_sources.policy_for_top_level(key)
        value = getattr(entry, key, "")
        if policy is not None and isinstance(value, str) and value:
            result.append(_resolved(entry.id, None, key, value, policy))
    # Built-in entry editors are persisted as top-level fields on both
    # clients.  Keep their original key in the reference so a link remains
    # stable if a later client also adds a module with the same fill role.
    for key, value in entry.fields.items():
        policy = autofill_sources.policy_for_top_level(key)
        if policy is not None and isinstance(value, str) and value:
            result.append(_resolved(entry.id, None, key, value, policy))

    module_otp_ids: set[str] = set()
    for module in modules.modules_from_fields(entry.fields):
        if module.get("type") == modules.OTP:
            module_otp_ids.add(str(module.get("id") or ""))
        result.extend(_module_values(entry.id, module, now=now))
    # Standalone Android OTP entries use top-level OTP fields; use the same
    # computed source key as the module form.  A module wins when both shapes
    # are present, matching Entry.otp_fields() and avoiding duplicate codes.
    if entry.secret_type == "otp" and not module_otp_ids:
        fields = entry.otp_fields()
        if fields.get("secret"):
            policy = autofill_sources.policy_for_field("otp", "@computed/one_time_code")
            try:
                code = otp.code_from_fields(fields, now)
            except (TypeError, ValueError):
                code = ""
            if policy is not None and code != "ERROR":
                result.append(_resolved(entry.id, None, "@computed/one_time_code", code, policy))
    return result


def _module_values(entry_id: str, module: dict, *, now: float | None) -> list[ResolvedAutofillValue]:
    module_type = str(module.get("type") or "")
    module_id = str(module.get("id") or "") or None
    value = module.get("value")
    configured = modules.configured_autofill_role(module)
    if module_type in {modules.TEXT, modules.PASSWORD, modules.DATETIME} and configured is not None:
        if isinstance(value, str) and value:
            policy = autofill_sources.FieldPolicy(
                configured,
                True,
                configured not in autofill_sources.SENSITIVE_ROLES,
                configured in autofill_sources.SENSITIVE_ROLES,
            )
            return [_resolved(entry_id, module_id, "value", value, policy)]
        return []
    if module_type == modules.OTP and isinstance(value, dict) and value.get("secret"):
        policy = autofill_sources.policy_for_field(module_type, "@computed/one_time_code")
        try:
            code = otp.code_from_fields(value, now)
        except (TypeError, ValueError):
            code = ""
        return [_resolved(entry_id, module_id, "@computed/one_time_code", code, policy)] if policy and code != "ERROR" else []
    if not isinstance(value, dict):
        return []
    result: list[ResolvedAutofillValue] = []
    for source_key, raw in value.items():
        policy = autofill_sources.policy_for_field(module_type, source_key)
        if policy is not None and isinstance(raw, str) and raw:
            result.append(_resolved(entry_id, module_id, source_key, raw, policy))
    return result


def _resolve_ref(source: Entry | None, ref: autofill_sources.AutofillFieldRef, *, now: float | None) -> ResolvedAutofillValue | None:
    if source is None:
        return None
    candidates = _entry_values(source, now=now)
    for candidate in candidates:
        if (
            candidate.module_id == ref.module_id
            and candidate.source_key == ref.source_key
            and candidate.role == ref.role
        ):
            return ResolvedAutofillValue(
                role=candidate.role,
                value=candidate.value,
                source_entry_id=candidate.source_entry_id,
                module_id=candidate.module_id,
                source_key=candidate.source_key,
                requires_verification=autofill_sources.enforce_verification(
                    candidate.role,
                    ref.requires_verification,
                ),
            )
    return None


def _resolved(entry_id: str, module_id: str | None, source_key: str, value: str, policy: autofill_sources.FieldPolicy) -> ResolvedAutofillValue:
    return ResolvedAutofillValue(
        role=policy.role,
        value=value,
        source_entry_id=entry_id,
        module_id=module_id,
        source_key=source_key,
        requires_verification=policy.requires_verification,
    )
