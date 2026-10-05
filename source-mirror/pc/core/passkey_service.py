"""Vault-side operations exposed to the native Windows Passkey provider."""

from __future__ import annotations

import copy
import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import modules, passkeys
from .models import Entry, SecretType


class PasskeyServiceError(RuntimeError):
    pass


class VaultLocked(PasskeyServiceError):
    pass


class DuplicateCredential(PasskeyServiceError):
    pass


class UnusableCredential(PasskeyServiceError):
    pass


@dataclass(frozen=True)
class CredentialMetadata:
    rp_id: str
    credential_id: bytes = field(repr=False)
    user_id: bytes = field(repr=False)
    user_name: str
    user_display_name: str


@dataclass(frozen=True)
class AssertionMaterial:
    entry_id: str
    module_id: str
    record: dict = field(repr=False)


class PasskeyService:
    def __init__(self, vault_provider: Callable[[], object | None]):
        self._vault_provider = vault_provider

    def commit_created(self, record: dict) -> str:
        parsed = passkeys.parse_record(record)
        if parsed.key_mode != "syncable":
            raise UnusableCredential("credential is not available on this device")
        vault = self._vault()
        if self._find(vault.entries, parsed.identity):
            raise DuplicateCredential("credential already exists")
        raw = parsed.value
        module_id = str(uuid.uuid4())
        module = {
            "id": module_id,
            "type": modules.PASSKEY,
            "title": "通行密钥",
            "sensitive": True,
            "config": {},
            "value": raw,
        }
        entry = Entry(
            title=raw.get("rp_name") or parsed.rp_id,
            username=raw.get("user_name") or "",
            url=f"https://{parsed.rp_id}",
            secret_type=SecretType.PASSKEY,
            fields=modules.fields_with_modules({}, [module]),
        )
        vault.add(entry)
        return entry.id

    def list_metadata(self, rp_id: str | None = None) -> tuple[CredentialMetadata, ...]:
        vault = self._vault()
        normalized = passkeys.normalized_rp_id(rp_id) if rp_id else None
        output: list[CredentialMetadata] = []
        for _entry, _module, parsed in self._usable(vault.entries):
            if normalized is not None and parsed.rp_id != normalized:
                continue
            raw = parsed.value
            output.append(CredentialMetadata(
                parsed.rp_id,
                parsed.credential_id_bytes,
                passkeys.decode_user_id(raw["user_id"]),
                raw.get("user_name") or "",
                raw.get("user_display_name") or "",
            ))
        return tuple(output)

    def get_for_assertion(self, rp_id: str, credential_id: bytes) -> AssertionMaterial:
        identity = (passkeys.normalized_rp_id(rp_id), bytes(credential_id))
        matches = self._find(self._vault().entries, identity)
        usable = [(entry, module, parsed) for entry, module, parsed in matches if self._is_usable(module, parsed)]
        if len(matches) != 1 or len(usable) != 1:
            raise UnusableCredential("credential is missing, damaged, or conflicted")
        entry, module, parsed = usable[0]
        return AssertionMaterial(entry.id, str(module.get("id") or ""), parsed.value)

    def commit_use(self, material: AssertionMaterial, *, used_at: dt.datetime) -> None:
        vault = self._vault()
        for current in vault.entries:
            if current.id != material.entry_id:
                continue
            updated = copy.deepcopy(current)
            updated_modules = modules.modules_from_fields(updated.fields)
            found = False
            for module in updated_modules:
                if module.get("id") != material.module_id:
                    continue
                parsed = passkeys.parse_record(module.get("value"))
                value = parsed.value
                value["last_used_at"] = used_at.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
                value["sign_count"] = "0"
                module["value"] = passkeys.validate_record(value)
                found = True
                break
            if not found:
                raise UnusableCredential("credential changed before usage commit")
            updated.fields = modules.fields_with_modules(updated.fields, updated_modules)
            vault.update(updated)
            return
        raise UnusableCredential("credential no longer exists")

    def _vault(self):
        vault = self._vault_provider()
        if vault is None:
            raise VaultLocked("vault is locked")
        return vault

    @classmethod
    def _usable(cls, entries: Iterable[Entry]):
        for entry in entries:
            if entry.deleted_at is not None:
                continue
            for module in modules.modules_from_fields(entry.fields):
                if module.get("type") != modules.PASSKEY:
                    continue
                try:
                    parsed = passkeys.parse_record(module.get("value"))
                except passkeys.PasskeyError:
                    continue
                if cls._is_usable(module, parsed):
                    yield entry, module, parsed

    @staticmethod
    def _is_usable(module: dict, parsed: passkeys.ValidatedPasskey) -> bool:
        config = module.get("config")
        return (
            parsed.key_mode == "syncable"
            and isinstance(config, dict)
            and not config.get("passkeyConflictStatus")
        )

    @staticmethod
    def _find(entries: Iterable[Entry], identity: tuple[str, bytes]):
        found = []
        for entry in entries:
            if entry.deleted_at is not None:
                continue
            for module in modules.modules_from_fields(entry.fields):
                if module.get("type") != modules.PASSKEY:
                    continue
                try:
                    parsed = passkeys.parse_record(module.get("value"))
                except passkeys.PasskeyError:
                    continue
                if parsed.identity == identity:
                    found.append((entry, module, parsed))
        return found
