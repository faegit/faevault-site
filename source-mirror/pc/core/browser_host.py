"""Native-host controller independent from the browser transport and Qt UI."""

from __future__ import annotations

import time
import unicodedata
from dataclasses import dataclass
from typing import Callable, Literal
from urllib.parse import urlsplit

from . import autofill_otp, autofill_resolver
from .browser_autofill import BrowserRequest, ProtocolError, is_ip_origin, matching_entries, word_matching_entries, origin_is_excluded, browser_match_reason, normalize_origin
from .models import Entry, SecretType
from .autofill_sources import entry_is_fillable, with_linked_sources, entry_bindings, AUTOFILL_BINDINGS_KEY, shares_matching_word, entry_matching_text
from .storage import ExternalVaultChange, Vault


@dataclass(frozen=True)
class SaveSelection:
    action: Literal["create", "update", "cancel"]
    credential_id: str | None = None


@dataclass(frozen=True)
class FillSelection:
    allow: bool
    remember: bool = False


UnlockVault = Callable[[], Vault | None]
UnlockWithPassword = Callable[[str], Vault]
ConfirmSave = Callable[[BrowserRequest, list[Entry]], SaveSelection]
AuthorizeOrigin = Callable[[str], bool]
IsOriginAuthorized = Callable[[str], bool]
IsOriginExcluded = Callable[[str], bool]
ConfirmWordMatch = Callable[[str, Entry], bool | FillSelection]


class BrowserAutofillController:
    def __init__(
        self,
        unlock_vault: UnlockVault,
        confirm_save: ConfirmSave,
        *,
        unlock_with_password: UnlockWithPassword | None = None,
        is_origin_authorized: IsOriginAuthorized | None = None,
        authorize_origin: AuthorizeOrigin | None = None,
        is_origin_excluded: IsOriginExcluded | None = None,
        confirm_word_match: ConfirmWordMatch | None = None,
        confirm_field_mapping: Callable[[str, Entry, str, str], bool] | None = None,
        lock_after_seconds: Callable[[], int],
        clock: Callable[[], float] = time.monotonic,
        otp_clock: Callable[[], float] = time.time,
    ):
        self._unlock_vault = unlock_vault
        self._confirm_save = confirm_save
        self._unlock_with_password = unlock_with_password
        self._is_origin_authorized = is_origin_authorized
        self._authorize_origin = authorize_origin
        self._is_origin_excluded = is_origin_excluded
        self._confirm_word_match = confirm_word_match
        self._confirm_field_mapping = confirm_field_mapping
        self._lock_after_seconds = lock_after_seconds
        self._clock = clock
        self._otp_clock = otp_clock
        self._vault: Vault | None = None
        self._last_used = 0.0

    def close(self) -> None:
        if self._vault is not None:
            self._vault.close()
        self._vault = None
        self._last_used = 0.0

    def handle(self, request: BrowserRequest) -> dict:
        if request.action == "status":
            return {"locked": not self._session_alive()}
        if request.action == "unlock":
            if self._session_alive():
                return {"locked": False, "alreadyUnlocked": True}
            if self._unlock_with_password is None:
                raise ProtocolError("UNSUPPORTED_ACTION", "当前宿主不支持浏览器解锁")
            self.close()
            self._vault = self._unlock_with_password(request.master_password)
            self._last_used = self._clock()
            return {"locked": False, "alreadyUnlocked": False}
        if request.action == "lock":
            self.close()
            return {"locked": True}
        vault = self._fresh_vault()
        if request.action == "authorize":
            if not request.origin or not is_ip_origin(request.origin):
                raise ProtocolError("INVALID_ORIGIN", "当前网页不是可授权的 IP 地址来源")
            if self._authorize_origin is None or not self._authorize_origin(request.origin):
                raise ProtocolError("ORIGIN_NOT_AUTHORIZED", "未允许在此 IP 地址自动填充", retryable=True)
            return {"authorized": True, "origin": request.origin}
        self._ensure_origin_allowed(request.origin)
        if request.origin and self._origin_excluded(vault, request.origin):
            if request.action == "list":
                return {"locked": False, "credentials": [], "excluded": True}
            raise ProtocolError("ORIGIN_EXCLUDED", "此网站已关闭自动填充")
        if request.action == "list":
            matches = self._candidate_matches(vault, request.origin or "")
            if request.query:
                all_entries = [e for eid in vault.list_entry_ids(SecretType.LOGIN) if (e := vault.read_entry(eid)) is not None]
                sources = with_linked_sources(vault, all_entries)
                matches = [e for e in all_entries if e.deleted_at is None and entry_is_fillable(e, sources)
                           and unicodedata.normalize("NFKC", request.query).casefold() in unicodedata.normalize("NFKC", entry_matching_text(e) + " " + e.username).casefold()]
                matches.sort(key=lambda e: (e.title.casefold(), e.username.casefold(), e.id))
            represented_otp_ids = {
                source.id
                for entry in matches
                if not self._is_word_match(entry, request.origin or "")
                and (source := autofill_otp.resolve_source(vault, entry)) is not None
            }
            standalone = [
                entry
                for entry in autofill_otp.matching_standalone(vault, request.origin or "")
                if entry.id not in represented_otp_ids
            ]
            return {
                "locked": False,
                "credentials": [
                    dict(self._credential_summary(vault, entry, request.origin or ""), **({"matchReason": "manual", "requiresSelection": True, "manualSelection": True} if request.query and browser_match_reason(entry, request.origin or "") is None else {}))
                    for entry in (*matches, *standalone)
                ],
            }
        if request.action == "get":
            selected = self._find_autofill_entry(vault, request.origin or "", request.credential_id or "")
            if selected is None:
                selected = next((entry for entry in self._candidate_matches(vault, request.origin or "")
                                 if entry.id == request.credential_id), None)
                if selected is None and request.manual_selection:
                    candidate = vault.read_entry(request.credential_id or "")
                    if candidate is not None and candidate.secret_type == SecretType.LOGIN and candidate.deleted_at is None and entry_is_fillable(candidate, with_linked_sources(vault, [candidate])):
                        selected = candidate
                if selected is None:
                    raise ProtocolError("NOT_FOUND", "凭据不存在或已不再匹配此网页")
                decision = self._confirm_word_match(request.origin or "", selected) if self._confirm_word_match else False
                consent = decision if isinstance(decision, FillSelection) else FillSelection(bool(decision))
                if not consent.allow:
                    raise ProtocolError("ORIGIN_NOT_AUTHORIZED", "未允许将所选条目填充到此网页")
                # Consent applies to this one release and the exact selected revision.
                approved = selected.to_dict()
                vault = self._fresh_vault()
                selected = vault.read_entry(selected.id)
                if (self._origin_excluded(vault, request.origin or "") or selected is None
                        or selected.to_dict() != approved
                        or (not request.manual_selection and not browser_match_reason(selected, request.origin or ""))):
                    raise ProtocolError("CONFLICT", "条目或网页权限已变化，请重试", retryable=True)
                if consent.remember:
                    changed = Entry.from_dict(selected.to_dict())
                    origin = normalize_origin(request.origin, allow_ip=True)
                    binding = {"kind": "web", "host": urlsplit(origin).hostname, "origin": origin}
                    changed.fields[AUTOFILL_BINDINGS_KEY] = [*entry_bindings(changed), binding]
                    vault.update(changed)
                    selected = changed
            linked = [
                source
                for link in selected.autofill_links()
                if (source := vault.read_entry(link.source_entry_id)) is not None
            ]
            snapshot = autofill_resolver.resolve_snapshot(
                selected,
                [selected, *linked],
                now=self._otp_clock(),
            )
            fields = {role: value.value for role, value in snapshot.values.items()}
            result = {
                "username": fields.get("username", selected.username),
                "password": fields.get("password", selected.password),
                "fields": fields,
                "unavailableRoles": sorted(snapshot.unavailable_roles),
            }
            otp_source_id = snapshot.values.get("one_time_code").source_entry_id if snapshot.values.get("one_time_code") else selected.id
            otp_source = vault.read_entry(otp_source_id) if otp_source_id != selected.id else selected
            otp_value = autofill_otp.snapshot(vault, otp_source, now=self._otp_clock()) if otp_source is not None else None
            if otp_value is not None:
                result["otp"] = self._otp_payload(otp_value)
                if otp_value.kind == "hotp":
                    autofill_otp.advance_hotp(vault, otp_value.source_id)
            from .autofill_field_mapping import mappings_for
            mappings = mappings_for(selected, request.origin or "")
            if mappings:
                result["fieldMappings"] = mappings
            return result
        if request.action == "map_field":
            selected = vault.read_entry(request.credential_id or "")
            if selected is None or selected.deleted_at is not None or selected.secret_type != SecretType.LOGIN:
                raise ProtocolError("NOT_FOUND", "凭据不存在")
            linked = [source for link in selected.autofill_links() if (source := vault.read_entry(link.source_entry_id)) is not None]
            snapshot = autofill_resolver.resolve_snapshot(selected, [selected, *linked], now=self._otp_clock())
            if request.field_role and request.field_role not in snapshot.values:
                raise ProtocolError("INVALID_REQUEST", "条目没有此字段角色")
            approved = selected.to_dict()
            if self._confirm_field_mapping is None or not self._confirm_field_mapping(request.origin or "", selected, request.field_key, request.field_role):
                raise ProtocolError("ORIGIN_NOT_AUTHORIZED", "未允许保存字段映射")
            vault = self._fresh_vault()
            current = vault.read_entry(selected.id)
            if self._origin_excluded(vault, request.origin or "") or current is None or current.to_dict() != approved:
                raise ProtocolError("CONFLICT", "条目或网页权限已变化，请重试", retryable=True)
            linked = [source for link in current.autofill_links() if (source := vault.read_entry(link.source_entry_id)) is not None]
            snapshot = autofill_resolver.resolve_snapshot(current, [current, *linked], now=self._otp_clock())
            if request.field_role and request.field_role not in snapshot.values:
                raise ProtocolError("CONFLICT", "字段来源已变化，请重试", retryable=True)
            from .autofill_field_mapping import with_mapping, mappings_for
            changed = with_mapping(current, request.origin or "", request.field_key, request.field_role)
            vault.update(changed)
            return {"fieldMappings": mappings_for(changed, request.origin or "")}
        if request.action == "save":
            return self._save(request, vault)
        raise ProtocolError("UNSUPPORTED_ACTION", "不支持的操作")

    def _session_alive(self) -> bool:
        if self._vault is None:
            return False
        timeout = max(30, min(int(self._lock_after_seconds()), 3600))
        if self._clock() - self._last_used >= timeout:
            self.close()
            return False
        return True

    def _fresh_vault(self) -> Vault:
        if not self._session_alive():
            self.close()
            self._vault = self._unlock_vault()
            if self._vault is None:
                raise ProtocolError("LOCKED", "未解锁保险库", retryable=True)
        else:
            try:
                self._vault = self._vault.reopen()
            except Exception as exc:
                self.close()
                raise ProtocolError("LOCKED", "保险库会话已失效", retryable=True) from exc
        self._last_used = self._clock()
        return self._vault

    @staticmethod
    def _find(vault: Vault, origin: str, credential_id: str) -> Entry | None:
        return next((entry for entry in BrowserAutofillController._matches(vault, origin)
                     if entry.id == credential_id), None)

    def _find_autofill_entry(self, vault: Vault, origin: str, credential_id: str) -> Entry | None:
        selected = self._find(vault, origin, credential_id)
        if selected is not None:
            return selected
        return next(
            (entry for entry in autofill_otp.matching_standalone(vault, origin) if entry.id == credential_id),
            None,
        )

    def _credential_summary(self, vault: Vault, entry: Entry, origin: str) -> dict:
        result = {
            "id": entry.id,
            "title": entry.title[:256],
            "username": entry.username[:512],
            "origin": origin,
            "kind": "otp" if entry.secret_type == SecretType.OTP else "login",
            "matchReason": browser_match_reason(entry, origin) if entry.secret_type == SecretType.LOGIN else "exact",
        }
        if self._is_word_match(entry, origin):
            result["requiresSelection"] = True
            return result
        otp_value = autofill_otp.snapshot(vault, entry, now=self._otp_clock())
        if otp_value is not None:
            result["otp"] = self._otp_payload(otp_value)
        return result

    @staticmethod
    def _otp_payload(value: autofill_otp.OtpSnapshot) -> dict:
        return {
            "code": value.code,
            "type": value.kind,
            "remaining": value.remaining,
            "expiresAt": value.expires_at,
            "issuer": value.issuer[:256],
            "label": value.label[:256],
        }

    @staticmethod
    def _matches(vault: Vault, origin: str) -> list[Entry]:
        candidates = [entry for entry_id in vault.list_entry_ids(SecretType.LOGIN)
                      if (entry := vault.read_entry(entry_id)) is not None]
        sources = with_linked_sources(vault, candidates)
        return [e for e in candidates if e.deleted_at is None and entry_is_fillable(e, sources)
                and browser_match_reason(e, origin) in {"confirmed", "exact"}]

    @staticmethod
    def _is_word_match(entry: Entry, origin: str) -> bool:
        return entry.secret_type == SecretType.LOGIN and browser_match_reason(entry, origin) not in {"confirmed", "exact"}

    @staticmethod
    def _candidate_matches(vault: Vault, origin: str) -> list[Entry]:
        candidates = [entry for entry_id in vault.list_entry_ids(SecretType.LOGIN)
                      if (entry := vault.read_entry(entry_id)) is not None]
        sources = with_linked_sources(vault, candidates)
        matches = [e for e in candidates if e.deleted_at is None and entry_is_fillable(e, sources)
                   and browser_match_reason(e, origin)]
        rank = {"confirmed": 0, "exact": 1, "same_site": 2, "name": 3}
        return sorted(matches, key=lambda e: (rank[browser_match_reason(e, origin)], e.title.casefold(), e.username.casefold(), e.id))[:20]

    def _origin_excluded(self, vault: Vault, origin: str) -> bool:
        rules = getattr(vault, "autofill_exclusions", None)
        if isinstance(rules, dict):
            return origin_is_excluded(origin, rules.get("hosts", []))
        return bool(self._is_origin_excluded is not None and self._is_origin_excluded(origin))

    def _ensure_origin_allowed(self, origin: str | None) -> None:
        if not origin or not is_ip_origin(origin):
            return
        if self._is_origin_authorized is None or not self._is_origin_authorized(origin):
            raise ProtocolError("ORIGIN_NOT_AUTHORIZED", "此 IP 地址尚未授权自动填充", retryable=True)

    def _save(self, request: BrowserRequest, vault: Vault) -> dict:
        matches = self._matches(vault, request.origin or "")
        unchanged = next(
            (
                entry
                for entry in matches
                if entry.username == request.username and entry.password == request.password
            ),
            None,
        )
        if unchanged is not None:
            return {"status": "unchanged", "credentialId": unchanged.id}

        selection = self._confirm_save(request, matches)
        if selection.action == "cancel":
            return {"status": "cancelled"}
        vault = self._fresh_vault()
        if self._origin_excluded(vault, request.origin or ""):
            raise ProtocolError("ORIGIN_EXCLUDED", "此网站已关闭自动填充")
        try:
            if selection.action == "update":
                selected = self._find(vault, request.origin or "", selection.credential_id or "")
                if selected is None:
                    raise ProtocolError("CONFLICT", "条目已变化，请重试", retryable=True)
                changed = Entry.from_dict(selected.to_dict())
                changed.username = request.username
                changed.password = request.password
                changed.invalidate_haystack()
                vault.update(changed)
                return {"status": "updated", "credentialId": changed.id}

            host = urlsplit(request.origin or "").hostname or "登录条目"
            entry = Entry(
                title=request.title.strip() or host,
                username=request.username,
                password=request.password,
                url=request.origin or "",
            )
            vault.add(entry)
            return {"status": "created", "credentialId": entry.id}
        except ExternalVaultChange as exc:
            raise ProtocolError("CONFLICT", "保险库已在其他窗口更新，请重试", retryable=True) from exc
