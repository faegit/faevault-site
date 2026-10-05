"""Authenticated dispatch core for the Windows Passkey named-pipe broker."""

from __future__ import annotations

import base64
import datetime as dt
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from .passkey_broker_protocol import Request, b64u_decode
from .passkey_service import (
    PasskeyService,
    PasskeyServiceError,
    UnusableCredential,
    VaultLocked,
)


class BrokerError(RuntimeError):
    pass


class OperationState(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class VerifiedPeer:
    process_id: int
    user_sid: str
    package_family_name: str
    image_path: str
    publisher_thumbprint: str


class OperationRegistry:
    """Thread-safe replay prevention and exactly-once terminal transitions."""

    def __init__(self, *, limit: int = 128):
        self._limit = limit
        self._states: dict[uuid.UUID, OperationState] = {}
        self._lock = threading.Lock()

    def begin(self, request_id: uuid.UUID) -> bool:
        with self._lock:
            if request_id in self._states or len(self._states) >= self._limit:
                return False
            self._states[request_id] = OperationState.ACTIVE
            return True

    def complete(self, request_id: uuid.UUID) -> bool:
        return self._finish(request_id, OperationState.COMPLETED)

    def cancel(self, request_id: uuid.UUID) -> bool:
        return self._finish(request_id, OperationState.CANCELLED)

    def state(self, request_id: uuid.UUID) -> OperationState | None:
        with self._lock:
            return self._states.get(request_id)

    def _finish(self, request_id: uuid.UUID, terminal: OperationState) -> bool:
        with self._lock:
            if self._states.get(request_id) is not OperationState.ACTIVE:
                return False
            self._states[request_id] = terminal
            return True


class PasskeyBroker:
    def __init__(
        self,
        service: PasskeyService,
        *,
        peer_validator: Callable[[VerifiedPeer], bool],
        now_ms: Callable[[], int] | None = None,
    ):
        self._service = service
        self._peer_validator = peer_validator
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._operations = OperationRegistry()
        self._challenge = secrets.token_bytes(32)

    @property
    def challenge(self) -> bytes:
        return self._challenge

    def dispatch(self, peer: VerifiedPeer, request: Request) -> dict[str, Any]:
        if not self._peer_validator(peer):
            return self._error("unauthorized_peer")
        if request.deadline_ms <= self._now_ms():
            return self._error("request_expired")
        if request.type == "cancel":
            return self._cancel(request)
        if not self._operations.begin(request.request_id):
            return self._error("duplicate_or_busy")
        try:
            result = self._dispatch_active(request)
        except VaultLocked:
            result = self._error("vault_locked")
        except UnusableCredential:
            result = self._error("credential_unusable")
        except PasskeyServiceError:
            result = self._error("vault_operation_failed")
        except Exception:
            result = self._error("internal_error")
        if not self._operations.complete(request.request_id):
            return self._error("cancelled")
        return result

    def _dispatch_active(self, request: Request) -> dict[str, Any]:
        payload = request.payload
        if request.type == "hello":
            supplied = b64u_decode(payload.get("challenge"), maximum=64)
            if not secrets.compare_digest(supplied, self._challenge):
                return self._error("challenge_mismatch")
            return {"ok": True, "result": {"authenticated": True}}
        if request.type == "status":
            self._service.list_metadata()
            return {"ok": True, "result": {"locked": False}}
        if request.type == "list":
            requested_rp = str(payload.get("rpId") or "")
            items = self._service.list_metadata(requested_rp or None)
            raw_allow = payload.get("allowCredentialIds")
            if raw_allow:
                if not isinstance(raw_allow, list):
                    raise PasskeyServiceError("invalid credential allow list")
                allow = {b64u_decode(value, maximum=1024) for value in raw_allow}
                items = tuple(item for item in items if item.credential_id in allow)
            return {"ok": True, "result": {"credentials": [self._metadata(item) for item in items]}}
        if request.type == "make":
            record = payload.get("record")
            if not isinstance(record, dict):
                raise PasskeyServiceError("invalid record")
            return {"ok": True, "result": {"entryId": self._service.commit_created(record)}}
        if request.type == "get":
            material = self._service.get_for_assertion(
                str(payload.get("rpId") or ""), b64u_decode(payload.get("credentialId"), maximum=1024)
            )
            return {"ok": True, "result": {
                "entryId": material.entry_id,
                "moduleId": material.module_id,
                "record": material.record,
            }}
        if request.type == "commit-use":
            material = self._service.get_for_assertion(
                str(payload.get("rpId") or ""), b64u_decode(payload.get("credentialId"), maximum=1024)
            )
            used_at = self._parse_utc(payload.get("lastUsedAt"))
            if str(payload.get("signCount")) != "0":
                raise PasskeyServiceError("syncable credentials require a zero sign counter")
            self._service.commit_use(material, used_at=used_at)
            return {"ok": True, "result": {"committed": True}}
        raise PasskeyServiceError("message is not dispatchable")

    @staticmethod
    def _parse_utc(value: object) -> dt.datetime:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise PasskeyServiceError("invalid usage timestamp")
        try:
            parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise PasskeyServiceError("invalid usage timestamp") from exc
        if parsed.tzinfo is None:
            raise PasskeyServiceError("invalid usage timestamp")
        return parsed.astimezone(dt.timezone.utc)

    def _cancel(self, request: Request) -> dict[str, Any]:
        try:
            target = uuid.UUID(str(request.payload.get("targetRequestId")))
        except (ValueError, TypeError, AttributeError):
            return self._error("invalid_cancel_target")
        return {"ok": self._operations.cancel(target)}

    @staticmethod
    def _metadata(item) -> dict[str, Any]:
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        return {
            "rpId": item.rp_id,
            "credentialId": b64(item.credential_id),
            "userId": b64(item.user_id),
            "userName": item.user_name,
            "userDisplayName": item.user_display_name,
        }

    @staticmethod
    def _error(code: str) -> dict[str, Any]:
        return {"ok": False, "error": code}
