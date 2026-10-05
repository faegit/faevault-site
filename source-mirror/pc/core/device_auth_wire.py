"""Device authorization wire protocol (mirror of the Android DeviceAuthWire)."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass

from . import pmv_sync_authorization


PROTOCOL_VERSION = 1
ZERO_UUID = uuid.UUID(int=0)


@dataclass(frozen=True, slots=True)
class ChallengeRequest:
    client_nonce: bytes
    device_id: uuid.UUID
    device_public_key: bytes
    vault_id: uuid.UUID
    operation: pmv_sync_authorization.Operation
    requested_commit_id: uuid.UUID | None
    request_digest: bytes


@dataclass(frozen=True, slots=True)
class ConfirmRequest:
    challenge: bytes
    signature: bytes


def _b64decode(raw: str, size: int, name: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception as error:
        raise ValueError(f"{name} base64 is invalid") from error
    if len(decoded) != size:
        raise ValueError(f"{name} must be {size} bytes")
    return decoded


def _uuid(raw: str, name: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(raw)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{name} is invalid") from error
    if str(parsed) != raw:
        raise ValueError(f"{name} must use canonical lowercase UUID representation")
    return parsed


def _operation(raw: str) -> pmv_sync_authorization.Operation:
    mapping = {
        "read": pmv_sync_authorization.Operation.READ,
        "write": pmv_sync_authorization.Operation.WRITE,
        "authorize": pmv_sync_authorization.Operation.AUTHORIZE,
    }
    if raw not in mapping:
        raise ValueError("device authentication operation is invalid")
    return mapping[raw]


def parse_challenge_request(body: str) -> ChallengeRequest:
    data = json.loads(body)
    if data.get("v") != PROTOCOL_VERSION:
        raise ValueError("device authentication protocol version is invalid")
    requested = data.get("requestedCommitId")
    requested_commit = (
        None if requested in (None, "", "null") else _uuid(str(requested), "requestedCommitId")
    )
    digest_text = data.get("requestDigest")
    request_digest = (
        bytes(32) if digest_text in (None, "", "null") else _b64decode(str(digest_text), 32, "requestDigest")
    )
    return ChallengeRequest(
        client_nonce=_b64decode(str(data["clientNonce"]), 32, "clientNonce"),
        device_id=_uuid(str(data["deviceId"]), "deviceId"),
        device_public_key=_b64decode(str(data["devicePublicKey"]), 32, "devicePublicKey"),
        vault_id=_uuid(str(data["vaultId"]), "vaultId"),
        operation=_operation(str(data["op"])),
        requested_commit_id=requested_commit,
        request_digest=request_digest,
    )


def challenge_response(challenge: bytes) -> str:
    return json.dumps(
        {
            "v": PROTOCOL_VERSION,
            "challenge": base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("="),
        },
        ensure_ascii=False,
    )


def parse_confirm_request(body: str) -> ConfirmRequest:
    data = json.loads(body)
    if data.get("v") != PROTOCOL_VERSION:
        raise ValueError("device authentication protocol version is invalid")
    return ConfirmRequest(
        challenge=_b64decode(str(data["challenge"]), pmv_sync_authorization.CHALLENGE_SIZE, "challenge"),
        signature=_b64decode(str(data["signature"]), 64, "signature"),
    )


def confirm_response() -> str:
    return json.dumps({"v": PROTOCOL_VERSION}, ensure_ascii=False)


def sign_challenge(challenge: bytes, device_id: uuid.UUID, device_private_seed: bytes) -> bytes:
    decoded = pmv_sync_authorization.decode_challenge(challenge)
    if decoded.device_id != device_id:
        raise ValueError("challenge is bound to another device")
    return pmv_sync_authorization.sign_challenge(decoded, device_private_seed)
