from __future__ import annotations

import struct
from uuid import UUID

import pytest

from core.pmv_kdf_policy import PmvKdfProfile
from core.pmv_vault_header import (
    HEADER_SIZE,
    Nonces,
    create_header,
    decode_header,
    rewrap_password,
    rewrap_password_with_recovery,
    rewrap_recovery,
    select_latest_with_recovery,
    unlock_candidates_with_recovery,
    unlock_candidates_with_root_key,
    unlock_with_password,
    unlock_with_recovery,
    unlock_with_root_key,
)

VAULT_ID = UUID("00112233-4455-6677-8899-aabbccddeeff")
PASSWORD = "pāss-原始".encode()
RECOVERY = bytes(range(0x20, 0x40))
ROOT = bytes(range(0x40, 0x60))
SEED = bytes(range(1, 33))
SALT = bytes(range(0xA0, 0xB0))
NONCES = Nonces(bytes(range(0x10, 0x1C)), bytes(range(0x30, 0x3C)), bytes(range(0x50, 0x5C)))


def _create() -> bytes:
    return create_header(
        vault_id=VAULT_ID,
        key_revision=7,
        header_revision=11,
        password_utf8=PASSWORD,
        recovery_secret=RECOVERY,
        vault_root_key=ROOT,
        signing_private_seed=SEED,
        salt=SALT,
        nonces=NONCES,
    )


def test_deterministic_header_unlocks_with_password_and_recovery() -> None:
    raw = _create()
    assert len(raw) == HEADER_SIZE
    assert raw[:16] == b"PMVH" + struct.pack(">III", 1, 4096, 1)
    password = unlock_with_password(raw, PASSWORD)
    recovery = unlock_with_recovery(raw, RECOVERY)
    assert password.header.vault_id == VAULT_ID
    assert password.header.key_revision == 7
    assert password.header.header_revision == 11
    assert password.vault_root_key == recovery.vault_root_key == ROOT
    assert password.signing_private_seed == recovery.signing_private_seed == SEED


def test_wrong_credentials_tampering_unknown_suite_and_parameters_fail_closed() -> None:
    raw = _create()
    with pytest.raises(ValueError):
        unlock_with_password(raw, b"wrong")
    with pytest.raises(ValueError):
        unlock_with_recovery(raw, bytes(32))
    for offset in (120, 190, 250, 500, len(raw) - 1):
        changed = bytearray(raw)
        changed[offset] ^= 1
        with pytest.raises(ValueError):
            unlock_with_password(bytes(changed), PASSWORD)
    changed = bytearray(raw)
    changed[15] = 2
    with pytest.raises(ValueError):
        decode_header(bytes(changed))
    changed = bytearray(raw)
    changed[53] = 0
    with pytest.raises(ValueError):
        decode_header(bytes(changed))


def test_password_rewrap_preserves_recovery_and_selects_only_authenticated_slot() -> None:
    old = _create()
    updated = rewrap_password(
        old,
        PASSWORD,
        b"new-password",
        bytes(range(0xC0, 0xD0)),
        12,
        bytes(range(0x70, 0x7C)),
    )
    with pytest.raises(ValueError):
        unlock_with_password(updated, PASSWORD)
    assert unlock_with_password(updated, b"new-password").vault_root_key == ROOT
    assert unlock_with_recovery(updated, RECOVERY).vault_root_key == ROOT
    assert select_latest_with_recovery(old, updated, RECOVERY).header.header_revision == 12

    forged = bytearray(old)
    forged[47] = 99
    assert select_latest_with_recovery(bytes(forged), updated, RECOVERY).header.header_revision == 12


def test_hardened_parameters_round_trip_and_rewrap_preserves_other_slots() -> None:
    hardened = create_header(
        vault_id=VAULT_ID,
        key_revision=7,
        header_revision=11,
        password_utf8=PASSWORD,
        recovery_secret=RECOVERY,
        vault_root_key=ROOT,
        signing_private_seed=SEED,
        salt=SALT,
        nonces=NONCES,
        kdf_parameters=PmvKdfProfile.HARDENED.parameters,
    )
    old_header = decode_header(hardened)
    assert old_header.kdf_parameters == PmvKdfProfile.HARDENED.parameters
    assert unlock_with_password(hardened, PASSWORD).vault_root_key == ROOT

    updated = rewrap_password(
        hardened,
        PASSWORD,
        PASSWORD,
        bytes(range(0xC0, 0xD0)),
        12,
        bytes(range(0x70, 0x7C)),
        target_parameters=PmvKdfProfile.STANDARD.parameters,
    )
    new_header = decode_header(updated)
    assert new_header.kdf_parameters == PmvKdfProfile.STANDARD.parameters
    assert new_header.key_revision == old_header.key_revision
    assert new_header.header_revision == old_header.header_revision + 1
    assert new_header.recovery_envelope == old_header.recovery_envelope
    assert new_header.signing_seed_envelope == old_header.signing_seed_envelope
    assert unlock_with_password(updated, PASSWORD).vault_root_key == ROOT
    assert unlock_with_recovery(updated, RECOVERY).vault_root_key == ROOT


def test_root_key_unlock_authenticates_whole_header_and_signing_identity() -> None:
    raw = _create()
    unlocked = unlock_with_root_key(raw, ROOT)
    assert unlocked.header.header_revision == 11
    assert unlocked.vault_root_key == ROOT
    assert unlocked.signing_private_seed == SEED
    assert unlocked.vault_root_key is not ROOT
    with pytest.raises(ValueError):
        unlock_with_root_key(raw, bytes(32))
    tampered = bytearray(raw)
    tampered[500] ^= 1
    with pytest.raises(ValueError):
        unlock_with_root_key(bytes(tampered), ROOT)


def test_recovery_rotation_preserves_root_signing_identity_and_password_envelope() -> None:
    old = _create()
    old_header = decode_header(old)
    new_recovery = bytes(range(0x60, 0x80))
    updated = rewrap_recovery(old, RECOVERY, new_recovery, 12, bytes(range(0x72, 0x7E)))
    updated_header = decode_header(updated)

    assert updated_header.header_revision == 12
    assert updated_header.password_envelope == old_header.password_envelope
    assert updated_header.signing_public_key == old_header.signing_public_key
    with pytest.raises(ValueError):
        unlock_with_recovery(updated, RECOVERY)
    unlocked = unlock_with_recovery(updated, new_recovery)
    assert unlocked.vault_root_key == ROOT
    assert unlocked.signing_private_seed == SEED
    assert unlock_with_password(updated, PASSWORD).vault_root_key == ROOT


def test_recovery_unlock_can_rewrap_password_without_changing_root_or_recovery() -> None:
    updated = rewrap_password_with_recovery(
        _create(),
        RECOVERY,
        b"recovered-password",
        bytes(range(0xD0, 0xE0)),
        12,
        bytes(range(0x7E, 0x8A)),
    )
    with pytest.raises(ValueError):
        unlock_with_password(updated, PASSWORD)
    unlocked = unlock_with_password(updated, b"recovered-password")
    assert unlocked.vault_root_key == ROOT
    assert unlocked.signing_private_seed == SEED
    assert unlock_with_recovery(updated, RECOVERY).vault_root_key == ROOT


def test_unlock_candidates_returns_every_authenticated_slot_newest_first() -> None:
    old = _create()
    newer = rewrap_password(
        old,
        PASSWORD,
        b"new-password",
        bytes(range(0xC0, 0xD0)),
        12,
        bytes(range(0x70, 0x7C)),
    )
    candidates = unlock_candidates_with_recovery(old, newer, RECOVERY)
    assert [item.header.header_revision for item in candidates] == [12, 11]

    forged = bytearray(old)
    forged[47] = 99
    root_candidates = unlock_candidates_with_root_key(bytes(forged), newer, ROOT)
    assert [item.header.header_revision for item in root_candidates] == [12]
