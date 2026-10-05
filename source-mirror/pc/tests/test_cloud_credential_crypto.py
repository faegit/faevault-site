from uuid import UUID

import pytest
from cryptography.exceptions import InvalidTag

from core.cloud_credential_crypto import open_field, seal_field
from core.pmv_key_schedule import derive_cloud_credential_key, derive_root_keys


VAULT_ID = UUID("00112233-4455-6677-8899-aabbccddeeff")
ROOT_KEY = bytes(range(32))
NONCE = bytes(range(0x40, 0x4C))


def test_field_round_trip_and_vault_bound_derivation() -> None:
    key_wrap = derive_root_keys(ROOT_KEY, VAULT_ID).key_wrap_key
    key = derive_cloud_credential_key(key_wrap)
    packed = seal_field(key, VAULT_ID, "webdav", "password", 1, "用户:秘密".encode(), NONCE)
    assert open_field(key, VAULT_ID, "webdav", "password", 1, packed) == "用户:秘密".encode()


@pytest.mark.parametrize(
    "vault_id,provider,field,version",
    [
        (UUID("10112233-4455-6677-8899-aabbccddeeff"), "webdav", "password", 1),
        (VAULT_ID, "drive", "password", 1),
        (VAULT_ID, "webdav", "cookie", 1),
        (VAULT_ID, "webdav", "password", 2),
    ],
)
def test_field_context_mismatch_fails_closed(vault_id, provider, field, version) -> None:
    key = derive_cloud_credential_key(derive_root_keys(ROOT_KEY, VAULT_ID).key_wrap_key)
    packed = seal_field(key, VAULT_ID, "webdav", "password", 1, b"secret", NONCE)
    with pytest.raises(InvalidTag):
        open_field(key, vault_id, provider, field, version, packed)
