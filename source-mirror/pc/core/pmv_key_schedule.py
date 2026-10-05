"""Suite 1 key derivation shared with the Android PMV implementation.

All identifiers are accepted as :class:`uuid.UUID` objects so their canonical
16-byte representation is unambiguous. Generation and revision counters use
the cross-runtime range 0..2^63-1 and are encoded as unsigned 64-bit big-endian
integers.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.pmv_kdf_policy import PmvKdfParameters, PmvKdfPolicy, PmvKdfProfile


KEY_SIZE = 32
ARGON2_SALT_SIZE = 16
ARGON2_MEMORY_COST_KIB = 65_536
ARGON2_ITERATIONS = 3
ARGON2_LANES = 1

_ZERO_SALT = bytes(KEY_SIZE)
_MAX_WIRE_COUNTER = (1 << 63) - 1

_ROOT_KEY_INFO = (
    ("metadata_key", b"pmv/v1/metadata"),
    ("entry_root_key", b"pmv/v1/entry-root"),
    ("attachment_root_key", b"pmv/v1/attachment-root"),
    ("index_key", b"pmv/v1/index"),
    ("search_index_key", b"pmv/v1/search-index"),
    ("integrity_key", b"pmv/v1/integrity"),
    ("sync_auth_key", b"pmv/v1/sync-auth"),
    ("key_wrap_key", b"pmv/v1/key-wrap"),
)
_ENTRY_GENERATION_INFO = b"pmv/v1/entry-generation\0"
_ATTACHMENT_GENERATION_INFO = b"pmv/v1/attachment-generation\0"
_CHUNK_INFO = b"pmv/v1/chunk\0"
_COMMIT_BLOCK_INFO = b"pmv/v1/commit-block-key\0"
_METADATA_BLOCK_INFO = b"pmv/v1/metadata-block-key\0"
_INDEX_PAGE_INFO = b"pmv/v1/index-page-key\0"
_CLOUD_CREDENTIAL_INFO = b"pmv/v1/cloud-credentials"


class IndexPageType(Enum):
    """Logical page domains; all are physically INDEX_PAGE blocks."""

    ENTRY_INDEX = b"entry-index"
    VAULT_ROOT = b"vault-root"
    LOGIN_INDEX = b"login-index"
    OBJECT_INDEX = b"object-index"
    CHUNK_INDEX = b"chunk-index"


def _require_bytes(value: object, name: str, *, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _require_uuid(value: object, name: str) -> UUID:
    if not isinstance(value, UUID):
        raise TypeError(f"{name} must be a UUID")
    return value


def _u64be(value: object, name: str) -> bytes:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value > _MAX_WIRE_COUNTER:
        raise ValueError(f"{name} must be between 0 and 2^63 - 1")
    return value.to_bytes(8, "big")


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
    ).derive(ikm)


@dataclass(frozen=True, slots=True)
class RootKeys:
    """The eight purpose-separated 256-bit keys in PMV Suite 1."""

    metadata_key: bytes
    entry_root_key: bytes
    attachment_root_key: bytes
    index_key: bytes
    search_index_key: bytes
    integrity_key: bytes
    sync_auth_key: bytes
    key_wrap_key: bytes

    def __post_init__(self) -> None:
        for field in fields(self):
            _require_bytes(getattr(self, field.name), field.name, length=KEY_SIZE)


def derive_password_kek(
    password_utf8: bytes,
    salt: bytes,
    parameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
) -> bytes:
    """Derive the Suite 1 password KEK without text normalization or trimming.

    ``password_utf8`` is the caller-provided raw UTF-8 byte sequence.  Argon2id
    uses version 1.3 as implemented by ``cryptography``.
    """

    password = _require_bytes(password_utf8, "password_utf8")
    checked_salt = _require_bytes(salt, "salt", length=ARGON2_SALT_SIZE)
    PmvKdfPolicy.validate(parameters)
    return Argon2id(
        salt=checked_salt,
        length=KEY_SIZE,
        iterations=parameters.iterations,
        lanes=parameters.parallelism,
        memory_cost=parameters.memory_kib,
    ).derive(password)


def derive_root_keys(vault_root_key: bytes, vault_id: UUID) -> RootKeys:
    """Derive all Suite 1 root keys using the vault UUID bytes as HKDF salt."""

    root_key = _require_bytes(vault_root_key, "vault_root_key", length=KEY_SIZE)
    salt = _require_uuid(vault_id, "vault_id").bytes
    derived = {
        field_name: _hkdf(root_key, salt, info)
        for field_name, info in _ROOT_KEY_INFO
    }
    return RootKeys(**derived)


def derive_cloud_credential_key(key_wrap_key: bytes) -> bytes:
    """Derive the vault-bound key used only for cloud credential fields."""
    parent = _require_bytes(key_wrap_key, "key_wrap_key", length=KEY_SIZE)
    return _hkdf(parent, _ZERO_SALT, _CLOUD_CREDENTIAL_INFO)


def derive_entry_generation_key(
    entry_root_key: bytes,
    entry_id: UUID,
    generation: int,
) -> bytes:
    """Derive the key for one immutable entry generation."""

    root_key = _require_bytes(entry_root_key, "entry_root_key", length=KEY_SIZE)
    salt = _require_uuid(entry_id, "entry_id").bytes
    info = _ENTRY_GENERATION_INFO + _u64be(generation, "generation")
    return _hkdf(root_key, salt, info)


def derive_attachment_object_key(
    attachment_root_key: bytes,
    attachment_id: UUID,
    generation: int,
) -> bytes:
    """Derive the object key for one immutable attachment generation."""

    root_key = _require_bytes(
        attachment_root_key,
        "attachment_root_key",
        length=KEY_SIZE,
    )
    salt = _require_uuid(attachment_id, "attachment_id").bytes
    info = _ATTACHMENT_GENERATION_INFO + _u64be(generation, "generation")
    return _hkdf(root_key, salt, info)


def derive_chunk_key(attachment_object_key: bytes, chunk_index: int) -> bytes:
    """Derive the key for one attachment chunk."""

    object_key = _require_bytes(
        attachment_object_key,
        "attachment_object_key",
        length=KEY_SIZE,
    )
    info = _CHUNK_INFO + _u64be(chunk_index, "chunk_index")
    return _hkdf(object_key, _ZERO_SALT, info)


def derive_commit_block_key(
    integrity_key: bytes,
    commit_id: UUID,
    revision: int,
) -> bytes:
    """Derive a unique key for one immutable commit block.

    Frozen layout: salt = commit UUID raw16; info =
    ``ASCII("pmv/v1/commit-block-key\\0") || u64be(revision)``.
    """

    parent_key = _require_bytes(integrity_key, "integrity_key", length=KEY_SIZE)
    salt = _require_uuid(commit_id, "commit_id").bytes
    info = _COMMIT_BLOCK_INFO + _u64be(revision, "revision")
    return _hkdf(parent_key, salt, info)


def derive_metadata_block_key(
    metadata_key: bytes,
    object_id: UUID,
    generation: int,
) -> bytes:
    """Derive a unique key for one immutable Vault Metadata generation."""

    parent_key = _require_bytes(metadata_key, "metadata_key", length=KEY_SIZE)
    salt = _require_uuid(object_id, "object_id").bytes
    info = _METADATA_BLOCK_INFO + _u64be(generation, "generation")
    return _hkdf(parent_key, salt, info)


def derive_index_page_key(
    parent_key: bytes,
    object_id: UUID,
    generation: int,
    page_type: IndexPageType,
) -> bytes:
    """Derive a unique key for one immutable logical index page.

    Frozen layout: salt = object UUID raw16; info =
    ``ASCII("pmv/v1/index-page-key\\0") || page_type ASCII || NUL || u64be(generation)``.
    """

    checked_key = _require_bytes(parent_key, "parent_key", length=KEY_SIZE)
    salt = _require_uuid(object_id, "object_id").bytes
    if not isinstance(page_type, IndexPageType):
        raise TypeError("page_type must be an IndexPageType")
    info = _INDEX_PAGE_INFO + page_type.value + b"\0" + _u64be(generation, "generation")
    return _hkdf(checked_key, salt, info)
