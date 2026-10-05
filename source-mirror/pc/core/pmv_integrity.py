"""Canonical SHA-256 digests for the logical PMV entry-index tree."""

from __future__ import annotations

import hashlib
import struct

from .pmv_container import EncodedBlock, encode_block_header
from .pmv_entry_index import EntryIndexPage, EntryIndexRecord, EntryIndexRoot


_RECORD_DOMAIN = b"pmv/v1/entry-index-record\0"
_PAGE_DOMAIN = b"pmv/v1/entry-index-page\0"
_ROOT_DOMAIN = b"pmv/v1/entry-index-root\0"
_ZERO_UUID = bytes(16)


def encrypted_block_digest(block: EncodedBlock) -> bytes:
    return hashlib.sha256(encode_block_header(block.header) + block.ciphertext).digest()


def entry_record_digest(record: EntryIndexRecord) -> bytes:
    entry_type = record.entry_type.encode("utf-8", errors="strict")
    title = record.display_title.encode("utf-8", errors="strict")
    if len(entry_type) > 0xFFFF or len(title) > 0xFFFF:
        raise ValueError("canonical text field exceeds u16")
    payload = bytearray(_RECORD_DOMAIN)
    payload.extend(record.entry_id.bytes)
    payload.extend(struct.pack(">H", len(entry_type)))
    payload.extend(entry_type)
    payload.extend(struct.pack(">qB", record.revision, int(record.state)))
    payload.extend(struct.pack(">H", len(title)))
    payload.extend(title)
    payload.extend(bytes((int(record.favorite), int(record.icon_object_id is not None))))
    payload.extend((record.icon_object_id.bytes if record.icon_object_id else _ZERO_UUID))
    payload.extend(struct.pack(">q", record.modified_at_epoch_millis))
    payload.extend(record.content_digest)
    return hashlib.sha256(payload).digest()


def entry_page_digest(page: EntryIndexPage) -> bytes:
    digest = hashlib.sha256()
    digest.update(_PAGE_DOMAIN)
    digest.update(struct.pack(">I", len(page.records)))
    for record in page.records:
        digest.update(entry_record_digest(record))
    return digest.digest()


def entry_root_digest(root: EntryIndexRoot) -> bytes:
    digest = hashlib.sha256()
    digest.update(_ROOT_DOMAIN)
    digest.update(struct.pack(">I", len(root.records)))
    for record in root.records:
        digest.update(record.min_entry_id.bytes)
        digest.update(record.max_entry_id.bytes)
        digest.update(record.page_digest)
    return digest.digest()


__all__ = [
    "encrypted_block_digest",
    "entry_record_digest",
    "entry_page_digest",
    "entry_root_digest",
]
