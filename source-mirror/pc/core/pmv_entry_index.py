"""Fixed-size PMV entry-index pages shared with the Android implementation."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar, Iterable

from .pmv_container import (
    BLOCK_HEADER_SIZE,
    DATA_START,
    GCM_TAG_SIZE,
    MAX_BLOCK_CIPHER_SIZE,
)


PAGE_SIZE = 16 * 1024

_INDEX_MAGIC = b"PMEI"
_ROOT_MAGIC = b"PMER"
_VERSION = 1
_HEADER_SIZE = 32
_RECORD_FIXED_SIZE = 108
_ROOT_RECORD_SIZE = 72
_MAX_TYPE_BYTES = 64
_MAX_TITLE_BYTES = 1024
_MAX_RECORDS_PER_PAGE = (PAGE_SIZE - _HEADER_SIZE) // _RECORD_FIXED_SIZE
_MAX_ROOT_RECORDS = (PAGE_SIZE - _HEADER_SIZE) // _ROOT_RECORD_SIZE
_MIN_BLOCK_LENGTH = BLOCK_HEADER_SIZE + GCM_TAG_SIZE
_MAX_BLOCK_LENGTH = BLOCK_HEADER_SIZE + MAX_BLOCK_CIPHER_SIZE
_MAX_SIGNED_LONG = (1 << 63) - 1
_ZERO_UUID = uuid.UUID(int=0)
_HEADER = struct.Struct(">4sIIIqq")
_ROOT_RECORD = struct.Struct(">16s16sq32s")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _require_uuid(value: object, label: str) -> None:
    _require(isinstance(value, uuid.UUID), f"{label} must be a UUID")


def _require_long(value: object, label: str, minimum: int = 0) -> None:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= _MAX_SIGNED_LONG,
        f"{label} is outside the signed 64-bit range",
    )


def _uuid_key(value: uuid.UUID) -> str:
    # Android compares UUID.toString(), whose fixed canonical representation has
    # the same ordering as these lowercase canonical strings.
    return str(value)


def _encode_text(value: object, label: str, minimum: int, maximum: int) -> bytes:
    _require(isinstance(value, str), f"{label} must be a string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 text") from exc
    _require(minimum <= len(encoded) <= maximum, f"{label} byte length is invalid")
    return encoded


def _decode_text(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} contains malformed UTF-8") from exc


class EntryIndexState(IntEnum):
    ACTIVE = 1
    TOMBSTONE = 2

    @classmethod
    def from_id(cls, value: int) -> "EntryIndexState":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("unknown entry-index state") from exc


@dataclass(frozen=True, slots=True)
class EntryIndexRecord:
    entry_id: uuid.UUID
    entry_type: str
    revision: int
    offset: int
    length: int
    state: EntryIndexState
    display_title: str = ""
    favorite: bool = False
    icon_object_id: uuid.UUID | None = None
    modified_at_epoch_millis: int = 0
    content_digest: bytes = bytes(32)

    def __post_init__(self) -> None:
        _require_uuid(self.entry_id, "entry_id")
        _encode_text(self.entry_type, "entry_type", 1, _MAX_TYPE_BYTES)
        _encode_text(self.display_title, "display_title", 0, _MAX_TITLE_BYTES)
        _require_long(self.revision, "revision")
        _require_long(self.modified_at_epoch_millis, "modified_at_epoch_millis")
        _require_long(self.offset, "offset", DATA_START)
        _require_long(self.length, "length", _MIN_BLOCK_LENGTH)
        _require(self.length <= _MAX_BLOCK_LENGTH, "entry block length is invalid")
        _require(isinstance(self.state, EntryIndexState), "state is invalid")
        _require(type(self.favorite) is bool, "favorite must be a boolean")
        if self.icon_object_id is not None:
            _require_uuid(self.icon_object_id, "icon_object_id")
        _require(isinstance(self.content_digest, bytes) and len(self.content_digest) == 32,
                 "content_digest must be 32 bytes")


@dataclass(frozen=True, slots=True)
class EntryIndexPage:
    records: tuple[EntryIndexRecord, ...] | Iterable[EntryIndexRecord]
    next_page_offset: int = 0

    def __post_init__(self) -> None:
        records = tuple(self.records)
        object.__setattr__(self, "records", records)
        _require(len(records) <= _MAX_RECORDS_PER_PAGE, "too many entry-index records")
        _require_long(self.next_page_offset, "next_page_offset")
        _require(
            self.next_page_offset == 0 or self.next_page_offset >= DATA_START,
            "next entry-index page offset is invalid",
        )
        for record in records:
            _require(isinstance(record, EntryIndexRecord), "entry-index record is invalid")
        _require(
            all(
                _uuid_key(left.entry_id) < _uuid_key(right.entry_id)
                for left, right in zip(records, records[1:])
            ),
            "entry-index records must be strictly UUID-sorted and unique",
        )

    def find(self, entry_id: uuid.UUID) -> EntryIndexRecord | None:
        _require_uuid(entry_id, "entry_id")
        target = _uuid_key(entry_id)
        low = 0
        high = len(self.records) - 1
        while low <= high:
            middle = (low + high) >> 1
            candidate = self.records[middle]
            candidate_key = _uuid_key(candidate.entry_id)
            if candidate_key < target:
                low = middle + 1
            elif candidate_key > target:
                high = middle - 1
            else:
                return candidate
        return None


@dataclass(frozen=True, slots=True)
class EntryIndexRootRecord:
    min_entry_id: uuid.UUID
    max_entry_id: uuid.UUID
    page_offset: int
    page_digest: bytes = bytes(32)

    def __post_init__(self) -> None:
        _require_uuid(self.min_entry_id, "min_entry_id")
        _require_uuid(self.max_entry_id, "max_entry_id")
        _require(
            _uuid_key(self.min_entry_id) <= _uuid_key(self.max_entry_id),
            "entry-index root range is invalid",
        )
        _require_long(self.page_offset, "page_offset", DATA_START)
        _require(isinstance(self.page_digest, bytes) and len(self.page_digest) == 32,
                 "page_digest must be 32 bytes")


@dataclass(frozen=True, slots=True)
class EntryIndexRoot:
    records: tuple[EntryIndexRootRecord, ...] | Iterable[EntryIndexRootRecord]

    def __post_init__(self) -> None:
        records = tuple(self.records)
        object.__setattr__(self, "records", records)
        _require(len(records) <= _MAX_ROOT_RECORDS, "too many entry-index root records")
        for record in records:
            _require(isinstance(record, EntryIndexRootRecord), "entry-index root record is invalid")
        _require(
            len({record.page_offset for record in records}) == len(records),
            "entry-index root page offsets must be unique",
        )
        _require(
            all(
                _uuid_key(left.max_entry_id) < _uuid_key(right.min_entry_id)
                for left, right in zip(records, records[1:])
            ),
            "entry-index root ranges must be strictly increasing and non-overlapping",
        )

    def find_page(self, entry_id: uuid.UUID) -> EntryIndexRootRecord | None:
        _require_uuid(entry_id, "entry_id")
        target = _uuid_key(entry_id)
        low = 0
        high = len(self.records) - 1
        while low <= high:
            middle = (low + high) >> 1
            candidate = self.records[middle]
            if target < _uuid_key(candidate.min_entry_id):
                high = middle - 1
            elif target > _uuid_key(candidate.max_entry_id):
                low = middle + 1
            else:
                return candidate
        return None


def encode_entry_index_page(page: EntryIndexPage) -> bytes:
    _require(isinstance(page, EntryIndexPage), "page is invalid")
    output = bytearray(PAGE_SIZE)
    _HEADER.pack_into(
        output,
        0,
        _INDEX_MAGIC,
        _VERSION,
        PAGE_SIZE,
        len(page.records),
        page.next_page_offset,
        0,
    )
    position = _HEADER_SIZE
    for record in page.records:
        type_bytes = _encode_text(record.entry_type, "entry_type", 1, _MAX_TYPE_BYTES)
        title_bytes = _encode_text(record.display_title, "display_title", 0, _MAX_TITLE_BYTES)
        record_size = _RECORD_FIXED_SIZE + len(type_bytes) + len(title_bytes)
        _require(position + record_size <= PAGE_SIZE, "entry-index page capacity exceeded")

        output[position : position + 16] = record.entry_id.bytes
        position += 16
        struct.pack_into(">H", output, position, len(type_bytes))
        position += 2
        output[position : position + len(type_bytes)] = type_bytes
        position += len(type_bytes)
        struct.pack_into(">H", output, position, len(title_bytes))
        position += 2
        output[position : position + len(title_bytes)] = title_bytes
        position += len(title_bytes)
        struct.pack_into(
            ">qqqBBB5x16sq",
            output,
            position,
            record.revision,
            record.offset,
            record.length,
            int(record.state),
            int(record.favorite),
            int(record.icon_object_id is not None),
            (record.icon_object_id or _ZERO_UUID).bytes,
            record.modified_at_epoch_millis,
        )
        position += 56
        output[position : position + 32] = record.content_digest
        position += 32
    return bytes(output)


def decode_entry_index_page(raw: bytes) -> EntryIndexPage:
    _require(isinstance(raw, bytes), "entry-index page must be bytes")
    _require(len(raw) == PAGE_SIZE, "entry-index page size is invalid")
    magic, version, declared_size, count, next_page_offset, reserved = _HEADER.unpack_from(raw)
    _require(magic == _INDEX_MAGIC, "entry-index magic is invalid")
    _require(version == _VERSION, "entry-index version is invalid")
    _require(declared_size == PAGE_SIZE, "entry-index declared page size is invalid")
    _require(0 <= count <= _MAX_RECORDS_PER_PAGE, "entry-index record count is invalid")
    _require(reserved == 0, "entry-index header reserved field is nonzero")

    records: list[EntryIndexRecord] = []
    position = _HEADER_SIZE
    for _ in range(count):
        _require(PAGE_SIZE - position >= 18, "entry-index record is truncated")
        entry_id = uuid.UUID(bytes=raw[position : position + 16])
        position += 16
        (type_length,) = struct.unpack_from(">H", raw, position)
        position += 2
        _require(1 <= type_length <= _MAX_TYPE_BYTES, "entry_type byte length is invalid")
        _require(PAGE_SIZE - position >= type_length + 2, "entry-index record is truncated")
        entry_type = _decode_text(raw[position : position + type_length], "entry_type")
        position += type_length
        (title_length,) = struct.unpack_from(">H", raw, position)
        position += 2
        _require(0 <= title_length <= _MAX_TITLE_BYTES, "display_title byte length is invalid")
        _require(
            PAGE_SIZE - position >= title_length + _RECORD_FIXED_SIZE - 20,
            "entry-index record is truncated",
        )
        display_title = _decode_text(raw[position : position + title_length], "display_title")
        position += title_length
        revision, offset, length, state_id, favorite, has_icon = struct.unpack_from(
            ">qqqBBB", raw, position
        )
        position += 27
        _require(
            raw[position : position + 5] == b"\0" * 5,
            "entry-index record reserved field is nonzero",
        )
        position += 5
        encoded_icon = uuid.UUID(bytes=raw[position : position + 16])
        position += 16
        (modified_at_epoch_millis,) = struct.unpack_from(">q", raw, position)
        position += 8
        content_digest = raw[position : position + 32]
        position += 32
        _require(favorite in (0, 1), "entry-index favorite flag is invalid")
        _require(has_icon in (0, 1), "entry-index icon flag is invalid")
        _require(
            has_icon == 1 or encoded_icon == _ZERO_UUID,
            "iconless record contains an icon UUID",
        )
        records.append(
            EntryIndexRecord(
                entry_id=entry_id,
                entry_type=entry_type,
                revision=revision,
                offset=offset,
                length=length,
                state=EntryIndexState.from_id(state_id),
                display_title=display_title,
                favorite=bool(favorite),
                icon_object_id=encoded_icon if has_icon else None,
                modified_at_epoch_millis=modified_at_epoch_millis,
                content_digest=content_digest,
            )
        )
    _require(not any(raw[position:]), "entry-index page trailing reserved bytes are nonzero")
    return EntryIndexPage(records=records, next_page_offset=next_page_offset)


def encode_entry_index_root(root: EntryIndexRoot) -> bytes:
    _require(isinstance(root, EntryIndexRoot), "root is invalid")
    output = bytearray(PAGE_SIZE)
    _HEADER.pack_into(output, 0, _ROOT_MAGIC, _VERSION, PAGE_SIZE, len(root.records), 0, 0)
    position = _HEADER_SIZE
    for record in root.records:
        _ROOT_RECORD.pack_into(
            output,
            position,
            record.min_entry_id.bytes,
            record.max_entry_id.bytes,
            record.page_offset,
            record.page_digest,
        )
        position += _ROOT_RECORD_SIZE
    return bytes(output)


def decode_entry_index_root(raw: bytes) -> EntryIndexRoot:
    _require(isinstance(raw, bytes), "entry-index root page must be bytes")
    _require(len(raw) == PAGE_SIZE, "entry-index root page size is invalid")
    magic, version, declared_size, count, reserved_1, reserved_2 = _HEADER.unpack_from(raw)
    _require(magic == _ROOT_MAGIC, "entry-index root magic is invalid")
    _require(version == _VERSION, "entry-index root version is invalid")
    _require(declared_size == PAGE_SIZE, "entry-index root declared page size is invalid")
    _require(0 <= count <= _MAX_ROOT_RECORDS, "entry-index root record count is invalid")
    _require(
        reserved_1 == 0 and reserved_2 == 0,
        "entry-index root header reserved field is nonzero",
    )

    records: list[EntryIndexRootRecord] = []
    position = _HEADER_SIZE
    for _ in range(count):
        _require(PAGE_SIZE - position >= _ROOT_RECORD_SIZE, "entry-index root record is truncated")
        min_entry_id, max_entry_id, page_offset, page_digest = _ROOT_RECORD.unpack_from(raw, position)
        position += _ROOT_RECORD_SIZE
        records.append(
            EntryIndexRootRecord(
                min_entry_id=uuid.UUID(bytes=min_entry_id),
                max_entry_id=uuid.UUID(bytes=max_entry_id),
                page_offset=page_offset,
                page_digest=page_digest,
            )
        )
    _require(not any(raw[position:]), "entry-index root trailing reserved bytes are nonzero")
    return EntryIndexRoot(records=records)


class PmvEntryIndexCodec:
    """Android-shaped facade for leaf entry-index pages."""

    PAGE_SIZE: ClassVar[int] = PAGE_SIZE
    State: ClassVar[type[EntryIndexState]] = EntryIndexState
    Record: ClassVar[type[EntryIndexRecord]] = EntryIndexRecord
    Page: ClassVar[type[EntryIndexPage]] = EntryIndexPage
    encode = staticmethod(encode_entry_index_page)
    decode = staticmethod(decode_entry_index_page)


class PmvEntryIndexRootCodec:
    """Android-shaped facade for root directory pages."""

    PAGE_SIZE: ClassVar[int] = PAGE_SIZE
    Record: ClassVar[type[EntryIndexRootRecord]] = EntryIndexRootRecord
    Root: ClassVar[type[EntryIndexRoot]] = EntryIndexRoot
    encode = staticmethod(encode_entry_index_root)
    decode = staticmethod(decode_entry_index_root)


# Concise aliases for callers that already qualify the module name.
State = EntryIndexState
Record = EntryIndexRecord
Page = EntryIndexPage
RootRecord = EntryIndexRootRecord
Root = EntryIndexRoot


__all__ = [
    "PAGE_SIZE",
    "EntryIndexState",
    "EntryIndexRecord",
    "EntryIndexPage",
    "EntryIndexRootRecord",
    "EntryIndexRoot",
    "PmvEntryIndexCodec",
    "PmvEntryIndexRootCodec",
    "encode_entry_index_page",
    "decode_entry_index_page",
    "encode_entry_index_root",
    "decode_entry_index_root",
    "State",
    "Record",
    "Page",
    "RootRecord",
    "Root",
]
