"""Fixed-size keyed login lookup index shared with the Android implementation.

The page contains only HMAC-SHA256 lookup tokens and candidate entry UUIDs. It
must be stored as its own encrypted PMV block; it never contains entry fields.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, ClassVar, Iterable

from .pmv_container import DATA_START


PAGE_SIZE = 16 * 1024

_MAGIC = b"PMLF"
_VERSION = 1
_HEADER_SIZE = 32
_RECORD_SIZE = 56
_TOKEN_SIZE = 32
_MAX_RECORDS = (PAGE_SIZE - _HEADER_SIZE) // _RECORD_SIZE
_TOKEN_PREFIX = b"pmv/v1/login-fast-index\0"
_PACKAGE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
_IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ASCII_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_HEADER = struct.Struct(">4sIIIqq")
_RECORD = struct.Struct(">16sBBB5x32s")
_ROOT_MAGIC = b"PMLR"
_ROOT_RECORD = struct.Struct(">BB6s32s32sqq32s")
_MAX_ROOT_RANGES = (PAGE_SIZE - _HEADER_SIZE) // _ROOT_RECORD.size
_LEAF_DIGEST_DOMAIN = b"pmv/v1/login-fast-leaf\0"
_ROOT_DIGEST_DOMAIN = b"pmv/v1/login-fast-root\0"
_MAX_WIRE_LONG = (1 << 63) - 1


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class EntryType(IntEnum):
    LOGIN = 1
    PASSKEY = 2

    @classmethod
    def from_id(cls, value: int) -> "EntryType":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("invalid login-fast-index entry type") from exc


class State(IntEnum):
    ACTIVE = 1
    TOMBSTONE = 2

    @classmethod
    def from_id(cls, value: int) -> "State":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("invalid login-fast-index state") from exc


class LookupKind(IntEnum):
    DOMAIN = 1
    PACKAGE = 2
    RP_ID = 3

    @classmethod
    def from_id(cls, value: int) -> "LookupKind":
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("invalid login-fast-index lookup kind") from exc


@dataclass(frozen=True, slots=True)
class Record:
    entry_id: uuid.UUID
    entry_type: EntryType
    state: State
    lookup_kind: LookupKind
    lookup_token: bytes

    def __post_init__(self) -> None:
        _require(isinstance(self.entry_id, uuid.UUID), "entry_id must be a UUID")
        _require(isinstance(self.entry_type, EntryType), "entry_type is invalid")
        _require(isinstance(self.state, State), "state is invalid")
        _require(isinstance(self.lookup_kind, LookupKind), "lookup_kind is invalid")
        _require(
            isinstance(self.lookup_token, bytes) and len(self.lookup_token) == _TOKEN_SIZE,
            "lookup_token must be an HMAC-SHA256 value",
        )


def _record_key(record: Record) -> tuple[int, bytes, bytes]:
    return int(record.lookup_kind), record.lookup_token, record.entry_id.bytes


@dataclass(frozen=True, slots=True)
class Page:
    records: tuple[Record, ...] | Iterable[Record]

    def __post_init__(self) -> None:
        records = tuple(self.records)
        object.__setattr__(self, "records", records)
        _require(len(records) <= _MAX_RECORDS, "too many login-fast-index records")
        _require(
            all(isinstance(record, Record) for record in records),
            "login-fast-index record is invalid",
        )
        _require(
            all(_record_key(left) < _record_key(right) for left, right in zip(records, records[1:])),
            "login-fast-index records must be strictly sorted and unique",
        )

    def query(self, kind: LookupKind, token: bytes) -> list[uuid.UUID]:
        _require(isinstance(kind, LookupKind), "lookup kind is invalid")
        _require(isinstance(token, bytes) and len(token) == _TOKEN_SIZE, "query token is invalid")
        target = int(kind), token
        low = 0
        high = len(self.records)
        while low < high:
            middle = (low + high) >> 1
            candidate = self.records[middle]
            candidate_key = int(candidate.lookup_kind), candidate.lookup_token
            if candidate_key < target:
                low = middle + 1
            else:
                high = middle

        result: list[uuid.UUID] = []
        index = low
        while index < len(self.records):
            record = self.records[index]
            if (int(record.lookup_kind), record.lookup_token) != target:
                break
            if record.state is State.ACTIVE:
                result.append(record.entry_id)
            index += 1
        return result


def _lookup_key(kind: LookupKind, token: bytes) -> tuple[int, bytes]:
    return int(kind), token


@dataclass(frozen=True, slots=True)
class PageLocation:
    offset: int
    length: int

    def __post_init__(self) -> None:
        _require(type(self.offset) is int and DATA_START <= self.offset <= _MAX_WIRE_LONG,
                 "page offset must be in the signed 64-bit PMV data range")
        _require(type(self.length) is int and 1 <= self.length <= _MAX_WIRE_LONG,
                 "page length must be in the signed 64-bit range")
        _require(self.offset <= _MAX_WIRE_LONG - self.length,
                 "page range exceeds the signed 64-bit range")


@dataclass(frozen=True, slots=True)
class PageRange:
    min_kind: LookupKind
    min_token: bytes
    max_kind: LookupKind
    max_token: bytes
    page_offset: int
    page_length: int
    page_logical_digest: bytes

    def __post_init__(self) -> None:
        _require(isinstance(self.min_kind, LookupKind) and isinstance(self.max_kind, LookupKind),
                 "root range lookup kind is invalid")
        _require(type(self.min_token) is bytes and len(self.min_token) == _TOKEN_SIZE and
                 type(self.max_token) is bytes and len(self.max_token) == _TOKEN_SIZE,
                 "root range token is invalid")
        _require(_lookup_key(self.min_kind, self.min_token) <= _lookup_key(self.max_kind, self.max_token),
                 "root range bounds are invalid")
        PageLocation(self.page_offset, self.page_length)
        _require(type(self.page_logical_digest) is bytes and len(self.page_logical_digest) == 32 and
                 any(self.page_logical_digest), "leaf logical digest is invalid")


@dataclass(frozen=True, slots=True)
class Root:
    ranges: tuple[PageRange, ...] | Iterable[PageRange]

    def __post_init__(self) -> None:
        ranges = tuple(self.ranges)
        object.__setattr__(self, "ranges", ranges)
        _require(1 <= len(ranges) <= _MAX_ROOT_RANGES, "invalid login-fast-index root range count")
        _require(all(isinstance(item, PageRange) for item in ranges), "invalid login-fast-index root range")
        _require(all(_lookup_key(left.max_kind, left.max_token) < _lookup_key(right.min_kind, right.min_token)
                     for left, right in zip(ranges, ranges[1:])),
                 "login-fast-index root ranges must be strictly sorted and non-overlapping")


@dataclass(frozen=True, slots=True)
class Plan:
    pages: tuple[Page, ...]
    root: Root | None

    def __post_init__(self) -> None:
        pages = tuple(self.pages)
        object.__setattr__(self, "pages", pages)
        _require(all(isinstance(page, Page) for page in pages), "login-fast-index plan page is invalid")
        _require((not pages and self.root is None) or
                 (bool(pages) and isinstance(self.root, Root) and len(pages) == len(self.root.ranges)),
                 "login-fast-index plan pages and root disagree")


def encode(page: Page) -> bytes:
    _require(isinstance(page, Page), "login-fast-index page is invalid")
    output = bytearray(PAGE_SIZE)
    _HEADER.pack_into(output, 0, _MAGIC, _VERSION, PAGE_SIZE, len(page.records), 0, 0)
    position = _HEADER_SIZE
    for record in page.records:
        _RECORD.pack_into(
            output,
            position,
            record.entry_id.bytes,
            int(record.entry_type),
            int(record.state),
            int(record.lookup_kind),
            record.lookup_token,
        )
        position += _RECORD_SIZE
    return bytes(output)


def decode(raw: bytes) -> Page:
    _require(isinstance(raw, bytes), "login-fast-index page must be bytes")
    _require(len(raw) == PAGE_SIZE, "login-fast-index page size is invalid")
    magic, version, declared_size, count, reserved_1, reserved_2 = _HEADER.unpack_from(raw)
    _require(magic == _MAGIC, "login-fast-index magic is invalid")
    _require(version == _VERSION, "login-fast-index version is invalid")
    _require(declared_size == PAGE_SIZE, "login-fast-index declared page size is invalid")
    _require(0 <= count <= _MAX_RECORDS, "login-fast-index record count is invalid")
    _require(reserved_1 == 0 and reserved_2 == 0, "login-fast-index header reserved field is nonzero")

    records: list[Record] = []
    position = _HEADER_SIZE
    for _ in range(count):
        _require(PAGE_SIZE - position >= _RECORD_SIZE, "login-fast-index record is truncated")
        entry_id, entry_type, state, lookup_kind, token = _RECORD.unpack_from(raw, position)
        # struct's 5x padding skips bytes, so validate them explicitly.
        _require(
            raw[position + 19 : position + 24] == b"\0" * 5,
            "login-fast-index record reserved field is nonzero",
        )
        records.append(
            Record(
                entry_id=uuid.UUID(bytes=entry_id),
                entry_type=EntryType.from_id(entry_type),
                state=State.from_id(state),
                lookup_kind=LookupKind.from_id(lookup_kind),
                lookup_token=token,
            )
        )
        position += _RECORD_SIZE
    _require(not any(raw[position:]), "login-fast-index trailing reserved bytes are nonzero")
    return Page(records)


def build_pages(records: Iterable[Record]) -> tuple[Page, ...]:
    values = tuple(records)
    _require(all(isinstance(record, Record) for record in values), "login-fast-index record is invalid")
    if not values:
        return ()
    ordered = tuple(sorted(values, key=_record_key))
    _require(all(_record_key(left) < _record_key(right) for left, right in zip(ordered, ordered[1:])),
             "login-fast-index records must be unique")
    pages: list[Page] = []
    current: list[Record] = []
    position = 0
    while position < len(ordered):
        end = position + 1
        group_key = _lookup_key(ordered[position].lookup_kind, ordered[position].lookup_token)
        while end < len(ordered) and _lookup_key(ordered[end].lookup_kind, ordered[end].lookup_token) == group_key:
            end += 1
        group = ordered[position:end]
        _require(len(group) <= _MAX_RECORDS, "login-fast-index token group exceeds leaf capacity")
        if current and len(current) + len(group) > _MAX_RECORDS:
            pages.append(Page(current))
            current = []
        current.extend(group)
        position = end
    if current:
        pages.append(Page(current))
    _require(len(pages) <= _MAX_ROOT_RANGES, "login-fast-index root capacity exceeded")
    return tuple(pages)


def logical_page_digest(page: Page) -> bytes:
    _require(isinstance(page, Page), "login-fast-index page is invalid")
    canonical = bytearray(_LEAF_DIGEST_DOMAIN)
    canonical += struct.pack(">I", len(page.records))
    for record in page.records:
        canonical += struct.pack(">B32s16sBB", int(record.lookup_kind), record.lookup_token,
                                 record.entry_id.bytes, int(record.entry_type), int(record.state))
    return hashlib.sha256(canonical).digest()


def build_root(pages: Iterable[Page], locations: Iterable[PageLocation]) -> Root:
    page_values = tuple(pages)
    location_values = tuple(locations)
    _require(bool(page_values) and len(page_values) == len(location_values),
             "login-fast-index page/location count mismatch")
    ranges: list[PageRange] = []
    for page, location in zip(page_values, location_values):
        _require(isinstance(page, Page) and bool(page.records), "multi-page login leaf must not be empty")
        _require(isinstance(location, PageLocation), "login-fast-index page location is invalid")
        first, last = page.records[0], page.records[-1]
        ranges.append(PageRange(first.lookup_kind, first.lookup_token, last.lookup_kind, last.lookup_token,
                                location.offset, location.length, logical_page_digest(page)))
    return Root(ranges)


def build_plan(records: Iterable[Record], first_page_offset: int, page_stored_length: int) -> Plan:
    pages = build_pages(records)
    if not pages:
        return Plan((), None)
    _require(type(first_page_offset) is int and DATA_START <= first_page_offset <= _MAX_WIRE_LONG,
             "first page offset must be in the signed 64-bit PMV data range")
    _require(type(page_stored_length) is int and 1 <= page_stored_length <= _MAX_WIRE_LONG,
             "page stored length must be in the signed 64-bit range")
    locations = []
    for page_index in range(len(pages)):
        _require(page_index <= (_MAX_WIRE_LONG - first_page_offset) // page_stored_length,
                 "login-fast-index layout exceeds the signed 64-bit range")
        locations.append(PageLocation(first_page_offset + page_index * page_stored_length, page_stored_length))
    return Plan(pages, build_root(pages, locations))


def encode_root(root: Root) -> bytes:
    _require(isinstance(root, Root), "login-fast-index root is invalid")
    output = bytearray(PAGE_SIZE)
    _HEADER.pack_into(output, 0, _ROOT_MAGIC, _VERSION, PAGE_SIZE, len(root.ranges), 0, 0)
    position = _HEADER_SIZE
    for item in root.ranges:
        _ROOT_RECORD.pack_into(output, position, int(item.min_kind), int(item.max_kind), bytes(6),
                               item.min_token, item.max_token, item.page_offset, item.page_length,
                               item.page_logical_digest)
        position += _ROOT_RECORD.size
    return bytes(output)


def decode_root(raw: bytes) -> Root:
    _require(type(raw) is bytes and len(raw) == PAGE_SIZE, "login-fast-index root page size is invalid")
    magic, version, declared_size, count, reserved_1, reserved_2 = _HEADER.unpack_from(raw)
    _require(magic == _ROOT_MAGIC and version == _VERSION and declared_size == PAGE_SIZE,
             "login-fast-index root header is invalid")
    _require(1 <= count <= _MAX_ROOT_RANGES, "login-fast-index root range count is invalid")
    _require(reserved_1 == 0 and reserved_2 == 0, "login-fast-index root header reserved field is nonzero")
    ranges: list[PageRange] = []
    position = _HEADER_SIZE
    for _ in range(count):
        min_kind, max_kind, reserved, min_token, max_token, page_offset, page_length, digest = \
            _ROOT_RECORD.unpack_from(raw, position)
        _require(reserved == bytes(6), "login-fast-index root record reserved field is nonzero")
        ranges.append(PageRange(LookupKind.from_id(min_kind), min_token, LookupKind.from_id(max_kind), max_token,
                                page_offset, page_length, digest))
        position += _ROOT_RECORD.size
    _require(not any(raw[position:]), "login-fast-index root trailing reserved bytes are nonzero")
    return Root(ranges)


def logical_root_digest(root: Root) -> bytes:
    _require(isinstance(root, Root), "login-fast-index root is invalid")
    canonical = bytearray(_ROOT_DIGEST_DOMAIN)
    canonical += struct.pack(">I", len(root.ranges))
    for item in root.ranges:
        canonical += struct.pack(">B32sB32sq32s", int(item.min_kind), item.min_token,
                                 int(item.max_kind), item.max_token, item.page_length,
                                 item.page_logical_digest)
    return hashlib.sha256(canonical).digest()


def locate(root: Root, kind: LookupKind, token: bytes) -> PageRange | None:
    _require(isinstance(root, Root), "login-fast-index root is invalid")
    _require(isinstance(kind, LookupKind) and type(token) is bytes and len(token) == _TOKEN_SIZE,
             "login-fast-index query key is invalid")
    target = _lookup_key(kind, token)
    low, high = 0, len(root.ranges)
    while low < high:
        middle = (low + high) >> 1
        if _lookup_key(root.ranges[middle].max_kind, root.ranges[middle].max_token) < target:
            low = middle + 1
        else:
            high = middle
    if low >= len(root.ranges):
        return None
    item = root.ranges[low]
    return item if target >= _lookup_key(item.min_kind, item.min_token) else None


def query(root: Root, kind: LookupKind, token: bytes, load_page: Callable[[PageRange], Page]) -> list[uuid.UUID]:
    selected = locate(root, kind, token)
    if selected is None:
        return []
    page = load_page(selected)
    _require(isinstance(page, Page) and bool(page.records), "login-fast-index root references an empty leaf")
    _require(hmac.compare_digest(logical_page_digest(page), selected.page_logical_digest),
             "login-fast-index leaf logical digest mismatch")
    first, last = page.records[0], page.records[-1]
    _require(_lookup_key(first.lookup_kind, first.lookup_token) ==
             _lookup_key(selected.min_kind, selected.min_token) and
             _lookup_key(last.lookup_kind, last.lookup_token) ==
             _lookup_key(selected.max_kind, selected.max_token),
             "login-fast-index leaf bounds do not match root")
    return page.query(kind, token)


def normalize_domain(raw: str) -> str:
    return _normalize_host(raw, remove_www=True, label="domain")


def normalize_rp_id(raw: str) -> str:
    return _normalize_host(raw, remove_www=False, label="RP ID")


def normalize_package(raw: str) -> str:
    _require(isinstance(raw, str), "package name is invalid")
    normalized = raw.strip().lower()
    _require(
        3 <= len(normalized) <= 255 and _PACKAGE_PATTERN.fullmatch(normalized) is not None,
        "package name is invalid",
    )
    return normalized


def _normalize_host(raw: str, *, remove_www: bool, label: str) -> str:
    _require(isinstance(raw, str), f"{label} is invalid")
    cleaned = raw.strip().rstrip(".").lower()
    _require(bool(cleaned) and "/" not in cleaned and ":" not in cleaned, f"{label} is invalid")
    try:
        # Python's built-in IDNA codec implements the IDNA 2003 mapping used by
        # java.net.IDN, including Unicode dot folding and case normalization.
        ascii_host = cleaned.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc

    labels = ascii_host.split(".")
    _require(len(ascii_host) <= 253 and _IPV4_PATTERN.fullmatch(ascii_host) is None, f"{label} is invalid")
    _require(
        len(labels) >= 2
        and all(
            1 <= len(part) <= 63 and _ASCII_LABEL_PATTERN.fullmatch(part) is not None
            for part in labels
        ),
        f"{label} is invalid",
    )
    normalized = ascii_host[4:] if remove_www and ascii_host.startswith("www.") else ascii_host
    _require("." in normalized, f"{label} is invalid")
    return normalized


def _lookup_token(search_index_key: bytes, kind: LookupKind, normalized: str) -> bytes:
    _require(
        isinstance(search_index_key, bytes) and len(search_index_key) == _TOKEN_SIZE,
        "SearchIndexKey must be 32 bytes",
    )
    return hmac.new(
        search_index_key,
        _TOKEN_PREFIX + bytes((int(kind),)) + normalized.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def domain_token(search_index_key: bytes, domain: str) -> bytes:
    return _lookup_token(search_index_key, LookupKind.DOMAIN, normalize_domain(domain))


def package_token(search_index_key: bytes, package_name: str) -> bytes:
    return _lookup_token(search_index_key, LookupKind.PACKAGE, normalize_package(package_name))


def rp_id_token(search_index_key: bytes, rp_id: str) -> bytes:
    return _lookup_token(search_index_key, LookupKind.RP_ID, normalize_rp_id(rp_id))


def _parent_domain_candidates(normalized: str) -> list[str]:
    labels = normalized.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def query_domain(page: Page | Root, search_index_key: bytes, domain: str,
                 load_page: Callable[[PageRange], Page] | None = None) -> list[uuid.UUID]:
    normalized = normalize_domain(domain)
    result: list[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for candidate in _parent_domain_candidates(normalized):
        token = _lookup_token(search_index_key, LookupKind.DOMAIN, candidate)
        matches = (page.query(LookupKind.DOMAIN, token) if isinstance(page, Page) else
                   query(page, LookupKind.DOMAIN, token, _required_loader(load_page)))
        for entry_id in matches:
            if entry_id not in seen:
                seen.add(entry_id)
                result.append(entry_id)
    return result


def query_package(page: Page | Root, search_index_key: bytes, package_name: str,
                  load_page: Callable[[PageRange], Page] | None = None) -> list[uuid.UUID]:
    token = package_token(search_index_key, package_name)
    return (page.query(LookupKind.PACKAGE, token) if isinstance(page, Page) else
            query(page, LookupKind.PACKAGE, token, _required_loader(load_page)))


def query_rp_id(page: Page | Root, search_index_key: bytes, rp_id: str,
                load_page: Callable[[PageRange], Page] | None = None) -> list[uuid.UUID]:
    token = rp_id_token(search_index_key, rp_id)
    return (page.query(LookupKind.RP_ID, token) if isinstance(page, Page) else
            query(page, LookupKind.RP_ID, token, _required_loader(load_page)))


def _required_loader(load_page: Callable[[PageRange], Page] | None) -> Callable[[PageRange], Page]:
    _require(callable(load_page), "multi-page login-fast-index query requires a page loader")
    return load_page


class PmvLoginFastIndex:
    """Android-shaped facade for the shared login-fast-index page."""

    PAGE_SIZE: ClassVar[int] = PAGE_SIZE
    EntryType: ClassVar[type[EntryType]] = EntryType
    State: ClassVar[type[State]] = State
    LookupKind: ClassVar[type[LookupKind]] = LookupKind
    Record: ClassVar[type[Record]] = Record
    Page: ClassVar[type[Page]] = Page
    PageLocation: ClassVar[type[PageLocation]] = PageLocation
    PageRange: ClassVar[type[PageRange]] = PageRange
    Root: ClassVar[type[Root]] = Root
    Plan: ClassVar[type[Plan]] = Plan
    encode = staticmethod(encode)
    decode = staticmethod(decode)
    normalizeDomain = staticmethod(normalize_domain)
    normalizeRpId = staticmethod(normalize_rp_id)
    normalizePackage = staticmethod(normalize_package)
    domainToken = staticmethod(domain_token)
    packageToken = staticmethod(package_token)
    rpIdToken = staticmethod(rp_id_token)
    queryDomain = staticmethod(query_domain)
    queryPackage = staticmethod(query_package)
    queryRpId = staticmethod(query_rp_id)
    buildPages = staticmethod(build_pages)
    buildRoot = staticmethod(build_root)
    buildPlan = staticmethod(build_plan)
    encodeRoot = staticmethod(encode_root)
    decodeRoot = staticmethod(decode_root)
    logicalPageDigest = staticmethod(logical_page_digest)
    logicalRootDigest = staticmethod(logical_root_digest)
    locate = staticmethod(locate)
    query = staticmethod(query)


__all__ = [
    "PAGE_SIZE",
    "EntryType",
    "State",
    "LookupKind",
    "Record",
    "Page",
    "PageLocation",
    "PageRange",
    "Root",
    "Plan",
    "PmvLoginFastIndex",
    "encode",
    "decode",
    "normalize_domain",
    "normalize_rp_id",
    "normalize_package",
    "domain_token",
    "package_token",
    "rp_id_token",
    "query_domain",
    "query_package",
    "query_rp_id",
    "build_pages",
    "build_root",
    "build_plan",
    "encode_root",
    "decode_root",
    "logical_page_digest",
    "logical_root_digest",
    "locate",
    "query",
]
