"""Canonical PMVE media references and declarative legacy-stream import plans."""

from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO, Mapping, Sequence

from .models import Entry
from .pmv_attachment import AttachmentKind
from .pmv_vault_store import MutationContent, ObjectImport, ObjectRef


TYPE_KEY = "$pmv_media_ref"
TYPE_VALUE = "pmv4-object-v1"
STRING_PREFIX = "pmv4-object:v1:"
_IMAGE_KEYS = frozenset(("images", "card_images_b64"))
_ATTACHMENT_KEYS = frozenset(("attachments",))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
_WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/].+\Z")


def _kind_name(kind: AttachmentKind) -> str:
    if kind is AttachmentKind.IMAGE:
        return "image"
    if kind is AttachmentKind.ATTACHMENT:
        return "attachment"
    raise ValueError("invalid media kind")


def _parse_kind(value: object) -> AttachmentKind:
    if value == "image":
        return AttachmentKind.IMAGE
    if value == "attachment":
        return AttachmentKind.ATTACHMENT
    raise ValueError("invalid media kind")


@dataclass(frozen=True, slots=True)
class MediaRef:
    object_id: uuid.UUID
    generation: int
    kind: AttachmentKind
    size: int
    sha256: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.object_id, uuid.UUID):
            raise TypeError("object_id must be UUID")
        if type(self.generation) is not int or not 0 <= self.generation <= (1 << 63) - 1:
            raise ValueError("generation must be a non-negative signed Long")
        if not isinstance(self.kind, AttachmentKind):
            raise TypeError("kind must be AttachmentKind")
        if type(self.size) is not int or not 0 <= self.size <= (1 << 63) - 1:
            raise ValueError("size must be a non-negative signed Long")
        if not isinstance(self.sha256, (bytes, bytearray, memoryview)):
            raise TypeError("sha256 must be bytes-like")
        digest = bytes(self.sha256)
        if len(digest) != 32:
            raise ValueError("sha256 must contain 32 bytes")
        object.__setattr__(self, "sha256", digest)

    def to_json(self) -> dict[str, object]:
        return {
            TYPE_KEY: TYPE_VALUE,
            "object_id": str(self.object_id),
            "generation": self.generation,
            "kind": _kind_name(self.kind),
            "size": self.size,
            "sha256": self.sha256.hex(),
        }

    def to_external_string(self) -> str:
        return (f"{STRING_PREFIX}{self.object_id}:{self.generation}:{_kind_name(self.kind)}:"
                f"{self.size}:{self.sha256.hex()}")


class Classification(str, Enum):
    OBJECT = "object"
    LEGACY_EXTERNAL = "legacy_external"
    INLINE = "inline"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Occurrence:
    path: str
    classification: Classification
    kind: AttachmentKind | None
    raw: object
    ref: MediaRef | None = None


@dataclass(frozen=True, slots=True)
class LegacyStream:
    path: str
    stream: BinaryIO
    expected_size: int
    object_id: uuid.UUID
    generation: int
    kind: AttachmentKind


@dataclass(frozen=True, slots=True)
class TransformPlan:
    original: Entry
    object_imports: tuple[ObjectImport, ...]
    paths: tuple[str, ...]
    path_import_indexes: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not self.path_import_indexes:
            object.__setattr__(self, "path_import_indexes", tuple(range(len(self.paths))))

    def transform(self, object_refs: Sequence[ObjectRef]) -> Entry:
        refs = tuple(object_refs)
        if len(refs) != len(self.object_imports):
            raise ValueError("ObjectRef count does not match media import plan")
        replacements: dict[str, object] = {}
        for path, import_index in zip(self.paths, self.path_import_indexes):
            request = self.object_imports[import_index]
            value = refs[import_index]
            if (value.object_id != request.object_id or value.generation != request.generation or
                    value.kind is not request.kind or value.size != request.expected_size):
                raise ValueError("ObjectRef does not match media import plan")
            replacements[path] = from_store_ref(value).to_json()
        fields = {
            key: _replace(value, f"/fields/{_escape(key)}", replacements)
            for key, value in self.original.fields.items()
        }
        payload = self.original.to_dict()
        payload["fields"] = fields
        return Entry.from_dict(payload)

    def prepare(self, object_refs: Sequence[ObjectRef], metadata: Mapping[str, object],
                other_entries: Sequence[Entry] = ()) -> MutationContent:
        """Convenience bridge passed directly as apply_mutation's prepare callback."""
        transformed = self.transform(object_refs)
        return MutationContent(metadata, (*other_entries, transformed))


def from_json(value: object) -> MediaRef:
    if not isinstance(value, dict):
        raise ValueError("media ref JSON must be an object")
    expected = {TYPE_KEY, "object_id", "generation", "kind", "size", "sha256"}
    if set(value) != expected or value.get(TYPE_KEY) != TYPE_VALUE:
        raise ValueError("media ref JSON fields are not canonical")
    object_text = value["object_id"]
    if not isinstance(object_text, str):
        raise ValueError("object_id must be canonical UUID text")
    object_id = uuid.UUID(object_text)
    if str(object_id) != object_text:
        raise ValueError("object_id must be lowercase canonical UUID")
    generation = value["generation"]
    size = value["size"]
    if type(generation) is not int or type(size) is not int:
        raise ValueError("generation and size must be JSON integers")
    digest = value["sha256"]
    if not isinstance(digest, str) or _HEX.fullmatch(digest) is None:
        raise ValueError("sha256 must be lowercase hex")
    return MediaRef(object_id, generation, _parse_kind(value["kind"]), size, bytes.fromhex(digest))


def from_external_string(value: str) -> MediaRef:
    if not isinstance(value, str) or not value.startswith(STRING_PREFIX):
        raise ValueError("invalid media ref string prefix")
    parts = value.removeprefix(STRING_PREFIX).split(":")
    if len(parts) != 5:
        raise ValueError("invalid media ref string field count")
    object_id = uuid.UUID(parts[0])
    if str(object_id) != parts[0]:
        raise ValueError("object_id must be lowercase canonical UUID")
    if not re.fullmatch(r"0|[1-9][0-9]*", parts[1]) or not re.fullmatch(r"0|[1-9][0-9]*", parts[3]):
        raise ValueError("generation and size must be canonical integers")
    if _HEX.fullmatch(parts[4]) is None:
        raise ValueError("sha256 must be lowercase hex")
    return MediaRef(object_id, int(parts[1]), _parse_kind(parts[2]), int(parts[3]), bytes.fromhex(parts[4]))


def scan(entry: Entry) -> tuple[Occurrence, ...]:
    result: list[Occurrence] = []
    for key, value in entry.fields.items():
        _scan(value, f"/fields/{_escape(key)}", _kind_for_key(key), result)
    return tuple(result)


def scan_value(value: object, base_path: str = "/metadata") -> tuple[Occurrence, ...]:
    """Scan canonical refs anywhere in metadata without treating ordinary strings as media."""
    result: list[Occurrence] = []
    _scan(value, base_path, None, result)
    return tuple(result)


def plan(entry: Entry, streams: Sequence[LegacyStream]) -> TransformPlan:
    sources = tuple(streams)
    if len({item.path for item in sources}) != len(sources):
        raise ValueError("media import paths must be unique")
    occurrences = {item.path: item for item in scan(entry)}
    for source in sources:
        occurrence = occurrences.get(source.path)
        if occurrence is None:
            raise ValueError(f"media import path does not exist: {source.path}")
        if occurrence.classification not in (Classification.LEGACY_EXTERNAL, Classification.INLINE):
            raise ValueError(f"media import path is not legacy or inline: {source.path}")
        if occurrence.kind is not source.kind:
            raise ValueError(f"media import kind does not match field: {source.path}")
        if type(source.expected_size) is not int or source.expected_size < 0:
            raise ValueError("media expected_size must be non-negative")
        if type(source.generation) is not int or source.generation < 0:
            raise ValueError("media generation must be non-negative")
    imports: list[ObjectImport] = []
    indexes: list[int] = []
    by_key: dict[tuple[uuid.UUID, int], int] = {}
    for item in sources:
        key = item.object_id, item.generation
        index = by_key.get(key)
        if index is None:
            index = len(imports)
            by_key[key] = index
            imports.append(ObjectImport(item.stream, item.expected_size, item.object_id,
                                        item.generation, item.kind))
        indexes.append(index)
    return TransformPlan(entry, tuple(imports), tuple(item.path for item in sources), tuple(indexes))


def from_store_ref(value: ObjectRef) -> MediaRef:
    return MediaRef(value.object_id, value.generation, value.kind, value.size, value.sha256)


def _scan(value: object, path: str, inherited_kind: AttachmentKind | None,
          output: list[Occurrence]) -> None:
    try:
        ref = from_json(value)
    except (TypeError, ValueError):
        ref = None
    if ref is not None:
        output.append(Occurrence(path, Classification.OBJECT, ref.kind, value, ref))
        return
    if isinstance(value, dict):
        if TYPE_KEY in value:
            output.append(Occurrence(path, Classification.UNKNOWN, inherited_kind, value))
            return
        if inherited_kind is not None and any(key in value for key in ("name", "mime", "size", "sha256")) and "data" not in value:
            output.append(Occurrence(path, Classification.UNKNOWN, inherited_kind, value))
            return
        module_kind = _kind_for_key(value.get("type")) if isinstance(value.get("type"), str) else None
        for key, child in value.items():
            child_kind = _kind_for_key(key)
            if child_kind is None and key == "value":
                child_kind = module_kind
            elif child_kind is None and key == "data":
                child_kind = inherited_kind
            _scan(child, f"{path}/{_escape(key)}", child_kind, output)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _scan(child, f"{path}/{index}", inherited_kind, output)
        return
    if isinstance(value, str):
        try:
            ref = from_external_string(value)
        except (TypeError, ValueError):
            ref = None
        if ref is not None:
            output.append(Occurrence(path, Classification.OBJECT, ref.kind, value, ref))
            return
        if value.startswith(STRING_PREFIX):
            output.append(Occurrence(path, Classification.UNKNOWN, inherited_kind, value))
            return
        if value.startswith(("img:", "att:", "blb:")):
            kind = (AttachmentKind.IMAGE if value.startswith(("img:", "blb:image:")) else
                    AttachmentKind.ATTACHMENT if value.startswith(("att:", "blb:attachment:")) else
                    inherited_kind)
            output.append(Occurrence(path, Classification.LEGACY_EXTERNAL, kind, value))
            return
    if inherited_kind is not None:
        if isinstance(value, str) and _is_legacy(value):
            classification = Classification.LEGACY_EXTERNAL
        elif isinstance(value, str) and _is_inline(value):
            classification = Classification.INLINE
        else:
            classification = Classification.UNKNOWN
        kind = (AttachmentKind.IMAGE if isinstance(value, str) and value.startswith("img:") else
                AttachmentKind.ATTACHMENT if isinstance(value, str) and value.startswith("att:") else
                inherited_kind)
        output.append(Occurrence(path, classification, kind, value))


def _replace(value: object, path: str, replacements: Mapping[str, object]) -> object:
    if path in replacements:
        return copy.deepcopy(replacements[path])
    if isinstance(value, dict):
        return {key: _replace(child, f"{path}/{_escape(key)}", replacements)
                for key, child in value.items()}
    if isinstance(value, list):
        return [_replace(child, f"{path}/{index}", replacements)
                for index, child in enumerate(value)]
    return copy.deepcopy(value)


def _kind_for_key(key: str) -> AttachmentKind | None:
    if key in _IMAGE_KEYS or key in ("image", "photo"):
        return AttachmentKind.IMAGE
    if key in _ATTACHMENT_KEYS or key == "attachment":
        return AttachmentKind.ATTACHMENT
    return None


def _is_legacy(value: str) -> bool:
    return (value.startswith(("img:", "att:", "blb:", "file://", "/")) or
            _WINDOWS_PATH.fullmatch(value) is not None)


def _is_inline(value: str) -> bool:
    if value.startswith("data:") and ";base64," in value:
        return True
    compact = "".join(value.split())
    if len(compact) < 16 or len(compact) % 4 or _BASE64.fullmatch(compact) is None:
        return False
    return True


def _escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")
