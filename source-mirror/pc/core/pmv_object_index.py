"""Fixed object/chunk lookup pages and binary-search range roots.

Wire 64-bit counters, offsets, and lengths are restricted to Android's
non-negative ``Long`` range even though their logical encoding is unsigned.
"""
from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from typing import Generic, Iterable, TypeVar

from .pmv_container import DATA_START

PAGE_SIZE = 16 * 1024
_HEADER = struct.Struct(">4sIIIqq")
_VERSION = 1
_OBJECT = struct.Struct(">16sqqq32s32sq")
_CHUNK = struct.Struct(">16sqi iqq32s32sqq")
_OBJECT_ROOT = struct.Struct(">16sq16sqq32s16s")
_CHUNK_ROOT = struct.Struct(">16sqi16sqi q32s8s")
assert _OBJECT.size == 112 and _CHUNK.size == 128
assert _OBJECT_ROOT.size == 104 and _CHUNK_ROOT.size == 104
K = TypeVar("K")
_MAX_WIRE_LONG = (1 << 63) - 1
_MAX_WIRE_INT = (1 << 31) - 1


def _require_wire_long(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not minimum <= value <= _MAX_WIRE_LONG:
        raise ValueError(f"{label} must be between {minimum} and 2^63 - 1")
    return value


def _require_wire_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not 0 <= value <= _MAX_WIRE_INT:
        raise ValueError(f"{label} must be between 0 and 2^31 - 1")
    return value


def _require_block_range(offset: object, length: object, label: str) -> None:
    checked_offset = _require_wire_long(offset, f"{label}_offset", minimum=DATA_START)
    checked_length = _require_wire_long(length, f"{label}_length", minimum=1)
    if checked_offset > _MAX_WIRE_LONG - checked_length:
        raise ValueError(f"{label} range exceeds the cross-runtime signed 64-bit range")


@dataclass(frozen=True, order=True, slots=True)
class ObjectKey:
    object_id: uuid.UUID
    generation: int
    def __post_init__(self):
        if not isinstance(self.object_id, uuid.UUID): raise ValueError("invalid object key")
        _require_wire_long(self.generation, "generation")

@dataclass(frozen=True, order=True, slots=True)
class ChunkKey:
    object_id: uuid.UUID
    generation: int
    chunk_index: int
    def __post_init__(self):
        if not isinstance(self.object_id, uuid.UUID): raise ValueError("invalid chunk key")
        _require_wire_long(self.generation, "generation")
        _require_wire_int(self.chunk_index, "chunk_index")

def _check_digest(value):
    if type(value) is not bytes or len(value) != 32: raise ValueError("digest must be 32 bytes")

@dataclass(frozen=True, slots=True)
class ObjectRecord:
    key: ObjectKey; manifest_offset: int; manifest_length: int; plain_digest: bytes; cipher_digest: bytes
    def __post_init__(self):
        if not isinstance(self.key, ObjectKey): raise ValueError("invalid object key")
        _require_block_range(self.manifest_offset, self.manifest_length, "manifest")
        _check_digest(self.plain_digest); _check_digest(self.cipher_digest)

@dataclass(frozen=True, slots=True)
class ChunkRecord:
    key: ChunkKey; block_offset: int; block_length: int; plain_digest: bytes; cipher_digest: bytes
    def __post_init__(self):
        if not isinstance(self.key, ChunkKey): raise ValueError("invalid chunk key")
        _require_block_range(self.block_offset, self.block_length, "block")
        _check_digest(self.plain_digest); _check_digest(self.cipher_digest)

def _tuple(value): return tuple(value)
def _sorted_unique(values):
    if any(a >= b for a,b in zip(values,values[1:])): raise ValueError("index keys must be strictly sorted and unique")

@dataclass(frozen=True, slots=True)
class ObjectPage:
    records: tuple[ObjectRecord,...] | Iterable[ObjectRecord]
    def __post_init__(self):
        records=_tuple(self.records); object.__setattr__(self,"records",records); _sorted_unique([r.key for r in records])
        if len(records) > (PAGE_SIZE-_HEADER.size)//_OBJECT.size: raise ValueError("too many object records")
    def find(self, key): return _binary_find(self.records, key)

@dataclass(frozen=True, slots=True)
class ChunkPage:
    records: tuple[ChunkRecord,...] | Iterable[ChunkRecord]
    def __post_init__(self):
        records=_tuple(self.records); object.__setattr__(self,"records",records); _sorted_unique([r.key for r in records])
        if len(records) > (PAGE_SIZE-_HEADER.size)//_CHUNK.size: raise ValueError("too many chunk records")
    def find(self, key): return _binary_find(self.records, key)

def _binary_find(records, key):
    lo,hi=0,len(records)-1
    while lo<=hi:
        m=(lo+hi)//2;candidate=records[m]
        if candidate.key<key:lo=m+1
        elif candidate.key>key:hi=m-1
        else:return candidate
    return None

@dataclass(frozen=True, slots=True)
class RangeRecord(Generic[K]):
    min_key: K; max_key: K; page_offset: int; page_digest: bytes
    def __post_init__(self):
        if self.min_key > self.max_key: raise ValueError("invalid root range")
        _require_wire_long(self.page_offset, "page_offset", minimum=DATA_START)
        _check_digest(self.page_digest)

@dataclass(frozen=True, slots=True)
class RangeRoot(Generic[K]):
    records: tuple[RangeRecord[K],...] | Iterable[RangeRecord[K]]
    def __post_init__(self):
        records=_tuple(self.records);object.__setattr__(self,"records",records)
        if len(records) > (PAGE_SIZE-_HEADER.size)//104 or len({r.page_offset for r in records}) != len(records): raise ValueError("invalid range root")
        if any(a.max_key >= b.min_key for a,b in zip(records,records[1:])): raise ValueError("overlapping root ranges")
    def find_page(self,key):
        lo,hi=0,len(self.records)-1
        while lo<=hi:
            m=(lo+hi)//2;r=self.records[m]
            if key<r.min_key:hi=m-1
            elif key>r.max_key:lo=m+1
            else:return r
        return None

@dataclass(frozen=True, slots=True)
class ExistingPage(Generic[K]):
    min_key: K; max_key: K; offset: int; digest: bytes
    def __post_init__(self):
        if self.min_key > self.max_key: raise ValueError("invalid existing page range")
        _require_wire_long(self.offset, "offset", minimum=DATA_START)
        _check_digest(self.digest)

@dataclass(frozen=True, slots=True)
class PlannedPage(Generic[K]):
    page: object; digest: bytes; reused_offset: int | None
    def __post_init__(self):
        _check_digest(self.digest)
        if self.reused_offset is not None:
            _require_wire_long(self.reused_offset, "reused_offset", minimum=DATA_START)

def _header(magic,count):
    out=bytearray(PAGE_SIZE);_HEADER.pack_into(out,0,magic,_VERSION,PAGE_SIZE,count,0,0);return out
def _read(raw,magic,max_count):
    if type(raw) is not bytes or len(raw)!=PAGE_SIZE:raise ValueError("invalid index page size")
    got,ver,size,count,r1,r2=_HEADER.unpack_from(raw)
    if got!=magic or ver!=_VERSION or size!=PAGE_SIZE or not 0<=count<=max_count or r1 or r2:raise ValueError("invalid index header")
    return count

def encode_object_page(page):
    out=_header(b"PMOI",len(page.records));p=_HEADER.size
    for r in page.records:_OBJECT.pack_into(out,p,r.key.object_id.bytes,r.key.generation,r.manifest_offset,r.manifest_length,r.plain_digest,r.cipher_digest,0);p+=_OBJECT.size
    return bytes(out)
def decode_object_page(raw):
    n=_read(raw,b"PMOI",(PAGE_SIZE-_HEADER.size)//_OBJECT.size);p=_HEADER.size;items=[]
    for _ in range(n):
        oid,g,o,l,pd,cd,res=_OBJECT.unpack_from(raw,p);p+=_OBJECT.size
        if res:raise ValueError("non-zero object reserved field")
        items.append(ObjectRecord(ObjectKey(uuid.UUID(bytes=oid),g),o,l,pd,cd))
    if any(raw[p:]):raise ValueError("non-zero trailing bytes")
    return ObjectPage(items)
def encode_chunk_page(page):
    out=_header(b"PMCI",len(page.records));p=_HEADER.size
    for r in page.records:_CHUNK.pack_into(out,p,r.key.object_id.bytes,r.key.generation,r.key.chunk_index,0,r.block_offset,r.block_length,r.plain_digest,r.cipher_digest,0,0);p+=_CHUNK.size
    return bytes(out)
def decode_chunk_page(raw):
    n=_read(raw,b"PMCI",(PAGE_SIZE-_HEADER.size)//_CHUNK.size);p=_HEADER.size;items=[]
    for _ in range(n):
        oid,g,i,res,o,l,pd,cd,r1,r2=_CHUNK.unpack_from(raw,p);p+=_CHUNK.size
        if res or r1 or r2:raise ValueError("non-zero chunk reserved field")
        items.append(ChunkRecord(ChunkKey(uuid.UUID(bytes=oid),g,i),o,l,pd,cd))
    if any(raw[p:]):raise ValueError("non-zero trailing bytes")
    return ChunkPage(items)

def _encode_root(root,magic,packer):
    out=_header(magic,len(root.records));p=_HEADER.size
    for r in root.records:packer.pack_into(out,p,r.min_key.object_id.bytes,r.min_key.generation,*(([r.min_key.chunk_index]) if isinstance(r.min_key,ChunkKey) else []),r.max_key.object_id.bytes,r.max_key.generation,*(([r.max_key.chunk_index]) if isinstance(r.max_key,ChunkKey) else []),r.page_offset,r.page_digest,bytes(8 if isinstance(r.min_key,ChunkKey) else 16));p+=104
    return bytes(out)
def encode_object_root(root):return _encode_root(root,b"PMOR",_OBJECT_ROOT)
def encode_chunk_root(root):return _encode_root(root,b"PMCR",_CHUNK_ROOT)
def _decode_root(raw,magic,packer,chunk):
    n=_read(raw,magic,(PAGE_SIZE-_HEADER.size)//104);p=_HEADER.size;items=[]
    for _ in range(n):
        values=packer.unpack_from(raw,p);p+=104
        if any(values[-1]):raise ValueError("non-zero root reserved field")
        if chunk:min_key=ChunkKey(uuid.UUID(bytes=values[0]),values[1],values[2]);max_key=ChunkKey(uuid.UUID(bytes=values[3]),values[4],values[5]);o,d=values[6:8]
        else:min_key=ObjectKey(uuid.UUID(bytes=values[0]),values[1]);max_key=ObjectKey(uuid.UUID(bytes=values[2]),values[3]);o,d=values[4:6]
        items.append(RangeRecord(min_key,max_key,o,d))
    if any(raw[p:]):raise ValueError("non-zero trailing bytes")
    return RangeRoot(items)
def decode_object_root(raw):return _decode_root(raw,b"PMOR",_OBJECT_ROOT,False)
def decode_chunk_root(raw):return _decode_root(raw,b"PMCR",_CHUNK_ROOT,True)

def _digest(domain,records,body):
    h=hashlib.sha256();h.update(domain);h.update(len(records).to_bytes(4,"big"));[h.update(body(r)) for r in records];return h.digest()
def object_page_digest(page):return _digest(b"pmv/v1/object-index-page\0",page.records,lambda r:r.key.object_id.bytes+struct.pack(">qq",r.key.generation,r.manifest_length)+r.plain_digest+r.cipher_digest)
def chunk_page_digest(page):return _digest(b"pmv/v1/chunk-index-page\0",page.records,lambda r:r.key.object_id.bytes+struct.pack(">qiq",r.key.generation,r.key.chunk_index,r.block_length)+r.plain_digest+r.cipher_digest)
def object_root_digest(root):return _digest(b"pmv/v1/object-index-root\0",root.records,lambda r:r.min_key.object_id.bytes+struct.pack(">q",r.min_key.generation)+r.max_key.object_id.bytes+struct.pack(">q",r.max_key.generation)+r.page_digest)
def chunk_root_digest(root):return _digest(b"pmv/v1/chunk-index-root\0",root.records,lambda r:r.min_key.object_id.bytes+struct.pack(">qi",r.min_key.generation,r.min_key.chunk_index)+r.max_key.object_id.bytes+struct.pack(">qi",r.max_key.generation,r.max_key.chunk_index)+r.page_digest)

def _plan(records,size,page_type,digest_fn,previous):
    _sorted_unique([record.key for record in records])
    result=[]
    for i in range(0,len(records),size):
        page=page_type(records[i:i+size]);digest=digest_fn(page);min_key,max_key=page.records[0].key,page.records[-1].key
        old=next((p for p in previous if p.min_key==min_key and p.max_key==max_key and p.digest==digest),None);result.append(PlannedPage(page,digest,old.offset if old else None))
    return result
def plan_object_pages(records,previous=()):return _plan(records,(PAGE_SIZE-_HEADER.size)//_OBJECT.size,ObjectPage,object_page_digest,previous)
def plan_chunk_pages(records,previous=()):return _plan(records,(PAGE_SIZE-_HEADER.size)//_CHUNK.size,ChunkPage,chunk_page_digest,previous)
