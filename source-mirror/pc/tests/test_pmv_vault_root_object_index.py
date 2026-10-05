import uuid
import pytest

from core.pmv_commit import ROOT_DIGEST_SIZE
from core.pmv_container import DATA_START
from core.pmv_vault_root import RootReference, RootType, VaultRoot, decode_vault_root, encode_vault_root, logical_root_digest
from core.pmv_object_index import (
    ChunkKey, ChunkPage, ChunkRecord, ExistingPage, ObjectKey, ObjectPage, ObjectRecord,
    RangeRecord, RangeRoot, decode_chunk_page, decode_object_page, decode_object_root,
    decode_chunk_root, encode_chunk_page, encode_chunk_root, encode_object_page, encode_object_root, object_page_digest,
    object_root_digest, plan_object_pages,
)

ID1 = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
ID2 = uuid.UUID("10112233-4455-6677-8899-aabbccddeeff")
D1 = bytes(range(32))
D2 = bytes(255-i for i in range(32))

def root(entry_offset=DATA_START, object_offset=20000):
    return VaultRoot(RootReference(RootType.ENTRY, entry_offset, 1000, D1),
                     object_index=RootReference(RootType.OBJECT, object_offset, 2000, D2))

def test_cross_end_fixed_vault_root_fixture_and_logical_digest():
    raw = encode_vault_root(root())
    assert len(raw) == 16*1024 and raw[:4] == b"PMVR"
    assert raw[32:34] == b"\x01\x01" and raw[96] == 0
    assert decode_vault_root(raw) == root()
    assert logical_root_digest(root()) == logical_root_digest(root(80000, 120000))
    assert len(logical_root_digest(root())) == ROOT_DIGEST_SIZE

def test_vault_root_rejects_reserved_and_noncanonical_absent():
    raw=bytearray(encode_vault_root(root()));raw[-1]=1
    with pytest.raises(ValueError):decode_vault_root(bytes(raw))
    raw=bytearray(encode_vault_root(root()));raw[111]=1
    with pytest.raises(ValueError):decode_vault_root(bytes(raw))

def test_object_and_chunk_fixed_fixtures_round_trip_and_tamper_binding():
    objects=ObjectPage([ObjectRecord(ObjectKey(ID1,7),DATA_START,512,D1,D2),ObjectRecord(ObjectKey(ID2,8),20000,640,D2,D1)])
    chunks=ChunkPage([ChunkRecord(ChunkKey(ID1,7,0),24576,1024,D1,D2),ChunkRecord(ChunkKey(ID1,7,1),25600,1024,D2,D1)])
    assert encode_object_page(objects)[:4] == b"PMOI"
    assert encode_chunk_page(chunks)[:4] == b"PMCI"
    assert decode_object_page(encode_object_page(objects)) == objects
    assert decode_chunk_page(encode_chunk_page(chunks)) == chunks
    assert objects.find(ObjectKey(ID2,8)) == objects.records[1]
    assert chunks.find(ChunkKey(ID1,7,1)) == chunks.records[1]
    moved=ObjectPage([ObjectRecord(ObjectKey(ID1,7),30000,512,D1,D2),ObjectRecord(ObjectKey(ID2,8),31000,640,D2,D1)])
    assert object_page_digest(objects) == object_page_digest(moved)
    changed=ObjectPage([ObjectRecord(ObjectKey(ID1,7),DATA_START,512,D1,D1),objects.records[1]])
    assert object_page_digest(objects) != object_page_digest(changed)
    raw=bytearray(encode_object_page(objects));raw[143]=1
    with pytest.raises(ValueError):decode_object_page(bytes(raw))

def test_range_binary_lookup_overlap_and_offset_independent_digest():
    left=RangeRecord(ObjectKey(ID1,1),ObjectKey(ID1,9),DATA_START,D1)
    right=RangeRecord(ObjectKey(ID2,1),ObjectKey(ID2,9),20000,D2)
    root_value=RangeRoot([left,right])
    assert root_value.find_page(ObjectKey(ID2,4)) == right
    moved=RangeRoot([RangeRecord(left.min_key,left.max_key,40000,D1),RangeRecord(right.min_key,right.max_key,60000,D2)])
    assert object_root_digest(root_value) == object_root_digest(moved)
    assert decode_object_root(encode_object_root(root_value)) == root_value
    with pytest.raises(ValueError):RangeRoot([left,RangeRecord(left.min_key,left.max_key,30000,D1)])
    chunk_left=RangeRecord(ChunkKey(ID1,3,0),ChunkKey(ID1,3,9),DATA_START,D1)
    chunk_right=RangeRecord(ChunkKey(ID2,4,0),ChunkKey(ID2,4,9),30000,D2)
    chunk_root=RangeRoot([chunk_left,chunk_right])
    assert chunk_root.find_page(ChunkKey(ID2,4,5)) == chunk_right
    assert decode_chunk_root(encode_chunk_root(chunk_root)) == chunk_root

def test_duplicate_rejected_and_unchanged_cow_page_reused():
    record=ObjectRecord(ObjectKey(ID1,1),DATA_START,200,D1,D2)
    with pytest.raises(ValueError):ObjectPage([record,record])
    digest=object_page_digest(ObjectPage([record]))
    plan=plan_object_pages([record],[ExistingPage(record.key,record.key,44000,digest)])
    assert plan[0].reused_offset == 44000


@pytest.mark.parametrize("invalid", [True, -1, 1 << 63])
def test_wire_long_fields_reject_values_android_cannot_represent(invalid):
    with pytest.raises((TypeError, ValueError)):
        ObjectKey(ID1, invalid)
    with pytest.raises((TypeError, ValueError)):
        ChunkKey(ID1, invalid, 0)
    with pytest.raises((TypeError, ValueError)):
        ObjectRecord(ObjectKey(ID1, 1), invalid, 512, D1, D2)
    with pytest.raises((TypeError, ValueError)):
        ObjectRecord(ObjectKey(ID1, 1), DATA_START, invalid, D1, D2)
    with pytest.raises((TypeError, ValueError)):
        ChunkRecord(ChunkKey(ID1, 1, 0), invalid, 512, D1, D2)
    with pytest.raises((TypeError, ValueError)):
        RangeRecord(ObjectKey(ID1, 1), ObjectKey(ID1, 2), invalid, D1)
    with pytest.raises((TypeError, ValueError)):
        RootReference(RootType.ENTRY, invalid, 512, D1)
    with pytest.raises((TypeError, ValueError)):
        RootReference(RootType.ENTRY, DATA_START, invalid, D1)


@pytest.mark.parametrize("invalid", [True, -1, 1 << 31])
def test_chunk_index_rejects_values_android_int_cannot_represent(invalid):
    with pytest.raises((TypeError, ValueError)):
        ChunkKey(ID1, 1, invalid)
