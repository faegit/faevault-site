import io
import uuid

import pytest

from core.pmv_attachment import CHUNK_SIZE, AttachmentKind, ChunkFailure
from core.pmv_container import BLOCK_HEADER_SIZE
from core.pmv_integrity import encrypted_block_digest
from core.pmv_object_store import StoredBlock, import_from, open_range_to, open_to


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
OBJECT_ID = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")
ROOT_KEY = bytes(range(32))


class Storage:
    def __init__(self):
        self.next = 16 * 1024
        self.blocks = {}

    def append(self, block):
        offset = self.next
        length = BLOCK_HEADER_SIZE + len(block.ciphertext)
        self.blocks[offset] = block
        self.next += length
        return StoredBlock(offset, length)

    def read(self, offset, length):
        block = self.blocks[offset]
        assert BLOCK_HEADER_SIZE + len(block.ciphertext) == length
        return block


@pytest.mark.parametrize("size", [0, CHUNK_SIZE, CHUNK_SIZE + 19])
def test_multichunk_zero_and_boundary_objects_round_trip(size):
    plain = bytes((value * 31) & 0xff for value in range(size))
    storage = Storage()
    result = import_from(io.BytesIO(plain), size, VAULT_ID, OBJECT_ID, size,
                         AttachmentKind.ATTACHMENT, ROOT_KEY, storage.append)
    chunks = {record.key: record for record in result.chunk_records}
    output = io.BytesIO()
    open_to(result.object_record, VAULT_ID, ROOT_KEY, storage.read, chunks.get, output)
    assert output.getvalue() == plain
    assert len(result.chunk_records) == (0 if size == 0 else (size - 1) // CHUNK_SIZE + 1)


def test_range_reads_only_intersecting_chunks():
    plain = bytes(value & 0xff for value in range(CHUNK_SIZE * 2 + 31))
    storage = Storage()
    result = import_from(io.BytesIO(plain), len(plain), VAULT_ID, OBJECT_ID, 4,
                         AttachmentKind.IMAGE, ROOT_KEY, storage.append)
    chunks = {record.key: record for record in result.chunk_records}
    requested = []

    def find_chunk(key):
        requested.append(key)
        return chunks.get(key)

    output = io.BytesIO()
    start = CHUNK_SIZE - 3
    open_range_to(result.object_record, start, 9, VAULT_ID, ROOT_KEY,
                  storage.read, find_chunk, output)
    assert output.getvalue() == plain[start:start + 9]
    assert [key.chunk_index for key in requested] == [0, 1]


def test_rejects_swapped_location_tag_and_digest():
    plain = bytes(CHUNK_SIZE + 1)
    storage = Storage()
    result = import_from(io.BytesIO(plain), len(plain), VAULT_ID, OBJECT_ID, 8,
                         AttachmentKind.ATTACHMENT, ROOT_KEY, storage.append)
    chunks = {record.key: record for record in result.chunk_records}

    def swapped(offset, length):
        if offset == result.chunk_records[0].block_offset:
            other = result.chunk_records[1]
            return storage.read(other.block_offset, other.block_length)
        return storage.read(offset, length)

    with pytest.raises(ChunkFailure):
        open_to(result.object_record, VAULT_ID, ROOT_KEY, swapped, chunks.get, io.BytesIO())

    first = result.chunk_records[0]
    from dataclasses import replace
    wrong_location = replace(first, block_length=first.block_length + 1)
    with pytest.raises(ChunkFailure):
        open_to(result.object_record, VAULT_ID, ROOT_KEY, storage.read,
                lambda key: wrong_location if key == first.key else chunks.get(key), io.BytesIO())

    block = storage.blocks[first.block_offset]
    damaged = bytearray(block.ciphertext)
    damaged[0] ^= 1
    from core.pmv_container import EncodedBlock
    storage.blocks[first.block_offset] = EncodedBlock(block.header, damaged)
    with pytest.raises(ChunkFailure):
        open_to(result.object_record, VAULT_ID, ROOT_KEY, storage.read, chunks.get, io.BytesIO())

    bad_tag_record = replace(first, cipher_digest=encrypted_block_digest(storage.blocks[first.block_offset]))
    with pytest.raises(ChunkFailure):
        open_to(result.object_record, VAULT_ID, ROOT_KEY, storage.read,
                lambda key: bad_tag_record if key == first.key else chunks.get(key), io.BytesIO())

    bad_manifest = replace(result.object_record, plain_digest=bytes([1]) * 32)
    with pytest.raises(ValueError):
        open_to(bad_manifest, VAULT_ID, ROOT_KEY, storage.read, chunks.get, io.BytesIO())


def test_cancelled_ten_gib_simulation_never_publishes_records_and_reads_one_chunk_at_a_time():
    class SimulatedTenGiB:
        def __init__(self):
            self.max_request = 0

        def read(self, size=-1):
            self.max_request = max(self.max_request, size)
            return bytes(size)

    stream = SimulatedTenGiB()
    storage = Storage()
    appended = 0
    published = None

    def cancel_after_second(block):
        nonlocal appended
        location = storage.append(block)
        appended += 1
        if appended == 2:
            raise KeyboardInterrupt
        return location

    with pytest.raises(KeyboardInterrupt):
        published = import_from(stream, 10 * 1024**3, VAULT_ID, OBJECT_ID, 9,
                                AttachmentKind.ATTACHMENT, ROOT_KEY, cancel_after_second)
    assert published is None
    assert storage.blocks
    assert stream.max_request <= CHUNK_SIZE
