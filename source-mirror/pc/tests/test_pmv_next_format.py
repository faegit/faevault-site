from dataclasses import replace
import uuid

import pytest
from cryptography.exceptions import InvalidTag

from core import pmv_container, pmv_entry_index


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
OTHER_VAULT_ID = uuid.UUID("ffeeddcc-bbaa-9988-7766-554433221100")
BLOCK_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
OBJECT_ID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
OTHER_OBJECT_ID = uuid.UUID("eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa")
AUTH_KEY = bytes((index * 7) % 256 for index in range(32))
BLOCK_KEY = bytes(range(32))
WRONG_BLOCK_KEY = bytes(reversed(range(32)))

ID_1 = uuid.UUID("00000000-0000-0000-0000-000000000001")
ID_2 = uuid.UUID("00000000-0000-0000-0000-000000000002")
ID_3 = uuid.UUID("00000000-0000-0000-0000-000000000003")
ID_4 = uuid.UUID("00000000-0000-0000-0000-000000000004")
ID_5 = uuid.UUID("00000000-0000-0000-0000-000000000005")


def _superblock(sequence, commit_offset, index_offset, file_end):
    return pmv_container.Superblock(
        vault_id=VAULT_ID,
        sequence=sequence,
        latest_commit_offset=commit_offset,
        latest_index_offset=index_offset,
        committed_file_end=file_end,
        kdf_parameters_offset=pmv_container.DATA_START,
        feature_flags=5,
    )


def _block_header():
    return pmv_container.BlockHeader(
        block_id=BLOCK_ID,
        block_type=pmv_container.BlockType.ATTACHMENT_CHUNK,
        object_id=OBJECT_ID,
        object_revision=9,
        chunk_index=3,
        flags=2,
        crypto_suite_id=1,
        codec_id=0,
        plain_size=8 * 1024 * 1024,
        cipher_size=8 * 1024 * 1024 + pmv_container.GCM_TAG_SIZE,
        nonce=bytes(range(pmv_container.GCM_NONCE_SIZE)),
    )


def _entry_record(
    entry_id,
    entry_type="login",
    revision=1,
    offset=pmv_container.DATA_START,
    *,
    display_title="",
    favorite=False,
    icon_object_id=None,
    modified_at=0,
    state=pmv_entry_index.EntryIndexState.ACTIVE,
):
    return pmv_entry_index.EntryIndexRecord(
        entry_id=entry_id,
        entry_type=entry_type,
        revision=revision,
        offset=offset,
        length=pmv_container.BLOCK_HEADER_SIZE + 256,
        state=state,
        display_title=display_title,
        favorite=favorite,
        icon_object_id=icon_object_id,
        modified_at_epoch_millis=modified_at,
    )


def test_superblock_is_a_fixed_4096_byte_authenticated_roundtrip():
    assert pmv_container.VAULT_HEADER_PRIMARY_OFFSET == 8_192
    assert pmv_container.VAULT_HEADER_SECONDARY_OFFSET == 12_288
    assert pmv_container.DATA_START == 16_384
    original = _superblock(42, 16_384, 18_432, 20_480)

    encoded = pmv_container.encode_superblock(original, AUTH_KEY)

    assert len(encoded) == 4_096 == pmv_container.SUPERBLOCK_SIZE
    assert pmv_container.decode_superblock(encoded, AUTH_KEY) == original


def test_invalid_newer_superblock_falls_back_to_previous_authenticated_slot():
    older = _superblock(7, 16_384, 16_384, 16_384)
    newer = _superblock(8, 20_480, 16_384, 24_576)
    older_bytes = pmv_container.encode_superblock(older, AUTH_KEY)
    tampered_newer = bytearray(pmv_container.encode_superblock(newer, AUTH_KEY))
    tampered_newer[80] ^= 1

    assert (
        pmv_container.select_latest_superblock(
            older_bytes,
            bytes(tampered_newer),
            AUTH_KEY,
        )
        == older
    )
    assert (
        pmv_container.select_latest_superblock(
            bytes(tampered_newer),
            bytes(tampered_newer),
            AUTH_KEY,
        )
        is None
    )


def test_block_header_is_a_fixed_128_byte_roundtrip():
    original = _block_header()

    encoded = pmv_container.encode_block_header(original)

    assert len(encoded) == 128 == pmv_container.BLOCK_HEADER_SIZE
    assert pmv_container.decode_block_header(encoded) == original


@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("block_id", uuid.UUID("22222222-3333-4444-5555-666666666666")),
        ("block_type", pmv_container.BlockType.IMAGE_CHUNK),
        ("object_id", OTHER_OBJECT_ID),
        ("object_revision", 10),
        ("chunk_index", 4),
        ("flags", 3),
        ("crypto_suite_id", 2),
        ("codec_id", 1),
        ("plain_size", 8 * 1024 * 1024 - 1),
        ("cipher_size", 8 * 1024 * 1024 + pmv_container.GCM_TAG_SIZE + 1),
        ("nonce", bytes(reversed(range(pmv_container.GCM_NONCE_SIZE)))),
    ],
)
def test_every_encoded_block_header_field_is_bound_into_aad(field, changed_value):
    header = _block_header()
    original_aad = pmv_container.block_aad(VAULT_ID, header)

    changed_header = replace(header, **{field: changed_value})

    assert pmv_container.block_aad(VAULT_ID, changed_header) != original_aad


def test_vault_id_is_bound_into_block_aad():
    header = _block_header()

    assert pmv_container.block_aad(OTHER_VAULT_ID, header) != pmv_container.block_aad(
        VAULT_ID,
        header,
    )


def test_block_header_rejects_nonzero_reserved_fields():
    encoded = bytearray(pmv_container.encode_block_header(_block_header()))
    encoded[-1] = 1

    with pytest.raises(ValueError):
        pmv_container.decode_block_header(bytes(encoded))


def test_aes_gcm_block_roundtrips_with_fixed_identity_and_key():
    plaintext = "PMV next format: 账户附件".encode()

    sealed = pmv_container.seal(
        VAULT_ID,
        BLOCK_KEY,
        pmv_container.BlockType.ENTRY,
        OBJECT_ID,
        7,
        plaintext,
        block_id=BLOCK_ID,
        flags=4,
    )

    assert sealed.header.block_id == BLOCK_ID
    assert sealed.header.object_id == OBJECT_ID
    assert sealed.header.plain_size == len(plaintext)
    assert sealed.header.cipher_size == len(plaintext) + pmv_container.GCM_TAG_SIZE
    assert pmv_container.open(VAULT_ID, BLOCK_KEY, sealed) == plaintext


def test_aes_gcm_block_rejects_wrong_key_wrong_vault_and_tampering():
    sealed = pmv_container.seal(
        VAULT_ID,
        BLOCK_KEY,
        pmv_container.BlockType.ENTRY,
        OBJECT_ID,
        7,
        b"authenticated entry payload",
        block_id=BLOCK_ID,
    )

    with pytest.raises(InvalidTag):
        pmv_container.open(VAULT_ID, WRONG_BLOCK_KEY, sealed)
    with pytest.raises(InvalidTag):
        pmv_container.open(OTHER_VAULT_ID, BLOCK_KEY, sealed)

    tampered = bytearray(sealed.ciphertext)
    tampered[-1] ^= 1
    tampered_block = pmv_container.EncodedBlock(sealed.header, bytes(tampered))
    with pytest.raises(InvalidTag):
        pmv_container.open(VAULT_ID, BLOCK_KEY, tampered_block)


def test_pmei_leaf_page_is_16_kib_and_roundtrips_every_record_field():
    icon_id = uuid.UUID("10000000-0000-0000-0000-000000000001")
    page = pmv_entry_index.EntryIndexPage(
        records=(
            _entry_record(
                ID_1,
                display_title="账户",
                favorite=True,
                icon_object_id=icon_id,
                modified_at=1_700_000_000_000,
            ),
            _entry_record(
                ID_2,
                entry_type="secure_note",
                revision=4,
                offset=16_384,
                display_title="私密笔记",
                modified_at=1_700_000_000_001,
                state=pmv_entry_index.EntryIndexState.TOMBSTONE,
            ),
        ),
        next_page_offset=65_536,
    )

    encoded = pmv_entry_index.encode_entry_index_page(page)

    assert len(encoded) == 16 * 1024 == pmv_entry_index.PAGE_SIZE
    assert pmv_entry_index.decode_entry_index_page(encoded) == page


def test_pmei_leaf_page_binary_searches_first_middle_last_and_missing_ids():
    page = pmv_entry_index.EntryIndexPage(
        records=(
            _entry_record(ID_1, offset=pmv_container.DATA_START),
            _entry_record(ID_3, offset=pmv_container.DATA_START + 8_192),
            _entry_record(ID_5, offset=pmv_container.DATA_START + 16_384),
        )
    )

    assert page.find(ID_1).entry_id == ID_1
    assert page.find(ID_3).entry_id == ID_3
    assert page.find(ID_5).entry_id == ID_5
    assert page.find(ID_2) is None


def test_pmei_leaf_page_rejects_unsorted_and_duplicate_ids():
    with pytest.raises(ValueError):
        pmv_entry_index.EntryIndexPage(
            (_entry_record(ID_2), _entry_record(ID_1, offset=pmv_container.DATA_START + 8_192))
        )

    with pytest.raises(ValueError):
        pmv_entry_index.EntryIndexPage(
            (_entry_record(ID_1), _entry_record(ID_1, offset=pmv_container.DATA_START + 8_192))
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("revision", True),
        ("revision", -1),
        ("revision", 1 << 63),
        ("offset", True),
        ("offset", 1 << 63),
        ("length", True),
        ("length", 1 << 63),
        ("modified_at_epoch_millis", True),
        ("modified_at_epoch_millis", -1),
        ("modified_at_epoch_millis", 1 << 63),
    ],
)
def test_pmei_record_rejects_values_android_long_cannot_represent(field, value):
    with pytest.raises(ValueError, match="signed 64-bit"):
        replace(_entry_record(ID_1), **{field: value})


@pytest.mark.parametrize("value", [True, -1, 1 << 63])
def test_pmei_page_offsets_reject_values_android_long_cannot_represent(value):
    with pytest.raises(ValueError, match="signed 64-bit"):
        pmv_entry_index.EntryIndexPage((_entry_record(ID_1),), next_page_offset=value)
    with pytest.raises(ValueError, match="signed 64-bit"):
        pmv_entry_index.EntryIndexRootRecord(ID_1, ID_2, value)


def test_pmei_leaf_page_rejects_variable_length_capacity_overflow():
    records = tuple(
        _entry_record(
            uuid.UUID(int=index),
            entry_type="t" * 64,
            offset=pmv_container.DATA_START + index * 1_024,
            display_title="x" * 1_024,
        )
        for index in range(1, 152)
    )
    page = pmv_entry_index.EntryIndexPage(records)

    with pytest.raises(ValueError, match="capacity"):
        pmv_entry_index.encode_entry_index_page(page)


@pytest.mark.parametrize("reserved_offset", [31, 84, -1])
def test_pmei_leaf_page_rejects_nonzero_reserved_fields(reserved_offset):
    page = pmv_entry_index.EntryIndexPage((_entry_record(ID_1),))
    encoded = bytearray(pmv_entry_index.encode_entry_index_page(page))
    encoded[reserved_offset] = 1

    with pytest.raises(ValueError, match="reserved"):
        pmv_entry_index.decode_entry_index_page(bytes(encoded))


def test_pmer_root_page_is_16_kib_roundtrips_and_binary_searches_ranges():
    root = pmv_entry_index.EntryIndexRoot(
        records=(
            pmv_entry_index.EntryIndexRootRecord(ID_1, ID_2, 16_384),
            pmv_entry_index.EntryIndexRootRecord(ID_3, ID_4, 32_768),
        )
    )

    encoded = pmv_entry_index.encode_entry_index_root(root)
    decoded = pmv_entry_index.decode_entry_index_root(encoded)

    assert len(encoded) == 16 * 1024 == pmv_entry_index.PAGE_SIZE
    assert decoded == root
    assert decoded.find_page(ID_1).page_offset == 16_384
    assert decoded.find_page(ID_4).page_offset == 32_768
    assert decoded.find_page(ID_5) is None


def test_pmer_root_rejects_reversed_or_overlapping_ranges():
    with pytest.raises(ValueError):
        pmv_entry_index.EntryIndexRootRecord(ID_2, ID_1, 16_384)

    with pytest.raises(ValueError):
        pmv_entry_index.EntryIndexRoot(
            records=(
                pmv_entry_index.EntryIndexRootRecord(ID_1, ID_3, 16_384),
                pmv_entry_index.EntryIndexRootRecord(ID_3, ID_4, 32_768),
            )
        )


def test_pmer_root_rejects_duplicate_page_offsets():
    with pytest.raises(ValueError, match="offsets must be unique"):
        pmv_entry_index.EntryIndexRoot(
            records=(
                pmv_entry_index.EntryIndexRootRecord(ID_1, ID_2, 16_384),
                pmv_entry_index.EntryIndexRootRecord(ID_3, ID_4, 16_384),
            )
        )


@pytest.mark.parametrize("reserved_offset", [31, -1])
def test_pmer_root_rejects_nonzero_reserved_fields(reserved_offset):
    root = pmv_entry_index.EntryIndexRoot(
        (pmv_entry_index.EntryIndexRootRecord(ID_1, ID_2, 16_384),)
    )
    encoded = bytearray(pmv_entry_index.encode_entry_index_root(root))
    encoded[reserved_offset] = 1

    with pytest.raises(ValueError, match="reserved"):
        pmv_entry_index.decode_entry_index_root(bytes(encoded))
