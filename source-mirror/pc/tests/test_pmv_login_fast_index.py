import uuid

import pytest

from core import pmv_login_fast_index as index


KEY = bytes(range(32))
EXACT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
PARENT_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")


def _record(entry_id, kind, value, *, state=index.State.ACTIVE, entry_type=index.EntryType.LOGIN):
    token = {
        index.LookupKind.DOMAIN: index.domain_token,
        index.LookupKind.PACKAGE: index.package_token,
        index.LookupKind.RP_ID: index.rp_id_token,
    }[kind](KEY, value)
    return index.Record(entry_id, entry_type, state, kind, token)


def _page(*records):
    return index.Page(sorted(records, key=lambda record: (
        int(record.lookup_kind), record.lookup_token, record.entry_id.bytes
    )))


def test_normalization_matches_android_case_trailing_dot_www_and_idn_rules():
    assert index.normalize_domain(" WWW.例子.测试. ") == "xn--fsqu00a.xn--0zwm56d"
    assert index.normalize_rp_id("WWW.例子.测试.") == "www.xn--fsqu00a.xn--0zwm56d"
    assert index.normalize_package(" COM.Example_App.Login ") == "com.example_app.login"

    for invalid in ("https://example.com", "127.0.0.1", "localhost", "-bad.example"):
        with pytest.raises(ValueError):
            index.normalize_domain(invalid)


def test_tokens_are_keyed_kind_separated_and_deterministic():
    first = index.domain_token(KEY, "www.Example.com.")
    alias = index.domain_token(KEY, "example.com")

    assert first == alias
    assert first != index.domain_token(bytes((7,)) * 32, "example.com")
    assert first != index.rp_id_token(KEY, "example.com")
    with pytest.raises(ValueError):
        index.domain_token(bytes(31), "example.com")


def test_fixed_page_roundtrip_matches_the_android_record_layout():
    records = _page(
        _record(EXACT_ID, index.LookupKind.DOMAIN, "login.example.com"),
        _record(PARENT_ID, index.LookupKind.DOMAIN, "example.com"),
        _record(
            uuid.UUID("00000000-0000-0000-0000-000000000003"),
            index.LookupKind.RP_ID,
            "example.com",
            state=index.State.TOMBSTONE,
            entry_type=index.EntryType.PASSKEY,
        ),
    ).records
    encoded = index.encode(index.Page(records))

    assert len(encoded) == 16 * 1024 == index.PAGE_SIZE
    assert encoded[:32] == b"PMLF" + (1).to_bytes(4, "big") + (16 * 1024).to_bytes(4, "big") + (3).to_bytes(4, "big") + bytes(16)
    assert index.decode(encoded) == index.Page(records)


def test_domain_query_returns_exact_then_parent_candidates_and_deduplicates():
    shared_id = uuid.UUID("00000000-0000-0000-0000-000000000004")
    page = _page(
        _record(EXACT_ID, index.LookupKind.DOMAIN, "accounts.login.example.com"),
        _record(PARENT_ID, index.LookupKind.DOMAIN, "example.com"),
        _record(shared_id, index.LookupKind.DOMAIN, "accounts.login.example.com"),
        _record(shared_id, index.LookupKind.DOMAIN, "example.com"),
    )

    assert index.query_domain(page, KEY, "www.accounts.login.example.com.") == [
        EXACT_ID, shared_id, PARENT_ID
    ]


def test_package_and_rp_id_are_exact_and_tombstones_are_not_candidates():
    page = _page(
        _record(EXACT_ID, index.LookupKind.PACKAGE, "com.example.app"),
        _record(
            PARENT_ID,
            index.LookupKind.RP_ID,
            "example.com",
            state=index.State.TOMBSTONE,
            entry_type=index.EntryType.PASSKEY,
        ),
    )

    assert index.query_package(page, KEY, "COM.EXAMPLE.APP") == [EXACT_ID]
    assert index.query_package(page, KEY, "com.example") == []
    assert index.query_rp_id(page, KEY, "example.com") == []


def test_page_rejects_unsorted_duplicates_and_capacity_overflow():
    one = _record(EXACT_ID, index.LookupKind.DOMAIN, "example.com")
    two = _record(PARENT_ID, index.LookupKind.DOMAIN, "example.com")
    with pytest.raises(ValueError):
        index.Page((two, one))
    with pytest.raises(ValueError):
        index.Page((one, one))

    records = tuple(
        index.Record(uuid.UUID(int=value), index.EntryType.LOGIN, index.State.ACTIVE,
                     index.LookupKind.DOMAIN, value.to_bytes(32, "big"))
        for value in range(1, 294)
    )
    with pytest.raises(ValueError, match="too many"):
        index.Page(records)


@pytest.mark.parametrize("offset", [19, 51, -1])
def test_decoder_rejects_nonzero_reserved_fields(offset):
    encoded = bytearray(index.encode(_page(
        _record(EXACT_ID, index.LookupKind.DOMAIN, "example.com")
    )))
    encoded[offset] = 1
    with pytest.raises(ValueError, match="reserved"):
        index.decode(bytes(encoded))


@pytest.mark.parametrize(
    ("normalizer", "value"),
    [
        (index.normalize_package, "a.b" * 128),
        (index.normalize_package, "com.example-app"),
        (index.normalize_domain, "a" * 64 + ".example"),
        (index.normalize_rp_id, "example.com:443"),
    ],
)
def test_normalizers_reject_android_boundary_violations(normalizer, value):
    with pytest.raises(ValueError):
        normalizer(value)


def test_multi_page_plan_uses_non_overlapping_ranges_and_binary_lookup():
    records = tuple(
        index.Record(uuid.UUID(int=value), index.EntryType.LOGIN, index.State.ACTIVE,
                     index.LookupKind.DOMAIN, value.to_bytes(32, "big"))
        for value in range(1, 301)
    )
    plan = index.build_plan(reversed(records), 20_000, 16_528)

    assert len(plan.pages) == 2
    assert plan.root is not None and len(plan.root.ranges) == 2
    wanted = records[-1].lookup_token
    selected = index.locate(plan.root, index.LookupKind.DOMAIN, wanted)
    assert selected is plan.root.ranges[1]
    assert index.query(plan.root, index.LookupKind.DOMAIN, wanted,
                       lambda item: plan.pages[plan.root.ranges.index(item)]) == [records[-1].entry_id]
    assert index.locate(plan.root, index.LookupKind.PACKAGE, wanted) is None

    encoded = index.encode_root(plan.root)
    assert len(encoded) == index.PAGE_SIZE and encoded[:4] == b"PMLR"
    assert index.decode_root(encoded) == plan.root


def test_page_and_root_logical_digests_ignore_offsets_but_bind_logical_records():
    first = _page(_record(EXACT_ID, index.LookupKind.DOMAIN, "example.com"))
    changed = _page(_record(PARENT_ID, index.LookupKind.DOMAIN, "example.com"))
    assert index.logical_page_digest(first) != index.logical_page_digest(changed)

    root_a = index.build_root((first,), (index.PageLocation(20_000, 16_528),))
    root_b = index.build_root((first,), (index.PageLocation(40_000, 16_528),))
    assert index.logical_root_digest(root_a) == index.logical_root_digest(root_b)
    changed_root = index.build_root((changed,), (index.PageLocation(40_000, 16_528),))
    assert index.logical_root_digest(root_a) != index.logical_root_digest(changed_root)


def test_multipage_builder_never_splits_token_group_and_rejects_invalid_roots():
    shared_token = bytes((7,)) * 32
    oversized_group = tuple(
        index.Record(uuid.UUID(int=value), index.EntryType.LOGIN, index.State.ACTIVE,
                     index.LookupKind.DOMAIN, shared_token)
        for value in range(1, 294)
    )
    with pytest.raises(ValueError, match="token group"):
        index.build_pages(oversized_group)
    with pytest.raises(ValueError, match="signed 64-bit"):
        index.build_plan(oversized_group[:1], (1 << 63) - 6, 16_528)

    root = index.build_root((index.Page(oversized_group[:1]),), (index.PageLocation(20_000, 16_528),))
    reserved = bytearray(index.encode_root(root))
    reserved[34] = 1
    with pytest.raises(ValueError, match="reserved"):
        index.decode_root(bytes(reserved))
