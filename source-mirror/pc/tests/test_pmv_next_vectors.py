from __future__ import annotations

import hashlib
import json
import os
import pytest
from dataclasses import replace
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import cloud_credential_crypto, pmv_commit, pmv_container, pmv_entry_codec, pmv_entry_index, pmv_integrity, pmv_key_schedule
from core import pmv_kdf_policy
from core import pmv_login_fast_index, pmv_sync_authorization, pmv_tombstone, pmv_vault_header, pmv_vault_metadata
from core.models import Entry


SUITE = "PMV_NEXT_V1_SUITE_1"
EXPECTED_FILES = {
    "argon2id.json",
    "hkdf.json",
    "block_aead.json",
    "container.json",
    "commit_entry_index.json",
    "vault_header.json",
    "entry_codec.json",
    "vault_metadata.json",
    "login_fast_index.json",
    "media_ref.json",
    "legacy_media_migration.json",
    "compression.json",
    "tombstone.json",
    "sync_authorization.json",
    "store_interop.json",
    "cloud_credentials.json",
}


def test_cloud_credential_vectors() -> None:
    case = _single_case("cloud_credentials.json")
    inputs, expected = case["inputs"], case["expected"]
    vault_id = UUID(inputs["vaultId"])
    key_wrap = pmv_key_schedule.derive_root_keys(_hex(inputs["rootKeyHex"]), vault_id).key_wrap_key
    key = pmv_key_schedule.derive_cloud_credential_key(key_wrap)
    assert key.hex() == expected["cloudCredentialKeyHex"]
    packed = cloud_credential_crypto.seal_field(
        key, vault_id, inputs["provider"], inputs["field"], inputs["fieldVersion"],
        _hex(inputs["plaintextUtf8Hex"]), _hex(inputs["nonceHex"]),
    )
    assert packed.hex() == expected["packedHex"]


def _vector_root() -> Path:
    override = os.environ.get("VAULT_SHARED_SPEC_DIR")
    root = (
        Path(override).expanduser()
        if override
        else Path(__file__).resolve().parents[2] / "vault_android" / "spec" / "interop" / "pmv_next" / "v1"
    )
    if not root.is_dir():
        raise AssertionError(f"required PMV next vector directory is missing: {root}")
    return root


def _document(name: str) -> dict:
    path = _vector_root() / name
    if not path.is_file():
        raise AssertionError(f"required PMV next shared vector is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _single_case(name: str) -> dict:
    document = _document(name)
    assert document["schemaVersion"] == 1
    assert document["suite"] == SUITE
    [case] = document["cases"]
    return case


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def test_manifest_enumerates_every_vector_case_and_file() -> None:
    root = _vector_root()
    manifest = _document("manifest.json")
    assert manifest["schemaVersion"] == 1
    assert manifest["suite"] == SUITE
    declared = {item["file"]: set(item["caseIds"]) for item in manifest["artifacts"]}
    assert set(declared) == EXPECTED_FILES
    assert {path.name for path in root.glob("*.json") if path.name != "manifest.json"} == EXPECTED_FILES
    for name, expected_ids in declared.items():
        assert (_vector_root() / name).is_file()
        assert {case["id"] for case in _document(name)["cases"]} == expected_ids


def test_tombstone_vectors() -> None:
    case = _single_case("tombstone.json")
    inputs = case["inputs"]
    value = pmv_tombstone.Tombstone(
        UUID(inputs["entryId"]),
        inputs["revision"],
        inputs["purgedAtEpochMillis"],
        bytes.fromhex(inputs["previousContentDigestHex"]),
        inputs["flags"],
    )
    raw = pmv_tombstone.encode_tombstone(value)
    assert raw.hex() == case["expected"]["plaintextHex"]
    assert pmv_tombstone.decode_tombstone(raw) == value


def test_sync_authorization_vectors() -> None:
    for case in _document("sync_authorization.json")["cases"]:
        value, expected = case["inputs"], case["expected"]
        authorization = pmv_sync_authorization.sign_authorization(
            pmv_sync_authorization.DeviceAuthorization(
                UUID(value["vaultId"]), UUID(value["deviceId"]), bytes.fromhex(value["devicePublicKeyHex"]),
                value["permissions"], value["issuedAtEpochMillis"], value["expiresAtEpochMillis"],
                value["revokedAtEpochMillis"], value["authorizationEpoch"],
            ),
            bytes.fromhex(value["vaultPrivateSeedHex"]),
        )
        assert pmv_sync_authorization.encode_authorization(authorization).hex() == expected["authorizationHex"]
        assert pmv_sync_authorization.verify_authorization(
            authorization, bytes.fromhex(value["vaultPublicKeyHex"])
        )
        # 重新编码必须逐字节复现原始记录，否则签名会失效。
        raw = pmv_sync_authorization.encode_authorization(authorization)
        assert pmv_sync_authorization.encode_authorization(
            pmv_sync_authorization.decode_authorization(raw)
        ) == raw
        if "grantedPermissions" in expected:
            decoded = pmv_sync_authorization.decode_authorization(raw)
            assert decoded.permissions == value["permissions"]
            assert decoded.granted_permissions == expected["grantedPermissions"]
        challenge = pmv_sync_authorization.Challenge(
            authorization.vault_id, authorization.device_id, bytes.fromhex(value["serverNonceHex"]),
            bytes.fromhex(value["clientNonceHex"]), pmv_sync_authorization.Operation(value["operation"]),
            UUID(value["requestedCommitId"]), bytes.fromhex(value["requestDigestHex"]),
            UUID(value["sessionId"]), value["challengeExpiresAtEpochMillis"],
        )
        assert pmv_sync_authorization.encode_challenge(challenge).hex() == expected["challengeHex"]
        assert pmv_sync_authorization.sign_challenge(
            challenge, bytes.fromhex(value["devicePrivateSeedHex"])
        ).hex() == expected["responseSignatureHex"]


def test_argon2id_vectors() -> None:
    for vector in _document("argon2id.json")["cases"]:
        assert vector["profile"] in {"STANDARD", "HARDENED"}
        assert vector["version"] == 19
        assert vector["outputBytes"] == pmv_key_schedule.KEY_SIZE
        selected = pmv_kdf_policy.PmvKdfParameters(
            vector["memoryKiB"],
            vector["iterations"],
            vector["parallelism"],
        )
        assert pmv_key_schedule.derive_password_kek(
            _hex(vector["passwordUtf8Hex"]),
            _hex(vector["saltHex"]),
            selected,
        ) == _hex(vector["derivedKekHex"])


def test_hkdf_hierarchy_vectors() -> None:
    vector = _single_case("hkdf.json")
    keys = pmv_key_schedule.derive_root_keys(
        _hex(vector["vaultRootKeyHex"]),
        UUID(vector["vaultId"]),
    )
    expected = vector["rootKeys"]
    assert keys.metadata_key == _hex(expected["metadata"])
    assert keys.entry_root_key == _hex(expected["entryRoot"])
    assert keys.attachment_root_key == _hex(expected["attachmentRoot"])
    assert keys.index_key == _hex(expected["index"])
    assert keys.search_index_key == _hex(expected["searchIndex"])
    assert keys.integrity_key == _hex(expected["integrity"])
    assert keys.sync_auth_key == _hex(expected["syncAuth"])
    assert keys.key_wrap_key == _hex(expected["keyWrap"])

    entry = vector["entryGeneration"]
    assert pmv_key_schedule.derive_entry_generation_key(
        keys.entry_root_key,
        UUID(entry["entryId"]),
        entry["generation"],
    ) == _hex(entry["expectedKeyHex"])
    attachment = vector["attachmentGeneration"]
    attachment_key = pmv_key_schedule.derive_attachment_object_key(
        keys.attachment_root_key,
        UUID(attachment["attachmentId"]),
        attachment["generation"],
    )
    assert attachment_key == _hex(attachment["expectedKeyHex"])
    chunk = vector["chunk"]
    assert pmv_key_schedule.derive_chunk_key(attachment_key, chunk["chunkIndex"]) == _hex(
        chunk["expectedKeyHex"]
    )
    commit = vector["commitBlock"]
    assert pmv_key_schedule.derive_commit_block_key(
        keys.integrity_key,
        UUID(commit["commitId"]),
        commit["revision"],
    ) == _hex(commit["expectedKeyHex"])
    metadata = vector["metadataBlock"]
    assert pmv_key_schedule.derive_metadata_block_key(
        keys.metadata_key,
        UUID(metadata["objectId"]),
        metadata["generation"],
    ) == _hex(metadata["expectedKeyHex"])
    pages = vector["indexPages"]
    for page in pages["cases"]:
        assert pmv_key_schedule.derive_index_page_key(
            keys.index_key,
            UUID(pages["objectId"]),
            pages["generation"],
            pmv_key_schedule.IndexPageType[page["pageType"]],
        ) == _hex(page["expectedKeyHex"])


def test_derived_block_keys_separate_domain_identity_and_generation_and_enforce_long_range() -> None:
    parent = bytes(range(pmv_key_schedule.KEY_SIZE))
    first_id = UUID("00000000-0000-0000-0000-000000000001")
    second_id = UUID("00000000-0000-0000-0000-000000000002")
    entry = pmv_key_schedule.derive_index_page_key(
        parent, first_id, 0, pmv_key_schedule.IndexPageType.ENTRY_INDEX
    )
    assert entry != pmv_key_schedule.derive_index_page_key(
        parent, second_id, 0, pmv_key_schedule.IndexPageType.ENTRY_INDEX
    )
    assert entry != pmv_key_schedule.derive_index_page_key(
        parent, first_id, 1, pmv_key_schedule.IndexPageType.ENTRY_INDEX
    )
    assert entry != pmv_key_schedule.derive_index_page_key(
        parent, first_id, 0, pmv_key_schedule.IndexPageType.LOGIN_INDEX
    )
    page_keys = {
        pmv_key_schedule.derive_index_page_key(parent, first_id, 0, page_type)
        for page_type in pmv_key_schedule.IndexPageType
    }
    assert len(page_keys) == len(pmv_key_schedule.IndexPageType)
    commit = pmv_key_schedule.derive_commit_block_key(parent, first_id, 0)
    metadata = pmv_key_schedule.derive_metadata_block_key(parent, first_id, 0)
    assert commit != entry
    assert metadata != commit
    assert metadata != pmv_key_schedule.derive_metadata_block_key(parent, second_id, 0)
    assert metadata != pmv_key_schedule.derive_metadata_block_key(parent, first_id, 1)
    assert commit != pmv_key_schedule.derive_commit_block_key(parent, second_id, 0)
    assert commit != pmv_key_schedule.derive_commit_block_key(parent, first_id, 1)
    assert len(pmv_key_schedule.derive_commit_block_key(
        parent, first_id, (1 << 63) - 1
    )) == pmv_key_schedule.KEY_SIZE
    with pytest.raises(ValueError):
        pmv_key_schedule.derive_commit_block_key(parent, first_id, -1)
    with pytest.raises(ValueError):
        pmv_key_schedule.derive_commit_block_key(parent, first_id, 1 << 63)
    with pytest.raises(ValueError):
        pmv_key_schedule.derive_index_page_key(
            parent, first_id, -1, pmv_key_schedule.IndexPageType.VAULT_ROOT
        )
    for invalid in (True, -1, 1 << 63):
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_entry_generation_key(parent, first_id, invalid)
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_attachment_object_key(parent, first_id, invalid)
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_chunk_key(parent, invalid)
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_commit_block_key(parent, first_id, invalid)
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_metadata_block_key(parent, first_id, invalid)
        with pytest.raises((TypeError, ValueError)):
            pmv_key_schedule.derive_index_page_key(
                parent, first_id, invalid, pmv_key_schedule.IndexPageType.VAULT_ROOT
            )


def test_login_fast_index_leaf_and_range_root_vectors() -> None:
    vector = _single_case("login_fast_index.json")
    records = tuple(
        pmv_login_fast_index.Record(
            UUID(value["entryId"]),
            pmv_login_fast_index.EntryType[value["entryType"]],
            pmv_login_fast_index.State[value["state"]],
            pmv_login_fast_index.LookupKind[value["lookupKind"]],
            _hex(value["lookupTokenHex"]),
        )
        for value in vector["records"]
    )
    leaf = pmv_login_fast_index.Page(records)
    assert pmv_login_fast_index.logical_page_digest(leaf) == _hex(vector["leaf"]["expectedLogicalDigestHex"])
    assert hashlib.sha256(pmv_login_fast_index.encode(leaf)).digest() == _hex(
        vector["leaf"]["expectedEncodedSha256Hex"]
    )
    root = pmv_login_fast_index.build_root(
        (leaf,),
        (pmv_login_fast_index.PageLocation(vector["root"]["pageOffset"], vector["root"]["pageLength"]),),
    )
    assert pmv_login_fast_index.logical_root_digest(root) == _hex(vector["root"]["expectedLogicalDigestHex"])
    encoded_root = pmv_login_fast_index.encode_root(root)
    assert hashlib.sha256(encoded_root).digest() == _hex(vector["root"]["expectedEncodedSha256Hex"])
    assert pmv_login_fast_index.decode_root(encoded_root) == root
    relocated = pmv_login_fast_index.build_root(
        (leaf,),
        (pmv_login_fast_index.PageLocation(vector["root"]["pageOffset"] + 4096,
                                           vector["root"]["pageLength"]),),
    )
    assert pmv_login_fast_index.logical_root_digest(relocated) == pmv_login_fast_index.logical_root_digest(root)


def _block_header(value: dict) -> pmv_container.BlockHeader:
    return pmv_container.BlockHeader(
        block_id=UUID(value["blockId"]),
        block_type=pmv_container.BlockType[value["blockType"]],
        object_id=UUID(value["objectId"]),
        object_revision=value["objectRevision"],
        chunk_index=value["chunkIndex"],
        flags=value["flags"],
        crypto_suite_id=value["cryptoSuiteId"],
        codec_id=value["codecId"],
        plain_size=value["plainSize"],
        cipher_size=value["cipherSize"],
        nonce=_hex(value["nonceHex"]),
    )


def test_block_header_aad_and_aead_vectors() -> None:
    vector = _single_case("block_aead.json")
    header = _block_header(vector["header"])
    vault_id = UUID(vector["vaultId"])
    key = _hex(vector["keyHex"])
    plaintext = _hex(vector["plaintextHex"])
    expected_ciphertext = _hex(vector["expectedCiphertextHex"])
    assert pmv_container.encode_block_header(header) == _hex(vector["expectedHeaderHex"])
    assert pmv_container.block_aad(vault_id, header) == _hex(vector["expectedAadHex"])
    assert AESGCM(key).encrypt(header.nonce, plaintext, pmv_container.block_aad(vault_id, header)) == expected_ciphertext
    assert pmv_container.open(
        vault_id,
        key,
        pmv_container.EncodedBlock(header, expected_ciphertext),
    ) == plaintext


def test_superblock_vectors() -> None:
    vector = _single_case("container.json")
    value = vector["superblock"]
    authentication_key = _hex(vector["authenticationKeyHex"])
    superblock = pmv_container.Superblock(
        vault_id=UUID(value["vaultId"]),
        sequence=value["sequence"],
        latest_commit_offset=value["latestCommitOffset"],
        latest_index_offset=value["latestIndexOffset"],
        committed_file_end=value["committedFileEnd"],
        kdf_parameters_offset=value["kdfParametersOffset"],
        feature_flags=value["featureFlags"],
    )
    encoded = pmv_container.encode_superblock(superblock, authentication_key)
    assert len(encoded) == vector["expectedEncodedBytes"]
    assert encoded.startswith(_hex(vector["expectedPrefixHex"]))
    assert encoded[-32:] == _hex(vector["expectedAuthTagHex"])
    assert hashlib.sha256(encoded).digest() == _hex(vector["expectedSha256Hex"])
    assert pmv_container.decode_superblock(encoded, authentication_key) == superblock


def test_vault_header_vectors_freeze_bootstrap_layout_and_bytes() -> None:
    document = _document("vault_header.json")
    layout = document["layout"]
    assert layout == {
        "superblockAOffset": 0,
        "superblockBOffset": pmv_container.SUPERBLOCK_SIZE,
        "vaultHeaderAOffset": pmv_container.VAULT_HEADER_PRIMARY_OFFSET,
        "vaultHeaderBOffset": pmv_container.VAULT_HEADER_SECONDARY_OFFSET,
        "dataStartOffset": pmv_container.DATA_START,
        "slotSize": pmv_vault_header.HEADER_SIZE,
    }
    vector = _single_case("vault_header.json")
    encoded = pmv_vault_header.create_header(
        vault_id=UUID(vector["vaultId"]),
        key_revision=vector["keyRevision"],
        header_revision=vector["headerRevision"],
        password_utf8=_hex(vector["passwordUtf8Hex"]),
        recovery_secret=_hex(vector["recoverySecretHex"]),
        vault_root_key=_hex(vector["vaultRootKeyHex"]),
        signing_private_seed=_hex(vector["signingPrivateSeedHex"]),
        salt=_hex(vector["saltHex"]),
        nonces=pmv_vault_header.Nonces(
            _hex(vector["passwordNonceHex"]),
            _hex(vector["recoveryNonceHex"]),
            _hex(vector["signingSeedNonceHex"]),
        ),
    )
    assert len(encoded) == vector["expectedEncodedBytes"]
    prefix = _hex(vector["expectedStructuredPrefixHex"])
    auth_tag = _hex(vector["expectedAuthTagHex"])
    assert encoded.startswith(prefix)
    reserved = encoded[len(prefix):-len(auth_tag)]
    assert len(reserved) == vector["expectedReservedZeroBytes"]
    assert reserved == bytes(len(reserved))
    assert encoded.endswith(auth_tag)
    assert hashlib.sha256(encoded).digest() == _hex(vector["expectedSha256Hex"])
    password = pmv_vault_header.unlock_with_password(encoded, _hex(vector["passwordUtf8Hex"]))
    recovery = pmv_vault_header.unlock_with_recovery(encoded, _hex(vector["recoverySecretHex"]))
    assert password.vault_root_key == recovery.vault_root_key == _hex(vector["vaultRootKeyHex"])
    assert password.signing_private_seed == _hex(vector["signingPrivateSeedHex"])


def test_entry_index_wire_and_logical_digest_vectors() -> None:
    vector = _single_case("commit_entry_index.json")
    records_by_id: dict[str, pmv_entry_index.EntryIndexRecord] = {}
    for value in vector["records"]:
        record = pmv_entry_index.EntryIndexRecord(
            entry_id=UUID(value["entryId"]),
            entry_type=value["entryType"],
            revision=value["revision"],
            offset=value["offset"],
            length=value["length"],
            state=pmv_entry_index.EntryIndexState[value["state"]],
            display_title=value["displayTitle"],
            favorite=value["favorite"],
            icon_object_id=UUID(value["iconObjectId"]) if value["iconObjectId"] else None,
            modified_at_epoch_millis=value["modifiedAtEpochMillis"],
            content_digest=_hex(value["contentDigestHex"]),
        )
        assert pmv_integrity.entry_record_digest(record) == _hex(value["expectedRecordDigestHex"])
        assert pmv_integrity.entry_record_digest(
            replace(record, offset=record.offset + 4096, length=record.length + 1)
        ) == pmv_integrity.entry_record_digest(record)
        records_by_id[value["id"]] = record

    pages: list[pmv_entry_index.EntryIndexPage] = []
    for value in vector["pages"]:
        page = pmv_entry_index.EntryIndexPage(
            records=tuple(records_by_id[record_id] for record_id in value["recordIds"]),
            next_page_offset=value["nextPageOffset"],
        )
        encoded = pmv_entry_index.encode_entry_index_page(page)
        assert pmv_integrity.entry_page_digest(page) == _hex(value["expectedLogicalDigestHex"])
        assert hashlib.sha256(encoded).digest() == _hex(value["expectedEncodedSha256Hex"])
        assert pmv_entry_index.encode_entry_index_page(
            pmv_entry_index.decode_entry_index_page(encoded)
        ) == encoded
        alternate_next = 32768 if page.next_page_offset == 0 else 0
        assert pmv_integrity.entry_page_digest(
            replace(page, next_page_offset=alternate_next)
        ) == pmv_integrity.entry_page_digest(page)
        pages.append(page)
    assert len(pages) == 2

    root_value = vector["root"]
    root = pmv_entry_index.EntryIndexRoot(
        records=tuple(
            pmv_entry_index.EntryIndexRootRecord(
                min_entry_id=UUID(value["minEntryId"]),
                max_entry_id=UUID(value["maxEntryId"]),
                page_offset=value["pageOffset"],
                page_digest=_hex(value["pageDigestHex"]),
            )
            for value in root_value["records"]
        )
    )
    encoded_root = pmv_entry_index.encode_entry_index_root(root)
    assert pmv_integrity.entry_root_digest(root) == _hex(root_value["expectedLogicalDigestHex"])
    assert hashlib.sha256(encoded_root).digest() == _hex(root_value["expectedEncodedSha256Hex"])
    assert pmv_entry_index.encode_entry_index_root(
        pmv_entry_index.decode_entry_index_root(encoded_root)
    ) == encoded_root
    relocated = pmv_entry_index.EntryIndexRoot(
        records=tuple(
            replace(record, page_offset=32768 + index * 8192)
            for index, record in enumerate(root.records)
        )
    )
    assert pmv_integrity.entry_root_digest(relocated) == pmv_integrity.entry_root_digest(root)

    commit_value = vector["commit"]
    vault_id = UUID(commit_value["vaultId"])
    commit_id = UUID(commit_value["commitId"])
    parent_commit_id = UUID(commit_value["parentCommitId"])
    root_digest = _hex(commit_value["rootDigestHex"])
    assert pmv_commit.canonical_signing_bytes(
        vault_id,
        commit_id,
        parent_commit_id,
        commit_value["revision"],
        root_digest,
    ) == _hex(commit_value["expectedCanonicalSigningBytesHex"])
    unsigned = pmv_commit.Commit(
        vault_id=vault_id,
        commit_id=commit_id,
        parent_commit_id=parent_commit_id,
        revision=commit_value["revision"],
        index_root_offset=commit_value["indexRootOffset"],
        index_root_length=commit_value["indexRootLength"],
        root_digest=root_digest,
        signing_public_key=bytes(32),
        signature=bytes(64),
    )
    commit = pmv_commit.sign_commit(
        unsigned,
        Ed25519PrivateKey.from_private_bytes(_hex(commit_value["privateSeedHex"])),
    )
    assert commit.signing_public_key == _hex(commit_value["expectedPublicKeyHex"])
    assert commit.signature == _hex(commit_value["expectedSignatureHex"])
    encoded_commit = pmv_commit.encode_commit(commit)
    assert encoded_commit == _hex(commit_value["expectedEncodedHex"])
    assert hashlib.sha256(encoded_commit).digest() == _hex(commit_value["expectedEncodedSha256Hex"])
    assert pmv_commit.decode_commit(encoded_commit) == commit


def test_entry_canonical_json_vectors() -> None:
    vector = _single_case("entry_codec.json")
    entry = Entry.from_dict(vector["entry"])
    expected = vector["expectedCanonicalJson"].encode("utf-8")
    assert pmv_entry_codec.encode_entry(entry) == expected
    assert pmv_entry_codec.decode_entry(expected, UUID(entry.id)).to_dict() == entry.to_dict()


def test_vault_metadata_canonical_json_and_logical_digest_vectors() -> None:
    vector = _single_case("vault_metadata.json")
    metadata = vector["metadata"]
    expected = vector["expectedCanonicalJson"].encode("utf-8")
    assert pmv_vault_metadata.BLOCK_TYPE.name == vector["blockType"]
    assert pmv_vault_metadata.encode_metadata(metadata) == expected
    assert pmv_vault_metadata.decode_metadata(expected, UUID(metadata["vault_id"])) == metadata
    assert pmv_vault_metadata.logical_digest(metadata) == _hex(vector["expectedLogicalDigestHex"])
