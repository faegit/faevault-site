from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.pmv_append import DATA_START, PmvAppendOnlyFile, WriteStage
from core.pmv_commit import Commit, encode_commit, sign_commit
from core.pmv_container import BLOCK_HEADER_SIZE, BlockType, seal
from core.pmv_key_schedule import IndexPageType, derive_commit_block_key, derive_index_page_key
from core.pmv_vault_root import PmvVaultRootCodec, RootReference, RootType, VaultRoot

VAULT_ID=uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
AUTH=bytes(range(32));INDEX=bytes(range(32,64));INTEGRITY=bytes(range(64,96))
SIGNING=Ed25519PrivateKey.from_private_bytes(bytes(range(1,33)))
PUBLIC=SIGNING.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)

def _length(block):return BLOCK_HEADER_SIZE+len(block.ciphertext)

def _prepared_publish(tx):
    entry_id=uuid.uuid4()
    entry_root=seal(VAULT_ID,bytes(32),BlockType.INDEX_PAGE,entry_id,tx.next_revision,b"entry-root")
    entry_ref=tx.append_block(entry_root)
    root=VaultRoot(RootReference(RootType.ENTRY,entry_ref.offset,entry_ref.length,bytes(range(32))))
    root_id=uuid.uuid4()
    root_block=seal(VAULT_ID,derive_index_page_key(INDEX,root_id,tx.next_revision,IndexPageType.VAULT_ROOT),
                    BlockType.INDEX_PAGE,root_id,tx.next_revision,PmvVaultRootCodec.encode(root))
    root_ref=tx.append_block(root_block)
    unsigned=Commit(VAULT_ID,uuid.uuid4(),tx.parent_commit_id,tx.next_revision,root_ref.offset,root_ref.length,
                    PmvVaultRootCodec.logical_digest(root),bytes(32),bytes(64))
    commit=sign_commit(unsigned,SIGNING)
    encrypted=seal(VAULT_ID,derive_commit_block_key(INTEGRITY,commit.commit_id,commit.revision),
                   BlockType.COMMIT,commit.commit_id,commit.revision,encode_commit(commit))
    return root_ref,encrypted,commit

def _publish(tx):
    root_ref,encrypted,commit=_prepared_publish(tx)
    return tx.publish(index_root_ref=root_ref,encrypted_commit=encrypted,commit=commit,
                      index_root_key=INDEX,integrity_key=INTEGRITY,trusted_signing_public_key=PUBLIC)

@pytest.mark.parametrize("stage",[WriteStage.AFTER_APPEND,WriteStage.BEFORE_COMMIT,WriteStage.BEFORE_SUPERBLOCK])
def test_fault_injection_aborts_to_old_committed_boundary(tmp_path,stage):
    path=tmp_path/"fault.pmv";container=PmvAppendOnlyFile.create(path,VAULT_ID,AUTH);old_end=container.candidate_states()[0].superblock.committed_file_end
    def fail(actual):
        if actual==stage:raise OSError(stage)
    tx=container._begin_write_for_test(0,fail)
    with pytest.raises(OSError):
        if stage==WriteStage.AFTER_APPEND:tx.append_block(seal(VAULT_ID,bytes(32),BlockType.ENTRY,uuid.uuid4(),1,b"x"))
        else:_publish(tx)
    assert path.stat().st_size==old_end
    assert PmvAppendOnlyFile(path,AUTH).candidate_states()[0].superblock.sequence==0

def test_second_writer_blocks_then_stale_base_is_rejected(tmp_path):
    path=tmp_path/"writers.pmv";container=PmvAppendOnlyFile.create(path,VAULT_ID,AUTH);first=container.begin_write(0)
    started=threading.Event()
    def open_second():started.set();return PmvAppendOnlyFile(path,AUTH).begin_write(0)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(open_second);assert started.wait(1);time.sleep(.05);assert not future.done()
        _publish(first)
        with pytest.raises(ValueError,match="stale"):future.result(timeout=5)

def test_thousand_streamed_chunks_retain_only_refs_and_publish(tmp_path):
    path=tmp_path/"large.pmv";container=PmvAppendOnlyFile.create(path,VAULT_ID,AUTH);tx=container.begin_write(0)
    for index in range(1000):
        tx.append_block(seal(VAULT_ID,bytes(32),BlockType.ATTACHMENT_CHUNK,uuid.UUID(int=1),1,b"x",chunk_index=index))
    assert tx._last_ref is not None and not hasattr(tx._last_ref,"ciphertext")
    published=_publish(tx)
    assert published.superblock.sequence==1 and published.superblock.committed_file_end>DATA_START

def test_close_aborts_unpublished_tail_and_stale_begin_rejects(tmp_path):
    path=tmp_path/"abort.pmv";container=PmvAppendOnlyFile.create(path,VAULT_ID,AUTH)
    tx=container.begin_write(0);tx.append_block(seal(VAULT_ID,bytes(32),BlockType.ENTRY,uuid.uuid4(),1,b"tail"));tx.close()
    assert path.stat().st_size==DATA_START
    _publish(container.begin_write(0))
    with pytest.raises(ValueError,match="stale"):container.begin_write(0)
