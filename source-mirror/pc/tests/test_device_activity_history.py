import uuid
import pytest
from core.models import Entry
from core.storage import Vault, ExternalVaultChange
from core.vault_history import HistoryStore
from core import device_activity

@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setattr('core.device_identity.load_or_create', lambda v: (uuid.UUID(int=7), b's'*32))
    monkeypatch.setattr('core.storage.vault_dir', lambda: tmp_path/'private')
    values={}
    monkeypatch.setattr('core.config.get', lambda key, default=None: values.get(key,default))
    monkeypatch.setattr('core.config.set', lambda key,value: values.update({key:value}))
    value=Vault.create_pmve(tmp_path/'vault.pmv', 'master', b'r'*32)
    yield value
    value.close()

def test_selective_restore_roundtrip(vault, tmp_path):
    a,b=Entry(title='old',password='secret'),Entry(title='keep')
    vault.add(a);vault.add(b)
    history=HistoryStore(vault)
    snapshot=history.capture()
    a.title='new';vault.update(a)
    preview=history.preview(snapshot['snapshot_id'])
    try:
        assert history.restore(preview,[a.id])==1
        assert vault.read_entry(a.id).title=='old'
        assert vault.read_entry(b.id).title=='keep'
        assert vault.read_entry(a.id).updated_at>a.updated_at
        assert any(r['protected'] for r in history.list())
        assert device_activity.verified_last_writer(vault._pmve_store)['device_id']==str(uuid.UUID(int=7))
    finally: preview.close()
    import json
    index=json.dumps(history.list())
    assert 'secret' not in index and 'title' not in index

def test_stale_preview_and_tamper(vault):
    a=Entry(title='original');vault.add(a)
    history=HistoryStore(vault);record=history.capture()
    preview=history.preview(record['snapshot_id'])
    vault.add(Entry(title='extra'))
    with pytest.raises(ExternalVaultChange): history.restore(preview,[a.id])
    preview.close()
    path=history.directory/(record['snapshot_id']+'.pmv')
    with path.open('ab') as f:f.write(b'tampered')
    with pytest.raises(ValueError,match='完整性'):history.preview(record['snapshot_id'])

def test_profile_merge_commutative():
    key=str(uuid.UUID(int=2))
    left={'profiles':[{'device_id':key,'name':'a','platform':'pc','updated_at':4,'last_seen_at':6}]}
    right={'profiles':[{'device_id':key,'name':'b','platform':'android','updated_at':4,'last_seen_at':7}]}
    assert device_activity.merge(left,right)==device_activity.merge(right,left)

def test_retention_and_password_rotation(vault):
    history=HistoryStore(vault)
    a=Entry(title='first');vault.add(a)
    first=history.capture(protected=True)
    for i in range(22):
        a.title=f'change-{i}';vault.update(a)
    assert len([r for r in history.list() if not r['protected']])==20
    assert any(r['snapshot_id']==first['snapshot_id'] for r in history.list())
    vault.change_password('next-password')
    preview=history.preview(first['snapshot_id'],password='master')
    try: assert preview.entries[0].title=='first'
    finally:preview.close()

def test_shared_writer_binding_fixtures():
    import json
    from pathlib import Path
    from types import SimpleNamespace
    data=json.loads(Path('spec/device_activity_v1_fixtures.json').read_text())
    for case in data['writer_cases']:
        store=SimpleNamespace(metadata=lambda: {device_activity.FIELD:case['metadata']},
             identity=SimpleNamespace(parent_commit_id=uuid.UUID(case['parent_commit_id'])))
        result=device_activity.verified_last_writer(store)
        assert (result['device_id'] if result else None)==case['expected_device_id'],case['name']


def test_mutated_preview_cannot_forge_historical_content(vault):
    entry=Entry(title="original");vault.add(entry)
    history=HistoryStore(vault);record=history.capture()
    preview=history.preview(record['snapshot_id'])
    try:
        preview.entries[0].title="forged"
        with pytest.raises(ValueError,match="预览内容"):history.restore(preview,[entry.id])
        assert vault.read_entry(entry.id).title=="original"
    finally:preview.close()

def test_old_password_media_restore_survives_compaction(vault):
    from io import BytesIO
    from core.pmv_vault_store import MutationContent,ObjectImport
    from core.pmv_attachment import AttachmentKind
    from core.pmv_media_ref import from_store_ref
    store=vault._pmve_store
    data=b"historical-image"*5000
    entry=Entry(title="historical photo")
    def prepare(refs):
        entry.fields={"images":[from_store_ref(refs[0]).to_json()]}
        return MutationContent(store.metadata(),[entry])
    store.apply_mutation(expected_sequence=store.identity.sequence,object_imports=[ObjectImport(BytesIO(data),len(data),uuid.uuid4(),1,AttachmentKind.IMAGE)],prepare=prepare)
    fresh=vault.reopen();vault.__dict__.update(fresh.__dict__)
    history=HistoryStore(vault);record=history.capture()
    current=Entry.from_dict(vault.read_entry(entry.id).to_dict());current.fields={};vault.update(current)
    vault.compact_before_sync()
    vault.change_password('new-password')
    preview=history.preview(record['snapshot_id'],password='master')
    try:
        assert history.restore(preview,[entry.id])==1
        vault.compact_before_sync()
        ref=vault.read_entry(entry.id).fields['images'][0]
        output=BytesIO();vault._pmve_store.open_object(uuid.UUID(ref['object_id']),ref['generation'],output)
        assert output.getvalue()==data
    finally:preview.close()

def test_unsupported_device_schema_is_preserved(vault):
    future={"version":2,"future":{"secret":"retained"}}
    assert device_activity.stamp({device_activity.FIELD:future},uuid.UUID(int=7))[device_activity.FIELD]==future


def test_authorization_keeps_unknown_device_activity_schema(vault):
    future={"version":2,"future":{"retained":True}}
    vault._pmve_metadata[device_activity.FIELD]=future
    vault.save()
    vault.ensure_device_authorized()
    assert vault._pmve_store.metadata()[device_activity.FIELD]==future
