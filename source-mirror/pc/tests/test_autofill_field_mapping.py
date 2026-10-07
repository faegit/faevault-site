from core.models import Entry
from core.autofill_field_mapping import mappings_for, with_mapping
import pytest

def test_mapping_roundtrip_and_removal_preserve_source():
    source=Entry(title='Example',password='secret',fields={'other':{'x':1}})
    mapped=with_mapping(source,'https://example.com','/login|input|id|name','custom_secret')
    assert mappings_for(source,'https://example.com')=={}
    assert mappings_for(mapped,'https://example.com')=={'/login|input|id|name':'custom_secret'}
    assert mappings_for(Entry.from_dict(mapped.to_dict()),'https://other.example.com')=={}
    removed=with_mapping(mapped,'https://example.com','/login|input|id|name','')
    assert mappings_for(removed,'https://example.com')=={}
    assert removed.fields['other']=={'x':1}
    assert removed.fields['_autofill_field_mappings'][0]['deleted'] is True

def test_mapping_rejects_unknown_role_and_key():
    for key,role in [('', 'password'),('x','nonsense'),('x'*257,'username')]:
        with pytest.raises(ValueError):with_mapping(Entry(),'https://example.com',key,role)

def test_mapping_ignores_malformed_and_cross_origin_rows():
    entry=Entry(fields={'_autofill_field_mappings':[None,{'origin':'https://example.com','field_key':'a','role':'nonsense'}, {'origin':'https://elsewhere.com','field_key':'a','role':'password'}]})
    assert mappings_for(entry,'https://example.com')=={}


def test_native_mapping_identity_and_signature_are_stable():
    from core.autofill_field_mapping import native_origin, native_field_key, apply_native_mappings
    from core.native_autofill import NativeTarget, FieldInfo, PreparedFill
    first=NativeTarget(1,123,"example.exe",executable_path="C:/Apps/Example.exe",signer_sha256="a"*64)
    field=FieldInfo(object(),"unknown",name="Client Token",automation_id="token",focused=True)
    entry=with_mapping(Entry(),native_origin(first),native_field_key(field),"api_key")
    prepared=PreparedFill(first,(field,))
    assert apply_native_mappings(entry,prepared).fields[0].role=="api_key"
    changed=NativeTarget(2,456,"example.exe",executable_path="C:/Apps/Example.exe",signer_sha256="b"*64)
    assert apply_native_mappings(entry,PreparedFill(changed,(field,))).fields[0].role=="unknown"
    assert prepared.fields[0].role=="unknown"


def test_mapping_equal_timestamp_tombstone_wins_in_both_orders():
    active={"origin":"https://example.com","field_key":"x","role":"password","updated_at":200,"deleted":False}
    deleted=dict(active,deleted=True)
    for rows in [[active,deleted],[deleted,active]]:
        assert mappings_for(Entry(fields={"_autofill_field_mappings":rows}),"https://example.com")=={}


def test_mapping_encrypted_reopen_and_normal_sync_preserve_revocation(tmp_path):
    from core.storage import Vault
    from core.sync import merge
    path=tmp_path/"mapping.pmv"
    vault=Vault.create(path,"test-master")
    original=Entry(title="Example",url="https://example.com",password="synthetic")
    vault.add(original)
    mapped=with_mapping(vault.read_entry(original.id),"https://example.com","uia:synthetic-id","password")
    vault.update(mapped)
    vault=vault.reopen()
    persisted=Entry.from_dict(vault.read_entry(original.id).to_dict())
    assert b"uia:synthetic-id" not in path.read_bytes()
    merged,_=merge([original],[persisted])
    assert mappings_for(merged[0],"https://example.com")=={"uia:synthetic-id":"password"}
    revoked=with_mapping(persisted,"https://example.com","uia:synthetic-id","")
    vault.update(revoked)
    vault=vault.reopen()
    removed=Entry.from_dict(vault.read_entry(original.id).to_dict())
    merged,_=merge([persisted],[removed])
    assert mappings_for(merged[0],"https://example.com")=={}
    vault.close()
