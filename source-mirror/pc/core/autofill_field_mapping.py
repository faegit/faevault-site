"""Origin-scoped, encrypted entry metadata for explicitly selected field roles."""
from __future__ import annotations
import time
from .models import Entry
from .autofill_sources import AUTOFILL_ROLES

FIELD_KEY = '_autofill_field_mappings'

def mappings_for(entry: Entry, origin: str) -> dict[str,str]:
    raw=entry.fields.get(FIELD_KEY,[])
    if not isinstance(raw,list):return {}
    latest={}
    for row in raw:
        if not isinstance(row,dict) or row.get('origin')!=origin:continue
        key,role=row.get('field_key'),row.get('role')
        timestamp=row.get('updated_at',0)
        if not isinstance(key,str) or not 1<=len(key)<=256 or not isinstance(timestamp,(int,float)):continue
        if role not in AUTOFILL_ROLES and not row.get('deleted'):continue
        def precedence(value):
            return (value.get('updated_at',0),bool(value.get('deleted')),str(value.get('role','')))
        if key not in latest or precedence(row)>precedence(latest[key]):latest[key]=row
    return {key:row['role'] for key,row in latest.items() if not row.get('deleted') and row.get('role') in AUTOFILL_ROLES}

def with_mapping(entry: Entry, origin: str, key: str, role: str) -> Entry:
    if not isinstance(origin,str) or not origin or not isinstance(key,str) or not 1<=len(key)<=256 or (role and role not in AUTOFILL_ROLES):
        raise ValueError('Invalid autofill field mapping')
    result=Entry.from_dict(entry.to_dict())
    raw=result.fields.get(FIELD_KEY,[])
    rows=[row for row in raw if isinstance(row,dict)] if isinstance(raw,list) else []
    previous=max((float(row.get('updated_at',0)) for row in rows if row.get('origin')==origin and row.get('field_key')==key and isinstance(row.get('updated_at',0),(int,float))),default=0)
    rows=[row for row in rows if not(row.get('origin')==origin and row.get('field_key')==key)]
    rows.append({'origin':origin,'field_key':key,'role':role,'updated_at':max(int(time.time()*1000),int(previous)+1),'deleted':not bool(role)})
    result.fields[FIELD_KEY]=rows
    return result


def native_origin(target) -> str:
    from .native_autofill import normalize_executable_path, normalize_process_name
    import json
    if not target.executable_path:
        return ""
    return "windows:"+json.dumps([normalize_process_name(target.process_name),normalize_executable_path(target.executable_path),target.signer_sha256.lower()],ensure_ascii=False,separators=(",",":"))


def native_field_key(field, fields=None) -> str:
    import json
    if not field.automation_id and not field.name:
        return ""
    import hashlib
    layout=json.dumps(sorted((item.automation_id,item.name) for item in (fields or [field])),ensure_ascii=False,separators=(",",":"))
    signature=hashlib.sha256(layout.encode()).hexdigest()[:24]
    key="uia:"+json.dumps([signature,field.automation_id,field.name],ensure_ascii=False,separators=(",",":"))
    return key if len(key)<=256 else ""


def apply_native_mappings(entry: Entry, prepared):
    from dataclasses import replace
    origin=native_origin(prepared.target)
    if not origin:return prepared
    mapped=mappings_for(entry,origin)
    keys=[native_field_key(field,prepared.fields) for field in prepared.fields]
    return replace(prepared,fields=tuple(replace(field,role=mapped[key] if mapped[key]!="one_time_code" else "otp") if key and keys.count(key)==1 and key in mapped else field for field,key in zip(prepared.fields,keys)))
