"""Authenticated descriptive device activity; independent of authorization policy."""
import copy
import json
import platform
import socket
import time
import uuid

FIELD = "_device_activity_v1"

def normalize(value):
    result = {"version": 1, "profiles": []}
    if not isinstance(value, dict):
        return result
    if value.get("version", 1) != 1:
        return copy.deepcopy(value)
    result = copy.deepcopy(value)
    result["version"] = value.get("version", 1)
    deleted = {}
    raw_deleted = value.get("deleted_profiles", {})
    for key, timestamp in raw_deleted.items() if isinstance(raw_deleted, dict) else []:
        try:
            if type(timestamp) is int and 0 <= timestamp <= 2**63 - 1:
                canonical_key = str(uuid.UUID(key))
                deleted[canonical_key] = max(timestamp, deleted.get(canonical_key, -1))
        except (ValueError, TypeError, AttributeError):
            continue
    if deleted or "deleted_profiles" in value:
        result["deleted_profiles"] = dict(sorted(deleted.items()))
    by_id = {}
    raw_profiles = value.get("profiles", [])
    for raw in raw_profiles if isinstance(raw_profiles, list) else []:
        try:
            item = copy.deepcopy(raw)
            item["device_id"] = str(uuid.UUID(item["device_id"]))
            item["name"] = str(item.get("name", ""))[:64]
            if item.get("platform") not in ("pc", "android"):
                continue
            for key in ("last_seen_at", "updated_at"):
                item[key] = max(0, int(item.get(key, 0)))
            old = by_id.get(item["device_id"])
            if old is None or (item["updated_at"], item["name"], item["platform"], json.dumps(item, sort_keys=True)) > (old["updated_at"], old["name"], old["platform"], json.dumps(old, sort_keys=True)):
                by_id[item["device_id"]] = item
        except (ValueError, TypeError, KeyError):
            continue
    result["profiles"] = [by_id[key] for key in sorted(by_id) if by_id[key]["updated_at"] > deleted.get(key, -1)]
    writer = value.get("last_writer")
    try:
        result["last_writer"] = {"device_id": str(uuid.UUID(writer["device_id"])), "updated_at": max(0, int(writer["updated_at"]))}
        if writer.get("parent_commit_id") is not None:
            result["last_writer"]["parent_commit_id"] = str(uuid.UUID(writer["parent_commit_id"]))
    except (ValueError, TypeError, KeyError):
        result.pop("last_writer", None)
    return result

def merge(left, right):
    a, b = normalize(left), normalize(right)
    if a.get("version", 1) != 1 or b.get("version", 1) != 1:
        return copy.deepcopy(max((a, b), key=lambda v: (v.get("version", 1) if isinstance(v.get("version", 1), int) else 0, json.dumps(v, sort_keys=True))))
    combined = copy.deepcopy(a)
    for key, value in b.items():
        if key not in combined:
            combined[key] = copy.deepcopy(value)
    combined["version"] = max(int(a.get("version", 1)), int(b.get("version", 1)))
    combined["profiles"] = a["profiles"] + b["profiles"]
    deleted = dict(a.get("deleted_profiles", {}))
    for key, timestamp in b.get("deleted_profiles", {}).items():
        deleted[key] = max(timestamp, deleted.get(key, -1))
    if deleted:
        combined["deleted_profiles"] = deleted
    result = normalize(combined)
    for profile in result["profiles"]:
        profile["last_seen_at"] = max(p["last_seen_at"] for p in a["profiles"] + b["profiles"] if p["device_id"] == profile["device_id"])
    writers = [v["last_writer"] for v in (a, b) if "last_writer" in v]
    if writers:
        result["last_writer"] = max(writers, key=lambda w: (w["updated_at"], w["device_id"]))
    return result

def current_device_id(vault):
    from .device_identity import load_or_create
    return str(load_or_create(vault._pmve_store.identity.vault_id)[0])

def system_device_name():
    """Read the current OS computer name, including changes made after unlock."""
    for read_name in (socket.gethostname, platform.node):
        try:
            name = read_name().strip()
        except (OSError, UnicodeError):
            continue
        if name:
            return name[:64]
    return "PC"


def stamp(metadata, device_id, now=None):
    updated = copy.deepcopy(metadata)
    activity = normalize(updated.get(FIELD))
    if activity.get("version", 1) != 1:
        return updated
    device_id = str(uuid.UUID(str(device_id)))
    now = int(time.time() * 1000) if now is None else int(now)
    now = max(now, activity.get("last_writer", {}).get("updated_at", -1) + 1, activity.get("deleted_profiles", {}).get(device_id, -1) + 1)
    profile = next((p for p in activity["profiles"] if p["device_id"] == device_id), None)
    name = system_device_name()
    if profile is None:
        profile = {"device_id": device_id, "name": name, "platform": "pc", "updated_at": now}
        activity["profiles"].append(profile)
    if profile.get("name") != name:
        profile["name"] = name
        profile["updated_at"] = max(now, profile["updated_at"] + 1)
    profile["last_seen_at"] = max(now, profile.get("last_seen_at", 0))
    activity["last_writer"] = {"device_id": device_id, "updated_at": now}
    updated[FIELD] = normalize(activity)
    return updated

def devices(vault):
    from . import pmv_device_registry
    metadata = vault._pmve_store.metadata()
    records = pmv_device_registry.verify_all(pmv_device_registry.decode(metadata), vault._pmve_store.identity.signing_public_key)
    own = current_device_id(vault)
    activity = normalize(metadata.get(FIELD))
    profiles = {p["device_id"]: p for p in activity["profiles"]} if activity.get("version", 1) == 1 else {}
    latest = {}
    for r in records:
        if r.device_id not in latest or r.epoch > latest[r.device_id].epoch:
            latest[r.device_id] = r
    result = []
    for key in sorted(set(profiles) | {str(k) for k in latest} | {own}):
        p = copy.deepcopy(profiles.get(key, {"device_id": key, "name": system_device_name() if key == own else "未知设备", "platform": "pc" if key == own else "unknown", "last_seen_at": 0, "updated_at": 0}))
        if key == own:
            p["name"] = system_device_name()
        record = latest.get(uuid.UUID(key))
        if record is None or record.vault_id != vault._pmve_store.identity.vault_id or not record.active_at(int(time.time() * 1000)):
            continue
        p.update(is_current=key == own, authorized=True)
        result.append(p)
    return result

def verified_last_writer(store):
    activity = normalize(store.metadata().get(FIELD))
    if activity.get("version", 1) != 1:
        return None
    writer = activity.get("last_writer")
    parent = store.identity.parent_commit_id
    if not writer or writer.get("parent_commit_id") != str(parent):
        return None
    profile = next((p for p in activity["profiles"] if p["device_id"] == writer["device_id"]), None)
    return copy.deepcopy(profile) if profile else None


def remove_profile(metadata, device_id, now=None):
    updated = copy.deepcopy(metadata)
    raw_activity = updated.get(FIELD)
    if FIELD in updated and (not isinstance(raw_activity, dict)
                             or type(raw_activity.get("version", 1)) is not int
                             or raw_activity.get("version", 1) != 1):
        raise ValueError("设备记录版本不受支持，无法删除。")
    activity = normalize(raw_activity)
    if activity.get("version", 1) != 1:
        raise ValueError("设备记录版本不受支持，无法删除。")
    key = str(uuid.UUID(str(device_id)))
    timestamp = int(time.time() * 1000) if now is None else int(now)
    timestamp = max(timestamp, activity.get("last_writer", {}).get("updated_at", -1) + 1,
                    activity.get("deleted_profiles", {}).get(key, -1) + 1,
                    max((p["updated_at"] + 1 for p in activity["profiles"] if p["device_id"] == key), default=0))
    if not 0 <= timestamp <= 2**63 - 1:
        raise ValueError("设备记录时间超出支持范围，无法删除。")
    activity.setdefault("deleted_profiles", {})[key] = timestamp
    updated[FIELD] = normalize(activity)
    return updated
