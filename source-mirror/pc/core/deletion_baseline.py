"""Deletion-record checkpoints. Activity timestamps never prove acknowledgement."""
import copy
import math
import uuid

FIELD = "deletion_baseline"
FLOOR_KEY = "deletion_baseline_floors"
KNOWN_FIELD = "_deletion_known_members_v1"

def _advance_floor(floors, vault_id, candidate):
    floors = copy.deepcopy(floors or {})
    if not isinstance(floors, dict):
        raise ValueError("删除记录基线配置无效")
    previous = floors.get(str(vault_id))
    if previous is not None:
        old = baseline(previous)
        if candidate["generation"] < old["generation"] or (candidate["generation"] == old["generation"] and candidate["epoch"] != old["epoch"]):
            raise ValueError("此库副本早于已确认的删除记录基线，须恢复当前完整库")
    if candidate["generation"]:
        candidate = copy.deepcopy(candidate)
        candidate["checkpoint"] = None
        floors[str(vault_id)] = candidate
    return floors


def accept_floor(vault_id, value):
    from . import config
    candidate = baseline(value)
    config.update(FLOOR_KEY, lambda floors: _advance_floor(floors, vault_id, candidate))


def commit_with_floor(vault_id, value, commit):
    from . import config
    candidate = baseline(value)
    result = []
    def update(floors):
        advanced = _advance_floor(floors, vault_id, candidate)
        result.append(commit())
        return advanced
    config.update(FLOOR_KEY, update)
    return result[0]


def guard_adoption(local, incoming):
    a, b = baseline(local), baseline(incoming)
    if b["generation"] > a["generation"]:
        return
    guard(a, b)

def baseline(value=None):
    if value is None:
        return {"schema_version": 1, "generation": 0, "epoch": "", "checkpoint": None}
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("删除记录基线版本不受支持，请更新客户端")
    result = copy.deepcopy(value)
    result.setdefault("checkpoint", None)
    generation = result.get("generation")
    if type(generation) is not int or not 0 <= generation < 2**63:
        raise ValueError("删除记录基线代数无效")
    if generation:
        _uuid(result.get("epoch"))
    elif result.get("epoch") != "":
        raise ValueError("初始删除记录基线无效")
    checkpoint = result.get("checkpoint")
    if checkpoint is not None:
        if not isinstance(checkpoint, dict):
            raise ValueError("删除记录检查点无效")
        _uuid(checkpoint.get("checkpoint_id"))
        members = checkpoint.get("member_ids")
        if not isinstance(members, list) or not members or any(not isinstance(m, str) for m in members) or len(members) != len(set(members)):
            raise ValueError("删除记录设备集合无效")
        for member in members:
            _uuid(member)
        purges = checkpoint.get("purge_snapshot")
        if not isinstance(purges, dict):
            raise ValueError("删除记录快照无效")
        for key, timestamp in purges.items():
            _uuid(key)
            if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError("删除记录时间无效")
        acks = checkpoint.get("acknowledgements")
        if not isinstance(acks, dict) or any(k not in members or v != checkpoint["checkpoint_id"] for k, v in acks.items()):
            raise ValueError("删除记录确认无效")
    return result

def _uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("删除记录标识无效")

def guard(local, incoming):
    a, b = baseline(local), baseline(incoming)
    if (a["generation"], a["epoch"]) != (b["generation"], b["epoch"]):
        raise ValueError("删除记录基线不一致：旧设备须从当前完整库重新初始化；旧备份只能单独恢复")

def members(metadata, own):
    from . import device_activity, pmv_device_registry
    raw = metadata.get(device_activity.FIELD)
    if raw is not None:
        if not isinstance(raw, dict) or type(raw.get("version", 1)) is not int or raw.get("version", 1) != 1 or not isinstance(raw.get("profiles", []), list):
            raise ValueError("设备活动记录不受支持")
        for profile in raw.get("profiles", []):
            if not isinstance(profile, dict) or profile.get("platform") not in ("pc", "android"):
                raise ValueError("设备活动记录不受支持")
            _uuid(profile.get("device_id"))
    activity = device_activity.normalize(metadata.get(device_activity.FIELD))
    if activity.get("version") != 1:
        raise ValueError("设备活动版本不受支持")
    known = metadata.get(KNOWN_FIELD, [])
    if not isinstance(known, list) or any(not isinstance(m, str) for m in known) or len(known) != len(set(known)):
        raise ValueError("历史设备记录无效")
    for member in known:
        _uuid(member)
    raw_ids = {p["device_id"] for p in raw.get("profiles", [])} if raw else set()
    return sorted(({own} if own else set()) | set(known) | raw_ids | {str(r.device_id) for r in pmv_device_registry.decode(metadata)})

def preserve_members(metadata, own=None):
    result = copy.deepcopy(metadata)
    activity = metadata.get("_device_activity_v1")
    if isinstance(activity, dict) and type(activity.get("version")) is int and activity["version"] > 1:
        # Ordinary writes retain opaque future activity. Cleanup still calls
        # members on the original metadata and cannot infer its holder set.
        known_metadata = copy.deepcopy(metadata)
        known_metadata.pop("_device_activity_v1")
        result[KNOWN_FIELD] = members(known_metadata, own)
    else:
        result[KNOWN_FIELD] = members(metadata, own)
    return result

def start(metadata, own):
    result = copy.deepcopy(metadata)
    value = baseline(result.get(FIELD))
    checkpoint_id = str(uuid.uuid4())
    value["checkpoint"] = {"checkpoint_id": checkpoint_id, "purge_snapshot": copy.deepcopy(result.get("purge_tombstones", {})), "member_ids": members(result, own), "acknowledgements": {own: checkpoint_id}}
    result[FIELD] = value
    return result

def ready(metadata, own):
    value = baseline(metadata.get(FIELD))
    cp = value["checkpoint"]
    return bool(cp and cp["purge_snapshot"] and cp["purge_snapshot"] == metadata.get("purge_tombstones", {}) and cp["member_ids"] == members(metadata, own) and all(cp["acknowledgements"].get(m) == cp["checkpoint_id"] for m in cp["member_ids"]))

def acknowledge(metadata, own):
    result = copy.deepcopy(metadata)
    value = baseline(result.get(FIELD))
    cp = value["checkpoint"]
    if cp is None:
        return result
    activity = result.get("_device_activity_v1")
    if isinstance(activity, dict) and type(activity.get("version")) is int and activity["version"] > 1:
        return result
    if cp and cp["purge_snapshot"] == result.get("purge_tombstones", {}) and cp["member_ids"] == members(result, own):
        cp["acknowledgements"][own] = cp["checkpoint_id"]
    result[FIELD] = value
    return result

def merge(local, remote):
    guard(local, remote)
    a, b = baseline(local), baseline(remote)
    ca, cb = a["checkpoint"], b["checkpoint"]
    if ca and cb and ca["checkpoint_id"] == cb["checkpoint_id"]:
        if ca["purge_snapshot"] != cb["purge_snapshot"] or ca["member_ids"] != cb["member_ids"]:
            a["checkpoint"] = None
            return a
        ca["acknowledgements"].update(cb["acknowledgements"])
        return a
    if ca and cb:
        a["checkpoint"] = None
        return a
    return a if ca else b

def finish(metadata, own, checkpoint_id):
    if not ready(metadata, own) or baseline(metadata.get(FIELD))["checkpoint"]["checkpoint_id"] != checkpoint_id:
        raise ValueError("清理条件已变化，请所有设备重新同步")
    result = copy.deepcopy(metadata)
    value = baseline(result.get(FIELD))
    for key in value["checkpoint"]["purge_snapshot"]:
        result["purge_tombstones"].pop(key, None)
    value.update(generation=value["generation"] + 1, epoch=str(uuid.uuid4()), checkpoint=None)
    result[FIELD] = value
    return result
