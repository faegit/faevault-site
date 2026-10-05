"""多端双向同步（Sync v2）。

实现条目级 LWW（Last-Writer-Wins）合并、墓碑（tombstone）删除传播与单调时间戳。
权威规范见 ``vault_android/spec/SYNC_V2.md``，跨端测试向量见 ``sync_v2_fixtures.json``——
桌面端与移动端共用同一份合并语义，必须都能跑通该向量。

设计要点：

- 合并以 ``Entry`` 为单位（``id`` 匹配），不到字段级
- ``updated_at`` 大者胜；同秒且内容不同才算真冲突，交给 ``on_conflict`` 决定
- ``deleted_at != null`` 即墓碑（逻辑删除），随同步传播；本地的墓碑保存在
  ``Vault.trash`` 列表里，合并时与 ``entries`` 一起参与
- ``export_epoch`` 只作文件元数据；合并比较原始条目时间戳，本地写入保证单调递增
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Callable

from .models import Entry
from . import modules as entry_modules, passkey_merge


class ConflictChoice:
    KEEP_LOCAL = "keep_local"
    KEEP_REMOTE = "keep_remote"
    KEEP_BOTH = "keep_both"


OnConflict = Callable[[Entry, Entry], str]


def same_lineage(local_id: str | None, incoming_id: str | None) -> bool:
    """两份库是否同源（SYNC_V2 §7.5 谱系护栏）。

    仅当两端 ``deviceId`` 都非空且相等才判为同一谱系；任一为空（老 v1 文件 / 第三方
    导出，无法判断归属）或不等都返回 False，调用方据此要求用户二次确认后才合并。
    """
    return bool(local_id and incoming_id and local_id == incoming_id)


def calibrate(
    incoming: list[Entry],
    export_epoch: float | None,
    local_now: float,
) -> list[Entry]:
    """Return copies of incoming entries without changing per-entry timestamps.

    ``export_epoch`` is file metadata only. Merge decisions compare each entry's
    own ``updated_at`` so an old export is not made artificially newer.
    """
    _ = export_epoch, local_now
    return [copy.copy(e) for e in incoming]


def _effectively_equal(a: Entry, b: Entry) -> bool:
    """Same revision with the same editable content and tombstone state."""
    if (a.deleted_at is None) != (b.deleted_at is None):
        return False
    return a.content_equals(b)


def _enrich_target_app(primary: Entry, secondary: Entry) -> Entry:
    """Preserve an Android package binding when the winning revision lacks one."""
    primary_value = primary.target_app or entry_modules.target_app_value(primary.fields)
    secondary_value = secondary.target_app or entry_modules.target_app_value(secondary.fields)
    if primary_value or not secondary_value:
        return primary
    enriched = copy.copy(primary)
    enriched.target_app = secondary_value
    return enriched


def _passkey_modules(entry: Entry) -> list[dict]:
    return [
        module
        for module in entry_modules.modules_from_fields(entry.fields)
        if module.get("type") == entry_modules.PASSKEY
    ]


def _with_merged_passkeys(primary: Entry, merged_modules: list[dict]) -> Entry:
    ordinary_modules = [
        copy.deepcopy(module)
        for module in entry_modules.modules_from_fields(primary.fields)
        if module.get("type") != entry_modules.PASSKEY
    ]
    fields = copy.deepcopy(primary.fields)
    combined = ordinary_modules + copy.deepcopy(merged_modules)
    if combined:
        fields[entry_modules.MODULES_KEY] = combined
    else:
        fields.pop(entry_modules.MODULES_KEY, None)
    enriched = copy.copy(primary)
    enriched.fields = fields
    enriched.invalidate_haystack()
    return enriched


def merge_passkeys_for_entries(local: Entry, incoming: Entry) -> tuple[Entry, Entry, bool]:
    """Attach one lossless Passkey merge result to both Entry revisions."""
    local_passkeys = _passkey_modules(local)
    incoming_passkeys = _passkey_modules(incoming)
    if not local_passkeys and not incoming_passkeys:
        return local, incoming, False
    result = passkey_merge.merge_module_sets(local_passkeys, incoming_passkeys)
    return (
        _with_merged_passkeys(local, result.modules),
        _with_merged_passkeys(incoming, result.modules),
        result.has_key_conflict,
    )


def _fields_without_target_app(entry: Entry) -> dict:
    fields = copy.deepcopy(entry.fields)
    modules = [
        module for module in entry_modules.modules_from_fields(fields)
        if module.get("type") != entry_modules.TARGET_APP
    ]
    if modules:
        fields[entry_modules.MODULES_KEY] = modules
    else:
        fields.pop(entry_modules.MODULES_KEY, None)
    return fields


def _package_only_duplicate(a: Entry, b: Entry) -> bool:
    """Different IDs for the same login, where only one side has an app binding."""
    a_package = a.target_app or entry_modules.target_app_value(a.fields)
    b_package = b.target_app or entry_modules.target_app_value(b.fields)
    if a.id == b.id or a.deleted_at is not None or b.deleted_at is not None:
        return False
    if a.secret_type != "login" or b.secret_type != "login" or bool(a_package) == bool(b_package):
        return False
    return (
        a.title == b.title
        and a.username == b.username
        and a.password == b.password
        and a.url == b.url
        and a.notes == b.notes
        and set(a.tags or []) == set(b.tags or [])
        and _fields_without_target_app(a) == _fields_without_target_app(b)
    )


def merge(local: list[Entry], incoming: list[Entry], on_conflict: OnConflict | None = None) -> tuple[list[Entry], dict]:
    """按 SYNC_V2 §5 合并。``incoming`` 必须已 :func:`calibrate`。

    返回 ``(合并后的条目列表, 统计)``。同秒冲突且 ``on_conflict`` 为 None 时默认保留本地。
    """
    by_id = {e.id: e for e in local}
    stats = dict(
        added=0,
        remote_wins=0,
        local_wins=0,
        identical=0,
        kept_both=0,
        conflicts=0,
        passkey_conflicts=0,
    )

    for inc in incoming:
        cur = by_id.get(inc.id)
        if cur is None:
            by_id[inc.id] = inc
            stats["added"] += 1
            continue
        cur = _enrich_target_app(cur, inc)
        inc = _enrich_target_app(inc, cur)
        cur, inc, passkey_conflict = merge_passkeys_for_entries(cur, inc)
        stats["passkey_conflicts"] += int(passkey_conflict)
        by_id[cur.id] = cur
        if inc.updated_at > cur.updated_at:
            by_id[inc.id] = inc
            stats["remote_wins"] += 1
        elif inc.updated_at < cur.updated_at:
            stats["local_wins"] += 1
        else:
            if _effectively_equal(cur, inc):
                stats["identical"] += 1
                continue
            stats["conflicts"] += 1
            choice = on_conflict(cur, inc) if on_conflict else ConflictChoice.KEEP_LOCAL
            if choice == ConflictChoice.KEEP_REMOTE:
                by_id[inc.id] = inc
                stats["remote_wins"] += 1
            elif choice == ConflictChoice.KEEP_BOTH:
                dup = copy.copy(inc)
                dup.id = str(uuid.uuid4())
                by_id[dup.id] = dup
                stats["kept_both"] += 1
            else:  # KEEP_LOCAL（含取消/未知）
                stats["local_wins"] += 1

    return list(by_id.values()), stats


def merge_with_purges(
    local: list[Entry],
    incoming: list[Entry],
    local_purges: dict[str, float] | None = None,
    incoming_purges: dict[str, float] | None = None,
    on_conflict: OnConflict | None = None,
) -> tuple[list[Entry], dict, dict[str, float]]:
    """LWW merge plus physical-delete tombstones.

    ``purges`` maps entry id to the time it was permanently deleted. A purge
    wins over an entry only when ``purged_at > entry.updated_at``; a newer entry
    keeps the data and suppresses an older purge.
    """
    local_purges = {str(k): float(v) for k, v in (local_purges or {}).items()}
    incoming_purges = {str(k): float(v) for k, v in (incoming_purges or {}).items()}
    merged_purges = dict(local_purges)
    stats = dict(
        added=0,
        remote_wins=0,
        local_wins=0,
        identical=0,
        kept_both=0,
        conflicts=0,
        passkey_conflicts=0,
        purged=0,
        purge_skipped=0,
        coalesced=0,
    )

    for entry_id, purged_at in incoming_purges.items():
        if purged_at > merged_purges.get(entry_id, 0.0):
            merged_purges[entry_id] = purged_at

    by_id = {e.id: e for e in local}

    for entry_id, purged_at in list(merged_purges.items()):
        cur = by_id.get(entry_id)
        if cur is not None:
            if purged_at > cur.updated_at:
                by_id.pop(entry_id, None)
                stats["purged"] += 1
            else:
                merged_purges.pop(entry_id, None)
                stats["purge_skipped"] += 1

    for inc in incoming:
        purge_at = merged_purges.get(inc.id)
        if purge_at is not None and purge_at > inc.updated_at:
            stats["purge_skipped"] += 1
            continue
        if purge_at is not None:
            merged_purges.pop(inc.id, None)

        cur = by_id.get(inc.id)
        if cur is None:
            duplicate = next((entry for entry in by_id.values() if _package_only_duplicate(entry, inc)), None)
            if duplicate is not None:
                by_id[duplicate.id] = _enrich_target_app(duplicate, inc)
                purged_at = max(time.time(), duplicate.updated_at, inc.updated_at) + 0.001
                merged_purges[inc.id] = max(merged_purges.get(inc.id, 0.0), purged_at)
                stats["coalesced"] += 1
                continue
            by_id[inc.id] = inc
            stats["added"] += 1
            continue
        cur = _enrich_target_app(cur, inc)
        inc = _enrich_target_app(inc, cur)
        cur, inc, passkey_conflict = merge_passkeys_for_entries(cur, inc)
        stats["passkey_conflicts"] += int(passkey_conflict)
        by_id[cur.id] = cur
        if inc.updated_at > cur.updated_at:
            by_id[inc.id] = inc
            stats["remote_wins"] += 1
        elif inc.updated_at < cur.updated_at:
            stats["local_wins"] += 1
        else:
            if _effectively_equal(cur, inc):
                stats["identical"] += 1
                continue
            stats["conflicts"] += 1
            choice = on_conflict(cur, inc) if on_conflict else ConflictChoice.KEEP_LOCAL
            if choice == ConflictChoice.KEEP_REMOTE:
                by_id[inc.id] = inc
                stats["remote_wins"] += 1
            elif choice == ConflictChoice.KEEP_BOTH:
                dup = copy.copy(inc)
                dup.id = str(uuid.uuid4())
                by_id[dup.id] = dup
                stats["kept_both"] += 1
            else:
                stats["local_wins"] += 1

    return list(by_id.values()), stats, merged_purges
