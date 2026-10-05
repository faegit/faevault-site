"""Cross-platform, per-item LWW exclusions stored in authenticated PMVE metadata."""
from __future__ import annotations

import time
from collections.abc import Mapping

FIELD = "autofill_exclusions"
CATEGORIES = ("packages", "hosts", "processes")
MAX_TIMESTAMP = (1 << 63) - 1


def normalize_value(category: str, value: object) -> str:
    if not isinstance(value, str):
        return ""
    if category == "hosts":
        from .browser_autofill import normalize_excluded_host
        return normalize_excluded_host(value)
    if category == "processes":
        from .native_autofill import normalize_process_name
        return normalize_process_name(value)
    if category == "packages":
        return value.strip().lower()
    return ""


def normalize(raw: object) -> dict:
    raw = raw if isinstance(raw, Mapping) else {}
    states = {}
    for category in CATEGORIES:
        values = raw.get(category, [])
        for value in values if isinstance(values, (list, tuple, set)) else ():
            if value := normalize_value(category, value):
                states[f"{category}:{value}"] = {"updated_at": 0, "deleted": False}
    raw_states = raw.get("states", {})
    for key, state in raw_states.items() if isinstance(raw_states, Mapping) else ():
        if not isinstance(key, str) or not isinstance(state, Mapping):
            continue
        category, separator, value = key.partition(":")
        if not separator or category not in CATEGORIES:
            continue
        value = normalize_value(category, value)
        timestamp, deleted = state.get("updated_at"), state.get("deleted")
        if not value or type(timestamp) is not int or not 0 <= timestamp <= MAX_TIMESTAMP or type(deleted) is not bool:
            continue
        key = f"{category}:{value}"
        candidate = {"updated_at": timestamp, "deleted": deleted}
        old = states.get(key)
        if old is None or (timestamp, deleted) >= (old["updated_at"], old["deleted"]):
            states[key] = candidate
    result = {category: [] for category in CATEGORIES}
    for key in sorted(states):
        if not states[key]["deleted"]:
            category, value = key.split(":", 1)
            result[category].append(value)
    result["states"] = dict(sorted(states.items()))
    return result


def merge(local: object, remote: object) -> dict:
    left, right = normalize(local), normalize(remote)
    states = dict(left["states"])
    for key, state in right["states"].items():
        old = states.get(key)
        if old is None or (state["updated_at"], state["deleted"]) > (old["updated_at"], old["deleted"]):
            states[key] = state
    return normalize({"states": states})


def update(raw: object, category: str, values: list[str], *, now: int | None = None) -> dict:
    if category not in CATEGORIES:
        raise ValueError("Unknown autofill exclusion category")
    result = normalize(raw)
    requested = {normalized for value in values if (normalized := normalize_value(category, value))}
    previous = set(result[category])
    changed = previous ^ requested
    if not changed:
        return result
    timestamp = max(int(time.time() * 1000) if now is None else now,
                    max((state["updated_at"] for state in result["states"].values()), default=0) + 1)
    if timestamp > MAX_TIMESTAMP:
        raise ValueError("Autofill exclusion timestamp exhausted")
    for value in changed:
        result["states"][f"{category}:{value}"] = {"updated_at": timestamp, "deleted": value not in requested}
    return normalize({"states": result["states"]})


def sync_local_config(vault, *, migrate: bool = False) -> None:
    """Restore the active account cache; migrate legacy lists once for this vault."""
    from . import config
    if not hasattr(vault, "autofill_exclusions"):
        return
    marker = "autofill_exclusions_migrated_vault_id"
    vault_id = str(vault.vault_identity.vault_id)
    if migrate and config.get(marker) != vault_id:
        legacy = {
            "hosts": config.get("browser_autofill_excluded_hosts", []) or [],
            "processes": config.get("native_autofill_excluded", []) or [],
        }
        merged = merge(vault.autofill_exclusions, legacy)
        if merged != vault.autofill_exclusions:
            vault.replace_autofill_exclusions(merged)
        config.set(marker, vault_id)
    current = vault.autofill_exclusions
    for key, category in (("browser_autofill_excluded_hosts", "hosts"), ("native_autofill_excluded", "processes")):
        if config.get(key, []) != current[category]:
            config.set(key, current[category])
