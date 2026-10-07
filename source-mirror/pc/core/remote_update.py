from __future__ import annotations

from dataclasses import dataclass, asdict, replace
from hashlib import sha256
from . import config

HISTORY_LIMIT = 32
INTERVAL_SECONDS = 300

@dataclass(frozen=True)
class UpdateState:
    baseline: str = ''
    pending: str = ''
    notified: tuple[str, ...] = ()
    detected_at: int = 0


def reduce(state: UpdateState, event: dict) -> tuple[UpdateState, bool]:
    kind = event['type']
    version = str(event.get('version') or '')
    if kind == 'reset':
        return UpdateState(), False
    if kind == 'snooze' or not version:
        return state, False
    if kind == 'acknowledge':
        consumed = str(event.get('consumed_version') or '')
        acknowledged = state.pending == version or bool(consumed and state.pending == consumed)
        return replace(state, baseline=version, pending='' if acknowledged else state.pending,
                       detected_at=0 if acknowledged else state.detected_at), False
    if kind != 'observe':
        raise ValueError(kind)
    if not state.baseline:
        return replace(state, baseline=version), False
    if version == state.baseline:
        return replace(state, pending='', detected_at=0), False
    notify = version not in state.notified
    history = (state.notified + (version,))[-HISTORY_LIMIT:] if notify else state.notified
    return replace(state, pending=version, notified=history,
                   detected_at=int(event.get('now', 0)) if state.pending != version else state.detected_at), notify


def key(vault_id: str, target: str, name: str) -> str:
    if target not in ('drive', 'webdav'):
        raise ValueError(target)
    suffix = sha256(str(vault_id).encode()).hexdigest()[:24]
    return f'cloud_remote_update_{target}_{name}_{suffix}'


def enabled(vault_id: str, target: str) -> bool:
    return bool(config.get(key(vault_id, target, 'enabled'), False))


def load(vault_id: str, target: str, association: str) -> UpdateState:
    if config.get(key(vault_id, target, 'association'), '') != association:
        return UpdateState()
    raw = config.get(key(vault_id, target, 'state'), {})
    if not isinstance(raw, dict):
        return UpdateState()
    return UpdateState(str(raw.get('baseline') or ''), str(raw.get('pending') or ''),
                       tuple(str(v) for v in raw.get('notified', []) if v)[-HISTORY_LIMIT:],
                       int(raw.get('detected_at') or 0))


def save(vault_id: str, target: str, association: str, state: UpdateState) -> None:
    config.set(key(vault_id, target, 'association'), association)
    config.set(key(vault_id, target, 'state'), asdict(state))


def set_enabled(vault_id: str, target: str, value: bool) -> None:
    config.set(key(vault_id, target, 'enabled'), bool(value))
    if not value:
        raw = config.get(key(vault_id, target, 'state'), {})
        preserved = dict(raw) if isinstance(raw, dict) else {}
        preserved.update(pending='', detected_at=0)
        config.set(key(vault_id, target, 'state'), preserved)


def association_fingerprint(target: str, connection) -> str:
    # Hash the full configuration, including auth/certificate changes. Persist no credentials.
    value = str(connection.resolve()) if target == 'drive' else repr(connection)
    return sha256(value.encode()).hexdigest()


def metadata_version(target: str, metadata) -> str:
    if not metadata.exists:
        return ''
    revision = getattr(metadata, 'revision', None)
    if target == 'webdav' and revision and not revision.startswith('W/'):
        return str(revision)
    size, modified = metadata.size, metadata.modified_at
    if size < 0 or modified <= 0:
        return ''
    return f'{target}:{size}:{modified}'
