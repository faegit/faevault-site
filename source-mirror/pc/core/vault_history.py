"""Private immutable encrypted PMVE snapshots and selective, guarded restore."""
import copy
import hashlib
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from .pmv_vault_store import PmvVaultStore
from .models import monotonic_timestamp

def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

def _history_root():
    from .storage import vault_dir
    return vault_dir() / 'history'

class HistoricalPasswordRequired(ValueError):
    """Snapshot authentication needs its original password."""

@dataclass
class HistoryPreview:
    snapshot_id: str
    sha256: str
    current_head: bytes
    vault_id: uuid.UUID
    entries: list
    source: PmvVaultStore
    def close(self):
        self.entries.clear()
        self.source.close()

class HistoryStore:
    def __init__(self, vault, root=None):
        from .storage import vault_dir
        self.vault = vault
        self.vault_id = vault._pmve_store.identity.vault_id
        self.root = Path(root) if root is not None else _history_root()
        self.directory = self.root / str(self.vault_id)
        for p in (*self.root.absolute().parents, self.root, self.directory):
            if p.is_symlink() or (p.exists() and getattr(p.stat(), 'st_file_attributes', 0) & 0x400):
                raise ValueError('历史目录不能为链接')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory = self.directory.resolve()
        self.index_key = 'vault_history_v1_' + hashlib.sha256(str(self.directory).encode('utf-8')).hexdigest()
    def _path(self, filename):
        if Path(filename).name != filename:
            raise ValueError('无效历史路径')
        path = self.directory / filename
        if path.is_symlink() or (path.exists() and getattr(path.stat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('历史文件不能为链接')
        if path.resolve().parent != self.directory:
            raise ValueError('历史路径越界')
        return path
    def list(self):
        from . import config
        values = copy.deepcopy(config.get(self.index_key, []))
        if not isinstance(values, list):
            raise ValueError('历史索引格式无效')
        for item in values:
            uuid.UUID(item['snapshot_id'])
            self._path(item['snapshot_id'] + '.pmv')
        return sorted(values, key=lambda v: v['created_at'], reverse=True)
    def _write_index(self, records):
        from . import config
        config.set(self.index_key, copy.deepcopy(records))
    def capture(self, reason='manual', protected=False):
        from .storage import _vault_write_lock
        with _vault_write_lock(self.vault.path):
            return self._capture(reason, protected)
    def _capture(self, reason, protected):
        from .pmv_append import _process_lock, _exclusive_os_lock
        with _process_lock(self.vault.path), _exclusive_os_lock(self.vault.path):
            return self._capture_locked(reason, protected)

    def _capture_locked(self, reason, protected):
        import shutil
        records = self.list()
        snapshot_id = str(uuid.uuid4())
        target = self._path(snapshot_id + '.pmv')
        with self.vault.path.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
        try:
            source = self._open(target)
            try:
                if source.identity.vault_id != self.vault_id:
                    raise ValueError('保险库标识不匹配')
                source.list()
                sequence = source.identity.sequence
                from .device_activity import verified_last_writer
                writer = verified_last_writer(source)
                commit_id = str(source.identity.commit_id)
                signer = source.identity.signing_public_key.hex()
            finally:
                source.close()
            digest = _sha256(target)
            same = next((r for r in records if (r.get('commit_id') == commit_id and r.get('signer') == signer) or r['sha256'] == digest), None)
            if same is not None:
                if _sha256(self._path(same['snapshot_id'] + '.pmv')) != same['sha256']:
                    raise ValueError('历史快照完整性验证失败')
                target.unlink()
                if protected and not same['protected']:
                    same.update(protected=True, reason='pre-restore')
                    self._write_index(records)
                return same
            record = dict(snapshot_id=snapshot_id, sha256=digest, sequence=sequence,
                          writer_name=writer.get('name', '') if writer else '', commit_id=commit_id, signer=signer, created_at=int(time.time()*1000), reason=str(reason)[:64], protected=bool(protected), size_bytes=target.stat().st_size)
            records.insert(0, record)
            unprotected = [r for r in records if not r['protected']]
            expired = unprotected[20:]
            retained = [r for r in records if r not in expired]
            self._write_index(retained)
            for r in expired:
                self._path(r['snapshot_id'] + '.pmv').unlink(missing_ok=True)
            return record
        except Exception:
            target.unlink(missing_ok=True)
            raise
    def _open(self, path, password=None):
        if password is not None:
            secret = bytearray(password.encode('utf-8') if isinstance(password, str) else password)
            try:
                return PmvVaultStore.open_password(path, bytes(secret))
            finally:
                secret[:] = bytes(len(secret))
        secret = bytearray(self.vault.root_key_for_device_unlock())
        try:
            return PmvVaultStore.open_root_key(path, bytes(secret))
        finally:
            secret[:] = bytes(len(secret))
    def preview(self, snapshot_id, password=None):
        record = next((r for r in self.list() if r['snapshot_id'] == str(snapshot_id)), None)
        if record is None:
            raise ValueError('历史快照不存在')
        path = self._path(record['snapshot_id'] + '.pmv')
        if _sha256(path) != record['sha256']:
            raise ValueError('历史快照完整性验证失败')
        try:
            source = self._open(path, password)
        except Exception as error:
            if password is None:
                raise HistoricalPasswordRequired("此快照需要创建时的主密码") from error
            raise
        try:
            if source.identity.vault_id != self.vault_id:
                raise ValueError('历史快照属于其他保险库')
            entries = [source.read_entry(s.entry_id) for s in source.list()]
            entries = [e for e in entries if e is not None and e.deleted_at is None]
            return HistoryPreview(record['snapshot_id'], record['sha256'], self.vault._pmve_store.identity.root_digest,
                                  self.vault_id, entries, source)
        except Exception:
            source.close()
            raise
    def restore(self, preview, entry_ids, *, is_cancelled=lambda: False):
        from .storage import _vault_write_lock, ExternalVaultChange
        from .device_activity import stamp, current_device_id
        selected = set(map(str, entry_ids))
        if not selected:
            raise ValueError('请选择恢复条目')
        historical = {e.id: e for e in preview.entries}
        if not selected.issubset(historical):
            raise ValueError('只能恢复预览中的有效条目')
        from . import modules
        from .models import SecretType
        for key in selected:
            entry = historical[key]
            if entry.secret_type == SecretType.PASSKEY or any(isinstance(m, dict) and m.get('type') == modules.PASSKEY for m in entry.fields.get('modules', [])):
                raise ValueError('通行密钥条目暂不支持历史恢复')
        with _vault_write_lock(self.vault.path):
            store = self.vault._pmve_store
            if preview.vault_id != self.vault_id or store.identity.root_digest != preview.current_head:
                raise ExternalVaultChange('保险库已变化，请重新预览')
            current = self._open(self.vault.path)
            try:
                if current.identity.root_digest != preview.current_head:
                    raise ExternalVaultChange('保险库已变化，请重新预览')
            finally:
                current.close()
            path = self._path(preview.snapshot_id + '.pmv')
            if preview.source.path.resolve() != path.resolve():
                raise ValueError('历史预览来源不匹配')
            if _sha256(path) != preview.sha256:
                raise ValueError('历史快照已被修改')
            if is_cancelled():
                raise RuntimeError('历史恢复已取消')
            self._capture('pre-restore', True)
            metadata = copy.deepcopy(self.vault._pmve_metadata)
            entries = {str(s.entry_id): store.read_entry(s.entry_id) for s in store.list()}
            purges = metadata.get('purge_tombstones', {})
            if selected.intersection(purges):
                raise ValueError('已永久删除的条目不能从历史恢复')
            for key in selected:
                authenticated = preview.source.read_entry(uuid.UUID(key))
                if authenticated is None or authenticated.to_dict() != historical[key].to_dict():
                    raise ValueError('历史预览内容已变化，请重新预览')
                value = copy.deepcopy(authenticated)
                old = entries.get(key)
                value.updated_at = monotonic_timestamp(max(value.updated_at, old.updated_at if old else 0,
                                                          float(purges.get(key, 0))))
                value.deleted_at = None
                entries[key] = value
            active = [e.id for e in entries.values() if e.deleted_at is None]
            trash = [e.id for e in entries.values() if e.deleted_at is not None]
            metadata['entry_order'], metadata['trash_order'] = active, trash
            metadata = stamp(metadata, current_device_id(self.vault))
            if metadata['_device_activity_v1'].get('version', 1) == 1:
                metadata['_device_activity_v1']['last_writer']['parent_commit_id'] = str(store.identity.commit_id)
            if is_cancelled():
                raise RuntimeError('历史恢复已取消')
            identity = store.save_merged(preview.source, expected_sequence=self.vault._pmve_sequence, metadata=metadata, entries=entries.values())
            fresh = self.vault.reopen()
            self.vault.__dict__.update(fresh.__dict__)
            # Optional housekeeping must not misreport an already committed restore as failure.
            try:
                records = self.list()
                safety = [r for r in records if r['protected']]
                expired = [r for r in safety[2:] if r['snapshot_id'] != preview.snapshot_id]
                self._write_index([r for r in records if r not in expired])
                for r in expired:
                    self._path(r['snapshot_id'] + '.pmv').unlink(missing_ok=True)
            except Exception as error:
                import logging
                logging.getLogger(__name__).warning('History cleanup failed: %s', type(error).__name__)
            return len(selected)
