from pathlib import Path
from types import SimpleNamespace

from core import cloud_sync_prefs
from ui import app as app_ui


class _Signal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback):
        self.callbacks.append(callback)


class _Worker:
    created = []

    def __init__(self, vault_path, password, target, payload, parent):
        self.vault_path = vault_path
        self.target = target
        self.payload = payload
        self.completed = _Signal()
        self.failed = _Signal()
        self.finished = _Signal()
        self.started = False
        self.__class__.created.append(self)

    def start(self):
        self.started = True

    def deleteLater(self):
        pass


def test_auto_sync_tick_serializes_due_targets_that_share_the_local_vault(monkeypatch):
    vid = "vault-id"
    values = {
        cloud_sync_prefs.key(vid, "target"): "drive",
        cloud_sync_prefs.key(vid, "drive_enabled"): True,
        cloud_sync_prefs.key(vid, "drive_interval"): 15,
        cloud_sync_prefs.key(vid, "drive_enabled_at"): 0.0,
        cloud_sync_prefs.key(vid, "drive_last_success"): 0.0,
    }
    writes = {}
    monkeypatch.setattr(app_ui.config, "get", lambda key, default=None: values.get(key, default))
    monkeypatch.setattr(app_ui.config, "set", lambda key, value: writes.__setitem__(key, value))
    monkeypatch.setattr(app_ui.cloud, "load_cloud_drive", lambda _vault_id: Path("drive.pmv"))
    monkeypatch.setattr(
        app_ui.cloud,
        "load_webdav",
        lambda _vault_id: SimpleNamespace(label="DAV"),
    )
    monkeypatch.setattr(app_ui, "_AutoCloudSyncWorker", _Worker)
    _Worker.created.clear()

    host = SimpleNamespace(
        _locked=False,
        _auto_sync_workers={},
        _set_auto_lock_blocker=lambda _name, _active: None,
        _cloud_sync_enabled=lambda: True,
        _cloud_threads_running=lambda: False,
        _cloud_sync_vault_id=lambda: vid,
        _auto_sync_target_pref_key=lambda name, target=None: cloud_sync_prefs.key(vid, f"{target}_{name}"),
        vault=SimpleNamespace(
            device_id="vault-id",
            path=Path("vault.pmv"),
            _password=SimpleNamespace(clone=lambda: "secret:master"),
        ),
    )

    app_ui.MainWindow._auto_sync_tick(host)

    assert [worker.target for worker in _Worker.created if worker.started] == ["drive"]
    assert set(host._auto_sync_workers) == {"drive"}
    assert writes[cloud_sync_prefs.key(vid, "drive_status")] == "正在自动同步"
    assert cloud_sync_prefs.key(vid, "webdav_status") not in writes
