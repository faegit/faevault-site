import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from PySide6.QtCore import QObject
from PySide6.QtWidgets import QApplication
from core import remote_update, cloud_sync_prefs, cloud, crypto
from ui.cloud_sync_controller import CloudSyncController, RemoteMetadataWorker

@pytest.fixture
def controller(monkeypatch):
    app = QApplication.instance() or QApplication([])
    values = {}
    monkeypatch.setattr(remote_update.config, 'get', lambda k, d=None: values.get(k, d))
    monkeypatch.setattr(remote_update.config, 'set', lambda k, v: values.__setitem__(k, v))
    parent = QObject()
    parent._locked = False
    parent._auto_sync_workers = {}
    c = CloudSyncController(SimpleNamespace(), vault_path=Path('local.pmv'), password=crypto.SecureString('secret'), cloud_vault_id='vault', parent=parent)
    c.loaded = True
    c.drive_path = Path('remote.pmv')
    cloud_sync_prefs.set_master_enabled('vault', True)
    remote_update.set_enabled('vault', 'drive', True)
    yield c, parent, values
    from shiboken6 import isValid
    if isValid(c):
        c.cancel_active_operations()

def test_pending_persisted_dedup_and_stale_epoch_discard(controller):
    c, parent, _ = controller
    a = c._update_association('drive')
    notify = Mock()
    c.remoteUpdateFound.connect(notify)
    c._remote_observed('drive', a, 0, cloud.RemoteMetadata(True, 10, 1))
    assert not c.remote_update_state('drive').pending
    c._remote_observed('drive', a, 0, cloud.RemoteMetadata(True, 12, 2))
    c._remote_observed('drive', a, 0, cloud.RemoteMetadata(True, 12, 2))
    assert notify.call_count == 1
    assert c.remote_update_state('drive').pending == 'drive:12:2'
    parent._locked = True
    c._remote_observed('drive', a, 0, cloud.RemoteMetadata(True, 15, 3))
    assert c.remote_update_state('drive').pending == 'drive:12:2'
    parent._locked = False
    c.set_remote_detection('drive', False)
    c._remote_observed('drive', a, 0, cloud.RemoteMetadata(True, 15, 3))
    assert not c.remote_update_state('drive').pending

def test_head_only_worker_does_not_download(monkeypatch):
    connection = cloud.WebDavConfig('DAV', 'https://example.test/vault.pmv')
    request = Mock(return_value=(200, {'ETag': '"A"', 'Content-Length': '12'}, Mock()))
    client = SimpleNamespace(_request=request)
    monkeypatch.setattr(cloud, 'WebDavClient', lambda config: client)
    worker = RemoteMetadataWorker('webdav', connection)
    result = Mock()
    worker.completed.connect(result)
    worker.run()
    assert request.call_args.args == ('HEAD',)
    assert result.call_args.args[0].revision == '"A"'

def test_busy_and_lock_prevent_scheduler(controller, monkeypatch):
    c, parent, _ = controller
    start = Mock()
    monkeypatch.setattr(c, '_start', start)
    c._busy_targets.add('drive')
    c.check_remote_updates()
    assert not start.called
    c._busy_targets.clear()
    parent._locked = True
    c.check_remote_updates()
    assert not start.called

def test_five_minute_throttle_and_config_epoch(controller, monkeypatch):
    c, _, _ = controller
    starts = []
    monkeypatch.setattr(c, '_start', starts.append)
    c.check_remote_updates()
    assert len(starts) == 1
    epoch = c._remote_epochs['drive']
    c._remote_checks.clear()
    c.check_remote_updates()
    assert len(starts) == 1
    c.drive_path = Path('new-target.pmv')
    c.check_remote_updates()
    assert len(starts) == 2
    assert c._remote_epochs['drive'] > epoch
    c._remote_checks.clear()

def test_ack_preserves_newer_pending(controller):
    c, _, _ = controller
    association = c._update_association('drive')
    remote_update.save('vault', 'drive', association, remote_update.UpdateState('A', 'C', ('C',), 2000))
    c.acknowledge_remote_update('drive', 'B')
    assert c.remote_update_state('drive').pending == 'C'
    c.acknowledge_remote_update('drive', 'C')
    assert not c.remote_update_state('drive').pending

def test_eager_app_startup_without_page(controller, monkeypatch):
    from ui import app as app_ui
    from ui import cloud_sync_controller as controller_module
    c, parent, _ = controller
    remote_update.set_enabled('vault', 'drive', True)
    created = []
    class Signal:
        def connect(self, callback): pass
    class FakeController:
        def __init__(self, **kwargs):
            created.append(kwargs)
            self.vaultReplaced = Signal()
            self.localVaultReplaced = Signal()
            self.message = Signal()
            self.checks = 0
        def load_async(self): self.loaded = True
        def check_remote_updates(self): self.checks += 1
    monkeypatch.setattr(controller_module, 'CloudSyncController', FakeController)
    host = SimpleNamespace(_locked=False, _cloud_sync_enabled=lambda: True,
                           _cloud_sync_vault_id=lambda: 'vault',
                           vault=SimpleNamespace(path=Path('local.pmv'), _password=SimpleNamespace(clone=lambda: 'secret')),
                           _adopt_cloud_vault=lambda v: None, _reopen_local_vault=lambda: None,
                           _flash=lambda text: None, _connect_remote_notifications=lambda c: None)
    app_ui.MainWindow._remote_update_tick(host)
    assert len(created) == 1
    assert host._cloud_controller.checks == 1
    app_ui.MainWindow._remote_update_tick(host)
    assert len(created) == 1
    host._locked = True
    app_ui.MainWindow._remote_update_tick(host)
    assert host._cloud_controller.checks == 2


def test_page_card_sync_uses_existing_button(controller):
    from ui.cloud_sync_page import CloudSyncPage
    c, parent, _ = controller
    page = CloudSyncPage()
    invoked = Mock()
    page.drive.sync.clicked.connect(invoked)
    page.drive.update_sync.clicked.connect(page.drive.sync.click)
    page.drive.update_sync.click()
    assert invoked.call_count == 1
    assert not page.drive.detection_toggle.isChecked()
    page.deleteLater()


def test_tray_unavailable_retains_pending_card(controller, monkeypatch):
    from ui import tray
    c, parent, _ = controller
    remote_update.save('vault', 'drive', c._update_association('drive'), remote_update.UpdateState('A', 'B', ('B',), 1000))
    monkeypatch.setattr(tray, '_tray', None)
    assert not tray.show_update_notification(Mock(), 'update', 'body')
    c.snooze_remote_update('drive')
    assert c.remote_update_state('drive').pending == 'B'



def test_queued_check_after_controller_deleted_is_inert(controller):
    from PySide6.QtCore import QCoreApplication, QEvent, QTimer
    from shiboken6 import isValid
    c, parent, _ = controller
    # Reproduce page-open singleShot still queued while page/session is destroyed.
    c.cancel_active_operations()
    c.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(c)
    QTimer.singleShot(0, c.check_remote_updates)
    QApplication.instance().processEvents()
    c.check_remote_updates()


def test_parent_deletion_before_queued_check_is_inert(controller):
    from PySide6.QtCore import QCoreApplication, QEvent
    from shiboken6 import isValid
    c, parent, _ = controller
    parent.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(c)
    assert not c._closed
    c.check_remote_updates()
    c.load_async()


def test_ambiguous_notification_click_shows_overview_without_unlock():
    from ui.app import MainWindow
    opened = Mock()
    host = SimpleNamespace(isMinimized=lambda: False, show=Mock(), showNormal=Mock(),
                           raise_=Mock(), activateWindow=Mock(), _locked=True,
                           _open_cloud_sync=opened, _relock_prompt=Mock())
    MainWindow._open_remote_update_overview(host)
    host.show.assert_called_once()
    assert not opened.called
    assert not host._relock_prompt.called
    host._locked = False
    MainWindow._open_remote_update_overview(host)
    assert opened.call_count == 1


def test_explicit_overwrite_ack_consumes_captured_pending(controller, monkeypatch):
    from core.storage import VaultLineage
    c, parent, _ = controller
    c._vault = SimpleNamespace(pmve_identity=object(), classify_lineage=lambda left, right: VaultLineage.SAME)
    association = c._update_association('drive')
    remote_update.save('vault', 'drive', association, remote_update.UpdateState('A', 'B', ('B',), 1000))
    c._overwrite_update_inputs['drive'] = (association, c._remote_epochs['drive'], 'B')
    monkeypatch.setattr(cloud, 'save_cloud_drive', lambda *args, **kwargs: None)
    monkeypatch.setattr(cloud, 'save_cloud_drive_sync', lambda *args, **kwargs: None)
    monkeypatch.setattr(c, 'inspect_drive', lambda: None)
    c._overwrite_verified('drive', c.drive_path, False, cloud.RemoteMetadata(True, 20, 2), object())
    assert not c.remote_update_state('drive').pending
    remote_update.save('vault', 'drive', association, remote_update.UpdateState('A', 'D', ('D',), 3000))
    c._overwrite_update_inputs['drive'] = (association, c._remote_epochs['drive'], 'B')
    c._overwrite_verified('drive', c.drive_path, False, cloud.RemoteMetadata(True, 20, 2), object())
    assert c.remote_update_state('drive').pending == 'D'


def test_queued_mainwindow_tick_after_cpp_deletion_is_inert():
    from PySide6.QtCore import QCoreApplication, QEvent
    from ui.app import MainWindow
    host = QObject()
    host._cloud_sync_enabled = Mock(side_effect=AssertionError("dead window queried config"))
    host.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    MainWindow._remote_update_tick(host)
    host._cloud_sync_enabled.assert_not_called()
