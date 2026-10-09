"""Ordered background persistence for non-secret automatic sync preferences."""

from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QObject, QTimer, Signal, Slot
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from core import config
from core.log import get

_log = get("cloud_preferences")
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vault-cloud-preferences")


class CloudPreferenceWriter(QObject):
    failed = Signal(str)
    _worker_failed = Signal(str)
    completed = Signal(object, object)

    def __init__(self, parent=None):
        # Outlive detachable pages, including lock/close while a write runs.
        super().__init__(QApplication.instance())
        self._pending: dict[str, object] = {}
        self._pending_generations: dict[str, int] = {}
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self.flush)
        self.completed.connect(self._reconcile)
        self._worker_failed.connect(self._report_error)
        QApplication.instance().aboutToQuit.connect(self.flush)

    def stage(self, values: dict[str, object]) -> None:
        # Cache staging is on the UI thread; workers never touch that cache.
        self._pending_generations.update(config.stage_cloud_auto_many(values))
        self._pending.update(values)
        self._timer.start()

    def flush(self) -> None:
        self._timer.stop()
        if not self._pending:
            return
        values, self._pending = self._pending, {}
        generations, self._pending_generations = self._pending_generations, {}
        future = _executor.submit(config.persist_cloud_auto_many, values, generations=generations)
        future.add_done_callback(lambda result: self._finished(result, values, generations))

    @Slot(object, object)
    def _reconcile(self, values, generations) -> None:
        config.reconcile_cloud_auto_many(values, generations)

    @Slot(str)
    def _report_error(self, error) -> None:
        self.failed.emit(error)

    def _finished(self, future, values, generations) -> None:
        error = future.exception()
        if error is not None:
            _log.error("自动同步设置保存失败：%s", error)
        if not isValid(self):
            return
        try:
            if error is not None:
                self._worker_failed.emit(str(error))
            else:
                self.completed.emit(values, generations)
        except RuntimeError:
            # The application may destroy its QObject during shutdown; the
            # executor still completes the encrypted disk write independently.
            return


def cloud_preference_writer() -> CloudPreferenceWriter:
    application = QApplication.instance()
    writer = getattr(application, "_cloud_preference_writer", None)
    if writer is None or not isValid(writer):
        writer = CloudPreferenceWriter()
        application._cloud_preference_writer = writer
    return writer


class SettingsPreferenceWriter(QObject):
    """Application-owned ordered writer for captured-account safe preferences."""

    failed = Signal(object, str)
    _worker_failed = Signal(object, str)
    completed = Signal(object, object, object)

    def __init__(self):
        super().__init__(QApplication.instance())
        self.completed.connect(self._reconcile)
        self._worker_failed.connect(self._report_error)

    def submit(self, account, values, generations=None):
        snapshot = dict(values)
        tokens = dict(generations if generations is not None else config.settings_generations_snapshot(account, values))
        future = _executor.submit(config.persist_settings_many, account, snapshot, generations=tokens)
        future.add_done_callback(lambda result: self._finished(result, account, snapshot, tokens))

    @Slot(object, object, object)
    def _reconcile(self, account, values, generations):
        config.reconcile_settings_many(account, values, generations)

    @Slot(object, str)
    def _report_error(self, account, error):
        self.failed.emit(account, error)

    def _finished(self, future, account, values, generations):
        error = future.exception()
        if error is not None:
            _log.error("账户设置保存失败：%s", error)
        if not isValid(self):
            return
        try:
            if error is None:
                self.completed.emit(account, values, generations)
            else:
                self._worker_failed.emit(account, str(error))
        except RuntimeError:
            return


def settings_preference_writer() -> SettingsPreferenceWriter:
    application = QApplication.instance()
    writer = getattr(application, "_settings_preference_writer", None)
    if writer is None or not isValid(writer):
        writer = SettingsPreferenceWriter()
        application._settings_preference_writer = writer
    return writer
