"""Keep test-owned Qt windows from leaking into later tests."""

import sys

import pytest


@pytest.fixture(autouse=True)
def _dispose_test_windows(monkeypatch):
    # Depend on monkeypatch so cleanup happens before test stubs are restored.
    # Do not initialize Qt for tests that do not use it.
    widgets = sys.modules.get("PySide6.QtWidgets")
    application = widgets.QApplication.instance() if widgets else None
    original_windows = set(application.topLevelWidgets()) if application else set()
    yield
    widgets = sys.modules.get("PySide6.QtWidgets")
    application = widgets.QApplication.instance() if widgets else None
    if application is None:
        return

    from PySide6.QtCore import QCoreApplication, QEvent, QThread

    for window in application.topLevelWidgets():
        if window in original_windows:
            continue
        controller = getattr(window, "_cloud_controller", None)
        cancel = getattr(controller, "cancel_active_operations", None)
        if callable(cancel):
            cancel()
        threads = window.findChildren(QThread)
        for thread in threads:
            if thread.isRunning():
                thread.requestInterruption()
                thread.quit()
                thread.wait(1000)
        # Qt must not destroy a thread's owner while it is still running.
        if any(thread.isRunning() for thread in threads):
            continue
        window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    application.processEvents()
