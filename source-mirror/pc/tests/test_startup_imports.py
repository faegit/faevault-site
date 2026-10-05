"""Regression tests for the cold-start import boundary."""

from __future__ import annotations

import importlib.util
import sys
import subprocess
import time
from pathlib import Path

from PySide6.QtWidgets import QApplication


def test_entry_module_does_not_eagerly_import_main_window() -> None:
    """The full vault UI must stay out of the pre-unlock startup path."""

    entry_path = Path(__file__).resolve().parents[1] / "__main__.py"
    probe = """
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('faevault_entry', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert 'ui.app' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", probe, str(entry_path)],
        cwd=entry_path.parent, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_unlock_dialog_defers_windows_hello_probe(monkeypatch) -> None:
    """A slow Windows service must not delay construction of the unlock UI."""

    from ui import dialogs

    app = QApplication.instance() or QApplication([])
    calls: list[bool] = []
    scheduled: list[tuple[int, object]] = []
    monkeypatch.setattr(dialogs.biometric, "available", lambda: calls.append(True) or False)
    monkeypatch.setattr(dialogs.config, "list_users", lambda: [])
    monkeypatch.setattr(dialogs.config, "get_current_user", lambda: None)
    monkeypatch.setattr(dialogs.config, "get_lockout", lambda _key: (0, True))
    monkeypatch.setattr(
        dialogs.QTimer,
        "singleShot",
        lambda delay, *args: scheduled.append((delay, args[-1])),
    )

    dialog = dialogs.UnlockDialog()
    assert calls == []
    assert any(delay == 250 for delay, _callback in scheduled)

    dialog._load_hello_availability()
    from PySide6.QtTest import QTest
    deadline = time.monotonic() + 2
    while not calls and time.monotonic() < deadline:
        QTest.qWait(10)
    assert calls == [True]
    dialog.close()
    assert app is not None
