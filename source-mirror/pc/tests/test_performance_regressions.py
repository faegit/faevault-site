"""Guards for import-time performance regressions."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_main_window_import_defers_lan_sync_server() -> None:
    probe = "import sys; import ui.app; raise SystemExit('core.sync_server' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
