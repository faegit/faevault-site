import json
import os
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _frame(message: dict) -> bytes:
    payload = json.dumps(message, separators=(",", ":")).encode()
    return struct.pack("<I", len(payload)) + payload


def _decode(value: bytes) -> dict:
    length = struct.unpack("<I", value[:4])[0]
    return json.loads(value[4 : 4 + length])


def test_native_host_status_protocol_works_without_qt_unlock():
    env = os.environ.copy()
    env["VAULT_AUTOFILL_ALLOW_TEST_CALLER"] = "1"
    process = subprocess.run(
        [sys.executable, str(ROOT / "browser_host.py")],
        input=_frame({"version": 1, "requestId": "status-1", "action": "status"}),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=ROOT,
        timeout=15,
        check=True,
    )

    response = _decode(process.stdout)
    assert response["result"].pop("uiLocale") in {"zh-Hans", "en"}
    assert response == {
        "version": 1,
        "requestId": "status-1",
        "ok": True,
        "result": {"locked": True},
    }


def test_native_host_rejects_unknown_caller_before_reading_requests():
    env = os.environ.copy()
    env.pop("VAULT_AUTOFILL_ALLOW_TEST_CALLER", None)
    process = subprocess.run(
        [sys.executable, str(ROOT / "browser_host.py"), "chrome-extension://unknown/"],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=ROOT,
        timeout=15,
    )

    assert process.returncode == 2
    assert process.stdout == b""
