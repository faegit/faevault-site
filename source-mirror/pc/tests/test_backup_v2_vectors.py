"""跨端共享向量：新备份 v2（PMXB, Argon2id + AAD）与安卓端互解。

向量文件由两端共享：``vault_android/spec/backup_v2_fixture.json``（由桌面端生成，
固定 salt/nonce 与已知明文）。桌面端与安卓端测试都读取同一份字节，验证解密结果
一致，保证 `.pmbak` v2 格式跨端逐字节兼容。规范见 ``spec/VAULT_FORMAT.md`` §7。
"""

from __future__ import annotations

import json
import os
import pytest
from pathlib import Path

from core import pmv_backup


def _fixture_root() -> Path:
    override = os.environ.get("VAULT_SHARED_SPEC_DIR")
    root = (
        Path(override).expanduser()
        if override
        else Path(__file__).resolve().parents[2] / "vault_android" / "spec"
    )
    if not root.is_dir():
        raise AssertionError(f"required shared spec directory is missing: {root}")
    return root


def _fixture() -> dict:
    path = _fixture_root() / "backup_v2_fixture.json"
    if not path.is_file():
        raise AssertionError(f"required shared backup v2 fixture is missing: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schemaVersion"] == 1
    assert document["suite"] == "PMV_BACKUP_V2"
    [case] = document["cases"]
    return document, case


def test_shared_vector_decrypts_to_known_plaintext() -> None:
    document, case = _fixture()
    password = bytes.fromhex(document["passwordUtf8Hex"]).decode("utf-8")
    expected = bytes.fromhex(document["plaintextUtf8Hex"])
    file_bytes = bytes.fromhex(case["fileHex"])
    plaintext = pmv_backup.decrypt_v2(file_bytes, password.encode("utf-8"))
    assert plaintext == expected
    # 语义校验：明文是合法备份 payload
    payload = json.loads(plaintext.decode("utf-8"))
    assert payload["version"] == 2
    assert payload["sync_meta"]["device_id"] == "lineage-123"


def test_shared_vector_roundtrip_preserves_header() -> None:
    """用向量同款固定 salt/nonce 重新加密，AAD/布局一致时可解出相同明文。"""
    document, case = _fixture()
    password = bytes.fromhex(document["passwordUtf8Hex"]).decode("utf-8")
    expected = bytes.fromhex(document["plaintextUtf8Hex"])
    file_bytes = bytes.fromhex(case["fileHex"])
    assert file_bytes[:4] == pmv_backup.MAGIC
    assert file_bytes[4] == pmv_backup.VERSION_V2
    assert file_bytes[5] == pmv_backup.KDF_ID_ARGON2ID
    assert pmv_backup.decrypt_v2(file_bytes, password.encode("utf-8")) == expected


def test_shared_vector_rejects_wrong_password() -> None:
    document, case = _fixture()
    file_bytes = bytes.fromhex(case["fileHex"])
    with pytest.raises(pmv_backup.crypto.DecryptError):
        pmv_backup.decrypt_v2(file_bytes, "wrong-password".encode("utf-8"))


def test_shared_vector_rejects_tampered_parameter() -> None:
    """篡改头部 KDF 参数 → ValueError（结构损坏，区别于密码错误）。"""
    document, case = _fixture()
    password = bytes.fromhex(document["passwordUtf8Hex"]).decode("utf-8")
    file_bytes = bytearray(bytes.fromhex(case["fileHex"]))
    file_bytes[7] = 0x00  # MEMORY_KIB 次高字节（原 0x01）翻转 → 与实现常量不符
    with pytest.raises(ValueError):
        pmv_backup.decrypt_v2(bytes(file_bytes), password.encode("utf-8"))