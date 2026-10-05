import importlib.util
from pathlib import Path


spec = importlib.util.spec_from_file_location("vault_pc_main", Path(__file__).resolve().parents[1] / "__main__.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
_passkey_unlock_requested = module._passkey_unlock_requested


def test_passkey_unlock_activation_accepts_only_exact_fixed_argument():
    assert _passkey_unlock_requested(["--passkey-unlock"])
    assert not _passkey_unlock_requested([])
    assert not _passkey_unlock_requested(["--passkey-unlock", "C:/vault.pmv"])
    assert not _passkey_unlock_requested(["--password", "secret"])
