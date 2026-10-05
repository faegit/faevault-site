import json
import base64
import hashlib
from pathlib import Path

from core import browser_install


def test_extension_identity_matches_manifest_key():
    manifest = json.loads((Path(__file__).parents[1] / "browser_extension" / "manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).digest()[:16]
    extension_id = "".join(chr(ord("a") + nibble) for byte in digest for nibble in (byte >> 4, byte & 15))
    assert browser_install.CHROMIUM_EXTENSION_ID == extension_id
    for size in (16, 32, 48, 128):
        assert (Path(__file__).parents[1] / "browser_extension" / "icons" / f"icon{size}.png").is_file()


def test_install_status_requires_host_manifests_and_extension(monkeypatch, tmp_path):
    monkeypatch.setattr(browser_install, "vault_dir", lambda: tmp_path)
    monkeypatch.setattr(browser_install, "_registry_default", lambda _key: None)

    state = browser_install.status()

    assert not state.installed
    assert not state.host_exists
    assert state.extension_dir == tmp_path / "browser_autofill" / "extension"


def test_copy_extension_excludes_alternate_manifest(tmp_path):
    source = Path(__file__).parents[1] / "browser_extension"
    destination = tmp_path / "extension"

    browser_install._copy_extension(source, destination)

    assert (destination / "manifest.json").is_file()
    assert not (destination / "manifest.firefox.json").exists()
