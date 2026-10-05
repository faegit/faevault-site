"""Exercise release preflight in PowerShell without publishing or packaging."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(not PWSH or os.name != "nt", reason="Windows PowerShell release scripts")


def run_script(path, cwd, *arguments, env=None):
    return subprocess.run(
        [PWSH, "-NoProfile", "-File", str(ROOT / path), *arguments],
        cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )


def test_build_from_another_directory_rejects_mismatched_tag_before_building(tmp_path):
    env = dict(os.environ, GITHUB_REF_TYPE="tag", GITHUB_REF_NAME="pc/v0.0.0-invalid")
    result = run_script("tools/build_release.ps1", tmp_path, env=env)
    assert result.returncode != 0
    assert "pc/v0.0.0-invalid" in result.stderr
    assert "不一致" in result.stderr
    assert not (tmp_path / "dist").exists()


def test_publish_from_another_directory_reads_project_version(tmp_path):
    if not shutil.which("gh"):
        pytest.skip("GitHub CLI preflight dependency")
    result = run_script("tools/publish_release.ps1", tmp_path, "-Tag", "pc/v0.0.0-invalid")
    assert result.returncode != 0
    assert "不一致" in result.stderr
    assert "FileNotFoundError" not in result.stderr


def test_provider_requires_signing_configuration_before_restore(tmp_path):
    result = run_script(
        "native/passkey_provider/scripts/build-package.ps1", tmp_path,
        env=dict(os.environ, FAE_PASSKEY_CERT_THUMBPRINT=""),
    )
    assert result.returncode != 0
    assert "FAE_PASSKEY_CERT_THUMBPRINT" in result.stderr
    assert "NuGet" not in result.stdout


def test_signing_key_generator_rejects_repository_directory_before_key_creation():
    result = run_script(
        "native/passkey_provider/scripts/new-signing-certificate.ps1", ROOT,
        "-OutputDirectory", str(ROOT / "artifacts" / "signing"),
    )
    assert result.returncode != 0
    assert "仓库之外" in result.stderr


def test_release_powershell_scripts_parse():
    script = """
    $files = @('tools/build_release.ps1', 'tools/publish_release.ps1',
      'native/passkey_provider/scripts/build-package.ps1',
      'native/passkey_provider/scripts/new-signing-certificate.ps1',
      'native/passkey_provider/installer/install.ps1',
      'native/passkey_provider/scripts/restore-packages.ps1')
    foreach ($file in $files) {
      $errors = $null
      [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PWD $file), [ref]$null, [ref]$errors) | Out-Null
      if ($errors) { throw ($errors | Out-String) }
    }
    """
    result = subprocess.run([PWSH, "-NoProfile", "-Command", script], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
