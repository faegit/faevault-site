from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "native" / "passkey_provider"


def test_native_provider_declares_official_requirements() -> None:
    text = (PROVIDER / "README.md").read_text(encoding="utf-8")
    assert "10.0.26100.7175" in text
    assert "IPluginAuthenticator" in text
    assert "C++20" in text
    assert "Windows-classic-samples" in text


def test_prerequisite_check_is_non_mutating_and_covers_all_gates() -> None:
    text = (PROVIDER / "scripts" / "check-prerequisites.ps1").read_text(
        encoding="utf-8"
    )
    for requirement in (
        "CurrentBuild",
        "UBR",
        "vswhere.exe",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "10.0.26100.7175",
    ):
        assert requirement in text
    assert "winget install" not in text
    assert "Start-Process" not in text


def test_official_provider_baseline_has_stable_vault_identity() -> None:
    manifest = (PROVIDER / "app" / "Package.appxmanifest").read_text("utf-8")
    registration = (
        PROVIDER / "app" / "PluginManagement" / "PluginRegistrationManager.h"
    ).read_text("utf-8")
    authenticator = (
        PROVIDER / "app" / "PluginAuthenticator" / "PluginAuthenticatorImpl.h"
    ).read_text("utf-8")
    assert "FAE.Vault.PasskeyProvider" in manifest
    assert "443e631d-c94b-4d9c-b43e-daa99a0311d8" in manifest
    assert "22d9be39-8865-42e3-a143-dda6ae9796af" in registration
    assert "########" not in registration
    assert "7fa07696" not in authenticator


def test_native_provider_uses_only_fixed_non_secret_unlock_activation() -> None:
    native = (PROVIDER / "app" / "VaultBrokerClient.cpp").read_text("utf-8")
    entry = (Path(__file__).resolve().parents[1] / "__main__.py").read_text("utf-8")
    assert 'launch.lpParameters = L"--passkey-unlock"' in native
    assert '_PASSKEY_UNLOCK_ARGUMENT = "--passkey-unlock"' in entry
    for forbidden in ("masterPassword", "recoveryKey", "vaultPath"):
        assert forbidden not in native


def test_official_sdk_build_tools_are_pinned_to_supported_patch() -> None:
    project = (PROVIDER / "app" / "PasskeyManager.vcxproj").read_text("utf-8")
    packages = (PROVIDER / "app" / "packages.config").read_text("utf-8")
    assert "10.0.26100.7175" in project
    assert "10.0.26100.7175" in packages
    assert "10.0.26100.4188" not in project


def test_installer_is_windows_powershell_compatible_and_preserves_enablement() -> None:
    script = (PROVIDER / "installer" / "install.ps1").read_text("utf-8")
    parameter_block = script.split(")", 1)[0]
    assert "$PSScriptRoot" not in parameter_block
    assert "$status = Get-ProviderStatus" in script
    assert "if (-not $status)" in script
    assert script.index("$status = Get-ProviderStatus") < script.index(
        "-ArgumentList '--register'"
    )
    assert "exit 0" in script

    inno = (ROOT / "installer" / "FAEVault.iss").read_text("utf-8")
    assert "AfterInstall: InstallPasskeyProvider" in inno
    assert "ExecAsOriginalUser" in inno
    assert "if ResultCode <> 0 then" in inno
    assert "RaiseException" in inno
    assert "(not WizardSilent)" in inno
    initialize_setup = inno.split("function InitializeSetup", 1)[1]
    assert "UninstallPrevious(CurrentInnoKey)" not in initialize_setup
