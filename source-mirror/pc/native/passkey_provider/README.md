# Vault Windows Passkey Provider

This directory contains the native Windows component that integrates Vault with
the Microsoft WebAuthn Plugin API. WebAuthn request handling, key generation,
and signing are implemented in C++20; they are not delegated to Python.

The implementation follows Microsoft's `Windows-classic-samples` PasskeyManager
sample and implements `IPluginAuthenticator` with C++/WinRT and WinUI 3. The
sample is a structural reference only: its Contoso identity, in-memory store,
and test toggles must not enter the production provider.

The imported baseline is Microsoft commit
`d59e5f1dc9c768615e4e1ab1f0f009e6a3ed747c`; its MIT license is preserved in
`MICROSOFT_SAMPLE_LICENSE.txt`.

Official references:

- https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager
- https://learn.microsoft.com/windows/apps/develop/security/third-party

## Required platform

- Windows 11 24H2 build 26100.6725 or newer, or Windows 11 25H2 build
  26200.6725 or newer.
- Windows SDK 10.0.26100.7175 or newer.
- Visual Studio 2022 with Desktop development with C++ and the Windows App SDK.

Run the read-only prerequisite check before building:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/check-prerequisites.ps1
```

An unsupported machine must not register the provider. Vault will keep its
existing encrypted Passkey storage and sync behavior, but the Windows system
integration remains disabled.

## Build and install

The production package uses `Package.Host.appxmanifest` and the C++ host build
mode `ProviderHostOnly=true`. `installer/install.ps1` installs the signed MSIX,
registers the authenticator through `WebAuthNPluginAddAuthenticator`, and reads
back the Windows state. `installer/uninstall.ps1` unregisters and removes the
package while preserving all Vault data.

The imported WinUI 3 application remains the official UI project baseline. The
packaged host keeps COM activation independent from XAML build workloads while
implementing the same official `IPluginAuthenticator` interface with the same
C++ provider sources.
