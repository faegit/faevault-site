#include "pch.h"
#include "DelayLoad.h"
#include "ProviderIdentity.h"
#include "PluginAuthenticator/PluginAuthenticatorImpl.h"
#include "VaultBrokerClient.h"

#include <algorithm>
#include <array>
#include <iostream>
#include <string_view>

namespace
{
    constexpr wchar_t kRegistryPath[] = L"Software\\FAE\\Vault\\PasskeyProvider";
    constexpr wchar_t kSigningKeyName[] = L"RequestSigningKeyBlob";
    constexpr wchar_t kPluginName[] = L"FAE Vault";
    constexpr wchar_t kPluginRpId[] = L"vault.local";
    constexpr wchar_t kLogo[] =
        L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9JzAgMCA2NCA2NCc+"
        L"PHBhdGggZmlsbD0nIzE2OTZlMScgZD0nTTMyIDRhMTYgMTYgMCAwIDAtMTAgMjguNXYxOS41YTQgNCAwIDAg"
        L"MCA0IDRoMTJhNCA0IDAgMCAwIDQtNHYtMTkuNUEyOCAyOCAwIDAgMCAzMiA0em0wIDhhOCA4IDAgMSAxIDAg"
        L"MTYgOCA4IDAgMCAxIDAtMTZ6Jy8+PC9zdmc+";

    std::vector<BYTE> AuthenticatorInfo()
    {
        // CTAP 2.1 getInfo: versions, AAGUID, rk/up/uv, internal transport, ES256.
        static constexpr std::array<BYTE, 88> prefixAndSuffix{
            0xA5,0x01,0x82,0x68,0x46,0x49,0x44,0x4F,0x5F,0x32,0x5F,0x30,0x68,0x46,0x49,0x44,
            0x4F,0x5F,0x32,0x5F,0x31,0x03,0x50,
            0x22,0xd9,0xbe,0x39,0x88,0x65,0x42,0xe3,0xa1,0x43,0xdd,0xa6,0xae,0x97,0x96,0xaf,
            0x04,0xA3,0x62,0x72,0x6B,0xF5,0x62,0x75,0x70,0xF5,0x62,0x75,0x76,0xF5,
            0x09,0x81,0x68,0x69,0x6E,0x74,0x65,0x72,0x6E,0x61,0x6C,
            0x0A,0x81,0xA2,0x63,0x61,0x6C,0x67,0x26,0x64,0x74,0x79,0x70,0x65,0x6A,0x70,0x75,
            0x62,0x6C,0x69,0x63,0x2D,0x6B,0x65,0x79
        };
        return {prefixAndSuffix.begin(), prefixAndSuffix.end()};
    }

    HRESULT RegisterProvider()
    {
        AUTHENTICATOR_STATE existingState{};
        if (SUCCEEDED(WebAuthNPluginGetAuthenticatorState(vault_plugin_guid, &existingState))) return S_OK;
        auto info = AuthenticatorInfo();
        WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS options{
            .pwszAuthenticatorName = kPluginName,
            .rclsid = vault_plugin_guid,
            .pwszPluginRpId = kPluginRpId,
            .pwszLightThemeLogoSvg = kLogo,
            .pwszDarkThemeLogoSvg = kLogo,
            .cbAuthenticatorInfo = static_cast<DWORD>(info.size()),
            .pbAuthenticatorInfo = info.data(),
            .cSupportedRpIds = 0,
            .ppwszSupportedRpIds = nullptr
        };
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE response = nullptr;
        RETURN_IF_FAILED(WebAuthNPluginAddAuthenticator(&options, &response));
        auto cleanup = wil::scope_exit([&] { WebAuthNPluginFreeAddAuthenticatorResponse(response); });
        wil::unique_hkey key;
        RETURN_IF_WIN32_ERROR(RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr));
        RETURN_IF_WIN32_ERROR(RegSetValueExW(key.get(), kSigningKeyName, 0, REG_BINARY,
            response->pbOpSignPubKey, response->cbOpSignPubKey));
        return S_OK;
    }

    HRESULT ReconcileCredentials()
    {
        auto credentials = fae::vault::passkeys::VaultBrokerClient().List(L"");
        std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> details(credentials.size());
        for (size_t index = 0; index < credentials.size(); ++index)
        {
            auto const& source = credentials[index];
            details[index] = {
                .cbCredentialId = static_cast<DWORD>(source.credentialId.size()),
                .pbCredentialId = source.credentialId.data(),
                .pwszRpId = source.rpId.c_str(),
                .pwszRpName = source.rpId.c_str(),
                .cbUserId = static_cast<DWORD>(source.userId.size()),
                .pbUserId = source.userId.data(),
                .pwszUserName = source.userName.c_str(),
                .pwszUserDisplayName = source.userDisplayName.c_str()
            };
        }
        RETURN_IF_FAILED(WebAuthNPluginAuthenticatorRemoveAllCredentials(vault_plugin_guid));
        if (!details.empty())
            RETURN_IF_FAILED(WebAuthNPluginAuthenticatorAddCredentials(
                vault_plugin_guid, static_cast<DWORD>(details.size()), details.data()));
        return S_OK;
    }

    int PrintResult(std::wstring_view action, HRESULT hr)
    {
        if (SUCCEEDED(hr)) { std::wcout << action << L": success\n"; return 0; }
        std::wcerr << action << L": failed (0x" << std::hex << static_cast<unsigned long>(hr) << L")\n";
        return 1;
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR commandLine, int)
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    std::wstring_view args{commandLine ? commandLine : L""};
    if (args.find(L"--register") != std::wstring_view::npos) return PrintResult(L"register", RegisterProvider());
    if (args.find(L"--unregister") != std::wstring_view::npos) return PrintResult(L"unregister", WebAuthNPluginRemoveAuthenticator(vault_plugin_guid));
    if (args.find(L"--reconcile") != std::wstring_view::npos)
    {
        try { return PrintResult(L"reconcile", ReconcileCredentials()); }
        catch (...) { return PrintResult(L"reconcile", wil::ResultFromCaughtException()); }
    }
    if (args.find(L"--status") != std::wstring_view::npos)
    {
        AUTHENTICATOR_STATE state{};
        HRESULT hr = WebAuthNPluginGetAuthenticatorState(vault_plugin_guid, &state);
        if (SUCCEEDED(hr)) std::wcout << L"registered, state=" << static_cast<unsigned>(state) << L"\n";
        // Exit 10 + AUTHENTICATOR_STATE so non-console installers can read the exact system state.
        return SUCCEEDED(hr) ? 10 + static_cast<int>(state) : PrintResult(L"status", hr);
    }

    auto completed = wil::shared_event(wil::EventOptions::ManualReset);
    auto ready = wil::shared_event(wil::EventOptions::ManualReset);
    auto cancelled = wil::shared_event(wil::EventOptions::ManualReset);
    DWORD registration = 0;
    auto factory = winrt::make<winrt::PasskeyManager::implementation::ContosoPluginFactory>(completed, ready, cancelled);
    HRESULT hr = CoRegisterClassObject(vault_plugin_guid, factory.get(), CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED, &registration);
    if (FAILED(hr)) return PrintResult(L"activate", hr);
    hr = CoResumeClassObjects();
    if (FAILED(hr)) { CoRevokeClassObject(registration); return PrintResult(L"activate", hr); }
    WaitForSingleObject(completed.get(), INFINITE);
    CoRevokeClassObject(registration);
    return 0;
}
