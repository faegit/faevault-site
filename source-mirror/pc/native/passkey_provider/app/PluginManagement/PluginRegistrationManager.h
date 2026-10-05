#pragma once
#include "pch.h"
#include <App.xaml.h>
#include <MainWindow.xaml.h>
#include <MainPage.xaml.h>
#include <PluginAuthenticator/PluginAuthenticatorImpl.h>
#include <ProviderIdentity.h>

constexpr wchar_t c_pluginName[] = L"FAE Vault";
constexpr wchar_t c_pluginRpId[] = L"vault.local";
constexpr wchar_t c_rpName[] = L"FAE Vault";
constexpr wchar_t c_userName[] = L"VaultUser";
constexpr wchar_t c_userDisplayName[] = L"Vault User";
constexpr wchar_t c_userId[] = L"VaultUserId";
constexpr wchar_t c_dummySecretVault[] = L"RemovedDuringVaultBrokerIntegration";

/* The AAGUID is a unique identifier for the FIDO authenticator model.
*'AAGUID' maybe used to fetch information about the authenticator from the FIDO Metadata Service and other sources.
* Refer: https://fidoalliance.org/metadata/
*/
#define c_pluginAaguidString vault_plugin_aaguid_string // 22d9be39-8865-42e3-a143-dda6ae9796af
#define c_pluginAaguidBytes vault_plugin_aaguid_bytes

constexpr wchar_t c_pluginSigningKeyName[] = L"TestAppPluginIdKey";
constexpr wchar_t c_pluginRegistryPath[] = L"Software\\FAE\\Vault\\PasskeyProvider";
constexpr wchar_t c_windowsPluginRequestSigningKeyRegKeyName[] = L"RequestSigningKeyBlob";
constexpr wchar_t c_windowsPluginVaultLockedRegKeyName[] = L"VaultLocked";
constexpr wchar_t c_windowsPluginSilentOperationRegKeyName[] = L"SilentOperation";
constexpr wchar_t c_windowsPluginDBUpdateInd[] = L"PluginDBUpdate";
constexpr wchar_t c_pluginHMACSecretInput[] = L"HMACSecretInput";
constexpr wchar_t c_pluginEncryptedVaultData[] = L"EncryptedVaultData";
constexpr wchar_t c_windowsPluginVaultUnlockMethodRegKeyName[] = L"VaultUnlockMethod";

namespace winrt::PasskeyManager::implementation
{
    class PluginRegistrationManager
    {
    public:
        static PluginRegistrationManager& getInstance()
        {
            static PluginRegistrationManager instance;
            return instance;
        }

        HRESULT Initialize(); // calls GetPluginState to check if the plugin is already registered

        HRESULT RegisterPlugin();
        HRESULT UnregisterPlugin();
        HRESULT UpdatePlugin();

        HRESULT RefreshPluginState();

        bool IsPluginRegistered() const
        {
            return m_pluginRegistered;
        }

        AUTHENTICATOR_STATE GetPluginState() const
        {
            return m_pluginState;
        }

        HRESULT CreateVaultPasskey(HWND hwnd);
        HRESULT SetHMACSecret(std::vector<BYTE> hmacSecret);
        std::vector<BYTE> GetHMACSecret() const
        {
            return m_hmacSecret;
        }

        HRESULT WriteEncryptedVaultData(std::vector<BYTE> cipherText);
        HRESULT ReadEncryptedVaultData(std::vector<BYTE>& cipherText);

        void ReloadRegistryValues()
        {
            std::lock_guard<std::mutex> lock(m_pluginOperationConfigMutex);
            auto opt = wil::reg::try_get_value_binary(HKEY_CURRENT_USER, c_pluginRegistryPath, c_pluginHMACSecretInput, REG_BINARY);
            m_hmacSecret = opt.value_or(m_hmacSecret);
        }

    private:
        AUTHENTICATOR_STATE m_pluginState;
        bool m_initialized = false;
        bool m_pluginRegistered = false;

        std::mutex m_pluginOperationConfigMutex;
        _Guarded_by_(m_pluginOperationConfigMutex) std::vector<BYTE> m_hmacSecret = {};

        PluginRegistrationManager();
        ~PluginRegistrationManager();
        PluginRegistrationManager(const PluginRegistrationManager&) = delete;
        PluginRegistrationManager& operator=(const PluginRegistrationManager&) = delete;

        void UpdatePasskeyOperationStatusText(hstring const& statusText)
        {
            com_ptr<App> curApp = winrt::Microsoft::UI::Xaml::Application::Current().as<App>();
            curApp->GetDispatcherQueue().TryEnqueue([curApp, statusText]()
            {
                curApp->m_window.Content().try_as<Microsoft::UI::Xaml::Controls::Frame>().Content().try_as<MainPage>()->UpdatePasskeyOperationStatusText(statusText);
            });
        }
    };
};
