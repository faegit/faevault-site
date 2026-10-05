#pragma once
#include <pch.h>
#include <ProviderIdentity.h>
#include <pluginauthenticator.h>
#if !defined(PROVIDER_HOST_ONLY)
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#endif
#include <vector>
#include <atomic>
#include <mutex>

static constexpr wchar_t contosoplugin_key_domain[] = L"contoso/";

namespace winrt::PasskeyManager::implementation
{
    enum class PluginOperationType
    {
        MakeCredential = 0,
        GetAssertion = 1
    };

    struct ContosoPlugin : winrt::implements<ContosoPlugin, IPluginAuthenticator>
    {
        HRESULT __stdcall MakeCredential(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall GetAssertion(__RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest, __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept;
        HRESULT __stdcall CancelOperation(__RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest);
        HRESULT __stdcall GetLockStatus(__RPC__out PLUGIN_LOCK_STATUS* lockStatus) noexcept;

        HRESULT PerformUserVerification(
            HWND hWnd,
            GUID transactionId,
            PluginOperationType operationType,
            const std::vector<BYTE>& requestBuffer,
            wil::shared_cotaskmem_string rpName,
            wil::shared_cotaskmem_string userName);

        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        std::atomic_bool m_operationInProgress{ false };
        std::mutex m_transactionMutex;
        GUID m_transactionId{};
        ContosoPlugin() = delete;
        // Contructor that takes in the event that set hPluginOpCompletedEvent
        ContosoPlugin(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };

    struct ContosoPluginFactory : implements<ContosoPluginFactory, IClassFactory>
    {
        HRESULT __stdcall CreateInstance(::IUnknown* outer, GUID const& iid, void** result) noexcept;
        HRESULT __stdcall LockServer(BOOL) noexcept;
        wil::shared_event m_hPluginOpCompletedEvent;
        wil::shared_event m_hAppReadyForPluginOpEvent;
        wil::shared_event m_hPluginCancelOperationEvent;
        ContosoPluginFactory() = delete;
        ContosoPluginFactory(wil::shared_event hPluginOpCompletedEvent,
            wil::shared_event hAppReadyForPluginOpEvent,
            wil::shared_event hPluginUserCancelEvent) :
            m_hPluginOpCompletedEvent(hPluginOpCompletedEvent),
            m_hAppReadyForPluginOpEvent(hAppReadyForPluginOpEvent),
            m_hPluginCancelOperationEvent(hPluginUserCancelEvent)
        {
        }
    };
}
