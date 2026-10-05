#pragma once

#include <chrono>
#include <span>
#include <string>
#include <vector>
#include <winrt/Windows.Data.Json.h>

namespace fae::vault::passkeys
{
    struct BrokerCredential
    {
        std::wstring rpId;
        std::vector<std::uint8_t> credentialId;
        std::vector<std::uint8_t> userId;
        std::wstring userName;
        std::wstring userDisplayName;
    };

    struct BrokerAssertionMaterial
    {
        std::wstring entryId;
        std::wstring moduleId;
        winrt::Windows::Data::Json::JsonObject record;
    };

    class VaultBrokerClient final
    {
    public:
        explicit VaultBrokerClient(std::chrono::milliseconds timeout = std::chrono::seconds(8));

        [[nodiscard]] bool IsUnlocked() const;
        [[nodiscard]] bool RequestUnlockAndWait(HANDLE cancelEvent) const;
        [[nodiscard]] std::vector<BrokerCredential> List(
            std::wstring_view rpId,
            std::span<const std::vector<std::uint8_t>> allowCredentialIds = {}) const;
        void CommitCreated(winrt::Windows::Data::Json::JsonObject const& record) const;
        [[nodiscard]] BrokerAssertionMaterial Get(
            std::wstring_view rpId, std::span<const std::uint8_t> credentialId) const;
        void CommitUse(std::wstring_view rpId, std::span<const std::uint8_t> credentialId) const;
        void Cancel(GUID const& requestId) const noexcept;

        [[nodiscard]] static std::wstring Base64Url(std::span<const std::uint8_t> value);
        [[nodiscard]] static std::vector<std::uint8_t> DecodeBase64Url(std::wstring_view value);

    private:
        [[nodiscard]] winrt::Windows::Data::Json::JsonObject Execute(
            winrt::Windows::Data::Json::JsonObject const& request) const;
        [[nodiscard]] winrt::Windows::Data::Json::JsonObject NewRequest(std::wstring_view type) const;

        std::chrono::milliseconds m_timeout;
    };
}
