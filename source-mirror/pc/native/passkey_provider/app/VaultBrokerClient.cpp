#include "pch.h"
#include "VaultBrokerClient.h"
#include "../shared/BrokerProtocol.h"

#include <bcrypt.h>
#include <sddl.h>
#include <wil/result.h>

#pragma comment(lib, "bcrypt.lib")

using namespace winrt::Windows::Data::Json;

namespace
{
    using namespace fae::vault::passkeys::broker;

    std::vector<std::uint8_t> Utf8(std::wstring_view value)
    {
        if (value.empty()) return {};
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        THROW_LAST_ERROR_IF(size <= 0);
        std::vector<std::uint8_t> result(size);
        THROW_LAST_ERROR_IF(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), reinterpret_cast<char*>(result.data()), size, nullptr, nullptr) != size);
        return result;
    }

    std::wstring Wide(std::span<const std::uint8_t> value)
    {
        if (value.empty()) return {};
        const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<char const*>(value.data()), static_cast<int>(value.size()), nullptr, 0);
        THROW_LAST_ERROR_IF(size <= 0);
        std::wstring result(size, L'\0');
        THROW_LAST_ERROR_IF(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<char const*>(value.data()), static_cast<int>(value.size()), result.data(), size) != size);
        return result;
    }

    std::wstring CurrentUserSid()
    {
        wil::unique_handle token;
        THROW_IF_WIN32_BOOL_FALSE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.put()));
        DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        THROW_LAST_ERROR_IF(size == 0);
        std::vector<std::uint8_t> buffer(size);
        THROW_IF_WIN32_BOOL_FALSE(GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size));
        auto user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        wil::unique_hlocal_string sid;
        THROW_IF_WIN32_BOOL_FALSE(ConvertSidToStringSidW(user->User.Sid, sid.put()));
        return sid.get();
    }

    std::wstring CurrentUserSuffix()
    {
        const auto sid = Utf8(CurrentUserSid());
        std::array<std::uint8_t, 32> digest{};
        THROW_IF_NTSTATUS_FAILED(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
            const_cast<PUCHAR>(sid.data()), static_cast<ULONG>(sid.size()), digest.data(),
            static_cast<ULONG>(digest.size())));
        static constexpr wchar_t hex[] = L"0123456789abcdef";
        std::wstring suffix;
        suffix.reserve(24);
        for (std::size_t index = 0; index < 12; ++index)
        {
            suffix.push_back(hex[digest[index] >> 4]);
            suffix.push_back(hex[digest[index] & 0x0f]);
        }
        return suffix;
    }

    std::wstring PipeName()
    {
        return L"\\\\.\\pipe\\FAEVault.PasskeyBroker.v1." + CurrentUserSuffix();
    }

    std::wstring UnlockEventName()
    {
        return L"Local\\FAEVault.PasskeyUnlock.v1." + CurrentUserSuffix();
    }

    void WriteAll(HANDLE pipe, std::span<const std::uint8_t> bytes)
    {
        while (!bytes.empty())
        {
            DWORD written = 0;
            THROW_IF_WIN32_BOOL_FALSE(WriteFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr));
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE), written == 0);
            bytes = bytes.subspan(written);
        }
    }

    void ReadAll(HANDLE pipe, std::span<std::uint8_t> bytes)
    {
        while (!bytes.empty())
        {
            DWORD read = 0;
            THROW_IF_WIN32_BOOL_FALSE(ReadFile(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr));
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE), read == 0);
            bytes = bytes.subspan(read);
        }
    }

    void WriteJson(HANDLE pipe, JsonObject const& value)
    {
        const auto payload = Utf8(value.Stringify().c_str());
        THROW_HR_IF(E_INVALIDARG, payload.empty() || payload.size() > kMaxFrame);
        const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
        WriteAll(pipe, std::span(reinterpret_cast<std::uint8_t const*>(&size), sizeof(size)));
        WriteAll(pipe, payload);
    }

    JsonObject ReadJson(HANDLE pipe)
    {
        std::uint32_t size = 0;
        ReadAll(pipe, std::span(reinterpret_cast<std::uint8_t*>(&size), sizeof(size)));
        THROW_HR_IF(E_INVALIDARG, size < 2 || size > kMaxFrame);
        std::vector<std::uint8_t> payload(size);
        ReadAll(pipe, payload);
        return JsonObject::Parse(Wide(payload));
    }

    std::wstring GuidString()
    {
        GUID value{};
        THROW_IF_FAILED(CoCreateGuid(&value));
        wchar_t buffer[39]{};
        THROW_HR_IF(E_UNEXPECTED, StringFromGUID2(value, buffer, ARRAYSIZE(buffer)) == 0);
        std::wstring result(buffer);
        result.erase(result.begin());
        result.pop_back();
        return result;
    }

    std::int64_t Deadline(std::chrono::milliseconds timeout)
    {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now).count() + timeout.count();
    }
}

namespace fae::vault::passkeys
{
    namespace
    {
        bool LaunchVaultUnlock()
        {
            constexpr wchar_t uninstallKey[] =
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{C83A71DC-3F1D-4A65-8BB3-EACFC15EFC7A}_is1";
            wchar_t installLocation[MAX_PATH]{};
            DWORD bytes = sizeof(installLocation);
            const auto result = RegGetValueW(HKEY_LOCAL_MACHINE, uninstallKey, L"InstallLocation",
                RRF_RT_REG_SZ, nullptr, installLocation, &bytes);
            if (result != ERROR_SUCCESS || installLocation[0] == L'\0') return false;
            std::filesystem::path executable(installLocation);
            executable /= L"FAEVault.exe";
            std::error_code error;
            if (!std::filesystem::is_regular_file(executable, error) || error) return false;

            SHELLEXECUTEINFOW launch{ sizeof(launch) };
            launch.fMask = SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
            launch.lpFile = executable.c_str();
            launch.lpParameters = L"--passkey-unlock";
            launch.lpDirectory = installLocation;
            launch.nShow = SW_SHOWNORMAL;
            return ShellExecuteExW(&launch) != FALSE;
        }
    }

    VaultBrokerClient::VaultBrokerClient(std::chrono::milliseconds timeout) : m_timeout(timeout)
    {
        THROW_HR_IF(E_INVALIDARG, timeout <= std::chrono::milliseconds::zero() || timeout > std::chrono::seconds(120));
    }

    JsonObject VaultBrokerClient::NewRequest(std::wstring_view type) const
    {
        JsonObject request;
        request.Insert(L"v", JsonValue::CreateNumberValue(1));
        request.Insert(L"type", JsonValue::CreateStringValue(type));
        request.Insert(L"requestId", JsonValue::CreateStringValue(GuidString()));
        request.Insert(L"deadlineMs", JsonValue::CreateNumberValue(static_cast<double>(Deadline(m_timeout))));
        return request;
    }

    JsonObject VaultBrokerClient::Execute(JsonObject const& request) const
    {
        const auto name = PipeName();
        THROW_IF_WIN32_BOOL_FALSE(WaitNamedPipeW(name.c_str(), static_cast<DWORD>(m_timeout.count())));
        wil::unique_hfile pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        THROW_LAST_ERROR_IF(!pipe);
        const auto greeting = ReadJson(pipe.get());
        THROW_HR_IF(E_ACCESSDENIED, greeting.GetNamedString(L"type", L"") != L"challenge");
        auto hello = NewRequest(L"hello");
        hello.Insert(L"challenge", JsonValue::CreateStringValue(greeting.GetNamedString(L"challenge")));
        WriteJson(pipe.get(), hello);
        const auto helloReply = ReadJson(pipe.get());
        THROW_HR_IF(E_ACCESSDENIED, !helloReply.GetNamedBoolean(L"ok", false));
        WriteJson(pipe.get(), request);
        const auto reply = ReadJson(pipe.get());
        THROW_HR_IF(E_FAIL, !reply.GetNamedBoolean(L"ok", false));
        return reply.GetNamedObject(L"result", JsonObject{});
    }

    bool VaultBrokerClient::IsUnlocked() const
    {
        try { return !Execute(NewRequest(L"status")).GetNamedBoolean(L"locked", true); }
        catch (...) { return false; }
    }

    bool VaultBrokerClient::RequestUnlockAndWait(HANDLE cancelEvent) const
    {
        if (IsUnlocked()) return true;
        const auto name = UnlockEventName();
        wil::unique_handle request(OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str()));
        if (request)
        {
            if (!SetEvent(request.get())) return false;
        }
        else if (!LaunchVaultUnlock())
        {
            return false;
        }
        // The existing Vault unlock dialog is the authority. Poll only the non-secret lock status.
        constexpr auto total = std::chrono::seconds(120);
        const auto deadline = std::chrono::steady_clock::now() + total;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (cancelEvent && WaitForSingleObject(cancelEvent, 250) == WAIT_OBJECT_0) return false;
            if (!cancelEvent) Sleep(250);
            if (!request)
            {
                request.reset(OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str()));
                if (request) (void)SetEvent(request.get());
            }
            if (IsUnlocked()) return true;
        }
        return false;
    }

    std::vector<BrokerCredential> VaultBrokerClient::List(
        std::wstring_view rpId, std::span<const std::vector<std::uint8_t>> allowCredentialIds) const
    {
        auto request = NewRequest(L"list");
        request.Insert(L"rpId", JsonValue::CreateStringValue(rpId));
        JsonArray allow;
        for (auto const& id : allowCredentialIds) allow.Append(JsonValue::CreateStringValue(Base64Url(id)));
        request.Insert(L"allowCredentialIds", allow);
        std::vector<BrokerCredential> output;
        for (auto const& value : Execute(request).GetNamedArray(L"credentials"))
        {
            auto item = value.GetObject();
            output.push_back({ item.GetNamedString(L"rpId").c_str(), DecodeBase64Url(item.GetNamedString(L"credentialId").c_str()),
                DecodeBase64Url(item.GetNamedString(L"userId").c_str()), item.GetNamedString(L"userName").c_str(),
                item.GetNamedString(L"userDisplayName").c_str() });
        }
        return output;
    }

    void VaultBrokerClient::CommitCreated(JsonObject const& record) const
    {
        auto request = NewRequest(L"make");
        request.Insert(L"record", record);
        (void)Execute(request);
    }

    BrokerAssertionMaterial VaultBrokerClient::Get(std::wstring_view rpId, std::span<const std::uint8_t> credentialId) const
    {
        auto request = NewRequest(L"get");
        request.Insert(L"rpId", JsonValue::CreateStringValue(rpId));
        request.Insert(L"credentialId", JsonValue::CreateStringValue(Base64Url(credentialId)));
        auto result = Execute(request);
        return { result.GetNamedString(L"entryId").c_str(), result.GetNamedString(L"moduleId").c_str(), result.GetNamedObject(L"record") };
    }

    void VaultBrokerClient::CommitUse(std::wstring_view rpId, std::span<const std::uint8_t> credentialId) const
    {
        SYSTEMTIME now{};
        GetSystemTime(&now);
        wchar_t timestamp[25]{};
        THROW_HR_IF(E_UNEXPECTED, swprintf_s(timestamp, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond) <= 0);
        auto request = NewRequest(L"commit-use");
        request.Insert(L"rpId", JsonValue::CreateStringValue(rpId));
        request.Insert(L"credentialId", JsonValue::CreateStringValue(Base64Url(credentialId)));
        request.Insert(L"lastUsedAt", JsonValue::CreateStringValue(timestamp));
        request.Insert(L"signCount", JsonValue::CreateStringValue(L"0"));
        (void)Execute(request);
    }

    void VaultBrokerClient::Cancel(GUID const& requestId) const noexcept
    {
        try
        {
            wchar_t buffer[39]{};
            if (!StringFromGUID2(requestId, buffer, ARRAYSIZE(buffer))) return;
            std::wstring target(buffer); target.erase(target.begin()); target.pop_back();
            auto request = NewRequest(L"cancel");
            request.Insert(L"targetRequestId", JsonValue::CreateStringValue(target));
            (void)Execute(request);
        }
        catch (...) {}
    }

    std::wstring VaultBrokerClient::Base64Url(std::span<const std::uint8_t> value)
    {
        static constexpr wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::wstring output;
        output.reserve((value.size() * 4 + 2) / 3);
        std::uint32_t bits = 0; int count = 0;
        for (auto byte : value)
        {
            bits = (bits << 8) | byte; count += 8;
            while (count >= 6) { count -= 6; output.push_back(alphabet[(bits >> count) & 63]); }
        }
        if (count) output.push_back(alphabet[(bits << (6 - count)) & 63]);
        return output;
    }

    std::vector<std::uint8_t> VaultBrokerClient::DecodeBase64Url(std::wstring_view value)
    {
        THROW_HR_IF(E_INVALIDARG, value.empty());
        std::vector<std::uint8_t> output;
        std::uint32_t bits = 0; int count = 0;
        for (wchar_t ch : value)
        {
            int decoded = ch >= L'A' && ch <= L'Z' ? ch - L'A' : ch >= L'a' && ch <= L'z' ? ch - L'a' + 26 :
                ch >= L'0' && ch <= L'9' ? ch - L'0' + 52 : ch == L'-' ? 62 : ch == L'_' ? 63 : -1;
            THROW_HR_IF(E_INVALIDARG, decoded < 0);
            bits = (bits << 6) | static_cast<unsigned>(decoded); count += 6;
            if (count >= 8) { count -= 8; output.push_back(static_cast<std::uint8_t>((bits >> count) & 0xff)); }
        }
        THROW_HR_IF(E_INVALIDARG, count >= 6 || (count && (bits & ((1u << count) - 1u))));
        return output;
    }
}
