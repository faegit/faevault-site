#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace fae::vault::passkeys::broker
{
    inline constexpr unsigned int kProtocolVersion = 1;
    inline constexpr std::size_t kMaxFrame = 1024 * 1024;

    inline constexpr std::array<std::wstring_view, 8> kMessageTypes{
        L"hello", L"status", L"list", L"make", L"get", L"commit-use", L"reconcile", L"cancel"
    };

    inline constexpr std::array<std::wstring_view, 10> kSensitiveFields{
        L"masterPassword", L"password", L"recoveryKey", L"rootKey", L"syncKey",
        L"accessToken", L"refreshToken", L"command", L"environment", L"vaultPath"
    };
}
