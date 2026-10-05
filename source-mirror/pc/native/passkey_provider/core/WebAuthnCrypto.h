#pragma once

#include "SecureBuffer.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace fae::vault::passkeys
{
    struct GeneratedCredential final
    {
        SecureBuffer privateKeyPkcs8;
        std::vector<std::uint8_t> publicKeyCose;
        std::vector<std::uint8_t> publicKeyBlob;
        std::array<std::uint8_t, 32> credentialId{};
    };

    GeneratedCredential GenerateCredential();
    std::array<std::uint8_t, 32> Sha256(std::span<std::uint8_t const> input);
    std::vector<std::uint8_t> BuildAuthenticatorData(
        std::span<std::uint8_t const> rpIdUtf8,
        bool includeAttestedCredentialData,
        std::span<std::uint8_t const> credentialId = {},
        std::span<std::uint8_t const> publicKeyCose = {});
    std::vector<std::uint8_t> SignAssertion(
        std::span<std::uint8_t const> privateKeyPkcs8,
        std::span<std::uint8_t const> authenticatorData,
        std::span<std::uint8_t const> clientDataHash);
    bool VerifyAssertionForTest(
        std::span<std::uint8_t const> publicKeyBlob,
        std::span<std::uint8_t const> authenticatorData,
        std::span<std::uint8_t const> clientDataHash,
        std::span<std::uint8_t const> derSignature);
}
