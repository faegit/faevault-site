#include "WebAuthnCrypto.h"

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <memory>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

namespace fae::vault::passkeys
{
    namespace
    {
        struct ProviderDeleter { void operator()(NCRYPT_PROV_HANDLE* value) const noexcept { if (*value) NCryptFreeObject(*value); delete value; } };
        struct KeyDeleter { void operator()(NCRYPT_KEY_HANDLE* value) const noexcept { if (*value) NCryptFreeObject(*value); delete value; } };
        using Provider = std::unique_ptr<NCRYPT_PROV_HANDLE, ProviderDeleter>;
        using Key = std::unique_ptr<NCRYPT_KEY_HANDLE, KeyDeleter>;

        void Check(SECURITY_STATUS status)
        {
            if (status != ERROR_SUCCESS) throw std::runtime_error("Windows CNG operation failed");
        }

        Provider OpenProvider()
        {
            Provider provider(new NCRYPT_PROV_HANDLE{});
            Check(NCryptOpenStorageProvider(provider.get(), MS_KEY_STORAGE_PROVIDER, 0));
            return provider;
        }

        std::vector<std::uint8_t> Export(NCRYPT_KEY_HANDLE key, wchar_t const* type)
        {
            DWORD size = 0;
            Check(NCryptExportKey(key, 0, type, nullptr, nullptr, 0, &size, 0));
            if (size == 0 || size > 64 * 1024) throw std::runtime_error("invalid CNG export size");
            std::vector<std::uint8_t> output(size);
            Check(NCryptExportKey(key, 0, type, nullptr, output.data(), size, &size, 0));
            output.resize(size);
            return output;
        }

        std::vector<std::uint8_t> PrivateBlobToPkcs8(std::span<std::uint8_t const> blob)
        {
            if (blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 96) throw std::runtime_error("invalid P-256 private key");
            auto const* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB const*>(blob.data());
            if (header->dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC || header->cbKey != 32) throw std::runtime_error("invalid P-256 private key");
            auto const* x = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
            auto const* y = x + 32;
            auto const* d = y + 32;
            std::vector<std::uint8_t> output{
                0x30,0x81,0x87,0x02,0x01,0x00,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x04,0x6D,0x30,0x6B,0x02,0x01,0x01,0x04,0x20
            };
            output.insert(output.end(), d, d + 32);
            output.insert(output.end(), { 0xA1,0x44,0x03,0x42,0x00,0x04 });
            output.insert(output.end(), x, x + 32);
            output.insert(output.end(), y, y + 32);
            return output;
        }

        std::vector<std::uint8_t> Pkcs8ToPrivateBlob(std::span<std::uint8_t const> value)
        {
            constexpr std::uint8_t prefix[] = {
                0x30,0x81,0x87,0x02,0x01,0x00,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x04,0x6D,0x30,0x6B,0x02,0x01,0x01,0x04,0x20
            };
            constexpr std::uint8_t publicPrefix[] = { 0xA1,0x44,0x03,0x42,0x00,0x04 };
            if (value.size() != 138 || !std::equal(std::begin(prefix), std::end(prefix), value.begin()) ||
                !std::equal(std::begin(publicPrefix), std::end(publicPrefix), value.begin() + 68))
                throw std::invalid_argument("invalid P-256 PKCS#8 key");
            BCRYPT_ECCKEY_BLOB header{ BCRYPT_ECDSA_PRIVATE_P256_MAGIC, 32 };
            std::vector<std::uint8_t> blob(sizeof(header));
            std::memcpy(blob.data(), &header, sizeof(header));
            blob.insert(blob.end(), value.begin() + 74, value.begin() + 106); // x
            blob.insert(blob.end(), value.begin() + 106, value.begin() + 138); // y
            blob.insert(blob.end(), value.begin() + 36, value.begin() + 68); // d
            return blob;
        }

        Key ImportPkcs8(NCRYPT_PROV_HANDLE provider, std::span<std::uint8_t const> value)
        {
            auto blob = Pkcs8ToPrivateBlob(value);
            Key key(new NCRYPT_KEY_HANDLE{});
            Check(NCryptImportKey(provider, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, key.get(),
                blob.data(), static_cast<DWORD>(blob.size()), 0));
            SecureZeroMemory(blob.data(), blob.size());
            return key;
        }

        std::vector<std::uint8_t> CoseFromPublicBlob(std::span<std::uint8_t const> blob)
        {
            if (blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 64) throw std::runtime_error("invalid P-256 public key");
            auto const* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB const*>(blob.data());
            if (header->dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header->cbKey != 32) throw std::runtime_error("invalid P-256 public key");
            auto const* x = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);
            auto const* y = x + 32;
            std::vector<std::uint8_t> cose{ 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 };
            cose.insert(cose.end(), x, x + 32);
            cose.insert(cose.end(), { 0x22, 0x58, 0x20 });
            cose.insert(cose.end(), y, y + 32);
            return cose;
        }

        std::vector<std::uint8_t> SignedDigest(std::span<std::uint8_t const> authenticatorData, std::span<std::uint8_t const> clientDataHash)
        {
            if (authenticatorData.size() < 37 || authenticatorData.size() > 4096 || clientDataHash.size() != 32)
                throw std::invalid_argument("invalid assertion input");
            std::vector<std::uint8_t> value(authenticatorData.begin(), authenticatorData.end());
            value.insert(value.end(), clientDataHash.begin(), clientDataHash.end());
            auto digest = Sha256(value);
            return { digest.begin(), digest.end() };
        }

        void AppendDerInteger(std::vector<std::uint8_t>& output, std::span<std::uint8_t const> integer)
        {
            while (integer.size() > 1 && integer.front() == 0) integer = integer.subspan(1);
            bool prefix = (integer.front() & 0x80) != 0;
            output.push_back(0x02);
            output.push_back(static_cast<std::uint8_t>(integer.size() + (prefix ? 1 : 0)));
            if (prefix) output.push_back(0);
            output.insert(output.end(), integer.begin(), integer.end());
        }

        std::vector<std::uint8_t> RawToDer(std::span<std::uint8_t const> raw)
        {
            if (raw.size() != 64) throw std::runtime_error("invalid ECDSA signature");
            std::vector<std::uint8_t> body;
            AppendDerInteger(body, raw.first(32));
            AppendDerInteger(body, raw.subspan(32));
            std::vector<std::uint8_t> result{ 0x30, static_cast<std::uint8_t>(body.size()) };
            result.insert(result.end(), body.begin(), body.end());
            return result;
        }

        std::array<std::uint8_t, 64> DerToRaw(std::span<std::uint8_t const> der)
        {
            std::array<std::uint8_t, 64> raw{};
            if (der.size() < 8 || der[0] != 0x30 || der[1] != der.size() - 2) throw std::invalid_argument("invalid DER signature");
            std::size_t offset = 2;
            for (int part = 0; part < 2; ++part)
            {
                if (offset + 2 > der.size() || der[offset++] != 0x02) throw std::invalid_argument("invalid DER signature");
                auto length = der[offset++];
                if (length == 0 || offset + length > der.size()) throw std::invalid_argument("invalid DER signature");
                auto integer = der.subspan(offset, length);
                offset += length;
                if (integer.size() == 33 && integer.front() == 0) integer = integer.subspan(1);
                if (integer.size() > 32) throw std::invalid_argument("invalid DER signature");
                std::copy(integer.begin(), integer.end(), raw.begin() + part * 32 + (32 - integer.size()));
            }
            if (offset != der.size()) throw std::invalid_argument("invalid DER signature");
            return raw;
        }
    }

    std::array<std::uint8_t, 32> Sha256(std::span<std::uint8_t const> input)
    {
        BCRYPT_ALG_HANDLE algorithm{};
        BCRYPT_HASH_HANDLE hash{};
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) throw std::runtime_error("SHA-256 unavailable");
        auto closeAlgorithm = std::unique_ptr<void, decltype([](void* value) { if (value) BCryptCloseAlgorithmProvider(value, 0); })>(algorithm, {});
        if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0) throw std::runtime_error("SHA-256 unavailable");
        auto closeHash = std::unique_ptr<void, decltype([](void* value) { if (value) BCryptDestroyHash(value); })>(hash, {});
        if (!input.empty() && BCryptHashData(hash, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), 0) < 0) throw std::runtime_error("SHA-256 failed");
        std::array<std::uint8_t, 32> output{};
        if (BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0) < 0) throw std::runtime_error("SHA-256 failed");
        return output;
    }

    GeneratedCredential GenerateCredential()
    {
        auto provider = OpenProvider();
        Key key(new NCRYPT_KEY_HANDLE{});
        Check(NCryptCreatePersistedKey(*provider, key.get(), NCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0, 0));
        DWORD exportPolicy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        Check(NCryptSetProperty(*key, NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<PBYTE>(&exportPolicy), sizeof(exportPolicy), NCRYPT_PERSIST_FLAG));
        Check(NCryptFinalizeKey(*key, 0));
        auto publicBlob = Export(*key, BCRYPT_ECCPUBLIC_BLOB);
        auto privateCngBlob = Export(*key, BCRYPT_ECCPRIVATE_BLOB);
        auto privateBlob = PrivateBlobToPkcs8(privateCngBlob);
        SecureZeroMemory(privateCngBlob.data(), privateCngBlob.size());
        GeneratedCredential result{ SecureBuffer(std::move(privateBlob)), CoseFromPublicBlob(publicBlob), std::move(publicBlob), {} };
        if (BCryptGenRandom(nullptr, result.credentialId.data(), static_cast<ULONG>(result.credentialId.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            throw std::runtime_error("secure random generation failed");
        return result;
    }

    std::vector<std::uint8_t> BuildAuthenticatorData(
        std::span<std::uint8_t const> rpIdUtf8,
        bool includeAttestedCredentialData,
        std::span<std::uint8_t const> credentialId,
        std::span<std::uint8_t const> publicKeyCose)
    {
        if (rpIdUtf8.empty() || rpIdUtf8.size() > 253)
            throw std::invalid_argument("invalid RP ID");
        if (includeAttestedCredentialData)
        {
            if (credentialId.size() < 16 || credentialId.size() > 1024 || publicKeyCose.empty() || publicKeyCose.size() > 4096)
                throw std::invalid_argument("invalid attested credential data");
        }
        else if (!credentialId.empty() || !publicKeyCose.empty())
        {
            throw std::invalid_argument("assertion data must not contain attested credential data");
        }

        auto rpHash = Sha256(rpIdUtf8);
        std::vector<std::uint8_t> output(rpHash.begin(), rpHash.end());
        // UP + UV + BE. BS remains clear because syncable Vault records use backup_state=false.
        output.push_back(includeAttestedCredentialData ? 0x4d : 0x0d);
        output.insert(output.end(), 4, 0); // big-endian signature counter, always zero
        if (includeAttestedCredentialData)
        {
            constexpr std::uint8_t aaguid[] = {
                0x22,0xd9,0xbe,0x39,0x88,0x65,0x42,0xe3,0xa1,0x43,0xdd,0xa6,0xae,0x97,0x96,0xaf
            };
            output.insert(output.end(), std::begin(aaguid), std::end(aaguid));
            output.push_back(static_cast<std::uint8_t>(credentialId.size() >> 8));
            output.push_back(static_cast<std::uint8_t>(credentialId.size()));
            output.insert(output.end(), credentialId.begin(), credentialId.end());
            output.insert(output.end(), publicKeyCose.begin(), publicKeyCose.end());
        }
        return output;
    }

    std::vector<std::uint8_t> SignAssertion(std::span<std::uint8_t const> privateKeyPkcs8, std::span<std::uint8_t const> authenticatorData, std::span<std::uint8_t const> clientDataHash)
    {
        auto provider = OpenProvider();
        auto key = ImportPkcs8(*provider, privateKeyPkcs8);
        auto digest = SignedDigest(authenticatorData, clientDataHash);
        DWORD size = 0;
        Check(NCryptSignHash(*key, nullptr, digest.data(), static_cast<DWORD>(digest.size()), nullptr, 0, &size, 0));
        std::vector<std::uint8_t> raw(size);
        Check(NCryptSignHash(*key, nullptr, digest.data(), static_cast<DWORD>(digest.size()), raw.data(), static_cast<DWORD>(raw.size()), &size, 0));
        raw.resize(size);
        return RawToDer(raw);
    }

    bool VerifyAssertionForTest(std::span<std::uint8_t const> publicKeyBlob, std::span<std::uint8_t const> authenticatorData, std::span<std::uint8_t const> clientDataHash, std::span<std::uint8_t const> derSignature)
    {
        BCRYPT_ALG_HANDLE algorithm{};
        BCRYPT_KEY_HANDLE key{};
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0) return false;
        auto closeAlgorithm = std::unique_ptr<void, decltype([](void* value) { if (value) BCryptCloseAlgorithmProvider(value, 0); })>(algorithm, {});
        if (publicKeyBlob.size() > 4096) return false;
        if (BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, const_cast<PUCHAR>(publicKeyBlob.data()), static_cast<ULONG>(publicKeyBlob.size()), 0) < 0) return false;
        auto closeKey = std::unique_ptr<void, decltype([](void* value) { if (value) BCryptDestroyKey(value); })>(key, {});
        try
        {
            auto digest = SignedDigest(authenticatorData, clientDataHash);
            auto raw = DerToRaw(derSignature);
            return BCryptVerifySignature(key, nullptr, digest.data(), static_cast<ULONG>(digest.size()), raw.data(), static_cast<ULONG>(raw.size()), 0) >= 0;
        }
        catch (...) { return false; }
    }
}
