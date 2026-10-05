#include "pch.h"
#include "PluginAuthenticatorImpl.h"
#include <ProviderIdentity.h>
#include <VaultBrokerClient.h>
#include "../../core/WebAuthnCrypto.h"
#include <include/cbor-lite/codec.h>
#include <string>
#include <iostream>
#include <fstream>
#include <helpers/buffer_read_write.h>
#include <wil/result.h>
#include <wil/resource.h>
#include <algorithm>
#include <memory>

namespace winrt
{
    using namespace winrt::Windows::Foundation;
#if !defined(PROVIDER_HOST_ONLY)
    using namespace winrt::Microsoft::UI::Windowing;
    using namespace winrt::Microsoft::UI::Xaml;
    using namespace winrt::Microsoft::UI::Xaml::Controls;
    using namespace winrt::Microsoft::UI::Xaml::Navigation;
    using namespace PasskeyManager;
    using namespace PasskeyManager::implementation;
#endif
    using namespace CborLite;
}

namespace winrt::PasskeyManager::implementation
{
    namespace {
        // Helper function to get request signing public key with proper error handling
        std::vector<uint8_t> GetRequestSigningPubKey()
        {
            DWORD cbKeyData = 0;
            unique_plugin_public_key pbKeyData = nullptr;
            HRESULT hr = WebAuthNPluginGetOperationSigningPublicKey(
                vault_plugin_guid,
                &cbKeyData,
                &pbKeyData);

            if (SUCCEEDED(hr) && pbKeyData && cbKeyData > 0)
            {
                std::vector<BYTE> response(pbKeyData.get(), pbKeyData.get() + cbKeyData);
                return response;
            }

            return {};
        }

        /*
        * This function is used to verify the signature of a request buffer.
        * The public key is part of response to plugin registration.
        */
        HRESULT VerifySignatureHelper(
            std::span<const BYTE> dataBuffer,
            PBYTE pbKeyData,
            DWORD cbKeyData,
            PBYTE pbSignature,
            DWORD cbSignature)
        {
            // Create key provider
            wil::unique_ncrypt_prov hProvider;
            wil::unique_ncrypt_key reqSigningKey;

            // Get the provider
            RETURN_IF_FAILED(NCryptOpenStorageProvider(&hProvider, nullptr, 0));
            
            // Create a NCrypt key handle from the public key
            RETURN_IF_FAILED(NCryptImportKey(
                hProvider.get(),
                NULL,
                BCRYPT_PUBLIC_KEY_BLOB,
                nullptr,
                &reqSigningKey,
                pbKeyData,
                cbKeyData,
                0));

            // Verify the signature over the hash of dataBuffer using the hKey
            DWORD objLenSize = 0;
            DWORD bytesRead = 0;
            RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
                BCRYPT_SHA256_ALG_HANDLE,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PBYTE>(&objLenSize),
                sizeof(objLenSize),
                &bytesRead, 
                0));

            auto objLen = wil::make_unique_cotaskmem<BYTE[]>(objLenSize);
            RETURN_HR_IF_NULL(E_OUTOFMEMORY, objLen);

            wil::unique_bcrypt_hash hashHandle;
            RETURN_IF_NTSTATUS_FAILED(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                wil::out_param(hashHandle),
                objLen.get(),
                objLenSize,
                nullptr, 
                0, 
                0));

            RETURN_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(),
                const_cast<PUCHAR>(dataBuffer.data()),
                static_cast<ULONG>(dataBuffer.size()), 
                0));

            DWORD localHashByteCount = 0;
            RETURN_IF_NTSTATUS_FAILED(BCryptGetProperty(
                BCRYPT_SHA256_ALG_HANDLE,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PBYTE>(&localHashByteCount),
                sizeof(localHashByteCount),
                &bytesRead, 
                0));

            auto localHashBuffer = wil::make_unique_cotaskmem<BYTE[]>(localHashByteCount);
            RETURN_HR_IF_NULL(E_OUTOFMEMORY, localHashBuffer);

            RETURN_IF_NTSTATUS_FAILED(BCryptFinishHash(
                hashHandle.get(), 
                localHashBuffer.get(), 
                localHashByteCount, 
                0));

            PVOID paddingInfo = nullptr;
            DWORD dwCngFlags = 0;
            RETURN_HR_IF(E_INVALIDARG, cbKeyData < sizeof(BCRYPT_KEY_BLOB));
            
            BCRYPT_KEY_BLOB* pKeyBlob = reinterpret_cast<BCRYPT_KEY_BLOB*>(pbKeyData);
            if (pKeyBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC)
            {
                BCRYPT_PKCS1_PADDING_INFO paddingInfoStruct = {};
                paddingInfoStruct.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                paddingInfo = &paddingInfoStruct;
                dwCngFlags = BCRYPT_PAD_PKCS1;
            }

            RETURN_IF_WIN32_ERROR(NCryptVerifySignature(
                reqSigningKey.get(),
                paddingInfo,
                localHashBuffer.get(),
                localHashByteCount,
                pbSignature,
                cbSignature,
                dwCngFlags));

            return S_OK;
        }

    } // anonymous namespace

    HRESULT ContosoPlugin::PerformUserVerification(
        HWND hWnd,
        GUID transactionId,
        PluginOperationType operationType,
        const std::vector<BYTE>& requestBuffer,
        wil::shared_cotaskmem_string rpName,
        wil::shared_cotaskmem_string userName)
    {
        RETURN_HR_IF(E_INVALIDARG, requestBuffer.empty());
        (void)rpName;
        try
        {
            // The real Vault session, never a registry/mock flag, is the lock authority.
            RETURN_HR_IF(NTE_USER_CANCELLED,
                !fae::vault::passkeys::VaultBrokerClient().RequestUnlockAndWait(m_hPluginCancelOperationEvent.get()));

            // Optional Step: Get the UV count. The UV count tracks the number of times the user has performed a gesture to unlock the vault.
            DWORD uvCount = 0;
            RETURN_IF_FAILED(WebAuthNPluginGetUserVerificationCount(vault_plugin_guid, &uvCount));

            // Step 1: Get the public key.
            DWORD cbPubKeyData = 0;
            unique_plugin_public_key pbPubKeyData = nullptr;
            RETURN_IF_FAILED(WebAuthNPluginGetUserVerificationPublicKey(
                vault_plugin_guid,
                &cbPubKeyData,
                &pbPubKeyData));
            RETURN_HR_IF_NULL(E_FAIL, pbPubKeyData);

            // Step 2: Perform UV. This step uses a Windows Hello prompt to authenticate the user.
            // WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST: This structure defines the request parameters for Windows Hello user verification.
            // Enables plugins to leverage familiar Windows Hello biometric authentication for user verification workflows.
            WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST pluginPerformUv = {
                nullptr,      // hwnd
                transactionId, // rguidTransactionId
                nullptr,      // pwszUsername
                nullptr       // pwszDisplayHint
            };

            pluginPerformUv.hwnd = hWnd;

            auto localUserName = wil::make_cotaskmem_string(userName.get());
            pluginPerformUv.pwszUsername = localUserName.get();

            // pwszDisplayHint can be used to provide additional context to the user.
            // This is displayed alongside the username in the Windows Hello passkey user verification dialog.
            auto localDisplayHint = wil::make_cotaskmem_string(
                operationType == PluginOperationType::MakeCredential ? L"Create a passkey in FAE Vault" : L"Sign in with FAE Vault");
            pluginPerformUv.pwszDisplayHint = localDisplayHint.get();

            DWORD cbResponse = 0;
            PBYTE pbResponse = nullptr;

            RETURN_IF_FAILED(WebAuthNPluginPerformUserVerification(&pluginPerformUv, &cbResponse, &pbResponse));
            auto cleanupUvResponse = wil::scope_exit([&] {
                WebAuthNPluginFreeUserVerificationResponse(pbResponse);
            });

            // Verify the signature over the hash of requestBuffer using the hKey
            auto signatureVerifyResult = VerifySignatureHelper(
                requestBuffer,
                pbPubKeyData.get(),
                cbPubKeyData,
                pbResponse,
                cbResponse);

            return signatureVerifyResult;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    /*
    * This function is used to create a simplified version of authenticator data for the webauthn authenticator operations.
    * Refer: https://www.w3.org/TR/webauthn-3/#authenticator-data for more details.
    */
    HRESULT CreateAuthenticatorData(
        const NCRYPT_KEY_HANDLE hKey,
        const PluginOperationType operationType,
        DWORD cbRpId,
        PBYTE pbRpId,
        DWORD& pcbPackedAuthenticatorData,
        wil::unique_hlocal_ptr<BYTE[]>& ppbpackedAuthenticatorData,
        std::vector<uint8_t>& vCredentialIdBuffer)
    {
        try
        {
            // Get the public key blob
            DWORD cbPubKeyBlob = 0;
            THROW_IF_FAILED(NCryptExportKey(
                hKey,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                nullptr,
                nullptr,
                0,
                &cbPubKeyBlob,
                0));

            auto pbPubKeyBlob = std::make_unique<BYTE[]>(cbPubKeyBlob);

            DWORD cbPubKeyBlobOutput = 0;
            THROW_IF_FAILED(NCryptExportKey(
                hKey,
                NULL,
                BCRYPT_ECCPUBLIC_BLOB,
                nullptr,
                pbPubKeyBlob.get(),
                cbPubKeyBlob,
                &cbPubKeyBlobOutput,
                0));

            BCRYPT_ECCKEY_BLOB* pPubKeyBlobHeader = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pbPubKeyBlob.get());
            DWORD cbXCoord = pPubKeyBlobHeader->cbKey;
            PBYTE pbXCoord = reinterpret_cast<PBYTE>(&pPubKeyBlobHeader[1]);
            DWORD cbYCoord = pPubKeyBlobHeader->cbKey;
            PBYTE pbYCoord = pbXCoord + cbXCoord;

            // create byte span for x and y
            std::span<const BYTE> xCoord(pbXCoord, cbXCoord);
            std::span<const BYTE> yCoord(pbYCoord, cbYCoord);

            // CBOR encode the public key in this order: kty, alg, crv, x, y
            std::vector<BYTE> buffer;

#pragma warning(push)
#pragma warning(disable: 4293)
            size_t bufferSize = CborLite::encodeMapSize(buffer, 5u);
#pragma warning(pop)

            // COSE CBOR encoding format. Refer to https://datatracker.ietf.org/doc/html/rfc9052#section-7 for more details.
            constexpr int8_t ktyIndex = 1;
            constexpr int8_t algIndex = 3;
            constexpr int8_t crvIndex = -1;
            constexpr int8_t xIndex = -2;
            constexpr int8_t yIndex = -3;

            // Example values for EC2 P-256 ES256 Keys. Refer to https://www.w3.org/TR/webauthn-3/#example-bdbd14cc
            // Note that this sample authenticator only supports ES256 keys.
            constexpr int8_t kty = 2; // Key type is EC2
            constexpr int8_t crv = 1; // Curve is P-256
            constexpr int8_t alg = -7; // Algorithm is ES256

            bufferSize += CborLite::encodeInteger(buffer, ktyIndex);
            bufferSize += CborLite::encodeInteger(buffer, kty);
            bufferSize += CborLite::encodeInteger(buffer, algIndex);
            bufferSize += CborLite::encodeInteger(buffer, alg);
            bufferSize += CborLite::encodeInteger(buffer, crvIndex);
            bufferSize += CborLite::encodeInteger(buffer, crv);
            bufferSize += CborLite::encodeInteger(buffer, xIndex);
            bufferSize += CborLite::encodeBytes(buffer, xCoord);
            bufferSize += CborLite::encodeInteger(buffer, yIndex);
            bufferSize += CborLite::encodeBytes(buffer, yCoord);

            wil::unique_bcrypt_hash hashHandle;
            THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &hashHandle,
                nullptr,
                0,
                nullptr,
                0,
                0));

            THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(), 
                reinterpret_cast<PUCHAR>(pbXCoord), 
                cbXCoord, 
                0));

            THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                hashHandle.get(), 
                reinterpret_cast<PUCHAR>(pbYCoord), 
                cbYCoord, 
                0));

            DWORD cbHash = 0;
            DWORD bytesRead = 0;
            THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(
                hashHandle.get(),
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PBYTE>(&cbHash),
                sizeof(cbHash),
                &bytesRead,
                0));

            wil::unique_hlocal_ptr<BYTE[]> pbCredentialId = wil::make_unique_hlocal<BYTE[]>(cbHash);

            THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
                hashHandle.get(), 
                pbCredentialId.get(), 
                cbHash, 
                0));

            // Refer to learn about packing credential data https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
            constexpr DWORD rpidsha256Size = 32; // SHA256 hash of rpId
            constexpr DWORD flagsSize = 1; // flags
            constexpr DWORD signCountSize = 4; // signCount
            DWORD cbPackedAuthenticatorData = rpidsha256Size + flagsSize + signCountSize;

            if (operationType == PluginOperationType::MakeCredential)
            {
                cbPackedAuthenticatorData += sizeof(GUID); // aaGuid
                cbPackedAuthenticatorData += sizeof(WORD); // credentialId length
                cbPackedAuthenticatorData += cbHash; // credentialId
                cbPackedAuthenticatorData += static_cast<DWORD>(buffer.size()); // public key
            }

            std::vector<BYTE> vPackedAuthenticatorData(cbPackedAuthenticatorData);
            auto writer = buffer_writer{ vPackedAuthenticatorData };

            auto rgbRpIdHash = writer.reserve_space<std::array<BYTE, rpidsha256Size>>(); // 32 bytes of rpIdHash which is SHA256 hash of rpName. https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
            DWORD cbRpIdHash = rpidsha256Size;
            THROW_IF_WIN32_BOOL_FALSE(CryptHashCertificate2(
                BCRYPT_SHA256_ALGORITHM,
                0,
                nullptr,
                pbRpId,
                cbRpId,
                rgbRpIdHash->data(),
                &cbRpIdHash));

            // Flags uv, up, be, and at are set
            if (operationType == PluginOperationType::GetAssertion)
            {
                // Refer https://www.w3.org/TR/webauthn-3/#authdata-flags
                *writer.reserve_space<uint8_t>() = 0x1d; // credential data flags of size 1 byte

                *writer.reserve_space<uint32_t>() = 0u; // Sign count of size 4 bytes is set to 0

                vCredentialIdBuffer.assign(pbCredentialId.get(), pbCredentialId.get() + cbHash);
            }
            else
            {
                // Refer https://www.w3.org/TR/webauthn-3/#authdata-flags
                *writer.reserve_space<uint8_t>() = 0x5d; // credential data flags of size 1 byte

                *writer.reserve_space<uint32_t>() = 0u; // Sign count of size 4 bytes is set to 0

                // aaGuid of size 16 bytes is set to predefined bytes in big-endian. Refer https://www.w3.org/TR/webauthn-3/#aaguid
                writer.add(std::span<const BYTE>(vault_plugin_aaguid_bytes, sizeof(vault_plugin_aaguid_bytes)));

                // Retrieve credential id
                WORD cbCredentialId = static_cast<WORD>(cbHash);
                WORD cbCredentialIdBigEndian = _byteswap_ushort(cbCredentialId);

                *writer.reserve_space<WORD>() = cbCredentialIdBigEndian; // Size of credential id in unsigned big endian of size 2 bytes

                writer.add(std::span<BYTE>(pbCredentialId.get(), cbHash)); // Set credential id

                vCredentialIdBuffer.assign(pbCredentialId.get(), pbCredentialId.get() + cbHash);

                writer.add(std::span<BYTE>(buffer.data(), buffer.size())); // Set CBOR encoded public key
            }

            pcbPackedAuthenticatorData = static_cast<DWORD>(vPackedAuthenticatorData.size());
            ppbpackedAuthenticatorData = wil::make_unique_hlocal<BYTE[]>(pcbPackedAuthenticatorData);

            memcpy_s(ppbpackedAuthenticatorData.get(), pcbPackedAuthenticatorData, vPackedAuthenticatorData.data(), pcbPackedAuthenticatorData);

            return S_OK;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    /*
    * This function is invoked by the platform to request the plugin to handle a make credential operation.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl
    */
    HRESULT STDMETHODCALLTYPE ContosoPlugin::MakeCredential(
        /* [in] */ __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginMakeCredentialRequest,
        /* [out] */ __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        HRESULT hr = S_OK;
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, response);
            *response = {};
            RETURN_HR_IF_NULL(E_INVALIDARG, pPluginMakeCredentialRequest);

            bool expected = false;
            if (!m_operationInProgress.compare_exchange_strong(expected, true))
            {
                return HRESULT_FROM_WIN32(ERROR_BUSY); // Another operation is running.
            }
            // Ensure the flag is cleared when the function exits, for any reason.
            auto clearOperationInProgress = wil::scope_exit([&]
            {
                m_operationInProgress = false;
            });
            { std::lock_guard lock(m_transactionMutex); m_transactionId = pPluginMakeCredentialRequest->transactionId; }
            auto completePluginOperation = wil::SetEvent_scope_exit(m_hPluginOpCompletedEvent.get());

            // WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST: This structure represents the decoded CTAP make credential request.
            // Provides structured access to CBOR-encoded operation parameters for third-party plugin implementations.
            PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pDecodedMakeCredentialRequest;

            THROW_IF_FAILED(WebAuthNDecodeMakeCredentialRequest(
                pPluginMakeCredentialRequest->cbEncodedRequest,
                pPluginMakeCredentialRequest->pbEncodedRequest,
                &pDecodedMakeCredentialRequest));

            auto cleanup = wil::scope_exit([&] {
                WebAuthNFreeDecodedMakeCredentialRequest(pDecodedMakeCredentialRequest);
            });

            auto rpName = wil::make_cotaskmem_string(pDecodedMakeCredentialRequest->pRpInformation->pwszName);

            auto userName = wil::make_cotaskmem_string(pDecodedMakeCredentialRequest->pUserInformation->pwszName);
            std::vector<BYTE> requestBuffer(
                pPluginMakeCredentialRequest->pbEncodedRequest,
                pPluginMakeCredentialRequest->pbEncodedRequest + pPluginMakeCredentialRequest->cbEncodedRequest);

            auto pubKeyData = GetRequestSigningPubKey();
            HRESULT requestSignResult = E_FAIL;
            if (!pubKeyData.empty())
            {
                requestSignResult = VerifySignatureHelper(
                    requestBuffer,
                    pubKeyData.data(),
                    static_cast<DWORD>(pubKeyData.size()),
                    pPluginMakeCredentialRequest->pbRequestSignature,
                    pPluginMakeCredentialRequest->cbRequestSignature);
            }

            THROW_IF_FAILED(requestSignResult);

            hr = PerformUserVerification(
                pPluginMakeCredentialRequest->hWnd,
                pPluginMakeCredentialRequest->transactionId,
                PluginOperationType::MakeCredential,
                requestBuffer,
                std::move(rpName),
                std::move(userName));
            THROW_IF_FAILED(hr);

            // Generate/export the WebAuthn key only in native C++ through Windows CNG.
            auto generated = fae::vault::passkeys::GenerateCredential();
            std::vector<uint8_t> vCredentialIdBuffer(generated.credentialId.begin(), generated.credentialId.end());
            auto authenticatorData = fae::vault::passkeys::BuildAuthenticatorData(
                std::span<const uint8_t>(pDecodedMakeCredentialRequest->pbRpId, pDecodedMakeCredentialRequest->cbRpId),
                true, vCredentialIdBuffer, generated.publicKeyCose);

            WEBAUTHN_CREDENTIAL_ATTESTATION attestationResponse = {};
            attestationResponse.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
            attestationResponse.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
            attestationResponse.cbAttestation = 0;
            attestationResponse.pbAttestation = nullptr;
            attestationResponse.cbAuthenticatorData = 0;
            attestationResponse.pbAuthenticatorData = nullptr;

            attestationResponse.pbAuthenticatorData = authenticatorData.data();
            attestationResponse.cbAuthenticatorData = static_cast<DWORD>(authenticatorData.size());

            DWORD cbAttestationBuffer = 0;
            wil::unique_cotaskmem_ptr<BYTE[]> pbAttestationBuffer;

            THROW_IF_FAILED(WebAuthNEncodeMakeCredentialResponse(
                &attestationResponse,
                &cbAttestationBuffer,
                wil::out_param(pbAttestationBuffer)));

            // Vault is the sole source of truth.  Commit before returning success or caching metadata.
            using winrt::Windows::Data::Json::JsonObject;
            using winrt::Windows::Data::Json::JsonValue;
            JsonObject record;
            record.Insert(L"schema_version", JsonValue::CreateStringValue(L"3"));
            record.Insert(L"rp_id", JsonValue::CreateStringValue(pDecodedMakeCredentialRequest->pRpInformation->pwszId));
            record.Insert(L"rp_name", JsonValue::CreateStringValue(pDecodedMakeCredentialRequest->pRpInformation->pwszName));
            record.Insert(L"user_id", JsonValue::CreateStringValue(fae::vault::passkeys::VaultBrokerClient::Base64Url(
                std::span<const uint8_t>(pDecodedMakeCredentialRequest->pUserInformation->pbId, pDecodedMakeCredentialRequest->pUserInformation->cbId))));
            record.Insert(L"user_name", JsonValue::CreateStringValue(pDecodedMakeCredentialRequest->pUserInformation->pwszName));
            record.Insert(L"user_display_name", JsonValue::CreateStringValue(pDecodedMakeCredentialRequest->pUserInformation->pwszDisplayName));
            record.Insert(L"credential_id", JsonValue::CreateStringValue(fae::vault::passkeys::VaultBrokerClient::Base64Url(vCredentialIdBuffer)));
            record.Insert(L"key_mode", JsonValue::CreateStringValue(L"syncable"));
            record.Insert(L"private_key", JsonValue::CreateStringValue(fae::vault::passkeys::VaultBrokerClient::Base64Url(generated.privateKeyPkcs8.view())));
            record.Insert(L"public_key", JsonValue::CreateStringValue(fae::vault::passkeys::VaultBrokerClient::Base64Url(generated.publicKeyCose)));
            record.Insert(L"algorithm", JsonValue::CreateStringValue(L"-7"));
            record.Insert(L"transports", JsonValue::CreateStringValue(L"internal"));
            record.Insert(L"aaguid", JsonValue::CreateStringValue(L"22d9be39-8865-42e3-a143-dda6ae9796af"));
            record.Insert(L"discoverable", JsonValue::CreateStringValue(L"true"));
            record.Insert(L"backup_eligible", JsonValue::CreateStringValue(L"true"));
            record.Insert(L"backup_state", JsonValue::CreateStringValue(L"false"));
            record.Insert(L"counter_mode", JsonValue::CreateStringValue(L"synced_zero"));
            record.Insert(L"sign_count", JsonValue::CreateStringValue(L"0"));
            SYSTEMTIME now{}; GetSystemTime(&now); wchar_t createdAt[25]{};
            THROW_HR_IF(E_UNEXPECTED, swprintf_s(createdAt, L"%04u-%02u-%02uT%02u:%02u:%02uZ", now.wYear, now.wMonth,
                now.wDay, now.wHour, now.wMinute, now.wSecond) <= 0);
            record.Insert(L"created_at", JsonValue::CreateStringValue(createdAt));
            record.Insert(L"last_used_at", JsonValue::CreateStringValue(L""));
            fae::vault::passkeys::VaultBrokerClient broker;
            broker.CommitCreated(record);

            WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS cached{};
            cached.cbCredentialId = static_cast<DWORD>(vCredentialIdBuffer.size()); cached.pbCredentialId = vCredentialIdBuffer.data();
            cached.pwszRpId = pDecodedMakeCredentialRequest->pRpInformation->pwszId;
            cached.pwszRpName = pDecodedMakeCredentialRequest->pRpInformation->pwszName;
            cached.cbUserId = pDecodedMakeCredentialRequest->pUserInformation->cbId;
            cached.pbUserId = pDecodedMakeCredentialRequest->pUserInformation->pbId;
            cached.pwszUserName = pDecodedMakeCredentialRequest->pUserInformation->pwszName;
            cached.pwszUserDisplayName = pDecodedMakeCredentialRequest->pUserInformation->pwszDisplayName;
            THROW_IF_FAILED(WebAuthNPluginAuthenticatorAddCredentials(vault_plugin_guid, 1, &cached));

            response->cbEncodedResponse = cbAttestationBuffer;
            response->pbEncodedResponse = pbAttestationBuffer.release();
            return S_OK;
        }
        catch (...)
        {
            hr = wil::ResultFromCaughtException();
            return hr;
        }
    }

    /*
    * This function is invoked by the platform to request the plugin to handle a get assertion operation.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl
    */
    HRESULT STDMETHODCALLTYPE ContosoPlugin::GetAssertion(
        /* [in] */ __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST pPluginGetAssertionRequest,
        /* [out] */ __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept
    {
        HRESULT hr = S_OK;
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, response);
            *response = {};
            RETURN_HR_IF_NULL(E_INVALIDARG, pPluginGetAssertionRequest);

            bool expected = false;
            if (!m_operationInProgress.compare_exchange_strong(expected, true))
            {
                return HRESULT_FROM_WIN32(ERROR_BUSY); // Another operation is running.
            }
            // Ensure the flag is cleared when the function exits, for any reason.
            auto clearOperationInProgress = wil::scope_exit([&]
            {
                m_operationInProgress = false;
            });
            { std::lock_guard lock(m_transactionMutex); m_transactionId = pPluginGetAssertionRequest->transactionId; }
            auto completePluginOperation = wil::SetEvent_scope_exit(this->m_hPluginOpCompletedEvent.get());

            // WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST: This structure represents the decoded CTAP get assertion request.
            // Provides structured access to authentication parameters including RP ID, allowed credentials, and client
            // data hash for plugin processing.
            PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST pDecodedAssertionRequest;

            THROW_IF_FAILED(WebAuthNDecodeGetAssertionRequest(
                pPluginGetAssertionRequest->cbEncodedRequest, 
                pPluginGetAssertionRequest->pbEncodedRequest, 
                &pDecodedAssertionRequest));

            auto cleanup = wil::scope_exit([&] {
                WebAuthNFreeDecodedGetAssertionRequest(pDecodedAssertionRequest);
            });

            wil::shared_cotaskmem_string rpName = wil::make_cotaskmem_string(pDecodedAssertionRequest->pwszRpId);

            // Resolve only Vault-owned, usable credentials through the protected broker.
            std::vector<std::vector<uint8_t>> allowCredentialIds;
            allowCredentialIds.reserve(pDecodedAssertionRequest->CredentialList.cCredentials);
            for (DWORD index = 0; index < pDecodedAssertionRequest->CredentialList.cCredentials; ++index)
            {
                auto allowed = pDecodedAssertionRequest->CredentialList.ppCredentials[index];
                if (allowed && allowed->pbId && allowed->cbId)
                    allowCredentialIds.emplace_back(allowed->pbId, allowed->pbId + allowed->cbId);
            }
            fae::vault::passkeys::VaultBrokerClient broker;
            auto brokerCredentials = broker.List(pDecodedAssertionRequest->pwszRpId, allowCredentialIds);
            std::vector<WEBAUTHN_RP_ENTITY_INFORMATION> rpEntities(brokerCredentials.size());
            std::vector<WEBAUTHN_USER_ENTITY_INFORMATION> userEntities(brokerCredentials.size());
            std::vector<WEBAUTHN_CREDENTIAL_DETAILS> credentialDetails(brokerCredentials.size());
            const WEBAUTHN_CREDENTIAL_DETAILS* selectedCredential = nullptr;
            std::vector<const WEBAUTHN_CREDENTIAL_DETAILS*> selectedCredentials;
            selectedCredentials.reserve(brokerCredentials.size());
            for (size_t index = 0; index < brokerCredentials.size(); ++index)
            {
                auto& source = brokerCredentials[index];
                auto& rp = rpEntities[index];
                rp.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
                rp.pwszId = source.rpId.data(); rp.pwszName = source.rpId.data();
                auto& user = userEntities[index];
                user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
                user.cbId = static_cast<DWORD>(source.userId.size()); user.pbId = source.userId.data();
                user.pwszName = source.userName.data(); user.pwszDisplayName = source.userDisplayName.data();
                auto& detail = credentialDetails[index];
                detail.dwVersion = WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION;
                detail.cbCredentialID = static_cast<DWORD>(source.credentialId.size()); detail.pbCredentialID = source.credentialId.data();
                detail.pRpInformation = &rp; detail.pUserInformation = &user;
                selectedCredentials.push_back(&detail);
            }

            if (selectedCredentials.empty())
            {
                THROW_HR(NTE_NOT_FOUND);
            }
            else if (selectedCredentials.size() == 1)
            {
                selectedCredential = selectedCredentials[0];
            }
            else { selectedCredential = selectedCredentials.front(); }

            wil::shared_cotaskmem_string userName = wil::make_cotaskmem_string(selectedCredential->pUserInformation->pwszName);

            std::vector<BYTE> requestBuffer(
                pPluginGetAssertionRequest->pbEncodedRequest,
                pPluginGetAssertionRequest->pbEncodedRequest + pPluginGetAssertionRequest->cbEncodedRequest);

            auto pubKeyData = GetRequestSigningPubKey();
            HRESULT requestSignResult = E_FAIL;
            if (!pubKeyData.empty())
            {
                requestSignResult = VerifySignatureHelper(
                    requestBuffer,
                    pubKeyData.data(),
                    static_cast<DWORD>(pubKeyData.size()),
                    pPluginGetAssertionRequest->pbRequestSignature,
                    pPluginGetAssertionRequest->cbRequestSignature);
            }

            THROW_IF_FAILED(requestSignResult);

            hr = PerformUserVerification(
                pPluginGetAssertionRequest->hWnd,
                pPluginGetAssertionRequest->transactionId,
                PluginOperationType::GetAssertion,
                requestBuffer,
                rpName,
                userName);
            THROW_IF_FAILED(hr);

            std::vector<uint8_t> vCredentialIdBuffer(
                selectedCredential->pbCredentialID,
                selectedCredential->pbCredentialID + selectedCredential->cbCredentialID);
            auto material = broker.Get(pDecodedAssertionRequest->pwszRpId, vCredentialIdBuffer);
            fae::vault::passkeys::SecureBuffer privateKey(
                fae::vault::passkeys::VaultBrokerClient::DecodeBase64Url(material.record.GetNamedString(L"private_key").c_str()));
            material.record.Remove(L"private_key");
            auto packedAuthenticatorData = fae::vault::passkeys::BuildAuthenticatorData(
                std::span<const uint8_t>(pDecodedAssertionRequest->pbRpId, pDecodedAssertionRequest->cbRpId), false);
            auto signature = fae::vault::passkeys::SignAssertion(
                privateKey.view(),
                packedAuthenticatorData,
                std::span<const uint8_t>(pDecodedAssertionRequest->pbClientDataHash, pDecodedAssertionRequest->cbClientDataHash));

            auto assertionResponse = wil::make_unique_cotaskmem<WEBAUTHN_ASSERTION>();
            THROW_HR_IF_NULL(E_OUTOFMEMORY, assertionResponse);

            assertionResponse->dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;

            // [1] Credential (optional)
            assertionResponse->Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            assertionResponse->Credential.cbId = static_cast<DWORD>(vCredentialIdBuffer.size());
            assertionResponse->Credential.pbId = vCredentialIdBuffer.data();
            assertionResponse->Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

            // [2] AuthenticatorData
            assertionResponse->cbAuthenticatorData = static_cast<DWORD>(packedAuthenticatorData.size());
            assertionResponse->pbAuthenticatorData = packedAuthenticatorData.data();

            // [3] Signature
            assertionResponse->cbSignature = static_cast<DWORD>(signature.size());
            assertionResponse->pbSignature = signature.data();

            // [4] User (optional)
            assertionResponse->cbUserId = selectedCredential->pUserInformation->cbId;
            auto userIdBuffer = wil::make_unique_cotaskmem<BYTE[]>(selectedCredential->pUserInformation->cbId);
            THROW_HR_IF_NULL(E_OUTOFMEMORY, userIdBuffer);

            memcpy_s(userIdBuffer.get(),
                selectedCredential->pUserInformation->cbId,
                selectedCredential->pUserInformation->pbId,
                selectedCredential->pUserInformation->cbId);
            assertionResponse->pbUserId = userIdBuffer.get();

            WEBAUTHN_USER_ENTITY_INFORMATION userEntityInformation = {};
            userEntityInformation.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
            userEntityInformation.cbId = assertionResponse->cbUserId;
            userEntityInformation.pbId = assertionResponse->pbUserId;

            // WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE: This structure represents the complete get assertion
            // response including WebAuthn assertion, user information, and credential count.
            // Used for encoding into CBOR format for platform consumption.
            auto ctapGetAssertionResponse = wil::make_unique_cotaskmem<WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE>();
            THROW_HR_IF_NULL(E_OUTOFMEMORY, ctapGetAssertionResponse);

            ctapGetAssertionResponse->WebAuthNAssertion = *(assertionResponse.get()); // [1] Credential, [2] AuthenticatorData, [3] Signature
            ctapGetAssertionResponse->pUserInformation = &userEntityInformation; // [4] User
            ctapGetAssertionResponse->dwNumberOfCredentials = 1; // [5] NumberOfCredentials

            DWORD cbAssertionBuffer = 0;
            wil::unique_cotaskmem_ptr<BYTE[]> pbAssertionBuffer;

            // PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE: Pointer to get assertion response
            // structure used for encoding operations. Provides const access to response data.
            THROW_IF_FAILED(WebAuthNEncodeGetAssertionResponse(
                (PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE)(ctapGetAssertionResponse.get()),
                &cbAssertionBuffer,
                wil::out_param(pbAssertionBuffer)));

            // Usage metadata is non-security-critical; never invalidate a valid signature if this retryable write fails.
            try { broker.CommitUse(pDecodedAssertionRequest->pwszRpId, vCredentialIdBuffer); }
            catch (...) { LOG_CAUGHT_EXCEPTION(); }

            response->cbEncodedResponse = cbAssertionBuffer;
            response->pbEncodedResponse = pbAssertionBuffer.release();
            return S_OK;
        }
        catch (...)
        {
            hr = wil::ResultFromCaughtException();
            return hr;
        }
    }

    /*
    * This function is invoked by the platform to fetch the state of the plugin's vault
    */
    HRESULT STDMETHODCALLTYPE ContosoPlugin::GetLockStatus(
        /* [out] */ __RPC__out PLUGIN_LOCK_STATUS* vaultState) noexcept
    {
        RETURN_HR_IF_NULL(E_INVALIDARG, vaultState);
        *vaultState = fae::vault::passkeys::VaultBrokerClient().IsUnlocked() ? PluginUnlocked : PluginLocked;
        return S_OK;
    }

    /*
    * This function is invoked by the platform to request the plugin to cancel an ongoing operation.
    */
    HRESULT STDMETHODCALLTYPE ContosoPlugin::CancelOperation(
        /* [out] */ __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST pCancelRequest)
    {
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, pCancelRequest);

            { std::lock_guard lock(m_transactionMutex); RETURN_HR_IF(NTE_NOT_FOUND, m_transactionId != pCancelRequest->transactionId); }
            SetEvent(m_hPluginOpCompletedEvent.get());
            SetEvent(m_hPluginCancelOperationEvent.get());
            return S_OK;
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    /*
    * This is a sample implementation of a factory method that creates an instance of the Class that implements
    * the IPluginAuthenticator interface. The IPluginAuthenticator interface is the core COM interface that
    * third-party passkey authenticator plugins must implement for Windows. This interface enables plugins to
    * participate in WebAuthn operations by handling make credential, get assertion, lock status, and operation
    * cancellation requests.
    * Refer: pluginauthenticator.h/pluginauthenticator.idl for the interface definition.
    */
    HRESULT __stdcall ContosoPluginFactory::CreateInstance(
        ::IUnknown* outer,
        GUID const& iid,
        void** result) noexcept
    {
        try
        {
            RETURN_HR_IF_NULL(E_INVALIDARG, result);
            *result = nullptr;

            if (outer)
            {
                return CLASS_E_NOAGGREGATION;
            }

            return make<ContosoPlugin>(m_hPluginOpCompletedEvent, m_hAppReadyForPluginOpEvent, m_hPluginCancelOperationEvent)->QueryInterface(iid, result);
        }
        catch (...)
        {
            return winrt::to_hresult();
        }
    }

    HRESULT __stdcall ContosoPluginFactory::LockServer(BOOL) noexcept
    {
        return S_OK;
    }
}
