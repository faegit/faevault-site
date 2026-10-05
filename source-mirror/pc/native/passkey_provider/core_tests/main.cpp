#include "../core/WebAuthnCrypto.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

int main()
{
    using namespace fae::vault::passkeys;
    auto credential = GenerateCredential();
    assert(credential.privateKeyPkcs8.size() > 64);
    assert(credential.publicKeyBlob.size() == sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    assert(credential.publicKeyCose.size() == 77);
    assert(credential.publicKeyCose[0] == 0xA5);

    const std::vector<std::uint8_t> rpId{ 'e','x','a','m','p','l','e','.','c','o','m' };
    auto creationData = BuildAuthenticatorData(rpId, true, credential.credentialId, credential.publicKeyCose);
    assert(creationData.size() == 37 + 16 + 2 + credential.credentialId.size() + credential.publicKeyCose.size());
    assert(creationData[32] == 0x4d);
    assert(creationData[53] == 0 && creationData[54] == credential.credentialId.size());
    auto assertionData = BuildAuthenticatorData(rpId, false);
    assert(assertionData.size() == 37 && assertionData[32] == 0x0d);

    std::vector<std::uint8_t> clientDataHash(32, 0x42);
    auto signature = SignAssertion(credential.privateKeyPkcs8.view(), assertionData, clientDataHash);
    assert(signature.size() >= 70 && signature.size() <= 72);
    assert(VerifyAssertionForTest(credential.publicKeyBlob, assertionData, clientDataHash, signature));
    signature.back() ^= 1;
    assert(!VerifyAssertionForTest(credential.publicKeyBlob, assertionData, clientDataHash, signature));

    auto hash = Sha256(std::span<std::uint8_t const>{});
    constexpr std::uint8_t emptySha256[] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    assert(std::equal(hash.begin(), hash.end(), std::begin(emptySha256)));
    std::cout << "Vault Passkey CNG tests passed\n";
    return 0;
}
