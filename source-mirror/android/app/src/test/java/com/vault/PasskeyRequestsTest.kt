package com.vault

import com.vault.passkeys.PasskeyRequests
import com.vault.passkeys.UserVerificationRequirement
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class PasskeyRequestsTest {
    @Test
    fun createSelectsEs256AndCollectsOptions() {
        val parsed = PasskeyRequests.parseCreate(
            """
            {
              "challenge":"${base64Url("create challenge")}",
              "rp":{"id":"EXAMPLE.COM","name":"Example"},
              "user":{"id":"${base64Url("user-123")}","name":"alice","displayName":"Alice"},
              "pubKeyCredParams":[
                {"type":"public-key","alg":-257},
                {"type":"public-key","alg":-7}
              ],
              "excludeCredentials":[
                {"type":"public-key","id":"${base64Url("existing credential")}"}
              ],
              "authenticatorSelection":{
                "residentKey":"required",
                "userVerification":"required"
              }
            }
            """.trimIndent(),
        )

        assertEquals("example.com", parsed.rpId)
        assertEquals("Example", parsed.rpName)
        assertArrayEquals("user-123".toByteArray(), parsed.userId)
        assertEquals("alice", parsed.userName)
        assertEquals("Alice", parsed.userDisplayName)
        assertArrayEquals("create challenge".toByteArray(), parsed.challenge)
        assertEquals(-7, parsed.algorithm)
        assertEquals(setOf(base64Url("existing credential")), parsed.excludeCredentialIds)
        assertTrue(parsed.residentKeyRequired)
        assertEquals(UserVerificationRequirement.REQUIRED, parsed.userVerification)
        assertFalse(parsed.credentialPropertiesRequested)
    }

    @Test
    fun discoverableGetHasNoAllowList() {
        val parsed = PasskeyRequests.parseGet(
            """
            {
              "challenge":"${base64Url("get challenge")}",
              "rpId":"bücher.example",
              "userVerification":"discouraged"
            }
            """.trimIndent(),
        )

        assertEquals("xn--bcher-kva.example", parsed.rpId)
        assertArrayEquals("get challenge".toByteArray(), parsed.challenge)
        assertTrue(parsed.allowCredentialIds.isEmpty())
        assertEquals(UserVerificationRequirement.DISCOURAGED, parsed.userVerification)
    }

    @Test
    fun getCollectsAllowCredentialsAndDefaultsUserVerification() {
        val first = base64Url("first credential")
        val second = base64Url("second credential")
        val parsed = PasskeyRequests.parseGet(
            """
            {
              "challenge":"${base64Url("get challenge")}",
              "rpId":"login.example.com",
              "allowCredentials":[
                {"type":"public-key","id":"$first","transports":["internal"]},
                {"type":"public-key","id":"$second"}
              ]
            }
            """.trimIndent(),
        )

        assertEquals(setOf(first, second), parsed.allowCredentialIds)
        assertEquals(UserVerificationRequirement.PREFERRED, parsed.userVerification)
        assertFalse(parsed.toString().contains(first))
    }

    @Test
    fun createSupportsWebAuthnRequireResidentKeyAndDefaults() {
        val required = PasskeyRequests.parseCreate(
            validCreateJson(
                selection = """"authenticatorSelection":{"requireResidentKey":true}""",
            ),
        )
        val defaults = PasskeyRequests.parseCreate(validCreateJson())

        assertTrue(required.residentKeyRequired)
        assertEquals(UserVerificationRequirement.PREFERRED, required.userVerification)
        assertFalse(defaults.residentKeyRequired)
        assertEquals(UserVerificationRequirement.PREFERRED, defaults.userVerification)
    }

    @Test
    fun rejectsUnsupportedOrMalformedAlgorithms() {
        val unsupported = validCreateJson(
            algorithms = """[{"type":"public-key","alg":-256}]""",
        )
        val wrongType = validCreateJson(
            algorithms = """[{"type":"not-public-key","alg":-7}]""",
        )
        val stringAlgorithm = validCreateJson(
            algorithms = """[{"type":"public-key","alg":"-7"}]""",
        )

        assertInvalid(unsupported)
        assertInvalid(wrongType)
        assertInvalid(stringAlgorithm)
    }

    @Test
    fun rejectsEmptyMalformedAndOversizedChallenges() {
        val invalidChallenges = listOf(
            "",
            "A",
            "not+base64",
            base64Url(ByteArray(1_025) { 1 }),
        )

        invalidChallenges.forEach { challenge ->
            assertInvalid(validCreateJson(challenge = challenge))
            assertInvalidGet(validGetJson(challenge = challenge))
        }
    }

    @Test
    fun rejectsEmptyMalformedAndOversizedUserHandles() {
        val invalidUserHandles = listOf(
            "",
            "A",
            "not/base64",
            base64Url(ByteArray(65) { 2 }),
        )

        invalidUserHandles.forEach { userId ->
            assertInvalid(validCreateJson(userId = userId))
        }
    }

    @Test
    fun acceptsPaddedBase64UrlUserHandleForCredentialManagerCompatibility() {
        val parsed = PasskeyRequests.parseCreate(validCreateJson(userId = "dXNlcg=="))
        assertArrayEquals("user".toByteArray(), parsed.userId)
    }

    @Test
    fun rejectsEmptyMalformedAndOversizedCredentialIds() {
        val invalidIds = listOf(
            "",
            "A",
            "not+base64",
            base64Url(ByteArray(1_024) { 3 }),
        )

        invalidIds.forEach { id ->
            assertInvalid(
                validCreateJson(
                    extra = """"excludeCredentials":[{"type":"public-key","id":"$id"}]""",
                ),
            )
            assertInvalidGet(
                validGetJson(
                    extra = """"allowCredentials":[{"type":"public-key","id":"$id"}]""",
                ),
            )
        }
    }

    @Test
    fun acceptsPaddedBase64UrlAndCanonicalizesCredentialIds() {
        val create = PasskeyRequests.parseCreate(
            validCreateJson(
                challenge = "YQ==",
                extra = """"excludeCredentials":[{"type":"public-key","id":"YQ=="}]""",
            ),
        )
        val get = PasskeyRequests.parseGet(
            validGetJson(
                challenge = "YQ==",
                extra = """"allowCredentials":[{"type":"public-key","id":"YQ=="}]""",
            ),
        )
        assertArrayEquals(byteArrayOf('a'.code.toByte()), create.challenge)
        assertEquals(setOf("YQ"), create.excludeCredentialIds)
        assertEquals(setOf("YQ"), get.allowCredentialIds)
    }

    @Test
    fun rejectsDuplicateCredentialIdsAcrossPaddedAndUnpaddedForms() {
        assertInvalid(
            validCreateJson(
                extra = """"excludeCredentials":[{"type":"public-key","id":"YQ"},{"type":"public-key","id":"YQ=="}]""",
            ),
        )
    }

    @Test
    fun rejectsDuplicateCredentialIds() {
        val id = base64Url("same credential")
        assertInvalid(
            validCreateJson(
                extra =
                    """"excludeCredentials":[{"type":"public-key","id":"$id"},{"type":"public-key","id":"$id"}]""",
            ),
        )
        assertInvalidGet(
            validGetJson(
                extra =
                    """"allowCredentials":[{"type":"public-key","id":"$id"},{"type":"public-key","id":"$id"}]""",
            ),
        )
    }

    @Test
    fun rejectsMalformedCredentialDescriptors() {
        assertInvalid(
            validCreateJson(
                extra = """"excludeCredentials":[{"type":"password","id":"${base64Url("id")}"}]""",
            ),
        )
        assertInvalidGet(
            validGetJson(
                extra = """"allowCredentials":[{"type":"public-key","id":"${base64Url("id")}","transports":["internal","internal"]}]""",
            ),
        )
        assertInvalidGet(
            validGetJson(extra = """"allowCredentials":{}"""),
        )
    }

    @Test
    fun rejectsRequiredUnsupportedExtensionsButAllowsAdvisoryExtensions() {
        assertInvalid(
            validCreateJson(
                extra = """"extensions":{"largeBlob":{"support":"required"}}""",
            ),
        )
        assertInvalidGet(
            validGetJson(
                extra = """"extensions":{"futureExtension":{"required":true,"opaque":"value"}}""",
            ),
        )

        val parsed = PasskeyRequests.parseCreate(
            validCreateJson(
                extra = """"extensions":{"credProps":true,"largeBlob":{"support":"preferred"}}""",
            ),
        )
        assertEquals("example.com", parsed.rpId)
        assertTrue(parsed.credentialPropertiesRequested)
        assertInvalid(
            validCreateJson(extra = """"extensions":{"credProps":"true"}"""),
        )
    }

    @Test
    fun normalizesInternationalAndAbsoluteRpIds() {
        val international = PasskeyRequests.parseGet(validGetJson(rpId = "BÜCHER.EXAMPLE"))
        val absolute = PasskeyRequests.parseGet(validGetJson(rpId = "Login.Example.COM."))

        assertEquals("xn--bcher-kva.example", international.rpId)
        assertEquals("login.example.com", absolute.rpId)
    }

    @Test
    fun rejectsUnsafeRpIdForms() {
        val invalidRpIds = listOf(
            "",
            "localhost",
            "login.localhost",
            "127.0.0.1",
            "[2001:db8::1]",
            "https://example.com",
            "user@example.com",
            "example.com:443",
            "example.com/path",
            "example.com?query",
            "example.com#fragment",
            " example.com",
            "example.com ",
            "example..com",
            "-bad.example.com",
            "bad-.example.com",
            "bad_name.example.com",
            "a".repeat(64) + ".example.com",
            listOf("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62)).joinToString("."),
            "com",
            "co.uk",
        )

        invalidRpIds.forEach { rpId ->
            assertInvalid(validCreateJson(rpId = rpId))
            assertInvalidGet(validGetJson(rpId = rpId))
        }
    }

    @Test
    fun rejectsMissingEmptyOrOverlongNames() {
        assertInvalid(validCreateJson(rpName = ""))
        assertInvalid(validCreateJson(userName = ""))
        assertInvalid(validCreateJson(displayName = " "))
        assertInvalid(validCreateJson(rpName = "é".repeat(33)))
        assertInvalid(validCreateJson(userName = "a".repeat(65)))
        assertInvalid(validCreateJson(displayName = "Alice\u0000Admin"))
    }

    @Test
    fun rejectsInvalidResidentKeyAndUserVerificationValues() {
        assertInvalid(
            validCreateJson(
                selection = """"authenticatorSelection":{"residentKey":"sometimes"}""",
            ),
        )
        assertInvalid(
            validCreateJson(
                selection =
                    """"authenticatorSelection":{"residentKey":"preferred","requireResidentKey":true}""",
            ),
        )
        assertInvalid(
            validCreateJson(
                selection = """"authenticatorSelection":{"userVerification":"always"}""",
            ),
        )
        assertInvalidGet(validGetJson(userVerification = "always"))
        assertInvalid(
            validCreateJson(
                selection = """"authenticatorSelection":{"authenticatorAttachment":"cross-platform"}""",
            ),
        )
    }

    @Test
    fun boundsRequestByUtf8ByteSize() {
        val oversizedCreate = validCreateJson(
            extra = """"ignored":"${"界".repeat(50_000)}"""",
        )
        val oversizedGet = validGetJson(
            extra = """"ignored":"${"界".repeat(50_000)}"""",
        )

        assertTrue(oversizedCreate.length < 131_072)
        assertInvalid(oversizedCreate)
        assertInvalidGet(oversizedGet)
    }

    @Test
    fun requestObjectsDefensivelyCopyByteArraysAndHaveContentEquality() {
        val first = PasskeyRequests.parseCreate(validCreateJson())
        val same = PasskeyRequests.parseCreate(validCreateJson())
        val different = PasskeyRequests.parseCreate(
            validCreateJson(challenge = base64Url("different challenge")),
        )
        val exposedUserId = first.userId
        val exposedChallenge = first.challenge
        exposedUserId.fill(0)
        exposedChallenge.fill(0)

        assertArrayEquals("user".toByteArray(), first.userId)
        assertArrayEquals("challenge".toByteArray(), first.challenge)
        assertEquals(first, same)
        assertEquals(first.hashCode(), same.hashCode())
        assertNotEquals(first, different)
    }

    @Test
    fun credentialSetsAreImmutableAndRepresentationsAreRedacted() {
        val credentialId = base64Url("credential-secret-marker")
        val create = PasskeyRequests.parseCreate(
            validCreateJson(
                userId = base64Url("user-secret-marker"),
                challenge = base64Url("challenge-secret-marker"),
                extra = """"excludeCredentials":[{"type":"public-key","id":"$credentialId"}]""",
            ),
        )
        val get = PasskeyRequests.parseGet(
            validGetJson(
                challenge = base64Url("challenge-secret-marker"),
                extra = """"allowCredentials":[{"type":"public-key","id":"$credentialId"}]""",
            ),
        )

        @Suppress("UNCHECKED_CAST")
        assertThrows(UnsupportedOperationException::class.java) {
            (create.excludeCredentialIds as MutableSet<String>).add(base64Url("new id"))
        }
        @Suppress("UNCHECKED_CAST")
        assertThrows(UnsupportedOperationException::class.java) {
            (get.allowCredentialIds as MutableSet<String>).clear()
        }
        listOf(create.toString(), get.toString()).forEach { representation ->
            assertFalse(representation.contains("secret-marker"))
            assertFalse(representation.contains(credentialId))
        }
    }

    @Test
    fun failuresDoNotEchoRawRequestSecrets() {
        val secret = "raw-secret-challenge+"
        val createError = assertThrows(IllegalArgumentException::class.java) {
            PasskeyRequests.parseCreate(validCreateJson(challenge = secret))
        }
        val malformedJsonSecret = "malformed-secret-marker"
        val jsonError = assertThrows(IllegalArgumentException::class.java) {
            PasskeyRequests.parseGet("""{"challenge":"$malformedJsonSecret"""")
        }

        assertFalse(createError.message.orEmpty().contains(secret))
        assertFalse(jsonError.message.orEmpty().contains(malformedJsonSecret))
    }

    @Test
    fun createSupportsRsaAndEd25519Algorithms() {
        val rsa = PasskeyRequests.parseCreate(
            validCreateJson(
                algorithms = """[{"type":"public-key","alg":-257}]""",
            ),
        )
        assertEquals(-257, rsa.algorithm)

        val eddsa = PasskeyRequests.parseCreate(
            validCreateJson(
                algorithms = """[{"type":"public-key","alg":-8}]""",
            ),
        )
        assertEquals(-8, eddsa.algorithm)

        val prefersEs256 = PasskeyRequests.parseCreate(
            validCreateJson(
                algorithms = """[{"type":"public-key","alg":-257},{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}]""",
            ),
        )
        assertEquals(-7, prefersEs256.algorithm)

        val rsaOnly = PasskeyRequests.parseCreate(
            validCreateJson(
                algorithms = """[{"type":"public-key","alg":-257},{"type":"public-key","alg":-8}]""",
            ),
        )
        assertEquals(-257, rsaOnly.algorithm)
    }

    @Test
    fun acceptsEnterpriseAttestationPreference() {
        val parsed = PasskeyRequests.parseCreate(
            validCreateJson(extra = """"attestation":"enterprise""""),
        )

        assertEquals("enterprise", parsed.attestation)
    }

    private fun validCreateJson(
        rpId: String = "example.com",
        rpName: String = "Example",
        userId: String = base64Url("user"),
        userName: String = "alice",
        displayName: String = "Alice",
        challenge: String = base64Url("challenge"),
        algorithms: String = """[{"type":"public-key","alg":-7}]""",
        selection: String? = null,
        extra: String? = null,
    ): String = buildList {
        add(""""challenge":"$challenge"""")
        add(""""rp":{"id":"$rpId","name":"$rpName"}""")
        add(""""user":{"id":"$userId","name":"$userName","displayName":"$displayName"}""")
        add(""""pubKeyCredParams":$algorithms""")
        selection?.let(::add)
        extra?.let(::add)
    }.joinToString(prefix = "{", postfix = "}")

    private fun validGetJson(
        rpId: String = "example.com",
        challenge: String = base64Url("challenge"),
        userVerification: String? = null,
        extra: String? = null,
    ): String = buildList {
        add(""""challenge":"$challenge"""")
        add(""""rpId":"$rpId"""")
        userVerification?.let { add(""""userVerification":"$it"""") }
        extra?.let(::add)
    }.joinToString(prefix = "{", postfix = "}")

    private fun assertInvalid(request: String) {
        assertThrows(IllegalArgumentException::class.java) {
            PasskeyRequests.parseCreate(request)
        }
    }

    private fun assertInvalidGet(request: String) {
        assertThrows(IllegalArgumentException::class.java) {
            PasskeyRequests.parseGet(request)
        }
    }

    private fun base64Url(value: String): String =
        base64Url(value.toByteArray())

    private fun base64Url(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)
}
