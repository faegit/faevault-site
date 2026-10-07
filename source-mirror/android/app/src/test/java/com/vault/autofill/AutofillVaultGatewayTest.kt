package com.vault.autofill

import com.vault.model.withEntryModules

import com.vault.crypto.VaultCrypto
import com.vault.model.Entry
import com.vault.model.AutofillExclusions
import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.EntryModules
import com.vault.model.PasskeyRecord
import com.vault.model.SecretType
import com.vault.model.VaultPayload
import com.vault.model.entryModules
import com.vault.model.withAutofillLinks
import com.vault.model.withEntryModules
import com.vault.model.autofill.AutofillRole
import com.vault.passkeys.PasskeyMutationResult
import com.vault.passkeys.PasskeyRepository
import com.vault.passkeys.PasskeyRequests
import com.vault.storage.VaultCodec
import com.vault.storage.VaultEntrySummary
import com.vault.storage.VaultFileFormat
import com.vault.storage.VaultIdentity
import com.vault.storage.VaultQuerySession
import com.vault.storage.VaultStaleMutationException
import com.vault.security.VaultKeyIdentity
import java.io.File
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillVaultGatewayTest {
    @Test
    fun authenticatesAndReturnsOnlyOriginMatches() {
        val source = FakeSource(
            VaultPayload(entries = listOf(entry("one", "https://example.com"), entry("two", "https://other.com"))),
        )
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)

        val auth = gateway.authenticate("main", "master".toCharArray())
        assertTrue(auth is VaultAuthResult.Success)
        val session = (auth as VaultAuthResult.Success).session

        assertEquals(
            listOf("one"),
            gateway.findMatches(session, TargetOrigin.Web("example.com")).map { it.entryId },
        )
    }

    @Test
    fun wrongPasswordRecordsFailure() {
        val policy = RecordingAttemptPolicy()
        val gateway = AutofillVaultGateway(FakeSource(VaultPayload()), policy)

        val result = gateway.authenticate("main", "wrong".toCharArray())

        assertTrue(result is VaultAuthResult.WrongPassword)
        assertEquals(1, policy.failures)
    }

    @Test
    fun createAndUpdatePreservePayloadAndEntryFields() {
        val original = entry("one", "https://example.com").copy(notes = "keep", tags = listOf("tag"), updatedAt = 4.0)
        val source = FakeSource(VaultPayload(version = 2, entries = listOf(original)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 }, idFactory = { "new" })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(
            gateway.updateLogin(session, "one", 4.0, "alice2", "new-password") is VaultWriteResult.Success,
        )
        val updated = source.payload.entries.first { it.id == "one" }
        assertEquals("keep", updated.notes)
        assertEquals(listOf("tag"), updated.tags)
        assertEquals("alice2", updated.username)
        assertEquals(2, source.payload.version)

        assertTrue(
            gateway.createLogin(
                session,
                TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64))),
                "bob",
                "pw",
            ) is VaultWriteResult.Success,
        )
        val created = source.payload.entries.first { it.id == "new" }
        assertEquals("com.example.app", created.url)
        assertEquals("com.example.app", created.targetApp)
        assertTrue(created.fields.containsKey(AutofillOriginMetadata.FIELD_KEY))
    }

    @Test
    fun `generated empty username login stays discoverable and later autofill save updates it`() {
        val source = FakeSource(VaultPayload())
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, idFactory = { "generated" })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        // “生成密码并填充”路径：空用户名 + 生成密码写入登录条目暂存
        assertTrue(
            gateway.createLogin(session, TargetOrigin.Web("example.com"), "", "GenP@ss1!") is VaultWriteResult.Success,
        )
        val created = source.payload.entries.single()
        assertEquals("generated", created.id)
        assertEquals("", created.username)
        assertEquals("GenP@ss1!", created.password)

        // 条目按来源可被发现，供后续填充/保存定位
        assertTrue(gateway.findMatches(session, TargetOrigin.Web("example.com")).any { it.entryId == "generated" })

        // 用户后续提交表单（可能改了用户名/密码）→ autofill 保存/更新机制更新该条目
        assertTrue(
            gateway.updateLogin(
                session,
                "generated",
                created.updatedAt,
                "real-user",
                "Changed-Pw-2!",
            ) is VaultWriteResult.Success,
        )
        val updated = source.payload.entries.single()
        assertEquals("real-user", updated.username)
        assertEquals("Changed-Pw-2!", updated.password)
    }

    @Test
    fun staleUpdateIsRejected() {
        val source = FakeSource(VaultPayload(entries = listOf(entry("one", "https://example.com").copy(updatedAt = 8.0))))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(gateway.updateLogin(session, "one", 7.0, "u", "p") is VaultWriteResult.Stale)
    }

    @Test
    fun diskChangeAfterAuthenticationIsNotOverwritten() {
        val original = entry("one", "https://example.com").copy(updatedAt = 1.0)
        val source = FakeSource(VaultPayload(entries = listOf(original)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        source.payload = source.payload.copy(
            entries = listOf(original.copy(password = "newer", updatedAt = 2.0, notes = "external change")),
        )

        assertTrue(gateway.credential(session, "one", 1.0) == null)
        assertTrue(gateway.updateLogin(session, "one", 1.0, "u", "old") is VaultWriteResult.Stale)
        assertEquals("newer", source.payload.entries.single().password)
    }

    @Test
    fun `pmve query decrypts only indexed candidates and retains parent domain final checks`() {
        val login = entry("11111111-1111-4111-8111-111111111111", "https://example.com")
        val note = login.copy(
            id = "22222222-2222-4222-8222-222222222222",
            secretType = SecretType.SECURE_NOTE,
            password = "must-not-read",
        )
        val query = RecordingQuerySession(mapOf(login.id to login, note.id to note)).apply {
            domainCandidates["login.example.com"] = listOf(login.id)
            domainCandidates["example.com"] = listOf(login.id)
        }
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(listOf(login.id), gateway.findMatches(session, TargetOrigin.Web("login.example.com")).map { it.entryId })
        assertEquals(setOf(login.id), query.readIds.toSet())
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `pmve fast index miss never decrypts the full vault`() {
        // LoginFastIndex 是 PMVE 自动填充的权威路径；缺失索引应由正常保存/迁移重建，
        // 自动填充请求本身不能借兼容名义解密整库。
        val legacyWeb = entry("11111111-1111-4111-8111-111111111111", "http://example.com/login")
        val legacyApp = entry(
            "22222222-2222-4222-8222-222222222222",
            "com.example.legacy.app",
        )
        val query = RecordingQuerySession(emptyMap())
        val source = QuerySource(query).apply {
            fullPayload = VaultPayload(entries = listOf(legacyWeb, legacyApp))
        }
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(gateway.findMatches(session, TargetOrigin.Web("example.com")).isEmpty())
        assertTrue(gateway.findMatches(
            session,
            TargetOrigin.AndroidPackage("com.example.legacy.app", setOf("a".repeat(64))),
        ).isEmpty())
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `fast index hit never materializes the full payload`() {
        val login = entry("11111111-1111-4111-8111-111111111111", "https://example.com")
        val query = RecordingQuerySession(mapOf(login.id to login)).apply {
            domainCandidates["example.com"] = listOf(login.id)
        }
        val source = QuerySource(query).apply {
            fullPayload = VaultPayload(entries = listOf(login))
        }
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(
            listOf(login.id),
            gateway.findMatches(session, TargetOrigin.Web("example.com")).map { it.entryId },
        )
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `pmve passkey query uses rp id index and reads only matching entry`() {
        val fixture = passkeyFixture()
        val passkeyEntry = (PasskeyRepository.add(
            VaultPayload(),
            entry("33333333-3333-4333-8333-333333333333", "https://example.com")
                .copy(secretType = SecretType.PASSKEY),
            fixture,
        ) as PasskeyMutationResult.Success).entry
        val unrelated = entry("44444444-4444-4444-8444-444444444444", "https://other.example")
        val query = RecordingQuerySession(mapOf(passkeyEntry.id to passkeyEntry, unrelated.id to unrelated)).apply {
            rpCandidates[fixture.rpId] = listOf(passkeyEntry.id)
        }
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val request = PasskeyRequests.parseGet(
            """{"challenge":"Y2hhbGxlbmdl","rpId":"${fixture.rpId}"}""",
        )

        assertEquals(listOf(fixture.credentialId), gateway.findPasskeys(session, request).map { it.record.credentialId })
        assertEquals(listOf(passkeyEntry.id), query.readIds)
    }

    @Test
    fun `pmve device root key opens format neutral query without full payload`() {
        val login = entry("55555555-5555-4555-8555-555555555555", "https://example.com")
        val query = RecordingQuerySession(mapOf(login.id to login)).apply {
            domainCandidates["example.com"] = listOf(login.id)
        }
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)

        val identity = requireNotNull(query.identity)
        val binding = VaultKeyIdentity(identity.vaultId, identity.keyRevision, identity.signingPublicKey)
        val session = (gateway.authenticateWithDeviceKey(
            "main",
            ByteArray(32) { 7 },
            binding,
        ) as VaultAuthResult.Success).session

        assertEquals(listOf(login.id), gateway.findMatches(session, TargetOrigin.Web("example.com")).map { it.entryId })
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `pmve candidate list never reads unrelated login entries`() {
        val wanted = entry("66666666-6666-4666-8666-666666666666", "https://example.com")
        val unrelated = entry("77777777-7777-4777-8777-777777777777", "https://other.example")
        val query = RecordingQuerySession(mapOf(wanted.id to wanted, unrelated.id to unrelated)).apply {
            domainCandidates["example.com"] = listOf(wanted.id)
        }
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(listOf(wanted.id), gateway.findMatchingEntries(session, TargetOrigin.Web("example.com")).map { it.id })
        assertEquals(listOf(wanted.id), query.readIds)
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `web lookup delegates parent domain expansion to the login index once`() {
        val query = RecordingQuerySession(emptyMap())
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        gateway.findMatchingEntries(session, TargetOrigin.Web("login.example.com"))

        assertEquals(listOf("login.example.com"), query.queriedDomains)
    }

    @Test
    fun `pmve package candidates exclude entries without signer metadata`() {
        val origin = TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64)))
        val signed = entry("signed", "com.example.app").copy(
            fields = mapOf(
                AutofillOriginMetadata.FIELD_KEY to AutofillOriginMetadata.from(origin),
            ),
        )
        val legacy = entry("legacy", "com.example.app")
        val query = RecordingQuerySession(mapOf(signed.id to signed, legacy.id to legacy)).apply {
            packageCandidates["com.example.app"] = listOf(signed.id, legacy.id)
        }
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(listOf(signed.id), gateway.findMatchingEntries(session, origin).map { it.id })
    }

    @Test
    fun `explicitly selected legacy package login can be upgraded to a verified binding`() {
        val origin = TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64)))
        val legacy = entry("legacy", "com.example.app").copy(targetApp = "com.example.app")
        val source = FakeSource(VaultPayload(entries = listOf(legacy)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(gateway.findMatches(session, origin).isEmpty())
        assertTrue(gateway.upgradeLegacyAndroidBinding(session, legacy.id, origin) is VaultWriteResult.Success)
        assertEquals(listOf(legacy.id), gateway.findMatches(session, origin).map { it.entryId })
    }

    @Test
    fun `pmve device root key rejects an envelope bound to another vault identity`() {
        val query = RecordingQuerySession(emptyMap())
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val wrong = VaultKeyIdentity(
            UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            1,
            ByteArray(32) { 1 },
        )

        val result = gateway.authenticateWithDeviceKey("main", ByteArray(32) { 7 }, wrong)

        assertTrue(result is VaultAuthResult.Failure)
    }

    @Test
    fun `pmve expected sequence conflict is returned as stale`() {
        val query = RecordingQuerySession(emptyMap())
        val source = QuerySource(query).apply { staleMutation = true }
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        val result = gateway.createLogin(
            session,
            TargetOrigin.Web("example.com"),
            username = "alice",
            password = "secret",
        )

        assertTrue(result is VaultWriteResult.Stale)
    }

    @Test
    fun `finds otp entries by origin url or issuer for two factor pages`() {
        val loginOtp = entry("11111111-1111-4111-8111-111111111111", "https://example.com").copy(
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val standalone = Entry(
            id = "22222222-2222-4222-8222-222222222222",
            title = "Example OTP",
            username = "alice",
            url = "",
            secretType = SecretType.OTP,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "issuer" to JsonPrimitive("example"),
            ),
        )
        val deleted = standalone.copy(id = "44444444-4444-4444-8444-444444444444", deletedAt = 5.0)
        val unrelated = Entry(
            id = "33333333-3333-4333-8333-333333333333",
            title = "Other OTP",
            url = "",
            secretType = SecretType.OTP,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "issuer" to JsonPrimitive("elsewhere"),
            ),
        )
        val source = FakeSource(
            VaultPayload(entries = listOf(loginOtp, standalone, deleted, unrelated)),
        )
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        // 独立 OTP 按 issuer 命中；带动态码模块的登录条目由 findMatchingEntries 覆盖，不在此重复返回
        assertEquals(
            setOf(standalone.id),
            gateway.findOtpEntries(session, TargetOrigin.Web("example.com")).map { it.id }.toSet(),
        )
        assertEquals(
            setOf(loginOtp.id),
            gateway.findMatchingEntries(session, TargetOrigin.Web("example.com")).map { it.id }.toSet(),
        )
    }

    @Test
    fun `otp source resolves self module or bound standalone entry`() {
        val embedded = entry("11111111-1111-4111-8111-111111111111", "https://example.com").copy(
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val boundLogin = entry("22222222-2222-4222-8222-222222222222", "https://example.com").copy(
            fields = mapOf("bound_otp_id" to JsonPrimitive("33333333-3333-4333-8333-333333333333")),
        )
        val standalone = Entry(
            id = "33333333-3333-4333-8333-333333333333",
            title = "Standalone",
            url = "",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val dangling = entry("44444444-4444-4444-8444-444444444444", "https://example.com").copy(
            fields = mapOf("bound_otp_id" to JsonPrimitive("missing-id")),
        )
        val boundToDeleted = entry("55555555-5555-4555-8555-555555555555", "https://example.com").copy(
            fields = mapOf("bound_otp_id" to JsonPrimitive("66666666-6666-4666-8666-666666666666")),
        )
        val deletedOtp = standalone.copy(id = "66666666-6666-4666-8666-666666666666", deletedAt = 5.0)
        val boundToNonOtp = entry("77777777-7777-4777-8777-777777777777", "https://example.com").copy(
            fields = mapOf("bound_otp_id" to JsonPrimitive("88888888-8888-4888-8888-888888888888")),
        )
        val plainLogin = entry("88888888-8888-4888-8888-888888888888", "https://example.com")
        val source = FakeSource(
            VaultPayload(
                entries = listOf(
                    embedded, boundLogin, standalone, dangling, boundToDeleted, deletedOtp, boundToNonOtp, plainLogin,
                ),
            ),
        )
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(embedded.id, gateway.otpSource(session, embedded)?.id)
        assertEquals(standalone.id, gateway.otpSource(session, boundLogin)?.id)
        assertEquals(null, gateway.otpSource(session, dangling))
        assertEquals(null, gateway.otpSource(session, boundToDeleted))
        assertEquals(null, gateway.otpSource(session, boundToNonOtp))
        assertEquals(null, gateway.otpSource(session, plainLogin))
    }

    @Test
    fun `other otp entries exclude shown candidates and their bound ids`() {
        val shown = entry("11111111-1111-4111-8111-111111111111", "https://example.com").copy(
            fields = mapOf("bound_otp_id" to JsonPrimitive("22222222-2222-4222-8222-222222222222")),
        )
        val boundOtp = Entry(
            id = "22222222-2222-4222-8222-222222222222",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val matchedOtp = Entry(
            id = "33333333-3333-4333-8333-333333333333",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"), "issuer" to JsonPrimitive("example")),
        )
        val otherOtp = Entry(
            id = "44444444-4444-4444-8444-444444444444",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"), "issuer" to JsonPrimitive("elsewhere")),
        )
        val deletedOtp = Entry(
            id = "55555555-5555-4555-8555-555555555555",
            deletedAt = 5.0,
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val source = FakeSource(VaultPayload(entries = listOf(shown, boundOtp, matchedOtp, otherOtp, deletedOtp)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        // excludeIds = 主候选自身 + 其绑定的独立 OTP；未绑定的独立 OTP 保留，已删除剔除
        assertEquals(
            setOf(otherOtp.id),
            gateway.findOtherOtpEntries(session, setOf(shown.id, boundOtp.id, matchedOtp.id)).map { it.id }.toSet(),
        )
    }

    @Test
    fun `find all login entries returns non deleted logins with actual fillable values`() {
        val loginA = entry("11111111-1111-4111-8111-111111111111", "https://example.com")
        val noPassword = entry("22222222-2222-4222-8222-222222222222", "https://example.com").copy(password = "")
        val deleted = entry("33333333-3333-4333-8333-333333333333", "https://example.com").copy(deletedAt = 5.0)
        val otp = Entry(
            id = "44444444-4444-4444-8444-444444444444",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val source = FakeSource(VaultPayload(entries = listOf(loginA, noPassword, deleted, otp)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertEquals(listOf(loginA.id, noPassword.id), gateway.findAllLoginEntries(session).map { it.id })
    }

    @Test
    fun `otp lookups enumerate entry index without full materialization`() {
        val otpA = Entry(
            id = "11111111-1111-4111-8111-111111111111",
            secretType = SecretType.OTP,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "issuer" to JsonPrimitive("example"),
            ),
        )
        val otpB = Entry(
            id = "22222222-2222-4222-8222-222222222222",
            secretType = SecretType.OTP,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "issuer" to JsonPrimitive("elsewhere"),
            ),
        )
        val login = entry("33333333-3333-4333-8333-333333333333", "https://example.com").copy(
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val query = RecordingQuerySession(mapOf(otpA.id to otpA, otpB.id to otpB, login.id to login))
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        val web = gateway.findOtpEntries(session, TargetOrigin.Web("example.com"))
        assertEquals(setOf(otpA.id), web.map { it.id }.toSet())
        // 只解密 OTP 类型条目，不解密登录条目，也不物化整库
        assertEquals(setOf(otpA.id, otpB.id), query.readIds.filter { it != login.id }.toSet())
        assertEquals(0, source.fullOpenCalls)

        query.readIds.clear()
        val others = gateway.findOtherOtpEntries(session, setOf(otpA.id))
        assertEquals(listOf(otpB.id), others.map { it.id })
        assertEquals(listOf(otpB.id), query.readIds)
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `find all login entries enumerates entry index without full materialization`() {
        val loginA = entry("11111111-1111-4111-8111-111111111111", "https://example.com")
        val loginB = entry("22222222-2222-4222-8222-222222222222", "https://other.com")
        val otp = Entry(
            id = "33333333-3333-4333-8333-333333333333",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val query = RecordingQuerySession(mapOf(loginA.id to loginA, loginB.id to loginB, otp.id to otp))
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        val logins = gateway.findAllLoginEntries(session)
        assertEquals(setOf(loginA.id, loginB.id), logins.map { it.id }.toSet())
        // 只解密登录条目，不解密 OTP 条目，也不物化整库
        assertEquals(setOf(loginA.id, loginB.id), query.readIds.toSet())
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun `advance otp counter persists next counter for legacy hotp entry`() {
        val legacy = Entry(
            id = "hotp-legacy",
            secretType = SecretType.OTP,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "type" to JsonPrimitive("hotp"),
                "counter" to JsonPrimitive("41"),
            ),
        )
        val source = FakeSource(VaultPayload(entries = listOf(legacy)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(gateway.advanceOtpCounter(session, legacy) is VaultWriteResult.Success)
        assertEquals("42", source.payload.entries.first().fields["counter"]!!.jsonPrimitive.content)
    }

    @Test
    fun `advance otp counter updates embedded otp module`() {
        val module = JsonObject(mapOf(
            "type" to JsonPrimitive("otp"),
            "value" to JsonObject(mapOf(
                "secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "type" to JsonPrimitive("hotp"),
                "counter" to JsonPrimitive("5"),
            )),
        ))
        val login = Entry(
            id = "login-module",
            secretType = SecretType.LOGIN,
            username = "u",
            password = "p",
            fields = mapOf(EntryModules.FIELD_KEY to JsonArray(listOf(module))),
        )
        val source = FakeSource(VaultPayload(entries = listOf(login)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        assertTrue(gateway.advanceOtpCounter(session, login) is VaultWriteResult.Success)
        val updatedModule = source.payload.entries.first().entryModules().first()
        assertEquals("6", updatedModule["value"]!!.jsonObject["counter"]!!.jsonPrimitive.content)
    }

    @Test
    fun `advance otp counter rejects deleted or missing entry`() {
        val entry = Entry(
            id = "hotp-gone",
            secretType = SecretType.OTP,
            updatedAt = 4.0,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "type" to JsonPrimitive("hotp"),
                "counter" to JsonPrimitive("0"),
            ),
        )
        val source = FakeSource(VaultPayload(entries = listOf(entry)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        source.payload = VaultPayload(entries = listOf(entry.copy(deletedAt = 9.0)))
        assertTrue(gateway.advanceOtpCounter(session, entry) is VaultWriteResult.Stale)
        assertTrue(gateway.advanceOtpCounter(session, entry.copy(id = "missing")) is VaultWriteResult.Missing)
    }

    @Test
    fun `advance otp counter increments from latest counter despite stale caller snapshot`() {
        val entry = Entry(
            id = "hotp-race",
            secretType = SecretType.OTP,
            updatedAt = 4.0,
            fields = mapOf(
                "otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "type" to JsonPrimitive("hotp"),
                "counter" to JsonPrimitive("10"),
            ),
        )
        val source = FakeSource(VaultPayload(entries = listOf(entry)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        source.payload = VaultPayload(
            entries = listOf(
                entry.copy(
                    updatedAt = 7.0,
                    fields = entry.fields + ("counter" to JsonPrimitive("12")),
                ),
            ),
        )
        assertTrue(gateway.advanceOtpCounter(session, entry) is VaultWriteResult.Success)
        assertEquals("13", source.payload.entries.first().fields["counter"]!!.jsonPrimitive.content)
    }

    @Test
    fun `find otp entries for android origin uses index without materializing`() {
        val otpLogin = Entry(
            id = "otp-login",
            secretType = SecretType.LOGIN,
            username = "u",
            password = "p",
            url = "com.example.app",
            fields = mapOf(
                AutofillOriginMetadata.FIELD_KEY to AutofillOriginMetadata.from(
                    TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64))),
                ),
                EntryModules.FIELD_KEY to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "type" to JsonPrimitive("otp"),
                                "value" to JsonObject(mapOf("secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"))),
                            ),
                        ),
                    ),
                ),
            ),
        )
        val plainLogin = entry("plain", "com.example.app")
        val standalone = Entry(
            id = "standalone",
            secretType = SecretType.OTP,
            fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
        )
        val query = RecordingQuerySession(mapOf(otpLogin.id to otpLogin, plainLogin.id to plainLogin)).apply {
            packageCandidates["com.example.app"] = listOf(otpLogin.id, plainLogin.id)
        }
        val source = QuerySource(query)
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        val result = gateway.findOtpEntries(
            session,
            TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64))),
        )
        assertEquals(listOf(otpLogin.id), result.map { it.id })
        assertEquals(0, source.fullOpenCalls)
    }

    @Test
    fun wordCandidatesAreOnlyAvailableToExplicitFillPickerAndKeepVerifiedEntriesFirst() {
        val exact = entry("exact", "https://example.com").copy(title = "Z Exact")
        val title = entry("title", "").copy(title = "A EXAMPLE personal")
        val binding = entry("binding", "https://example.net").copy(title = "B Other")
        val substring = entry("substring", "https://notexample.net").copy(title = "Examples")
        val note = title.copy(id = "note", secretType = SecretType.SECURE_NOTE)
        val passkey = title.copy(id = "passkey", secretType = SecretType.PASSKEY)
        val query = RecordingQuerySession(listOf(exact, title, binding, substring, note, passkey).associateBy { it.id })
            .apply { domainCandidates["example.com"] = listOf(exact.id) }
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val origin = TargetOrigin.Web("example.com")
        assertEquals(listOf("exact", "title", "binding"), gateway.findFillCandidates(session, origin).map { it.id })
        assertTrue("note" !in query.readIds && "passkey" !in query.readIds)
        assertEquals(listOf("exact"), gateway.findMatches(session, origin).map { it.entryId })
        assertEquals(listOf("exact"), gateway.findMatchingEntries(session, origin).map { it.id })
    }

    @Test
    fun excludedOriginPreventsWordCandidatesAndCanBeRecheckedBeforeRelease() {
        val query = RecordingQuerySession(mapOf("one" to entry("one", "").copy(title = "EXAMPLE")))
        var excluded = true
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy, excludeFilter = { excluded })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val origin = TargetOrigin.Web("example.com")
        assertTrue(gateway.findFillCandidates(session, origin).isEmpty())
        assertTrue(query.readIds.isEmpty())
        excluded = false
        assertEquals(listOf("one"), gateway.findFillCandidates(session, origin).map { it.id })
        assertTrue(gateway.findMatches(session, origin).isEmpty())
        excluded = true
        assertTrue(gateway.isOriginExcluded(origin))
    }

    @Test
    fun appDisplayNameWordCanSuggestLoginWithoutCreatingSignedPackageMatch() {
        val login = entry("one", "").copy(title = "EXAMPLE personal")
        val gateway = AutofillVaultGateway(FakeSource(VaultPayload(entries = listOf(login))), NoopAttemptPolicy,
            appNameResolver = { "Example Mobile" })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val origin = TargetOrigin.AndroidPackage("com.vendor.client", setOf("a".repeat(64)))
        assertEquals(listOf("one"), gateway.findFillCandidates(session, origin).map { it.id })
        assertTrue(gateway.findMatches(session, origin).isEmpty())
        assertTrue(gateway.findMatchingEntries(session, origin).isEmpty())
    }

    @Test
    fun selectedCaseInsensitiveWordCandidateFillsOnlyLinkedCustomFieldsForTheirConfiguredRoles() {
        fun customModule(id: String, type: String, role: AutofillRole, value: String): JsonObject =
            EntryModules.withAutofillRole(EntryModules.create(type), role).let { module ->
                JsonObject(module.toMutableMap().also {
                    it["id"] = JsonPrimitive(id)
                    it["label"] = JsonPrimitive("Custom ${role.wire}")
                    it["value"] = JsonPrimitive(value)
                })
            }
        val source = entry("custom-source", "").copy(secretType = SecretType.SECURE_NOTE)
            .withEntryModules(listOf(
                customModule("email-decoy", com.vault.model.ModuleType.TEXT, AutofillRole.EMAIL, "wrong@example.net"),
                customModule("work-email", com.vault.model.ModuleType.TEXT, AutofillRole.EMAIL, "custom.work@example.net"),
                customModule("password-decoy", com.vault.model.ModuleType.PASSWORD, AutofillRole.PASSWORD, "wrong-secret"),
                customModule("work-secret", com.vault.model.ModuleType.PASSWORD, AutofillRole.PASSWORD, "Custom-Secret-42!"),
            ))
        val login = entry("word-login", "").copy(title = "My EXAMPLE personal", password = "internal-secret")
            .withAutofillLinks(listOf(AutofillLink(
                id = "custom-fields",
                sourceEntryId = source.id,
                fields = listOf(
                    AutofillFieldRef("work-email", "value", AutofillRole.EMAIL, false),
                    AutofillFieldRef("work-secret", "value", AutofillRole.PASSWORD, false),
                    // A selected module cannot be reused for a different target role.
                    AutofillFieldRef("work-email", "value", AutofillRole.PHONE, false),
                ),
            )))
        val gateway = AutofillVaultGateway(FakeSource(VaultPayload(entries = listOf(login, source))), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val origin = TargetOrigin.Web("example.com")
        assertTrue(gateway.findMatches(session, origin).isEmpty())
        val selected = gateway.findFillCandidates(session, origin).single()
        assertEquals(login.id, selected.id)
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, selected))

        // This is the same source resolver invoked by finishFill after the user selects a row.
        val snapshot = gateway.resolveAutofillValues(session, selected)
        assertEquals("custom.work@example.net", snapshot.valueFor(AutofillRole.EMAIL, verificationGranted = true))
        assertEquals("Custom-Secret-42!", snapshot.valueFor(AutofillRole.PASSWORD, verificationGranted = true))
        assertEquals(null, snapshot.valueFor(AutofillRole.PASSWORD, verificationGranted = false))
        assertEquals(null, snapshot.valueFor(AutofillRole.PHONE, verificationGranted = true))
        assertTrue(AutofillRole.PHONE in snapshot.unavailableRoles)
        val email = snapshot.values.getValue(AutofillRole.EMAIL)
        val password = snapshot.values.getValue(AutofillRole.PASSWORD)
        assertEquals(source.id, email.sourceEntryId)
        assertEquals("work-email", email.moduleId)
        assertEquals("value", email.sourceKey)
        assertEquals(source.id, password.sourceEntryId)
        assertEquals("work-secret", password.moduleId)
        assertEquals("value", password.sourceKey)
    }

    @Test
    fun importedMetadataExclusionsBlockColdPasswordAndDeviceKeyQueriesWithEmptyLocalCache() {
        val origin = TargetOrigin.Web("example.com")
        val app = TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64)))
        for (deviceAuth in listOf(false, true)) {
            val login = entry("login", "https://example.com").copy(title = "EXAMPLE")
            val query = RecordingQuerySession(mapOf(login.id to login)).apply {
                exclusions = AutofillExclusions(hosts = listOf(origin.host), packages = listOf(app.packageName))
                domainCandidates[origin.host] = listOf(login.id)
                packageCandidates[app.packageName] = listOf(login.id)
            }
            val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy,
                excludeFilter = { false }, exclusionRulesResolver = { AutofillExclusions() })
            val auth = if (deviceAuth) gateway.authenticateWithDek("main", ByteArray(32) { 1 })
                else gateway.authenticate("main", "master".toCharArray())
            val session = (auth as VaultAuthResult.Success).session
            assertTrue(gateway.isOriginExcluded(origin, session))
            assertTrue(gateway.isOriginExcluded(app, session))
            assertTrue(gateway.findMatches(session, origin).isEmpty())
            assertTrue(gateway.findFillCandidates(session, origin).isEmpty())
            assertTrue(gateway.findOtpEntries(session, origin).isEmpty())
            assertTrue(gateway.findMatchingEntries(session, app).isEmpty())
            assertTrue(query.readIds.isEmpty())
            assertTrue(query.queriedDomains.isEmpty())
        }
    }

    @Test
    fun authenticatedQueryCacheUsesExplicitVaultNamePreservesNewerRemovalAndClosesOnWriteFailure() {
        val metadata = AutofillExclusions().edit("hosts", "example.com", false, 10)
        val newerCache = metadata.edit("hosts", "example.com", true, 20)
            .edit("packages", "com.local.app", false, 30)
        val query = RecordingQuerySession(emptyMap()).apply { exclusions = metadata }
        var savedName = ""
        var savedRules = AutofillExclusions()
        cacheAuthenticatedAutofillExclusions(query, "imported-vault",
            readCache = { name -> assertEquals("imported-vault", name); newerCache },
            writeCache = { name, rules -> savedName = name; savedRules = rules })
        assertEquals("imported-vault", savedName)
        assertTrue(savedRules.hosts.isEmpty())
        assertEquals(listOf("com.local.app"), savedRules.packages)
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy,
            exclusionRulesResolver = { newerCache })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertTrue(!gateway.isOriginExcluded(TargetOrigin.Web("example.com"), session))
        assertTrue(!query.closed)
        try {
            cacheAuthenticatedAutofillExclusions(query, "imported-vault", { newerCache }, { _, _ -> error("cache failure") })
            org.junit.Assert.fail("Cache failure must reject the authenticated query")
        } catch (_: IllegalStateException) {
            assertTrue(query.closed)
        }
    }

    private fun entry(id: String, url: String) = Entry(
        id = id,
        title = id,
        username = "alice",
        password = "password",
        url = url,
        createdAt = 1.0,
        updatedAt = 1.0,
    )

    @Test
    fun unifiedCandidatesRankAllReasonsAndIncludeModulePasswords() {
        val origin = TargetOrigin.Web("login.example.com")
        val confirmed = entry("confirmed", "").copy(title = "Z", fields = AutofillOriginMetadata.addBinding(emptyMap(), origin))
        val exact = entry("exact-source", "https://login.example.com").copy(title = "Y")
        val site = entry("same-site", "https://accounts.example.com").copy(title = "B")
        val named = entry("named", "").copy(title = "A Example")
        val module = entry("module", "https://login.example.com").copy(title = "X", password = "",
            fields = mapOf(EntryModules.FIELD_KEY to Json.parseToJsonElement(
                """[{"id":"secret","type":"password","value":"module-secret","config":{"autofill_role":"password"}}]""").jsonArray))
        val empty = entry("empty", "https://login.example.com").copy(password = "", username = "")
        val query = RecordingQuerySession(listOf(named, site, exact, confirmed, module, empty).associateBy { it.id })
            .apply { domainCandidates[origin.host] = listOf(exact.id, module.id, empty.id) }
        val gateway = AutofillVaultGateway(QuerySource(query), NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertEquals(listOf("confirmed", "module", "exact-source", "same-site", "named"), gateway.findFillCandidates(session, origin).map { it.id })
        assertEquals(listOf("exact-source", "module"), gateway.findMatchingEntries(session, origin).map { it.id })
        assertEquals("module-secret", gateway.resolveAutofillValues(session, module).values[AutofillRole.PASSWORD]?.value)
        assertEquals(module, gateway.credential(session, module.id, module.updatedAt))
    }

    @Test
    fun rememberingOriginBindingPreservesModuleSecretAndAddsConfirmedReason() {
        val module = entry("module", "").copy(password = "", fields = mapOf(EntryModules.FIELD_KEY to
            Json.parseToJsonElement("""[{"id":"secret","type":"password","value":"module-secret","config":{"autofill_role":"password"}}]""").jsonArray))
        val source = FakeSource(VaultPayload(entries = listOf(module)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        val origin = TargetOrigin.Web("example.com")
        assertTrue(gateway.rememberOriginBinding(session, module.id, origin) is VaultWriteResult.Success)
        val saved = source.payload.entries.single()
        assertEquals("", saved.password)
        assertEquals(module.fields[EntryModules.FIELD_KEY], saved.fields[EntryModules.FIELD_KEY])
        assertEquals(AutofillCandidateReason.CONFIRMED_BINDING, OriginMatcher.fillCandidateReason(origin, saved))
    }

    @Test
    fun preferencesAreOriginScopedAndRevocationDoesNotRestoreLegacyBinding() {
        val origin = TargetOrigin.Web("example.com")
        val other = TargetOrigin.Web("other.com")
        val original = entry("preferences", "").copy(fields = AutofillOriginMetadata.addBinding(
            AutofillOriginMetadata.addBinding(emptyMap(), origin), other))
        val source = FakeSource(VaultPayload(entries = listOf(original)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertTrue(gateway.rememberFieldMapping(session, original.id, origin, "custom-input", "password") is VaultWriteResult.Success)
        assertEquals(mapOf("custom-input" to "password"), gateway.fieldMappings(session, original.id, origin))
        assertEquals(emptyMap<String, String>(), gateway.fieldMappings(session, original.id, other))
        assertTrue(gateway.forgetOriginPreferences(session, original.id, origin) is VaultWriteResult.Success)
        val saved = source.payload.entries.single()
        assertEquals(emptyMap<String, String>(), gateway.fieldMappings(session, original.id, origin))
        assertEquals(listOf(other.host), AutofillOriginMetadata.webHosts(saved))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.matchLevel(origin, saved))
        assertEquals(AutofillCandidateReason.CONFIRMED_BINDING, OriginMatcher.fillCandidateReason(other, saved))
        assertEquals(original.password, saved.password)
    }

    @Test
    fun knownSignerMismatchCannotBeRememberedAsBindingOrFieldMapping() {
        val originalOrigin = TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64)))
        val attacker = originalOrigin.copy(signingCertificateSha256 = setOf("b".repeat(64)))
        val original = entry("preferences", "").copy(fields = AutofillOriginMetadata.addBinding(emptyMap(), originalOrigin))
        val source = FakeSource(VaultPayload(entries = listOf(original)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertTrue(gateway.rememberOriginBinding(session, original.id, attacker) is VaultWriteResult.Failure)
        assertTrue(gateway.rememberFieldMapping(session, original.id, attacker, "custom-input", "password") is VaultWriteResult.Failure)
        assertTrue(gateway.forgetOriginPreferences(session, original.id, attacker) is VaultWriteResult.Failure)
        assertEquals(original, source.payload.entries.single())
    }

    @Test
    fun customSecretOnlyLoginRemainsAvailableForExplicitFieldMapping() {
        val original = entry("custom", "https://example.com").copy(username = "", password = "", fields = mapOf(
            EntryModules.FIELD_KEY to Json.parseToJsonElement(
                """[{"id":"custom-secret","type":"password","value":"secret-value","config":{"autofill_role":"custom_secret"}}]""").jsonArray))
        val source = FakeSource(VaultPayload(entries = listOf(original)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertEquals(listOf(original.id), gateway.findFillCandidates(session, TargetOrigin.Web("example.com")).map { it.id })
        assertEquals(listOf(original.id), gateway.findAllLoginEntries(session).map { it.id })
        assertEquals("secret-value", gateway.resolveAutofillValues(session, original).values[AutofillRole.CUSTOM_SECRET]?.value)
    }

    @Test
    fun explicitFillRejectsKnownSignerMismatchEvenWithStoredMappingAndAllowsUnassociatedLogin() {
        val trusted = TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64)))
        val attacker = trusted.copy(signingCertificateSha256 = setOf("b".repeat(64)))
        val bound = entry("bound", "").copy(fields = AutofillFieldMappingMetadata.add(
            AutofillOriginMetadata.addBinding(emptyMap(), trusted), trusted, "custom-input", "password"))
        val unassociated = entry("unassociated", "")
        val source = FakeSource(VaultPayload(entries = listOf(bound, unassociated)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy)
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session
        assertTrue(gateway.allowedForExplicitFill(session, bound, trusted))
        assertTrue(!gateway.allowedForExplicitFill(session, bound, attacker))
        assertTrue(gateway.fieldMappings(session, bound.id, attacker).isNotEmpty())
        assertTrue(gateway.allowedForExplicitFill(session, unassociated, attacker))
        assertTrue(!gateway.allowedForExplicitFill(session, bound.copy(deletedAt = 1.0), trusted))
        val excluded = AutofillVaultGateway(source, NoopAttemptPolicy, excludeFilter = { true })
        assertTrue(!excluded.allowedForExplicitFill(session, unassociated, trusted))
    }

    private class FakeSource(var payload: VaultPayload) : AutofillVaultDataSource {
        override fun listVaults() = listOf("main")
        override fun exists(vaultName: String) = vaultName == "main"
        override fun openQueryWithPassword(vaultName: String, password: String): VaultQuerySession {
            if (password != "master") throw VaultCrypto.DecryptError("wrong")
            return FakeQuerySession { payload }
        }
        override fun openQueryWithDeviceKey(vaultName: String, deviceKey: ByteArray): VaultQuerySession =
            FakeQuerySession { payload }
        override fun mutatePmvEWithPassword(
            vaultName: String,
            password: String,
            expectedSequence: Long,
            transform: (VaultPayload) -> VaultPayload,
        ): VaultIdentity {
            if (password != "master") throw VaultCrypto.DecryptError("wrong")
            payload = transform(payload)
            return fakeIdentity()
        }
        override fun mutatePmvEWithDeviceKey(
            vaultName: String,
            deviceKey: ByteArray,
            expectedSequence: Long,
            transform: (VaultPayload) -> VaultPayload,
        ): VaultIdentity {
            payload = transform(payload)
            return fakeIdentity()
        }
    }

    private class QuerySource(private val query: VaultQuerySession) : AutofillVaultDataSource {
        var fullOpenCalls = 0
        var staleMutation = false
        var fullPayload: VaultPayload = VaultPayload()
        override fun listVaults() = listOf("main")
        override fun exists(vaultName: String) = true
        override fun openQueryWithPassword(vaultName: String, password: String): VaultQuerySession = query
        override fun openQueryWithDeviceKey(vaultName: String, deviceKey: ByteArray): VaultQuerySession = query
        override fun mutatePmvEWithPassword(
            vaultName: String,
            password: String,
            expectedSequence: Long,
            transform: (VaultPayload) -> VaultPayload,
        ): VaultIdentity {
            if (staleMutation) throw VaultStaleMutationException("stale")
            return requireNotNull(query.identity)
        }
    }

    private class FakeQuerySession(private val payloadProvider: () -> VaultPayload) : VaultQuerySession {
        override val format = VaultFileFormat.PMVE
        override val identity: VaultIdentity? = fakeIdentity()
        override fun queryDomain(domain: String): List<String> = payloadProvider().entries
            .filter { it.deletedAt == null && it.secretType == SecretType.LOGIN && it.url.isNotBlank() }
            .filter { entry ->
                val normalized = entry.url.removePrefix("https://").removePrefix("http://").trimEnd('/')
                normalized == domain || normalized.endsWith(".$domain")
            }.map { it.id }
        override fun queryPackage(packageName: String): List<String> = payloadProvider().entries
            .filter { it.deletedAt == null && (it.url == packageName || it.targetApp == packageName) }
            .map { it.id }
        override fun queryRpId(rpId: String): List<String> = payloadProvider().entries
            .filter { it.deletedAt == null && it.secretType == SecretType.PASSKEY && it.url == "https://$rpId" }
            .map { it.id }
        override fun readEntry(entryId: String): Entry? =
            payloadProvider().entries.firstOrNull { it.id == entryId && it.deletedAt == null }
        override fun listSummaries(): List<VaultEntrySummary> = payloadProvider().entries
            .filter { it.deletedAt == null }
            .map { entry ->
                VaultEntrySummary(
                    entryId = entry.id,
                    entryType = entry.secretType,
                    displayTitle = entry.title,
                    favorite = false,
                    revision = entry.updatedAt.toLong(),
                )
            }
        override fun close() = Unit
    }

    @Test
    fun `linked hotp source selects its module and advances that module counter`() {
        val otpModule = JsonObject(mapOf(
            "id" to JsonPrimitive("selected-otp"),
            "type" to JsonPrimitive("otp"),
            "value" to JsonObject(mapOf(
                "secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "type" to JsonPrimitive("hotp"),
                "counter" to JsonPrimitive("8"),
            )),
        ))
        val sourceEntry = Entry(
            id = "otp-source",
            secretType = SecretType.OTP,
            fields = mapOf(EntryModules.FIELD_KEY to JsonArray(listOf(otpModule))),
        )
        val login = entry("login-linked-hotp", "https://example.com").withAutofillLinks(
            listOf(
                AutofillLink(
                    "hotp-link",
                    sourceEntry.id,
                    listOf(AutofillFieldRef("selected-otp", "@computed/one_time_code", AutofillRole.ONE_TIME_CODE, false)),
                ),
            ),
        )
        val source = FakeSource(VaultPayload(entries = listOf(login, sourceEntry)))
        val gateway = AutofillVaultGateway(source, NoopAttemptPolicy, clock = { 10.0 })
        val session = (gateway.authenticate("main", "master".toCharArray()) as VaultAuthResult.Success).session

        val resolved = gateway.otpSourceRef(session, login)
        assertEquals(sourceEntry.id, resolved?.entry?.id)
        assertEquals("selected-otp", resolved?.moduleId)
        assertTrue(gateway.advanceOtpCounter(session, requireNotNull(resolved)) is VaultWriteResult.Success)
        assertEquals(
            "9",
            source.payload.entries.first { it.id == sourceEntry.id }.entryModules().single()["value"]!!
                .jsonObject["counter"]!!.jsonPrimitive.content,
        )
    }

    private class RecordingQuerySession(private val entries: Map<String, Entry>) : VaultQuerySession {
        var exclusions: AutofillExclusions? = null
        var closed = false
        override fun autofillExclusions(): AutofillExclusions? = exclusions
        val domainCandidates = mutableMapOf<String, List<String>>()
        val packageCandidates = mutableMapOf<String, List<String>>()
        val rpCandidates = mutableMapOf<String, List<String>>()
        val queriedDomains = mutableListOf<String>()
        val readIds = mutableListOf<String>()
        override val format = VaultFileFormat.PMVE
        override val identity = VaultIdentity(
            UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            1,
            UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            null,
            1,
            1,
            ByteArray(32) { 1 },
            ByteArray(32) { 2 },
        )
        override fun queryDomain(domain: String): List<String> {
            queriedDomains += domain
            return domainCandidates[domain].orEmpty()
        }
        override fun queryPackage(packageName: String) = packageCandidates[packageName].orEmpty()
        override fun queryRpId(rpId: String) = rpCandidates[rpId].orEmpty()
        override fun readEntry(entryId: String): Entry? {
            readIds += entryId
            return entries[entryId]
        }
        override fun listSummaries(): List<VaultEntrySummary> = entries.map { (id, entry) ->
            VaultEntrySummary(
                entryId = id,
                entryType = entry.secretType,
                displayTitle = entry.title,
                favorite = false,
                revision = entry.updatedAt.toLong(),
            )
        }
        override fun close() { closed = true }
    }

    private fun passkeyFixture(): PasskeyRecord {
        val dir = System.getProperty("spec.dir") ?: "spec"
        val value = Json.parseToJsonElement(File(dir, "passkey_v3_fixtures.json").readText())
            .jsonObject.getValue("legacyV2").jsonObject.getValue("valid").jsonArray.first().jsonObject.getValue("record").jsonObject
        return requireNotNull(PasskeyRecord.parse(value))
    }

    private object NoopAttemptPolicy : AutofillAttemptPolicy {
        override fun coolingRemainingMs() = 0L
        override fun recordFailure() = AttemptFailure(4, 250L, 0L)
        override fun clear() = Unit
    }

    private class RecordingAttemptPolicy : AutofillAttemptPolicy {
        var failures = 0
        override fun coolingRemainingMs() = 0L
        override fun recordFailure(): AttemptFailure {
            failures++
            return AttemptFailure(4, 250L, 0L)
        }
        override fun clear() = Unit
    }
}

private fun fakeIdentity() = VaultIdentity(
    UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
    1,
    UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
    null,
    1,
    1,
    ByteArray(32) { 1 },
    ByteArray(32) { 2 },
)
