package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.jsonArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OriginMatcherTest {
    private val certificate = "a".repeat(64)

    @Test
    fun normalizesPackageAndHttpsOrigins() {
        assertEquals(
            TargetOrigin.AndroidPackage("com.example.app", setOf(certificate)),
            OriginMatcher.originFrom("com.example.app", null, "app.fae.vault", setOf(certificate)),
        )
        assertEquals(
            TargetOrigin.Web("login.example.com", "com.android.chrome", setOf(certificate)),
            OriginMatcher.originFrom(
                "com.android.chrome", "LOGIN.Example.COM.", "app.fae.vault", setOf(certificate),
                trustedBrowserSigningCertificateSha256 = setOf(certificate),
            ),
        )
        assertEquals("example.com", OriginMatcher.webHost("https://www.Example.com:443/login?q=secret#x"))
        assertEquals("xn--bcher-kva.example", OriginMatcher.webHost("https://bücher.example/login"))
        // 旧库条目常见 http:// 或无 scheme 裸域名，绑定值宽容解析后仍按 host 匹配
        assertEquals("example.com", OriginMatcher.webHost("http://example.com/login"))
        assertEquals("example.com", OriginMatcher.webHost("www.example.com/login"))
        assertEquals("example.com", OriginMatcher.webHost("example.com"))
    }

    @Test
    fun rejectsWebDomainFromBrowserWithUntrustedSigner() {
        assertNull(
            OriginMatcher.originFrom(
                packageName = "com.android.chrome",
                webDomain = "login.example.com",
                ownPackage = "app.fae.vault",
                signingCertificateSha256 = setOf("b".repeat(64)),
                trustedBrowserSigningCertificateSha256 = setOf(certificate),
            ),
        )
    }

    @Test
    fun rejectsUnsafeOrigins() {
        assertNull(OriginMatcher.webHost(""))
        assertNull(OriginMatcher.webHost("https://user@example.com/login"))
        assertNull(OriginMatcher.webHost("androidapp://com.example.app"))
        assertNull(OriginMatcher.webHost("https://localhost/login"))
        assertNull(OriginMatcher.originFrom("app.fae.vault", null, "app.fae.vault", setOf(certificate)))
        assertNull(OriginMatcher.originFrom("com.android.settings", null, "app.fae.vault", setOf(certificate)))
        assertNull(OriginMatcher.originFrom("com.android.permissioncontroller", null, "app.fae.vault", setOf(certificate)))
        assertNull(OriginMatcher.originFrom("com.example.app", null, "app.fae.vault"))
        assertNull(OriginMatcher.originFrom("com.android.chrome", null, "app.fae.vault", setOf(certificate)))
        assertNull(OriginMatcher.originFrom("com.example.fakebrowser", "example.com", "app.fae.vault", setOf(certificate)))
    }

    @Test
    fun hostMatchingUsesLabelBoundaries() {
        assertEquals(
            OriginMatchLevel.PARENT_DOMAIN,
            OriginMatcher.matchLevel(TargetOrigin.Web("login.example.com"), "https://example.com"),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(TargetOrigin.Web("evil-example.com"), "https://example.com"),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(TargetOrigin.Web("login.example.co.uk"), "https://co.uk"),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(TargetOrigin.Web("tenant.github.io"), "https://github.io"),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(TargetOrigin.Web("www.github.io"), "https://github.io"),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(TargetOrigin.Web("www.co.uk"), "https://co.uk"),
        )
    }

    @Test
    fun ranksExactBeforeParentAndFiltersUnsafeEntries() {
        val entries = listOf(
            login("exact", "Exact", "https://login.example.com", "alice", "pw"),
            login("parent", "Parent", "https://example.com", "bob", "pw"),
            login("none", "None", "https://other.example", "c", "pw"),
            login("deleted", "Deleted", "https://login.example.com", "d", "pw", deleted = true),
            login("empty", "Empty", "https://login.example.com", "", ""),
            login("wifi", "Wifi", "https://login.example.com", "f", "pw", type = SecretType.WIFI),
        )

        val result = OriginMatcher.rank(entries, TargetOrigin.Web("login.example.com"))

        assertEquals(listOf("exact", "parent"), result.map { it.entryId })
        assertEquals(OriginMatchLevel.EXACT, result[0].level)
        assertEquals(OriginMatchLevel.PARENT_DOMAIN, result[1].level)
    }

    @Test
    fun exactBindingWinsWhenTheSameEntryAlsoContainsAParentDomainBinding() {
        val modules = kotlinx.serialization.json.Json.parseToJsonElement(
            """[{"type":"url","value":"https://example.com"}]""",
        ).jsonArray
        val entry = login(
            "multi-domain",
            "Example",
            "https://login.example.com",
            "alice",
            "pw",
        ).copy(fields = mapOf(com.vault.model.EntryModules.FIELD_KEY to modules))

        assertEquals(
            OriginMatchLevel.EXACT,
            OriginMatcher.matchLevel(TargetOrigin.Web("login.example.com"), entry),
        )
    }

    @Test
    fun signedPackageBindingIsExactAndResultIsCapped() {
        val origin = TargetOrigin.AndroidPackage("com.example.app", setOf(certificate))
        val entries = (0 until 12).map { index ->
            login("id$index", "Title ${index.toString().padStart(2, '0')}", "com.example.app", "u$index", "pw")
                .copy(fields = mapOf(
                    AutofillOriginMetadata.FIELD_KEY to AutofillOriginMetadata.from(origin),
                ))
        }

        val result = OriginMatcher.rank(entries, origin)

        assertEquals(8, result.size)
        assertTrue(result.all { it.level == OriginMatchLevel.EXACT })
    }

    @Test
    fun signedPackageRejectsDifferentSignerAndDoesNotReturnLegacyEntry() {
        val signed = login("signed", "Signed", "com.example.app", "u", "pw").copy(
            fields = mapOf(
                AutofillOriginMetadata.FIELD_KEY to AutofillOriginMetadata.from(
                    TargetOrigin.AndroidPackage("com.example.app", setOf(certificate)),
                ),
            ),
        )
        val legacy = login("legacy", "Legacy", "com.example.app", "u", "pw")

        assertEquals(
            listOf("signed"),
            OriginMatcher.rank(listOf(legacy, signed), TargetOrigin.AndroidPackage("com.example.app", setOf(certificate)))
                .map { it.entryId },
        )
        assertEquals(
            emptyList<String>(),
            OriginMatcher.rank(listOf(legacy, signed), TargetOrigin.AndroidPackage("com.example.app", setOf("b".repeat(64))))
                .map { it.entryId },
        )
    }

    @Test
    fun multipleVerifiedApplicationBindingsCanMatchTheSameLogin() {
        val first = TargetOrigin.AndroidPackage("com.example.personal", setOf("a".repeat(64)))
        val second = TargetOrigin.AndroidPackage("com.example.work", setOf("b".repeat(64)))
        val fields = AutofillOriginMetadata.addBinding(
            AutofillOriginMetadata.addBinding(emptyMap(), first),
            second,
        )
        val login = login("shared", "Shared", first.packageName, "alice", "pw").copy(
            targetApp = first.packageName,
            fields = fields,
        )

        assertEquals(OriginMatchLevel.EXACT, OriginMatcher.matchLevel(first, login))
        assertEquals(OriginMatchLevel.EXACT, OriginMatcher.matchLevel(second, login))
    }

    @Test
    fun legacyPackageWithoutCertificateMetadataIsRejected() {
        val legacy = login("legacy", "Legacy", "com.example.app", "u", "pw")

        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(
                TargetOrigin.AndroidPackage("com.example.app", setOf(certificate)),
                legacy,
            ),
        )
        assertTrue(
            OriginMatcher.rank(
                listOf(legacy),
                TargetOrigin.AndroidPackage("com.example.app", setOf(certificate)),
            ).isEmpty(),
        )
    }

    @Test
    fun legacyModuleBindingsMatchWhenTopLevelFieldsAreBlank() {
        // 旧库升级常见形态：网址/包名只存在自定义模块，顶层 url/targetApp 为空。
        val modules = kotlinx.serialization.json.Json.parseToJsonElement(
            """[
                {"type":"url","value":"https://example.com/login"},
                {"type":"target_app","value":"com.example.legacy.app"}
            ]""",
        ).jsonArray
        val legacy = login("legacy", "Legacy", "", "u", "pw").copy(
            targetApp = "",
            fields = mapOf(com.vault.model.EntryModules.FIELD_KEY to modules),
        )

        assertEquals(
            OriginMatchLevel.EXACT,
            OriginMatcher.matchLevel(TargetOrigin.Web("example.com"), legacy),
        )
        assertEquals(
            OriginMatchLevel.NONE,
            OriginMatcher.matchLevel(
                TargetOrigin.AndroidPackage("com.example.legacy.app", setOf(certificate)),
                legacy,
            ),
        )
    }

    @Test
    fun wordSuggestionsMatchOneWholeWordIgnoringCaseButNeverAuthorizeAnOrigin() {
        val origin = TargetOrigin.Web("login.example.com")
        val title = login("title", "My EXAMPLE account", "", "u", "pw")
        val binding = login("binding", "Other", "https://example.net", "u", "pw")
        val substring = login("substring", "Examples", "https://notexample.net", "u", "pw")
        val suffix = login("suffix", "COM login", "https://other.com", "u", "pw")
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, title))
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, binding))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.fillCandidateLevel(origin, substring))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.fillCandidateLevel(origin, suffix))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.matchLevel(origin, title))
        assertTrue(OriginMatcher.rank(listOf(title, binding), origin).isEmpty())
        assertTrue(!mayAutoApplySavedCredentialUpdate(OriginMatchLevel.WORD_CANDIDATE))
    }

    @Test
    fun appNameAndModuleWordsAreCandidatesButKnownSignerMismatchIsRejected() {
        val origin = TargetOrigin.AndroidPackage("com.vendor.client", setOf(certificate))
        val byName = login("name", "EXAMPLE Personal", "", "u", "pw")
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, byName, "Example App"))
        val modules = kotlinx.serialization.json.Json.parseToJsonElement(
            """[{"type":"target_app","value":"com.EXAMPLE.mobile"}]""",
        ).jsonArray
        val byModule = byName.copy(title = "Unrelated", fields = mapOf(com.vault.model.EntryModules.FIELD_KEY to modules))
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, byModule, "Example App"))
        val signed = byName.copy(fields = mapOf(
            AutofillOriginMetadata.FIELD_KEY to AutofillOriginMetadata.from(
                origin.copy(signingCertificateSha256 = setOf("b".repeat(64))),
            ),
        ))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.fillCandidateLevel(origin, signed, "Example App"))
        assertEquals(OriginMatchLevel.EXACT, OriginMatcher.fillCandidateLevel(
            TargetOrigin.Web("example.com"), byName.copy(url = "https://example.com"),
        ))
    }

    @Test
    fun wordBoundariesPreservePunctuationUnicodeAndPrivateSuffixIsolation() {
        val matching = login("matching", "ＭＹ—ＥＸＡＭＰＬＥ", "", "u", "pw")
        assertEquals(OriginMatchLevel.WORD_CANDIDATE,
            OriginMatcher.fillCandidateLevel(TargetOrigin.Web("example.co.uk"), matching))
        val suffixOnly = matching.copy(title = "Github IO")
        assertEquals(OriginMatchLevel.NONE,
            OriginMatcher.fillCandidateLevel(TargetOrigin.Web("tenant.github.io"), suffixOnly))
        assertEquals(OriginMatchLevel.WORD_CANDIDATE,
            OriginMatcher.fillCandidateLevel(TargetOrigin.Web("tenant.github.io"), matching.copy(title = "TENANT backup")))
    }

    @Test
    fun candidateReasonsDistinguishConfirmedExactSameSiteAndName() {
        val origin = TargetOrigin.Web("login.example.com")
        val confirmed = login("bound", "Z", "", "u", "pw").copy(
            fields = AutofillOriginMetadata.addBinding(emptyMap(), origin))
        assertEquals(AutofillCandidateReason.CONFIRMED_BINDING, OriginMatcher.fillCandidateReason(origin, confirmed))
        assertEquals(AutofillCandidateReason.EXACT_SOURCE, OriginMatcher.fillCandidateReason(origin, confirmed.copy(fields = emptyMap(), url = "https://login.example.com")))
        val sibling = confirmed.copy(fields = emptyMap(), url = "https://accounts.example.com")
        assertEquals(AutofillCandidateReason.SAME_SITE, OriginMatcher.fillCandidateReason(origin, sibling))
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.matchLevel(origin, sibling))
        assertEquals(OriginMatchLevel.WORD_CANDIDATE, OriginMatcher.fillCandidateLevel(origin, sibling))
        assertEquals(AutofillCandidateReason.RELATED_NAME, OriginMatcher.fillCandidateReason(origin, sibling.copy(url = "", title = "Example Personal")))
        assertEquals(null, OriginMatcher.fillCandidateReason(TargetOrigin.Web("alice.github.io"), sibling.copy(url = "https://bob.github.io", title = "Other")))
    }

    @Test
    fun rememberedNondefaultPortCannotAuthorizeAndroidHostOnlyRequest() {
        val metadata = kotlinx.serialization.json.Json.parseToJsonElement(
            """[{"kind":"web","host":"example.com","origin":"https://example.com:8443"}]""").jsonArray
        val entry = login("port", "Other", "", "u", "pw").copy(fields = mapOf(AutofillOriginMetadata.BINDINGS_FIELD_KEY to metadata))
        val origin = TargetOrigin.Web("example.com")
        assertEquals(OriginMatchLevel.NONE, OriginMatcher.matchLevel(origin, entry))
        assertEquals(null, OriginMatcher.fillCandidateReason(origin, entry))
        assertEquals(metadata, AutofillOriginMetadata.removeBinding(entry.fields, origin)[AutofillOriginMetadata.BINDINGS_FIELD_KEY])
        val defaultPort = entry.copy(fields = mapOf(AutofillOriginMetadata.BINDINGS_FIELD_KEY to
            kotlinx.serialization.json.Json.parseToJsonElement("""[{"kind":"web","host":"example.com","origin":"https://example.com:443"}]""").jsonArray))
        assertEquals(OriginMatchLevel.EXACT, OriginMatcher.matchLevel(origin, defaultPort))
    }

    private fun login(
        id: String,
        title: String,
        url: String,
        username: String,
        password: String,
        deleted: Boolean = false,
        type: String = SecretType.LOGIN,
    ) = Entry(
        id = id,
        title = title,
        url = url,
        username = username,
        password = password,
        secretType = type,
        deletedAt = if (deleted) 1.0 else null,
    )
}
