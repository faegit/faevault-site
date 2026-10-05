package com.vault

import com.vault.model.SecretType
import com.vault.model.getStringField
import com.vault.model.hasCurrentLeakCache
import com.vault.storage.CsvImporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CsvImporterTest {

    @Test
    fun otpAuthUrlImportsAsUsableOtp() {
        val csv = "title,url\nExample,otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP"
        val entry = CsvImporter.parseText(csv).single()
        assertEquals(SecretType.OTP, entry.secretType)
        assertEquals("JBSWY3DPEHPK3PXP", entry.getStringField("secret"))
        assertEquals("totp", entry.getStringField("type"))
    }

    @Test
    fun invalidOtpAuthUrlDoesNotBecomeOtp() {
        val entry = CsvImporter.parseText("title,url\nExample,otpauth://totp/Example?secret=NOT-BASE32!").single()
        assertEquals(SecretType.LOGIN, entry.secretType)
    }

    /** M-10：导出时给公式前缀加单引号，避免在 Excel/LibreOffice 里被当公式执行。 */
    @Test
    fun exporterGuardsFormulaLeadingValues() {
        val out = java.io.ByteArrayOutputStream()
        val entry = com.vault.model.Entry(
            secretType = SecretType.LOGIN,
            title = "=SUM(A1:A9)",
            username = "+cmd",
            password = "plainPass",
        )
        com.vault.storage.CsvExporter.writeTo(out, listOf(entry), guardFormulas = true)
        val csv = out.toString(Charsets.UTF_8.name())

        assertTrue("formula-leading title must be quoted with '", csv.contains("'=SUM(A1:A9)"))
        assertTrue("formula-leading username must be quoted with '", csv.contains("'+cmd"))
        assertTrue("ordinary password must stay untouched", csv.contains("plainPass"))
        assertFalse(csv.contains("'plainPass"))
    }

    /** 归档内的 logins.csv 由本应用与 PC 端解析，不加防护以免污染跨端字段。 */
    @Test
    fun exporterLeavesValuesUnguardedWhenAsked() {
        val out = java.io.ByteArrayOutputStream()
        val entry = com.vault.model.Entry(
            secretType = SecretType.LOGIN,
            title = "=SUM(A1:A9)",
            password = "x",
        )
        com.vault.storage.CsvExporter.writeTo(out, listOf(entry), guardFormulas = false)

        assertTrue(out.toString(Charsets.UTF_8.name()).contains("=SUM(A1:A9)"))
    }

    /** M-10 往返：剥掉导出时加的前导单引号，本应用导出再导入不丢字符。 */
    @Test
    fun importerStripsExporterFormulaGuard() {
        val entries = CsvImporter.parseText("type,title,username,password\nlogin,'=SUM(A1),'+cmd,pass")
        val entry = entries.single()

        assertEquals("=SUM(A1)", entry.title)
        assertEquals("+cmd", entry.username)
        assertEquals("pass", entry.password)
    }

    /** 只剥“单引号 + 公式触发字符”，用户本来以单引号开头的普通值不受影响。 */
    @Test
    fun importerKeepsOrdinaryApostrophe() {
        assertEquals("'quoted name", CsvImporter.parseText("type,title,password\nlogin,'quoted name,x").single().title)
    }

    @Test
    fun chromePasswordCsvWithoutTypeImportsAsLogin() {
        val csv = """
            name,url,username,password,note
            Google,https://accounts.google.com,user@example.com,secret,
            Example,https://example.com,alice,pass123,plain note
        """.trimIndent()

        val entries = CsvImporter.parseText(csv)

        assertEquals(2, entries.size)
        assertEquals(setOf(SecretType.LOGIN), entries.map { it.secretType }.toSet())
        assertEquals("Google", entries[0].title)
        assertEquals("https://accounts.google.com", entries[0].url)
        assertEquals("user@example.com", entries[0].username)
        assertEquals("secret", entries[0].password)
        assertFalse(entries[0].fields.containsKey("full_name"))
    }

    @Test
    fun genericCredentialTypeImportsAsLogin() {
        val csv = """
            type,title,username,password
            credential,Example,alice,secret
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals(SecretType.LOGIN, entry.secretType)
    }

    @Test
    fun explicitFullNameStillImportsAsIdCardSignal() {
        val csv = """
            type,full_name,id_number
            id_card,张三,110101199001011234
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals(SecretType.CARD_DOCUMENT, entry.secretType)
        assertEquals("张三", entry.getStringField("full_name"))
        assertEquals("110101199001011234", entry.getStringField("id_number"))
    }

    @Test
    fun loginCsvImportsLeakCacheAsTopLevelState() {
        val csv = """
            type,title,username,password,leak_pwned_count,leak_common_weak,leak_checked_at
            login,Leaked,alice,secret,42,true,1700000000
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals(SecretType.LOGIN, entry.secretType)
        assertEquals(42, entry.leakPwnedCount)
        assertEquals(true, entry.leakCommonWeak)
        assertEquals(1700000000.0, entry.leakCheckedAt!!, 0.001)
        assertEquals(entry.updatedAt, entry.leakCheckRevision!!, 0.001)
        assertEquals(true, entry.hasCurrentLeakCache())
        assertFalse(entry.fields.containsKey("leak_pwned_count"))
    }

    @Test
    fun bitwardenCsvMapsFolderTotpAndCustomFields() {
        val csv = """
            folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
            Work,0,login,GitHub,primary,"team: platform",0,https://github.com,alice,secret,JBSWY3DPEHPK3PXP
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals("GitHub", entry.title)
        assertEquals(listOf("Work"), entry.tags)
        assertEquals("https://github.com", entry.url)
        assertEquals("alice", entry.username)
        assertEquals("secret", entry.password)
        assertEquals("JBSWY3DPEHPK3PXP", entry.getStringField("otp_secret"))
        assertTrue(entry.notes.contains("team: platform"))
    }

    @Test
    fun onePasswordCsvPreservesOtpAuth() {
        val csv = """
            Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
            Example,https://example.com,user,pw,otpauth://totp/Example:user?secret=ABC123,0,0,personal,hello
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals("otpauth://totp/Example:user?secret=ABC123", entry.getStringField("otp_uri"))
        assertEquals(listOf("personal"), entry.tags)
    }

    @Test
    fun keepassAndLastPassFoldersBecomeTags() {
        val keepass = CsvImporter.parseText(
            "Group,Title,Username,Password,URL,Notes\nWork,Portal,alice,pw,https://portal.example,note"
        ).single()
        val lastPass = CsvImporter.parseText(
            "url,username,password,extra,name,grouping,fav\nhttps://mail.example,bob,pw2,memo,Mail,Personal,0"
        ).single()

        assertEquals(listOf("Work"), keepass.tags)
        assertEquals(listOf("Personal"), lastPass.tags)
        assertEquals("memo", lastPass.notes)
    }

    @Test
    fun firefoxCsvUsesHostAsMissingTitle() {
        val csv = """
            url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
            https://accounts.example.com/login,alice,pw,,,id,1,2,3
        """.trimIndent()

        val entry = CsvImporter.parseText(csv).single()

        assertEquals("accounts.example.com", entry.title)
    }

    @Test
    fun quotedCsvNotesMayContainNewlines() {
        val csv = "title,username,password,notes\nExample,alice,pw,\"first line\nsecond line\""

        val entry = CsvImporter.parseText(csv).single()

        assertEquals("first line\nsecond line", entry.notes)
    }

    @Test
    fun bitwardenJsonImportsFoldersTotpAndCustomFields() {
        val json = """
            {
              "encrypted": false,
              "folders": [{"id": "folder-1", "name": "Work"}],
              "items": [{
                "type": 1,
                "folderId": "folder-1",
                "name": "GitHub",
                "notes": "primary",
                "login": {
                  "username": "alice",
                  "password": "secret",
                  "totp": "JBSWY3DPEHPK3PXP",
                  "uris": [{"uri": "https://github.com"}]
                },
                "fields": [{"name": "team", "value": "platform"}]
              }]
            }
        """.trimIndent()

        val result = CsvImporter.parse(json)
        val entry = result.entries.single()

        assertEquals("Bitwarden JSON", result.source)
        assertEquals("GitHub", entry.title)
        assertEquals(listOf("Work"), entry.tags)
        assertEquals("alice", entry.username)
        assertEquals("secret", entry.password)
        assertEquals("https://github.com", entry.url)
        assertEquals("JBSWY3DPEHPK3PXP", entry.getStringField("otp_secret"))
        assertEquals("platform", entry.getStringField("team"))
        assertTrue(entry.notes.contains("team: platform"))
    }
}
