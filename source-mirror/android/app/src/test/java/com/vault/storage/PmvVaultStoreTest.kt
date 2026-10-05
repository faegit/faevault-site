package com.vault.storage

import org.junit.Assert.assertArrayEquals

import com.vault.autofill.AutofillOriginMetadata
import com.vault.autofill.TargetOrigin
import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.PmvKdfProfile
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.SecretType
import com.vault.security.VaultDeviceIdentity
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.util.UUID
import java.util.concurrent.CancellationException

class PmvVaultStoreTest {
    private val password = "correct horse battery staple".encodeToByteArray()
    private val newPassword = "a newer and longer password".encodeToByteArray()
    private val recoverySecret = ByteArray(32) { (it * 7 + 3).toByte() }

    @Test
    fun `rotation preserves media trash and extensions and rejects replayed headers`() = withVault { file ->
        val plain = ByteArray(100_000) { (it % 251).toByte() }
        val newRecovery = ByteArray(32) { 93 }
        var oldHeader = byteArrayOf()
        var objectId = UUID.randomUUID()
        var originalEntries = emptyList<Entry>()
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { source ->
            oldHeader = source.copyHeaderRaw()
            source.applyMutation(source.identity().sequence, listOf(PmvVaultStore.ObjectImport(
                ByteArrayInputStream(plain), plain.size.toLong(), objectId, 1, PmvAttachmentCodec.Kind.IMAGE,
            ))) { refs ->
                val ref = refs.single()
                originalEntries = listOf(entry("image", "image").copy(fields = mapOf("images" to
                    JsonArray(listOf(PmvMediaRef.Ref(ref.objectId, ref.generation, ref.kind, ref.size, ref.sha256).toJson())))),
                    entry("trash", "trash").copy(deletedAt = 1.0))
                PmvVaultStore.MutationContent(metadata("extension preserved"), originalEntries)
            }
            source.rewrapPasswordProfile(password, PmvKdfProfile.HARDENED)
            source.rotatePassword(newPassword, newRecovery)
        }
        PmvVaultStore.openPassword(file, newPassword).use { target ->
            assertEquals(originalEntries, target.listSummaries().map { target.readEntry(it.entryId) })
            assertEquals(JsonPrimitive("extension preserved"), target.readMetadata()["future_metadata"])
            val output = ByteArrayOutputStream()
            target.openObject(objectId, 1, output)
            assertArrayEquals(plain, output.toByteArray())
            assertEquals(2L, target.identity().keyRevision)
            assertEquals(PmvKdfProfile.HARDENED.parameters, target.kdfParameters())
            target.saveFull(target.readMetadata(), originalEntries + entry("after-change", "new secret"), target.identity().sequence)
        }
        PmvVaultStore.openRecovery(file, newRecovery).close()
        assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openPassword(file, password).close() }
        assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openRecovery(file, recoverySecret).close() }
        RandomAccessFile(file, "rw").use {
            it.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET); it.write(oldHeader)
            it.seek(PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET); it.write(oldHeader)
        }
        assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openPassword(file, password).close() }
        oldHeader.fill(0)
    }

    @Test
    fun `rotation failure before atomic replace leaves original vault unchanged`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("safe", "safe"))).close()
        val original = file.readBytes()
        PmvVaultStore.openPassword(file, password).use { source ->
            assertThrows(IllegalStateException::class.java) {
                source.rotatePassword(newPassword, recoverySecret) { error("simulated interruption") }
            }
        }
        assertArrayEquals(original, file.readBytes())
        PmvVaultStore.openPassword(file, password).close()
        assertTrue(file.parentFile!!.listFiles()!!.none { it.name.endsWith(".rekey.tmp") })
    }

    @Test
    fun `password change revokes root recovered from old header`() = withVault { file ->
        val before = PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("rotation", "original"))).use {
            it.copyRootKeyForDeviceUnlock()
        }
        try {
            PmvVaultStore.openPassword(file, password).use { it.rotatePassword(newPassword, recoverySecret) }
            val accepted = runCatching { PmvVaultStore.openRootKey(file, before).use { it.readMetadata() } }.isSuccess
            assertFalse("Old header root must not authenticate the changed vault", accepted)
        } finally { before.fill(0) }
    }

    @Test
    fun `vault file never contains the password or direct syncable passkey key material`() = withVault { file ->
        val privateKeyMarker = "syncable-passkey-private-key-must-remain-encrypted"
        val passkeyEntry = entry("encrypted-passkey", "Passkey").copy(
            fields = mapOf(
                EntryModules.FIELD_KEY to JsonArray(
                    listOf(
                        EntryModules.create(com.vault.model.ModuleType.PASSKEY).let { module ->
                            JsonObject(
                                module + ("value" to JsonObject(mapOf("private_key" to JsonPrimitive(privateKeyMarker)))),
                            )
                        },
                    ),
                ),
            ),
        )

        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(passkeyEntry)).close()

        val raw = file.readBytes()
        try {
            assertFalse(raw.containsSubsequence(password))
            assertFalse(raw.containsSubsequence(privateKeyMarker.encodeToByteArray()))
            PmvVaultStore.openPassword(file, password).use { session ->
                val restored = session.readEntry(UUID.fromString(passkeyEntry.id))!!
                val value = restored.fields.getValue(EntryModules.FIELD_KEY).jsonArray
                    .single().jsonObject.getValue("value").jsonObject
                assertEquals(privateKeyMarker, value.getValue("private_key").jsonPrimitive.content)
            }
        } finally {
            raw.fill(0)
        }
    }

    @Test
    fun `create opens with password and recovery and preserves metadata and extension fields`() = withVault { file ->
        val entry = entry("first", "initial").copy(
            fields = mapOf("future_extension" to JsonObject(mapOf("answer" to JsonPrimitive(42)))),
        )
        val secondEntry = entry("second", "second")
        val trashEntry = entry("trash", "trashed").copy(deletedAt = 2.0)
        val created = PmvVaultStore.create(
            file,
            password,
            recoverySecret,
            metadata(),
            listOf(secondEntry, trashEntry, entry),
        )
        val vaultId = created.identity().vaultId
        assertEquals(1L, created.identity().sequence)
        assertEquals(1L, created.identity().keyRevision)
        assertEquals(1L, created.identity().headerRevision)
        created.close()

        PmvVaultStore.openPassword(file, password).use { session ->
            assertEquals(vaultId, session.identity().vaultId)
            assertEquals("initial", session.readEntry(UUID.fromString(entry.id))?.title)
            assertEquals(
                JsonPrimitive(42),
                session.readEntry(UUID.fromString(entry.id))?.fields
                    ?.get("future_extension")
                    ?.let { (it as JsonObject)["answer"] },
            )
            assertEquals("kept", session.readMetadata()["future_metadata"]?.let { (it as JsonPrimitive).content })
            assertEquals(listOf("second", "initial", "trashed"), session.listSummaries().map { it.displayTitle })
            assertEquals("trashed", session.readEntry(UUID.fromString(trashEntry.id))?.title)
            assertEquals(listOf(UUID.fromString(secondEntry.id)), session.queryDomain("second.example"))
            assertEquals(listOf(UUID.fromString(entry.id)), session.queryPackage("com.example.first"))
            assertTrue(session.queryDomain("trash.example").isEmpty())
        }
        PmvVaultStore.openRecovery(file, recoverySecret).use { session ->
            assertEquals(vaultId, session.identity().vaultId)
            assertNotNull(session.readEntry(UUID.fromString(entry.id)))
        }
    }

    @Test
    fun `touchKeyRevision persists logical key revision bump and timestamp`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            assertEquals(0L, session.readMetadata().syncMetaKeyRevision())
            session.touchKeyRevision(1234.5)
            assertEquals(1L, session.readMetadata().syncMetaKeyRevision())
            assertEquals(1234.5, session.readMetadata().syncMetaKeyUpdatedAt(), 0.0)
        }
        // 重启后从磁盘读回仍保持 +1，避免“修改后版本回退”。
        PmvVaultStore.openPassword(file, password).use { session ->
            assertEquals(1L, session.readMetadata().syncMetaKeyRevision())
            assertEquals(1234.5, session.readMetadata().syncMetaKeyUpdatedAt(), 0.0)
        }
    }

    @Test
    fun `wrong credentials are rejected and completed password rewrap retires old password`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "one"))).use { session ->
            assertThrows(IllegalArgumentException::class.java) {
                PmvVaultStore.openPassword(file, "wrong".encodeToByteArray())
            }
            assertThrows(IllegalArgumentException::class.java) {
                PmvVaultStore.openRecovery(file, ByteArray(32) { 0x55 })
            }
            session.rewrapPassword(password, newPassword)
        }
        assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openPassword(file, password) }
        PmvVaultStore.openPassword(file, newPassword).use { assertEquals(1L, it.identity().sequence) }
        PmvVaultStore.openRecovery(file, recoverySecret).use { assertEquals(1L, it.identity().sequence) }
    }

    @Test
    fun `profile rewrap upgrades only PMVH parameters and remains recovery accessible`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "one"))).use { session ->
            val before = session.identity()
            assertEquals(PmvKdfProfile.STANDARD.parameters, session.kdfParameters())
            session.rewrapPasswordProfile(password, PmvKdfProfile.HARDENED)
            assertEquals(PmvKdfProfile.HARDENED.parameters, session.kdfParameters())
            assertEquals(before.keyRevision, session.identity().keyRevision)
            assertEquals(before.headerRevision + 1, session.identity().headerRevision)
        }
        PmvVaultStore.openPassword(file, password).use {
            assertEquals(PmvKdfProfile.HARDENED.parameters, it.kdfParameters())
            assertEquals(1L, it.identity().sequence)
        }
        PmvVaultStore.openRecovery(file, recoverySecret).use {
            assertEquals(PmvKdfProfile.HARDENED.parameters, it.kdfParameters())
            assertEquals(1L, it.identity().sequence)
        }
    }

    @Test
    fun `login with url-only package binding is still indexed for autofill`() = withVault { file ->
        // 旧库升级常见形态：包名只存在 url 字段（无 target_app），索引必须可命中。
        val appLogin = entry("apponly", "App only").copy(
            targetApp = "",
            url = "com.example.legacy.app",
        )
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(appLogin)).use { session ->
            assertEquals(
                listOf(UUID.fromString(appLogin.id)),
                session.queryPackage("com.example.legacy.app"),
            )
        }
    }

    @Test
    fun `legacy module bindings are indexed for autofill`() = withVault { file ->
        // 旧库升级常见形态：网址/包名只存在自定义模块，顶层 url/targetApp 为空。
        val legacy = entry("legacy", "Legacy").copy(
            url = "",
            targetApp = "",
            fields = mapOf(
                EntryModules.FIELD_KEY to Json.parseToJsonElement(
                    """[
                        {"type":"url","value":"https://example.com/login"},
                        {"type":"target_app","value":"com.example.legacy.app"}
                    ]""",
                ).jsonArray,
            ),
        )
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(legacy)).use { session ->
            assertEquals(
                listOf(UUID.fromString(legacy.id)),
                session.queryDomain("example.com"),
            )
            assertEquals(
                listOf(UUID.fromString(legacy.id)),
                session.queryPackage("com.example.legacy.app"),
            )
        }
    }

    @Test
    fun `all verified autofill bindings are indexed`() = withVault { file ->
        val fields = AutofillOriginMetadata.addBinding(
            AutofillOriginMetadata.addBinding(
                emptyMap(),
                TargetOrigin.Web("accounts.example.com"),
            ),
            TargetOrigin.AndroidPackage("com.example.app", setOf("a".repeat(64))),
        )
        val login = entry("bindings", "Bindings").copy(url = "", targetApp = "", fields = fields)

        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(login)).use { session ->
            assertEquals(listOf(UUID.fromString(login.id)), session.queryDomain("accounts.example.com"))
            assertEquals(listOf(UUID.fromString(login.id)), session.queryPackage("com.example.app"))
        }
    }

    @Test
    fun `interrupted second header-slot rewrite leaves both old and new recovery paths`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "one"))).close()
        val oldPrimary = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
        RandomAccessFile(file, "r").use { input ->
            input.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
            input.readFully(oldPrimary)
        }
        PmvVaultStore.openPassword(file, password).use { it.rewrapPassword(password, newPassword) }
        // Model power loss after the secondary new-password slot is durable but before primary replacement.
        RandomAccessFile(file, "rw").use { output ->
            output.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET)
            output.write(oldPrimary)
            output.fd.sync()
        }
        oldPrimary.fill(0)
        PmvVaultStore.openPassword(file, newPassword).use { assertEquals(1L, it.identity().sequence) }
        PmvVaultStore.openPassword(file, password).use { assertEquals(1L, it.identity().sequence) }
    }

    @Test
    fun `two saves form a strict parent chain and reject stale writers`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "v1"))).close()
        PmvVaultStore.openPassword(file, password).use { first ->
            PmvVaultStore.openPassword(file, password).use { stale ->
                val parent = first.identity().latestCommitId
                first.saveFull(metadata("m2"), listOf(entry("first", "v2")), expectedSequence = 1)
                assertEquals(2L, first.identity().sequence)
                assertTrue(first.identity().latestCommitId != parent)
                assertEquals(parent, first.identity().parentCommitId)
                val secondCommit = first.identity().latestCommitId
                first.saveFull(metadata("m3"), listOf(entry("first", "v3")), expectedSequence = 2)
                assertEquals(3L, first.identity().sequence)
                assertEquals(secondCommit, first.identity().parentCommitId)
                assertThrows(IllegalArgumentException::class.java) {
                    stale.saveFull(metadata("stale"), listOf(entry("first", "stale")), expectedSequence = 1)
                }
            }
        }
        PmvVaultStore.openPassword(file, password).use {
            assertEquals("v3", it.readEntry(entryId("first"))?.title)
            assertEquals("m3", (it.readMetadata()["future_metadata"] as JsonPrimitive).content)
        }
    }

    @Test
    fun `one damaged header slot falls back to the authenticated peer slot`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "one"))).close()
        RandomAccessFile(file, "rw").use { output ->
            output.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET + 200)
            val original = output.read()
            output.seek(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET + 200)
            output.write(original xor 1)
            output.fd.sync()
        }
        PmvVaultStore.openPassword(file, password).use { assertEquals("one", it.readEntry(entryId("first"))?.title) }
    }

    @Test
    fun `damaged newest target entry falls back to the previous committed snapshot`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry("first", "v1"))).use { session ->
            session.saveFull(metadata("v2"), listOf(entry("first", "v2")), 1)
            session.saveFull(metadata("v3"), listOf(entry("first", "v3")), 2)
        }
        corruptNewestEntry(file, entryId("first"))
        PmvVaultStore.openPassword(file, password).use {
            assertEquals("v2", it.readEntry(entryId("first"))?.title)
        }
    }

    @Test
    fun `damaged newest login index fails closed without returning mappings from an older origin`() = withVault { file ->
        val entry = entry("first", "v1")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(entry)).use { session ->
            session.saveFull(
                metadata("url-modified"),
                listOf(entry.copy(title = "v2", url = "https://new-origin.example/login")),
                1,
            )
        }
        corruptNewestBlock(file, PmvContainerFormat.BlockType.LOGIN_INDEX)
        PmvVaultStore.openPassword(file, password).use { session ->
            assertEquals(2L, session.identity().sequence)
            assertThrows(IllegalArgumentException::class.java) { session.queryDomain("first.example") }
            assertThrows(IllegalArgumentException::class.java) { session.queryDomain("new-origin.example") }
            assertEquals("v2", session.readEntry(UUID.fromString(entry.id))?.title)
        }
    }

    @Test
    fun `RP ID index reads passkey modules from every active entry and deduplicates`() = withVault { file ->
        val fixture = Json.parseToJsonElement(
            File(requireNotNull(System.getProperty("spec.dir")), "passkey_v3_fixtures.json").readText(),
        ).jsonObject["legacyV2"]!!.jsonObject["valid"]!!.jsonArray.first().jsonObject["record"]!!.jsonObject
        fun passkeyModule(rpId: String) = JsonObject(mapOf(
            "type" to JsonPrimitive("passkey"),
            "value" to JsonObject(fixture + ("rp_id" to JsonPrimitive(rpId))),
        ))
        val login = entry("module-login", "module login").copy(fields = mapOf(
            "modules" to JsonArray(listOf(passkeyModule("example.com"), passkeyModule("example.com"))),
        ))
        val note = entry("module-note", "module note").copy(
            secretType = SecretType.SECURE_NOTE,
            fields = mapOf("modules" to JsonArray(listOf(passkeyModule("note.example")))),
        )
        val legacy = entry("legacy-passkey", "legacy").copy(
            secretType = SecretType.PASSKEY,
            fields = mapOf("rp_id" to JsonPrimitive("legacy.example")),
        )
        val deleted = entry("deleted-passkey", "deleted").copy(
            deletedAt = 3.0,
            fields = mapOf("modules" to JsonArray(listOf(passkeyModule("deleted.example")))),
        )
        val invalid = entry("invalid-passkey", "invalid").copy(fields = mapOf(
            "rp_id" to JsonPrimitive("ignored-top.example"),
            "modules" to JsonArray(listOf(
                JsonPrimitive("not-an-object"),
                JsonObject(mapOf("type" to JsonPrimitive("password"), "value" to JsonObject(
                    mapOf("rp_id" to JsonPrimitive("wrong-type.example")),
                ))),
                JsonObject(mapOf("type" to JsonPrimitive("passkey"), "value" to JsonPrimitive("invalid"))),
                JsonObject(mapOf("type" to JsonPrimitive("passkey"), "value" to JsonObject(
                    mapOf("rp_id" to JsonPrimitive(7)),
                ))),
            )),
        ))
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(login, note, legacy, deleted, invalid)).use {
            assertEquals(listOf(UUID.fromString(login.id)), it.queryRpId("example.com"))
            assertEquals(listOf(UUID.fromString(note.id)), it.queryRpId("note.example"))
            assertEquals(listOf(UUID.fromString(legacy.id)), it.queryRpId("legacy.example"))
            assertTrue(it.queryRpId("deleted.example").isEmpty())
            assertTrue(it.queryRpId("wrong-type.example").isEmpty())
            assertTrue(it.queryRpId("ignored-top.example").isEmpty())
        }
    }

    @Test
    fun `open traverses header candidates and rejects a newer header for another authenticated vault`() = withVault { file ->
        val other = File.createTempFile("pmv-vault-store-other-", ".pmv")
        try {
            val rootKey = PmvVaultStore.create(
                file,
                password,
                recoverySecret,
                metadata("expected"),
                listOf(entry("first", "expected")),
            ).use { it.copyRootKeyForDeviceUnlock() }
            PmvVaultStore.create(
                other,
                password,
                recoverySecret,
                metadata("wrong-vault"),
                listOf(entry("other", "wrong-vault")),
            ).use { it.rewrapPassword(password, password) }
            copyHeaderSlot(
                from = other,
                fromOffset = PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET,
                to = file,
                toOffset = PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET,
            )

            PmvVaultStore.openPassword(file, password).use {
                assertEquals("expected", it.readEntry(entryId("first"))?.title)
                assertEquals(1L, it.identity().headerRevision)
            }
            PmvVaultStore.openRecovery(file, recoverySecret).use {
                assertEquals("expected", it.readEntry(entryId("first"))?.title)
            }
            PmvVaultStore.openRootKey(file, rootKey).use {
                assertEquals("expected", it.readEntry(entryId("first"))?.title)
            }
            rootKey.fill(0)
        } finally {
            other.delete()
        }
    }

    @Test
    fun `identity is bound to the latest commit root even when latest metadata is damaged`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata("v1"), listOf(entry("first", "v1"))).use {
            val first = it.identity()
            assertEquals(32, first.rootDigest.size)
            it.saveFull(metadata("v2"), listOf(entry("first", "v2")), 1)
            val second = it.identity()
            assertEquals(2L, second.sequence)
            assertTrue(!first.rootDigest.contentEquals(second.rootDigest))
        }
        corruptNewestBlock(file, PmvContainerFormat.BlockType.OBJECT_METADATA)
        PmvVaultStore.openPassword(file, password).use {
            assertEquals(2L, it.identity().sequence)
            assertEquals(32, it.identity().rootDigest.size)
        }
    }

    @Test
    fun `device unlock root key copies are isolated and callback copies are cleared`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            val firstCopy = session.copyRootKeyForDeviceUnlock()
            val originalFirstByte = firstCopy[0]
            firstCopy[0] = (originalFirstByte.toInt() xor 1).toByte()
            val secondCopy = session.copyRootKeyForDeviceUnlock()
            assertEquals(originalFirstByte, secondCopy[0])
            PmvVaultStore.openRootKey(file, secondCopy).use { assertEquals(1L, it.identity().sequence) }
            firstCopy.fill(0)
            secondCopy.fill(0)

            lateinit var callbackCopy: ByteArray
            session.withRootKeyForDeviceUnlock { rootKey ->
                callbackCopy = rootKey
                PmvVaultStore.openRootKey(file, rootKey).use { assertEquals(1L, it.identity().sequence) }
            }
            assertTrue(callbackCopy.all { it == 0.toByte() })
        }
    }

    @Test
    fun `recovery rotation and recovery password reset retire the old credentials`() = withVault { file ->
        val newRecovery = ByteArray(32) { (it * 11 + 5).toByte() }
        try {
            PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
                session.rotateRecovery(recoverySecret, newRecovery)
            }
            assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openRecovery(file, recoverySecret) }
            PmvVaultStore.openRecovery(file, newRecovery).use { session ->
                session.resetPasswordWithRecovery(newRecovery, newPassword)
            }
            assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openPassword(file, password) }
            PmvVaultStore.openPassword(file, newPassword).use { assertEquals(1L, it.identity().sequence) }
            PmvVaultStore.openRecovery(file, newRecovery).use { assertEquals(1L, it.identity().sequence) }
        } finally {
            newRecovery.fill(0)
        }
    }

    @Test
    fun `password regenerates recovery key without the old recovery secret`() = withVault { file ->
        val newRecovery = ByteArray(32) { (it * 13 + 9).toByte() }
        try {
            PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
                session.regenerateRecoveryKey(password, newRecovery)
            }
            assertThrows(IllegalArgumentException::class.java) { PmvVaultStore.openRecovery(file, recoverySecret) }
            PmvVaultStore.openRecovery(file, newRecovery).use { assertEquals(1L, it.identity().sequence) }
            PmvVaultStore.openPassword(file, password).use { assertEquals(1L, it.identity().sequence) }
        } finally {
            newRecovery.fill(0)
        }
    }

    @Test
    fun `object import publishes indexes atomically and full save unlinks orphan records`() = withVault { file ->
        val firstId = entryId("first-object")
        val secondId = entryId("second-object")
        val firstPlain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 37) { (it * 17).toByte() }
        val secondPlain = "second streamed object".encodeToByteArray()
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            assertEquals(
                2L,
                session.importObject(
                    ByteArrayInputStream(firstPlain),
                    firstPlain.size.toLong(),
                    firstId,
                    1,
                    PmvAttachmentCodec.Kind.ATTACHMENT,
                    1,
                ).sequence,
            )
            assertEquals(
                3L,
                session.importObject(
                    ByteArrayInputStream(secondPlain),
                    secondPlain.size.toLong(),
                    secondId,
                    4,
                    PmvAttachmentCodec.Kind.IMAGE,
                    2,
                ).sequence,
            )
            val firstOutput = ByteArrayOutputStream()
            session.openObject(firstId, 1, firstOutput)
            assertTrue(firstPlain.contentEquals(firstOutput.toByteArray()))
            val rangeOutput = ByteArrayOutputStream()
            session.openObjectRange(firstId, 1, PmvAttachmentCodec.CHUNK_SIZE.toLong() - 9, 28, rangeOutput)
            assertTrue(firstPlain.copyOfRange(PmvAttachmentCodec.CHUNK_SIZE - 9, PmvAttachmentCodec.CHUNK_SIZE + 19)
                .contentEquals(rangeOutput.toByteArray()))
            val secondOutput = ByteArrayOutputStream()
            session.openObject(secondId, 4, secondOutput)
            assertTrue(secondPlain.contentEquals(secondOutput.toByteArray()))

            session.saveFull(metadata("after-objects"), emptyList(), expectedSequence = 3)
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(firstId, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `corrupted media chunk fails closed on object open`() = withVault { file ->
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 13) { (it * 5).toByte() }
        val id = entryId("media-corrupt")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            session.importObject(
                ByteArrayInputStream(plain),
                plain.size.toLong(),
                id,
                1,
                PmvAttachmentCodec.Kind.ATTACHMENT,
                1,
            )
        }
        corruptNewestBlock(file, PmvContainerFormat.BlockType.ATTACHMENT_CHUNK)
        PmvVaultStore.openPassword(file, password).use { session ->
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(id, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `permanent purge publishes tombstone and excludes the old Entry`() = withVault { file ->
        val removed = entry("purged", "gone")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(removed)).use { session ->
            val purgeMetadata = JsonObject(metadata().toMutableMap().apply {
                put("purge_tombstones", JsonObject(mapOf(removed.id to JsonPrimitive(9.25))))
            })
            session.saveFull(purgeMetadata, emptyList(), expectedSequence = 1)
            assertTrue(session.listSummaries().isEmpty())
            assertEquals(null, session.readEntry(UUID.fromString(removed.id)))
            assertTrue(hasBlock(file, PmvContainerFormat.BlockType.TOMBSTONE))
        }
    }

    @Test
    fun `compact reclaims obsolete blocks without changing signed identity`() = withVault { file ->
        var current = entry("compact", "revision-1")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(current)).use { session ->
            for (revision in 2L..6L) {
                current = current.copy(title = "revision-$revision", updatedAt = revision.toDouble())
                session.saveFull(metadata(), listOf(current), expectedSequence = revision - 1)
            }
            val identity = session.identity()
            val before = file.length()
            assertEquals(identity, session.compact())
            assertTrue(file.length() < before)
            assertEquals(identity, session.identity())
            assertEquals("revision-6", session.readEntry(UUID.fromString(current.id))?.title)
        }
        PmvVaultStore.openPassword(file, password).use { session ->
            assertEquals("revision-6", session.readEntry(UUID.fromString(current.id))?.title)
        }
    }

    @Test
    fun `compact preserves the full authenticated commit lineage`() = withVault { file ->
        var current = entry("compact-lineage", "r1")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(current)).use { session ->
            for (revision in 2L..4L) {
                current = current.copy(title = "r$revision", updatedAt = revision.toDouble())
                session.saveFull(metadata(), listOf(current), expectedSequence = revision - 1)
            }
            val identity = session.identity()
            session.compact()
            // 压缩后头部提交身份不变，且仍能重新打开（含祖先链读取路径）
            assertEquals(identity, session.identity())
        }
        // 通过容器扫描确认祖先 COMMIT 块仍存在：latest 之前的所有提交块应可解码认证
        PmvVaultStore.openPassword(file, password).use { session ->
            val latest = session.identity()
            val rootKeys = PmvKeySchedule.deriveRootKeys(
                session.copyRootKeyForDeviceUnlock(),
                latest.vaultId,
            )
            val commitIds = mutableListOf<java.util.UUID>()
            PmvAppendOnlyFile.open(file, rootKeys.integrityKey).use { container ->
                val state = container.state().superblock
                var offset = PmvContainerFormat.DATA_START
                while (offset < state.committedFileEnd) {
                    val block = container.readBlock(offset)
                    if (block.header.blockType == PmvContainerFormat.BlockType.COMMIT) {
                        commitIds += block.header.objectId
                    }
                    offset += PmvContainerFormat.BLOCK_HEADER_SIZE + block.header.cipherSize
                }
            }
            // 4 个提交（create + 3 次 saveFull）应全部保留
            assertEquals(4, commitIds.size)
            assertEquals(commitIds.last(), latest.latestCommitId)
        }
    }

    @Test
    fun `interrupted compact leaves the authoritative file unchanged`() = withVault { file ->
        val value = entry("compact-fault", "old")
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(value)).use { session ->
            session.saveFull(metadata(), listOf(value.copy(title = "new", updatedAt = 2.0)), 1)
            val identity = session.identity()
            val length = file.length()
            assertThrows(IllegalStateException::class.java) {
                session.compactForTest { stage ->
                    if (stage == "beforeReplace") throw IllegalStateException("injected compact interruption")
                }
            }
            assertEquals(length, file.length())
            assertEquals(identity, session.identity())
            assertEquals("new", session.readEntry(UUID.fromString(value.id))?.title)
            assertTrue(file.parentFile.listFiles().orEmpty().none { it.name.endsWith(".compact.tmp") })
        }
    }

    @Test
    fun `failed object import rolls back streamed blocks without publishing an index root`() = withVault { file ->
        val objectId = entryId("truncated-object")
        // The first complete chunk is appended before the declared trailing byte is found missing.
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE) { (it * 5).toByte() }
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            val committedLength = file.length()
            assertThrows(IllegalArgumentException::class.java) {
                session.importObject(
                    ByteArrayInputStream(plain),
                    expectedSize = plain.size + 1L,
                    objectId = objectId,
                    generation = 1,
                    kind = PmvAttachmentCodec.Kind.ATTACHMENT,
                    expectedSequence = 1,
                )
            }
            assertEquals(1L, session.identity().sequence)
            assertEquals(committedLength, file.length())
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(objectId, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `object reads never combine object and chunk indexes from different snapshots`() = withVault { file ->
        val oldId = entryId("old-object")
        val newId = entryId("new-object")
        val oldPlain = "old snapshot object".encodeToByteArray()
        val newPlain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 11) { (it * 3).toByte() }
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            session.importObject(ByteArrayInputStream(oldPlain), oldPlain.size.toLong(), oldId, 1,
                PmvAttachmentCodec.Kind.ATTACHMENT, 1)
            session.importObject(ByteArrayInputStream(newPlain), newPlain.size.toLong(), newId, 1,
                PmvAttachmentCodec.Kind.ATTACHMENT, 2)
        }
        corruptNewestBlock(file, PmvContainerFormat.BlockType.INDEX_PAGE)
        PmvVaultStore.openPassword(file, password).use { session ->
            val output = ByteArrayOutputStream()
            session.openObject(oldId, 1, output)
            assertTrue(oldPlain.contentEquals(output.toByteArray()))
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(newId, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `vault mutation publishes entries metadata and two objects in one commit`() = withVault { file ->
        val firstId = entryId("mutation-first")
        val secondId = entryId("mutation-second")
        val entryId = entryId("mutation-entry")
        val first = "first atomic object".encodeToByteArray()
        val second = "second atomic object".encodeToByteArray()
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            val result = session.applyMutation(
                expectedSequence = 1,
                objectImports = listOf(
                    PmvVaultStore.ObjectImport(ByteArrayInputStream(first), first.size.toLong(), firstId, 2,
                        PmvAttachmentCodec.Kind.IMAGE),
                    PmvVaultStore.ObjectImport(ByteArrayInputStream(second), second.size.toLong(), secondId, 7,
                        PmvAttachmentCodec.Kind.ATTACHMENT),
                ),
            ) { refs ->
                assertEquals(listOf(firstId, secondId), refs.map { it.objectId })
                val linked = entry("mutation-entry", "linked").copy(
                    fields = mapOf(
                        "media_refs" to JsonArray(refs.map { PmvMediaRef.fromStoreRef(it).toJson() }),
                    ),
                )
                PmvVaultStore.MutationContent(metadata("atomic"), listOf(linked))
            }
            assertEquals(2L, result.identity.sequence)
            assertEquals(2, result.objectRefs.size)
            assertEquals(secondId, PmvMediaRef.fromJson(
                requireNotNull((session.readEntry(entryId)?.fields?.get("media_refs") as? JsonArray)?.get(1)),
            ).objectId)
            ByteArrayOutputStream().use { output ->
                session.openObject(secondId, 7, output)
                assertTrue(second.contentEquals(output.toByteArray()))
            }
            session.saveFull(metadata("preserved"), listOf(requireNotNull(session.readEntry(entryId))), 2)
            ByteArrayOutputStream().use { output ->
                session.openObject(firstId, 2, output)
                assertTrue(first.contentEquals(output.toByteArray()))
            }
            assertEquals(3L, session.identity().sequence)
            val beforeCompact = file.length()
            val compactIdentity = session.identity()
            assertEquals(compactIdentity, session.compact())
            assertTrue(file.length() < beforeCompact)
            ByteArrayOutputStream().use { output ->
                session.openObject(secondId, 7, output)
                assertTrue(second.contentEquals(output.toByteArray()))
            }
        }
    }

    @Test
    fun `device authorization registry persists in signed metadata`() = withVault { file ->
        val deviceId = UUID.randomUUID()
        val devicePublic = ByteArray(32) { (it + 5).toByte() }
        val signed = PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            session.signDeviceAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    vaultId = session.identity().vaultId,
                    deviceId = deviceId,
                    devicePublicKey = devicePublic,
                    permissions = PmvSyncAuthorization.PERMISSION_READ,
                    issuedAtEpochMillis = 100L,
                    expiresAtEpochMillis = 0L,
                    revokedAtEpochMillis = 0L,
                    epoch = 1,
                ),
            )
        }
        PmvVaultStore.openPassword(file, password).use { session ->
            val updated = PmvDeviceRegistry.withRegistry(session.readMetadata(), listOf(signed))
            val entries = session.listSummaries().map { summary ->
                requireNotNull(session.readEntry(summary.entryId)) { "PMVE EntryIndex 引用了不存在的 Entry" }
            }
            session.saveFull(updated, entries, session.identity().sequence)
        }
        PmvVaultStore.openPassword(file, password).use { session ->
            val records = PmvDeviceRegistry.decode(session.readMetadata())
            assertEquals(1, records.size)
            assertTrue(PmvSyncAuthorization.verifyAuthorization(records.single(), session.identity().signingPublicKey))
        }
    }

    @Test
    fun `divergent vaults converge by merging registries on the remote head`() = withTempDirectory { dir ->
        val base = File(dir, "base.pmv")
        val fileA = File(dir, "a.pmv")
        val fileB = File(dir, "b.pmv")
        val deviceA = VaultDeviceIdentity.generate()
        val deviceB = VaultDeviceIdentity.generate()
        try {
            val baseEntry = entry("base", "base-entry")
            PmvVaultStore.create(base, password, recoverySecret, metadata(), listOf(baseEntry)).close()
            val permissions = PmvSyncAuthorization.PERMISSION_READ or
                PmvSyncAuthorization.PERMISSION_WRITE or PmvSyncAuthorization.PERMISSION_AUTHORIZE
            fun enroll(file: File, device: VaultDeviceIdentity) {
                base.copyTo(file, overwrite = true)
                PmvVaultStore.openPassword(file, password).use { session ->
                    val auth = session.signDeviceAuthorization(
                        PmvSyncAuthorization.DeviceAuthorization(
                            vaultId = session.identity().vaultId,
                            deviceId = device.deviceId,
                            devicePublicKey = device.publicKey,
                            permissions = permissions,
                            issuedAtEpochMillis = 100L,
                            expiresAtEpochMillis = 0L,
                            revokedAtEpochMillis = 0L,
                            epoch = 1,
                        ),
                    )
                    val meta = PmvDeviceRegistry.withRegistry(session.readMetadata(), listOf(auth))
                    val entries = session.listSummaries().map { summary ->
                        requireNotNull(session.readEntry(summary.entryId)) { "Entry 缺失" }
                    }
                    session.saveFull(meta, entries, session.identity().sequence)
                }
            }
            enroll(fileA, deviceA)
            enroll(fileB, deviceB)

            // 以 B 为“远端头”，把 A 与 B 的注册表 union 后提交到 B 之上。
            PmvVaultStore.openPassword(fileB, password).use { session ->
                val localRegistry = PmvVaultStore.openPassword(fileA, password).use { a ->
                    PmvDeviceRegistry.decode(a.readMetadata())
                }
                val remoteRegistry = PmvDeviceRegistry.decode(session.readMetadata())
                val mergedRegistry = (localRegistry + remoteRegistry)
                    .groupBy { it.deviceId }
                    .map { (_, records) -> records.maxBy { it.epoch } }
                val entries = session.listSummaries().map { summary ->
                    requireNotNull(session.readEntry(summary.entryId)) { "Entry 缺失" }
                }
                session.saveFull(
                    PmvDeviceRegistry.withRegistry(session.readMetadata(), mergedRegistry),
                    entries,
                    session.identity().sequence,
                )
            }
            PmvVaultStore.openPassword(fileB, password).use { session ->
                val records = PmvDeviceRegistry.decode(session.readMetadata())
                assertEquals(setOf(deviceA.deviceId, deviceB.deviceId), records.map { it.deviceId }.toSet())
                assertEquals("base-entry", session.listSummaries().single().displayTitle)
            }
        } finally {
            deviceA.close()
            deviceB.close()
        }
    }

    @Test
    fun `signed autofill origin metadata is indexed and rebuilt after update`() = withVault { file ->
        val id = UUID.fromString(entry("origin", "Origin").id)
        val web = entry("origin", "Origin").copy(
            url = "", targetApp = "",
            fields = mapOf("_autofill_origin" to Json.parseToJsonElement(
                """{"kind":"web","host":"accounts.example.com","browser_package":"com.browser","browser_signing_cert_sha256":[]}""",
            )),
        )
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(web)).use { session ->
            assertEquals(listOf(id), session.queryDomain("accounts.example.com"))
            val app = web.copy(
                updatedAt = 2.0,
                fields = mapOf("_autofill_origin" to Json.parseToJsonElement(
                    """{"kind":"android","package":"com.example.login","signing_cert_sha256":[]}""",
                )),
            )
            session.saveFull(metadata(), listOf(app), session.identity().sequence)
            assertTrue(session.queryDomain("accounts.example.com").isEmpty())
            assertEquals(listOf(id), session.queryPackage("com.example.login"))
        }
    }

    @Test
    fun `large structured entries are adaptively compressed and round trip losslessly`() = withVault { file ->
        val large = entry("compressed", "Compressed").copy(notes = "repeatable secret text ".repeat(10_000))
        var authenticationKey: ByteArray? = null
        PmvVaultStore.create(file, password, recoverySecret, metadata(), listOf(large)).use { session ->
            assertEquals(large.notes, session.readEntry(UUID.fromString(large.id))?.notes)
            val rootKey = session.copyRootKeyForDeviceUnlock()
            try {
                PmvKeySchedule.deriveRootKeys(rootKey, session.identity().vaultId).use { keys ->
                    authenticationKey = keys.integrityKey.copyOf()
                }
            } finally {
                rootKey.fill(0)
            }
        }
        PmvAppendOnlyFile.open(file, requireNotNull(authenticationKey)).use { container ->
            val entryBlocks = sequence {
                var offset = PmvContainerFormat.DATA_START
                val end = container.state().superblock.committedFileEnd
                while (offset < end) {
                    val block = container.readBlock(offset)
                    if (block.header.blockType == PmvContainerFormat.BlockType.ENTRY) yield(block)
                    offset += PmvContainerFormat.BLOCK_HEADER_SIZE + block.ciphertext.size
                }
            }.toList()
            assertEquals(1, entryBlocks.size)
            assertEquals(PmvCompression.CODEC_ZSTD_FRAME_V1, entryBlocks.single().header.codecId)
        }
    }

    @Test
    fun `merge candidate adopts newest password header so new password unlocks`() = withTempDirectory { dir ->
        val base = File(dir, "base.pmv")
        val local = File(dir, "local.pmv")
        val candidate = File(dir, "candidate.pmv")
        PmvVaultStore.create(base, password, recoverySecret, metadata(), listOf(entry("base", "base-entry"))).close()
        base.copyTo(local, overwrite = true)
        base.copyTo(candidate, overwrite = true)

        // 本端（local）修改主密码 → 头部 rev 2 + 新密码槽。
        val localHeaderRaw = PmvVaultStore.openPassword(local, password).use { session ->
            session.rewrapPassword(password, newPassword)
            session.copyHeaderRaw()
        }
        // 候选端（candidate）新增条目 → 与 local 分叉。
        PmvVaultStore.openPassword(candidate, password).use { session ->
            val entries = session.listSummaries().map { requireNotNull(session.readEntry(it.entryId)) } +
                entry("remote", "remote-entry")
            session.saveFull(session.readMetadata(), entries, session.identity().sequence)
        }
        // 合并：候选端提交合并内容后，采纳本端（更新）密码头部。
        val rootKey = PmvVaultStore.openPassword(local, newPassword).use { it.copyRootKeyForDeviceUnlock() }
        try {
            PmvVaultStore.openRootKey(candidate, rootKey).use { session ->
                val entries = session.listSummaries().map { requireNotNull(session.readEntry(it.entryId)) }
                session.saveFull(session.readMetadata(), entries, session.identity().sequence)
                session.adoptHeader(localHeaderRaw)
            }
        } finally {
            rootKey.fill(0)
            localHeaderRaw.fill(0)
        }
        // 合并文件必须可用新密码解锁、旧密码失效，且条目保留。
        PmvVaultStore.openPassword(candidate, newPassword).use { session ->
            assertTrue(session.listSummaries().any { it.displayTitle == "remote-entry" })
        }
        assertThrows(IllegalArgumentException::class.java) {
            PmvVaultStore.openPassword(candidate, password)
        }
    }

    @Test
    fun `merged candidate retains local only image and remote entry`() = withTempDirectory { dir ->
        val local = File(dir, "local.pmv")
        val remote = File(dir, "remote.pmv")
        PmvVaultStore.create(local, password, recoverySecret, metadata(), emptyList()).close()
        local.copyTo(remote)
        val plain = "local-only image".encodeToByteArray()
        val objectId = entryId("local-image")
        PmvVaultStore.openPassword(local, password).use { source ->
            source.applyMutation(1, listOf(PmvVaultStore.ObjectImport(
                ByteArrayInputStream(plain), plain.size.toLong(), objectId, 1, PmvAttachmentCodec.Kind.IMAGE,
            ))) { refs ->
                val ref = refs.single()
                val media = PmvMediaRef.Ref(ref.objectId, ref.generation, ref.kind, ref.size, ref.sha256)
                PmvVaultStore.MutationContent(metadata(), listOf(entry("local", "local").copy(
                    fields = mapOf("images" to JsonArray(listOf(media.toJson()))),
                )))
            }
            PmvVaultStore.openPassword(remote, password).use { target ->
                val remoteEntry = entry("remote", "remote")
                target.saveFull(metadata(), listOf(remoteEntry), 1)
                val localEntry = requireNotNull(source.readEntry(entryId("local")))
                target.saveMerged(source, metadata(), listOf(localEntry, remoteEntry), 2)
                assertEquals(3L, target.identity().sequence)
                val output = ByteArrayOutputStream()
                target.openObject(objectId, 1, output)
                assertArrayEquals(plain, output.toByteArray())
                assertEquals(2, target.listSummaries().size)
            }
            assertEquals(2L, source.identity().sequence)
        }
        PmvVaultStore.openPassword(remote, password).use { target ->
            val output = ByteArrayOutputStream()
            target.openObject(objectId, 1, output)
            assertArrayEquals(plain, output.toByteArray())
        }
    }

    @Test
    fun `merge preserves large metadata media and deduplicates repeated references`() = withTempDirectory { dir ->
        val local = File(dir, "local.pmv")
        val remote = File(dir, "remote.pmv")
        PmvVaultStore.create(local, password, recoverySecret, metadata(), emptyList()).close()
        local.copyTo(remote)
        val plain = ByteArray(PmvAttachmentCodec.CHUNK_SIZE + 17) { (it % 251).toByte() }
        val objectId = entryId("large-media")
        PmvVaultStore.openPassword(local, password).use { source ->
            source.applyMutation(1, listOf(PmvVaultStore.ObjectImport(
                ByteArrayInputStream(plain), plain.size.toLong(), objectId, 1, PmvAttachmentCodec.Kind.ATTACHMENT,
            ))) { refs ->
                val ref = refs.single().let { PmvMediaRef.Ref(it.objectId, it.generation, it.kind, it.size, it.sha256) }
                PmvVaultStore.MutationContent(JsonObject(metadata() + ("media_extension" to ref.toJson())),
                    listOf(entry("trash-media", "trash").copy(deletedAt = 1.0,
                        fields = mapOf("attachments" to JsonArray(listOf(ref.toJson(), ref.toJson()))))))
            }
            PmvVaultStore.openPassword(remote, password).use { target ->
                val entries = source.listSummaries().map { requireNotNull(source.readEntry(it.entryId)) }
                val head = target.identity()
                target.saveMerged(source, source.readMetadata(), entries, head.sequence)
                assertEquals(head.latestCommitId, target.identity().parentCommitId)
                assertEquals(head.sequence + 1, target.identity().sequence)
                // Existing objects must be reused on a subsequent merge.
                target.saveMerged(source, source.readMetadata(), entries, target.identity().sequence)
                val output = ByteArrayOutputStream()
                target.openObject(objectId, 1, output)
                assertArrayEquals(plain, output.toByteArray())
                assertEquals(1.0, target.readEntry(entryId("trash-media"))?.deletedAt)
            }
        }
    }

    @Test
    fun `merge rejects missing or conflicting media without changing either file`() = withTempDirectory { dir ->
        val local = File(dir, "local.pmv")
        val remote = File(dir, "remote.pmv")
        PmvVaultStore.create(local, password, recoverySecret, metadata(), emptyList()).close()
        local.copyTo(remote)
        val objectId = entryId("collision")
        fun add(session: PmvVaultStore.Session, plain: ByteArray): PmvMediaRef.Ref {
            val result = session.applyMutation(1, listOf(PmvVaultStore.ObjectImport(
                ByteArrayInputStream(plain), plain.size.toLong(), objectId, 1, PmvAttachmentCodec.Kind.IMAGE,
            ))) { refs ->
                val ref = refs.single().let { PmvMediaRef.Ref(it.objectId, it.generation, it.kind, it.size, it.sha256) }
                PmvVaultStore.MutationContent(metadata(), listOf(entry("image", "image").copy(
                    fields = mapOf("images" to JsonArray(listOf(ref.toJson()))))))
            }
            return result.objectRefs.single().let { PmvMediaRef.Ref(it.objectId, it.generation, it.kind, it.size, it.sha256) }
        }
        PmvVaultStore.openPassword(local, password).use { source ->
            val ref = add(source, byteArrayOf(1))
            PmvVaultStore.openPassword(remote, password).use { target ->
                add(target, byteArrayOf(2))
                val originalLocal = local.readBytes()
                val originalRemote = remote.readBytes()
                val cases = listOf(
                    listOf(ref), // same identity but different authenticated contents on target
                    listOf(ref.copy(objectId = entryId("missing"))),
                    listOf(ref, ref.copy(sha256 = ByteArray(32))),
                )
                cases.forEach { refs ->
                    assertThrows(IllegalArgumentException::class.java) {
                        target.saveMerged(source, metadata(), listOf(entry("merge", "merge").copy(
                            fields = mapOf("images" to JsonArray(refs.map { it.toJson() })))), 2)
                    }
                    assertArrayEquals(originalLocal, local.readBytes())
                    assertArrayEquals(originalRemote, remote.readBytes())
                }
            }
        }
    }

    @Test
    fun `second mutation object EOF rolls back first object and entry changes`() = withVault { file ->
        val firstId = entryId("rolled-back-first")
        val secondId = entryId("rolled-back-second")
        PmvVaultStore.create(file, password, recoverySecret, metadata("old"), emptyList()).use { session ->
            val committedLength = file.length()
            assertThrows(IllegalArgumentException::class.java) {
                session.applyMutation(
                    1,
                    listOf(
                        PmvVaultStore.ObjectImport(ByteArrayInputStream(byteArrayOf(1, 2)), 2, firstId, 1,
                            PmvAttachmentCodec.Kind.ATTACHMENT),
                        PmvVaultStore.ObjectImport(ByteArrayInputStream(byteArrayOf(3)), 2, secondId, 1,
                            PmvAttachmentCodec.Kind.ATTACHMENT),
                    ),
                ) { PmvVaultStore.MutationContent(metadata("new"), listOf(entry("never", "never"))) }
            }
            assertEquals(1L, session.identity().sequence)
            assertEquals(committedLength, file.length())
            assertEquals("old", session.readMetadata()["future_metadata"]?.jsonPrimitive?.content)
            assertThrows(IllegalArgumentException::class.java) {
                session.openObject(firstId, 1, ByteArrayOutputStream())
            }
        }
    }

    @Test
    fun `stale and cancelled vault mutations do not publish`() = withVault { file ->
        PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList()).use { session ->
            session.applyMutation(1) {
                assertTrue(it.isEmpty())
                PmvVaultStore.MutationContent(metadata("baseline-2"), emptyList())
            }
            var prepared = false
            assertThrows(IllegalArgumentException::class.java) {
                session.applyMutation(1) { prepared = true; PmvVaultStore.MutationContent(metadata(), emptyList()) }
            }
            assertTrue(!prepared)
            val cancelled = object : java.io.InputStream() {
                override fun read(): Int = throw CancellationException("cancelled")
            }
            assertThrows(CancellationException::class.java) {
                session.applyMutation(
                    2,
                    listOf(PmvVaultStore.ObjectImport(cancelled, 1, entryId("cancelled"), 1,
                        PmvAttachmentCodec.Kind.ATTACHMENT)),
                ) { PmvVaultStore.MutationContent(metadata(), emptyList()) }
            }
            assertEquals(2L, session.identity().sequence)
        }
    }

    @Test
    fun `closed session rejects every operation`() = withVault { file ->
        val session = PmvVaultStore.create(file, password, recoverySecret, metadata(), emptyList())
        session.close()
        assertThrows(IllegalStateException::class.java) { session.identity() }
        assertThrows(IllegalStateException::class.java) { session.listSummaries() }
        assertThrows(IllegalStateException::class.java) { session.readMetadata() }
        assertThrows(IllegalStateException::class.java) { session.readEntry(UUID.randomUUID()) }
        assertThrows(IllegalStateException::class.java) { session.queryDomain("example.com") }
        assertThrows(IllegalStateException::class.java) {
            session.importObject(ByteArrayInputStream(byteArrayOf(1)), 1, UUID.randomUUID(), 1,
                PmvAttachmentCodec.Kind.ATTACHMENT, expectedSequence = 1)
        }
        assertThrows(IllegalStateException::class.java) {
            session.openObject(UUID.randomUUID(), 1, ByteArrayOutputStream())
        }
        assertThrows(IllegalStateException::class.java) {
            session.openObjectRange(UUID.randomUUID(), 1, 0, 0, ByteArrayOutputStream())
        }
        assertThrows(IllegalStateException::class.java) {
            session.saveFull(metadata(), emptyList(), expectedSequence = 1)
        }
        assertThrows(IllegalStateException::class.java) {
            session.applyMutation(1) { PmvVaultStore.MutationContent(metadata(), emptyList()) }
        }
        assertThrows(IllegalStateException::class.java) { session.copyRootKeyForDeviceUnlock() }
        assertThrows(IllegalStateException::class.java) {
            session.withRootKeyForDeviceUnlock { error("must not run") }
        }
        assertThrows(IllegalStateException::class.java) {
            session.rotateRecovery(recoverySecret, ByteArray(32))
        }
        assertThrows(IllegalStateException::class.java) {
            session.resetPasswordWithRecovery(recoverySecret, newPassword)
        }
    }

    private fun metadata(marker: String = "kept") = JsonObject(
        mapOf(
            "schema" to JsonPrimitive(PmvVaultMetadataCodec.SCHEMA),
            "version" to JsonPrimitive(PmvVaultMetadataCodec.VERSION),
            "vault_id" to JsonPrimitive(UUID(0, 1).toString()),
            "entry_order" to JsonArray(emptyList()),
            "trash_order" to JsonArray(emptyList()),
            "sync_meta" to JsonObject(
                mapOf(
                    "device_id" to JsonPrimitive(UUID(0, 2).toString()),
                    "key_revision" to JsonPrimitive(0),
                ),
            ),
            "key_revision" to JsonPrimitive(0),
            "export_epoch" to JsonNull,
            "purge_tombstones" to JsonObject(emptyMap()),
            "future_metadata" to JsonPrimitive(marker),
        ),
    )

    private fun JsonObject.syncMetaKeyRevision(): Long =
        (this["sync_meta"] as? JsonObject)?.get("key_revision")
            ?.let { (it as JsonPrimitive).content.toLongOrNull() }
            ?: 0L

    private fun JsonObject.syncMetaKeyUpdatedAt(): Double =
        (this["sync_meta"] as? JsonObject)?.get("key_updated_at")
            ?.let { (it as JsonPrimitive).content.toDoubleOrNull() }
            ?: 0.0

    private fun entry(seed: String, title: String) = Entry(
        id = entryId(seed).toString(),
        title = title,
        username = "user@$seed.example",
        password = "secret",
        url = "https://$seed.example/login",
        targetApp = "com.example.$seed",
        secretType = "login",
        updatedAt = 1.25,
    )

    private fun entryId(seed: String): UUID = UUID.nameUUIDFromBytes(seed.encodeToByteArray())

    private fun corruptNewestEntry(file: File, entryId: UUID) {
        var newestOffset = -1L
        var newestRevision = -1L
        RandomAccessFile(file, "r").use { input ->
            var offset = PmvContainerFormat.DATA_START
            while (offset + PmvContainerFormat.BLOCK_HEADER_SIZE <= input.length()) {
                input.seek(offset)
                val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
                input.readFully(rawHeader)
                val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
                if (header.blockType == PmvContainerFormat.BlockType.ENTRY &&
                    header.objectId == entryId && header.objectRevision > newestRevision
                ) {
                    newestOffset = offset
                    newestRevision = header.objectRevision
                }
                offset += PmvContainerFormat.BLOCK_HEADER_SIZE + header.cipherSize
            }
        }
        require(newestOffset >= 0)
        RandomAccessFile(file, "rw").use { output ->
            output.seek(newestOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            val original = output.read()
            output.seek(newestOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            output.write(original xor 1)
            output.fd.sync()
        }
    }

    private fun hasBlock(file: File, blockType: PmvContainerFormat.BlockType): Boolean =
        RandomAccessFile(file, "r").use { input ->
            var offset = PmvContainerFormat.DATA_START
            while (offset + PmvContainerFormat.BLOCK_HEADER_SIZE <= input.length()) {
                input.seek(offset)
                val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
                input.readFully(rawHeader)
                val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
                if (header.blockType == blockType) return@use true
                offset += PmvContainerFormat.BLOCK_HEADER_SIZE + header.cipherSize
            }
            false
        }

    private fun corruptNewestBlock(file: File, blockType: PmvContainerFormat.BlockType) {
        var newestOffset = -1L
        var newestRevision = -1L
        RandomAccessFile(file, "r").use { input ->
            var offset = PmvContainerFormat.DATA_START
            while (offset + PmvContainerFormat.BLOCK_HEADER_SIZE <= input.length()) {
                input.seek(offset)
                val rawHeader = ByteArray(PmvContainerFormat.BLOCK_HEADER_SIZE)
                input.readFully(rawHeader)
                val header = PmvContainerFormat.decodeBlockHeader(rawHeader)
                if (header.blockType == blockType && header.objectRevision >= newestRevision) {
                    newestOffset = offset
                    newestRevision = header.objectRevision
                }
                offset += PmvContainerFormat.BLOCK_HEADER_SIZE + header.cipherSize
            }
        }
        require(newestOffset >= 0)
        RandomAccessFile(file, "rw").use { output ->
            output.seek(newestOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            val original = output.read()
            output.seek(newestOffset + PmvContainerFormat.BLOCK_HEADER_SIZE)
            output.write(original xor 1)
            output.fd.sync()
        }
    }

    private fun copyHeaderSlot(from: File, fromOffset: Long, to: File, toOffset: Long) {
        val raw = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
        try {
            RandomAccessFile(from, "r").use { input ->
                input.seek(fromOffset)
                input.readFully(raw)
            }
            RandomAccessFile(to, "rw").use { output ->
                output.seek(toOffset)
                output.write(raw)
                output.fd.sync()
            }
        } finally {
            raw.fill(0)
        }
    }

    private fun withVault(block: (File) -> Unit) {
        val file = File.createTempFile("pmv-vault-store-", ".pmv")
        try {
            block(file)
        } finally {
            password.fill(0)
            newPassword.fill(0)
            recoverySecret.fill(0)
            file.delete()
        }
    }

    private fun withTempDirectory(block: (File) -> Unit) {
        val directory = java.nio.file.Files.createTempDirectory("pmve-merge-").toFile()
        try {
            block(directory)
        } finally {
            directory.listFiles()?.forEach { it.delete() }
            directory.delete()
        }
    }

    private fun ByteArray.containsSubsequence(needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > size) return false
        return indices.take(size - needle.size + 1).any { start ->
            needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
    }
}
