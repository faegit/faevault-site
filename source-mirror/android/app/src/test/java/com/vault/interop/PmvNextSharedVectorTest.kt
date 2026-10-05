package com.vault.interop

import com.vault.crypto.PmvKeySchedule
import com.vault.crypto.PmvKdfParameters
import com.vault.security.CloudCredentialCrypto
import com.vault.storage.PmvBlockCrypto
import com.vault.storage.PmvContainerFormat
import com.vault.storage.PmvCommitCodec
import com.vault.storage.PmvEntryIndexCodec
import com.vault.storage.PmvEntryIndexRootCodec
import com.vault.storage.PmvLoginFastIndex
import com.vault.storage.PmvIntegrity
import com.vault.storage.PmvEntryCodec
import com.vault.storage.PmvVaultHeaderCodec
import com.vault.storage.PmvVaultMetadataCodec
import com.vault.storage.PmvTombstoneCodec
import com.vault.storage.PmvSyncAuthorization
import com.vault.storage.VaultCodec
import com.vault.model.Entry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PmvNextSharedVectorTest {
    @Test
    fun cloudCredentialVectors() {
        val vector = singleCase("cloud_credentials.json")
        val inputs = vector["inputs"]!!.jsonObject
        val expected = vector["expected"]!!.jsonObject
        val vaultId = inputs.string("vaultId")
        val cloudKey = PmvKeySchedule.deriveRootKeys(inputs.string("rootKeyHex").decodeHex(), UUID.fromString(vaultId)).use {
            PmvKeySchedule.deriveCloudCredentialKey(it.keyWrapKey)
        }
        assertArrayEquals(expected.string("cloudCredentialKeyHex").decodeHex(), cloudKey)
        val packed = CloudCredentialCrypto.sealField(
            cloudKey, vaultId, inputs.string("provider"), inputs.string("field"),
            inputs.int("fieldVersion"), inputs.string("plaintextUtf8Hex").decodeHex(),
            inputs.string("nonceHex").decodeHex(),
        )
        assertArrayEquals(expected.string("packedHex").decodeHex(), packed)
        cloudKey.fill(0)
    }

    @Test
    fun manifestEnumeratesEveryVectorCaseAndFile() {
        val root = vectorRoot()
        val manifest = document("manifest.json")
        assertEquals(1, manifest.int("schemaVersion"))
        assertEquals(SUITE, manifest.string("suite"))

        val declared = manifest["artifacts"]!!.jsonArray.associate { artifactElement ->
            val artifact = artifactElement.jsonObject
            artifact.string("file") to artifact["caseIds"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
        }
        assertEquals(EXPECTED_FILES, declared.keys)
        assertEquals(
            EXPECTED_FILES,
            root.listFiles().orEmpty()
                .filter { it.isFile && it.extension == "json" && it.name != "manifest.json" }
                .map { it.name }
                .toSet(),
        )
        declared.forEach { (name, expectedIds) ->
            assertTrue("manifest references missing vector file: $name", File(root, name).isFile)
            val actualIds = document(name)["cases"]!!.jsonArray
                .map { it.jsonObject.string("id") }
                .toSet()
            assertEquals("manifest case list differs for $name", expectedIds, actualIds)
        }
    }

    @Test
    fun tombstoneVectors() {
        val vector = singleCase("tombstone.json")
        val inputs = vector["inputs"]!!.jsonObject
        val expected = vector["expected"]!!.jsonObject
        val tombstone = PmvTombstoneCodec.Tombstone(
            UUID.fromString(inputs.string("entryId")),
            inputs.long("revision"),
            inputs.long("purgedAtEpochMillis"),
            inputs.string("previousContentDigestHex").decodeHex(),
            inputs.int("flags"),
        )
        val raw = PmvTombstoneCodec.encode(tombstone)
        assertTrue(raw.contentEquals(expected.string("plaintextHex").decodeHex()))
        assertEquals(tombstone, PmvTombstoneCodec.decode(raw))
    }

    @Test
    fun syncAuthorizationVectors() {
        document("sync_authorization.json")["cases"]!!.jsonArray.forEach { caseElement ->
            val vector = caseElement.jsonObject
            val input = vector["inputs"]!!.jsonObject
            val expected = vector["expected"]!!.jsonObject
            val authorization = PmvSyncAuthorization.signAuthorization(
                PmvSyncAuthorization.DeviceAuthorization(
                    UUID.fromString(input.string("vaultId")), UUID.fromString(input.string("deviceId")),
                    input.string("devicePublicKeyHex").decodeHex(), input.int("permissions"),
                    input.long("issuedAtEpochMillis"), input.long("expiresAtEpochMillis"),
                    input.long("revokedAtEpochMillis"), input.long("authorizationEpoch"),
                ),
                input.string("vaultPrivateSeedHex").decodeHex(),
            )
            val raw = PmvSyncAuthorization.encodeAuthorization(authorization)
            assertArrayEquals(expected.string("authorizationHex").decodeHex(), raw)
            assertTrue(PmvSyncAuthorization.verifyAuthorization(
                authorization, input.string("vaultPublicKeyHex").decodeHex()))
            // 重新解码再编码必须逐字节复现，否则签名会失效。
            val decoded = PmvSyncAuthorization.decodeAuthorization(raw)
            assertArrayEquals(raw, PmvSyncAuthorization.encodeAuthorization(decoded))
            assertEquals(authorization, decoded)
            if (expected.containsKey("grantedPermissions")) {
                assertEquals(input.int("permissions"), decoded.permissions)
                assertEquals(expected.int("grantedPermissions"), decoded.grantedPermissions)
            }
            val challenge = PmvSyncAuthorization.Challenge(
                authorization.vaultId, authorization.deviceId,
                input.string("serverNonceHex").decodeHex(), input.string("clientNonceHex").decodeHex(),
                PmvSyncAuthorization.Operation.fromId(input.int("operation")),
                UUID.fromString(input.string("requestedCommitId")), input.string("requestDigestHex").decodeHex(),
                UUID.fromString(input.string("sessionId")), input.long("challengeExpiresAtEpochMillis"),
            )
            assertArrayEquals(expected.string("challengeHex").decodeHex(), PmvSyncAuthorization.encodeChallenge(challenge))
            assertArrayEquals(expected.string("responseSignatureHex").decodeHex(),
                PmvSyncAuthorization.signChallenge(challenge, input.string("devicePrivateSeedHex").decodeHex()))
        }
    }

    @Test
    fun argon2idVectors() {
        document("argon2id.json")["cases"]!!.jsonArray.forEach { caseElement ->
            val vector = caseElement.jsonObject
            assertTrue(vector.string("profile") in setOf("STANDARD", "HARDENED"))
            assertEquals(19, vector.int("version"))
            assertEquals(PmvKeySchedule.KEY_SIZE, vector.int("outputBytes"))
            assertArrayEquals(
                vector.hex("derivedKekHex"),
                PmvKeySchedule.derivePasswordKek(
                    vector.hex("passwordUtf8Hex"),
                    vector.hex("saltHex"),
                    PmvKdfParameters(
                        vector.int("memoryKiB"),
                        vector.int("iterations"),
                        vector.int("parallelism"),
                    ),
                ),
            )
        }
    }

    @Test
    fun hkdfHierarchyVectors() {
        val vector = singleCase("hkdf.json")
        val rootKeys = PmvKeySchedule.deriveRootKeys(
            vector.hex("vaultRootKeyHex"),
            UUID.fromString(vector.string("vaultId")),
        )
        try {
            val expected = vector["rootKeys"]!!.jsonObject
            assertArrayEquals(expected.hex("metadata"), rootKeys.metadataKey)
            assertArrayEquals(expected.hex("entryRoot"), rootKeys.entryRootKey)
            assertArrayEquals(expected.hex("attachmentRoot"), rootKeys.attachmentRootKey)
            assertArrayEquals(expected.hex("index"), rootKeys.indexKey)
            assertArrayEquals(expected.hex("searchIndex"), rootKeys.searchIndexKey)
            assertArrayEquals(expected.hex("integrity"), rootKeys.integrityKey)
            assertArrayEquals(expected.hex("syncAuth"), rootKeys.syncAuthKey)
            assertArrayEquals(expected.hex("keyWrap"), rootKeys.keyWrapKey)

            val entry = vector["entryGeneration"]!!.jsonObject
            assertArrayEquals(
                entry.hex("expectedKeyHex"),
                PmvKeySchedule.deriveEntryKey(
                    rootKeys.entryRootKey,
                    UUID.fromString(entry.string("entryId")),
                    entry.long("generation"),
                ),
            )
            val attachment = vector["attachmentGeneration"]!!.jsonObject
            val attachmentKey = PmvKeySchedule.deriveAttachmentObjectKey(
                rootKeys.attachmentRootKey,
                UUID.fromString(attachment.string("attachmentId")),
                attachment.long("generation"),
            )
            assertArrayEquals(attachment.hex("expectedKeyHex"), attachmentKey)
            val chunk = vector["chunk"]!!.jsonObject
            assertArrayEquals(
                chunk.hex("expectedKeyHex"),
                PmvKeySchedule.deriveChunkKey(attachmentKey, chunk.long("chunkIndex")),
            )

            val commit = vector["commitBlock"]!!.jsonObject
            assertArrayEquals(
                commit.hex("expectedKeyHex"),
                PmvKeySchedule.deriveCommitBlockKey(
                    rootKeys.integrityKey,
                    UUID.fromString(commit.string("commitId")),
                    commit.long("revision"),
                ),
            )
            val metadata = vector["metadataBlock"]!!.jsonObject
            assertArrayEquals(
                metadata.hex("expectedKeyHex"),
                PmvKeySchedule.deriveMetadataBlockKey(
                    rootKeys.metadataKey,
                    UUID.fromString(metadata.string("objectId")),
                    metadata.long("generation"),
                ),
            )

            val indexPages = vector["indexPages"]!!.jsonObject
            val pageObjectId = UUID.fromString(indexPages.string("objectId"))
            val pageGeneration = indexPages.long("generation")
            indexPages["cases"]!!.jsonArray.forEach { pageElement ->
                val page = pageElement.jsonObject
                assertArrayEquals(
                    page.hex("expectedKeyHex"),
                    PmvKeySchedule.deriveIndexPageKey(
                        rootKeys.indexKey,
                        pageObjectId,
                        pageGeneration,
                        PmvKeySchedule.IndexPageType.valueOf(page.string("pageType")),
                    ),
                )
            }
        } finally {
            rootKeys.close()
        }
    }

    @Test
    fun derivedBlockKeysSeparateDomainIdentityAndGenerationAndEnforceLongRange() {
        val parent = ByteArray(PmvKeySchedule.KEY_SIZE) { it.toByte() }
        val firstId = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val secondId = UUID.fromString("00000000-0000-0000-0000-000000000002")
        val entry = PmvKeySchedule.deriveIndexPageKey(
            parent, firstId, 0, PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )
        assertTrue(!entry.contentEquals(PmvKeySchedule.deriveIndexPageKey(
            parent, secondId, 0, PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )))
        assertTrue(!entry.contentEquals(PmvKeySchedule.deriveIndexPageKey(
            parent, firstId, 1, PmvKeySchedule.IndexPageType.ENTRY_INDEX,
        )))
        assertTrue(!entry.contentEquals(PmvKeySchedule.deriveIndexPageKey(
            parent, firstId, 0, PmvKeySchedule.IndexPageType.LOGIN_INDEX,
        )))
        val pageKeys = PmvKeySchedule.IndexPageType.entries.map { type ->
            PmvKeySchedule.deriveIndexPageKey(parent, firstId, 0, type).toList()
        }
        assertEquals(PmvKeySchedule.IndexPageType.entries.size, pageKeys.toSet().size)
        val commit = PmvKeySchedule.deriveCommitBlockKey(parent, firstId, 0)
        val metadata = PmvKeySchedule.deriveMetadataBlockKey(parent, firstId, 0)
        assertTrue(!commit.contentEquals(entry))
        assertTrue(!metadata.contentEquals(commit))
        assertTrue(!metadata.contentEquals(PmvKeySchedule.deriveMetadataBlockKey(parent, secondId, 0)))
        assertTrue(!metadata.contentEquals(PmvKeySchedule.deriveMetadataBlockKey(parent, firstId, 1)))
        assertTrue(!commit.contentEquals(PmvKeySchedule.deriveCommitBlockKey(parent, secondId, 0)))
        assertTrue(!commit.contentEquals(PmvKeySchedule.deriveCommitBlockKey(parent, firstId, 1)))
        assertEquals(PmvKeySchedule.KEY_SIZE, PmvKeySchedule.deriveCommitBlockKey(
            parent, firstId, Long.MAX_VALUE,
        ).size)
        assertIllegalArgument { PmvKeySchedule.deriveCommitBlockKey(parent, firstId, -1) }
        assertIllegalArgument { PmvKeySchedule.deriveMetadataBlockKey(parent, firstId, -1) }
        assertIllegalArgument {
            PmvKeySchedule.deriveIndexPageKey(
                parent, firstId, -1, PmvKeySchedule.IndexPageType.VAULT_ROOT,
            )
        }
    }

    @Test
    fun loginFastIndexLeafAndRangeRootVectors() {
        val vector = singleCase("login_fast_index.json")
        val records = vector["records"]!!.jsonArray.map { element ->
            val value = element.jsonObject
            PmvLoginFastIndex.Record(
                UUID.fromString(value.string("entryId")),
                PmvLoginFastIndex.EntryType.valueOf(value.string("entryType")),
                PmvLoginFastIndex.State.valueOf(value.string("state")),
                PmvLoginFastIndex.LookupKind.valueOf(value.string("lookupKind")),
                value.hex("lookupTokenHex"),
            )
        }
        val leaf = PmvLoginFastIndex.Page(records)
        val leafVector = vector["leaf"]!!.jsonObject
        assertArrayEquals(leafVector.hex("expectedLogicalDigestHex"), PmvLoginFastIndex.logicalDigest(leaf))
        assertArrayEquals(leafVector.hex("expectedEncodedSha256Hex"), sha256(PmvLoginFastIndex.encode(leaf)))

        val rootVector = vector["root"]!!.jsonObject
        val root = PmvLoginFastIndex.buildRoot(
            leaf,
            PmvLoginFastIndex.PageLocation(rootVector.long("pageOffset"), rootVector.long("pageLength")),
        )
        assertArrayEquals(rootVector.hex("expectedLogicalDigestHex"), PmvLoginFastIndex.logicalDigest(root))
        val encodedRoot = PmvLoginFastIndex.encodeRoot(root)
        assertArrayEquals(rootVector.hex("expectedEncodedSha256Hex"), sha256(encodedRoot))
        assertEquals(root, PmvLoginFastIndex.decodeRoot(encodedRoot))
        val relocated = PmvLoginFastIndex.buildRoot(
            leaf,
            PmvLoginFastIndex.PageLocation(rootVector.long("pageOffset") + 4096, rootVector.long("pageLength")),
        )
        assertArrayEquals(PmvLoginFastIndex.logicalDigest(root), PmvLoginFastIndex.logicalDigest(relocated))
    }

    @Test
    fun blockHeaderAadAndAeadVectors() {
        val vector = singleCase("block_aead.json")
        val headerJson = vector["header"]!!.jsonObject
        val header = PmvContainerFormat.BlockHeader(
            blockId = UUID.fromString(headerJson.string("blockId")),
            blockType = PmvContainerFormat.BlockType.valueOf(headerJson.string("blockType")),
            objectId = UUID.fromString(headerJson.string("objectId")),
            objectRevision = headerJson.long("objectRevision"),
            chunkIndex = headerJson.int("chunkIndex"),
            flags = headerJson.int("flags"),
            cryptoSuiteId = headerJson.int("cryptoSuiteId"),
            codecId = headerJson.int("codecId"),
            plainSize = headerJson.long("plainSize"),
            cipherSize = headerJson.long("cipherSize"),
            nonce = headerJson.hex("nonceHex"),
        )
        val vaultId = UUID.fromString(vector.string("vaultId"))
        val expectedCiphertext = vector.hex("expectedCiphertextHex")
        assertArrayEquals(vector.hex("expectedHeaderHex"), PmvContainerFormat.encodeBlockHeader(header))
        assertArrayEquals(vector.hex("expectedAadHex"), PmvContainerFormat.blockAad(vaultId, header))

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(vector.hex("keyHex"), "AES"),
            GCMParameterSpec(128, header.nonce),
        )
        cipher.updateAAD(PmvContainerFormat.blockAad(vaultId, header))
        assertArrayEquals(expectedCiphertext, cipher.doFinal(vector.hex("plaintextHex")))
        assertArrayEquals(
            vector.hex("plaintextHex"),
            PmvBlockCrypto.open(vaultId, vector.hex("keyHex"), PmvContainerFormat.EncodedBlock(header, expectedCiphertext)),
        )
    }

    @Test
    fun superblockVectors() {
        val vector = singleCase("container.json")
        val value = vector["superblock"]!!.jsonObject
        val encoded = PmvContainerFormat.encodeSuperblock(
            PmvContainerFormat.Superblock(
                vaultId = UUID.fromString(value.string("vaultId")),
                sequence = value.long("sequence"),
                latestCommitOffset = value.long("latestCommitOffset"),
                latestIndexOffset = value.long("latestIndexOffset"),
                committedFileEnd = value.long("committedFileEnd"),
                kdfParametersOffset = value.long("kdfParametersOffset"),
                featureFlags = value.long("featureFlags"),
            ),
            vector.hex("authenticationKeyHex"),
        )
        assertEquals(vector.int("expectedEncodedBytes"), encoded.size)
        val prefix = vector.hex("expectedPrefixHex")
        assertArrayEquals(prefix, encoded.copyOfRange(0, prefix.size))
        assertArrayEquals(vector.hex("expectedAuthTagHex"), encoded.copyOfRange(encoded.size - 32, encoded.size))
        assertArrayEquals(vector.hex("expectedSha256Hex"), MessageDigest.getInstance("SHA-256").digest(encoded))
        assertEquals(
            value.long("sequence"),
            PmvContainerFormat.decodeSuperblock(encoded, vector.hex("authenticationKeyHex")).sequence,
        )
    }

    @Test
    fun vaultHeaderVectorsFreezeBootstrapLayoutAndBytes() {
        val document = document("vault_header.json")
        val layout = document["layout"]!!.jsonObject
        assertEquals(0L, layout.long("superblockAOffset"))
        assertEquals(PmvContainerFormat.SUPERBLOCK_SIZE.toLong(), layout.long("superblockBOffset"))
        assertEquals(PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET, layout.long("vaultHeaderAOffset"))
        assertEquals(PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET, layout.long("vaultHeaderBOffset"))
        assertEquals(PmvContainerFormat.DATA_START, layout.long("dataStartOffset"))
        assertEquals(PmvVaultHeaderCodec.HEADER_SIZE, layout.int("slotSize"))

        val vector = singleCase("vault_header.json")
        val encoded = PmvVaultHeaderCodec.create(
            vaultId = UUID.fromString(vector.string("vaultId")),
            keyRevision = vector.long("keyRevision"),
            headerRevision = vector.long("headerRevision"),
            passwordUtf8 = vector.hex("passwordUtf8Hex"),
            recoverySecret = vector.hex("recoverySecretHex"),
            vaultRootKey = vector.hex("vaultRootKeyHex"),
            signingPrivateSeed = vector.hex("signingPrivateSeedHex"),
            salt = vector.hex("saltHex"),
            nonces = PmvVaultHeaderCodec.Nonces(
                vector.hex("passwordNonceHex"),
                vector.hex("recoveryNonceHex"),
                vector.hex("signingSeedNonceHex"),
            ),
        )
        assertEquals(vector.int("expectedEncodedBytes"), encoded.size)
        val prefix = vector.hex("expectedStructuredPrefixHex")
        assertArrayEquals(prefix, encoded.copyOfRange(0, prefix.size))
        val authTag = vector.hex("expectedAuthTagHex")
        val reserved = encoded.copyOfRange(prefix.size, encoded.size - authTag.size)
        assertEquals(vector.int("expectedReservedZeroBytes"), reserved.size)
        assertTrue(reserved.all { it == 0.toByte() })
        assertArrayEquals(authTag, encoded.copyOfRange(encoded.size - authTag.size, encoded.size))
        assertArrayEquals(vector.hex("expectedSha256Hex"), sha256(encoded))
        PmvVaultHeaderCodec.unlockWithPassword(encoded, vector.hex("passwordUtf8Hex")).use { unlocked ->
            assertArrayEquals(vector.hex("vaultRootKeyHex"), unlocked.vaultRootKey)
            assertArrayEquals(vector.hex("signingPrivateSeedHex"), unlocked.signingPrivateSeed)
        }
        PmvVaultHeaderCodec.unlockWithRecovery(encoded, vector.hex("recoverySecretHex")).use { unlocked ->
            assertArrayEquals(vector.hex("vaultRootKeyHex"), unlocked.vaultRootKey)
        }
    }

    @Test
    fun entryIndexWireAndLogicalDigestVectors() {
        val vector = singleCase("commit_entry_index.json")
        val recordsById = vector["records"]!!.jsonArray.associate { element ->
            val value = element.jsonObject
            val icon = value["iconObjectId"]
            val record = PmvEntryIndexCodec.Record(
                entryId = UUID.fromString(value.string("entryId")),
                entryType = value.string("entryType"),
                revision = value.long("revision"),
                offset = value.long("offset"),
                length = value.long("length"),
                state = PmvEntryIndexCodec.State.valueOf(value.string("state")),
                displayTitle = value.string("displayTitle"),
                favorite = value.string("favorite").toBooleanStrict(),
                iconObjectId = if (icon == null || icon is JsonNull) null else UUID.fromString(icon.jsonPrimitive.content),
                modifiedAtEpochMillis = value.long("modifiedAtEpochMillis"),
                contentDigest = value.hex("contentDigestHex"),
            )
            assertArrayEquals(value.hex("expectedRecordDigestHex"), PmvIntegrity.entryRecordDigest(record))
            assertArrayEquals(
                "record digest must exclude physical offset and length",
                PmvIntegrity.entryRecordDigest(record),
                PmvIntegrity.entryRecordDigest(record.copy(offset = record.offset + 4096, length = record.length + 1)),
            )
            value.string("id") to record
        }

        val pages = vector["pages"]!!.jsonArray.map { element ->
            val value = element.jsonObject
            val page = PmvEntryIndexCodec.Page(
                records = value["recordIds"]!!.jsonArray.map { recordsById.getValue(it.jsonPrimitive.content) },
                nextPageOffset = value.long("nextPageOffset"),
            )
            val encoded = PmvEntryIndexCodec.encode(page)
            assertArrayEquals(value.hex("expectedLogicalDigestHex"), PmvIntegrity.entryPageDigest(page))
            assertArrayEquals(value.hex("expectedEncodedSha256Hex"), sha256(encoded))
            assertArrayEquals(encoded, PmvEntryIndexCodec.encode(PmvEntryIndexCodec.decode(encoded)))
            val alternateNext = if (page.nextPageOffset == 0L) 32768L else 0L
            assertArrayEquals(
                "page digest must exclude its physical next-page pointer",
                PmvIntegrity.entryPageDigest(page),
                PmvIntegrity.entryPageDigest(page.copy(nextPageOffset = alternateNext)),
            )
            page
        }
        assertEquals(2, pages.size)

        val rootJson = vector["root"]!!.jsonObject
        val root = PmvEntryIndexRootCodec.Root(
            rootJson["records"]!!.jsonArray.map { element ->
                val value = element.jsonObject
                PmvEntryIndexRootCodec.Record(
                    minEntryId = UUID.fromString(value.string("minEntryId")),
                    maxEntryId = UUID.fromString(value.string("maxEntryId")),
                    pageOffset = value.long("pageOffset"),
                    pageDigest = value.hex("pageDigestHex"),
                )
            },
        )
        val encodedRoot = PmvEntryIndexRootCodec.encode(root)
        assertArrayEquals(rootJson.hex("expectedLogicalDigestHex"), PmvIntegrity.entryRootDigest(root))
        assertArrayEquals(rootJson.hex("expectedEncodedSha256Hex"), sha256(encodedRoot))
        assertArrayEquals(encodedRoot, PmvEntryIndexRootCodec.encode(PmvEntryIndexRootCodec.decode(encodedRoot)))
        val relocated = PmvEntryIndexRootCodec.Root(
            root.records.mapIndexed { index, record -> record.copy(pageOffset = 32768L + index * 8192L) },
        )
        assertArrayEquals(
            "root digest must exclude physical leaf offsets",
            PmvIntegrity.entryRootDigest(root),
            PmvIntegrity.entryRootDigest(relocated),
        )

        val commitJson = vector["commit"]!!.jsonObject
        val vaultId = UUID.fromString(commitJson.string("vaultId"))
        val commitId = UUID.fromString(commitJson.string("commitId"))
        val parentCommitId = UUID.fromString(commitJson.string("parentCommitId"))
        assertArrayEquals(
            commitJson.hex("expectedCanonicalSigningBytesHex"),
            PmvCommitCodec.canonicalSigningBytes(
                vaultId,
                commitId,
                parentCommitId,
                commitJson.long("revision"),
                commitJson.hex("rootDigestHex"),
            ),
        )
        val commit = PmvCommitCodec.sign(
            vaultId = vaultId,
            commitId = commitId,
            parentCommitId = parentCommitId,
            revision = commitJson.long("revision"),
            indexRootOffset = commitJson.long("indexRootOffset"),
            indexRootLength = commitJson.long("indexRootLength"),
            rootDigest = commitJson.hex("rootDigestHex"),
            privateSeed = commitJson.hex("privateSeedHex"),
        )
        assertArrayEquals(commitJson.hex("expectedPublicKeyHex"), commit.signingPublicKey)
        assertArrayEquals(commitJson.hex("expectedSignatureHex"), commit.signature)
        val encodedCommit = PmvCommitCodec.encode(commit)
        assertArrayEquals(commitJson.hex("expectedEncodedHex"), encodedCommit)
        assertArrayEquals(commitJson.hex("expectedEncodedSha256Hex"), sha256(encodedCommit))
        assertEquals(commit, PmvCommitCodec.decode(encodedCommit))
    }

    @Test
    fun entryCanonicalJsonVectors() {
        val vector = singleCase("entry_codec.json")
        val entry = VaultCodec.json.decodeFromJsonElement<Entry>(vector["entry"]!!)
        val expected = vector.string("expectedCanonicalJson").encodeToByteArray()
        assertArrayEquals(expected, PmvEntryCodec.encode(entry))
        val decoded = PmvEntryCodec.decode(expected, UUID.fromString(entry.id))
        assertEquals(entry.id, decoded.id)
        assertArrayEquals(expected, PmvEntryCodec.encode(decoded))
    }

    @Test
    fun vaultMetadataCanonicalJsonAndLogicalDigestVectors() {
        val vector = singleCase("vault_metadata.json")
        val metadata = vector["metadata"]!!.jsonObject
        val expected = vector.string("expectedCanonicalJson").encodeToByteArray()
        assertEquals(vector.string("blockType"), PmvVaultMetadataCodec.BLOCK_TYPE.name)
        assertArrayEquals(expected, PmvVaultMetadataCodec.encode(metadata))
        assertArrayEquals(
            expected,
            PmvVaultMetadataCodec.encode(
                PmvVaultMetadataCodec.decode(expected, UUID.fromString(metadata.string("vault_id"))),
            ),
        )
        assertArrayEquals(vector.hex("expectedLogicalDigestHex"), PmvVaultMetadataCodec.logicalDigest(metadata))
    }

    private fun singleCase(name: String): JsonObject {
        val document = document(name)
        assertEquals(1, document.int("schemaVersion"))
        assertEquals(SUITE, document.string("suite"))
        return document["cases"]!!.jsonArray.single().jsonObject
    }

    private fun document(name: String): JsonObject {
        val file = File(vectorRoot(), name)
        require(file.isFile) { "required PMV next shared vector is missing: ${file.absolutePath}" }
        return Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
    }

    private fun vectorRoot(): File {
        val spec = System.getProperty("spec.dir") ?: error("spec.dir is required for PMV next interop tests")
        return File(spec, "interop/pmv_next/v1").also {
            require(it.isDirectory) { "required PMV next vector directory is missing: ${it.absolutePath}" }
        }
    }

    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
    private fun JsonObject.int(name: String): Int = string(name).toInt()
    private fun JsonObject.long(name: String): Long = string(name).toLong()
    private fun JsonObject.hex(name: String): ByteArray = string(name).decodeHex()

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun assertIllegalArgument(block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected.
        }
    }

    private fun String.decodeHex(): ByteArray {
        require(length % 2 == 0) { "hex value must have even length" }
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private companion object {
        const val SUITE = "PMV_NEXT_V1_SUITE_1"
        val EXPECTED_FILES = setOf(
            "argon2id.json",
            "hkdf.json",
            "block_aead.json",
            "container.json",
            "commit_entry_index.json",
            "vault_header.json",
            "entry_codec.json",
            "vault_metadata.json",
            "login_fast_index.json",
            "media_ref.json",
            "legacy_media_migration.json",
            "compression.json",
            "tombstone.json",
            "sync_authorization.json",
            "store_interop.json",
            "cloud_credentials.json",
        )
    }
}
