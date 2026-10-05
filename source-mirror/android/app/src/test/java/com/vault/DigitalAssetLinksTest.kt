package com.vault

import com.vault.passkeys.DigitalAssetLinksDocument
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DigitalAssetLinksTest {
    private val fingerprintA = List(32) { "AA" }.joinToString(":")
    private val fingerprintB = List(32) { "BB" }.joinToString(":")

    @Test
    fun authorizesExactPackageRelationAndAllCurrentSigners() {
        val document = statement(
            packageName = "com.example.app",
            relations = """["delegate_permission/common.get_login_creds"]""",
            fingerprints = """["$fingerprintA","$fingerprintB"]""",
        )

        assertTrue(
            DigitalAssetLinksDocument.authorizes(
                document,
                "com.example.app",
                setOf(fingerprintA.lowercase(), fingerprintB.replace(":", "")),
            ),
        )
    }

    @Test
    fun rejectsWrongRelationPackageOrPartialMultisignerAuthorization() {
        assertFalse(
            DigitalAssetLinksDocument.authorizes(
                statement(
                    "com.example.app",
                    """["delegate_permission/common.handle_all_urls"]""",
                    """["$fingerprintA","$fingerprintB"]""",
                ),
                "com.example.app",
                setOf(fingerprintA),
            ),
        )
        assertFalse(
            DigitalAssetLinksDocument.authorizes(
                statement(
                    "com.other.app",
                    """["delegate_permission/common.get_login_creds"]""",
                    """["$fingerprintA","$fingerprintB"]""",
                ),
                "com.example.app",
                setOf(fingerprintA),
            ),
        )
        assertFalse(
            DigitalAssetLinksDocument.authorizes(
                statement(
                    "com.example.app",
                    """["delegate_permission/common.get_login_creds"]""",
                    """["$fingerprintA"]""",
                ),
                "com.example.app",
                setOf(fingerprintA, fingerprintB),
            ),
        )
    }

    @Test
    fun rejectsMalformedDocumentsAndFingerprints() {
        assertThrows(IllegalArgumentException::class.java) {
            DigitalAssetLinksDocument.authorizes(
                "{}",
                "com.example.app",
                setOf(fingerprintA),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            DigitalAssetLinksDocument.authorizes(
                statement(
                    "com.example.app",
                    """["delegate_permission/common.get_login_creds"]""",
                    """["invalid"]""",
                ),
                "com.example.app",
                setOf(fingerprintA),
            )
        }
    }

    private fun statement(
        packageName: String,
        relations: String,
        fingerprints: String,
    ): String =
        """[{"relation":$relations,"target":{"namespace":"android_app","package_name":"$packageName","sha256_cert_fingerprints":$fingerprints}}]"""
}
