package com.vault.ui

import com.vault.R
import com.vault.model.ModuleType
import com.vault.model.SecretType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class VaultIconResourcesTest {
    private val projectRoot: File
        get() = System.getProperty("spec.dir")
            ?.let(::File)
            ?.parentFile
            ?: File(System.getProperty("user.dir").orEmpty())

    @Test
    fun sameSemanticCategoriesAndModulesShareOneResource() {
        val pairs = listOf(
            SecretType.LOGIN to ModuleType.LOGIN_ACCOUNT,
            SecretType.API_KEY to ModuleType.API_CREDENTIAL,
            SecretType.WIFI to ModuleType.WIFI,
            SecretType.SERVER to ModuleType.SERVER_CONNECTION,
            SecretType.OTP to ModuleType.OTP,
            SecretType.CARD_DOCUMENT to ModuleType.CARD_DOCUMENT,
            SecretType.PASSKEY to ModuleType.PASSKEY,
        )

        pairs.forEach { (category, module) ->
            assertEquals(VaultIconResources.category(category), VaultIconResources.module(module))
        }
    }

    @Test
    fun ambiguousDifferentSemanticsUseDifferentResources() {
        val resources = listOf(
            VaultIconResources.category(SecretType.LOGIN),
            VaultIconResources.category(SecretType.API_KEY),
            VaultIconResources.category(SecretType.PASSKEY),
            VaultIconResources.category(SecretType.OTP),
            VaultIconResources.module(ModuleType.DATETIME),
            VaultIconResources.category(SecretType.SECURE_NOTE),
            VaultIconResources.module(ModuleType.MULTILINE),
            VaultIconResources.category(SecretType.CUSTOM),
            VaultIconResources.module(ModuleType.RECOVERY),
        )

        resources.forEachIndexed { index, resource ->
            resources.drop(index + 1).forEach { other -> assertNotEquals(resource, other) }
        }
    }

    @Test
    fun unknownTypesKeepExistingFallbacks() {
        assertEquals(R.drawable.ic_category_login, VaultIconResources.category("unknown"))
        assertEquals(R.drawable.ic_module_text, VaultIconResources.module("unknown"))
    }

    @Test
    fun activeDifferentSemanticIconsHaveDistinctCenterGlyphs() {
        val activeIcons = listOf(
            "ic_category_login",
            "ic_category_wifi",
            "ic_category_card_document",
            "ic_category_api_key",
            "ic_category_otp",
            "ic_category_secure_note",
            "ic_category_server",
            "ic_category_custom",
            "ic_category_passkey",
            "ic_module_text",
            "ic_module_password",
            "ic_module_markdown",
            "ic_module_boolean",
            "ic_module_datetime",
            "ic_module_images",
            "ic_module_attachments",
            "ic_module_target_app",
            "ic_module_ssh",
            "ic_module_database",
            "ic_module_address",
            "ic_module_recovery",
        )

        val signatures = activeIcons.associateWith(::centerGlyphSignature)
        val duplicates = signatures.entries
            .groupBy { it.value }
            .values
            .filter { it.size > 1 }
            .map { group -> group.map { it.key } }

        assertTrue("Duplicate center glyphs: $duplicates", duplicates.isEmpty())
        assertEquals(activeIcons.size, signatures.values.toSet().size)
    }

    private fun centerGlyphSignature(name: String): String {
        val vector = File(projectRoot, "app/src/main/res/drawable/$name.xml").readText()
        val paths = Regex("""android:pathData="([^"]+)"""")
            .findAll(vector)
            .map { it.groupValues[1].replace(Regex("\\s+"), "") }
            .toList()
        return paths.drop(3).joinToString("|").also { signature ->
            check(signature.isNotBlank()) { "Missing center glyph for $name" }
        }
    }
}
