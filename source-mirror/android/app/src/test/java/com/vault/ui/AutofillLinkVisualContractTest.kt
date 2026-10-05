package com.vault.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AutofillLinkVisualContractTest {
    private val projectRoot: File
        get() = System.getProperty("spec.dir")
            ?.let(::File)
            ?.parentFile
            ?: File(System.getProperty("user.dir").orEmpty())

    @Test
    fun linkedAutofillCategoryIconsPreserveTheirDrawableColors() {
        val picker = source("AppPickerSheet.kt")
        val pickerIcon = picker.substringAfter("if (row.categoryType != null)")
            .substringBefore("} else {")
        assertTrue(pickerIcon.contains("tint = Color.Unspecified"))

        val detail = source("EntryDetailScreen.kt")
        val linkedDetailIcon = detail.substringAfter("private fun LinkedAutofillDetails(")
            .substringAfter("if (source != null)")
            .substringBefore("} else {")
        assertTrue(linkedDetailIcon.contains("tint = Color.Unspecified"))
    }

    @Test
    fun linkedAutofillChipsWrapContentLikeTheManagedAppChip() {
        val editor = source("EntryEditScreen.kt")
        val linkedChips = editor.substringAfter("autofillLinks.forEach { link ->")
            .substringBefore("if (showAutofillPicker)")

        assertTrue(linkedChips.contains("modifier = Modifier.align(Alignment.Start)"))
    }

    private fun source(name: String): String = File(
        projectRoot,
        "app/src/main/java/com/vault/ui/screens/$name",
    ).readText()
}
