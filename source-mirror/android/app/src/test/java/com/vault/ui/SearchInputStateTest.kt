package com.vault.ui

import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import org.junit.Assert.*
import org.junit.Test

class SearchInputStateTest {
    @Test fun `old query acknowledgement cannot undo long text deletion or move cursor`() {
        val editor = SearchInputState("")
        val original = "x".repeat(90)
        editor.edit(TextFieldValue(original, TextRange(90)))
        val published = editor.publish()
        val edited = TextFieldValue(original.dropLast(1), TextRange(89))
        editor.edit(edited)
        editor.acceptExternal(published)
        assertEquals(edited, editor.value)
    }

    @Test fun `clearing cannot be undone by pending old query`() {
        val editor = SearchInputState("")
        editor.edit(TextFieldValue("old search", TextRange(5)))
        val pending = editor.publish()
        editor.clear()
        editor.acceptExternal(pending)
        assertEquals(TextFieldValue(), editor.value)
    }

    @Test fun `middle deletion keeps selection and composing range`() {
        val editor = SearchInputState("abcdef")
        val edit = TextFieldValue("abdef", TextRange(2), TextRange(0, 2))
        editor.edit(edit)
        editor.acceptExternal(editor.publish())
        assertEquals(edit, editor.value)
    }

    @Test fun `external reset and clear button erase query and selection`() {
        val editor = SearchInputState("query")
        editor.acceptExternal("")
        assertEquals(TextFieldValue(), editor.value)
        editor.edit(TextFieldValue("new", TextRange(2)))
        assertEquals("", editor.clear())
        assertEquals(TextFieldValue(), editor.value)
    }

    @Test fun `length limit preserves valid selection`() {
        val editor = SearchInputState("")
        editor.edit(TextFieldValue("x".repeat(110), TextRange(105)))
        assertEquals(100, editor.value.text.length)
        assertEquals(TextRange(100), editor.value.selection)
    }
}
