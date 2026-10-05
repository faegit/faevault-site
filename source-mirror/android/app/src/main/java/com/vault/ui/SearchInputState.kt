package com.vault.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue

/** Keep IME selection/composition local while publishing only the search query. */
internal class SearchInputState(initial: String) {
    var value by mutableStateOf(TextFieldValue(initial, TextRange(initial.length)))
        private set
    private var published = initial
    private val pendingAcknowledgements = linkedSetOf<String>()

    fun edit(next: TextFieldValue) {
        value = next.copy(text = InputFilters.capLength(next.text, 100))
    }

    fun publish(): String = value.text.also {
        published = it
        pendingAcknowledgements += it
        // StateFlow may conflate acknowledgements; keep only the bounded recent history.
        if (pendingAcknowledgements.size > 32) pendingAcknowledgements.remove(pendingAcknowledgements.first())
    }

    fun acceptExternal(query: String) {
        // A delayed acknowledgement belongs to our own query, not a new edit.
        if (pendingAcknowledgements.remove(query) || query == published) return
        if (query != published) {
            pendingAcknowledgements.clear()
            value = TextFieldValue(query, TextRange(query.length))
            published = query
        }
    }

    fun clear(): String {
        value = TextFieldValue()
        return publish()
    }
}
