package com.vault.ui.screens

import android.content.Context
import com.vault.ui.localizeUiText

/** Localizes transient screen messages at the same boundary as visible Compose text. */
internal object Toast {
    const val LENGTH_SHORT: Int = android.widget.Toast.LENGTH_SHORT
    const val LENGTH_LONG: Int = android.widget.Toast.LENGTH_LONG

    fun makeText(context: Context, text: CharSequence, duration: Int): android.widget.Toast {
        val locales = context.resources.configuration.locales
        val localized = localizeUiText(text.toString(), locales[0].toLanguageTag())
        return android.widget.Toast.makeText(context, localized, duration)
    }
}
