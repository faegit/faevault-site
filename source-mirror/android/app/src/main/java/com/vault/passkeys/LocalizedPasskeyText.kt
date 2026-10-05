package com.vault.passkeys

import android.content.Context
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text as MaterialText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import com.vault.ui.localizeUiText
import com.vault.ui.uiText

@Composable
internal fun Text(
    text: String,
    modifier: Modifier = Modifier,
    color: Color = Color.Unspecified,
    style: TextStyle = LocalTextStyle.current,
) {
    MaterialText(text = uiText(text), modifier = modifier, color = color, style = style)
}

internal object Toast {
    const val LENGTH_LONG: Int = android.widget.Toast.LENGTH_LONG

    fun makeText(context: Context, text: CharSequence?, duration: Int): android.widget.Toast {
        val locales = context.resources.configuration.locales
        val localized = localizeUiText(text?.toString().orEmpty(), locales[0].toLanguageTag())
        return android.widget.Toast.makeText(context, localized, duration)
    }
}
