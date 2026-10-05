package com.vault.ui.screens

internal data class PhotoPresentation(val locked: Boolean, val blurred: Boolean)

internal fun photoPresentation(protectionRequired: Boolean, verified: Boolean, alwaysBlur: Boolean): PhotoPresentation {
    val locked = protectionRequired && !verified
    return PhotoPresentation(locked, alwaysBlur || locked)
}
