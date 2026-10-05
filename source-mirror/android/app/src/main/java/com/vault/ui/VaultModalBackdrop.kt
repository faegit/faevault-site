package com.vault.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalView
import androidx.compose.runtime.mutableStateListOf

internal object VaultModalBackdrops {
    val owners = mutableStateListOf<Any>()
}

/** AppRoot draws the same full-window Haze backdrop used by the recycle bin.
 * Track each modal independently so closing a nested dialog keeps the backdrop.
 * Autofill activities have no AppRoot backdrop and retain their existing appearance.
 */
@Composable
internal fun VaultModalBackdrop() {
    val view = LocalView.current
    DisposableEffect(view) {
        val owner = Any()
        VaultModalBackdrops.owners.add(owner)
        onDispose {
            VaultModalBackdrops.owners.remove(owner)
        }
    }
}
