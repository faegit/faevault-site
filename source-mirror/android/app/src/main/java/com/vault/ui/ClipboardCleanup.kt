package com.vault.ui

/** A null snapshot means access was unavailable; a null tag means another owner. */
internal data class ClipboardOwner(val tag: String?)

internal fun cleanOwnedClipboard(
    expectedTag: String,
    readOwner: () -> ClipboardOwner?,
    clear: () -> Unit,
): Boolean = runCatching {
    val owner = readOwner() ?: return@runCatching false
    if (owner.tag != expectedTag) return@runCatching true
    clear()
    readOwner()?.tag != expectedTag
}.getOrDefault(false)
