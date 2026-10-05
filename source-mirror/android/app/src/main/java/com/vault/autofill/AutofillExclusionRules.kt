package com.vault.autofill

import java.net.IDN
import java.net.URI
import java.util.Locale

/** Store origins, not full login URLs, so paths/ports do not defeat exclusions. */
internal fun normalizeExcludedHost(value: String): String? = runCatching {
    val input = value.trim()
    if (input.isEmpty() || input.any(Char::isWhitespace)) return null
    val uri = URI(if (input.contains("://")) input else "https://$input")
    if (uri.scheme.lowercase(Locale.ROOT) !in setOf("http", "https")) return null
    if (uri.rawUserInfo != null) return null
    val host = uri.host ?: uri.rawAuthority?.substringBefore(':') ?: return null
    IDN.toASCII(host.trimEnd('.')).lowercase(Locale.ROOT).takeIf { it.isNotBlank() }
}.getOrNull()
