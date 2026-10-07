package com.vault.autofill

object AutofillFieldSignature {
    fun create(resourceId: String?, htmlId: String?, htmlName: String?, type: String?): String? {
        val identifiers = listOf(resourceId.orEmpty(), htmlId.orEmpty(), htmlName.orEmpty())
        if (identifiers.all(String::isBlank)) return null
        // Length-prefixed parts prevent delimiter collisions in supplied identifiers.
        return (listOf("android") + identifiers + type.orEmpty()).joinToString("") { "${it.length}:$it" }
            .takeIf { it.length <= 220 }
    }
    fun unique(keys: List<String?>): List<String?> {
        val counts = keys.filterNotNull().groupingBy { it }.eachCount()
        return keys.map { it?.takeIf { key -> counts[key] == 1 } }
    }
}
