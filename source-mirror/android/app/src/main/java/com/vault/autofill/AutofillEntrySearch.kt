package com.vault.autofill

import com.vault.model.Entry
import java.text.Normalizer
import java.util.Locale

/** User-initiated search only. This scorer must never be used to authorize automatic filling. */
object AutofillEntrySearch {
    fun search(
        entries: List<Entry>,
        query: String,
        excludeIds: Set<String> = emptySet(),
        limit: Int = 40,
    ): List<Entry> {
        val normalizedQuery = normalize(query)
        if (normalizedQuery.isEmpty()) return emptyList()
        return entries.asSequence()
            .filter { it.deletedAt == null && it.id !in excludeIds }
            .mapNotNull { entry -> score(entry, normalizedQuery)?.let { Scored(entry, it) } }
            .sortedWith(
                compareByDescending<Scored> { it.score }
                    .thenBy { normalize(it.entry.title) }
                    .thenBy { it.entry.id },
            )
            .take(limit.coerceIn(0, 100))
            .map(Scored::entry)
            .toList()
    }

    private fun score(entry: Entry, query: String): Int? {
        val fields = listOf(
            normalize(entry.title) to 50,
            normalize(entry.username) to 40,
            normalize(entry.url) to 30,
            normalize(entry.targetApp) to 20,
        ).filter { it.first.isNotEmpty() }
        var best = 0
        fields.forEach { (value, weight) ->
            best = maxOf(
                best,
                when {
                    value == query -> 1_000 + weight
                    value.startsWith(query) -> 800 + weight
                    value.contains(query) -> 600 + weight
                    else -> 0
                },
            )
        }

        val queryTokens = words(query)
        val combined = fields.joinToString(" ") { it.first }
        if (queryTokens.isNotEmpty() && queryTokens.all(combined::contains)) best = maxOf(best, 500)

        if (queryTokens.size == 1 && query.length >= 4) {
            val threshold = if (query.length >= 6) 2 else 1
            fields.forEach { (value, weight) ->
                words(value).forEach { candidate ->
                    val distance = editDistance(query, candidate, threshold)
                    if (distance <= threshold) best = maxOf(best, 400 - distance * 50 + weight)
                }
            }
        }
        return best.takeIf { it > 0 }
    }

    private fun normalize(value: String): String = Normalizer.normalize(value.trim(), Normalizer.Form.NFKC)
        .lowercase(Locale.ROOT)
        .replace(Regex("[^\\p{L}\\p{N}\\s]"), "")

    private fun words(value: String): List<String> = value.split(Regex("[^\\p{L}\\p{N}_]+"))
        .filter(String::isNotEmpty)

    private fun editDistance(left: String, right: String, limit: Int): Int {
        if (kotlin.math.abs(left.length - right.length) > limit) return limit + 1
        var previous = IntArray(right.length + 1) { it }
        left.forEachIndexed { leftIndex, leftChar ->
            val current = IntArray(right.length + 1)
            current[0] = leftIndex + 1
            var rowMinimum = current[0]
            right.forEachIndexed { rightIndex, rightChar ->
                current[rightIndex + 1] = minOf(
                    current[rightIndex] + 1,
                    previous[rightIndex + 1] + 1,
                    previous[rightIndex] + if (leftChar == rightChar) 0 else 1,
                )
                rowMinimum = minOf(rowMinimum, current[rightIndex + 1])
            }
            if (rowMinimum > limit) return limit + 1
            previous = current
        }
        return previous[right.length]
    }

    private data class Scored(val entry: Entry, val score: Int)
}
