package com.vault.autofill

object SaveCandidateExtractor {
    fun <T> extract(forms: List<ParsedForm<T>>): Pair<ParsedForm<T>, SaveCandidate>? {
        val passwordContextIndex = forms.indexOfLast { form ->
            form.fields.any { field ->
                (field.kind == FieldKind.PASSWORD || field.kind == FieldKind.NEW_PASSWORD) &&
                    !field.currentText.isNullOrEmpty()
            }
        }
        if (passwordContextIndex < 0) return null
        val latest = forms[passwordContextIndex]
        val relevant = forms.subList(0, passwordContextIndex + 1).filter {
            it.packageName == latest.packageName && it.origin == latest.origin
        }

        fun latestText(vararg kinds: FieldKind): String? = relevant.asReversed()
            .asSequence()
            .flatMap { it.fields.asSequence() }
            .firstOrNull { it.kind in kinds && !it.currentText.isNullOrEmpty() }
            ?.currentText

        val newPasswords = relevant.asReversed().firstNotNullOfOrNull { form ->
            form.fields.filter { it.kind == FieldKind.NEW_PASSWORD }
                .mapNotNull { it.currentText?.takeIf(String::isNotEmpty) }
                .takeIf(List<String>::isNotEmpty)
        }.orEmpty()
        return latest to SaveCandidate(
            username = latestText(FieldKind.USERNAME, FieldKind.EMAIL),
            password = latestText(FieldKind.PASSWORD),
            newPassword = newPasswords.firstOrNull(),
            confirmationPassword = newPasswords.getOrNull(1),
        )
    }
}
