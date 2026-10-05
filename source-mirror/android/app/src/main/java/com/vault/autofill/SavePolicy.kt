package com.vault.autofill

object SavePolicy {
    const val ORIGIN_UNKNOWN = "save_policy_origin_unknown"
    const val PASSWORD_MISMATCH = "save_policy_password_mismatch"
    const val PASSWORD_EMPTY = "save_policy_password_empty"

    fun decide(
        candidate: SaveCandidate,
        origin: TargetOrigin?,
        exactMatchingEntryIds: List<String>,
        existing: ExistingCredential?,
    ): SaveDecision {
        if (origin == null) return SaveDecision.Reject(ORIGIN_UNKNOWN)
        val username = candidate.username.orEmpty().trim()
        val newPassword = candidate.newPassword.orEmpty()
        val confirmation = candidate.confirmationPassword
        if (newPassword.isNotEmpty() && confirmation != null && newPassword != confirmation) {
            return SaveDecision.Reject(PASSWORD_MISMATCH)
        }
        val password = newPassword.ifEmpty { candidate.password.orEmpty() }
        if (password.isEmpty()) return SaveDecision.Reject(PASSWORD_EMPTY)
        if (existing != null && existing.username == username && existing.password == password) {
            return SaveDecision.Unchanged
        }
        return if (exactMatchingEntryIds.isEmpty()) {
            SaveDecision.Create(username, password)
        } else {
            SaveDecision.UpdateChoice(username, password, exactMatchingEntryIds.distinct())
        }
    }
}
