package com.vault.ui

internal data class RemoteUpdateOpenRequest(val vault: String, val target: String, val nonce: Long)
internal enum class RemoteUpdateNavigationDecision { WAIT_FOR_UNLOCK, OPEN, DROP }

internal fun remoteUpdateNavigationDecision(request: RemoteUpdateOpenRequest, currentVault: String?, unlocked: Boolean): RemoteUpdateNavigationDecision {
    if (request.vault.isBlank() || request.vault.length > 200 || request.target !in setOf("drive", "webdav")) return RemoteUpdateNavigationDecision.DROP
    if (!unlocked) return RemoteUpdateNavigationDecision.WAIT_FOR_UNLOCK
    return if (request.vault == currentVault) RemoteUpdateNavigationDecision.OPEN else RemoteUpdateNavigationDecision.DROP
}
