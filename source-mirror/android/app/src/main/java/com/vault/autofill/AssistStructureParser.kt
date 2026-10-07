package com.vault.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.os.Build
import android.view.View
import android.view.autofill.AutofillId

class TraversalBudget(
    private val maxNodes: Int = 2_000,
    private val maxDepth: Int = 64,
) {
    private var visited = 0
    private var stopped = false

    fun accept(depth: Int, cancelled: Boolean): Boolean {
        if (stopped || cancelled || depth > maxDepth || visited >= maxNodes) {
            stopped = true
            return false
        }
        visited++
        return true
    }
}

object AssistStructureParser {
    fun parse(
        structure: AssistStructure,
        cancellationSignal: CancellationSignal,
        ownPackage: String,
        manualRequest: Boolean,
        signingCertificateSha256: Set<String>,
        trustedBrowserSigningCertificateSha256: Set<String>,
    ): ParsedForm<AutofillId>? {
        val packageName = structure.activityComponent?.packageName ?: return null
        val budget = TraversalBudget()
        val candidates = mutableListOf<FieldCandidate<AutofillId>>()
        var focusedWebDomain: String? = null
        var anyWebDomain: String? = null
        var focusedWebScheme: String? = null
        var anyWebScheme: String? = null
        val stack = ArrayDeque<NodeAtDepth>()

        for (windowIndex in structure.windowNodeCount - 1 downTo 0) {
            stack.addLast(NodeAtDepth(structure.getWindowNodeAt(windowIndex).rootViewNode, 0))
        }
        while (stack.isNotEmpty()) {
            val (node, depth, nearbyLabel) = stack.removeLast()
            if (!budget.accept(depth, cancellationSignal.isCanceled)) break
            val webDomain = node.webDomain?.toString()?.take(253)
            if (webDomain != null) {
                anyWebDomain = anyWebDomain ?: webDomain
                val scheme = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) node.webScheme else null
                anyWebScheme = anyWebScheme ?: scheme
                if (node.isFocused || containsFocusedChild(node)) {
                    focusedWebDomain = webDomain
                    focusedWebScheme = scheme
                }
            }
            node.autofillId?.let { id ->
                if (node.autofillType == View.AUTOFILL_TYPE_TEXT || node.autofillType == View.AUTOFILL_TYPE_LIST) {
                    val html = node.htmlInfo?.attributes.orEmpty()
                        .mapNotNull { attribute ->
                            attribute.first?.trim()?.lowercase()?.takeIf(String::isNotEmpty)?.let {
                                it to attribute.second.orEmpty().take(120)
                            }
                        }
                        .toMap()
                    val currentText = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
                        ?: node.text?.toString()
                    candidates += FieldCandidate(
                        id = id,
                        evidence = FieldEvidence(
                            autofillHints = node.autofillHints.orEmpty().mapTo(linkedSetOf()) { it.take(80) },
                            htmlAttributes = html,
                            resourceId = node.idEntry?.take(120),
                            className = node.className?.toString()?.take(120),
                            inputType = node.inputType,
                            label = listOfNotNull(node.hint?.toString(), node.contentDescription?.toString(), nearbyLabel)
                                .distinct().joinToString(" ").take(120).takeIf(String::isNotBlank),
                            focused = node.isFocused,
                            visible = node.visibility == View.VISIBLE,
                            enabled = node.isEnabled,
                            currentText = currentText,
                            fieldKey = AutofillFieldSignature.create(node.idEntry, html["id"], html["name"], html["type"]),
                        ),
                    )
                }
            }
            for (childIndex in node.childCount - 1 downTo 0) {
                val previous = if (childIndex > 0) node.getChildAt(childIndex - 1) else null
                val label = previous?.takeIf {
                    it.autofillType == View.AUTOFILL_TYPE_NONE && it.visibility == View.VISIBLE &&
                        it.childCount == 0 && it.inputType == 0
                }?.text?.toString()?.take(120)
                stack.addLast(NodeAtDepth(node.getChildAt(childIndex), depth + 1, label))
            }
        }
        if (cancellationSignal.isCanceled) return null
        val webDomain = focusedWebDomain ?: anyWebDomain
        val webScheme = focusedWebScheme ?: anyWebScheme
        // getWebScheme() was added in API 28 and several standards-compliant browsers
        // still omit it. Reject an explicit non-HTTPS scheme, but keep domain-bound
        // requests with an absent scheme behind the authenticated disclosure flow.
        if (webDomain != null && webScheme != null && !webScheme.equals("https", ignoreCase = true)) return null
        val origin = OriginMatcher.originFrom(
            packageName = packageName,
            webDomain = webDomain,
            ownPackage = ownPackage,
            signingCertificateSha256 = signingCertificateSha256,
            trustedBrowserSigningCertificateSha256 = trustedBrowserSigningCertificateSha256,
        ) ?: return null
        // Scope a remembered role to the stable form layout, never to entered values.
        val formSignature = candidates.mapNotNull { it.evidence.fieldKey }.sorted().joinToString("\n")
        val formHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(formSignature.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }.take(24)
        val uniqueKeys = AutofillFieldSignature.unique(candidates.map { it.evidence.fieldKey })
        val uniqueCandidates = candidates.mapIndexed { index, candidate ->
            candidate.copy(evidence = candidate.evidence.copy(fieldKey = uniqueKeys[index]))
        }
        val fields = FieldClassifier.selectFields(uniqueCandidates, manualRequest).map { field ->
            field.copy(fieldKey = field.fieldKey?.let { "android:$formHash:$it".take(256) })
        }
        if (fields.isEmpty()) return null
        return ParsedForm(origin = origin, fields = fields, packageName = packageName)
    }

    private data class NodeAtDepth(val node: AssistStructure.ViewNode, val depth: Int, val nearbyLabel: String? = null)

    private fun containsFocusedChild(node: AssistStructure.ViewNode): Boolean {
        for (index in 0 until node.childCount) {
            if (node.getChildAt(index).isFocused) return true
        }
        return false
    }
}
