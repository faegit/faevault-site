package com.vault.ui

/** 传输列表里一行的显示名。主机侧与连接方必须同一口径，否则两端列表看起来不一样。 */
internal fun transferDisplayName(kind: String, name: String, textPreview: String): String {
    // 文本传输显示内容本身，而不是入队时生成的文件名（message_<时间戳>.txt）。
    if (kind == "text" && textPreview.isNotBlank()) {
        return textPreview.lineSequence().firstOrNull().orEmpty().take(80)
    }
    return name
}
