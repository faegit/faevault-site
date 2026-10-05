package com.vault.storage

import java.io.File

/** Wire-level vault generation。旧格式（PMV1/2/3）已移除，仅保留 PMVE。 */
enum class VaultFileFormat(private val wireMagic: String?) {
    PMVE("PMVS"),
    UNKNOWN(null),
    ;

    companion object {
        private const val MAGIC_SIZE = 4

        fun detect(file: File): VaultFileFormat {
            if (!file.isFile || file.length() < MAGIC_SIZE) return UNKNOWN
            return file.inputStream().use { input ->
                val magic = ByteArray(MAGIC_SIZE)
                if (input.read(magic) == MAGIC_SIZE) detect(magic) else UNKNOWN
            }
        }

        fun detect(magic: ByteArray): VaultFileFormat {
            if (magic.size < MAGIC_SIZE) return UNKNOWN
            return entries.firstOrNull { format ->
                format.wireMagic?.encodeToByteArray()?.let { expected ->
                    magic.size == MAGIC_SIZE && magic.contentEquals(expected)
                } == true
            } ?: UNKNOWN
        }
    }
}
