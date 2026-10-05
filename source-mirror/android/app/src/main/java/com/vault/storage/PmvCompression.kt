package com.vault.storage

import com.github.luben.zstd.Zstd

/** Strict, bounded PMV block compression shared byte-for-byte with the PC implementation. */
object PmvCompression {
    const val CODEC_NONE = 0
    const val CODEC_ZSTD_FRAME_V1 = 1
    const val ZSTD_LEVEL = 3
    const val SAMPLE_BYTES = 1024 * 1024
    const val MIN_INPUT_BYTES = 4096
    const val MIN_SAVINGS_PERCENT = 10
    const val MAX_PLAIN_BYTES = 16 * 1024 * 1024
    private val ZSTD_MAGIC = byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte())

    fun chooseCodec(plain: ByteArray): Int {
        if (plain.size < MIN_INPUT_BYTES) return CODEC_NONE
        val sample = if (plain.size <= SAMPLE_BYTES) plain else plain.copyOf(SAMPLE_BYTES)
        val compressed = try { compressZstdFrame(sample) } finally {
            if (sample !== plain) sample.fill(0)
        }
        return try {
            if (compressed.size.toLong() * 100L <=
                sampleSize(plain).toLong() * (100L - MIN_SAVINGS_PERCENT)
            ) CODEC_ZSTD_FRAME_V1 else CODEC_NONE
        } finally {
            compressed.fill(0)
        }
    }

    fun encode(codecId: Int, plain: ByteArray): ByteArray = when (codecId) {
        CODEC_NONE -> plain
        CODEC_ZSTD_FRAME_V1 -> compressZstdFrame(plain)
        else -> throw IllegalArgumentException("不支持的 PMV 压缩编码")
    }

    fun decode(codecId: Int, encoded: ByteArray, expectedPlainSize: Long): ByteArray {
        require(expectedPlainSize in 0..MAX_PLAIN_BYTES.toLong()) { "PMV 解压长度无效" }
        return when (codecId) {
            CODEC_NONE -> encoded.also {
                require(it.size.toLong() == expectedPlainSize) { "未压缩 PMV Block 长度不一致" }
            }
            CODEC_ZSTD_FRAME_V1 -> {
                val declared = validateSingleZstdFrame(encoded)
                require(declared == expectedPlainSize) { "Zstandard content size 与 Block Header 不一致" }
                Zstd.decompress(encoded, expectedPlainSize.toInt()).also {
                    require(it.size.toLong() == expectedPlainSize) { "Zstandard 输出长度不一致" }
                }
            }
            else -> throw IllegalArgumentException("不支持的 PMV 压缩编码")
        }
    }

    fun compressZstdFrame(plain: ByteArray): ByteArray {
        require(plain.size <= MAX_PLAIN_BYTES) { "压缩输入超过 PMV Block 上限" }
        return Zstd.compress(plain, ZSTD_LEVEL)
    }

    /** Returns the declared content size after proving that [encoded] is exactly one frame. */
    fun validateSingleZstdFrame(encoded: ByteArray): Long {
        require(encoded.size >= 6 && encoded.copyOfRange(0, 4).contentEquals(ZSTD_MAGIC)) {
            "Zstandard frame magic 无效"
        }
        var index = 4
        val descriptor = encoded[index++].toInt() and 0xff
        require(descriptor and 0x18 == 0) { "Zstandard frame header 保留位非零" }
        val contentSizeFlag = descriptor ushr 6
        val singleSegment = descriptor and 0x20 != 0
        val checksum = descriptor and 0x04 != 0
        val dictionaryFlag = descriptor and 0x03
        if (!singleSegment) index = advance(index, 1, encoded.size, "window descriptor")
        val dictionarySize = intArrayOf(0, 1, 2, 4)[dictionaryFlag]
        require(dictionarySize == 0) { "Zstandard 字典不受支持" }
        index = advance(index, dictionarySize, encoded.size, "dictionary id")
        val contentSizeBytes = intArrayOf(if (singleSegment) 1 else 0, 2, 4, 8)[contentSizeFlag]
        require(contentSizeBytes != 0) { "Zstandard frame 必须声明 content size" }
        val contentEnd = advance(index, contentSizeBytes, encoded.size, "content size")
        var declared = readLittleEndian(encoded, index, contentSizeBytes)
        if (contentSizeBytes == 2) declared = Math.addExact(declared, 256L)
        index = contentEnd
        while (true) {
            val headerEnd = advance(index, 3, encoded.size, "block header")
            val header = readLittleEndian(encoded, index, 3).toInt()
            index = headerEnd
            val lastBlock = header and 1 != 0
            val blockType = (header ushr 1) and 0x03
            val blockSize = header ushr 3
            require(blockType != 3) { "Zstandard block type 保留值" }
            val payloadSize = if (blockType == 1) 1 else blockSize
            index = advance(index, payloadSize, encoded.size, "block payload")
            if (lastBlock) break
        }
        require(!checksum) { "Zstandard frame checksum 不受支持" }
        require(index == encoded.size) { "Zstandard 禁止多 frame 或尾随数据" }
        return declared
    }

    private fun sampleSize(plain: ByteArray) = minOf(plain.size, SAMPLE_BYTES)

    private fun advance(index: Int, count: Int, total: Int, label: String): Int {
        val end = index.toLong() + count.toLong()
        require(count >= 0 && end in index.toLong()..total.toLong()) { "Zstandard $label 被截断" }
        return end.toInt()
    }

    private fun readLittleEndian(raw: ByteArray, offset: Int, count: Int): Long {
        require(count in 1..8)
        var value = 0L
        for (index in 0 until count) {
            val byte = raw[offset + index].toLong() and 0xffL
            if (count == 8 && index == 7) require(byte and 0x80L == 0L) { "Zstandard content size 超出 signed Long" }
            value = value or (byte shl (index * 8))
        }
        return value
    }
}
