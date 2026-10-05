package com.vault.ocr

import android.content.Context
import android.net.Uri
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.chinese.ChineseTextRecognizerOptions
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext

/**
 * ML Kit 文字识别：默认走中文识别器（同时支持拉丁字符），失败回退拉丁识别器。
 * 全部本地推理，无网络依赖；首次运行会按需下载约 5MB 模型。
 */
object Ocr {

    /** 识别一张图（来自 SAF Uri），返回拼接好的多行文本。 */
    suspend fun recognize(context: Context, uri: Uri): String = withContext(Dispatchers.IO) {
        val img = InputImage.fromFilePath(context, uri)
        runRecognize(img)
    }

    /** 识别一张图（来自 JPEG / PNG 字节）。 */
    suspend fun recognize(bytes: ByteArray, rotation: Int = 0): String = withContext(Dispatchers.IO) {
        val bmp = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            ?: error("图片解码失败")
        try {
            runRecognize(InputImage.fromBitmap(bmp, rotation))
        } finally {
            bmp.recycle()
        }
    }

    private suspend fun runRecognize(img: InputImage): String {
        // 中文识别器内置 Latin 字符支持，优先使用
        val zh = TextRecognition.getClient(ChineseTextRecognizerOptions.Builder().build())
        try {
            return runCatching { zh.process(img).await().text }.getOrElse {
                val en = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
                try {
                    en.process(img).await().text
                } finally {
                    en.close()
                }
            }
        } finally {
            zh.close()
        }
    }
}
