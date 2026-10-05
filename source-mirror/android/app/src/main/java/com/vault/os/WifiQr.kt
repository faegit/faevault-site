package com.vault.os

import android.content.Context
import android.graphics.BitmapFactory
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.GenericMultipleBarcodeReader

/**
 * Wi-Fi 二维码扫描 + 解析。
 *
 *  - 实时取景：CameraX + ZXing（所有设备共用）
 *  - 静态图识别（相册导入 / 系统相机拍照兜底）：ZXing 本地解码，无网络、无 GMS 依赖
 *
 * Wi-Fi 二维码标准格式：WIFI:T:<auth>;S:<ssid>;P:<password>;H:<hidden>;;
 *  - T = 加密类型：WPA / WPA2 / WPA3 / nopass
 *  - S = SSID
 *  - P = 密码（nopass 时可省略）
 *  - H = 是否隐藏网络（true/false，可省）
 */
object WifiQr {
    data class Parsed(
        val ssid: String,
        val password: String,
        val security: String,
        val hidden: Boolean,
    )

    /**
     * 从图片中识别二维码（ZXing 本地解码）。用于相册导入和系统相机拍照后兜底。
     * 无 ML Kit / GMS 依赖，所以非 Google 渠道也能用。
     */
    fun scanFromUri(context: android.content.Context, uri: android.net.Uri): String? {
        return scanAllFromUri(context, uri).singleOrNull()
    }

    /** Returns every distinct QR payload in the image. A single-result caller must not guess when ambiguous. */
    fun scanAllFromUri(context: android.content.Context, uri: android.net.Uri): List<String> {
        return runCatching {
            val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: return emptyList()
            // 控制位图最大尺寸，避免拍照原图（>4000px）触发 OOM
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
            var sample = 1
            val longest = maxOf(bounds.outWidth, bounds.outHeight)
            while (longest / sample > 2048) sample *= 2
            val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
            val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts) ?: return emptyList()
            try {
                val w = bmp.width; val h = bmp.height
                val pixels = IntArray(w * h)
                bmp.getPixels(pixels, 0, w, 0, 0, w, h)
                val source = RGBLuminanceSource(w, h, pixels)
                val binary = BinaryBitmap(HybridBinarizer(source))
                val hints = mapOf(
                    DecodeHintType.TRY_HARDER to true,
                    DecodeHintType.ALSO_INVERTED to true,
                    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                )
                val reader = MultiFormatReader().apply { setHints(hints) }
                fun decodeAll(bitmap: BinaryBitmap): List<String> = try {
                    GenericMultipleBarcodeReader(reader).decodeMultiple(bitmap, hints)
                        .map { it.text.trim() }.filter { it.isNotEmpty() }
                } catch (_: NotFoundException) {
                    runCatching { listOf(reader.decode(bitmap, hints).text.trim()) }.getOrDefault(emptyList())
                } finally {
                    reader.reset()
                }
                (decodeAll(binary) + decodeAll(BinaryBitmap(HybridBinarizer(source.invert())))).distinct()
            } finally {
                bmp.recycle()
            }
        }.getOrDefault(emptyList())
    }

    /**
     * 解析 `WIFI:T:WPA;S:Home;P:hunter2;;` 这种字符串。
     * 容错：分号 / 等号被 `\` 转义；缺字段时给空串；非 WIFI: 开头返回 null。
     */
    fun parse(raw: String): Parsed? {
        // 上限：标准 Wi-Fi QR 内容远小于 1KB，超长一律视为非法输入避免 DoS / 内存压力
        if (raw.length > 1024) return null
        val text = raw.trim()
        if (!text.startsWith("WIFI:", ignoreCase = true)) return null
        val body = text.substring(5).trimEnd(';')
        val map = mutableMapOf<String, String>()
        var i = 0
        val n = body.length
        while (i < n) {
            // 取一个键
            val keyEnd = body.indexOf(':', i)
            if (keyEnd < 0) break
            val key = body.substring(i, keyEnd).trim().uppercase()
            i = keyEnd + 1
            // 取值：支持反斜杠转义的分号
            val sb = StringBuilder()
            while (i < n) {
                val ch = body[i]
                if (ch == '\\' && i + 1 < n) {
                    sb.append(body[i + 1]); i += 2; continue
                }
                if (ch == ';') { i++; break }
                sb.append(ch); i++
            }
            map[key] = sb.toString()
        }
        // 字段长度上限按 IEEE 802.11 标准：SSID ≤32 字节，密码 ≤63 字节。超长丢弃。
        val ssid = map["S"].orEmpty()
        if (ssid.isEmpty() || ssid.toByteArray(Charsets.UTF_8).size > 32) return null
        val pw = map["P"].orEmpty()
        if (pw.toByteArray(Charsets.UTF_8).size > 63) return null
        val auth = WifiSecurity.normalizeSecurity(map["T"])
        val hidden = map["H"]?.equals("true", ignoreCase = true) == true
        return Parsed(ssid = ssid, password = pw, security = auth, hidden = hidden)
    }
}
