package com.vault.ui.media

import com.vault.ui.uiText
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** 生成 Wi-Fi QR 码标准编码。WPA 族聚合为 T:WPA；有密码时不做 nopass。 */
fun wifiQrPayload(ssid: String, password: String, security: String? = null): String {
    val token = com.vault.os.WifiSecurity.qrAuthToken(security, password.isNotEmpty())
    fun esc(s: String) = s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace(":", "\\:").replace("\"", "\\\"")
    return "WIFI:T:${token};S:${esc(ssid)};P:${esc(password)};;"
}

fun encodeQr(content: String, size: Int = 512): Bitmap {
    val hints = mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.MARGIN to 1,
        EncodeHintType.CHARACTER_SET to "UTF-8",
    )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints)
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    for (y in 0 until size) for (x in 0 until size) {
        bmp.setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
    }
    return bmp
}

@Composable
fun QrImage(content: String, sizeDp: Int = 220) {
    val bmp = remember(content) { encodeQr(content) }
    Image(
        bitmap = bmp.asImageBitmap(),
        contentDescription = uiText("二维码"),
        modifier = Modifier.size(sizeDp.dp),
    )
}
