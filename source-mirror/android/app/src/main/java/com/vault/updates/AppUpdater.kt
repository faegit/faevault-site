package com.vault.updates

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** 应用内更新：下载 APK → 校验签名与版本 → 拉起系统安装器。 */
object AppUpdater {

    private const val DIR_NAME = "updates"
    private const val FILE_NAME = "faevault-update.apk"

    /**
     * 下载闸门。UI 侧也有重入守卫，但这里的临时文件名是共享的：两次下载会交错写同一个
     * .part、并互相删对方的文件，SHA-256 必然失配。闸门放在持有共享资源这一层，
     * 任何新增调用点都自动受保护。
     */
    private val downloadInFlight = java.util.concurrent.atomic.AtomicBoolean(false)

    enum class VerifyResult { OK, SIGNATURE_MISMATCH, INVALID_INFO, INVALID_VERSION }

    fun apkFile(context: Context): File =
        File(File(context.filesDir, DIR_NAME).apply { mkdirs() }, FILE_NAME)

    fun canRequestPackageInstalls(context: Context): Boolean =
        context.packageManager.canRequestPackageInstalls()

    fun installPermissionSettingsIntent(context: Context): Intent =
        Intent(
            android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
            Uri.parse("package:${context.packageName}"),
        )

    fun downloadApk(
        context: Context,
        info: UpdateInfo,
        onProgress: (received: Long, total: Long) -> Unit,
    ): File {
        check(downloadInFlight.compareAndSet(false, true)) { "更新包下载已在进行中" }
        val dest = apkFile(context)
        var target = URL(info.downloadUrl)
        var connection: HttpURLConnection? = null
        // 每次下载独占一个 .part：固定名会让并发的两条流写进同一文件，finally 里的
        // delete() 也会删掉对方正在写的那一个。
        val partial = File(dest.parentFile, "$FILE_NAME.${java.util.UUID.randomUUID()}.part")
        try {
            for (redirect in 0..5) {
                requireTrustedDownloadUrl(target)
                val next = (target.openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15_000
                    readTimeout = 20_000
                    setRequestProperty("User-Agent", "FAEVault-Android-Updater")
                    instanceFollowRedirects = false
                }
                connection = next
                if (next.responseCode !in listOf(301, 302, 303, 307, 308)) break
                val location = next.getHeaderField("Location") ?: error("Missing APK redirect")
                require(redirect < 5) { "Too many APK redirects" }
                target = URL(target, location)
                next.disconnect()
            }
            val active = requireNotNull(connection)
            require(active.responseCode == 200) { "下载服务返回 HTTP ${active.responseCode}" }
            val total = active.contentLengthLong.coerceAtLeast(0L)
            var received = 0L
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            partial.outputStream().use { out ->
                active.inputStream.use { input ->
                    val buffer = ByteArray(1 shl 16)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        digest.update(buffer, 0, read)
                        out.write(buffer, 0, read)
                        received += read
                        onProgress(received, total)
                    }
                }
            }
            require(total == 0L || received == total) { "Incomplete APK download" }
            verifyAssetDigest(digest.digest(), info.sha256)
            java.nio.file.Files.move(partial.toPath(), dest.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            onProgress(received, received)
            return dest
        } finally {
            connection?.disconnect()
            partial.delete()
            downloadInFlight.set(false)
        }
    }

    fun verify(context: Context, apk: File): VerifyResult {
        val archive = context.packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
            ?: return VerifyResult.INVALID_INFO
        // 签名比对是交集语义，同一发布密钥签出的其它包名也能过；这里先把包名钉死。
        if (archive.packageName != context.packageName) return VerifyResult.INVALID_INFO
        if (PackageInfoCompat.getLongVersionCode(archive) < com.vault.BuildConfig.VERSION_CODE) {
            return VerifyResult.INVALID_VERSION
        }
        return if (signaturesMatch(context, apk)) VerifyResult.OK else VerifyResult.SIGNATURE_MISMATCH
    }

    fun buildInstallIntent(context: Context, apk: File): Intent {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (context !is Activity) addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    @Suppress("DEPRECATION")
    private fun signaturesMatch(context: Context, apk: File): Boolean {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            val archive = pm.getPackageArchiveInfo(apk.absolutePath, flags) ?: return false
            val current = pm.getPackageInfo(context.packageName, flags) ?: return false
            val archiveSigners = archive.signingInfo?.apkContentsSigners.orEmpty()
            val currentSigners = current.signingInfo?.apkContentsSigners.orEmpty()
            archiveSigners.any { a -> currentSigners.any { c -> a.toByteArray().contentEquals(c.toByteArray()) } }
        } else {
            val flags = PackageManager.GET_SIGNATURES
            val archive = pm.getPackageArchiveInfo(apk.absolutePath, flags) ?: return false
            val current = pm.getPackageInfo(context.packageName, flags) ?: return false
            val a = archive.signatures?.firstOrNull() ?: return false
            val c = current.signatures?.firstOrNull() ?: return false
            a.toByteArray().contentEquals(c.toByteArray())
        }
    }
}
