# kotlinx.serialization：保留 @Serializable 生成的序列化器
-keepattributes *Annotation*, InnerClasses, Signature, EnclosingMethod
-dontnote kotlinx.serialization.**
-keepclassmembers class com.vault.** {
    *** Companion;
}
-keepclasseswithmembers class com.vault.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-if @kotlinx.serialization.Serializable class **
-keepclassmembers class <1> {
    static <1>$Companion Companion;
    public static **$* *;
}
# kotlinx.coroutines：调试不必要的 stub
-dontwarn kotlinx.coroutines.debug.**

# Bouncy Castle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ML Kit & Google Play Services：保留 native 入口与回调
-keep class com.google.mlkit.** { *; }
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.mlkit.**
-dontwarn com.google.android.gms.**

# AndroidX Biometric：BiometricPrompt 用反射调用 callback
-keep class androidx.biometric.** { *; }

# ZXing
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**

# 模型数据类：被 kotlinx.serialization 生成的序列化器引用，
# -keepclasseswithmembers 已覆盖；这里额外保留枚举值的 valueOf 反射路径
-keepclassmembers enum com.vault.model.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# AndroidX Credentials：Passkey Credential Provider 框架用反射调用部分内部方法
-keep class androidx.credentials.** { *; }
-dontwarn androidx.credentials.**
-keep class com.vault.passkeys.** { *; }

# OkHttp：WebDAV 网络请求
-dontwarn okhttp3.**
-dontwarn okio.**

# CameraX：文档扫描
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# Compose：BOM 已含 consumer rules，无需额外。这里只屏蔽常见噪声
-dontwarn org.jetbrains.annotations.**

# zip4j：导出/导入加密压缩包
-keep class net.lingala.zip4j.** { *; }
-dontwarn net.lingala.zip4j.**
# OpenCV JNI looks up these Java types by name; they are not referenced from Kotlin.
-keep class org.opencv.core.CvException { *; }
-keep class org.opencv.core.MatOfInt { *; }
