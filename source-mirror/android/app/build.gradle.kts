plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlin.plugin.compose")
    // CycloneDX SBOM：生成 app/build/reports/cyclonedx-direct/bom.{json,xml}
    id("org.cyclonedx.bom") version "3.4.1"
}

val releaseSigningPropertyNames = listOf(
    "FAEVAULT_KEYSTORE",
    "FAEVAULT_KEYSTORE_PASSWORD",
    "FAEVAULT_KEY_ALIAS",
    "FAEVAULT_KEY_PASSWORD",
)

fun releaseSigningConfigurationErrors(
    properties: Map<String, String?>,
    keystoreIsFile: (String) -> Boolean,
): List<String> = buildList {
    releaseSigningPropertyNames.forEach { name ->
        if (properties[name].isNullOrBlank()) add("$name is missing or blank")
    }
    properties["FAEVAULT_KEYSTORE"]
        ?.takeUnless(String::isBlank)
        ?.trim()
        ?.let { path ->
            if (!keystoreIsFile(path)) add("FAEVAULT_KEYSTORE must point to an existing file")
        }
}

val releaseSigningProperties = releaseSigningPropertyNames.associateWith { name ->
    providers.gradleProperty(name).orNull
}

val testReleaseSigningValidation = tasks.register("testReleaseSigningValidation") {
    group = "verification"
    description = "Tests release signing configuration validation without accessing real secrets."
    doLast {
        val errors = releaseSigningConfigurationErrors(
            properties = emptyMap<String, String?>(),
            keystoreIsFile = { false },
        )
        check(errors == listOf(
            "FAEVAULT_KEYSTORE is missing or blank",
            "FAEVAULT_KEYSTORE_PASSWORD is missing or blank",
            "FAEVAULT_KEY_ALIAS is missing or blank",
            "FAEVAULT_KEY_PASSWORD is missing or blank",
        )) { "Unexpected errors for missing release signing properties: $errors" }

        val missingFileErrors = releaseSigningConfigurationErrors(
            properties = releaseSigningPropertyNames.associateWith { "configured" },
            keystoreIsFile = { false },
        )
        check(missingFileErrors == listOf("FAEVAULT_KEYSTORE must point to an existing file")) {
            "Unexpected errors for a missing release keystore file: $missingFileErrors"
        }

        val blankPasswordErrors = releaseSigningConfigurationErrors(
            properties = releaseSigningPropertyNames.associateWith { name ->
                if (name.endsWith("PASSWORD")) "   " else "configured"
            },
            keystoreIsFile = { true },
        )
        check(blankPasswordErrors == listOf(
            "FAEVAULT_KEYSTORE_PASSWORD is missing or blank",
            "FAEVAULT_KEY_PASSWORD is missing or blank",
        )) { "Unexpected errors for blank release signing passwords: $blankPasswordErrors" }

        val validErrors = releaseSigningConfigurationErrors(
            properties = releaseSigningPropertyNames.associateWith { "configured" },
            keystoreIsFile = { true },
        )
        check(validErrors.isEmpty()) { "A valid release signing configuration was rejected: $validErrors" }
    }
}

android {
    namespace = "com.vault"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.fae.vault"
        minSdk = 26          // Android 8.0：AES-GCM、BiometricPrompt 基线
        targetSdk = 35
        versionCode = 467
        versionName = "4.6.7"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // 显式声明支持语言，确保 lint 的 MissingTranslation 按正确方向检查（默认中文，英文为翻译）。
        resConfigs("zh-rCN", "en")
        // 同时打包 32/64 位 ABI：ML Kit 等原生库需要对应 ABI 才能加载。
        // 若需缩小包体，可在 splits.abi 中关闭 x86 或 arm64-v8a 之外的分支。
        ndk { abiFilters += listOf("arm64-v8a", "x86_64", "armeabi-v7a", "x86") }
    }

    // Android 15+ 要求 native 库按 16KB 页对齐。新版打包格式默认开启该对齐，
    // 同时禁用历史遗留的 legacy ZIP 打包，保证加载 ML Kit 的本地代码时不被拒
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    // Release 签名：从 gradle.properties（项目根目录）读取，避免把密钥写进代码仓库。
    // 你只需在 ~/.gradle/gradle.properties 或项目根 gradle.properties 中填入：
    //   FAEVAULT_KEYSTORE=D:/path/to/release.jks
    //   FAEVAULT_KEYSTORE_PASSWORD=...
    //   FAEVAULT_KEY_ALIAS=...
    //   FAEVAULT_KEY_PASSWORD=...
    signingConfigs {
        create("release") {
            val ksPath = releaseSigningProperties["FAEVAULT_KEYSTORE"]?.trim().orEmpty()
            if (ksPath.isNotEmpty()) {
                storeFile = file(ksPath)
                storePassword = releaseSigningProperties["FAEVAULT_KEYSTORE_PASSWORD"]
                keyAlias = releaseSigningProperties["FAEVAULT_KEY_ALIAS"]
                keyPassword = releaseSigningProperties["FAEVAULT_KEY_PASSWORD"]
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            // R8 压缩/混淆已开启（含资源收缩）
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
    // 多 ABI 时分包，避免单 APK 把全部架构 native 库都打进去（包体可缩小 ~40%）。
    // ⚠️ AGP 限制：splits.abi 与 bundleRelease 互斥。构建 AAB 时必须传 -PforBundle=true 关掉它。
    // 见 https://issuetracker.google.com/402800800
    val buildingBundle = (project.findProperty("forBundle") as String?)?.toBoolean() == true
    splits {
        abi {
            isEnable = !buildingBundle
            reset()
            include("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
            isUniversalApk = true   // 同时产出一份 universal apk，便于直接侧载
        }
    }

    // App Bundle 配置：Google Play 自 2021 起强制 AAB 上架
    //  - splits 让 Play 按 ABI / 屏幕密度 / 语言分别分发，进一步压缩用户下载量
    //  - 不启用 enableSplit 时仍会产出 AAB，但用户下载全部架构 native 库，包体翻倍
    bundle {
        language { enableSplit = true }
        density  { enableSplit = true }
        abi      { enableSplit = true }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true; buildConfig = true }
    lint {
        abortOnError = true
        checkReleaseBuilds = true
        lintConfig = file("lint.xml")
        // 既有 lint 债务入基线，只对新增问题报错（含 MissingTranslation 强制）。
        baseline = file("lint-baseline.xml")
    }
    // 让 JVM 单元测试能读到 spec/ 下的跨端测试向量
    testOptions { unitTests.all { it.systemProperty("spec.dir", "${rootDir}/spec") } }
}

testReleaseSigningValidation.configure {
    doLast {
        check(android.buildTypes.getByName("release").signingConfig?.name == "release") {
            "Release builds must use only the release signing configuration"
        }
        check(android.buildTypes.getByName("debug").signingConfig?.name != "release") {
            "Debug builds must never use the release signing configuration"
        }
    }
}

val validateReleaseSigningConfiguration = tasks.register("validateReleaseSigningConfiguration") {
    group = "verification"
    description = "Fails when the release signing properties are incomplete or invalid."
    doLast {
        val errors = releaseSigningConfigurationErrors(
            properties = releaseSigningProperties,
            keystoreIsFile = { path -> file(path).isFile },
        )
        if (errors.isNotEmpty()) {
            throw GradleException(
                "Release signing configuration is invalid:\n" +
                    errors.joinToString(separator = "\n") { "- $it" },
            )
        }
    }
}

// preReleaseBuild is present only in release task graphs, so debug/test configuration stays usable.
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(validateReleaseSigningConfiguration)
}

androidComponents {
    onVariants { variant ->
        // 统一打包产物命名：FAEVault-<abi>-<buildType>.apk（分 ABI 分包 + universal）
        if (variant is com.android.build.api.variant.ApplicationVariant) {
            variant.outputs.forEach { output ->
                val abi = output.filters
                    .firstOrNull { it.filterType == com.android.build.api.variant.FilterConfiguration.FilterType.ABI }
                    ?.identifier
                val label = when {
                    abi != null -> abi
                    output.outputType == com.android.build.api.variant.VariantOutputConfiguration.OutputType.UNIVERSAL -> "universal"
                    else -> "full"
                }
                output.outputFileName.set("FAEVault-${label}-${variant.name}.apk")
            }
        }
    }
}

dependencies {
    implementation("dev.chrisbanes.haze:haze:1.5.4")
    implementation(platform("androidx.compose:compose-bom:2024.10.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    // 1.10.0 起提供 LocalActivity：AppRoot 用它替代 LocalContext 到 Activity 的强转（lint
    // ContextCastToActivity 会报错）。声明版本与实际解析版本对齐，避免依赖传递解析的巧合。
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // JSON 序列化（kotlinx.serialization，宽松解析保留未知字段）
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    // scrypt：JCA 不内置，用 Bouncy Castle
    implementation("org.bouncycastle:bcprov-jdk18on:1.84")
    // X509 临时证书生成（局域网传输站服务端用；X509v3CertificateBuilder 在 bcpkix）
    implementation("org.bouncycastle:bcpkix-jdk18on:1.84")
    // zstd 必须用 Android AAR（否则只打包桌面版 win/darwin/linux 原生库，运行时报 NoClassDefFoundError）
    implementation("com.github.luben:zstd-jni:1.5.7-11@aar") {
        exclude(group = "com.github.luben", module = "zstd-jni")
    }
    // JVM 单元测试需要桌面版原生库（.dll/.so），与 APK 内安卓 AAR 互不冲突
    testImplementation("com.github.luben:zstd-jni:1.5.7-11")
    // Markdown 解析：commonmark-java 官方参考实现 + 官方扩展（GFM 表格/删除线/任务列表、自动链接、脚注、下划线）
    implementation("org.commonmark:commonmark:0.24.0")
    implementation("org.commonmark:commonmark-ext-gfm-tables:0.24.0")
    implementation("org.commonmark:commonmark-ext-gfm-strikethrough:0.24.0")
    implementation("org.commonmark:commonmark-ext-task-list-items:0.24.0")
    implementation("org.commonmark:commonmark-ext-autolink:0.24.0")
    implementation("org.commonmark:commonmark-ext-footnotes:0.24.0")
    implementation("org.commonmark:commonmark-ext-ins:0.24.0")
    // 生物识别解锁
    implementation("androidx.biometric:biometric:1.1.0")
    // Android 11+ keyboard inline suggestions for the Autofill provider.
    implementation("androidx.autofill:autofill:1.3.0")
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.webkit:webkit:1.12.1")
    implementation("com.caverock:androidsvg-aar:1.4")
    implementation("androidx.work:work-runtime-ktx:2.11.2")
    // ZXing 二维码生成（Wi-Fi 分享）+ 静态图本地识别（WifiQr.scanFromUri）
    implementation("com.google.zxing:core:3.5.3")
    // CameraX：自写文档扫描相机的预览 / 抓帧 / 拍照
    implementation("androidx.camera:camera-camera2:1.4.0")
    implementation("androidx.camera:camera-lifecycle:1.4.0")
    implementation("androidx.camera:camera-view:1.4.0")
    // ML Kit 文字识别（端上推理，无需联网）：拉丁字符 + 中文
    implementation("com.google.mlkit:text-recognition:16.0.1")
    implementation("com.google.mlkit:text-recognition-chinese:16.0.1")
    // 密码强度估算：zxcvbn（弱密码检测，覆盖常见词汇/键盘序列/重复模式等可预测内容）
    implementation("com.nulab-inc:zxcvbn:1.9.0")
    // 官方 OpenCV：离线文档边缘检测和透视校正，不依赖 Play Services 扫描界面。
    implementation("org.opencv:opencv:4.12.0")
    // Kotlin 协程 Play Services 互操作（Task → suspend）
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // 加密 ZIP 导出（WinZip AES-256，通用解压工具可开）
    implementation("net.lingala.zip4j:zip4j:2.11.5")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    // JVM 单元测试用真实 org.json 实现（android.jar 中的桩会抛 "not mocked"）
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
