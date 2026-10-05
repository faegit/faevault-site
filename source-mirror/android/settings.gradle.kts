pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    // 依赖解析只用 google/mavenCentral：gradlePluginPortal 只应出现在 pluginManagement，
    // 放在这里会把插件门户纳入普通依赖的搜索路径（M-15 的供应链边界）。
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "FAEVault"
include(":app")
