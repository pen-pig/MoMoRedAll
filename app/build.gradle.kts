plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.marvis.momoreball"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.marvis.momoreball"
        minSdk = 29
        targetSdk = 35
        versionCode = 4
        versionName = "2.4"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}
