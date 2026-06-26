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
        versionCode = 3
        versionName = "2.2"
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}
