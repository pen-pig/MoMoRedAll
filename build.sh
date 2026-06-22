#!/bin/bash
# MomoRedAll 一键编译脚本
# 用法: chmod +x build.sh && ./build.sh
# 前提: 容器有 curl, unzip, tar, 约 2G 空闲空间
set -e

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="$WORKDIR/android-sdk"
JAVA_HOME_DIR="$WORKDIR/jdk17"

echo "=== 1/4 下载 JDK 17 ==="
if [ ! -d "$JAVA_HOME_DIR" ]; then
    JDK_URL="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.19%2B10/OpenJDK17U-jdk_x64_linux_hotspot_17.0.19_10.tar.gz"
    echo "下载中 (~185MB)..."
    wget -q --show-progress -c -t 10 -L "$JDK_URL" -O jdk17.tar.gz || curl -L -C - --retry 10 -o jdk17.tar.gz "$JDK_URL"
    mkdir -p "$JAVA_HOME_DIR"
    tar xzf jdk17.tar.gz -C "$JAVA_HOME_DIR" --strip-components=1
    rm -f jdk17.tar.gz
fi
export JAVA_HOME="$JAVA_HOME_DIR"
export PATH="$JAVA_HOME/bin:$PATH"
java -version

echo "=== 2/4 下载 Android SDK ==="
if [ ! -f "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" ]; then
    mkdir -p "$SDK_DIR/cmdline-tools"
    SDK_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    echo "下载中 (~150MB)..."
    wget -q --show-progress -c -t 10 "$SDK_URL" -O cmdline-tools.zip || curl -L -C - --retry 10 -o cmdline-tools.zip "$SDK_URL"
    unzip -qo cmdline-tools.zip -d "$SDK_DIR/cmdline-tools"
    mv "$SDK_DIR/cmdline-tools/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
    rm -f cmdline-tools.zip
fi

export ANDROID_HOME="$SDK_DIR"
export ANDROID_SDK_ROOT="$SDK_DIR"
yes | "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$SDK_DIR" \
    "platforms;android-35" "build-tools;35.0.0" "platform-tools" 2>&1 | tail -3

echo "=== 3/4 生成项目文件 ==="
cd "$WORKDIR"
# 创建工程目录
mkdir -p app/src/main/java/com/marvis/momoreball
mkdir -p app/src/main/res/values
mkdir -p gradle/wrapper

# app/build.gradle.kts
cat > app/build.gradle.kts << 'GRADLEEOF'
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
        versionCode = 1
        versionName = "1.0"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    kotlinOptions { jvmTarget = "17" }
}
dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}
GRADLEEOF

# 根 build.gradle.kts
cat > build.gradle.kts << 'GRADLEEOF'
plugins {
    id("com.android.application") version "8.7.3" apply false
    kotlin("android") version "2.1.0" apply false
}
GRADLEEOF

# settings.gradle.kts
cat > settings.gradle.kts << 'GRADLEEOF'
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolution {
    repositories { google(); mavenCentral() }
}
rootProject.name = "MomoRedAll"
include(":app")
GRADLEEOF

# gradle wrapper properties
cat > gradle/wrapper/gradle-wrapper.properties << 'GRADLEEOF'
distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\://services.gradle.org/distributions/gradle-8.11.1-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
GRADLEEOF

# AndroidManifest.xml
cat > app/src/main/AndroidManifest.xml << 'XMLEOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="false" android:supportsRtl="true">
        <meta-data android:name="xposedmodule" android:value="true" />
        <meta-data android:name="xposeddescription" android:value="让 Momo 全部检测报红" />
        <meta-data android:name="xposedminversion" android:value="82" />
        <meta-data android:name="xposedscope" android:resource="@array/xposed_scope" />
    </application>
</manifest>
XMLEOF

# arrays.xml
cat > app/src/main/res/values/arrays.xml << 'XMLEOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string-array name="xposed_scope">
        <item>io.github.vvb2060.mahoshojo</item>
        <item>io.github.vvb2060.keyattestation</item>
        <item>duckduckgo.mobile.android</item>
    </string-array>
</resources>
XMLEOF

# 写入 Kotlin 源文件（由外部脚本构建）
if [ -f "$WORKDIR/MomoRedAll.kt" ]; then
    cp "$WORKDIR/MomoRedAll.kt" app/src/main/java/com/marvis/momoreball/
fi

echo "=== 4/4 编译 APK ==="
# 下载 gradle wrapper
cat > gradlew << 'GRADLEW_EOF'
#!/bin/sh
# Gradle wrapper stub - 用已安装的 gradle 或下载
GRADLE_USER_HOME="$WORKDIR/.gradle"
export GRADLE_USER_HOME
ANDROID_HOME="$SDK_DIR"
export ANDROID_HOME
JAVA_HOME="$JAVA_HOME_DIR"
export JAVA_HOME
PATH="$JAVA_HOME/bin:$PATH"

# 如果没有 gradle，下载
if ! command -v gradle &>/dev/null; then
    GRADLE_ZIP="$WORKDIR/gradle-8.11.1-bin.zip"
    if [ ! -f "$GRADLE_ZIP" ]; then
        echo "下载 Gradle 8.11.1..."
        wget -q --show-progress -c -t 10 "https://services.gradle.org/distributions/gradle-8.11.1-bin.zip" -O "$GRADLE_ZIP" || \
        curl -L -C - --retry 10 -o "$GRADLE_ZIP" "https://services.gradle.org/distributions/gradle-8.11.1-bin.zip"
    fi
    GRADLE_DIR="$WORKDIR/gradle-8.11.1"
    if [ ! -d "$GRADLE_DIR" ]; then
        unzip -qo "$GRADLE_ZIP" -d "$WORKDIR"
    fi
    export PATH="$GRADLE_DIR/bin:$PATH"
fi

cd "$WORKDIR"
gradle assembleRelease --no-daemon -q 2>&1
cp app/build/outputs/apk/release/app-release-unsigned.apk ../MomoRedAll.apk 2>/dev/null || \
cp app/build/outputs/apk/debug/app-debug.apk ../MomoRedAll.apk 2>/dev/null

echo ""
echo "===== 编译完成 ====="
echo "APK 输出: $WORKDIR/../MomoRedAll.apk"
echo "==================="
GRADLEW_EOF

chmod +x gradlew
./gradlew
