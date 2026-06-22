# MomoRedAll — 让 Momo 26项检测全部报红

两种方案：**Frida 脚本**（立即可用）和 **LSPosed 模块**（需要编译）。

---

## 方案 A：Frida 脚本（推荐，无需编译）

### 前提

手机上有 `frida-server` 在跑，PC 上有 `frida-tools`。

### 使用

```bash
# 注入 Momo
frida -U -f io.github.vvb2060.mahoshojo -l momo_red_all.js --no-pause

# 或已运行中的 Momo
frida -U io.github.vvb2060.mahoshojo -l momo_red_all.js

# DuckDector
frida -U -f duckduckgo.mobile.android -l momo_red_all.js --no-pause
```

**优点**：写完即用，不需要 Android Studio，不需要编译 APK。
**副作用**：Frida 自身触发 "发现代码注入" ——但你要的就是全红。

### 脚本做了什么

| Hook 点 | 伪造效果 |
|----------|----------|
| `SystemProperties.get()` | TEE 损坏、debuggable=1、SELinux 0 |
| `File.exists()` | su/Magisk/Riru 文件全部"存在" |
| `File.listFiles()` | /data/adb/ 下注入模块目录 |
| `ProcessBuilder.start()` | ps 输出注入 zygisk/magiskd 进程 |
| `FileInputStream(/proc/self/maps)` | 注入 zygisk.so 内存映射行 |

### Frida-server 安装

```bash
# 下载对应架构的 frida-server
# https://github.com/frida/frida/releases
# 小米 14 (houji) 用 android-arm64

adb push frida-server-16.x.x-android-arm64 /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/frida-server-16.x.x-android-arm64"
adb shell su -c "/data/local/tmp/frida-server-16.x.x-android-arm64 &"
```

---

## 方案 B：LSPosed 模块（编译后安装）

### 目录结构

```
MomoRedAll/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle/wrapper/gradle-wrapper.properties
└── app/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        ├── res/values/arrays.xml
        └── java/com/marvis/momoreball/MomoRedAll.kt
```

### 编译

用 Android Studio 打开项目根目录，Build → Build APK。

或命令行：

```bash
cd MomoRedAll
./gradlew assembleRelease
# 输出在 app/build/outputs/apk/release/
```

### 安装

1. 安装 APK
2. LSPosed → 模块 → 启用 MomoRedAll
3. 作用域勾选 Momo 和 DuckDector
4. 强制停止目标 App，重启

---

## 能达到的效果

| 检测项 | 状态 |
|--------|------|
| Zygisk / Zygote 被注入 | ✅ 红（伪造 maps + ps 输出） |
| 找到 Magisk | ✅ 红 |
| 找到 SU | ✅ 红 |
| SELinux 宽容模式 | ✅ 红 |
| debug 环境 | ✅ 红 |
| ART 参数异常 | ✅ 红 |
| TEE 损坏 | ✅ 红（伪造 props） |
| 找到 Riru | ✅ 红 |
| 代码注入 | ✅ 红 |
| 非原厂系统 | ✅ 红 |
| 分区挂载异常 | ✅ 红 |
| init.rc 被修改 | ✅ 红 |
| **TEE 硬件级探针** | ⚠️ 部分红（App 层能骗，native Keymaster 探针无法） |

**唯一可能的缺口**：DuckDector 的 TEE 检测如果走 native 层直接调 `android.hardware.keymint` HAL，Java 层 Hook 无法拦截。这需要 KernelSU + susfs 或类似内核级方案。
