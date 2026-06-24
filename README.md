# MomoRedAll Xposed v3.0 — 爆红版

Xposed (LSPosed) 模块：**主动注入脏数据**，让所有 Root 检测器确认"此环境已被修改"（爆红）。

配合 [MomoRedAll-Magisk v3.0](https://github.com/pen-pig/MomoRedAll-Magisk) Native Hook 模块使用，Java + Native 双管齐下全面爆红。

**哲学反转**：v2.x 是隐藏 Root 痕迹（过滤 Root App / magisk 进程），v3.0 是让一切 Root 证据暴露出来。设计目标：所有检测器全部报红。

## 覆盖检测器（12+）

| 检测器 | 包名 |
|---|---|
| **Momo** | `io.github.vvb2060.mahoshojo` |
| **MagiskDetector** | `io.github.vvb2060.magiskdetector` |
| **NativeTest/MinotaurPoc** | `icu.nullptr.nativetest` |
| **Ruru** | `com.byxiaorun.detector` |
| **Hunter** | `com.zhenxi.hunter` |
| **Oprek Detector** | `com.godevelopers.OprekCek` |
| **SafeCheck** | `com.ysh.hookapkverify` |
| **DetectZ** | `com.test.detectz` |
| **Key Attestation** | `io.github.vvb2060.keyattestation` |
| **DuckDuckGo** | `duckduckgo.mobile.android` |
| **DirtySepolicy** | `org.lsposed.dirtysepolicy` |
| **DetectMagisk** | `com.darvin.security` |

## v3.0 爆红变更

### PackageManager：不再过滤（从隐藏改为暴露）
- ~~`queryIntentActivities` 滤除 Magisk/LSPosed 等 Root App~~ → **透传，让检测器看到真实安装的 Root 应用**
- ~~`getInstalledApplications` / `getInstalledPackages` 滤除 Root App~~ → **透传**
- ~~`getPackageInfo` 对 Root App 抛 NameNotFoundException~~ → **透传**

### ActivityManager：不再过滤
- ~~`getRunningAppProcesses` 滤除 magiskd/zygisk/frida 进程~~ → **透传，让检测器看到真实运行的进程**

### 已有爆红注入（保持不变）
- **假属性 60+**：ro.debuggable=1, ro.secure=0, ro.magisk.version=27000 等全脏值
- **假文件 80+**：所有 Root/Magisk/KSU/APatch/Frida/Xposed 路径返回伪造文件对象
- **假 Shell 25+**：ps（含 magiskd/frida 进程）、getprop（全脏属性）、mount（magisk 挂载）
- **/proc/net/tcp + tcp6**：frida-server 端口注入
- **File.length()**：假文件返回非零长度
- **SELinux**：isSELinuxEnforced() → false
- **LD_PRELOAD**：getenv → libriruloader.so

## Hook 清单

| 类别 | API | v3.0 行为 |
|---|---|---|
| **属性** | `SystemProperties.get()` | 返回脏值 |
| **文件** | `File.exists()/canRead()/canExecute()` | 假路径返回真 |
| **文件** | `FileInputStream(File)` | 假路径返回假内容 |
| **文件** | `File.length()` | 假路径返回非零长度 |
| **文件** | `java.io.File.<init>` | 假路径自动矫正路径 |
| **Shell** | `Runtime.exec()` | 返回假输出 |
| **Shell** | `ProcessBuilder.start()` | 返回假输出 |
| **/proc** | `/proc/self/maps` 文件流 | 注入 magisk/lsposed/frida 条目 |
| **/proc** | `/proc/net/tcp` + `tcp6` | 注入 frida-server 端口 |
| **PM** | `queryIntentActivities` | 透传（不过滤） |
| **PM** | `getInstalledApplications/Packages` | 透传（不过滤） |
| **PM** | `getPackageInfo` | 透传（不隐藏） |
| **AM** | `getRunningAppProcesses` | 透传（不过滤） |
| **SELinux** | `isSELinuxEnforced/checkSELinuxAccess` | 返回 false/true |
| **环境** | `System.getenv(LD_PRELOAD)` | 返回 libriruloader.so |

## 与 Magisk 版配合

| 层面 | Magisk 版 (Zygisk) | Xposed 版 (LSPosed) |
|---|---|---|
| **文件访问** | /proc/* memfd 注入 | File API 假文件对象 |
| **属性** | libc __system_property_get | SystemProperties.get() |
| **Shell** | popen() | Runtime.exec() |
| **进程检测** | /proc/self/status/maps 注入 | ActivityManager 透传 |
| **包检测** | 不适用（Native 层） | PackageManager 透传 |
| **ptrace** | 拦截（返回 EPERM） | 不适用（Java 层） |

## 构建

```bash
./gradlew assembleRelease
```

输出 `app/build/outputs/apk/release/app-release.apk`。

## 安装

1. 安装 LSPosed
2. 在 LSPosed 中启用本模块，勾选所有目标检测器
3. 重启目标应用（或软重启）
4. 验证：打开 Momo，应**全部爆红**

---

> 本项目由 AI 辅助生成。仅供教育用途。
