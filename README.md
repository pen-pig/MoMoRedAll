# MomoRedAll Xposed v2.0

Xposed 模块：Java 层全量痕迹注入，覆盖 12+ 主流 Root/Magisk 检测器。

配合 [MomoRedAll-Magisk](https://github.com/pen-pig/MomoRedAll-Magisk) Native Hook 模块使用，双管齐下实现 Java + Native 层全量绕过。

## 覆盖检测器

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

## v2.0 新增

### PackageManager 拦截（Java 层独家能力）
- `queryIntentActivities` — 从结果中滤除 Magisk/LSPosed/KernelSU/Frida 等 Root 管理 App
- `getInstalledApplications` / `getInstalledPackages` — 同上
- `getPackageInfo` — 对 Root App 包名直接抛 NameNotFoundException

### ActivityManager 拦截
- `getRunningAppProcesses` — 滤除 magiskd/zygisk/xposed/frida 进程

### 扩展数据
- 假属性：**37 → 60+**（新增 ro.build.fingerprint/ro.crypto.*/ro.modversion/ro.lineage.version 等）
- 假文件路径：**50 → 80+**（新增 KSU/APatch/PlayIntegrityFix/TrickyStore/Zygisk-Assistant/LSPosed 路径）
- Shell 输出：**12 → 25+**（新增 pgrep/pidof/sestatus/getenforce/ss 等）
- `/proc/net/tcp6`：新增 IPv6 frida 端口注入
- File.length()：新 hook，假文件返回非零长度

## Hook 清单

| 类别 | Hook 目标 |
|---|---|
| 系统属性 | SystemProperties.get/getBoolean/getInt/getLong（60+ 假属性） |
| 文件存在 | File.exists/canRead/canExecute/isFile/isDirectory/length |
| 目录遍历 | File.listFiles — 注入 /data/adb/*, /sbin/*, /data/local/tmp/* 的假文件 |
| Shell 命令 | ProcessBuilder.start + Runtime.exec（4种签名兜底） |
| /proc 文件 | FileInputStream — /proc/self/maps/status/mounts/wchan/attr + /proc/net/tcp + /sys/fs/selinux/enforce |
| TEE | KeyInfo.isInsideSecureHardware, setAttestationChallenge, setStrongBoxBacked, getCertificateChain |
| SELinux | SELinux.isSELinuxEnforced, checkSELinuxAccess |
| 环境变量 | System.getenv("LD_PRELOAD") |
| PackageManager | queryIntentActivities, getInstalledApplications, getInstalledPackages, getPackageInfo |
| ActivityManager | getRunningAppProcesses |

## 安装

1. 安装 LSPosed / EdXposed
2. 在 LSPosed 管理器中勾选目标 App（至少 Momo + MagiskDetector）
3. 同时安装 [MomoRedAll-Magisk](https://github.com/pen-pig/MomoRedAll-Magisk) 覆盖 Native 层
4. 重启设备

## CDN 下载

<https://cdn.jsdelivr.net/gh/pen-pig/MoMoRedAll@master/apk/app-release-signed.apk>

---

> 本项目由 AI 辅助生成。仅供教育用途。
