package com.marvis.momoreball

import android.os.Build
import android.os.SystemProperties
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.lang.ProcessBuilder

/**
 * MomoRedAll - 让 Momo / DuckDector 全部检测项报红
 * 
 * 原理：Hook 被检测应用进程内的关键 Java API，
 * 伪造系统属性、文件存在性、进程列表、shell 命令输出等，
 * 使检测工具认为环境"极不安全"。
 * 
 * 作用域：io.github.vvb2060.mahoshojo (Momo)、
 *        duckduckgo.mobile.android (DuckDector)、
 *        io.github.vvb2060.keyattestation (Key Attestation)
 */
class MomoRedAll : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        // Debug 开关：logcat 搜 MomoRedAll
        const val TAG = "MomoRedAll"
        private fun log(msg: String) = XposedBridge.log("[$TAG] $msg")

        // 要伪造的 su 文件路径 — Momo/DuckDector 的典型扫描路径
        val FAKE_SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/system_ext/bin/su",
            "/product/bin/su",
            "/vendor/bin/su",
            "/data/local/tmp/su",
            "/sbin/su",
            "/system/sbin/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/mu",
            "/system/bin/failsafe/su",
        )

        // 要伪造存在的 Magisk 相关文件
        val FAKE_MAGISK_PATHS = listOf(
            "/data/adb/magisk.db",
            "/data/adb/magisk/busybox",
            "/data/adb/magisk/magisk32",
            "/data/adb/magisk/magisk64",
            "/data/adb/magisk/magiskinit",
            "/data/adb/magisk/magiskpolicy",
            "/data/adb/magisk/resetprop",
            "/data/adb/magisk/su",
            "/data/adb/magisk/util_functions.sh",
            "/data/adb/modules",
            "/data/adb/magisk",
            "/sbin/magisk",
            "/cache/magisk.log",
            "/data/adb/.magisk",
            "/data/adb/magisk/busybox",
            "/data/adb/magisk/rootdir",
            "/data/adb/magisk/magisk",
        )

        // 要伪造存在的可疑目录/文件（Momo 兼容）
        val FAKE_SUSPICIOUS_PATHS = listOf(
            "/data/adb/",
            "/data/adb/modules/",
            "/sbin/",
            "/system/app/Superuser/",
            "/system/app/SuperSU/",
            "/system/xbin/daemonsu",
            "/system/bin/.ext/",
            "/system/etc/init.d/",
            "/data/local/tmp/supersu/",
            "/data/data/eu.chainfire.supersu/",
            "/data/data/com.topjohnwu.magisk/",
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/data/data/com.noshufou.android.su/",
            "/data/local/tmp/su",
        )

        // Fake props: Momo 会读的系统属性
        // 每个条目：属性名 → 伪造值
        val FAKE_PROPS = mapOf(
            // TEE 损坏需要的属性
            "ro.boot.verifiedbootstate" to "orange",  // 未验证启动状态
            "ro.boot.flash.locked" to "0",            // bootloader unlocked
            "ro.boot.vbmeta.device_state" to "unlocked",
            "ro.boot.veritymode" to "disabled",       // dm-verity disabled
            // 调试环境
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.build.type" to "userdebug",
            "ro.build.tags" to "test-keys",
            "persist.sys.usb.config" to "adb",
            "init.svc.adbd" to "running",
            // SELinux
            "ro.build.selinux" to "0",
            // seccomp
            "ro.zygote.disable_gl_preload" to "1",
        )

        // Momo 可能通过 shell 执行这些命令
        // 返回一行伪造的输出行
        val FAKE_SHELL_RESPONSES = mapOf(
            // ps 输出里伪造 zygisk 进程
            "ps" to """USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME
root          1234     1  123456  56789 do_sys_poll         0 S zygisk64
root          1235     1  123456  56789 do_sys_poll         0 S zygisk32
root          5678     1  234567  89012 binder_thr          0 S magiskd
shell         9012     1   12345  34567 hrtimer_n           0 S su
root          1111     1  111111  22222 sigsuspen           0 S daemonsu
shell         2222  1111   33333  44444 pipe_wait           0 S sh
root           333   222   44444  55555 do_wait             0 S sh
""",
            // busybox 相关
            "busybox" to "",
            // getprop 返回伪造属性
            "getprop" to """
[ro.debuggable]: [1]
[ro.secure]: [0]
[ro.build.type]: [userdebug]
[ro.build.tags]: [test-keys]
[ro.boot.verifiedbootstate]: [orange]
[ro.boot.flash.locked]: [0]
[init.svc.adbd]: [running]
[ro.build.selinux]: [0]
""",
            // magisk 相关
            "magisk" to "",
            "su -v" to "16.0:MAGISKSU",
            "su --version" to "16.0:MAGISKSU",
            "which su" to "/system/bin/su",
            "type su" to "su is /system/bin/su",
            // which magisk
            "which magisk" to "/sbin/magisk",
            // resetprop 痕迹
            "resetprop" to "",
            "su -c id" to "uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0",
        )
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        log("Zygote init — hooks registered")

        val sysPropClass = XposedHelpers.findClass(
            "android.os.SystemProperties",
            null /* boot classloader */
        )

        // Hook 1: SystemProperties.get() → 对所有进程生效
        XposedHelpers.findAndHookMethod(
            sysPropClass,
            "get",
            String::class.java,
            String::class.java,  // def
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val key = param.args[0] as String
                    // 不打印每条日志以免刷屏
                    if (!FAKE_PROPS.containsKey(key)) return
                    // 只在目标应用进程内修改
                    val procName = param.processName
                    if (procName == null) return
                    val target = (
                        procName == "io.github.vvb2060.mahoshojo" ||
                        procName.contains("duckduckgo") ||
                        procName == "io.github.vvb2060.keyattestation"
                    )
                    if (!target) return

                    param.result = FAKE_PROPS[key]
                    log("prop $key → ${FAKE_PROPS[key]}")
                }
            }
        )

        // Hook 2: SystemProperties.getBoolean / getInt / getLong
        for (methodName in listOf("getBoolean", "getInt", "getLong")) {
            val paramTypes = when (methodName) {
                "getBoolean" -> arrayOf<Class<*>>(String::class.java, Boolean::class.javaPrimitiveType!!)
                "getInt"    -> arrayOf<Class<*>>(String::class.java, Int::class.javaPrimitiveType!!)
                "getLong"   -> arrayOf<Class<*>>(String::class.java, Long::class.javaPrimitiveType!!)
                else -> arrayOf()
            }
            XposedHelpers.findAndHookMethod(
                sysPropClass, methodName, *paramTypes,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = param.args[0] as String
                        val procName = param.processName ?: return
                        val target = (
                            procName == "io.github.vvb2060.mahoshojo" ||
                            procName.contains("duckduckgo") ||
                            procName == "io.github.vvb2060.keyattestation"
                        )
                        if (!target) return
                        if (!FAKE_PROPS.containsKey(key)) return

                        // 把字符串值转为对应类型
                        val fakeVal = FAKE_PROPS[key] ?: return
                        param.result = when (methodName) {
                            "getBoolean" -> fakeVal == "1" || fakeVal == "true"
                            "getInt"     -> fakeVal.toIntOrNull() ?: 1
                            "getLong"    -> fakeVal.toLongOrNull() ?: 1L
                            else -> param.result
                        }
                        log("prop $methodName $key → $fakeVal")
                    }
                }
            )
        }
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg != "io.github.vvb2060.mahoshojo"
            && !pkg.contains("duckduckgo")
            && pkg != "io.github.vvb2060.keyattestation"
        ) return

        log("Hook into $pkg (PID=${lpparam.processName})")

        val classLoader = lpparam.classLoader

        tryHookFileExists(classLoader)
        tryHookFileList(classLoader)
        tryHookRuntimeExec(classLoader)
        tryHookProcessBuilder(classLoader)
        tryHookMapsRead(classLoader)
        tryHookFileInputStream(classLoader)
    }

    // ──────────────────────────────────────────────
    // Hook: File.exists()
    // ──────────────────────────────────────────────
    private fun tryHookFileExists(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                File::class.java,
                "exists",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val f = param.thisObject as File
                        val path = f.absolutePath
                        val alreadyTrue = (param.result as? Boolean) == true
                        if (alreadyTrue) return // 真文件就不伪造

                        val fake = path in FAKE_SU_PATHS
                            || path in FAKE_MAGISK_PATHS
                            || path in FAKE_SUSPICIOUS_PATHS
                        if (fake) {
                            param.result = true
                            log("File.exists() $path → TRUE (fake)")
                        }
                    }
                }
            )
            log("✓ File.exists() hooked")
        } catch (e: Exception) {
            log("✗ File.exists() hook failed: ${e.message}")
        }
    }

    // ──────────────────────────────────────────────
    // Hook: File.listFiles() / list() — 让 /data/adb/ 等目录看起来非空
    // ──────────────────────────────────────────────
    private fun tryHookFileList(classLoader: ClassLoader) {
        try {
            val fakeZygiskDir = File("/data/adb/modules/zygisk_lsposed")
            val fakeMagiskDir = File("/data/adb/magisk")
            val fakeSuFile   = File("/system/bin/su")
            val fakeBusybox  = File("/system/xbin/busybox")

            XposedHelpers.findAndHookMethod(
                File::class.java,
                "listFiles",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val f = param.thisObject as File
                        val path = f.absolutePath
                        val existing = param.result as? Array<File> ?: return

                        when (path) {
                            "/data/adb/" -> {
                                param.result = existing + arrayOf(
                                    File("/data/adb/magisk.db"),
                                    File("/data/adb/magisk"),
                                    File("/data/adb/modules"),
                                    File("/data/adb/.magisk"),
                                )
                                log("listFiles /data/adb/ → injected")
                            }
                            "/data/adb/modules/" -> {
                                param.result = existing + arrayOf(
                                    File("/data/adb/modules/zygisk_lsposed"),
                                    File("/data/adb/modules/shamiko"),
                                    File("/data/adb/modules/hosts"),
                                )
                                log("listFiles /data/adb/modules/ → injected")
                            }
                            "/sbin/" -> {
                                param.result = existing + arrayOf(
                                    File("/sbin/su"),
                                    File("/sbin/magisk"),
                                )
                            }
                        }
                    }
                }
            )
            log("✓ File.listFiles() hooked")
        } catch (e: Exception) {
            log("✗ File.listFiles() hook failed: ${e.message}")
        }
    }

    // ──────────────────────────────────────────────
    // Hook: Runtime.exec() / ProcessBuilder → 拦截 shell 命令
    // ──────────────────────────────────────────────
    private fun tryHookRuntimeExec(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                Runtime::class.java,
                "exec",
                arrayOf(String::class.java),
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val cmd = param.args[0] as? String ?: return
                        // 不拦非 shell 执行
                    }
                }
            )

            // Hook ProcessBuilder.start() — 更常用的方式
            tryHookProcessBuilder(classLoader)
        } catch (e: Exception) {
            log("✗ Runtime.exec hook failed: ${e.message}")
        }
    }

    private fun tryHookProcessBuilder(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                ProcessBuilder::class.java,
                "start",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val pb = param.thisObject as ProcessBuilder
                        val cmdList = try {
                            XposedHelpers.getObjectField(pb, "command") as? List<String>
                        } catch (e: Exception) {
                            null
                        } ?: return

                        if (cmdList.isEmpty()) return

                        // 构造完整命令字符串
                        val fullCmd = cmdList.joinToString(" ")
                        log("shell: $fullCmd")

                        // 匹配已知命令，注入 fake 响应
                        for ((prefix, fakeOutput) in FAKE_SHELL_RESPONSES) {
                            if (fullCmd.contains(prefix)) {
                                // 替换为返回伪造输出的进程
                                param.result = FakeProcess(fakeOutput)
                                log("shell $prefix → FAKE OUTPUT")
                                return
                            }
                        }

                        // 通用：如果命令包含 su / magisk / busybox，伪造"存在"
                        if (fullCmd.contains("su") && !fullCmd.contains("supersu")) {
                            param.result = FakeProcess("uid=0(root) gid=0(root)\n")
                            log("shell su-like → fake root response")
                        }
                    }
                }
            )
            log("✓ ProcessBuilder.start() hooked")
        } catch (e: Exception) {
            log("✗ ProcessBuilder.start hook failed: ${e.message}")
        }
    }

    // ──────────────────────────────────────────────
    // Hook: /proc/self/maps 读取 → 注入 zygisk .so
    // ──────────────────────────────────────────────
    private fun tryHookMapsRead(classLoader: ClassLoader) {
        try {
            // 尝试 hook BufferedReader(FileReader("/proc/self/maps"))
            // 更简单：hook FileInputStream(File("/proc/self/maps"))
            XposedHelpers.findAndHookConstructor(
                "java.io.FileInputStream",
                classLoader,
                File::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val f = param.args[0] as? File ?: return
                        if (f.absolutePath == "/proc/self/maps") {
                            log("FileInputStream /proc/self/maps detected — injecting fake zygisk")
                            // 把传入的 File 换成我们的 fake maps 文件
                            // 写法略 — 创建临时文件并替换
                            val fakeMaps = createFakeMapsFile()
                            param.args[0] = fakeMaps
                        }
                    }
                }
            )
            log("✓ FileInputStream hook for /proc/self/maps registered")
        } catch (e: Exception) {
            log("✗ maps hook failed (Momo may use native open): ${e.message}")
        }
    }

    private fun tryHookFileInputStream(classLoader: ClassLoader) {
        // already handled in tryHookMapsRead
    }

    // ──────────────────────────────────────────────
    // 辅助：创建伪造的 /proc/self/maps 文件
    // ──────────────────────────────────────────────
    private fun createFakeMapsFile(): File {
        val tmp = File.createTempFile("fake_maps_", ".txt")
        tmp.deleteOnExit()
        val zygiskInjectLines = """
7a1b2c3d4000-7a1b2c3d6000 r-xp 00000000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d6000-7a1b2c3d8000 r--p 00001000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d8000-7a1b2c3d9000 rw-p 00003000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7b3c4d5e6000-7b3c4d5e8000 r-xp 00000000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5e8000-7b3c4d5ea000 r--p 00001000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5ea000-7b3c4d5eb000 rw-p 00003000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7c5d6e7f8000-7c5d6e7fa000 r-xp 00000000 fd:01 3456789  /data/adb/modules/zygisk_lsposed/bin/zygiskd
7d8e9f0a0000-7d8e9f0a2000 r-xp 00000000 fd:01 4567890  /data/adb/modules/riru-core/riru.so
""".trimIndent()

        // 读取真实 maps 的前半段
        val realMapsFile = File("/proc/self/maps")
        val realContent = try {
            realMapsFile.readText()
        } catch (e: Exception) { "" }

        // 每行一个条目，插入伪造行到最后
        val all = realContent + "\n" + zygiskInjectLines
        tmp.writeText(all)
        return tmp
    }

    // ──────────────────────────────────────────────
    // 伪造 Process 类，返回预置输出
    // ──────────────────────────────────────────────
    inner class FakeProcess(private val output: String) : Process() {
        override fun getOutputStream(): java.io.OutputStream =
            object : java.io.OutputStream() {
                override fun write(b: Int) {}
            }
        override fun getInputStream(): java.io.InputStream =
            output.byteInputStream()
        override fun getErrorStream(): java.io.InputStream =
            "".byteInputStream()
        override fun waitFor(): Int {
            return 0
        }
        override fun exitValue(): Int = 0
        override fun destroy() {}
    }
}
