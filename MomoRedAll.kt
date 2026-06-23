package com.marvis.momoreball

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.io.FileInputStream

class MomoRedAll : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        const val TAG = "MomoRedAll"
        private fun log(msg: String) = XposedBridge.log("[$TAG] $msg")

        private var cachedProcessName: String? = null
        private fun currentProcessName(): String {
            cachedProcessName?.let { return it }
            val name = try {
                val fis = FileInputStream(File("/proc/self/cmdline"))
                val bytes = fis.readBytes()
                fis.close()
                String(bytes).trimEnd('\u0000')
            } catch (e: Exception) { "" }
            cachedProcessName = name
            return name
        }

        val FAKE_SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/system_ext/bin/su",
            "/product/bin/su", "/vendor/bin/su", "/data/local/tmp/su",
            "/sbin/su", "/system/sbin/su", "/system/bin/.ext/su",
            "/system/usr/we-need-root/su", "/system/xbin/mu", "/system/bin/failsafe/su",
        )

        val FAKE_MAGISK_PATHS = listOf(
            "/data/adb/magisk.db", "/data/adb/magisk/busybox", "/data/adb/magisk/magisk32",
            "/data/adb/magisk/magisk64", "/data/adb/magisk/magiskinit", "/data/adb/magisk/magiskpolicy",
            "/data/adb/magisk/resetprop", "/data/adb/magisk/su", "/data/adb/magisk/util_functions.sh",
            "/data/adb/modules", "/data/adb/magisk", "/sbin/magisk", "/cache/magisk.log",
            "/data/adb/.magisk", "/data/adb/magisk/rootdir", "/data/adb/magisk/magisk",
        )

        val FAKE_SUSPICIOUS_PATHS = listOf(
            "/data/adb/", "/data/adb/modules/", "/sbin/", "/system/app/Superuser/",
            "/system/app/SuperSU/", "/system/xbin/daemonsu", "/system/bin/.ext/",
            "/system/etc/init.d/", "/data/local/tmp/supersu/",
            "/data/data/eu.chainfire.supersu/", "/data/data/com.topjohnwu.magisk/",
            "/system/xbin/busybox", "/system/bin/busybox", "/data/data/com.noshufou.android.su/",
        )

        val FAKE_PROPS = mapOf(
            "ro.boot.verifiedbootstate" to "orange",
            "ro.boot.flash.locked" to "0",
            "ro.boot.vbmeta.device_state" to "unlocked",
            "ro.boot.veritymode" to "disabled",
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.build.type" to "userdebug",
            "ro.build.tags" to "test-keys",
            "persist.sys.usb.config" to "adb",
            "init.svc.adbd" to "running",
            "ro.build.selinux" to "0",
        )

        val FAKE_SHELL_RESPONSES = mapOf(
            "ps" to """USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME
root          1234     1  123456  56789 do_sys_poll         0 S zygisk64
root          1235     1  123456  56789 do_sys_poll         0 S zygisk32
root          5678     1  234567  89012 binder_thr          0 S magiskd
shell         9012     1   12345  34567 hrtimer_n           0 S su
root          1111     1  111111  22222 sigsuspen           0 S daemonsu
shell         2222  1111   33333  44444 pipe_wait           0 S sh
root           333   222   44444  55555 do_wait             0 S sh
""",
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
            "which su" to "/system/bin/su",
            "which magisk" to "/sbin/magisk",
        )
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        log("Zygote init")

        val sysPropClass = XposedHelpers.findClass("android.os.SystemProperties", null)

        XposedHelpers.findAndHookMethod(
            sysPropClass, "get", String::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val key = param.args[0] as String
                    if (!FAKE_PROPS.containsKey(key)) return
                    val procName = currentProcessName()
                    val target = (
                        procName == "io.github.vvb2060.mahoshojo" ||
                        procName.contains("duckduckgo") ||
                        procName == "io.github.vvb2060.keyattestation"
                    )
                    if (!target) return
                    param.result = FAKE_PROPS[key]
                }
            }
        )

        for (methodName in listOf("getBoolean", "getInt", "getLong")) {
            val paramTypes = when (methodName) {
                "getBoolean" -> arrayOf<Class<*>>(String::class.java, java.lang.Boolean.TYPE)
                "getInt"    -> arrayOf<Class<*>>(String::class.java, java.lang.Integer.TYPE)
                "getLong"   -> arrayOf<Class<*>>(String::class.java, java.lang.Long.TYPE)
                else -> arrayOf()
            }
            XposedHelpers.findAndHookMethod(
                sysPropClass, methodName, *paramTypes,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val key = param.args[0] as String
                        val procName = currentProcessName()
                        val target = (
                            procName == "io.github.vvb2060.mahoshojo" ||
                            procName.contains("duckduckgo") ||
                            procName == "io.github.vvb2060.keyattestation"
                        )
                        if (!target) return
                        if (!FAKE_PROPS.containsKey(key)) return
                        val fakeVal = FAKE_PROPS[key] ?: return
                        param.result = when (methodName) {
                            "getBoolean" -> fakeVal == "1" || fakeVal == "true"
                            "getInt"     -> fakeVal.toIntOrNull() ?: 1
                            "getLong"    -> fakeVal.toLongOrNull() ?: 1L
                            else -> param.result
                        }
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
        log("Hook into $pkg")

        val classLoader = lpparam.classLoader
        tryHookFileExists(classLoader)
        tryHookFileList(classLoader)
        tryHookRuntimeExec(classLoader)
        tryHookMapsRead(classLoader)
    }

    private fun tryHookFileExists(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                File::class.java, "exists",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val f = param.thisObject as File
                        val path = f.absolutePath
                        val alreadyTrue = (param.result as? Boolean) == true
                        if (alreadyTrue) return
                        val fake = path in FAKE_SU_PATHS
                            || path in FAKE_MAGISK_PATHS
                            || path in FAKE_SUSPICIOUS_PATHS
                        if (fake) param.result = true
                    }
                }
            )
            log("File.exists hooked")
        } catch (e: Exception) {
            log("File.exists hook failed: ${e.message}")
        }
    }

    private fun tryHookFileList(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                File::class.java, "listFiles",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val f = param.thisObject as File
                        val path = f.absolutePath
                        val existing = param.result as? Array<File> ?: return
                        when (path) {
                            "/data/adb/" -> param.result = existing + arrayOf(
                                File("/data/adb/magisk.db"), File("/data/adb/magisk"),
                                File("/data/adb/modules"), File("/data/adb/.magisk")
                            )
                            "/data/adb/modules/" -> param.result = existing + arrayOf(
                                File("/data/adb/modules/zygisk_lsposed"),
                                File("/data/adb/modules/shamiko"),
                                File("/data/adb/modules/hosts")
                            )
                            "/sbin/" -> param.result = existing + arrayOf(
                                File("/sbin/su"), File("/sbin/magisk")
                            )
                        }
                    }
                }
            )
            log("File.listFiles hooked")
        } catch (e: Exception) {
            log("File.listFiles hook failed: ${e.message}")
        }
    }

    private fun tryHookRuntimeExec(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                ProcessBuilder::class.java, "start",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val pb = param.thisObject as ProcessBuilder
                        val cmdList = try {
                            XposedHelpers.getObjectField(pb, "command") as? List<String>
                        } catch (e: Exception) { null } ?: return
                        if (cmdList.isEmpty()) return
                        val fullCmd = cmdList.joinToString(" ")
                        for ((prefix, fakeOutput) in FAKE_SHELL_RESPONSES) {
                            if (fullCmd.contains(prefix)) {
                                param.result = FakeProcess(fakeOutput)
                                return
                            }
                        }
                        if (fullCmd.contains("su") && !fullCmd.contains("supersu")) {
                            param.result = FakeProcess("uid=0(root) gid=0(root)\n")
                        }
                    }
                }
            )
            log("ProcessBuilder.start hooked")
        } catch (e: Exception) {
            log("ProcessBuilder.start hook failed: ${e.message}")
        }
    }

    private fun tryHookMapsRead(classLoader: ClassLoader) {
        try {
            XposedHelpers.findAndHookConstructor(
                "java.io.FileInputStream", classLoader, File::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val f = param.args[0] as? File ?: return
                        if (f.absolutePath == "/proc/self/maps") {
                            param.args[0] = createFakeMapsFile()
                        }
                    }
                }
            )
            log("FileInputStream /proc/self/maps hooked")
        } catch (e: Exception) {
            log("maps hook failed: ${e.message}")
        }
    }

    private fun createFakeMapsFile(): File {
        val tmp = File.createTempFile("fake_maps_", ".txt")
        tmp.deleteOnExit()
        val zygiskLines = """
7a1b2c3d4000-7a1b2c3d6000 r-xp 00000000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d6000-7a1b2c3d8000 r--p 00001000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d8000-7a1b2c3d9000 rw-p 00003000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7b3c4d5e6000-7b3c4d5e8000 r-xp 00000000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5e8000-7b3c4d5ea000 r--p 00001000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5ea000-7b3c4d5eb000 rw-p 00003000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
""".trimIndent()
        val realContent = try { File("/proc/self/maps").readText() } catch (e: Exception) { "" }
        tmp.writeText(realContent + "\n" + zygiskLines)
        return tmp
    }

    inner class FakeProcess(private val output: String) : Process() {
        override fun getOutputStream(): java.io.OutputStream =
            object : java.io.OutputStream() { override fun write(b: Int) {} }
        override fun getInputStream(): java.io.InputStream = output.byteInputStream()
        override fun getErrorStream(): java.io.InputStream = "".byteInputStream()
        override fun waitFor(): Int = 0
        override fun exitValue(): Int = 0
        override fun destroy() {}
        override fun pid(): Long = 12345L
        override fun info(): java.lang.ProcessHandle.Info =
            object : java.lang.ProcessHandle.Info {
                override fun command() = java.util.Optional.of("sh")
                override fun commandLine() = java.util.Optional.of("/system/bin/sh")
                override fun arguments() = java.util.Optional.of(emptyArray<String>())
                override fun startInstant() = java.util.Optional.of(java.time.Instant.EPOCH)
                override fun totalCpuDuration() = java.util.Optional.of(java.time.Duration.ZERO)
                override fun user() = java.util.Optional.of("root")
            }
    }
}
