package com.marvis.momoreball

import de.robv.android.xposed.*
import de.robv.android.xposed.callbacks.XC_LoadPackage

/**
 * MomoRedAll Xposed v2.3 — Hook All Detection Functions Directly
 * ==============================================================
 * 架构反转：不再依赖模糊的全局 boolean 方法模式匹配或 TextView 兜底，
 * 改为按检测器精确 hook 每个判定方法的返回值。
 *
 * 覆盖 17 个检测器，每个检测器至少 hook 一个关键判定出口。
 */
class MomoRedAll : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        const val TAG = "MomoRedAll-v2.3"
        fun log(msg: String) = XposedBridge.log("[$TAG] $msg")

        val TARGET_PACKAGES = setOf(
            "io.github.vvb2060.mahoshojo",       // Momo
            "io.github.vvb2060.magiskdetector",  // Magisk Detector
            "icu.nullptr.nativetest",            // NativeTest
            "com.darvin.security",               // DetectMagisk
            "com.scottyab.rootbeer",             // Rootbeer
            "com.godevelopers.OprekCek",         // OprekCek
            "com.byxiaorun.detector",            // Ruru
            "com.zhenxi.hunter",                 // Hunter
            "com.ysh.hookapkverify",             // SafeCheck
            "me.garfieldhan.hiapatch",           // APTest
            "com.kikyps.crackme",                // CrackME
            "com.test.detectz",                  // DetectZygisk
            "org.lsposed.dirtysepolicy",         // DirtySepolicy
            "com.eltavine.duckdetector",         // DuckDetector
            "com.reveny.nativecheck",            // Native Root Detector
            "me.garfieldhan.holmes",             // Holmes
            "org.matrix.demo",                   // JingMatrix Demo
        )
    }

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {}

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg !in TARGET_PACKAGES) return

        val cl = lpparam.classLoader
        log("Hook into $pkg")

        when (pkg) {
            "com.scottyab.rootbeer"             -> hookRootbeer(cl)
            "org.lsposed.dirtysepolicy"         -> hookDirtySepolicy(cl)
            "com.ysh.hookapkverify"             -> hookSafeCheck(cl)
            "me.garfieldhan.holmes"             -> hookHolmes(cl)
            "com.darvin.security"               -> hookDetectMagisk(cl)
            "com.kikyps.crackme"                -> hookCrackME(cl)
            "io.github.vvb2060.magiskdetector"  -> hookMagiskDetector(cl)
            "com.zhenxi.hunter"                 -> hookHunter(cl)
            "com.reveny.nativecheck"            -> hookNativeRootDetector(cl)
            "com.byxiaorun.detector"            -> hookRuru(cl)
            "io.github.vvb2060.mahoshojo"       -> hookMomo(cl)
            "icu.nullptr.nativetest"            -> hookNativeTest(cl)
            "com.godevelopers.OprekCek"         -> hookOprek(cl)
            "com.test.detectz"                  -> hookDetectZygisk(cl)
            "com.eltavine.duckdetector"         -> hookDuckDetector(cl)
            "me.garfieldhan.hiapatch"           -> hookAPTest(cl)
            "org.matrix.demo"                   -> hookJingMatrix(cl)
        }
    }

    // ============================================================
    // Rootbeer — isRooted() → false
    // ============================================================
    private fun hookRootbeer(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.scottyab.rootbeer.RootBeer", cl, "isRooted",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
            // 同时覆盖带参数的变体
            XposedHelpers.findAndHookMethod(
                "com.scottyab.rootbeer.RootBeer", cl, "isRootedWithBusyBoxCheck",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
            log("  v Rootbeer: isRooted -> false")
        } catch (e: Exception) { log("  x Rootbeer: ${e.message?.take(80)}") }
    }

    // ============================================================
    // DirtySepolicy — doCheck() → "DETECTED"
    // ============================================================
    private fun hookDirtySepolicy(cl: ClassLoader) {
        try {
            val appZygote = XposedHelpers.findClass(
                "org.lsposed.dirtysepolicy.AppZygote", cl)
            XposedHelpers.findAndHookMethod(appZygote, "doCheck",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = "DETECTED: Magisk/KSU/Xposed/ZygiskNext"
                    }
                })
            log("  v DirtySepolicy: doCheck -> DETECTED")
        } catch (e: Exception) { log("  x DirtySepolicy: ${e.message?.take(80)}") }
    }

    // ============================================================
    // SafeCheck — checkSU / checkMagiskHide / checkZygisk / checkRiru → 1
    // ============================================================
    private fun hookSafeCheck(cl: ClassLoader) {
        try {
            val ma = XposedHelpers.findClass(
                "com.ysh.hookapkverify.MainActivity", cl)
            for (method in arrayOf("checkSU", "checkMagiskHide", "checkSystemFile")) {
                try {
                    XposedHelpers.findAndHookMethod(ma, method,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = 1
                            }
                        })
                } catch (_: Exception) {}
            }
            log("  v SafeCheck: checkSU/checkMagiskHide -> 1")
        } catch (e: Exception) {
            log("  x SafeCheck MainActivity: ${e.message?.take(60)}")
        }

        // CheckZygisk
        try {
            val cz = XposedHelpers.findClass(
                "com.ysh.hookapkverify.CheckZygisk", cl)
            XposedHelpers.findAndHookMethod(cz, "checkZygisk",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = "NOT_DETECTED"
                    }
                })
            XposedHelpers.findAndHookMethod(cz, "checkRiru",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
            log("  v SafeCheck: Zygisk/Riru hooked")
        } catch (_: Exception) {}
    }

    // ============================================================
    // Holmes — preload() / test() → 异常
    // ============================================================
    private fun hookHolmes(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "me.garfieldhan.holmes.HolmesZygotePreload", cl, "preload",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = -1 // 预加载失败
                    }
                })
            log("  v Holmes: preload -> -1")
        } catch (e: Exception) { log("  x Holmes preload: ${e.message?.take(60)}") }

        try {
            XposedHelpers.findAndHookMethod(
                "me.garfieldhan.holmes.MainActivity", cl, "test",
                android.content.Context::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = arrayOf("CLEAN", "NO_ROOT", "PASSED")
                    }
                })
            log("  v Holmes: test -> CLEAN array")
        } catch (e: Exception) { log("  x Holmes test: ${e.message?.take(60)}") }
    }

    // ============================================================
    // DetectMagisk — isMagiskPresent → false
    // ============================================================
    private fun hookDetectMagisk(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.darvin.security.Native", cl, "isMagiskPresentNative",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
            log("  v DetectMagisk: isMagiskPresentNative -> false")
        } catch (e: Exception) { log("  x DetectMagisk: ${e.message?.take(80)}") }

        // IsolatedService 透传
        try {
            val svc = XposedHelpers.findClass(
                "com.darvin.security.IsolatedService\$1", cl)
            XposedHelpers.findAndHookMethod(svc, "isMagiskPresent",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
        } catch (_: Exception) {}
    }

    // ============================================================
    // CrackME — invokeIsRoot() → 0
    // ============================================================
    private fun hookCrackME(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.kikyps.crackme.MainActivity", cl, "invokeIsRoot",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = 0
                    }
                })
            log("  v CrackME: invokeIsRoot -> 0")
        } catch (e: Exception) { log("  x CrackME: ${e.message?.take(80)}") }
    }

    // ============================================================
    // MagiskDetector — haveSu/haveMagiskHide/haveMagicMount → 1
    // ============================================================
    private fun hookMagiskDetector(cl: ClassLoader) {
        try {
            val rs = XposedHelpers.findClass(
                "io.github.vvb2060.magiskdetector.RemoteService", cl)
            for (method in arrayOf("haveSu", "haveMagiskHide", "haveMagicMount")) {
                XposedHelpers.findAndHookMethod(rs, method,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            param.result = 1
                        }
                    })
            }
            log("  v MagiskDetector: 3 native -> 1")
        } catch (e: Exception) { log("  x MagiskDetector: ${e.message?.take(80)}") }
    }

    // ============================================================
    // Hunter — checkRootFromAVCLog / checkZygisk / checkRiskFile → 异常
    // ============================================================
    private fun hookHunter(cl: ClassLoader) {
        try {
            val ne = XposedHelpers.findClass(
                "com.zhenxi.hunter.NativeEngine", cl)
            for (method in arrayOf("checkRootFromAVCLog", "checkZygisk", "checkRiskFile")) {
                try {
                    XposedHelpers.findAndHookMethod(ne, method,
                        object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                // ListItemBean — 构造一个 clean result
                                param.result = null
                            }
                        })
                } catch (_: Exception) {}
            }
            log("  v Hunter: checkRootFromAVCLog/checkZygisk/checkRiskFile -> null")
        } catch (e: Exception) { log("  x Hunter: ${e.message?.take(80)}") }
    }

    // ============================================================
    // Native Root Detector — getDetections → clean array
    // ============================================================
    private fun hookNativeRootDetector(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "com.reveny.nativecheck.app.Native", cl, "getDetections",
                android.content.Context::class.java,
                android.content.pm.PackageManager::class.java,
                Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = emptyArray<Any>()
                    }
                })
            log("  v NativeRootDetector: getDetections -> empty")
        } catch (e: Exception) { log("  x NativeRootDetector: ${e.message?.take(80)}") }
    }

    // ============================================================
    // Ruru — runDetector 跳过 + AbnormalEnvironment.detect → NOT_FOUND
    // ============================================================
    private fun hookRuru(cl: ClassLoader) {
        try {
            val mp = XposedHelpers.findClass(
                "icu.nullptr.applistdetector.MainPage", cl)
            XposedHelpers.findAndHookMethod(mp, "runDetector",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = null
                    }
                })
            log("  v Ruru: runDetector skipped")
        } catch (e: Exception) { log("  x Ruru MainPage: ${e.message?.take(60)}") }

        try {
            val ae = XposedHelpers.findClass(
                "icu.nullptr.applistdetector.AbnormalEnvironment", cl)
            XposedHelpers.findAndHookMethod(ae, "run",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = "NOT_FOUND"
                    }
                })
        } catch (_: Exception) {}
    }

    // ============================================================
    // Momo — pattern boolean hooks
    // ============================================================
    private fun hookMomo(cl: ClassLoader) {
        val classes = arrayOf(
            "io.github.vvb2060.mahoshojo.App",
            "io.github.vvb2060.mahoshojo.Native",
            "io.github.vvb2060.mahoshojo.Detector",
            "io.github.vvb2060.mahoshojo.MainActivity",
        )
        for (cname in classes) {
            try { hookAllBooleanMethods(cl.loadClass(cname), "Momo") } catch (_: Exception) {}
        }
    }

    // ============================================================
    // NativeTest — pattern boolean hooks
    // ============================================================
    private fun hookNativeTest(cl: ClassLoader) {
        val classes = arrayOf(
            "icu.nullptr.nativetest.MainActivity",
            "icu.nullptr.nativetest.NativeLib",
        )
        for (cname in classes) {
            try { hookAllBooleanMethods(cl.loadClass(cname), "NativeTest") } catch (_: Exception) {}
        }
    }

    // ============================================================
    // OprekCek — pattern boolean hooks
    // ============================================================
    private fun hookOprek(cl: ClassLoader) {
        val targets = listOf(
            "com.godevelopers.OprekCek.MainActivity",
            "com.godevelopers.OprekCek.DetectActivity",
            "com.godevelopers.OprekCek.RootCheck",
        )
        for (cname in targets) {
            try { hookAllBooleanMethods(cl.loadClass(cname), "Oprek") } catch (_: Exception) {}
        }
    }

    // ============================================================
    // DetectZygisk — detectZygisk → false pattern
    // ============================================================
    private fun hookDetectZygisk(cl: ClassLoader) {
        try {
            val ma = cl.loadClass("com.test.detectz.MainActivity")
            hookAllBooleanMethods(ma, "DetectZygisk")
        } catch (_: Exception) {}
    }

    // ============================================================
    // DuckDetector — nativeCollectSnapshot → empty
    // ============================================================
    private fun hookDuckDetector(cl: ClassLoader) {
        val prefixes = listOf(
            "com.eltavine.duckdetector",
        )
        try {
            // 遍历已加载的类找 nativeCollectSnapshot 方法
            for (clz in listOf(
                try { cl.loadClass("com.eltavine.duckdetector.features.mount.MountNativeBridge") } catch (_: Exception) { null },
                try { cl.loadClass("com.eltavine.duckdetector.features.zygisk.ZygiskNativeBridge") } catch (_: Exception) { null },
                try { cl.loadClass("com.eltavine.duckdetector.features.nativeroot.NativeRootNativeBridge") } catch (_: Exception) { null },
                try { cl.loadClass("com.eltavine.duckdetector.features.selinux.SelinuxContextValidityBridge") } catch (_: Exception) { null },
                try { cl.loadClass("com.eltavine.duckdetector.features.systemproperties.SystemPropertiesNativeBridge") } catch (_: Exception) { null },
                try { cl.loadClass("com.eltavine.duckdetector.features.memory.MemoryNativeBridge") } catch (_: Exception) { null },
            )) {
                if (clz == null) continue
                for (method in clz.declaredMethods) {
                    if (method.name.startsWith("nativeCollect") || method.name.startsWith("native")) {
                        if (method.returnType == String::class.java) {
                            try {
                                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                    override fun beforeHookedMethod(param: MethodHookParam) {
                                        param.result = "{}"
                                    }
                                })
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
            log("  v DuckDetector: native bridges hooked")
        } catch (e: Exception) { log("  x DuckDetector: ${e.message?.take(80)}") }
    }

    // ============================================================
    // APTest (me.garfieldhan.hiapatch)
    // ============================================================
    private fun hookAPTest(cl: ClassLoader) {
        try {
            val targets = listOf(
                "me.garfieldhan.hiapatch.MainActivity",
                "me.garfieldhan.hiapatch.Detector",
            )
            for (cname in targets) {
                try { hookAllBooleanMethods(cl.loadClass(cname), "APTest") } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    // ============================================================
    // JingMatrix Demo — DetectModules / DetectInjection
    // ============================================================
    private fun hookJingMatrix(cl: ClassLoader) {
        try {
            val ma = XposedHelpers.findClass(
                "org.matrix.demo.MainActivity", cl)
            // stringFromJNI 等 native 入口
            for (method in ma.declaredMethods) {
                if (method.returnType == String::class.java && method.parameterTypes.isEmpty()) {
                    try {
                        XposedBridge.hookMethod(method, object : XC_MethodHook() {
                            override fun beforeHookedMethod(param: MethodHookParam) {
                                param.result = "NO_INJECTION"
                            }
                        })
                    } catch (_: Exception) {}
                }
            }
            log("  v JingMatrix: string methods -> NO_INJECTION")
        } catch (e: Exception) { log("  x JingMatrix: ${e.message?.take(80)}") }
    }

    // ============================================================
    // 通用工具：hook 类中所有返回 boolean 的方法 → return false
    // ============================================================
    private fun hookAllBooleanMethods(clz: Class<*>, tag: String) {
        var count = 0
        for (method in clz.declaredMethods) {
            if (java.lang.reflect.Modifier.isNative(method.modifiers)) continue
            if (method.returnType != Boolean::class.javaPrimitiveType &&
                method.returnType != Boolean::class.java) continue
            if (method.name == "toString" || method.name == "equals" || method.name == "hashCode") continue
            try {
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
                count++
            } catch (_: Exception) {}
        }
        if (count > 0) log("    $tag: $count boolean -> false in ${clz.simpleName}")
    }
}
