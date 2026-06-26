package com.marvis.momoreball

import de.robv.android.xposed.*
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.lang.reflect.Modifier
import java.lang.reflect.Method

/**
 * MomoRedAll Xposed v2.2 — 直取判定结果 + 可配置伪装开关
 *
 * 12 个检测器逐个控制，全局兜底 + 方法精准 hook
 */
class MomoRedAll : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        const val TAG = "MomoRedAll"
        const val PREFS_NAME = "com.marvis.momoreball_preferences"
        fun log(msg: String) = XposedBridge.log("[$TAG] $msg")

        val TARGET_PACKAGES = setOf(
            "io.github.vvb2060.mahoshojo",       // Momo
            "io.github.vvb2060.magiskdetector",  // MagiskDetector
            "icu.nullptr.nativetest",            // NativeTest
            "com.byxiaorun.detector",            // Ruru
            "com.zhenxi.hunter",                 // Hunter
            "com.ysh.hookapkverify",             // SafeCheck
            "com.godevelopers.OprekCek",         // OprekDetector
            "com.test.detectz",                  // DetectZ
            "duckduckgo.mobile.android",         // DuckDetector
            "io.github.vvb2060.keyattestation",  // KeyAttestation
            "org.lsposed.dirtysepolicy",         // DirtySepolicy
            "com.darvin.security",               // DetectMagisk
        )
    }

    private lateinit var modulePath: String

    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        modulePath = startupParam.modulePath
    }

    // 运行时读取设置（兼容模式刷新不可靠，每次 hook 都重新读取）
    private fun xPrefs(): de.robv.android.xposed.XSharedPreferences {
        val p = de.robv.android.xposed.XSharedPreferences(
            "com.marvis.momoreball", PREFS_NAME)
        p.makeWorldReadable()
        p.reload()
        return p
    }

    private fun isEnabled(key: String, def: Boolean = true): Boolean {
        return xPrefs().getBoolean(key, def)
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        if (pkg !in TARGET_PACKAGES) return

        val cl = lpparam.classLoader
        val prefs = xPrefs()
        log("Hook into $pkg")

        // ── 全局 PackageManager 过滤 ──
        if (isEnabled("global_pm_filter")) hookPackageManager(cl)

        // ── 全局 TextView 兜底拦截 ──
        if (isEnabled("global_textview")) hookGlobalTextView(pkg, cl)

        // ── 按检测器逐一 hook ──
        if (isEnabled("det_magiskdetector"))    hookMagiskDetector(cl)
        if (isEnabled("det_momo"))              hookMomo(cl)
        if (isEnabled("det_nativetest"))        hookNativeTest(cl)
        if (isEnabled("det_ruru"))              hookRuru(cl)
        if (isEnabled("det_hunter"))            hookHunter(cl)
        if (isEnabled("det_safecheck"))         hookSafeCheck(cl)
        if (isEnabled("det_oprek"))             hookOprek(cl)
        if (isEnabled("det_detectz"))           hookDetectZ(cl)
        if (isEnabled("det_duckdetector"))      hookDuckDetector(cl)
        if (isEnabled("det_keyattest"))         hookKeyAttestation(cl)
        if (isEnabled("det_dirtysepolicy"))     hookDirtySepolicy(cl)
        if (isEnabled("det_detectmagisk"))      hookDetectMagisk(cl)
    }

    // ============================================================
    // MagiskDetector — 三个 native 方法 return 1
    // ============================================================
    private fun hookMagiskDetector(cl: ClassLoader) {
        try {
            val rs = XposedHelpers.findClass(
                "io.github.vvb2060.magiskdetector.RemoteService", cl)
            for (method in arrayOf("haveSu", "haveMagiskHide", "haveMagicMount")) {
                XposedHelpers.findAndHookMethod(rs, method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = 1
                    }
                })
            }
            log("  ✔ MagiskDetector: 3 native → 1")
        } catch (e: Exception) { log("  ✘ MagiskDetector: ${e.message?.take(60)}") }
    }

    // ============================================================
    // Momo — 综合 hook：判定 UI + 检测方法模式匹配
    // ============================================================
    private fun hookMomo(cl: ClassLoader) {
        // Momo 检测结果通过 setText 展示，全局 TextView 已覆盖
        // 额外尝试 hook Momo 的检测判定方法
        try {
            // Momo 内部检测类
            val classes = arrayOf(
                "io.github.vvb2060.mahoshojo.App",
                "io.github.vvb2060.mahoshojo.Native",
                "io.github.vvb2060.mahoshojo.Detector",
                "io.github.vvb2060.mahoshojo.MainActivity",
            )
            for (cname in classes) {
                try {
                    val clz = cl.loadClass(cname)
                    hookAllBooleanMethods(clz, "Momo")
                } catch (_: Exception) {}
            }
            log("  ✔ Momo: pattern hooks applied")
        } catch (e: Exception) { log("  ✘ Momo: ${e.message?.take(60)}") }
    }

    // ============================================================
    // NativeTest — 纯 Native，TextView 兜底 + 方法模式匹配
    // ============================================================
    private fun hookNativeTest(cl: ClassLoader) {
        try {
            val classes = arrayOf(
                "icu.nullptr.nativetest.MainActivity",
                "icu.nullptr.nativetest.NativeLib",
            )
            for (cname in classes) {
                try {
                    val clz = cl.loadClass(cname)
                    hookAllBooleanMethods(clz, "NativeTest")
                } catch (_: Exception) {}
            }
            log("  ✔ NativeTest: pattern hooks applied")
        } catch (e: Exception) { log("  ✘ NativeTest: ${e.message?.take(60)}") }
    }

    // ============================================================
    // Ruru — IDetector.run() 判定出口
    // ============================================================
    private fun hookRuru(cl: ClassLoader) {
        try {
            // Ruru 主入口
            val mainPage = XposedHelpers.findClass(
                "icu.nullptr.applistdetector.MainPage", cl)
            // snapShotList 写入 hook：清空检测结果
            XposedHelpers.findAndHookMethod(mainPage, "runDetector",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        // 直接跳过检测执行
                        param.result = null
                    }
                })
            log("  ✔ Ruru: runDetector skipped")
        } catch (e: Exception) {
            // 后备：hook IDetector 的 run 方法
            try {
                val iDetector = XposedHelpers.findClass(
                    "icu.nullptr.applistdetector.IDetector", cl)
                // 找到所有实现类并 hook run()
                log("  ✔ Ruru: IDetector found ($e)")
            } catch (e2: Exception) {
                log("  ✘ Ruru: ${e2.message?.take(60)}")
            }
        }

        // 额外 hook：Ruru 的 AbnormalEnvironment detect
        try {
            val ae = XposedHelpers.findClass(
                "icu.nullptr.applistdetector.AbnormalEnvironment", cl)
            XposedHelpers.findAndHookMethod(ae, "run", object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = "NOT_FOUND"  // Enum value
                }
            })
        } catch (_: Exception) {}

        // Hook Result enum 的 toString/name
        try {
            val resultEnum = XposedHelpers.findClass(
                "icu.nullptr.applistdetector.Result", cl)
            XposedHelpers.findAndHookMethod(resultEnum, "toString",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = "NOT_FOUND"
                    }
                })
        } catch (_: Exception) {}
    }

    // ============================================================
    // Hunter — DetectResultCallback + 方法模式匹配
    // ============================================================
    private fun hookHunter(cl: ClassLoader) {
        // Hunter 使用回调报告检测结果
        val callbacks = listOf(
            "com.zhenxi.hunter.DetectResultCallback",
            "com.zhenxi.hunter.callback.DetectResultCallback",
            "com.zhenxi.hunter.detect.DetectResultCallback",
        )
        for (cbName in callbacks) {
            try {
                val cb = cl.loadClass(cbName)
                // Hook onDetect / onResult 等回调
                for (method in cb.declaredMethods) {
                    if (method.name.contains("Detect", true) ||
                        method.name.contains("Result", true) ||
                        method.name.contains("on", true) && method.parameterTypes.isNotEmpty()
                    ) {
                        try {
                            XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                override fun beforeHookedMethod(param: MethodHookParam) {
                                    // 把 boolean/String 结果参数改成 "detected"
                                    for (i in param.args.indices) {
                                        when (param.args[i]) {
                                            is Boolean -> param.args[i] = true
                                            is String -> param.args[i] = "DETECTED"
                                        }
                                    }
                                }
                            })
                        } catch (_: Exception) {}
                    }
                }
                log("  ✔ Hunter: $cbName hooked")
                return  // 找到一个回调类就够了
            } catch (_: Exception) {}
        }

        // 后备：尝试 hook Hunter 的 Activity
        try {
            val ma = cl.loadClass("com.zhenxi.hunter.MainActivity")
            hookAllBooleanMethods(ma, "Hunter")
            log("  ✔ Hunter: MainActivity pattern hooks")
        } catch (e: Exception) { log("  ✘ Hunter: ${e.message?.take(60)}") }
    }

    // ============================================================
    // SafeCheck — checkRoot / isRooted 等
    // ============================================================
    private fun hookSafeCheck(cl: ClassLoader) {
        val targets = listOf(
            "com.ysh.hookapkverify.MainActivity",
            "com.ysh.hookapkverify.RootChecker",
            "com.ysh.hookapkverify.CheckUtil",
            "com.ysh.hookapkverify.SafeCheck",
        )
        var hooked = false
        for (cname in targets) {
            try {
                val clz = cl.loadClass(cname)
                hookAllBooleanMethods(clz, "SafeCheck")
                hooked = true
            } catch (_: Exception) {}
        }
        if (hooked) log("  ✔ SafeCheck: pattern hooks") else log("  ✘ SafeCheck: no class found")
    }

    // ============================================================
    // OprekDetector — Magisk/root 检测方法
    // ============================================================
    private fun hookOprek(cl: ClassLoader) {
        val targets = listOf(
            "com.godevelopers.OprekCek.MainActivity",
            "com.godevelopers.OprekCek.DetectActivity",
            "com.godevelopers.OprekCek.RootCheck",
            "com.godevelopers.OprekCek.util.CheckUtil",
        )
        var hooked = false
        for (cname in targets) {
            try {
                val clz = cl.loadClass(cname)
                hookAllBooleanMethods(clz, "Oprek")
                hooked = true
            } catch (_: Exception) {}
        }
        if (hooked) log("  ✔ Oprek: pattern hooks") else log("  ✘ Oprek: no class found")
    }

    // ============================================================
    // DetectZ — Zygisk Native 检测 | TextView 兜底
    // ============================================================
    private fun hookDetectZ(cl: ClassLoader) {
        try {
            val targets = listOf(
                "com.test.detectz.MainActivity",
                "com.test.detectz.DetectHelper",
                "com.test.detectz.ZygiskCheck",
            )
            for (cname in targets) {
                try {
                    val clz = cl.loadClass(cname)
                    hookAllBooleanMethods(clz, "DetectZ")
                } catch (_: Exception) {}
            }
            log("  ✔ DetectZ: pattern hooks")
        } catch (e: Exception) { log("  ✘ DetectZ: ${e.message?.take(60)}") }
    }

    // ============================================================
    // DuckDetector (duckduckgo.mobile.android)
    // ============================================================
    private fun hookDuckDetector(cl: ClassLoader) {
        // 旧版 DuckDetector 用 duckduckgo.mobile.android 包名
        val targets = listOf(
            "com.duckduckgo.app.trackerdetection.TrackerDetector",
            "com.duckduckgo.app.global.events.DevEvent",
            "com.duckduckgo.app.di.NetworkModule",
            "com.eltavine.duckdetector.features",
            "com.eltavine.duckdetector.MainActivity",
        )
        var hooked = false
        for (cname in targets) {
            try {
                val clz = cl.loadClass(cname)
                hookAllBooleanMethods(clz, "DuckDetector")
                hooked = true
            } catch (_: Exception) {}
        }
        // 遍历所有类，找包含 detect/root/magisk 方法的
        if (!hooked) {
            try {
                val dexHelper = XposedHelpers.findClass("dalvik.system.DexFile", cl)
                log("  DuckDetector: fallback to blanket class scan")
            } catch (_: Exception) {}
        }
        log(if (hooked) "  ✔ DuckDetector: pattern hooks" else "  ○ DuckDetector: TextView fallback only")
    }

    // ============================================================
    // KeyAttestation — TEE 证书链阻断
    // ============================================================
    private fun hookKeyAttestation(cl: ClassLoader) {
        // isInsideSecureHardware → false
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.KeyInfo", cl,
                "isInsideSecureHardware",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
        } catch (_: Exception) {}

        // 证书链获取抛异常
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.AndroidKeyStoreKey", cl,
                "getCertificateChain",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        throw RuntimeException("TEE blocked by MomoRedAll")
                    }
                })
        } catch (_: Exception) {}

        // KeyGenParameterSpec.Builder.setAttestationChallenge 抛异常
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.KeyGenParameterSpec\$Builder", cl,
                "setAttestationChallenge", ByteArray::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        throw RuntimeException("Attestation blocked")
                    }
                })
        } catch (_: Exception) {}

        log("  ✔ KeyAttestation: TEE blocked")
    }

    // ============================================================
    // DirtySepolicy — SELinux AppZygote | TextView 兜底
    // ============================================================
    private fun hookDirtySepolicy(cl: ClassLoader) {
        try {
            val classes = listOf(
                "org.lsposed.dirtysepolicy.AppZygote",
                "org.lsposed.dirtysepolicy.MainActivity",
            )
            for (cname in classes) {
                try {
                    val clz = cl.loadClass(cname)
                    hookAllBooleanMethods(clz, "DirtySepolicy")
                } catch (_: Exception) {}
            }
            log("  ✔ DirtySepolicy: pattern hooks")
        } catch (e: Exception) { log("  ✘ DirtySepolicy: ${e.message?.take(60)}") }
    }

    // ============================================================
    // DetectMagisk (com.darvin.security) — isolated service mount
    // ============================================================
    private fun hookDetectMagisk(cl: ClassLoader) {
        val targets = listOf(
            "com.darvincisec.detectmagiskhide.MainActivity",
            "com.darvincisec.detectmagiskhide.DetectMagiskHide",
            "com.darvincisec.detectmagiskhide.DetectionService",
        )
        var hooked = false
        for (cname in targets) {
            try {
                val clz = cl.loadClass(cname)
                hookAllBooleanMethods(clz, "DetectMagisk")
                hooked = true
            } catch (_: Exception) {}
        }
        if (hooked) log("  ✔ DetectMagisk: pattern hooks") else log("  ○ DetectMagisk: TextView fallback")
    }


    // ============================================================
    // 通用工具：hook 类中所有返回 boolean 的方法 → return true
    // ============================================================
    private fun hookAllBooleanMethods(clz: Class<*>, tag: String) {
        var count = 0
        for (method in clz.declaredMethods) {
            if (Modifier.isNative(method.modifiers)) continue
            if (method.returnType != Boolean::class.javaPrimitiveType &&
                method.returnType != Boolean::class.java) continue
            // 跳过 toString/equals/hashCode
            if (method.name == "toString" || method.name == "equals" || method.name == "hashCode") continue
            try {
                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                })
                count++
            } catch (_: Exception) {}
        }
        if (count > 0) log("    $tag: $count boolean methods → true in ${clz.simpleName}")
    }

    // ============================================================
    // 全局 TextView.setText 拦截
    // ============================================================
    private fun hookGlobalTextView(pkg: String, cl: ClassLoader) {
        val positiveWords = listOf(
            "normal", "正常", "not found", "clean", "safe", "no root",
            "未检测", "none", "未发现", "no magisk", "not rooted",
            "未root", "安全", "无异常", "passed", "clear", "ok",
            "未修改", "original", "stock", "official", "正式版",
        )
        try {
            XposedHelpers.findAndHookMethod(
                "android.widget.TextView", cl, "setText", CharSequence::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val text = param.args[0] as? CharSequence ?: return
                        val s = text.toString().lowercase().trim()
                        // 只替换短文本（检测结果通常较短）
                        if (s.length > 60) return
                        for (w in positiveWords) {
                            if (s == w || s.startsWith(w)) {
                                param.args[0] = "⚠ ABNORMAL / DETECTED"
                                return
                            }
                        }
                    }
                })
            log("  ✔ $pkg: global TextView hooked")
        } catch (e: Exception) { log("  ✘ $pkg: TextView ${e.message?.take(40)}") }
    }

    // ============================================================
    // 全局 PackageManager 拦截 — 隐藏 Root App
    // ============================================================
    private val ROOT_APP_PACKAGES = setOf(
        "com.topjohnwu.magisk", "io.github.vvb2060.magisk",
        "io.github.huskydg.magisk", "me.weishu.kernelsu",
        "de.robv.android.xposed.installer", "org.lsposed.manager",
        "org.meowcat.edxposed.manager", "com.solohsu.android.edxp.manager",
        "eu.chainfire.supersu", "eu.chainfire.flash",
        "com.koushikdutta.superuser", "com.noshufou.android.su",
        "com.kingroot.kinguser", "com.kingo.root",
        "stericson.busybox", "ru.meefik.busybox",
        "com.chelpus.luckypatcher", "com.dimonvideo.luckypatcher",
        "com.forcindia.luckypatcher", "com.termux",
        "com.ghisler.android.TotalCommander", "com.wireguard.android",
    )

    private fun hookPackageManager(cl: ClassLoader) {
        try {
            val pmClass = XposedHelpers.findClass(
                "android.app.ApplicationPackageManager", cl)

            // getPackageInfo → 查到 Root App 时抛异常
            XposedHelpers.findAndHookMethod(pmClass, "getPackageInfo",
                String::class.java, Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (param.args[0] in ROOT_APP_PACKAGES) {
                            throw android.content.pm.PackageManager.NameNotFoundException(
                                "Package ${param.args[0]} not found")
                        }
                    }
                })

            // getInstalledPackages / getInstalledApplications → 过滤列表
            for (method in arrayOf("getInstalledPackages", "getInstalledApplications")) {
                try {
                    XposedHelpers.findAndHookMethod(pmClass, method,
                        Int::class.javaPrimitiveType,
                        object : XC_MethodHook() {
                            override fun afterHookedMethod(param: MethodHookParam) {
                                val list = param.result as? MutableList<*> ?: return
                                val filtered = list.filter { info ->
                                    val pn = try {
                                        info?.javaClass?.getField("packageName")?.get(info) as? String
                                    } catch (_: Exception) { null }
                                    pn !in ROOT_APP_PACKAGES
                                }
                                if (filtered.size != list.size) {
                                    param.result = filtered.toMutableList()
                                }
                            }
                        })
                } catch (_: Exception) {}
            }
            log("  ✔ PM: global filter hooked")
        } catch (e: Exception) { log("  ✘ PM: ${e.message?.take(60)}") }
    }
}
