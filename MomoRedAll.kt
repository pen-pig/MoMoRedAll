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

        val FAKE_PROPS = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0",
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
                    param.result = FAKE_PROPS[key]
                }
            }
        )
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        log("Loaded: ${lpparam.packageName}")
    }
}
