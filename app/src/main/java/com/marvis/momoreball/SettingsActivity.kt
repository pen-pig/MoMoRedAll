package com.marvis.momoreball

import android.app.Activity
import android.os.Bundle
import android.widget.*
import android.graphics.Color
import android.view.Gravity
import android.view.ViewGroup
import android.content.SharedPreferences
import android.preference.PreferenceManager

/**
 * MomoRedAll v2.2 UI — 逐检测器伪装控制面板
 */
class SettingsActivity : Activity() {

    private lateinit var prefs: SharedPreferences

    data class DetectorEntry(
        val pkg: String,
        val label: String,
        val desc: String,
        val prefKey: String
    )

    private val detectors = listOf(
        DetectorEntry("io.github.vvb2060.magiskdetector",  "MagiskDetector",  "haveSu/MagiskHide/MagicMount → return 1", "det_magiskdetector"),
        DetectorEntry("io.github.vvb2060.mahoshojo",       "Momo",            "Native 检测器 | TextView 兜底替换",        "det_momo"),
        DetectorEntry("icu.nullptr.nativetest",            "NativeTest",      "Native 检测器 | TextView 兜底替换",        "det_nativetest"),
        DetectorEntry("com.byxiaorun.detector",            "Ruru",            "IDetector.run() + snapShotList 拦截",     "det_ruru"),
        DetectorEntry("com.zhenxi.hunter",                 "Hunter",          "DetectResultCallback 方法拦截",            "det_hunter"),
        DetectorEntry("com.ysh.hookapkverify",             "SafeCheck",       "签名/Root检测方法拦截 + TextView 兜底",    "det_safecheck"),
        DetectorEntry("com.godevelopers.OprekCek",         "OprekDetector",   "Magisk/root检测方法拦截",                  "det_oprek"),
        DetectorEntry("com.test.detectz",                  "DetectZ",         "Zygisk Native检测 | TextView 兜底",        "det_detectz"),
        DetectorEntry("duckduckgo.mobile.android",         "DuckDetector",    "伪装 DuckDuckGo 的检测器",                 "det_duckdetector"),
        DetectorEntry("io.github.vvb2060.keyattestation",  "KeyAttestation",  "TEE 证书链阻断",                           "det_keyattest"),
        DetectorEntry("org.lsposed.dirtysepolicy",         "DirtySepolicy",   "SELinux AppZygote 检测 | TextView 兜底",   "det_dirtysepolicy"),
        DetectorEntry("com.darvin.security",               "DetectMagisk",    "isolated service mount 检测",              "det_detectmagisk"),
    )

    // 全局开关
    private val globalKeys = listOf(
        "global_pm_filter"    to "PackageManager 过滤 Root App",
        "global_textview"     to "全局 TextView 拦截 (兜底)",
        "global_signature"    to "签名伪装 (返回原始签名)",
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        setTitle("MomoRedAll v2.2")

        val scroll = ScrollView(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }

        // 标题
        root.addView(TextView(this).apply {
            text = "MomoRedAll v2.2"
            textSize = 24f
            setTextColor(Color.parseColor("#E0E0E0"))
            setPadding(0, 0, 0, 8)
        })
        root.addView(TextView(this).apply {
            text = "逐检测器伪装开关 | 重启目标 App 生效"
            textSize = 14f
            setTextColor(Color.parseColor("#888888"))
            setPadding(0, 0, 0, 24)
        })

        // 全局开关
        root.addView(sectionLabel("──── 全局控制 ────"))
        globalKeys.forEach { (key, label) ->
            root.addView(makeSwitch(key, label, prefs.getBoolean(key, true)))
        }

        // 检测器开关
        root.addView(sectionLabel("──── 检测器伪装 ────"))
        detectors.forEach { det ->
            val checked = prefs.getBoolean(det.prefKey, true)
            root.addView(makeSwitch(det.prefKey, det.label, checked, det.desc))
        }

        // 一键全开/全关
        root.addView(sectionLabel("──── 快捷操作 ────"))
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 0)
        }
        btnRow.addView(makeBtn("全开", Color.parseColor("#4CAF50")) { setAll(true) })
        btnRow.addView(makeBtn("全关", Color.parseColor("#F44336")) { setAll(false) })
        btnRow.addView(makeBtn("默认", Color.parseColor("#2196F3")) { setAll(true) })
        root.addView(btnRow)

        scroll.addView(root)
        setContentView(scroll)
    }

    private fun sectionLabel(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 13f
        setTextColor(Color.parseColor("#666666"))
        setPadding(0, 32, 0, 8)
    }

    private fun makeSwitch(key: String, label: String, checked: Boolean, desc: String? = null): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 6, 0, 6)
        }
        val topRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val text = TextView(this).apply {
            this.text = label
            textSize = 16f
            setTextColor(Color.parseColor("#CCCCCC"))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val sw = Switch(this).apply {
            isChecked = checked
            setOnCheckedChangeListener { _, v ->
                prefs.edit().putBoolean(key, v).apply()
            }
        }
        topRow.addView(text)
        topRow.addView(sw)
        row.addView(topRow)
        if (desc != null) {
            row.addView(TextView(this).apply {
                this.text = "  $desc"
                textSize = 11f
                setTextColor(Color.parseColor("#666666"))
            })
        }
        return row
    }

    private fun makeBtn(text: String, bgColor: Int, action: () -> Unit): Button =
        Button(this).apply {
            this.text = text
            setBackgroundColor(bgColor)
            setTextColor(Color.WHITE)
            textSize = 13f
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(8, 0, 8, 0)
            }
            setOnClickListener { action() }
        }

    private fun setAll(on: Boolean) {
        prefs.edit().apply {
            globalKeys.forEach { putBoolean(it.first, on) }
            detectors.forEach { putBoolean(it.prefKey, on) }
        }.apply()
        recreate()
    }
}
