package com.marvis.momoreball

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.widget.CompoundButton
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import de.robv.android.xposed.XposedBridge

class SettingsActivity : android.app.Activity() {

    companion object {
        const val PREFS_NAME = "momo_red_all_prefs"
        const val KEY_MAGISK_DETECTOR = "magisk_detector"
        const val KEY_MOMO = "momo"
        const val KEY_NATIVE_TEST = "native_test"
        const val KEY_RURU = "ruru"
        const val KEY_HUNTER = "hunter"
        const val KEY_SAFE_CHECK = "safe_check"
        const val KEY_OPREK = "oprek"
        const val KEY_DETECTZ = "detectz"
        const val KEY_DUCK_DETECTOR = "duck_detector"
        const val KEY_KEY_ATTESTATION = "key_attestation"
        const val KEY_DIRTY_SEPOLICY = "dirty_sepolicy"
        const val KEY_DETECT_MAGISK = "detect_magisk"

        fun isEnabled(ctx: Context, key: String, default: Boolean = true): Boolean {
            return ctx.getSharedPreferences(PREFS_NAME, Context.MODE_WORLD_READABLE)
                .getBoolean(key, default)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_WORLD_READABLE)

        val scrollView = ScrollView(this)
        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.VERTICAL
        layout.setPadding(40, 40, 40, 40)

        val title = TextView(this)
        title.text = "MomoRedAll v2.2 - 检测器开关"
        title.textSize = 20f
        layout.addView(title)

        val detectors = listOf(
            "Magisk Detector" to KEY_MAGISK_DETECTOR,
            "Momo" to KEY_MOMO,
            "Native Test" to KEY_NATIVE_TEST,
            "Ruru" to KEY_RURU,
            "Hunter" to KEY_HUNTER,
            "Safe Check" to KEY_SAFE_CHECK,
            "Oprek" to KEY_OPREK,
            "DetectZ" to KEY_DETECTZ,
            "Duck Detector" to KEY_DUCK_DETECTOR,
            "Key Attestation" to KEY_KEY_ATTESTATION,
            "Dirty Sepolicy" to KEY_DIRTY_SEPOLICY,
            "Detect Magisk" to KEY_DETECT_MAGISK
        )

        for ((label, key) in detectors) {
            val row = LinearLayout(this)
            row.orientation = LinearLayout.HORIZONTAL

            val text = TextView(this)
            text.text = label
            text.textSize = 16f
            text.layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)

            val switch = Switch(this)
            switch.isChecked = prefs.getBoolean(key, true)
            switch.setOnCheckedChangeListener { _, isChecked ->
                prefs.edit().putBoolean(key, isChecked).apply()
            }

            row.addView(text)
            row.addView(switch)
            layout.addView(row)
        }

        scrollView.addView(layout)
        setContentView(scrollView)
    }
}
