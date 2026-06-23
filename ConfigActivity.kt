package com.marvis.momoreball

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.card.MaterialCardView
import java.io.File

class ConfigActivity : AppCompatActivity() {

    companion object {
        private const val PREFS_NAME = "momoreball_config"
        private const val CONFIG_OUTPUT_PATH = "/data/adb/modules/MomoRedAll-Native/config.json"

        private val TARGET_KEYS = arrayOf(
            "target_momo", "target_native_test", "target_applist_detector",
            "target_ruru", "target_detect_magisk_hide", "target_momo_strong",
            "target_safetynet", "target_safetynet_playstore", "target_cat_and_mouse",
            "target_android_cts", "target_rootbeer", "target_rootbeer_fresh"
        )

        private val TARGET_LABELS = arrayOf(
            "Momo", "Native Test", "Applist Detector", "Ruru",
            "Detect Magisk Hide", "Momo Strong", "SafetyNet",
            "SafetyNet PlayStore", "Cat and Mouse", "Android CTS",
            "RootBeer", "RootBeer Fresh"
        )

        private val HOOK_KEYS = arrayOf(
            "hook_fopen", "hook_open", "hook_stat", "hook_access",
            "hook_opendir", "hook_popen_system", "hook_readlink", "hook_ptrace",
            "hook_getenv", "hook_property", "hook_proc", "hook_mounts", "hook_extra"
        )

        private val HOOK_LABELS = arrayOf(
            "fopen", "open", "stat", "access",
            "opendir", "popen / system", "readlink", "ptrace",
            "getenv", "property", "/proc 拦截", "/proc/mounts", "额外 Hook"
        )
    }

    private lateinit var prefs: SharedPreferences
    private val targetSwitches = mutableListOf<Switch>()
    private val hookSwitches = mutableListOf<Switch>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

        val scrollView = ScrollView(this).apply {
            setBackgroundColor(0xFF121212.toInt())
        }

        val rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }

        // Title
        rootLayout.addView(TextView(this).apply {
            text = "MoMoRedAll 配置"
            textSize = 22f
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(0, 0, 0, 8)
        })

        rootLayout.addView(TextView(this).apply {
            text = "Xposed 模块 · 检测器目标与 Hook 功能开关"
            textSize = 13f
            setTextColor(0xFFAAAAAA.toInt())
            setPadding(0, 0, 0, 24)
        })

        // --- Section: 检测器目标 ---
        addSectionHeader(rootLayout, "检测器目标（12个）")
        val targetCard = createSwitchCard(TARGET_LABELS, TARGET_KEYS, targetSwitches, ::onTargetChanged)
        rootLayout.addView(targetCard)

        // --- Section: Hook 功能开关 ---
        addSectionHeader(rootLayout, "Hook 功能开关（13个）")
        val hookCard = createSwitchCard(HOOK_LABELS, HOOK_KEYS, hookSwitches, ::onHookChanged)
        rootLayout.addView(hookCard)

        // --- Save Button ---
        val saveButton = Button(this).apply {
            text = "保存配置到 /data/adb/modules/MomoRedAll-Native/config.json"
            setBackgroundColor(0xFF1A73E8.toInt())
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(0, 24, 0, 24)
            setOnClickListener { saveConfig() }
        }
        rootLayout.addView(saveButton)

        scrollView.addView(rootLayout)
        setContentView(scrollView)
    }

    private fun addSectionHeader(parent: LinearLayout, title: String) {
        parent.addView(TextView(this).apply {
            text = title
            textSize = 16f
            setTextColor(0xFF90CAF9.toInt())
            setPadding(0, 16, 0, 8)
        })
    }

    private fun createSwitchCard(
        labels: Array<String>,
        keys: Array<String>,
        switchList: MutableList<Switch>,
        listener: (Int, Boolean) -> Unit
    ): MaterialCardView {
        switchList.clear()

        return MaterialCardView(this).apply {
            setCardBackgroundColor(0xFF1E1E1E.toInt())
            radius = 16f
            setContentPadding(16, 8, 16, 8)

            val innerLayout = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }

            for (i in labels.indices) {
                val row = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    setPadding(8, 8, 8, 8)
                }

                val label = TextView(context).apply {
                    text = labels[i]
                    textSize = 14f
                    setTextColor(0xFFE0E0E0.toInt())
                    layoutParams = LinearLayout.LayoutParams(
                        0,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        1f
                    )
                }

                val switch = Switch(context).apply {
                    isChecked = prefs.getBoolean(keys[i], true)
                    setOnCheckedChangeListener { _, isChecked ->
                        listener(i, isChecked)
                    }
                }

                row.addView(label)
                row.addView(switch)
                innerLayout.addView(row)
                switchList.add(switch)
            }

            addView(innerLayout)
        }
    }

    private fun onTargetChanged(index: Int, isChecked: Boolean) {
        prefs.edit().putBoolean(TARGET_KEYS[index], isChecked).apply()
    }

    private fun onHookChanged(index: Int, isChecked: Boolean) {
        prefs.edit().putBoolean(HOOK_KEYS[index], isChecked).apply()
    }

    private fun saveConfig() {
        try {
            val targetKeysJson = arrayOf(
                "momo", "native_test", "applist_detector", "ruru",
                "detect_magisk_hide", "momo_strong", "safetynet",
                "safetynet_playstore", "cat_and_mouse", "android_cts",
                "rootbeer", "rootbeer_fresh"
            )
            val hookKeysJson = arrayOf(
                "fopen", "open", "stat", "access", "opendir",
                "popen_system", "readlink", "ptrace", "getenv",
                "property", "proc", "mounts", "extra"
            )

            val sb = StringBuilder()
            sb.appendLine("{")

            // targets
            sb.appendLine("  \"targets\": {")
            for (i in targetKeysJson.indices) {
                val valStr = if (targetSwitches[i].isChecked) "true" else "false"
                val comma = if (i < targetKeysJson.size - 1) "," else ""
                sb.appendLine("    \"${targetKeysJson[i]}\": $valStr$comma")
            }
            sb.appendLine("  },")

            // hooks
            sb.appendLine("  \"hooks\": {")
            for (i in hookKeysJson.indices) {
                val valStr = if (hookSwitches[i].isChecked) "true" else "false"
                val comma = if (i < hookKeysJson.size - 1) "," else ""
                sb.appendLine("    \"${hookKeysJson[i]}\": $valStr$comma")
            }
            sb.appendLine("  }")
            sb.append("}")

            val configFile = File(CONFIG_OUTPUT_PATH)
            configFile.parentFile?.mkdirs()
            configFile.writeText(sb.toString())

            Toast.makeText(this, "配置已保存到 $CONFIG_OUTPUT_PATH", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, "保存失败: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
