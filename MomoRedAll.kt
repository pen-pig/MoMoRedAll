package com.marvis.momoreball

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.IXposedHookZygoteInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.io.FileInputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.ByteArrayInputStream

/**
 * MomoRedAll Xposed v2.0
 *
 * 目标检测器（12+）：
 *   Momo, MagiskDetector, NativeTest, MinotaurPoc, Ruru, Hunter,
 *   Oprek Detector, SafeCheck, DetectZ, DuckDetector/DirtySepolicy,
 *   NativeRootDetector, DetectMagisk, KeyAttestation, DuckDuckGo
 *
 * 新增 v2.0:
 *   - PackageManager.queryIntentActivities 拦截（安装的 Root App 检测）
 *   - Context.getPackageManager / ActivityManager.getRunningAppProcesses
 *   - 80+ 假文件路径、50+ 假属性、25+ shell输出
 *   - /proc/net/tcp6 拦截
 */
class MomoRedAll : IXposedHookLoadPackage, IXposedHookZygoteInit {

    companion object {
        const val TAG = "MomoRedAll"
        private fun log(msg: String) = XposedBridge.log("[$TAG] $msg")

        // 当前进程名缓存
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

        // ====== 目标检测器包名 — 全面覆盖 ======
        val TARGET_PACKAGES = setOf(
            "io.github.vvb2060.mahoshojo",           // Momo
            "io.github.vvb2060.magiskdetector",      // Magisk Detector
            "icu.nullptr.nativetest",                // NativeTest / MinotaurPoc
            "com.byxiaorun.detector",               // Ruru
            "com.zhenxi.hunter",                    // Hunter
            "com.godevelopers.OprekCek",            // Oprek Detector
            "com.ysh.hookapkverify",                // SafeCheck
            "com.test.detectz",                     // DetectZ
            "io.github.vvb2060.keyattestation",     // Key Attestation
            "duckduckgo.mobile.android",            // DuckDuckGo
            "org.lsposed.dirtysepolicy",            // DirtySepolicy
            "com.darvin.security",                  // Detect Magisk
        )

        private val isTarget: Boolean get() {
            val procName = currentProcessName()
            return TARGET_PACKAGES.contains(procName)
        }

        // ====== 全量假属性 (60+) ======
        val FAKE_PROPS = mapOf(
            // Bootloader/Verified Boot
            "ro.boot.verifiedbootstate" to "orange",
            "ro.boot.flash.locked" to "0",
            "ro.boot.vbmeta.device_state" to "unlocked",
            "ro.boot.veritymode" to "disabled",
            "ro.boot.selinux" to "permissive",
            "ro.boot.warranty_bit" to "1",
            "ro.warranty_bit" to "1",
            "ro.boot.vbmeta.avb_version" to "0.0",
            "ro.boot.vbmeta.invalidate_on_error" to "yes",
            "ro.boot.slot_suffix" to "_a",
            "ro.boot.mode" to "charger",
            "ro.boottime" to "1",
            // 调试/开发
            "ro.debuggable" to "1",
            "ro.secure" to "0",
            "ro.adb.secure" to "0",
            "ro.build.type" to "userdebug",
            "ro.build.tags" to "test-keys",
            "ro.build.selinux" to "0",
            "ro.build.flavor" to "userdebug",
            "ro.build.characteristics" to "default,emulator",
            "ro.build.id" to "ENG",
            "ro.build.user" to "root",
            "ro.build.host" to "ubuntu-build-server",
            "ro.build.version.incremental" to "eng.root.20231225.120000",
            "ro.build.version.security_patch" to "2023-12-01",
            // ADB
            "persist.sys.usb.config" to "adb,mtp",
            "init.svc.adbd" to "running",
            "sys.usb.config" to "adb",
            "sys.usb.state" to "adb",
            "persist.service.adb.enable" to "1",
            "persist.service.debuggable" to "1",
            // SELinux
            "ro.build.selinux.enforce" to "0",
            "persist.sys.selinux.enforce" to "0",
            // TEE/Keymaster
            "ro.hardware.keystore" to "software",
            "ro.boot.keymaster" to "0",
            "keymaster_ver" to "0.3",
            "ro.hardware.keystore_desede" to "software",
            // Magisk
            "ro.dalvik.vm.native.bridge" to "libriruloader.so",
            "init.svc.magisk_pfs" to "running",
            "init.svc.magisk_pfsd" to "running",
            "init.svc.magisk_service" to "running",
            "ro.magisk.version" to "27000",
            "ro.magisk.hide" to "1",
            "persist.sys.magisk" to "1",
            // 模拟器痕迹
            "ro.kernel.qemu" to "1",
            "ro.kernel.android.qemud" to "1",
            "ro.hardware" to "goldfish",
            "ro.product.cpu.abi" to "x86",
            "ro.product.cpu.abi2" to "armeabi-v7a",
            "qemu.hw.mainkeys" to "0",
            "ro.kernel.qemu.gles" to "1",
            // 注入/Hook 痕迹
            "net.dns1" to "10.0.2.3",
            "ro.monkey" to "1",
            "ro.kernel.android.checkjni" to "1",
            "dalvik.vm.checkjni" to "true",
            "ro.allow.mock.location" to "1",
            "dalvik.vm.dex2oat-filter" to "verify-none",
            // 自定义ROM
            "ro.modversion" to "LineageOS-20-20240101",
            "ro.lineage.version" to "20.0",
            "ro.cm.version" to "14.1",
            // 加密状态
            "ro.crypto.state" to "unencrypted",
            "ro.crypto.type" to "none",
            // 指纹
            "ro.build.fingerprint" to "google/marlin/marlin:7.1.2/NJH47F/4146041:userdebug/test-keys",
        )

        // ====== 假文件路径 (80+) ======
        val FAKE_SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/system_ext/bin/su",
            "/product/bin/su", "/vendor/bin/su", "/data/local/tmp/su",
            "/sbin/su", "/system/sbin/su", "/system/bin/.ext/su",
            "/system/usr/we-need-root/su", "/system/xbin/mu",
            "/system/bin/failsafe/su", "/su/bin/su",
            "/data/local/bin/su", "/data/local/xbin/su",
            "/vendor/bin/.ext/su",
        )

        val FAKE_MAGISK_PATHS = listOf(
            "/data/adb/magisk.db", "/data/adb/magisk/busybox",
            "/data/adb/magisk/magisk32", "/data/adb/magisk/magisk64",
            "/data/adb/magisk/magiskinit", "/data/adb/magisk/magiskpolicy",
            "/data/adb/magisk/resetprop", "/data/adb/magisk/su",
            "/data/adb/magisk/util_functions.sh",
            "/data/adb/modules", "/data/adb/magisk",
            "/sbin/magisk", "/cache/magisk.log",
            "/data/adb/.magisk", "/data/adb/magisk/rootdir",
            "/data/adb/magisk/magisk",
            "/data/adb/magisk.db-wal", "/data/adb/magisk.db-shm",
            "/dev/.magisk.unblock", "/dev/.magisk.block",
        )

        val FAKE_SUSPICIOUS_PATHS = listOf(
            "/data/adb/", "/data/adb/modules/", "/sbin/",
            "/system/app/Superuser/", "/system/app/SuperSU/",
            "/system/xbin/daemonsu", "/system/bin/.ext/",
            "/system/etc/init.d/", "/data/local/tmp/supersu/",
            "/data/data/eu.chainfire.supersu/",
            "/data/data/com.topjohnwu.magisk/",
            "/system/xbin/busybox", "/system/bin/busybox",
            "/data/data/com.noshufou.android.su/",
            "/data/data/com.termux/",
            "/data/data/com.koushikdutta.rommanager/",
            "/cache/.supersu", "/dev/com.koushikdutta.superuser.daemon/",
            // v2.0 新增: KSU
            "/data/adb/ksu/", "/data/adb/ksud",
            // v2.0 新增: APatch
            "/data/adb/ap/", "/data/adb/apd",
            // v2.0 新增: 各种隐藏模块
            "/data/adb/modules/playintegrityfix",
            "/data/adb/modules/tricky_store",
            "/data/adb/modules/playcurl",
            "/data/adb/modules/Zygisk-Assistant",
        )

        val FAKE_XPOSED_PATHS = listOf(
            "/data/data/de.robv.android.xposed.installer/",
            "/data/data/org.meowcat.edxposed.manager/",
            "/data/app/de.robv.android.xposed.installer-1/",
            "/system/framework/XposedBridge.jar",
            "/data/local/tmp/xposed/",
            // v2.0 新增: LSPosed
            "/data/adb/modules/zygisk_lsposed",
            "/data/adb/lspd",
            "/data/misc/lsposed",
        )

        val FAKE_FRIDA_PATHS = listOf(
            "/data/local/tmp/frida-server-16.5.7-android-arm64",
            "/data/local/tmp/re.frida.server/",
            "/data/local/tmp/frida-server",
            "/sdcard/frida-server",
            "/data/local/tmp/hluda-server",
            // v2.0 新增
            "/data/local/tmp/frida-agent.so",
            "/data/local/tmp/gum-js-loop",
            "/data/local/tmp/linjector",
        )

        // ====== 假 shell 输出 (25+ 命令) ======
        const val FAKE_STATUS = """Name:   magisk.bin
Umask:  0077
State:  S (sleeping)
Tgid:   31337
Ngid:   0
Pid:    31337
PPid:   1
TracerPid:  9999
Uid:    0   0   0   0
Gid:    0   0   0   0
FDSize: 256
Groups: 0 1004 1007 1011 1015 1028 3001 3002 3003 3006 3009 3011
VmPeak:   123456 kB
VmSize:   123456 kB
VmLck:         0 kB
VmPin:         0 kB
VmHWM:     56789 kB
VmRSS:     56789 kB
RssAnon:   23456 kB
RssFile:   33333 kB
RssShmem:       0 kB
VmData:    45678 kB
VmStk:       132 kB
VmExe:        44 kB
VmLib:      6789 kB
VmPTE:       123 kB
VmSwap:        0 kB
CoreDumping:    0
THP_enabled:    1
Threads:   3
SigQ:   0/12345
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000001204
SigIgn: 0000000000001000
SigCgt: 00000001800146ef
CapInh: 0000000000000000
CapPrm: 000000ffffffffff
CapEff: 000000ffffffffff
CapBnd: 000000ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        2
Seccomp_filters:        1
Speculation_Store_Bypass:       thread vulnerable
SpeculationIndirectBranch:      always enabled
Cpus_allowed:   ff
Cpus_allowed_list:      0-7
Mems_allowed:   1
Mems_allowed_list:      0
voluntary_ctxt_switches:        999
nonvoluntary_ctxt_switches:     313
"""
        const val FAKE_MOUNTS = """rootfs / rootfs ro,seclabel,size=1844344k,nr_inodes=461086 0 0
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,size=1861600k,nr_inodes=465400,mode=755 0 0
devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,mode=600,ptmxmode=000 0 0
magisk /sbin tmpfs rw,seclabel,relatime 0 0
magisk /system/bin tmpfs rw,seclabel,relatime 0 0
magisk /system/xbin tmpfs rw,seclabel,relatime 0 0
/data/adb/modules /data/adb/modules tmpfs rw,seclabel,relatime 0 0
/dev/block/mmcblk0p42 /system ext4 ro,seclabel,relatime 0 0
fuse /mnt/runtime/default/emulated fuse rw,nosuid,nodev,noexec,noatime,user_id=0,group_id=0,allow_other 0 0
"""

        val FAKE_SHELL_RESPONSES = mapOf(
            "ps" to """USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME
root             1     0   12345  6789 SyS_epoll_wait      0 S init
root           234     1   12345  6789 SyS_epoll_wait      0 S zygisk64
root           235     1   12345  6789 SyS_epoll_wait      0 S zygisk32
root          1234     1  123456  56789 do_sys_poll         0 S magiskd
shell         5678     1  234567  89012 binder_thr          0 S su
root          9999     1  111111  22222 sigsuspen           0 S daemonsu
root         11111     1  222222  33333 hrtimer_n           0 S frida-server
root         22222     1  333333  44444 do_wait             0 S xposed_loade
root         33333     1  444444  55555 futex_wai           0 S magisk.bin
root         44444     1  555555  66666 SyS_epoll_wait      0 S ksud
root         55555     1  666666  77777 SyS_epoll_wait      0 S apd
""",
            "getprop" to """
[ro.debuggable]: [1]
[ro.secure]: [0]
[ro.build.type]: [userdebug]
[ro.build.tags]: [test-keys]
[ro.boot.verifiedbootstate]: [orange]
[ro.boot.flash.locked]: [0]
[ro.boot.vbmeta.device_state]: [unlocked]
[init.svc.adbd]: [running]
[ro.build.selinux]: [0]
[init.svc.magisk_pfs]: [running]
[init.svc.magisk_service]: [running]
[ro.dalvik.vm.native.bridge]: [libriruloader.so]
[ro.hardware.keystore]: [software]
[ro.magisk.version]: [27000]
""",
            "which su" to "/system/bin/su",
            "which magisk" to "/sbin/magisk",
            "which frida" to "/data/local/tmp/frida-server",
            "id" to "uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:magisk:s0",
            "whoami" to "root",
            "mount" to """
rootfs on / type rootfs (ro,seclabel,size=1844344k,nr_inodes=461086)
tmpfs on /dev type tmpfs (rw,seclabel,nosuid,relatime,size=1861600k,nr_inodes=465400,mode=755)
magisk on /sbin type tmpfs (rw,seclabel,relatime)
magisk on /system/bin type tmpfs (rw,seclabel,relatime)
/dev/root on /system type ext4 (ro,seclabel,relatime)
/data/adb/modules on /data/adb/modules type tmpfs (rw,seclabel,relatime)
fuse on /mnt/runtime/default/emulated type fuse (rw,nosuid,nodev,noexec,noatime,user_id=0,group_id=0,allow_other)
""",
            "netstat -tlnp" to """
tcp        0      0 0.0.0.0:27042           0.0.0.0:*               LISTEN      11111/frida-server
tcp        0      0 127.0.0.1:5555           0.0.0.0:*               LISTEN      1234/magiskd
tcp        0      0 0.0.0.0:27043           0.0.0.0:*               LISTEN      11111/frida-server
""",
            "ss -tlnp" to """
LISTEN 0      128        0.0.0.0:27042      0.0.0.0:*    users:(("frida-server",pid=11111,fd=4))
LISTEN 0      128        0.0.0.0:27043      0.0.0.0:*    users:(("frida-server",pid=11111,fd=5))
""",
            "ls -la /data/local/tmp" to """
total 4096
-rwxr-xr-x 1 root root 4567890 2025-01-01 00:00 frida-server
-rwxr-xr-x 1 root root   12345 2025-01-01 00:00 su
drwxr-xr-x 2 root root    4096 2025-01-01 00:00 supersu
drwxr-xr-x 2 root root    4096 2025-01-01 00:00 re.frida.server
-rwxr-xr-x 1 root root   54321 2025-01-01 00:00 hluda-server
""",
            "ls -la /data/adb" to """
total 4096
drwxr-xr-x  2 root root 4096 2025-01-01 00:00 modules
drwxr-xr-x  2 root root 4096 2025-01-01 00:00 magisk
drwxr-xr-x  2 root root 4096 2025-01-01 00:00 ksu
drwxr-xr-x  2 root root 4096 2025-01-01 00:00 ap
-rw-r--r--  1 root root 8192 2025-01-01 00:00 magisk.db
-rw-r--r--  1 root root    0 2025-01-01 00:00 .magisk
""",
            "cat /proc/self/status" to FAKE_STATUS,
            "cat /proc/self/mounts" to FAKE_MOUNTS,
            "cat /proc/mounts" to FAKE_MOUNTS,
            "cat /sys/fs/selinux/enforce" to "0",
            "getenforce" to "Permissive",
            "sestatus" to "SELinux status:         disabled",
            "pgrep magisk" to "1234",
            "pgrep frida" to "11111",
            "pidof frida-server" to "11111",
            "dumpsys" to """DUMP OF SERVICE activity:
  mFocusedApp=AppWindowToken{deadbeef token=Token{deadbeef ActivityRecord{deadbeef u0 com.topjohnwu.magisk/.MainActivity}}}
""",
        )

        // ====== Root App 包名列表（用于 PackageManager 拦截） ======
        val ROOT_APP_PACKAGES = setOf(
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "io.github.huskydg.magisk",
            "com.chiller3.magiskapp",
            "com.solohsu.android.edxp.manager",
            "org.meowcat.edxposed.manager",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.lsposed.lspatch",
            "com.oasisfeng.island",
            "com.offshore",
            "me.weishu.kernelsu",
            "com.android.vending.billing.InAppBillingService.COIN",
            "eu.chainfire.supersu",
            "eu.chainfire.flash",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.airinstalle",
            "com.radikalle.batch",
            "com.ghisler.android.TotalCommander",
            "com.ghisler.tcplugins.FTP",
            "stericson.busybox",
            "stericson.busybox.donate",
            "ru.meefik.busybox",
            "com.chelpus.luckypatcher",
            "com.forcindia.luckypatcher",
            "com.dimonvideo.luckypatcher",
            "com.byxiaorun.detector",
            "io.github.vvb2060.keyattestation",
            "com.zhenxi.hunter",
            "com.godevelopers.OprekCek",
            "com.ysh.hookapkverify",
            "com.test.detectz",
            "com.darvin.security",
            "icu.nullptr.nativetest",
            "org.lsposed.dirtysepolicy",
            "de.robv.android.xposed.installer",
            "com.wind.vpn.mobile",
            // v2.0 新增
            "com.wireguard.android",
            "io.github.vvb2060.magisk.delta",
            "io.github.vvb2060.magisk.alpha",
        )

        // ====== Tmp file cache ======
        private val fakeMapsCache = createFakeMapsContent()
        private val fakeWchanFile = textFile("SyS_epoll_wait\n")
        private val fakeAttrCurrentFile = textFile("u:r:magisk:s0\n")
        private val fakeSelinuxEnforceFile = textFile("0")
        private val fakeNetTcpFile = textFile("""  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:69A3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
""")
        private val fakeNetTcp6File = textFile("""  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:69A2 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
""")

        // ====== /proc 注入数据 ======
        val PROC_REPLACEMENTS = mapOf(
            "/proc/self/maps"   to { fakeMapsCache },
            "/proc/self/status" to { textFile(FAKE_STATUS) },
            "/proc/self/mounts" to { textFile(FAKE_MOUNTS) },
            "/proc/self/wchan"  to { fakeWchanFile },
            "/proc/self/attr/current" to { fakeAttrCurrentFile },
            "/proc/net/tcp"     to { fakeNetTcpFile },
            "/proc/net/tcp6"    to { fakeNetTcp6File },
            "/sys/fs/selinux/enforce" to { fakeSelinuxEnforceFile },
        )

        fun textFile(content: String): File {
            val tmp = File.createTempFile("fake_", ".txt")
            tmp.deleteOnExit()
            tmp.writeText(content)
            return tmp
        }

        fun createFakeMapsContent(): String {
            val zygisk =
                """
7a1b2c3d4000-7a1b2c3d6000 r-xp 00000000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d6000-7a1b2c3d8000 r--p 00001000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7a1b2c3d8000-7a1b2c3d9000 rw-p 00003000 fd:01 1234567  /data/adb/modules/zygisk_lsposed/zygisk.so
7b3c4d5e6000-7b3c4d5e8000 r-xp 00000000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5e8000-7b3c4d5ea000 r--p 00001000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7b3c4d5ea000-7b3c4d5eb000 rw-p 00003000 fd:01 2345678  /data/adb/modules/zygisk_shamiko/zygisk.so
7c5d6e7f8000-7c5d6e7fb000 r-xp 00000000 fd:01 3456789  /data/adb/magisk/magisk32
7c5d6e7fb000-7c5d6e7fc000 r--p 00002000 fd:01 3456789  /data/adb/magisk/magisk32
7c5d6e7fc000-7c5d6e7fd000 rw-p 00003000 fd:01 3456789  /data/adb/magisk/magisk32
7d8e9f0a1000-7d8e9f0a4000 r-xp 00000000 103:17 4567890  /system/framework/XposedBridge.jar
7e0f1a2b3000-7e0f1a2b6000 r-xp 00000000 103:17 5678901  /data/local/tmp/frida-server
7e0f1a2b6000-7e0f1a2b8000 r--p 00002000 103:17 5678901  /data/local/tmp/frida-server
7e0f1a2b8000-7e0f1a2b9000 rw-p 00004000 103:17 5678901  /data/local/tmp/frida-server
7f1a2b3c4000-7f1a2b3c7000 r-xp 00000000 103:17 6789012  /data/adb/modules/lsposed/lspd
7f1a2b3c7000-7f1a2b3c8000 r--p 00002000 103:17 6789012  /data/adb/modules/lsposed/lspd
8a1b2c3d5000-8a1b2c3d8000 rwxp 00000000 00:00 0          [anon:libc_malloc_hook]
8a1b2c3d8000-8a1b2c3da000 r-xp 00000000 00:00 0          [anon:.bss_ART_hook]
8f1a2b3c4000-8f1a2b3c6000 r-xp 00000000 00:00 0          /data/adb/ksu/modules/zygisk_on_kernelsu.so
8f1a2b3c6000-8f1a2b3c7000 r--p 00001000 00:00 0          /data/adb/ksu/modules/zygisk_on_kernelsu.so
""".trimIndent()
            val real = try { File("/proc/self/maps").readText() } catch (e: Exception) { "" }
            return real + "\n" + zygisk
        }
    }

    // ====== Zygote: 全量属性篡改 ======
    override fun initZygote(startupParam: IXposedHookZygoteInit.StartupParam) {
        log("Zygote init — v2.0")
        hookSystemProperties()
    }

    private fun hookSystemProperties() {
        val sysPropClass = XposedHelpers.findClass("android.os.SystemProperties", null)

        // get(String, String)
        XposedHelpers.findAndHookMethod(
            sysPropClass, "get", String::class.java, String::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    if (!isTarget) return
                    val key = param.args[0] as String
                    if (!FAKE_PROPS.containsKey(key)) return
                    param.result = FAKE_PROPS[key]
                }
            }
        )

        // getBoolean, getInt, getLong
        for ((methodName, resultType) in listOf(
            "getBoolean" to "bool",
            "getInt" to "int",
            "getLong" to "long"
        )) {
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
                        if (!isTarget) return
                        val key = param.args[0] as String
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

    // ====== App 进程: 全量痕迹注入 ======
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        if (!TARGET_PACKAGES.contains(pkg)) return
        log("Hook into $pkg")

        val cl = lpparam.classLoader
        hookTeeBroken(cl)
        hookFileExists()
        hookFileListFiles()
        hookFileCanRead()
        hookFileIsFile()
        hookFileIsDirectory()
        hookFileCanExecute()
        hookFileLength()
        hookRuntimeExec(cl)
        hookFileInputStream()
        hookSelinuxIsEnforced()
        hookSystemGetenv(cl)
        hookPackageManager(cl)      // v2.0 新增
        hookActivityManager(cl)     // v2.0 新增
    }

    // ====== TEE 损坏 ======
    private fun hookTeeBroken(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.KeyInfo", cl, "isInsideSecureHardware",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                }
            )
            log("KeyInfo.isInsideSecureHardware hooked")
        } catch (e: Exception) { log("KeyInfo err: ${e.message}") }

        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.KeyGenParameterSpec\$Builder", cl,
                "setAttestationChallenge", ByteArray::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        throw RuntimeException("TEE attestation broken")
                    }
                }
            )
        } catch (e: Exception) {}

        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.KeyGenParameterSpec\$Builder", cl,
                "setIsStrongBoxBacked", java.lang.Boolean.TYPE,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        param.args[0] = false
                    }
                }
            )
        } catch (e: Exception) {}

        // v2.0 新增: 阻断 getCertificateChain
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.keystore.AndroidKeyStoreKey", cl,
                "getCertificateChain",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        throw RuntimeException("Key attestation chain blocked")
                    }
                }
            )
        } catch (e: Exception) {}
    }

    // ====== File.exists/canRead/isFile/isDirectory/canExecute/length ======
    private fun hookFileExists() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "exists",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (param.result == true) return
                        if (path in FAKE_SU_PATHS || path in FAKE_MAGISK_PATHS
                            || path in FAKE_SUSPICIOUS_PATHS || path in FAKE_XPOSED_PATHS
                            || path in FAKE_FRIDA_PATHS)
                            param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    private fun hookFileListFiles() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "listFiles",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val dir = param.thisObject as File
                        val existing = param.result as? Array<File> ?: return
                        val inject = when (dir.absolutePath) {
                            "/data/adb/" -> listOf(
                                F("/data/adb/magisk.db"), F("/data/adb/magisk"),
                                F("/data/adb/modules"), F("/data/adb/.magisk"),
                                F("/data/adb/magisk.db-wal"), F("/data/adb/magisk.db-shm"),
                                F("/data/adb/ksu"), F("/data/adb/ap"),
                            )
                            "/data/adb/modules/" -> listOf(
                                F("/data/adb/modules/zygisk_lsposed"),
                                F("/data/adb/modules/shamiko"),
                                F("/data/adb/modules/hosts"),
                                F("/data/adb/modules/playintegrityfix"),
                                F("/data/adb/modules/zygisk_shamiko"),
                                F("/data/adb/modules/tricky_store"),
                                F("/data/adb/modules/playcurl"),
                                F("/data/adb/modules/Zygisk-Assistant"),
                            )
                            "/sbin/" -> listOf(
                                F("/sbin/su"), F("/sbin/magisk"),
                                F("/sbin/magiskpolicy"), F("/sbin/magiskinit"),
                                F("/sbin/busybox"),
                            )
                            "/data/local/tmp/" -> listOf(
                                F("/data/local/tmp/frida-server"),
                                F("/data/local/tmp/re.frida.server"),
                                F("/data/local/tmp/su"),
                                F("/data/local/tmp/frida-agent.so"),
                                F("/data/local/tmp/hluda-server"),
                            )
                            else -> emptyList()
                        }
                        if (inject.isNotEmpty())
                            param.result = existing + inject.toTypedArray()
                    }
                })
        } catch (e: Exception) {}
    }

    private fun hookFileCanRead() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "canRead",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (path in FAKE_SU_PATHS || path in FAKE_MAGISK_PATHS
                            || path in FAKE_XPOSED_PATHS || path in FAKE_FRIDA_PATHS)
                            param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    private fun hookFileIsFile() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "isFile",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (path in FAKE_SU_PATHS || path in FAKE_MAGISK_PATHS)
                            param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    private fun hookFileIsDirectory() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "isDirectory",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (path in FAKE_SUSPICIOUS_PATHS)
                            param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    private fun hookFileCanExecute() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "canExecute",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (path in FAKE_SU_PATHS)
                            param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    // v2.0 新增: File.length() — 返回非零使文件看起来"真实"
    private fun hookFileLength() {
        try {
            XposedHelpers.findAndHookMethod(File::class.java, "length",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val path = (param.thisObject as File).absolutePath
                        if (param.result as Long > 0) return
                        if (path in FAKE_SU_PATHS || path in FAKE_MAGISK_PATHS
                            || path in FAKE_FRIDA_PATHS)
                            param.result = 31337L
                    }
                })
        } catch (e: Exception) {}
    }

    // ====== ProcessBuilder / Runtime.exec ======
    private fun hookRuntimeExec(cl: ClassLoader) {
        // ProcessBuilder.start()
        try {
            XposedHelpers.findAndHookMethod(
                ProcessBuilder::class.java, "start",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val cmdList = try {
                            XposedHelpers.getObjectField(param.thisObject, "command") as? List<String>
                        } catch (e: Exception) {
                            try { XposedHelpers.getObjectField(param.thisObject, "commands") as? List<String> }
                            catch (e2: Exception) { null }
                        } ?: return
                        if (cmdList.isEmpty()) return
                        val fullCmd = cmdList.joinToString(" ")
                        for ((keyword, output) in FAKE_SHELL_RESPONSES) {
                            if (fullCmd.lowercase().contains(keyword)) {
                                param.result = FakeProcess(output)
                                return
                            }
                        }
                        if (cmdList.any { it == "su" || it.endsWith("/su") }) {
                            param.result = FakeProcess("uid=0(root)\n")
                        }
                    }
                })
        } catch (e: Exception) { log("ProcessBuilder err: ${e.message}") }

        // Runtime.exec() — 4 种签名兜底
        for (sig in listOf(
            arrayOf<Class<*>>(String::class.java),
            arrayOf<Class<*>>(Array<String>::class.java),
            arrayOf<Class<*>>(String::class.java, Array<String>::class.java),
            arrayOf<Class<*>>(String::class.java, Array<String>::class.java, File::class.java)
        )) {
            try {
                XposedHelpers.findAndHookMethod(
                    Runtime::class.java, "exec", *sig,
                    object : XC_MethodHook() {
                        override fun beforeHookedMethod(param: MethodHookParam) {
                            val cmdStr = when {
                                param.args[0] is String -> param.args[0] as String
                                param.args[0] is Array<*> -> (param.args[0] as Array<*>).joinToString(" ")
                                else -> return
                            }
                            for ((keyword, output) in FAKE_SHELL_RESPONSES) {
                                if (cmdStr.lowercase().contains(keyword)) {
                                    param.result = FakeProcess(output)
                                    return
                                }
                            }
                        }
                    })
            } catch (e: Exception) {}
        }
    }

    // ====== FileInputStream: /proc & /sys 全量注入 ======
    private fun hookFileInputStream() {
        // FileInputStream(File)
        try {
            XposedHelpers.findAndHookConstructor(
                "java.io.FileInputStream", null, File::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val f = param.args[0] as? File ?: return
                        val path = f.absolutePath
                        val replacement = PROC_REPLACEMENTS[path]?.invoke() ?: return
                        param.args[0] = replacement
                    }
                })
        } catch (e: Exception) { log("FIS(File) err: ${e.message}") }

        // FileInputStream(String)
        try {
            XposedHelpers.findAndHookConstructor(
                "java.io.FileInputStream", null, String::class.java,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val path = param.args[0] as? String ?: return
                        val replacement = PROC_REPLACEMENTS[path]?.invoke() ?: return
                        param.args[0] = replacement.absolutePath
                    }
                })
        } catch (e: Exception) {}

        // FileInputStream(FileDescriptor) — not hookable, pass through
    }

    // ====== SELinux (Java API + File) ======
    private fun hookSelinuxIsEnforced() {
        // android.os.SELinux.isSELinuxEnforced()
        try {
            val selClass = XposedHelpers.findClass("android.os.SELinux", null)
            XposedHelpers.findAndHookMethod(selClass, "isSELinuxEnforced",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = false
                    }
                })
        } catch (e: Exception) { log("SELinux err: ${e.message}") }

        try {
            val selClass = XposedHelpers.findClass("android.os.SELinux", null)
            XposedHelpers.findAndHookMethod(selClass, "checkSELinuxAccess",
                String::class.java, String::class.java, String::class.java, String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        param.result = true
                    }
                })
        } catch (e: Exception) {}
    }

    // ====== System.getenv("LD_PRELOAD") ======
    private fun hookSystemGetenv(cl: ClassLoader) {
        try {
            XposedHelpers.findAndHookMethod(
                System::class.java, "getenv", String::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val name = param.args[0] as String
                        if (name == "LD_PRELOAD") {
                            param.result = "/data/local/tmp/libriruloader.so"
                        }
                    }
                })
        } catch (e: Exception) { log("getenv err: ${e.message}") }
    }

    // ====== v2.0 新增: PackageManager 拦截 ======
    private fun hookPackageManager(cl: ClassLoader) {
        try {
            // queryIntentActivities — 最常见检测方式
            val pmClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", cl)
            XposedHelpers.findAndHookMethod(
                pmClass, "queryIntentActivities",
                android.content.Intent::class.java, java.lang.Integer.TYPE,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result as? MutableList<*> ?: return
                        // Filter out root apps from results
                        val filtered = result.filter { info ->
                            val pn = try {
                                val pnField = info?.javaClass?.getField("activityInfo")
                                val ai = pnField?.get(info)
                                val pkgField = ai?.javaClass?.getField("packageName")
                                pkgField?.get(ai) as? String ?: ""
                            } catch (e: Exception) { "" }
                            !ROOT_APP_PACKAGES.contains(pn)
                        }
                        if (filtered.size < result.size) {
                            param.result = filtered.toMutableList()
                        }
                    }
                })
        } catch (e: Exception) { log("PM query err: ${e.message}") }

        // getInstalledApplications
        try {
            val pmClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", cl)
            XposedHelpers.findAndHookMethod(
                pmClass, "getInstalledApplications", java.lang.Integer.TYPE,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result as? MutableList<*> ?: return
                        val filtered = result.filter { info ->
                            val pn = try {
                                val pkgField = info?.javaClass?.getField("packageName")
                                pkgField?.get(info) as? String ?: ""
                            } catch (e: Exception) { "" }
                            !ROOT_APP_PACKAGES.contains(pn)
                        }
                        if (filtered.size < result.size) {
                            param.result = filtered.toMutableList()
                        }
                    }
                })
        } catch (e: Exception) {}

        // getInstalledPackages
        try {
            val pmClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", cl)
            XposedHelpers.findAndHookMethod(
                pmClass, "getInstalledPackages", java.lang.Integer.TYPE,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result as? MutableList<*> ?: return
                        val filtered = result.filter { info ->
                            val pn = try {
                                val pkgField = info?.javaClass?.getField("packageName")
                                pkgField?.get(info) as? String ?: ""
                            } catch (e: Exception) { "" }
                            !ROOT_APP_PACKAGES.contains(pn)
                        }
                        if (filtered.size < result.size) {
                            param.result = filtered.toMutableList()
                        }
                    }
                })
        } catch (e: Exception) {}

        // getPackageInfo — 单个查询拦截
        try {
            val pmClass = XposedHelpers.findClass("android.app.ApplicationPackageManager", cl)
            XposedHelpers.findAndHookMethod(
                pmClass, "getPackageInfo",
                String::class.java, java.lang.Integer.TYPE,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val pkg = param.args[0] as? String ?: return
                        if (ROOT_APP_PACKAGES.contains(pkg)) {
                            throw android.content.pm.PackageManager.NameNotFoundException(
                                "Package $pkg not found"
                            )
                        }
                    }
                })
        } catch (e: Exception) {}
    }

    // ====== v2.0 新增: ActivityManager 拦截 ======
    private fun hookActivityManager(cl: ClassLoader) {
        // getRunningAppProcesses — 检测 magiskd 进程
        try {
            val amClass = XposedHelpers.findClass("android.app.ActivityManager", cl)
            XposedHelpers.findAndHookMethod(
                amClass, "getRunningAppProcesses",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val result = param.result as? MutableList<*> ?: return
                        val filtered = result.filter { process ->
                            val pn = try {
                                val pnField = process?.javaClass?.getField("processName")
                                pnField?.get(process) as? String ?: ""
                            } catch (e: Exception) { "" }
                            !pn.contains("magisk") && !pn.contains("zygisk")
                            && !pn.contains("xposed") && !pn.contains("frida")
                            && !pn.contains("lsposed") && !pn.contains("riru")
                            && !pn.contains("shamiko") && !pn.contains("ksud")
                        }
                        if (filtered.size < result.size) {
                            param.result = filtered.toMutableList()
                        }
                    }
                })
        } catch (e: Exception) { log("AM err: ${e.message}") }
    }

    // ====== Helpers ======
    fun F(path: String) = File(path)

    inner class FakeProcess(private val output: String) : Process() {
        override fun getOutputStream(): java.io.OutputStream =
            object : java.io.OutputStream() { override fun write(b: Int) {} }
        override fun getInputStream(): java.io.InputStream =
            java.io.ByteArrayInputStream(output.toByteArray())
        override fun getErrorStream(): java.io.InputStream =
            java.io.ByteArrayInputStream(ByteArray(0))
        override fun waitFor(): Int = 0
        override fun exitValue(): Int = 0
        override fun destroy() {}
    }
}
