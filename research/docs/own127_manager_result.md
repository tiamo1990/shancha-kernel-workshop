# KernelSU manager visibility on the own127 loaded LKM (live boot, 2026-11-02 13:41-13:44)

Module confirmed live the whole time:
`/proc/modules` line 1: `kernelsu 180224 0 - Live 0x0 (O)` (refcount later 1 while
apps were querying it); 638 modules; hooks_defend still #444.
`/sys/module/kernelsu` does not exist (the prepared module hides its sysfs dir);
no /dev/ksu or /proc/ksu (userspace uses the prctl interface).

## Manager results (screenshots in this dir)

### 1. Official KernelSU — me.weishu.kernelsu (v3.2.5-44-g0f65ab64, 32569-2)
`am start -W -n me.weishu.kernelsu/.ui.MainActivity` -> Status: ok (COLD).
Screenshot `ksu_weishu3.png`:
- GREEN CARD: **工作中 [越狱模式]** — 版本: **32680-5** — **LKM**
- RED BANNER: 当前 KernelSU 管理器版本 32569 过低，KernelSU 无法正常工作，
  请将 KernelSU 管理器版本升级至 32680 或以上！
- 内核版本 6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k;
  设备 vivo X200s; SELinux 强制执行; Seccomp 过滤模式.
=> the app DOES see and use the module (jailbreak mode, LKM, version 32680-5);
   only the manager APK is too old: needs versionCode >= 32680.

### 2. SakiSU — com.sakisu.sakisu (v4.3.0-sakisu.1, 35039/2)
`am start -W -n com.sakisu.sakisu/.ui.MainActivity` -> ok. Screenshot `ksu_sakisu2.png`:
- RED: 当前运行的内核尚未授权此 SakiSU 管理器。请安装与之匹配的
  SakiSU 内核/LKM；若正从旧签名版本迁移，请先配置动态管理器。
=> SakiSU is the wrong fork/signature for this module; version number alone
   (35039 >= 32680) is not enough.

### 3. vivo fork — me.inkdye.vivoksu (vivo-59-g72bdc5db, 32578-2)
`am start -W -n me.inkdye.vivoksu/.ui.MainActivity` -> ok. Screenshot `ksu_vivo2.png`:
- "未安装 / 点击安装" (not installed) — this fork does not recognise the module.
=> wrong fork; also 32578 < 32680.

## Conclusion
The owner127 LKM is fully functional and the official KernelSU manager detects it
as **working jailbreak mode, LKM, version 32680-5**. The only mismatch is the
manager APK version: installed official 32569 / vivo 32578 / SakiSU 35039 (wrong
fork), while the module requires an official-fork manager with versionCode
**>= 32680**. Install a matching official KernelSU manager build (>= 32680) and
the red banner should disappear.

## Artifacts
- ksu_weishu3.png, ksu_sakisu2.png, ksu_vivo2.png (screenshots)
- dump_weishu.txt, dump_sakisu.txt, dump_vivoksu.txt (dumpsys package)
- logcat_ksu.txt
- pkg_probe.sh, ksu_manager_probe.sh, collect_ksu.sh
