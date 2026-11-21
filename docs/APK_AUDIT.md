# 山茶 · 内核工坊（com.shancha.ownctl v95 / 7.7）全面体检报告

- 体检时间：2026-11-21 23:12–23:25（Asia/Shanghai）
- 设备：vivo V2458A（PD2415M / PD2415），adbd serial `10AF5S06220034H`，内核 `6.6.127-android15-8-gd489d4ad2a70-abogki573773666-4k`，`/proc/uptime` ≈ 667 s（本次体检期间未重启）
- 被测件：已安装 `versionCode=95 / versionName=7.7`，`minSdk=23 targetSdk=34`，`compileSdk=37`，`/data/app/~~DZpTGb4yLczXAuW__13upA==/com.shancha.ownctl-jZU_UaDJOOQd9JyLY0MMJA==/base.apk`
- 代码基线：`work/vivo/apk/src/com/shancha/ownctl/*.java`（MainActivity.java 2168 行 / 非空 2036 行）、`AndroidManifest.xml`、`res/`、`as/`、`assets/`
- 只读承诺：未修改任何源码/资源/清单，未打包、未安装，**未点击「启动链路」**，未重启、未清理设备上的任何文件。
- 校验「审的代码 == 跑的代码」：从已装 APK 抽出 `classes.dex`（143,576 B，与本地 `apk/dex/classes.dex` 同尺寸）做字节级检索，`本轮日志改名失败`、`已接管/已驻留`、`上次运行因重启结束`、`进行中-`、`实时日志-最近一次`、`载荷校验失败` 等源串**全部命中**（`上次…@129440`、`本轮…@131507`、`进行中-@132628`、`载荷校验失败@94917`）。→ **本报告的行号与线上行为一一对应。**

---

## 0. 当前设备真实状态（体检开始时的既成事实）

| 项 | 观测 | 命令 |
|---|---|---|
| kernelsu 模块 | **已加载**（计数 1） | `adb shell "grep -c kernelsu /proc/modules"` → `1` |
| 载荷进程 | **仍存活，pid 14995**（已 `pause()` 驻留） | `adb shell "pidof own127; pidof own128"` → `14995`（own128 无） |
| 载荷成功标记 | `/data/local/tmp/.chain_ok137`，root:root，2 B，23:07 | `ls -la /data/local/tmp` |
| 最后一次 3666 结果 | **全链成功**：`S6\|装载\|全链成功\|E6080\|uptime=93.48\|ok=1`，随后 `E6120 保活挂起` / `E6122 保活跟随` | `tail -c 200 …/run-20261121-231534-3666.txt` |
| App 界面 | **「链路待机 / 进度 0 / 6 / 待机」** | 截图 `_audit_tmp/screen.png` |

> 也就是说：**内核已被接管、载荷正在驻留，而界面告诉用户可以「启动链路」。** 这是本报告 P0-1 的现场直证。

**取证边界说明（避免过度推断）**：
- 23:15:17 我用 `adb shell am start` 拉起 App（任务要求的「启动 App 看 logcat」），这**触发 App 自身**在 23:15:34 写出一份 `run-20261121-231534-3666.txt`、并把 `实时日志-最近一次.txt` 从 51,135 B 覆盖成 429 B。**这些文件是 App 写的，不是我写的**；我只做了读、`screencap`、`uiautomator dump`（失败，未落文件）。
- 那条 `日志已保存 · run-…-231534-3666.txt` 出现在**重建后的新实例视图**里，而同一时刻上一实例的读线程仍在运行。究竟是 `exportLog()` 还是 `runViaShizuku()` 的收尾路径写出它，**因 prefs 不可读（§10-2）无法确证**，本报告只把它当作「重建后仍有旧线程在产出」的旁证。

---

## 1. P0 — 会崩 / 会误操作

### P0-1 界面状态与真实运行态解耦：重建后显示「待机」，可在已接管内核上再跑一轮
- **位置**：`MainActivity.java:133-145`（onCreate）、`279-283`（onDestroy）、`1834-1941`（start）、`1925-1940`（裸 Thread）、`AndroidManifest.xml:51-59`（无 `android:configChanges`）
- **现象**：运行态全部存在 Activity 实例字段里（`running/sawSuccess/stageIdx/hist/liveBuf`），链路线程是 `new Thread(...).start()`，不随 Activity 结束。旋转、分屏、返回键退出、系统回收后再进入，都会新建实例 → 状态归零、日志缓冲清空、`running=false`，而旧实例的线程仍活着并继续往已 detach 的 `TextView` 里 append。
- **证据**：
  - 现场：`grep -c kernelsu /proc/modules` = 1、`pidof own127` = 14995，而截图 1 显示「链路待机 / 进度 0 / 6 / 待机 / 启动链路」可点。onCreate 首行日志为 `23:15:17 上次异常已记录`——说明视图是**新建实例**重建的。
  - 代码：`onDestroy()` 只有一行 `Shizuku.removeRequestPermissionResultListener(this)`（281），不 `rp.destroy()`、不 `watchStop=true`；`startBreathe()` 的 `ObjectAnimator`（1294-1300）也从不随生命周期停。
- **建议修法**：运行态与读线程迁到前台 Service（或 ViewModel + 单例状态机），`onCreate` 用 `moduleLoaded()`/`pidof own127` 回填真实状态并在已接管时禁用「启动链路」。
- **影响面**：**最高**。设备已接管 + 载荷驻留（杀掉会 UAF、`fix_rc_uid` 写路径会概率性 panic）时，界面却邀请用户再点一次启动。

### P0-2 `start()` 不复位上一轮门闩：第二轮「无输出 + 无卡死保护」
- **位置**：`MainActivity.java:1915-1924`（复位清单）、`858/859`（sawSuccess/watchStop）、`832/833`（shownStage/tailDropped）、`992`、`1009-1015`、`2021`、`2046`
- **现象**：`start()` 只复位 `liveBuf / pills / stageIdx / progress / badge / stage`，**不复位** `sawSuccess / successDeclared / tailDropped / watchStop / shownStage`。
  - `sawSuccess` 残留 true → `narrate()` 把 S1–S5 的行当「收尾」整段丢弃（1009-1015），`E6121` 直接 return（992），`declareSuccess()` 早退（866）。
  - `watchStop` 残留 true → 看门狗线程第一轮就 `return`（2019-2021），45 秒无输出的清理逻辑永久失效。
- **证据**：`1916-1924` 逐行可数，清单中确无上述 5 个字段；`2046` 在上一轮结束时把 `watchStop` 置 true。
- **建议修法**：`start()` 入口统一复位这 5 个字段，或引入 `RunSession` 对象每次新建。
- **影响面**：同进程第二次启动必然静默、无日志、卡死也不自愈。

### P0-3 `running=true` 与建线程之间无保护：可卡死为永久「运行中」
- **位置**：`MainActivity.java:1915`（`running = true`）、`1919`（`pills[i].setBackgroundResource`，无判空）、`1925`（才创建线程）
- **现象**：`running` 置 true 之后、线程创建之前若抛异常（`pills[i]` 为 null 即 NPE；`startSession()` 里 MediaStore 之外的一切），`running` 就永远停在 true，此后所有 `start()` 都被 1835 行的 `if (running) { emit("§ 链路已在运行"); return; }` 挡住 → 只有杀进程能恢复。
- **证据**：1915-1925 区间没有 try/catch 或 try/finally；1919 行与同文件 `refreshPills()`（422-423 有 `if (p == null) continue;`）的写法不一致。
- **建议修法**：把 `running=true … 线程启动` 整段放进 try，失败时复位；或先建线程再置标志。
- **影响面**：一次偶发 NPE 就锁死整个 App，直到强杀。

### P0-4 `ChainService` 在 targetSdk 34 下调 `startForeground()` 无 type → 必崩
- **位置**：`ChainService.java:28`、`BootReceiver.java:17`、`AndroidManifest.xml:43-45`
- **现象**：`<service android:name=".ChainService" android:exported="false" />` 未声明 `android:foregroundServiceType`。targetSdk ≥ 34 时 `startForeground()` 抛 `MissingForegroundServiceTypeException`。
- **证据**：manifest 43-45 只有 name/exported；`aapt2 dump badging` → `targetSdkVersion:'34'`；`ChainService:28` 直接 `startForeground(1, note(...))`。
- **现状缓解**：入口被 `BootReceiver:14-15` 的 `auto_run`（默认 false）挡住，而全仓**没有任何代码写 `auto_run`**（`grep` 仅 `BootReceiver.java:15` 一处读取）→ 目前是**死代码里的定时炸弹**。
- **建议修法**：要么删掉这条自启链路连同它多申请的权限，要么补 `foregroundServiceType` + 类型权限。
- **影响面**：一旦有人打开 `auto_run`，开机即崩；且为这条死链路多申请了 `RECEIVE_BOOT_COMPLETED` / `FOREGROUND_SERVICE` / `POST_NOTIFICATIONS`。

### P0-5 工作树 `assets/` 与已发布包不一致：从当前树重建即得坏包
- **位置**：`assets/own127`、缺失的 `assets/own127_prev` 与 `assets/payloads.json`；`build_v30..v43*.ps1` 都用 `-A (Join-Path $apk "assets")`
- **现象**：磁盘上 `assets/own127` = **527,672 B / sha256 `EA91FE67…`**，既不是 3666（`8038F24F…`）也不是 7879（`EA780134…`）；`assets/own127_prev` 不存在。而**已装 APK 与 `out/base.apk` 里 `assets/own127` = 532,280 B / `8038F24F…`（正确）**。
- **证据**（三重对照）：

  | 文件 | 大小 | sha256 |
  |---|---|---|
  | `apk/assets/own127`（工作树） | 527,672 | `EA91FE673B3527C1FF90091085FF28C064D1238882226FC6E17186EC16E80593` |
  | `apk/as/own127` | 532,280 | `8038F24F0A39E7628ED8CBD4AD26FA658D99ECA762CFD411AA1610AF11A083C5` |
  | `apk/as/own127_prev` | 527,672 | `EA78013468BD0C8FCCF5CEDB030A08D9162D450757288EE5CAC15185B75B43D2` |
  | 已装 APK `assets/own127` | 532,280 | `8038F24F0A39E7628ED8CBD4AD26FA658D99ECA762CFD411AA1610AF11A083C5` |
  | 已装 APK `assets/own127_prev` | 527,672 | `EA78013468BD0C8FCCF5CEDB030A08D9162D450757288EE5CAC15185B75B43D2` |

  `assets/own127` 的 mtime 是 **2026-11-21 01:57**，而 `out/base.apk` 是 **23:04** —— 两者不可能同源。
- **后果（推演，逻辑确定）**：从当前树重打，3666 会把 527,672 B 的旧载荷灌进 `/data/local/tmp/own127`，再被 `MainActivity.java:2002-2003` 的 sha 门禁以 `exit 9` 拦下（灌错文件已发生）；7879 走 `pushAsset(svc,"own127_prev",…)`（`1974`），`getAssets().open("own127_prev")` 抛 `FileNotFoundException` → 由 `1933-1934` 兜成 `!! 启动异常`。→ **两条链路全废**。
- **建议修法**：以 `as/` 为唯一载荷源，构建前用 sha256 断言，产物里再校验一遍（脚本已可复用 `pack.py` 的 `as/` 引用）。
- **影响面**：下一次发版；且 3666 会在「已经覆盖了正确的 `/data/local/tmp/own127`」之后才失败，污染现场。

---

## 2. P1 — 功能错误

### P1-1 7879 分支从不调用 `finishSession()` → 必然残留「进行中-…」
- **位置**：`MainActivity.java:1987-1997`（7879 分支）、`1514`（finishSession 定义）
- **证据**：全仓 `finishSession(` 只出现 3 次 —— `1514` 定义、`1825`（recoverLastRun）、`2058`（3666 收尾）。7879 分支 `1992-1997` 只有 `legacyStart → saveLog → return`。
- **现场**：`/sdcard/Download/山茶内核工坊/日志/` 现存 `进行中-20261121-230500-3666.txt`（13,399 B，见 P1-6）。
- **建议修法**：7879 分支 return 前补 `finishSession(parkedZombie?"驻留":sawSuccess?"成功":"失败")`。
- **影响面**：每跑一次 7879 留一个永不改名的文件；且 7879 即便 `gate127 SUCCESS` 也不走 `declareSuccess()`，徽标永远不显示「已接管」。

### P1-2 7879 载荷**完全没有** sha 校验（`wantSha` 传了不用）
- **位置**：`MainActivity.java:1719`（形参 `wantSha`）、`1721-1778`（函数体）
- **证据**：`wantSha` 全仓出现于 `1719 / 1951 / 1954 / 1992 / 2002-2004`，其中 `2002-2004` 属于 **3666** 的 shell 命令；`legacyStart` 函数体（1721-1778）**零引用**。7879 的启动串（1732-1738）只有 `setsid /data/local/tmp/own127 fake nofix`。
- **结论（任务明确要求如实说明）**：**3666 有门禁，7879 无门禁。** 3666 是硬拦截（`if [ "$H" != "$W" ]; then … exit 9`）；7879 会直接执行 `/data/local/tmp/own127` 里当时存在的任何东西。
- **建议修法**：在 1732-1738 的 run 串前插入与 3666 相同的 `sha256sum` 比对 + `exit 9`。
- **影响面**：与 P0-5 / P1-4 叠加 → 用错载荷跑内核写路径（最危险组合）。

### P1-3 su 回退链路同样无校验，且与 Shizuku 链路不同源、不同文件名
- **位置**：`MainActivity.java:2122-2147`（runViaSu）、`2134-2138`
- **证据**：`inner` 只做 `cp/chmod/cd; ./own128 fake nofix`，无 `sha256sum`；shizuku 路径跑 `/data/local/tmp/own127`，su 路径跑 `/data/local/tmp/own128`，而 `saveLog` 仍按 `verChoice()` 去读 `cve-2026-98260.log`（1575-1576）。
- **建议修法**：两条链路统一落地路径与校验。
- **影响面**：无 Shizuku 时的回退通道不可信、且日志可能对不上号。

### P1-4 `unpack()` 按文件名缓存，跨版本污染
- **位置**：`MainActivity.java:2149-2158`（`if (dst.exists() && dst.length() > 0) { … return; }`）、调用点 `1963`、`2131`
- **证据**：两个版本都落到 `getFilesDir()/own128`；缓存判据只有「存在且长度>0」，不校验内容/sha。先跑 3666 再跑 7879（且 `nativeLibraryDir` 里缺库时）会直接复用 3666 的字节。
- **建议修法**：目标文件名带 payload id，或落盘前比对 sha。
- **影响面**：与 P1-2 叠加即「用 3666 的载荷当 7879 跑」。

### P1-5 「实时日志」用 `"wt"` 全量重写 + 单一文件名 → 把真实链路日志覆盖成 UI 噪声
- **位置**：`MainActivity.java:1543-1568`（flushLive）、`1461-1487`（ensureLiveUri，固定 `LIVE_NAME`）
- **证据**（同一文件前后对比）：
  - 23:07：`实时日志-最近一次.txt` = **51,135 B**，内容是 `S4|回收|布种…E4027/E4048/E4047`、`S2|标定|kcore|E2003` 等真实载荷行。
  - 23:15（体检时）：同一文件 = **429 B**，内容只剩 `上次异常已记录 / Shizuku 已授权×3 / 工坊就绪 / 日志已保存`。
- **成因**：会话结束后 `finishSession` 把 `liveUri` 置空（1534），下一次 `flushLive → ensureLiveUri` 又落到同一个 `LIVE_NAME`，且 `openOutputStream(u,"wt")` 先截断。
- **建议修法**：改为 `"wa"` 追加，或每轮独立文件、LIVE 文件只在会话内使用。
- **影响面**：重启/切会话后现场证据被抹掉，排障证据链断裂。

### P1-6 非正常结束时会话文件变成**全 0x00** 且永不改名
- **位置**：`MainActivity.java:1490-1511`（startSession）、`1543-1568`
- **证据**：`进行中-20261121-230500-3666.txt`，13,399 B：
  - `od -An -tx1 -N 48` → `00 00 00 …`（全 0）
  - `tr -d '\000' < f | tr -d ' ' | wc -c` → **0**（去掉 NUL 与空格后无任何内容）
  - mtime 23:05，而设备在 **23:06:17 重启**（`/proc/uptime` 667 s 反推 + 目录里 23:06:40 的「重启」改名文件吻合）。
- **成因（推断，非直证）**：`"wt"` 先截断再写入，写未落盘即掉电；F2FS/ext4 提交了文件长度但数据未落盘 → 全 0。**同一机制也是 P1-5 的根**。
- **建议修法**：写临时文件后原子 `rename`，或先写后 `ftruncate`；启动时扫描并标记/删除孤儿「进行中」。
- **影响面**：崩溃/重启那一轮日志 100% 丢失（这轮恰恰最需要），目录里长期留垃圾。

### P1-7 每行日志写两遍（raw + 叙述），体积翻倍、语义混杂
- **位置**：`MainActivity.java:988`（`narrate` 里 `liveBuf.append(l)`）、`1203`（`emit` 里再次 `liveBuf.append`）
- **证据**：`tail` 实时日志可见成对出现：
  ```
  S4|回收|布种耗时|E4048|plant=1|ok=1|retry=0|el=723
  ④ S4|回收|布种耗时|E4048|plant=1|ok=1|retry=0|el=723
  ```
- **建议修法**：删掉 988 行（只由 `emit` 记账），`narrate` 保留 `flushLive()` 即可。
- **影响面**：与 P1-8 叠加，IO 与文件体积直接翻倍。

### P1-8 `flushLive` 每秒 `new Thread` + 全量 `toString` + 全量写 → O(n²) IO
- **位置**：`MainActivity.java:1544-1548`（1 秒闸门 + 全量拷贝）、`1549-1567`（每次新建线程）
- **证据**：`if (now - lastLiveFlush < 1000) return;` 后 `body = liveBuf.toString()`（1548），再起新线程 `"wt"` 全量写；`liveBuf` **从无裁剪**（对照 `emit` 里 `raw` 有 120000 上限，1220 行）。
- **建议修法**：单线程 + 只追加增量 + 给 `liveBuf` 设上限。
- **影响面**：7879 的 240 秒轮询长跑时 IO/GC 明显；实测 App 空闲 CPU 30.7%（见 P2-1）。
- **附带**：`lastLiveFlush` 也不按会话复位（1459），新一轮第一秒的日志可能被闸门吞掉。

### P1-9 「已补存日志」的提示与事实无关
- **位置**：`MainActivity.java:1826-1828`（recoverLastRun）
- **证据**：`saveLog(...)` 的返回值 `p2` 拿到后**不使用**，无条件 `emit("上次运行因重启结束 · 已补存日志" + …)`；对比 `exportLog()`（1712-1713）按返回值分支是正确写法。
- **建议修法**：按 `p2 != null` 分支文案，并把失败留在 prefs 里下次重试。
- **影响面**：重启后用户以为日志已留存，实际没有。

### P1-10 「中止」对 7879 无效；`stop()` 无条件宣称已回收
- **位置**：`MainActivity.java:217-240`（停止按钮）、`1746-1776`（legacyStart 观察循环）、`2160-2167`（stop）
- **证据**：`legacyStart` 的 `while (System.currentTimeMillis() - t0 < 240000L)` 只 break 于 `sawSuccess || parkedZombie`（1775），**不读 `watchStop`**；`pkill` 之后循环仍会跑满 240 秒并继续 `narrate`。7879 路径**从未给 `rp` 赋值**，`stop()` 里 `if (rp != null) rp.destroy()` 是空操作，却照样 `emit("已中止链路 · 进程已回收")`。
- **建议修法**：`legacyStart` 加 `watchStop` 检查；`stop()` 按实际结果给文案。
- **影响面**：用户以为已中止，在驻留风险下再次启动（撞 P0-1）。

### P1-11 崩溃守卫吞掉全部未捕获异常且不转发，进程变僵尸
- **位置**：`MainActivity.java:302-327`
- **证据**：`Thread.setDefaultUncaughtExceptionHandler` 内只写 `last_crash.txt` + `emit`，**既不调用 `prev` 也不 `Process.killProcess/myPid()`**；`RuntimeInit` 原本的 handler（负责记录 FATAL 并杀掉进程）被替换。
- **现场**：截图 1 首行 `23:15:17 上次异常已记录（last_crash.txt）` —— 代码只有在 `f.exists() && f.length()>0` 时才发这句（324-325），**证明真发生过未捕获异常**，且这次没有出现在 logcat 的 `AndroidRuntime` 里（`adb logcat -d | grep AndroidRuntime` 无本应用记录）。
- **建议修法**：记录后转发 `prev` 或主动杀进程。
- **影响面**：主线程死后进程存活但无 Looper → 黑屏/无响应且不产生 ANR 报告；「本次无崩溃」的判断全部失真。

### P1-12 主线程做阻塞 IPC / 进程调用（ANR 面）
- **位置**：`MainActivity.java:272`（`emit("工坊就绪 · 内核 " + Payloads.uname())`）、`1865`（`Payloads.uname()`）、`1896`（`hasSu()`）、`223`（停止按钮里 `moduleLoaded()`）
- **证据**：`hasSu()` 走 `Runtime.exec("sh -c su -c id")` + `waitFor()`（2109-2119）；`moduleLoaded()` 起 Shizuku 进程并读管道（687-699），却被 UI 线程的停止按钮直接调用；`Payloads.uname()` 是 `ProcessBuilder + waitFor`（`Payloads.java:51-62`）。
- **建议修法**：全部移出主线程，按钮先置灰再异步判定。
- **影响面**：KernelSU 授权弹窗/Shizuku 卡顿时直接 ANR；`start()` 在 UI 线程，用户点「启动链路」就会同步等 `su -c id`。

### P1-13 3666 成功后 `running=false` 但读线程永久阻塞，`IRemoteProcess` 不释放
- **位置**：`MainActivity.java:885`（declareSuccess 里 `running = false`）、`2040-2048`（读循环 + waitFor）
- **证据**：`while ((line = r.readLine()) != null)` 不因 `running=false` 退出；成功后载荷 `pause()` 驻留，线程永久挂在 `readLine`。`rp` 在正常收尾路径上从不 `destroy()`/`close()`。
- **建议修法**：明确「成功后不退出线程」的设计，但把 UI 门闩从 `running` 换成独立的 runSession 状态；`rp` 在收尾路径显式释放。
- **影响面**：与 P0-1/P0-2 叠加可再起一轮；每轮泄漏一个 binder 代理 + 两个线程。

### P1-14 MediaStore 相关路径在 API < 29 上静默失效
- **位置**：`MainActivity.java:1461-1487`、`1490-1511`、`1514-1540`、`1642-1689`（均无 SDK 判断）；对照 `saveLog` 在 `1604` 有 `SDK_INT >= 29` 分支
- **证据**：`MediaStore.Downloads` 是 API 29+ 常量；`minSdk=23`。这些方法整段包在 `catch (Throwable ignored)` 里（1485、1510、1538、1684），`NoSuchFieldError` 被吞 → 用户只看到「没有实时日志、没有进行中文件、改名失败」。
- **建议修法**：统一走一个 `FileProvider`/`getExternalFilesDir` 兼容分支，或在 29 以下明确提示不支持。
- **影响面**：Android 6–9 上日志/会话功能全哑，且没有任何错误提示。

---

## 3. P2 — 资源与性能

### P2-1 两个 70f 模糊图层 + 无限动画：93 MB 图形内存、空闲 CPU 30.7%
- **位置**：`MainActivity.java:506-533`（installGlass，`RenderEffect.createBlurEffect(70f,70f,…)` + 9 秒位移）、`205-215`（statusCard 的 `INFINITE` 位移动画）
- **证据**：`dumpsys meminfo 14297` → `EGL mtrack 23,700 KB`、`GL mtrack 69,316 KB`、`TOTAL PSS 140,870 KB`、`RSS 278,880 KB`、`SwapPss 17,074 KB`；`top -n 1` → 该进程 **%CPU 30.7**；`ps` → `RSS 261,528 KB`，`/proc/14297/task` 39 个线程。
- **建议修法**：把模糊做成一次性静态位图，去掉 `INFINITE` 动画。
- **影响面**：待机耗电、低端机掉帧；39 个线程中部分是 Shizuku/binder 线程池，但持续动画是主要 CPU 来源。

### P2-2 无限动画导致 UI 永远不进入 idle，UiAutomator/Espresso 不可用
- **位置**：`MainActivity.java:205-215`
- **证据**：`adb shell uiautomator dump /sdcard/ui_audit.xml` → **`ERROR: could not get idle state.`**（无 dump 产物）。改用截图 + `res/layout/activity_main.xml` + 代码交叉验证界面元素（见第 5 节）。
- **建议修法**：同 P2-1；测试构建下关闭动画。
- **影响面**：任何依赖 idle 的自动化/无障碍脚本全部失效。

### P2-3 `saveLog` 固定只存最后 400 KB，头部丢失且无提示
- **位置**：`MainActivity.java:1579-1580`
- **证据**：载荷自己的日志 `/data/local/tmp/cve-2026-98260.log` = **471,527 B**（mtime 23:07）；保存出来的 `run-20261121-231534-3666.txt` = **400,106 B**；三个 run 文件都是 400,10x B。→ 每次丢约 71 KB（前 15%，包含 `[check]`/`[base]` 阶段）。
- **建议修法**：分段保存或全量 + 在文件头标注「已截断，丢弃前 N 字节」。
- **影响面**：问题复现时最关键的早期阶段被剪掉。

### P2-4 `shellText` 静默截断 64 KB，且可能截断 UTF-8 多字节
- **位置**：`MainActivity.java:1692-1705`（`while ((n=in.read(b))>0 && total<65536)`，随后 `bo.toString("UTF-8")`）
- **证据**：循环内每次可写 8192 B，总量可达 65536+8192；`new String(byte[],"UTF-8")` 对残缺序列做 U+FFFD 替换，不报错也不标记。`exportDiag` 里 `tail -c 120000` + `tail -c 80000`（1663-1665）远超 64 KB 上限，实际必然被截。
- **建议修法**：用 `CharsetDecoder`（`onMalformedInput(REPLACE)`）并在尾部显式标注截断；或按行读。
- **影响面**：诊断包末尾的符号/日志残缺，且看起来像「本来就没有」。

### P2-5 `exportDiag` 不用 try-with-resources，cacheDir 文件不清理
- **位置**：`MainActivity.java:1666-1668`（`new FileOutputStream` → write → close）、`1679-1682`
- **证据**：无 finally；`f = new File(getCacheDir(), name)` 从不 `delete()`，每长按一次留一个诊断包。
- **建议修法**：try-with-resources + 写完 `delete()`。
- **影响面**：写失败即泄漏 fd；cache 目录缓慢增长。

### P2-6 `saveLog` 未判空流；插入成功后失败会留空行
- **位置**：`MainActivity.java:1610-1618`
- **证据**：`OutputStream os = getContentResolver().openOutputStream(uri); os.write(hb);` —— `openOutputStream` 可返回 null（当 provider 拒绝时），此处直接 NPE 被 `1636` 的 `catch (Throwable)` 吞成 `return null`，同时已插入的 MediaStore 行不删除。
- **建议修法**：判空 + 失败时 `delete(uri)`。
- **影响面**：用户只看到「日志保存失败」，下载目录里多一条 0 B 记录。

### P2-7 `ensureLiveUri` / `startSession` / `flushLive` 跨线程改字段无同步
- **位置**：`MainActivity.java:1455-1459`（字段）、`1475/1484`（工作线程写 `liveUri`）、`1501-1504`（UI 线程写 `liveUri/sessionId`）
- **证据**：只有 `liveBuf` 有 `synchronized`（988/1203/1548）；`liveUri`、`sessionId`、`sessionStart`、`lastLiveFlush` 均无锁、非 volatile，被 UI 线程与 flush 工作线程同时读写。
- **建议修法**：所有会话状态收敛到单线程（或加锁 / volatile）。
- **影响面**：偶发写到上一轮的文件、改名改错对象。

### P2-8 `startSession` 失败时 `finishSession` 会去改「上一轮」的文件
- **位置**：`MainActivity.java:1503-1509`（仅 `liveUri != null` 才写 prefs）、`1518-1522`（失败时回退读 prefs）
- **证据**：`sessionId = ContentUris.parseId(liveUri)` 与 `prefs.putLong("session_id", …)` 都在 `if (liveUri != null)` 内；而 `finishSession` 成功路径才把 prefs 置 `-1`（1535-1536）。若本轮 insert 失败，prefs 里残留的是上一轮的 id。
- **建议修法**：`startSession` 无论成败都写 prefs（失败写 `-1`）。
- **影响面**：改名落到错误的文件（把历史文件改成「本轮失败」）。

### P2-9 `advance()` / `paintStageProgress` 对视图无判空
- **位置**：`MainActivity.java:1276-1279`（`p.setBackgroundResource`）、`1283-1286`（`stage.setText`/`progress.setText`）
- **证据**：同文件 `refreshPills()`（422-423）、`recolor()`（453-461）都有判空，这里没有；异常发生在 `emit` 的 `ui.post` 内 → 走 P1-11 的僵尸路径。
- **建议修法**：加判空。
- **影响面**：布局变体/分区屏下偶发 NPE 直接毁掉界面线程。

### P2-10 `finishSession` 改名失败后无补救
- **位置**：`MainActivity.java:1533-1539`
- **证据**：`int n = …update(...)`；`n <= 0` 时直接掉到 `return null`，而 `liveUri = null; sessionId = -1;` 已在 1534-1536 执行 —— 连重试的机会都没了。
- **建议修法**：失败时保留 session 记录，下次启动重试。
- **影响面**：改名失败即永久留「进行中」（叠加 P1-1）。

### P2-11 死代码 / 空转代码
- **位置与证据**：
  - `MainActivity.java:823-825`：`for (int i = 0; i < stage; i++) { if (i < stage - 1 || true) { } }` —— 条件恒真、循环体空，纯空转。
  - `MainActivity.java:739-749` `remoteSize()` 全仓无调用（`ChainService.java:273` 同名方法同样无调用）。
  - `MainActivity.java:1331-1334` `VER` 与 `VER_SHA`（1308-1311）+ `assets/payloads.json` 三份重复的版本表。
  - `MainActivity.java:857` `successDeclared` 非 volatile，却在读线程与 UI 线程间读写（`223`/`620`/`866`/`996`）。
- **建议修法**：清理空转与重复表，`successDeclared` 加 volatile 或改为 UI 线程独占。
- **影响面**：可读性、以及 `successDeclared` 的可见性竞态。

### P2-12 主题不落盘、不跟随系统
- **位置**：`MainActivity.java:194`（注释明写「只在本次运行内切换，重启回到默认浅色」）、`339`（`darkUI = false`）
- **证据**：`darkUI` 每次 `onCreate` 都重置为 false；`applyTheme()` 不读 `UiModeManager`/`Configuration.uiMode`。
- **建议修法**：落盘 + 支持跟随系统。
- **影响面**：体验；深色用户每次进来被闪一次浅色。

---

## 4. P3 — 体验与规范

### P3-1 `WRITE_EXTERNAL_STORAGE` 是多余权限（任务点名项，结论：应删）
- **位置**：`AndroidManifest.xml:13`
- **证据**：`aapt2 dump permissions installed.apk` 只有 5 条（`API_V23 / RECEIVE_BOOT_COMPLETED / FOREGROUND_SERVICE / POST_NOTIFICATIONS / WRITE_EXTERNAL_STORAGE`）；`dumpsys` 显示 `WRITE_EXTERNAL_STORAGE: granted=false`；而日志文件**确实写成功**（8 个文件在 Download 目录）。→ 应用完全走 MediaStore，该权限在 `targetSdk 34` 下本身也已被系统忽略。
- **建议修法**：删除该行。
- **影响面**：只影响商店审核与用户观感。

### P3-2 `READ_EXTERNAL_STORAGE` 不是清单声明的
- **证据**：`aapt2 dump permissions` 里没有 READ；`dumpsys package` 的 requested 列表里有 —— 这是 PackageManager 因 `WRITE_EXTERNAL_STORAGE` 而追加的 **implied permission**。删掉 P3-1 后它会一并消失。
- **影响面**：无功能影响，但容易被误判为「清单多要权限」。

### P3-3 `OnboardActivity` 是未实现的假流程，且 `exported=true`
- **位置**：`OnboardActivity.java:66-97`（只做 `AdbPair.reachable()` 的 TCP 探测就 `putBoolean("paired", true)`）、`AdbPair.java:11-21`（注释自承「配对握手在后续版本接入」）、`AndroidManifest.xml:47-49`（`exported="true"`，无 intent-filter）
- **证据**：全仓无任何地方读 `paired`；`Integer.parseInt(p)`（77）对非数字端口会抛 `NumberFormatException` 且无 catch。
- **建议修法**：删除或明确标注「未实现」，`exported` 改 false。
- **影响面**：误导用户以为已授权；任意应用可拉起该页。

### P3-4 目录堆积（无保留策略）
- **证据**：`/data/local/tmp` **302 个条目 / 58 MB**（含 8 个 `D2..G8.png` 调试截图共 ~20 MB、`own127b`、`own128`、`98260.log`、`_t.log`、`ksu.log`、`run.log`、`run133.log`、`own127.log`、`own128.log`）；`/sdcard/.../日志` 8 个文件 / 1.5 MB，其中 1 个全 0 垃圾 + 3 个 400 KB 重复。
- **建议修法**：轮转保留 N 个 / N 天；启动时清 `/data/local/tmp` 里自己的历史文件。
- **影响面**：磁盘占用与目录可读性。

### P3-5 版本说明三处不一致
- **位置**：`res/layout/activity_main.xml:166`（`verHint` 静态文案「必选；7879 实测 7946、6638 也可用；3666 未知，可自行测试」）、`MainActivity.java:1401-1406`（菜单里用 `payloads.json` 的 `label/kernel`）、`Payloads.java:15-22`（MAP 第三套内核特征表）
- **建议修法**：单一数据源（`payloads.json`），其余从它派生。
- **影响面**：用户看到的内核说明与实际选中的资产可能对不上。

### P3-6 仓库里没有能复现 `versionCode 95` 的构建脚本
- **证据**：`build_v*.ps1` 最新的是 `build_v29.ps1`（2026-11-09），其注释写 `versionCode 31`，且 `-A (Join-Path $apk "assets_v29")`；全仓 `*.ps1/*.py` 检索 `versionCode 95` / `7.7` / `提权-v7` **零命中**；`assets_v29/own127` 只有 83,520 B（另一代残留）。`out/shancha-提权-v7.7.apk` 与 `out/base.apk` 都是 23:04 产出，产它的流程不在树内。
- **建议修法**：补一个 release 脚本（含 P0-5 的 sha 断言）+ 记录产物清单。
- **影响面**：发版不可复现，出事无法回溯到确定的源码+资产组合。

### P3-7 `payloads.json` 在 `as/` 里是坏的（乱码 + 引号未闭合）
- **证据**：`as/payloads.json` 的 `label` 为 `"3666 路 鏂板唴鏍?,`（GBK 被当 UTF-8 读坏的产物，字符串未闭合 → **不是合法 JSON**）。已装 APK 里那份是干净 UTF-8 且可解析（`ConvertFrom-Json` 通过，2 条）。`Payloads.loadManifest` 解析失败会返回 null（`Payloads.java:45-47`）→ 静默回落到内置 `VER_SHA`。
- **后果**：谁把 `as/payloads.json` 原样拷进 `assets/`，菜单标签变乱码且回落到内置表（行为不变，但 P3-5 的单一数据源改造会被静默废掉）。
- **建议修法**：重建该文件并加编码校验。

### P3-8 `rel` 一个变量被当两种语义用（MediaStore 相对路径 vs 文件系统子路径）
- **位置**：`MainActivity.java:1593 / 1464 / 1496 / 1670`（`rel = DIRECTORY_DOWNLOADS + "/山茶内核工坊/日志"`，无尾斜杠）、`1470`（查询时又补 `rel + "/"`）、`1609 / 1500 / 1674`（写入 `RELATIVE_PATH = rel`）、`1618 / 1622`（拼成 `"/sdcard/" + rel + "/" + name`）
- **证据**：MediaStore 的 `RELATIVE_PATH` 落库后带尾斜杠，所以查询（1470）必须补 `"/"`，而 insert（1500/1609/1674）不能带 —— 同一个字符串被两种规则使用。**返回值本身是对的**：截图 1 显示 `/sdcard/Download/山茶内核工坊/日志/run-20261121-231534-3666.txt`，与 `ls` 完全一致。
- **建议修法**：拆成 `REL_SUB`（无尾斜杠）、`REL_QUERY`（带尾斜杠）、`ABS_DIR` 三个常量。
- **影响面**：无现行缺陷，但这是最容易在下次改动时踩坏的地方（多一个斜杠就静默丢日志）。

---

## 5. 界面元素核对（任务点名项）

`uiautomator dump` 因 P2-2 无法取得 idle，改用 **截图 + layout + 代码** 三方交叉验证：

| 控件 | id | layout | 监听器 | 截图可见 | 可点 |
|---|---|---|---|---|---|
| 版本选择 | `verPick` | `activity_main.xml:149`，`:155 android:clickable="true"` | `MainActivity.java:1344-1349` | ✅「已选 · 3666 · 新内核」 | ✅ |
| 保存日志 | `logSave` | `:250` | `:173-175`（单击）/`:176-178`（长按=诊断包） | ✅「保存」 | ✅ |
| 启动链路 | `start` | `:185` | `:217-219` | ✅ 绿色主按钮 | ✅ |
| 中止 | `stop` | `:197` | `:220-240` | ✅ | ✅（成功/驻留态会主动拒绝，见代码 223-226） |
| 复制 | `copy` | `:209` | `:241-250`（长按=导出日志） | ✅ | ✅ |
| 重启手机 | `reboot` | `:283` | `:251-253` | ✅ 底部整条 | ✅ |
| 六段进度 | `p1..p6` | `:111-116` | — | ✅ 6 个胶囊 | 不适用 |
| 日志滚动区 | `scroll` + `log` | `:262-279` | `installLogScroll()` `:1116-1164` | ✅ | 可滚 |

结论：**界面元素齐全、无缺失、无重叠遮挡**；层级是外层页面 `ScrollView` + 内层 `scroll`（日志区），代码用 `holdPage()` 处理手势冲突（1167-1173）。

---

## 6. 两条链路的隔离与 sha 门禁（任务点名项）

| 检查点 | 3666 → own127 | 7879 → own127_prev | 结论 |
|---|---|---|---|
| 资产选择 | `libown128.so`（`1960`），落 `/data/local/tmp/own127` | `libown128p.so`（`1961`），**同落 `/data/local/tmp/own127`** | 同名不同源 |
| 落盘判据 | `sameRemote()` = md5 比对（`1973`） | 无判据，**强制覆盖**（`1973` 的 `\|\|` 短路） | 7879 必覆盖 |
| sha 门禁 | ✅ shell 内 `sha256sum` 硬比对，不等则 `exit 9`（`2001-2004`） | ❌ **完全没有**（`wantSha` 形参未使用） | **门禁只覆盖 3666** |
| su 回退 | ❌ 无校验（`2134-2138`） | ❌ 无校验 | 两条回退都无门禁 |
| 出错方向 | `assetMd5` 失败→`false`→强制重灌（`753`）；`remoteMd5` 失败→`""`→不等→重灌 | — | 失败方向是**安全**的（宁可重灌） |

**隔离风险结论**：正常路径下（两个 `.so` 都在 `nativeLibraryDir`）两条链路是隔离的，失败方向也安全。真正的串味入口是 **P1-4**（`getFilesDir()/own128` 共用文件名 + `unpack` 只按长度缓存），叠加 **P1-2/P1-3**（无 sha）才会跑错载荷。**7879 路径现在没有 sha 校验，这条要如实记为「未做」。**

---

## 7. 注入面与边界（任务点名项）

- **用户可控输入**：只有「版本选择」（`3666`/`7879`），写入 `SharedPreferences("payload_ver")`，**只用于从 `manifest()` 里匹配 `r[0].equals(c)`**（`1444-1448`），不参与任何命令拼接。→ **无命令注入面**（任务判断正确）。
- 唯一被拼进 shell 的动态值：`wantSha`（来自内置表/`assets/payloads.json`）、`verChoice()`（仅出现在 `echo` 文案里），`path`/`dest` 全是常量。`Payloads.uname()` 的输出只用于显示与 `contains` 判断，不拼命令。
- `exportDiag` 的读取边界：`tail -c 120000` + `tail -c 80000`（1663-1665）→ 实际被 `shellText` 的 64 KB 上限截断（P2-4），**不会**因为大文件 OOM（`ByteArrayOutputStream` 上限约 73 KB）。
- `saveLog` 的边界：`tail -c 400000` → `ByteArrayOutputStream` 约 400 KB，可控。
- `shellText` 的 UTF-8 截断：**会截断**（P2-4 已给证据与修法）。

---

## 8. 问题统计总表

| 档位 | 条数 | 编号 | 一句话概括 |
|---|---|---|---|
| **P0 会崩/会误操作** | **5** | P0-1 … P0-5 | 状态解耦可再启动、门闩不复位、running 可卡死、FGS 无 type 必崩、工作树资产漂移重建即废 |
| **P1 功能错误** | **14** | P1-1 … P1-14 | 7879 不 finalize/无 sha、实时日志被覆盖、全 0 会话文件、日志双写、中止无效、崩溃守卫僵尸化、主线程阻塞、SDK<29 静默失效 |
| **P2 资源与性能** | **12** | P2-1 … P2-12 | 93 MB 图形内存 + 空闲 30.7% CPU、uiautomator 不可用、400 KB 截断、UTF-8 截断、流未关、跨线程竞态、死代码 |
| **P3 体验与规范** | **8** | P3-1 … P3-8 | 多余权限、假 Onboarding、目录堆积、三份版本表、构建不可复现、坏 JSON、路径串语义不一致 |
| **合计** | **39** | — | — |

按「是否阻断发布」再切一刀：

| 分类 | 条数 | 编号 |
|---|---|---|
| 阻断发布（必须修） | 6 | P0-1、P0-2、P0-3、P0-5、P1-1、P1-2 |
| 发版前应修（数据/安全） | 5 | P1-5、P1-6、P1-11、P1-12、P1-14 |
| 可随下一版修 | 20 | P0-4、P1-3、P1-4、P1-7、P1-8、P1-9、P1-10、P1-13、P2-1…P2-12 |
| 择机清理 | 8 | P3-1 … P3-8 |
| **合计** | **39** | 6 + 5 + 20 + 8 |

---

## 9. 体检结论（≤10 行）

1. **当前版本不能按「可发布」签发**：功能主路径（3666）在真机上确实能成功（`E6080 全链成功 @uptime=93.48`），但**状态管理与日志可靠性不过关**。
2. 发布前**必须修 6 条**：`P0-1`（重建后显示待机、可在已接管内核上再启动）、`P0-2`（第二轮门闩不复位→静默失败）、`P0-3`（`running` 可卡死）、`P0-5`（工作树 `assets/own127` 是错载荷，重建即废）、`P1-1`（7879 必留「进行中」）、`P1-2`（7879 无 sha 门禁）。
3. `P0-5` + `P1-2` 是同一个雷的两面：**错载荷 + 无校验 = 用任意旧文件跑内核写路径**，这是本版本最高危的组合，务必两条一起修。
4. `P1-5` / `P1-6` 让「每轮独立日志」的承诺在崩溃场景下失效（实测把 51 KB 真日志覆盖成 429 B，并留下 13 KB 全 0 文件）——排障能力是这类工具的核心资产，建议同批发修。
5. `P0-4`（FGS 无 type）目前只是死代码里的定时炸弹（`auto_run` 无人写入），但为此多申请的 3 个权限应一并回收。
6. 性能上，待机 30.7% CPU / 93 MB 图形内存（P2-1）与「UI 永不 idle」（P2-2）同源，都是那两个无限动画 + 70f 模糊，改起来最便宜、收益最大。
7. 权限侧唯一的实账是 `WRITE_EXTERNAL_STORAGE` 多余（P3-1），删掉即最小化。
8. `uiautomator` 走不通，但界面本身完好：8 个交互元素齐全、可点（第 5 节三方交叉验证）。
9. 设备当前处于「内核已接管 + 载荷驻留（pid 14995）」状态，**我没有触发任何内核动作，也没有清理/重启**，现场原样保留。
10. 复现性欠账（P3-6）：树里找不到产出 v95 的脚本，建议补 release 脚本 + 资产 sha 断言后再谈发版。

---

## 10. 明确无法确认的点（不编造）

| # | 无法确认的内容 | 原因 | 需要什么才能确认 |
|---|---|---|---|
| 1 | `last_crash.txt` 里到底是哪个异常、哪一行 | 应用**不可调试**（`run-as` → `package not debuggable`），无 root 读不到 `files/` | root，或出 debug 签名包后 `run-as cat files/last_crash.txt` |
| 2 | 当前 `SharedPreferences` 真值（`run_pending` / `session_id` / `ran_boot` / `ran_boot_ok` / `payload_ver`） | 同上 | 同上 |
| 3 | 7879 链路在这台内核上到底能不能成功 | 按要求**不点「启动链路」**；且设备已接管、再跑可能 panic | 重启后立刻选 7879 跑一轮（有风险，需授权） |
| 4 | 3666 的 `fix_rc_uid` 写路径概率性 panic、成功后 `pause()` 被杀 UAF 的真实概率 | 需要反复触发内核写路径 | 受控环境多次实验；本次不做 |
| 5 | MediaStore `"wt"` 在 Android 14/17 上是否报特定异常 | 本次设备（Android 15）上**写入是成功的**，只观察到「中断即全 0」的后果，未捕获到 provider 抛错 | 反复 flush 并抓 `logcat -b all` 中的 `MediaProvider`；或在 API 34/36 模拟器上跑 |
| 6 | 旋转/分屏的真实表现 | 未在真机上旋转（避免改变现场）；结论基于代码 + 「新建实例 onCreate、界面归零」的旁证 | 一次旋转即可验证，属于低风险复现 |
| 7 | `out/shancha-提权-v7.7.apk` 到底由哪个脚本/流程产出 | 树内无匹配脚本（P3-6） | 作者提供发版流程，或查 shell 历史 |
| 8 | `进行中-…230500` 全 0 的确切成因（掉电时序 vs FUSE 提交语义） | 需要复现并抓 `ftrace`/`MediaProvider` 日志 | 可控重启实验 |
| 9 | 内层日志滚动与「跟随最新行」在真机手势下的实际体验 | 需要人工触摸操作（属于交互，非只读检查） | 人工试用 |
| 10 | `ChainService` 自启链路的真实行为 | `auto_run` 无人写入，无法在不改 prefs 的前提下触发 | 人工置 `auto_run=true` 后重启（会改设备状态，未做） |

---

## 附录 A：取证命令清单（可复跑）

```bash
# 版本/权限
adb shell dumpsys package com.shancha.ownctl | grep -E "versionCode|versionName|targetSdk|minSdk"
adb shell dumpsys package com.shancha.ownctl | grep -E "granted=|requested permissions"
aapt2 dump permissions installed.apk
aapt2 dump badging installed.apk | grep -E "package:|sdkVersion|uses-permission"

# 运行态
adb shell "pidof own127; pidof own128"
adb shell "grep -c kernelsu /proc/modules"
adb shell "cat /proc/uptime"
adb shell "ps -A -o PID,PPID,STAT,%CPU,RSS,NAME | grep -i ownctl"
adb shell "top -n 1 -b -o PID,%CPU,RSS,CMD | grep -i ownctl"
adb shell "dumpsys meminfo com.shancha.ownctl"
adb shell "ls /proc/<pid>/task | wc -l"

# 日志目录审计
adb shell "ls -la '/sdcard/Download/山茶内核工坊/日志/'"
adb shell "wc -c < '/sdcard/Download/山茶内核工坊/日志/进行中-20261121-230500-3666.txt'"
adb shell "od -An -tx1 -N 48 '/sdcard/Download/山茶内核工坊/日志/进行中-20261121-230500-3666.txt'"
adb shell "tr -d '\000' < '/sdcard/Download/山茶内核工坊/日志/进行中-20261121-230500-3666.txt' | tr -d ' ' | wc -c"
adb shell "ls -la /data/local/tmp/*.log /data/local/tmp/cve* /data/local/tmp/own12*"
adb shell "du -sh /data/local/tmp; ls /data/local/tmp | wc -l"

# 崩溃/异常
adb logcat -d -t 4000 | grep -E "ownctl|AndroidRuntime|Shizuku|FATAL|ANR in"
adb shell uiautomator dump /sdcard/ui_audit.xml     # → ERROR: could not get idle state.

# 载荷资产对照（本地）
Get-FileHash as\own127, as\own127_prev, assets\own127 -Algorithm SHA256
# APK 内对照
[System.IO.Compression.ZipFile]::OpenRead("installed.apk").Entries | ? { $_.FullName -match 'assets/|lib/' }
```

## 附录 B：载荷资产 sha256 对照表

| 位置 | 大小 | sha256 | 判定 |
|---|---|---|---|
| `as/own127`、`as/libown128.so` | 532,280 | `8038F24F…A083C5` | ✅ 3666 正确 |
| `as/own127_prev`、`as/libown128p.so` | 527,672 | `EA780134…5B43D2` | ✅ 7879 正确 |
| 已装 APK `assets/own127`、`lib/arm64-v8a/libown128.so` | 532,280 | `8038F24F…A083C5` | ✅ |
| 已装 APK `assets/own127_prev`、`lib/…/libown128p.so` | 527,672 | `EA780134…5B43D2` | ✅ |
| **`apk/assets/own127`（工作树）** | 527,672 | **`EA91FE67…16E80593`** | ❌ **两个版本都不是** |
| `apk/assets/own127_prev` | — | — | ❌ **不存在** |
| `apk/assets_v29/own127` | 83,520 | （另一代残留） | ❌ 无关 |
| `/data/local/tmp/own127`（设备上当前） | 532,280 | （mtime 23:03） | ✅ 与 3666 一致 |
| `/data/local/tmp/own128`、`own127b` | 527,672 | | 旧代残留 |

## 附录 C：本次体检的临时取证文件（可删）

`work/vivo/dev/_audit_tmp/`：`installed.apk`（1.73 MB）、`screen.png`、`screen2.png`、`ui_audit.xml`（dump 失败未生成）。
未在设备上留任何文件（`/sdcard/ui_audit.xml` 已被 `rm`）。
