# HANDOFF — vivo X200s (PD2415M / V2458A) 临时 root + KernelSU

最后更新：2026-11-02 10:2x（会话交接）
设备序列号：10AF5S06220034H（adb 路径 `C:\platform-tools\adb.exe`）
内核：`6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k`

## 目标
1. 用 CVE-2026-98260 拿到临时 root（**已达成**）；
2. 加载 kernelsu.ko，让 KSU 管理器显示“越狱模式”（**未达成，被 vivo hks/hooks_defend 拦**）。
   不需要 BL 解锁、不写分区；重启丢失。

## 已达成 / 已验证
- **临时 root 链可用**（own121 / own122 系列）：
  `slide 自校验 → __tracepoint_sys_exit.funcs 清零 → fake cred（UAF plant）→ fake_uid 修复 → 唤醒 child（uid=0/euid=0）→ permissive → worker（真 cred：uid 0 + CapEff 0x1ffffffffff + kernel 域 sid=1）`
- **root shell（own121）可用**，一次开机一次：
  `sh /data/local/tmp/getroot.sh start|cmd '...'|shell|status`
  （注意：exec `/system/bin/sh` 之后 CapEff=0，只有 uid 0；强 root 只在 exec 前的 worker）
- **真 root 证据**：/proc/self/status Uid 0 0 0 0、CapEff 000001ffffffffff、Seccomp 0、写 selinux enforce、读 /data/vendor/aee_exp、复制 364 个 /vendor/lib/modules/*.ko。

## 当前卡点：模块加载被拦
`init_module`/`finit_module` 一律 `EPERM`，内核日志：
```
hks-dfd: kh_in_ret=0, 162
hks-dfd: phlm num--=1011,<pid>,<comm>      （我们自己的 binary）
hks-dfd: phkpt num--=502,<pid>,ksud        （管理器的 libksud）
hks-dfd: phmdop num++, kra=2, krsaved=2, 718   ← 最新发现，最可疑
```
已排除：SELinux（permissive 仍 EPERM）、能力（全满）、签名强制（`is_module_sig_enforced` 反汇编=return 0）、load_module 入口 kprobe（全 kprobe 表 dump 无此项）、module notifier 链（截断 trace_module_notify 后仍 EPERM）、comm 名字（7 个名字全失败）、ogki tracepoint funcs（**全为 0**）、直接卸载 hooks_defend（`[permanent]`，EBUSY）。

## 关键结论（最新一轮）
- `hooks_defend`（36864 B，`[permanent]`，srcversion `2FC864A70E7AF604CF74112`，从 initramfs 加载，磁盘上无 .ko）是拦截者；
- 论坛线索“一个指针（不是 vr.ko）”：目前最可能是 hooks_defend 里 `phmdop`（num/kra/krsaved）这份记账/规则数据；
- 内核符号（static，加本次 slide）：
  - `modules` 链表头 = `0xffffffc0821ec498`
  - `struct module`：state@0、list@8、name@24、taints@1144、refcnt@1472
  - `__tracepoint_android_rvh_ogki_audit_log_module_sign` = `0xffffffc08230a5f0`（+0x48 是 funcs，实测为 0）
  - `load_module` = `0xffffffc08017d51c`（2 个调用点：`0xffffffc08017c200`、`0xffffffc08017c4b0`）
  - `capable` = `0xffffffc0800c09c8`、`kprobe_table` = `0xffffffc08237ec80`、`module_notify_list` = `0xffffffc0821ec4a8`（head@+0x40）
- `kptr_restrict` = 2，root 也写不进（rc=1）；`/sys/module/*/sections/*` 全 0。

## 工作目录与产物（work/vivo/）
| 文件 | 用途 |
|---|---|
| `own121` | root shell 版（fork 后再 setresuid，避免 put_cred 引用下溢） |
| `own122` | gate 工作版：kprobe dump + notifier 截断 + ogki funcs 探针 + manager 链（system→fork+execv 已修） |
| `own110/106/105/…` | 各阶段实验体 |
| `getroot/getroot.sh` | 设备端 root shell 脚本（已去掉 mkfifo，改 tail -f 管道；EXPLOIT 默认 own121） |
| `getroot/getroot.bat/.ps1/README.md` | Windows 封装 |
| `ksu/kernelsu_patched.ko`、`ksu/ksyms_table.h` | 离线绑定符号的 LKM |
| `managers/*_arm64.so` | 三个管理器的 libksud.so（官方/vivo 专版/SakiSU） |
| `vmlinux.elf`、`vmlinux.btf` | 与运行内核一致的符号 |
| `STATUS.md` | 中文状态记录（§34/§35） |
| `/data/local/tmp/cve-2026-98260.log` | **设备端权威日志**（fsync，跨重启保留） |

## 编译命令（NDK）
```
$d = C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\vivo
$ndk = C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\ndk\android-ndk-r27
$cc  = $ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd
& $cc -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function "$d\ownNNN.c" -o "$d\ownNNN"
& $ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe --strip-all "$d\ownNNN"
```
（TEMP/TMP/TMPDIR 指到 work/vivo/tmp）

## 设备纪律（重要）
- 用 `.sh` 脚本上机，避免 PowerShell 引号吃掉 `[ ] | $`；
- 每次实验**先 reboot**，`sys.boot_completed=1` 后 2-3 秒内跑；等待≤60s，命中标记即停；
- 设备可能自己重启：命令用 `adb wait-for-device`，失败先 reboot 不要连跑；
- 一次开机只能跑一次利用链（fake 页要被 parked 父进程持有，`.lock2` 占用）；
- 日志以 `/data/local/tmp/cve-2026-98260.log` 为准。

## 下一步（按顺序）
1. **own123**：在 own122 的 gate 里加 `modules` 链表遍历（伪代码见 STATUS §35），用 kread 找出 `hooks_defend` 的模块地址：
   - `head=0xffffffc0821ec498+slide`，节点 list 在 mod+8，name 在 mod+24；
   - 命中后在 mod+0x80..0x400 每 8 字节读指针，若指向模块区且首个 4 字节 == `0xd503233f`（paciasp）则为 `.text` base。
2. 用 base 在模块 `.rodata/.data` 里找 `"hks-dfd"` 字符串引用与 `phmdop` 的三个整数字段（kra=2, krsaved=2）；
3. 用 plant（已有的任意地址 8 字节零写）清/改这些字段或判定函数指针 → `init_module` 验证；
4. 成功后用管理器自己的 libksud 加载（版本匹配），确认 KSU 显示“越狱模式”；
5. 若 `phmdop` 不是门：改扫 hooks_defend `.text` 里 init 路径上的 hook 注册（ftrace_ops->func / LSM hook 列表项 / 规则表指针）。

## 交接后更新（2026-11-02 10:5x）
- **hooks_defend.ko 已离线提取**：`vendor_boot_30.img` ramdisk 是 LZ4-legacy cpio，内含 `lib/modules/hooks_defend.ko`（65616 B，带 .symtab）；其 .rodata 差分加密已解码（`dev/dec_ro.py`）。构建 `g64697b1fe5e3` vs 设备 `g3b723d0e8507`（同源不同构建），13 个 sysfs 属性名与设备一致。
- **EPERM 机制**：hooks_defend 在 `load_module` 上注册 kprobe，pre_handler（.text+0x1e90）校验后查白名单（`kh_in_ret`，二分查找 `.data._ka`）；未命中则 `regs[0]=-1; regs->pc=LR; return 1` → 跳过 load_module → -EPERM。对应 kmsg `kh_in_ret=0, 162` / `phlm num--=1011,pid,comm`。
- **绕过（无需 kread/plant）**：模块暴露 `/sys/kernel/bsp_security/` 13 个 0600 root 属性，store 是裸 `kstrtou8` + 单字节写配置数组，无 capable 检查。写 `def_on=0` + `unlocked=1`（或 `compile_mode=1`）让判定函数走放行分支。**own124** 已实现并推到设备（`/data/local/tmp/own124`、`run124.sh`）。
- **kread 澄清**：原语可用（own123 run 2 连续 30 轮读到真实模块链表，名字与 /proc/modules 一致）；失败原因是 exploit 全局开启 kmem 事件导致共享 ring 洪泛、krN 记录被丢。v3 改用私有 trace instance `/sys/kernel/tracing/instances/kr`（已编译未测）作为模块遍历的回退方案。
- 团队任务：task-1 完成（负结果：无 base）；task-2 = own124 sysfs 绕过 + init_module + 管理器链，由 hks-analyst 执行中。

### 新线索：hooks_defend 是晚加载模块（竞态窗口）
own123 的 walk 实测：gate 时刻 /proc/modules 只有 ~160 个模块，**hooks_defend 不在其中**（全量开机后它是第 443/444 个，共 637/653）。而 walk 读到的名字/顺序与 /proc/modules 完全一致，所以结论可信。
⇒ 开机早期存在一个 **hooks_defend 尚未加载** 的窗口；此刻直接 `init_module` 不会触发它的 kprobe。
own124 的 gate 应先查 /proc/modules：
- 无 hooks_defend → 立刻 init_module（抢窗口，先别写 sysfs）；
- 有 hooks_defend → 走 bsp_security def_on=0 + unlocked=1 的 sysfs 绕过。
