# vivo X200s (PD2415M / V2458A) 临时 Root 与 KernelSU 越狱模式 —— 项目报告

> 设备：vivo X200s（`PD2415M` / `V2458A`，内核 `6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k`）
> 漏洞：CVE-2026-98260（posix-cpu-timers UAF → `rb_erase` 8 字节任意零写）
> 结果：**临时 root（内存态）+ kernelsu.ko 成功加载 + 官方管理器显示「工作中 [越狱模式]」**
> 性质：不写分区、不解锁 BL，**重启即失效**

---

## 1. 最终成果

| 项目 | 状态 | 证据 |
|---|---|---|
| 临时 root（真内核 cred） | ✅ | `Uid: 0 0 0 0`、`CapEff: 000001ffffffffff`、`Seccomp: 0`、kernel 域、permissive |
| `init_module` 通过厂商拦截 | ✅ | `[al] init_module rc=0 errno=0` |
| kernelsu 模块 | ✅ | `/proc/modules` 第 1 行 `kernelsu 180224 0 - Live 0x0 (O)` |
| 管理器识别 | ✅ | 官方 KernelSU：**工作中 [越狱模式] · 版本 32680-5 · LKM**（附红横幅要求管理器 ≥32680） |
| 一键工具 | ✅ | `work/vivo/ksu_load/dist/KsuLoad.exe`（内置 own127 + ko + 脚本，预检 + 实时日志 + 中文收尾） |

---

## 2. 遇到的困难与解决（按时间顺序）

| # | 困难 | 根因 | 解决 |
|---|---|---|---|
| 1 | 利用链随机 panic | ① 清 `android_rvh_commit_creds.funcs` 后其 traceiter 无 NULL 检查；② trace ring 截断导致 victim 索引错位 | 去掉该 tracepoint 的 disarm；用 `victim_idx = VICTIM_IDX - (NTIMERS - nrec)` 修正 |
| 2 | fake cred 装不上 / child 被杀 | plant 命中率与 ring 状态相关 | 加 plant 重试、`fake nofix` 跳过第二次 plant（实测 `rb_erase` 写已把 uid/gid 置 0） |
| 3 | `init_module` 一直 EPERM | 厂商 `hooks_defend` 在 `load_module` 上挂 kprobe，命中失败就改返回值并跳过 | 见第 3 节 |
| 4 | sysfs 关不掉拦截器 | 13 个属性中关键项有 **write-once 原子字**，开机守护进程已写死 | 不写 sysfs，直接改内存里的判定位 `g(7)` |
| 5 | 白名单接口被卡 | `khs_num`/`write_hash` 被 `g(7)=insko_dfd_on != 1` 限制 | 先 plant 清 `g(7)`，再写白名单 |
| 6 | 内核读（kread）不稳 | 用全局 trace 环，被 exploit 自己开的 kmem 事件洪泛挤掉记录（自检 21/50、0/50） | 切到**私有 trace instance** `/sys/kernel/tracing/instances/kr` |
| 7 | 定位 hooks_defend 失败 | `kread` 不稳时走链表会读垃圾 | 自检不过就拒绝走查（保护逻辑），并先修 kread |
| 8 | 管理器不认模块 | 官方管理器 32569 低于模块 uapi 32680 | 需装 ≥32680 的官方管理器（SakiSU/vivo 专版是不同 fork，不认） |
| 9 | 一键脚本第二次跑失败 | 一次开机只能一次；kread 抖动 | 失败自动重启重试；一次开机一次 |

---

## 3. 反模块安装（hooks_defend）——完整细节

### 3.1 它是什么
- 开机约 13 秒加载（第 443/637 个模块），`[permanent]`（无 exit，**无法 `delete_module`**）；
- 文件不在任何分区上：来自 **vendor_boot ramdisk（LZ4-legacy cpio）** 的 `lib/modules/hooks_defend.ko`（65616 B，带 .symtab）；
- `.rodata` 用差分加密，已离线解码（`dev/dec_ro.py`）；
- 注意：该 ko 构建 `g64697b1fe5e3` 与设备 `g3b723d0e8507` 同源不同次，**符号布局可用于分析，但运行时数据要现场读**。

### 3.2 拦截原理
```
hooks_defend 用一次性 register_kprobe 拿 kallsyms_lookup_name
  → 在 load_module 注册 kprobe
  → pre_handler(.text+0x1e90) 依次检查：
      (1) .cs[0] == .cs[0x16c] == 0xdeadbeef
      (2) .cs+8 指向的 24 字节 key 与 .cs+0x10/0x20/0x30 的副本自洽
      (3) 判定 aec()：
            sum(g0..g4)&0xff==0 ? g(8)
          : (def_on==1 ? g(8) : 1)        // 1 = 放行
      (4) 否则查白名单：SHA256(模块镜像)[0:8] 必须在
          *_.data._ka 的有序 u64 数组里（魔数 0xcafebabe）
  → 未命中：regs[0]=-1; regs->pc=x30(LR); return 1
  → load_module 被跳过 ⇒ init_module 返回 -EPERM
```
对应 kmsg：`hks-dfd: kh_in_ret=0, 162`（162 是源码行常量）、`hks-dfd: phlm num--=1011,pid,comm`、`hks-dfd: phkpt num--=502,pid,ksud`。

### 3.3 为什么“关不掉”
- `/sys/kernel/bsp_security/` 的 13 个属性里，`unlocked / compile_mode / rem_authed / em_authed / vroot_authed / insko_dfd_on` 的 store 有 **attr+0x20 的 write-once 原子字**，开机守护进程已各写一次（写 0）并封死 → 再写一律 EPERM；
- `def_on` 能写只是因为它的自定义 store（`.text+0x484`）漏了 write-once 判断（厂商 bug）；
- `g(8)` 只能由 `vusb_msg` 写入，需要 **vivo RSA 签名消息** → 配置放行分支不可用。

### 3.4 我们的绕过（四步）
1. **拿真 root**：fake-cred 链（见第 1 节）。
2. **找 hooks_defend 基址**：`modules` 链表（`0xffffffc0821ec498 + slide`，list@8、name@24）→ 命中；再读 `struct module.mem[MOD_DATA]`（BTF：mem@0x1c0、entry 0x48、base@0/size@8）→ `.data` 段。
   - 校验：`data_base <= mod < data_base+size`（不能用“是否落在 vmlinux 镜像区间”，模块内存会落在该区间内被误判）。
3. **绕过 write-once**：`.cs` 用双 `0xdeadbeef` 魔数自识别 → 读每 boot 随机的置换表 `perm[0..13]` → `g(i) = .cs[0x140 + perm[i]]` → 用 UAF plant（任意地址 8 字节零写）清 `g(7)`（=`insko_dfd_on`），**完全不碰 sysfs**。
4. **用厂商自己的白名单接口**：`khs_num=1`（分配 1 个 u64）+ `write_hash=SHA256(绑定后镜像)[0:8]`（原生小端 u64）→ 发布新 `_ka` 白名单，含我们的哈希 → `init_module` → pre_handler 命中 → 放行 → `rc=0`。

### 3.5 关键数据（本次实测）
```
MOD_DATA = 0xffffffd7aed72000 size 0x2000
.cs       = MOD_DATA + 0
perm[0..9]= 00 02 04 0d 07 0a 0c 01 03 0b   perm[7]=1
g(7)      = .cs + 0x140 + 1 = 0xffffffd7aed72141（对齐到 ...140 后 plant）
image sha256[0:8] = 367b933802edc537（len 330664）
khs_num: 364 → 1     init_module rc=0
```

---

## 4. 已排除的思路（负结果，避免重复踩坑）

| 思路 | 结论 |
|---|---|
| 改 SELinux permissive 再加载 | ❌ permissive 下仍 EPERM（不是 SELinux 门） |
| 补全 caps / 改 uid | ❌ 已 `CapEff=0x1ffffffffff`、uid 0 |
| 模块签名强制 | ❌ `is_module_sig_enforced` 反汇编就是 `return 0` |
| 找 load_module 入口 kprobe 并清 pre_handler | ❌ 全 kprobe 表 dump 无此项（M3 那套是 6.12.58 的） |
| 截断 module notifier 链 | ❌ 成功截断 `trace_module_notify` 后仍 EPERM |
| 改进程名（init/vold/…） | ❌ 7 个名字全失败 |
| 卸载 hooks_defend | ❌ `[permanent]`，EBUSY |
| ogki tracepoint funcs 指针 | ❌ 实测全为 0（不是它） |
| 抢在 hooks_defend 加载前 init_module | ❌ uptime 12.96s 时 637 个模块已全加载，而链需 ~25s 才拿到 root |
| 写 sysfs 解锁 | ❌ write-once 封死（insko_dfd_on=1 写不进） |

---

## 5. 注意事项与风险

1. **临时性**：root 与模块都在内存，重启即消失；不能当持久 root 用。
2. **一次开机一次**：fake-cred 父进程必须 park 住伪造页；`.lock2` 占用，重复跑会失败——先重启。
3. **设备会自发重启**：链路约 50% 概率在 fake-cred 阶段 panic；脚本已内置“失败自动重启重试一次”。
4. **kread 依赖 tracefs**：必须 `/sys/kernel/tracing` 存在；且必须走**私有 instance**，否则被系统事件洪泛挤掉。
5. **符号必须匹配**：所有偏移（`modules`、`mem[]`、`.cs`、`perm`、`g(i)`、白名单接口）都针对 `6.6.127-android15-8-g3b723d0e8507`；换内核必须重新推导。
6. **管理器版本**：模块 uapi 32680-5，官方管理器需 **versionCode ≥ 32680**，否则有红横幅（功能不受影响）。
7. **别在失败后连跑**：会撞锁/残留状态，先 reboot。
8. **SELinux 会被 vivo 恢复**：permissive 只维持很短时间，不要依赖它做后续操作。
9. **`/sys/module/kernelsu` 不存在**：prebuilt ko 隐藏了 sysfs 目录，不影响 `/proc/modules` 与 prctl 接口。

---

## 6. 对其他机型的启发（重点：论坛的 PD2436）

### 6.1 方法论（可直接迁移）
这次的关键不是“找到某个地址”，而是**一套定位厂商拦截器的方法**：

1. **先确认它是不是内核模块**：`/proc/modules` 里找可疑名字（`hooks_defend`、`common_hooks`、`*_hook_*`、`*_security*`）；`delete_module` 试探 `[permanent]`。
2. **离线拿模块**：如果文件不在分区上，去 `vendor_boot.img` 的 ramdisk 里找（LZ4-legacy cpio / gzip）；`.rodata` 可能被差分加密，用日志里的格式串反推解密。
3. **定位钩子类型**：kprobe（查 `kprobe_table`）、notifier（查 `module_notify_list`）、tracepoint funcs（查 `__tracepoint_* + 0x48`）、还是 sysfs/配置表。
4. **找“判定位”而不是关钩子**：优先找白名单/开关表；被 write-once 封死就找它背后的内存字段，用任意零写清理。
5. **用厂商自己的接口放行**：如果存在 `*_num`/`*_hash`/`*_add` 这类“追加白名单”接口，把目标模块的哈希/签名塞进去，比硬关更稳。

### 6.2 在 PD2436 上要重新确认的清单
| 项 | 为什么 | 怎么查 |
|---|---|---|
| 内核版本与 KMI | 所有偏移都绑定内核 | `uname -r`；与符号表比对 |
| 拦截模块名/是否存在 | PD2436 可能用别的模块名 | `cat /proc/modules`、`ls /sys/module` |
| 钩子类型 | 可能不是 kprobe | kprobe 表 dump、notifier 链、tracepoint funcs |
| `.cs` 布局与魔数 | 不同构建可能改魔数/偏移 | 读 `.data` 找 `0xdeadbeef` 对 |
| `perm[]` 置换表 | 每 boot 随机、长度可能不同 | 读 `.cs+0x14e..0x15b`，用 `g(i)=.cs[0x140+perm[i]]` 验证 |
| 白名单接口是否同样无 write-once | 这是可复用的关键 | 逐个写 `/sys/kernel/bsp_security/*`，看哪些返回 EOK |
| 白名单哈希算法 | 不一定是 `SHA256(image)[0:8]` | 反汇编 pre_handler 的 hash 调用与比较长度 |
| root 链是否可用 | KASLR/slide/符号都不同 | 先做 slide 自校验（写 `selinux_state` 看 enforce 变 0） |

### 6.3 给 PD2436 的具体建议
1. **先做只读侦察**（不需要 root）：`/proc/modules`、`/sys/module/*/sections`（若可读）、`/sys/kernel/*` 下可疑目录、dmesg 里的厂商日志前缀（如 `hks-dfd`）；
2. 如果 PD2436 上同样存在 `hks-dfd` 与 `hooks_defend`，**很可能同源**：按本文第 3 节流程，先尝试找 `.cs` 双魔数 → `perm[7]` → `g(7)` → `khs_num`/`write_hash`；
3. 如果 `.cs` 魔数不同，改从**格式串**入手：在 `.rodata` 里搜 `"hks-dfd"`/`"kh_in_ret"`/`"phkpt"`，定位引用它的函数，再反推判定位；
4. **别直接套本机地址**：`modules`、`mem[]`、`g(i)` 全部是“符号 + 偏移 + 现场读”，换机型必须重新取；
5. 管理器选择：优先用**与所加载 ko 同版本**的官方 KernelSU（uapi 匹配才会显示越狱模式）；SakiSU/vivo 专版是不同 fork，不一定认。

### 6.4 这套方法为什么有普适性
- 厂商反模块安装通常只有三种落点：**kprobe/notifier/tracepoint 钩子**、**sysfs 开关**、**白名单表**；
- 我们的做法是“**读（kread）→ 定位 → 最小写（plant）→ 走厂商合法接口**”，不依赖具体地址，只依赖“能拿到任意读 + 任意零写”这两个原语；
- 只要目标机型也有一个可用的任意零写漏洞（UAF/越界写等），这套流程就能复制。

---

## 7. 产物与复现

### 7.1 目录
```
work/vivo/
├── own127(.c)                  # 最终利用 + 打门 + 加载
├── ksu/kernelsu_patched.ko     # 已离线绑定符号的 LKM
├── ksu_load/                   # 一键工具
│   ├── dist/KsuLoad.exe        # 单文件 EXE（内置全部）
│   ├── load_ksu.ps1 / run_ksu.sh / chk_ksu.sh
│   └── README.md
├── getroot/                    # 临时 root 工具（另一条线）
├── dev/                        # 各阶段结果、截图、日志
└── STATUS.md / HANDOFF.md      # 过程记录
```

### 7.2 一键复现
```powershell
双击 work\vivo\ksu_load\dist\KsuLoad.exe
# 或命令行
.\KsuLoad.exe            # 预检 → 重启 → 运行 → 实时日志 → 中文结果 → 按任意键退出
.\KsuLoad.exe --check    # 只预检
.\KsuLoad.exe --nopause  # 自动化模式
```
预检会拦：adb 未授权、型号不符（需 V2458A / PD2415）、内核不符（需 6.6.127-android15-8-g3b723d0e8507）、无 tracefs。

### 7.3 成功标志
```
[kr] selftest 50/50 ok
[kw] .cs at MOD_DATA+0 (both magics ok)
[kw] g(7) cleared   insko_dfd_on show='0'
[al] khs_num now='1'
[al] init_module rc=0 errno=0
/proc/modules: kernelsu 180224 0 - Live 0x0 (O)
管理器：工作中 [越狱模式] · 版本 32680-5 · LKM
```

---

## 8. 附录：关键常量（本机，static 地址需加 slide）

| 符号/偏移 | 值 |
|---|---|
| `modules` 链表头 | `0xffffffc0821ec498` |
| `struct module`：state/list/name/taints/refcnt | `0` / `8` / `24` / `1144` / `1472` |
| `struct module.mem[]` | `0x1c0`，entry `0x48`，base@0, size@8 |
| `MOD_DATA` | 索引 1 |
| `.cs` 魔数 | `.cs[0] == .cs[0x16c] == 0xdeadbeef` |
| `perm[]` | `.cs[0x14e .. 0x15b]`（14 字节） |
| `g(i)` | `.cs[0x140 + perm[i]]` |
| `init_module` 白名单哈希 | `SHA256(image)[0:8]`，原生小端 u64 |
| `__tracepoint_android_rvh_ogki_audit_log_module_sign` | `0xffffffc08230a5f0`（funcs 实测为 0，不是门） |
| `capable` | `0xffffffc0800c09c8` |
| `kprobe_table` | `0xffffffc08237ec80` |
| `module_notify_list` | `0xffffffc0821ec4a8`（head@+0x40） |

---

*文档由本次会话（Lead + 4 个子智能体协作）整理；所有结论均来自真机日志，证据见 `work/vivo/dev/`。*
