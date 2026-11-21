# CRED_FIX — cred 阶段离线定位与修复（own127.c → own131.c）

> 全程离线：未连接手机、未使用 adb、未 reboot。所有结论来自本地静态反汇编 + 本地独立编译。
> 参考样本 `（本地样本）`（参考实现体积，sha256 `参考实现…C69C4E6`）为只读，未修改。

---

## 0. TL;DR

**根因是「call-site 低 21 位常量」这一维错了，而且只错这一个字面量：**

| 维度 | 参考实现（能跑） | own127.c（我们的） | 判定 |
|---|---|---|---|
| `EV_CACHE_ALLOC` type | `0x10d` (269) | `269` | ✅ 一致 |
| `ev.pid` | `== 子进程 pid`（严格相等） | `!= p && != 0` 才跳过（放行 pid==0） | ⚠️ 我们更宽 |
| `ev.req` | `0xb8` | `CRED_REQ 0xb8` | ✅ 一致 |
| `ev.alloc` | `0xc0` | `CRED_ALLOC 0xc0` | ✅ 一致 |
| **`ev.site & 0x1fffff`** | **`0xe5770`** | **`CRED_SITE_LOW21 0xe5754`** | ❌ **差 0x1c** |

`0xe5770 - 0xe5754 = 0x1c (28 B)`，正好等于目标内核 `prepare_creds` 相对旧内核的
`.text` 内漂移 `+0x1c`（见 §2.3）。site 对不上 → `matches=0` → `R=0` → 父进程根本不进入
`poll()`，于是同一行日志里 `hello=0`（不是 hello 协议坏了，是压根没读）。

修复后 `own131` 的匹配链与 参考实现 **逐指令同构**，常量、掩码、fd、超时全部对齐（§6）。

> **第二轮（§7）** 把其余会漂移的常量一次核完，产出 **`own131b`**
> （528,248 B，sha256 `（已隐去）`）：
> cred `0xe5770` + timer `0x198000` + gate 三常量；全程序 A/B 证明只有 `leak_cred`/`run_plant` 两个函数变了。

---

## 1. 根因（哪一维、为什么）

cred 阶段父进程只从 trace 环形缓冲里挑一条记录当作子进程的 `cred`：

```
type==EV_CACHE_ALLOC && pid==child && req==0xb8 && alloc==0xc0 && (site & 0x1fffff)==SITE_CONST
```

前四维在我们的源码/旧二进制里都能对得上（旧编译里 pid 也是严格相等），**只有 `SITE_CONST` 是旧内核的值**：

* 我们的 `own127.c:130` → `#define CRED_SITE_LOW21 0xe5754UL`
* 目标内核实测/参考二进制 → `0xe5770`

`site` 是内核 `_RET_IP_`（`kmem_cache_alloc` 的返回地址），KASLR slide 按 2 MB 对齐，
所以 `& 0x1fffff`（低 21 位）是 slide 不变量、是纯链接期量。内核一换，这个量就变；
旧值 `0xe5754` 在新内核上永远匹配不到任何记录 → `matches=0`。

> 与我们自己的文档 `dev/OWN128_NEW_KERNEL.md` §4.1 完全一致：
> `prepare_creds+0x20（cred_jar 分配点）: low21 0xe5754 → low21 0xe5770`，
> 且该文档记录了设备实测 `[cred] site_low=0xe5770`。

---

## 2. 证据（反汇编片段 + 偏移）

符号已 strip，函数靠字符串 xref 定位（`adrp+add` 解析脚本见 `dev/re_cred/analyze.py`）。

### 2.1 参考实现 的 cred 匹配链（`leak_cred`，函数 0x229688–0x229a58，长 0x3d0）

`.text` 映射：vaddr = 文件偏移 + `0x204000`（`.text` @ vaddr `0x221800` / off `0x1d800`）。

```
; 循环遍历 parse_events() 结果，步长 0x40（= sizeof(struct ev)）
  229910: ldr  w9,  [x8, x19]      ; ev->type        (rec+0x00)   文件 0x25910
  229914: cmp  w9,  #0x10d         ; EV_CACHE_ALLOC = 269
  229918: b.ne 0x229904
  22991c: add  x9,  x8, x19
  229920: ldr  w10, [x9, #0x4]     ; ev->pid         (rec+0x04)
  229924: cmp  w10, w24            ; w24 = fork() 返回的子进程 pid —— 严格相等，无 pid==0 放行
  229928: b.ne 0x229904
  22992c: ldr  x9,  [x9, #0x18]    ; ev->req         (rec+0x18)
  229930: cmp  x9,  #0xb8          ; CRED_REQ
  229934: b.ne 0x229904
  229938: add  x9,  x8, x19
  22993c: ldr  x10, [x9, #0x20]    ; ev->alloc       (rec+0x20)
  229940: cmp  x10, #0xc0          ; CRED_ALLOC
  229944: b.ne 0x229904
  229948: ldr  x9,  [x9, #0x8]     ; ev->site        (rec+0x08)   文件 0x25948
  22994c: mov  w10, #0x5770
  229950: movk w10, #0xe, lsl #16  ; w10 = 0x000e5770
  229954: and  x9,  x9, #0x1fffff
  229958: cmp  x9,  x10
  22995c: b.ne 0x229904            ; ← 这一条 cmp 就是我们的整条链断掉的地方
```

匹配成功后的取值与日志（`R = ptr`，最后一次命中覆盖）：

```
  229960: add  x8,  x8, x19
  229964: add  w21, w21, #0x1      ; nmatch++
  229968: mov  w3,  #0x5770        ; 日志里打印的 site_low（= 0xe5770）
  22996c: ldr  x2,  [x8, #0x10]    ; ptr
  229970: adrp x0,  0x201000 / add x0, x0, #0x75d   ; "[cred]   match#%d ptr=%#llx site_low=%#llx"
  ...
  229990: ldp  x27, x23, [x9, #0x8]  ; x27 = site, x23 = ptr(R)
  229998: ... "[cred] attempt=%d child=%d matches=%d"
  2299b0: cbz  x23, 0x229a08         ; R==0 → 不 poll，直接失败日志
```

### 2.2 同一段在我们两个二进制里

旧编译 `work\vivo\own127`（528,952 B，sha256 `856382C1…`）——**结构和参考一致，常量是旧值**：

```
  2281b4: ldr  w9,  [x8, x19]      ; type
  2281b8: cmp  w9,  #0x10d
  2281c0: add  x9,  x8, x19
  2281c4: ldr  w10, [x9, #0x4]     ; pid
  2281c8: cmp  w10, w24            ; 严格相等（旧编译没有 pid==0 放行）
  2281d0: ldr  x9,  [x9, #0x18]    ; req
  2281d4: cmp  x9,  #0xb8
  2281e0: ldr  x10, [x9, #0x20]    ; alloc
  2281e4: cmp  x10, #0xc0
  2281ec: ldr  x9,  [x9, #0x8]     ; site
  2281f0: mov  w10, #0x5754        ; ← 0xe5754
  2281f4: movk w10, #0xe, lsl #16
  2281f8: and  x9,  x9, #0x1fffff
  2281fc: cmp  x9,  w10            ; 永远不相等 → matches=0
```

新编译 `own131`（本次产物）——**与 参考实现 逐指令同构**：

```
  228184: ldr  w9,  [x8, x28]      ; type          文件 0x71b4（.text delta 0x21000）
  228188: cmp  w9,  #0x10d
  228190: add  x9,  x8, x28
  228194: ldr  w10, [x9, #0x4]     ; pid
  228198: cmp  w10, w24            ; 严格相等
  2281a0: ldr  x9,  [x9, #0x18]    ; req
  2281a4: cmp  x9,  #0xb8
  2281ac: add  x9,  x8, x28
  2281b0: ldr  x10, [x9, #0x20]    ; alloc
  2281b4: cmp  x10, #0xc0
  2281bc: ldr  x9,  [x9, #0x8]     ; site
  2281c0: mov  w10, #0x5770        ; ← 0xe5770，与 参考实现 0x22994c 同值
  2281c4: movk w10, #0xe, lsl #16
  2281c8: and  x9,  x9, #0x1fffff
  2281cc: cmp  x9,  w10
  2281d0: b.ne 0x228178
```

### 2.3 交叉验证（独立来源）

`dev/OWN128_NEW_KERNEL.md` §4（旧内核 vs 新内核符号表逐字节比对）：

```
| prepare_creds | 0x（已隐去） | 0x（已隐去） | +0x1c |
| `prepare_creds+0x20`（cred_jar 分配点） | low21 0xe5754 | low21 0xe5770 | 0xe576c 处 `0x940a6c6d` = BL → 同一目标 ✓ |
```

`0xe5754 + 0x1c = 0xe5770`，与反汇编完全吻合。**我们携带的是 v2.9/旧内核的血统常量。**

### 2.4 为什么 `pid` 不是根因

旧编译 `work\vivo\own127` 的 pid 判据已经是严格相等（0x2281c8 `cmp w10, w24`，无 `cbz/cmp #0` 分支），
它在新内核上同样 `matches=0`。所以失败只能来自 site。当前源码里那句
`&& g_evs[i].pid != 0`（`own127.c:2476`）是旧编译之后才加进去的放松，本次一并收回成参考语义。

---

## 3. 补丁内容（`work\vivo\patch_cred.py`，精确字符串替换 + assert）

| # | 行 | 前 | 后 |
|---|---|---|---|
| 1 | 130 | `#define CRED_SITE_LOW21 0xe5754UL	/* prepare_creds+0x20: BL+4 == _RET_IP_ */` | `#define CRED_SITE_LOW21 0xe5770UL	/* prepare_creds+0x24: BL+4 == _RET_IP_ (6.6.127 abogki573773666) */` |
| 2 | 2476 | `if (g_evs[i].pid != (int)p && g_evs[i].pid != 0)` | `if (g_evs[i].pid != (int)p)` |

* 输入 `own127.c` 只读，输出 `own131.c`（184,741 B → 184,746 B）。
* 每处替换 `assert count == 1`，末尾自检 `0xe5754UL` 计数 0、`0xe5770UL` 计数 1。
* 未复制 参考实现 的任何字符串/代码块：只改了一个数值字面量与一个布尔条件。
* 可选开关 `--also-timer`（默认关）会把 plant 阶段的 `STATIC_TIMER_SITE/TIMER_SITE_LOW21`
  一并修到新内核（见 §7 风险 1），本次交付的 `own131.c` **不含**该改动。

---

## 4. 编译产物

```
$env:TEMP=$env:TMP='work\vivo\tmp2'          # 否则 clang 报 unable to make temporary file
$cc="$ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
& $cc -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE -Wall -Wextra \
      -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -I. own131.c -o own131
llvm-strip.exe --strip-all own131
```

| 项 | 值 |
|---|---|
| `own131`（strip 后） | **528,248 B** |
| sha256 | **`（已隐去）`** |
| `.text` / `.data` / `.bss` | 503,856 / 10,372 / 482,112 |
| 编译告警 | 10 条，全部是既有代码的 `-Wunused-variable` / `-Wcomment` / `_GNU_SOURCE` 重定义，与本次改动无关 |
| 对照：同 flags 重编未打补丁的 `own127.c` | 528,248 B，sha256 `（已隐去）` |
| 对照：11-03 旧产物 `work\vivo\own127` | 528,952 B，sha256 `（已隐去）` |
| 参考 `（本地样本）` | 参考实现体积，sha256 `参考实现` |

**第二轮产物（推荐交付：`own131b`，= cred + timer + gate 常量）**

| 项 | 值 |
|---|---|
| `own131b.c` | 184,746 B，sha256 `（已隐去）` |
| `own131b`（strip 后） | **528,248 B** |
| sha256 | **`（已隐去）`** |
| `.text` / `.data` / `.bss` | 503,856 / 10,372 / 482,112 |
| 生成命令 | `python patch_cred.py --all -o own131b.c`（7 处，全部 assert 命中 1） |

两份重编 `.text` 大小相同（503,856）是正常的：第 2 处补丁净删 2 条指令（8 B），
被函数对齐吃掉；但字节内容不同（sha 不同），差异见 §5.3 / §7.5。

---

## 5. 静态核查（不上机）

### 5.1 关键字符串都在

```
$ llvm-strings -a own131 | grep -E '\[cred\]|hello|site_low'
[cred] attempt=%d child=%d R=%#llx site_low=%#llx recs=%d task=%#llx
[cred]   match#%d ptr=%#llx site_low=%#llx
[cred] probe req=%d alloc=%d site=%#llx pid=%d
[cred] attempt=%d child=%d matches=%d
[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d failed
[child] hello write failed errno=%d
hello-sent
```

`CHILD_HELLO` 是常量不是字符串，按指令核查：

```
  228354: mov  w8, #0x5931
  228358: movk w8, #0x5244, lsl #16   ; 0x52445931 —— leak_cred 里读回值的比较
  22835c: cmp  w4, w8
```

### 5.2 hello 写入的 fd 与时机

`wait_child_main`（exec 后的子进程入口，own131 @0x22695c）：

```
  22697c: mov  w8, #0x5931
  226988: movk w8, #0x5244, lsl #16   ; hello = 0x52445931
  ...
  226a28: sub  x1, x29, #0x30         ; &hello
  226a2c: mov  w0, #0x4               ; fd = 4
  226a30: mov  w2, #0x4               ; 4 字节
  226a34: bl   write
  226a38: cmp  x0, #0x4
  226a3c: b.ne 0x226dc4               ; → "[child] hello write failed errno=%d"; _exit(130)
```

与参考完全一致（参考实现 `wait_child_main` 段）：

```
  22828c: movk w8, #0x5244, lsl #16
  228294: stur w8, [x29, #-0x30]
  2282e4: bl   sched_setaffinity      ; pin(g_cpu)
  2282e8: ... child_mark("start")
  228330: sub  x1, x29, #0x30
  228334: mov  w0, #0x4               ; fd 4
  228338: mov  w2, #0x4
  22833c: bl   write
  228340: cmp  x0, #0x4
  228344: b.ne → "[child] hello write failed errno=%d" ; _exit(130)  (0x228480)
  228348: ... child_mark("hello-sent")
```

时机：`pin → child_mark("start") → write(4, hello) → child_mark("hello-sent") → write(2,"PRE\n") → read(3, gate)`。
父进程侧只有在 `R != 0` 时才 `poll(st[0], 1, 2000)`，然后 `read(st[0], &hello, 4)` 并比较
`0x52445931`（参考实现 0x2299c4 `mov w2,#0x7d0` = 2000 ms；own131 同构）。
这解释了失败日志里 `hello=0`：`R==0` 时 `poll/read` 根本没执行。

### 5.3 与旧编译 `own127` 的函数级差异

用同一套 flags 重编未打补丁的 `own127.c` 作基线（`tmp2/base.dbg`，带符号），对三个 cred 相关函数做
归一化指令级 diff（`dev/re_cred/diff_fn.py`）：

| 函数 | 基线 | own131 | 结论 |
|---|---|---|---|
| `leak_cred` | 0x227f74，0x690，420 条 | 0x227f74，0x68c，419 条 | 3 个改动块 ↓ |
| `wait_child_main` | 0x22695c，0xacc，691 条 | 同址同长 | **完全相同** |
| `scan_task_allocs` | 0x229ebc，0x90，36 条 | 0x229eb8，0x90，36 条 | **完全相同** |

`leak_cred` 的 3 个改动块：

```
--- replace A[138:140] B[138:139]
   - b.eq  <leak_cred+…>
   - cbnz  w10, <leak_cred+…>      ; pid==0 放行
   + b.ne  <leak_cred+…>           ; 严格 pid 相等
--- replace A[148:149] B[147:148]
   - mov  w10, #0x5754  // =22356
   + mov  w10, #0x5770  // =22384
--- replace A[155:156] B[154:155]
   - mov  w3,  #0x5754  // =22356
   + mov  w3,  #0x5770  // =22384
```

即：**只有 cred 匹配的那两处常量 + pid 谓词变了，其余 cred 代码逐指令不变。**

### 5.4 与 参考实现 的行为要素对照（语义等价，但不是抄的）

| 行为要素 | 参考实现（地址） | own131（地址） | 判定 |
|---|---|---|---|
| 事件类型 | `0x10d` @0x229914 | `0x10d` @0x228188 | 等价 |
| pid 判据 | `pid == fork() 子 pid`（严格）@0x229924 | 同 @0x228198 | 等价 |
| `req` | `0xb8` @0x229930 | `0xb8` @0x2281a4 | 等价 |
| `alloc` | `0xc0` @0x229940 | `0xc0` @0x2281b4 | 等价 |
| site 掩码/值 | `& 0x1fffff == 0xe5770` @0x22994c–0x229958 | 同 @0x2281c0–0x2281cc | 等价 |
| 尝试次数 | `attempt < 4` @0x229744 | `attempt < 4` | 等价 |
| 采完缓冲后的等待 | `usleep(80000)` @0x2297fc | `usleep(80000)` | 等价 |
| 父等 hello 超时 | `poll(…, 2000)` @0x2299c4 | `poll(…, 2000)` | 等价 |
| hello fd/长度/值 | fd 4 / 4 B / `0x52445931` | fd 4 / 4 B / `0x52445931` | 等价 |
| 子进程 gate | `read(3,…)`，失败 `_exit(126)` | 同 | 等价 |
| 子进程 fd 布局 | `dup2(g2,3)` `dup2(s2,4)`，`F_DUPFD 20` | 同 | 等价 |
| task_struct 扫描 | site `0xac790`，req=alloc `0x12c0`，pid=`getpid()` @0x229a70 | `TASK_ALLOC_LOW21 0xac790`、`0x12c0`、`getpid()` | 等价（本来就对） |
| `execve` 目标 | `/proc/self/exe` + mode/fix 参数 | 同 | 等价 |

**不是抄的**（按行为来源与改动面判定，不比代码体量）：
* 我们这支有自己的 `[cred] probe …` 诊断循环（`own127.c:2496-2507`，参考实现 里没有这条字符串）、
  自己的 `logf` 包装与栈布局；行为对齐点是“值”，不是“文本”。
* 本次改动**只动数值字面量与一个谓词**，没有搬任何字符串、宏名或代码块。
* 依据来源是三条独立证据（参考实现 反汇编 + 目标内核 kallsyms + 全程序 A/B），
  不是把参考实现整段搬过来（§7.5 的全程序 A/B 也证明只碰了两个函数）。

---

## 6. 补丁后的语义推断（不上机，属推断不是实测）

`site & 0x1fffff` 命中 `0xe5770` 后，`matches≥1`、`R≠0`，父进程才会进入
`poll(2000) → read(4) → ==0x52445931` 分支并调用 `scan_task_allocs()`。
在目标内核 `abogki573773666` 上，`prepare_exec_creds → prepare_creds` 的 cred_jar 分配点
就是 `0xe5770`（§2.3 两个独立来源），因此该链应当打通。
**这条是推断；真值只能在实机上跑一次确认（本任务禁止上机）。**

---

## 7. 第二轮：全常量核对（→ `own131b`）

目标：把所有“随内核 `.text` 漂移”的常量一次性核完，产出 `own131b.c` / `own131b`。

### 7.1 做法与工具

1. `python patch_cred.py --all -o own131b.c` —— 7 处精确替换（cred 2 + timer 2 + gate 3），
   每处 `assert 命中 = 1`，末尾自检 6 个旧值归零、6 个新值唯一。
2. 核对来源有三类，按强度排序：
   * **参考实现 反汇编**（`llvm-objdump -d` + 自写 `adrp/add`、`movz/movk` 解析）；
   * **目标内核 kallsyms**（`work\vivo\new\kallsyms_new.txt`，新 boot 镜像导出；对照
     `kallsyms_old.txt`）——这一步比参考二进制更硬，因为它是内核镜像本身；
   * **全程序 A/B**（同 flags 重编未打补丁的 `own127.c`，按符号名逐函数比指令）。

### 7.2 四个（+1 派生）常量的核对结果

| 常量 | 参考实现 里的值（证据） | 我们的旧值 | 我们的新值 | 判定 / 依据 |
|---|---|---|---|---|
| `CRED_SITE_LOW21` | **`0xe5770`**（@`0x22994c` `mov w10,#0x5770` / `0x229950` `movk #0xe,lsl#16`） | `0xe5754` | **`0xe5770`** | 已核对一致（双源：参考实现 反汇编 + kallsyms `prepare_creds=0x（已隐去）`，+0x24 → low21 `0xe5770`） |
| `TIMER_SITE_LOW21` | **`0x198000`**（@`0x229fe8` `cmp x13,#0x198,lsl#12`） | `0x197fe4` | **`0x198000`** | 已核对一致（双源：参考实现 反汇编 + kallsyms `do_timer_create=0x（已隐去）`，+0xa8 → `0x198000`） |
| `STATIC_TIMER_SITE` | 由上一行派生 | `0x（已隐去）` | **`0x（已隐去）`** | 已核对一致（参考实现 里以**负值**出现：`0x228aa8` `mov x12,#0x3fffff8000` + `0x228ab4` `movk #0x7fe6` = `0x3F7FE68000` = `-0x（已隐去）`） |
| `CAPABLE_STATIC` | **未知**（参考实现 未嵌入，见 §7.3） | `0x（已隐去）` | **`0x（已隐去）`** | 用目标内核 kallsyms 核对：`Tcapable 0x（已隐去）` ✅；**但该宏在本源码中未被任何代码引用**（§7.4） |
| `LOAD_MODULE_STATIC` | **未知**（同上） | `0x（已隐去）` | **`0x（已隐去）`** | kallsyms `tload_module 0x（已隐去）` ✅；同样未被引用 |
| `TRACE_MODULE_NOTIFY_STATIC` | **未知**（同上） | `0x（已隐去）` | **`0x（已隐去）`** | kallsyms `ttrace_module_notify 0x（已隐去）` ✅；同样未被引用 |
| `KIMAGE_STATIC` | — | `0x（已隐去）` | 不改 | kallsyms `T_text`，新旧同址 ✅ |
| 全部 `.data/.bss` 常量（`SELINUX_STATE_STATIC`、`KPTR_RESTRICT_STATIC`、`PANIC_ON_WARN_STATIC`、`ROOT_USER_STATIC`、`INIT_USER_NS/UCOUNTS/GROUPS_STATIC`、两个 `TRACEPOINT_*`、`MODULE_NOTIFY_LIST_STATIC`、`MODULES_HEAD_STATIC`、`KPROBE_TABLE_STATIC`、11 个去重后的 vendor tracepoint 地址） | `selinux_state` 以 8 字节字面量出现在 参考实现 `0x78d18` | 同左 | **不改** | 逐个在 `kallsyms_new.txt` 里按原名精确命中、地址与旧值**逐字节相同** ✅（“`.data/.bss` 一个字节没动”被独立复现） |

（补充：`0x（已隐去）`、`0x（已隐去）` 是掩码/比较门限，不是符号地址，不在核对范围。）

### 7.3 为什么三处 gate 常量在 参考实现 里“未知”

三种独立扫法都查不到，且都带**阳性对照**：

| 扫法 | 覆盖 | 结果 |
|---|---|---|
| `movz/movk` 链还原（`constscan.py`） | 参考实现 全 `.text`，共还原 62 个内核 VA 常量 | 只有 3 个落在 `0xffffffc082xxxxxx`（`.data`）；**没有任何 `0xffffffc080xxxxxx`（`.text`）绝对地址** |
| 8 字节裸字面量 | 全文件 | `0x（已隐去） / …17d538 / …1f9f6c`（以及旧值）**全部 0 次**；对照：`0x（已隐去）`（selinux_state）命中 1 次 @`0x78d18` → 方法有效，缺失是真缺失 |
| 反汇编 grep（`#0x800c` / `#0x8017` / `#0x801f` 等高位半字） | 全 `.text` | 0 命中 |

结论：参考实现 **没有把这三个 `.text` 绝对地址编进代码**（它对这些目标走的是运行期解析/其它路径），
所以“从他的二进制读值”这条路对这三项**确认为“未知”**——不猜。
改用的替代证据是**目标内核自身 kallsyms**（`work\vivo\new\kallsyms_new.txt`，与 §4.1 文档表逐位吻合），
这一来源对这三个符号是精确命中（`Tcapable` / `tload_module` / `ttrace_module_notify`），可信度高于参考二进制。

### 7.4 关键发现：那三个 gate 宏是**死宏**，改了对二进制零影响

`grep` 全源码：`CAPABLE_STATIC / LOAD_MODULE_STATIC / TRACE_MODULE_NOTIFY_STATIC / KPROBE_TABLE_STATIC`
**只有 `#define` 行，没有任何使用点**。三项实测印证：

* `own131b` 全反汇编里搜不到 `#0x800c`/`#0x8017`/`#0x801f`/`#0xc09d0`/`#0x17d538`/`#0x1f9f6c` → 立即数不存在；
* 全文件 8 字节裸值搜索 → 不存在；
* 全程序 A/B（§7.5）→ 改动只落在 `leak_cred` 与 `run_plant` 两个函数，gate 相关函数**逐指令未变**。

因此：把它们对齐到新内核是**语义卫生**（防止以后有人启用这块代码时踩旧值），
但**不能声称“反汇编里能看到新立即数”**——看不到，因为编译器把它们整个丢掉了。

### 7.5 全程序 A/B（同 flags，未打补丁基线 vs `own131b`）

按符号名逐函数比较（`ab_diff.py`，adrp/分支目标做布局归一，其余立即数逐字比）：

```
functions: left=1504 right=1504 common=1504
地址/大小变化的函数: 1357      ← 仅因 leak_cred 少 4 B、run_plant 少 12 B 造成的整体位移
指令内容变化的函数: 2
  leak_cred: 420 -> 419 条
  run_plant: 1176 -> 1173 条
```

`leak_cred` 的差异块（全部）：

```
   cmp  w10, w24
-  b.eq ; -cbnz w10        (pid==0 放行)
+  b.ne                    (严格 pid 相等)
-  mov  w10, #0x5754  // =22356
+  mov  w10, #0x5770  // =22384
-  mov  w3,  #0x5754  // =22356      (match# 日志里的 site_low)
+  mov  w3,  #0x5770  // =22384
```

`run_plant` 的差异块（全部）：

```
-  mov  w11, #0x7fe4 ; movk w11, #0x19, lsl #16     ; 拼 0x197fe4 再 cmp
+  cmp  x13, #0x198, lsl #12                          ; =0x198000（单指令，少 3 条）
-  mov  x12, #0x801c ; movk #0x7fe6, lsl #16 ; movk #0x3f, lsl #32   ; -(0x（已隐去）)
+  mov  x12, #0x3fffff8000 ; movk #0x7fe6, lsl #16                     ; -(0x（已隐去）)
```

**结论：本次全部改动 = 3 个数值常量 + 1 个 pid 谓词，没有其它副作用。**

### 7.6 `own131b` 静态核查（逐条实测）

| # | 判据 | 实测 |
|---|---|---|
| 1 | 关键串齐全 | `llvm-strings -a own131b` → `[cred]   match#%d ptr=%#llx site_low=%#llx`、`[cred] attempt=%d child=%d matches=%d`、`[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d failed`、`[cred] probe req=%d alloc=%d site=%#llx pid=%d`、`[child] hello write failed errno=%d`、`hello-sent` 全在 |
| 2 | cred 立即数 = 新值 | `2281c0: mov w10,#0x5770` / `2281c4: movk w10,#0xe,lsl#16` / `2281cc: cmp x9,x10`；日志侧 `2281dc: mov w3,#0x5770` |
| 3 | timer 立即数 = 新值 | `228a64: cmp x13,#0x198,lsl#12`（=0x198000）；slide 常量 `228aa8/228ab4` = `0x3F7FE68000` = `-0x（已隐去）` |
| 4 | hello 写入未变 | `226a28: sub x1,x29,#0x30` / `226a2c: mov w0,#0x4` / `226a30: mov w2,#0x4` / `226a34: bl write` / `226a38: cmp x0,#0x4` / `226a3c: b.ne 0x226dc4` → 日志后 `226dd8: mov w0,#0x82`(=130) `bl _exit`；hello 值 `22697c: mov w8,#0x5931` + `226988: movk #0x5244` |
| 5 | gate 三常量“无立即数”已解释 | 见 §7.4（死宏），不是漏改 |

### 7.7 与 参考实现 的行为要素对照（第二轮，只列行为，不比代码体量）

| 行为要素 | 参考实现 | own131b | 判定 |
|---|---|---|---|
| cred 事件类型 | `0x10d` @`0x229914` | `0x10d` @`0x228188` | 等价 |
| cred pid 判据 | `== 子 pid`（严格）@`0x229924` | 严格 @`0x228198` | 等价（第二轮收紧后） |
| cred req / alloc | `0xb8` / `0xc0` @`0x229930/0x229940` | `0xb8` / `0xc0` | 等价 |
| cred site 低 21 位 | `0xe5770` @`0x22994c` | `0xe5770` | 等价 |
| timer site 低 21 位 | `0x198000` @`0x229fe8` | `0x198000` @`0x228a64` | 等价 |
| timer req / alloc / 门限 | `0x108` / `0x108`，victim 索引 `0x800`(2048) @`0x229ff4/0x22a00c` | `0x108` / `0x108`，`VICTIM_IDX 2048` | 等价 |
| 事件记录步长/字段偏移 | `0x40`，type@0 pid@4 site@8 ptr@0x10 req@0x18 alloc@0x20 | 同 | 等价 |
| hello fd/长度/值/失败码 | fd 4 / 4 B / `0x52445931` / `_exit(130)` @`0x228330` | 同 @`0x226a2c` | 等价 |
| 父等 hello 超时 | `poll(…,2000)` @`0x2299c4` | `poll(…,2000)` | 等价 |
| 采样后等待 / 尝试次数 | `usleep(80000)` / `attempt<4` | 同 | 等价 |
| 静态 slide 锚点 | timer 站点（负常量）@`0x228aa8` | 同 | 等价 |

---

## 8. 剩余风险 / 未知项（第二轮更新）

1. ~~plant（timer）阶段同类漂移~~ —— **第二轮已修**：`own131b.c` 的
   `STATIC_TIMER_SITE 0x（已隐去）` / `TIMER_SITE_LOW21 0x198000`，
   反汇编 `228a64: cmp x13,#0x198,lsl#12` + `228aa8/228ab8` 的负常量已核对（§7.6）。
   注意：`own131.c`（第一轮产物）**不含**这项，只有 `own131b.c` 含。
2. ~~三处 gate 常量未复核~~ —— **第二轮已核**：新内核 kallsyms 精确命中
   `…09d0 / …17d538 / …1f9f6c`，已写进 `own131b.c`；但它们是**死宏**，
   二进制里本就不存在，改动无运行时影响（§7.4）。真正的 gate/insmod 路径走的是
   `kprobe_events` + 符号表（`ksu/ksyms_table.h`），那条路径的地址来自
   `kallsyms_lookup_name`/符号表，**本轮未逐条核对那张表**（见第 6 条）。
3. **`0xe5770` 的适用边界**：它只对 `abogki573773666`（与 `gd489d4ad2a70`）这一版内核成立。
   换内核必须重新取（`prepare_creds+0x24` 的 `_RET_IP_` 低 21 位，或 `prepare_creds` 地址 +0x24）。
   源码里没有做多值兼容（与参考一致，单一常量）——这是刻意的语义对齐，不是遗漏。
4. **pid 谓词收紧的影响**：如果某次 trace 记录把子进程的 cred 分配记成 `pid==0`，
   收紧后会漏掉该记录（旧源码会接住）。参考实现是严格相等且在该内核上成功，
   故判定收紧安全；若实机出现 `matches=0` 复发而 `[cred] probe` 里能看到 `pid=0` 的同形记录，
   把 `own127.c:2476` 改回带 `!= 0` 的宽松版即可（一行回滚）。
5. **未上机验证**：本次没有跑任何 target。`[preflight] PASS` 之后的行为（fake cred 落点、
   slide 计算、`gate127` 分支）都不在本轮证据范围内；所有“应当打通”的判断都是静态推断。
6. **未核对项（明确标未知）**：`ksu/ksyms_table.h` 里那张 225 项符号表（`g_ksyms`）本轮没有
   逐项对新 kallsyms 复核；若新内核对个别符号改名/裁剪，表现为 `[insmod] bound=%d missing=%d`
   里 `missing>0`。这是 gate 路径真正的地址来源，优先级高于前面三个死宏。

---

## 9. 复现命令

```powershell
$v='C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\vivo'
$b='C:\Users\Camellia\Documents\deepseek-harness\default-workspace\work\ndk\android-ndk-r27\toolchains\llvm\prebuilt\windows-x86_64\bin'
Set-Location $v

# 第一轮（仅 cred）
python patch_cred.py                       # own127.c -> own131.c
# 第二轮（cred + timer + gate 常量）
python patch_cred.py --all -o own131b.c    # own127.c -> own131b.c

$env:TEMP="$v\tmp2"; $env:TMP="$v\tmp2"    # 否则 clang 报 unable to make temporary file
& "$b\aarch64-linux-android35-clang.cmd" -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE `
  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -I. own131b.c -o own131b
& "$b\llvm-strip.exe" --strip-all own131b

# 静态核查
& "$b\llvm-strings.exe" -a own131b | Select-String -Pattern '\[cred\]|hello|site_low'
& "$b\llvm-objdump.exe" -d --no-show-raw-insn --start-address=0x2281a0 --stop-address=0x2281e0 own131b   # cred 0xe5770
& "$b\llvm-objdump.exe" -d --no-show-raw-insn --start-address=0x228a58 --stop-address=0x228a70 own131b   # timer 0x198000
# 参考侧同段：
& "$b\llvm-objdump.exe" -d --no-show-raw-insn --start-address=0x229910 --stop-address=0x229960 '（本地样本）'
& "$b\llvm-objdump.exe" -d --no-show-raw-insn --start-address=0x229fd0 --stop-address=0x22a000 '（本地样本）'

# 常量核对（新/旧内核 kallsyms 对照）
python dev\re_cred\verify_consts.py own127.c new\kallsyms_old.txt new\kallsyms_new.txt
# 全程序 A/B（需先同 flags 重编 own127.c 为 tmp2\base.dbg）
python dev\re_cred\ab_diff.py tmp2\base.dbg tmp2\own131b.dbg 0x220300 0x27c2c0
```

辅助脚本（均在 `dev/re_cred/`）：`xref.py`（adrp/add 解析）、`analyze.py`（字符串 xref + 窗口）、
`findref.py`（movz/movk、字面量池、裸指针扫描）、`diff_fn.py`（单函数指令 diff）、
`constscan.py`（全 .text movz/movk 链还原内核 VA）、`verify_consts.py`（源码常量 × kallsyms 对照）、
`ab_diff.py`（全程序按符号名 A/B）。
