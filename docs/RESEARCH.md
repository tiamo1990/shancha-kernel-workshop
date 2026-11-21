# 研究记录

本文记录这条链路在 `6.6.127-android15-8-gd489d4ad2a70-abogki573773666-4k` 上的关键事实、证据与踩坑过程。全部为本机实测与静态分析所得。

---

## 1. 原语

CVE-2026-98260 的成因：非组领导者线程 `exec` 失败后，`posix-cpu-timer` 的 `rb_node` 已被解链但未清空，随后 `cleanup_timerqueue()` 再次调用 `timerqueue_del()`，走到 `rb_erase()` 的 case-1 分支，形成**一次 8 字节写 0**。

这条链把它用来：
1. 把一个已释放的 slab 页重新拿回（页回收 + 喷射竞争）；
2. 用零写把目标地址上的指针/字段清掉（门控位、`selinux_state` 的 enforce、`cred` 的 uid 字段）。

---

## 2. 常量的三重核对

单靠反汇编容易看错，单靠符号表容易过期，所以我们用三条独立路径交叉验证：

### 2.1 反汇编（立即数）

`prepare_creds` 的调用点匹配由一条 `mov/movk` 序列决定：

```asm
22994c: mov  w10,#0x5770
229950: movk w10,#0xe,lsl#16      ; → 0xe5770
229954: and  x9,x9,#0x1fffff
229958: cmp  x9,x10
```

旧内核同位置是 `0xe5754`，差值 `0x1c`，正是 `.text` 漂移量。

### 2.2 kallsyms 命中

```
prepare_creds: 0xffffffc0800e5730 → 0xffffffc0800e574c   (+0x1c，低21位 = 0xe5770)
do_timer_create: 0xffffffc080197f3c → 0xffffffc080197f58 (+0x1c，+0xa8 → 0x198000)
capable: 0xffffffc0800c09c8 → 0xffffffc0800c09d0
load_module: 0xffffffc08017d51c → 0xffffffc08017d538
trace_module_notify: 0xffffffc0801f9ec4 → 0xffffffc0801f9f6c
```

### 2.3 符号表对角线对照

| 表 \ 符号源 | 旧内核 | 新内核 |
|---|---|---|
| 旧表 | 225 命中 | 20 命中 / **205 漂移** |
| 新表 | 20 命中 / 205 漂移 | **225 命中 / 0 漂移 / 0 缺失** |

对角线干净、反对角线大面积漂移 —— 说明审计方法本身有效，不是恒真判断。

---

## 3. 页回收的判据（最脆弱的一环）

单次 plant 的流程：喷射若干 socket 页 → 释放其中一部分 → 触发 `exec` 制造释放事件 → 从 trace 环形缓冲里读 `kmem_cache_alloc` / `mm_page_alloc` 事件 → 若命中自己的页即捕获成功。

实测统计（成功那一轮，最近 60 次 plant）：

```
el:  min=473ms  p50=655ms  p90=932ms  max=4192ms  avg=804ms
E4025: hit=1 占 100%，其中 free_seen=0 占 85%
```

**问题**：`free_seen`（页已释放事件）有 85% 拿不到，判据只能靠 `hit=1` 推断。这是这条链概率性失败的主因，也是下一步要改的地方（用 `mm_page_alloc` 的 pfn 变化做二次确认）。

---

## 4. 时序与耗时（实测）

| 起跑 | 成功 | 链路耗时 |
|---|---|---|
| uptime 35.23 | 102.53 | 67.3 s |
| uptime 36.04 | 106.62 | 70.6 s |
| uptime 36.41 | 112.29 | 75.9 s |
| uptime 46.53 | 100.76 | 54.2 s |

各段占比：S4（回收）+ S5（落位）合计 > 60%。

---

## 5. 成功后必须"停手"

真机上出现过一类崩溃：`E6080 ok=1`（门控已过、模块已装）之后，链路仍在做页回收，随后内核 panic 重启（`sys.boot.reason = kernel_panic`）。

原因链：
1. 成功后内核状态已被改写（门控、`selinux_state`、kprobe 表）；
2. 继续 plant 会释放**可能仍被存活 `cred` 引用**的页；
3. 一旦命中 → UAF → `rb_erase` panic。

因此正确做法是：**成功即停止一切内核写，但进程以 `pause()` 驻留，绝不退出、绝不释放页**。

两种错误做法都验证过会崩：
- 成功后 `return 0` 退出 → 页归还 buddy → panic；
- 超时后 `kill` 持页子进程 → 同样 UAF → panic。

---

## 6. App 侧的工程要点

1. **载荷投递**：Shizuku 的 shell 读不到 App 私有目录，必须通过进程 stdin 把资产灌到 `/data/local/tmp`。
2. **强制重推**：曾用"远端尺寸相同就跳过灌文件"的优化，结果运行时用的是旧载荷 —— 教训是**每次无条件重推**。
3. **关闭 `panic_on_warn`**：App 直接调 `su` 会被 KSU 拒绝（按调用者授权），必须借 shell 身份：`shizuku → su -c 'echo 0 > /proc/sys/kernel/panic_on_warn'`，并且**读回值等于 0 才算成功**。
4. **看门狗不能杀保活进程**：成功后链路静默是正常状态，若按"45 秒无输出"去 `destroy()`，会把保活进程杀掉 → 归还页 → panic。正确做法是成功后直接关掉看门狗。
5. **界面收尾 ≠ 结束进程**：成功后让 UI 回到可用状态，但载荷继续驻留。