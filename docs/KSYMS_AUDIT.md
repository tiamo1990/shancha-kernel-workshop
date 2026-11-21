# KSYMS_AUDIT — `ksu/ksyms_table.h` × 新内核 kallsyms 全量核对

> 离线纯静态。未连接设备、未使用 adb、未安装/未运行任何目标二进制、未触碰 `apk/as/*`。
> 所有结论可由 `work/vivo/audit_ksyms.py` 与本文件列出的命令原样复现。

## 0. 结论先行

| 问题 | 答案 |
|---|---|
| 这张表在新内核上能直接用吗 | **能。225/225 精确命中（名字+地址双精确），DRIFT 0、MISSING 0** |
| 需要修几项 | **0**（225 条表项零改动；`ksyms_table_new.h` 只在末尾追加 6 行 `AUDIT` 注释） |
| 其中几项高危 | **0**（高危定义：被 `.ko` 引用 且 DRIFT/MISSING） |
| 那这张表为什么值得核 | 表头声明它由 `6.6.127-...-abogki573773666`(17.2.14.2.W10) 重新生成；本次核对**独立证明**了这一点，并顺手证明**旧表 17.2.11.2 在新内核上有 205 项漂移** |

## 1. 输入与解析口径

| 输入 | 路径 | 规模 |
|---|---|---|
| 待审计表 | `ksyms_table.h` | 225 条 |
| 新内核符号 | `kallsyms_new.txt` | 110398 行 / 106315 唯一名 |
| 旧内核符号 | `new/kallsyms_old.txt` | 110394 行（对照用） |
| 待加载 LKM | `android15-6.6_kernelsu.ko` | 225 个 SHN_UNDEF 符号（扫描 1753 个 symtab 项） |
| 源码（只读） | `own131b.c` | 6381 行 / 184746 B |

**解析规则（两条，都容易踩错）**

1. 表项正则 `\{\s*"([^"]+)"\s*,\s*(0x[0-9a-fA-F]+)\s*ULL\s*\}` —— 只认 `{ "name", 0x… }`，
   表尾 `#define N_KSYMS` 不计入。实得 **225** 条（与文件 225 行表项一致）。
2. kallsyms 行形如 `（已隐去） Tprepare_creds`：**地址后一个空格，紧跟 1 个类型字符，
   类型字符与名字之间没有空格**。因此切分必须是 `addr` + `space` + `type[0]` + `name=rest`，
   绝不能按空格 split 后把 `Tprepare_creds` 当名字——那会让 225 项全变 MISSING。
   本脚本用 `^([0-9a-fA-F]{8,16})[ \t](.)(.*)$`，类型字符单独捕获并丢弃。

判定口径：

- `OK`：该名字在 kallsyms 中存在，**且表里的旧地址精确出现在该名字的地址集合里**（多地址名字要求命中其一）。
- `DRIFT`：名字在，但表里地址不在其地址集合中 → 取同名字下距离最近的地址为候选，给 `新-旧` 差值。
- `MISSING`：名字在 kallsyms 中完全不存在 → 给 1–3 个模糊候选（difflib 比率 + 下划线/子串信号），**仅作线索**。
- 地址一律按无符号 64 位处理，差值带符号输出。

## 2. 命令

```powershell
cd work\vivo
python audit_ksyms.py                       # 主审计 -> dev/ksyms_audit.json
python audit_ksyms.py --md dev/KSYMS_AUDIT.md
# 控制实验：证明判定器不是“什么都判 OK”
python audit_ksyms.py --table ksu\ksyms_table_old_17.2.11.2.h --json dev\_ctl_oldtable.json
python audit_ksyms.py --new new\kallsyms_old.txt      --json dev\_ctl_oldkallsyms.json
python audit_ksyms.py --table ksu\ksyms_table_old_17.2.11.2.h --new new\kallsyms_old.txt --json dev\_ctl_old_old.json
python patch_ksyms.py --table ksu\ksyms_table.h --kallsyms new\kallsyms_new.txt --out ksu\ksyms_table_new.h
```

## 3. 统计

| 类别 | 数量 | 占比 |
|---|---|---|
| 总数 | **225** | 100.0% |
| OK | **225** | 100.0% |
| DRIFT | **0** | 0.0% |
| MISSING | **0** | 0.0% |

### 3.1 OK 前 5 例（全量 225 项，`dev/ksyms_audit.json` 有完整列表）

| # | 符号 | 地址 | 路径 | 表行 |
|---|---|---|---|---|
| 1 | `__put_cred` | `0x（已隐去）` | cred 路径（提权本体） | 24 |
| 2 | `abort_creds` | `0x（已隐去）` | cred 路径（提权本体） | 47 |
| 3 | `alloc_uid` | `0x（已隐去）` | cred 路径（提权本体） | 48 |
| 4 | `commit_creds` | `0x（已隐去）` | cred 路径（提权本体） | 64 |
| 5 | `free_uid` | `0x（已隐去）` | cred 路径（提权本体） | 94 |

### 3.2 DRIFT 全清单（0 项）

**空。** 当前表 225 项在新 kallsyms 中名字与地址同时精确命中，无一项漂移。
唯一存在的漂移集合来自**旧表** 17.2.11.2，见 §6 对照实验（205 项全列）。

### 3.3 MISSING 全清单（0 项）

**空。** 225 项在新 kallsyms 中全部存在，无改名、无裁剪、无符号消失。

## 4. 交叉验证：什么才算“真正被用到”

任务约定用 `own131b.c` 里的引用建子集。实测该文件**没有** `KSYM(` / `kaddr(` 宏，
它用的是另一条路径：`bind_ko_symbols()` 遍历 LKM 的 `.symtab`，
对每个 `SHN_UNDEF` 符号在 `g_ksyms[]` 里线性查名字，命中就写地址并改 `SHN_ABS`（own131b.c:3004–3073）：

```
for (k = 0; k < N_KSYMS; k++)
        if (strlen(cn) == nl && !strncmp(cn, &strtab[nameoff], nl)) {
                wr64(img, e + 8, g_ksyms[k].a + slide);   /* st_value */
                wr16(img, e + 6, 0xfff1);                 /* SHN_ABS  */
```

所以“被用到”的**权威定义**是：LKM 的未定义符号集。离线解析 `android15-6.6_kernelsu.ko` 得到 **225** 个未定义符号，与表内 225 个名字**一一对应、零差集**（`ko_not_in_table = 0`）。
这说明这张表本来就是照着这个 `.ko` 生成的，且覆盖完整——LKM 不会因为缺符号而 bind 失败。

`own131b.c` 文本层面的引用只作为补充证据（二级信号）：

| 形式 | 符号 | 位置 | 说明 |
|---|---|---|---|
| 字符串常量 | `selinux_state` | L6157（共 1 处） | `[+] fake cred A=%#llx rc_page=%#llx selinux_state=%#llx\n` |
| 标识符/注释 | `commit_creds` | L167 | 非符号引用（常量注释），见下注 |
| 标识符/注释 | `prepare_creds` | L130 | 非符号引用（常量注释），见下注 |

注：`memcpy/memset/strlen/strcmp/strncmp/strstr/snprintf/sprintf/sscanf/strrchr` 在 own131b.c 里
是**工具自己的 libc 调用**（同名不同物），不能当内核符号引用；`commit_creds`/`prepare_creds` 只出现在
注释与常量名里（如 `CRED_SITE_LOW21 0xe5770 /* prepare_creds+0x24 */`）。
这正说明：**不能靠源码文本找引用，只能靠 `.ko` 的 symtab**——否则会漏 200 多项、又多认 10 项假引用。

### 4.1 表外常量顺手核（29 个硬编码 `0xffffffc0…ULL`）

这些常量不在 `g_ksyms[]` 里，因此不在 225 项审计范围内，但同样会随内核漂移。核对结果：

| 常量 | 出现在 | 是否精确等于某个 kallsyms 符号起始 | 符号 / 归属 |
|---|---|---|---|
| `0x（已隐去）` | L3408 | 是 | `_text` |
| `0x（已隐去）` | L3093 | 是 | `capable` |
| `0x（已隐去）` | L3095 | 是 | `load_module` |
| `0x（已隐去）` | L140 | 否 | `do_timer_create`+0xa8 内部地址（非符号起始） |
| `0x（已隐去）` | L3096 | 是 | `trace_module_notify` |
| `0x（已隐去）` | L145 | 是 | `panic_on_warn` |
| `0x（已隐去）` | L144 | 是 | `kptr_restrict` |
| `0x（已隐去）` | L147 | 是 | `init_user_ns` |
| `0x（已隐去）` | L146 | 是 | `root_user` |
| `0x（已隐去）` | L149 | 是 | `init_groups` |
| `0x（已隐去）` | L148 | 是 | `init_ucounts` |
| `0x（已隐去）` | L3407 | 是 | `modules` |
| `0x（已隐去）` | L175 | 是 | `module_notify_list` |
| `0x（已隐去）` | L5506 | 否 | `module_notify_list`+0x38 内部地址（非符号起始） |
| `0x（已隐去）` | L5503 | 否 | `module_notify_list`+0x40 内部地址（非符号起始） |
| `0x（已隐去）` | L168 | 是 | `__tracepoint_sys_exit` |
| `0x（已隐去）` | L4027 | 是 | `__tracepoint_android_vh_ogki_audit_log_setid` |
| `0x（已隐去）` | L4026,4055,5423 | 是 | `__tracepoint_android_rvh_ogki_audit_log_module_sign` |
| `0x（已隐去）` | L4029 | 是 | `__tracepoint_android_rvh_ogki_get_task_tags` |
| `0x（已隐去）` | L4028 | 是 | `__tracepoint_android_rvh_ogki_check_task_tags` |
| `0x（已隐去）` | L5420 | 是 | `__tracepoint_android_rvh_selinux_avc_insert` |
| `0x（已隐去）` | L5421 | 是 | `__tracepoint_android_rvh_selinux_avc_node_delete` |
| `0x（已隐去）` | L5422 | 是 | `__tracepoint_android_rvh_selinux_avc_node_replace` |
| `0x（已隐去）` | L5419 | 是 | `__tracepoint_android_rvh_selinux_avc_lookup` |
| `0x（已隐去）` | L169,5417 | 是 | `__tracepoint_android_rvh_commit_creds` |
| `0x（已隐去）` | L5418 | 是 | `__tracepoint_android_rvh_exit_creds` |
| `0x（已隐去）` | L5416 | 是 | `__tracepoint_android_vh_check_file_open` |
| `0x（已隐去）` | L3094 | 是 | `kprobe_table` |
| `0x（已隐去）` | L143 | 是 | `selinux_state` |

**26/29 个硬编码常量精确落在 kallsyms_new 的符号起始地址上**，包括 `__tracepoint_android_rvh_commit_creds`、`__tracepoint_android_rvh_selinux_avc_*`、`selinux_state`、`kprobe_table`、`init_user_ns`、`root_user`、`init_groups`、`init_ucounts`、`panic_on_warn`、`kptr_restrict`。剩下 3 个不是符号起始，但同样能落到具体对象里：

| 常量 | 精确推导 | 结论 |
|---|---|---|
| `0x（已隐去）`（`STATIC_TIMER_SITE`） | `do_timer_create` = `0x（已隐去）`，`+0xa8` = `0x（已隐去）` | timer 站点精确对得上，是**函数内部地址**，不是符号 |
| `0x（已隐去）` / `0x（已隐去）` | `modules` = `0x（已隐去）`，`+0x48` / `+0x50` 分别精确等于这两个常量 | 是 `modules` 对象内部的字段偏移，不是独立符号 |

顺带一条**不影响结论的观察**（不改代码，仅记录）：`own131b.c:139` 的注释写 `do_timer_create+0x94: bl kmem_cache_alloc; _RET_IP_ = +0x94`，而 `:140` 的常量 `STATIC_TIMER_SITE` 精确等于 `do_timer_create+0xa8`。两者差 `0x14`。既然常量对得上内核，那么旧的是注释里的 `+0x94`（若 `bl` 实际在 `+0xa4`，则 `_RET_IP_ = +0xa8` 自洽）。下次手上有 vmlinux 时用反汇编确认 `do_timer_create` 首条 `bl` 的真实偏移即可，**不要凭注释改常量**。

结论：own131b.c 里 29 个硬编码常量全部与这个内核自洽——26 个精确命中符号起始，3 个精确落在目标对象内部。
这与表审计的结果互相独立，但指向同一个事实：源码与表都是照这一版内核写的。

## 5. 高危表

定义：**被 LKM 引用（SHN_UNDEF）且 非 OK**。按影响排序（cred → gate → timer → kprobe → task → mm → vfs → crypto → misc）。

**本次为空：0 项。** 225 个被引用符号全部 OK，因此不存在“用错地址”的绑定。

为了让这张表在**下一次换内核**时有用，下面给按影响排序的**判据清单**（当前全部 OK，任何一项将来变 DRIFT/MISSING 就按这个顺序先看）：

| 优先级 | 路径 | 表内符号数 | 该类出问题的直接后果 |
|---|---|---|---|
| P1 | cred 路径（提权本体） | 14 | `commit_creds`/`prepare_creds` 绑到错地址 → 跳进他方函数中段，轻则 cred 没换（`R=0`、非 root），重则 panic |
| P2 | SELinux/AVC 门（gate 路径） | 37 | SELinux 门常量绑错 → `avc_has_perm` 判错，提权后被 LSM 拦回 EPERM |
| P3 | timer/wait/work 路径 | 14 | `ktime_get`/`schedule`/`__wake_up` 绑错 → 父进程 poll 超时或 soft lockup，表现为 `hello=0` |
| P4 | kprobe/tracepoint 路径 | 8 | `register_kprobe` 绑错 → 钩子注册失败，trace 环形缓冲永远空 → `matches=0` |
| P5 | task/pid/cpu 路径 | 13 | `find_task_by_vpid`/`tasklist_lock` 绑错 → 找不到子进程或遍历越界 |
| P6 | 内存/字符串越界防护 | 24 | `__kmalloc`/`copy_*_nofault` 绑错 → 分配/越界防护失效，随机 panic |
| P7 | VFS/挂载/命名空间 | 35 | `filp_open`/`path_*` 绑错 → 模块加载与文件读写全废 |
| P8 | crypto shash | 3 | `crypto_shash_digest` 绑错 → 模块签名/校验失败 |
| P9 | 其它（字符串/锁/打印/模块/静态键） | 77 | 锁/打印/静态键绑错 → 死锁或日志全乱 |


## 6. 对照实验（这份“全 OK”是怎么被证明不是瞎判的）

同一套判定器跑四组配对，只有对角线上是干净的：

| 表 \ kallsyms | 旧 `kallsyms_old.txt` | 新 `kallsyms_new.txt` |
|---|---|---|
| 旧表 `ksyms_table_old_17.2.11.2.h` | **225 OK / 0 DRIFT** | 20 OK / **205 DRIFT** / 0 MISSING |
| 当前表 `ksyms_table.h` | 20 OK / **205 DRIFT** / 0 MISSING | **225 OK / 0 DRIFT / 0 MISSING** |

对角线 225/225、反对角线 205 漂移，说明判定器既能命中也能报错，且两张表各自严格对应各自那一版内核。
同时反向印证：`kallsyms_new.txt` 与 `ksyms_table.h` 出自同一次构建，不是把同一个文件拿来对比自己。

### 6.1 旧表 205 项漂移的分布（这就是“同代漂移”的样子）

| 差值 | 项数 | 含义 |
|---|---|---|
| +8 | 2 | 单个函数内 2 条指令级差异 |
| +28 | 37 | = 0x1c，正是 CRED_FIX §0 记录的 `prepare_creds` 漂移量 |
| +108 | 38 | 前序函数体各涨一小段后累积 |
| +168 | 31 | 同上，跨一个更大的函数 |
| +192 | 3 | 偶发 |
| +384 | 49 | 整段编译单元位移 |
| +936 | 22 | 大段（含 or_report / raw_spinlock 群） |
| +960 | 23 | 更大一段 |

差值全部是 4 的倍数、且集中在 8/28/108/168/192/384/936/960 这几个档位——
这是**同一次构建内的段内位移**特征（代码增删导致后续函数整体平移），
与“换了大版本、符号重排”那种随机大跳变完全不同。旧表 205 项里有 37 项差 28(0x1c)，
`prepare_creds` 就是其中之一，独立复现了 CRED_FIX §2.3 的结论。

### 6.2 旧表 DRIFT 全清单（205 项，按影响排序）

| P | 符号 | 旧表地址 | 新内核地址 | 差值 | 类型 | 路径 |
|---|---|---|---|---|---|---|
| P1 | `__put_cred` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `abort_creds` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `alloc_uid` | `0x（已隐去）` | `0x（已隐去）` | +8 | SAME-FN | cred 路径（提权本体） |
| P1 | `commit_creds` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `free_uid` | `0x（已隐去）` | `0x（已隐去）` | +8 | SAME-FN | cred 路径（提权本体） |
| P1 | `get_task_cred` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `groups_alloc` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `groups_free` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `groups_sort` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `override_creds` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `prepare_creds` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `revert_creds` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `set_cred_ucounts` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P1 | `set_groups` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | cred 路径（提权本体） |
| P2 | `avc_has_perm` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avc_ss_reset` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avtab_alloc` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avtab_destroy` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avtab_insert_nonunique` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avtab_search_node` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `avtab_search_node_next` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `cond_compute_av` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `ebitmap_cmp` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `ebitmap_contains` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `ebitmap_destroy` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `ebitmap_get_bit` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `ebitmap_set_bit` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `mls_compute_context_len` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `mls_context_to_sid` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `mls_sid_to_context` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_context_isvalid` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_destroy` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_filenametr_search` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_load_isids` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_read` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `policydb_write` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `security_bounded_transition` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `security_release_secctx` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `security_secctx_to_secid` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `security_secid_to_secctx` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `selinux_blob_sizes` | `0x（已隐去）` | `0x（已隐去）` | +192 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `selinux_status_update_policyload` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `selnl_notify_policyload` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `sidtab_context_to_sid` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `sidtab_destroy` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `sidtab_search_entry` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `sidtab_sid2str_get` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `sidtab_sid2str_put` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `symtab_insert` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P2 | `symtab_search` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | SELinux/AVC 门（gate 路径） |
| P3 | `__init_waitqueue_head` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `__wake_up` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `finish_wait` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `init_wait_entry` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `kick_all_cpus_sync` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | timer/wait/work 路径 |
| P3 | `ktime_get` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `kvfree_call_rcu` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `prepare_to_wait_event` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `queue_work_on` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `schedule` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | timer/wait/work 路径 |
| P3 | `stop_machine` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | timer/wait/work 路径 |
| P3 | `synchronize_rcu` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P3 | `synchronize_srcu` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | timer/wait/work 路径 |
| P4 | `register_kprobe` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P4 | `register_kretprobe` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P4 | `tracepoint_probe_register_prio` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P4 | `tracepoint_probe_unregister` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P4 | `unregister_kprobe` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P4 | `unregister_kretprobe` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | kprobe/tracepoint 路径 |
| P5 | `__task_pid_nr_ns` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `change_pid` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `find_pid_ns` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `find_task_by_vpid` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `find_vpid` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `get_pid_task` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P5 | `task_work_add` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | task/pid/cpu 路径 |
| P6 | `__alloc_pages` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 内存/字符串越界防护 |
| P6 | `__check_object_size` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 内存/字符串越界防护 |
| P6 | `__copy_overflow` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `__free_pages` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 内存/字符串越界防护 |
| P6 | `__kmalloc` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `copy_from_user_nofault` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `copy_to_kernel_nofault` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `copy_to_user_nofault` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kfree` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kmalloc_caches` | `0x（已隐去）` | `0x（已隐去）` | +192 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kmalloc_trace` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kmemdup` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kmemdup_nul` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `krealloc` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kvfree` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kvmalloc_node` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `kvrealloc` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `memstart_addr` | `0x（已隐去）` | `0x（已隐去）` | +192 | SAME-FN | 内存/字符串越界防护 |
| P6 | `strncpy_from_user_nofault` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 内存/字符串越界防护 |
| P6 | `vmalloc` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 内存/字符串越界防护 |
| P7 | `anon_inode_getfile` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `anon_inode_getfile_secure` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `d_path` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `dentry_open` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `ext4_unregister_sysfs` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fd_install` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fget` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `filp_close` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `filp_open` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fput` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_add_mark` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_alloc_group` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_destroy_mark` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_init_mark` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_put_group` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `fsnotify_put_mark` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `generic_file_llseek` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `get_unused_fd_flags` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `ihold` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `iput` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `iterate_dir` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `kern_path` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `kernel_read` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `kernel_write` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `noop_llseek` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `ns_get_path` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `path_get` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `path_mount` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `path_put` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `path_umount` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `put_unused_fd` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `seccomp_filter_release` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | VFS/挂载/命名空间 |
| P7 | `set_fs_pwd` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | VFS/挂载/命名空间 |
| P8 | `crypto_alloc_shash` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | crypto shash |
| P8 | `crypto_destroy_tfm` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | crypto shash |
| P8 | `crypto_shash_digest` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | crypto shash |
| P9 | `___ratelimit` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__arch_copy_from_user` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__arch_copy_to_user` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__arm64_sys_close` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__arm64_sys_setns` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__get_task_comm` | `0x（已隐去）` | `0x（已隐去）` | +108 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__hashtab_insert` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__list_add_valid_or_report` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__list_del_entry_valid_or_report` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__mutex_init` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__rcu_read_lock` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__rcu_read_unlock` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `__stack_chk_fail` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_copy_to_iter` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_find_first_bit` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_find_next_bit` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_printk` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_read_lock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_read_unlock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_lock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_lock_irq` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_lock_irqsave` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_unlock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_unlock_irq` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_spin_unlock_irqrestore` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_write_lock_irq` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `_raw_write_unlock_irq` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `alt_cb_patch_nops` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `bcmp` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `bin2hex` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `current_is_single_threaded` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `down_read` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `down_write` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `fortify_panic` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kallsyms_lookup` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kallsyms_lookup_name` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kallsyms_lookup_size_offset` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kallsyms_on_each_symbol` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kasprintf` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kobject_del` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kstrdup` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kstrtouint` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `kstrtoull` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `memchr` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `memcpy` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `memset` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `module_put` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `mutex_lock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `mutex_lock_interruptible` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `mutex_unlock` | `0x（已隐去）` | `0x（已隐去）` | +936 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `refcount_warn_saturate` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `scnprintf` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `snprintf` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `sprintf` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `sscanf` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `static_key_count` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `static_key_disable` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `static_key_enable` | `0x（已隐去）` | `0x（已隐去）` | +168 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strchr` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strchrnul` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strcmp` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strlen` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strncmp` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strncpy_from_user` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strnlen` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strrchr` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strscpy` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strscpy_pad` | `0x（已隐去）` | `0x（已隐去）` | +384 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strsep` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `strstr` | `0x（已隐去）` | `0x（已隐去）` | +960 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `try_module_get` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `up_read` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |
| P9 | `up_write` | `0x（已隐去）` | `0x（已隐去）` | +28 | SAME-FN | 其它（字符串/锁/打印/模块/静态键） |

### 6.3 两版之间地址不变的 20 项（可当 sanity anchor）

`__cpu_online_mask`, `__num_online_cpus`, `__put_task_struct`, `__set_fixmap`, `__tracepoint_sys_enter`, `arm64_use_ng_mappings`, `caches_clean_inval_pou`, `dcache_clean_inval_poc`, `init_mm`, `init_pid_ns`, `init_task`, `kasan_flag_enabled`, `ksys_unshare`, `mntns_operations`, `param_ops_bool`, `selinux_state`, `system_cpucaps`, `system_wq`, `tasklist_lock`, `tracepoint_srcu`

这些是数据段对象或位置稳定的入口（`init_task`、`init_mm`、`selinux_state`、`system_wq`、
`tasklist_lock`、`kasan_flag_enabled` 等）。换内核后它们若也变了，通常意味着段布局整体重排，
此时不能只改表，要重新生成整张表。

## 7. 产物

| 文件 | 作用 |
|---|---|
| `audit_ksyms.py` | 本审计脚本（解析/判定/交叉验证/MD 生成） |
| `dev/ksyms_audit.json` | 机器可读全量结果（225 项逐项分类 + LKM 未定义符号表） |
| `patch_ksyms.py` | 修补器：只改 DRIFT 地址，MISSING 只记注释，逐处 `assert` |
| `ksu/ksyms_table_new.h` | 修补结果（225 条表项零改动，仅末尾追加 6 行 `AUDIT` 注释；已用 clang `-fsyntax-only` 验证仍是合法 C） |
| `dev/KSYMS_AUDIT.md` | 本文件 |

## 8. 一句话结论

**这张表在新内核（`6.6.127-...-abogki573773666` / 17.2.14.2.W10）上可直接使用：
225 项全部精确命中，需修 0 项，高危 0 项；**
作为对照，仓库里那份 17.2.11.2 旧表在新内核上有 **205 项漂移**（其中 cred 路径 14 项、gate 路径 36 项、timer 路径 13 项、kprobe 路径 6 项），一旦错用旧表就是全链路崩，这也解释了为什么必须重新生成。
