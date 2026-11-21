# 山茶 · 内核工坊 (Shancha Kernel Workshop)

一套面向 Android 17 / Linux 6.6.127 内核的**本地研究用**提权链与配套 App 的公开研究记录。

> 本项目仅为**自有机型上的内核安全研究**与工程记录，用于验证一个已公开披露的定时器竞态缺陷（CVE-2026-98260）在 6.6.127 上的可利用性、以及内核模块装载链路的工程实现。**请仅在你自己的设备上使用。**

---

## 1. 研究目标

| 项 | 内容 |
|---|---|
| 目标内核 | `6.6.127-android15-8-gd489d4ad2a70-abogki573773666-4k` |
| 缺陷 | CVE-2026-98260：`posix-cpu-timer` 在非组领导者 `exec` 失败后遗留的悬空 `rb_node` |
| 原语 | `cleanup_timerqueue()` → `timerqueue_del()` → `rb_erase()` 的 case-1 路径，形成**单次 8 字节零写** |
| 结果 | 在自有机型上完成 `KernelSU` LKM 的 `init_module`，获得 `u:r:ksu:s0` 的 root |

---

## 2. 方法概述（六段链路）

我们自己把整条链分成六段，每一段都有**可判定的成功标志**，全部以事件码形式输出：

| 段 | 名称 | 做什么 | 关键事件码 |
|---|---|---|---|
| S1 | 自检 | 通道可用性、tracefs、权限、内核版本 | `E1012` 起点 |
| S2 | 标定 | 由内核事件反推 `direct map` 基址 | `E2011` 候选 |
| S3 | 定位 | 命中 `prepare_creds` 的 `kmem_cache_alloc`，拿到目标页 | `E3031` 未命中 |
| S4 | 回收 | 喷射 + 释放 + 捕获，把目标页拿到手 | `E4001/E4010/E4048` |
| S5 | 落位 | 替身页落位、身份字段修复 | `E5003/E5013` |
| S6 | 装载 | 门控解除、白名单放行、`init_module` | `E6080` 全链成功 |

### 2.1 关键常量（随内核版本漂移，必须逐版核对）

| 常量 | 本内核取值 | 说明 |
|---|---|---|
| `CRED_SITE_LOW21` | `0xe5770` | `prepare_creds` 调用点低 21 位 |
| `TIMER_SITE_LOW21` | `0x198000` | `do_timer_create` 调用点低 21 位 |
| `STATIC_TIMER_SITE` | `0xffffffc080198000` | 上者的内核 VA |
| `CAPABLE_STATIC` | `0xffffffc0800c09d0` | — |
| `LOAD_MODULE_STATIC` | `0xffffffc08017d538` | — |
| `TRACE_MODULE_NOTIFY_STATIC` | `0xffffffc0801f9f6c` | — |

**这些值不是拍出来的**：我们用三重独立证据确认——反汇编立即数、`kallsyms` 精确命中、以及同一份旧内核符号表的对角线对照。详见 [docs/RESEARCH.md](docs/RESEARCH.md)。

### 2.2 符号表

内核模块通过 `SHN_UNDEF` 重定位与内核符号绑定，本项目对 225 项符号做了**全量审计**：名字 + 地址双精确命中，0 漂移、0 缺失。方法见 [docs/RESEARCH.md](docs/RESEARCH.md) 第 4 节。

### 2.3 日志体系

链路输出使用自有固定字段语法，便于机器解析与界面呈现：

```
S<1-6>|<段名>|<动作>|<事件码>|k1=v1|k2=v2…
D|S<n>|…          调试通道，默认静默
```

示例：

```
S3|定位|凭据命中|E3012|pid=1234|site=0xe5770|ok=1
S4|回收|布种耗时|E4048|plant=1|el=657|ok=1
S6|装载|全链成功|E6080|uptime=98.73|ok=1
S6|装载|保活挂起|E6120|mark=1|ok=1
```

**成功之后的行为**：链路停止一切内核写操作，进程以 `pause()` 驻留保活（不退出、不释放页），实测 CPU 占用为 0。这一点很关键：成功后若继续做页回收，会反复释放仍被存活 `cred` 引用的页，进而触发内核 panic。

---

## 3. 工程要点（踩过的坑）

1. **一次开机只有一次利用窗口**：kprobe 表与 trace 环形缓冲会被首次尝试消耗，第二次通常退化。
2. **`panic_on_warn` 是重启的直接原因**：注入链会触发 WARN，若该开关为 1 则直接 panic 重启。因此拿到 root 后第一件事是通过 `su` 把它置 0。
3. **App 直接调用 `su` 会被拒**：KSU 的授权按调用者判定，需借助 shell 身份（如 Shizuku）执行 `su`。
4. **成功后不要"优雅退出"**：退出会把页归还 buddy，而活的 `task->cred` 仍指向它 → `rb_erase` panic。
5. **双内核载荷**：包内同时携带两代内核对应的载荷，运行时按 `uname -r` 选择，避免换版即失效。

---

## 4. 仓库内容

```
`shancha-提权-v5.5.apk`（正式版命名规范：`shancha-提权-vX.X`）
docs/RESEARCH.md                     研究记录：原语、常量核对、符号审计、时序分析
docs/LOG_SCHEME.md                   日志语法规范与事件码表
src/payload/own137.c                 载荷源码
src/payload/ksyms_table.h            225 项内核符号表
src/app/                             配套 App 源码（Java + Manifest）
research/                            历史研究记录（报告、脚本、早期源码）
```

APK 信息：

| 项 | 值 |
|---|---|
| 包名 | `com.shancha.ownctl` |
| versionCode / versionName | 63 / 5.5 |
| 大小 | 1,714,778 B |
| sha256 | `53415BBA8563EFAF…`（完整值见 `release/SHA256SUMS.txt`） |

---

## 5. 使用前提

- 自有机型、自有内核构建（`abogki573773666`）
- 已安装对应版本的管理器（32680 / uapi 5）
- Shizuku 已通过无线调试启动并授权
- 每次尝试前重启设备，开机后 90 秒内启动链路，**只点一次**

---

## 6. 免责声明

本项目为**内核安全研究**记录，用于理解定时器竞态、SLUB 页回收与内核模块装载链路。作者不对任何滥用、数据丢失或设备损坏负责。请在你拥有完全控制权的设备上使用。
---

## 下载

- **安装包**：`release/shancha-提权-v5.5.apk`（正式版命名 `shancha-提权-vX.X`）
- **Release 页**：[v5.5](https://github.com/tiamo1990/shancha-kernel-workshop/releases/tag/v5.5)（附件为 ASCII 别名 `shancha-v5.5.apk`，内容一致）
- **源码**：[src/](src/)（载荷 `own137.c` + App Java 源码）
- **历史研究记录**：[research/](research/)（项目报告、各阶段脚本、早期 `own127.c`）