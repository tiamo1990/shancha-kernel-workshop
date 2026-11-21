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

- **安装包**：``release/shancha-提权-v7.6.apk`（正式版命名规范：`shancha-提权-vX.X`）
- **Release 页**：[v5.5](https://github.com/tiamo1990/shancha-kernel-workshop/releases/tag/v5.5)（附件为 ASCII 别名 `shancha-v5.5.apk`，内容一致）
- **源码**：[src/](src/)（载荷 `own137.c` + App Java 源码）
- **历史研究记录**：[research/](research/)（项目报告、各阶段脚本、早期 `own127.c`）
---

## v6.9 更新要点（versionCode 77）

| 项 | 说明 |
|---|---|
| 双版本必选 | 3666（新内核）/ 7879（旧内核）；界面提示「7879 实测 7946、6638 也可用；3666 未知，可自行测试」 |
| 选择 = 载荷 | `assets/payloads.json` 外置清单；选择直接决定资产，不再经过自动匹配 |
| sha256 门禁 | 运行前校验，**大小写归一**；不符才阻止执行 |
| 内核不符 | 仅警告「已放行」，仍按所选执行 |
| 7879 日志 | 2.9 原版原样输出，不格式化，只按关键词着色 |
| 成功即停手 | 成功后停止一切内核写，`pause()` 保活，实测 CPU 0% |
| 误触保护 | 成功「中止」拒绝；「重启」需 4 秒内双击确认 |
| 失败可重试 | 同一次开机内允许再试；成功后需双击才能强行再跑 |
| 日志导出 | 长按「复制」→ `/sdcard/Download/shancha-log-<时间>.txt` |

### 下载

- 仓库内：`release/shancha-提权-v7.6.apk`
- Release 附件：`shancha-v6.9.apk`（ASCII 别名，字节一致）
---

## v6.4（versionCode 82）

| 项 | 说明 |
|---|---|
| 日志位置 | 自动保存到 `下载/山茶内核工坊/日志/run-<时间>-<版本>.txt` |
| 界面提示 | 日志卡标题右侧显示保存路径，并有「保存」按钮 |
| 7879 启动方式 | 还原 2.9 原版：`rm -f .lock2 own127.lock` → `setsid … > own127.log 2>&1 < /dev/null &` → tail 日志 |
| 驻留保护 | 识别 `parking without reap` 后拒绝中止/重复启动，提示重启 |
| sha 校验 | 大小写归一，只有真正不一致才阻止 |
| 误触保护 | 成功中止拒绝；重启需 4 秒内双击；超窗（>150 s）需二次确认 |
| 卡住自动清理 | 未成功且 45 s 无输出 → 自动 `pkill own127` |

### 日志查看方式

1. App 内「实时回显」卡片
2. 文件管理 → 下载 → **山茶内核工坊** → **日志**
3. 点日志卡右上「保存」手动留一份
4. 电脑：`adb pull /sdcard/Download/山茶内核工坊/日志/`
---

## v7.0 → v7.6（versionCode 88 → 94）

### 日志（重做）

| 项 | 说明 |
|---|---|
| 每轮独立文件 | 起跑即建 `进行中-<时间>-<版本>.txt`，**每 1 秒**覆盖刷新 |
| 结束改名 | 成功 → `…_成功.txt`；失败 → `…_失败-codeN.txt`；驻留 → `…_驻留.txt`；**断电/panic → …_重启.txt** |
| 位置 | `Download/山茶内核工坊/日志/`（经 MediaStore 写入，文件管理器可见） |
| 重启补存 | 下次启动检测 `run_pending`，自动归档并另存一份 |
| 界面 | 日志卡标题显示路径，右侧「保存」按钮；**长按保存 = 导出诊断包** |

### 7879 旧链路（严格对齐 v2.9）

```
cd /data/local/tmp
mkdir -p /data/local/tmp
[ -f cve-2026-98260.log ] || : > cve-2026-98260.log; chmod 666 …
chmod 777 /data/local/tmp; chmod 755 /data/local/tmp/own127
rm -f .lock2 own127.lock
rm -rf chan; mkdir -p chan; chmod 777 chan; rm -f ksu_slide.txt
setsid /data/local/tmp/own127 fake nofix > own127.log 2>&1 < /dev/null &
# 观察：wc -c 判增量 + tail -c +N
```

关键修复：**cwd 必须是 `/data/local/tmp`**（2.9 载荷用相对路径 `chan`）、**强制重推载荷**（等价 `cp -f`）、**预建日志 666 + tmp 777**。

### 载荷

- `own138`（532,280 B, sha `8038F24F…`）：cred 未命中改为**连续 3 轮才判失败**（原第 1 轮就停，会把偶发丢帧当结论）
- 成功后停止一切内核写，`pause()` 保活（实测 CPU 0%）

### 其它

- 起跑前环境预检（kmem/残留锁/旧进程/模块在线）—— **只提示不拦截**
- sha256 门禁大小写归一；内核与所选不一致仅警告
- 成功后「中止」拒绝、「重启」需 4 秒内双击；超窗（>150 s）需二次确认
- 卡住（未成功且 45 s 无输出）自动清理链路进程