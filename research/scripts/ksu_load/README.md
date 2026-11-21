# ksu_load — 一键加载 KernelSU（own127 路线）

一条命令完成：重启取干净开机窗口 → 跑 own127（提权 + 打穿 hooks_defend）→ 加载
`kernelsu_patched.ko` → 实时显示设备日志 → 验证 `/proc/modules` → 拉起管理器看「越狱模式」。

## 用法

```powershell
cd work\vivo\ksu_load
.\load_ksu.ps1                 # 完整流程（自动重启 + 运行 + 实时日志）
.\load_ksu.ps1 -NoReboot       # 不开机，在当前 boot 上跑
.\load_ksu.ps1 -SkipRun        # 只看状态/正在运行的日志
.\load_ksu.ps1 -Tmo 120 -Retry 0
```

参数：`-Tmo` 实时日志上限秒数（默认 90）、`-Retry` 设备自重启时是否重试一次（默认 1）、
`-Manager` 结束后拉起的管理器包名（默认 `me.weishu.kernelsu`）、`-Adb` adb 路径。

## 它会做什么

1. **预检**：adb 在、设备在、`/sys/kernel/tracing` 在；打印内核版本 / SELinux / uptime。
2. **推送并校验**：`own127`、`kernelsu_patched.ko`、`run_ksu.sh`、`chk_ksu.sh`；
   逐个比对远端字节数（防「重启前 <1s 推送得到 NUL 文件」的坑），`sync` 后 `chmod 755`。
3. **重启**（除非 `-NoReboot`）：等 `sys.boot_completed=1`，再等 2 秒（利用窗口）。
4. **启动**：`run_ksu.sh` 在设备侧做 ELF 头校验后 `setsid ./own127 fake nofix`。
5. **实时日志**：每 1 秒把 `cve-2026-98260.log` 的新增字节打到终端（delta pump），
   同时用 uptime 下降识别设备自重启；命中
   `[gate127] SUCCESS` / `[al] init_module rc=0` 立即停。
6. **验证**：`grep kernelsu /proc/modules`，再跑 `chk_ksu.sh`（gate 关键行 + kmsg + 末尾日志）。
7. **成功**：拉起管理器（默认官方 KernelSU），屏幕应显示「工作中 [越狱模式]」。
8. **失败**：若设备自重启且 `-Retry 1`，自动等开机后重试一次；否则打印失败点。

## 成功标志

```
[al] init_module rc=0 errno=0
[gate127] SUCCESS uptime=5x
/proc/modules: kernelsu 180224 0 - Live 0x0 (O)
```

## 已知限制 / 注意

- **一次开机一次**：fake-cred 父进程 park 住伪造页；重启才清干净。
- 链路有 boot 级抖动（约一半概率在 fake-cred 阶段自重启）；脚本默认重试一次。
- 管理器版本：模块 uapi 是 **32680-5**，官方管理器需 **versionCode ≥ 32680**，
  否则会显示「工作中 [越狱模式]」+ 一条“管理器版本过低”的红横幅（功能不受影响）。
- SakiSU 是另一个 fork（提示“尚未授权”），vivo 专版提示“未安装”，均属正常。
- `/sys/module/kernelsu` 不存在是 prebuilt ko 隐藏了 sysfs 目录，不影响模块状态。

## 文件

| 文件 | 作用 |
|---|---|
| `load_ksu.ps1` | 一键主脚本（宿主侧） |
| `run_ksu.sh` | 设备侧启动器（ELF 校验收 + setsid 启动 + 日志分隔） |
| `chk_ksu.sh` | 设备侧验证（模块 / gate 行 / kmsg / tail） |
| `../own127` | 利用 + 打门 + 加载二进制（520440 B） |
| `../ksu/kernelsu_patched.ko` | 已离线绑定符号的 LKM（330664 B） |
| `../dev/own127_result.md`、`../dev/own127_manager_result.md` | 证据与逐行记录 |
