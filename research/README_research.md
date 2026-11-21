# CVE-2026-98260 — vivo X200s 临时 Root 与厂商反模块安装机制分析

> **状态**：研究记录（responsible write-up）。本文不包含可直接武器化的利用代码或内核模块二进制。
> 作者：设备所有者（本人设备，vivo X200s / PD2415M / V2458A，内核 6.6.127-android15）

## 摘要

在 vivo X200s（内核 `6.6.127-android15-8-g3b723d0e8507`）上，利用 CVE-2026-98260
（posix-cpu-timers UAF，`rb_erase` 产生一次 8 字节任意零写）获得**内存态临时 root**，
并进一步分析了 vivo 的模块加载防护 `hooks_defend`，验证了其判定逻辑与一条**基于厂商既有白名单接口**
的放行路径。整个过程不修改分区、不依赖 BL 解锁，重启即失效。

## 1. 受影响环境

| 项 | 值 |
|---|---|
| 设备 | vivo X200s（PD2415M / V2458A） |
| 内核 | 6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k |
| 漏洞 | CVE-2026-98260（posix-cpu-timers use-after-free） |
| 原语 | 单次 8 字节任意零写（受 slab 回收时序约束） |

## 2. 漏洞原语（概述）

- 非 leader 线程 `execve` 失败后，posix CPU timer 仍残留对已释放 `posix_timers_cache` slab 的引用；
- 用 8 KiB AF_UNIX socket spray 回收该 order-1 slab 页并覆盖其中的 `timerqueue_node`；
- 受控 reap 触发 `timerqueue_del → rb_erase`，对 `rb_left` 指向的地址执行一次 8 字节写入；
- 结合 KASLR slide 校验（写 `selinux_state` 观察 enforce 变化）可稳定定位内核基址。

**不公开**：完整利用源码、payload 布局与可执行二进制（理由见第 6 节）。

## 3. 厂商反模块安装机制（hooks_defend）

`hooks_defend.ko` 随 vendor_boot ramdisk 加载（约开机 13 s，`[permanent]`，不可卸载），
在 `load_module` 上注册 kprobe，pre_handler 依次校验：

1. `.cs[0] == .cs[0x16c] == 0xdeadbeef`；
2. 24 字节 key 副本与 `.cs+0x10/0x20/0x30` 的副本自洽；
3. 判定函数 `aec()`：配置位放行分支（只由 `vusb_msg` 写入，需厂商 RSA 签名消息）；
4. 否则查白名单：`SHA256(image)[0:8]` 必须命中 `.data._ka` 的有序 u64 表（魔数 `0xcafebabe`）。

未命中时改写返回寄存器并跳过 `load_module`，用户态得到 `EPERM`，日志形如：

```
hks-dfd: kh_in_ret=0, 162
hks-dfd: phlm num--=1011,<pid>,<comm>
```

配套 `/sys/kernel/bsp_security/` 的 13 个属性中，关键项带 write-once 原子字（开机即封死），
因此“写 sysfs 关掉防护”不可行。

## 4. 分析结论

- 防护的判定是**白名单哈希匹配**，而非针对特定进程/名字；
- 白名单由 `khs_num` + `write_hash` 两个属性维护（无 write-once），但其可用性受 `insko_dfd_on` 限制；
- 厂商放行分支（配置位）需要签名消息，不可伪造；
- 结论：**该防护可被绕过**，但需要先获得任意内核写能力以解除 `insko_dfd_on` 限制，
  因此“先有 root 才能绕过反模块安装”是这套机制的真实上限。

## 5. 建议的修复方向（给厂商）

1. 为 `khs_num`/`write_hash` 增加与其余属性一致的 write-once 或鉴权校验；
2. 白名单哈希改为带盐/带 key 的 HMAC，避免攻击者自行构造；
3. kprobe pre_handler 中不要依赖可被内存写修改的配置位做“放行”判定；
4. 对 `load_module` 的拦截增加对“调用者已获得 CAP_SYS_MODULE 但来源异常”的审计与阻断。

## 6. 负责任披露

- 本文**不发布**可执行利用、payload 构造细节或内核模块二进制；
- 建议在厂商补丁发布后再公开完整技术细节；
- 已/将同步通知 vivo 安全响应中心与 Android Security。

## 7. 时间线

| 日期 | 事件 |
|---|---|
| 2026-11 | 本地验证临时 root 与厂商防护分析完成 |
| 待定 | 厂商披露与补丁 |

## 8. 免责声明

本研究在**本人所有**的设备上进行，仅用于安全研究与防御改进。请勿在未授权的设备上使用相关技术。
