# hks-analyst findings — hooks_defend / load_module gate (2026-11-02)

## 0. TL;DR for the team

- The module that returns EPERM on `init_module` **is `hooks_defend`**, and the
  mechanism is a **kprobe on `load_module`** whose pre-handler skips the call
  and fabricates `-EPERM` in `regs[0]`.
- The module also creates `/sys/kernel/bsp_security/` (13 attrs, 0600 root).
  Its `store` handler is a plain `kstrtou8` + one-byte write into the module's
  obfuscated config array — **no capability check**. Writing `def_on=0` and
  `unlocked=1` changes the checksum the pre-handler uses and makes it take the
  **allow** branch. The gate worker already runs as uid 0 with full caps, so it
  can do this itself: **no kread, no plant, no module base needed**.
- `kread` (kprobe fetcharg on `capable`) does **not** work on this device:
  `/proc/kcore` is ENOENT and the kprobe event never appears in `trace`
  (every `[kread] krN not found`). Any plan that needs kernel reads (module
  list walk, kprobe_table scan) is blocked until that is fixed.

## 1. Where the module binary came from (new)

`work/vivo/vendor_boot_30.img` is an LZ4-legacy vendor_boot; its vendor ramdisk
is a 139 MB cpio. It contains `lib/modules/hooks_defend.ko` (65,616 B) plus
~400 other vendor modules. Extracted with `dev/list_cpio.py` into
`dev/cpio_vb30/` (all `*.ko` saved there).

- Full `.symtab` present (`init_module`, `sub_4D24`, `sub_4D24_init`), rest of
  the functions stripped, but the `.rela.*` tables give every call site.
- `.rodata` (0x374 B) is string-obfuscated with a **differential stream
  cipher**: `out[i] = rol8((in[i]-in[i-1]) & 0xff, 3) ^ 0x25`, first
  `in[-1] = 0x3d`, strings concatenated with no NULs. Decoder:
  `dev/dec_ro.py` (whole section) and `dev/dec_refs.py` (per call site).
- **Caveat:** this build's vermagic is
  `6.6.127-android15-8-g64697b1fe5e3-4k`, the running kernel is
  `6.6.127-android15-8-g3b723d0e8507-abogki558077879-4k`, and the loaded
  module's `srcversion` matched (`2FC864A70E7AF604CF74112`) but the file is
  not necessarily byte-identical to the one loaded. The 13 sysfs attr names
  below **do** match the live device exactly, so the build is at least the
  same source.

## 2. How the gate works (from the extracted build)

Kprobe targets resolved via `kallsyms_lookup_name` (itself obtained with a
throw-away `register_kprobe` on the symbol, see `.init.text+0xc34` = `get_kln`):
`register_kprobe`, `unregister_kprobe`, `kptr_restrict`, `write_enabled_file_bool`,
`proc_dointvec_minmax_sysadmin`, `find_modules_open`, `kallsyms_open`,
`register_kretprobe`, `register_module_notifier`, `load_module`.

`load_module` hook (`.init.text+0xce0` fills the kprobe at module `.bss+0xf8`,
pre_handler = module `.text+0x1e90`):

```
regs[0] = info
if (!info) return 0
if (.cs magic 0xdeadbeef bad)              -> deny
if (0x9d4: 24-byte random-key copy bad)    -> deny
w = 0xaec()                                 ; config checksum
if (w != 0)                                -> ALLOW
if (0x2020(info) != 0)                     -> ALLOW   ; "kh_in_ret" allowlist hit
deny:
    printk("hks-dfd: phlm num--=1011,%d,%s")  (pid, comm)
    x8 = [regs+0x100] (=x30/LR)
    regs[0] = -1                              ; -EPERM
    [regs+0x100] = x8 (regs->pc = LR)         ; skip load_module entirely
    return 1
```

- `0x2020` = **`kh_in_ret`**: prints
  `"hks-dfd: kh_in_ret=%d, %d"` with the second arg a source line (162) —
  this is exactly the kmsg line that was observed. It binary-searches the
  allowlist struct pointed to by `.data._ka` (magic 0xcafebabe, sorted u64
  array) for a value derived from `load_info`; `0` = not allowed.
- `0xaec` (config checksum): let `g(i) = .cs[0x140 + .cs[0x14e[i]]]`
  (a per-boot permuted 14-byte config array, all zero at boot).
  - if `sum(g(0..4)) & 0xff == 0`  -> returns `g(8)`
  - else                            -> if `g(9) == 1` returns `g(8)`, else returns **1**
  - i.e. **any non-zero g(0..4) (with def_on=0) makes it return 1 = ALLOW**.

### sysfs knobs (live on device, `/sys/kernel/bsp_security/`, all 0600 root)

| attr | decrypted from | store | config slot |
|---|---|---|---|
| rem_authed | .rodata+0x12 | generic 0xa4 | g(0) |
| em_authed | .rodata+0x1c | generic 0xa4 | g(1) |
| vroot_authed | .rodata+0x25 | generic 0xa4 | g(2) |
| unlocked | immediate 0x…e3bbb3ea22d9b047 | generic 0xa4 | g(3) |
| compile_mode | .rodata+0x31 | generic 0xa4 | g(4) |
| dbgfs_dfd_on | .rodata+0x3d | generic 0xa4 | g(5) |
| kptr_dfd_on | .rodata+0x49 | generic 0xa4 | g(6) |
| insko_dfd_on | .rodata+0x54 | generic 0xa4 | g(7) |
| def_on | .rodata+0x7b | 0x484 (0/1 only) | g(9) |
| token_hwid | .rodata+0x60 | custom | — |
| vusb_msg | immediate 0x…cd85bbb2637bb1a7 | custom | — |
| write_hash | .rodata+0x6a | custom | — |
| khs_num | .rodata+0x74 | custom | — |

Generic store `0xa4`: `kstrtou8` -> write-once atomic flag on attr+0x20 ->
`value` into `.cs+0x10+attr->0x28` (a padding byte) **and** into
`g(attr->0x30)`. No `capable()`, no auth token. `show` (0x44 / 0x43c) reads
the same `g()` slot back, so a readback verifies the write.

## 3. Why the previous gate kept failing / kread

- `/proc/kcore` is absent (`[kcore] open errno=2`), the kprobe-fetcharg
  fallback registers the probe (no error logged) but the `krN` event never
  shows up in `/sys/kernel/tracing/trace`, so every `kread()` fails.
- own123's module walk therefore read garbage and gave up
  (`[mod] walk FAILED: hooks_defend not found`), and any kprobe_table scan is
  equally blocked.

## 4. What was prepared

`work/vivo/own124.c` / `own124` (built from own122, NDK, stripped, 506,904 B):

- gate mode first reads back `def_on` / `unlocked`, then writes
  `def_on=0, unlocked=1, compile_mode=1, rem_authed=1, em_authed=1,
  vroot_authed=1`, reads `def_on`/`unlocked` back;
- then `insmod_try()`: open `/data/local/tmp/kernelsu_patched.ko` (330,664 B,
  vermagic already the running kernel), bind all undefined symbols to
  `vmlinux addr + slide` (slide from `/data/local/tmp/ksu_slide.txt` written by
  the chain right after its own selinux slide verification), call
  `init_module`, then `finit_module`, log `rc/errno` and the `/dev/kmsg` tail;
- then `/proc/modules` check; fallback: `run_manager_chain()`.

Everything needed to try it is on the device except the binary.

## 5. Files

- `dev/list_cpio.py` — boot/vendor_boot cpio lister/extractor (handles LZ4 legacy)
- `dev/cpio_vb30/hooks_defend.ko` — the extracted module
- `dev/ko_elf.py`, `dev/ko_data.py`, `dev/ko_strings.py` — ELF/reloc/data helpers
- `dev/dec_ro.py`, `dev/dec_refs.py` — string-cipher decoder
- `dev/disrange.py` — disassembly range helper (`hooks_defend.dis.txt`, UTF-16)
