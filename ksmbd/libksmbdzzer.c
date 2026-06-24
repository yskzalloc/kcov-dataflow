/*
 * libksmbdzzer.c — KSMBD fuzzer core library.
 *
 * Provides:
 *   - Authenticated SMB2 session via libsmbclient (NTLMv2/signing/encryption)
 *   - kcov_dataflow remote capture (mmap'd buffer, handle-based)
 *   - Race pattern primitives (pthread-based, true concurrency)
 *   - Feature extraction from kcov_df buffer
 *
 * Used by:
 *   - ksmbdzzer.py (via ctypes) as the fast C transport layer
 *   - grain/ C files (linked directly) for libFuzzer harnesses from gen.py
 *
 * Build:
 *   cc -shared -fPIC -O2 -I/usr/include/samba-4.0 -I. \
 *      libksmbdzzer.c -o libksmbdzzer.so -lsmbclient -lpthread -lcrypto
 *   (-I. and -lcrypto are needed for grain/ntlmv2.h NTLMv2 auth.)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <libsmbclient.h>

/* kcov_dataflow ioctls */
#define KCOV_DF_INIT_TRACE     _IOR('d', 1, unsigned long)
#define KCOV_DF_REMOTE_ENABLE  _IOW('d', 102, unsigned long)
#define KCOV_DF_REMOTE_DISABLE _IO('d', 103)
/*
 * 8M words = 64MB. Sized to survive an entire reset→op→get_features cycle
 * without overflowing now that each worker has a *private* buffer (one
 * connection's worth of records, not all workers funneled into one). The old
 * 64K-word buffer overflowed within a few requests and get_features() then
 * reported zero coverage for the whole round.
 */
#define DF_BUF_WORDS           (1 << 23)

/* ─── Colored, located logging (parity with ksmbdzzer.py teal / gen.py orange) ──
 * libksmbdzzer.c is self-contained (does NOT include libksmbdzzer.h), so the macro
 * is defined locally with this component's palette color. pfz_err(fmt, ...) is a
 * drop-in for fprintf(stderr, fmt, ...): it prepends a dmesg-style CLOCK_MONOTONIC
 * timestamp (aligns with kernel printk) + file:line and wraps the line in 24-bit
 * truecolor. Metric substrings (KERNEL_PCS=, RET_TOKEN_HITS=, …) stay intact for the
 * host-side parsers. */
#include <time.h>
#define PFZ_LOG_COLOR "\033[38;2;200;229;255m"   /* #c8e5ff — libksmbdzzer.c */
#define PFZ_LOG_RESET "\033[0m"
#ifdef __FILE_NAME__
# define PFZ_FILE __FILE_NAME__
#else
# define PFZ_FILE __FILE__
#endif
__attribute__((unused))
static inline const char *pfz_dts(void)
{
    static __thread char _b[24];
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    snprintf(_b, sizeof(_b), "[%5ld.%06ld]", (long)_ts.tv_sec, _ts.tv_nsec / 1000);
    return _b;
}
#define pfz_err(fmt, ...) \
    fprintf(stderr, PFZ_LOG_COLOR "%s %s:%d | " fmt PFZ_LOG_RESET, \
            pfz_dts(), PFZ_FILE, __LINE__, ##__VA_ARGS__)

/*
 * Per-worker coverage routing. Each worker connects to a distinct loopback
 * address 127.0.0.<octet> and registers the handle the kernel derives from
 * that address (fs/smb/server/connection.h: KSMBD_KCOV_DF_IP_HANDLE). Keep
 * this formula identical to the kernel's. octet is the low byte of the
 * host-order IPv4 address, so the low 16 bits reduce to <octet> for 127.0.0.x.
 */
#define KSMBD_KCOV_DF_IP_HANDLE(octet)  (0x4b440000UL | ((octet) & 0xFFFFUL))

/* ─── State ─────────────────────────────────────────────────────────────── */
/* libsmbclient is NOT thread-safe (one global tevent/talloc context). The
 * threaded race helpers below used to call smbc_* concurrently from two pthreads,
 * which corrupted talloc ("Bad talloc magic value - access after free") and
 * segfaulted libtevent — killing the worker pool mid-campaign. Serialize every
 * smbc_* call made from a race thread through this lock. Real kernel-level race
 * coverage comes from the RAW-SOCKET races (pfz_pool_oplock_race / _lock_race),
 * which use independent per-thread sockets and need no lock. */
static pthread_mutex_t g_smbc_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_smb_fd = -1;
static int g_smb_fd2 = -1;
static int g_df_fd = -1;
static uint64_t *g_df_buf = NULL;
static int g_raw_sock = -1;
static uint64_t g_raw_mid = 1000;
static int g_worker_octet = 1;             /* 127.0.0.<octet> for this worker */
static char g_target_ip[16] = "127.0.0.1"; /* server address this worker dials */

/* ─── Engine ablation + coverage metrics (parity with grain/common.h) ────────
 * The lib-backed grains (gen.py gen_grain / *_combo_*) use THIS file's
 * pfz_get_features() for coverage — so the engine switch and the KERNEL_PCS metric
 * must live here too, or the "pc-only" comparison arms silently keep value coverage
 * for most of the fleet (only the 2 raw common.h grains would honor it). Read once
 * from KSMBDZZER_ENGINE: blind=1 (pc-i2s/pc-havoc) folds the kernel PC ONLY, exactly
 * what an edge/pc fuzzer sees; blind=0 (dataflow) folds the observed argument/return
 * VALUE too. g_pc_bitmap counts the distinct kernel PCs this worker reached across
 * the run (the trustworthy cross-arm metric — libFuzzer's ft conflates harness edges
 * with value buckets); reported at exit as KERNEL_PCS=N, parsed by gen.py. */
static int g_eng_blind = -1;               /* -1 = unresolved; 1 = pc-only coverage */
static int g_eng_i2s   = 1;                /* 1 = i2s-directed mutation, 0 = pure havoc */
#define PFZ_PC_BITS (1u << 17)
static uint8_t g_pc_bitmap[PFZ_PC_BITS / 8];
static void pfz_pc_mark(uint64_t pc) {
    uint64_t h = pc * 0x9E3779B97F4A7C15ULL;
    uint32_t i = (uint32_t)(h >> 47) & (PFZ_PC_BITS - 1);
    g_pc_bitmap[i >> 3] |= (uint8_t)(1u << (i & 7));
}
static void pfz_engine_init(void) {
    if (g_eng_blind >= 0) return;
    const char *e = getenv("KSMBDZZER_ENGINE");
    /* pc-i2s and pc-havoc are the two pc-only arms; dataflow (default) is value-fold.
     * i2s is ON for dataflow + pc-i2s, OFF only for pc-havoc (the pure-havoc control). */
    g_eng_blind = (e && (!strcmp(e, "pc-i2s") || !strcmp(e, "pc-havoc"))) ? 1 : 0;
    g_eng_i2s   = (e && !strcmp(e, "pc-havoc")) ? 0 : 1;
}

/* ─── Reverse-flow RedQueen dictionary + i2s proof counters (fleet-wide) ────────
 * Parity with grain/common.h, but for the LIB-backed grains (the majority of the
 * fleet). Kernel RETURN values (0xF) are harvested every exec inside pfz_get_features
 * into a persistent deduped ring; pfz_mutate_i2s() splices them (and this-exec cmp
 * operands / entry-arg values) into the next input. g_ret_hits/g_cmp_hits are the
 * proof the bi-directional loop fires; pfz_report_metrics() prints them at exit so
 * the comparison table's ret_hits/cmp_hits cover the WHOLE fleet, not just the 2 raw
 * common.h grains. */
#define PFZ_RETDICT_N 512
static uint64_t g_retdict[PFZ_RETDICT_N];
static uint32_t g_retdict_n;
static uint8_t  g_retdict_seen[8192];
static unsigned long g_ret_hits;
static unsigned long g_cmp_hits;
static inline void ret_dict_add(uint64_t v) {
    if (v <= 1 || v >= 0xffff000000000000ULL) return;      /* skip trivial + kernel ptrs */
    uint32_t idx = (uint32_t)((v * 0x9E3779B97F4A7C15ULL) >> 48);
    if (g_retdict_seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) return;
    g_retdict_seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
    g_retdict[g_retdict_n % PFZ_RETDICT_N] = v;
    if (g_retdict_n < 0xffffffffu) g_retdict_n++;
}
static void pfz_report_metrics(void) {
    unsigned c = 0;
    for (unsigned i = 0; i < sizeof(g_pc_bitmap); i++)
        c += (unsigned)__builtin_popcount(g_pc_bitmap[i]);
    /* fleet-wide, parsed by gen.py / engine_compare_campagin.sh table */
    pfz_err("KERNEL_PCS=%u RET_TOKEN_HITS=%lu CMP_I2S_HITS=%lu RET_DICT=%u\n",
            c, g_ret_hits, g_cmp_hits,
            g_retdict_n < PFZ_RETDICT_N ? g_retdict_n : PFZ_RETDICT_N);
}

/* ─── Auth callback ─────────────────────────────────────────────────────── */
static void auth_fn(const char *srv, const char *shr,
                    char *wg, int wglen, char *un, int unlen, char *pw, int pwlen)
{
    strncpy(wg, "WORKGROUP", wglen - 1);
    strncpy(un, "fuzz", unlen - 1);
    strncpy(pw, "fuzz", pwlen - 1);
}

/* ─── Public API ────────────────────────────────────────────────────────── */

/**
 * pfz_init - Initialize session + kcov_df + raw socket for one worker.
 * @worker_octet: selects this worker's loopback address 127.0.0.<octet> and
 *   the matching kcov_df remote handle. Pass a distinct value per parallel
 *   worker (1..254); 0 is treated as 1 (127.0.0.1, the single-process default).
 *
 * All of this worker's connections (libsmbclient + raw TCP) dial the same
 * 127.0.0.<octet>, so the kernel routes their coverage into this worker's
 * private buffer. Returns 0 on success, -1 on failure.
 */
int pfz_init(unsigned long worker_octet)
{
    g_worker_octet = (worker_octet >= 1 && worker_octet <= 254)
                     ? (int)worker_octet : 1;
    snprintf(g_target_ip, sizeof(g_target_ip), "127.0.0.%d", g_worker_octet);
    pfz_engine_init();                 /* resolve pc-only vs value-fold vs havoc for this arm */
    atexit(pfz_report_metrics);        /* emit KERNEL_PCS/RET_TOKEN_HITS/CMP_I2S_HITS */

    /* 1. kcov_dataflow — register the handle the kernel derives from our IP */
    g_df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (g_df_fd >= 0) {
        unsigned long handle = KSMBD_KCOV_DF_IP_HANDLE((unsigned long)g_worker_octet);
        ioctl(g_df_fd, KCOV_DF_INIT_TRACE, (unsigned long)DF_BUF_WORDS);
        g_df_buf = mmap(NULL, DF_BUF_WORDS * 8, PROT_READ | PROT_WRITE,
                        MAP_SHARED, g_df_fd, 0);
        if (g_df_buf == MAP_FAILED) g_df_buf = NULL;
        if (g_df_buf) {
            /*
             * A non-zero return here means another worker already owns this
             * handle (EEXIST) or the device rejected us — coverage would be
             * silently dead, so make the failure loud instead.
             */
            if (ioctl(g_df_fd, KCOV_DF_REMOTE_ENABLE, handle) != 0) {
                pfz_err(
                    "[ksmbdzzer] REMOTE_ENABLE(0x%lx) failed for %s: %s — "
                    "coverage disabled for this worker\n",
                    handle, g_target_ip, strerror(errno));
                munmap(g_df_buf, DF_BUF_WORDS * 8);
                g_df_buf = NULL;
            }
        }
    } else {
        pfz_err("[ksmbdzzer] open(kcov_dataflow) failed: %s — "
                "running without coverage feedback\n", strerror(errno));
    }

    /* 2. libsmbclient session (dials this worker's IP).
     * Use the context API (smbc_init() is deprecated). smbc_set_context() installs
     * it as the global default, so the smbc_open()/smbc_read()/... calls below use
     * it transparently — same behavior as smbc_init(auth_fn, 0). */
    char url[64];
    SMBCCTX *smbctx = smbc_new_context();
    if (!smbctx) return -1;
    smbc_setFunctionAuthData(smbctx, auth_fn);
    if (!smbc_init_context(smbctx)) { smbc_free_context(smbctx, 1); return -1; }
    /* Bound EVERY libsmbclient op (smbc_open/read/write/opendir) to 5s. Without
     * this, libsmbclient's socket has no timeout (unlike the raw pool sockets,
     * which set SO_RCVTIMEO), so a wedged/degraded ksmbd makes any smbc_* call
     * block indefinitely — an grain stuck in an uninterruptible read can't even
     * be reaped by the harness SIGKILL. This is the smbc analogue of the raw-socket
     * SO_RCVTIMEO and closes the last "grain blocks forever on a bad server" hole. */
    smbc_setTimeout(smbctx, 5000);
    smbc_set_context(smbctx);
    snprintf(url, sizeof(url), "smb://%s/share/fuzz_target", g_target_ip);
    g_smb_fd = smbc_open(url, O_RDWR | O_CREAT, 0666);
    if (g_smb_fd < 0) return -1;
    snprintf(url, sizeof(url), "smb://%s/share/fuzz_race", g_target_ip);
    g_smb_fd2 = smbc_open(url, O_RDWR | O_CREAT, 0666);

    /* 3. Raw TCP (for PDU injection) — same IP so it routes to our buffer */
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(445) };
    addr.sin_addr.s_addr = inet_addr(g_target_ip);
    g_raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_raw_sock >= 0) {
        struct timeval tv = {.tv_sec = 2};
        setsockopt(g_raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        connect(g_raw_sock, (struct sockaddr *)&addr, sizeof(addr));
    }

    return 0;
}

/**
 * pfz_reset - Reset coverage buffer (call before each operation).
 */
void pfz_reset(void)
{
    if (g_df_buf) g_df_buf[0] = 0;
}

/**
 * pfz_write - Write data via libsmbclient at offset.
 * Returns bytes written or -1.
 */
int pfz_write(long offset, const void *buf, int len)
{
    if (g_smb_fd < 0) return -1;
    smbc_lseek(g_smb_fd, offset, SEEK_SET);
    return smbc_write(g_smb_fd, buf, len);
}

/**
 * pfz_truncate - Truncate file via libsmbclient.
 */
int pfz_truncate(long size)
{
    if (g_smb_fd < 0) return -1;
    return smbc_ftruncate(g_smb_fd, size);
}

/**
 * pfz_setxattr - Set extended attribute via libsmbclient.
 */
int pfz_setxattr(const char *name, const void *val, int vlen)
{
    if (g_smb_fd < 0) return -1;
    return smbc_fsetxattr(g_smb_fd, name, val, vlen, 0);
}

/* write-side: write at a FULL 64-bit fuzzed offset (grain_write masks to 16MB) —
 * drives ksmbd_vfs_write()'s pos to sparse/boundary values (holes, >4GB, ~2^63),
 * exercising the size/quota/hole paths grain_write never reaches. */
int pfz_write_ext(unsigned long long offset, const void *buf, int len)
{
    if (g_smb_fd < 0) return -1;
    smbc_lseek(g_smb_fd, (off_t)offset, SEEK_SET);
    return smbc_write(g_smb_fd, buf, len);
}

/* write-side: SET_INFO basic-info surface — file mode + a/mtime with fuzzed values
 * (smbc_chmod/smbc_utimes) → ksmbd set_file_basic_info / notify_change / vfs setattr. */
int pfz_setattr(unsigned int mode, long atime, long mtime)
{
    char url[64];
    snprintf(url, sizeof(url), "smb://%s/share/fuzz_target", g_target_ip);
    struct timeval tv[2];
    tv[0].tv_sec = atime; tv[0].tv_usec = 0;
    tv[1].tv_sec = mtime; tv[1].tv_usec = 0;
    smbc_utimes(url, tv);
    return smbc_chmod(url, (mode_t)(mode & 07777));
}

/* write-side: rename-path fuzzing — rename a dedicated victim to a fuzzed name
 * component (traversal/unicode/casing), then rename back so the victim persists.
 * Exercises ksmbd's SMB2 rename + path resolution (ksmbd_vfs_rename, symlink
 * follow, cross-dir), a classic write-side / traversal attack surface. */
int pfz_rename(const void *name, int nlen)
{
    char src[80], dst[160], nm[64];
    int j = 0;
    for (int i = 0; i < nlen && j < (int)sizeof(nm) - 1; i++) {
        uint8_t c = ((const uint8_t *)name)[i];
        if (c >= 0x20 && c < 0x7f && c != '?' && c != '*') nm[j++] = (char)c;
    }
    if (j == 0) { nm[j++] = 'r'; }
    nm[j] = 0;
    snprintf(src, sizeof(src), "smb://%s/share/rename_v", g_target_ip);
    int fd = smbc_open(src, O_RDWR | O_CREAT, 0666);   /* ensure victim exists (preamble) */
    if (fd >= 0) smbc_close(fd);
    snprintf(dst, sizeof(dst), "smb://%s/share/%s", g_target_ip, nm);
    int r = smbc_rename(src, dst);
    if (r == 0) smbc_rename(dst, src);                 /* restore */
    return r;
}

/* write-side ACL: set an NT security descriptor with fuzzed owner RID + ACE
 * type/flags/access-mask. The SDDL (REVISION/OWNER/GROUP/ACL per libsmbclient) is
 * parsed client-side into a binary SD and applied by ksmbd (smb2 set_info_sec →
 * ndr_decode_dacl / ksmbd_vfs_set_sd_xattr) — the write-side access-control /
 * ACL-modification surface the contract oracle targets. */
int pfz_set_secdesc(const void *d, int n)
{
    const uint8_t *p = d; char url[80], sd[256];
    /* Target [aclshare]: it is the ONLY share with `vfs objects = ... acl_xattr`,
     * i.e. the one whose security-descriptor write path (smb_check_perm_dacl /
     * smbacl.c / ksmbd_vfs_set_sd_xattr) is active. [share] has streams_xattr only
     * and silently no-ops SD writes. force user = fuzz there → real perm checks. */
    snprintf(url, sizeof(url), "smb://%s/aclshare/acl_victim", g_target_ip);
    int fd = smbc_open(url, O_RDWR | O_CREAT, 0666);   /* preamble: ensure victim exists */
    if (fd >= 0) smbc_close(fd);
    unsigned rid  = n >= 4  ? *(const uint32_t *)(p)     : 500;
    unsigned mask = n >= 8  ? *(const uint32_t *)(p + 4) : 0x001f01ffu;
    unsigned type = n >= 9  ? (p[8] & 3)                 : 0;   /* 0=ALLOWED 1=DENIED */
    unsigned flg  = n >= 10 ? (p[9] & 0x1f)              : 0;
    unsigned arid = n >= 14 ? *(const uint32_t *)(p + 10): 545;
    snprintf(sd, sizeof(sd),
        "REVISION:1,OWNER:S-1-5-21-1-2-3-%u,GROUP:S-1-5-21-1-2-3-513,"
        "ACL:S-1-5-21-1-2-3-%u:%u/%u/0x%08x", rid, arid, type, flg, mask);
    return smbc_setxattr(url, "system.nt_sec_desc.*", sd, strlen(sd), 0);
}

/* write-side DOS attrs: set system.dos_attr.mode (readonly/hidden/system/archive)
 * with fuzzed bits → ksmbd DOS-attribute write (xattr-backed metadata / set_info). */
int pfz_set_dosattr(unsigned int mode)
{
    char url[64], val[16];
    snprintf(url, sizeof(url), "smb://%s/share/fuzz_target", g_target_ip);
    snprintf(val, sizeof(val), "0x%x", mode & 0x3f);
    return smbc_setxattr(url, "system.dos_attr.mode", val, strlen(val), 0);
}

/* write-side namespace: unlink a dedicated victim (recreated as preamble) →
 * ksmbd SMB2 set-disposition + unlink path. */
int pfz_unlink_victim(void)
{
    char url[80];
    snprintf(url, sizeof(url), "smb://%s/share/unlink_v", g_target_ip);
    int fd = smbc_open(url, O_RDWR | O_CREAT, 0666);   /* preamble: ensure it exists */
    if (fd >= 0) smbc_close(fd);
    return smbc_unlink(url);
}

/* write-side namespace: mkdir a fuzzed-named dir then rmdir it → ksmbd dir
 * create/remove + path resolution. */
int pfz_mkrmdir(const void *name, int nlen)
{
    char url[160], nm[64]; int j = 0;
    for (int i = 0; i < nlen && j < (int)sizeof(nm) - 1; i++) {
        uint8_t c = ((const uint8_t *)name)[i];
        if (c >= 0x20 && c < 0x7f && c != '?' && c != '*' && c != '/' && c != '\\')
            nm[j++] = (char)c;
    }
    if (j == 0) nm[j++] = 'd';
    nm[j] = 0;
    snprintf(url, sizeof(url), "smb://%s/share/mkd_%s", g_target_ip, nm);
    int r = smbc_mkdir(url, 0755);
    smbc_rmdir(url);
    return r;
}

/* write-side EA: set then remove a user xattr → ksmbd EA add + remove paths. */
int pfz_rmxattr(const void *d, int n)
{
    if (g_smb_fd < 0) return -1;
    smbc_fsetxattr(g_smb_fd, "user.rmv", d, n > 128 ? 128 : n, 0);
    return smbc_fremovexattr(g_smb_fd, "user.rmv");
}

/**
 * pfz_raw_pdu - Send raw SMB2 PDU bytes and receive response.
 * Returns response length or -1.
 */
int pfz_raw_pdu(const void *pdu, int len, void *resp, int resp_max)
{
    if (g_raw_sock < 0) return -1;
    uint32_t nb = htonl(len);
    if (write(g_raw_sock, &nb, 4) < 0) return -1;
    if (write(g_raw_sock, pdu, len) < 0) return -1;

    uint32_t rlen;
    if (read(g_raw_sock, &rlen, 4) != 4) return -1;
    rlen = ntohl(rlen);
    if (rlen > (uint32_t)resp_max) rlen = resp_max;
    int got = 0;
    while (got < (int)rlen) {
        int r = read(g_raw_sock, (char *)resp + got, rlen - got);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

/**
 * pfz_get_features - Extract coverage features from kcov_df buffer.
 * Returns number of features written to out[].
 */
int pfz_get_features(uint32_t *out, int max)
{
    if (!g_df_buf) return 0;
    uint64_t n = g_df_buf[0];
    if (n == 0) return 0;
    /* Overflow: kernel may report more words than fit. Parse what's in-bounds
     * instead of discarding the whole round's coverage. */
    if (n > DF_BUF_WORDS - 1) n = DF_BUF_WORDS - 1;

    int count = 0;
    uint64_t pos = 1;
    while (pos + 3 <= 1 + n && count < max) {
        uint64_t header = g_df_buf[pos];
        uint64_t pc = g_df_buf[pos + 1];
        int rtype = (header >> 28) & 0xF;
        int nfields = (header >> 24) & 0xF;
        if (!nfields) nfields = 1;
        uint64_t rlen = 3 + nfields;
        if (pos + rlen > 1 + n) break;

        if (pc >= 0xffffffff80000000UL) {
            pfz_pc_mark(pc);                    /* KERNEL_PCS metric (distinct PCs reached) */
            if (rtype == 0xF) ret_dict_add(g_df_buf[pos + 3]);   /* reverse-flow harvest */
            uint64_t val = g_df_buf[pos + 3];
            uint64_t h = 0xcbf29ce484222325UL;
            if (g_eng_blind || rtype == 0xC) {   /* PC only:
                * - blind arm (pc-i2s/pc-havoc): what an edge/pc fuzzer sees, so the
                *   comparison actually ablates the dataflow VALUE contribution;
                * - cmp (0xC) always: operands are input-derived, folding them as
                *   coverage would explode the map — the pair feeds mutate_i2s (i2s). */
                h ^= pc; h *= 0x100000001b3UL;
            } else if (rtype == 0xE) { h ^= val; h *= 0x100000001b3UL; }
            else { h ^= pc; h *= 0x100000001b3UL; h ^= val; h *= 0x100000001b3UL; }
            out[count++] = (uint32_t)(h & 0xFFFFFFFF);
        }
        pos += rlen;
    }
    return count;
}


/**
 * pfz_get_pc_ret_pairs - Extract (PC, return_value) pairs for return records.
 * out format: out[i*2] = PC, out[i*2+1] = ret_value. Returns pair count.
 */
int pfz_get_pc_ret_pairs(uint64_t *out, int max_pairs)
{
    if (!g_df_buf) return 0;
    uint64_t n = g_df_buf[0];
    if (n == 0) return 0;
    /* Overflow: kernel may report more words than fit. Parse what's in-bounds
     * instead of discarding the whole round's coverage. */
    if (n > DF_BUF_WORDS - 1) n = DF_BUF_WORDS - 1;
    int count = 0;
    uint64_t pos = 1;
    while (pos + 3 <= 1 + n && count < max_pairs) {
        uint64_t header = g_df_buf[pos];
        uint64_t pc = g_df_buf[pos + 1];
        int rtype = (header >> 28) & 0xF;
        int nfields = (header >> 24) & 0xF;
        if (!nfields) nfields = 1;
        uint64_t rlen = 3 + nfields;
        if (pos + rlen > 1 + n) break;
        if (pc >= 0xffffffff80000000UL && rtype == 0xF) { /* 0xF = return */
            out[count * 2] = pc;
            out[count * 2 + 1] = g_df_buf[pos + 3];
            count++;
        }
        pos += rlen;
    }
    return count;
}


/**
 * pfz_mutate_i2s - Dataflow-directed (RedQueen / input-to-state) mutation for the
 * LIB-backed grain fleet, so i2s and its proof counters are FLEET-WIDE (not just the
 * 2 raw common.h grains). Mirrors grain/common.h mutate_i2s: consults the df_buf
 * the previous grain execution populated (last-exec state — the standard libFuzzer
 * custom-mutator model) plus the persistent g_retdict, and splices:
 *   pass 0: trace_cmp (0xC) operand pairs — flip a magic-value gate in one step;
 *   pass 2: kernel RETURN tokens (reverse flow) and entry-arg (0xE) values into the
 *           input bytes that encode them.
 * Engine-gated: returns the new size when it steered, or 0 to tell the caller to fall
 * back to plain havoc — so pc-havoc (g_eng_i2s=0) and 2-of-3 exploration execs stay
 * pure havoc. The caller keeps LLVMFuzzerMutate in the GRAIN (where libFuzzer's
 * symbol resolves); this function is pure memory ops with no libFuzzer dependency. */
static const uint64_t _PFZ_B8[] = {0,1,0x7fffffffULL,0x80000000ULL,0xffffffffULL,
    0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0x1000ULL};
static const uint32_t _PFZ_B4[] = {0,1,0x7fffffffu,0x80000000u,0xffffffffu,0x100u,0x112u,0x1000u};
static const uint16_t _PFZ_B2[] = {0,1,0x7fff,0x8000,0xffff,0x70,0x71,0x100};

size_t pfz_mutate_i2s(uint8_t *data, size_t size, size_t maxsize, unsigned seed)
{
    (void)maxsize;
    pfz_engine_init();
    if (!g_eng_i2s || (seed % 3u) != 0u) return 0;   /* pc-havoc / 2-of-3 execs → havoc */
    if (!g_df_buf) return 0;
    uint64_t n = g_df_buf[0], pos;
    int hits = 0;

    /* pass 0 — trace_cmp RedQueen: overwrite one observed operand with the other */
    for (pos = 1; pos + 3 <= 1 + n && pos < DF_BUF_WORDS; ) {
        uint32_t rt = (g_df_buf[pos] >> 28) & 0xF, nf = (g_df_buf[pos] >> 24) & 0xF;
        if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xC && nf >= 2) {
            uint64_t ctype = g_df_buf[pos+2], a1 = g_df_buf[pos+3], a2 = g_df_buf[pos+4];
            int w = 1 << ((ctype >> 1) & 3);              /* KCOV_CMP_SIZE: 1/2/4/8B */
            if (w >= 2 && a1 != a2) {
                for (int dir = 0; dir < 2; dir++) {
                    uint64_t find = dir ? a2 : a1, put = dir ? a1 : a2;
                    if (find == 0) continue;
                    if (w < 8 && (find >> (w*8))) continue;
                    uint8_t needle[8], repl[8];
                    for (int i=0;i<w;i++){ needle[i]=(find>>(i*8))&0xFF; repl[i]=(put>>(i*8))&0xFF; }
                    for (size_t o = 0; o + (size_t)w <= size; o++) {
                        if (memcmp(data+o, needle, w)) continue;
                        for (int i=0;i<w;i++) data[o+i] = repl[i];
                        hits++; g_cmp_hits++;
                        break;
                    }
                }
            }
        }
        pos += 3 + nf;
    }

    /* pass 1 — collect THIS exec's return values (supplement the persistent dict) */
    uint64_t rets[32]; int nret = 0;
    for (pos = 1; pos + 3 <= 1 + n && pos < DF_BUF_WORDS && nret < 32; ) {
        uint32_t rt = (g_df_buf[pos] >> 28) & 0xF, nf = (g_df_buf[pos] >> 24) & 0xF;
        if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xF) { uint64_t rv = g_df_buf[pos+3];
            if (rv > 1 && rv < 0xffff000000000000ULL) rets[nret++] = rv; }
        pos += 3 + nf;
    }

    /* pass 2 — drive entry-arg (0xE) fields, preferring a kernel RETURN token */
    for (pos = 1; pos + 3 <= 1 + n && pos < DF_BUF_WORDS; ) {
        uint32_t rt = (g_df_buf[pos] >> 28) & 0xF, nf = (g_df_buf[pos] >> 24) & 0xF;
        if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xE) {
            for (uint32_t k = 0; k < nf; k++) {
                uint64_t v = g_df_buf[pos+3+k];
                if (v == 0 || v == 0xBADADD85ULL) continue;
                for (int w = 8; w >= 2; w >>= 1) {
                    if (w < 8 && (v >> (w*8))) continue;
                    uint8_t needle[8]; for (int i=0;i<w;i++) needle[i] = (v>>(i*8))&0xFF;
                    for (size_t o = 0; o + (size_t)w <= size; o++) {
                        if (memcmp(data+o, needle, w)) continue;
                        unsigned pick = seed + (unsigned)o + k*7u;
                        uint64_t repl; int from_ret = 0;
                        uint32_t rdn = g_retdict_n < PFZ_RETDICT_N ? g_retdict_n : PFZ_RETDICT_N;
                        if (rdn && (pick & 3u) == 0) { repl = g_retdict[pick % rdn]; from_ret = 1; }
                        else if (nret && (pick & 3u) == 2) { repl = rets[pick % (unsigned)nret]; from_ret = 1; }
                        else if (w == 8) repl = _PFZ_B8[pick % (sizeof(_PFZ_B8)/8)];
                        else if (w == 4) repl = _PFZ_B4[pick % (sizeof(_PFZ_B4)/4)];
                        else            repl = _PFZ_B2[pick % (sizeof(_PFZ_B2)/2)];
                        for (int i=0;i<w;i++) data[o+i] = (repl>>(i*8))&0xFF;
                        hits++; if (from_ret) g_ret_hits++;
                        break;
                    }
                    if (hits) break;
                }
            }
        }
        pos += 3 + nf;
    }
    return hits ? size : 0;      /* 0 ⇒ caller falls back to LLVMFuzzerMutate (havoc) */
}


/* ─── Full dataflow record export (I2S mutator + contract oracle) ──────────── */

/*
 * One decoded TLV record. Unlike the feature/PC getters this preserves the
 * argument index, size and per-field values, which the Python side needs to
 * (a) match observed argument values back to input bytes (input-to-state) and
 * (b) evaluate access-control contracts at specific function boundaries.
 * Layout mirrored by ctypes in ksmbdzzer.py.
 */
struct pfz_rec {
    uint64_t pc;        /* instrumented function address */
    uint64_t vals[6];   /* scalar value, or up to 6 decomposed struct fields */
    uint32_t type;      /* 0xE = entry (args), 0xF = return */
    uint32_t arg_idx;   /* source-level argument index (0 for return) */
    uint32_t size;      /* argument size in bytes */
    uint32_t nfields;   /* number of valid entries in vals[] */
    uint32_t seq;       /* per-task sequence number (groups args of one call) */
    uint32_t _pad;
};

/**
 * pfz_get_records - Decode the kcov_df buffer into structured records.
 * Returns the number of records written to out[] (capped at max).
 */
int pfz_get_records(struct pfz_rec *out, int max)
{
    if (!g_df_buf) return 0;
    uint64_t n = g_df_buf[0];
    if (n == 0) return 0;
    if (n > DF_BUF_WORDS - 1) n = DF_BUF_WORDS - 1;

    int count = 0;
    uint64_t pos = 1;
    while (pos + 3 <= 1 + n && count < max) {
        uint64_t header = g_df_buf[pos];
        uint64_t pc = g_df_buf[pos + 1];
        uint64_t meta = g_df_buf[pos + 2];
        int rtype = (header >> 28) & 0xF;
        int nfields = (header >> 24) & 0xF;
        if (!nfields) nfields = 1;
        uint64_t rlen = 3 + nfields;
        if (pos + rlen > 1 + n) break;

        if (pc >= 0xffffffff80000000UL && (rtype == 0xE || rtype == 0xF)) {
            struct pfz_rec *r = &out[count++];
            r->pc = pc;
            r->type = (uint32_t)rtype;
            r->arg_idx = (meta >> 56) & 0xFF;
            r->size = (meta >> 48) & 0xFF;
            r->seq = (uint32_t)(header & 0x00FFFFFF);
            int nv = nfields > 6 ? 6 : nfields;
            r->nfields = (uint32_t)nv;
            r->_pad = 0;
            for (int i = 0; i < nv; i++) r->vals[i] = g_df_buf[pos + 3 + i];
            for (int i = nv; i < 6; i++) r->vals[i] = 0;
        }
        pos += rlen;
    }
    return count;
}

/* ─── Race primitives ───────────────────────────────────────────────────── */

struct race_ctx { const void *data; int len; int iters; };

static void *_race_writer(void *arg)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    struct race_ctx *ctx = arg;
    for (int i = 0; i < ctx->iters; i++) {
        pthread_mutex_lock(&g_smbc_lock);
        smbc_lseek(g_smb_fd, (i * 4096) & 0xFFFFF, SEEK_SET);
        smbc_write(g_smb_fd, ctx->data, ctx->len > 4096 ? 4096 : ctx->len);
        pthread_mutex_unlock(&g_smbc_lock);
    }
    return NULL;
}

static void *_race_closer(void *arg)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset); CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    (void)arg;
    usleep(100);
    pthread_mutex_lock(&g_smbc_lock);
    smbc_close(g_smb_fd2);
    char _u[64];
    snprintf(_u, sizeof(_u), "smb://%s/share/fuzz_race", g_target_ip);
    g_smb_fd2 = smbc_open(_u, O_RDWR | O_CREAT, 0666);
    pthread_mutex_unlock(&g_smbc_lock);
    return NULL;
}

/**
 * pfz_race_write_close - Race WRITE on fd1 against CLOSE on fd2.
 * Targets UAF when conn->fp accessed after disconnect.
 */
int pfz_race_write_close(const void *data, int len, int iters)
{
    struct race_ctx ctx = { .data = data, .len = len, .iters = iters };
    pthread_t tw, tc;
    pthread_create(&tw, NULL, _race_writer, &ctx);
    pthread_create(&tc, NULL, _race_closer, NULL);
    pthread_join(tw, NULL);
    pthread_join(tc, NULL);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* ─── Session state for authed PDU building ─────────────────────────────── */
static uint64_t g_sid = 0;
static uint32_t g_tid = 0;

/**
 * pfz_raw_pdu_authed - Build SMB2 header with real sid/tid/mid, send body.
 * @cmd: SMB2 command code
 * @body: request body (after 64-byte header)
 * @body_len: length of body
 * @resp: response buffer
 * @resp_max: max response length
 * Returns response length or -1.
 */
int pfz_raw_pdu_authed(uint16_t cmd, const void *body, int body_len,
                             void *resp, int resp_max)
{
    if (g_raw_sock < 0) return -1;
    uint8_t pdu[4096];
    if (body_len > (int)sizeof(pdu) - 64) body_len = sizeof(pdu) - 64;
    memset(pdu, 0, 64);
    memcpy(pdu, "\xfeSMB", 4);
    *(uint16_t *)(pdu + 4) = 64;
    *(uint16_t *)(pdu + 6) = 1;
    *(uint16_t *)(pdu + 12) = cmd;
    *(uint16_t *)(pdu + 14) = 31;
    *(uint64_t *)(pdu + 24) = g_raw_mid++;
    *(uint32_t *)(pdu + 36) = g_tid;
    *(uint64_t *)(pdu + 40) = g_sid;
    memcpy(pdu + 64, body, body_len);
    return pfz_raw_pdu(pdu, 64 + body_len, resp, resp_max);
}

/**
 * pfz_compound - Send a pre-built compound chain PDU.
 * @chain_data: full compound PDU (with all headers already built)
 * @chain_len: total length
 * @resp: response buffer
 * @resp_max: max response length
 * Returns response length or -1.
 */
int pfz_compound(const void *chain_data, int chain_len,
                       void *resp, int resp_max)
{
    return pfz_raw_pdu(chain_data, chain_len, resp, resp_max);
}

/**
 * pfz_reconnect - Close session and reconnect everything.
 * Returns 0 on success, -1 on failure.
 */
int pfz_reconnect(void)
{
    /* Tear down existing state */
    if (g_smb_fd >= 0) { smbc_close(g_smb_fd); g_smb_fd = -1; }
    if (g_smb_fd2 >= 0) { smbc_close(g_smb_fd2); g_smb_fd2 = -1; }
    if (g_raw_sock >= 0) { close(g_raw_sock); g_raw_sock = -1; }
    if (g_df_buf) {
        ioctl(g_df_fd, KCOV_DF_REMOTE_DISABLE, 0);
        munmap(g_df_buf, DF_BUF_WORDS * 8);
        g_df_buf = NULL;
    }
    if (g_df_fd >= 0) { close(g_df_fd); g_df_fd = -1; }

    /* Re-initialize with the same worker identity so we keep our private
     * coverage handle and loopback address. */
    return pfz_init((unsigned long)g_worker_octet);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Multi-Connection Pool + Attack Patterns
 * ======================================================================= */

#define MAX_POOL 8

struct pool_conn {
    int  sock;
    uint64_t sid;
    uint32_t tid;
    uint64_t mid;
    uint8_t  fid[16];
    int      has_fid;
};

static struct pool_conn g_pool[MAX_POOL];
static int g_pool_n = 0;

static void pool_smb2_hdr(uint8_t *buf, uint16_t cmd, struct pool_conn *c)
{
    memset(buf, 0, 64);
    memcpy(buf, "\xfeSMB", 4);
    *(uint16_t *)(buf + 4) = 64;
    *(uint16_t *)(buf + 12) = cmd;
    *(uint16_t *)(buf + 14) = 31;
    *(uint64_t *)(buf + 24) = c->mid++;
    *(uint32_t *)(buf + 36) = c->tid;
    *(uint64_t *)(buf + 40) = c->sid;
}

static int pool_xact(struct pool_conn *c, const void *pdu, int len, void *resp, int rmax)
{
    uint32_t nb = htonl(len);
    if (write(c->sock, &nb, 4) < 0) return -1;
    if (write(c->sock, pdu, len) < 0) return -1;
    uint32_t rlen;
    if (read(c->sock, &rlen, 4) != 4) return -1;
    rlen = ntohl(rlen);
    if (rlen > (uint32_t)rmax) rlen = rmax;
    int got = 0;
    while (got < (int)rlen) {
        int r = read(c->sock, (char *)resp + got, rlen - got);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

/* Full SPNEGO+NTLMv2 authenticated connect (defined below) — the pool reuses it. */
static int pool_connect_auth(struct pool_conn *c, const char *share);

/*
 * Open one authenticated pool connection (session + tree to [share]).
 *
 * NOTE: the previous implementation sent only the NTLMSSP NEGOTIATE (type 1)
 * message and then issued TREE_CONNECT *without ever sending the AUTHENTICATE
 * (type 3) message* — so the session stayed in MORE_PROCESSING_REQUIRED, the
 * tree-connect was rejected, and every pool-based grain saw has_fid=0 (the
 * "fids<2 PREREQ" starvation). The fix is to run the same complete, correct,
 * SPNEGO-wrapped fuzz:fuzz handshake the oracle probe uses, tree-connecting to
 * the guest-writable [share] instead of [privtest]. Returns 0 on success.
 */
static int pool_connect_one(struct pool_conn *c)
{
    return pool_connect_auth(c, "share");
}

static void pool_create_file(struct pool_conn *c, const char *name)
{
    uint8_t pdu[256], resp[256];
    int nlen = strlen(name) * 2;
    pool_smb2_hdr(pdu, 0x0005, c);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F; /* DesiredAccess */
    *(uint32_t *)(b + 28) = 0x80;
    *(uint32_t *)(b + 32) = 0x07; /* ShareAccess */
    *(uint32_t *)(b + 36) = 0x05; /* CREATE_DISPOSITION */
    *(uint32_t *)(b + 40) = 0x40;
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = nlen;
    /* Simple ASCII→UTF-16 */
    for (int i = 0; i < (int)strlen(name); i++) {
        pdu[120 + i*2] = name[i]; pdu[120 + i*2 + 1] = 0;
    }
    int r = pool_xact(c, pdu, 120 + nlen, resp, sizeof(resp));
    /* Only accept a real CREATE success (NTSTATUS==0 + full response). The old
     * `r>=144`-only check set has_fid on error/short responses → grains ran with a
     * garbage fid or (worse) silently believed they had one. FileId is at body+64
     * = abs 128 in the SMB2 CREATE response. */
    uint32_t status = (r >= 12) ? *(uint32_t *)(resp + 8) : 0xFFFFFFFFu;
    if (r >= 144 && status == 0) { memcpy(c->fid, resp + 128, 16); c->has_fid = 1; }
}

/* Working-preamble helper for raw-PDU grains: guarantee an open fid on the pool
 * connection before the fuzzed last endpoint (grain-structure principle — each
 * grain owns its reach-target preamble; duplicated open→fid setup is expected). */
/* Tear down a dead pool connection and re-authenticate it (full SPNEGO+NTLMv2 to
 * [share]). Used when a CREATE fails mid-campaign — the connection was killed by the
 * 2nd-wave session death or by a session/protocol-level grain (encrypt/session_setup/
 * smb1_*). */
static int pool_reconnect(struct pool_conn *c)
{
    if (c->sock >= 0) { close(c->sock); c->sock = -1; }
    c->has_fid = 0; c->sid = 0; c->tid = 0; c->mid = 0;
    return pool_connect_one(c);
}

static int pool_ensure_fid(struct pool_conn *c, const char *name)
{
    if (c->has_fid) return 1;
    pool_create_file(c, name);
    if (c->has_fid) return 1;
    /* CREATE failed → the connection is likely dead. Reconnect + retry ONCE so the
     * grain self-heals instead of BAILing — this is the fids=0-under-load fix (the
     * authed pool loses fids under sustained load / after conn-disrupting grains). */
    if (pool_reconnect(c) == 0)
        pool_create_file(c, name);
    return c->has_fid;
}

/* Generic SMB2 IOCTL(0x0B) sender. need_fid=1 uses the pool's open fid; =0 uses the
 * all-0xFF fid (session-level FSCTLs: validate_negotiate / dfs / netif). Reaches
 * ksmbd's smb2_ioctl dispatch + the per-FSCTL handler with fuzzed input. */
static int pool_ioctl(uint32_t ctl, const void *input, int inlen, int need_fid)
{
    if (g_pool_n < 1) return -1;
    if (need_fid && !pool_ensure_fid(&g_pool[0], "ioctl_v")) return -1;
    uint8_t pdu[1024], resp[1024];
    if (inlen > 400) inlen = 400;
    pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 56);
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 4) = ctl;
    if (need_fid) memcpy(b + 8, g_pool[0].fid, 16);
    else          memset(b + 8, 0xFF, 16);
    *(uint32_t *)(b + 24) = 64 + 56;         /* InputOffset */
    *(uint32_t *)(b + 28) = inlen;           /* InputCount */
    *(uint32_t *)(b + 44) = 4096;            /* MaxOutputResponse */
    *(uint32_t *)(b + 48) = 1;               /* Flags = IS_FSCTL */
    if (inlen > 0) memcpy(b + 56, input, inlen);
    return pool_xact(&g_pool[0], pdu, 64 + 56 + inlen, resp, sizeof(resp));
}

/* Build+send a CREATE(0x05) carrying ONE create context (tag+data) → exercises
 * ksmbd's create-context parser (smb2_find_context_vals + the per-tag handler:
 * ExtA/SecD/MxAc/AlSi/QFid/POSIX). tag is the 4-16 byte context name. */
static int pool_create_with_ctx(const char *name, const char *tag, int taglen,
                                const void *data, int datalen)
{
    if (g_pool_n < 1) return -1;
    struct pool_conn *c = &g_pool[0];
    uint8_t pdu[1024], resp[512];
    if (datalen > 400) datalen = 400;
    int nlen = strlen(name) * 2;
    pool_smb2_hdr(pdu, 0x0005, c);
    uint8_t *b = pdu + 64;
    memset(b, 0, 56);
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;        /* DesiredAccess */
    *(uint32_t *)(b + 28) = 0x80;            /* FileAttributes */
    *(uint32_t *)(b + 32) = 0x07;            /* ShareAccess */
    *(uint32_t *)(b + 36) = 0x05;            /* Disposition = OVERWRITE_IF */
    *(uint32_t *)(b + 40) = 0x40;            /* Options */
    *(uint16_t *)(b + 44) = 120;             /* NameOffset (from hdr) */
    *(uint16_t *)(b + 46) = nlen;            /* NameLength */
    for (int i = 0; i < (int)strlen(name); i++) { pdu[120 + i*2] = name[i]; pdu[120 + i*2 + 1] = 0; }
    int ctx = (120 + nlen + 7) & ~7;         /* 8-aligned context offset */
    int dataoff = 16 + ((taglen + 7) & ~7);  /* data after the (aligned) tag name */
    memset(pdu + ctx, 0, dataoff);
    *(uint32_t *)(pdu + ctx + 0)  = 0;               /* Next (last) */
    *(uint16_t *)(pdu + ctx + 4)  = 16;              /* NameOffset (rel) */
    *(uint16_t *)(pdu + ctx + 6)  = taglen;          /* NameLength */
    *(uint16_t *)(pdu + ctx + 10) = dataoff;         /* DataOffset (rel) */
    *(uint32_t *)(pdu + ctx + 12) = datalen;         /* DataLength */
    memcpy(pdu + ctx + 16, tag, taglen);
    if (datalen > 0) memcpy(pdu + ctx + dataoff, data, datalen);
    int cclen = dataoff + datalen;
    *(uint32_t *)(b + 48) = ctx;             /* CreateContextsOffset (from hdr) */
    *(uint32_t *)(b + 52) = cclen;           /* CreateContextsLength */
    int r = pool_xact(c, pdu, ctx + cclen, resp, sizeof(resp));
    if (r >= 144 && (*(uint32_t *)(resp + 8)) == 0) { memcpy(c->fid, resp + 128, 16); c->has_fid = 1; }
    return r;
}

/* Generic SMB2 SET_INFO(0x11) FILE-info sender on the pool's open fid → the
 * write-side metadata handlers (smb2_set_info + ksmbd_vfs_*). info_class is the
 * FILE_*_INFORMATION number; data/dlen is the fuzzed info buffer. */
static int pool_setinfo(uint8_t info_class, const void *data, int dlen)
{
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "si_v")) return -1;
    uint8_t pdu[512], resp[128];
    if (dlen > 400) dlen = 400;
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 32);
    *(uint16_t *)b = 33;
    b[2] = 1;                                 /* InfoType = SMB2_O_INFO_FILE */
    b[3] = info_class;                        /* FileInfoClass */
    *(uint32_t *)(b + 4) = dlen;              /* BufferLength */
    *(uint16_t *)(b + 8) = 64 + 32;           /* BufferOffset */
    memcpy(b + 16, g_pool[0].fid, 16);
    if (dlen > 0) memcpy(b + 32, data, dlen);
    return pool_xact(&g_pool[0], pdu, 64 + 32 + dlen, resp, sizeof(resp));
}

/**
 * pfz_pool_init - Open N authenticated connections with files open.
 */
int pfz_pool_init(int n)
{
    if (n > MAX_POOL) n = MAX_POOL;
    g_pool_n = 0;
    for (int i = 0; i < n; i++) {
        if (pool_connect_one(&g_pool[i]) < 0) break;
        char fname[32];
        snprintf(fname, sizeof(fname), "pool_%d", i);
        pool_create_file(&g_pool[i], fname);
        g_pool_n++;
    }
    return g_pool_n;
}

/* ─── NTLMv2 authenticated connect (for DesiredAccess-honoring shares) ─────── */
#include "grain/ntlmv2.h"   /* ntlmv2_response() — links against -lcrypto */

/* Build an NTLMSSP AUTHENTICATE (type 3) message for fuzz:fuzz. */
static int build_ntlmssp_auth(const uint8_t server_chal[8], uint8_t *out)
{
    uint8_t nt_resp[80], lm_resp[32];
    int nt_len = 0, lm_len = 0;
    ntlmv2_response(server_chal, nt_resp, &nt_len, lm_resp, &lm_len);
    static const uint8_t user_u16[] = { 'f',0,'u',0,'z',0,'z',0 };
    int user_len = (int)sizeof(user_u16);

    memset(out, 0, 64);
    memcpy(out, "NTLMSSP\x00", 8);
    *(uint32_t *)(out + 8) = 3;                 /* MessageType = AUTHENTICATE */

    int p = 64;                                 /* payload starts after header */
    int lm_off = p; memcpy(out + p, lm_resp, lm_len); p += lm_len;
    int nt_off = p; memcpy(out + p, nt_resp, nt_len); p += nt_len;
    int dom_off = p;                            /* empty domain */
    int usr_off = p; memcpy(out + p, user_u16, user_len); p += user_len;
    int ws_off  = p;                            /* empty workstation */
    int key_off = p;                            /* empty session key */

    /* security buffers: len(2) maxlen(2) offset(4) */
    *(uint16_t *)(out + 12) = lm_len; *(uint16_t *)(out + 14) = lm_len; *(uint32_t *)(out + 16) = lm_off;
    *(uint16_t *)(out + 20) = nt_len; *(uint16_t *)(out + 22) = nt_len; *(uint32_t *)(out + 24) = nt_off;
    *(uint16_t *)(out + 28) = 0;      *(uint16_t *)(out + 30) = 0;      *(uint32_t *)(out + 32) = dom_off;
    *(uint16_t *)(out + 36) = user_len; *(uint16_t *)(out + 38) = user_len; *(uint32_t *)(out + 40) = usr_off;
    *(uint16_t *)(out + 44) = 0;      *(uint16_t *)(out + 46) = 0;      *(uint32_t *)(out + 48) = ws_off;
    *(uint16_t *)(out + 52) = 0;      *(uint16_t *)(out + 54) = 0;      *(uint32_t *)(out + 56) = key_off;
    *(uint32_t *)(out + 60) = 0xe2088215;       /* NegotiateFlags (match common.h smb_auth) */
    return p;                                   /* total message length */
}

/* Build a UTF-16LE \\<ip>\<share> UNC into out, returns byte length. */
static int build_unc_utf16(const char *share, uint8_t *out)
{
    char unc[128];
    int n = snprintf(unc, sizeof(unc), "\\\\%s\\%s", g_target_ip, share);
    int len = 0;
    for (int i = 0; i < n; i++) { out[len++] = unc[i]; out[len++] = 0; }
    return len;
}

/* DER definite length (handles <256, enough for our NTLMSSP blobs). */
static int der_len(uint8_t *p, int len)
{
    if (len < 0x80) { p[0] = (uint8_t)len; return 1; }
    p[0] = 0x81; p[1] = (uint8_t)len; return 2;
}

/* NTLMSSP OID 1.3.6.1.4.1.311.2.2.10 and SPNEGO OID 1.3.6.1.5.5.2 (DER). */
static const uint8_t OID_NTLMSSP[] = {0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
static const uint8_t OID_SPNEGO[]  = {0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02};

/* Wrap an NTLMSSP NEGOTIATE in a GSS-API SPNEGO NegTokenInit. Returns length. */
static int spnego_wrap_init(const uint8_t *ntlm, int nlen, uint8_t *out)
{
    uint8_t inner[1024]; int p = 0, l;
    /* [2] mechToken { OCTET STRING ntlm } */
    uint8_t mt[1024]; int m = 0;
    mt[m++] = 0x04; m += der_len(mt + m, nlen); memcpy(mt + m, ntlm, nlen); m += nlen;
    /* [0] mechTypes { SEQUENCE { NTLMSSP OID } } */
    uint8_t mech[64]; int k = 0;
    mech[k++] = 0x30; k += der_len(mech + k, sizeof(OID_NTLMSSP));
    memcpy(mech + k, OID_NTLMSSP, sizeof(OID_NTLMSSP)); k += sizeof(OID_NTLMSSP);
    /* NegTokenInit SEQUENCE { [0] mechTypes, [2] mechToken } */
    inner[p++] = 0xa0; p += der_len(inner + p, k); memcpy(inner + p, mech, k); p += k;
    inner[p++] = 0xa2; p += der_len(inner + p, m); memcpy(inner + p, mt, m); p += m;
    uint8_t seq[1200]; int s = 0;
    seq[s++] = 0x30; s += der_len(seq + s, p); memcpy(seq + s, inner, p); s += p;
    /* [0] NegotiationToken */
    uint8_t neg[1200]; int n = 0;
    neg[n++] = 0xa0; n += der_len(neg + n, s); memcpy(neg + n, seq, s); n += s;
    /* InitialContextToken: [APPLICATION 0] { SPNEGO OID, [0] NegotiationToken } */
    int body = sizeof(OID_SPNEGO) + n;
    l = 0;
    out[l++] = 0x60; l += der_len(out + l, body);
    memcpy(out + l, OID_SPNEGO, sizeof(OID_SPNEGO)); l += sizeof(OID_SPNEGO);
    memcpy(out + l, neg, n); l += n;
    return l;
}

/* Wrap an NTLMSSP AUTHENTICATE in a SPNEGO NegTokenResp. Returns length.
 * Retained for reference; pool_connect_auth now sends the AUTHENTICATE raw
 * because ksmbd's negTokenTarg decoder rejected this wrapper (see the comment
 * at the SESSION_SETUP #2 site). */
static int spnego_wrap_resp(const uint8_t *ntlm, int nlen, uint8_t *out) __attribute__((unused));
static int spnego_wrap_resp(const uint8_t *ntlm, int nlen, uint8_t *out)
{
    uint8_t rt[1024]; int r = 0;
    /* [2] responseToken { OCTET STRING ntlm } */
    rt[r++] = 0x04; r += der_len(rt + r, nlen); memcpy(rt + r, ntlm, nlen); r += nlen;
    uint8_t resp[1100]; int x = 0;
    resp[x++] = 0xa2; x += der_len(resp + x, r); memcpy(resp + x, rt, r); x += r;
    /* SEQUENCE { [2] responseToken } */
    uint8_t seq[1200]; int s = 0;
    seq[s++] = 0x30; s += der_len(seq + s, x); memcpy(seq + s, resp, x); s += x;
    /* [1] NegTokenResp */
    int l = 0;
    out[l++] = 0xa1; l += der_len(out + l, s); memcpy(out + l, seq, s); l += s;
    return l;
}

/*
 * Connect + authenticate as fuzz:fuzz (NTLMv2) + tree-connect to @share.
 * Unlike the guest pool path, this reaches shares with guest ok = no that
 * honor DesiredAccess (e.g. [privtest]) — required for the access-control
 * contract oracle to be meaningful. Returns 0 on success, -1 on failure.
 */
static int pool_connect_auth(struct pool_conn *c, const char *share)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(445) };
    addr.sin_addr.s_addr = inet_addr(g_target_ip);
    c->sock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = {.tv_sec = 2};
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(c->sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    c->mid = 0; c->has_fid = 0; c->sid = 0; c->tid = 0;

    uint8_t pdu[1024], resp[1024];
    uint8_t *b;

    /* AUTH root cause (FIXED 2026-07-04, empirically from the guest console): the
     * [privtest] SESSION_SETUP returned 0xc000000d because ksmbd logged "Unknown
     * NTLMSSP message type: 0x25a00205" — our hand-built SPNEGO type-1 was rejected
     * by ksmbd's negTokenInit ASN.1 decoder, so ksmbd read MessageType from the 0x60
     * envelope (garbage). Fix: send BOTH SESSION_SETUP messages RAW (below). Three
     * static guesses (missing AUTHENTICATE, SPNEGO framing, NEGOTIATE DialectCount)
     * were wrong; the console pinned it. Temporary kernel pr_info + `echo auth`
     * debug have been reverted.
     * SECOND ROOT CAUSE (FIXED 2026-07-04, from `sess_setup out_err rc=-22 sid=0x3`
     *   in dmesg): after the raw type-1 fix made SS#1 dispatch correctly, SS#2 still
     *   returned 0xc000000d. dmesg showed rc=-EINVAL BEFORE the NTLMSSP dispatch. The
     *   SS body's Flags byte (b[2], PDU offset 66) was never written — stack garbage.
     *   With `server multi channel support = yes` and dialect SMB3.0, a stray bit 0
     *   (SMB2_SESSION_REQ_FLAG_BINDING) sent SS#2 down the multichannel-binding path,
     *   which requires a SIGNED request (smb2pdu.c smb2_sess_setup) -> -EINVAL. Fix:
     *   memset(b,0,24) before both SESSION_SETUPs (below) so Flags/Caps/Channel/
     *   PrevSessionId are clean. probe-test now returns status=0x00000000 and the full
     *   DataflowDirector (auth + oracle + UAF/frag/race + redqueen + arbiter) runs. */

    /* NEGOTIATE (SMB 3.0 only — no neg contexts).
     * BUGFIX: the body is stack-uninitialized (pool_smb2_hdr zeros only the 64-byte
     * header). The old `b[2] = 1` set DialectCount's low byte but left b[3] as garbage,
     * so DialectCount = 1|(junk<<8): ksmbd read junk dialects, negotiated SMB 3.1.1,
     * then failed deassemble_neg_contexts (no preauth context) -> 0xc000000d. The
     * client ignored the NEGOTIATE status and reported it later as an "AUTHENTICATE"
     * failure — the real root cause of the oracle/pool-auth breakage. Zero the body
     * and write DialectCount as a full u16. */
    pool_smb2_hdr(pdu, 0x0000, c);
    b = pdu + 64;
    memset(b, 0, 40);
    *(uint16_t *)(b + 0)  = 36;      /* StructureSize */
    *(uint16_t *)(b + 2)  = 1;       /* DialectCount = 1 (full u16) */
    *(uint16_t *)(b + 4)  = 1;       /* SecurityMode = SIGNING_ENABLED */
    *(uint16_t *)(b + 36) = 0x0300;  /* Dialects[0] = SMB 3.0 */
    if (pool_xact(c, pdu, 64 + 38, resp, sizeof(resp)) < 0) return -1;

    /* SESSION_SETUP #1: NTLMSSP NEGOTIATE → expect CHALLENGE */
    static const uint8_t ntlm_neg[] =
        "NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    int neg_len = (int)sizeof(ntlm_neg) - 1;
    /* ROOT-CAUSE FIX (empirical, from guest console): send the NTLMSSP NEGOTIATE
     * RAW, not SPNEGO-wrapped. ksmbd's negTokenInit ASN.1 decoder REJECTED our
     * hand-built SPNEGO wrapper (cifs's is accepted, ours wasn't) -> ksmbd set
     * use_spnego=false, treated the 0x60 GSSAPI envelope as raw NTLMSSP, read
     * MessageType from offset 8 = garbage (0x25a00205), and hit "Unknown NTLMSSP
     * message type" -> -EINVAL -> STATUS_INVALID_PARAMETER (0xc000000d) — surfaced
     * to the client as a bogus "AUTHENTICATE rejected". Sending BOTH SESSION_SETUP
     * messages as plain NTLMSSP makes ksmbd read MessageType correctly (1 then 3)
     * and reach decode_ntlmssp_authenticate_blob -> the NTLMv2 crypto. */
    pool_smb2_hdr(pdu, 0x0001, c);
    b = pdu + 64;
    memset(b, 0, 24);                           /* zero Flags/Caps/Channel/PrevSid (stack garbage) */
    *(uint16_t *)b = 25; b[3] = 1;              /* StructureSize, SecurityMode */
    *(uint16_t *)(b + 12) = 88;                 /* SecurityBufferOffset */
    *(uint16_t *)(b + 14) = neg_len;            /* SecurityBufferLength (raw) */
    memcpy(b + 24, ntlm_neg, neg_len);
    int r = pool_xact(c, pdu, 64 + 24 + neg_len, resp, sizeof(resp));
    if (r < 72) {
        pfz_err("[probe] SESSION_SETUP#1 short resp r=%d\n", r);
        return -1;
    }
    c->sid = *(uint64_t *)(resp + 40);          /* session id from header */

    /*
     * Extract the 8-byte server challenge. ksmbd may wrap the NTLMSSP CHALLENGE
     * in SPNEGO, so a fixed offset is unreliable — scan the response for the
     * "NTLMSSP\0\x02" (CHALLENGE) signature and take ServerChallenge at +24.
     */
    uint8_t server_chal[8];
    int found_chal = 0;
    for (int i = 64; i + 32 <= r; i++) {
        if (memcmp(resp + i, "NTLMSSP\x00\x02", 9) == 0) {
            memcpy(server_chal, resp + i + 24, 8);
            found_chal = 1;
            break;
        }
    }
    if (!found_chal) {
        pfz_err("[probe] NTLMSSP CHALLENGE not found in SESSION_SETUP#1 "
                "resp (r=%d)\n", r);
        return -1;
    }
    /*
     * SESSION_SETUP #2: NTLMSSP AUTHENTICATE (fuzz:fuzz), sent RAW (not
     * SPNEGO-wrapped).
     *
     * Why raw: ksmbd's SPNEGO NegTokenResp path (ksmbd_decode_negTokenTarg)
     * rejected our hand-built [1]{SEQ{[2]OCTET STRING}} wrapper, leaving
     * conn->mechToken NULL (it is freed after the type-1 NEGOTIATE, smb2pdu.c
     * out_err). smb2_sess_setup then reads negblob->MessageType from the raw
     * SPNEGO bytes → not NtLmAuthenticate → "Unknown NTLMSSP message type" →
     * rc=-EINVAL → STATUS_INVALID_PARAMETER (0xc000000d) — exactly the failure
     * observed. Sending the bare NTLMSSP AUTHENTICATE makes BOTH SPNEGO decoders
     * fail, so ksmbd sets conn->use_spnego=false and dispatches the raw
     * MessageType=3 straight to ntlm_authenticate() — a first-class code path.
     * (A credential mismatch would instead be -EPERM → STATUS_LOGON_FAILURE
     * 0xc000006d, so this framing fix is orthogonal to the NTLMv2 hash.)
     */
    uint8_t authmsg[512];
    int auth_len = build_ntlmssp_auth(server_chal, authmsg);
    pool_smb2_hdr(pdu, 0x0001, c);
    *(uint64_t *)(pdu + 40) = c->sid;           /* same session id */
    b = pdu + 64;
    memset(b, 0, 24);                           /* zero Flags (bit0=BINDING) — garbage bit sent SS#2
                                                 * down the multichannel-binding path -> -EINVAL */
    *(uint16_t *)b = 25; b[3] = 1;
    *(uint16_t *)(b + 12) = 88;
    *(uint16_t *)(b + 14) = auth_len;
    memcpy(b + 24, authmsg, auth_len);
    r = pool_xact(c, pdu, 64 + 24 + auth_len, resp, sizeof(resp));
    uint32_t st = (r >= 12) ? *(uint32_t *)(resp + 8) : 0xFFFFFFFF;
    if (getenv("KSMBDZZER_AUTH_DEBUG")) {
        pfz_err("[probe] AUTHENTICATE(raw) sent auth_len=%d -> status=0x%08x r=%d "
                "chal=%02x%02x%02x%02x%02x%02x%02x%02x\n", auth_len, st, r,
                server_chal[0], server_chal[1], server_chal[2], server_chal[3],
                server_chal[4], server_chal[5], server_chal[6], server_chal[7]);
    }
    if (r < 4 || st != 0) {
        pfz_err("[probe] AUTHENTICATE rejected status=0x%08x r=%d "
                "auth_len=%d (fuzz:fuzz NTLMv2, raw). 0xc000000d=framing, "
                "0xc000006d=credentials\n", st, r, auth_len);
        return -1;
    }

    /* TREE_CONNECT to \\ip\share */
    uint8_t path_utf16[256];
    int pathlen = build_unc_utf16(share, path_utf16);
    pool_smb2_hdr(pdu, 0x0003, c);
    b = pdu + 64;
    *(uint16_t *)b = 9; *(uint16_t *)(b + 4) = 72; *(uint16_t *)(b + 6) = pathlen;
    memcpy(b + 8, path_utf16, pathlen);
    r = pool_xact(c, pdu, 64 + 8 + pathlen, resp, sizeof(resp));
    st = (r >= 12) ? *(uint32_t *)(resp + 8) : 0xFFFFFFFF;
    if (r < 40 || st != 0) {
        pfz_err("[probe] TREE_CONNECT(%s) rejected status=0x%08x r=%d\n",
                share, st, r);
        return -1;
    }
    c->tid = *(uint32_t *)(resp + 36);
    pfz_err("[probe] authenticated fuzz@%s sid=0x%llx tid=0x%x\n",
            share, (unsigned long long)c->sid, c->tid);
    return 0;
}

/* ─── Authenticated probe connection (I2S directed CREATE/WRITE) ───────────── */
/*
 * A single authenticated connection whose request *body* bytes are fully
 * controlled by the Python side. This is what lets the I2S mutator drive
 * smb2_create_open_flags()/ksmbd_vfs_write() argument values directly: Python
 * builds the SMB2 body, we frame it with a valid header on an authed session,
 * reset the dataflow buffer, send, and the resulting trace-args/ret records
 * describe exactly this one request.
 */
static struct pool_conn g_probe;
static int g_probe_ready = 0;

/**
 * pfz_probe_init_share - Establish the authenticated probe connection
 * (fuzz:fuzz NTLMv2) and tree-connect to @share. Use a DesiredAccess-honoring
 * share (e.g. "privtest") so the contract oracle isn't masked by force-user.
 * Returns 0 on success, -1 on failure.
 */
int pfz_probe_init_share(const char *share)
{
    if (g_probe_ready) return 0;
    if (pool_connect_auth(&g_probe, share && share[0] ? share : "privtest") < 0)
        return -1;
    g_probe_ready = 1;
    return 0;
}

/**
 * pfz_probe_init - Establish the authenticated probe connection to the
 * default DesiredAccess-honoring share ([privtest]).
 */
int pfz_probe_init(void)
{
    return pfz_probe_init_share("privtest");
}

/**
 * pfz_probe_send - Send a caller-built SMB2 body on the authed session.
 * @cmd: SMB2 command (e.g. 0x0005 CREATE, 0x0009 WRITE, 0x000A LOCK).
 * @body: request body bytes (everything after the 64-byte SMB2 header).
 * Resets the dataflow buffer before sending so get_records() returns only the
 * records produced by this request. CREATE responses update the cached FileId.
 * Returns the response length, or -1.
 */
int pfz_probe_send(uint16_t cmd, const void *body, int body_len,
                         void *resp, int resp_max)
{
    if (!g_probe_ready && pfz_probe_init() < 0) return -1;
    if (body_len < 0) body_len = 0;
    if (body_len > 4000) body_len = 4000;
    uint8_t pdu[4096];
    pool_smb2_hdr(pdu, cmd, &g_probe);
    memcpy(pdu + 64, body, body_len);

    if (g_df_buf) g_df_buf[0] = 0;   /* records below belong to this request */
    int r = pool_xact(&g_probe, pdu, 64 + body_len, resp, resp_max);
    if (cmd == 0x0005 && r >= 144) {  /* cache FileId from CREATE response */
        memcpy(g_probe.fid, (uint8_t *)resp + 128, 16);
        g_probe.has_fid = 1;
    }
    return r;
}

/**
 * pfz_probe_get_fid - Copy the probe connection's last CREATE FileId.
 * Returns 0 if a FileId is available, -1 otherwise.
 */
int pfz_probe_get_fid(void *out16)
{
    if (!g_probe_ready || !g_probe.has_fid) return -1;
    memcpy(out16, g_probe.fid, 16);
    return 0;
}

/**
 * pfz_probe_reconnect - Force a fresh authenticated probe session.
 * The teardown/UAF oracle deliberately destroys the probe's session/tree
 * (LOGOFF / TREE_DISCONNECT) to test dangling-reference paths; this rebuilds a
 * clean session+tree so the next sequence starts from a known-good state.
 * Returns 0 on success, -1 on failure.
 */
int pfz_probe_reconnect(const char *share)
{
    if (g_probe.sock >= 0) { close(g_probe.sock); g_probe.sock = -1; }
    g_probe.sid = 0; g_probe.tid = 0; g_probe.mid = 0; g_probe.has_fid = 0;
    g_probe_ready = 0;
    if (pool_connect_auth(&g_probe, share && share[0] ? share : "privtest") < 0)
        return -1;
    g_probe_ready = 1;
    return 0;
}

/**
 * pfz_probe_send_frag - Like pfz_probe_send, but writes the transport-framed PDU
 * in @nseg TCP segments (with a short inter-segment delay) instead of one write.
 * This deliberately drives ksmbd_tcp_readv()'s partial-read/reassembly loop —
 * the short-read path a single loopback write() coalesces away and normal
 * request/response traffic never exercises (limitation: loopback-only framing).
 * @nseg is clamped to [1, 16]. Returns the response length, or -1.
 */
int pfz_probe_send_frag(uint16_t cmd, const void *body, int body_len,
                        void *resp, int resp_max, int nseg)
{
    if (!g_probe_ready && pfz_probe_init() < 0) return -1;
    if (body_len < 0) body_len = 0;
    if (body_len > 4000) body_len = 4000;
    if (nseg < 1) nseg = 1;
    if (nseg > 16) nseg = 16;
    uint8_t pdu[4096];
    pool_smb2_hdr(pdu, cmd, &g_probe);
    memcpy(pdu + 64, body, body_len);
    int len = 64 + body_len;

    if (g_df_buf) g_df_buf[0] = 0;   /* records below belong to this request */
    /* 4-byte big-endian transport length prefix, then the PDU split into nseg
     * chunks. Sending the prefix alone first forces ksmbd to enter its read loop
     * before the body arrives. */
    uint32_t nb = htonl((uint32_t)len);
    if (write(g_probe.sock, &nb, 4) != 4) return -1;
    int off = 0, chunk = (len + nseg - 1) / nseg;
    if (chunk < 1) chunk = 1;
    while (off < len) {
        int seg = len - off; if (seg > chunk) seg = chunk;
        if (write(g_probe.sock, pdu + off, seg) != seg) return -1;
        off += seg;
        if (off < len) usleep(200);  /* let the segment land as its own read */
    }
    /* Read the response with the same transport framing pool_xact uses. */
    uint32_t rlen;
    if (read(g_probe.sock, &rlen, 4) != 4) return -1;
    rlen = ntohl(rlen);
    if (rlen > (uint32_t)resp_max) rlen = resp_max;
    int got = 0;
    while (got < (int)rlen) {
        int r = read(g_probe.sock, (char *)resp + got, rlen - got);
        if (r <= 0) break;
        got += r;
    }
    if (cmd == 0x0005 && got >= 144) {
        memcpy(g_probe.fid, (uint8_t *)resp + 128, 16);
        g_probe.has_fid = 1;
    }
    return got;
}

/* Shared worker for the pool race primitives (oplock / lock / durable races):
 * fires a prebuilt PDU on its own connection+CPU so two requests truly overlap. */
struct _race_arg { struct pool_conn *c; uint8_t *pdu; int len; uint8_t resp[4096]; int rlen; };
static void *_pool_race_thread(void *arg) {
    struct _race_arg *a = arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset); CPU_SET(a == arg ? 0 : 1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    a->rlen = pool_xact(a->c, a->pdu, a->len, a->resp, sizeof(a->resp));
    return NULL;
}


/**
 * pfz_pool_oplock_race - Conn A opens file with oplock, conn B opens same file,
 * then A disconnects mid-break. Targets UAF in opinfo_get/put.
 */
int pfz_pool_oplock_race(const char *filename)
{
    if (g_pool_n < 2) return -1;
    uint8_t pdu[256], resp[256];
    int nlen = strlen(filename) * 2;

    /* Conn 0: CREATE with batch oplock */
    pool_smb2_hdr(pdu, 0x0005, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;
    *(uint32_t *)(b + 28) = 0x80;
    *(uint32_t *)(b + 32) = 0x07;
    *(uint32_t *)(b + 36) = 0x05;
    *(uint32_t *)(b + 40) = 0x40;
    b[3] = 0x08; /* OplockLevel = Batch */
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) {
        pdu[120 + i*2] = filename[i]; pdu[120 + i*2 + 1] = 0;
    }
    pool_xact(&g_pool[0], pdu, 120 + nlen, resp, sizeof(resp));

    /* Race: Conn 1 opens same file (triggers oplock break) while Conn 0 disconnects */
    if (g_df_buf) g_df_buf[0] = 0;
    struct _race_arg open_arg;
    pool_smb2_hdr(pdu, 0x0005, &g_pool[1]);
    b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;
    *(uint32_t *)(b + 28) = 0x80;
    *(uint32_t *)(b + 32) = 0x07;
    *(uint32_t *)(b + 36) = 0x05;
    *(uint32_t *)(b + 40) = 0x40;
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) {
        pdu[120 + i*2] = filename[i]; pdu[120 + i*2 + 1] = 0;
    }
    memcpy(open_arg.pdu = malloc(256), pdu, 120 + nlen);
    open_arg.c = &g_pool[1]; open_arg.len = 120 + nlen;

    pthread_t t_open;
    pthread_create(&t_open, NULL, _pool_race_thread, &open_arg);
    usleep(50); /* tiny delay — disconnect during oplock break notification */
    close(g_pool[0].sock); g_pool[0].sock = -1;
    pthread_join(t_open, NULL);
    free(open_arg.pdu);

    /* Reconnect pool[0] */
    pool_connect_one(&g_pool[0]);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/**
 * pfz_pool_lock_race - Rapid LOCK/UNLOCK from 2 connections on overlapping ranges.
 * Targets list_del corruption in smb2_lock().
 */
int pfz_pool_lock_race(int iters)
{
    if (g_pool_n < 2 || !pool_ensure_fid(&g_pool[0], "lk0") ||
        !pool_ensure_fid(&g_pool[1], "lk1")) return -1;
    if (g_df_buf) g_df_buf[0] = 0;

    /* Both connections open the SAME file */
    pool_create_file(&g_pool[1], "pool_0"); /* same as pool[0] */

    for (int i = 0; i < iters; i++) {
        uint8_t pdu_a[128], pdu_b[128];
        uint64_t off = (uint64_t)(rand() & 0xFFFF);
        uint64_t len = (uint64_t)(rand() & 0xFFF) + 1;

        /* Conn 0: LOCK exclusive */
        pool_smb2_hdr(pdu_a, 0x000A, &g_pool[0]);
        uint8_t *ba = pdu_a + 64;
        *(uint16_t *)ba = 48; *(uint32_t *)(ba + 2) = 1;
        memcpy(ba + 8, g_pool[0].fid, 16);
        *(uint64_t *)(ba + 24) = off; *(uint64_t *)(ba + 32) = len;
        *(uint32_t *)(ba + 40) = 0x03; /* EXCLUSIVE|FAIL_IMMEDIATELY */

        /* Conn 1: LOCK same range */
        pool_smb2_hdr(pdu_b, 0x000A, &g_pool[1]);
        uint8_t *bb = pdu_b + 64;
        *(uint16_t *)bb = 48; *(uint32_t *)(bb + 2) = 1;
        memcpy(bb + 8, g_pool[1].fid, 16);
        *(uint64_t *)(bb + 24) = off; *(uint64_t *)(bb + 32) = len;
        *(uint32_t *)(bb + 40) = 0x03;

        /* Race both locks */
        struct _race_arg ra = { .c = &g_pool[0], .pdu = pdu_a, .len = 112 };
        struct _race_arg rb = { .c = &g_pool[1], .pdu = pdu_b, .len = 112 };
        pthread_t ta, tb;
        pthread_create(&ta, NULL, _pool_race_thread, &ra);
        pthread_create(&tb, NULL, _pool_race_thread, &rb);
        pthread_join(ta, NULL);
        pthread_join(tb, NULL);

        /* Unlock from both */
        *(uint32_t *)(ba + 40) = 0x20; /* UNLOCK */
        *(uint32_t *)(bb + 40) = 0x20;
        pool_xact(&g_pool[0], pdu_a, 112, (uint8_t[256]){}, 256);
        pool_xact(&g_pool[1], pdu_b, 112, (uint8_t[256]){}, 256);
    }
    return g_df_buf ? (int)g_df_buf[0] : 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Attack Patterns #1-#7
 * ======================================================================= */

/* #1: Compression transform — PRE-AUTH, no session needed.
 * Sends SMB2_COMPRESSION_TRANSFORM_ID (0xFC534D42) directly on a fresh TCP socket.
 * Targets ksmbd_decompress_request() which parses orig_size from attacker input.
 */
int pfz_compress_fuzz(uint16_t algo, const void *data, int len, uint32_t orig_size)
{
    int sock;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(445) };
    addr.sin_addr.s_addr = inet_addr(g_target_ip);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv = {.tv_sec = 1};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    /* SMB2 Compression Transform Header (RFC1002 framed) */
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = 0x424D53FC; /* ProtocolId = SMB2_COMPRESSION_TRANSFORM_ID (LE) */
    *(uint32_t *)(hdr + 4) = orig_size;   /* OriginalCompressedSegmentSize */
    *(uint16_t *)(hdr + 8) = algo;        /* CompressionAlgorithm (LZ77=1, LZNT1=2, LZ77+Huff=3) */
    *(uint16_t *)(hdr + 10) = 0;          /* Flags (0=unchained, 1=chained) */
    *(uint32_t *)(hdr + 12) = 0;          /* Offset (for unchained) */

    int total = 24 + (len > 4000 ? 4000 : len);
    uint32_t nb = htonl(total);
    if (g_df_buf) g_df_buf[0] = 0;
    write(sock, &nb, 4);
    write(sock, hdr, 24);
    write(sock, data, len > 4000 ? 4000 : len);

    /* Read whatever response (may be error, may crash ksmbd) */
    uint8_t resp[256];
    read(sock, resp, sizeof(resp));
    close(sock);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #2: Fix pool auth — use libsmbclient for each pool connection.
 * Opens N separate libsmbclient sessions (full NTLMv2 auth).
 */
static int g_pool_smb_fds[MAX_POOL];

int pfz_pool_init_authed(int n)
{
    if (n > MAX_POOL) n = MAX_POOL;
    g_pool_n = 0;
    for (int i = 0; i < n; i++) {
        char url[64];
        snprintf(url, sizeof(url), "smb://%s/share/pool_file_%d", g_target_ip, i);
        g_pool_smb_fds[i] = smbc_open(url, O_RDWR | O_CREAT, 0666);
        if (g_pool_smb_fds[i] < 0) break;
        /* Also open raw socket for this connection's races */
        if (pool_connect_one(&g_pool[i]) == 0) {
            char fname[32];
            snprintf(fname, sizeof(fname), "pool_file_%d", i);
            pool_create_file(&g_pool[i], fname);
        }
        g_pool_n++;
    }
    return g_pool_n;
}

/* #4 prerequisite assertion: how many pool connections actually have an OPEN fid.
 * Pool-based grains (copychunk/lease/compound/…) early-return -1 unless has_fid is
 * set, so a grain that stays shallow because fids<2 is a HARNESS gap (the raw guest
 * session / create failed), not a hardened target. The grain harness prints this so
 * a silent bail is visible instead of masquerading as "shallow". */
int pfz_pool_fids_ready(void) {
    int r = 0;
    for (int i = 0; i < g_pool_n; i++) {
        if (!g_pool[i].has_fid) {                 /* reconnect+create dead conns */
            char fn[32]; snprintf(fn, sizeof(fn), "pool_%d", i);
            pool_ensure_fid(&g_pool[i], fn);
        }
        if (g_pool[i].has_fid) r++;
    }
    return r;
}

/* Race using authenticated libsmbclient handles */
struct _authed_race_arg { int fd; const void *data; int len; int off; };
static void *_authed_race_writer(void *arg) {
    struct _authed_race_arg *a = arg;
    pthread_mutex_lock(&g_smbc_lock);
    smbc_lseek(a->fd, a->off, SEEK_SET);
    smbc_write(a->fd, a->data, a->len);
    pthread_mutex_unlock(&g_smbc_lock);
    return NULL;
}
static void *_authed_race_closer(void *arg) {
    struct _authed_race_arg *a = arg;
    usleep(50);
    pthread_mutex_lock(&g_smbc_lock);
    smbc_close(a->fd);
    /* Reopen immediately */
    char url[64];
    snprintf(url, sizeof(url), "smb://%s/share/pool_file_%d", g_target_ip, a->off);
    a->fd = smbc_open(url, O_RDWR | O_CREAT, 0666);
    pthread_mutex_unlock(&g_smbc_lock);
    return NULL;
}

int pfz_pool_race_authed(int a_idx, int b_idx, const void *data, int len)
{
    if (a_idx >= g_pool_n || b_idx >= g_pool_n) return -1;
    if (g_df_buf) g_df_buf[0] = 0;
    struct _authed_race_arg arg_a = { .fd = g_pool_smb_fds[a_idx], .data = data, .len = len, .off = 0 };
    struct _authed_race_arg arg_b = { .fd = g_pool_smb_fds[b_idx], .data = data, .len = len, .off = b_idx };
    pthread_t ta, tb;
    pthread_create(&ta, NULL, _authed_race_writer, &arg_a);
    pthread_create(&tb, NULL, _authed_race_closer, &arg_b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    g_pool_smb_fds[b_idx] = arg_b.fd; /* update if reopened */
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #3: Durable handle reconnect cycle.
 * CREATE with DH2Q → disconnect → reconnect → CREATE with DH2C.
 */
int pfz_durable_reconnect(const char *filename)
{
    if (g_pool_n < 1) return -1;
    struct pool_conn *c = &g_pool[0];
    uint8_t pdu[512], resp[512];
    int nlen = strlen(filename) * 2;

    /* CREATE with DH2Q (Durable Handle v2 Request) create context */
    pool_smb2_hdr(pdu, 0x0005, c);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;
    *(uint32_t *)(b + 28) = 0x80;
    *(uint32_t *)(b + 32) = 0x07;
    *(uint32_t *)(b + 36) = 0x05;
    *(uint32_t *)(b + 40) = 0x40;
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) { pdu[120+i*2]=filename[i]; pdu[121+i*2]=0; }
    /* DH2Q context at offset after filename (8-byte aligned) */
    int ctx_off = (120 + nlen + 7) & ~7;
    *(uint32_t *)(b + 48) = ctx_off; /* CreateContextsOffset */
    /* DH2Q context: Next=0, NameOff=16, NameLen=4, DataOff=24, DataLen=32 */
    uint8_t *ctx = pdu + ctx_off;
    *(uint32_t *)(ctx + 0) = 0;    /* Next */
    *(uint16_t *)(ctx + 4) = 16;   /* NameOffset */
    *(uint16_t *)(ctx + 6) = 4;    /* NameLength */
    *(uint16_t *)(ctx + 8) = 24;   /* DataOffset (reserved field, actually Reserved) */
    *(uint16_t *)(ctx + 10) = 32;  /* DataLength */
    memcpy(ctx + 16, "DH2Q", 4);
    /* DH2Q data: Timeout=0, Flags=0, Reserved=0, CreateGuid=random */
    memset(ctx + 24, 0, 32);
    *(uint32_t *)(ctx + 24) = 60000; /* Timeout ms */
    int create_len = ctx_off + 56;
    *(uint32_t *)(b + 52) = 56; /* CreateContextsLength */

    if (g_df_buf) g_df_buf[0] = 0;
    int r = pool_xact(c, pdu, create_len, resp, sizeof(resp));
    uint8_t persistent_fid[8] = {0};
    if (r >= 144) memcpy(persistent_fid, resp + 128, 8);

    /* Disconnect (simulates client crash) */
    close(c->sock); c->sock = -1;
    usleep(10000); /* 10ms for ksmbd to notice */

    /* Reconnect */
    pool_connect_one(c);

    /* CREATE with DH2C (Durable Handle v2 Reconnect) */
    pool_smb2_hdr(pdu, 0x0005, c);
    b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;
    *(uint32_t *)(b + 28) = 0x80;
    *(uint32_t *)(b + 32) = 0x07;
    *(uint32_t *)(b + 36) = 0x01; /* FILE_OPEN */
    *(uint32_t *)(b + 40) = 0x40;
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) { pdu[120+i*2]=filename[i]; pdu[121+i*2]=0; }
    ctx_off = (120 + nlen + 7) & ~7;
    *(uint32_t *)(b + 48) = ctx_off;
    ctx = pdu + ctx_off;
    *(uint32_t *)(ctx + 0) = 0;
    *(uint16_t *)(ctx + 4) = 16; *(uint16_t *)(ctx + 6) = 4;
    *(uint16_t *)(ctx + 8) = 24; *(uint16_t *)(ctx + 10) = 32;
    memcpy(ctx + 16, "DH2C", 4);
    /* DH2C data: FileId (persistent) + CreateGuid */
    memcpy(ctx + 24, persistent_fid, 8);
    memset(ctx + 32, 0, 24);
    create_len = ctx_off + 56;
    *(uint32_t *)(b + 52) = 56;

    pool_xact(c, pdu, create_len, resp, sizeof(resp));
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #4: Session binding race — CVE-2024-50286 pattern.
 * Conn A has session, Conn B tries to bind to it while A disconnects.
 */
int pfz_session_binding_race(void)
{
    if (g_pool_n < 2) return -1;
    if (g_df_buf) g_df_buf[0] = 0;

    /* Conn 1: SESSION_SETUP with SMB2_SESSION_FLAG_BINDING + Conn 0's sid */
    uint8_t pdu[256];
    uint8_t ntlm[] = "NTLMSSP\x00\x01\x00\x00\x00\x97\x82\x08\xe2"
                     "\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00";
    pool_smb2_hdr(pdu, 0x0001, &g_pool[1]);
    /* Set SMB2_SESSION_FLAG_BINDING in SessionSetup flags */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 25;
    b[2] = 0x01; /* Flags = SMB2_SESSION_FLAG_BINDING */
    b[3] = 1;
    *(uint32_t *)(b + 4) = 0;
    *(uint16_t *)(b + 8) = 88; *(uint16_t *)(b + 10) = sizeof(ntlm) - 1;
    /* PreviousSessionId = conn 0's session */
    *(uint64_t *)(b + 12) = g_pool[0].sid;
    memcpy(b + 20, ntlm, sizeof(ntlm) - 1);

    /* Race: send binding while disconnecting conn 0 */
    struct _race_arg bind_arg = { .c = &g_pool[1], .pdu = pdu, .len = 64 + 20 + (int)sizeof(ntlm) - 1 };
    pthread_t t_bind;
    pthread_create(&t_bind, NULL, _pool_race_thread, &bind_arg);
    usleep(30);
    close(g_pool[0].sock); g_pool[0].sock = -1;
    pthread_join(t_bind, NULL);

    /* Reconnect pool[0] */
    pool_connect_one(&g_pool[0]);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #5: QUERY_DIRECTORY with extreme OutputBufferLength.
 * Tests smb2_query_dir() with huge/zero buffer, crafted patterns.
 */
int pfz_query_dir(uint8_t info_class, uint32_t output_buf_len,
                        const void *pattern, int pattern_len)
{
    /* libsmbclient-based (Round 2 quick win): enumerate the share dir → reaches
     * ksmbd's QUERY_DIRECTORY / readdir path DEEP-BY-CONSTRUCTION (robust auth),
     * instead of the raw pool that failed to authenticate in the harness. The
     * fuzzer's `pattern` steers which subpath is listed, deepening path-resolution
     * + dir-iteration coverage. */
    (void)info_class; (void)output_buf_len;
    char url[256], sub[128];
    int m = (pattern_len > 100) ? 100 : pattern_len, j = 0;
    for (int i = 0; i < m; i++) {
        unsigned char c = ((const unsigned char *)pattern)[i];
        sub[j++] = (c >= 32 && c < 127 && c != '/' && c != '\\') ? (char)c : '_';
    }
    sub[j] = 0;
    if (g_df_buf) g_df_buf[0] = 0;
    snprintf(url, sizeof(url), "smb://%s/share/%s", g_target_ip, sub);
    int dh = smbc_opendir(url);
    if (dh < 0) {                          /* fuzzed subpath absent → list share root */
        snprintf(url, sizeof(url), "smb://%s/share", g_target_ip);
        dh = smbc_opendir(url);
    }
    if (dh < 0) return -1;
    struct smbc_dirent *de; int cnt = 0;
    while ((de = smbc_readdir(dh)) != NULL && cnt < 512) { (void)de; cnt++; }
    smbc_closedir(dh);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}


/* #7: NDR/IPC$ pipe fuzzing via FSCTL_PIPE_TRANSCEIVE.
 * Opens \srvsvc pipe on IPC$ tree, sends malformed DCE/RPC.
 */
int pfz_ndr_fuzz(const void *rpc_data, int rpc_len)
{
    if (g_pool_n < 1) return -1;
    struct pool_conn *c = &g_pool[0];
    uint8_t pdu[1024], resp[4096];

    /* TREE_CONNECT to IPC$ */
    const uint8_t ipc_path[] = { '\\',0,'\\',0,'1',0,'2',0,'7',0,'.',0,'0',0,'.',0,'0',0,'.',0,'1',0,'\\',0,'I',0,'P',0,'C',0,'$',0 };
    pool_smb2_hdr(pdu, 0x0003, c);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 9; *(uint16_t *)(b + 4) = 72; *(uint16_t *)(b + 6) = sizeof(ipc_path);
    memcpy(b + 8, ipc_path, sizeof(ipc_path));
    int r = pool_xact(c, pdu, 64 + 8 + sizeof(ipc_path), resp, sizeof(resp));
    uint32_t ipc_tid = 0;
    if (r > 40) ipc_tid = *(uint32_t *)(resp + 36);
    if (!ipc_tid) return -1;

    /* CREATE \srvsvc pipe */
    uint32_t saved_tid = c->tid;
    c->tid = ipc_tid;
    const uint8_t pipe_name[] = { 's',0,'r',0,'v',0,'s',0,'v',0,'c',0 };
    pool_smb2_hdr(pdu, 0x0005, c);
    b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 24) = 0x12019F;
    *(uint32_t *)(b + 32) = 0x07;
    *(uint32_t *)(b + 36) = 0x01; /* FILE_OPEN */
    *(uint32_t *)(b + 40) = 0x00200000; /* FILE_OPEN_NO_RECALL */
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = sizeof(pipe_name);
    memcpy(pdu + 120, pipe_name, sizeof(pipe_name));
    r = pool_xact(c, pdu, 120 + sizeof(pipe_name), resp, sizeof(resp));
    uint8_t pipe_fid[16] = {0};
    if (r >= 144) memcpy(pipe_fid, resp + 128, 16);

    /* IOCTL: FSCTL_PIPE_TRANSCEIVE (0x0011C017) */
    if (g_df_buf) g_df_buf[0] = 0;
    int dlen = rpc_len > 800 ? 800 : rpc_len;
    pool_smb2_hdr(pdu, 0x000B, c);
    b = pdu + 64;
    *(uint16_t *)b = 57; *(uint16_t *)(b + 2) = 0;
    *(uint32_t *)(b + 4) = 0x0011C017; /* FSCTL_PIPE_TRANSCEIVE */
    memcpy(b + 8, pipe_fid, 16);
    *(uint32_t *)(b + 24) = 120;    /* InputOffset */
    *(uint32_t *)(b + 28) = dlen;   /* InputCount */
    *(uint32_t *)(b + 32) = 4096;   /* MaxInputResponse */
    *(uint32_t *)(b + 36) = 0;      /* OutputOffset */
    *(uint32_t *)(b + 40) = 0;      /* OutputCount */
    *(uint32_t *)(b + 44) = 4096;   /* MaxOutputResponse */
    *(uint32_t *)(b + 48) = 1;      /* Flags: SMB2_0_IOCTL_IS_FSCTL */
    memcpy(pdu + 120, rpc_data, dlen);
    pool_xact(c, pdu, 120 + dlen, resp, sizeof(resp));

    c->tid = saved_tid;
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Frontier Attack Patterns #1-#7
 * ======================================================================= */


/* #2: Lease race — CREATE with RqLs context + second CREATE triggers lease break.
 * Disconnect during break notification → UAF in opinfo_get/put.
 */
int pfz_lease_race(const char *filename, const void *lease_key, uint32_t lease_state)
{
    if (g_pool_n < 2) return -1;
    uint8_t pdu[512], resp[512];
    int nlen = strlen(filename) * 2;

    /* Conn 0: CREATE with RqLs (Request Lease) context */
    pool_smb2_hdr(pdu, 0x0005, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+24) = 0x12019F; *(uint32_t *)(b+28) = 0x80;
    *(uint32_t *)(b+32) = 0x07; *(uint32_t *)(b+36) = 0x05;
    *(uint32_t *)(b+40) = 0x40;
    *(uint16_t *)(b+44) = 120; *(uint16_t *)(b+46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) { pdu[120+i*2]=filename[i]; pdu[121+i*2]=0; }
    /* RqLs context after filename */
    int ctx_off = (120 + nlen + 7) & ~7;
    *(uint32_t *)(b+48) = ctx_off; /* CreateContextsOffset */
    uint8_t *ctx = pdu + ctx_off;
    *(uint32_t *)(ctx+0) = 0; *(uint16_t *)(ctx+4) = 16; *(uint16_t *)(ctx+6) = 4;
    *(uint16_t *)(ctx+8) = 24; *(uint16_t *)(ctx+10) = 52; /* DataLength=52 for v2 lease */
    memcpy(ctx+16, "RqLs", 4);
    /* Lease data: LeaseKey(16) + LeaseState(4) + LeaseFlags(4) + LeaseDuration(8) + ParentLeaseKey(16) + Epoch(2) */
    memcpy(ctx+24, lease_key ? lease_key : "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", 16);
    /* Fuzz-driven LeaseState (#3): steer the lease-break state machine to all
     * R/W/H combinations, not just the fixed full lease. 0 -> full lease default. */
    *(uint32_t *)(ctx+40) = lease_state ? (lease_state & 0x7) : 0x07;
    int total = ctx_off + 76;
    *(uint32_t *)(b+52) = 76;
    pool_xact(&g_pool[0], pdu, total, resp, sizeof(resp));

    /* Conn 1: CREATE same file → triggers lease break on conn 0 */
    if (g_df_buf) g_df_buf[0] = 0;
    struct _race_arg open_arg;
    pool_smb2_hdr(pdu, 0x0005, &g_pool[1]);
    b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+24) = 0x12019F; *(uint32_t *)(b+28) = 0x80;
    *(uint32_t *)(b+32) = 0x07; *(uint32_t *)(b+36) = 0x05;
    *(uint32_t *)(b+40) = 0x40;
    *(uint16_t *)(b+44) = 120; *(uint16_t *)(b+46) = nlen;
    for (int i = 0; i < (int)strlen(filename); i++) { pdu[120+i*2]=filename[i]; pdu[121+i*2]=0; }
    open_arg.c = &g_pool[1]; open_arg.pdu = malloc(256);
    memcpy(open_arg.pdu, pdu, 120+nlen); open_arg.len = 120+nlen;
    pthread_t t1;
    pthread_create(&t1, NULL, _pool_race_thread, &open_arg);
    usleep(100); /* disconnect conn 0 during lease break notification */
    close(g_pool[0].sock); g_pool[0].sock = -1;
    pthread_join(t1, NULL);
    free(open_arg.pdu);
    pool_connect_one(&g_pool[0]);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #3: FSCTL_SRV_COPYCHUNK — two fids, crafted chunk array with offset+length overflow. */
int pfz_copychunk(uint64_t src_off, uint64_t dst_off, uint32_t length, int n_chunks)
{
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "cc_v")) return -1;
    uint8_t pdu[512], resp[512];

    /* Create a second file for destination */
    pool_create_file(&g_pool[0], "copydst");
    uint8_t dst_fid[16];
    memcpy(dst_fid, g_pool[0].fid, 16);
    pool_create_file(&g_pool[0], "pool_0"); /* re-open source */

    /* Fetch a REAL 24-byte ResumeKey for the source via FSCTL_SRV_REQUEST_RESUME_KEY
     * (0x00140078). ksmbd looks the source fp up by this key; with the old all-zero
     * key the copychunk was rejected before the crafted chunk offsets/lengths ever
     * reached ksmbd_vfs_copy_file_ranges — so the directed I2S never went deep (#3).
     * A valid key lets the fuzzed src/dst offset + length actually drive the copy
     * bounds check and range loop, which is the interesting write-side surface. */
    uint8_t resume_key[24];
    memset(resume_key, 0, sizeof(resume_key));
    {
        pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
        uint8_t *rb = pdu + 64;
        memset(rb, 0, 64);
        *(uint16_t *)rb = 57;
        *(uint32_t *)(rb+4) = 0x00140078;   /* FSCTL_SRV_REQUEST_RESUME_KEY */
        memcpy(rb+8, g_pool[0].fid, 16);    /* source fid (pool_0) */
        *(uint32_t *)(rb+24) = 120;         /* InputOffset */
        *(uint32_t *)(rb+28) = 0;           /* InputCount = 0 */
        *(uint32_t *)(rb+44) = 4096;        /* MaxOutputResponse */
        *(uint32_t *)(rb+48) = 1;           /* IS_FSCTL */
        int rk = pool_xact(&g_pool[0], pdu, 120, resp, sizeof(resp));
        if (rk >= 12 && *(uint32_t *)(resp+8) == 0) {      /* STATUS_SUCCESS */
            uint32_t oo = *(uint32_t *)(resp + 64 + 32);   /* OutputOffset */
            uint32_t oc = *(uint32_t *)(resp + 64 + 36);   /* OutputCount */
            if (oc >= 24 && oo + 24 <= (uint32_t)rk)
                memcpy(resume_key, resp + oo, 24);
        }
    }

    /* IOCTL: FSCTL_SRV_COPYCHUNK_WRITE (0x001480044) */
    pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+4) = 0x001480044; /* FSCTL_SRV_COPYCHUNK_WRITE */
    memcpy(b+8, dst_fid, 16); /* FileId = destination */
    /* Input: copychunk_ioctl_req {ResumeKey(24), ChunkCount(4), Reserved(4), Chunks[]} */
    uint8_t input[256];
    memcpy(input, resume_key, 24); /* real source ResumeKey (fetched above) */
    if (n_chunks > 8) n_chunks = 8;
    *(uint32_t *)(input+24) = n_chunks;
    *(uint32_t *)(input+28) = 0;
    for (int i = 0; i < n_chunks; i++) {
        /* Each chunk: SourceOffset(8) + TargetOffset(8) + Length(4) + Reserved(4) */
        int off = 32 + i * 24;
        *(uint64_t *)(input+off) = src_off + (uint64_t)i * length;
        *(uint64_t *)(input+off+8) = dst_off + (uint64_t)i * length;
        *(uint32_t *)(input+off+16) = length;
    }
    int ilen = 32 + n_chunks * 24;
    *(uint32_t *)(b+24) = 120; *(uint32_t *)(b+28) = ilen;
    *(uint32_t *)(b+32) = 4096; /* MaxInput */
    *(uint32_t *)(b+44) = 4096; /* MaxOutput */
    *(uint32_t *)(b+48) = 1; /* IS_FSCTL */
    memcpy(pdu+120, input, ilen);

    if (g_df_buf) g_df_buf[0] = 0;
    pool_xact(&g_pool[0], pdu, 120 + ilen, resp, sizeof(resp));
    return g_df_buf ? (int)g_df_buf[0] : 0;
}



/* #6: FSCTL_SET_REPARSE_POINT — symlink/junction injection for path traversal. */
int pfz_set_reparse(uint32_t reparse_tag, const void *data, int len)
{
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "rp_v")) return -1;
    uint8_t pdu[1024], resp[256];
    /* IOCTL: FSCTL_SET_REPARSE_POINT (0x000900A4) */
    pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
    uint8_t *b = pdu+64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+4) = 0x000900A4; /* FSCTL_SET_REPARSE_POINT */
    memcpy(b+8, g_pool[0].fid, 16);
    /* REPARSE_DATA_BUFFER: Tag(4) + DataLength(2) + Reserved(2) + data */
    uint8_t input[512];
    *(uint32_t *)(input+0) = reparse_tag;
    *(uint16_t *)(input+4) = len > 500 ? 500 : len;
    *(uint16_t *)(input+6) = 0;
    int dlen = len > 500 ? 500 : len;
    memcpy(input+8, data, dlen);
    int ilen = 8 + dlen;
    *(uint32_t *)(b+24) = 120; *(uint32_t *)(b+28) = ilen;
    *(uint32_t *)(b+32) = 4096; *(uint32_t *)(b+44) = 4096;
    *(uint32_t *)(b+48) = 1;
    memcpy(pdu+120, input, ilen);

    if (g_df_buf) g_df_buf[0] = 0;
    pool_xact(&g_pool[0], pdu, 120+ilen, resp, sizeof(resp));
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* #7: Malformed Kerberos AP-REQ in SESSION_SETUP (if KDC available).
 * Sends SPNEGO with OID=1.2.840.113554.1.2.2 (Kerberos) + garbage token.
 */
int pfz_krb5_fuzz(const void *ap_req_data, int len)
{
    if (g_pool_n < 1) return -1;
    uint8_t pdu[1024], resp[512];
    /* Build SPNEGO with Kerberos mechtype + malformed token */
    uint8_t krb5_oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
    uint8_t spnego_oid[] = {0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    int toklen = len > 800 ? 800 : len;
    /* MechTypes */
    uint8_t mech_types[20]; int mt_len = 0;
    mech_types[mt_len++] = 0xa0; mech_types[mt_len++] = sizeof(krb5_oid)+2;
    mech_types[mt_len++] = 0x30; mech_types[mt_len++] = sizeof(krb5_oid);
    memcpy(mech_types+mt_len, krb5_oid, sizeof(krb5_oid)); mt_len += sizeof(krb5_oid);
    /* MechToken */
    uint8_t gss[1024]; int gss_len = 0;
    gss[gss_len++] = 0x60;
    int inner_len = sizeof(spnego_oid) + mt_len + toklen + 6;
    gss[gss_len++] = 0x82; gss[gss_len++] = (inner_len>>8)&0xFF; gss[gss_len++] = inner_len&0xFF;
    memcpy(gss+gss_len, spnego_oid, sizeof(spnego_oid)); gss_len += sizeof(spnego_oid);
    gss[gss_len++] = 0xa0; gss[gss_len++] = mt_len + toklen + 4;
    gss[gss_len++] = 0x30; gss[gss_len++] = mt_len + toklen + 2;
    memcpy(gss+gss_len, mech_types, mt_len); gss_len += mt_len;
    gss[gss_len++] = 0xa2; gss[gss_len++] = toklen + 2;
    gss[gss_len++] = 0x04; gss[gss_len++] = toklen;
    memcpy(gss+gss_len, ap_req_data, toklen); gss_len += toklen;

    /* SESSION_SETUP with the Kerberos token */
    pool_smb2_hdr(pdu, 0x0001, &g_pool[0]);
    uint8_t *b = pdu+64;
    *(uint16_t *)b = 25; b[2] = 0; b[3] = 1;
    *(uint32_t *)(b+4) = 0;
    *(uint16_t *)(b+8) = 88; *(uint16_t *)(b+10) = gss_len;
    memset(b+12, 0, 8);
    memcpy(b+20, gss, gss_len);

    if (g_df_buf) g_df_buf[0] = 0;
    pool_xact(&g_pool[0], pdu, 64+20+gss_len, resp, sizeof(resp));
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Deep Frontier Patterns
 * ======================================================================= */

/* #3 (most impactful): Failslab toggle — force kernel allocation failures. */
int pfz_set_failslab(int probability)
{
    char buf[16];
    int fd = open("/sys/kernel/debug/failslab/probability", O_WRONLY);
    if (fd < 0) return -1;
    int n = snprintf(buf, sizeof(buf), "%d", probability);
    write(fd, buf, n);
    close(fd);
    /* Also set interval */
    fd = open("/sys/kernel/debug/failslab/interval", O_WRONLY);
    if (fd >= 0) { write(fd, "1", 1); close(fd); }
    return 0;
}

/* #1: SMB 3.1.1 negotiate with malformed contexts.
 * Sends NEGOTIATE with dialect 0x0311 + crafted negotiate contexts.
 */
int pfz_negotiate_contexts(const void *ctx_data, int ctx_len)
{
    int sock;
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(445) };
    addr.sin_addr.s_addr = inet_addr(g_target_ip);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv = {.tv_sec = 2};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(sock); return -1; }

    uint8_t pdu[1024];
    memset(pdu, 0, 64);
    memcpy(pdu, "\xfeSMB", 4);
    *(uint16_t *)(pdu+4) = 64; *(uint16_t *)(pdu+12) = 0; /* NEGOTIATE */
    /* Body */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 36; /* StructureSize */
    *(uint16_t *)(b+2) = 1; /* DialectCount */
    *(uint16_t *)(b+4) = 1; /* SecurityMode */
    *(uint32_t *)(b+8) = 0x7F; /* Capabilities (all bits) */
    memset(b+12, 0xAA, 16); /* ClientGuid */
    /* NegotiateContextOffset points to after dialects */
    int ctx_offset = 64 + 36 + 2; /* header + body + 1 dialect */
    *(uint32_t *)(b+28) = ctx_offset;
    *(uint16_t *)(b+32) = ctx_len > 0 ? 1 : 0; /* NegotiateContextCount */
    *(uint16_t *)(b+36) = 0x0311; /* Dialect: SMB 3.1.1 */
    /* Append contexts */
    int clen = ctx_len > 800 ? 800 : ctx_len;
    memcpy(pdu + ctx_offset, ctx_data, clen);
    int total = ctx_offset + clen;

    if (g_df_buf) g_df_buf[0] = 0;
    uint32_t nb = htonl(total);
    write(sock, &nb, 4); write(sock, pdu, total);
    uint8_t resp[1024];
    read(sock, resp, sizeof(resp));
    close(sock);
    return g_df_buf ? (int)g_df_buf[0] : 0;
}


/* #4: Unknown pipe names — CREATE on IPC$ with garbage/unknown pipe names. */
int pfz_unknown_pipe(const void *pipe_name, int name_len)
{
    if (g_pool_n < 1) return -1;
    uint8_t pdu[512], resp[512];
    /* TREE_CONNECT to IPC$ first */
    const uint8_t ipc[] = {'\\',0,'\\',0,'1',0,'2',0,'7',0,'.',0,'0',0,'.',0,'0',0,'.',0,'1',0,'\\',0,'I',0,'P',0,'C',0,'$',0};
    pool_smb2_hdr(pdu, 0x0003, &g_pool[0]);
    uint8_t *b = pdu+64;
    *(uint16_t *)b = 9; *(uint16_t *)(b+4) = 72; *(uint16_t *)(b+6) = sizeof(ipc);
    memcpy(b+8, ipc, sizeof(ipc));
    int r = pool_xact(&g_pool[0], pdu, 64+8+sizeof(ipc), resp, sizeof(resp));
    uint32_t ipc_tid = (r > 40) ? *(uint32_t *)(resp+36) : 0;
    if (!ipc_tid) return -1;

    /* CREATE with the unknown pipe name */
    uint32_t saved = g_pool[0].tid;
    g_pool[0].tid = ipc_tid;
    pool_smb2_hdr(pdu, 0x0005, &g_pool[0]);
    b = pdu+64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+24) = 0x12019F;
    *(uint32_t *)(b+32) = 0x07;
    *(uint32_t *)(b+36) = 0x01;
    *(uint32_t *)(b+40) = 0x00200000;
    int nlen = name_len > 200 ? 200 : name_len;
    *(uint16_t *)(b+44) = 120; *(uint16_t *)(b+46) = nlen;
    memcpy(pdu+120, pipe_name, nlen);

    if (g_df_buf) g_df_buf[0] = 0;
    pool_xact(&g_pool[0], pdu, 120+nlen, resp, sizeof(resp));
    g_pool[0].tid = saved;
    return g_df_buf ? (int)g_df_buf[0] : 0;
}



/* #7: Unicode/path edge cases — CREATE with extreme filenames. */
int pfz_unicode_path(const void *filename_utf16, int name_len)
{
    if (g_pool_n < 1) return -1;
    uint8_t pdu[4096], resp[512];
    int nlen = name_len > 3000 ? 3000 : name_len;
    pool_smb2_hdr(pdu, 0x0005, &g_pool[0]);
    uint8_t *b = pdu+64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b+24) = 0x12019F; *(uint32_t *)(b+28) = 0x80;
    *(uint32_t *)(b+32) = 0x07; *(uint32_t *)(b+36) = 0x05;
    *(uint32_t *)(b+40) = 0x40;
    *(uint16_t *)(b+44) = 120; *(uint16_t *)(b+46) = nlen;
    memcpy(pdu+120, filename_utf16, nlen);

    if (g_df_buf) g_df_buf[0] = 0;
    pool_xact(&g_pool[0], pdu, 120+nlen, resp, sizeof(resp));
    return g_df_buf ? (int)g_df_buf[0] : 0;
}

/* State Machine Sequence Fuzzing — multi-step with FileId capture */

/* Helper: CREATE via pool, capture real FileId from response */
static int _seq_pool_create(int conn, const char *fn16, int fn_len,
                           uint32_t access, uint32_t disp, uint8_t oplk,
                           uint8_t fid[16])
{
    uint8_t pdu[512], resp[256];
    pool_smb2_hdr(pdu, 0x0005, &g_pool[conn]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint8_t *)(b+3) = oplk;
    *(uint32_t *)(b+24) = access;
    *(uint32_t *)(b+28) = 0x80;
    *(uint32_t *)(b+32) = 0x07;
    *(uint32_t *)(b+36) = disp;
    *(uint32_t *)(b+40) = 0x40;
    *(uint16_t *)(b+44) = 120; *(uint16_t *)(b+46) = fn_len;
    memcpy(pdu+120, fn16, fn_len);
    int r = pool_xact(&g_pool[conn], pdu, 120+fn_len, resp, sizeof(resp));
    if (r >= 152 && fid) {
        if (*(uint32_t*)(resp+8) == 0) memcpy(fid, resp+64+66, 16);
        else return -1;
    }
    return 0;
}

static int _seq_cmd(int conn, uint16_t cmd, uint8_t *body, int blen, uint8_t fid[16], int fid_off)
{
    uint8_t pdu[4096], resp[4096];
    pool_smb2_hdr(pdu, cmd, &g_pool[conn]);
    memcpy(pdu+64, body, blen > 3900 ? 3900 : blen);
    if (fid && fid_off >= 0) memcpy(pdu+64+fid_off, fid, 16);
    return pool_xact(&g_pool[conn], pdu, 64+blen, resp, sizeof(resp));
}

static int _seq_close(int conn, uint8_t fid[16])
{
    uint8_t body[24] = {0}; *(uint16_t*)body = 24;
    return _seq_cmd(conn, 0x0006, body, 24, fid, 8);
}

/* Seq 0: write with mutated offset/len */
static int _seq0_write(const void *f, int fl) {
    char url[64]; snprintf(url, sizeof(url), "smb://%s/share/sq0", g_target_ip);
    int fd = smbc_open(url, O_RDWR|O_CREAT, 0666);
    if (fd<0) return -1;
    long off = (fl>=8) ? (*(long*)f & 0x7FFFFFFF) : 0;
    smbc_lseek(fd, off, SEEK_SET);
    smbc_write(fd, (fl>8)?(char*)f+8:f, (fl>8)?fl-8:fl);
    smbc_close(fd);
    return 0;
}

/* Seq 1: lock + write into locked range */
static int _seq1_lock_write(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16], body[48]={0};
    if (_seq_pool_create(0,"s\0q\0001\0",6,0x12019F,0x05,0,fid)) return -1;
    *(uint16_t*)body=48; *(uint16_t*)(body+2)=1;
    uint64_t lo=0,ll=4096;
    if(fl>=16){lo=*(uint64_t*)f;ll=*(uint64_t*)((char*)f+8);}
    *(uint64_t*)(body+24)=lo; *(uint64_t*)(body+32)=ll; *(uint32_t*)(body+40)=1;
    _seq_cmd(0,0x000A,body,48,fid,8);
    char url[64]; snprintf(url, sizeof(url), "smb://%s/share/sq1", g_target_ip);
    int fd=smbc_open(url,O_RDWR|O_CREAT,0666);
    if(fd>=0){smbc_lseek(fd,(long)(lo&0x7FFFFFFF),SEEK_SET);smbc_write(fd,(fl>16)?(char*)f+16:"x",(fl>16)?fl-16:1);smbc_close(fd);}
    *(uint32_t*)(body+40)=2; _seq_cmd(0,0x000A,body,48,fid,8);
    _seq_close(0,fid);
    return 0;
}

/* Seq 2: oplock + setinfo (mutated) */
static int _seq2_oplock_setinfo(const void *f, int fl) {
    if (g_pool_n<2) return -1;
    uint8_t fid1[16], fid2[16];
    const char fn[]="s\0q\0002\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0x02,fid1)) return -1;
    _seq_pool_create(1,fn,6,0x12019F,0x01,0,fid2);
    uint8_t body[512]={0}; *(uint16_t*)body=33;
    int bl=fl>400?400:fl; memcpy(body+2,f,bl);
    _seq_cmd(0,0x0011,body,2+bl,fid1,16);
    _seq_close(0,fid1); _seq_close(1,fid2);
    return 0;
}

/* Seq 3: ioctl with mutated ctl_code + data */
static int _seq3_ioctl(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\0003\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0,fid)) return -1;
    uint8_t body[4096]={0}; *(uint16_t*)body=57;
    uint32_t ctl=(fl>=4)?*(uint32_t*)f:0x00090000;
    *(uint32_t*)(body+4)=ctl;
    int il=(fl>4)?fl-4:0; if(il>3800)il=3800;
    *(uint32_t*)(body+24)=120; *(uint32_t*)(body+28)=il;
    *(uint32_t*)(body+32)=4096; *(uint32_t*)(body+44)=4096;
    *(uint32_t*)(body+48)=1;
    if(il>0)memcpy(body+56,(char*)f+4,il);
    _seq_cmd(0,0x000B,body,56+il,fid,8);
    _seq_close(0,fid);
    return 0;
}

/* Seq 4: query_info (mutated info_type/class) */
static int _seq4_query_info(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\0004\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0,fid)) return -1;
    uint8_t body[64]={0}; *(uint16_t*)body=41;
    *(uint8_t*)(body+2)=(fl>=1)?((uint8_t*)f)[0]&3:1;
    *(uint8_t*)(body+3)=(fl>=2)?((uint8_t*)f)[1]:5;
    *(uint32_t*)(body+4)=4096;
    *(uint32_t*)(body+8)=(fl>=6)?*(uint32_t*)((char*)f+2):0;
    _seq_cmd(0,0x0010,body,41,fid,16);
    _seq_close(0,fid);
    return 0;
}

/* Seq 5: query_directory (mutated pattern/class) */
static int _seq5_query_dir(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]=".\0";
    uint8_t pdu[512],resp[4096];
    pool_smb2_hdr(pdu,0x0005,&g_pool[0]);
    uint8_t *b=pdu+64; *(uint16_t*)b=57;
    *(uint32_t*)(b+24)=0x00100001; *(uint32_t*)(b+28)=0x10;
    *(uint32_t*)(b+32)=0x07; *(uint32_t*)(b+36)=0x01; *(uint32_t*)(b+40)=0x01;
    *(uint16_t*)(b+44)=120; *(uint16_t*)(b+46)=2;
    memcpy(pdu+120,fn,2);
    int r=pool_xact(&g_pool[0],pdu,122,resp,sizeof(resp));
    if(r>=152&&*(uint32_t*)(resp+8)==0) memcpy(fid,resp+64+66,16); else return -1;
    uint8_t body[256]={0}; *(uint16_t*)body=33;
    *(uint8_t*)(body+2)=(fl>=1)?((uint8_t*)f)[0]:37;
    *(uint32_t*)(body+28)=4096;
    int pl=(fl>1)?fl-1:2; if(pl>200)pl=200;
    *(uint16_t*)(body+24)=32; *(uint16_t*)(body+26)=pl;
    if(fl>1) memcpy(body+32,(char*)f+1,pl); else memcpy(body+32,"*\0",2);
    _seq_cmd(0,0x000E,body,32+pl,fid,8);
    _seq_close(0,fid);
    return 0;
}

/* Seq 6: lease break — CREATE with lease on 2 conns */
static int _seq6_lease(const void *f, int fl) {
    if (g_pool_n<2) return -1;
    uint8_t fid1[16],fid2[16];
    const char fn[]="s\0q\0006\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0x04,fid1)) return -1; /* SMB2_OPLOCK_LEVEL_LEASE */
    _seq_pool_create(1,fn,6,0x12019F,0x01,0,fid2); /* triggers break */
    /* SET_INFO with mutated body after lease break */
    uint8_t body[256]={0}; *(uint16_t*)body=33; *(uint8_t*)(body+2)=1; *(uint8_t*)(body+3)=13;
    int bl=fl>200?200:fl; memcpy(body+16,f,bl);
    _seq_cmd(0,0x0011,body,16+bl,fid1,32);
    _seq_close(0,fid1); _seq_close(1,fid2);
    return 0;
}

/* Seq 7: durable reconnect — CREATE durable, close conn, reconnect */
static int _seq7_durable(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\0007\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0,fid)) return -1;
    /* WRITE then CLOSE */
    char url[64]; snprintf(url, sizeof(url), "smb://%s/share/sq7", g_target_ip);
    int fd=smbc_open(url,O_RDWR|O_CREAT,0666);
    if(fd>=0){smbc_write(fd,f,fl>4096?4096:fl);smbc_close(fd);}
    _seq_close(0,fid);
    return 0;
}

/* Seq 8: compound CREATE+SET_INFO (mutated security descriptor) */
static int _seq8_compound(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t pdu[1024]={0},resp[1024];
    /* Cmd1: CREATE */
    memcpy(pdu,"\xfeSMB",4); *(uint16_t*)(pdu+4)=64; *(uint16_t*)(pdu+12)=0x0005;
    uint8_t *b1=pdu+64; *(uint16_t*)b1=57;
    *(uint32_t*)(b1+24)=0x12019F; *(uint32_t*)(b1+28)=0x80;
    *(uint32_t*)(b1+32)=0x07; *(uint32_t*)(b1+36)=0x05; *(uint32_t*)(b1+40)=0x40;
    const char cfn[]="s\0q\0008\0";
    *(uint16_t*)(b1+44)=120; *(uint16_t*)(b1+46)=6;
    memcpy(pdu+120,cfn,6);
    int cmd1_len=128; cmd1_len+=(8-cmd1_len%8)%8;
    *(uint32_t*)(pdu+20)=cmd1_len;
    /* Cmd2: SET_INFO (related, FILEID sentinel) */
    uint8_t *c2=pdu+cmd1_len;
    memcpy(c2,"\xfeSMB",4); *(uint16_t*)(c2+4)=64; *(uint16_t*)(c2+12)=0x0011;
    *(uint32_t*)(c2+16)=0x04; /* FLAGS_RELATED */
    uint8_t *b2=c2+64; *(uint16_t*)b2=33; *(uint8_t*)(b2+2)=3;
    int sdlen=fl>200?200:fl;
    *(uint32_t*)(b2+4)=sdlen; *(uint16_t*)(b2+8)=96; *(uint32_t*)(b2+12)=7;
    memset(b2+16,0xFF,16); memcpy(b2+32,f,sdlen);
    int total=cmd1_len+64+32+sdlen;
    pool_smb2_hdr(pdu,0x0005,&g_pool[0]);
    *(uint32_t*)(pdu+20)=cmd1_len;
    pool_xact(&g_pool[0],pdu,total,resp,sizeof(resp));
    return 0;
}

/* Seq 9: multi-credit large write (mutated size) */
static int _seq9_multi_credit(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\0009\0";
    if (_seq_pool_create(0,fn,6,0x12019F,0x05,0,fid)) return -1;
    uint8_t body[256]={0}; *(uint16_t*)body=49;
    *(uint16_t*)(body+2)=70; /* DataOffset */
    uint32_t wlen=(fl>=4)?*(uint32_t*)f&0xFFFF:4096;
    *(uint32_t*)(body+4)=wlen; /* Length (mutated) */
    *(uint64_t*)(body+8)=0; /* Offset */
    _seq_cmd(0,0x0009,body,70,fid,16);
    _seq_close(0,fid);
    return 0;
}

/* Seq 10: set_info with mutated FileBasicInfo/FileDispositionInfo */
static int _seq10_setinfo(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\00010\0";
    if (_seq_pool_create(0,fn,8,0x12019F,0x05,0,fid)) return -1;
    uint8_t body[512]={0}; *(uint16_t*)body=33;
    *(uint8_t*)(body+2)=1; /* InfoType=FILE */
    *(uint8_t*)(body+3)=(fl>=1)?((uint8_t*)f)[0]:4; /* InfoClass mutated */
    int dl=fl>400?400:fl;
    *(uint32_t*)(body+4)=dl; *(uint16_t*)(body+8)=96;
    memcpy(body+32,f,dl);
    _seq_cmd(0,0x0011,body,32+dl,fid,16);
    _seq_close(0,fid);
    return 0;
}

/* Seq 11: change notify (if supported) */
static int _seq11_notify(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]=".\0";
    uint8_t pdu[256],resp[256];
    pool_smb2_hdr(pdu,0x0005,&g_pool[0]);
    uint8_t *b=pdu+64; *(uint16_t*)b=57;
    *(uint32_t*)(b+24)=0x00100001; *(uint32_t*)(b+28)=0x10;
    *(uint32_t*)(b+32)=0x07; *(uint32_t*)(b+36)=0x01; *(uint32_t*)(b+40)=0x01;
    *(uint16_t*)(b+44)=120; *(uint16_t*)(b+46)=2; memcpy(pdu+120,fn,2);
    int r=pool_xact(&g_pool[0],pdu,122,resp,sizeof(resp));
    if(r>=152&&*(uint32_t*)(resp+8)==0) memcpy(fid,resp+64+66,16); else return -1;
    /* CHANGE_NOTIFY */
    uint8_t body[32]={0}; *(uint16_t*)body=32;
    *(uint16_t*)(body+2)=0; /* Flags */
    *(uint32_t*)(body+4)=4096; /* OutputBufferLength */
    uint32_t filter=(fl>=4)?*(uint32_t*)f:0xFFF;
    *(uint32_t*)(body+24)=filter; /* CompletionFilter mutated */
    _seq_cmd(0,0x000F,body,32,fid,8);
    _seq_close(0,fid);
    return 0;
}

/* Seq 12: copychunk via IOCTL */
static int _seq12_copychunk(const void *f, int fl) {
    if (g_pool_n<1) return -1;
    uint8_t fid[16];
    const char fn[]="s\0q\00012\0";
    if (_seq_pool_create(0,fn,8,0x12019F,0x05,0,fid)) return -1;
    /* FSCTL_SRV_COPYCHUNK = 0x001440F2 */
    uint8_t body[256]={0}; *(uint16_t*)body=57;
    *(uint32_t*)(body+4)=0x001440F2;
    /* Copychunk input: resume_key(24) + chunk_count(4) + chunks */
    uint8_t input[64]={0};
    memcpy(input,fid,16); /* use fid as resume key */
    uint32_t nchunks=(fl>=4)?(*(uint32_t*)f&0xF):1;
    *(uint32_t*)(input+24)=nchunks;
    if(fl>4) memcpy(input+28,((char*)f)+4,(fl-4>36)?36:fl-4);
    *(uint32_t*)(body+24)=120; *(uint32_t*)(body+28)=28+nchunks*24;
    *(uint32_t*)(body+32)=4096; *(uint32_t*)(body+44)=4096; *(uint32_t*)(body+48)=1;
    memcpy(body+56,input,sizeof(input));
    _seq_cmd(0,0x000B,body,56+sizeof(input),fid,8);
    _seq_close(0,fid);
    return 0;
}

#define NUM_SEQUENCES 13

int pfz_sequence(int seq_id, const void *fuzz_data, int fuzz_len)
{
    if (g_df_buf) g_df_buf[0] = 0;
    int r;
    switch (seq_id) {
    case 0: r = _seq0_write(fuzz_data, fuzz_len); break;
    case 1: r = _seq1_lock_write(fuzz_data, fuzz_len); break;
    case 2: r = _seq2_oplock_setinfo(fuzz_data, fuzz_len); break;
    case 3: r = _seq3_ioctl(fuzz_data, fuzz_len); break;
    case 4: r = _seq4_query_info(fuzz_data, fuzz_len); break;
    case 5: r = _seq5_query_dir(fuzz_data, fuzz_len); break;
    case 6: r = _seq6_lease(fuzz_data, fuzz_len); break;
    case 7: r = _seq7_durable(fuzz_data, fuzz_len); break;
    case 8: r = _seq8_compound(fuzz_data, fuzz_len); break;
    case 9: r = _seq9_multi_credit(fuzz_data, fuzz_len); break;
    case 10: r = _seq10_setinfo(fuzz_data, fuzz_len); break;
    case 11: r = _seq11_notify(fuzz_data, fuzz_len); break;
    case 12: r = _seq12_copychunk(fuzz_data, fuzz_len); break;
    default: return -1;
    }
    return (r == 0 && g_df_buf) ? (int)g_df_buf[0] : r;
}

/* RDMA Transport Fuzzing (SMBDirect over SIW) */
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>

struct smbd_negotiate_req {
    uint16_t min_version;
    uint16_t max_version;
    uint16_t reserved;
    uint16_t credits_requested;
    uint32_t preferred_send_size;
    uint32_t max_receive_size;
    uint32_t max_fragmented_size;
};

static const char *_get_rdma_ip(void)
{
    static char ip[64] = {0};
    if (ip[0]) return ip;
    /* Try any global-scope IP (eth0 on bridge, or dummy0 for RXE loopback) */
    FILE *f = popen("ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \\K[0-9.]+' | head -1", "r");
    if (f) { if (fgets(ip, sizeof(ip), f)) { ip[strcspn(ip, "\n")] = 0; } pclose(f); }
    if (!ip[0]) strcpy(ip, "127.0.0.1");
    return ip;
}

/*
 * ksmbd serves SMBDirect on TWO ports by transport (transport_rdma.c):
 *   SMB_DIRECT_PORT_INFINIBAND = 445   (InfiniBand / RoCEv1 / RoCEv2, incl. RXE)
 *   SMB_DIRECT_PORT_IWARP      = 5445  (iWARP, incl. SIW)
 * Pick the port matching the local device's transport, else a connect to the
 * wrong listener is REJECTED (status=8) with zero coverage. RXE (Soft-RoCE)
 * reports IBV_TRANSPORT_IB; SIW (Soft-iWARP) reports IBV_TRANSPORT_IWARP.
 */
static uint16_t _rdma_smbd_port(void)
{
    static uint16_t port = 0;
    if (port) return port;
    port = 445;                 /* default: IB/RoCE (the RXE fallback) */
    int n = 0;
    struct ibv_device **list = ibv_get_device_list(&n);
    if (list) {
        if (n > 0 && list[0]->transport_type == IBV_TRANSPORT_IWARP)
            port = 5445;        /* SIW / iWARP */
        ibv_free_device_list(list);
    }
    return port;
}

static int _rdma_connect_and_send(uint16_t port, const void *data, int len)
{
    struct rdma_cm_id *cm_id = NULL;
    struct rdma_event_channel *ec = NULL;
    const char *rdma_ip = _get_rdma_ip();
    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(port ? port : 445) };
    dst.sin_addr.s_addr = inet_addr(rdma_ip);
    int ret = -1;
#define RDBG(...) do { if (getenv("KSMBDZZER_RDMA_DEBUG")) { \
        pfz_err("[rdma] " __VA_ARGS__); fputc('\n', stderr); } } while (0)
    RDBG("connect target=%s:%u len=%d", rdma_ip, port ? port : 445, len);

    ec = rdma_create_event_channel();
    if (!ec) { RDBG("create_event_channel FAILED: %s", strerror(errno)); return -1; }

    if (rdma_create_id(ec, &cm_id, NULL, RDMA_PS_TCP)) { RDBG("create_id FAILED"); goto out; }
    /* Don't bind source — let RDMA CM resolve automatically (works for RXE on lo) */
    if (rdma_resolve_addr(cm_id, NULL, (struct sockaddr *)&dst, 2000)) { RDBG("resolve_addr call FAILED: %s", strerror(errno)); goto out; }

    struct rdma_cm_event *event = NULL;
    if (rdma_get_cm_event(ec, &event)) { RDBG("get_cm_event(addr) FAILED"); goto out; }
    if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED) { RDBG("expected ADDR_RESOLVED got %s status=%d", rdma_event_str(event->event), event->status); rdma_ack_cm_event(event); goto out; }
    rdma_ack_cm_event(event);
    RDBG("ADDR_RESOLVED ok (dev=%s)", cm_id->verbs ? ibv_get_device_name(cm_id->verbs->device) : "?");

    if (rdma_resolve_route(cm_id, 2000)) { RDBG("resolve_route call FAILED"); goto out; }
    if (rdma_get_cm_event(ec, &event)) { RDBG("get_cm_event(route) FAILED"); goto out; }
    if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) { RDBG("expected ROUTE_RESOLVED got %s status=%d", rdma_event_str(event->event), event->status); rdma_ack_cm_event(event); goto out; }
    rdma_ack_cm_event(event);
    RDBG("ROUTE_RESOLVED ok");

    /* Create QP */
    struct ibv_pd *pd = ibv_alloc_pd(cm_id->verbs);
    if (!pd) goto out;
    struct ibv_cq *cq = ibv_create_cq(cm_id->verbs, 16, NULL, NULL, 0);
    if (!cq) { ibv_dealloc_pd(pd); goto out; }

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = cq, .recv_cq = cq,
        .cap = { .max_send_wr = 4, .max_recv_wr = 4, .max_send_sge = 1, .max_recv_sge = 1 },
        .qp_type = IBV_QPT_RC,
    };
    if (rdma_create_qp(cm_id, pd, &qp_attr)) { ibv_destroy_cq(cq); ibv_dealloc_pd(pd); goto out; }

    /* Post receive for negotiate response */
    struct ibv_mr *recv_mr = ibv_reg_mr(pd, (void *)data, len > 0 ? len : 64,
                                        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    /* Connect */
    struct rdma_conn_param conn_param = { .responder_resources = 1, .initiator_depth = 1, .retry_count = 3 };
    if (rdma_connect(cm_id, &conn_param)) { RDBG("rdma_connect call FAILED"); goto cleanup; }
    RDBG("rdma_connect sent, waiting for ESTABLISHED...");

    if (rdma_get_cm_event(ec, &event)) { RDBG("get_cm_event(connect) FAILED"); goto cleanup; }
    if (event->event != RDMA_CM_EVENT_ESTABLISHED) { RDBG("expected ESTABLISHED got %s status=%d (ksmbd did NOT accept)", rdma_event_str(event->event), event->status); rdma_ack_cm_event(event); goto cleanup; }
    rdma_ack_cm_event(event);
    RDBG("ESTABLISHED — ksmbd accepted; sending negotiate (%d bytes)", len);

    /* Connected! Send malformed negotiate */
    if (data && len > 0) {
        struct ibv_mr *send_mr = ibv_reg_mr(pd, (void *)data, len, IBV_ACCESS_LOCAL_WRITE);
        if (send_mr) {
            struct ibv_sge sge = { .addr = (uintptr_t)data, .length = len, .lkey = send_mr->lkey };
            struct ibv_send_wr wr = { .sg_list = &sge, .num_sge = 1, .opcode = IBV_WR_SEND, .send_flags = IBV_SEND_SIGNALED };
            struct ibv_send_wr *bad_wr;
            ibv_post_send(cm_id->qp, &wr, &bad_wr);
            /* Wait briefly for completion */
            struct ibv_wc wc;
            for (int i = 0; i < 100; i++) { if (ibv_poll_cq(cq, 1, &wc) > 0) break; usleep(1000); }
            ibv_dereg_mr(send_mr);
        }
    }
    ret = g_df_buf ? (int)g_df_buf[0] : 0;

cleanup:
    if (recv_mr) ibv_dereg_mr(recv_mr);
    rdma_disconnect(cm_id);
    rdma_destroy_qp(cm_id);
    ibv_destroy_cq(cq);
    ibv_dealloc_pd(pd);
out:
    if (cm_id) rdma_destroy_id(cm_id);
    if (ec) rdma_destroy_event_channel(ec);
    return ret;
}

int pfz_rdma_fuzz(const void *payload, int payload_len, uint16_t port)
{
    if (g_df_buf) g_df_buf[0] = 0;
    /* Build negotiate request (possibly mutated) */
    uint8_t buf[4096];
    struct smbd_negotiate_req neg = {
        .min_version = 0x0100, .max_version = 0x0100,
        .credits_requested = 255,
        .preferred_send_size = 1364, .max_receive_size = 1364,
        .max_fragmented_size = 1048576,
    };
    if (payload && payload_len >= (int)sizeof(neg))
        memcpy(&neg, payload, sizeof(neg));
    memcpy(buf, &neg, sizeof(neg));
    int total = sizeof(neg);
    if (payload && payload_len > (int)sizeof(neg)) {
        int extra = payload_len - sizeof(neg);
        if (extra > (int)(sizeof(buf) - total)) extra = sizeof(buf) - total;
        memcpy(buf + total, (const uint8_t *)payload + sizeof(neg), extra);
        total += extra;
    }
    return _rdma_connect_and_send(port, buf, total);
}





/* ═══════════════════════════════════════════════════════════════════════════
 * GRAIN REGISTRY — the atom of the new phase architecture
 * ---------------------------------------------------------------------------
 * A "grain" is a working code block for ONE normal scenario, parameterized by
 * the fuzzer input. Each grain drives a REAL authenticated operation (the
 * libsmbclient ops above), so it reaches deep VFS code BY CONSTRUCTION (aligned)
 * — unlike a hand-built raw-SMB2 prefix, which the alignment gate showed is
 * shallow. The phase architecture is then uniform over grains:
 *   P1 grain     : enumerate grains (the normal-scenario library)
 *   P2 saturate  : LibFuzzer-fuzz each grain to coverage saturation (trace-args/ret)
 *   P3 combine   : run grain combinations — concurrent = race, chained = compound
 *   P4 save      : carry the strong grains + corpus to the next generation
 * This section only ADDS the uniform registry; the per-op functions above are the
 * grain bodies, reused unchanged. Mutation maps fuzzer bytes → the op's semantic
 * fields (offset/length/name/value) — the I2S-relevant parameters.
 * ======================================================================= */

/* little-endian read of `width` bytes from the fuzzer input at `off` (0 if short) */
static uint64_t grain_u(const uint8_t *d, size_t n, size_t off, int width) {
    uint64_t v = 0;
    for (int i = 0; i < width && off + (size_t)i < n; i++)
        v |= (uint64_t)d[off + i] << (8 * i);
    return v;
}

static int grain_write(const uint8_t *d, size_t n) {
    long off = (long)(grain_u(d, n, 0, 8) & 0xFFFFFF);
    const uint8_t *buf = (n > 8) ? d + 8 : d;
    int blen = (n > 8) ? (int)(n - 8) : (int)n;
    if (blen <= 0) blen = 1;
    return pfz_write(off, buf, blen > 512 ? 512 : blen);
}
static int grain_truncate(const uint8_t *d, size_t n) {
    return pfz_truncate((long)(grain_u(d, n, 0, 8) & 0x7FFFFFFF));
}
static int grain_setxattr(const uint8_t *d, size_t n) {
    return pfz_setxattr("user.grain", d, n > 256 ? 256 : (int)n);
}
static int grain_copychunk(const uint8_t *d, size_t n) {
    return pfz_copychunk(grain_u(d, n, 0, 8), grain_u(d, n, 8, 8),
                               (uint32_t)(grain_u(d, n, 16, 4) & 0xFFFFFF),
                               1 + (int)(grain_u(d, n, 20, 1) & 7));
}
static int grain_query_dir(const uint8_t *d, size_t n) {
    return pfz_query_dir((uint8_t)(n ? d[0] : 1),
                               (uint32_t)grain_u(d, n, 1, 4), d, n > 64 ? 64 : (int)n);
}
static int grain_compress(const uint8_t *d, size_t n) {
    return pfz_compress_fuzz((uint16_t)(1 + (n ? d[0] % 3 : 0)),
                                   d, (int)n, (uint32_t)grain_u(d, n, 0, 4));
}
static int grain_reparse(const uint8_t *d, size_t n) {
    return pfz_set_reparse((uint32_t)grain_u(d, n, 0, 4), d, (int)n);
}
static int grain_unicode(const uint8_t *d, size_t n) {
    return pfz_unicode_path(d, n > 128 ? 128 : (int)n);
}
static int grain_ndr(const uint8_t *d, size_t n) {
    return pfz_ndr_fuzz(d, (int)n);
}
static int grain_negotiate(const uint8_t *d, size_t n) {
    return pfz_negotiate_contexts(d, (int)n);
}
static int grain_lease(const uint8_t *d, size_t n) {           /* SMB2 lease path */
    uint8_t key[16] = {0};
    for (size_t i = 0; i < 16 && i < n; i++) key[i] = d[i];
    /* bytes [16,20) drive the requested LeaseState (I2S on the lease body). */
    return pfz_lease_race("grain_lease", key, (uint32_t)grain_u(d, n, 16, 4));
}
static int grain_durable(const uint8_t *d, size_t n) {         /* durable handle path */
    (void)d; (void)n;
    return pfz_durable_reconnect("grain_dur");
}
/* Former phases 4/7b/8/8b/7, now uniform grains (concurrency/structure scenarios). */
static int grain_race(const uint8_t *d, size_t n) {            /* was P4: write/close race */
    return pfz_race_write_close(d, (int)n, 2 + (int)(grain_u(d, n, 0, 1) & 7));
}
static int grain_sequence(const uint8_t *d, size_t n) {        /* was P7b: stateful seq */
    return pfz_sequence((int)(grain_u(d, n, 0, 1) % 8), d, (int)n);
}
static int grain_compound(const uint8_t *d, size_t n) {        /* was P8: compound chain */
    uint8_t resp[2048];
    return pfz_compound(d, (int)n, resp, sizeof(resp));
}
static int grain_pipe(const uint8_t *d, size_t n) {            /* was P7: IPC$ pipe */
    return pfz_unknown_pipe(d, n > 64 ? 64 : (int)n);
}
static int grain_rdma(const uint8_t *d, size_t n) {            /* was P8b: SMB-direct */
    return pfz_rdma_fuzz(d, (int)n, _rdma_smbd_port());       /* 445 RoCE/RXE, 5445 iWARP/SIW */
}

/* write-side coverage grains (built on the proven g_smb_fd libsmbclient preamble). */
static int grain_write_ext(const uint8_t *d, size_t n) {      /* sparse/boundary write */
    unsigned long long off = grain_u(d, n, 0, 8);             /* full 64-bit offset */
    const uint8_t *buf = (n > 8) ? d + 8 : d;
    int blen = (n > 8) ? (int)(n - 8) : (int)n;
    if (blen <= 0) blen = 1;
    return pfz_write_ext(off, buf, blen > 512 ? 512 : blen);
}
static int grain_setattr(const uint8_t *d, size_t n) {        /* SET_INFO basic: mode+times */
    return pfz_setattr((unsigned int)grain_u(d, n, 0, 4),
                       (long)grain_u(d, n, 4, 4), (long)grain_u(d, n, 8, 4));
}
static int grain_rename(const uint8_t *d, size_t n) {         /* rename-path/traversal */
    return pfz_rename(d, (int)n);
}
static int grain_secdesc(const uint8_t *d, size_t n) {        /* ACL / security descriptor */
    return pfz_set_secdesc(d, (int)n);
}
static int grain_dosattr(const uint8_t *d, size_t n) {        /* DOS attribute mode */
    return pfz_set_dosattr((unsigned int)grain_u(d, n, 0, 4));
}
static int grain_unlink(const uint8_t *d, size_t n) {         /* delete/unlink path */
    (void)d; (void)n; return pfz_unlink_victim();
}
static int grain_mkrmdir(const uint8_t *d, size_t n) {        /* dir create/remove */
    return pfz_mkrmdir(d, (int)n);
}
static int grain_rmxattr(const uint8_t *d, size_t n) {        /* EA add+remove */
    return pfz_rmxattr(d, (int)n);
}

/* ─── GRAIN.md gap grains: raw SMB2 procedures with a working open→fid preamble ───
 * Each builds a raw SMB2 PDU on the authed pool connection g_pool[0] and fuzzes the
 * LAST endpoint's fields. Reaching ksmbd's handler (even to reject) is the coverage;
 * pool_ensure_fid() is the working preamble for the file-based ones. */

static int grain_read(const uint8_t *d, size_t n) {          /* SMB2 READ 0x08 */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "read_v")) return -1;
    uint8_t pdu[128], resp[8192];
    pool_smb2_hdr(pdu, 0x0008, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 49;                              /* StructureSize */
    b[3] = (uint8_t)grain_u(d, n, 0, 1);             /* Flags */
    *(uint32_t *)(b + 4)  = (uint32_t)grain_u(d, n, 1, 4);   /* Length (fuzzed) */
    *(uint64_t *)(b + 8)  = grain_u(d, n, 5, 8);            /* Offset (boundary) */
    memcpy(b + 16, g_pool[0].fid, 16);
    *(uint32_t *)(b + 32) = (uint32_t)grain_u(d, n, 13, 4); /* MinimumCount */
    *(uint32_t *)(b + 36) = (uint32_t)grain_u(d, n, 17, 4); /* Channel */
    return pool_xact(&g_pool[0], pdu, 64 + 49, resp, sizeof(resp));
}

static int grain_lock(const uint8_t *d, size_t n) {          /* SMB2 LOCK 0x0A */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "lock_v")) return -1;
    uint8_t pdu[128], resp[256];
    pool_smb2_hdr(pdu, 0x000A, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 48;                              /* StructureSize */
    *(uint16_t *)(b + 2) = 1;                         /* LockCount */
    *(uint32_t *)(b + 4) = (uint32_t)grain_u(d, n, 0, 4);   /* LockSequence */
    memcpy(b + 8, g_pool[0].fid, 16);
    /* SMB2_LOCK_GRAIN @24: Offset(8) Length(8) Flags(4) Reserved(4) */
    *(uint64_t *)(b + 24) = grain_u(d, n, 4, 8);           /* Offset */
    *(uint64_t *)(b + 32) = grain_u(d, n, 12, 8);          /* Length */
    *(uint32_t *)(b + 40) = (uint32_t)grain_u(d, n, 20, 4);/* Flags (SHARED/EXCL/UNLOCK) */
    return pool_xact(&g_pool[0], pdu, 64 + 48, resp, sizeof(resp));
}

static int grain_flush(const uint8_t *d, size_t n) {         /* SMB2 FLUSH 0x07 */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "flush_v")) return -1;
    uint8_t pdu[128], resp[128];
    pool_smb2_hdr(pdu, 0x0007, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 24;
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 0, 2);  /* Reserved1 (fuzzed) */
    *(uint32_t *)(b + 4) = (uint32_t)grain_u(d, n, 2, 4);  /* Reserved2 (fuzzed) */
    memcpy(b + 8, g_pool[0].fid, 16);
    return pool_xact(&g_pool[0], pdu, 64 + 24, resp, sizeof(resp));
}

static int grain_echo(const uint8_t *d, size_t n) {          /* SMB2 ECHO 0x0D */
    if (g_pool_n < 1) return -1;
    uint8_t pdu[80], resp[80];
    pool_smb2_hdr(pdu, 0x000D, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 4;
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 0, 2);  /* Reserved (fuzzed) */
    return pool_xact(&g_pool[0], pdu, 64 + 4, resp, sizeof(resp));
}

static int grain_cancel(const uint8_t *d, size_t n) {        /* SMB2 CANCEL 0x0C */
    if (g_pool_n < 1) return -1;
    uint8_t pdu[80], resp[80];
    pool_smb2_hdr(pdu, 0x000C, &g_pool[0]);
    /* Cancel a (possibly non-existent) async op by MID → async-teardown path. */
    *(uint64_t *)(pdu + 24) = grain_u(d, n, 0, 8);         /* fuzz MessageId */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 4;
    return pool_xact(&g_pool[0], pdu, 64 + 4, resp, sizeof(resp));
}

static int grain_query_info(const uint8_t *d, size_t n) {    /* SMB2 QUERY_INFO 0x10 */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "qinfo_v")) return -1;
    uint8_t pdu[128], resp[4096];
    pool_smb2_hdr(pdu, 0x0010, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 41;
    b[2] = (uint8_t)grain_u(d, n, 0, 1);             /* InfoType (FILE/FS/SEC/QUOTA) */
    b[3] = (uint8_t)grain_u(d, n, 1, 1);             /* FileInfoClass (fuzzed) */
    *(uint32_t *)(b + 4)  = 4096;                     /* OutputBufferLength */
    *(uint32_t *)(b + 16) = (uint32_t)grain_u(d, n, 2, 4); /* AdditionalInformation */
    *(uint32_t *)(b + 20) = (uint32_t)grain_u(d, n, 6, 4); /* Flags */
    memcpy(b + 24, g_pool[0].fid, 16);
    return pool_xact(&g_pool[0], pdu, 64 + 41, resp, sizeof(resp));
}

static int grain_get_quota(const uint8_t *d, size_t n) {     /* QUERY_INFO InfoType=QUOTA 0x04 */
    /* The QUERY side of quota (Samba cli_smb2_get_user_quota / list_user_quota). Unlike
     * the generic query_info grain — which can set InfoType=QUOTA but sends NO input
     * buffer, so ksmbd rejects before the quota parser — this builds a real (fuzzed)
     * SMB2_QUERY_QUOTA_INFO input (ReturnSingle/RestartScan/SidListLength/StartSidLength/
     * StartSidOffset + a fuzzed SID blob) so smb2_query_info's QUOTA path actually walks
     * it. ksmbd may not fully support quota-query → reaches the handler/reject path (the
     * "whole procedure even if ksmbd rejects" goal). */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "getquota_v")) return -1;
    uint8_t pdu[256], resp[4096];
    pool_smb2_hdr(pdu, 0x0010, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 40);
    *(uint16_t *)b = 41;                              /* StructureSize (40 fixed + 1) */
    b[2] = 0x04;                                      /* InfoType = QUOTA */
    *(uint32_t *)(b + 4)  = 4096;                     /* OutputBufferLength */
    *(uint16_t *)(b + 8)  = 64 + 40;                  /* InputBufferOffset (abs 104) */
    uint8_t *q = b + 40;                              /* SMB2_QUERY_QUOTA_INFO */
    q[0] = (uint8_t)grain_u(d, n, 0, 1);             /* ReturnSingle */
    q[1] = (uint8_t)grain_u(d, n, 1, 1);             /* RestartScan */
    *(uint32_t *)(q + 4)  = (uint32_t)grain_u(d, n, 2, 4);  /* SidListLength (fuzzed) */
    *(uint32_t *)(q + 8)  = (uint32_t)grain_u(d, n, 6, 4);  /* StartSidLength (fuzzed) */
    *(uint32_t *)(q + 12) = (uint32_t)grain_u(d, n, 10, 4); /* StartSidOffset (fuzzed) */
    int qlen = 24;                                    /* fixed SMB2_QUERY_QUOTA_INFO */
    int extra = (n > 14) ? (int)(n - 14) : 0; if (extra > 64) extra = 64;
    for (int i = 0; i < extra; i++) q[qlen + i] = d[14 + i]; /* fuzzed SID-list bytes */
    qlen += extra;
    *(uint32_t *)(b + 12) = (uint32_t)qlen;          /* InputBufferLength */
    memcpy(b + 24, g_pool[0].fid, 16);               /* FileId (volume handle) */
    return pool_xact(&g_pool[0], pdu, 64 + 40 + qlen, resp, sizeof(resp));
}

static int grain_notify(const uint8_t *d, size_t n) {        /* SMB2 CHANGE_NOTIFY 0x0F */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "notify_v")) return -1;
    uint8_t pdu[128], resp[256];
    pool_smb2_hdr(pdu, 0x000F, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 32;
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 0, 2);  /* Flags (WATCH_TREE) */
    *(uint32_t *)(b + 4)  = (uint32_t)grain_u(d, n, 2, 4); /* OutputBufferLength */
    memcpy(b + 8, g_pool[0].fid, 16);
    *(uint32_t *)(b + 24) = (uint32_t)grain_u(d, n, 6, 4); /* CompletionFilter (fuzzed) */
    return pool_xact(&g_pool[0], pdu, 64 + 32, resp, sizeof(resp));
}

static int grain_tdis(const uint8_t *d, size_t n) {          /* SMB2 TREE_DISCONNECT 0x04 */
    if (g_pool_n < 1) return -1;
    uint8_t pdu[80], resp[80];
    pool_smb2_hdr(pdu, 0x0004, &g_pool[0]);
    *(uint32_t *)(pdu + 36) = (uint32_t)grain_u(d, n, 0, 4);/* fuzz TreeId */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 4;
    int r = pool_xact(&g_pool[0], pdu, 64 + 4, resp, sizeof(resp));
    g_pool[0].has_fid = 0;   /* tree gone; force fid re-open next grain */
    return r;
}

static int grain_close(const uint8_t *d, size_t n) {         /* SMB2 CLOSE 0x06 */
    /* The last SMB2 command that had only a preamble grain (GRAIN.md §1). Beyond
     * fuzzing Flags/Reserved, this is a post-close USE-AFTER-CLOSE probe: CLOSE the
     * fid, then (data-gated) send a SECOND CLOSE on the SAME now-stale FileId →
     * smb2_close() re-runs against a freed ksmbd_file / ida-released volatile id.
     * That double-close / stale-fid path is a classic UAF class. */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "close_v")) return -1;
    uint8_t pdu[96], resp[128];
    pool_smb2_hdr(pdu, 0x0006, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 24;                                    /* StructureSize */
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 0, 2);  /* Flags (POSTQUERY_ATTRIB) */
    *(uint32_t *)(b + 4) = (uint32_t)grain_u(d, n, 2, 4);  /* Reserved (fuzzed) */
    memcpy(b + 8, g_pool[0].fid, 16);                      /* FileId */
    int r = pool_xact(&g_pool[0], pdu, 64 + 24, resp, sizeof(resp));
    if (grain_u(d, n, 6, 1) & 1) {                         /* double-close the stale id */
        pool_smb2_hdr(pdu, 0x0006, &g_pool[0]);
        b = pdu + 64;
        *(uint16_t *)b = 24;
        memcpy(b + 8, g_pool[0].fid, 16);                  /* SAME (now freed) FileId */
        pool_xact(&g_pool[0], pdu, 64 + 24, resp, sizeof(resp));
    }
    g_pool[0].has_fid = 0;   /* fid closed; force re-open next grain */
    return r;
}

static int grain_logoff(const uint8_t *d, size_t n) {        /* SMB2 LOGOFF 0x02 */
    /* Dedicated session-teardown grain (was only exercised via the teardown oracle,
     * GRAIN.md §1). Sends LOGOFF — optionally against a fuzzed SessionId (logoff of a
     * wrong/other session → smb2_session_logoff lookup path) — then forces a full
     * re-auth so the pool self-heals. Exercises session-object lifetime/teardown, the
     * session UAF/race surface, on the [share] connection. */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "logoff_v")) return -1;
    uint8_t pdu[80], resp[80];
    pool_smb2_hdr(pdu, 0x0002, &g_pool[0]);
    if (grain_u(d, n, 0, 1) & 1)
        *(uint64_t *)(pdu + 40) = grain_u(d, n, 1, 8);     /* fuzz SessionId */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 4;                                    /* StructureSize */
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 9, 2);  /* Reserved (fuzzed) */
    int r = pool_xact(&g_pool[0], pdu, 64 + 4, resp, sizeof(resp));
    /* Session gone → drop the socket so pool_ensure_fid()/pool_reconnect() re-auths
     * (session + tree + fid) cleanly on the next grain instead of reusing a dead sid. */
    if (g_pool[0].sock >= 0) { close(g_pool[0].sock); g_pool[0].sock = -1; }
    g_pool[0].has_fid = 0; g_pool[0].sid = 0; g_pool[0].tid = 0; g_pool[0].mid = 0;
    return r;
}

/* IOCTL (0x0B) write-side FSCTLs: zero-data (hole punch) + duplicate-extents. */
static int grain_fsctl_zero(const uint8_t *d, size_t n) {    /* FSCTL_SET_ZERO_DATA */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "zero_v")) return -1;
    uint8_t pdu[160], resp[256];
    pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 4) = 0x000980C8;               /* FSCTL_SET_ZERO_DATA */
    memcpy(b + 8, g_pool[0].fid, 16);
    *(uint32_t *)(b + 24) = 64 + 56;                 /* InputOffset */
    *(uint32_t *)(b + 28) = 16;                       /* InputCount */
    *(uint32_t *)(b + 48) = 1;                        /* Flags = IS_FSCTL */
    *(uint64_t *)(b + 56) = grain_u(d, n, 0, 8);     /* FileOffset (fuzzed) */
    *(uint64_t *)(b + 64) = grain_u(d, n, 8, 8);     /* BeyondFinalZero (fuzzed) */
    return pool_xact(&g_pool[0], pdu, 64 + 56 + 16, resp, sizeof(resp));
}

static int grain_fsctl_dupext(const uint8_t *d, size_t n) {  /* FSCTL_DUPLICATE_EXTENTS_TO_FILE */
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "dup_v")) return -1;
    uint8_t pdu[192], resp[256];
    pool_smb2_hdr(pdu, 0x000B, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 57;
    *(uint32_t *)(b + 4) = 0x00098344;               /* FSCTL_DUPLICATE_EXTENTS_TO_FILE */
    memcpy(b + 8, g_pool[0].fid, 16);
    *(uint32_t *)(b + 24) = 64 + 56;                 /* InputOffset */
    *(uint32_t *)(b + 28) = 40;                       /* InputCount */
    *(uint32_t *)(b + 48) = 1;                        /* Flags = IS_FSCTL */
    memcpy(b + 56, g_pool[0].fid, 16);               /* SourceFileId (self) */
    *(uint64_t *)(b + 72) = grain_u(d, n, 0, 8);     /* SourceFileOffset */
    *(uint64_t *)(b + 80) = grain_u(d, n, 8, 8);     /* TargetFileOffset */
    *(uint64_t *)(b + 88) = grain_u(d, n, 16, 8);    /* ByteCount (fuzzed) */
    return pool_xact(&g_pool[0], pdu, 64 + 56 + 40, resp, sizeof(resp));
}

/* SET_INFO (0x11) FILE_ALLOCATION_INFORMATION (19): set allocation size. */
static int grain_set_alloc(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "alloc_v")) return -1;
    uint8_t pdu[128], resp[128];
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 33;
    b[2] = 1;                                         /* InfoType = FILE */
    b[3] = 19;                                        /* FILE_ALLOCATION_INFORMATION */
    *(uint32_t *)(b + 4) = 8;                         /* BufferLength */
    *(uint16_t *)(b + 8) = 64 + 32;                  /* BufferOffset */
    memcpy(b + 16, g_pool[0].fid, 16);
    *(uint64_t *)(b + 32) = grain_u(d, n, 0, 8);     /* AllocationSize (fuzzed) */
    return pool_xact(&g_pool[0], pdu, 64 + 32 + 8, resp, sizeof(resp));
}

/* SET_INFO (0x11) FILE_LINK_INFORMATION (11): create a hardlink to a fuzzed path. */
static int grain_hardlink(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "link_src")) return -1;
    uint8_t pdu[256], resp[128];
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64;
    /* FILE_LINK_INFORMATION: ReplaceIfExists(1) Reserved(7) RootDir(8) NameLen(4) Name */
    uint8_t nm[64]; int j = 0;
    for (int i = 0; i < (int)n && j < 30; i++) {
        uint8_t c = d[i];
        if (c >= 0x20 && c < 0x7f && c != '?' && c != '*' && c != '\\') nm[j++] = c;
    }
    if (j == 0) nm[j++] = 'h';
    int wlen = j * 2;
    *(uint16_t *)b = 33;
    b[2] = 1; b[3] = 11;                              /* FILE, FILE_LINK_INFORMATION */
    *(uint32_t *)(b + 4) = 20 + wlen;                /* BufferLength */
    *(uint16_t *)(b + 8) = 64 + 32;                  /* BufferOffset */
    memcpy(b + 16, g_pool[0].fid, 16);
    uint8_t *lb = b + 32;
    lb[0] = (uint8_t)grain_u(d, n, 0, 1) & 1;        /* ReplaceIfExists (fuzzed) */
    *(uint32_t *)(lb + 16) = wlen;                    /* FileNameLength */
    for (int i = 0; i < j; i++) { lb[20 + i*2] = nm[i]; lb[20 + i*2 + 1] = 0; }
    return pool_xact(&g_pool[0], pdu, 64 + 32 + 20 + wlen, resp, sizeof(resp));
}

/* SMB1 legacy version-conflict: send an SMB1 PDU (0xFF 'SMB' + fuzzed command) on
 * the authed socket. ksmbd only expects SMB1 NEGOTIATE for downgrade; any other
 * SMB1 command exercises the legacy/version-mismatch handling — a classic
 * "old protocol meets new server" security surface. */
static int grain_smb1(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[256], resp[256];
    memset(pdu, 0, sizeof(pdu));
    memcpy(pdu, "\xffSMB", 4);                        /* SMB1 magic */
    pdu[4] = (uint8_t)grain_u(d, n, 0, 1);           /* Command (SMBopen/write/trans...) */
    /* Flags/Flags2 + fuzzed WordCount/ByteCount body */
    pdu[13] = 0x18; pdu[14] = 0x01; pdu[15] = 0x20;
    int blen = (int)(n > 200 ? 200 : n);
    if (blen > 0) memcpy(pdu + 32, d, blen);
    pdu[32] = (uint8_t)grain_u(d, n, 1, 1);          /* WordCount */
    return pool_xact(&g_pool[0], pdu, 32 + (blen > 3 ? blen : 3), resp, sizeof(resp));
}

/* ─── CREATE-context grains (§4): fuzz each context parser via pool_create_with_ctx ─── */
static int grain_create_ea(const uint8_t *d, size_t n) {     /* ExtA: EA-on-create */
    return pool_create_with_ctx("cc_ea", "ExtA", 4, d, (int)n);   /* FILE_FULL_EA_INFO fuzzed */
}
static int grain_create_sd(const uint8_t *d, size_t n) {     /* SecD: security descriptor on create */
    return pool_create_with_ctx("cc_sd", "SecD", 4, d, (int)n);   /* raw SD bytes → ndr parser */
}
static int grain_create_mxac(const uint8_t *d, size_t n) {   /* MxAc: query maximal access */
    return pool_create_with_ctx("cc_mxac", "MxAc", 4, d, n > 8 ? 8 : (int)n);
}
static int grain_create_alsi(const uint8_t *d, size_t n) {   /* AlSi: allocation size on create */
    uint64_t sz = grain_u(d, n, 0, 8);
    return pool_create_with_ctx("cc_alsi", "AlSi", 4, &sz, 8);
}
static int grain_create_qfid(const uint8_t *d, size_t n) {   /* QFid: query on-disk id */
    (void)d; (void)n; return pool_create_with_ctx("cc_qfid", "QFid", 4, NULL, 0);
}
static int grain_create_posix(const uint8_t *d, size_t n) {  /* POSIX ext context (16-byte GUID tag) */
    static const char posix_tag[16] =
        "\x93\xAD\x25\x50\x9C\xB4\x11\xE7\xB4\x23\x83\xDE\x96\x8B\xCD\x7C";
    uint32_t mode = (uint32_t)grain_u(d, n, 0, 4);
    return pool_create_with_ctx("cc_posix", posix_tag, 16, &mode, 4);
}

/* ─── Remaining FSCTL grains (§2): via pool_ioctl ─── */
static int grain_fsctl_sparse(const uint8_t *d, size_t n) {  /* FSCTL_SET_SPARSE */
    uint8_t on = n > 0 ? (d[0] & 1) : 1;
    return pool_ioctl(0x000900C4, &on, 1, 1);
}
static int grain_fsctl_qar(const uint8_t *d, size_t n) {     /* FSCTL_QUERY_ALLOCATED_RANGES */
    uint64_t rng[2] = { grain_u(d, n, 0, 8), grain_u(d, n, 8, 8) };  /* Offset, Length */
    return pool_ioctl(0x000940CF, rng, 16, 1);
}
static int grain_fsctl_setcomp(const uint8_t *d, size_t n) { /* FSCTL_SET_COMPRESSION */
    uint16_t state = (uint16_t)grain_u(d, n, 0, 2);
    return pool_ioctl(0x0009C040, &state, 2, 1);
}
static int grain_fsctl_objid(const uint8_t *d, size_t n) {   /* FSCTL_CREATE_OR_GET_OBJECT_ID */
    (void)d; (void)n; return pool_ioctl(0x000900C0, NULL, 0, 1);
}
static int grain_fsctl_valneg(const uint8_t *d, size_t n) {  /* FSCTL_VALIDATE_NEGOTIATE_INFO (downgrade) */
    return pool_ioctl(0x00140204, d, n > 64 ? 64 : (int)n, 0);   /* session-level, no fid */
}
static int grain_fsctl_dfs(const uint8_t *d, size_t n) {     /* FSCTL_DFS_GET_REFERRALS (path parse) */
    uint8_t in[128]; int j = 0;
    *(uint16_t *)in = (uint16_t)grain_u(d, n, 0, 2);            /* MaxReferralLevel */
    j = 2;
    for (int i = 2; i < (int)n && j < 120; i++) { in[j++] = d[i]; in[j++] = 0; }  /* UTF-16 path */
    return pool_ioctl(0x00060194, in, j, 0);
}
static int grain_fsctl_netif(const uint8_t *d, size_t n) {   /* FSCTL_QUERY_NETWORK_INTERFACE_INFO */
    (void)d; (void)n; return pool_ioctl(0x001401FC, NULL, 0, 0);
}

/* TREE_CONNECT (0x03) with a fuzzed UNC/share path → ksmbd share lookup + path parse. */
static int grain_tcon(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[256], resp[256];
    pool_smb2_hdr(pdu, 0x0003, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 9;
    *(uint16_t *)(b + 2) = (uint16_t)grain_u(d, n, 0, 2);  /* Flags */
    *(uint16_t *)(b + 4) = 64 + 8;                          /* PathOffset */
    char path[80]; int p = snprintf(path, sizeof(path), "\\\\%s\\", g_target_ip);
    for (int i = 2; i < (int)n && p < 60; i++) {
        uint8_t c = d[i];
        if (c >= 0x20 && c < 0x7f && c != '?' && c != '*') path[p++] = (char)c;
    }
    int wlen = p * 2;
    *(uint16_t *)(b + 6) = wlen;                            /* PathLength */
    for (int i = 0; i < p; i++) { b[8 + i*2] = path[i]; b[8 + i*2 + 1] = 0; }
    return pool_xact(&g_pool[0], pdu, 64 + 8 + wlen, resp, sizeof(resp));
}

/* Remaining CREATE contexts: AAPL, APP_INSTANCE_ID (16-byte GUID tag), durable-v2. */
static int grain_create_aapl(const uint8_t *d, size_t n) {
    return pool_create_with_ctx("cc_aapl", "AAPL", 4, d, (int)n);
}
static int grain_create_appinst(const uint8_t *d, size_t n) {
    static const char tag[16] =
        "\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74";
    return pool_create_with_ctx("cc_appinst", tag, 16, d, n > 20 ? 20 : (int)n);
}
static int grain_create_dh2(const uint8_t *d, size_t n) {    /* DH2Q durable-v2 request */
    uint8_t data[32] = {0};
    *(uint32_t *)(data + 0) = (uint32_t)grain_u(d, n, 0, 4);   /* Timeout */
    *(uint32_t *)(data + 4) = (uint32_t)grain_u(d, n, 4, 4);   /* Flags (persistent) */
    for (int i = 0; i < 16 && i + 8 < (int)n; i++) data[16 + i] = d[8 + i]; /* CreateGuid */
    return pool_create_with_ctx("cc_dh2", "DH2Q", 4, data, 32);
}

/* ─── WRITE-SIDE focus (public storage server / OneDrive-like) ─────────────────── */

/* Alternate data streams: open "file:<fuzzed>:$DATA" and write → ksmbd streams_xattr
 * (stream-name parse + xattr-backed stream store). A classic storage-server write
 * surface (stream-name confusion, ::$DATA tricks, xattr size limits). */
static int grain_stream_write(const uint8_t *d, size_t n) {
    char url[160], nm[48]; int j = 0;
    for (int i = 0; i < (int)n && j < 30; i++) {
        uint8_t c = d[i];
        if (c >= 0x20 && c < 0x7f && c != '/' && c != '\\' && c != ':') nm[j++] = (char)c;
    }
    if (j == 0) nm[j++] = 's';
    nm[j] = 0;
    snprintf(url, sizeof(url), "smb://%s/share/sfile:%s:$DATA", g_target_ip, nm);
    int fd = smbc_open(url, O_RDWR | O_CREAT, 0666);
    if (fd < 0) return -1;
    const uint8_t *buf = (n > 16) ? d + 16 : d;
    int blen = (n > 16) ? (int)(n - 16) : (int)n;
    int r = smbc_write(fd, buf, blen > 256 ? 256 : (blen > 0 ? blen : 1));
    smbc_close(fd);
    return r;
}

/* Raw SMB2 WRITE with fuzzed WriteFlags (WRITETHROUGH=1 / UNBUFFERED=2) + boundary
 * offset → the write-through / direct-IO / size paths a sync client hammers. */
static int grain_write_flags(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "wf_v")) return -1;
    uint8_t pdu[600], resp[256];
    pool_smb2_hdr(pdu, 0x0009, &g_pool[0]);
    uint8_t *b = pdu + 64;
    int dlen = n > 256 ? 256 : (int)n; if (dlen < 1) dlen = 1;
    *(uint16_t *)b = 49;
    *(uint16_t *)(b + 2) = 64 + 48;                       /* DataOffset */
    *(uint32_t *)(b + 4) = dlen;                          /* Length */
    *(uint64_t *)(b + 8) = grain_u(d, n, 0, 8) & 0xFFFFFF;/* Offset (bounded — flags are the target) */
    memcpy(b + 16, g_pool[0].fid, 16);
    *(uint32_t *)(b + 44) = (uint32_t)grain_u(d, n, 8, 4); /* Flags (WRITETHROUGH/UNBUFFERED) */
    memcpy(b + 48, d, dlen);
    return pool_xact(&g_pool[0], pdu, 64 + 48 + dlen, resp, sizeof(resp));
}

/* Append/grow: seek to EOF and write → the file-grow / allocation path a sync
 * client uses for chunked uploads. */
static int grain_append(const uint8_t *d, size_t n) {
    if (g_smb_fd < 0) return -1;
    smbc_lseek(g_smb_fd, 0, SEEK_END);
    return smbc_write(g_smb_fd, d, n > 512 ? 512 : (n > 0 ? (int)n : 1));
}

/* ─── §8 remainder: SMB3 encryption / multichannel / lease-v2 / legacy per-opcode ─── */

/* SMB3 TRANSFORM_HEADER (0xFD'SMB'): fuzz Signature/Nonce/OrigSize/Flags + payload →
 * ksmbd's smb3 decrypt/transform path (needs `smb3 encryption = enabled`). */
static int grain_encrypt(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[256], resp[256];
    memset(pdu, 0, sizeof(pdu));
    memcpy(pdu, "\xfdSMB", 4);                             /* transform magic */
    for (int i = 0; i < 16 && i < (int)n; i++) pdu[4 + i] = d[i];        /* Signature */
    for (int i = 0; i < 16 && 16 + i < (int)n; i++) pdu[20 + i] = d[16 + i];/* Nonce */
    *(uint32_t *)(pdu + 36) = (uint32_t)grain_u(d, n, 0, 4);/* OriginalMessageSize */
    *(uint16_t *)(pdu + 42) = (uint16_t)grain_u(d, n, 4, 2);/* Flags (enc alg) */
    *(uint64_t *)(pdu + 44) = g_pool[0].sid;               /* SessionId */
    int blen = (int)(n > 150 ? 150 : n);
    if (blen > 0) memcpy(pdu + 52, d, blen);               /* "ciphertext" */
    return pool_xact(&g_pool[0], pdu, 52 + (blen > 4 ? blen : 4), resp, sizeof(resp));
}

/* Multichannel: SESSION_SETUP with SMB2_SESSION_FLAG_BINDING (reuses the existing
 * binding-race path) → ksmbd's channel-bind logic (the deadlock edge lives here). */
static int grain_session_bind(const uint8_t *d, size_t n) {
    (void)d; (void)n; return pfz_session_binding_race();
}

/* Lease v2 (RqLs, 52-byte lcontext with Epoch/ParentLeaseKey) → lease-v2 grant path. */
static int grain_lease_v2(const uint8_t *d, size_t n) {
    uint8_t ld[52] = {0};
    for (int i = 0; i < 16 && i < (int)n; i++) ld[i] = d[i];    /* LeaseKey */
    *(uint32_t *)(ld + 16) = (uint32_t)grain_u(d, n, 0, 4);     /* LeaseState */
    *(uint32_t *)(ld + 20) = (uint32_t)grain_u(d, n, 4, 4);     /* LeaseFlags */
    *(uint16_t *)(ld + 48) = (uint16_t)grain_u(d, n, 8, 2);     /* Epoch */
    return pool_create_with_ctx("lease2_v", "RqLs", 4, ld, 52);
}

/* Durable-v2 RECONNECT (DH2C): fuzzed FileId+CreateGuid+Flags → reconnect path. */
static int grain_dh2c(const uint8_t *d, size_t n) {
    uint8_t data[36] = {0};
    for (int i = 0; i < 32 && i < (int)n; i++) data[i] = d[i]; /* FileId + CreateGuid */
    *(uint32_t *)(data + 32) = (uint32_t)grain_u(d, n, 0, 4);  /* Flags */
    return pool_create_with_ctx("dh2c_v", "DH2C", 4, data, 36);
}

/* OPLOCK_BREAK (0x12) client acknowledgement with a fuzzed OplockLevel. */
static int grain_oplock_ack(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "opl_v")) return -1;
    uint8_t pdu[128], resp[128];
    pool_smb2_hdr(pdu, 0x0012, &g_pool[0]);
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 24;
    b[2] = (uint8_t)grain_u(d, n, 0, 1);                   /* OplockLevel (fuzzed) */
    memcpy(b + 8, g_pool[0].fid, 16);
    return pool_xact(&g_pool[0], pdu, 64 + 24, resp, sizeof(resp));
}

/* Dedicated SESSION_SETUP auth-fuzz: fuzz Flags/SecurityMode/Capabilities + the whole
 * security (SPNEGO/NTLMSSP) blob → ksmbd's auth/ASN.1 decode surface. */
static int grain_session_setup(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[512], resp[256];
    pool_smb2_hdr(pdu, 0x0001, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 24);
    *(uint16_t *)b = 25;
    b[2] = (uint8_t)grain_u(d, n, 0, 1);                   /* Flags */
    b[3] = (uint8_t)grain_u(d, n, 1, 1);                   /* SecurityMode */
    *(uint32_t *)(b + 4) = (uint32_t)grain_u(d, n, 2, 4);  /* Capabilities */
    int slen = (int)(n > 200 ? 200 : n);
    *(uint16_t *)(b + 12) = 88;                            /* SecurityBufferOffset */
    *(uint16_t *)(b + 14) = slen;                          /* SecurityBufferLength */
    if (slen > 0) memcpy(b + 24, d, slen);                /* fuzzed security blob */
    return pool_xact(&g_pool[0], pdu, 64 + 24 + slen, resp, sizeof(resp));
}

/* SMB1 per-opcode legacy grains: send a specific SMB1 command over the SMB2 session
 * (version-conflict). ksmbd only expects SMB1 NEGOTIATE — these hit legacy handling. */
static int smb1_cmd(uint8_t cmd, const uint8_t *d, int n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[256], resp[256];
    memset(pdu, 0, sizeof(pdu));
    memcpy(pdu, "\xffSMB", 4);
    pdu[4] = cmd;
    pdu[9] = 0x18; pdu[10] = 0x01; pdu[11] = 0x20;         /* Flags/Flags2 */
    int blen = n > 200 ? 200 : n;
    pdu[32] = (uint8_t)(n > 0 ? d[0] : 0);                 /* WordCount */
    if (blen > 0) memcpy(pdu + 33, d, blen);              /* params + ByteCount + data */
    return pool_xact(&g_pool[0], pdu, 33 + (blen > 0 ? blen : 0), resp, sizeof(resp));
}
static int grain_smb1_tconx(const uint8_t *d, size_t n)    { return smb1_cmd(0x75, d, (int)n); } /* SMBtconX */
static int grain_smb1_ntcreate(const uint8_t *d, size_t n) { return smb1_cmd(0xA2, d, (int)n); } /* SMBntcreateX */
static int grain_smb1_trans(const uint8_t *d, size_t n)    { return smb1_cmd(0x25, d, (int)n); } /* SMBtrans */
static int grain_smb1_open(const uint8_t *d, size_t n)     { return smb1_cmd(0x02, d, (int)n); } /* SMBopen */
static int grain_smb1_write(const uint8_t *d, size_t n)    { return smb1_cmd(0x0B, d, (int)n); } /* SMBwrite */

/* ─── More write-side depth (public storage server threatened via smbclient) ─────── */

/* SET_INFO FILE_VALID_DATA_LENGTH (39) — SetValidData: extends the "valid data"
 * length past written data, potentially exposing UNINITIALIZED on-disk bytes. A real
 * privileged/information-disclosure surface (needs SeManageVolumePrivilege on Win). */
static int grain_set_valid_data(const uint8_t *d, size_t n) {
    uint64_t vdl = grain_u(d, n, 0, 8);
    return pool_setinfo(39, &vdl, 8);
}
/* SET_INFO FILE_END_OF_FILE (20) via raw PDU with boundary sizes (distinct from the
 * libsmbclient ftruncate path in `truncate`). */
static int grain_set_eof(const uint8_t *d, size_t n) {
    uint64_t eof = grain_u(d, n, 0, 8);
    return pool_setinfo(20, &eof, 8);
}
/* SET_INFO FILE_POSITION (14) — current byte offset. */
static int grain_set_position(const uint8_t *d, size_t n) {
    uint64_t pos = grain_u(d, n, 0, 8);
    return pool_setinfo(14, &pos, 8);
}
/* SET_INFO FILE_MODE (16) — file mode flags (write-through/no-buffering/delete). */
static int grain_set_mode(const uint8_t *d, size_t n) {
    uint32_t mode = (uint32_t)grain_u(d, n, 0, 4);
    return pool_setinfo(16, &mode, 4);
}
/* SET_INFO FILE_DISPOSITION (13) — raw delete-pending flag. */
static int grain_set_disposition(const uint8_t *d, size_t n) {
    uint8_t del = n > 0 ? (d[0] & 1) : 1;
    return pool_setinfo(13, &del, 1);
}
/* SET_INFO FILE_FULL_EA (15) — a fuzzed extended-attribute entry list (the raw EA
 * parser: NextEntryOffset/Flags/EaNameLength/EaValueLength + name + value). */
static int grain_set_full_ea(const uint8_t *d, size_t n) {
    uint8_t ea[160]; memset(ea, 0, sizeof(ea));
    int namelen = 3 + (int)(n % 5);
    int vallen = (n > 16) ? (int)(n - 16 > 32 ? 32 : n - 16) : 4;
    *(uint32_t *)(ea + 0) = 0;                        /* NextEntryOffset */
    ea[4] = (uint8_t)grain_u(d, n, 0, 1);             /* Flags */
    ea[5] = (uint8_t)namelen;                         /* EaNameLength */
    *(uint16_t *)(ea + 6) = vallen;                   /* EaValueLength */
    for (int i = 0; i < namelen; i++) ea[8 + i] = 'A' + (i % 26);
    ea[8 + namelen] = 0;
    for (int i = 0; i < vallen && 8 + namelen + 1 + i < 150; i++)
        ea[8 + namelen + 1 + i] = (i < (int)n) ? d[i] : 0;
    return pool_setinfo(15, ea, 8 + namelen + 1 + vallen);
}

/* FSCTL_OFFLOAD_WRITE (0x00098268) — server-side token-based copy (write side). */
static int grain_offload_write(const uint8_t *d, size_t n) {
    return pool_ioctl(0x00098268, d, n > 64 ? 64 : (int)n, 1);
}
/* FSCTL_OFFLOAD_READ (0x00094264) — offload read token. */
static int grain_offload_read(const uint8_t *d, size_t n) {
    return pool_ioctl(0x00094264, d, n > 32 ? 32 : (int)n, 1);
}
/* FSCTL_DELETE_REPARSE_POINT (0x000900AC) — remove a reparse point (write-side). */
static int grain_del_reparse(const uint8_t *d, size_t n) {
    return pool_ioctl(0x000900AC, d, n > 24 ? 24 : (int)n, 1);
}

/* ─── Omission-audit grains (2026-07-05): handlers KSMBD has but we hadn't grained ─ */

/* SET_INFO InfoType=SECURITY (0x03): set the security descriptor / ACL via SET_INFO
 * → ksmbd smb2_set_info_sec + SD parser. The write-side ACL path (distinct from
 * create_sd's create-context path); works on [share] → addresses #42's goal. */
static int grain_set_secinfo(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "sec_v")) return -1;
    uint8_t pdu[512], resp[128];
    int dlen = n > 200 ? 200 : (int)n; if (dlen < 20) dlen = 20;
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 32);
    *(uint16_t *)b = 33;
    b[2] = 0x03;                                   /* InfoType = SECURITY */
    *(uint32_t *)(b + 4)  = dlen;                  /* BufferLength */
    *(uint16_t *)(b + 8)  = 64 + 32;              /* BufferOffset */
    *(uint32_t *)(b + 12) = (uint32_t)grain_u(d, n, 0, 4) & 0xF; /* AdditionalInformation (OWNER/GROUP/DACL/SACL) */
    memcpy(b + 16, g_pool[0].fid, 16);
    uint8_t *sd = b + 32;
    sd[0] = 1;                                     /* SD Revision */
    sd[2] = (uint8_t)grain_u(d, n, 4, 1);         /* Control lo (fuzzed) */
    sd[3] = (uint8_t)grain_u(d, n, 5, 1);         /* Control hi */
    for (int i = 8; i < dlen && i < (int)n; i++) sd[i] = d[i]; /* offsets + ACL bytes */
    return pool_xact(&g_pool[0], pdu, 64 + 32 + dlen, resp, sizeof(resp));
}

/* FSCTL_SRV_COPYCHUNK_WRITE (0x001480F2) — write variant of server-side copy. */
static int grain_copychunk_write(const uint8_t *d, size_t n) {
    uint8_t body[64]; memset(body, 0, sizeof(body));
    for (int i = 0; i < 24 && i < (int)n; i++) body[i] = d[i];       /* SourceKey */
    *(uint32_t *)(body + 24) = (uint32_t)grain_u(d, n, 0, 4) & 0xFF; /* ChunkCount */
    *(uint64_t *)(body + 32) = grain_u(d, n, 4, 8);                 /* SourceOffset */
    *(uint64_t *)(body + 40) = grain_u(d, n, 12, 8);                /* TargetOffset */
    *(uint32_t *)(body + 48) = (uint32_t)grain_u(d, n, 20, 4);      /* Length */
    return pool_ioctl(0x001480F2, body, 56, 1);
}
static int grain_resume_key(const uint8_t *d, size_t n) {    /* FSCTL_SRV_REQUEST_RESUME_KEY */
    (void)d; (void)n; return pool_ioctl(0x00140078, NULL, 0, 1);
}
static int grain_fsctl_dfs_ex(const uint8_t *d, size_t n) {  /* FSCTL_DFS_GET_REFERRALS_EX */
    return pool_ioctl(0x000601B0, d, n > 64 ? 64 : (int)n, 0);
}
static int grain_get_reparse(const uint8_t *d, size_t n) {   /* FSCTL_GET_REPARSE_POINT */
    (void)d; (void)n; return pool_ioctl(0x000900A8, NULL, 0, 1);
}
static int grain_get_compression(const uint8_t *d, size_t n) { /* FSCTL_GET_COMPRESSION */
    (void)d; (void)n; return pool_ioctl(0x0009003C, NULL, 0, 1);
}

/* SWEEP grains — the "non-implemented procedure = security hole" point: fuzz the
 * control code / info class across the FULL range → unimplemented handlers' default/
 * reject paths (unexpected-op / version-conflict robustness). */
static int grain_fsctl_sweep(const uint8_t *d, size_t n) {
    uint32_t ctl = (uint32_t)grain_u(d, n, 0, 4);           /* ANY FSCTL, incl. unimplemented */
    return pool_ioctl(ctl, (n > 4) ? d + 4 : d, n > 4 ? (int)(n - 4) : (int)n, 1);
}
static int grain_setinfo_sweep(const uint8_t *d, size_t n) {
    uint8_t cls = (uint8_t)grain_u(d, n, 0, 1);            /* ANY FILE info class, incl. unimpl. */
    return pool_setinfo(cls, (n > 1) ? d + 1 : d, n > 1 ? (int)(n - 1) : (int)n);
}

/* ─── Blind-spot grains (COVERAGE-blindspots.md): reach the un-grained subsystems ─── */

/* transport_ipc.c: fuzz the kernel↔ksmbd.mountd generic-netlink channel directly (NOT
 * SMB-reachable — the biggest blind spot). Sends a fuzzed *_RESPONSE event (what a
 * malicious/buggy mountd could send) to ksmbd's handle_generic_event. */
static int _genl_family_id(int s, const char *name)
{
    uint8_t buf[512]; memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nh);
    nh->nlmsg_type = GENL_ID_CTRL; nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq = 1; nh->nlmsg_pid = getpid();
    gh->cmd = CTRL_CMD_GETFAMILY; gh->version = 1;
    struct nlattr *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
    na->nla_type = CTRL_ATTR_FAMILY_NAME;
    int nlen = strlen(name) + 1;
    na->nla_len = NLA_HDRLEN + nlen;
    memcpy((char *)na + NLA_HDRLEN, name, nlen);
    nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN) + NLA_ALIGN(na->nla_len);
    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    if (sendto(s, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
        return -1;
    int rl = recv(s, buf, sizeof(buf), 0);
    if (rl < (int)NLMSG_HDRLEN) return -1;
    struct nlmsghdr *rh = (struct nlmsghdr *)buf;
    if (rh->nlmsg_type == NLMSG_ERROR) return -1;
    struct genlmsghdr *rg = (struct genlmsghdr *)NLMSG_DATA(rh);
    struct nlattr *a = (struct nlattr *)((char *)rg + GENL_HDRLEN);
    int alen = rh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    while (alen >= (int)NLA_HDRLEN) {
        if (a->nla_type == CTRL_ATTR_FAMILY_ID)
            return *(uint16_t *)((char *)a + NLA_HDRLEN);
        int l = NLA_ALIGN(a->nla_len);
        if (l <= 0) break;
        alen -= l; a = (struct nlattr *)((char *)a + l);
    }
    return -1;
}
static int grain_ipc(const uint8_t *d, size_t n) {
    int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (s < 0) return -1;
    /* Bound the netlink recv() (_genl_family_id + the response read below): a
     * kernel that never replies would otherwise block this grain forever. */
    struct timeval _nltv = { .tv_sec = 2 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &_nltv, sizeof(_nltv));
    int fid = _genl_family_id(s, "SMBD_GENL");
    if (fid <= 0) { close(s); return -1; }
    uint8_t buf[1024]; memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct genlmsghdr *gh = (struct genlmsghdr *)NLMSG_DATA(nh);
    nh->nlmsg_type = fid; nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq = 1; nh->nlmsg_pid = getpid();
    static const uint8_t resp_ev[] = {5, 7, 9, 13, 15, 17};   /* *_RESPONSE events */
    gh->cmd = (n > 0) ? resp_ev[d[0] % 6] : 5; gh->version = 1;
    struct nlattr *na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
    na->nla_type = gh->cmd;
    int pl = (n > 1) ? (int)(n - 1 > 200 ? 200 : n - 1) : 0;
    na->nla_len = NLA_HDRLEN + pl;
    if (pl > 0) memcpy((char *)na + NLA_HDRLEN, d + 1, pl);
    nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN) + NLA_ALIGN(na->nla_len);
    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    int r = sendto(s, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(s);
    return r;
}

/* smbacl.c: a STRUCTURALLY-VALID security descriptor with a fuzzed multi-ACE DACL
 * (2-4 ACEs, fuzzed type/flags/mask + 1-4 subauthority SIDs) → drives parse_dacl /
 * sid_to_id deep, past what create_sd's small blob reaches. Via SET_INFO SECURITY. */
static int grain_dacl_deep(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "dacl_v")) return -1;
    uint8_t sd[400]; memset(sd, 0, sizeof(sd));
    sd[0] = 1;                                   /* SD Revision */
    *(uint16_t *)(sd + 2) = 0x8004;              /* SE_DACL_PRESENT | SE_SELF_RELATIVE */
    *(uint32_t *)(sd + 16) = 20;                 /* OffsetDacl */
    uint8_t *acl = sd + 20;
    acl[0] = 2;                                  /* AclRevision */
    int nace = 2 + (n ? d[0] % 3 : 0);           /* 2-4 ACEs */
    *(uint16_t *)(acl + 4) = nace;               /* AceCount */
    int off = 8, p = 1;
    for (int i = 0; i < nace && off < 360; i++) {
        uint8_t *ace = acl + off;
        ace[0] = (uint8_t)grain_u(d, n, p, 1) & 0x0f;         /* AceType */
        ace[1] = (uint8_t)grain_u(d, n, p + 1, 1);           /* AceFlags */
        *(uint32_t *)(ace + 4) = (uint32_t)grain_u(d, n, p + 2, 4); /* Access mask */
        uint8_t *sid = ace + 8;
        sid[0] = 1;                                          /* SID Revision */
        int sub = 1 + (int)(grain_u(d, n, p + 6, 1) & 3);    /* 1-4 subauthorities */
        sid[1] = (uint8_t)sub;
        sid[7] = 5;                                          /* NT authority */
        for (int j = 0; j < sub; j++)
            *(uint32_t *)(sid + 8 + j * 4) = (uint32_t)grain_u(d, n, p + 7 + j * 4, 4);
        int acelen = 8 + 8 + sub * 4;
        *(uint16_t *)(ace + 2) = acelen;                     /* AceSize */
        off += acelen; p += 12;
    }
    *(uint16_t *)(acl + 2) = off;                /* AclSize */
    int sdlen = 20 + off;
    uint8_t pdu[512], resp[128];
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64; memset(b, 0, 32);
    *(uint16_t *)b = 33; b[2] = 0x03;            /* InfoType = SECURITY */
    *(uint32_t *)(b + 4) = sdlen;
    *(uint16_t *)(b + 8) = 64 + 32;
    *(uint32_t *)(b + 12) = 0x04;                /* DACL_SECURITY_INFORMATION */
    memcpy(b + 16, g_pool[0].fid, 16);
    memcpy(b + 32, sd, sdlen);
    return pool_xact(&g_pool[0], pdu, 64 + 32 + sdlen, resp, sizeof(resp));
}

/* crypto_ctx.c: send a SIGNED SMB2 request with a fuzzed 16-byte signature → ksmbd
 * computes the expected signature (HMAC-SHA256 / AES-CMAC engine) and compares.
 * Needs `server signing` enabled in the config (set to `auto`). */
static int grain_sign(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[128], resp[256];
    pool_smb2_hdr(pdu, 0x000E, &g_pool[0]);      /* QUERY_DIRECTORY */
    *(uint32_t *)(pdu + 16) |= 0x00000008u;      /* SMB2_FLAGS_SIGNED */
    for (int i = 0; i < 16 && i < (int)n; i++) pdu[48 + i] = d[i]; /* fuzzed Signature */
    uint8_t *b = pdu + 64;
    *(uint16_t *)b = 33;                          /* minimal QUERY_DIRECTORY body */
    return pool_xact(&g_pool[0], pdu, 64 + 33, resp, sizeof(resp));
}

/* ndr.c: DCE/RPC over the IPC$ \srvsvc pipe with a FUZZED opnum + stub → ksmbd's RPC
 * decoder / per-opnum dispatch (srvsvc/wkssvc/samr). Reuses pfz_ndr_fuzz's pipe path. */
static int grain_rpc_opnum(const uint8_t *d, size_t n) {
    uint8_t rpc[256]; memset(rpc, 0, sizeof(rpc));
    int stub = (int)(n > 150 ? 150 : n);
    rpc[0] = 5; rpc[1] = 0; rpc[2] = 0; rpc[3] = 0x03;     /* v5.0 REQUEST first+last frag */
    rpc[4] = 0x10;                                          /* drep: little-endian */
    *(uint16_t *)(rpc + 8) = (uint16_t)(24 + stub);        /* frag_length */
    *(uint32_t *)(rpc + 12) = (uint32_t)grain_u(d, n, 0, 4); /* call_id */
    *(uint32_t *)(rpc + 16) = stub;                        /* alloc_hint */
    *(uint16_t *)(rpc + 20) = 0;                           /* context_id */
    *(uint16_t *)(rpc + 22) = (uint16_t)grain_u(d, n, 4, 2); /* opnum (fuzzed) */
    if (stub > 0) memcpy(rpc + 24, d, stub);              /* stub data */
    return pfz_ndr_fuzz(rpc, 24 + stub);
}

/* ─── SMB3-standard procedures missing from GRAIN.md (incl. ones ksmbd may reject) ─ */

/* SMB2 COMPRESSION_TRANSFORM (0xFC'SMB', MS-SMB2 3.1.5.3 chained-message decompress) —
 * fuzz OriginalSize/Algorithm/Flags/Offset + compressed payload. A distinct standard
 * procedure (like the 0xFD encrypt transform); the decompress path is a known bug area
 * (decompression bombs, offset/length overflow). ksmbd added compression-transform
 * helpers; unsupported → protocol-detect reject (still exercises the dispatch). */
static int grain_compress_transform(const uint8_t *d, size_t n) {
    if (g_pool_n < 1) return -1;
    uint8_t pdu[256], resp[256];
    memset(pdu, 0, sizeof(pdu));
    *(uint32_t *)pdu       = 0x424d53fc;                   /* 0xFC'SMB' compression id */
    *(uint32_t *)(pdu + 4) = (uint32_t)grain_u(d, n, 0, 4);/* OriginalCompressedSegmentSize (bomb) */
    *(uint16_t *)(pdu + 8) = (uint16_t)grain_u(d, n, 4, 2);/* CompressionAlgorithm */
    *(uint16_t *)(pdu + 10)= (uint16_t)grain_u(d, n, 6, 2);/* Flags (chained) */
    *(uint32_t *)(pdu + 12)= (uint32_t)grain_u(d, n, 8, 4);/* Offset/Length (fuzzed) */
    int blen = (int)(n > 150 ? 150 : n);
    if (blen > 0) memcpy(pdu + 16, d, blen);              /* compressed payload */
    return pool_xact(&g_pool[0], pdu, 16 + (blen > 4 ? blen : 4), resp, sizeof(resp));
}

static int grain_shadow_copy(const uint8_t *d, size_t n) {   /* FSCTL_SRV_ENUMERATE_SNAPSHOTS (VSS) */
    (void)d; (void)n; return pool_ioctl(0x00144064, NULL, 0, 1);
}
static int grain_set_integrity(const uint8_t *d, size_t n) { /* FSCTL_SET_INTEGRITY_INFORMATION */
    return pool_ioctl(0x0009C280, d, n > 16 ? 16 : (int)n, 1);
}
static int grain_pipe_wait(const uint8_t *d, size_t n) {     /* FSCTL_PIPE_WAIT */
    return pool_ioctl(0x00110018, d, n > 64 ? 64 : (int)n, 0);
}
static int grain_resiliency(const uint8_t *d, size_t n) {    /* FSCTL_LMR_REQUEST_RESILIENCY */
    uint8_t body[8] = {0};
    *(uint32_t *)body = (uint32_t)grain_u(d, n, 0, 4);       /* Timeout (fuzzed) */
    return pool_ioctl(0x001401D4, body, 8, 1);
}

/* SET_INFO InfoType=QUOTA (0x04): set user quota with fuzzed FILE_QUOTA_INFORMATION →
 * ksmbd quota handling (Samba set_user_quota; ksmbd may reject → dispatch path). */
static int grain_set_quota(const uint8_t *d, size_t n) {
    if (g_pool_n < 1 || !pool_ensure_fid(&g_pool[0], "quota_v")) return -1;
    uint8_t pdu[512], resp[128];
    int dlen = n > 200 ? 200 : (int)n; if (dlen < 32) dlen = 32;
    pool_smb2_hdr(pdu, 0x0011, &g_pool[0]);
    uint8_t *b = pdu + 64;
    memset(b, 0, 32);
    *(uint16_t *)b = 33;
    b[2] = 0x04;                                    /* InfoType = QUOTA */
    *(uint32_t *)(b + 4) = dlen;                    /* BufferLength */
    *(uint16_t *)(b + 8) = 64 + 32;                /* BufferOffset */
    memcpy(b + 16, g_pool[0].fid, 16);
    for (int i = 0; i < dlen && i < (int)n; i++) b[32 + i] = d[i]; /* fuzzed quota info */
    return pool_xact(&g_pool[0], pdu, 64 + 32 + dlen, resp, sizeof(resp));
}

static const struct { const char *name; int (*fn)(const uint8_t *, size_t); } GRAINS[] = {
    { "write",     grain_write     },
    { "truncate",  grain_truncate  },
    { "setxattr",  grain_setxattr  },
    { "copychunk", grain_copychunk },
    { "query_dir", grain_query_dir },
    { "compress",  grain_compress  },
    { "reparse",   grain_reparse   },
    { "unicode",   grain_unicode   },
    { "ndr",       grain_ndr       },
    { "negotiate", grain_negotiate },
    { "lease",     grain_lease     },
    { "durable",   grain_durable   },
    { "race",      grain_race      },
    { "sequence",  grain_sequence  },
    { "compound",  grain_compound  },
    { "pipe",      grain_pipe      },
    { "rdma",      grain_rdma      },
    { "write_ext", grain_write_ext },
    { "setattr",   grain_setattr   },
    { "rename",    grain_rename    },
    /* { "secdesc", grain_secdesc } — the ACL/security-descriptor write path lives
     * only on [aclshare] (acl_xattr), which is currently NOT cleanly reachable
     * (CIFS BAD_NETWORK_NAME + SMB2 signature errors on 2nd-share access via
     * libsmbclient). Re-enable once aclshare is fixed / raw SET_INFO
     * FileSecurityInformation is wired. grain_secdesc()+pfz_set_secdesc() kept. */
    { "dosattr",   grain_dosattr   },
    { "unlink",    grain_unlink    },
    { "mkrmdir",   grain_mkrmdir   },
    { "rmxattr",   grain_rmxattr   },
    /* GRAIN.md gap grains — raw SMB2 procedures + legacy SMB1 conflict */
    { "read",      grain_read      },
    { "lock",      grain_lock      },
    { "flush",     grain_flush     },
    { "echo",      grain_echo      },
    { "cancel",    grain_cancel    },
    { "query_info", grain_query_info },
    { "notify",    grain_notify    },
    { "tdis",      grain_tdis      },
    { "close",     grain_close     },
    { "logoff",    grain_logoff    },
    { "get_quota", grain_get_quota },
    { "fsctl_zero", grain_fsctl_zero },
    { "fsctl_dupext", grain_fsctl_dupext },
    { "set_alloc", grain_set_alloc },
    { "hardlink",  grain_hardlink  },
    { "smb1",      grain_smb1      },
    /* CREATE contexts (§4) */
    { "create_ea",    grain_create_ea    },
    { "create_sd",    grain_create_sd    },
    { "create_mxac",  grain_create_mxac  },
    { "create_alsi",  grain_create_alsi  },
    { "create_qfid",  grain_create_qfid  },
    { "create_posix", grain_create_posix },
    /* Remaining FSCTLs (§2) */
    { "fsctl_sparse", grain_fsctl_sparse },
    { "fsctl_qar",    grain_fsctl_qar    },
    { "fsctl_setcomp", grain_fsctl_setcomp },
    { "fsctl_objid",  grain_fsctl_objid  },
    { "fsctl_valneg", grain_fsctl_valneg },
    { "fsctl_dfs",    grain_fsctl_dfs    },
    { "fsctl_netif",  grain_fsctl_netif  },
    { "tcon",         grain_tcon         },
    { "create_aapl",  grain_create_aapl  },
    { "create_appinst", grain_create_appinst },
    { "create_dh2",   grain_create_dh2   },
    /* write-side focus (storage-server / OneDrive-like) */
    { "stream_write", grain_stream_write },
    { "write_flags",  grain_write_flags  },
    { "append",       grain_append       },
    /* §8 remainder: SMB3 features + legacy per-opcode */
    { "encrypt",      grain_encrypt      },
    { "session_bind", grain_session_bind },
    { "lease_v2",     grain_lease_v2     },
    { "dh2c",         grain_dh2c         },
    { "oplock_ack",   grain_oplock_ack   },
    { "session_setup", grain_session_setup },
    { "smb1_tconx",   grain_smb1_tconx   },
    { "smb1_ntcreate", grain_smb1_ntcreate },
    { "smb1_trans",   grain_smb1_trans   },
    { "smb1_open",    grain_smb1_open    },
    { "smb1_write",   grain_smb1_write   },
    /* more write-side depth (storage-server threat model) */
    { "set_valid_data", grain_set_valid_data },
    { "set_eof",      grain_set_eof      },
    { "set_position", grain_set_position },
    { "set_mode",     grain_set_mode     },
    { "set_disposition", grain_set_disposition },
    { "set_full_ea",  grain_set_full_ea  },
    { "offload_write", grain_offload_write },
    { "offload_read", grain_offload_read },
    { "del_reparse",  grain_del_reparse  },
    /* omission audit: handlers ksmbd has but we hadn't grained + full-range sweeps */
    { "set_secinfo",  grain_set_secinfo  },
    { "copychunk_write", grain_copychunk_write },
    { "resume_key",   grain_resume_key   },
    { "fsctl_dfs_ex", grain_fsctl_dfs_ex },
    { "get_reparse",  grain_get_reparse  },
    { "get_compression", grain_get_compression },
    { "fsctl_sweep",  grain_fsctl_sweep  },
    { "setinfo_sweep", grain_setinfo_sweep },
    /* SMB3-standard procedures (incl. ones ksmbd may reject) */
    { "compress_transform", grain_compress_transform },
    { "shadow_copy",  grain_shadow_copy  },
    { "set_integrity", grain_set_integrity },
    { "pipe_wait",    grain_pipe_wait    },
    { "resiliency",   grain_resiliency   },
    { "set_quota",    grain_set_quota    },
    /* blind-spot grains (COVERAGE-blindspots.md) */
    { "ipc",          grain_ipc          },
    { "dacl_deep",    grain_dacl_deep    },
    { "sign",         grain_sign         },
    { "rpc_opnum",    grain_rpc_opnum    },
};
#define N_GRAINS ((int)(sizeof(GRAINS) / sizeof(GRAINS[0])))

/* P1: how many normal-scenario grains exist. */
int pfz_grain_count(void) { return N_GRAINS; }
/* P1: the name of grain i (for naming generated LibFuzzer grains / corpus). */
const char *pfz_grain_name(int i) {
    return (i >= 0 && i < N_GRAINS) ? GRAINS[i].name : "";
}
/* P2: run grain i with the fuzzer input; df_buf is reset so the caller reads this
 * grain's coverage/records via get_features/get_records right after. Returns the
 * grain body's status. */
int pfz_grain_run(int i, const void *data, int len) {
    if (i < 0 || i >= N_GRAINS) return -1;
    /* Deep-by-construction prerequisite (#2): several grains — copychunk, lease,
     * compound, sequence, validate_negotiate, unknown_pipe — operate on the AUTHED
     * multi-connection pool (g_pool) and early-return -1 when it is absent. That is
     * why they stayed shallow (ft<100): they never reached their real code, they
     * bailed at the g_pool_n guard. Lazily establish a 2-connection authed pool,
     * each with an open fid (pfz_pool_init_authed → pool_create_file), so those
     * grains reach deep VFS/IOCTL code like the write/truncate grains do. It runs
     * ONCE (pfz_reset only clears the coverage counter, so g_pool persists across
     * iterations → two handshakes per grain, not per input) and BEFORE pfz_reset
     * so the setup traffic's coverage is cleared and only the grain's own coverage
     * is measured. */
    if (g_pool_n < 2) pfz_pool_init_authed(2);
    pfz_reset();
    return GRAINS[i].fn((const uint8_t *)data, (size_t)len);
}
/* P3 combination: run grains A and B on a SHARED object/handle.
 *
 * The old combo2 ran A then B back-to-back, but every pool grain drives the same
 * hardcoded connection g_pool[0], and a grain that CREATEs its own file leaves A
 * and B on unrelated objects — so no real interaction was exercised. These modes
 * force A and B onto ONE shared object so the interesting bug class can arise:
 * B abusing state A established (a lease A holds, a byte-range lock A took, a
 * handle A left half-torn-down, a size/attr A changed). The mode is picked from
 * the first input byte so the fuzzer explores all three:
 *   0 SHARED      A then B on the SAME connection + handle (B inherits A's state)
 *   1 INTERLEAVE  A,B,A,B on the shared handle (repeatedly toggle the two ops)
 *   2 RACE        A (conn0) || B (conn1, forked) on the SAME path, concurrently
 *
 * combo_open_shared() pins conn0 (and, for RACE, conn1) to one path "combo_obj"
 * so pool grains that reuse the open fid (pool_ensure_fid short-circuits on
 * has_fid) act on that single object. RACE uses fork() rather than threads: the
 * child copies g_pool[0]=g_pool[1] so B's hardcoded conn-0 refs hit conn 1's
 * SEPARATE socket (no on-wire byte interleaving, no libsmbclient thread-unsafety),
 * while the parent runs A on conn 0 — genuine concurrent contention on one file. */
static int g_combo_obj_open = 0;
static void combo_open_shared(int two)
{
    if (g_pool_n < 1) return;
    if (!g_combo_obj_open) {
        pool_create_file(&g_pool[0], "combo_obj");              /* conn0 → combo_obj */
        if (two && g_pool_n >= 2)
            pool_create_file(&g_pool[1], "combo_obj");          /* conn1 → SAME path */
        g_combo_obj_open = 1;
    }
    /* self-heal: a prior grain may have replaced/lost the fid */
    if (!g_pool[0].has_fid) pool_ensure_fid(&g_pool[0], "combo_obj");
    if (two && g_pool_n >= 2 && !g_pool[1].has_fid)
        pool_ensure_fid(&g_pool[1], "combo_obj");
}

int pfz_grain_combo2(int a, int b, const void *data, int len) {
    if (a < 0 || a >= N_GRAINS || b < 0 || b >= N_GRAINS) return -1;
    const uint8_t *d = (const uint8_t *)data;
    size_t n = (size_t)len;
    /* First byte selects the interaction mode; the rest is split A|B. */
    int mode = (n >= 1) ? (d[0] % 3) : 0;
    if (n) { d++; n--; }
    size_t half = n / 2;
    const uint8_t *da = d, *db = d + half;
    size_t la = half, lb = n - half;

    if (mode == 2 && g_pool_n >= 2) {
        /* RACE: A on conn0, B on conn1, concurrently, on the SAME object. */
        combo_open_shared(1);
        pfz_reset();
        pid_t pid = fork();
        if (pid == 0) {
            /* child: redirect B's conn-0 refs onto conn 1's own socket, run B,
             * then hard-exit (skip libFuzzer/sanitizer teardown). Bound a hung
             * blocking read with a self-kill alarm so the parent's waitpid can't
             * stall the fuzz iteration; reset SIGALRM to default first so any
             * libFuzzer per-input timeout handler we inherited can't fire here. */
            signal(SIGALRM, SIG_DFL);
            alarm(5);
            g_pool[0] = g_pool[1];
            GRAINS[b].fn(db, lb);
            _exit(0);
        }
        int ra = GRAINS[a].fn(da, la);          /* parent: A on conn0, concurrent */
        if (pid > 0) {
            int st; waitpid(pid, &st, 0);
            /* keep conn1's message-ids monotonic across successive children */
            g_pool[1].mid += 4096;
        } else {
            /* fork failed → degrade to sequential shared */
            GRAINS[b].fn(db, lb);
        }
        return ra;
    }

    combo_open_shared(0);
    pfz_reset();
    if (mode == 1) {
        /* INTERLEAVE: toggle A/B twice on the shared handle. */
        int r = 0;
        r |= GRAINS[a].fn(da, la);
        r |= GRAINS[b].fn(db, lb);
        r |= GRAINS[a].fn(da, la);
        r |= GRAINS[b].fn(db, lb);
        return r ? -1 : 0;
    }
    /* SHARED (default): A then B on one handle, no reset between → B sees A's state. */
    int ra = GRAINS[a].fn(da, la);
    int rb = GRAINS[b].fn(db, lb);
    return (ra == 0 && rb == 0) ? 0 : -1;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Address → Source Line Resolution (libdw/elfutils, in-process)
 * Used to decode failslab-exclusive features back to source lines.
 * ======================================================================= */



