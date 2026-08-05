/*
 * grain_common.h — Shared authenticated SMB2 socket + kcov_df feedback.
 * Provides NTLMv2 auth with fuzz:fuzz credentials + reconnect + connection pooling.
 */
#ifndef GRAIN_COMMON_H
#define GRAIN_COMMON_H

/* This component's 24-bit log color (#c4ffcb); libksmbdzzer.h's pfz_err() honors
 * PFZ_LOG_COLOR when set before the include. Raw common.h grains log in green;
 * lib-only grains fall back to libksmbdzzer.h's default. */
#define PFZ_LOG_COLOR "\033[38;2;196;255;203m"   /* #c4ffcb — grain/common.h */
/* libksmbdzzer.h is copied alongside this header into GRAIN_DIR by gen.py's
 * _compile(), so include it by bare name (not ../) — otherwise every grain
 * fails to compile and the libFuzzer phase silently produces nothing. */
#include "libksmbdzzer.h"

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/*
 * kcov-dataflow ioctls — MUST match kernel/kcov_dataflow.c exactly.  Use the
 * _IO* macros (not hardcoded hex) so they can never drift from the kernel again:
 *   KCOV_DF_INIT_TRACK   _IOR('d', 1,   unsigned long)  == 0x80086401
 *   KCOV_DF_REMOTE_ENABLE _IOW('d', 102, unsigned long) == 0x40086466
 * The old hardcoded KCOV_DF_REMOTE_ENABLE (0x00006466) dropped the _IOW
 * direction+size bits, so ioctl() never matched the kernel case: the remote
 * handle was NEVER registered, the kernel routed NO dataflow records to the raw
 * grains, and df_buf stayed empty (KERNEL_PCS always 0).  This is why the whole
 * raw-grain fleet ran on libFuzzer harness self-coverage only.
 */
#ifndef KCOV_DF_INIT
#define KCOV_DF_INIT _IOR('d', 1, unsigned long)
#endif
#ifndef KCOV_DF_REMOTE_ENABLE
#define KCOV_DF_REMOTE_ENABLE _IOW('d', 102, unsigned long)
#endif
#ifndef BUF_WORDS
#define BUF_WORDS (1<<18)   /* headroom for high-volume trace_cmp records (assumed on) */
#endif

__attribute__((section("__libfuzzer_extra_counters")))
static uint8_t ctr[4096];

static int df_fd;
static volatile uint64_t *df_buf;
static int raw_sock = -1;
static uint64_t sid = 0, mid = 0;
static uint32_t tid = 0;
static uint8_t file_id[16];
static int has_file = 0;

/*
 * Snapshot THIS iteration's kernel kcov-dataflow coverage into the libFuzzer
 * extra-counter table `ctr[]`. Must be the LAST thing to touch ctr before
 * LLVMFuzzerTestOneInput returns — libFuzzer reads ctr afterwards and uses it
 * as the coverage signal driving mutation. We clear ctr here (not at end) so
 * the kernel (pc,val) records survive into libFuzzer's read; zeroing ctr after
 * fb() (the old bug) made libFuzzer blind to kernel coverage.
 */
/* Value-blind ablation switch (differential value-proof, fix #5). Default 0 =
 * dataflow mode: fold the kernel-observed argument/return VALUE into the coverage
 * hash, so libFuzzer sees "same PC, different value" as new coverage. GRAIN_BLIND=1
 * = path-only control: hash the PC alone (what a syzkaller-style edge fuzzer sees),
 * so value-gated branches get no extra signal. Running the same harness both ways
 * and diffing reached coverage proves how much the kcov-dataflow values add. */
/* Distinct kernel PCs reached across the whole run (the real dataflow-vs-blind
 * metric for #5 — libFuzzer's own ft conflates harness edges with the value
 * buckets). Each kcov-dataflow record's pc is hashed into this bitmap; the count
 * of set bits is printed at exit and parsed by run_diff_proof. */
#define PC_BITS (1u<<17)
static uint8_t pc_bitmap[PC_BITS/8];
static inline void pc_mark(uint64_t pc) {
    uint64_t h = pc * 0x9E3779B97F4A7C15ULL;
    uint32_t i = (uint32_t)(h >> 47) & (PC_BITS - 1);
    pc_bitmap[i >> 3] |= (uint8_t)(1u << (i & 7));
}
static unsigned pc_count(void) {
    unsigned c = 0;
    for (unsigned i = 0; i < sizeof(pc_bitmap); i++) c += __builtin_popcount(pc_bitmap[i]);
    return c;
}

/* ─── Reverse-flow RedQueen dictionary: kernel RETURN values → future tokens ────
 * The FORWARD half of RedQueen (mutate_i2s pass 2) drives INPUT bytes to the kernel
 * ARGUMENT values kcov-dataflow observed. The REVERSE half is the other direction: a
 * value the kernel COMPUTED and RETURNED (a file handle, an allocated size, an
 * NTSTATUS, a magic constant) is exactly what a LATER request will be checked
 * against — so we keep every plausible 0xF return value in a persistent, deduped
 * dictionary and let mutate_i2s splice it into subsequent inputs. This completes the
 * bi-directional loop for the whole grain FLEET, not just the Python arbiter's
 * prober. Unlike mutate_i2s's local pass-1 rets[] (this-exec-only), g_retdict PERSISTS
 * across iterations: a handle returned at iteration N is still a candidate token at
 * N+k — the actual cross-iteration RedQueen behaviour. Harvested every exec inside
 * fb() (no extra pass); consumed by mutate_i2s; the splice count is printed at exit
 * (RET_TOKEN_HITS) so the reverse flow is MEASURABLE and the claim is provable. */
#define RETDICT_N 512
static uint64_t g_retdict[RETDICT_N];      /* ring of newest unique kernel returns */
static uint32_t g_retdict_n;               /* total unique returns ever harvested */
static uint8_t  g_retdict_seen[8192];      /* 16-bit dedup bitmap over harvested returns */
static unsigned long g_ret_hits;           /* # inputs where a return token was spliced */
static unsigned long g_cmp_hits;           /* # inputs where a trace_cmp operand was spliced */
static inline void ret_dict_add(uint64_t v) {
    if (v <= 1 || v >= 0xffff000000000000ULL) return;   /* skip trivial + kernel ptrs */
    uint32_t idx = (uint32_t)((v * 0x9E3779B97F4A7C15ULL) >> 48);
    if (g_retdict_seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) return;   /* already have it */
    g_retdict_seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
    g_retdict[g_retdict_n % RETDICT_N] = v;             /* ring: keep the newest RETDICT_N */
    if (g_retdict_n < 0xffffffffu) g_retdict_n++;
}

/* ─── Engine-comparison switch (engine_compare_campaign.sh) ────────────────────
 * KSMBDZZER_ENGINE selects the coverage signal + mutator so the SAME grains, on
 * the SAME kernel, run as distinct fuzzing engines that can be diffed head-to-head.
 * A CONTROLLED ablation (identical instrumentation), so the only variables are
 * (a) value-sensitive vs pc-only coverage, and (b) i2s vs pure havoc mutation:
 *   dataflow (default): value-folded (pc,val) coverage + i2s  [1st engine]
 *   pc-i2s            : pc-only coverage           + i2s       [2nd engine — i2s]
 *   pc-havoc          : pc-only coverage           + havoc     [2nd engine — havoc]
 * (pc-only = hash the reached PCs only, exactly what an edge/pc fuzzer sees.) */
static int g_eng_blind = -1;   /* 1 = pc-only (drop the value region) */
static int g_eng_i2s   = -1;   /* 1 = i2s-directed mutation, 0 = pure havoc */
static int g_eng_vec   =  0;   /* 1 = dataflow-vec: value-class-normalize each folded field */
static int g_eng_rel   =  0;   /* 1 = dataflow-rel: dataflow-vec + within-record pairwise cmp3 */
static void grain_engine(void) {
    if (g_eng_blind >= 0) return;
    const char *e = getenv("KSMBDZZER_ENGINE"); if (!e || !e[0]) e = "dataflow";
    if      (!__builtin_strcmp(e, "pc-havoc")) { g_eng_blind = 1; g_eng_i2s = 0; }
    else if (!__builtin_strcmp(e, "pc-i2s"))   { g_eng_blind = 1; g_eng_i2s = 1; }
    else                                        { g_eng_blind = 0; g_eng_i2s = 1; }
    g_eng_rel = (!__builtin_strcmp(e, "dataflow-rel")) ? 1 : 0;
    g_eng_vec = (!__builtin_strcmp(e, "dataflow-vec") || g_eng_rel) ? 1 : 0;
}

/* Value-class normalize a folded field (dataflow-vec): collapse kernel POINTERS to a
 * small class token (NULL-ness + a few align bits) and quantize scalars to a log2
 * magnitude bucket, so pointer args stop minting per-address noise features and adjacent
 * lengths share a bucket. Parity with libksmbdzzer.c:pfz_valclass. */
static inline uint64_t valclass(uint64_t v) {
    if (v == 0) return 0;
    if (v >= 0xffff000000000000ULL) return 0x1000ULL | (v & 0x38ULL);   /* kernel pointer */
    if (v >  0x00007fffffffffffULL) return 0x2000ULL;                   /* other high/non-canonical */
    return (uint64_t)(63u - __builtin_clzll(v));                        /* scalar → magnitude bucket */
}

static void grain_atexit(void);   /* clean teardown (#1) + PC report (#5) */
static void grain_emit_metrics(void);   /* KERNEL_PCS/RET_TOKEN_HITS/CMP_I2S_HITS — periodic + atexit */

/* Coverage mode for the libFuzzer feedback counter ctr[]. ctr[] is split into a
 * PATH region and a bounded VALUE region (fixes #1/#5/#6 together):
 *   PATH region ctr[0..PATH_N-1] — fold only the kernel PC. Value-independent, so
 *     bounded by the reachable PC set: libFuzzer's ft PLATEAUS once no new path is
 *     found (grains actually SATURATE and free the time budget, #1) and libFuzzer
 *     keeps a corpus input only on a NEW path, bounding the persistent corpus (#5).
 *   VALUE region ctr[PATH_N..4095] — bumped ONLY the FIRST time a given (pc^val)
 *     pair is ever seen (persistent val_seen dedup). This restores kcov-dataflow
 *     value sensitivity — an input that drives a kernel argument/return to a NEW
 *     value is rewarded and kept (RedQueen-style) — WITHOUT the old unbounded
 *     blowup: repeated same-value inputs mint no feature, so the value contribution
 *     is capped by the reachable (pc,val) set and the whole counter still saturates (#6).
 *   GRAIN_DATAFLOW=1 — legacy UNBOUNDED value-fold, kept as an opt-in for the
 *     differential value-proof; it does NOT saturate by design. */
#define CTR_N  4096
#define PATH_N_DEFAULT 3584                  /* ctr[0..3583]   = path bulk (default) */
static int path_n = PATH_N_DEFAULT;          /* runtime split point, GRAIN_PATH_N   */
static int val_n  = CTR_N - PATH_N_DEFAULT;  /* ctr[path_n..4095] = value buckets      */
static uint8_t val_seen[8192];               /* 65536-bit first-seen (pc^val) dedup, persistent */
static int cov_mode = -1;                    /* 0 = path+bounded-value (default), 1 = unbounded value-fold */

/* DONE: the arbiter-feedback connector is implemented below — `struct feedback`
 * + `load_feedback()` (packed-struct read, cf. the layout-sync note) and
 * `mutate_i2s()` which reads only memory (g_fb + df_buf) per-exec. The Python
 * arbiter (ksmbdzzer.py Arbiter._distill) writes FUZZDB/fb.bin; grains load it at
 * LLVMFuzzerInitialize via $GRAIN_FB. g_fb = distilled cross-round; df_buf = live. */
/* ── Coverage backend ─────────────────────────────────────────────────
 * dataflow (value-sensitive kcov_dataflow) vs kcov (stock trace-pc). The backend is
 * chosen ONCE in df_init() from KSMBDZZER_KCOV, so the hot path (fb()) just calls
 * cov->fold() — no per-record branch on the coverage source. Add a source by adding
 * one struct cov_ops, not by sprinkling if()s through the fold. */
static int kcov_fd = -1;
static volatile unsigned long *kcov_cover;

/* dataflow fold: rich (pc,val) records → ctr[] (path bulk + first-seen value buckets,
 * plus dataflow-vec/-rel) — the historical fb() body, moved verbatim. */
static void df_fold(void) {
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        pc_mark(pc);
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        if (pos + 3 + nf > 1 + n) break;                       /* truncated tail record: stop */
        if (rt == 0xF) ret_dict_add(val);                      /* reverse-flow: persist kernel return */
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (cov_mode) {                                        /* legacy unbounded value-fold (opt-in) */
            if (rt == 0xC) ctr[(h>>12)%CTR_N]++;               /* cmp: path only (no value explosion) */
            else if (rt == 0xF && val == 0) ctr[(h>>12)%CTR_N] += 3;
            else { h ^= val; ctr[h % CTR_N]++; }
        } else {
            ctr[(h>>12) % path_n]++;                           /* PATH bulk — saturates (#1/#5) */
            /* Upgrade 1: fold EVERY decomposed struct field (kcov-dataflow writes up
             * to nf fields per pointer arg via the trace-args offsets[] array), not
             * just field 0. A never-before-seen value in ANY field of a struct arg
             * (e.g. a length/flags member several fields deep) now rewards libFuzzer.
             * Skip null and the KCOV_DF_MAGIC_BAD (0xBADADD85) failed-read sentinel so
             * unread fields don't spam the value region. Field index k is mixed into
             * the hash so the same value in different slots stays distinguishable.
             * CMP (0xC) records are EXCLUDED: their operands are input-derived and
             * vary wildly, so folding them saturates the value region; the PATH bulk
             * above already credits reaching the comparison, and the operand PAIR is
             * consumed by mutate_i2s (RedQueen i2s) rather than as coverage.
             * g_eng_blind (KSMBDZZER_ENGINE=pc-*) drops the value region entirely —
             * pc-only coverage, what an edge fuzzer sees. */
            if (!g_eng_blind && rt != 0xC)
            for (uint32_t k = 0; k < nf; k++) {
                uint64_t fv = df_buf[pos + 3 + k];
                if (fv == 0 || fv == 0xBADADD85ULL) continue;
                /* dataflow-vec: fold the value CLASS, not the raw value — kills pointer
                 * address noise + adjacent-scalar feature spray. Baseline folds fv raw. */
                uint64_t cv = g_eng_vec ? valclass(fv) : fv;
                uint64_t vh = ((pc ^ cv) + (uint64_t)k * 0x9E3779B9ULL)
                              * 0x9E3779B97F4A7C15ULL;          /* bounded first-seen (#6) */
                uint32_t vb = (uint32_t)(vh >> 48);             /* 16-bit dedup index */
                if (!(val_seen[vb >> 3] & (uint8_t)(1u << (vb & 7)))) {
                    val_seen[vb >> 3] |= (uint8_t)(1u << (vb & 7));
                    ctr[path_n + (vb % val_n)]++;               /* reward: never-before-seen (pc,field) */
                }
            }
            /* dataflow-rel: within-record pairwise cmp3 (<,==,>) on RAW fields — splits the
             * OOB gate (offset vs length at the same magnitude) that value buckets collapse.
             * Skip null/unread sentinels so a missing field can't fabricate an ordering. */
            if (!g_eng_blind && rt != 0xC && g_eng_rel)
            for (uint32_t a = 0; a < nf; a++)
              for (uint32_t b = a + 1; b < nf; b++) {
                uint64_t x = df_buf[pos + 3 + a], y = df_buf[pos + 3 + b];
                if (x == 0 || x == 0xBADADD85ULL || y == 0 || y == 0xBADADD85ULL) continue;
                uint64_t rr = (x < y) ? 0 : (x == y) ? 1 : 2;
                uint64_t rh = (pc ^ (rr + (uint64_t)(a * 7 + b) * 0x9E37ULL))
                              * 0x9E3779B97F4A7C15ULL;
                uint32_t rb = (uint32_t)(rh >> 48);
                if (!(val_seen[rb >> 3] & (uint8_t)(1u << (rb & 7)))) {
                    val_seen[rb >> 3] |= (uint8_t)(1u << (rb & 7));
                    ctr[path_n + (rb % val_n)]++;               /* reward: never-before-seen (pc,rel) */
                }
              }
        }
        pos += 3 + nf;
    }
}
/* kcov fold: stock trace-pc carries no values — PC-only (path bulk + pc_mark), i.e.
 * exactly what an edge fuzzer sees. */
static void kcov_fold(void) {
    unsigned long n = kcov_cover ? kcov_cover[0] : 0;
    if (n > (unsigned long)KCOV_COVER_WORDS - 1) n = KCOV_COVER_WORDS - 1;
    for (unsigned long i = 1; i <= n; i++) {
        uint64_t pc = (uint64_t)kcov_cover[i];
        pc_mark(pc);
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        ctr[(h>>12) % path_n]++;
    }
}
static void df_dev_init(unsigned long h) {
    df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) _exit(1);
    ioctl(df_fd, KCOV_DF_INIT, (unsigned long)BUF_WORDS);
    df_buf = mmap(0, BUF_WORDS*8, PROT_READ|PROT_WRITE, MAP_SHARED, df_fd, 0);
    ioctl(df_fd, KCOV_DF_REMOTE_ENABLE, h);
}
static void df_dev_reset(void) { if (df_buf) df_buf[0] = 0; }
static void kcov_dev_init(unsigned long h) {
    kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd < 0) _exit(1);
    ioctl(kcov_fd, KCOV_INIT_TRACE, (unsigned long)KCOV_COVER_WORDS);
    kcov_cover = mmap(0, KCOV_COVER_WORDS*sizeof(unsigned long),
                      PROT_READ|PROT_WRITE, MAP_SHARED, kcov_fd, 0);
    struct kcov_remote_arg arg = { .trace_mode = KCOV_TRACE_PC, .area_size = KCOV_COVER_WORDS,
                                   .num_handles = 0, .common_handle = h };
    ioctl(kcov_fd, KCOV_REMOTE_ENABLE, &arg);
}
static void kcov_dev_reset(void) { if (kcov_cover) kcov_cover[0] = 0; }
struct cov_ops { const char *name; void (*init)(unsigned long); void (*reset)(void); void (*fold)(void); };
static const struct cov_ops COV_DF   = { "dataflow", df_dev_init,   df_dev_reset,   df_fold  };
static const struct cov_ops COV_KCOV = { "kcov",     kcov_dev_init, kcov_dev_reset, kcov_fold };
static const struct cov_ops *cov = &COV_DF;


static void fb(void) {
    if (cov_mode < 0) {
        grain_engine();
        const char *e = getenv("GRAIN_DATAFLOW"); cov_mode = (e && e[0]=='1');
        /* #5 tuning: sweep the path/value split against a real run with no
         * recompile — smaller path_n => more value buckets (RedQueen-heavy),
         * larger => more path bulk. Bounds keep both regions non-degenerate. */
        const char *p = getenv("GRAIN_PATH_N");
        if (p && p[0]) { int v = atoi(p); if (v >= 256 && v <= CTR_N - 64) { path_n = v; val_n = CTR_N - v; } }
    }
    __builtin_memset((void *)ctr, 0, sizeof(ctr));
    cov->fold();
    /* Periodic metric emission: grain_atexit() is bypassed by the saturation SIGKILL
     * teardown, so KERNEL_PCS/RET_TOKEN_HITS/CMP_I2S_HITS were always 0 in the engine
     * table. Re-emit on the first fb() call and every 64 thereafter so gen.py's reader
     * captures the latest value however the grain dies; the table takes the max. */
    static unsigned long _emit_ctr;
    if (++_emit_ctr == 1 || (_emit_ctr & 63u) == 0)
        grain_emit_metrics();
}

/* ─── mutate_i2s: shared dataflow-directed (RedQueen/I2S) mutator ──────────────
 * The engine-maximizing step: instead of blind havoc, consult df_buf (this exec's
 * kcov trace-args/ret) to find the INPUT byte that became a kernel argument value,
 * and drive it to a type-boundary or an observed RETURN value. Covers 2/4/8-byte
 * widths and ALL struct fields (vals[0..nf-1]); biases toward the widest match
 * (8-byte = the length/offset args where overflows live). Call from the STUCK path
 * (amortized), not every exec. Returns the new size, or falls back to havoc if
 * nothing steerable was found. */
extern size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);
static const uint64_t _I2S_B8[] = {0,1,0x7fffffffULL,0x80000000ULL,0xffffffffULL,
    0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0x1000ULL};
static const uint32_t _I2S_B4[] = {0,1,0x7fffffffu,0x80000000u,0xffffffffu,0x100u,0x112u,0x1000u};
static const uint16_t _I2S_B2[] = {0,1,0x7fff,0x8000,0xffff,0x70,0x71,0x100};

/* ─── Arbiter feedback (the connector, cross-round DATA-driven loop) ───────────
 * Loaded ONCE at init from $GRAIN_FB — a packed LE blob the Python arbiter
 * (ksmbdzzer.py Arbiter.distill()) writes from the prior round's dataflow records
 * + oracle hits. mutate_i2s() consults it so this round's mutation is steered by
 * what PAID OFF last round, with the C compiled once (behavior from data). KEEP
 * THIS LAYOUT IN SYNC with the Python struct.pack format. Memory-only per-exec. */
struct feedback {
    uint32_t magic;         /* 0xF00DDA7A */
    uint32_t n_hot;         /* # hot body offsets */
    uint32_t n_val;         /* # interesting values */
    uint32_t _pad;
    uint16_t hot_off[64];   /* offsets that increased coverage / tripped the oracle */
    uint64_t vals[128];     /* interesting values carried from prior rounds */
};
static struct feedback g_fb;
static int g_fb_loaded = 0;
static void load_feedback(void) {
    const char *p = getenv("GRAIN_FB");
    if (!p || !p[0]) return;
    int fd = open(p, O_RDONLY);
    if (fd < 0) return;
    struct feedback tmp;
    ssize_t r = read(fd, &tmp, sizeof(tmp));
    close(fd);
    if (r == (ssize_t)sizeof(tmp) && tmp.magic == 0xF00DDA7Au) {
        if (tmp.n_hot > 64) tmp.n_hot = 64;
        if (tmp.n_val > 128) tmp.n_val = 128;
        g_fb = tmp; g_fb_loaded = 1;
    }
}

static size_t mutate_i2s(uint8_t *data, size_t size, size_t maxsize, unsigned seed) {
    uint64_t n = df_buf ? df_buf[0] : 0, pos;
    /* pass 1: collect observed RETURN values (kernel-computed magic constants) */
    uint64_t rets[32]; int nret = 0;
    for (pos = 1; pos + 3 <= 1 + n && pos < BUF_WORDS && nret < 32; ) {
        uint32_t rt = (df_buf[pos]>>28)&0xF, nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xF) { uint64_t rv = df_buf[pos+3];
            if (rv > 1 && rv < 0xffff000000000000ULL) rets[nret++] = rv; }
        pos += 3 + nf;
    }
    int hits = 0;
    /* Grow a too-small input so the splices below have room to land (mirror of
     * libksmbdzzer.c pfz_mutate_i2s): a size<w input skips every `size>=w` splice, which
     * kept CMP_I2S_HITS at 0 for grains driven by tiny inputs. Bounded by maxsize,
     * zero-filled; libFuzzer keeps the enlarged input only if it improves coverage. */
    if (size < 16 && maxsize > size) {
        size_t grow = maxsize < 16 ? maxsize : 16;
        if (grow > size) { memset(data + size, 0, grow - size); size = grow; }
    }
    /* pass 0 (trace_cmp / RedQueen — the strongest i2s): each 0xC record carries
     * the TWO operands of a kernel comparison. If the input holds one operand,
     * overwrite it with the other so the comparison flips — clears a magic-value
     * gate in ONE step instead of guessing type boundaries (the args/ret passes
     * below). trace_cmp is assumed always on, so this is the primary driver. */
    for (pos = 1; pos + 3 <= 1 + n && pos < BUF_WORDS; ) {
        uint32_t rt = (df_buf[pos]>>28)&0xF, nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xC && nf >= 2) {
            uint64_t ctype = df_buf[pos+2], a1 = df_buf[pos+3], a2 = df_buf[pos+4];
            int w = 1 << ((ctype >> 1) & 3);            /* KCOV_CMP_SIZE: 1/2/4/8B */
            if (w >= 2 && a1 != a2) {
                for (int dir = 0; dir < 2; dir++) {     /* input has a1->put a2, & vv */
                    uint64_t find = dir ? a2 : a1, put = dir ? a1 : a2;
                    if (find == 0) continue;            /* skip the trivial 0 needle */
                    if (w < 8 && (find >> (w*8))) continue;
                    uint8_t needle[8], repl[8];
                    for (int i=0;i<w;i++){ needle[i]=(find>>(i*8))&0xFF; repl[i]=(put>>(i*8))&0xFF; }
                    for (size_t o = 0; o + (size_t)w <= size; o++) {
                        if (__builtin_memcmp(data+o, needle, w)) continue;
                        for (int i=0;i<w;i++) data[o+i] = repl[i];
                        hits++; g_cmp_hits++;           /* proof: trace_cmp operand spliced */
                        break;                          /* one substitution per operand */
                    }
                }
            }
        }
        pos += 3 + nf;
    }
    /* pass 2: drive input bytes that control ENTRY args/fields */
    for (pos = 1; pos + 3 <= 1 + n && pos < BUF_WORDS; ) {
        uint32_t rt = (df_buf[pos]>>28)&0xF, nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        if (pos + 3 + nf > 1 + n) break;
        if (rt == 0xE) {
            for (uint32_t k = 0; k < nf; k++) {
                uint64_t v = df_buf[pos+3+k];
                if (v == 0 || v == 0xBADADD85ULL) continue;
                for (int w = 8; w >= 2; w >>= 1) {          /* widest first (len/off args) */
                    if (w < 8 && (v >> (w*8))) continue;
                    uint8_t needle[8]; for (int i=0;i<w;i++) needle[i] = (v>>(i*8))&0xFF;
                    for (size_t o = 0; o + (size_t)w <= size; o++) {
                        if (__builtin_memcmp(data+o, needle, w)) continue;
                        unsigned pick = seed + (unsigned)o + k*7u;
                        uint64_t repl; int from_ret = 0;
                        /* Reverse-flow RedQueen: prefer a value the kernel RETURNED
                         * (persistent g_retdict, then this-exec rets[]) as the token
                         * driven into this argument, so a handle/size/status computed
                         * earlier satisfies a downstream check without brute force. */
                        uint32_t rdn = g_retdict_n < RETDICT_N ? g_retdict_n : RETDICT_N;
                        if (rdn && (pick & 3u) == 0) { repl = g_retdict[pick % rdn]; from_ret = 1; }
                        else if (nret && (pick & 3u) == 2) { repl = rets[pick % (unsigned)nret]; from_ret = 1; }
                        else if (g_fb_loaded && g_fb.n_val && (pick & 7u) == 1)
                            repl = g_fb.vals[pick % g_fb.n_val];   /* cross-round hot value */
                        else if (w == 8) repl = _I2S_B8[pick % (sizeof(_I2S_B8)/8)];
                        else if (w == 4) repl = _I2S_B4[pick % (sizeof(_I2S_B4)/4)];
                        else            repl = _I2S_B2[pick % (sizeof(_I2S_B2)/2)];
                        for (int i=0;i<w;i++) data[o+i] = (repl>>(i*8))&0xFF;
                        hits++; if (from_ret) g_ret_hits++;    /* proof: return token spliced */
                        break;
                    }
                    if (hits) break;                        /* one drive per field */
                }
            }
        }
        pos += 3 + nf;
    }
    /* g_fb hot-offset pass: drive the body offsets that paid off in prior rounds,
     * even without a df_buf match this exec (cross-round directed memory). */
    if (g_fb_loaded) {
        for (uint32_t h = 0; h < g_fb.n_hot; h++) {
            uint16_t o = g_fb.hot_off[h];
            if ((size_t)o + 4 > size) continue;
            unsigned pick = seed + h*13u;
            uint64_t repl = (g_fb.n_val && (pick & 1u)) ? g_fb.vals[pick % g_fb.n_val]
                                                        : _I2S_B4[pick % (sizeof(_I2S_B4)/4)];
            for (int i=0;i<4;i++) data[o+i] = (repl>>(i*8))&0xFF;
            hits++;
        }
    }
    return hits ? size : LLVMFuzzerMutate(data, size, maxsize);
}

/* Drop-in custom mutator for any socket harness: cheap havoc until the coverage
 * plateaus (STUCK_LIMIT windows with no new path), then ONE dataflow-directed
 * mutate_i2s() nudge. Harness must define run_target(data,size) (build+send the
 * PDU into df_buf) and a static int g_stuck.  Use: paste GRAIN_I2S_MUTATOR()
 * once in the harness .c. */
/* Harness must first provide, in the same .c: `static int g_stuck;` (bumped in
 * LLVMFuzzerTestOneInput: g_stuck=0 on new coverage else ++) and a
 * `static int run_target(const uint8_t*, size_t)` that builds+sends its target PDU
 * into df_buf. Then paste GRAIN_I2S_MUTATOR() once. */
#define GRAIN_I2S_MUTATOR() \
size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t s, size_t m, unsigned seed) { \
    grain_engine();             /* resolve the arm's g_eng_i2s */ \
    if (!g_eng_i2s || g_stuck < 64) return LLVMFuzzerMutate(d, s, m); \
    run_target(d, s);           /* refresh df_buf for THIS input at the stuck point */ \
    g_stuck = 0; \
    return mutate_i2s(d, s, m, seed); \
}

/*
 * mutate_i2s rollout (task #35): a DEFAULT custom mutator for every harness that
 * doesn't define its own.  mutate_i2s() steers from the df_buf the previous
 * LLVMFuzzerTestOneInput populated + the arbiter's g_fb, and self-falls-back to
 * LLVMFuzzerMutate() when there's nothing to steer.  1-in-3 execs are dataflow-
 * directed; the rest stay plain havoc for exploration.  A harness with its own
 * LLVMFuzzerCustomMutator (e.g. the v2 grain, which has run_target/g_stuck) defines
 * GRAIN_HAS_MUTATOR before including this header to opt out — this strong def then
 * cleanly overrides libFuzzer's weak no-op default for all the raw harnesses.
 */
#ifndef GRAIN_HAS_MUTATOR
size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t s, size_t m, unsigned seed) {
    grain_engine();
    if (g_eng_i2s && (seed % 3u) == 0u)     /* pc-havoc arm forces pure havoc */
        return mutate_i2s(d, s, m, seed);
    return LLVMFuzzerMutate(d, s, m);
}
#endif

/* Per-grain target: GRAIN_IP env (127.0.0.<octet>) lets many libFuzzer
 * grains run in parallel, each on its own loopback address so ksmbd routes
 * each one's kernel coverage to its OWN buffer (no handle collision). */
static const char *grain_ip(void) {
    const char *e = getenv("GRAIN_IP");
    return (e && e[0]) ? e : "127.0.0.1";
}
/* Mirror of kernel KSMBD_KCOV_IP_HANDLE for 127.0.0.<octet>. */
static unsigned long grain_handle(void) {
    const char *ip = grain_ip();
    const char *dot = strrchr(ip, '.');
    unsigned octet = dot ? (unsigned)atoi(dot + 1) : 1;
    return 0x4b440000UL | (octet & 0xFFFF);
}

static void df_init(void) {
    setvbuf(stderr, NULL, _IOLBF, 0);   /* line-buffer: metric emits survive the
                                         * saturation SIGKILL (pipe = block-buffered). */
    /* Select the coverage backend ONCE (KSMBDZZER_KCOV=1 → stock trace-pc, else
     * kcov-dataflow) and open its device with the per-connection IP handle. */
    const char *k = getenv("KSMBDZZER_KCOV");
    cov = (k && k[0] == '1') ? &COV_KCOV : &COV_DF;
    cov->init(grain_handle());
    atexit(grain_atexit);
}

static void smb2_hdr(uint8_t *h, uint16_t cmd) {
    memset(h, 0, 64);
    memcpy(h, "\xfeSMB", 4);
    *(uint16_t*)(h+4) = 64;
    *(uint16_t*)(h+6) = 1;
    *(uint16_t*)(h+12) = cmd;
    *(uint16_t*)(h+14) = 31;
    *(uint64_t*)(h+24) = mid++;
    *(uint32_t*)(h+36) = tid;
    *(uint64_t*)(h+40) = sid;
}

static int xact(uint8_t *pdu, size_t len, uint8_t *resp, size_t rmax) {
    uint8_t frame[4];
    uint32_t fl = len;
    frame[0]=fl>>24; frame[1]=(fl>>16)&0xff; frame[2]=(fl>>8)&0xff; frame[3]=fl&0xff;
    if (send(raw_sock, frame, 4, MSG_NOSIGNAL) < 0) return -1;
    if (send(raw_sock, pdu, len, MSG_NOSIGNAL) < 0) return -1;
    if (recv(raw_sock, frame, 4, MSG_WAITALL) != 4) return -1;
    uint32_t rlen = (frame[0]<<24)|(frame[1]<<16)|(frame[2]<<8)|frame[3];
    if (rlen > rmax) rlen = rmax;
    int got = 0;
    while ((size_t)got < rlen) {
        int r = recv(raw_sock, resp+got, rlen-got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

static void send_only(uint8_t *pdu, size_t len) {
    uint8_t frame[4];
    uint32_t fl = len;
    frame[0]=fl>>24; frame[1]=(fl>>16)&0xff; frame[2]=(fl>>8)&0xff; frame[3]=fl&0xff;
    send(raw_sock, frame, 4, MSG_NOSIGNAL);
    send(raw_sock, pdu, len, MSG_NOSIGNAL);
}

#ifdef USE_NTLMV2
#include "ntlmv2.h"
#endif

static int smb_connect(void) {
    raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (raw_sock < 0) return -1;
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(445)};
    inet_pton(AF_INET, grain_ip(), &addr.sin_addr);   /* per-grain loopback IP */
    if (connect(raw_sock, (void*)&addr, sizeof(addr)) < 0) return -1;
    struct timeval tv = {.tv_sec=1};   /* 2s→1s: fail a slow op fast so the grain cycles */
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

/*
 * NTLMv2 auth with fuzz:fuzz credentials.
 *
 * Since ksmbd's [share] has "guest ok = yes" + "force user = root",
 * even a minimal NTLMSSP negotiate → authenticate with username "fuzz"
 * will get session established. The key is sending the username in the
 * AUTHENTICATE_MESSAGE so ksmbd maps to the right user.
 *
 * For the [aclshare] (guest ok = no), we need valid NTLMv2. However,
 * since ksmbd with "restrict anonymous = 0" + our config accepts the
 * user if ksmbd.adduser was done, we send a proper NTLMSSP flow with
 * the username set. If NTLMv2 computation fails, guest fallback works
 * for [share].
 */
static uint8_t server_challenge[8];

static int smb_auth(const char *share) {
    uint8_t pdu[1024], resp[2048];
    int r;

    /* NEGOTIATE */
    smb2_hdr(pdu, 0);
    uint8_t *nb = pdu+64;
    *(uint16_t*)(nb+0) = 36;      /* StructureSize */
    *(uint16_t*)(nb+2) = 1;       /* DialectCount */
    *(uint16_t*)(nb+4) = 1;       /* SecurityMode */
    *(uint16_t*)(nb+6) = 0;       /* Reserved */
    *(uint32_t*)(nb+8) = 0;       /* Capabilities */
    memset(nb+12, 0, 16);         /* ClientGuid */
    memset(nb+28, 0, 8);          /* NegContextOffset/Count/Reserved2 */
    *(uint16_t*)(nb+36) = 0x0300; /* Dialect SMB 3.0 */
    r = xact(pdu, 64+38, resp, sizeof(resp));
    if (r < 64) return -1;

    /* Extract server challenge from NEGOTIATE response's security buffer */
    uint16_t sec_off = *(uint16_t*)(resp+56);
    uint16_t sec_len = *(uint16_t*)(resp+58);
    /* The challenge is inside NTLMSSP_CHALLENGE at offset +24 in the token */
    if (sec_off + sec_len <= (unsigned)r && sec_len > 32) {
        /* Find "NTLMSSP\0\x02" in the security buffer */
        for (int i = sec_off; i + 32 < sec_off + sec_len && i + 32 < r; i++) {
            if (memcmp(resp+i, "NTLMSSP\x00\x02", 9) == 0) {
                memcpy(server_challenge, resp+i+24, 8);
                break;
            }
        }
    }

    /* SESSION_SETUP 1: NTLMSSP_NEGOTIATE */
    smb2_hdr(pdu, 1);
    nb = pdu+64;
    memset(nb, 0, 24); /* zero entire body */
    *(uint16_t*)(nb+0) = 25;   /* StructureSize */
    nb[2] = 0;                  /* Flags */
    nb[3] = 1;                  /* SecurityMode */
    /* Capabilities(4) + Channel(4) already zeroed */
    /* SPNEGO wrapping the NTLMSSP_NEGOTIATE */
    uint8_t ntlm_neg[] = {
        /* NTLMSSP header */
        'N','T','L','M','S','S','P',0, 0x01,0,0,0,
        /* NegotiateFlags: NTLM|Unicode|RequestTarget|NTLMv2|128|56 */
        0x97,0x82,0x08,0xe2,
        /* DomainNameFields (0,0,0) */
        0,0, 0,0, 0x28,0,0,0,
        /* WorkstationFields (0,0,0) */
        0,0, 0,0, 0x28,0,0,0,
    };
    uint16_t sec_buf_off = 88;
    *(uint16_t*)(nb+12) = sec_buf_off;
    *(uint16_t*)(nb+14) = sizeof(ntlm_neg);
    memcpy(pdu+sec_buf_off, ntlm_neg, sizeof(ntlm_neg));
    r = xact(pdu, sec_buf_off + sizeof(ntlm_neg), resp, sizeof(resp));
    if (r >= 48) sid = *(uint64_t*)(resp+40);

    /* SESSION_SETUP 2: NTLMSSP_AUTHENTICATE (unknown user → guest) */
    smb2_hdr(pdu, 1);
    nb = pdu+64;
    memset(nb, 0, 24);
    *(uint16_t*)(nb+0) = 25; nb[3] = 1;

    /* Build NTLMSSP_AUTHENTICATE message with user="fuzz" */
    uint8_t auth[512];
    memset(auth, 0, sizeof(auth));
    memcpy(auth, "NTLMSSP\x00\x03\x00\x00\x00", 12);
    /* NegotiateFlags */
    *(uint32_t*)(auth+60) = 0xe2088215;

    int payload_off = 72;

#ifdef USE_NTLMV2
    /* Real NTLMv2 auth (requires -lcrypto) */
    uint8_t lm_buf[24], nt_buf[64];
    int lm_len = 0, nt_len = 0;
    ntlmv2_response(server_challenge, nt_buf, &nt_len, lm_buf, &lm_len);

    /* LmChallengeResponse */
    *(uint16_t*)(auth+12) = lm_len;
    *(uint16_t*)(auth+14) = lm_len;
    *(uint32_t*)(auth+16) = payload_off;
    memcpy(auth+payload_off, lm_buf, lm_len);
    payload_off += lm_len;

    /* NtChallengeResponse */
    *(uint16_t*)(auth+20) = nt_len;
    *(uint16_t*)(auth+22) = nt_len;
    *(uint32_t*)(auth+24) = payload_off;
    memcpy(auth+payload_off, nt_buf, nt_len);
    payload_off += nt_len;
#else
    /* Guest/anonymous fallback (works for shares with guest ok = yes) */
    *(uint16_t*)(auth+12) = 24;
    *(uint16_t*)(auth+14) = 24;
    *(uint32_t*)(auth+16) = payload_off;
    memset(auth+payload_off, 0, 24);
    payload_off += 24;

    *(uint16_t*)(auth+20) = 24;
    *(uint16_t*)(auth+22) = 24;
    *(uint32_t*)(auth+24) = payload_off;
    memset(auth+payload_off, 0, 24);
    payload_off += 24;
#endif

    /* DomainName: empty */
    *(uint16_t*)(auth+28) = 0;
    *(uint16_t*)(auth+30) = 0;
    *(uint32_t*)(auth+32) = payload_off;

    /* UserName: "fuzz" for NTLMv2 auth, "guest" for guest fallback */
#ifdef USE_NTLMV2
    uint8_t user_utf16[] = {'f',0,'u',0,'z',0,'z',0};
#else
    uint8_t user_utf16[] = {'g',0,'u',0,'e',0,'s',0,'t',0};
#endif
    *(uint16_t*)(auth+36) = sizeof(user_utf16);
    *(uint16_t*)(auth+38) = sizeof(user_utf16);
    *(uint32_t*)(auth+40) = payload_off;
    memcpy(auth+payload_off, user_utf16, sizeof(user_utf16));
    payload_off += sizeof(user_utf16);

    /* Workstation: empty */
    *(uint16_t*)(auth+44) = 0;
    *(uint16_t*)(auth+46) = 0;
    *(uint32_t*)(auth+48) = payload_off;

    /* EncryptedRandomSessionKey: empty */
    *(uint16_t*)(auth+52) = 0;
    *(uint16_t*)(auth+54) = 0;
    *(uint32_t*)(auth+56) = payload_off;

    *(uint16_t*)(nb+12) = sec_buf_off;
    *(uint16_t*)(nb+14) = payload_off;
    memcpy(pdu+sec_buf_off, auth, payload_off);
    r = xact(pdu, sec_buf_off + payload_off, resp, sizeof(resp));
    if (r >= 48) {
        sid = *(uint64_t*)(resp+40);
        /* Check NT_STATUS — 0 = success, 0xC000006D = bad password */
        uint32_t status = *(uint32_t*)(resp+8);
        if (status != 0 && status != 0x00000016) {
            /* Auth failed — try with empty user (guest fallback) */
            /* Already have sid from MORE_PROCESSING status */
        }
    }

    /* TREE_CONNECT */
    smb2_hdr(pdu, 3);
    nb = pdu+64;
    *(uint16_t*)(nb) = 9;
    uint16_t pathlen = 0;
    for (int i = 0; share[i]; i++) { pdu[72+i*2]=share[i]; pdu[73+i*2]=0; pathlen+=2; }
    *(uint16_t*)(nb+4) = 72; *(uint16_t*)(nb+6) = pathlen;
    r = xact(pdu, 72+pathlen, resp, sizeof(resp));
    if (r >= 40) tid = *(uint32_t*)(resp+36);
    else return -1;
    return 0;
}

static int smb_reconnect(const char *share) {
    if (raw_sock >= 0) close(raw_sock);
    raw_sock = -1; sid = 0; tid = 0; mid = 0; has_file = 0;
    if (smb_connect() < 0) return -1;
    return smb_auth(share);
}

/* Robust one-shot setup for LLVMFuzzerInitialize: retry connect+auth a few
 * times with backoff. Under 8-way-parallel grains (and any residual kmalloc
 * fault injection) a single connect/auth round can transiently fail; retrying
 * keeps the grain alive instead of exiting at init with 0 executions. */
static int smb_setup(const char *share) {
    int last_step = 0, last_errno = 0;   /* step: 1=connect, 2=auth */
    for (int _t = 0; _t < 6; _t++) {
        if (raw_sock >= 0) { close(raw_sock); raw_sock = -1; }
        sid = 0; tid = 0; mid = 0; has_file = 0;
        errno = 0;
        if (smb_connect() != 0) { last_step = 1; last_errno = errno; }
        else if (smb_auth(share) != 0) { last_step = 2; last_errno = errno; }
        else return 0;
        /* EAGAIN (Resource temporarily unavailable) is ksmbd transiently at its
         * connection/session limit — the late-wave GRAIN_SETUP_FAIL storm under -procs
         * concurrency, where earlier grains' sessions haven't been reaped yet. Back off
         * HARD on it (200ms..1.2s) so the limit clears, instead of burning quick retries
         * and dying at 0-exec; other errors keep the light 40ms linear backoff. */
        unsigned base = (last_errno == EAGAIN || last_errno == EWOULDBLOCK)
                        ? 200000u : 40000u;
        usleep(base * (unsigned)(_t + 1));
    }
    /* CONNECTION-LAYER death diagnostic: name WHICH step exhausted its retries so the
     * "0 executions — exited at init" grains stop being a black box. step=1 CONNECT
     * (ksmbd not accepting / reset at accept — transport/conn-limit) vs step=2 AUTH
     * (negotiate/session-setup/mountd-IPC). errno pins connect-side failures
     * (ECONNREFUSED/ECONNRESET/ETIMEDOUT). Emitted once per dead grain; gen.py captures it. */
    pfz_err("GRAIN_SETUP_FAIL step=%s errno=%d(%s) ip=%s share=%s\n",
            last_step == 1 ? "CONNECT" : last_step == 2 ? "AUTH" : "?",
            last_errno, last_errno ? strerror(last_errno) : "none", grain_ip(), share);
    return -1;
}

/* Runs at process exit (registered in df_init). (#1) Cleanly tears down the SMB2
 * session — TREE_DISCONNECT + LOGOFF — so ksmbd reaps it immediately instead of
 * leaving it for a timeout; lingering wave-1 sessions are the leading suspect for
 * the wave-2 session-setup failures. (#5) Reports the distinct kernel PCs reached. */
/* Emit the three engine-comparison metrics (all monotonic counters). Called
 * periodically from fb() so the saturation SIGKILL teardown can't lose them, and once
 * from grain_atexit() on a clean exit. gen.py / the engine table take the high-water mark. */
static void grain_emit_metrics(void) {
    unsigned c = pc_count();
    pfz_err("KERNEL_PCS=%u RET_TOKEN_HITS=%lu CMP_I2S_HITS=%lu RET_DICT=%u\n",
            c, g_ret_hits, g_cmp_hits,
            g_retdict_n < RETDICT_N ? g_retdict_n : RETDICT_N);
    fflush(stderr);   /* stderr is a PIPE under gen.py → block-buffered; flush so the
                       * saturation SIGKILL can't drop the emit (else metrics read 0). */

    /* Fleet-UNION dump — twin of libksmbdzzer.c pfz_report_metrics(). Same 2^17-bit
     * layout + hash as the lib grains, so gen.py ORs all bitmaps into one deduplicated
     * fleet union (the throughput-fair primary metric). Dump only when the popcount grew
     * so a saturated grain stops writing (bounds churn to distinct-PC increases). */
    const char *bmp = getenv("GRAIN_PCBMP");
    if (bmp) {
        static unsigned last_dumped;
        if (c > last_dumped) {
            int fd = open(bmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0) {
                ssize_t w = write(fd, pc_bitmap, sizeof(pc_bitmap));
                (void)w;
                close(fd);
            }
            last_dumped = c;
        }
    }
}

static void grain_atexit(void) {
    if (raw_sock >= 0 && sid) {
        uint8_t pdu[128], resp[256];
        if (tid) {
            smb2_hdr(pdu, 4);                 /* SMB2 TREE_DISCONNECT */
            *(uint16_t *)(pdu + 64) = 4;      /* StructureSize */
            xact(pdu, 64 + 4, resp, sizeof(resp));
        }
        smb2_hdr(pdu, 2);                     /* SMB2 LOGOFF */
        *(uint16_t *)(pdu + 64) = 4;          /* StructureSize */
        xact(pdu, 64 + 4, resp, sizeof(resp));
    }
    /* Reverse-flow proof (RET_TOKEN_HITS / CMP_I2S_HITS): direct evidence the
     * bi-directional RedQueen loop fired. Emitted through the shared helper (also called
     * periodically from fb()) so a SIGKILLed grain still reports its high-water counters. */
    grain_emit_metrics();
}

static int smb_create_file(const char *fname) {
    uint8_t pdu[256], resp[256];
    smb2_hdr(pdu, 5);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+24) = 0x12019F; /* GENERIC_ALL */
    *(uint32_t*)(body+28) = 0x80;
    *(uint32_t*)(body+32) = 0x07; /* ShareAccess=ALL */
    *(uint32_t*)(body+36) = 0x05; /* FILE_OPEN_IF */
    *(uint32_t*)(body+40) = 0x40; /* FILE_NON_DIRECTORY_FILE */
    uint16_t nlen = 0;
    for (int i = 0; fname[i]; i++) { pdu[120+i*2]=fname[i]; pdu[121+i*2]=0; nlen+=2; }
    *(uint16_t*)(body+44) = 120;
    *(uint16_t*)(body+46) = nlen;
    int r = xact(pdu, 120+nlen, resp, sizeof(resp));
    if (r >= 144) { memcpy(file_id, resp+128, 16); has_file = 1; return 0; }
    return -1;
}

static void smb_logoff_disconnect(void) {
    /* TREE_DISCONNECT */
    uint8_t pdu[128], resp[128];
    smb2_hdr(pdu, 4); /* CMD_TREE_DISCONNECT */
    *(uint16_t*)(pdu+64) = 4;
    xact(pdu, 68, resp, sizeof(resp));
    /* LOGOFF */
    smb2_hdr(pdu, 2); /* CMD_LOGOFF */
    *(uint16_t*)(pdu+64) = 4;
    xact(pdu, 68, resp, sizeof(resp));
    /* Close socket */
    if (raw_sock >= 0) { close(raw_sock); raw_sock = -1; }
    sid = 0; tid = 0; has_file = 0;
}

static int _iter_count = 0;
/* Call at end of each iteration — disconnects every 200 iterations to release server resources */
#define GRAIN_ITER_END() do { \
    if (++_iter_count % 200 == 0) smb_logoff_disconnect(); \
} while(0)

/* ─── Runtime PDU spec: shape the harness by hand WITHOUT recompiling ─────────
 * A generic interpreter harness (gen_spec_grain) reads a text spec file named
 * by $GRAIN_SPEC once at startup and builds the target PDU from it each
 * iteration. Edit the file, rerun — no clang. The libFuzzer input drives ONLY the
 * fields you mark `fuzz`, so mutations stay structurally valid and land where you
 * point them (structured fuzzing). Text format (one directive per line, # = note):
 *
 *     cmd   0x0005          SMB2 opcode (hex 0x.. or decimal)
 *     len   120             body length in bytes (after the 64-byte SMB2 header)
 *     create pool_0         optional: pre-open this file; `fid` overlays its handle
 *     b     0 3900          fixed skeleton bytes at offset 0  (0x39 0x00)
 *     b     44 7800         NameOffset=120 (0x78) as a fixed field, etc.
 *     fuzz  24 4            route 4 input bytes into offset 24 (DesiredAccess)
 *     fuzz  36 4            route 4 input bytes into offset 36 (CreateDisposition)
 *     flen  4  4            auto-write the body length as a 4-byte LE field at off 4
 *     fid   16             write the open FileId (16 bytes) at offset 16
 *
 * Offsets/widths are body-relative (0 = first byte after the SMB2 header). */
enum { OV_FUZZ, OV_FLEN, OV_FID };
struct pdu_ov { uint16_t off; uint8_t width; uint8_t kind; };
struct pdu_spec {
    uint16_t cmd;
    uint16_t body_len;
    int      n_ov;
    struct   pdu_ov ov[64];
    uint8_t  skel[2048];      /* base body bytes (from `b` directives, else zero) */
    char     create_name[128];
    int      have_create;
    int      loaded;
};

static int _spec_hexnib(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse $GRAIN_SPEC into `s`. Returns 0 on success, -1 on any load error. */
static int spec_load(struct pdu_spec *s, const char *path) {
    memset(s, 0, sizeof(*s));
    if (!path || !path[0]) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[4096], name[128], hex[3072];
    int cmd, blen, off, w;
    while (fgets(line, sizeof(line), f)) {
        char *p = line; while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;
        if (sscanf(p, "cmd %i", &cmd) == 1) {
            s->cmd = (uint16_t)cmd;
        } else if (sscanf(p, "len %i", &blen) == 1) {
            if (blen > 0 && blen <= (int)sizeof(s->skel)) s->body_len = (uint16_t)blen;
        } else if (sscanf(p, "create %127s", name) == 1) {
            strncpy(s->create_name, name, sizeof(s->create_name) - 1);
            s->have_create = 1;
        } else if (sscanf(p, "fuzz %i %i", &off, &w) == 2) {
            if (s->n_ov < 64 && off >= 0 && w > 0 && off + w <= (int)sizeof(s->skel)) {
                s->ov[s->n_ov].off = (uint16_t)off; s->ov[s->n_ov].width = (uint8_t)w;
                s->ov[s->n_ov].kind = OV_FUZZ; s->n_ov++;
            }
        } else if (sscanf(p, "flen %i %i", &off, &w) == 2) {
            if (s->n_ov < 64 && off >= 0 && w > 0 && w <= 8 && off + w <= (int)sizeof(s->skel)) {
                s->ov[s->n_ov].off = (uint16_t)off; s->ov[s->n_ov].width = (uint8_t)w;
                s->ov[s->n_ov].kind = OV_FLEN; s->n_ov++;
            }
        } else if (sscanf(p, "fid %i", &off) == 1) {
            if (s->n_ov < 64 && off >= 0 && off + 16 <= (int)sizeof(s->skel)) {
                s->ov[s->n_ov].off = (uint16_t)off; s->ov[s->n_ov].width = 16;
                s->ov[s->n_ov].kind = OV_FID; s->n_ov++;
            }
        } else if (sscanf(p, "b %i %3071s", &off, hex) == 2) {
            for (int i = 0; hex[i] && hex[i + 1] && off < (int)sizeof(s->skel); i += 2) {
                int hi = _spec_hexnib(hex[i]), lo = _spec_hexnib(hex[i + 1]);
                if (hi < 0 || lo < 0) break;
                s->skel[off++] = (uint8_t)((hi << 4) | lo);
            }
        }
        /* unknown directives are ignored so the format can grow compatibly */
    }
    fclose(f);
    if (s->body_len == 0) return -1;      /* a spec with no body is useless */
    s->loaded = 1;
    return 0;
}

/* Build the PDU from the spec (skeleton + overlays) and send it. The fuzz input
 * fills the `fuzz` fields left-to-right; `flen`/`fid` are derived at runtime.
 * Returns the xact() result. */
static int spec_run(struct pdu_spec *s, const uint8_t *data, size_t size) {
    uint8_t pdu[64 + 2048], resp[2048];
    smb2_hdr(pdu, s->cmd);
    uint8_t *b = pdu + 64;
    memcpy(b, s->skel, s->body_len);
    size_t di = 0;
    for (int i = 0; i < s->n_ov; i++) {
        struct pdu_ov *o = &s->ov[i];
        if (o->kind == OV_FUZZ) {
            if (di + o->width <= size && o->off + o->width <= sizeof(s->skel)) {
                memcpy(b + o->off, data + di, o->width);
                di += o->width;
            }
        } else if (o->kind == OV_FLEN) {
            uint64_t L = s->body_len;
            if (o->off + o->width <= sizeof(s->skel)) memcpy(b + o->off, &L, o->width);
        } else if (o->kind == OV_FID) {
            if (has_file && o->off + 16 <= sizeof(s->skel)) memcpy(b + o->off, file_id, 16);
        }
    }
    cov->reset();
    return xact(pdu, 64 + s->body_len, resp, sizeof(resp));
}

#endif /* GRAIN_COMMON_H */
