/*
 * libksmbdzzer.h — Public API for libksmbdzzer.so
 *
 * Used by element harnesses (via #include "../libksmbdzzer.h") for
 * authenticated session management and kcov_dataflow capture.
 */
#ifndef LIBKSMBDZZER_H
#define LIBKSMBDZZER_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ─── Colored, located logging for the C fuzzer side ───────────────────────────
 * Parity with the Python side (ksmbdzzer.py teal / gen.py orange): every log line
 * carries a dmesg-style CLOCK_MONOTONIC timestamp (aligns with kernel printk) +
 * file:line, wrapped in this component's 24-bit truecolor so each fuzzer program is
 * visually distinct in a combined log. A translation unit may pick its palette
 * color by #defining PFZ_LOG_COLOR before including this header (default #c8e5ff).
 * Use pfz_err(fmt, ...) exactly like fprintf(stderr, fmt, ...). */
#ifndef PFZ_LOG_COLOR
#define PFZ_LOG_COLOR "\033[38;2;200;229;255m"   /* #c8e5ff — default C color */
#endif
#define PFZ_LOG_RESET "\033[0m"
#ifdef __FILE_NAME__
# define PFZ_FILE __FILE_NAME__          /* clang: basename only */
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

#ifdef __cplusplus
extern "C" {
#endif

/* kcov_dataflow ioctls */
#ifndef KCOV_DF_INIT_TRACE
#define KCOV_DF_INIT_TRACE     _IOR('d', 1, unsigned long)
#endif
#ifndef KCOV_DF_REMOTE_ENABLE
#define KCOV_DF_REMOTE_ENABLE  _IOW('d', 102, unsigned long)
#endif
#ifndef KCOV_DF_REMOTE_DISABLE
#define KCOV_DF_REMOTE_DISABLE _IO('d', 103)
#endif
#ifndef DF_BUF_WORDS
#define DF_BUF_WORDS           (1 << 23)
#endif

/* ─── SMB2 header helper (for elements building raw PDUs) ─────────────────── */
static inline void smb2_hdr_build(uint8_t *h, uint16_t cmd,
                                  uint64_t mid, uint32_t tid, uint64_t sid)
{
    memset(h, 0, 64);
    memcpy(h, "\xfeSMB", 4);
    *(uint16_t *)(h + 4) = 64;
    *(uint16_t *)(h + 6) = 1;
    *(uint16_t *)(h + 12) = cmd;
    *(uint16_t *)(h + 14) = 31;
    *(uint64_t *)(h + 24) = mid;
    *(uint32_t *)(h + 36) = tid;
    *(uint64_t *)(h + 40) = sid;
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

int  pfz_init(unsigned long worker_octet); /* 127.0.0.<octet>; 0 => 1 */
void pfz_reset(void);
int  pfz_write(long offset, const void *buf, int len);
int  pfz_truncate(long size);
int  pfz_setxattr(const char *name, const void *val, int vlen);
int  pfz_raw_pdu(const void *pdu, int len, void *resp, int resp_max);
int  pfz_raw_pdu_authed(uint16_t cmd, const void *body, int body_len,
                              void *resp, int resp_max);
int  pfz_compound(const void *chain_data, int chain_len,
                        void *resp, int resp_max);
int  pfz_get_features(uint32_t *out, int max);
int  pfz_get_pc_ret_pairs(uint64_t *out, int max_pairs);
/* Fleet-wide RedQueen/i2s mutator: returns new size if it steered, 0 ⇒ havoc. */
size_t pfz_mutate_i2s(uint8_t *data, size_t size, size_t maxsize, unsigned seed);

/* Full dataflow record export — keep layout in sync with ksmbdzzer.py ctypes */
struct pfz_rec {
    uint64_t pc;
    uint64_t vals[6];
    uint32_t type;      /* 0xE entry, 0xF return */
    uint32_t arg_idx;
    uint32_t size;
    uint32_t nfields;
    uint32_t seq;
    uint32_t _pad;
};
int  pfz_get_records(struct pfz_rec *out, int max);

/* Authenticated probe connection with caller-controlled body (I2S directed) */
int  pfz_probe_init(void);
int  pfz_probe_init_share(const char *share);
int  pfz_probe_send(uint16_t cmd, const void *body, int body_len,
                          void *resp, int resp_max);
int  pfz_probe_get_fid(void *out16);
int  pfz_probe_reconnect(const char *share);   /* rebuild session after teardown oracle */
int  pfz_probe_send_frag(uint16_t cmd, const void *body, int body_len,
                         void *resp, int resp_max, int nseg); /* fragmented framing */
int  pfz_race_write_close(const void *data, int len, int iters);
int  pfz_reconnect(void);

/* ─── Grain registry (normal-scenario atoms; new phase architecture) ──────── */
int         pfz_grain_count(void);
const char *pfz_grain_name(int i);
int         pfz_grain_run(int i, const void *data, int len);
int         pfz_grain_combo2(int a, int b, const void *data, int len);

#ifdef __cplusplus
}
#endif

#endif /* LIBKSMBDZZER_H */

/* ─── Multi-Connection Pool (for race condition testing) ──────────────── */
int  pfz_pool_init(int n_conns);
int  pfz_pool_oplock_race(const char *filename);
int  pfz_pool_lock_race(int iters);

/* ─── Attack Pattern APIs ─────────────────────────────────────────────── */
int  pfz_compress_fuzz(uint16_t algo, const void *data, int len, uint32_t orig_size);
int  pfz_pool_init_authed(int n);
int  pfz_pool_fids_ready(void);   /* #4: count of pool conns with an open fid */
int  pfz_pool_race_authed(int a_idx, int b_idx, const void *data, int len);
int  pfz_durable_reconnect(const char *filename);
int  pfz_session_binding_race(void);
int  pfz_query_dir(uint8_t info_class, uint32_t output_buf_len,
                         const void *pattern, int pattern_len);
int  pfz_ndr_fuzz(const void *rpc_data, int rpc_len);

/* ─── Frontier Attack APIs ────────────────────────────────────────────── */
int  pfz_lease_race(const char *filename, const void *lease_key, uint32_t lease_state);
int  pfz_copychunk(uint64_t src_off, uint64_t dst_off, uint32_t length, int n_chunks);
int  pfz_set_reparse(uint32_t reparse_tag, const void *data, int len);
int  pfz_krb5_fuzz(const void *ap_req_data, int len);

/* ─── Deep Frontier APIs ──────────────────────────────────────────────── */
int  pfz_set_failslab(int probability);
int  pfz_negotiate_contexts(const void *ctx_data, int ctx_len);
int  pfz_unknown_pipe(const void *pipe_name, int name_len);
int  pfz_unicode_path(const void *filename_utf16, int name_len);

/* ─── RDMA Transport APIs ─────────────────────────────────────────────── */
int  pfz_rdma_fuzz(const void *payload, int payload_len, uint16_t port);

/* ─── State Machine Sequence Fuzzing ─────────────────────────────────── */
int  pfz_sequence(int seq_id, const void *fuzz_data, int fuzz_len);
