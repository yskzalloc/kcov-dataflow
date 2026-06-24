"""
grain_gen.py — Auto-generates targeted libFuzzer C harnesses.

All socket-based grains use grain_common.h for authenticated session + reconnect.
Value pool from Phase 1-5 is injected into dictionaries at generation time.
"""
import struct, os, subprocess, shutil, time, json, hashlib
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
# GRAIN_DIR holds the compiled grain harnesses + their .dict + .c. It lives on the
# HOST 9p mount (next to gen.py), NOT guest /tmp — so the byte-identical-source compile
# cache in _compile() SURVIVES across VM runs. The engine-comparison campaign rebuilds
# libksmbdzzer.so ONCE up front, so after the first (arm,trial) compiles the fleet, the
# other 8 runs find every binary newer than the .so + headers and SKIP clang entirely
# (grain binaries are engine-agnostic — the arm is chosen at runtime via KSMBDZZER_ENGINE,
# so reusing them across arms is correct). Override with KSMBDZZER_GRAIN_DIR.
GRAIN_DIR = Path(os.environ.get('KSMBDZZER_GRAIN_DIR', str(SCRIPT_DIR / '.grains')))
CRASH_DIR = Path('/tmp/ksmbdzzer_crashes')
# Durability (overcomes "learning lost on VM wedge"): the distilled DB — arbiter
# feedback (fb.bin), and a corpus/value_pool mirror — lives on the repo mount
# (9p-visible to the host), NOT guest /tmp. A VM crash costs the in-flight round,
# not the campaign. Under ksmbd/ so it rides the existing repo checkout.
FUZZDB = SCRIPT_DIR.parent / '.fuzzdb'
FUZZDB.mkdir(exist_ok=True)


def _dts():
    """dmesg-style monotonic `[   SS.uuuuuu]` timestamp (same CLOCK_MONOTONIC base
    as the kernel's printk), so a per-grain fuzzer line lines up against a
    kernel oops/KASAN line in `dmesg`."""
    t = time.clock_gettime(time.CLOCK_MONOTONIC)
    sec = int(t)
    return f"[{sec:5d}.{int((t - sec) * 1_000_000):06d}]"


# ─── Colored, located logging (auto-applied to EVERY print in this module) ─────
# See ksmbdzzer.py for rationale. Distinct 24-bit color per fuzzer component; the
# dmesg-style stamp + file:line is prepended and a pre-existing stamp is stripped.
import sys as _sys, os as _os, re as _re, builtins as _bi
_LOG_COLOR = "\033[38;2;237;154;122m"   # #ed9a7a — grain/gen.py
_LOG_RESET = "\033[0m"
_LOG_TS_RE = _re.compile(r'^\s*\[\s*\d+\.\d{6}\]\s*')
def print(*args, **kwargs):
    end = kwargs.pop("end", "\n"); file = kwargs.pop("file", _sys.stdout)
    flush = kwargs.pop("flush", False); sep = kwargs.pop("sep", " ")
    fr = _sys._getframe(1)
    loc = "%s:%d" % (_os.path.basename(fr.f_code.co_filename), fr.f_lineno)
    body = _LOG_TS_RE.sub("", sep.join(str(a) for a in args))
    _bi.print("%s%s %s | %s%s" % (_LOG_COLOR, _dts(), loc, body, _LOG_RESET),
              end=end, file=file, flush=flush)


def _dict_tok(bs):
    r"""A libFuzzer dictionary token for raw bytes `bs`.

    libFuzzer parses a dict body's `\xNN` as one binary byte but a bare hex string
    (`"01000000"`) as its literal ASCII characters. The old code wrote
    struct.pack(...).hex(), so every boundary/audit value was injected as its
    8-char ASCII spelling and NEVER matched the 4/8-byte little-endian field on the
    SMB2 wire — the dictionary was effectively inert. Emit proper \xNN escapes so
    the value the mutator splices IS the binary field."""
    return '"' + "".join("\\x%02x" % c for c in bs) + '"'

def _write_dict(name, extra_entries=None, value_pool=None):
    dp = GRAIN_DIR / f'{name}.dict'
    seen = set()
    with open(dp, 'w') as f:
        def emit(bs, tag):
            tok = _dict_tok(bs)
            if tok in seen:
                return
            seen.add(tok)
            f.write(f'{tag}_{len(seen)}={tok}\n')
        # Standard boundaries (LE u32)
        for bv in [0, 1, 0xFF, 0x100, 0xFFF, 0x1000, 0xFFFF, 0x10000,
                   0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]:
            emit(struct.pack("<I", bv), "b32")
        # === CRITICAL AUDIT FINDINGS ===
        # #1: Compound WRITE OOB — DataOffset past sub-request (values > 112) — LE u16
        for v in [112, 113, 128, 200, 255, 256, 512]:
            emit(struct.pack("<H", v), "off16")
        # #2: AllocationSize overflow — values near 0xFFFFFFFFFFFFFE00 — LE u64
        for v in [0xFFFFFFFFFFFFFE00, 0xFFFFFFFFFFFFFE01, 0xFFFFFFFFFFFFFDFF,
                  0xFFFFFFFFFFFFFF00, 0xFFFFFFFFFFFFFFFF]:
            emit(struct.pack("<Q", v), "alloc64")
        # #3: loff_t signed overflow — Offset near LLONG_MAX + NEGATIVE — LE u64
        for v in [0x7FFFFFFFFFFFFFF0, 0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFE,
                  0x7FFFFFFFFFFFF000, 0x7FFFFFFFFFFF0000,
                  0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFF0000,
                  0x8000000000000001, 0x8000000000000000]:
            emit(struct.pack("<Q", v), "loff64")
        # #5: DENY ACE bypass — FILE_MAXIMAL_ACCESS = 0x02000000
        emit(struct.pack("<I", 0x02000000), "maxacc")
        # Extra entries (already-escaped or ascii keyword tokens: pass through)
        if extra_entries:
            for e in extra_entries:
                f.write(f'"{e}"\n')
        # Value pool — emit BOTH u32 and (when wide) u64 LE forms so the mutator can
        # splice a carried value into either field width.
        if value_pool:
            for v in value_pool[:40]:
                if 0 < v < 0x100000000:
                    emit(struct.pack("<I", v & 0xFFFFFFFF), "pool32")
                elif 0 < v <= 0xFFFFFFFFFFFFFFFF:
                    emit(struct.pack("<Q", v), "pool64")
    return str(dp)


def _copy_header_atomic(src, dst):
    """Stage a header into GRAIN_DIR race-safely — parallel P1 compiles all call this.
    Skip when dst is already current; else copy to a UNIQUE temp and os.replace (atomic),
    so a concurrent clang never reads a half-written header."""
    try:
        s = src.stat()
        if dst.exists():
            d = dst.stat()
            if d.st_size == s.st_size and d.st_mtime >= s.st_mtime:
                return                     # already staged and current
    except OSError:
        pass
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=str(dst.parent), prefix='.hdr.')
    os.close(fd)
    try:
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)               # atomic on the same fs
    except OSError:
        try: os.unlink(tmp)
        except OSError: pass


def _compile(name, src, value_pool=None, extra_dict=None):
    GRAIN_DIR.mkdir(exist_ok=True)
    # Stage headers (race-safe: parallel compiles share GRAIN_DIR).
    for hdr in ['common.h', 'ntlmv2.h']:
        hs = SCRIPT_DIR / hdr
        if hs.exists():
            _copy_header_atomic(hs, GRAIN_DIR / hdr)
    hs = SCRIPT_DIR.parent / 'libksmbdzzer.h'   # session API header
    if hs.exists():
        _copy_header_atomic(hs, GRAIN_DIR / 'libksmbdzzer.h')

    sp = GRAIN_DIR / f'grain_{name}.c'
    bp = GRAIN_DIR / f'grain_{name}'
    LIB_DIR = str(SCRIPT_DIR.parent)

    # COMPILE CACHE (kills the per-round recompile stall). The value_pool is fed
    # to libFuzzer via the .dict (_write_dict below), NOT baked into the C source,
    # so identical source ⇒ identical binary. Recompiling all ~34 harnesses every
    # round was starving round 2 (round-1 P1 finished, round-2 P1 rebuilt for
    # ~10min before its P2 could run). Skip clang when the source is byte-identical
    # to what produced the existing binary AND that binary is newer than every
    # build input (lib + headers). The dict is ALWAYS rewritten, so value
    # feed-forward is unaffected — only the redundant recompile is removed.
    old_src = sp.read_text() if sp.exists() else None
    sp.write_text(src)
    dp = _write_dict(name, extra_dict, value_pool)
    if bp.exists() and old_src == src:
        deps = [Path(LIB_DIR) / 'libksmbdzzer.so',
                SCRIPT_DIR / 'common.h', SCRIPT_DIR / 'ntlmv2.h',
                SCRIPT_DIR.parent / 'libksmbdzzer.h']
        try:
            btime = bp.stat().st_mtime
            if all((not d.exists()) or d.stat().st_mtime <= btime for d in deps):
                return (str(bp), dp)      # binary current — skip clang, keep new dict
        except OSError:
            pass

    link_flags = [f'-L{LIB_DIR}', '-lksmbdzzer', f'-Wl,-rpath,{LIB_DIR}']

    # Try with NTLMv2 (requires libcrypto)
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2', '-DUSE_NTLMV2',
         f'-I{GRAIN_DIR}', '-o', str(bp), str(sp)] + link_flags + ['-lcrypto'],
        capture_output=True)
    if r.returncode == 0:
        return (str(bp), dp)
    # Fallback: without NTLMv2 (guest auth only)
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2',
         f'-I{GRAIN_DIR}', '-o', str(bp), str(sp)] + link_flags,
        capture_output=True)
    return (str(bp), dp) if r.returncode == 0 else (None, None)


# ─── VFS-based grains (use mounted file, no socket needed) ──────────────────



def gen_raw_write_grain(vpool):
    """Raw SMB2 WRITE: Length=payload_len (reaches ksmbd_vfs_write) +
    trace-args/ret feedback: ret=0 means write SUCCEEDED → weight 3×."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
/* Dictionary learned from ret=0 (successful writes) */
static uint32_t good_lengths[64];
static uint64_t good_offsets[64];
static int ngood = 0;
static uint8_t persistent_fid[16];
static uint8_t stream_fid[16];
static int has_fid = 0, has_stream = 0;

static void create_targets(void) {
    uint8_t pdu[256], resp[256];
    /* Regular file */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='w'; pdu[122]='r';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r >= 144) { memcpy(persistent_fid, resp+128, 16); has_fid = 1; }
    /* Stream file */
    smb2_hdr(pdu, 5);
    b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='w'; pdu[122]='r'; pdu[124]=':'; pdu[126]='s';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 8;
    r = xact(pdu, 128, resp, sizeof(resp));
    if (r >= 144) { memcpy(stream_fid, resp+128, 16); has_stream = 1; }
}

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    create_targets();
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) { create_targets(); return 0; }
    if (!has_fid) { create_targets(); if (!has_fid) return 0; }
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* Select target: stream (50%) or regular file */
    uint8_t *fid = (data[0] & 0x40 && has_stream) ? stream_fid : persistent_fid;

    /* WRITE with Length = actual payload (persistent handle — no CREATE overhead!) */
    smb2_hdr(pdu, 0x0009);
    uint8_t *body = pdu + 64;
    *(uint16_t*)(body+0) = 49;
    *(uint16_t*)(body+2) = 112; /* DataOffset */

    /* Payload = fuzzer data after control bytes */
    size_t payload_len = size - 10;
    if (payload_len > 512) payload_len = 512;

    /* Length = EXACTLY payload_len (KEY FIX: passes ksmbd validation) */
    *(uint32_t*)(body+4) = payload_len;

    /* Offset: boundary-aware from fuzzer + learned good offsets */
    uint64_t write_off;
    if (data[0] & 0x80 && ngood > 0) {
        /* 50%: reuse an offset that previously succeeded (ret=0) */
        write_off = good_offsets[data[1] % ngood];
        /* Mutate slightly: ±1, ±4096 */
        int delta[] = {0, -1, 1, -4096, 4096, -4095, 4097};
        write_off += delta[data[2] % 7];
    } else {
        /* 50%: fresh from fuzzer — includes LLONG_MAX + negative boundaries */
        uint64_t bases[] = {0, 4095, 4096, 0xFFFF, 0x10000, 0xFFFFF,
                            0x7FFFFFFFFFFFFFF0ULL, 0x7FFFFFFFFFFFFFFEULL, 0x7FFFFFFFFFFFF000ULL,
                            0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFF0ULL, 0x8000000000000001ULL};
        write_off = bases[data[1] % 12];
        if (data[2] & 0x80) { memcpy(&write_off, data+3, 4); write_off &= 0x7FFFFFFFULL; }
    }
    *(uint64_t*)(body+8) = write_off;

    memcpy(body+16, fid, 16);
    *(uint32_t*)(body+32) = 0;                   /* Channel=0 */
    *(uint32_t*)(body+36) = 0;                   /* RemainingBytes */
    *(uint16_t*)(body+40) = 0;
    *(uint16_t*)(body+42) = 0;
    *(uint32_t*)(body+44) = data[9] & 0x01;      /* WRITE_THROUGH */

    /* Copy payload */
    memcpy(pdu+176, data+10, payload_len);

    int r = xact(pdu, 176 + payload_len, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); create_targets(); }

    /* === TRACE-ARGS/RET FEEDBACK === */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t hdr_w = df_buf[pos], pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (hdr_w >> 24) & 0xF; if (!nf) nf = 1;
        uint32_t rt = (hdr_w >> 28) & 0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;

        if (rt == 0xF && val == 0) {
            /* ret=0 = WRITE SUCCEEDED past validation → 3× weight */
            ctr[(h >> 12) % 4096] += 3;
            /* Learn: this offset+length combo works */
            if (ngood < 64) {
                good_offsets[ngood] = write_off;
                good_lengths[ngood] = payload_len;
                ngood++;
            }
        } else if (rt == 0xF) {
            /* ret != 0: negative errno = rejection path */
            ctr[(h ^ val) % 4096]++;
        } else {
            /* Entry: trace-args (PC + arg value) */
            h ^= val; h *= 0x100000001b3ULL;
            ctr[h % 4096]++;
        }
        pos += 3 + nf;
    }
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('raw_write', src, vpool)


def gen_read_after_write_grain(vpool):
    """WRITE then READ at adjacent offset — catches UAF/uninitialized leaks.
    Write-side bugs manifest when data read back is corrupted/leaked."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[600], resp[512];

    /* CREATE file inline */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='r'; pdu[122]='w';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int rc = xact(pdu, 124, resp, sizeof(resp));
    if (rc < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    size_t wlen = size - 8;
    if (wlen > 400) wlen = 400;
    uint32_t off;
    memcpy(&off, data, 4);
    off &= 0xFFFFF; /* 0-1MB range */

    /* WRITE */
    smb2_hdr(pdu, 0x0009);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
    *(uint32_t*)(body+4) = wlen; /* Length = payload */
    *(uint64_t*)(body+8) = off;
    memcpy(body+16, fid, 16);
    *(uint32_t*)(body+32) = 0; *(uint32_t*)(body+36) = 0;
    *(uint16_t*)(body+40) = 0; *(uint16_t*)(body+42) = 0;
    *(uint32_t*)(body+44) = 0;
    memcpy(pdu+176, data+8, wlen);
    xact(pdu, 176+wlen, resp, sizeof(resp));

    /* READ at offset ± delta (catches stale/leaked data) */
    int32_t delta;
    memcpy(&delta, data+4, 4);
    delta = (delta % 8193) - 4096; /* -4096 to +4096 */
    uint64_t read_off = (int64_t)off + delta;
    if ((int64_t)read_off < 0) read_off = 0;

    smb2_hdr(pdu, 0x0008); /* CMD_READ */
    body = pdu+64;
    *(uint16_t*)(body) = 49; /* StructureSize */
    body[2] = 0; body[3] = 0; /* Padding, Flags */
    *(uint32_t*)(body+4) = 4096; /* ReadLength */
    *(uint64_t*)(body+8) = read_off;
    memcpy(body+16, fid, 16);
    *(uint32_t*)(body+32) = 1; /* MinimumCount */
    *(uint32_t*)(body+36) = 0; /* Channel */
    *(uint32_t*)(body+40) = 0; /* RemainingBytes */
    *(uint16_t*)(body+44) = 0; *(uint16_t*)(body+46) = 0;
    xact(pdu, 64+49, resp, sizeof(resp));

    /* Trace-args/ret: ret=0 on read = data returned (check for leaks) */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    fb();
    return 0;
}
'''
    return _compile('read_after_write', src, vpool)


# ─── Socket-based grains (use grain_common.h auth + reconnect) ──────────────

def gen_dacl_grain(vpool):
    """Raw SMB2 SET_INFO(SecurityInformation) — hits smb2_set_info_sec → parse_sec_desc."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 20) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* CREATE file */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='d'; pdu[122]='a';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* Build SD: valid header + mutated DACL */
    uint8_t sd[512];
    memset(sd, 0, sizeof(sd));
    sd[0] = 1; /* revision */
    sd[2] = 0x04; sd[3] = 0x80; /* DACL_PRESENT | SELF_RELATIVE */
    uint32_t doff = 20;
    memcpy(&sd[16], &doff, 4); /* dacloffset */
    sd[20] = 2; /* acl revision */
    memcpy(&sd[22], data, 2);   /* MUTATE: acl size */
    memcpy(&sd[24], data+2, 2); /* MUTATE: num_aces */
    size_t ace_len = size - 4 > 480 ? 480 : size - 4;
    memcpy(&sd[28], data+4, ace_len);
    size_t sd_len = 28 + ace_len;

    /* SMB2 SET_INFO: InfoType=3(Security), InfoClass=0, AdditionalInfo=DACL(4) */
    smb2_hdr(pdu, 0x0011); /* CMD_SET_INFO */
    uint8_t *body = pdu + 64;
    *(uint16_t*)(body) = 33;    /* StructureSize */
    body[2] = 3;                /* InfoType = SMB2_0_INFO_SECURITY */
    body[3] = 0;                /* FileInfoClass (unused for security) */
    *(uint32_t*)(body+4) = sd_len; /* BufferLength */
    /* #4 AUDIT: BufferOffset — sometimes past sub-request to trigger compound OOB */
    *(uint16_t*)(body+8) = (data[0] & 0x10) ? 96 + (data[1] & 0x3F) : 96;
    *(uint32_t*)(body+12) = 0x04; /* AdditionalInfo = DACL_SECURITY_INFORMATION */
    memcpy(body+16, fid, 16); /* FileId */
    memcpy(pdu+96, sd, sd_len);

    r = xact(pdu, 96 + sd_len, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); }

    fb();
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('dacl_setinfo', src, vpool)


def gen_create_ctx_grain(vpool):
    """CREATE with mutated contexts + reconnect-on-failure."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
static int iter_count = 0;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[600], resp[256];
    smb2_hdr(pdu, 5); /* CMD_CREATE */
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+24) = 0x12019F;
    *(uint32_t*)(body+28) = 0x80;
    *(uint32_t*)(body+32) = 0x07;
    *(uint32_t*)(body+36) = 0x05;
    *(uint32_t*)(body+40) = 0x40;
    pdu[120] = 'f'; pdu[121] = 0;
    *(uint16_t*)(body+44) = 120;
    *(uint16_t*)(body+46) = 2;

    /* MUTATE: create contexts */
    uint16_t ctx_off = 124;
    *(uint32_t*)(body+48) = ctx_off;
    size_t ctx_len = size > 470 ? 470 : size;
    *(uint32_t*)(body+52) = ctx_len;
    memcpy(pdu+ctx_off, data, ctx_len);

    int r = xact(pdu, ctx_off+ctx_len, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); }
    else if (r >= 144) {
        /* Got file — close it to avoid handle leak */
        smb2_hdr(pdu, 6); /* CLOSE */
        *(uint16_t*)(pdu+64) = 24;
        memcpy(pdu+72, resp+128, 16);
        send_only(pdu, 88); /* fire-and-forget close */
    }

    /* Reconnect every 500 iterations to prevent handle exhaustion */
    if (++iter_count % 500 == 0) smb_reconnect(SHARE);

    fb();
    fb();
    return 0;
}
'''
    extra = [b'DH2Q'.hex(), b'DH2C'.hex(), b'RqLs'.hex(), b'MxAc'.hex(),
             b'QFid'.hex(), b'TWrp'.hex(), b'AAPL'.hex()]
    return _compile('create_ctx', src, vpool, extra)


def gen_ndr_grain(vpool):
    """NDR: valid BIND to srvsvc, then mutated REQUEST with coverage-guided opnum."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
static const char *IPC = "\\\\127.0.0.1\\IPC$";
static uint8_t pipe_fid[16];
static int pipe_ok = 0;
static uint32_t ipc_tid = 0;
static uint8_t opnum_hits[64]; /* coverage per opnum */

static int tree_connect_ipc(void) {
    uint8_t pdu[256], resp[512];
    smb2_hdr(pdu, 3);
    uint8_t *nb = pdu+64;
    *(uint16_t*)(nb) = 9;
    uint16_t pl = 0;
    for (int i = 0; IPC[i]; i++) { pdu[72+i*2]=IPC[i]; pdu[73+i*2]=0; pl+=2; }
    *(uint16_t*)(nb+4) = 72; *(uint16_t*)(nb+6) = pl;
    int r = xact(pdu, 72+pl, resp, sizeof(resp));
    if (r >= 40) { ipc_tid = *(uint32_t*)(resp+36); return 0; }
    return -1;
}

static int open_pipe(void) {
    uint8_t pdu[256], resp[512];
    uint32_t saved_tid = tid;
    tid = ipc_tid; /* use IPC$ tree */
    /* CREATE \srvsvc */
    smb2_hdr(pdu, 5);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+24) = 0x12019F;
    *(uint32_t*)(body+32) = 0x07;
    *(uint32_t*)(body+36) = 0x01;
    *(uint32_t*)(body+40) = 0x00200000;
    /* \srvsvc in UTF-16 */
    const char *pn = "\\srvsvc";
    uint16_t nl = 0;
    for (int i=0; pn[i]; i++) { pdu[120+i*2]=pn[i]; pdu[121+i*2]=0; nl+=2; }
    *(uint16_t*)(body+44) = 120; *(uint16_t*)(body+46) = nl;
    int r = xact(pdu, 120+nl, resp, sizeof(resp));
    if (r >= 144) { memcpy(pipe_fid, resp+128, 16); pipe_ok = 1; }
    tid = saved_tid; /* restore original tree */
    return pipe_ok ? 0 : -1;
}

static int do_bind(void) {
    /* DCE/RPC BIND to srvsvc UUID: 4b324fc8-1670-01d3-1278-5a47bf6ee188 */
    uint8_t bind[72];
    memset(bind, 0, sizeof(bind));
    bind[0]=5; bind[1]=0; bind[2]=11; bind[3]=3; /* ver=5.0, type=bind, flags=first|last */
    bind[4]=0x10; /* data repr LE */
    *(uint16_t*)(bind+8) = 72; /* frag_length */
    *(uint32_t*)(bind+12) = 1; /* call_id */
    *(uint16_t*)(bind+16) = 4280; /* max_xmit */
    *(uint16_t*)(bind+18) = 4280; /* max_recv */
    /* context list: 1 item */
    bind[24] = 1; /* num_ctx_items */
    /* context[0]: srvsvc UUID */
    uint8_t uuid[] = {0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88};
    memcpy(bind+28, uuid, 16);
    *(uint16_t*)(bind+44) = 3; /* if_version */
    bind[48] = 1; /* num_transfer */
    /* NDR transfer syntax */
    uint8_t ndr_uuid[] = {0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60};
    memcpy(bind+52, ndr_uuid, 16);
    *(uint32_t*)(bind+68) = 2; /* syntax version */

    /* Send via IOCTL FSCTL_PIPE_TRANSCEIVE */
    uint8_t pdu[256], resp[512];
    smb2_hdr(pdu, 0x000B); /* IOCTL */
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+4) = 0x0011C017; /* FSCTL_PIPE_TRANSCEIVE */
    memcpy(body+8, pipe_fid, 16);
    *(uint32_t*)(body+24) = 120; /* InputOffset */
    *(uint32_t*)(body+28) = sizeof(bind); /* InputCount */
    *(uint32_t*)(body+32) = 4096; /* MaxInputResponse */
    *(uint32_t*)(body+40) = 4096; /* MaxOutputResponse */
    *(uint32_t*)(body+44) = 1; /* Flags = IS_FSCTL */
    memcpy(pdu+120, bind, sizeof(bind));
    return xact(pdu, 120+sizeof(bind), resp, sizeof(resp)) > 0 ? 0 : -1;
}

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    if (tree_connect_ipc() < 0 || open_pipe() < 0 || do_bind() < 0) _exit(1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || !pipe_ok) return 0;
    if (raw_sock < 0) {
        if (smb_reconnect(SHARE) < 0) return 0;
        if (open_pipe() < 0 || do_bind() < 0) return 0;
    }
    df_buf[0] = 0;

    /* Build DCE/RPC REQUEST with coverage-guided opnum */
    uint8_t rpc[300];
    memset(rpc, 0, sizeof(rpc));
    rpc[0] = 5; rpc[1] = 0; rpc[2] = 0; rpc[3] = 3; /* request, first|last */
    rpc[4] = 0x10; /* LE data repr */

    /* Pick opnum: bias toward ones that gained coverage */
    uint8_t opnum = data[0] % 32;
    /* If we have coverage data, bias toward high-hit opnums */
    uint8_t best = opnum;
    for (int i = 0; i < 32; i++) {
        if (opnum_hits[i] > opnum_hits[best]) best = i;
    }
    if (data[1] & 0x80) opnum = best; /* 50% chance: use best opnum */
    *(uint16_t*)(rpc+22) = opnum;

    /* Frag length = header(24) + payload */
    size_t payload_len = size - 2 > 250 ? 250 : size - 2;
    *(uint16_t*)(rpc+8) = 24 + payload_len;
    *(uint32_t*)(rpc+12) = mid; /* call_id */
    *(uint32_t*)(rpc+16) = payload_len; /* alloc_hint */
    memcpy(rpc+24, data+2, payload_len);

    /* IOCTL FSCTL_PIPE_TRANSCEIVE */
    uint8_t pdu[512], resp[512];
    smb2_hdr(pdu, 0x000B);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+4) = 0x0011C017;
    memcpy(body+8, pipe_fid, 16);
    size_t rpc_len = 24 + payload_len;
    *(uint32_t*)(body+24) = 120;
    *(uint32_t*)(body+28) = rpc_len;
    *(uint32_t*)(body+32) = 4096;
    *(uint32_t*)(body+40) = 4096;
    *(uint32_t*)(body+44) = 1;
    memcpy(pdu+120, rpc, rpc_len);

    int r = xact(pdu, 120+rpc_len, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); open_pipe(); do_bind(); }
    else {
        /* Track coverage per opnum */
        uint64_t n = df_buf[0];
        opnum_hits[opnum % 64] += (n > 10) ? 2 : 1;
    }

    fb();
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('ndr_rpc', src, vpool)


def gen_compound_grain(vpool):
    """WRITE+TRUNCATE+CLOSE compound race — most dangerous CVE pattern.
    Sends WRITE, then SET_INFO(EndOfFile=0) to truncate, then CLOSE.
    Race: write in progress while truncate invalidates pages → UAF."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* CREATE a fresh file each iteration (unique name from fuzzer) */
    char fname[16];
    __builtin_snprintf(fname, sizeof(fname), "wt%02x%02x", data[0], data[1]);
    smb2_hdr(pdu, 5);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+24) = 0x12019F;
    *(uint32_t*)(body+28) = 0x80;
    *(uint32_t*)(body+32) = 0x07;
    *(uint32_t*)(body+36) = 0x05;
    *(uint32_t*)(body+40) = 0x40;
    uint16_t nlen = 0;
    for (int i=0; fname[i]; i++) { pdu[120+i*2]=fname[i]; pdu[121+i*2]=0; nlen+=2; }
    *(uint16_t*)(body+44) = 120; *(uint16_t*)(body+46) = nlen;
    int r = xact(pdu, 120+nlen, resp, sizeof(resp));
    if (r < 144) return 0;
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* WRITE: data from fuzzer */
    size_t wlen = size - 4;
    if (wlen > 512) wlen = 512;
    uint32_t woff;
    memcpy(&woff, data+2, 4);
    woff &= 0xFFFF;

    smb2_hdr(pdu, 0x0009);
    body = pdu+64;
    *(uint16_t*)(body) = 49;
    /* #1 AUDIT: DataOffset — sometimes past sub-request boundary */
    uint16_t doff = (data[0] & 0x20) ? 112 + (data[1] & 0x7F) : 112;
    *(uint16_t*)(body+2) = doff;
    *(uint32_t*)(body+4) = wlen;
    *(uint64_t*)(body+8) = woff;
    memcpy(body+16, fid, 16);
    memset(body+32, 0, 16);
    memcpy(pdu+176, data+6, wlen > size-6 ? size-6 : wlen);
    xact(pdu, 176+wlen, resp, sizeof(resp)); /* fire-and-forget WRITE */

    /* #2 AUDIT: SET_INFO — alternate between AllocationSize overflow and truncate */
    smb2_hdr(pdu, 0x0011); /* SET_INFO */
    body = pdu+64;
    *(uint16_t*)(body) = 33;
    body[2] = 1; /* InfoType = FILE */
    if (data[0] & 0x40) {
        /* FileAllocationInformation (class=19) — overflow near 0xFFFFFFFFFFFFFE00 */
        body[3] = 19;
        *(uint32_t*)(body+4) = 8;
        *(uint16_t*)(body+8) = 96;
        *(uint32_t*)(body+12) = 0;
        memcpy(body+16, fid, 16);
        uint64_t alloc_vals[] = {0xFFFFFFFFFFFFFE00ULL, 0xFFFFFFFFFFFFFE01ULL,
                                 0xFFFFFFFFFFFFFF00ULL, 0xFFFFFFFFFFFFFFFFULL};
        *(uint64_t*)(pdu+96) = alloc_vals[data[1] & 0x03];
    } else {
        /* FileEndOfFileInformation (class=20) — truncate to zero (race) */
        body[3] = 20;
        *(uint32_t*)(body+4) = 8;
        *(uint16_t*)(body+8) = 96;
        *(uint32_t*)(body+12) = 0;
        memcpy(body+16, fid, 16);
        *(uint64_t*)(pdu+96) = 0;
    }
    xact(pdu, 104, resp, sizeof(resp));

    /* CLOSE immediately (races with pending write+truncate) */
    smb2_hdr(pdu, 6);
    body = pdu+64;
    *(uint16_t*)(body) = 24;
    *(uint16_t*)(body+2) = 0;
    memcpy(body+8, fid, 16);
    xact(pdu, 88, resp, sizeof(resp)); /* wait for close */

    /* Trace-args/ret feedback */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('compound', src, vpool)


def gen_write_lock_race_grain(vpool):
    """LOCK(blocking) + CANCEL race — triggers UAF in deferred lock cleanup (CVE revert)."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* CREATE file */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='l'; pdu[122]='c';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    uint32_t lock_off, lock_len;
    memcpy(&lock_off, data, 4); lock_off &= 0xFFFF;
    memcpy(&lock_len, data+4, 4); lock_len = (lock_len & 0xFFF) + 1;

    /* Step 1: Take an exclusive lock (FAIL_IMMEDIATELY so it succeeds) */
    smb2_hdr(pdu, 0x000A);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 48; *(uint16_t*)(body+2) = 1;
    *(uint32_t*)(body+4) = 0;
    memcpy(body+8, fid, 16);
    *(uint64_t*)(body+24) = lock_off;
    *(uint64_t*)(body+32) = lock_len;
    *(uint32_t*)(body+40) = 0x03; /* EXCLUSIVE | FAIL_IMMEDIATELY */
    *(uint32_t*)(body+44) = 0;
    xact(pdu, 64+48, resp, sizeof(resp));

    /* Step 2: Request BLOCKING lock on overlapping range (will DEFER) */
    uint64_t saved_mid = mid; /* save MID for cancel */
    smb2_hdr(pdu, 0x000A);
    body = pdu+64;
    *(uint16_t*)(body) = 48; *(uint16_t*)(body+2) = 1;
    *(uint32_t*)(body+4) = 0;
    memcpy(body+8, fid, 16);
    *(uint64_t*)(body+24) = lock_off;
    *(uint64_t*)(body+32) = lock_len + 1; /* overlapping → blocks */
    *(uint32_t*)(body+40) = 0x01; /* EXCLUSIVE (NO FAIL_IMMEDIATELY → blocks/defers) */
    *(uint32_t*)(body+44) = 0;
    send_only(pdu, 64+48); /* fire-and-forget — this will DEFER */

    /* Step 3: Immediately send SMB2_CANCEL targeting the deferred lock */
    smb2_hdr(pdu, 0x000C); /* CMD_CANCEL */
    /* Cancel uses the MID of the request to cancel */
    *(uint64_t*)(pdu+24) = saved_mid - 1; /* MID of the blocking lock */
    *(uint16_t*)(pdu+64) = 4; /* StructureSize */
    send_only(pdu, 68);

    /* Step 4: CLOSE (races with cancel cleanup — triggers UAF) */
    smb2_hdr(pdu, 6);
    body = pdu+64;
    *(uint16_t*)(body) = 24;
    memcpy(body+8, fid, 16);
    xact(pdu, 88, resp, sizeof(resp));

    /* Trace-args/ret feedback */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('write_lock_race', src, vpool)


def gen_priv_bypass_grain(vpool):
    """Opens file with RESTRICTED access, then attempts write/FSCTL operations.
    Detects permission bypass: if ret=0 on a denied operation → logic bug."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\privtest";

/* FSCTL codes */
#define FSCTL_SET_ZERO_DATA   0x000980C8
#define FSCTL_SET_SPARSE      0x000900C4
#define FSCTL_DUP_EXTENTS     0x00098344

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* CREATE with RESTRICTED access (READ-only, no WRITE/DELETE/DAC) */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    /* DesiredAccess: only FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE */
    uint32_t restricted_access = 0x00100081; /* READ_DATA|READ_ATTR|SYNCHRONIZE */
    /* Mutate: sometimes add bits that SHOULDN'T grant write */
    if (data[0] & 0x20) restricted_access |= 0x00000080; /* READ_EA */
    if (data[0] & 0x10) restricted_access |= 0x00020000; /* READ_CONTROL */
    *(uint32_t*)(b2+24) = restricted_access;
    *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; /* ShareAccess=ALL */
    *(uint32_t*)(b2+36) = 0x05; /* FILE_OPEN_IF */
    *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='p'; pdu[122]='b';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* Now attempt WRITE operations that SHOULD FAIL (no WRITE access) */
    uint8_t op = data[1] % 9;
    int bypassed = 0;

    switch (op) {
    case 0: { /* SMB2_WRITE — should fail with STATUS_ACCESS_DENIED */
        smb2_hdr(pdu, 0x0009);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
        *(uint32_t*)(body+4) = 64; /* Length */
        *(uint64_t*)(body+8) = 0;
        memcpy(body+16, fid, 16);
        memset(body+32, 0, 16);
        memcpy(pdu+176, data+2, size-2 > 64 ? 64 : size-2);
        r = xact(pdu, 240, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 1: { /* SET_INFO(FileEndOfFile) — truncate should fail */
        smb2_hdr(pdu, 0x0011);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 33; body[2] = 1; body[3] = 20;
        *(uint32_t*)(body+4) = 8; *(uint16_t*)(body+8) = 96;
        *(uint32_t*)(body+12) = 0;
        memcpy(body+16, fid, 16);
        *(uint64_t*)(pdu+96) = 0;
        r = xact(pdu, 104, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 2: { /* FSCTL_SET_ZERO_DATA — should fail */
        smb2_hdr(pdu, 0x000B); /* IOCTL */
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 57;
        *(uint32_t*)(body+4) = FSCTL_SET_ZERO_DATA;
        memcpy(body+8, fid, 16);
        *(uint32_t*)(body+24) = 120; /* InputOffset */
        *(uint32_t*)(body+28) = 16;  /* InputCount */
        *(uint32_t*)(body+32) = 0; *(uint32_t*)(body+40) = 0;
        *(uint32_t*)(body+44) = 1; /* IS_FSCTL */
        /* FileZeroDataInfo: offset + beyond */
        *(uint64_t*)(pdu+120) = 0; *(uint64_t*)(pdu+128) = 4096;
        r = xact(pdu, 136, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 3: { /* FSCTL_SET_SPARSE — should fail */
        smb2_hdr(pdu, 0x000B);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 57;
        *(uint32_t*)(body+4) = FSCTL_SET_SPARSE;
        memcpy(body+8, fid, 16);
        *(uint32_t*)(body+24) = 120; *(uint32_t*)(body+28) = 1;
        *(uint32_t*)(body+32) = 0; *(uint32_t*)(body+40) = 0;
        *(uint32_t*)(body+44) = 1;
        pdu[120] = 1; /* SetSparse = TRUE */
        r = xact(pdu, 121, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 4: { /* SET_INFO(Security) — should fail without WRITE_DAC */
        smb2_hdr(pdu, 0x0011);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 33; body[2] = 3; body[3] = 0;
        *(uint32_t*)(body+4) = 20; *(uint16_t*)(body+8) = 96;
        *(uint32_t*)(body+12) = 0x04; /* DACL */
        memcpy(body+16, fid, 16);
        /* Minimal SD */
        memset(pdu+96, 0, 20); pdu[96] = 1; pdu[98] = 4; pdu[99] = 0x80;
        r = xact(pdu, 116, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 5: { /* SET_INFO(FileLink) — should fail without DELETE */
        smb2_hdr(pdu, 0x0011);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 33; body[2] = 1; body[3] = 11; /* FileLinkInformation */
        *(uint32_t*)(body+4) = 24; *(uint16_t*)(body+8) = 96;
        *(uint32_t*)(body+12) = 0;
        memcpy(body+16, fid, 16);
        /* Link info: ReplaceIfExists=0, FileName="lnk" */
        memset(pdu+96, 0, 24);
        pdu[116] = 'l'; pdu[118] = 'n'; pdu[120] = 'k';
        *(uint32_t*)(pdu+104) = 6; /* FileNameLength */
        r = xact(pdu, 122, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 6: { /* SMB2_LOCK — spec requires WRITE for exclusive, ksmbd doesn't check! */
        smb2_hdr(pdu, 0x000A);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 48; *(uint16_t*)(body+2) = 1;
        *(uint32_t*)(body+4) = 0;
        memcpy(body+8, fid, 16);
        *(uint64_t*)(body+24) = 0;     /* Offset */
        *(uint64_t*)(body+32) = 4096;  /* Length */
        *(uint32_t*)(body+40) = 0x03;  /* EXCLUSIVE | FAIL_IMMEDIATELY */
        r = xact(pdu, 64+48, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 7: { /* FSCTL_QUERY_ALLOCATED_RANGES — no READ check! */
        smb2_hdr(pdu, 0x000B); /* IOCTL */
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 57;
        *(uint32_t*)(body+4) = 0x000940CF; /* FSCTL_QUERY_ALLOCATED_RANGES */
        memcpy(body+8, fid, 16);
        *(uint32_t*)(body+24) = 120; *(uint32_t*)(body+28) = 16;
        *(uint32_t*)(body+32) = 0; *(uint32_t*)(body+40) = 4096;
        *(uint32_t*)(body+44) = 1;
        /* FileOffset=0, Length=0x7FFFFFFF */
        *(uint64_t*)(pdu+120) = 0;
        *(uint64_t*)(pdu+128) = 0x7FFFFFFF;
        r = xact(pdu, 136, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        break;
    }
    case 8: { /* DELETE_ON_CLOSE without DELETE — confirmed spec violation! */
        /* Close current handle first */
        smb2_hdr(pdu, 6);
        uint8_t *cb = pdu+64; *(uint16_t*)(cb) = 24; memcpy(cb+8, fid, 16);
        xact(pdu, 88, resp, sizeof(resp));
        /* Re-open with READ + DELETE_ON_CLOSE (no FILE_DELETE in access) */
        smb2_hdr(pdu, 5);
        uint8_t *b3 = pdu+64;
        *(uint16_t*)(b3) = 57;
        *(uint32_t*)(b3+24) = 0x00000001; /* FILE_READ_DATA only */
        *(uint32_t*)(b3+28) = 0x80;
        *(uint32_t*)(b3+32) = 0x07;
        *(uint32_t*)(b3+36) = 0x01; /* FILE_OPEN */
        *(uint32_t*)(b3+40) = 0x1040; /* NON_DIR | DELETE_ON_CLOSE */
        pdu[120]='p'; pdu[122]='b';
        *(uint16_t*)(b3+44) = 120; *(uint16_t*)(b3+46) = 4;
        r = xact(pdu, 124, resp, sizeof(resp));
        if (r > 0 && *(uint32_t*)(resp+8) == 0) bypassed = 1;
        if (r >= 144) memcpy(fid, resp+128, 16); /* update fid for CLOSE below */
        break;
    }
    }

    /* CLOSE */
    smb2_hdr(pdu, 6);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 24; memcpy(body+8, fid, 16);
    xact(pdu, 88, resp, sizeof(resp));

    /* Feedback: BYPASSED = 10x weight (logic bug!) */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) {
            ctr[(h>>12)%4096] += bypassed ? 10 : 3; /* 10x if bypass! */
        } else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('priv_bypass', src, vpool)


def gen_dh_trust_grain(vpool):
    """Cross-boundary trust: attempts DH2C reconnect with forged/random CreateGuid.
    Tests if ksmbd validates the reconnecting user matches the original opener.
    If ret=0 → trust boundary bypass (privilege escalation via stale daccess)."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 24) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* Attempt DH2C (durable handle reconnect v2) with forged CreateGuid.
     * If ksmbd doesn't validate the owner, this creates a file handle
     * with another user's daccess permissions → privilege bypass. */
    smb2_hdr(pdu, 5); /* CREATE */
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x01; /* FILE_OPEN */
    *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='d'; pdu[122]='h';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;

    /* DH2C create context (reconnect attempt) */
    uint8_t ctx[48];
    memset(ctx, 0, sizeof(ctx));
    /* Context header */
    *(uint32_t*)(ctx+0) = 0;    /* Next */
    *(uint16_t*)(ctx+4) = 16;   /* NameOffset */
    *(uint16_t*)(ctx+6) = 4;    /* NameLength */
    *(uint16_t*)(ctx+10) = 32;  /* DataOffset */
    *(uint32_t*)(ctx+12) = 16;  /* DataLength (just the PersistentFileId) */
    memcpy(ctx+16, "DH2C", 4); /* Context name */
    /* DH2C data: PersistentFileId from fuzzer (forged) */
    memcpy(ctx+32, data, 16);

    uint16_t ctx_off = 128;
    *(uint32_t*)(b2+48) = ctx_off;
    *(uint32_t*)(b2+52) = sizeof(ctx);
    memcpy(pdu+ctx_off, ctx, sizeof(ctx));

    int r = xact(pdu, ctx_off + sizeof(ctx), resp, sizeof(resp));
    if (r > 0) {
        uint32_t st = *(uint32_t*)(resp+8);
        if (st == 0) {
            /* SUCCESS with forged DH2C = TRUST BOUNDARY BYPASS! */
            ctr[0] += 100; /* massive signal */
        }
    }

    /* Also try with random FileId + CreateGuid combinations from fuzzer */
    smb2_hdr(pdu, 5);
    b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x01;
    *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='d'; pdu[122]='h';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    /* DH2C with different data from fuzzer */
    memcpy(ctx+32, data+8, 16); /* different forged ID */
    *(uint32_t*)(b2+48) = ctx_off;
    *(uint32_t*)(b2+52) = sizeof(ctx);
    memcpy(pdu+ctx_off, ctx, sizeof(ctx));
    r = xact(pdu, ctx_off + sizeof(ctx), resp, sizeof(resp));
    if (r > 0 && *(uint32_t*)(resp+8) == 0) ctr[1] += 100;

    /* Feedback */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint64_t h = pc * 0x517cc1b727220a95ULL ^ val;
        ctr[h%4096]++;
        pos += 3 + nf;
    }
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('dh_trust', src, vpool)


def gen_mt_race_grain(vpool):
    """Multi-threaded: persistent handle, thread A writes concurrently,
    thread B sends CLOSE on same fid. Targets concurrent UAF in ksmbd_work."""
    src = r'''#include "common.h"
#include <pthread.h>
static const char *SHARE = "\\\\127.0.0.1\\share";

static uint8_t persistent_fid[16];
static volatile int racing = 0;
static int has_fid = 0;
static uint8_t g_payload[512];
static size_t g_payload_len = 0;
static uint64_t g_offset = 0;

static void create_file(void) {
    uint8_t pdu[256], resp[256];
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='m'; pdu[122]='t';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r >= 144) { memcpy(persistent_fid, resp+128, 16); has_fid = 1; }
}

/* Thread B: sends CLOSE while thread A writes */
static void *closer_thread(void *arg) {
    while (!racing) {}
    uint8_t pdu[128];
    memset(pdu, 0, sizeof(pdu));
    memcpy(pdu, "\xfeSMB", 4);
    *(uint16_t*)(pdu+4) = 64; *(uint16_t*)(pdu+6) = 1;
    *(uint16_t*)(pdu+12) = 6; /* CMD_CLOSE */
    *(uint16_t*)(pdu+14) = 31;
    *(uint64_t*)(pdu+24) = mid + 100;
    *(uint32_t*)(pdu+36) = tid;
    *(uint64_t*)(pdu+40) = sid;
    *(uint16_t*)(pdu+64) = 24;
    memcpy(pdu+72, persistent_fid, 16);
    send_only(pdu, 88);
    has_fid = 0; /* fid is now invalid */
    return NULL;
}

/* Thread C: sends WRITE while CLOSE is racing */
static void *writer_thread(void *arg) {
    while (!racing) {}
    uint8_t pdu[700];
    for (int i = 0; i < 5; i++) {
        smb2_hdr(pdu, 9);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
        *(uint32_t*)(body+4) = g_payload_len;
        *(uint64_t*)(body+8) = g_offset + i * 64;
        memcpy(body+16, persistent_fid, 16);
        memset(body+32, 0, 16);
        memcpy(pdu+176, g_payload, g_payload_len);
        send_only(pdu, 176+g_payload_len);
    }
    return NULL;
}

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    create_file();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    if (!has_fid) create_file();
    df_buf[0] = 0;   /* reset kernel coverage for this iteration */
    if (!has_fid) return 0;
    df_buf[0] = 0;

    /* Copy values to globals for concurrent threads */
    g_payload_len = size > 256 ? 256 : size;
    memcpy(g_payload, data, g_payload_len);
    
    /* Random write offset (including boundaries) */
    uint64_t bases[] = {0, 4095, 4096, 0xFFFF, 0x10000, 0xFFFFF,
                        0x7FFFFFFFFFFFFFF0ULL, 0x7FFFFFFFFFFFFFFEULL, 0x7FFFFFFFFFFFF000ULL,
                        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFF0ULL, 0x8000000000000001ULL};
    g_offset = bases[data[0] % 12];

    racing = 0;
    pthread_t th1, th2;
    pthread_create(&th1, NULL, closer_thread, NULL);
    pthread_create(&th2, NULL, writer_thread, NULL);
    
    /* Start the concurrent race */
    racing = 1;
    
    /* Main thread concurrently issues CANCEL to mess up ksmbd's request queue */
    if (data[1] & 0x01) {
        uint8_t pdu[64];
        smb2_hdr(pdu, 0x000C); /* CMD_CANCEL */
        send_only(pdu, 64);
    }

    pthread_join(th1, NULL);
    pthread_join(th2, NULL);

    /* Drain response buffers */
    uint8_t resp[256];
    struct timeval tv = {.tv_sec=0, .tv_usec=20000};
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (recv(raw_sock, resp, sizeof(resp), 0) > 0) {}
    tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Always recreate targets */
    create_file();
    fb();   /* feed this iteration's kernel coverage to libFuzzer */
    return 0;
}
'''
    GRAIN_DIR.mkdir(exist_ok=True)
    sp = GRAIN_DIR / 'grain_mt_race.c'
    bp = GRAIN_DIR / 'grain_mt_race'
    dp = _write_dict('mt_race', None, vpool)
    # Copy headers
    for hdr in ['common.h', 'ntlmv2.h']:
        hdr_src = SCRIPT_DIR / hdr
        if hdr_src.exists():
            import shutil; shutil.copy2(hdr_src, GRAIN_DIR / hdr)
    sp.write_text(src)
    LIB_DIR = str(SCRIPT_DIR.parent)
    link_flags = [f'-L{LIB_DIR}', '-lksmbdzzer', f'-Wl,-rpath,{LIB_DIR}']
    # Link with -lpthread
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2', '-DUSE_NTLMV2',
         f'-I{GRAIN_DIR}', '-o', str(bp), str(sp)] + link_flags + ['-lcrypto', '-lpthread'],
        capture_output=True)
    if r.returncode != 0:
        r = subprocess.run(
            ['clang', '-fsanitize=fuzzer', '-O2',
             f'-I{GRAIN_DIR}', '-o', str(bp), str(sp)] + link_flags + ['-lpthread'],
            capture_output=True)
    return (str(bp), dp) if r.returncode == 0 else (None, None)


def gen_spnego_grain(vpool):
    """Mutated SPNEGO/Kerberos AP_REQ tokens in SESSION_SETUP — exercises auth.c parsing."""
    src = r'''#include "common.h"
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0) _exit(1);
    /* Just NEGOTIATE — we'll send mutated SESSION_SETUP repeatedly */
    uint8_t pdu[128], resp[1024];
    smb2_hdr(pdu, 0);
    uint8_t *nb = pdu+64;
    *(uint16_t*)(nb) = 36; nb[2]=1; nb[4]=1;
    *(uint16_t*)(nb+36) = 0x0300;
    xact(pdu, 64+38, resp, sizeof(resp));
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    if (raw_sock < 0) {
        if (smb_connect() < 0) return 0;
        uint8_t pdu[128], resp[1024];
        smb2_hdr(pdu, 0);
        uint8_t *nb = pdu+64;
        *(uint16_t*)(nb) = 36; nb[2]=1; nb[4]=1;
        *(uint16_t*)(nb+36) = 0x0300;
        xact(pdu, 64+38, resp, sizeof(resp));
    }
    df_buf[0] = 0;

    /*
     * Build SESSION_SETUP with mutated SPNEGO token.
     * Structure: SPNEGO OID wrapper → Kerberos AP_REQ (mutated from fuzzer)
     *
     * Valid SPNEGO prefix so ksmbd enters the parsing path:
     *   0x60 [len] 0x06 0x06 2b 06 01 05 05 02 (SPNEGO OID)
     *   0xa0 [len] 0x30 [len] ...               (negTokenInit)
     */
    uint8_t pdu[600], resp[512];
    smb2_hdr(pdu, 1); /* SESSION_SETUP */
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 25;
    body[3] = 1; /* SecurityMode */

    uint8_t token[512];
    size_t tlen = 0;

    /* SPNEGO OID header (fixed) */
    uint8_t spnego_hdr[] = {
        0x60, 0x00, /* Application[0] — length patched below */
        0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, /* OID 1.2.840.113554.1.2.2 = SPNEGO */
        0xa0, 0x00, /* context[0] — length patched below */
        0x30, 0x00, /* SEQUENCE — length patched below */
        /* mechTypes */
        0xa0, 0x0e, 0x30, 0x0c,
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, /* NTLMSSP OID */
        /* mechToken (a2) */
        0xa2, 0x00  /* length patched below */
    };
    memcpy(token, spnego_hdr, sizeof(spnego_hdr));
    tlen = sizeof(spnego_hdr);

    /* MUTATE: mechToken body — fuzzer provides fake Kerberos AP_REQ / NTLMSSP */
    size_t mech_len = size > 450 ? 450 : size;
    memcpy(token + tlen, data, mech_len);
    tlen += mech_len;

    /* Patch lengths */
    token[1] = tlen - 2;        /* outer Application length */
    token[11] = tlen - 12;      /* context[0] length */
    token[13] = tlen - 14;      /* SEQUENCE length */
    token[sizeof(spnego_hdr)-1] = mech_len; /* mechToken length */

    uint16_t sec_off = 88;
    *(uint16_t*)(body+12) = sec_off;
    *(uint16_t*)(body+14) = tlen;
    memcpy(pdu+sec_off, token, tlen);

    int r = xact(pdu, sec_off + tlen, resp, sizeof(resp));
    if (r < 0) {
        close(raw_sock); raw_sock = -1;
    }

    fb();
    fb();
    return 0;
}
'''
    extra = [
        '4e544c4d53535000',  # NTLMSSP\0
        '6082',              # Application[0] long form
        '3082',              # SEQUENCE long form
        'a003',              # Kerberos version tag
    ]
    return _compile('spnego_auth', src, vpool, extra)



def gen_setinfo_meta_grain(vpool):
    """Meta-template: SMB2 SET_INFO across every write-side FileInformationClass.
    The fuzz input selects the class (FileEndOfFile=20→truncate, Allocation=19,
    Rename=10, Link=11, Disposition=13, FullEa=15, ValidDataLength=39, ...) and
    supplies the class buffer, driving set_end_of_file_info / set_rename_info /
    set_file_disposition_info / smb2_set_ea → ksmbd_vfs_{truncate,setxattr,
    rename}. Class set derived from MS-SMB2 / MS-FSCC (WindowsProtocolTestSuites).
    """
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
/* Write-side FileInformationClass values (MS-FSCC 2.4) */
static const uint8_t CLS[] = {10,11,13,14,15,16,19,20,39};
static int iter_count = 0;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];
    /* CREATE a target file with full access so SET_INFO reaches the VFS path */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x1301BF;  /* R/W/DELETE/attrs */
    *(uint32_t*)(b2+28) = 0x80; *(uint32_t*)(b2+32) = 0x07;
    *(uint32_t*)(b2+36) = 0x03;      /* FILE_OPEN_IF */
    *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='s'; pdu[122]='i';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* SET_INFO with a fuzz-selected write-side class + mutated buffer */
    smb2_hdr(pdu, 0x0011);           /* CMD_SET_INFO */
    uint8_t *body = pdu + 64;
    *(uint16_t*)(body) = 33;         /* StructureSize */
    body[2] = (data[0] & 0x20) ? ((data[1] & 3) + 1) : 1; /* mostly InfoType=FILE */
    body[3] = CLS[data[0] % (uint8_t)sizeof(CLS)];         /* FileInfoClass */
    size_t blen = size - 2; if (blen > 560) blen = 560;
    *(uint32_t*)(body+4) = (uint32_t)blen;   /* BufferLength */
    *(uint16_t*)(body+8) = 96;               /* BufferOffset (pdu+96) */
    *(uint32_t*)(body+12) = 0;               /* AdditionalInformation */
    memcpy(body+16, fid, 16);                /* FileId */
    memcpy(pdu+96, data+2, blen);            /* MUTATE: class buffer */
    r = xact(pdu, 96 + blen, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); }

    /* CLOSE to avoid handle leak */
    smb2_hdr(pdu, 6);
    *(uint16_t*)(pdu+64) = 24;
    memcpy(pdu+72, fid, 16);
    send_only(pdu, 88);

    if (++iter_count % 500 == 0) smb_reconnect(SHARE);
    fb();
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('setinfo_meta', src, vpool)


def gen_fsctl_meta_grain(vpool):
    """Meta-template: SMB2 IOCTL across the FSCTL codes ksmbd dispatches on, with
    a fuzz-selected code + mutated input buffer. Hits fsctl_set_zero_data,
    copychunk, duplicate_extents, set_sparse, query_allocated_ranges, set/get
    compression, object-id, resume-key, plus a few unhandled codes to exercise
    the -EOPNOTSUPP boundary. Codes from MS-SMB2 CtlCode_Values (WPTS).
    """
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
/* FSCTL control codes ksmbd's smb2_ioctl() switches on (+ a few it rejects) */
static const uint32_t FSCTL[] = {
    0x000980C8u /*SET_ZERO_DATA*/, 0x00098344u /*DUPLICATE_EXTENTS*/,
    0x001440F2u /*COPYCHUNK*/,     0x001480F2u /*COPYCHUNK_WRITE*/,
    0x000900C4u /*SET_SPARSE*/,    0x000940CFu /*QUERY_ALLOCATED_RANGES*/,
    0x0009C040u /*SET_COMPRESSION*/,0x0009003Cu /*GET_COMPRESSION*/,
    0x000900C0u /*CREATE_OR_GET_OBJECT_ID*/, 0x00140078u /*REQUEST_RESUME_KEY*/,
    0x000983E8u /*DUP_EXTENTS_EX(unhandled)*/, 0x000900A4u /*SET_REPARSE(unhandled)*/,
    0x00098208u /*FILE_LEVEL_TRIM(unhandled)*/
};
static int iter_count = 0;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[1200], resp[256];
    /* CREATE a target file with full access */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x1301BF; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x03; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='f'; pdu[122]='c';
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* IOCTL: fuzz-selected FSCTL + mutated input buffer (struct smb2_ioctl_req) */
    smb2_hdr(pdu, 0x000B);            /* CMD_IOCTL */
    uint8_t *body = pdu + 64;
    *(uint16_t*)(body) = 57;          /* StructureSize */
    *(uint32_t*)(body+4) = FSCTL[data[0] % (uint8_t)(sizeof(FSCTL)/4)];
    memcpy(body+8, fid, 16);          /* Persistent+Volatile FileId */
    size_t ilen = size - 1; if (ilen > 1024) ilen = 1024;
    *(uint32_t*)(body+24) = 120;      /* InputOffset (pdu+120) */
    *(uint32_t*)(body+28) = (uint32_t)ilen; /* InputCount */
    *(uint32_t*)(body+44) = 4096;     /* MaxOutputResponse */
    *(uint32_t*)(body+48) = 1;        /* SMB2_0_IOCTL_IS_FSCTL */
    memcpy(pdu+120, data+1, ilen);    /* MUTATE: FSCTL input */
    r = xact(pdu, 120 + ilen, resp, sizeof(resp));
    if (r < 0) { smb_reconnect(SHARE); }

    smb2_hdr(pdu, 6);                 /* CLOSE */
    *(uint16_t*)(pdu+64) = 24;
    memcpy(pdu+72, fid, 16);
    send_only(pdu, 88);

    if (++iter_count % 500 == 0) smb_reconnect(SHARE);
    fb();
    GRAIN_ITER_END(); fb();
    return 0;
}
'''
    return _compile('fsctl_meta', src, vpool)


def gen_spec_grain(vpool):
    """Runtime-shapeable interpreter harness (opt-in via $GRAIN_SPEC).

    Unlike every other gen_* — which bakes its command+layout into the C source —
    this one is GENERIC: the C is fixed, and the PDU shape is loaded at startup from
    the text spec file named by $GRAIN_SPEC (parsed by spec_load() in common.h).
    Re-target the command or which fields are fuzzed by EDITING THE FILE and
    rerunning — no clang, and the compile cache keeps this binary forever (the
    source never changes). The libFuzzer input drives only the `fuzz` fields, so
    mutations stay structurally valid. Returns (None, None) — i.e. skipped — unless
    GRAIN_SPEC is set, so it never disturbs a normal campaign."""
    if not os.environ.get('GRAIN_SPEC'):
        return (None, None)
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
static struct pdu_spec g_spec;

int LLVMFuzzerInitialize(int *a, char ***b) {
    (void)a; (void)b;
    df_init();
    if (smb_setup(SHARE) < 0) _exit(1);
    const char *sp = getenv("GRAIN_SPEC");
    if (!sp || spec_load(&g_spec, sp) < 0) {
        pfz_err("[spec] load FAILED — set GRAIN_SPEC to a valid spec file\n");
        _exit(2);
    }
    pfz_err("[spec] loaded cmd=0x%x body_len=%u overlays=%d create=%s\n",
            g_spec.cmd, g_spec.body_len, g_spec.n_ov,
            g_spec.have_create ? g_spec.create_name : "(none)");
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    if (g_spec.have_create && !has_file) smb_create_file(g_spec.create_name);
    spec_run(&g_spec, data, size);
    fb();                    /* fold kcov-dataflow coverage into libFuzzer counters */
    GRAIN_ITER_END();
    return 0;
}
'''
    return _compile('spec', src, vpool)


def generate_all_grains(value_pool):
    """Generate all grain harnesses with value_pool injected into dicts."""
    vpool = list(value_pool)[:100] if value_pool else []
    grains = []
    # Only SOCKET-based raw-PDU grains: each establishes the valid negotiate+auth
    # prefix and fuzzes the target PDU, so kcov-dataflow coverage is comparable and
    # deep-by-construction (principle 4/9). The former VFS-direct grains
    # (vfs_write/stream/ea/lock) bypassed the SMB2 parser — shallow, alignment-gate
    # failures — and were removed; the write grain reaches the same VFS code via the
    # proper SMB2 path.
    gens = [gen_raw_write_grain, gen_read_after_write_grain,
            gen_dacl_grain, gen_create_ctx_grain,
            gen_ndr_grain, gen_compound_grain, gen_write_lock_race_grain,
            gen_priv_bypass_grain, gen_dh_trust_grain,
            gen_mt_race_grain, gen_spnego_grain,
            gen_setinfo_meta_grain, gen_fsctl_meta_grain,
            gen_spec_grain]   # opt-in, active only when $GRAIN_SPEC is set
    # Compile the raw grains in parallel too (same link+I/O-bound cost as the lib grains).
    from concurrent.futures import ThreadPoolExecutor, as_completed
    def _run(gen):
        try:
            result = gen(vpool)
            return result if result and result[0] else None
        except Exception:
            return None
    # Heartbeat here too (same reason as generate_grains — keep the log
    # advancing so the stall-watchdog doesn't kill a healthy raw-grain compile).
    grains = []
    done = 0; total = len(gens)
    with ThreadPoolExecutor(max_workers=min(len(gens), (os.cpu_count() or 8) * 2)) as tp:
        futs = {tp.submit(_run, gen): gen.__name__ for gen in gens}
        for fut in as_completed(futs):
            done += 1
            r = fut.result()
            if r:
                grains.append(r)
            print(f"    [P1 raw] {done}/{total} built ({futs[fut]})", flush=True)
    return grains


# ── Grain-v2 hybrid harness (P1/P2 grain) ──────────────────────────────────
# One libFuzzer harness per grain: it fuzzes with plain KCOV *path* coverage
# (cheap) for the bulk, and only when it SATURATES (no new path for STUCK_LIMIT
# iters) does the custom mutator capture the stuck point with trace-args/ret and
# drive the controlling input field through. Python never fuzzes — it launches
# this binary and reads results.
#
# TODO(next-step): MAXIMIZE THE KCOV-DATAFLOW ENGINE (the design conclusion).
#   1) DONE: mutate_i2s() is now a SHARED common.h helper (all 2/4/8-byte widths +
#      every struct field + observed RETURN values + widest-match len/off bias) and
#      is wired into THIS grain-v2 mutator (replaced the old 4-byte/fixed loop).
#   1b) REMAINING — roll mutate_i2s out to the 13 raw gen_* harnesses (they still
#      fuzz blind havoc). The drop-in is `GRAIN_I2S_MUTATOR()` (common.h), but each
#      raw harness must first add: a `static int g_stuck;` bumped in its
#      LLVMFuzzerTestOneInput (g_stuck=0 on new coverage else ++), and a
#      `run_target(data,size)` that (re)builds+sends its target PDU into df_buf.
#      Then paste GRAIN_I2S_MUTATOR() once. Mechanical but per-harness; keep a few
#      on plain havoc as a CONTROL to prove directed > havoc.
#   2) Consolidate the SINGLE-REQUEST gen_* (write/truncate/setxattr/query_dir/
#      setinfo/fsctl) into $GRAIN_SPEC specs (gen_spec_grain) to shrink the
#      recompile surface — add a procedure by writing a spec line, not a fn+clang.
#      Keep hand-written C only for STATEFUL ones (compound/mt_race/dh_trust/spnego).
#   GATE: do 1b/2 only AFTER one oracle-live full campaign shows coverage stalling
#   at value-gates (INVALID_PARAMETER on structurally-valid PDUs) — measure first.
_GRAIN_V2_TEMPLATE = r'''#define GRAIN_HAS_MUTATOR   /* v2 grain has its own LLVMFuzzerCustomMutator */
#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
extern size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);

#define STUCK_LIMIT 64
static uint8_t  g_seen[1 << 16];   /* global PC-hash bitmap → detect saturation */
static int      g_stuck = 0;

/* KCOV path coverage: fold df_buf PCs (NOT values) into libFuzzer counters, and
 * track whether any NEW path appeared (returns #new path bits). */
static int mark_path(void) {
    uint64_t n = df_buf[0], pos = 1; int newp = 0;
    __builtin_memset((void *)ctr, 0, sizeof(ctr));
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos + 1];
        uint32_t nf = (df_buf[pos] >> 24) & 0xF; if (!nf) nf = 1;
        uint32_t bit = (uint32_t)((pc * 0x9E3779B97F4A7C15ULL) >> 48) & 0xFFFF;
        ctr[bit & 4095]++;
        if (!(g_seen[bit >> 3] & (1u << (bit & 7)))) { g_seen[bit >> 3] |= (1u << (bit & 7)); newp++; }
        pos += 3 + nf;
    }
    return newp;
}

/* Build + send the RAW target PDU from `data` (fixed valid auth prefix in init). */
static int run_target(const uint8_t *data, size_t size) {
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return -1;
    df_buf[0] = 0;
    uint8_t pdu[2048], resp[1024]; uint8_t *b = pdu + 64; size_t blen = 0;
    smb2_hdr(pdu, __CMD__);
    __BODY__
    return xact(pdu, 64 + (int)__BLEN__, resp, sizeof(resp));
}

int LLVMFuzzerInitialize(int *a, char ***b2) { (void)a; (void)b2;
    df_init(); load_feedback();   /* arbiter g_fb: cross-round directed memory */
    if (smb_setup(SHARE) < 0) _exit(1); return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run_target(data, size);
    if (mark_path() > 0) g_stuck = 0; else g_stuck++;   /* saturation detector */
    return 0;
}

/* Cheap KCOV-guided mutation until stuck; then ONE dataflow-directed nudge via the
 * SHARED mutate_i2s() (all widths + struct fields + observed return values — the
 * engine-maximizing upgrade over the old 4-byte/fixed-boundary loop). */
size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize, unsigned seed) {
    if (g_stuck < STUCK_LIMIT)                       /* not stuck → cheap havoc */
        return LLVMFuzzerMutate(data, size, maxsize);
    run_target(data, size);                          /* refresh df_buf for THIS input */
    g_stuck = 0;
    return mutate_i2s(data, size, maxsize, seed);
}
'''


def gen_grain_v2(name, cmd, body_c, body_len_c):
    """Clean hybrid grain (all fuzzing in C). `body_c` fills `b` + sets `blen`."""
    src = (_GRAIN_V2_TEMPLATE
           .replace('__CMD__', str(cmd))
           .replace('__BODY__', body_c)
           .replace('__BLEN__', body_len_c))
    return _compile('v2_' + name, src)


def generate_v2_grains():
    """The clean trace-args/ret-driven grains. CREATE is the proving-case grain:
    its DesiredAccess/Disposition/Options ARE the values smb2_create_open_flags()
    observes — so the I2S mutator can find them in the input and drive them."""
    CREATE_BODY = r'''
    uint32_t acc = 0x0012019F, disp = 0x05, opt = 0x40;
    if (size >= 4)  memcpy(&acc,  data,     4);   /* DesiredAccess   (I2S target) */
    if (size >= 8)  memcpy(&disp, data + 4, 4);   /* CreateDisposition (I2S target) */
    if (size >= 12) memcpy(&opt,  data + 8, 4);   /* CreateOptions   (I2S target) */
    *(uint16_t *)b = 57; b[2] = 0; b[3] = 0;
    *(uint64_t *)(b + 8) = 0; *(uint64_t *)(b + 16) = 0;
    *(uint32_t *)(b + 24) = acc;
    *(uint32_t *)(b + 28) = 0x80;                 /* FileAttributes */
    *(uint32_t *)(b + 32) = 0x07;                 /* ShareAccess    */
    *(uint32_t *)(b + 36) = disp;
    *(uint32_t *)(b + 40) = opt;
    *(uint16_t *)(b + 44) = 120; *(uint16_t *)(b + 46) = 4;   /* Name @120, len 4 */
    pdu[120] = 'f'; pdu[121] = 0; pdu[122] = 'z'; pdu[123] = 0;
    { size_t cx = (size > 12) ? (size - 12) : 0; if (cx > 1800) cx = 1800;
      if (cx) { *(uint32_t *)(b + 48) = 124; *(uint32_t *)(b + 52) = (uint32_t)cx;
                memcpy(pdu + 124, data + 12, cx); }
      blen = 56 + 4 + cx; }
    '''
    out = []
    binp, d = gen_grain_v2('create', 5, CREATE_BODY, 'blen')
    if binp:
        out.append((binp, d))
    return out


def gen_grain(idx, name, vpool):
    src = '''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "libksmbdzzer.h"
/* GRAIN grain: normal scenario "%(name)s" (idx %(idx)d), fuzzer-parameterized. */
__attribute__((used, section("__libfuzzer_extra_counters"))) static uint8_t ctr[4096];
static int g_octet = 1;
int LLVMFuzzerInitialize(int *a, char ***b){ (void)a; (void)b;
    const char *ip = getenv("GRAIN_IP");
    if (ip){ const char *p = strrchr(ip, 46); if (p) g_octet = atoi(p + 1); }  /* 46='.' */
    if (pfz_init((unsigned long)g_octet) < 0) _exit(1);
    /* Establish pool FileIds so pool-based grains (copychunk/lease/compound/...)
       reach deep instead of bailing at g_pool_n<1. #4: report the ACTUAL pool
       readiness so a grain that stays shallow because fids<2 (raw guest auth or
       create failed) is visible as a harness gap, not mistaken for a hardened
       target. Captured by run_grains → "[!] PREREQ ...". */
    int _pn = pfz_pool_init_authed(2);
    pfz_err("POOL grain=%(name)s n=%%d fids=%%d\\n", _pn, pfz_pool_fids_ready());
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    static uint32_t feats[4096];
    pfz_grain_run(%(idx)d, data, (int)size);   /* deep libsmbclient op */
    int n = pfz_get_features(feats, 4096);      /* lib's coverage → counters */
    memset(ctr, 0, sizeof(ctr));
    for (int i = 0; i < n; i++) ctr[feats[i] & 4095]++;
    return 0;
}
/* Fleet-wide RedQueen/i2s: consult the lib's df_buf + return dict, else havoc. */
extern size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t s, size_t m, unsigned seed){
    size_t r = pfz_mutate_i2s(d, s, m, seed);
    return r ? r : LLVMFuzzerMutate(d, s, m);
}
''' % {'name': name, 'idx': idx}
    return _compile(name, src, vpool)


def generate_grains(grains, vpool):
    """grains = [(idx, name), ...] from pfz_grain_count()/_grain_name().
    Build the uniform deep-by-construction harness for each (P1 grain set).

    COMPILED IN PARALLEL: each _compile is an independent clang subprocess (releases the
    GIL), and on the 9p rootfs the per-grain cost is link+I/O bound, so a thread pool
    gives a near-linear speedup over the old serial loop (the P1 bottleneck). Headers are
    staged atomically (_copy_header_atomic) so concurrent compiles don't race."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    GRAIN_DIR.mkdir(exist_ok=True)
    if not grains:
        return []
    workers = min(len(grains), (os.cpu_count() or 8) * 2)   # I/O-bound → oversubscribe
    total = len(grains)
    # PROGRESS HEARTBEAT (P1 is otherwise SILENT between [P1 START] and [P1 END] while
    # ~95 grains compile in-guest — long enough that the host stall-watchdog mistakes a
    # healthy cold build for a wedge and kills it). Emit ~1 line per grain-completion so
    # the log keeps advancing: this both narrates the expected blocking point (compile)
    # AND makes the watchdog a CORRECT signal — lines appear iff compiles finish, so a
    # genuinely hung clang still (correctly) trips the watchdog. Cheap: it's I/O already.
    _pt0 = time.time()
    results = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as tp:
        futs = {tp.submit(gen_grain, idx, nm, vpool): nm for (idx, nm) in grains}
        for fut in as_completed(futs):
            done += 1
            nm = futs[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"    [P1 build] grain '{nm}' FAILED to compile: {e!r}", flush=True)
                continue
            # one concise line per grain so the gap between log writes stays tiny
            print(f"    [P1 build] {done}/{total} compiled ({nm}) "
                  f"{time.time()-_pt0:.0f}s", flush=True)
    return [(b, d) for (b, d) in results if b]


def gen_grain_combo_grain(a, b, na, nb, vpool):
    """P3 combination grain: chained compound of grains a+b via grain_combo2
    (the concurrent/race form is run as parallel processes). Same deep-by-
    construction prefix; the fuzzer drives both grains' target points."""
    src = '''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libksmbdzzer.h"
/* GRAIN COMBO grain: %(na)s + %(nb)s (idx %(a)d+%(b)d) */
__attribute__((used, section("__libfuzzer_extra_counters"))) static uint8_t ctr[4096];
static int g_octet = 1;
int LLVMFuzzerInitialize(int *x, char ***y){ (void)x; (void)y;
    const char *ip = getenv("GRAIN_IP");
    if (ip){ const char *p = strrchr(ip, 46); if (p) g_octet = atoi(p + 1); }
    if (pfz_init((unsigned long)g_octet) < 0) _exit(1);
    pfz_pool_init_authed(2);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    static uint32_t feats[4096];
    pfz_grain_combo2(%(a)d, %(b)d, data, (int)size);
    int n = pfz_get_features(feats, 4096);
    memset(ctr, 0, sizeof(ctr));
    for (int i = 0; i < n; i++) ctr[feats[i] & 4095]++;
    return 0;
}
extern size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t s, size_t m, unsigned seed){
    size_t r = pfz_mutate_i2s(d, s, m, seed);   /* fleet-wide i2s (0 ⇒ havoc) */
    return r ? r : LLVMFuzzerMutate(d, s, m);
}
''' % {'na': na, 'nb': nb, 'a': a, 'b': b}
    return _compile(f'combo_{na}_{nb}', src, vpool)


def generate_grain_combo_grains(pairs, vpool):
    """pairs = [(a, na, b, nb), ...] — build a combination grain per grain pair."""
    out = []
    for a, na, b, nb in pairs:
        binp, d = gen_grain_combo_grain(a, b, na, nb, vpool)
        if binp:
            out.append((binp, d))
    return out


def generate_grain_combo_pool(pairs, vpool):
    """SCALABLE combination pool: compile ONE generic combo harness, then emit a
    per-pair SYMLINK `grain_gc_<a>_<b>` → it. The harness parses its own argv[0]
    (…/grain_gc_<a>_<b>) to pick the grain indices, so N pairs cost ONE clang
    run + N instant symlinks instead of N compiles. Each symlink is a distinct
    binary path ⇒ distinct corpus stem, so run_grains schedules all N through
    its `-procs`-bounded execution pool with no collision. This is what makes the
    full all-pairs C(n+1,2) sweep (e.g. 4,560 for 95 grains) tractable.

    pairs = [(a, na, b, nb), ...]; returns [(symlink_path, dict_path), ...]."""
    src = '''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libksmbdzzer.h"
/* Generic GRAIN-COMBO harness. The grain pair (a,b) is taken from the program
   name grain_gc_<a>_<b> (argv[0]); $GRAIN_A/$GRAIN_B is the fallback. One
   compiled binary, run via per-pair symlinks. */
__attribute__((used, section("__libfuzzer_extra_counters"))) static uint8_t ctr[4096];
static int g_octet = 1, g_a = 0, g_b = 0;
static void _pick(const char *argv0){
    int a = -1, b = -1;
    const char *base = argv0 ? strrchr(argv0, 47) : 0;   /* '/' */
    base = base ? base + 1 : (argv0 ? argv0 : "");
    char buf[256]; size_t n = strlen(base);
    if (n && n < sizeof(buf)){
        memcpy(buf, base, n + 1);
        char *u2 = strrchr(buf, 95);                     /* last '_'  → b */
        if (u2){ b = atoi(u2 + 1); *u2 = 0;
            char *u1 = strrchr(buf, 95);                 /* prev '_' → a */
            if (u1) a = atoi(u1 + 1);
        }
    }
    if (a < 0 || b < 0){
        const char *ea = getenv("GRAIN_A"), *eb = getenv("GRAIN_B");
        a = ea ? atoi(ea) : 0; b = eb ? atoi(eb) : 0;
    }
    g_a = a; g_b = b;
}
int LLVMFuzzerInitialize(int *x, char ***y){ (void)x;
    _pick((y && *y && (*y)[0]) ? (*y)[0] : "");
    const char *ip = getenv("GRAIN_IP");
    if (ip){ const char *p = strrchr(ip, 46); if (p) g_octet = atoi(p + 1); }
    if (pfz_init((unsigned long)g_octet) < 0) _exit(1);
    pfz_pool_init_authed(2);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    static uint32_t feats[4096];
    pfz_grain_combo2(g_a, g_b, data, (int)size);
    int n = pfz_get_features(feats, 4096);
    memset(ctr, 0, sizeof(ctr));
    for (int i = 0; i < n; i++) ctr[feats[i] & 4095]++;
    return 0;
}
extern size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *d, size_t s, size_t m, unsigned seed){
    size_t r = pfz_mutate_i2s(d, s, m, seed);   /* fleet-wide i2s (0 ⇒ havoc) */
    return r ? r : LLVMFuzzerMutate(d, s, m);
}
'''
    binp, dp = _compile('gc', src, vpool)      # → grain_gc (+ grain_gc.dict)
    if not binp:
        return []
    target = Path(binp).name                    # 'grain_gc' (relative symlink)
    out = []
    for a, na, b, nb in pairs:
        link = GRAIN_DIR / f'grain_gc_{a}_{b}'
        try:
            if link.is_symlink() or link.exists():
                link.unlink()
            os.symlink(target, link)
        except OSError:
            continue
        out.append((str(link), dp))
    return out


def _fuzz_until_saturated(cmd, sat_ratio=0.02, poll=5, patience=3,
                          min_time=10, max_time=180, env=None, pre_kill_delay=0.0):
    """Run a libFuzzer binary until its coverage SATURATES instead of for a fixed
    time. Saturation = the relative growth of 'ft' (features/edges) per `poll`-
    second window stays below `sat_ratio` for `patience` consecutive windows.
    Bounded by [min_time warmup, max_time ceiling]. A flat grain (no new
    coverage) saturates quickly; a productive one keeps going until it plateaus.
    Returns (ft, cov, execs, elapsed, saturated, stderr_tail)."""
    # Auto-scale the warmup floor to the ceiling (#5): with a small --grain-max a
    # fixed min_time could exceed max_time, so saturation could NEVER trigger (the
    # loop hits the max_time break first). Cap min_time at a third of the budget so
    # there is always room for the patience windows to detect a plateau.
    min_time = min(min_time, max(3, int(max_time / 3)))
    import threading, re
    # start_new_session=True → the grain is a process-group/session leader, so we
    # can tear down its WHOLE subtree (RACE-combo fork()s, libsmbclient/RDMA helper
    # threads) by group, not just the direct child. A grandchild blocked on a wedged
    # ksmbd socket otherwise survives terminate(), holds the stderr pipe open, and
    # keeps a live ksmbd connection — the lingering fds behind the exit-storm wedge.
    proc = subprocess.Popen(cmd + [f'-max_total_time={int(max_time)}'],
                            stderr=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            text=True, bufsize=1, env=env, start_new_session=True)
    st = {'ft': 0, 'ft0': None, 'cov': 0, 'execs': 0, 'tail': [], 'pool': None}
    ftre = re.compile(r'\bft:\s*(\d+)')
    covre = re.compile(r'\bcov:\s*(\d+)')
    exre = re.compile(r'^#(\d+)\b')

    def _reader():
        for line in proc.stderr:
            if 'POOL grain=' in line:     # #4 prerequisite report from the grain harness
                st['pool'] = line.strip()
            m = ftre.search(line)
            if m:
                st['ft'] = int(m.group(1))
                if st['ft0'] is None:    # baseline = first ft (≈ bare grain, no mutation)
                    st['ft0'] = st['ft']
            m = covre.search(line)
            if m:
                st['cov'] = int(m.group(1))
            m = exre.match(line.strip())
            if m:
                st['execs'] = int(m.group(1))
            st['tail'].append(line)
            if len(st['tail']) > 400:
                del st['tail'][:200]

    th = threading.Thread(target=_reader, daemon=True)
    th.start()
    start = time.time()
    last_ft = 0
    low = 0
    saturated = False
    while proc.poll() is None:
        time.sleep(poll)
        ft = st['ft']
        elapsed = time.time() - start
        ratio = (ft - last_ft) / max(1, ft)   # relative feature growth this window
        last_ft = ft
        if elapsed >= min_time and ratio < sat_ratio:
            low += 1
            if low >= patience:
                saturated = True
                break
        else:
            low = 0
        if elapsed >= max_time:
            break
    # DESYNC THE TEARDOWN (root cause of the round-5 exit-storm GPF). A flat/BAIL
    # grain has ft==ft0 forever, so `ratio` is always 0 and the saturation break
    # is PURELY time-based (low>=patience at t≈min_time+patience*poll) — IDENTICAL
    # across every flat grain in a wave. They therefore all reach terminate() in
    # the SAME instant and close their kcov_dataflow fds simultaneously = the
    # synchronized exit-storm behind the pick_next_entity GPF. The jmax ceiling
    # desync does NOT cover this (flat grains never reach the ceiling). Sleep a
    # per-grain offset so the kcov_df_close calls stagger out instead of thunder.
    if pre_kill_delay and proc.poll() is None:
        time.sleep(pre_kill_delay)
    # Tear the grain down by its PROCESS GROUP so forked RACE/RDMA grandchildren
    # die with it (a survivor holds the stderr pipe + a live ksmbd socket → feeds
    # the synchronized exit-storm behind the round-5 scheduler GPF). SIGTERM the
    # group, reap; if it won't die, SIGKILL the group and reap anyway so no zombie
    # lingers holding fds. Always wait() after a kill (the old code did not → zombie).
    import signal as _sig
    def _sigpg(s):
        try:
            os.killpg(os.getpgid(proc.pid), s)
        except (ProcessLookupError, PermissionError, OSError):
            try: proc.send_signal(s)          # fall back to the direct child
            except Exception: pass
    try:
        _sigpg(_sig.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        _sigpg(_sig.SIGKILL)
        try: proc.wait(timeout=5)
        except Exception: pass
    th.join(timeout=2)
    # #4 per-grain prerequisite assertion: a grain harness reports its authed-pool
    # readiness (POOL grain=<n> n=<conns> fids=<open-fids>). If fids<2 the pool-based
    # grains (copychunk/lease/compound/…) will silently bail (return -1) and look
    # "shallow" — but that's a HARNESS gap (raw guest auth/create failed), not a
    # hardened target. Surface it so it can't hide as a coverage result.
    if st['pool'] and 'fids=2' not in st['pool']:
        print(f"    [!] PREREQ {st['pool']} — pool-based grains will BAIL "
              f"(harness gap, not a hardening signal)", flush=True)
    return (st['ft'], st['cov'], st['execs'], time.time() - start, saturated,
            "".join(st['tail']), st['ft0'] or 0)


_KASAN_PATTERNS = (
    'BUG: KASAN', 'KASAN:', 'slab-out-of-bounds', 'use-after-free',
    'kernel BUG at', 'Kernel panic', 'sleeping in atomic',
    'general protection fault', 'stack-protector: Kernel stack is corrupted',
    'refcount_t: underflow', 'refcount_t: overflow', 'double free', 'Oops',
    'unable to handle kernel paging request',
    'unable to handle kernel NULL pointer dereference',
    'BUG: unable to handle page fault',
)

# ksmbd config (for the inter-wave reset). gen.py lives in ksmbd/grain/, so the
# sandbox config is one level up.
_KSMBD_CONF = str(SCRIPT_DIR.parent / 'ksmbd-sandbox.config')
_KSMBD_PWDB = '/tmp/ksmbd_conf/ksmbdpwd.db'
# Alignment gate (#2): an grain that runs but stays below this many libFuzzer
# features has a misaligned/shallow prefix — its antigen didn't penetrate. Measured
# by `ft` (NOT the KERNEL_PCS atexit counter, which libFuzzer's saturation-SIGKILL
# bypasses → always 0). Empirically deep grains reach ft in the thousands
# (create_ctx≈4300, spnego≈6400); shallow ones stay <30. 100 cleanly separates them.
ALIGN_MIN_FT = 100


def _ksmbd_healthy(timeout=1.0):
    """True iff ksmbd is accepting SMB on 127.0.0.1:445. A cheap liveness probe so
    the phase restarts the server ONLY when it is actually down — not on every
    single 0-exec grain (which is usually the harness's own fault and whose
    'fix' by restart just breaks every other in-flight connection)."""
    import socket
    try:
        s = socket.create_connection(('127.0.0.1', 445), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _wait_ksmbd_healthy(timeout=15.0):
    """Poll until ksmbd accepts connections again (post-restart), up to timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _ksmbd_healthy():
            return True
        time.sleep(0.4)
    return False


def _restart_target():
    """Reset ksmbd's connection/session state so the NEXT wave of grains can
    authenticate (fix #1). The later-wave session-setup death is a server-side
    resource that isn't reaped between concurrent connection waves — a control
    shutdown + mountd restart clears it. Best-effort; never raises (so a missing
    tool just degrades to the old behaviour instead of failing the phase).
    Waits for the server to be healthy again (bounded) so the next wave doesn't
    dial a still-down server and spuriously report 0-exec (the death-spiral)."""
    try:
        subprocess.run(['ksmbd.control', '-s'], capture_output=True, timeout=8)
    except Exception:
        pass
    subprocess.run(['pkill', '-9', 'ksmbd.mountd'], capture_output=True)
    time.sleep(0.5)
    try:
        subprocess.Popen(['ksmbd.mountd', '-C', _KSMBD_CONF, '-P', _KSMBD_PWDB, '-n'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return
    # Health-gated settle: proceed as soon as ksmbd is up (fast path), but wait up
    # to a few seconds if it's slow — never dial a down server.
    if not _wait_ksmbd_healthy(6.0):
        time.sleep(1.5)   # fallback: fixed settle if the probe can't confirm


def _run_bounded(cmd, env=None, timeout=120):
    """Run `cmd` bounded by `timeout` and NEVER block the caller — even when the
    child wedges in uninterruptible kernel sleep (D state) on a deadlocked ksmbd
    socket. subprocess.run(timeout=) is UNSAFE here: on timeout it kills then
    calls an UNBOUNDED wait()/communicate(), which hangs forever on a D-state
    child that SIGKILL cannot reap (the smbdirect/oplock lock-inversion). A P2
    wave went silent for 326s because a corpus `-merge=1` run hit exactly this.
    Instead: new session (so the whole subtree tears down together), poll for
    completion, and on timeout SIGTERM/SIGKILL the group with a BOUNDED reap and
    GIVE UP — an unkillable orphan is left to the kernel, but the phase keeps
    progressing (generational resilience). Returns True iff it exited 0 in time."""
    import signal as _sig
    try:
        proc = subprocess.Popen(cmd, env=env or os.environ,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
    except (OSError, subprocess.SubprocessError):
        return False
    deadline = time.time() + timeout
    while proc.poll() is None and time.time() < deadline:
        time.sleep(1)
    if proc.poll() is not None:
        return proc.returncode == 0
    def _pg(s):
        try: os.killpg(os.getpgid(proc.pid), s)
        except (ProcessLookupError, PermissionError, OSError):
            try: proc.send_signal(s)
            except Exception: pass
    _pg(_sig.SIGTERM)
    try:
        proc.wait(timeout=3)
    except Exception:
        _pg(_sig.SIGKILL)
        try: proc.wait(timeout=3)
        except Exception: pass    # D-state orphan — do NOT block the phase on it
    return False


def run_grains(grains, sat_ratio=0.02, max_time=180, parallelism=4, out_stats=None):
    """Run grain harnesses in PARALLEL — each libFuzzer grain on its OWN
    127.0.0.<n> so ksmbd routes each grain's kernel coverage to its own buffer
    (no handle collision), and each carries its own corpus/feedback. The kernel
    coverage drives that grain's mutation (extra-counters). Only the post-batch
    crash check + result aggregation are serial. Returns list of crashes."""
    from concurrent.futures import ThreadPoolExecutor
    CRASH_DIR.mkdir(exist_ok=True)
    live_dict = Path('/tmp/ksmbdzzer_live.dict')
    PERSISTENT_CORPUS = Path('/tmp/ksmbdzzer_corpus_persistent')
    PERSISTENT_CORPUS.mkdir(exist_ok=True)
    crashes = []
    grains = [(b, d) for b, d in grains if b]
    parallelism = max(1, parallelism)

    # Within-grain MAP-REDUCE: if there are fewer grains than CPU slots, fill the
    # idle cores with extra mutation instances of the same grains. Each replica
    # runs on its own loopback IP (own kernel-coverage buffer) but SHARES the
    # grain's persistent corpus dir (keyed by name) — so N libFuzzer processes
    # explore one grain in parallel and merge their finds via the shared corpus
    # (libFuzzer's own -jobs/-workers model). Utilizes all CPUs even for 1 grain.
    if 0 < len(grains) < parallelism:
        base = list(grains)
        i = 0
        while len(grains) < parallelism:
            grains.append(base[i % len(base)])
            i += 1

    # NOTE: this is the coverage-guided phase — it runs WITHOUT failslab. Global
    # kmalloc fault injection during the multi-round-trip connect/auth was killing
    # every grain that _exit(1)s on first failure (compounding ~20%/alloc over
    # ~30 allocs), so half the fleet showed "0 executions". Fault injection is a
    # separate campaign (gen_failslab_grains self-manages the knob per grain).
    os.system("echo 0 > /sys/kernel/debug/failslab/probability 2>/dev/null")  # ensure clean

    # Bound the per-grain persistent corpus. libFuzzer replays the WHOLE corpus
    # dir at startup before the first exec — and that replay is NOT counted by the
    # saturation ceiling — so an unbounded corpus makes each later round's startup
    # cost grow super-linearly (round 2 paid round 1's whole corpus). Keep the K
    # most-recently-written inputs (the most-evolved ones carry the deepest state);
    # crash-* files are always kept. This is the feed-forward cap, not a reset.
    # With PATH-based coverage (common.h fb() default), libFuzzer keeps a corpus
    # input only when it hits a NEW kernel path — so the corpus is already
    # path-deduped and grows far slower than under value-folding. This hard cap is
    # now a safety bound that keeps late-round replay cheap (fix #5).
    CORPUS_CAP = 400
    def _prune_corpus(cdir, binary=None, env=None):
        """Curate the feed-forward corpus by PATH coverage, not recency (#6).

        libFuzzer -merge=1 keeps the SMALLEST input subset that still reaches
        every feature (kernel path, under common.h's path-based fb()) the whole
        corpus reaches — a true dedup-by-path. This is what preserves the deep
        seeds that drive the round-2/3 ft0 jump: an mtime cap could drop the sole
        input covering a deep path in favor of a redundant newer one. Only if the
        minimized set STILL exceeds the cap do we hard-bound it (smallest inputs
        first — libFuzzer prefers small seeds), and we LOG the drop so a shrinking
        corpus never silently hides lost coverage.
        """
        try:
            files = [f for f in cdir.iterdir()
                     if f.is_file() and not f.name.startswith(('crash-', 'oom-', 'timeout-'))]
            if len(files) <= CORPUS_CAP:
                return
            # 1) Coverage-preserving minimization (dedup-by-path).
            if binary:
                mindir = cdir.parent / (cdir.name + '.min')
                try:
                    if mindir.exists():
                        shutil.rmtree(mindir)
                    mindir.mkdir(parents=True, exist_ok=True)
                    # Heartbeat + name the culprit: a merge is a KNOWN blocking
                    # point (re-runs the grain on every input) but used to print
                    # nothing, so a wedge here left the last log line pointing at
                    # some OTHER grain. Stamp the grain now so the watchdog log
                    # names who was merging.
                    print(f"    [corpus-merge] {cdir.name}: minimizing "
                          f"{len(files)} inputs (bounded 120s)", flush=True)
                    # BOUNDED, non-blocking: a merge re-runs the grain on every
                    # corpus input; if one wedges ksmbd into D-state, a plain
                    # subprocess.run(timeout=) would kill-then-wait() FOREVER on
                    # the unreapable child and stall the whole P2 wave. _run_bounded
                    # gives up after the budget so the phase keeps moving.
                    _run_bounded([binary, '-merge=1', str(mindir), str(cdir)],
                                 env=env or os.environ, timeout=120)
                    kept = [f for f in mindir.iterdir() if f.is_file()]
                    if kept:                       # merge succeeded — adopt minimized set
                        for f in files:
                            try: f.unlink()
                            except OSError: pass
                        for f in kept:
                            try: f.replace(cdir / f.name)
                            except OSError: pass
                        files = [f for f in cdir.iterdir()
                                 if f.is_file() and not f.name.startswith(('crash-', 'oom-', 'timeout-'))]
                    shutil.rmtree(mindir, ignore_errors=True)
                except (OSError, subprocess.SubprocessError):
                    pass                           # fall through to mtime cap below
            # 2) Safety hard-bound: only if still over cap after minimization.
            if len(files) > CORPUS_CAP:
                files.sort(key=lambda f: f.stat().st_size)   # smallest (best seeds) first
                dropped = len(files) - CORPUS_CAP
                for f in files[CORPUS_CAP:]:
                    try: f.unlink()
                    except OSError: pass
                print(f"    [corpus] {cdir.name}: minimized set still > {CORPUS_CAP}; "
                      f"dropped {dropped} distinct-path input(s) (coverage may narrow)",
                      flush=True)
        except OSError:
            pass

    def _run_one(slot_item):
        slot, (binary, dict_path) = slot_item
        name = Path(binary).stem
        corpus_dir = PERSISTENT_CORPUS / name      # per-grain corpus (feedforward)
        corpus_dir.mkdir(exist_ok=True)
        # Each grain gets a GLOBALLY-unique loopback IP (octet = its index in
        # the whole grain list, not just within the batch). ksmbd derives the
        # per-connection kcov_handle from the dest IP, so a globally-unique IP
        # guarantees no handle reuse across sequential batches — a reused IP made
        # batch 2 re-register a handle on the same 127.0.0.x batch 1 had just
        # used, and stale routing left batch-2 grains coverage-blind.
        ip = f"127.0.0.{2 + (slot % 250)}"   # %250 keeps octet in [2,251]; concurrent
        env = {**os.environ, 'GRAIN_IP': ip}  # grains (one batch) never alias mod 250
        # Arbiter cross-round feedback (g_fb): grains load_feedback() from this file
        # if the director wrote one this round. Host-durable path (survives VM wedge).
        _fb = FUZZDB / 'fb.bin'
        if _fb.exists():
            env['GRAIN_FB'] = str(_fb)
        _prune_corpus(corpus_dir, binary, env)     # dedup-by-path bound (fix #6)
        dicts = [f'-dict={dict_path}']
        if live_dict.exists():
            dicts.append(f'-dict={live_dict}')
        # Desynchronize the max_time ceiling per grain (round-survival, task #29).
        # tp.map() is a barrier, so ceiling-bound grains in a wave otherwise all
        # terminate in the SAME instant — every libFuzzer proc closing its
        # kcov_dataflow fd at once, the synchronized exit-storm that tipped the
        # scheduler into the round-5 GPF cascade. Spread the ceiling over
        # [0.80, 1.15]x with a deterministic per-slot hash (no RNG → runs stay
        # reproducible) so the fd-closes stagger out instead of thundering.
        h = (slot * 2654435761) & 0xffffffff
        jmax = max(3.0, max_time * (0.80 + 0.35 * (h % 1000) / 1000.0))
        # Teardown stagger: slots within one wave are CONSECUTIVE, so slot%parallelism
        # gives each concurrent grain a distinct offset (0, 0.5, 1.0, … s). This
        # desyncs the SATURATION-driven teardown that jmax can't (flat grains all
        # break at the same fixed time) → kcov_dataflow fd-closes spread out, no
        # exit-storm. Bounded: adds at most (parallelism-1)*0.5s to the slowest.
        pre_kill = (slot % parallelism) * 0.5
        # Deterministic per-trial libFuzzer seed (multi-trial comparison, KSMBDZZER_SEED):
        # each trial gets a distinct-but-reproducible RNG seed so repeated runs are
        # independent yet re-runnable, instead of libFuzzer's default wall-clock seed.
        # Mixed with the slot so grains within a trial don't all share one seed.
        seed_args = []
        _s = os.environ.get('KSMBDZZER_SEED')
        if _s and _s.isdigit():
            seed_args = [f'-seed={((int(_s) * 0x9E3779B1) ^ (slot + 1)) & 0x7fffffff}']
        try:
            ft, cov, execs, elapsed, sat, tail, ft0 = _fuzz_until_saturated(
                [binary, '-max_len=512', '-print_final_stats=1'] + seed_args + dicts + [str(corpus_dir)],
                sat_ratio=sat_ratio, max_time=jmax, env=env, pre_kill_delay=pre_kill)
            kpcs = _parse_kernel_pcs(tail)   # distinct kernel PCs reached (alignment gate)
            rh, ch, rd = _parse_i2s_hits(tail)   # reverse-flow proof (RedQueen return tokens)
            if rh or ch:
                vlog(f"[i2s] {name}: RET_TOKEN_HITS={rh} CMP_I2S_HITS={ch} RET_DICT={rd}"
                     f"  (reverse-flow RedQueen fired)")
            # A userspace crash leaves a crash-/oom-/timeout-* input in the corpus dir.
            # Carry the stderr tail so the report loop can export a reproducer.
            crashed = any(p.name.startswith(('crash-', 'oom-', 'timeout-'))
                          for p in corpus_dir.iterdir()) if corpus_dir.exists() else False
            return (name, binary, ip, corpus_dir, ft, cov, execs, elapsed, sat, kpcs,
                    tail if crashed else None, ft0)
        except Exception as e:
            return (name, binary, ip, corpus_dir, 0, 0, 0, 0.0, False, 0, None, 0)

    try:
        nbatches = (len(grains) + parallelism - 1) // parallelism
        # LIGHTENED RESTART: reset ksmbd only when we actually need a fresh server
        # — before the FIRST wave, or after a wave that showed session-setup death
        # (any 0-exec grain). An unconditional per-wave `ksmbd.control -s` cost
        # ~2.5-8s each AND re-triggered the smbdirect RDMA-listener cleanup (the
        # recursive-lock WARNING) on every wave for no reason. When a wave runs
        # clean, the next wave dials the same healthy server — no restart, no
        # WARNING, much faster rounds. The death-recovery is preserved: a wave that
        # dies forces a restart before the next one.
        # Restart ONCE before the first wave to clear stale state, then keep the
        # server ALIVE across waves. Restart mid-round ONLY when ksmbd is genuinely
        # down (liveness probe) AND a wave shows server-wide failure (majority
        # 0-exec), capped per round. A single/few dead grains are retried IN PLACE
        # without nuking the server. This breaks the death-spiral that killed the
        # 20-round run: one 0-exec grain → ksmbd.control -s → every in-flight
        # connection dropped → more 0-exec → 153 restarts → ~90% of grain-runs
        # never executed. (0-exec is usually the harness's own init fault, not the
        # server's — so don't punish the whole fleet for it.)
        _restart_target()
        restarts = 0
        MAX_RESTARTS_PER_ROUND = 4
        for bi, start in enumerate(range(0, len(grains), parallelism)):
            # enumerate(..., start=start) → `slot` is the GLOBAL index, so the
            # derived octet 2+slot is unique across batches (no IP/handle reuse).
            batch = list(enumerate(grains[start:start + parallelism], start=start))
            # ── PARALLEL: each grain runs concurrently on its own IP ──
            _wave_t0 = time.time()
            with ThreadPoolExecutor(max_workers=len(batch)) as tp:
                results = list(tp.map(_run_one, batch))
            # Post-wave settle (round-survival, task #29): let the just-exited
            # libFuzzer procs finish closing their kcov_dataflow fds and let ksmbd
            # reap the per-connection kworkers BEFORE the next wave's mass spawn.
            time.sleep(1.5)
            dead_idx = [i for i, r in enumerate(results) if r[6] == 0]
            if dead_idx:
                # Restart is warranted ONLY on server-wide death (majority of the
                # wave dead) AND ksmbd actually not accepting connections, AND under
                # the per-round cap. Otherwise retry the few dead IN PLACE.
                server_down = (len(dead_idx) >= max(2, (len(batch) + 1) // 2)
                               and not _ksmbd_healthy())
                if server_down and restarts < MAX_RESTARTS_PER_ROUND:
                    _restart_target(); restarts += 1
                dead_items = [batch[i] for i in dead_idx]
                with ThreadPoolExecutor(max_workers=len(dead_items)) as tp:
                    retried = list(tp.map(_run_one, dead_items))
                revived = 0
                for j, i in enumerate(dead_idx):
                    if retried[j][6] > 0:          # keep retry only if it actually ran
                        results[i] = retried[j]; revived += 1
                print(f"{_dts()}     [retry] {len(dead_idx)} dead grain(s) re-run"
                      f"{' after reset' if server_down else ' in place'} → {revived} "
                      f"revived (restarts {restarts}/{MAX_RESTARTS_PER_ROUND})", flush=True)
            # STARVATION GUARD (#3): a wave that hugely overshoots means the guest is
            # CPU-starved (host overload) — clock skews, CIFS times out (180s),
            # coverage/timing unreliable. Surface it loudly with the host load.
            _wave_dt = time.time() - _wave_t0
            print(f"{_dts()}     [wave {bi+1}/{nbatches}] {len(batch)} grains in "
                  f"{_wave_dt:.1f}s", flush=True)
            if _wave_dt > 3 * (max_time + 60):
                try: _la = open('/proc/loadavg').read().split()[0]
                except Exception: _la = '?'
                print(f"{_dts()}     [!!! STARVATION] wave {bi} took {_wave_dt:.0f}s "
                      f"(budget ~{max_time+60}s, host loadavg {_la}) — guest CPU-starved; "
                      f"coverage/timing unreliable. Lower -procs or idle the host.", flush=True)
            # ── SERIAL: report each grain. Kernel crash detection is NOT done
            # here — KASAN/BUG/Oops go to the serial console and are grepped on
            # the host after the run (with panic_on_warn/oops=panic the VM halts
            # on the first bug). Doing it in-process would re-serialize the
            # parallel batch on a full dmesg read every round. libFuzzer still
            # writes any userspace crash-* input to each grain's corpus dir. ──
            for (name, binary, ip, cdir, ft, cov, execs, elapsed, sat, kpcs, crash_tail, ft0) in results:
                # Export a reproducer for any grain that left a libFuzzer crash
                # input (userspace crash / sanitizer abort). Kernel KASAN/BUG still
                # come from the serial console host-side; this captures the rest.
                if crash_tail is not None:
                    try:
                        sub = export_crash(binary, crash_tail, cdir)
                        crashes.append((name, sub))
                        print(f"{_dts()}     !!! [P2] grain {name}@{ip}: CRASH — reproducer saved to {sub}", flush=True)
                    except Exception as _e:
                        print(f"    [!] grain {name}@{ip}: crash export failed ({_e!r})", flush=True)
                if execs == 0:
                    print(f"    [!] grain {name}@{ip}: 0 executions — exited at init "
                          f"(connect/auth failed?), NOT fuzzed", flush=True)
                else:
                    why = "SATURATED" if sat else f"capped@{max_time}s"
                    # Alignment gate (fix #2): an grain that ran but stays shallow
                    # (low ft) has a MISALIGNED prefix — it opened the wrong/shallow
                    # door, so its antigen never penetrated. Flag it so the
                    # generator/renewal can drop it instead of compounding shallowness.
                    align = "ALIGNED" if ft >= ALIGN_MIN_FT else f"SHALLOW(misaligned,ft<{ALIGN_MIN_FT})"
                    # Baseline (ft0 = bare grain) → saturated (ft). The anti-monkey
                    # rule: a mutation is only interesting if its coverage BEATS the
                    # working grain's own baseline. delta = ft-ft0.
                    #   PRODUCTIVE = mutation found new code beyond the normal scenario
                    #   FLAT       = reaches deep but fuzzing adds nothing (monkey)
                    delta = ft - ft0
                    productive = (delta >= 100) or (ft0 > 0 and delta >= 0.2 * ft0)
                    prod = "PRODUCTIVE" if productive else "FLAT(no-gain-over-baseline)"
                    print(f"{_dts()}     [P2] grain {name}@{ip}: {elapsed:.1f}s execs={execs} "
                          f"ft0={ft0}→{ft} (Δ+{delta}) [{align},{prod}] ({why})", flush=True)
                    if out_stats is not None:   # let the orchestrator select productive grains
                        prev = out_stats.get(name, {})
                        if ft >= prev.get('ft', -1):    # keep the best replica's numbers
                            out_stats[name] = {'ft0': ft0, 'ft': ft,
                                               'aligned': ft >= ALIGN_MIN_FT,
                                               'productive': productive}
    finally:
        os.system("echo 0 > /sys/kernel/debug/failslab/probability 2>/dev/null")
    return crashes


def _parse_kernel_pcs(tail):
    """Pull the distinct-kernel-PC count the harness prints at exit (KERNEL_PCS=N)."""
    import re
    best = 0
    for m in re.finditer(r'KERNEL_PCS=(\d+)', tail or ''):
        best = max(best, int(m.group(1)))
    return best


def _parse_i2s_hits(tail):
    """Pull the reverse-flow RedQueen proof counters the harness prints at exit:
    RET_TOKEN_HITS (inputs steered with a kernel RETURN value), CMP_I2S_HITS
    (inputs steered with a trace_cmp operand), RET_DICT (persistent return-dict
    size). Non-zero RET_TOKEN_HITS is direct evidence the bi-directional loop
    fired — used to tell a real i2s win apart from pc-havoc noise. Takes the max
    across the tail (multiple atexit lines under -jobs/replicas)."""
    import re
    rh = ch = rd = 0
    for m in re.finditer(r'RET_TOKEN_HITS=(\d+) CMP_I2S_HITS=(\d+) RET_DICT=(\d+)', tail or ''):
        rh = max(rh, int(m.group(1)))
        ch = max(ch, int(m.group(2)))
        rd = max(rd, int(m.group(3)))
    return rh, ch, rd




def export_crash(binary, stderr_tail, corpus_dir):
    """Save crash reproducer: input + stderr + dmesg + grain source.
    Each crashing input gets a BLAKE2b id (over the input bytes) so the same
    trigger re-discovered later collapses to one identity."""
    import hashlib
    ts = int(time.time())
    name = Path(binary).stem

    # BLAKE2b over the libFuzzer crash input(s) — the corpus bytes that fired.
    crash_inputs = [f for f in corpus_dir.iterdir()
                    if f.name.startswith(('crash-', 'oom-', 'timeout-'))]
    h = hashlib.blake2b(digest_size=16)
    for f in sorted(crash_inputs):
        try:
            h.update(f.read_bytes()); h.update(b'\x1e')
        except Exception:
            pass
    if not crash_inputs:                 # crash with no saved input — hash the trace
        h.update(stderr_tail.encode(errors='replace'))
    bug_id = h.hexdigest()

    crash_subdir = CRASH_DIR / f'{name}_{bug_id[:12]}'
    crash_subdir.mkdir(exist_ok=True)

    (crash_subdir / 'stderr.txt').write_text(stderr_tail)
    (crash_subdir / 'bug.json').write_text(json.dumps({
        'blake2b': bug_id, 'grain': name, 'ts': ts,
        'inputs': [f.name for f in crash_inputs],
    }, indent=2))

    for f in crash_inputs:
        shutil.copy2(f, crash_subdir / f.name)

    try:
        dmesg = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=5)
        (crash_subdir / 'dmesg.txt').write_text(dmesg.stdout[-5000:])
    except Exception:
        pass

    src_path = Path(binary).with_suffix('.c')
    if src_path.exists():
        shutil.copy2(src_path, crash_subdir / src_path.name)

    print(f"    [!] Crash exported → {crash_subdir}")
    return crash_subdir

