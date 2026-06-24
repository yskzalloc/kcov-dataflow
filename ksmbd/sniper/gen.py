"""
sniper_gen.py — Auto-generates targeted libFuzzer C harnesses.

All socket-based snipers use sniper_common.h for authenticated session + reconnect.
Value pool from Phase 1-5 is injected into dictionaries at generation time.
"""
import struct, os, subprocess, shutil, time
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SNIPER_DIR = Path('/tmp/ksmbdzzer_snipers')
CRASH_DIR = Path('/tmp/ksmbdzzer_crashes')


def _write_dict(name, extra_entries=None, value_pool=None):
    dp = SNIPER_DIR / f'{name}.dict'
    with open(dp, 'w') as f:
        # Standard boundaries
        for bv in [0, 1, 0xFF, 0x100, 0xFFF, 0x1000, 0xFFFF, 0x10000,
                   0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]:
            f.write(f'"{struct.pack("<I", bv).hex()}"\n')
        # === CRITICAL AUDIT FINDINGS ===
        # #1: Compound WRITE OOB — DataOffset past sub-request (values > 112)
        for v in [112, 113, 128, 200, 255, 256, 512]:
            f.write(f'"{struct.pack("<H", v).hex()}"\n')
        # #2: AllocationSize overflow — values near 0xFFFFFFFFFFFFFE00
        for v in [0xFFFFFFFFFFFFFE00, 0xFFFFFFFFFFFFFE01, 0xFFFFFFFFFFFFFDFF,
                  0xFFFFFFFFFFFFFF00, 0xFFFFFFFFFFFFFFFF]:
            f.write(f'"{struct.pack("<Q", v).hex()}"\n')
        # #3: loff_t signed overflow — Offset near LLONG_MAX + NEGATIVE
        for v in [0x7FFFFFFFFFFFFFF0, 0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFE,
                  0x7FFFFFFFFFFFF000, 0x7FFFFFFFFFFF0000,
                  0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFF0000,
                  0x8000000000000001, 0x8000000000000000]:
            f.write(f'"{struct.pack("<Q", v).hex()}"\n')
        # #5: DENY ACE bypass — FILE_MAXIMAL_ACCESS = 0x02000000
        f.write(f'"{struct.pack("<I", 0x02000000).hex()}"\n')
        # Extra entries
        if extra_entries:
            for e in extra_entries:
                f.write(f'"{e}"\n')
        # Value pool
        if value_pool:
            for v in value_pool[:40]:
                if 0 < v < 0x100000000:
                    f.write(f'"{struct.pack("<I", v & 0xFFFFFFFF).hex()}"\n')
    return str(dp)


def _compile(name, src, value_pool=None, extra_dict=None):
    SNIPER_DIR.mkdir(exist_ok=True)
    # Copy headers
    for hdr in ['common.h', 'ntlmv2.h']:
        hdr_src = SCRIPT_DIR / hdr
        if hdr_src.exists():
            shutil.copy2(hdr_src, SNIPER_DIR / hdr)

    sp = SNIPER_DIR / f'sniper_{name}.c'
    bp = SNIPER_DIR / f'sniper_{name}'
    sp.write_text(src)
    dp = _write_dict(name, extra_dict, value_pool)

    # Try with NTLMv2 (requires libcrypto)
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2', '-DUSE_NTLMV2',
         f'-I{SNIPER_DIR}', '-o', str(bp), str(sp), '-lcrypto'],
        capture_output=True)
    if r.returncode == 0:
        return (str(bp), dp)
    # Fallback: without NTLMv2 (guest auth only)
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2',
         f'-I{SNIPER_DIR}', '-o', str(bp), str(sp)],
        capture_output=True)
    return (str(bp), dp) if r.returncode == 0 else (None, None)


# ─── VFS-based snipers (use mounted file, no socket needed) ──────────────────

def gen_vfs_write_sniper(vpool):
    """VFS write via CIFS mount: boundary offsets, write+truncate race."""
    src = '''#include "common.h"
static int tfd;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    tfd = open("/home/debian-sid/mnt/fuzz_target", O_RDWR|O_CREAT, 0666);
    if (tfd < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;
    df_buf[0] = 0;

    uint8_t op = data[0] % 5;
    uint32_t offset, length;
    memcpy(&offset, data+1, 4);
    memcpy(&length, data+5, 4);
    const uint8_t *payload = data + 9;
    size_t plen = size - 9;

    switch (op) {
    case 0: /* Write at page boundary */
        offset = (offset & 0xFFFFF000) | (data[9] & 0x0F);
        if (plen > 0) pwrite(tfd, payload, plen > 8192 ? 8192 : plen, offset);
        break;
    case 1: /* Write then immediate truncate */
        if (plen > 0) pwrite(tfd, payload, plen > 4096 ? 4096 : plen, offset & 0xFFFFFF);
        ftruncate(tfd, (offset >> 8) & 0xFFFF);
        break;
    case 2: /* Large write */
        if (plen > 0) pwrite(tfd, payload, plen > 65536 ? 65536 : plen, 0);
        break;
    case 3: /* Write to sparse hole then read */
        ftruncate(tfd, 0x100000);
        if (plen > 0) pwrite(tfd, payload, plen > 64 ? 64 : plen, offset & 0xFFFFF);
        { char buf[64]; pread(tfd, buf, 64, (offset+1) & 0xFFFFF); }
        break;
    case 4: /* fallocate + write */
        fallocate(tfd, 0x03, offset & 0xFFFF, (length & 0xFFF) + 1);
        if (plen > 0) pwrite(tfd, payload, plen > 128 ? 128 : plen, offset & 0xFFFF);
        break;
    }

    fb();
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('vfs_write', src, vpool)


def gen_raw_write_sniper(vpool):
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
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('raw_write', src, vpool)


def gen_read_after_write_sniper(vpool):
    """WRITE then READ at adjacent offset — catches UAF/uninitialized leaks.
    Write-side bugs manifest when data read back is corrupted/leaked."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('read_after_write', src, vpool)


def gen_stream_sniper(vpool):
    src = '''#include "common.h"
static int tfd;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    tfd = open("/home/debian-sid/mnt/fuzz_target", O_RDWR|O_CREAT, 0666);
    if (tfd < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    df_buf[0] = 0;
    uint32_t pos_val;
    memcpy(&pos_val, data, 4);
    pos_val = (pos_val % 0x2000) + 0xF000;
    size_t wlen = size - 4 > 64 ? 64 : size - 4;
    pwrite(tfd, data + 4, wlen, (off_t)pos_val);
    fb();
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('stream_oob', src, vpool)


def gen_ea_sniper(vpool):
    src = '''#include "common.h"
static int tfd;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    tfd = open("/home/debian-sid/mnt/fuzz_target", O_RDWR|O_CREAT, 0666);
    if (tfd < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    df_buf[0] = 0;
    char name[64] = "user.";
    uint8_t nlen = (data[0] % 50) + 1;
    size_t cplen = nlen < size-1 ? nlen : size-1;
    memcpy(name+5, data+1, cplen > 50 ? 50 : cplen);
    name[5 + (cplen > 50 ? 50 : cplen)] = 0;
    size_t vlen = size > 1 + nlen ? size - 1 - nlen : 0;
    if (vlen > 256) vlen = 256;
    if (vlen > 0) fsetxattr(tfd, name, data+1+nlen, vlen, 0);
    char buf[512]; fgetxattr(tfd, name, buf, sizeof(buf));
    fb();
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('ea_alignment', src, vpool)


def gen_lock_sniper(vpool):
    src = '''#include "common.h"
static int tfd;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    tfd = open("/home/debian-sid/mnt/fuzz_target", O_RDWR|O_CREAT, 0666);
    if (tfd < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0;
    df_buf[0] = 0;
    struct flock fl = {0};
    uint64_t off, len;
    memcpy(&off, data, 8); memcpy(&len, data+8, 8);
    fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET;
    fl.l_start = off & 0xFFFFFF; fl.l_len = (len & 0xFFFF) + 1;
    fcntl(tfd, F_SETLK, &fl);
    fl.l_type = F_UNLCK;
    fcntl(tfd, F_SETLK, &fl);
    fb();
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('lock_race', src, vpool)


# ─── Socket-based snipers (use sniper_common.h auth + reconnect) ──────────────

def gen_dacl_sniper(vpool):
    """Raw SMB2 SET_INFO(SecurityInformation) — hits smb2_set_info_sec → parse_sec_desc."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('dacl_setinfo', src, vpool)


def gen_create_ctx_sniper(vpool):
    """CREATE with mutated contexts + reconnect-on-failure."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
static int iter_count = 0;
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    extra = [b'DH2Q'.hex(), b'DH2C'.hex(), b'RqLs'.hex(), b'MxAc'.hex(),
             b'QFid'.hex(), b'TWrp'.hex(), b'AAPL'.hex()]
    return _compile('create_ctx', src, vpool, extra)


def gen_ndr_sniper(vpool):
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
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('ndr_rpc', src, vpool)


def gen_compound_sniper(vpool):
    """WRITE+TRUNCATE+CLOSE compound race — most dangerous CVE pattern.
    Sends WRITE, then SET_INFO(EndOfFile=0) to truncate, then CLOSE.
    Race: write in progress while truncate invalidates pages → UAF."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('compound', src, vpool)


def gen_write_lock_race_sniper(vpool):
    """LOCK(blocking) + CANCEL race — triggers UAF in deferred lock cleanup (CVE revert)."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('write_lock_race', src, vpool)


def gen_priv_bypass_sniper(vpool):
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
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('priv_bypass', src, vpool)


def gen_dh_trust_sniper(vpool):
    """Cross-boundary trust: attempts DH2C reconnect with forged/random CreateGuid.
    Tests if ksmbd validates the reconnecting user matches the original opener.
    If ret=0 → trust boundary bypass (privilege escalation via stale daccess)."""
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
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
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    SNIPER_ITER_END(); __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile('dh_trust', src, vpool)


def gen_mt_race_sniper(vpool):
    """Multi-threaded: persistent handle, thread A writes at 22K ops/s,
    thread B sends CLOSE on same fid. Maximum race iteration speed."""
    src = r'''#include "common.h"
#include <pthread.h>
static const char *SHARE = "\\\\127.0.0.1\\share";

static uint8_t persistent_fid[16];
static volatile int racing = 0;
static int has_fid = 0;

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
    /* Fire CLOSE on the same fid writer is using */
    uint8_t pdu[128];
    memset(pdu, 0, sizeof(pdu));
    memcpy(pdu, "\xfeSMB", 4);
    *(uint16_t*)(pdu+4) = 64; *(uint16_t*)(pdu+6) = 1;
    *(uint16_t*)(pdu+12) = 6; /* CMD_CLOSE */
    *(uint16_t*)(pdu+14) = 31;
    *(uint64_t*)(pdu+24) = mid + 50;
    *(uint32_t*)(pdu+36) = tid;
    *(uint64_t*)(pdu+40) = sid;
    *(uint16_t*)(pdu+64) = 24;
    memcpy(pdu+72, persistent_fid, 16);
    send_only(pdu, 88);
    has_fid = 0; /* fid is now invalid */
    return NULL;
}

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
    create_file();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    if (!has_fid) create_file();
    if (!has_fid) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* Every 100 iterations: launch CLOSE race */
    if ((data[0] & 0x7F) == 0) {
        racing = 0;
        pthread_t th;
        pthread_create(&th, NULL, closer_thread, NULL);
        /* WRITE while CLOSE races */
        racing = 1;
        size_t wlen = size > 256 ? 256 : size;
        for (int i = 0; i < 10; i++) {
            smb2_hdr(pdu, 0x0009);
            uint8_t *body = pdu+64;
            *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
            *(uint32_t*)(body+4) = wlen;
            *(uint64_t*)(body+8) = i * 64;
            memcpy(body+16, persistent_fid, 16);
            memset(body+32, 0, 16);
            memcpy(pdu+176, data, wlen);
            send_only(pdu, 176+wlen);
        }
        pthread_join(th, NULL);
        /* Drain */
        struct timeval tv = {.tv_sec=0, .tv_usec=50000};
        setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        while (recv(raw_sock, resp, sizeof(resp), 0) > 0) {}
        tv.tv_sec = 2; tv.tv_usec = 0;
        setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        /* Re-create file for next iterations */
        create_file();
    } else {
        /* Fast path: just WRITE (persistent handle, no CREATE overhead) */
        smb2_hdr(pdu, 0x0009);
        uint8_t *body = pdu+64;
        *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
        size_t wlen = size > 256 ? 256 : size;
        *(uint32_t*)(body+4) = wlen;
        *(uint64_t*)(body+8) = (data[1] * 64) & 0xFFFF;
        memcpy(body+16, persistent_fid, 16);
        memset(body+32, 0, 16);
        memcpy(pdu+176, data, wlen);
        xact(pdu, 176+wlen, resp, sizeof(resp));
    }

    /* Feedback */
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
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    SNIPER_DIR.mkdir(exist_ok=True)
    sp = SNIPER_DIR / 'sniper_mt_race.c'
    bp = SNIPER_DIR / 'sniper_mt_race'
    dp = _write_dict('mt_race', None, vpool)
    # Copy headers
    for hdr in ['common.h', 'ntlmv2.h']:
        hdr_src = SCRIPT_DIR / hdr
        if hdr_src.exists():
            import shutil; shutil.copy2(hdr_src, SNIPER_DIR / hdr)
    sp.write_text(src)
    # Must link with -lpthread
    r = subprocess.run(
        ['clang', '-fsanitize=fuzzer', '-O2', '-DUSE_NTLMV2',
         f'-I{SNIPER_DIR}', '-o', str(bp), str(sp), '-lcrypto', '-lpthread'],
        capture_output=True)
    if r.returncode != 0:
        r = subprocess.run(
            ['clang', '-fsanitize=fuzzer', '-O2',
             f'-I{SNIPER_DIR}', '-o', str(bp), str(sp), '-lpthread'],
            capture_output=True)
    return (str(bp), dp) if r.returncode == 0 else (None, None)


def gen_spnego_sniper(vpool):
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
    __builtin_memset(ctr, 0, sizeof(ctr));
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


# ─── Public API ───────────────────────────────────────────────────────────────

_last_pool_size = 0

def generate_all_snipers(value_pool):
    """Generate all sniper harnesses with value_pool injected into dicts."""
    global _last_pool_size
    vpool = list(value_pool)[:100] if value_pool else []
    _last_pool_size = len(vpool) if vpool else 1
    snipers = []
    for gen in [gen_raw_write_sniper, gen_read_after_write_sniper,
                gen_vfs_write_sniper, gen_dacl_sniper, gen_stream_sniper,
                gen_ea_sniper, gen_lock_sniper, gen_create_ctx_sniper,
                gen_ndr_sniper, gen_compound_sniper, gen_write_lock_race_sniper,
                gen_priv_bypass_sniper, gen_dh_trust_sniper,
                gen_mt_race_sniper, gen_spnego_sniper]:
        try:
            result = gen(vpool)
            if result[0]:
                snipers.append(result)
        except Exception:
            pass
    return snipers


def should_regenerate(value_pool):
    """Regenerate when value_pool grows >2× since last generation."""
    return len(value_pool) > _last_pool_size * 2


def gen_discovery_sniper(pc, arg_val, ret_val, vpool):
    """Auto-generate a sniper targeting a specific (PC, arg) that returned ret=0.
    Mutates values NEAR arg_val to explore the boundary around this function."""
    name = f'disc_{pc & 0xFFFF:04x}'
    src = r'''#include "common.h"
static const char *SHARE = "\\\\127.0.0.1\\share";
/* Target: PC=0x''' + f'{pc:x}' + r''' arg_near=0x''' + f'{arg_val:x}' + r''' */
static uint64_t base_val = 0x''' + f'{arg_val:x}' + r''';

int LLVMFuzzerInitialize(int *a, char ***b) {
    df_init();
    if (smb_connect() < 0 || smb_auth(SHARE) < 0) _exit(1);
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    if (raw_sock < 0 && smb_reconnect(SHARE) < 0) return 0;
    df_buf[0] = 0;

    uint8_t pdu[700], resp[256];

    /* CREATE */
    smb2_hdr(pdu, 5);
    uint8_t *b2 = pdu+64;
    *(uint16_t*)(b2) = 57;
    *(uint32_t*)(b2+24) = 0x12019F; *(uint32_t*)(b2+28) = 0x80;
    *(uint32_t*)(b2+32) = 0x07; *(uint32_t*)(b2+36) = 0x05; *(uint32_t*)(b2+40) = 0x40;
    pdu[120]='d'; pdu[121]=0; pdu[122]='x'; pdu[123]=0;
    *(uint16_t*)(b2+44) = 120; *(uint16_t*)(b2+46) = 4;
    int r = xact(pdu, 124, resp, sizeof(resp));
    if (r < 144) { smb_reconnect(SHARE); return 0; }
    uint8_t fid[16];
    memcpy(fid, resp+128, 16);

    /* WRITE with Length/Offset derived from base_val + fuzzer mutation */
    uint64_t mutated_val = base_val;
    int32_t delta;
    memcpy(&delta, data, 4);
    mutated_val += delta; /* explore around the discovered value */

    size_t wlen = size - 4;
    if (wlen > 512) wlen = 512;
    if (wlen == 0) wlen = 64;

    smb2_hdr(pdu, 0x0009);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 49; *(uint16_t*)(body+2) = 112;
    *(uint32_t*)(body+4) = wlen;
    *(uint64_t*)(body+8) = mutated_val & 0x7FFFFFFFULL;
    memcpy(body+16, fid, 16);
    memset(body+32, 0, 16);
    if (size > 4) memcpy(pdu+176, data+4, wlen > size-4 ? size-4 : wlen);

    r = xact(pdu, 176+wlen, resp, sizeof(resp));

    /* CLOSE */
    smb2_hdr(pdu, 6);
    body = pdu+64; *(uint16_t*)(body) = 24; memcpy(body+8, fid, 16);
    xact(pdu, 88, resp, sizeof(resp));

    /* Feedback: weight ret=0 heavily */
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc2 = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc2 * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
    __builtin_memset(ctr, 0, sizeof(ctr));
    return 0;
}
'''
    return _compile(name, src, vpool)


def generate_discovery_snipers(discoveries, vpool):
    """Generate snipers from a list of (pc, arg_val, ret_val) discoveries.
    Only generates for PCs not already covered by existing snipers."""
    generated = []
    for pc, arg_val, ret_val in discoveries[:5]:  # max 5 new snipers per round
        result = gen_discovery_sniper(pc, arg_val, ret_val, vpool)
        if result[0]:
            generated.append(result)
    return generated


def run_snipers(snipers, time_per=3):
    """Run all sniper harnesses, detect + export crashes."""
    CRASH_DIR.mkdir(exist_ok=True)
    live_dict = Path('/tmp/ksmbdzzer_live.dict')
    PERSISTENT_CORPUS = Path('/tmp/ksmbdzzer_corpus_persistent')
    PERSISTENT_CORPUS.mkdir(exist_ok=True)
    crashes = []
    for binary, dict_path in snipers:
        if not binary:
            continue
        # Persistent corpus per sniper name (survives regeneration)
        name = Path(binary).stem
        corpus_dir = PERSISTENT_CORPUS / name
        corpus_dir.mkdir(exist_ok=True)
        # Merge live dict with sniper's own dict
        dicts = [f'-dict={dict_path}']
        if live_dict.exists():
            dicts.append(f'-dict={live_dict}')
        try:
            r = subprocess.run(
                [binary, f'-max_total_time={time_per}', '-max_len=512'] + dicts + [str(corpus_dir)],
                capture_output=True, text=True, timeout=time_per + 10)
            for line in r.stderr.split('\n'):
                if 'DONE' in line:
                    print(f"    {Path(binary).stem}: {line.strip()}")
                    break
            if 'SUMMARY' in r.stderr and ('AddressSanitizer' in r.stderr or 'deadly' in r.stderr):
                crash_info = r.stderr[-500:]
                crashes.append((binary, crash_info))
                export_crash(binary, crash_info, corpus_dir)
        except Exception:
            pass
    return crashes


def export_crash(binary, stderr_tail, corpus_dir):
    """Save crash reproducer: input + stderr + dmesg + sniper source."""
    ts = int(time.time())
    name = Path(binary).stem
    crash_subdir = CRASH_DIR / f'{name}_{ts}'
    crash_subdir.mkdir(exist_ok=True)

    (crash_subdir / 'stderr.txt').write_text(stderr_tail)

    for f in corpus_dir.iterdir():
        if f.name.startswith(('crash-', 'oom-', 'timeout-')):
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
