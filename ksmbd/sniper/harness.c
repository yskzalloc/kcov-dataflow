/*
 * smb_harness.c — Persistent fd C extension for ksmbdzzer.py.
 * Keeps file descriptor open across iterations (avoids open/close overhead).
 *
 * Build: cc -shared -fPIC -O2 -o smb_harness.so smb_harness.c
 * Usage from Python: ctypes.CDLL('./smb_harness.so')
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/xattr.h>
#include <linux/falloc.h>

static int g_fd = -1;
static char g_path[256];

int harness_open(const char *path) {
    strncpy(g_path, path, sizeof(g_path) - 1);
    g_fd = open(path, O_RDWR | O_CREAT, 0666);
    return g_fd;
}

int harness_pwrite(long offset, const void *buf, int len) {
    if (g_fd < 0) return -1;
    return pwrite(g_fd, buf, len, offset);
}

int harness_truncate(long size) {
    if (g_fd < 0) return -1;
    return ftruncate(g_fd, size);
}

int harness_xattr(const char *name, const void *val, int vlen) {
    if (g_fd < 0) return -1;
    return fsetxattr(g_fd, name, val, vlen, 0);
}

int harness_fallocate(long offset, long len) {
    if (g_fd < 0) return -1;
    return fallocate(g_fd, 0, offset, len);
}

void harness_close(void) {
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

/*
 * Fast dataflow buffer parse + FNV-1a feature hashing.
 * Returns number of unique features found.
 * features_out: caller-provided array to receive hashed features.
 */
int harness_parse_df(const unsigned long *buf, int buf_words,
                     unsigned int *features_out, int max_features) {
    unsigned long n = buf[0];
    if (n == 0 || n >= (unsigned long)(buf_words - 1))
        return 0;

    int count = 0;
    unsigned long pos = 1;

    while (pos + 3 <= 1 + n && pos + 3 < (unsigned long)buf_words) {
        unsigned long header = buf[pos];
        unsigned long pc = buf[pos + 1];
        int rtype = (header >> 28) & 0xF;
        int nfields = (header >> 24) & 0xF;
        if (nfields == 0) nfields = 1;
        unsigned long rlen = 3 + nfields;
        if (pos + rlen > 1 + n) break;

        /* Only kernel addresses, entry records */
        if (pc >= 0xffffffff80000000UL && rtype == 0xE) {
            unsigned long val = buf[pos + 3];
            if (val < 0x100000000UL) {
                /* FNV-1a 64-bit, truncated to 32 */
                unsigned long h = 0xcbf29ce484222325UL;
                h ^= val;
                h *= 0x100000001b3UL;
                if (count < max_features)
                    features_out[count] = (unsigned int)(h & 0xFFFFFFFF);
                count++;
            }
        }
        /* Return records for transition detection */
        if (pc >= 0xffffffff80000000UL && rtype == 0xF) {
            unsigned long val = buf[pos + 3];
            unsigned long h = 0xcbf29ce484222325UL;
            h ^= pc;
            h *= 0x100000001b3UL;
            h ^= val;
            h *= 0x100000001b3UL;
            if (count < max_features)
                features_out[count] = (unsigned int)(h & 0xFFFFFFFF);
            count++;
        }

        pos += rlen;
    }
    return count;
}
