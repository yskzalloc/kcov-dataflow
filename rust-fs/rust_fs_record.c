#define _GNU_SOURCE
#include <sys/uio.h>
/*
 * rust_fs_record.c — Record kcov-dataflow during Rust fs/uaccess operations.
 * Exercises: Page read at boundary, UserSlice with NULL/zero-length/kernel-ptr,
 * fget with wrapping u32 values.
 *
 * These operations go through rust/kernel/uaccess.rs, rust/kernel/page.rs,
 * rust/kernel/fs/file.rs — the Rust filesystem abstraction layer.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define KCOV_DF_INIT_TRACE  _IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE      _IO('d', 100)
#define KCOV_DF_DISABLE     _IO('d', 101)
#define BUF_SIZE            (512 << 10)

int main(void)
{
    int df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("open kcov_dataflow"); return 1; }

    if (ioctl(df_fd, KCOV_DF_INIT_TRACE, (unsigned long)BUF_SIZE))
        { perror("INIT"); return 1; }
    uint64_t *buf = mmap(NULL, BUF_SIZE * 8, PROT_READ|PROT_WRITE,
                         MAP_SHARED, df_fd, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    /* Load the Rust mm PoC module which exercises fs/uaccess paths */
    /* The module runs tests on debugfs trigger */
    int mod_loaded = 0;

    if (ioctl(df_fd, KCOV_DF_ENABLE, 0)) { perror("ENABLE"); return 1; }
    __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

    /* === Trigger Rust fs operations === */

    /* 1. Write to debugfs trigger (exercises Rust write handler) */
    int trig = open("/sys/kernel/debug/poc_rust_mm", O_WRONLY);
    if (trig >= 0) {
        write(trig, "1", 1);  /* triggers Page/UserSlice/fget tests */
        close(trig);
        mod_loaded = 1;
    }

    /* 2. Direct syscall exercises that go through VFS → Rust */
    /* read() with invalid fd to test error path */
    char tmp[8];
    read(0xFFFFFFFF, tmp, 8);  /* invalid fd */

    /* 3. write() to /dev/null — exercises VFS write path */
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        write(devnull, "test", 4);
        close(devnull);
    }

    /* 4. readv with zero-length iov — tests boundary */
    struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
    readv(devnull, &iov, 1);

    /* === End === */
    uint64_t n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);
    ioctl(df_fd, KCOV_DF_DISABLE, 0);

    fprintf(stderr, "Captured %lu words (%lu records)\n", n, n/4);
    if (!mod_loaded)
        fprintf(stderr, "Note: poc_rust_mm not loaded, only VFS paths captured\n");

    uint64_t i = 1;
    while (i + 3 <= n && i < BUF_SIZE) {
        uint64_t type_seq = buf[i];
        uint64_t pc = buf[i+1];
        uint64_t meta = buf[i+2];
        uint32_t type = (type_seq >> 28) & 0xF;
        uint32_t seq = type_seq & 0x00FFFFFF;
        uint32_t arg_idx = (meta >> 56) & 0xFF;
        uint32_t sz = (meta >> 48) & 0xFF;
        printf("[%s] seq=%u pc=0x%lx arg[%u] sz=%u val=0x%lx\n",
               type == 0xE ? "ENTRY" : "RET  ",
               seq, pc, arg_idx, sz, buf[i+3]);
        i += 4;
    }

    munmap(buf, BUF_SIZE * 8);
    close(df_fd);
    return 0;
}
