#define _GNU_SOURCE
/*
 * binder_record.c — Record kcov-dataflow during binder ioctl operations.
 * Exercises: SET_MAX_THREADS, BC_ENTER_LOOPER (duplicate), BINDER_VERSION
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

#define BINDER_VERSION         _IOWR('b', 9, int32_t)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)
#define BC_ENTER_LOOPER        0x630d

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

int main(void)
{
    int df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("open kcov_dataflow"); return 1; }

    if (ioctl(df_fd, KCOV_DF_INIT_TRACE, (unsigned long)BUF_SIZE))
        { perror("INIT"); return 1; }
    uint64_t *buf = mmap(NULL, BUF_SIZE * 8, PROT_READ|PROT_WRITE,
                         MAP_SHARED, df_fd, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    /* Open binder device */
    int binder_fd = open("/dev/binderfs/binder", O_RDWR);
    if (binder_fd < 0) binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) { perror("open binder"); return 1; }

    /* Enable recording */
    if (ioctl(df_fd, KCOV_DF_ENABLE, 0)) { perror("ENABLE"); return 1; }
    __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

    /* === Binder operations === */

    /* 1. BINDER_VERSION */
    int32_t version = 0;
    ioctl(binder_fd, BINDER_VERSION, &version);

    /* 2. SET_MAX_THREADS with dangerous value */
    uint32_t max_threads = 0xdeadbeef;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    /* 3. BC_ENTER_LOOPER */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    /* 4. BC_ENTER_LOOPER duplicate */
    bwr.write_consumed = 0;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    /* 5. SET_MAX_THREADS with 0xffffffff */
    max_threads = 0xffffffff;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    /* === End === */
    uint64_t n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);
    ioctl(df_fd, KCOV_DF_DISABLE, 0);
    close(binder_fd);

    fprintf(stderr, "Captured %lu words (%lu records)\n", n, n/4);

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
