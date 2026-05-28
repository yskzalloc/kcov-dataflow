// poc_binder.c - Audit binder.c via kcov_dataflow with buffer dump
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>

#define KCOV_DF_INIT_TRACE 0x80086401
#define KCOV_DF_ENABLE     0x6464
#define KCOV_DF_DISABLE    0x6465
#define BUF_WORDS          65536

#define BINDER_VERSION         _IOWR('b', 9, int32_t)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

#define BC_ENTER_LOOPER 0x630d

static int df_fd;

static void df_enable(void) { ioctl(df_fd, KCOV_DF_ENABLE, 0); }
static void df_disable(void) { ioctl(df_fd, KCOV_DF_DISABLE, 0); }

static int open_binder(void) {
    mkdir("/dev/binderfs", 0755);
    mount("binder", "/dev/binderfs", "binder", 0, NULL);
    int fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    return fd;
}

int main(void) {
    int binder_fd = open_binder();
    if (binder_fd < 0) { perror("binder"); return 1; }

    df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("kcov_dataflow"); return 1; }
    ioctl(df_fd, KCOV_DF_INIT_TRACE, BUF_WORDS);

    printf("=== Binder kcov_dataflow audit ===\n");

    // Test 1: BINDER_VERSION
    df_enable();
    int32_t ver = 0;
    ioctl(binder_fd, BINDER_VERSION, &ver);
    df_disable();
    printf("BINDER_VERSION: %d\n", ver);

    // Test 2: SET_MAX_THREADS(0)
    df_enable();
    uint32_t mt = 0;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &mt);
    df_disable();

    // Test 3: BC_ENTER_LOOPER
    df_enable();
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd), .write_buffer = (uint64_t)&cmd,
    };
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    df_disable();

    // Test 4: BC_ENTER_LOOPER again (duplicate!)
    df_enable();
    bwr.write_size = sizeof(cmd);
    bwr.write_consumed = 0;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    df_disable();

    // Test 5: SET_MAX_THREADS(0xffffffff)
    df_enable();
    mt = 0xffffffff;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &mt);
    df_disable();

    close(binder_fd);
    close(df_fd);
    printf("Done.\n");
    return 0;
}
