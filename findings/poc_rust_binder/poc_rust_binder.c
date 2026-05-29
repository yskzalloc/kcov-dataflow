// poc_rust_binder.c - Audit Rust Binder IPC via kcov_dataflow
// Exercises edge cases in the Rust binder implementation
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

#define KCOV_DF_INIT  0x80086401
#define KCOV_DF_EN    0x6464
#define KCOV_DF_DIS   0x6465

// Binder ioctls
#define BINDER_VERSION             _IOWR('b', 9, int32_t)
#define BINDER_SET_MAX_THREADS     _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ          _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_CONTEXT_MGR     _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT         _IOW('b', 8, int32_t)

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

// Binder commands
#define BC_ENTER_LOOPER     0x630d
#define BC_EXIT_LOOPER      0x630e
#define BC_REGISTER_LOOPER  0x630b
#define BC_INCREFS          0x6304
#define BC_ACQUIRE          0x6305
#define BC_RELEASE          0x6306
#define BC_DECREFS          0x6307
#define BC_FREE_BUFFER      0x630c

static int df_fd;
static void df_on(void) { ioctl(df_fd, KCOV_DF_EN, 0); }
static void df_off(void) { ioctl(df_fd, KCOV_DF_DIS, 0); }

static int binder_cmd(int fd, uint32_t cmd) {
    struct binder_write_read bwr = {
        .write_size = sizeof(cmd), .write_buffer = (uint64_t)&cmd,
    };
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int binder_cmd_u32(int fd, uint32_t cmd, uint32_t arg) {
    uint8_t buf[8];
    memcpy(buf, &cmd, 4);
    memcpy(buf+4, &arg, 4);
    struct binder_write_read bwr = {
        .write_size = 8, .write_buffer = (uint64_t)buf,
    };
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int binder_cmd_ptr(int fd, uint32_t cmd, uint64_t ptr) {
    uint8_t buf[12];
    memcpy(buf, &cmd, 4);
    memcpy(buf+4, &ptr, 8);
    struct binder_write_read bwr = {
        .write_size = 12, .write_buffer = (uint64_t)buf,
    };
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

int main(void) {
    int fd, ret;

    mkdir("/dev/binderfs", 0755);
    mount("binder", "/dev/binderfs", "binder", 0, NULL);
    fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("open binder"); return 1; }

    df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("open df"); return 1; }
    ioctl(df_fd, KCOV_DF_INIT, 65536);

    // mmap binder (required for transactions)
    void *mapped = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("binder mmap: %p\n", mapped);

    // Case 1: BINDER_VERSION
    printf("Case 1: BINDER_VERSION\n");
    int32_t ver = 0;
    df_on(); ioctl(fd, BINDER_VERSION, &ver); df_off();
    printf("  version=%d\n", ver);

    // Case 2: SET_MAX_THREADS(0) - minimum
    printf("Case 2: SET_MAX_THREADS(0)\n");
    uint32_t mt = 0;
    df_on(); ioctl(fd, BINDER_SET_MAX_THREADS, &mt); df_off();

    // Case 3: SET_MAX_THREADS(0xffffffff) - no validation?
    printf("Case 3: SET_MAX_THREADS(0xffffffff)\n");
    mt = 0xffffffff;
    df_on(); ioctl(fd, BINDER_SET_MAX_THREADS, &mt); df_off();

    // Case 4: BC_ENTER_LOOPER
    printf("Case 4: BC_ENTER_LOOPER\n");
    df_on(); ret = binder_cmd(fd, BC_ENTER_LOOPER); df_off();
    printf("  ret=%d\n", ret);

    // Case 5: BC_ENTER_LOOPER duplicate (should error in Rust binder)
    printf("Case 5: BC_ENTER_LOOPER (duplicate)\n");
    df_on(); ret = binder_cmd(fd, BC_ENTER_LOOPER); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 6: BC_REGISTER_LOOPER (without being requested)
    printf("Case 6: BC_REGISTER_LOOPER (unrequested)\n");
    df_on(); ret = binder_cmd(fd, BC_REGISTER_LOOPER); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 7: BC_FREE_BUFFER with NULL pointer
    printf("Case 7: BC_FREE_BUFFER(NULL)\n");
    df_on(); ret = binder_cmd_ptr(fd, BC_FREE_BUFFER, 0); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 8: BC_FREE_BUFFER with invalid pointer
    printf("Case 8: BC_FREE_BUFFER(0xdeadbeef)\n");
    df_on(); ret = binder_cmd_ptr(fd, BC_FREE_BUFFER, 0xdeadbeef); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 9: BC_INCREFS with handle 0 (context manager)
    printf("Case 9: BC_INCREFS(handle=0)\n");
    df_on(); ret = binder_cmd_u32(fd, BC_INCREFS, 0); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 10: BC_INCREFS with handle 0xffffffff (invalid)
    printf("Case 10: BC_INCREFS(handle=0xffffffff)\n");
    df_on(); ret = binder_cmd_u32(fd, BC_INCREFS, 0xffffffff); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 11: BINDER_SET_CONTEXT_MGR
    printf("Case 11: BINDER_SET_CONTEXT_MGR\n");
    int32_t uid = 0;
    df_on(); ret = ioctl(fd, BINDER_SET_CONTEXT_MGR, &uid); df_off();
    printf("  ret=%d errno=%d\n", ret, errno);

    // Case 12: BINDER_THREAD_EXIT
    printf("Case 12: BINDER_THREAD_EXIT\n");
    int32_t dummy = 0;
    df_on(); ret = ioctl(fd, BINDER_THREAD_EXIT, &dummy); df_off();
    printf("  ret=%d\n", ret);

    if (mapped != MAP_FAILED) munmap(mapped, 1024*1024);
    close(fd);
    close(df_fd);
    printf("Done.\n");
    return 0;
}
