// poc_rust_misc.c - Audit Rust misc device via kcov_dataflow
// Tests: integer boundaries, invalid ioctls, race conditions
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define KCOV_DF_INIT  0x80086401
#define KCOV_DF_EN    0x6464
#define KCOV_DF_DIS   0x6465

// Rust misc device ioctls
#define RUST_MISC_DEV_FAIL      0x00007c00  // _IO('|', 0)
#define RUST_MISC_DEV_HELLO     0x00007c80  // _IO('|', 0x80)
#define RUST_MISC_DEV_GET_VALUE 0x80047c81  // _IOR('|', 0x81, int)
#define RUST_MISC_DEV_SET_VALUE 0x40047c82  // _IOW('|', 0x82, int)

static int df_fd;

static void df_on(void) { ioctl(df_fd, KCOV_DF_EN, 0); }
static void df_off(void) { ioctl(df_fd, KCOV_DF_DIS, 0); }

int main(void) {
    int fd, ret;
    int32_t value;

    fd = open("/dev/rust-misc-device", O_RDWR);
    if (fd < 0) { perror("open misc"); return 1; }

    df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("open df"); return 1; }
    ioctl(df_fd, KCOV_DF_INIT, 65536);

    // Case 1: Normal SET_VALUE(42)
    printf("=== Case 1: SET_VALUE(42) ===\n");
    df_on();
    value = 42;
    ret = ioctl(fd, RUST_MISC_DEV_SET_VALUE, &value);
    df_off();
    printf("ret=%d\n", ret);

    // Case 2: SET_VALUE(INT32_MAX) - boundary
    printf("=== Case 2: SET_VALUE(0x7fffffff) ===\n");
    df_on();
    value = 0x7fffffff;
    ret = ioctl(fd, RUST_MISC_DEV_SET_VALUE, &value);
    df_off();
    printf("ret=%d\n", ret);

    // Case 3: SET_VALUE(INT32_MIN) - negative boundary
    printf("=== Case 3: SET_VALUE(0x80000000) ===\n");
    df_on();
    value = (int32_t)0x80000000;
    ret = ioctl(fd, RUST_MISC_DEV_SET_VALUE, &value);
    df_off();
    printf("ret=%d\n", ret);

    // Case 4: GET_VALUE after setting INT32_MIN
    printf("=== Case 4: GET_VALUE (should be 0x80000000) ===\n");
    df_on();
    value = 0;
    ret = ioctl(fd, RUST_MISC_DEV_GET_VALUE, &value);
    df_off();
    printf("ret=%d value=0x%x\n", ret, value);

    // Case 5: Invalid ioctl number - tests error path
    printf("=== Case 5: Invalid ioctl 0xdeadbeef ===\n");
    df_on();
    ret = ioctl(fd, 0xdeadbeef, NULL);
    df_off();
    printf("ret=%d errno=%d(%s)\n", ret, errno, strerror(errno));

    close(fd);
    close(df_fd);
    return 0;
}
